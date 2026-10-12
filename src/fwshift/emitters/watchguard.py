# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""WatchGuard emitter: neutral model -> the policy part of a Policy Manager configuration file (Fireware 12).

Design rules:

* Nothing is ever widened silently. A policy whose match cannot be expressed is written with
  ``<enabled>false</enabled>`` and reported.
* A policy has a From and a To list of aliases; an alias member is an address at an interface. A
  rule of the model becomes one policy whose lists hold every pair of zone and address it names:
  that is what it matched. Zones are interfaces.
* Policies are written in manual order, in the order of the model: the Firebox applies the first
  that matches. What no policy allows is denied.
* There is no negation: a negated list is written as the addresses that are left.
* Static NAT is an action in the To list of a policy. A NAT rule of the model that translates the
  destination is written as such an action, in the policies that allow exactly its traffic.
  Network dynamic NAT is not written: where the file keeps it is not known.
* The file holds the address groups, aliases, services, NAT actions and policies, and nothing of
  interfaces or system settings: it is not a configuration to restore as it is.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from xml.sax.saxutils import escape

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, ANY_V6, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..names import WATCHGUARD, NameRules, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity

_BAD = re.compile("[^\t\n\r\x20-퟿-�\U00010000-\U0010ffff]")
_BUILTIN: Set[str] = {"any", "any-external", "any-trusted", "any-optional", "firebox", "any-bovpn", "any-muvpn", "ssl-vpn",
                      "any-multicast", "external", "trusted", "optional"}  # fmt: skip


def _x(text: str) -> str:
    return escape(_BAD.sub("_", text))


def _e(tag: str, text: str) -> str:
    return f"<{tag}>{_x(text)}</{tag}>" if text else f"<{tag}/>"


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    for zone in {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}:
        if zone.lower() in _BUILTIN - {"external", "trusted", "optional"} or clean(zone, WATCHGUARD) != zone:
            raise FwshiftError(f"zone '{zone[:40]}' cannot be the name of a Firebox interface here: give it another name with "
                               "--zone-map")  # fmt: skip
    transform.ensure_references(p, report)
    keep = {n for n, a in p.addresses.items() if a.builtin == "watchguard"} | {n for n, g in p.address_groups.items() if g.builtin == "watchguard"}
    reserved = {"Any", "Firebox", "Any-External", "Any-Trusted", "Any-Optional", "Any-BOVPN", "Any-MUVPN", "SSL-VPN", "Any-Multicast"}
    transform.sanitize_names(p, WATCHGUARD, WATCHGUARD, report, reserved_addresses=reserved - keep, reserved_services={"Any"},
                             prefix=options.object_prefix, keep=keep)  # fmt: skip
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "watchguard"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s: Dict[str, str] = {}
        self.taken: Set[str] = {n.lower() for n in list(p.addresses) + list(p.address_groups) + list(p.services)}
        self.address_groups: List[str] = []
        self.aliases: List[str] = []
        self.services: List[str] = []
        self.nat: List[str] = []
        self.abs: List[str] = []
        self.concrete: List[str] = []
        self.leaf: Dict[str, str] = {}  # address of the model (or literal) -> address-group written for it
        self.literals: Dict[Interval, str] = {}
        self.svc_written: Set[str] = set()
        self.snat: Dict[str, str] = {}  # NAT rule origin -> SNAT alias
        self.nat_by_destination: List[NatRule] = []
        self.used_nat: Set[str] = set()
        self.zones: Set[str] = set()

    def _name(self, label: str, rules: NameRules = WATCHGUARD) -> str:
        base = clean(label, rules)
        candidate, counter = base, 2
        while candidate.lower() in self.taken:
            tail = f".{counter}"
            candidate = base[: rules.max_len - len(tail)] + tail
            counter += 1
        self.taken.add(candidate.lower())
        return candidate

    # -- top level --------------------------------------------------------------------------------

    def run(self) -> str:
        self._address_objects()
        self._services()
        self._nat_actions()
        for rule in self.p.rules:
            self._rule(rule)
        for nat in self.p.nat_rules:
            self._nat_left(nat)
        written = {n.origin for n in self.p.nat_rules if not self.report.item("nat", n.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "first-match")
        self._notes()
        out = ['<?xml version="1.0" encoding="UTF-8"?>',
               "<!-- Generated by FWShift: the policy part of a Policy Manager configuration file. Not a file to restore as it "
               "is: see the report. -->",
               "<profile>", " <for-version>12.2</for-version>",
               " <address-group-list>", *self.address_groups, " </address-group-list>",
               " <service-list>", *self.services, " </service-list>",
               " <nat-list>", *self.nat, " </nat-list>",
               " <alias-list>", *self.aliases, " </alias-list>",
               " <abs-policy-list>", *self.abs, " </abs-policy-list>",
               " <policy-list>", *self.concrete, " </policy-list>",
               " <system-parameters><misc-global-setting><auto-order-enabled>0</auto-order-enabled></misc-global-setting></system-parameters>",
               "</profile>"]  # fmt: skip
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "WATCHGUARD_LOAD",
            "the output is the policy part of a configuration file of Policy Manager: address groups, aliases, services, "
            "static NAT actions and policies in manual order. It holds no interfaces and no system settings, so it is not a "
            "file to restore on a Firebox as it is (a restore replaces the whole configuration). Merge its lists into a "
            "configuration saved from the target, open the result in Policy Manager and check it there before it goes to "
            "the Firebox. WatchGuard publishes no schema of the file: the elements are those of the published readers of "
            "the format, and the words for the action of a policy (Allow, Deny) are assumed",
        )  # fmt: skip
        if self.zones and not self.native:
            self.report.note(Severity.REVIEW, "INTERFACES_REQUIRED",
                             "the policies name these zones as interfaces of the Firebox, which must exist under these names "
                             "(or be renamed with --zone-map): " + ", ".join(sorted(self.zones)))  # fmt: skip
        if self.p.default_interzone == Action.ALLOW or self.p.default_intrazone == Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTERZONE_DEFAULT",
                             "the source allows what no rule matches; the Firebox denies it. Add a policy that allows it if "
                             "that was intended")  # fmt: skip

    # -- addresses --------------------------------------------------------------------------------

    def _group_xml(self, name: str, members: List[Tuple[str, str]], prop: str = "0", description: str = "") -> None:
        body = []
        for kind, value in members:
            if kind == "fqdn":
                body.append(f"<member><type>8</type>{_e('domain', value)}</member>")
                continue
            interval = parse_literal(value)
            assert interval is not None
            version, first, last = interval
            nets = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
            if first == last:
                body.append(f"<member><type>1</type>{_e('host-ip-addr', str(int_to_ip(version, first)))}</member>")
            elif len(nets) == 1 and version == 4 and kind != "range":
                net = ipaddress.ip_network(str(nets[0]))
                body.append(f"<member><type>2</type>{_e('ip-network-addr', str(net.network_address))}{_e('ip-mask', str(net.netmask))}</member>")
            else:
                body.append(f"<member><type>3</type>{_e('start-ip-addr', str(int_to_ip(version, first)))}"
                            f"{_e('end-ip-addr', str(int_to_ip(version, last)))}</member>")  # fmt: skip
        self.address_groups.append(f"  <address-group>{_e('name', name)}{_e('description', description[:200])}<property>{prop}</property>"
                                   f"<addr-group-member>{''.join(body)}</addr-group-member></address-group>")  # fmt: skip

    def _address_objects(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            if address.builtin == "watchguard" and self.native:
                continue
            if address.kind == AddressKind.UNSUPPORTED or name in self.taint_a:
                reason = self.taint_a.get(name) or address.raw or "address that could not be converted"
                self._group_xml(name, [("host", "192.0.0.8")], description=_placeholder(reason))  # the dummy address of RFC 7600
                self.leaf[name] = name
            elif address.kind == AddressKind.FQDN:
                self._group_xml(name, [("fqdn", address.value)])
                self.leaf[name] = name
            else:
                interval = parse_literal(address.value)
                if interval is None:
                    self.taint_a[name] = "address that could not be read"
                    self._group_xml(name, [("host", "192.0.0.8")], description=_placeholder(self.taint_a[name]))
                    self.leaf[name] = name
                    continue
                self._group_xml(name, [("range" if address.kind == AddressKind.RANGE else "net", interval_text(interval))])
                self.leaf[name] = name
                self.literals.setdefault(interval, name)
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a)), **self.taint_a}
        # Groups of the model become aliases, as Fireware has them: members that are objects, aliases or literals.
        for group in self.p.address_groups.values():
            if group.builtin == "watchguard" and self.native:
                continue
            members: List[str] = []
            for member in group.members:
                if member in self.p.address_groups:
                    members.append(f"<alias-member><type>2</type>{_e('alias-name', member)}</alias-member>")
                else:
                    members.append(self._tuple(self._leaf(member), ANY))
            if not members:
                members.append(self._tuple(self._leaf("192.0.0.8"), ANY))
            self.aliases.append(f"  <alias>{_e('name', group.name)}<description/><property>0</property><alias-member-list>"
                                f"{''.join(members)}</alias-member-list></alias>")  # fmt: skip

    def _leaf(self, member: str) -> str:
        """The address-group that holds one address of the model: the object itself, or one for a literal."""
        if member in self.leaf:
            return self.leaf[member]
        interval = parse_literal(member)
        assert interval is not None, member
        if interval not in self.literals:
            name = self._name(f"{self.options.object_prefix}{interval_text(interval).replace('/', '_')}.alm")
            self._group_xml(name, [("net", interval_text(interval))], "16")
            self.literals[interval] = name
        return self.literals[interval]

    @staticmethod
    def _tuple(address: str, zone: str) -> str:
        interface = "Any" if zone == ANY else zone
        return (f"<alias-member><type>1</type><user>Any</user>{_e('address', 'Any' if address == ANY else address)}"
                f"{_e('interface', interface)}</alias-member>")  # fmt: skip

    def _leaves(self, member: str, seen: Set[str]) -> List[str]:
        if member in self.p.address_groups:
            if member in seen:
                return []
            group = self.p.address_groups[member]
            if group.builtin == "watchguard" and self.native:
                return [member]
            return [leaf for inner in group.members for leaf in self._leaves(inner, seen | {member})]
        return [member]

    # -- services ---------------------------------------------------------------------------------

    def _service_members(self, entries: List[ServiceEntry]) -> Tuple[List[str], str]:
        out: List[str] = []
        for entry in entries:
            if entry.src_ports:
                return [], "source ports, which a service of Fireware does not match"
            if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                number = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132}[entry.protocol]
                if entry.protocol == Protocol.SCTP and entry.dst_ports:
                    return [], "SCTP ports"
                for part in (entry.dst_ports or "0").split(","):
                    low, _, high = part.partition("-")
                    if entry.dst_ports and int(low) == 0 and (not high or int(high) == 0):
                        return [], "port 0 and no other, which a service of Fireware cannot name (0 is every port)"
                    if not high or low == high:
                        out.append(f"<member><type>1</type><protocol>{number}</protocol><server-port>{int(low)}</server-port></member>")
                    else:
                        out.append(f"<member><type>2</type><protocol>{number}</protocol><start-server-port>{int(low)}</start-server-port>"
                                   f"<end-server-port>{int(high)}</end-server-port></member>")  # fmt: skip
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                kind = 255 if entry.icmp_type is None else entry.icmp_type
                code = 255 if entry.icmp_code is None else entry.icmp_code
                out.append(f"<member><type>1</type><protocol>{1 if entry.protocol == Protocol.ICMP else 58}</protocol>"
                           f"<icmp-type>{kind}</icmp-type><icmp-code>{code}</icmp-code></member>")  # fmt: skip
            else:
                if entry.ip_protocol == 0:
                    return [], "IP protocol 0, which a service of Fireware cannot name (0 is every protocol)"
                out.append(f"<member><type>1</type><protocol>{entry.ip_protocol or 0}</protocol><server-port>0</server-port></member>")
        return out, ""

    def _write_service(self, name: str, members: List[str], prop: str = "0") -> None:
        self.services.append(f"  <service>{_e('name', name)}<description/><property>{prop}</property><proxy-type/>"
                             f"<service-item>{''.join(members)}</service-item><idle-timeout>0</idle-timeout></service>")  # fmt: skip
        self.svc_written.add(name)

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        self._write_service("Any", ["<member><type>1</type><protocol>0</protocol><server-port>0</server-port></member>"], "4")
        for service in self.p.services.values():
            if service.name == "Any":
                continue
            if service.unsupported or not service.entries:
                bad[service.name] = service.unsupported or "a service without content"
                continue
            members, problem = self._service_members(service.entries)
            if problem:
                bad[service.name] = problem
                self.report.add("service", service.name, Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: not written, and the policies that use it are disabled")  # fmt: skip
                continue
            self._write_service(service.name, members)
        self.taint_s = transform.tainted_services(self.p, bad)

    def _rule_service(self, rule: Rule, reasons: List[transform.Reason]) -> str:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [e for _, found in lowered for e in found]
        else:
            if ANY in rule.services:
                return "Any"
            if len(rule.services) == 1 and rule.services[0] in self.svc_written:
                return rule.services[0]
            entries = [e for s in rule.services for e in (transform.flatten_services(self.p, s) or [])]
        if not entries:
            return "Any"
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return "Any"
        members, problem = self._service_members(entries)
        if problem:
            reasons.append(("UNCONVERTIBLE_OBJECT", f"the services of the rule hold {problem}"))
            return "Any"
        name = self._name(f"{self.options.object_prefix}{rule.name}.svc")
        self._write_service(name, members, "16")
        return name

    # -- policies ---------------------------------------------------------------------------------

    def _alias(self, label: str, members: List[str]) -> str:
        name = self._name(label)
        self.aliases.append(f"  <alias>{_e('name', name)}<description/><property>16</property><alias-member-list>"
                            f"{''.join(members)}</alias-member-list></alias>")  # fmt: skip
        return name

    def _side(self, rule: Rule, zones: List[str], members: List[str], negated: bool, side: str,
              reasons: List[transform.Reason]) -> Optional[List[str]]:  # fmt: skip
        """The alias members of one side of a policy: every zone with every address. None when it matches nothing."""
        addresses: List[str] = []
        if negated:
            named: List[Interval] = []
            for member in members:
                resolved = transform.address_intervals(self.p, member)
                if resolved is None:
                    reasons.append(("NEGATION_NOT_STATIC", f"the {side} is negated and holds a host name: what it leaves cannot "
                                    "be written as addresses"))  # fmt: skip
                    resolved = []
                named += resolved
            left = subtract([FULL_V4, FULL_V6], named)
            if not left:
                return None
            addresses = [ANY] if left == [FULL_V4, FULL_V6] else [self._leaf(interval_text(i)) for i in left]
            self.report.add("rule", rule.origin, Severity.INFO, "NEGATION_EXPANDED",
                            f"Fireware has no negation: 'not {side} {', '.join(members)}' is written as the addresses that are left")  # fmt: skip
        else:
            for member in members:
                for leaf in self._leaves(member, set()):
                    if self.native and leaf in self.p.addresses and self.p.addresses[leaf].builtin == "watchguard":
                        addresses.append(leaf)  # the Firebox itself: named, as the target has it
                    elif leaf in (ANY,) or (leaf in (ANY_V4, ANY_V6)):
                        addresses.append(ANY if leaf == ANY else self._leaf(leaf))
                    elif leaf in self.p.address_groups:
                        addresses.append(leaf)  # a group of the Firebox itself, from a WatchGuard
                    else:
                        addresses.append(self._leaf(leaf))
        if ANY in addresses:
            addresses = [ANY]
        out: List[str] = []
        for zone in zones:
            if zone != ANY:
                self.zones.add(zone)
            for address in dict.fromkeys(addresses):
                if address in self.p.address_groups or (self.native and address in self.p.addresses
                                                        and self.p.addresses[address].builtin == "watchguard"):
                    out.append(f"<alias-member><type>2</type>{_e('alias-name', address)}</alias-member>")
                else:
                    out.append(self._tuple(address, zone))
        return out

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service cannot be written: Fireware has no negation"))
        if rule.scope != RuleScope.UNIVERSAL:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a policy of Fireware names interfaces, not pairs of zones"))
        service = self._rule_service(rule, reasons)
        sources = self._side(rule, rule.src_zones, rule.sources, rule.negate_source, "source", reasons)
        destinations = self._side(rule, rule.dst_zones, rule.destinations, rule.negate_destination, "destination", reasons)
        if sources is None or destinations is None:
            self.report.skip("rule", rule.origin, "NO_COMMON_FAMILY", "a negation leaves no address: the rule matches nothing", Severity.INFO)
            return
        nat = self._nat_for(rule, reasons)
        if nat is not None:
            destinations = [f"<alias-member><type>2</type>{_e('alias-name', self.snat[nat.origin])}</alias-member>"]
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION", f"action {rule.action.value} becomes Deny")
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        name = self._name(rule.name)
        src_alias = self._alias(f"{name}.1.from", sources)
        dst_alias = self._alias(f"{name}.1.to", destinations)
        allow = rule.action == Action.ALLOW
        enabled = rule.enabled and not reasons
        description = " ".join(rule.description.split())
        if reasons:
            description = f"FWSHIFT inactive, see the report. {description}".strip()
        self.abs.append(
            f"  <abs-policy>{_e('name', name)}<property>0</property>{_e('service', service)}{_e('description', description[:200])}"
            f"<type>Firewall</type><traffic-type>1</traffic-type><enabled>{'true' if enabled else 'false'}</enabled>"
            f"<firewall>{'Allow' if allow else 'Deny'}</firewall>"
            f"<from-alias-list>{_e('alias', src_alias)}</from-alias-list><to-alias-list>{_e('alias', dst_alias)}</to-alias-list>"
            f"<settings><schedule>Always On</schedule><log-enabled>{'true' if rule.log_end or rule.log_start else 'false'}</log-enabled></settings>"
            f"<policy-list>{_e('policy', name + '-00')}</policy-list></abs-policy>"
        )  # fmt: skip
        self.concrete.append(
            f"  <policy>{_e('name', name + '-00')}<property>0</property>{_e('service', service)}<firewall>{1 if allow else 2}</firewall>"
            f"<enable>{1 if enabled else 0}</enable><from-alias-list>{_e('alias', src_alias)}</from-alias-list>"
            f"<to-alias-list>{_e('alias', dst_alias)}</to-alias-list></policy>"
        )  # fmt: skip
        item.emitted_as.append(name)

    # -- NAT --------------------------------------------------------------------------------------

    def _nat_actions(self) -> None:
        """Static NAT actions for the NAT rules that translate the destination only."""
        for nat in self.p.nat_rules:
            translation = nat.destination_translation
            if translation is None or nat.source_translation is not None:
                continue
            problems = list(nat.unsupported) + [f"references '{m}': {self.taint_a[m]}" for m in nat.destinations + [translation.address] if m in self.taint_a]
            if translation.spread:
                problems.append("a translation to one of several addresses (server load balancing is not written)")
            outside = transform.address_intervals(self.p, nat.destinations[0]) if len(nat.destinations) == 1 and nat.destinations[0] != ANY else None
            if not outside or len(outside) != 1 or outside[0][0] != 4:
                problems.append("a static NAT action of Fireware translates one external IPv4 address or range")
            inside = transform.address_intervals(self.p, translation.address)
            if not inside or len(inside) != 1 or inside[0][1] != inside[0][2] or inside[0][0] != 4:
                problems.append(f"translated destination '{translation.address}' is not one IPv4 address")
            if problems:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + "; ".join(transform.dedupe(problems)))
                continue
            name = self._name(nat.name)
            ext = self._name(f"{name}.1.snat")
            self._group_xml(ext, [("net", interval_text(parse_literal_of(self.p, nat.destinations[0])))], "16")
            internal = self._name(f"{name}.2.snat")
            self._group_xml(internal, [("net", interval_text(inside[0]))], "16")  # type: ignore[index]
            interface = nat.dst_zones[0] if nat.dst_zones and nat.dst_zones[0] != ANY else "Any-External"
            self.nat.append(f"  <nat>{_e('name', name)}<property>0</property><type>7</type><algorithm>0</algorithm><proxy-arp>0</proxy-arp>"
                            f"<nat-item><member><addr-type>4</addr-type><port>{translation.port or 0}</port>{_e('ext-addr-name', ext)}"
                            f"{_e('interface', interface)}{_e('addr-name', internal)}</member></nat-item></nat>")  # fmt: skip
            alias = self._name(f"{name}.snat")
            self.aliases.append(f"  <alias>{_e('name', alias)}<description/><property>32</property><alias-member-list>"
                                f"{self._tuple(ext, nat.dst_zones[0] if nat.dst_zones and nat.dst_zones[0] != ANY else ANY)}"
                                f"</alias-member-list></alias>")  # fmt: skip
            self.snat[nat.origin] = alias
            self.nat_by_destination.append(nat)

    def _nat_for(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[NatRule]:
        """The static NAT a policy carries: a NAT rule for exactly the destination it allows, its services and zones."""
        for nat in self.nat_by_destination:
            if rule.destinations != nat.destinations or rule.negate_destination:
                continue
            if rule.action != Action.ALLOW:
                return None
            # The first NAT rule of the model that can apply to this traffic decides; it must be this one.
            first = next((other for other in self.p.nat_rules if other.enabled and self._overlaps(other.destinations, rule.destinations)), None)
            same_service = nat.service == ANY or rule.services == [nat.service]
            same_zones = ANY in nat.src_zones or (ANY not in rule.src_zones and set(rule.src_zones) <= set(nat.src_zones))
            same_sources = ANY in nat.sources or (not rule.negate_source and set(rule.sources) <= set(nat.sources))
            if not (same_service and same_zones and same_sources and nat.enabled and first is nat):
                self.report.add("rule", rule.origin, Severity.REVIEW, "NAT_NOT_IN_POLICY",
                                f"the rule allows the destination of NAT rule '{nat.name}' for other services or zones than the "
                                "NAT rule translates: on a Firebox the translation is part of the policy, and it is not written "
                                "into this one, which allows the address without translating it")  # fmt: skip
                return None
            self.used_nat.add(nat.origin)
            if ANY not in rule.dst_zones:
                self.report.add("rule", rule.origin, Severity.APPROX, "NAT_ZONE_DROPPED",
                                f"the rule is for traffic to zone {', '.join(rule.dst_zones)}; with the static NAT action of "
                                f"'{nat.name}' the policy names the public address, and allows the translated traffic wherever "
                                "its server is")  # fmt: skip
            if nat.origin not in self.report.item("nat", nat.origin).emitted_as:
                self.report.item("nat", nat.origin).emitted_as.append(f"static NAT action {self.snat[nat.origin]}")
            return nat
        return None

    def _overlaps(self, first: List[str], second: List[str]) -> bool:
        if ANY in first or ANY in second:
            return True
        a = [i for m in first for i in transform.address_intervals(self.p, m) or []]
        b = [i for m in second for i in transform.address_intervals(self.p, m) or []]
        return any(x[0] == y[0] and x[1] <= y[2] and y[1] <= x[2] for x in a for y in b)

    def _nat_left(self, nat: NatRule) -> None:
        item = self.report.item("nat", nat.origin)
        if item.skipped:
            return
        if nat.origin in self.used_nat:
            return
        if nat.origin in self.snat:
            self.report.skip("nat", nat.origin, "NAT_NO_POLICY",
                             "on a Firebox static NAT is part of a policy, and no rule allows exactly the traffic this rule "
                             "translates: the action is written and used by no policy", Severity.INFO)  # fmt: skip
            return
        self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                         "not converted: source NAT is dynamic NAT on a Firebox, which this file does not hold (where Policy "
                         "Manager keeps it is not known)" if nat.source_translation is not None else "not converted: a rule "
                         "without translation (a NAT exemption) has no place in this file")  # fmt: skip


def _placeholder(reason: str) -> str:
    return " ".join(f"FWSHIFT PLACEHOLDER, matches nothing: {reason}".split())


def parse_literal_of(p: Policy, member: str) -> Interval:
    found = transform.address_intervals(p, member)
    assert found and len(found) == 1, member
    return found[0]


__all__ = ["emit"]
