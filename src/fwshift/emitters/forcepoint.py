# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Forcepoint NGFW emitter: neutral model -> a Python script that loads the policy into a Security Management Center.

The output is ``smc_loader.py`` with the policy as data at its end. Through the SMC REST API it creates the elements
(hosts, networks, ranges, domain names, groups, expressions, zones, match expressions, services) and a new firewall
policy on a template (``--target-template``, default the predefined Firewall Template), with the access rules and the
NAT rules in order. It changes nothing that exists and uploads the policy to no engine.

Design rules:

* Nothing is widened silently. A rule whose match cannot be written is written disabled, with what can be written of
  it (a cell with nothing left in it is NONE); it is reported.
* IPv4 and IPv6 rules are separate lists. A rule goes into the list of each IP version it can match, with the part of
  its groups of that version: a group that holds both is written once more for each version where a rule needs it.
* A zone in a cell is ORed with the addresses there. A rule that limits a side by zones and addresses gets a match
  expression per zone and address element, whose parts are ANDed.
* A negated side is an expression (exclusion) of the members.
* Access rules match the addresses before NAT, as the model does; NAT rules are first match, and translate source and
  destination together. Nothing is rewritten for NAT.
* What no rule decides: the policy ends in the rules of its template (the predefined ones refuse Ident and discard
  the rest), and an engine discards what no rule allows. Where the source allows more by default, rules at the end
  of the policy say so.
"""

from __future__ import annotations

import copy
import dataclasses
import ipaddress
import json
import pkgutil
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import __version__, transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, ANY_V6, Action, AddressKind, NatRule, Policy, Protocol, Rule, ServiceEntry, SnatKind
from ..names import FORCEPOINT, FORCEPOINT_NATIVE, FORCEPOINT_TEXT, NameRules, clean, unique
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, parse_literal, size
from ..options import Options
from ..report import Report, Severity
from .checkpoint import _zone_names  # zone names that cannot be element names are changed, and said

Json = Dict[str, Any]
Cell = Optional[Json]  # None: nothing of this IP version
LISTS = {4: "fw_ipv4_access_rule", 6: "fw_ipv6_access_rule"}
NAT_LISTS = {4: "fw_ipv4_nat_rule", 6: "fw_ipv6_nat_rule"}
_DEFAULT_NAT = ("default_nat_address_alias", "$$ Default NAT Address")
_INTERFACE_ALIAS = re.compile(r"Interface ID (\d+(?:\.\d+)?)")
_ICMP_NUMBERS = {Protocol.ICMP: 1, Protocol.ICMP6: 58}


def loader_source() -> str:
    data = pkgutil.get_data(__package__ or "fwshift.emitters", "smc_loader.py")
    if data is None:
        raise FwshiftError("the loader for a Security Management Center (smc_loader.py) is missing from this installation of FWShift")
    return data.decode("utf-8").replace("\r\n", "\n")


def ref(kind: str, name: str) -> Json:
    return {"@ref": kind, "name": name}


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    native = p.vendor == "forcepoint"
    rules = FORCEPOINT_NATIVE if native else FORCEPOINT
    source_zones = {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}
    options = dataclasses.replace(options, zone_map=_zone_names(p, options, source_zones, rules, report))
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    for option, value in (("--target-policy", options.target_policy), ("--target-template", options.target_template)):
        if not value or clean(value, FORCEPOINT_NATIVE) != value or len(value) > 254:
            raise FwshiftError(f"{option} '{value[:40]}' is not a name for a policy of a Security Management Center")
    prefix = options.object_prefix
    if prefix and (FORCEPOINT.invalid.search(prefix) or len(prefix) > 40):
        raise FwshiftError("--target-prefix takes up to 40 letters, digits, spaces, periods, underscores, hyphens and parentheses")
    zones = transform.target_zones(p, options.zone_map, [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY], [])
    # One namespace for every element the script creates, zones among them: which names an SMC tells apart is not
    # published.
    reserved = set(zones)
    transform.sanitize_names(p, rules, FORCEPOINT_TEXT, report, reserved, reserved, one_namespace=True, prefix=prefix)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones, zones, rules).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: Set[str], zones: List[str], rules: NameRules) -> None:
        self.p, self.report, self.options, self.names = p, report, options, rules
        self.native = p.vendor == "forcepoint"
        self.prefix = options.object_prefix
        self.source_zones = source_zones
        self.zones = zones
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s: Dict[str, str] = {}
        self.taken: Set[str] = set(p.addresses) | set(p.address_groups) | set(p.services) | set(p.service_groups) | set(zones)
        self.elements: List[Json] = []
        self.made: Dict[Tuple[str, str], Json] = {}  # (type, name) -> body of an element the script creates
        self.address_ref: Dict[str, Json] = {}  # model address or group -> element
        self.views: Dict[Tuple[str, int], Optional[Json]] = {}  # (group, IP version) -> its part of that version
        self.literals: Dict[Tuple[Interval, bool], Json] = {}
        self.domains: Dict[str, Json] = {}
        self.expressions: Dict[Tuple[str, ...], Json] = {}
        self.rows: Dict[Tuple[str, str], Json] = {}  # (zone, element name) -> match expression
        self.service_ref: Dict[str, List[Json]] = {}  # model service or group -> elements (several: ORed in a cell)
        self.service_family: Dict[str, Set[int]] = {}
        self.single_service: Dict[str, ServiceEntry] = {}
        self.app_services: Dict[Tuple[str, str], List[Json]] = {}
        self.port_services: Dict[Tuple[str, str], Json] = {}
        self.used_zones: List[str] = []
        self.existing: List[Json] = []
        self.lists: Dict[str, List[Json]] = {name: [] for name in list(LISTS.values()) + list(NAT_LISTS.values())}
        self.section: Dict[str, str] = {}
        self.refused = 0
        self.nat_written = 0
        self.interface_alias: List[str] = []

    # -- elements -------------------------------------------------------------------------------

    def _new_name(self, label: str) -> str:
        return unique(self.prefix + label, self.taken, FORCEPOINT)

    def _element(self, kind: str, body: Json) -> Json:
        key = (kind, str(body["name"]))
        if key not in self.made:
            self.made[key] = body
            self.elements.append({"type": kind, "body": body})
        return ref(kind, key[1])

    def _comment(self, body: Json, text: str) -> Json:
        text = " ".join(text.split())[:1000]
        if text:
            body["comment"] = text
        return body

    def _address_element(self, name: str, interval: Interval, is_range: bool, comment: str = "") -> Json:
        version, first, last = interval
        if first == last and not is_range:
            key = "address" if version == 4 else "ipv6_address"
            return self._element("host", self._comment({"name": name, key: str(int_to_ip(version, first))}, comment))
        networks = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
        if is_range or len(networks) != 1:
            text = f"{int_to_ip(version, first)}-{int_to_ip(version, last)}"
            return self._element("address_range", self._comment({"name": name, "ip_range": text}, comment))
        key = "ipv4_network" if version == 4 else "ipv6_network"
        return self._element("network", self._comment({"name": name, key: str(networks[0]), "broadcast": True}, comment))

    def _addresses(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            if name in self.taint_a:
                self._not_created("address", name, self.taint_a[name])
                continue
            if address.kind == AddressKind.FQDN:
                host = address.value.strip().rstrip(".").lower()
                others = set(self.p.addresses) | set(self.p.address_groups) | set(self.p.services) | set(self.p.service_groups) | set(self.zones)
                if host != name and host in others and host not in self.domains:
                    self.taint_a[name] = f"a domain name element is named after the domain, and '{host}' is the name of another object"
                    self._not_created("address", name, self.taint_a[name])
                    continue
                if host not in self.domains:
                    # A domain name element is named after the domain itself.
                    self.taken.add(host)
                    self.domains[host] = self._element("domain_name", self._comment({"name": host}, address.description))
                self.address_ref[name] = self.domains[host]
                continue
            interval = parse_literal(address.value)
            if interval is None:
                self.taint_a[name] = f"unreadable address '{address.value}'"
                self._not_created("address", name, self.taint_a[name])
                continue
            self.address_ref[name] = self._address_element(name, interval, address.kind == AddressKind.RANGE, address.description)
        changed = True
        while changed:  # a group that holds an object that is not created is not created either
            changed = False
            for group in self.p.address_groups.values():
                bad = [m for m in group.members if m in self.taint_a]
                if bad and group.name not in self.taint_a:
                    self.taint_a[group.name] = f"contains '{bad[0]}' ({self.taint_a[bad[0]]})"
                    changed = True
        for group in transform.topo_groups(self.p.address_groups):
            if group.name in self.taint_a:
                self._not_created("address-group", group.name, self.taint_a[group.name])
                continue
            members = self._refs([self._member(m) for m in group.members])
            self.address_ref[group.name] = self._element("group", self._comment({"name": group.name, "element": members}, group.description))

    def _not_created(self, kind: str, name: str, why: str) -> None:
        self.report.add(kind, name, Severity.INFO, "NOT_CREATED", f"not created ({why}); rules that use it are written disabled")

    @staticmethod
    def _refs(items: List[Json]) -> List[Json]:
        out: List[Json] = []
        for item in items:
            if item not in out:
                out.append(item)
        return out

    def _member(self, member: str) -> Json:
        """The element for a member of a group or a cell: an object of the policy, or a literal."""
        if member in self.address_ref:
            return self.address_ref[member]
        interval = parse_literal(member)
        assert interval is not None, member  # ensure_references made every other name an object
        is_range = "-" in member and "/" not in member and interval[1] != interval[2]
        if (interval, is_range) not in self.literals:
            version, first, last = interval
            if interval in (FULL_V4, FULL_V6):
                label = "All IPv4" if version == 4 else "All IPv6"
            elif first == last:
                label = f"h-{int_to_ip(version, first)}"
            elif is_range:
                label = f"r-{int_to_ip(version, first)}-{int_to_ip(version, last)}"
            else:
                net = ipaddress.ip_network(member.strip(), strict=False)
                label = f"n-{net.network_address}_{net.prefixlen}"
            self.literals[(interval, is_range)] = self._address_element(self._new_name(label.replace(":", ".")), interval, is_range)
        return self.literals[(interval, is_range)]

    def _view(self, member: str, family: int) -> Optional[Json]:
        """The element for the part of a member of one IP version; None when it has nothing of that version."""
        if member == ANY:
            return None
        if member in (ANY_V4, ANY_V6) or parse_literal(member) in (FULL_V4, FULL_V6):
            return None if (parse_literal(member) or (0,))[0] != family else {"any": True}
        families = transform.families(self.p, member)
        address = self.p.addresses.get(member)
        if address is not None and address.kind == AddressKind.FQDN:
            return self._member(member) if family in families else None
        if family not in families:
            return None
        if families == {family} or member not in self.p.address_groups:
            return self._member(member)
        key = (member, family)
        if key not in self.views:
            members: List[Json] = []
            for inner in self.p.address_groups[member].members:
                found = self._view(inner, family)
                if found is not None and "any" not in found:
                    members.append(found)
                elif found is not None:
                    members = [found]
                    break
            whole = [self._member(inner) for inner in self.p.address_groups[member].members]
            if members == [{"any": True}]:
                self.views[key] = {"any": True}
            elif not members:
                self.views[key] = None
            elif self._refs(members) == self._refs(whole):
                self.views[key] = self._member(member)  # (host names: in both)
            else:
                name = self._new_name(f"{member} IPv{family}")
                self.views[key] = self._element("group", {"name": name, "element": self._refs(members),
                                                          "comment": f"the IPv{family} addresses of {member}"})  # fmt: skip
        return self.views[key]

    # -- services -------------------------------------------------------------------------------

    @staticmethod
    def _pieces(entry: ServiceEntry) -> List[Tuple[str, str, Json]]:
        """(element type, label, fields) of the service elements one entry needs; [] when no element can say it."""
        out: List[Tuple[str, str, Json]] = []
        proto = entry.protocol
        if proto in (Protocol.TCP, Protocol.UDP):
            kind = "tcp_service" if proto == Protocol.TCP else "udp_service"
            for source in entry.src_ports.split(",") if entry.src_ports else [""]:
                for port in (entry.dst_ports or "1-65535").split(","):
                    low, _, high = port.partition("-")
                    fields: Json = {"min_dst_port": max(int(low), 1), "max_dst_port": int(high or low)}
                    label = f"{proto.value}-{port}"
                    if source:
                        first, _, last = source.partition("-")
                        fields.update({"min_src_port": max(int(first), 1), "max_src_port": int(last or first)})
                        label += f" from {source}"
                    if fields["max_dst_port"] < fields["min_dst_port"]:
                        return []  # port 0 only
                    out.append((kind, label, fields))
        elif proto in (Protocol.ICMP, Protocol.ICMP6):
            if entry.icmp_type is None:
                out.append(("ip_service", proto.value, {"protocol_number": _ICMP_NUMBERS[proto]}))
            else:
                kind = "icmp_service" if proto == Protocol.ICMP else "icmp_ipv6_service"
                fields = {"icmp_type": entry.icmp_type}
                label = f"{proto.value}-type{entry.icmp_type}"
                if entry.icmp_code is not None:
                    fields["icmp_code"] = entry.icmp_code
                    label += f"-code{entry.icmp_code}"
                out.append((kind, label, fields))
        elif proto == Protocol.SCTP:
            if entry.dst_ports or entry.src_ports:
                return []
            out.append(("ip_service", "sctp", {"protocol_number": 132}))
        elif entry.ip_protocol is not None:
            out.append(("ip_service", f"ip{entry.ip_protocol}", {"protocol_number": entry.ip_protocol}))
        return out

    @staticmethod
    def _entry_families(entry: ServiceEntry) -> Set[int]:
        if entry.protocol == Protocol.ICMP or (entry.protocol == Protocol.IP and entry.ip_protocol == 1):
            return {4}
        if entry.protocol == Protocol.ICMP6 or (entry.protocol == Protocol.IP and entry.ip_protocol == 58):
            return {6}
        return {4, 6}

    def _define_service(self, name: str, entries: List[ServiceEntry], comment: str = "") -> Tuple[Optional[Json], str]:
        """The element for a service: one service element, or several and a group. (None, why) when it cannot be one."""
        pieces: List[Tuple[str, str, Json]] = []
        for entry in entries:
            found = self._pieces(entry)
            if not found:
                if entry.protocol == Protocol.SCTP:
                    return None, "SCTP ports cannot be written (an SMC matches SCTP as an IP protocol only)"
                if entry.protocol == Protocol.IP:
                    return None, "a service that matches every IP protocol cannot be an element"
                return None, "a service of port 0 only"
            pieces += found
        if not pieces:
            return None, "no protocol or port to match"
        if len(pieces) == 1:
            kind, _, fields = pieces[0]
            return self._element(kind, self._comment({"name": name, **fields}, comment)), ""
        members: List[Json] = []
        for kind, label, fields in pieces:
            members.append(self._element(kind, {"name": unique(f"{name} {label}", self.taken, self.names), **fields}))
        return self._element("service_group", self._comment({"name": name, "element": self._refs(members)}, comment)), ""

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for service in self.p.services.values():
            name = service.name
            why = service.unsupported or ("" if service.entries else "unsupported or undefined service")
            element = None
            if not why:
                element, why = self._define_service(name, service.entries, service.description)
            if element is None:
                bad[name] = why
                self._not_created("service", name, why)
                continue
            self.service_ref[name] = [element]
            self.service_family[name] = set().union(*(self._entry_families(e) for e in service.entries))
            if len(service.entries) == 1 and len(self._pieces(service.entries[0])) == 1:
                self.single_service[name] = service.entries[0]
        self.taint_s = transform.tainted_services(self.p, bad)
        for group in transform.topo_groups(self.p.service_groups):
            if group.name in self.taint_s:
                self._not_created("service-group", group.name, self.taint_s[group.name])
                continue
            members = self._refs([element for member in transform.dedupe(group.members) for element in self.service_ref[member]])
            self.service_ref[group.name] = [self._element("service_group", self._comment({"name": group.name, "element": members},
                                                                                         group.description))]  # fmt: skip
            self.service_family[group.name] = set().union(*(self.service_family[m] for m in group.members))

    def _app_service(self, app: str, entries: List[ServiceEntry]) -> Optional[Json]:
        """The element for the ports of an application (of one IP version); None when they cannot be an element."""
        key = (app, repr(entries))
        if key not in self.app_services:
            element, _ = self._define_service(self._new_name(f"app-{app}"), entries, f"well-known ports of application {app}")
            self.app_services[key] = [element] if element is not None else []
        return self.app_services[key][0] if self.app_services[key] else None

    # -- cells ----------------------------------------------------------------------------------

    def _zone(self, zone: str) -> Json:
        if zone not in self.used_zones:
            self.used_zones.append(zone)
        return ref("interface_zone", zone)

    def _side(self, members: List[str], negated: bool, zones: List[str], family: int, label: str) -> Tuple[Cell, bool]:
        """The cell of one side for one IP version; (None, _) when the side matches nothing of it. The flag says whether
        a member was left out because it is not written (the rule is then disabled)."""
        refs: List[Json] = []
        whole = ANY in members
        dropped = False
        for member in members if not whole else []:
            if member in self.taint_a:
                dropped = True
                continue
            found = self._view(member, family)
            if found is None:
                continue
            if "any" in found:
                whole = True
                break
            refs.append(found)
        refs = self._refs(refs)
        if negated:
            if whole:
                return None, dropped
            if refs:
                refs = [self._exclusion(refs, label)]
            whole = not refs
        elif not whole and not refs:
            return None, dropped
        zone_refs = [self._zone(z) for z in zones if z != ANY]
        if not zone_refs:
            return ({"any": True} if whole else {"members": refs}), dropped
        if whole:
            return {"members": zone_refs}, dropped
        rows = [self._row(zone, element) for zone in zone_refs for element in refs]
        return {"members": rows}, dropped

    def _exclusion(self, refs: List[Json], label: str) -> Json:
        key = tuple(sorted(f"{r['@ref']}/{r['name']}" for r in refs))
        if key not in self.expressions:
            if len(refs) == 1:
                body: Json = {"operator": "exclusion", "ne_ref": refs, "sub_expression": []}
                name = self._new_name(f"not {refs[0]['name']}")
            else:
                body = {"operator": "exclusion", "ne_ref": [], "sub_expression": [{"operator": "union", "ne_ref": refs, "sub_expression": []}]}
                name = self._new_name(f"not {label}")
            self.expressions[key] = self._element("expression", {"name": name, **body})
        return self.expressions[key]

    def _row(self, zone: Json, element: Json) -> Json:
        key = (str(zone["name"]), f"{element['@ref']}/{element['name']}")
        if key not in self.rows:
            name = self._new_name(f"{zone['name']} and {element['name']}")
            self.rows[key] = self._element("match_expression", {"name": name, "ref": [zone, element]})
        return self.rows[key]

    @staticmethod
    def _cell(cell: Cell, key: str) -> Json:
        if cell is None:
            return {"none": True}
        if "any" in cell:
            return {"any": True}
        return {key: cell["members"]}

    # -- access rules ---------------------------------------------------------------------------

    def _native_apps(self, rule: Rule) -> bool:
        """Whether the rule matches network applications of an SMC that the SMC reading this has as well."""
        return self.native and rule.applications != [ANY] and rule.services == [ANY]

    def _service_cell(self, rule: Rule, family: int, lowered: Optional[List[Tuple[str, List[ServiceEntry]]]]) -> Tuple[Cell, bool]:
        if self._native_apps(rule):
            for app in rule.applications:
                entry = {"type": "application_situation", "name": app}
                if entry not in self.existing:
                    self.existing.append(entry)
            return {"members": [ref("application_situation", app) for app in rule.applications]}, False
        refs: List[Json] = []
        dropped = False
        if lowered is not None:
            for app, entries in lowered:
                mine = [e for e in entries if family in self._entry_families(e)]
                if not mine:
                    continue  # the application has nothing of this IP version
                element = self._app_service(app, mine)
                if element is None:
                    dropped = True
                else:
                    refs.append(element)
            return ({"members": self._refs(refs)} if refs else None), dropped
        if rule.services == [ANY]:
            return {"any": True}, False
        for service in rule.services:
            if service in self.taint_s or service not in self.service_ref:
                dropped = True
                continue
            if family in self.service_family.get(service, {4, 6}):
                refs += self.service_ref[service]
        return ({"members": self._refs(refs)} if refs else None), dropped

    def _rule(self, rule: Rule, number: int) -> None:
        report = self.report
        item = report.item("rule", rule.origin)
        transform.note_profiles(report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("NEGATED_SERVICE", "a negated service cannot be written: a cell of an SMC has no negation"))
        if self.native and rule.applications != [ANY] and rule.services not in ([ANY],):
            reasons.append(("APP_AND_SERVICE", "network applications and services together: in one cell of an SMC they would be ORed"))
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            fqdn = [m for m in self._reachable(members) if m in self.p.addresses and self.p.addresses[m].kind == AddressKind.FQDN]
            if negated and fqdn:
                reasons.append(("NEGATED_FQDN", f"a negated host name ('{fqdn[0]}'): an expression of an SMC combines addresses"))
        lowered = None if self._native_apps(rule) else transform.lower_applications(rule, self.options.app_ports, report, reasons)
        transform.note_fqdn_families(self.p, rule, report, "an SMC")
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as pairs of zones"))
        elif not pairs:
            report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                        f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing", Severity.INFO)  # fmt: skip
            return
        action = {Action.ALLOW: "allow", Action.DROP: "discard", Action.DENY: "discard"}.get(rule.action, "refuse")
        if action == "refuse" and not (self.native and rule.action == Action.RESET_CLIENT):
            report.add("rule", rule.origin, Severity.APPROX, "REFUSE_ACTION",
                       f"action {rule.action.value} becomes Refuse, which answers the sender with an ICMP error (whether a "
                       "TCP connection gets a reset is not documented)")  # fmt: skip
        entries: List[Tuple[int, Json, Json, Json]] = []
        dropped = False
        for src_zones, dst_zones in pairs or [(rule.src_zones, rule.dst_zones)]:
            for family in (4, 6):
                src, d1 = self._side(rule.sources, rule.negate_source, src_zones, family, f"{rule.name} sources")
                dst, d2 = self._side(rule.destinations, rule.negate_destination, dst_zones, family, f"{rule.name} destinations")
                svc, d3 = self._service_cell(rule, family, lowered)
                dropped = dropped or d1 or d2 or d3
                if src is None or dst is None or svc is None:
                    if reasons or not rule.enabled:
                        entries.append((family, self._cell(src, "src"), self._cell(dst, "dst"), self._cell(svc, "service")))
                    continue
                entries.append((family, self._cell(src, "src"), self._cell(dst, "dst"), self._cell(svc, "service")))
        if dropped and not reasons:
            reasons.append(("UNCONVERTIBLE_OBJECT", "it names an object that is not created"))
        if reasons:
            transform.disable_rule(report, rule, reasons)
        written = [e for e in entries if not any("none" in cell for cell in e[1:])]
        if not written and not reasons and rule.enabled:
            report.skip("rule", rule.origin, "MATCHES_NOTHING", "nothing in this rule can match a packet of an IP version", Severity.INFO)
            return
        # A rule that is written disabled keeps its place, with what can be written of it.
        entries = written or entries[:1] or [(4, {"none": True}, {"none": True}, {"none": True})]
        seen: List[Tuple[int, str]] = []
        for family, src_cell, dst_cell, svc_cell in entries:
            key = (family, json.dumps([src_cell, dst_cell, svc_cell], sort_keys=True))
            if key in seen:
                continue
            seen.append(key)
            body: Json = {"name": rule.name, "is_disabled": bool(reasons) or not rule.enabled, "sources": src_cell,
                          "destinations": dst_cell, "services": svc_cell, "action": {"action": [action]},
                          "options": {"log_level": "stored" if rule.log_start or rule.log_end else "none",
                                      "log_closing_mode": rule.log_end, "log_accounting_info_mode": False}}  # fmt: skip
            text = ("FWSHIFT: disabled by the converter, see the report. " if reasons else "") + rule.description
            self._comment(body, text)
            self._section(LISTS[family], rule)
            self.lists[LISTS[family]].append(body)
            item.emitted_as.append(f"{rule.name} (IPv{family})")
        if len({e for e, *_ in entries}) == 1 and len(entries) == 1:
            item.emitted_as = [rule.name]

    def _reachable(self, members: List[str]) -> List[str]:
        """The members and everything in the groups among them."""
        out: Dict[str, None] = {}
        todo = list(members)
        while todo:
            name = todo.pop()
            if name not in out:
                out[name] = None
                if name in self.p.address_groups:
                    todo += self.p.address_groups[name].members
        return list(out)

    def _section(self, where: str, rule: Rule) -> None:
        """A section of the source above the first of its rules (an SMC source only: its sections are tags)."""
        if not self.native or not rule.tags:
            return
        if self.section.get(where) != rule.tags[0]:
            self.section[where] = rule.tags[0]
            self.lists[where].append({"comment": " ".join(rule.tags[0].split())[:1000]})

    def _defaults(self) -> None:
        """The end of the policy: traffic inside a zone, and between zones, where the source allows it by default."""
        between = self.p.default_interzone == Action.ALLOW
        # A zone's own setting under its name before --zone-map; a zone the map makes of several is open only where the
        # source allows between them as well.
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        added: List[str] = []
        for zone in self.zones:
            inside = decided[zone]
            if inside == between:
                continue
            for family in (4, 6):
                self.lists[LISTS[family]].append({
                    "name": f"FWShift: inside zone {zone}", "is_disabled": False, "sources": {"src": [self._zone(zone)]},
                    "destinations": {"dst": [self._zone(zone)]}, "services": {"any": True},
                    "action": {"action": ["allow" if inside else "discard"]},
                    "options": {"log_level": "none", "log_closing_mode": False, "log_accounting_info_mode": False},
                    "comment": "Added by FWShift: what the source does with traffic inside this zone that no rule decides"})  # fmt: skip
            added.append(f"{zone} ({'allowed' if inside else 'discarded'})")
        if between:
            for family in (4, 6):
                self.lists[LISTS[family]].append({
                    "name": "FWShift: default", "is_disabled": False, "sources": {"any": True}, "destinations": {"any": True},
                    "services": {"any": True}, "action": {"action": ["allow"]},
                    "options": {"log_level": "none", "log_closing_mode": False, "log_accounting_info_mode": False},
                    "comment": "Added by FWShift: the source allows what no rule decides"})  # fmt: skip
            self.report.note(Severity.REVIEW, "DEFAULT_ALLOW_ADDED",
                             "the source allows traffic that no rule decides: the policy ends in a rule 'FWShift: default' "
                             "that allows everything, IPv4 and IPv6, above the rules of its template")  # fmt: skip
        if added:
            self.report.note(Severity.INFO, "INTRAZONE_RULES_ADDED",
                             "rules for traffic inside a zone were added at the end of the policy, as the source decides it "
                             "when no rule does: " + ", ".join(added))  # fmt: skip

    # -- NAT ------------------------------------------------------------------------------------

    def _single(self, member: str) -> Optional[Interval]:
        intervals = transform.address_intervals(self.p, member)
        return intervals[0] if intervals and len(intervals) == 1 else None

    def _nat_families(self, nat: NatRule) -> Set[int]:
        found: Set[int] = {4, 6}
        source, destination = nat.source_translation, nat.destination_translation
        for members in (nat.sources, nat.destinations, source.addresses if source else [], [destination.address] if destination else []):
            known = set().union(*(transform.families(self.p, m) for m in members)) if members and ANY not in members else {4, 6}
            found &= known
        return found

    def _nat_cell(self, members: List[str], family: int, key: str) -> Json:
        if ANY in members:
            return {"any": True}
        refs = [found for found in (self._view(m, family) for m in members) if found is not None]
        if any("any" in found for found in refs):
            return {"any": True}
        return {key: self._refs(refs)} if refs else {"none": True}

    def _value(self, member: str, family: int) -> Json:
        """A translated (or original) value: the element, or the address of a literal."""
        if member in self.address_ref or parse_literal(member) is None:
            found = self._view(member, family)
            return {"element": found if found is not None and "any" not in found else self._member(member)}
        interval = parse_literal(member)
        assert interval is not None
        if interval[1] == interval[2]:
            return {"ip_descriptor": str(int_to_ip(interval[0], interval[1]))}
        return {"element": self._member(member)}

    def _nat(self, nat: NatRule) -> None:
        report = self.report
        source, destination = nat.source_translation, nat.destination_translation
        members = nat.sources + nat.destinations + (source.addresses if source else []) + ([destination.address] if destination else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in transform.dedupe(members) if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        families = sorted(self._nat_families(nat))
        if families == [4, 6] and source is not None and source.kind == SnatKind.INTERFACE and destination is None:
            # Which IP version the source hid behind its interface address cannot be told; an SMC hides IPv4.
            families = [4]
            report.add("nat", nat.origin, Severity.APPROX, "NAT_IPV4_ONLY",
                       "source NAT to the address of the outgoing interface, for addresses of both IP versions: written for "
                       "IPv4 only; IPv6 traffic leaves with its own address")  # fmt: skip
        if not families and not problems:
            problems.append("its addresses are of different IP versions")
        if len(families) > 1 and (destination is not None or source is not None) and not problems:
            problems.append("a translation for addresses of both IP versions: an SMC has a NAT rule list for each, and the "
                            "translated addresses of each version are not told apart here")
        findings: List[Tuple[Severity, str, str]] = []
        options: Json = {}
        family = families[0] if families else 4
        if destination is not None and not problems:
            if destination.spread:
                problems.append("a destination translated to several addresses, one picked per connection")
            elif len([m for m in nat.destinations if m != ANY]) != 1:
                problems.append("a destination translation needs one destination element, which is the original value")
            else:
                inside, outside = self._single(nat.destinations[0]), self._single(destination.address)
                if inside is None or outside is None or size(inside) != size(outside):
                    problems.append("a destination translation needs one destination and one translated element of the same size")
            port = destination.port
            service = self.single_service.get(nat.service)
            original: Json = {}
            translated: Json = {}
            if port and not problems:
                if service is None or service.protocol not in (Protocol.TCP, Protocol.UDP) or not service.dst_ports or service.src_ports:
                    problems.append("a port translation needs a service of one TCP or UDP port or range on the rule")
                else:
                    low, _, high = service.dst_ports.partition("-")
                    new_low, _, new_high = port.partition("-")
                    count, new_count = int(high or low) - int(low), int(new_high or new_low) - int(new_low)
                    if "," in service.dst_ports or "," in port or count != new_count:
                        problems.append(f"ports {service.dst_ports} translated to {port}: an SMC translates a range to a range of the same size")
                    else:
                        original = {"min_port": low, "max_port": high or low}
                        translated = {"min_port": new_low, "max_port": new_high or new_low}
            if not problems:
                options["static_dst_nat"] = {"automatic_proxy": True,
                                             "original_value": {**self._value(nat.destinations[0], family), **original},
                                             "translated_value": {**self._value(destination.address, family), **translated}}  # fmt: skip
        if source is not None and not problems:
            kind = source.kind
            if kind == SnatKind.STATIC:
                inside = self._single(nat.sources[0]) if len(nat.sources) == 1 and nat.sources != [ANY] else None
                outside = self._single(source.addresses[0]) if len(source.addresses) == 1 else None
                if inside is None or outside is None or size(inside) != size(outside):
                    problems.append("static source NAT needs one source and one translated element of the same size")
                else:
                    options["static_src_nat"] = {"automatic_proxy": True, "original_value": self._value(nat.sources[0], family),
                                                 "translated_value": self._value(source.addresses[0], family)}  # fmt: skip
            elif kind in (SnatKind.DYNAMIC_PORT, SnatKind.DYNAMIC):
                values = [{**self._value(member, family), "min_port": 1024, "max_port": 65535} for member in source.addresses]
                if not values:
                    problems.append("source NAT to no address")
                else:
                    options["dynamic_src_nat"] = {"automatic_proxy": True, "translation_values": values}
                    if kind == SnatKind.DYNAMIC:
                        findings.append((Severity.APPROX, "NAT_PORTS",
                                         "dynamic NAT without port translation is written as dynamic NAT of an SMC, which "
                                         "translates ports as well"))  # fmt: skip
            else:
                match = _INTERFACE_ALIAS.fullmatch(source.interface) if self.native else None
                alias = ("interface_nic_x_ip_alias", f"$$ Interface ID {match.group(1)}.ip") if match else _DEFAULT_NAT
                entry = {"type": alias[0], "name": alias[1]}
                if entry not in self.existing:
                    self.existing.append(entry)
                options["dynamic_src_nat"] = {"automatic_proxy": True, "translation_values": [
                    {"element": ref(*alias), "min_port": 1024, "max_port": 65535}]}  # fmt: skip
                if not match:
                    findings.append((Severity.APPROX, "NAT_INTERFACE_ALIAS",
                                     "source NAT to the address of the outgoing interface is written as NAT to the alias "
                                     "'$$ Default NAT Address' of the engine: check that the default NAT address is the one "
                                     "the traffic should leave with"))  # fmt: skip
            if source.bidirectional and kind == SnatKind.STATIC and not problems:
                findings.append((Severity.INFO, "NAT_BIDIRECTIONAL", "bi-directional static NAT written as two NAT rules, one for each direction"))
        if problems:
            report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
            return
        for zones, what in ((nat.src_zones, "from"), (nat.dst_zones, "to")):
            if zones != [ANY]:
                unlimited = ANY in (nat.sources if what == "from" else nat.destinations)
                findings.append((Severity.REVIEW if unlimited else Severity.APPROX, "NAT_ZONES",
                                 f"the rule applied to traffic {what} {', '.join(zones)} only; a NAT rule of an SMC names "
                                 "no zone, and it is written without"))  # fmt: skip
        for severity, code, message in findings:
            report.add("nat", nat.origin, severity, code, message)
        services: Json = {"any": True}
        if nat.service != ANY:
            services = {"service": self.service_ref[nat.service]}
        item = report.item("nat", nat.origin)
        for one in families:
            body: Json = {"name": nat.name, "is_disabled": not nat.enabled, "used_on": {"any": True},
                          "sources": self._nat_cell(nat.sources, one, "src"), "destinations": self._nat_cell(nat.destinations, one, "dst"),
                          "services": services, "options": {"log_level": "undefined", **copy.deepcopy(options)}}  # fmt: skip
            self._comment(body, nat.description)
            self.lists[NAT_LISTS[one]].append(body)
            item.emitted_as.append(f"{nat.name} (IPv{one})" if len(families) > 1 else nat.name)
            self.nat_written += 1
            if source is not None and source.bidirectional and "static_src_nat" in options:
                back = dict(body, name=nat.name + " (inbound)", sources={"any": True}, services={"any": True},
                            destinations={"dst": [self._value(source.addresses[0], one).get("element") or self._member(source.addresses[0])]},
                            options={"log_level": "undefined", "static_dst_nat": {"automatic_proxy": True,
                                     "original_value": options["static_src_nat"]["translated_value"],
                                     "translated_value": options["static_src_nat"]["original_value"]}})  # fmt: skip
                self.lists[NAT_LISTS[one]].append(back)

    # -- output ---------------------------------------------------------------------------------

    def run(self) -> str:
        self._addresses()
        self._services()
        for number, rule in enumerate(self.p.rules, 1):
            self._rule(rule, number)
        self._defaults()
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "first-match")
        self._notes()
        zones = [z for z in self.used_zones]
        plan = {
            "format": 1, "generator": f"FWShift {__version__}", "policy": self.options.target_policy,
            "template": self.options.target_template,
            "comment": "Converted by FWShift" + (f" from {self.p.vendor}" if self.p.vendor else ""),
            "zones": zones, "existing": self.existing,
            "elements": [e for e in self.elements if not (e["type"] == "interface_zone")],
            "rules": {key: self.lists[key] for key in LISTS.values()},
            "nat": {key: self.lists[key] for key in NAT_LISTS.values()},
        }  # fmt: skip
        data = json.dumps(plan, indent=1, ensure_ascii=True)
        tail = ["", "# The policy, as data. Do not change it here: convert again.", "#"]
        return loader_source().rstrip("\n") + "\n" + "\n".join(tail + ["#: " + line for line in data.split("\n")]) + "\n"

    def _notes(self) -> None:
        note = self.report.note
        note(Severity.REVIEW, "SMC_LOADER",
             "the output is a Python program that loads the policy into a Security Management Center through its REST API "
             f"(python3 FILE --help). It creates the elements and a new firewall policy '{self.options.target_policy}' on "
             f"template '{self.options.target_template}', checks first that every name is free, and uploads the policy to "
             "no engine: review it in the Management Client, then install it yourself. --undo deletes what a run created")  # fmt: skip
        note(Severity.REVIEW, "TEMPLATE_RULES",
             f"the rules are written at the insert point of template '{self.options.target_template}': its rules above the "
             "insert point (the traffic of the engine with the SMC) come first, and its rules below come after the rules "
             "of the policy (the predefined templates refuse Ident and discard and log the rest)")  # fmt: skip
        if self.used_zones:
            note(Severity.REVIEW, "ZONES_REQUIRED",
                 "the rules use these zones, which must be set on the interfaces of the engine (or renamed with --zone-map); "
                 "a zone the SMC does not have is created without interfaces: " + ", ".join(self.used_zones))  # fmt: skip
        if self.rows:
            note(Severity.INFO, "MATCH_EXPRESSIONS",
                 "rules that limit a side by zones and addresses name a match expression per zone and address element "
                 f"(its parts must all match): {len(self.rows)} were written")  # fmt: skip
        if self.domains:
            note(Severity.INFO, "DOMAIN_NAMES",
                 "host names are written as domain name elements; the engine resolves them only with DNS servers in its "
                 "properties: " + ", ".join(sorted(self.domains)))  # fmt: skip
        if self.nat_written:
            note(Severity.REVIEW, "SMC_NAT",
                 "NAT rules are written in order to the policy, used on every engine. Element-based NAT and the default NAT "
                 "of an engine apply after them, to what they do not translate: check those on the engines")  # fmt: skip
        if not self.native and not self.prefix:
            note(Severity.INFO, "NAME_COLLISIONS",
                 "an SMC predefines many elements (HTTPS, SSH, ...). An element of the same name that says the same is used "
                 "by the loader; one that says something else stops it: convert again with --target-prefix")  # fmt: skip
        if self.prefix:
            note(Severity.INFO, "OBJECT_PREFIX", f"every element the script creates is named with the prefix '{self.prefix}'")
        tagged = any(holder.tags for holder in list(self.p.rules) + list(self.p.nat_rules) + list(self.p.addresses.values()))
        if tagged and not self.native:
            note(Severity.INFO, "TAGS_NOT_CONVERTED", "tags of rules and objects are not converted")
