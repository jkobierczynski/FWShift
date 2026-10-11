# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAN-OS emitter: neutral model -> configuration-mode ``set`` commands.

The output holds nothing but ``set`` lines, so it can be pasted into a
configuration-mode CLI session. Everything a person has to know is in the
conversion report instead.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .. import transform
from ..appmap import IP_PROTOCOL_APPS
from ..errors import FwshiftError
from ..model import (
    ANY,
    APP_DEFAULT,
    L4_PROTOCOLS,
    Action,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    ServiceEntry,
    SnatKind,
)
from ..names import PANOS, unique
from ..netutil import is_number, parse_literal
from ..options import Options
from ..report import Report, Severity

_PLACEHOLDER = "FWSHIFT PLACEHOLDER, matches nothing: "
_BARE = re.compile(r"[A-Za-z0-9._/:,-]+")
_ADDRESS_KEYS = {AddressKind.NETWORK: "ip-netmask", AddressKind.RANGE: "ip-range", AddressKind.FQDN: "fqdn"}
# Names PAN-OS predefines or reserves; objects from another platform carrying one are renamed.
_RESERVED_ADDRESSES: FrozenSet[str] = frozenset({ANY})
_RESERVED_SERVICES: FrozenSet[str] = frozenset({ANY, APP_DEFAULT, "service-http", "service-https"})


def q(text: str) -> str:
    if _BARE.fullmatch(text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def lst(items: List[str]) -> str:
    if len(items) == 1:
        return q(items[0])
    return "[ " + " ".join(q(item) for item in items) + " ]"


def _clip(text: str, limit: int = 1023) -> str:
    return q(" ".join(text.split())[:limit])


def _scope(target_scope: str) -> Tuple[str, str]:
    """(prefix of every command, name of the rulebase) for a target scope."""
    if not target_scope:
        return "", "rulebase"
    if target_scope == "shared":
        return "shared ", "pre-rulebase"
    kind, _, name = target_scope.partition(":")
    if kind == "vsys" and name:
        return f"vsys {q(name)} ", "rulebase"
    if kind == "device-group" and name:
        return f"device-group {q(name)} ", "pre-rulebase"
    raise FwshiftError(f"invalid PAN-OS target scope '{target_scope}'")


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    foreign = p.vendor != "panos"
    transform.sanitize_names(
        p,
        PANOS,
        PANOS,
        report,
        reserved_addresses=_RESERVED_ADDRESSES if foreign else frozenset(),
        reserved_services=_RESERVED_SERVICES if foreign else frozenset(),
    )
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: Set[str]) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones = source_zones  # zone and interface names of the rules before --zone-map
        self.prefix, self.rulebase = _scope(options.target_scope)
        self.keep_dynamic = p.vendor == "panos"
        self.taint_a = transform.tainted_addresses(p, keep_dynamic=self.keep_dynamic)
        self.taint_s: Dict[str, str] = {}
        self.lines: List[str] = []
        self.address_names: Set[str] = set(p.addresses) | set(p.address_groups)
        self.service_names: Set[str] = set(p.services) | set(p.service_groups)
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.literals: Dict[str, str] = {}
        # Per neutral service or group: the PAN-OS object carrying its TCP/UDP/SCTP
        # part (None if it has none) and the App-IDs standing for its ICMP/IP part.
        self.l4: Dict[str, Optional[str]] = {}
        self.apps: Dict[str, List[str]] = {}
        self.approx: Dict[str, str] = {}

    def cmd(self, text: str) -> None:
        self.lines.append(f"set {self.prefix}{text}")

    def run(self) -> str:
        self._tags()
        self._addresses()
        self._services()
        for rule in self.p.rules:
            self._rule(rule)
        self._intrazone_tail()
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "first-match")
        self._notes()
        return "\n".join(self.lines) + "\n"

    def _notes(self) -> None:
        if self.p.vendor != "panos":
            zones = transform.dedupe(
                [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
                + self._intrazone_allow_zones()
            )
            if zones:
                self.report.note(
                    Severity.REVIEW,
                    "ZONES_REQUIRED",
                    "the rules name these zones, which must exist on the target (or be renamed with "
                    "--zone-map): " + ", ".join(zones),
                )
        if self.p.default_interzone == Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTERZONE_DEFAULT",
                "the source allows traffic between zones that no rule matches; PAN-OS denies it unless "
                "interzone-default is overridden. That default is not carried over: add a final allow rule if it "
                "was intended",
            )

    # -- objects ----------------------------------------------------------

    def _tags(self) -> None:
        tags: List[str] = []
        for holder in (
            list(self.p.addresses.values())
            + list(self.p.address_groups.values())
            + list(self.p.services.values())
            + list(self.p.service_groups.values())
            + list(self.p.rules)
            + list(self.p.nat_rules)
        ):
            tags += holder.tags
        for tag in transform.dedupe(tags):
            self.cmd(f"tag {q(tag)}")

    def _describe(self, base: str, description: str, tags: List[str]) -> None:
        if description:
            self.cmd(f"{base} description {_clip(description)}")
        if tags:
            self.cmd(f"{base} tag {lst(tags)}")

    def _placeholder_address(self, name: str, reason: str) -> None:
        base = f"address {q(name)}"
        self.cmd(f"{base} ip-netmask 0.0.0.0/32")
        self.cmd(f"{base} description {_clip(_PLACEHOLDER + reason)}")

    def _addresses(self) -> None:
        for address in self.p.addresses.values():
            if address.kind == AddressKind.UNSUPPORTED:
                self._placeholder_address(address.name, address.raw)
                continue
            base = f"address {q(address.name)}"
            self.cmd(f"{base} {_ADDRESS_KEYS[address.kind]} {q(address.value)}")
            self._describe(base, address.description, address.tags)
        for group in transform.topo_groups(self.p.address_groups):
            if transform.is_placeholder_group(group, self.keep_dynamic):
                self._placeholder_address(group.name, self.taint_a.get(group.name, "unconvertible group"))
                continue
            base = f"address-group {q(group.name)}"
            if group.dynamic_filter:
                escaped = group.dynamic_filter.replace("\\", "\\\\").replace('"', '\\"')
                self.cmd(f'{base} dynamic filter "{escaped}"')
            else:
                self.cmd(f"{base} static {lst([self._member(m) for m in group.members])}")
            self._describe(base, group.description, group.tags)

    def _member(self, member: str) -> str:
        """Address-group members must be objects: wrap a literal in one."""
        if member in self.p.addresses or member in self.p.address_groups:
            return member
        interval = parse_literal(member)
        if interval is None:
            return member
        if member not in self.literals:
            if "-" in member and "/" not in member:
                label, key = f"r-{member}", "ip-range"
            else:
                net = ipaddress.ip_network(member.strip(), strict=False)
                host = interval[1] == interval[2]
                label = f"h-{net.network_address}" if host else f"n-{net.network_address}_{net.prefixlen}"
                key = "ip-netmask"
            name = unique(label, self.address_names, PANOS)
            self.cmd(f"address {q(name)} {key} {q(member)}")
            self.literals[member] = name
        return self.literals[member]

    # -- services ---------------------------------------------------------

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for service in self.p.services.values():
            name = service.name
            if service.builtin == "panos":
                self.l4[name], self.apps[name] = name, []
                continue
            if not service.entries or service.unsupported:
                reason = service.unsupported or "unsupported or undefined service"
                self.cmd(f"service {q(name)} protocol tcp port 1")
                self.cmd(f"service {q(name)} description {_clip(_PLACEHOLDER + reason)}")
                self.l4[name], self.apps[name] = name, []
                continue
            # A PAN-OS service holds one protocol with one source-port list.
            parts: Dict[Tuple[str, str], List[str]] = {}
            apps: List[str] = []
            for entry in service.entries:
                if entry.protocol in L4_PROTOCOLS:
                    parts.setdefault((entry.protocol.value, entry.src_ports), []).append(entry.dst_ports or "1-65535")
                    continue
                mapped = self._entry_apps(name, entry)
                if mapped is None:
                    bad[name] = "IP protocol without a known App-ID"
                else:
                    apps += [a for a in mapped if a not in apps]
            self.apps[name] = apps
            if not parts:
                self.l4[name] = None
                continue
            self.l4[name] = name
            if len(parts) == 1:
                (proto, src), ports = next(iter(parts.items()))
                self._service(name, proto, src, ports, service.description, service.tags)
                continue
            members: List[str] = []
            for (proto, src), ports in parts.items():
                member = unique(f"{name}-{proto}", self.service_names, PANOS)
                self._service(member, proto, src, ports, service.description, service.tags)
                members.append(member)
            self.cmd(f"service-group {q(name)} members {lst(members)}")
        self.taint_s = transform.tainted_services(self.p, bad)
        for group in transform.topo_groups(self.p.service_groups):
            members = [m for m in (self.l4.get(member) for member in group.members) if m]
            apps = []
            for member in group.members:
                apps += [a for a in self.apps.get(member, []) if a not in apps]
            self.apps[group.name] = apps
            self.l4[group.name] = group.name if members else None
            inexact = [self.approx[member] for member in group.members if member in self.approx]
            if inexact:
                self.approx[group.name] = inexact[0]
            if members:
                self.cmd(f"service-group {q(group.name)} members {lst(members)}")
                if group.tags:
                    self.cmd(f"service-group {q(group.name)} tag {lst(group.tags)}")

    def _service(self, name: str, proto: str, src: str, ports: List[str], description: str, tags: List[str]) -> None:
        base = f"service {q(name)}"
        self.cmd(f"{base} protocol {proto} port {','.join(ports)}")
        if src:
            self.cmd(f"{base} protocol {proto} source-port {src}")
        self._describe(base, description, tags)

    def _entry_apps(self, service: str, entry: ServiceEntry) -> Optional[List[str]]:
        """App-IDs standing for an ICMP or IP-protocol service entry; None if there is none."""
        if entry.protocol == Protocol.IP:
            app = IP_PROTOCOL_APPS.get(entry.ip_protocol or 0)
            return [app] if app else None
        echo, generic = ("ping", "icmp") if entry.protocol == Protocol.ICMP else ("ping6", "ipv6-icmp")
        echo_type = 8 if entry.protocol == Protocol.ICMP else 128
        if entry.icmp_type == echo_type:
            return [echo]
        if entry.icmp_type is None:
            return [generic, echo]
        self.approx[service] = (
            f"service '{service}' matches ICMP type {entry.icmp_type}; App-ID '{generic}' matches every type"
        )
        return [generic]

    # -- security rules ---------------------------------------------------

    def _variants(self, rule: Rule, reasons: List[transform.Reason]) -> List[Tuple[List[str], List[str]]]:
        """(applications, services) combinations the rule needs on PAN-OS."""
        if rule.services in ([ANY], [APP_DEFAULT]):
            return [(rule.applications, rule.services)]
        l4: List[str] = []
        apps: List[str] = []
        for service in rule.services:
            name = self.l4.get(service)
            if name and name not in l4:
                l4.append(name)
            apps += [a for a in self.apps.get(service, []) if a not in apps]
            if service in self.approx:
                self.report.add("rule", rule.origin, Severity.APPROX, "ICMP_TYPE", self.approx[service])
        if rule.applications != [ANY]:
            return [(rule.applications, l4 or [APP_DEFAULT])]
        out: List[Tuple[List[str], List[str]]] = []
        if l4:
            out.append(([ANY], l4))
        if apps:
            out.append((apps, [APP_DEFAULT]))
            self.report.add(
                "rule",
                rule.origin,
                Severity.APPROX,
                "PROTOCOL_AS_APP",
                "ICMP and IP-protocol services are matched as App-IDs on PAN-OS: "
                + ", ".join(apps)
                + ". Verify these names against the App-ID release in use",
            )
        if not out:
            if not reasons:
                reasons.append(("NO_SERVICE", "none of the services could be converted"))
            out.append(([ANY], [ANY]))
        return out

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        if self.p.vendor == "panos" and rule.profiles:
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "PROFILES_BY_NAME",
                "security profiles are referenced by name and must exist on the target: "
                + ", ".join(sorted(rule.profiles.values())),
            )
        else:
            transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service match does not exist on PAN-OS"))
        transform.note_fqdn_families(self.p, rule, self.report, "PAN-OS")
        variants = self._variants(rule, reasons)
        if len(variants) > 1:
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "RULE_SPLIT",
                "written as two rules, one for the port-based services and one for the application-based ones",
            )
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        for index, (apps, services) in enumerate(variants):
            name = unique(rule.name if index == 0 else f"{rule.name[:58]}-apps", self.rule_names, PANOS)
            item.emitted_as.append(name)
            self._emit_rule(rule, name, apps, services, disabled=bool(reasons) or not rule.enabled, flagged=bool(reasons))

    def _emit_rule(
        self, rule: Rule, name: str, apps: List[str], services: List[str], disabled: bool, flagged: bool
    ) -> None:
        base = f"{self.rulebase} security rules {q(name)}"
        if rule.scope != RuleScope.UNIVERSAL:
            self.cmd(f"{base} rule-type {rule.scope.value}")
        self.cmd(f"{base} from {lst(rule.src_zones)}")
        self.cmd(f"{base} to {lst(rule.src_zones if rule.scope == RuleScope.INTRAZONE else rule.dst_zones)}")
        self.cmd(f"{base} source {lst(rule.sources)}")
        self.cmd(f"{base} destination {lst(rule.destinations)}")
        self.cmd(f"{base} source-user {lst(rule.users)}")
        self.cmd(f"{base} category {lst(rule.url_categories)}")
        self.cmd(f"{base} application {lst(apps)}")
        self.cmd(f"{base} service {lst(services)}")
        self.cmd(f"{base} action {rule.action.value}")
        if rule.negate_source:
            self.cmd(f"{base} negate-source yes")
        if rule.negate_destination:
            self.cmd(f"{base} negate-destination yes")
        if rule.log_start:
            self.cmd(f"{base} log-start yes")
        self.cmd(f"{base} log-end {'yes' if rule.log_end else 'no'}")
        if disabled:
            self.cmd(f"{base} disabled yes")
        if self.p.vendor == "panos":
            for kind, names in rule.profiles.items():
                where = "group" if kind == "group" else f"profiles {kind}"
                self.cmd(f"{base} profile-setting {where} {lst(names.split(', '))}")
        description = ("FWSHIFT: disabled by the converter, see the report. " if flagged else "") + rule.description
        self._describe(base, description.strip(), rule.tags)

    def _intrazone_allow_zones(self) -> List[str]:
        return transform.intrazone_allow_zones(self.p, self.options.zone_map, self.source_zones, self.report)

    def _intrazone_tail(self) -> None:
        """Reproduce an implicit intrazone deny, which PAN-OS does not have by default."""
        if self.p.default_intrazone == Action.ALLOW or not self.p.rules:
            return
        names: List[str] = []
        allow = self._intrazone_allow_zones()
        if allow:
            permit = Rule(
                name="fwshift-intrazone-allow",
                src_zones=allow,
                dst_zones=allow,
                scope=RuleScope.INTRAZONE,
                log_end=False,
                description="Added by FWShift: these zones allow traffic between their own interfaces on the source.",
            )
            names.append(unique(permit.name, self.rule_names, PANOS))
            self._emit_rule(permit, names[-1], [ANY], [ANY], disabled=False, flagged=False)
        tail = Rule(
            name="fwshift-intrazone-deny",
            action=Action.DENY,
            scope=RuleScope.INTRAZONE,
            description="Added by FWShift: the source platform denies traffic inside a zone unless a rule allows it.",
        )
        names.append(unique(tail.name, self.rule_names, PANOS))
        self._emit_rule(tail, names[-1], [ANY], [ANY], disabled=False, flagged=False)
        self.report.note(
            Severity.INFO,
            "INTRAZONE_DENY_ADDED",
            "appended " + " and ".join(f"'{n}'" for n in names) + ": PAN-OS allows traffic inside a zone by "
            "default, the source denies it" + (" except in zones set to allow it" if allow else ""),
        )

    # -- NAT --------------------------------------------------------------

    def _nat(self, nat: NatRule) -> None:
        item = self.report.item("nat", nat.origin)
        source, destination = nat.source_translation, nat.destination_translation
        members = nat.sources + nat.destinations
        if source:
            members = members + source.addresses
        if destination:
            members = members + [destination.address]
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        if nat.service != ANY and not self.l4.get(nat.service):
            problems.append(f"service '{nat.service}' has no TCP/UDP definition")
        if destination and destination.port and not is_number(destination.port):
            problems.append(f"translated port '{destination.port}' is not a single port")
        translation: List[str] = []
        if source is not None and not problems:
            kind = source.kind
            if kind == SnatKind.INTERFACE:
                default = source.interface if self.p.vendor == "panos" else ""
                interface = self.options.interface_map.get(source.interface, default)
                dipp = "source-translation dynamic-ip-and-port"
                if interface:
                    translation.append(f"{dipp} interface-address interface {q(interface)}")
                    if source.addresses:
                        translation.append(f"{dipp} interface-address ip {q(source.addresses[0])}")
                elif source.addresses:
                    translation.append(f"{dipp} translated-address {q(source.addresses[0].split('/')[0])}")
                elif source.interface_address:
                    address = source.interface_address
                    translation.append(f"{dipp} translated-address {q(address)}")
                    self.report.add(
                        "nat",
                        nat.origin,
                        Severity.APPROX,
                        "NAT_INTERFACE_ADDRESS",
                        f"translates to {address}, the address interface '{source.interface}' has today; use "
                        f"--interface-map {source.interface}=<PAN-OS interface> to follow the interface instead",
                    )
                elif source.interface:
                    problems.append(
                        f"source NAT to the address of {source.interface}, which is unknown; map it with --interface-map"
                    )
                else:
                    problems.append(
                        "source NAT to the address of the outgoing interface, which the source does not name: "
                        "write this rule by hand"
                    )
            elif kind == SnatKind.STATIC:
                translation.append(f"source-translation static-ip translated-address {q(source.addresses[0])}")
                if source.bidirectional:
                    translation.append("source-translation static-ip bi-directional yes")
            else:
                translation.append(f"source-translation {kind.value} translated-address {lst(source.addresses)}")
        dst_zones = nat.dst_zones
        if dst_zones == [ANY] and not problems:
            if self.options.nat_zone:
                dst_zones = [self.options.nat_zone]
                self.report.add(
                    "nat",
                    nat.origin,
                    Severity.APPROX,
                    "NAT_ZONE_ASSUMED",
                    f"the source rule names no destination zone and PAN-OS needs one: '{dst_zones[0]}' "
                    "(--target-nat-zone) was used; check that the pre-NAT destination of this rule lies there",
                )
            else:
                problems.append(
                    "a PAN-OS NAT rule needs a destination zone and the source rule names none; give the zone "
                    "the traffic is routed to before translation with --target-nat-zone"
                )
        if problems:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
            return
        if destination is not None:
            translation.append(f"destination-translation translated-address {q(destination.address)}")
            if destination.port:
                translation.append(f"destination-translation translated-port {destination.port}")
        if len(dst_zones) > 1:
            self.report.add(
                "nat",
                nat.origin,
                Severity.INFO,
                "RULE_SPLIT",
                f"written as {len(dst_zones)} rules: a PAN-OS NAT rule has one destination zone",
            )
        service = ANY if nat.service == ANY else (self.l4.get(nat.service) or nat.service)
        for zone in dst_zones:
            name = unique(nat.name, self.nat_names, PANOS)
            item.emitted_as.append(name)
            base = f"{self.rulebase} nat rules {q(name)}"
            self.cmd(f"{base} from {lst(nat.src_zones)}")
            self.cmd(f"{base} to {q(zone)}")
            self.cmd(f"{base} source {lst(nat.sources)}")
            self.cmd(f"{base} destination {lst(nat.destinations)}")
            self.cmd(f"{base} service {q(service)}")
            for line in translation:
                self.cmd(f"{base} {line}")
            if not nat.enabled:
                self.cmd(f"{base} disabled yes")
            self._describe(base, nat.description, nat.tags)
