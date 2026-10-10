# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""FortiOS emitter: neutral model -> FortiGate CLI configuration.

Design rules:

* Nothing is ever widened silently. A rule whose match cannot be expressed is
  emitted with ``set status disable`` and reported.
* NAT is emitted as central NAT (``central-snat-map`` plus virtual IPs), because
  that is the FortiOS model that maps one-to-one onto a separate NAT rulebase.
* FortiOS matches IPv4 and IPv6 in separate fields of a policy; every address
  list of a rule is split by IP version.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .. import transform
from ..appmap import FORTIOS_FACTORY_SERVICE_NAMES, entries_for
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
    ServiceEntry,
    SnatKind,
)
from ..names import FORTIOS, FORTIOS_POLICY, unique
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, parse_literal, range_text, size
from ..options import Options
from ..report import Report, Severity

_PLACEHOLDER = "FWSHIFT PLACEHOLDER, matches nothing: "
_PORT_KEYS = {Protocol.TCP: "tcp-portrange", Protocol.UDP: "udp-portrange", Protocol.SCTP: "sctp-portrange"}
# Names FortiOS predefines. An object from another platform that carries one is
# renamed, so that it neither redefines the predefined object nor passes for it.
_RESERVED_ADDRESSES: FrozenSet[str] = frozenset({"all", "none"})
_RESERVED_SERVICES: FrozenSet[str] = FORTIOS_FACTORY_SERVICE_NAMES

Problem = Tuple[str, str, Severity]


def q(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ql(items: List[str]) -> str:
    return " ".join(q(item) for item in items)


def _comment(text: str, limit: int) -> str:
    return q(" ".join(text.split())[:limit])


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    foreign = p.vendor != "fortios"
    transform.sanitize_names(
        p,
        FORTIOS,
        FORTIOS_POLICY,
        report,
        reserved_addresses=_RESERVED_ADDRESSES if foreign else frozenset(),
        reserved_services=_RESERVED_SERVICES if foreign else frozenset(),
    )
    # Central NAT matches the post-NAT address. Rewrite the rules only for the
    # translations that will really be emitted.
    taint_a, taint_s = transform.tainted_addresses(p), transform.tainted_services(p)
    emitted = {
        nat.origin
        for nat in p.nat_rules
        if nat_problem(p, nat, taint_a, taint_s) is None
        and (nat.destination_translation is not None or _reverse_pair(p, nat) is not None)
    }
    transform.rewrite_destinations(p, report, to_post_nat=True, only=emitted)
    return _Emitter(p, report, options).run()


# -- what can be expressed (no side effects) --------------------------------


def _port_forward(p: Policy, nat: NatRule) -> Optional[ServiceEntry]:
    """The single protocol/port a NAT rule matches, if it can become a port-forwarding virtual IP."""
    if nat.service == ANY:
        return None
    entries = transform.flatten_services(p, nat.service)
    if entries is None or len(entries) != 1:
        return None
    entry = entries[0]
    if entry.protocol not in L4_PROTOCOLS or not entry.dst_ports or "," in entry.dst_ports or entry.src_ports:
        return None
    return entry


def _reverse_pair(p: Policy, nat: NatRule) -> Optional[Tuple[Interval, Interval]]:
    """(inside, outside) address of a bi-directional static NAT whose inbound half can be a virtual IP."""
    translation = nat.source_translation
    if translation is None or translation.kind != SnatKind.STATIC or not translation.bidirectional:
        return None
    if len(nat.sources) != 1 or len(translation.addresses) != 1:
        return None
    inside = transform.address_intervals(p, nat.sources[0])
    outside = transform.address_intervals(p, translation.addresses[0])
    if not inside or not outside or len(inside) != 1 or len(outside) != 1:
        return None
    if inside[0][0] != 4 or outside[0][0] != 4 or size(inside[0]) != size(outside[0]) or inside[0] == FULL_V4:
        return None
    return inside[0], outside[0]


def _pool_member(nat: NatRule, member: str, p: Policy) -> str:
    translation = nat.source_translation
    if translation is not None and translation.kind == SnatKind.INTERFACE and member not in p.addresses:
        return member.split("/")[0]  # PAN-OS writes an interface address with its mask
    return member


def nat_problem(p: Policy, nat: NatRule, taint_a: Dict[str, str], taint_s: Dict[str, str]) -> Optional[Problem]:
    """Why a NAT rule cannot be written as central NAT, or None when it can."""
    source, destination = nat.source_translation, nat.destination_translation
    members = nat.sources + nat.destinations
    if source:
        members = members + source.addresses
    if destination:
        members = members + [destination.address]
    problems = list(nat.unsupported)
    problems += [f"references '{m}': {taint_a[m]}" for m in members if m in taint_a]
    if nat.service in taint_s:
        problems.append(f"references '{nat.service}': {taint_s[nat.service]}")
    if problems:
        return "NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems), Severity.REVIEW
    if destination is not None:
        if not nat.enabled:
            return "NAT_DISABLED", "disabled in the source; virtual IP not created", Severity.INFO
        external = transform.address_intervals(p, nat.destinations[0]) if len(nat.destinations) == 1 else None
        mapped = transform.address_intervals(p, destination.address)
        if (
            not external
            or not mapped
            or len(external) != 1
            or len(mapped) != 1
            or external[0][0] != 4
            or mapped[0][0] != 4
            or external[0] == FULL_V4
        ):
            return (
                "NAT_DESTINATION",
                "destination NAT needs exactly one IPv4 address or range on each side to become a virtual IP",
                Severity.REVIEW,
            )
        if size(external[0]) != size(mapped[0]):
            return (
                "NAT_DESTINATION_SIZE",
                f"{size(external[0])} external addresses map to {size(mapped[0])}; not expressible as a virtual IP",
                Severity.REVIEW,
            )
        if destination.port and _port_forward(p, nat) is None:
            return (
                "NAT_PORT",
                "port translation needs a service with a single protocol and one port or port range",
                Severity.REVIEW,
            )
    if source is not None or destination is None:
        sides = [nat.sources] + ([nat.destinations] if destination is None else [])
        if not all(any(4 in transform.families(p, m) for m in side) for side in sides):
            return "NAT_IPV6", "only IPv4 NAT is converted", Severity.REVIEW
    if source is not None:
        for member in source.addresses:
            intervals = transform.address_intervals(p, _pool_member(nat, member, p))
            if not intervals or any(i[0] != 4 for i in intervals):
                return "NAT_POOL", f"translated address '{member}' is not a static IPv4 address", Severity.REVIEW
    return None


# -- emitter ------------------------------------------------------------------


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.addr4: Dict[str, List[str]] = {}
        self.addr6: Dict[str, List[str]] = {}
        self.grp4: Dict[str, List[str]] = {}
        self.grp6: Dict[str, List[str]] = {}
        self.services: Dict[str, List[str]] = {}
        self.service_groups: Dict[str, List[str]] = {}
        self.pools: Dict[str, List[str]] = {}
        self.pool_names: Dict[Tuple[str, Interval], str] = {}
        self.vips: Dict[str, List[str]] = {}
        self.policies: List[List[str]] = []
        self.snat: List[List[str]] = []
        # Names that are taken: generated objects and virtual IPs must not reuse them.
        self.address_names: Set[str] = set(p.addresses) | set(p.address_groups) | _RESERVED_ADDRESSES
        self.service_names: Set[str] = set(p.services) | set(p.service_groups) | _RESERVED_SERVICES
        self.policy_names: Set[str] = set()
        self.literals: Dict[str, str] = {}
        # Addresses something other than a NAT rule's own match refers to.
        self.referenced: Set[str] = {m for r in p.rules for m in r.sources + r.destinations}
        self.referenced |= {m for g in p.address_groups.values() for m in g.members}
        for nat in p.nat_rules:
            self.referenced |= set(nat.sources)
            if nat.destination_translation is None:
                self.referenced |= set(nat.destinations)
            else:
                self.referenced.add(nat.destination_translation.address)
            if nat.source_translation:
                self.referenced |= set(nat.source_translation.addresses)
        for address in p.addresses.values():
            interval = parse_literal(address.value) if address.kind in (AddressKind.NETWORK, AddressKind.RANGE) else None
            if interval:
                self.literals.setdefault(f"{interval[0]}:{interval[1]}:{interval[2]}", address.name)
        self.app_services: Dict[str, str] = {}
        self.next_id = options.policy_id_start

    # -- top level --------------------------------------------------------

    def run(self) -> str:
        self._addresses()
        self._services()
        for nat in self.p.nat_rules:
            self._nat(nat)
        for rule in self.p.rules:
            self._rule(rule)
        self._notes()

        out: List[str] = [
            "# Generated by FWShift - review the conversion report before loading this.",
            "# Rules the converter could not express are present but disabled.",
        ]
        out += self._zones()
        out += _table("firewall address", self.addr4)
        out += _table("firewall address6", self.addr6)
        out += _table("firewall addrgrp", {n: [f"set member {ql(m)}"] for n, m in self.grp4.items()})
        out += _table("firewall addrgrp6", {n: [f"set member {ql(m)}"] for n, m in self.grp6.items()})
        out += _table("firewall service custom", self.services)
        out += _table("firewall service group", {n: [f"set member {ql(m)}"] for n, m in self.service_groups.items()})
        out += _table("firewall ippool", self.pools)
        out += _table("firewall vip", self.vips)
        out += _numbered("firewall policy", self.policies)
        out += _numbered("firewall central-snat-map", self.snat)
        if self.options.target_vdom:
            out = out[:2] + ["config vdom", f"edit {q(self.options.target_vdom)}"] + out[2:] + ["end"]
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        self.report.note(
            Severity.INFO,
            "EXISTING_OBJECTS",
            "objects are created by name: an object that already exists on the target under the same name is "
            "overwritten by the one in this output",
        )
        if self.vips or self.snat:
            self.report.note(
                Severity.REVIEW,
                "CENTRAL_NAT",
                "NAT is emitted as central NAT. Enable it first ('config system settings', 'set central-nat "
                "enable'); on a FortiGate that already uses per-policy NAT this changes how existing policies "
                "translate. Virtual IPs are created with 'extintf any'",
            )
        if self.p.default_intrazone == Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_DEFAULT",
                "the source allows traffic inside a zone unless a rule denies it; FortiOS denies it unless a "
                "policy allows it or the zone has 'set intrazone allow'. Check zones with several interfaces",
            )
        if self.p.default_interzone == Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTERZONE_DEFAULT",
                "the source overrides its default rule to allow traffic between zones; FortiOS has an implicit "
                "deny, so add an explicit final allow policy if that was intended",
            )

    def _zones(self) -> List[str]:
        used: List[str] = []
        for rule in list(self.p.rules) + list(self.p.nat_rules):
            for zone_name in rule.src_zones + rule.dst_zones:
                if zone_name != ANY and zone_name not in used:
                    used.append(zone_name)
        mapped = set(self.options.zone_map.values())
        entries: Dict[str, List[str]] = {}
        empty: List[str] = []
        for name in used:
            if name in mapped:
                continue  # the user named an existing zone or interface
            zone = self.p.zones.get(name)
            if self.p.vendor == "fortios":
                if zone is None:
                    continue  # a plain interface
                interfaces = [self.options.interface_map.get(i, i) for i in zone.interfaces]
            else:
                members = zone.interfaces if zone else []
                interfaces = [self.options.interface_map[i] for i in members if i in self.options.interface_map]
            lines = [f"set interface {ql(interfaces)}"] if interfaces else []
            if zone is not None and zone.intrazone_allow:
                lines.append("set intrazone allow")
            if not interfaces:
                empty.append(name)
            entries[name] = lines
        if empty:
            self.report.note(
                Severity.REVIEW,
                "ZONES_WITHOUT_INTERFACES",
                "zones created without interfaces: "
                + ", ".join(empty)
                + ". Assign interfaces, or rerun with --zone-map / --interface-map to use existing names",
            )
        return _table("system zone", entries)

    # -- addresses --------------------------------------------------------

    def _addresses(self) -> None:
        for address in self.p.addresses.values():
            if address.kind == AddressKind.UNSUPPORTED:
                self._placeholder_address(address.name, address.raw)
                continue
            comment = [f"set comment {_comment(address.description, 255)}"] if address.description else []
            if address.kind == AddressKind.FQDN:
                # A name resolved for both IP versions gets its IPv6 object when a rule needs it.
                table = self.addr6 if address.fqdn_family == 6 else self.addr4
                table[address.name] = ["set type fqdn", f"set fqdn {q(address.value)}"] + comment
                continue
            version, lines = _address_lines(address.kind, address.value)
            (self.addr4 if version == 4 else self.addr6)[address.name] = lines + comment
        for group in transform.topo_groups(self.p.address_groups):
            if transform.is_placeholder_group(group):
                self._placeholder_address(group.name, self.taint_a.get(group.name, "unconvertible group"))
                continue
            v4 = [m for m in (self._ref(member, 4) for member in group.members) if m]
            v6 = [m for m in (self._ref(member, 6) for member in group.members) if m]
            if v4:
                self.grp4[group.name] = transform.dedupe(v4)
            if v6:
                self.grp6[group.name] = transform.dedupe(v6)

    def _placeholder_address(self, name: str, reason: str) -> None:
        self.addr4[name] = ["set subnet 0.0.0.0 255.255.255.255", f"set comment {_comment(_PLACEHOLDER + reason, 255)}"]

    def _ref(self, member: str, version: int) -> Optional[str]:
        """Name to use for a rule or group member in the IPv4 or IPv6 address field; None if not applicable."""
        if member == ANY:
            return "all"
        if member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.UNSUPPORTED:
                return member if version == 4 else None  # placeholders are IPv4 objects
            if version not in transform.families(self.p, member):
                return None
            if address.kind == AddressKind.FQDN and version == 6 and member not in self.addr6:
                self.addr6[member] = ["set type fqdn", f"set fqdn {q(address.value)}"]
            return member
        if member in self.p.address_groups:
            if transform.is_placeholder_group(self.p.address_groups[member]):
                return member if version == 4 else None
            return member if member in (self.grp4 if version == 4 else self.grp6) else None
        interval = parse_literal(member)
        if interval is None or interval[0] != version:
            return None
        if interval in (FULL_V4, FULL_V6):
            return "all"
        return self._literal(member, interval)

    def _literal(self, text: str, interval: Interval) -> str:
        """Address object standing for a literal used directly in a rule."""
        key = f"{interval[0]}:{interval[1]}:{interval[2]}"
        if key in self.literals:
            self.referenced.add(self.literals[key])
            return self.literals[key]
        version, first, last = interval
        if "-" in text and "/" not in text:
            name = f"r-{range_text(interval)}"
            lines = ["set type iprange", f"set start-ip {int_to_ip(version, first)}", f"set end-ip {int_to_ip(version, last)}"]
        else:
            net = ipaddress.ip_network(text.strip(), strict=False)
            name = f"h-{net.network_address}" if first == last else f"n-{net.network_address}_{net.prefixlen}"
            _, lines = _address_lines(AddressKind.NETWORK, text)
        name = unique(name, self.address_names, FORTIOS)
        (self.addr4 if version == 4 else self.addr6)[name] = lines
        self.literals[key] = name
        return name

    def _refs(self, members: List[str], version: int) -> List[str]:
        out = transform.dedupe([m for m in (self._ref(member, version) for member in members) if m])
        return ["all"] if "all" in out else out

    def _has(self, members: List[str], version: int) -> bool:
        """Whether an address list names anything of this IP version (placeholders count as IPv4)."""
        for member in members:
            unsupported = member in self.p.addresses and self.p.addresses[member].kind == AddressKind.UNSUPPORTED
            placeholder = member in self.p.address_groups and transform.is_placeholder_group(self.p.address_groups[member])
            if unsupported or placeholder:
                if version == 4:
                    return True
            elif version in transform.families(self.p, member):
                return True
        return False

    def _side(self, members: List[str], negated: bool, version: int) -> Tuple[List[str], bool]:
        """(objects, negate flag) of one address field for one IP version; no objects means no match."""
        if not self._has(members, version):
            # Only reached for a negated list: it excludes nothing of this version.
            return ["all"], False
        refs = self._refs(members, version)
        if negated and refs == ["all"]:
            return [], False  # everything of this version is excluded
        return refs, negated

    # -- services ---------------------------------------------------------

    def _services(self) -> None:
        for service in self.p.services.values():
            if service.builtin == "fortios":
                continue
            if not service.entries or service.unsupported:
                reason = service.unsupported or "unsupported or undefined service"
                self.services[service.name] = ["set tcp-portrange 1", f"set comment {_comment(_PLACEHOLDER + reason, 255)}"]
                continue
            self._define_service(service.name, service.entries, service.description)
        for group in transform.topo_groups(self.p.service_groups):
            if group.members:
                self.service_groups[group.name] = list(group.members)
            else:
                self.services[group.name] = [
                    "set tcp-portrange 1",
                    f"set comment {_comment(_PLACEHOLDER + 'empty service group', 255)}",
                ]

    def _define_service(self, name: str, entries: List[ServiceEntry], description: str = "") -> None:
        """One custom service, or several plus a group when FortiOS cannot mix the protocols."""
        parts = _service_parts(entries)
        comment = [f"set comment {_comment(description, 255)}"] if description else []
        if len(parts) == 1:
            self.services[name] = parts[0] + comment
            return
        members: List[str] = []
        for index, part in enumerate(parts):
            member = unique(f"{name}-{index + 1}", self.service_names, FORTIOS)
            self.services[member] = part + comment
            members.append(member)
        self.service_groups[name] = members

    def _app_service(self, app: str, entries: List[ServiceEntry]) -> str:
        if app not in self.app_services:
            name = unique(f"app-{app}", self.service_names, FORTIOS)
            self._define_service(name, entries, f"well-known ports of application {app}")
            self.app_services[app] = name
        return self.app_services[app]

    def _rule_services(self, rule: Rule, reasons: List[transform.Reason]) -> List[str]:
        apps, services = rule.applications, rule.services
        named = ["ALL" if s == ANY else s for s in services]
        deny = rule.action != Action.ALLOW
        if apps == [ANY]:
            if services == [APP_DEFAULT]:
                reasons.append(
                    ("APP_DEFAULT_ANY", "'any' application on its default ports has no layer-4 equivalent")
                )
                return ["ALL"]
            return named
        if services in ([APP_DEFAULT], [ANY]):
            names: List[str] = []
            unknown: List[str] = []
            for app in apps:
                entries = entries_for(app, self.options.app_ports)
                if entries is None:
                    unknown.append(app)
                else:
                    names.append(self._app_service(app, entries))
            if unknown:
                reasons.append(
                    (
                        "APP_UNKNOWN",
                        "no port mapping for application(s) " + ", ".join(unknown) + "; supply one with --app-map",
                    )
                )
            if names:
                known = ", ".join(a for a in apps if a not in unknown)
                if not deny:
                    extra = " (the source matched them on any port)" if services == [ANY] else ""
                    text = (
                        f"applications {known} reduced to their well-known ports{extra}; layer-7 identification "
                        "is lost, add application control if it is needed"
                    )
                elif services == [ANY]:
                    text = (
                        f"the source blocked applications {known} on every port; only their well-known ports are "
                        "blocked now, so the same applications on other ports are no longer stopped by this rule"
                    )
                else:
                    text = (
                        f"the source blocked applications {known}; everything on their well-known ports is "
                        "blocked now, which is more than the source rule did"
                    )
                self.report.add("rule", rule.origin, Severity.REVIEW if deny else Severity.APPROX, "APP_TO_PORTS", text)
            return names or ["ALL"]
        self.report.add(
            "rule",
            rule.origin,
            Severity.REVIEW if deny else Severity.APPROX,
            "APP_FILTER_DROPPED",
            "application match "
            + ", ".join(apps)
            + " dropped; the rule now matches everything on its services"
            + (" and so blocks more than the source rule" if deny else ""),
        )
        return named

    # -- security rules ---------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(
                ("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted")
            )
        services = self._rule_services(rule, reasons)

        # One (source, destination) pair of address fields per IP version. A negated
        # list covers both versions: the version it does not name becomes "all".
        fields: Dict[int, Tuple[List[str], bool, List[str], bool]] = {}
        for version in (4, 6):
            if not (rule.negate_source or self._has(rule.sources, version)):
                continue
            if not (rule.negate_destination or self._has(rule.destinations, version)):
                continue
            src, src_negate = self._side(rule.sources, rule.negate_source, version)
            dst, dst_negate = self._side(rule.destinations, rule.negate_destination, version)
            if src and dst:
                fields[version] = (src, src_negate, dst, dst_negate)
        if not fields:
            self.report.skip(
                "rule",
                rule.origin,
                "NO_COMMON_FAMILY",
                "source and destination share no IP version, or a negation excludes everything; nothing to emit",
            )
            return
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(
                ("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as FortiOS interface pairs")
            )
            pairs = [(rule.src_zones, rule.dst_zones)]
        elif not pairs:
            self.report.skip(
                "rule",
                rule.origin,
                "RULE_TYPE_EMPTY",
                f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing",
                Severity.INFO,
            )
            return
        elif len(pairs) > 1:
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "RULE_SPLIT",
                f"{rule.scope.value} rule written as {len(pairs)} policies, one per zone pair",
            )
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "RESET_ACTION",
                f"action {rule.action.value} becomes deny; FortiOS sends resets only with 'set send-deny-packet enable'",
            )
        if reasons:
            transform.disable_rule(self.report, rule, reasons)

        allow = rule.action == Action.ALLOW
        for src_zones, dst_zones in pairs:
            name = unique(rule.name, self.policy_names, FORTIOS_POLICY)
            item.emitted_as.append(name)
            lines = [
                f"edit {self.next_id}",
                f"set name {q(name)}",
                f"set srcintf {ql(src_zones)}",
                f"set dstintf {ql(dst_zones)}",
                f"set action {'accept' if allow else 'deny'}",
            ]
            if self.next_id:
                self.next_id += 1
            negations: List[str] = []
            for version, suffix in ((4, ""), (6, "6")):
                if version not in fields:
                    continue
                src, src_negate, dst, dst_negate = fields[version]
                lines += [f"set srcaddr{suffix} {ql(src)}", f"set dstaddr{suffix} {ql(dst)}"]
                if src_negate:
                    negations.append(f"set srcaddr{suffix}-negate enable")
                if dst_negate:
                    negations.append(f"set dstaddr{suffix}-negate enable")
            lines += negations
            lines += ['set schedule "always"', f"set service {ql(services)}"]
            if rule.negate_service:
                lines.append("set service-negate enable")
            lines.append("set logtraffic " + ("all" if rule.log_end else "utm" if allow else "disable"))
            if rule.log_start:
                lines.append("set logtraffic-start enable")
            if not rule.enabled or reasons:
                lines.append("set status disable")
            comment = ("FWSHIFT: disabled by the converter, see the report. " if reasons else "") + rule.description
            if comment.strip():
                lines.append(f"set comments {_comment(comment, 1023)}")
            self.policies.append(lines)

    # -- NAT --------------------------------------------------------------

    def _nat(self, nat: NatRule) -> None:
        problem = nat_problem(self.p, nat, self.taint_a, self.taint_s)
        if problem is not None:
            code, message, severity = problem
            self.report.skip("nat", nat.origin, code, message, severity)
            return
        self.report.item("nat", nat.origin)
        destinations = self._refs(nat.destinations, 4)
        if nat.destination_translation is not None:
            destinations = [self._dnat(nat)]
        if nat.source_translation is not None or nat.destination_translation is None:
            self._snat(nat, destinations)

    def _dnat(self, nat: NatRule) -> str:
        """Emit the virtual IP for a destination NAT rule; return the object naming the mapped address."""
        translation = nat.destination_translation
        assert translation is not None
        external = transform.address_intervals(self.p, nat.destinations[0])
        mapped = transform.address_intervals(self.p, translation.address)
        assert external and mapped  # checked by nat_problem
        lines = [f"set extip {range_text(external[0])}", f"set mappedip {q(range_text(mapped[0]))}", 'set extintf "any"']
        forward = _port_forward(self.p, nat)
        if forward is not None:
            lines += [
                "set portforward enable",
                f"set protocol {forward.protocol.value}",
                f"set extport {forward.dst_ports}",
                f"set mappedport {translation.port or forward.dst_ports}",
            ]
        elif nat.service != ANY:
            self.report.add(
                "nat",
                nat.origin,
                Severity.APPROX,
                "NAT_SERVICE_DROPPED",
                f"the rule translated only service '{nat.service}'; the virtual IP translates all ports",
            )
        if nat.sources != [ANY]:
            self.report.add(
                "nat",
                nat.origin,
                Severity.APPROX,
                "NAT_SOURCE_DROPPED",
                "the rule translated only traffic from " + ", ".join(nat.sources) + "; the virtual IP applies to all sources",
            )
        if nat.description:
            lines.append(f"set comment {_comment(nat.description, 255)}")
        stand_in = nat.destinations[0] == nat.name
        if stand_in and nat.name not in self.referenced and nat.name in self.addr4:
            # The address object only existed to name this external IP: the virtual IP replaces it.
            del self.addr4[nat.name]
            self.literals = {k: v for k, v in self.literals.items() if v != nat.name}
            name = nat.name
        else:
            name = unique(nat.name, self.address_names, FORTIOS)
        self.vips[name] = lines
        self.report.item("nat", nat.origin).emitted_as.append(f"virtual IP {name}")
        mapped_ref = self._ref(translation.address, 4)
        assert mapped_ref is not None
        return mapped_ref

    def _snat(self, nat: NatRule, destinations: List[str]) -> None:
        translation = nat.source_translation
        lines = [
            "edit 0",
            f"set srcintf {ql(nat.src_zones)}",
            f"set dstintf {ql(nat.dst_zones)}",
            f"set orig-addr {ql(self._refs(nat.sources, 4))}",
            f"set dst-addr {ql(destinations)}",
        ]
        if translation is None:
            lines.append("set nat disable")
        else:
            pools: List[str] = []
            pool_type = "one-to-one" if translation.kind in (SnatKind.DYNAMIC, SnatKind.STATIC) else "overload"
            for member in translation.addresses:
                member = _pool_member(nat, member, self.p)
                for interval in transform.address_intervals(self.p, member) or []:
                    pools.append(self._pool(member, interval, pool_type))
                    if translation.kind == SnatKind.STATIC and size(interval) > 1:
                        self.report.add(
                            "nat",
                            nat.origin,
                            Severity.APPROX,
                            "NAT_STATIC_RANGE",
                            f"static NAT of {size(interval)} addresses becomes a one-to-one pool, which does not "
                            "promise that each host keeps the same translated address",
                        )
            lines.append("set nat enable")
            if pools:
                lines.append(f"set nat-ippool {ql(transform.dedupe(pools))}")
            if translation.kind == SnatKind.STATIC and translation.bidirectional:
                self._reverse_vip(nat)
        if nat.service != ANY:
            self.report.add(
                "nat",
                nat.origin,
                Severity.REVIEW,
                "NAT_SERVICE_DROPPED",
                f"the rule translated only service '{nat.service}'; the central SNAT entry applies to all services",
            )
        if not nat.enabled:
            lines.append("set status disable")
        lines.append(f"set comments {_comment((nat.name + ' ' + nat.description).strip(), 1023)}")
        self.snat.append(lines)
        self.report.item("nat", nat.origin).emitted_as.insert(0, "central SNAT entry")

    def _pool(self, member: str, interval: Interval, pool_type: str) -> str:
        key = (pool_type, interval)
        if key not in self.pool_names:
            known = member in self.p.addresses or member in self.p.address_groups
            label = member if known else f"pool-{range_text(interval)}"
            name = unique(label, set(self.pools), FORTIOS)
            version, first, last = interval
            self.pools[name] = [
                f"set type {pool_type}",
                f"set startip {int_to_ip(version, first)}",
                f"set endip {int_to_ip(version, last)}",
            ]
            self.pool_names[key] = name
        return self.pool_names[key]

    def _reverse_vip(self, nat: NatRule) -> None:
        if not nat.enabled:
            return  # the SNAT entry is written disabled; a virtual IP cannot be
        pair = _reverse_pair(self.p, nat)
        if pair is None:
            self.report.add(
                "nat",
                nat.origin,
                Severity.REVIEW,
                "NAT_BIDIRECTIONAL",
                "bi-directional static NAT: the inbound direction could not be written as a virtual IP and is missing",
            )
            return
        inside, outside = pair
        name = unique(f"{nat.name}-in", self.address_names, FORTIOS)
        self.vips[name] = [
            f"set extip {range_text(outside)}",
            f"set mappedip {q(range_text(inside))}",
            'set extintf "any"',
            f"set comment {_comment('inbound half of bi-directional static NAT ' + nat.name, 255)}",
        ]
        self.report.item("nat", nat.origin).emitted_as.append(f"virtual IP {name}")
        self.report.add(
            "nat",
            nat.origin,
            Severity.APPROX,
            "NAT_BIDIRECTIONAL",
            f"bi-directional static NAT written as a central SNAT entry plus virtual IP '{name}' for the "
            "inbound direction",
        )


def _address_lines(kind: AddressKind, value: str) -> Tuple[int, List[str]]:
    interval = parse_literal(value)
    assert interval is not None, value
    version, first, last = interval
    if kind == AddressKind.RANGE:
        return version, [
            "set type iprange",
            f"set start-ip {int_to_ip(version, first)}",
            f"set end-ip {int_to_ip(version, last)}",
        ]
    net = ipaddress.ip_network(value.strip(), strict=False)
    if version == 4:
        return 4, [f"set subnet {net.network_address} {net.netmask}"]
    return 6, [f"set ip6 {net.compressed}"]


def _forti_ports(entry: ServiceEntry) -> List[str]:
    dst = entry.dst_ports.split(",") if entry.dst_ports else ["1-65535"]
    if not entry.src_ports:
        return dst
    return [f"{d}:{s}" for d in dst for s in entry.src_ports.split(",")]


def _service_parts(entries: List[ServiceEntry]) -> List[List[str]]:
    """Group entries into FortiOS custom services: one for TCP/UDP/SCTP, one per ICMP or IP entry."""
    ports: Dict[Protocol, List[str]] = {}
    others: List[List[str]] = []
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            ports.setdefault(entry.protocol, []).extend(_forti_ports(entry))
        elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            lines = ["set protocol " + ("ICMP" if entry.protocol == Protocol.ICMP else "ICMP6")]
            if entry.icmp_type is not None:
                lines.append(f"set icmptype {entry.icmp_type}")
                if entry.icmp_code is not None:
                    lines.append(f"set icmpcode {entry.icmp_code}")
            others.append(lines)
        else:
            others.append(["set protocol IP", f"set protocol-number {entry.ip_protocol or 0}"])
    parts: List[List[str]] = []
    if ports:
        parts.append([f"set {_PORT_KEYS[proto]} {' '.join(ports[proto])}" for proto in L4_PROTOCOLS if proto in ports])
    return parts + others


def _table(path: str, entries: Dict[str, List[str]]) -> List[str]:
    if not entries:
        return []
    out = [f"config {path}"]
    for name, lines in entries.items():
        out.append(f"    edit {q(name)}")
        out += ["        " + line for line in lines]
        out.append("    next")
    return out + ["end"]


def _numbered(path: str, blocks: List[List[str]]) -> List[str]:
    if not blocks:
        return []
    out = [f"config {path}"]
    for block in blocks:
        out.append("    " + block[0])
        out += ["        " + line for line in block[1:]]
        out.append("    next")
    return out + ["end"]
