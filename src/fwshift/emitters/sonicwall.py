# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""SonicWall emitter: neutral model -> commands of the SonicOS 7 command line (E-CLI).

Design rules:

* Nothing is ever widened silently. A rule whose match cannot be expressed is written with
  ``no enable`` and reported.
* A SonicOS access rule is for one pair of zones and names one source, one destination and one
  service: an object, a group or ``any``. A rule of the model with several zones becomes one rule
  per pair, a list becomes a group. Rules are first match within their pair; each is given its
  place in the pair (``priority manual``), so that SonicOS does not order them by itself.
* SonicOS has a default rule for every pair of zones, and some of them allow (LAN to WAN). Where the
  model denies what no rule matches, every pair of zones ends in a rule that denies.
* Address objects and groups are per IP version, and so are access rules. There is no negation:
  a negated list is written as the addresses that are left.
* An access rule matches the destination before NAT and the zone after it, as the model does. NAT
  policies are one table, first match; they match interfaces, not zones.
* Only TCP and UDP services are written, and ICMP echo as the default service ``Ping``: the
  command for other kinds of service was not found in what SonicWall publishes.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..names import SONICWALL, SONICWALL_NATIVE, NameRules, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text, is_number, normalize, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_ANY = "\0any"
_FULL = {4: "\0full4", 6: "\0full6"}
_ACTIONS = {Action.ALLOW: "allow", Action.DENY: "deny", Action.DROP: "discard", Action.RESET_CLIENT: "deny",
            Action.RESET_SERVER: "deny", Action.RESET_BOTH: "deny"}  # fmt: skip
# Words the command line uses where a name can stand, and objects every SonicOS has.
_WORDS: FrozenSet[str] = frozenset({"any", "original", "none", "all", "name", "group"})
_BUILTIN = re.compile(
    r"(?i)(X[0-9]+(:V[0-9]+)?|U[0-9]+|W[0-9]+|MGMT) (IP|Subnet|Default Gateway)|All (X[0-9]+|U[0-9]+|W[0-9]+|MGMT) Management IP"
    r"|.+ Subnets|Firewalled Subnets|All Interface IP|All WAN IP|WAN Primary (IP|Subnet)|Default Gateway|All SonicPoints"
)
_DEFAULT_SERVICES: FrozenSet[str] = frozenset(
    name.lower() for name in ("HTTP", "HTTPS", "SSH", "Telnet", "FTP", "SMTP (Send E-Mail)", "POP3 (Retrieve E-Mail)", "IMAP4",
                              "DNS (Name Service)", "NTP", "SNMP", "Syslog", "IKE", "Terminal Services", "Ping", "Any")
)  # fmt: skip
_PING = "Ping"
_MAX_ZONES = 100


_NOT_IN_COMMENT = re.compile(r"[^ -~]|[\"'\\\\]")

def _q(name: str) -> str:
    return f'"{name}"'


def _zq(zone: str) -> str:
    """A zone: quoted where it has a space."""
    return _q(zone) if " " in zone else zone


class _Names:
    def __init__(self, native: bool) -> None:
        self.native = native
        self.objects: NameRules = SONICWALL_NATIVE if native else SONICWALL
        self.addresses: Set[str] = set()
        self.services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.source: Dict[str, str] = {}

    def unique(self, name: str, taken: Set[str], suffix: str = "") -> str:
        rules = self.objects
        base = clean(name, rules)
        if suffix:
            base = base[: rules.max_len - len(suffix)].rstrip() + suffix
        candidate, counter = base, 2
        while candidate.lower() in taken:
            tail = f" {counter}"
            candidate = base[: rules.max_len - len(tail)].rstrip() + tail
            counter += 1
        taken.add(candidate.lower())
        return candidate


def _reserved(name: str, service: bool) -> bool:
    low = name.lower()
    return low in _WORDS or (low in _DEFAULT_SERVICES if service else _BUILTIN.fullmatch(name) is not None)


def _rename(p: Policy, report: Report, names: _Names, prefix: str) -> None:
    keep = {n for n, a in p.addresses.items() if a.builtin == "sonicwall"} | {n for n, g in p.address_groups.items() if g.builtin == "sonicwall"}
    keep |= {n for n, s in p.services.items() if s.builtin == "sonicwall"}
    if not names.native:
        keep = set()

    def plan(listed: List[Tuple[str, str]], taken: Set[str], service: bool) -> Dict[str, str]:
        stays: Set[str] = set()
        for name, _ in listed:
            fits = not prefix and clean(name, names.objects) == name and name.lower() not in taken and not (
                not names.native and _reserved(name, service))
            if name in keep or fits:
                stays.add(name)
                taken.add(name.lower())
        mapping: Dict[str, str] = {}
        for name, kind in listed:
            names.source[name] = name
            if name in stays:
                continue
            new = names.unique(prefix + name, taken)
            if _reserved(new, service):
                new = names.unique(f"{prefix}{name} 2", taken)
            mapping[name] = new
            names.source[new] = name
            report.item(kind, name).emitted_as = [new]
            report.add(kind, name, Severity.INFO, "RENAMED", f"renamed to '{new}' to fit the target's naming rules")
        return mapping

    address_map = plan([(n, "address") for n in p.addresses] + [(n, "address-group") for n in p.address_groups], names.addresses, False)
    service_map = plan([(n, "service") for n in p.services] + [(n, "service-group") for n in p.service_groups], names.services, True)
    transform.rename_objects(p, address_map, service_map)
    for rule in p.rules:
        rule.name = names.unique(rule.name, names.rule_names)
    for nat in p.nat_rules:
        nat.name = names.unique(nat.name, names.nat_names)


def emit(policy: Policy, report: Report, options: Options) -> str:
    zone_spaces(options.zone_networks)
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    for zone in {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}:
        if zone.lower() in _WORDS or not clean(zone, SONICWALL_NATIVE) == zone:
            mapped = zone in options.zone_map.values()
            raise FwshiftError(
                f"--zone-map: '{zone[:40]}' cannot be the name of a SonicOS zone" if mapped else
                f"zone '{zone[:40]}' cannot be the name of a SonicOS zone: give it another name with --zone-map"
            )  # fmt: skip
    transform.ensure_references(p, report)
    names = _Names(p.vendor == "sonicwall")
    _rename(p, report, names, options.object_prefix)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, names).run()


@dataclass
class _Side:
    ref: str  # "any", 'name "X"' or 'group "X"'
    nothing: bool = False


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, names: _Names) -> None:
        self.p, self.report, self.options, self.names = p, report, options, names
        self.native = names.native
        self.builtin = {n for n, a in p.addresses.items() if a.builtin == "sonicwall" and self.native}
        self.builtin |= {n for n, g in p.address_groups.items() if g.builtin == "sonicwall" and self.native}
        self.taint_a = transform.tainted_addresses(p, keep=self.builtin)
        self.taint_s: Dict[str, str] = {}
        self.objects: List[str] = []
        self.groups: List[str] = []
        self.services: List[str] = []
        self.service_groups: List[str] = []
        self.rules: List[str] = []
        self.nat: List[str] = []
        self.kind: Dict[str, Tuple[str, int]] = {_FULL[4]: ("full", 4), _FULL[6]: ("full", 6)}
        self.group_refs: Dict[Tuple[str, int], str] = {}  # (group of the model, IP version) -> group written
        self.literals: Dict[Interval, str] = {}
        self.svc_ref: Dict[str, str] = {}  # service or group of the model -> reference
        self.svc_any: Set[str] = set()
        self.port_services: Dict[Tuple[str, str], str] = {}
        self.app_services: Dict[str, Tuple[str, str]] = {}
        self.zone_of: Dict[str, str] = self._object_zones()
        used = {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}
        self.universe = sorted(used | set(p.zones))
        if len(self.universe) > _MAX_ZONES:
            raise FwshiftError(f"the policy has {len(self.universe)} zones; FWShift writes SonicOS rules for {_MAX_ZONES} at most "
                               "(a rule that denies for every pair of them would be a file nobody can load)")  # fmt: skip
        self.priority: Dict[Tuple[str, str, int], int] = {}
        self.last_catch_all: Dict[Tuple[str, str, int], bool] = {}
        self.split = 0
        self.unconfirmed: Set[str] = set()

    # -- top level --------------------------------------------------------------------------------

    def run(self) -> str:
        self._addresses()
        self._groups()
        self._services()
        for rule in self.p.rules:
            self._rule(rule)
        self._tails()
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "first-match")
        self._notes()
        out = ["configure terminal"]
        for block in (self.objects, self.groups, self.services, self.service_groups, self.nat, self.rules):
            out += block
        out += ["commit", "exit"]
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        note = self.report.note
        unconfirmed = ", ".join(sorted(self.unconfirmed))
        note(
            Severity.REVIEW, "SONICWALL_LOAD",
            "the output is commands of the SonicOS 7 command line. Log in by SSH, and paste them as they are: they enter "
            "the configuration mode ('configure terminal'; SonicOS 6.5 says 'configure'), create objects, NAT policies and "
            "access rules, and end with 'commit'. A command the firewall refuses stops nothing else: read what it answers, "
            "and compare the rules with this report before anything depends on them. New access rules go above the "
            "default rule of their pair of zones"
            + (f". These parts of the commands are not in the documentation FWShift was written from: {unconfirmed}" if unconfirmed else ""),
        )  # fmt: skip
        note(
            Severity.INFO, "EXISTING_OBJECTS",
            "a command for an object that the firewall has under the same name changes that object or is refused. "
            "--target-prefix gives every object that is created a name of its own",
        )  # fmt: skip
        if not self.native:
            zones = transform.dedupe([z for r in self.p.rules for z in r.src_zones + r.dst_zones if z != ANY])
            if zones:
                note(Severity.REVIEW, "ZONES_REQUIRED",
                     "the rules name these zones, which must exist on the target (or be renamed with --zone-map): "
                     + ", ".join(zones))  # fmt: skip
        if self.split:
            note(Severity.INFO, "IP_VERSION_SPLIT",
                 f"{self.split} rule(s) match IPv4 and IPv6 traffic and were written twice: SonicOS has address objects and "
                 "access rules per IP version")  # fmt: skip
        if self.p.default_interzone == Action.ALLOW:
            note(Severity.REVIEW, "INTERZONE_DEFAULT",
                 "the source allows traffic between zones that no rule matches. SonicOS decides that by the default rule of "
                 "each pair of zones, which allows from a zone of a higher trust to one of a lower trust only: add rules "
                 "that allow it where that was intended")  # fmt: skip

    # -- addresses --------------------------------------------------------------------------------

    def _object_zones(self) -> Dict[str, str]:
        """The zone an object is created in: where the networks given put it, or where the first rule that names it
        sees it. SonicOS asks for one, and does not match by it."""
        spaces = zone_spaces(self.options.zone_networks)
        out: Dict[str, str] = {}

        def place(member: str, zone: str, seen: FrozenSet[str] = frozenset()) -> None:
            if member in self.p.address_groups:
                if member not in seen:
                    for inner in self.p.address_groups[member].members:
                        place(inner, zone, seen | {member})
            elif member != ANY and zone != ANY and member not in out:
                out[member] = zone

        for name in list(self.p.addresses):
            found = transform.address_intervals(self.p, name) or []
            for zone, networks in sorted(spaces.items()):
                if found and all(any(n[0] == i[0] and n[1] <= i[1] and i[2] <= n[2] for n in networks) for i in found):
                    out[name] = zone
                    break
        for rule in self.p.rules:
            for member in rule.sources:
                place(member, rule.src_zones[0])
            for member in rule.destinations:
                place(member, rule.dst_zones[0])
        for nat in self.p.nat_rules:
            for member in nat.sources:
                place(member, nat.src_zones[0])
            for member in nat.destinations:
                place(member, nat.dst_zones[0])
        return out

    def _zone(self, name: str) -> str:
        return self.zone_of.get(name) or (self.universe[0] if "LAN" not in self.universe and self.universe else "LAN")

    def _addresses(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            if name in self.builtin:
                self.kind[name] = ("builtin", address.fqdn_family or 4)
                continue
            if address.kind == AddressKind.UNSUPPORTED:
                self._placeholder(name, address.raw or "unsupported address")
            elif address.kind == AddressKind.FQDN:
                self.unconfirmed.add("address-object fqdn")
                self.objects.append(f"address-object fqdn {_q(name)} domain {_q(address.value)} zone {_zq(self._zone(name))}")
                self.kind[name] = ("fqdn", address.fqdn_family)
            else:
                interval = parse_literal(address.value)
                if interval is None:
                    self.taint_a[name] = "address that could not be read"
                    self._placeholder(name, self.taint_a[name])
                elif interval in (FULL_V4, FULL_V6):
                    self.kind[name] = ("full", interval[0])
                else:
                    self._ip_object(name, interval, address.kind == AddressKind.RANGE)
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a) | self.builtin), **self.taint_a}

    def _placeholder(self, name: str, reason: str) -> None:
        """An object that keeps the name and matches nothing: the dummy address of RFC 7600."""
        self.objects.append(f"address-object ipv4 {_q(name)} host 192.0.0.8 zone {_zq(self._zone(name))}")
        self.kind[name] = ("placeholder", 4)
        self.taint_a.setdefault(name, reason)

    def _ip_object(self, name: str, interval: Interval, as_range: bool) -> None:
        version, first, last = interval
        family = f"ipv{version}"
        if version == 6:
            self.unconfirmed.add("address-object ipv6")
        networks = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
        if first == last:
            body = f"host {int_to_ip(version, first)}"
        elif len(networks) == 1 and not as_range:
            network = ipaddress.ip_network(str(networks[0]))
            body = f"network {network.network_address} {network.netmask if version == 4 else '/' + str(network.prefixlen)}"
        else:
            body = f"range {int_to_ip(version, first)} {int_to_ip(version, last)}"
        self.objects.append(f"address-object {family} {_q(name)} {body} zone {_zq(self._zone(name))}")
        self.kind[name] = ("ip", version)
        self.literals.setdefault(interval, name)

    def _literal(self, interval: Interval) -> str:
        if interval not in self.literals:
            text = interval_text(interval)
            label = ("h " if interval[1] == interval[2] else "n " if "/" in text else "r ") + text.replace("/", "_")
            name = self.names.unique(self.options.object_prefix + label, self.names.addresses)
            self._ip_object(name, interval, "/" not in text)
        return self.literals[interval]

    def _leaves(self, group: str, seen: Set[str]) -> List[str]:
        out: List[str] = []
        for member in self.p.address_groups[group].members:
            if member in self.builtin:
                out.append(member)  # a group SonicOS has itself: named, not spelled out
            elif member in self.p.address_groups:
                if member not in seen:
                    out += self._leaves(member, seen | {member})
            elif member in self.p.addresses:
                out.append(member)
            else:
                interval = parse_literal(member)
                if interval is not None:
                    out.append(_FULL[interval[0]] if interval in (FULL_V4, FULL_V6) else self._literal(interval))
        return transform.dedupe(out)

    def _write_group(self, name: str, version: int, members: List[str]) -> None:
        lines = [f"address-group ipv{version} {_q(name)}"]
        for member in members:
            kind = self.kind.get(member, ("group", version))[0]
            if member in self.p.address_groups:
                kind = "group"
            if kind == "fqdn":
                lines.append(f"    address-object fqdn {_q(member)}")
            elif kind == "group":
                lines.append(f"    address-group ipv{version} {_q(member)}")
            else:
                lines.append(f"    address-object ipv{version} {_q(member)}")
        lines.append("    exit")
        self.groups += lines

    def _groups(self) -> None:
        for name in self.builtin:
            if name in self.p.address_groups:
                self.kind[name] = ("builtin", 4)
        for group in self.p.address_groups.values():
            name = group.name
            if name in self.builtin:
                for version in (4, 6):
                    self.group_refs[(name, version)] = name
                self.kind[name] = ("builtin", 4)
                continue
            if name in self.taint_a:
                self._placeholder(name, self.taint_a[name])
                continue
            leaves = self._leaves(name, {name})
            made: List[str] = []
            for version in (4, 6):
                if any(self.kind.get(leaf) == ("full", version) for leaf in leaves):
                    self.group_refs[(name, version)] = _ANY
                    continue
                members = [leaf for leaf in leaves if self.kind.get(leaf, ("", 0))[0] in ("ip", "builtin") and self.kind[leaf][1] == version]
                members += [leaf for leaf in leaves if self.kind.get(leaf, ("", 0)) == ("fqdn", 0) or self.kind.get(leaf) == ("fqdn", version)]
                if not members:
                    continue
                new = name if not made else self.names.unique(name, self.names.addresses, " v6")
                made.append(new)
                self._write_group(new, version, members)
                self.group_refs[(name, version)] = new
            if len(made) > 1:
                origin = self.names.source.get(name, name)
                self.report.item("address-group", origin).emitted_as = list(made)
                self.report.add("address-group", origin, Severity.INFO, "GROUP_SPLIT",
                                "SonicOS keeps IPv4 and IPv6 addresses in groups of their own: written as "
                                + ", ".join(f"'{one}'" for one in made))  # fmt: skip

    def _families(self, member: str) -> Set[int]:
        if member == ANY:
            return {4, 6}
        if member in self.kind:
            kind, version = self.kind[member]
            return {version} if version else {4, 6}
        if any((member, v) in self.group_refs for v in (4, 6)):
            return {v for v in (4, 6) if (member, v) in self.group_refs}
        interval = parse_literal(member)
        return {interval[0]} if interval else {4}

    def _ref(self, member: str, version: int) -> List[str]:
        if member == ANY:
            return [_ANY]
        if member in self.kind:
            kind, family = self.kind[member]
            if family not in (0, version):
                return []
            return [_ANY] if kind == "full" else [member]
        if (member, version) in self.group_refs:
            return [self.group_refs[(member, version)]]
        interval = parse_literal(member)
        if interval is None or interval[0] != version:
            return []
        return [_ANY] if interval in (FULL_V4, FULL_V6) else [self._literal(interval)]

    def _side(self, rule: Rule, members: List[str], negated: bool, version: int, side: str,
              reasons: List[transform.Reason]) -> Optional[_Side]:  # fmt: skip
        """The reference of one address field in a rule of one IP version; None when it matches nothing."""
        refs = transform.dedupe([ref for member in members for ref in self._ref(member, version)])
        if _ANY in refs:
            refs = [_ANY]
        if negated:
            named: List[Interval] = []
            for member in members:
                resolved = transform.address_intervals(self.p, member)
                if resolved is None:
                    reasons.append(("NEGATION_NOT_STATIC", f"the {side} is negated and holds a host name: what it leaves "
                                    "cannot be written as addresses"))  # fmt: skip
                    return _Side("any")
                named += resolved
            left = subtract([FULL_V4 if version == 4 else FULL_V6], [i for i in named if i[0] == version])
            if not left:
                return None
            self.report.add("rule", rule.origin, Severity.INFO, "NEGATION_EXPANDED",
                            f"SonicOS has no negation: 'not {side} {', '.join(members)}' is written as the IPv{version} "
                            f"addresses that are left ({len(left)} range(s))")  # fmt: skip
            if left == [FULL_V4 if version == 4 else FULL_V6]:
                return _Side("any")
            refs = [self._literal(interval) for interval in left]
        if not refs:
            return None
        if refs == [_ANY]:
            return _Side("any")
        if len(refs) == 1:
            kind = self.kind.get(refs[0], ("group", version))[0]
            return _Side(f"{'group' if kind == 'group' or refs[0] in self.p.address_groups else 'name'} {_q(refs[0])}")
        label = "src" if side == "source" else "dst"
        name = self.names.unique(f"{self.options.object_prefix}{label} {rule.name}", self.names.addresses, f" v{version}" if version == 6 else "")
        self._write_group(name, version, refs)
        self.kind[name] = ("group", version)
        return _Side(f"group {_q(name)}")

    # -- services ---------------------------------------------------------------------------------

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for service in self.p.services.values():
            name = service.name
            if self.native and service.builtin == "sonicwall":
                self.svc_ref[name] = f"name {_q(name)}"
                continue
            if service.unsupported or not service.entries:
                bad[name] = service.unsupported or "a service without content"
                continue
            if any(entry.protocol == Protocol.IP and entry.ip_protocol is None for entry in service.entries):
                self.svc_any.add(name)
                continue
            problem = self._define_service(name, service.entries)
            if problem:
                bad[name] = problem
                self.report.add("service", self.names.source.get(name, name), Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: not written, and the rules that use it are disabled")  # fmt: skip
        self.taint_s = transform.tainted_services(self.p, bad)
        for group in self.p.service_groups.values():
            self._service_group(group.name, frozenset())

    def _service_group(self, name: str, seen: FrozenSet[str]) -> None:
        """A group, after the groups in it: SonicOS takes a member that exists."""
        if name in self.svc_ref or name in self.svc_any or name in self.taint_s:
            return
        if name in seen:
            self.taint_s[name] = "a group that holds itself"
            return
        if self._holds_any(name, {name}):
            self.svc_any.add(name)
            return
        group = self.p.service_groups[name]
        lines = [f"service-group {_q(name)}"]
        for member in group.members:
            if member in self.p.service_groups:
                self._service_group(member, seen | {name})
            ref = self.svc_ref.get(member)
            if ref is None:
                self.taint_s[name] = f"holds '{member}', which could not be written"
                return
            kind, _, label = ref.partition(" ")
            lines.append(f"    service-{'group' if kind == 'group' else 'object'} {label}")
        lines.append("    exit")
        self.service_groups += lines
        self.svc_ref[name] = f"group {_q(name)}"

    def _holds_any(self, group: str, seen: Set[str]) -> bool:
        return any(member in self.svc_any or (member in self.p.service_groups and member not in seen
                                              and self._holds_any(member, seen | {member})) for member in self.p.service_groups[group].members)  # fmt: skip

    def _pieces(self, entries: List[ServiceEntry]) -> Tuple[List[Tuple[str, int, int]], str]:
        """(protocol, first port, last port) of each object a service needs; why it cannot be written."""
        out: List[Tuple[str, int, int]] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                if entry.src_ports:
                    return [], "source ports, which a SonicOS service object does not have"
                for part in (entry.dst_ports or "1-65535").split(","):
                    first, _, last = part.partition("-")
                    low, high = max(int(first), 1), int(last or first)
                    if high >= low:
                        out.append((entry.protocol.value.upper(), low, high))
            elif entry.protocol == Protocol.ICMP and entry.icmp_type == 8 and entry.icmp_code is None:
                out.append(("PING", 0, 0))
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                return [], "ICMP other than echo request, for which FWShift does not know the command of SonicOS"
            else:
                return [], (f"IP protocol {entry.ip_protocol}" if entry.protocol == Protocol.IP else entry.protocol.value.upper()) + \
                    ", for which FWShift does not know the command of SonicOS"  # fmt: skip
        if not out:
            return [], "port 0 and no other"
        return list(dict.fromkeys(out)), ""

    def _define_service(self, name: str, entries: List[ServiceEntry]) -> str:
        pieces, problem = self._pieces(entries)
        if problem:
            return problem
        objects: List[str] = []
        for index, (protocol, low, high) in enumerate(pieces):
            if protocol == "PING":
                objects.append(_PING)
                continue
            member = name if len(pieces) == 1 else self.names.unique(f"{name} {protocol.lower()} {low}" + (f"-{high}" if high != low else ""), self.names.services)
            self.services.append(f"service-object {_q(member)} {protocol} {low} {high}")
            objects.append(member)
        origin = self.names.source.get(name, name)
        if objects == [_PING]:
            self.svc_ref[name] = f"name {_q(_PING)}"
            self.report.add("service", origin, Severity.INFO, "ICMP_AS_DEFAULT",
                            "ICMP echo request is written as the default service 'Ping' of SonicOS, which is taken to be that")  # fmt: skip
            return ""
        if len(objects) == 1:
            self.svc_ref[name] = f"name {_q(objects[0])}"
            return ""
        lines = [f"service-group {_q(name)}"] + [f"    service-object {_q(o)}" for o in objects] + ["    exit"]
        self.services += lines
        self.svc_ref[name] = f"group {_q(name)}"
        if name in self.p.services:
            self.report.item("service", origin).emitted_as = [name] + [o for o in objects if o != name]
            self.report.add("service", origin, Severity.INFO, "SERVICE_SPLIT",
                            "a SonicOS service object holds one protocol and one range of ports: written as service group "
                            f"'{name}' of " + ", ".join(f"'{o}'" for o in objects))  # fmt: skip
        return ""

    def _rule_service(self, rule: Rule, reasons: List[transform.Reason]) -> str:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            refs: List[str] = []
            for app, entries in lowered:
                if app not in self.app_services:
                    name = self.names.unique(f"{self.options.object_prefix}app {app}", self.names.services)
                    self.app_services[app] = (name, self._define_service(name, entries))
                name, problem = self.app_services[app]
                if problem:
                    reasons.append(("APP_PORTS", f"the ports of application {app} hold {problem}"))
                else:
                    refs.append(name)
            services = refs or [ANY]
        else:
            services = list(rule.services)
        if ANY in services or self.svc_any & set(services):
            return "any"
        unknown = [s for s in services if s not in self.svc_ref and s not in self.taint_s]
        if unknown:
            reasons.append(("UNCONVERTIBLE_OBJECT", f"service '{unknown[0]}' could not be written"))
        known = [s for s in services if s in self.svc_ref]
        if not known:
            return "any"
        if len(known) == 1:
            return self.svc_ref[known[0]]
        name = self.names.unique(f"{self.options.object_prefix}svc {rule.name}", self.names.services)
        lines = [f"service-group {_q(name)}"]
        for member in known:
            kind, _, label = self.svc_ref[member].partition(" ")
            lines.append(f"    service-{'group' if kind == 'group' else 'object'} {label}")
        self.service_groups += lines + ["    exit"]
        self.svc_ref[name] = f"group {_q(name)}"
        return self.svc_ref[name]

    # -- access rules -----------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> Optional[List[Tuple[str, str]]]:
        src = self.universe if ANY in rule.src_zones else rule.src_zones
        dst = self.universe if ANY in rule.dst_zones else rule.dst_zones
        if rule.scope == RuleScope.INTRAZONE:
            return [(z, z) for z in src]
        if rule.scope == RuleScope.INTERZONE:
            return [(a, b) for a in src for b in dst if a != b]
        return [(a, b) for a in src for b in dst]

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service cannot be written: SonicOS has no negation"))
        service = self._rule_service(rule, reasons)
        pairs = self._pairs(rule)
        if not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                             "the rule names no pair of zones that the policy has: it is written for none", Severity.INFO)  # fmt: skip
            return
        variants: List[Tuple[int, _Side, _Side]] = []
        for version in (4, 6):
            if not (rule.negate_source or any(version in self._families(m) for m in rule.sources)):
                continue
            if not (rule.negate_destination or any(version in self._families(m) for m in rule.destinations)):
                continue
            entries = [e for s in rule.services if s != ANY for e in (transform.flatten_services(self.p, s) or [])]
            if entries and all(e.protocol == (Protocol.ICMP6 if version == 4 else Protocol.ICMP) for e in entries):
                continue
            src = self._side(rule, rule.sources, rule.negate_source, version, "source", reasons)
            dst = self._side(rule, rule.destinations, rule.negate_destination, version, "destination", reasons)
            if src is None or dst is None:
                continue
            variants.append((version, src, dst))
        if not variants:
            self.report.skip("rule", rule.origin, "NO_COMMON_FAMILY",
                             "source, destination and service share no IP version, or a negation leaves nothing")  # fmt: skip
            return
        if len(pairs) > 1:
            self.report.add("rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                            f"a SonicOS rule is for one pair of zones: written as {len(pairs)} rules")  # fmt: skip
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH, Action.RESET_CLIENT):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION", f"action {rule.action.value} becomes deny")
        if len(variants) > 1:
            self.split += 1
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        first = True
        for src_zone, dst_zone in pairs:
            for version, src, dst in variants:
                name = rule.name if first else self.names.unique(rule.name, self.names.rule_names)
                first = False
                item.emitted_as.append(name)
                catch_all = src.ref == dst.ref == service == "any" and rule.enabled and not reasons
                self._write_rule(name, version, src_zone, dst_zone, _ACTIONS[rule.action], src.ref, dst.ref, service,
                                 enabled=rule.enabled and not reasons, catch_all=catch_all)  # fmt: skip

    def _write_rule(self, name: str, version: int, src_zone: str, dst_zone: str, action: str, src: str, dst: str, service: str,
                    enabled: bool, catch_all: bool) -> None:  # fmt: skip
        key = (src_zone, dst_zone, version)
        self.priority[key] = self.priority.get(key, 0) + 1
        self.last_catch_all[key] = catch_all
        if version == 6:
            self.unconfirmed.add("access-rule ipv6")
        self.unconfirmed.add("priority manual")
        self.rules += [
            f"access-rule ipv{version} from {_zq(src_zone)} to {_zq(dst_zone)} action {action} source address {src} service {service} "
            f"destination address {dst}",
            f"    name {_q(name)}",
            f"    priority manual {self.priority[key]}",
        ]
        if not enabled:
            self.rules.append("    no enable")
        self.rules.append("    exit")

    def _tails(self) -> None:
        """A rule that denies at the end of every pair of zones, where the model denies what no rule matches."""
        if not self.universe:
            return
        added = 0
        for src in self.universe:
            for dst in self.universe:
                if src == dst:
                    zone = self.p.zones.get(src)
                    if self.p.default_intrazone == Action.ALLOW or (zone is not None and zone.intrazone_allow):
                        continue
                elif self.p.default_interzone == Action.ALLOW:
                    continue
                for version in (4, 6):
                    if self.last_catch_all.get((src, dst, version)):
                        continue
                    name = self.names.unique(f"FWSHIFT {src} to {dst}" + (" v6" if version == 6 else ""), self.names.rule_names)
                    self._write_rule(name, version, src, dst, "deny", "any", "any", "any", True, True)
                    added += 1
        if added:
            self.report.note(
                Severity.INFO, "DEFAULT_DENY_ADDED",
                f"{added} rules that deny were added, one at the end of each pair of zones and IP version: SonicOS allows "
                "some traffic between zones by itself (from LAN to WAN, for example), and the source did not",
            )  # fmt: skip

    # -- NAT --------------------------------------------------------------------------------------

    def _interfaces(self, zones: List[str]) -> Optional[List[str]]:
        if ANY in zones:
            return ["any"]
        zone_map, interface_map = self.options.zone_map, self.options.interface_map
        out: List[str] = []
        for zone in zones:
            origins = [name for name in list(self.p.zones) + list(zone_map) if zone_map.get(name, name) == zone] or [zone]
            for origin in transform.dedupe(origins):
                held = self.p.zones[origin].interfaces if origin in self.p.zones else []
                for interface in held or [origin]:
                    if interface in interface_map:
                        out.append(interface_map[interface])
                    elif self.native and held:
                        out.append(interface)
                    else:
                        return None
        return transform.dedupe(out)

    def _object(self, members: List[str], version: int, what: str, problems: List[str]) -> Optional[str]:
        """The one object a NAT policy names for these addresses: "any", or an object that holds them."""
        if members in ([ANY], ["0.0.0.0/0"]):
            return "any"
        if len(members) == 1 and members[0] in self.kind and self.kind[members[0]][0] in ("ip", "builtin", "fqdn"):
            return f"name {_q(members[0])}"
        refs = [r for m in members for r in self._ref(m, version)]
        if _ANY in refs:
            return "any"
        if len(refs) == 1:
            kind = self.kind.get(refs[0], ("group", version))[0]
            return f"{'group' if kind == 'group' else 'name'} {_q(refs[0])}"
        if not refs:
            problems.append(f"the {what} has no IPv{version} address")
            return None
        name = self.names.unique(f"{self.options.object_prefix}nat {what[:3]} {len(self.nat)}", self.names.addresses)
        self._write_group(name, version, refs)
        self.kind[name] = ("group", version)
        return f"group {_q(name)}"

    def _translated(self, members: List[str], problems: List[str], what: str) -> Optional[str]:
        """A translation names one object: a host, a network or a range."""
        if len(members) == 1 and self.kind.get(members[0], ("", 0))[0] in ("ip", "builtin"):
            return f"name {_q(members[0])}"
        found: List[Interval] = []
        for member in members:
            resolved = transform.address_intervals(self.p, member)
            if resolved is None:
                problems.append(f"translated {what} {', '.join(members)} is not one address, network or range")
                return None
            found += resolved
        merged = normalize(found)
        if len(merged) != 1 or merged[0] in (FULL_V4, FULL_V6) or merged[0][0] != 4:
            problems.append(f"translated {what} {', '.join(members)} is not one IPv4 address, network or range")
            return None
        return f"name {_q(self._literal(merged[0]))}"

    def _port_service(self, nat: NatRule, port: str) -> Optional[str]:
        entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else None
        if not entries or not is_number(port):
            return None
        protocols = sorted({e.protocol.value.upper() for e in entries})
        if any(e.protocol not in (Protocol.TCP, Protocol.UDP) or e.src_ports or not is_number(e.dst_ports) for e in entries):
            return None
        if len({e.dst_ports for e in entries}) != 1 or len(protocols) != 1:
            return None
        if entries[0].dst_ports == port:
            return "original"
        key = (protocols[0], port)
        if key not in self.port_services:
            name = self.names.unique(f"{self.options.object_prefix}{protocols[0].lower()} {port}", self.names.services)
            self.services.append(f"service-object {_q(name)} {protocols[0]} {port} {port}")
            self.port_services[key] = name
        return f"name {_q(self.port_services[key])}"

    def _nat(self, nat: NatRule) -> None:
        item = self.report.item("nat", nat.origin)
        source, destination = nat.source_translation, nat.destination_translation
        members = nat.sources + nat.destinations + (source.addresses if source else []) + ([destination.address] if destination else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        named = [m for m in nat.sources + nat.destinations if m not in (ANY, "0.0.0.0/0", "::/0")]
        if any(6 in self._families(m) and 4 not in self._families(m) for m in named):
            self.report.skip("nat", nat.origin, "NAT_IPV6", "IPv6 NAT is not written")
            return
        src = self._object(nat.sources, 4, "source", problems)
        dst = self._object(nat.destinations, 4, "destination", problems)
        service = "any" if nat.service == ANY or nat.service in self.svc_any else self.svc_ref.get(nat.service)
        if service is None:
            problems.append(f"service '{nat.service}' could not be written")
        translated_source, translated_destination, translated_service = "original", "original", "original"
        if destination is not None:
            if destination.spread:
                problems.append(f"translation to one of several addresses ({destination.address}), which FWShift does not write for SonicOS")
            found = self._translated([destination.address], problems, "destination")
            translated_destination = found or "original"
            if destination.port:
                port = self._port_service(nat, destination.port)
                if port is None:
                    problems.append(f"translation to port {destination.port} needs a service of the rule that is one TCP or UDP port")
                else:
                    translated_service = port
        inbound = self._interfaces(nat.src_zones)
        outbound = ["any"] if destination is not None else self._interfaces(nat.dst_zones)
        if source is not None:
            if source.kind == SnatKind.INTERFACE:
                leaving = outbound or []
                interface = source.interface if source.interface in leaving else (leaving[0] if len(leaving) == 1 else "")
                if not interface or interface == "any" or not re.fullmatch(r"X[0-9]+(:V[0-9]+)?|U[0-9]+|W[0-9]+", interface):
                    problems.append("source NAT to the address of the outgoing interface needs one outgoing interface of SonicOS "
                                    "(X1, ...): name it with --interface-map")  # fmt: skip
                else:
                    translated_source = f"name {_q(interface + ' IP')}"
                    outbound = [interface]
            else:
                found = self._translated(source.addresses, problems, "source")
                translated_source = found or "original"
        if problems:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + "; ".join(transform.dedupe(problems)))
            return
        if inbound is None:
            self.report.add("nat", nat.origin, Severity.REVIEW if nat.sources == [ANY] else Severity.APPROX, "NAT_ZONES",
                            f"the rule applied to traffic from {', '.join(nat.src_zones)} only. A SonicOS NAT policy matches "
                            "interfaces, and the interfaces of that zone on the target are not known: written for any inbound "
                            "interface. Name them with --interface-map")  # fmt: skip
            inbound = ["any"]
        if outbound is None:
            self.report.add("nat", nat.origin, Severity.REVIEW if ANY in nat.destinations else Severity.APPROX, "NAT_ZONES",
                            f"the rule applied to traffic to {', '.join(nat.dst_zones)} only. A SonicOS NAT policy matches "
                            "interfaces, and the interfaces of that zone on the target are not known: written for any outbound "
                            "interface. Name them with --interface-map")  # fmt: skip
            outbound = ["any"]
        if destination is not None and ANY not in nat.dst_zones and ANY in nat.destinations:
            self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_DESTINATION_ZONE",
                            f"the rule applied to traffic on its way to zone {', '.join(nat.dst_zones)} only. A SonicOS NAT "
                            "policy that translates the destination cannot say where the traffic was going: it now translates "
                            "traffic to every destination")  # fmt: skip
        if source is not None and source.kind == SnatKind.DYNAMIC:
            self.report.add("nat", nat.origin, Severity.APPROX, "NAT_DYNAMIC_IP",
                            "translation to a pool without port translation becomes source NAT that shares the addresses")  # fmt: skip
        assert src is not None and dst is not None and service is not None
        count = 0
        for arriving in inbound:
            for departing in outbound:
                count += 1
                name = nat.name if count == 1 else self.names.unique(nat.name, self.names.nat_names)
                self._write_nat(name, arriving, departing, src, translated_source, dst, translated_destination, service, translated_service,
                                nat.enabled, nat.description or nat.name)  # fmt: skip
                item.emitted_as.append(name)
        if count > 1:
            self.report.add("nat", nat.origin, Severity.INFO, "RULE_SPLIT",
                            f"a SonicOS NAT policy names one inbound and one outbound interface: written as {count} policies")  # fmt: skip
        if source is not None and source.kind == SnatKind.STATIC and source.bidirectional:
            self._reverse(nat, outbound, translated_source)

    def _write_nat(self, name: str, inbound: str, outbound: str, src: str, trans_src: str, dst: str, trans_dst: str, service: str,
                   trans_service: str, enabled: bool, comment: str) -> None:  # fmt: skip
        self.unconfirmed.add("nat-policy name and comment")
        text = " ".join(_NOT_IN_COMMENT.sub(" ", comment).split())[:32].rstrip()  # no expression with a backslash in an f-string: Python 3.9
        self.nat += [
            f"nat-policy inbound {inbound} outbound {outbound} source {src} translated-source {trans_src} destination {dst} "
            f"translated-destination {trans_dst} service {service} translated-service {trans_service}",
            f"    name {_q(name)}",
            f"    comment {_q(text)}",
        ]
        if not enabled:
            self.nat.append("    no enable")
        self.nat.append("    exit")

    def _reverse(self, nat: NatRule, outbound: List[str], translated_source: str) -> None:
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is None:
            self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_BIDIRECTIONAL",
                            "bi-directional static NAT: the inbound direction could not be written and is missing")  # fmt: skip
            return
        inside, outside = pair
        name = self.names.unique(nat.name, self.names.nat_names, " in")
        self._write_nat(name, outbound[0] if outbound and outbound[0] != "any" else "any", "any", "any", "original",
                        f"name {_q(self._literal(outside))}", f"name {_q(self._literal(inside))}", "any", "original", nat.enabled,
                        f"inbound of {nat.name}")  # fmt: skip
        self.report.item("nat", nat.origin).emitted_as.append(name)
        self.report.add("nat", nat.origin, Severity.APPROX, "NAT_BIDIRECTIONAL",
                        f"bi-directional static NAT written as a source NAT policy plus policy '{name}' for the inbound direction")  # fmt: skip


__all__ = ["emit"]
