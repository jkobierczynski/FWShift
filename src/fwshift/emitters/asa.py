# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco ASA emitter: neutral model -> ASA configuration commands (9.x syntax).

Design rules:

* The zones are interface names (``nameif``). Every zone with rules of its own
  gets an access list, bound inbound; rules for traffic from any zone go into a
  global access list, which every interface falls back to. The global list ends
  the policy: with it bound no interface is left to the ASA's own "higher to
  lower security level" permit.
* An access list entry holds one source, one destination and one service:
  lists become object groups. It cannot negate: a negated address list is
  written as the addresses it leaves, which is exact.
* An entry cannot name the interface the traffic leaves by. A rule that needs
  that to stay as narrow as it was is written inactive, or - when it names
  destination addresses, which decide where traffic goes - without it, and
  reported.
* A rule that cannot be enforced is written ``inactive``; where an inactive
  entry would read as the opposite of the rule (a negation that cannot be
  written), only a remark is written.
* Access lists name the real address of a translated destination: rules are
  rewritten to it, as for every platform that looks policy up after NAT.
* NAT is written as twice NAT, in the order of the rules. A destination
  translation names its source side too, so that one rule applies to a
  connection, as in the model.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    L4_PROTOCOLS,
    Action,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    Service,
    ServiceEntry,
    SnatKind,
)
from ..names import ASA, ASA_NATIVE, ASA_TEXT, unique
from ..errors import FwshiftError
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text, normalize, overlaps
from ..netutil import parse_literal, size, subtract, within
from ..options import Options
from ..report import Report, Severity

_PLACEHOLDER = "FWSHIFT PLACEHOLDER, matches nothing: "
_PLACEHOLDER_HOST = "192.0.0.8"  # the IPv4 dummy address of RFC 7600: never a host, never a destination
_PLACEHOLDER_PROTOCOL = "255"  # reserved: no packet carries it
# Words of the command line that an object must not be called.
_RESERVED: FrozenSet[str] = frozenset(
    {"any", "any4", "any6", "interface", "host", "object", "object-group", "pat-pool", "source", "destination",
     "service", "static", "dynamic", "inactive", "description", "unidirectional"}
)  # fmt: skip
_PROTOCOL_NAMES = {1: "icmp", 2: "igmp", 4: "ipinip", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "icmp6",
                   88: "eigrp", 89: "ospf", 103: "pim", 132: "sctp"}  # fmt: skip
_NAMEIF = re.compile(r"[!-~]{1,48}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NOT_TEXT = re.compile(r"[^ -~]")
_MAX_NAT_LINES = 16  # NAT lines one rule may become (one per port of its service)

Problem = Tuple[str, str, Severity]
Finding = Tuple[Severity, str, str]


@dataclass
class _NatPlan:
    problem: Optional[Problem] = None
    lines: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    whole: bool = False  # written with a destination part: no other rule takes part in its connections
    interface_keyword: bool = False  # written with "interface" where the model holds the address of one


def zone_spaces(zone_networks: Dict[str, List[str]]) -> Dict[str, List[Interval]]:
    """The addresses behind each zone, as --zone-network gives them.

    Of two networks, one inside the other, the smaller one decides, as a route would: a zone may be
    given ``0.0.0.0/0`` for "everything that is not behind another zone".
    """
    listed = sorted(
        {(interval, zone) for zone, networks in zone_networks.items() for interval in map(parse_literal, networks) if interval},
        key=lambda item: (size(item[0]), item),
    )
    spaces: Dict[str, List[Interval]] = {zone: [] for zone in zone_networks}
    taken: List[Tuple[Interval, str]] = []
    for interval, zone in listed:
        for other, other_zone in taken:
            if other_zone != zone and overlaps([other], [interval]) and (other == interval or not within([other], [interval])):
                raise FwshiftError(
                    f"--zone-network: {interval_text(other)} of '{other_zone}' and {interval_text(interval)} of '{zone}' "
                    "overlap without one lying inside the other"
                )
        spaces[zone] += subtract([interval], [other for other, other_zone in taken if other_zone != zone])
        taken.append((interval, zone))
    return {zone: normalize(space) for zone, space in spaces.items()}


@dataclass
class _Areas:
    """What the networks given for the zones (--zone-network) tell about the zones of the ASA."""

    zones: Dict[str, List[Interval]] = field(default_factory=dict)  # the addresses behind each zone that was given networks
    nowhere: List[Interval] = field(default_factory=list)  # the addresses that lie in none of the networks
    squeezed: List[str] = field(default_factory=list)  # zones without networks, where the others leave no address
    full: List[int] = field(default_factory=list)  # the IP versions the networks cover entirely


def zone_areas(universe: List[str], spaces: Dict[str, List[Interval]]) -> _Areas:
    """Where addresses lie, by the networks given for the zones.

    Nothing is assumed about a zone that was given no networks, and nothing about an address
    that lies in none of them: a rule is only kept to its zones when every zone it has to be
    told apart from has networks, and then a permit rule leaves out the addresses nobody
    placed, and a deny rule keeps them.
    """
    areas = _Areas()
    if not spaces:
        return areas
    covered = normalize([interval for space in spaces.values() for interval in space])
    areas.zones = dict(spaces)
    areas.nowhere = subtract([FULL_V4, FULL_V6], covered)
    areas.full = [version for version in (4, 6) if not any(interval[0] == version for interval in areas.nowhere)]
    if areas.full:
        areas.squeezed = [zone for zone in universe if zone not in spaces]
    return areas


def _listing(intervals: List[Interval], limit: int = 4) -> str:
    words = ["every IPv4 address" if i == FULL_V4 else "every IPv6 address" if i == FULL_V6 else interval_text(i) for i in intervals]
    return ", ".join(words[:limit]) + (f" and {len(words) - limit} more" if len(words) > limit else "")


def emit(policy: Policy, report: Report, options: Options) -> str:
    if options.nat_zone and not valid_interface(options.nat_zone):
        raise FwshiftError(f"--target-nat-zone: '{options.nat_zone[:40]}' cannot be an interface name")
    zone_spaces(options.zone_networks)  # refuses networks that contradict each other
    p = copy.deepcopy(policy)
    zone_names = transform.dedupe([options.zone_map.get(name, name) for name in p.zones])
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    native = p.vendor == "asa"
    transform.sanitize_names(
        p,
        ASA_NATIVE if native else ASA,
        ASA_TEXT,
        report,
        reserved_addresses=_RESERVED,
        reserved_services=_RESERVED,
        one_namespace=True,
        prefix=options.object_prefix,
    )
    # Access lists see the real address of a translated destination. Rewrite the rules for the
    # translations that are really written.
    probe = _Emitter(p, Report(), options, zone_names)
    written = {nat.origin for nat in p.nat_rules if probe.nat_plan(nat).problem is None}
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, zone_names).run()


def valid_interface(name: str) -> bool:
    return bool(_NAMEIF.fullmatch(name)) and name not in _RESERVED and not any(char in "(),?" for char in name)


def _text(text: str, limit: int) -> str:
    """Free text on one line of configuration: printable ASCII, which is what the command line takes."""
    return " ".join(_NOT_TEXT.sub("?", _CONTROL.sub(" ", text)).split())[:limit].rstrip()


def _port_ops(ports: str) -> List[str]:
    """Port operators for a port list; "" stands for every port."""
    out: List[str] = []
    for part in ports.split(",") if ports else [""]:
        first, _, last = part.partition("-")
        low, high = (int(first), int(last or first)) if part else (0, 65535)
        if low == 0 and high == 65535:
            return [""]
        if low == high:
            out.append(f"eq {low}")
        elif low == 0:
            out.append(f"lt {high + 1}")
        elif high == 65535:
            out.append(f"gt {low - 1}")
        else:
            out.append(f"range {low} {high}")
    return transform.dedupe(out)


def _entry_parts(entry: ServiceEntry) -> List[Tuple[str, str, str]]:
    """(protocol, source port operator, destination port operator or ICMP type) per line an entry needs."""
    if entry.protocol in L4_PROTOCOLS:
        return [(entry.protocol.value, src, dst) for src in _port_ops(entry.src_ports) for dst in _port_ops(entry.dst_ports)]
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        tail = ""
        if entry.icmp_type is not None:
            tail = str(entry.icmp_type) + (f" {entry.icmp_code}" if entry.icmp_code is not None else "")
        return [(entry.protocol.value, "", tail)]
    if not entry.ip_protocol:
        return [("ip", "", "")]
    return [(_PROTOCOL_NAMES.get(entry.ip_protocol, str(entry.ip_protocol)), "", "")]


def _service_line(part: Tuple[str, str, str]) -> str:
    """A part as ``object service`` and ``service-object`` spell it."""
    protocol, src, dst = part
    if protocol in ("icmp", "icmp6"):
        return f"{protocol} {dst}".rstrip()
    return " ".join(word for word in (protocol, f"source {src}" if src else "", f"destination {dst}" if dst else "") if word)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, zone_names: List[str]) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "asa"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.names: Set[str] = set(p.addresses) | set(p.address_groups) | set(p.services) | set(p.service_groups) | _RESERVED
        self.objects: List[str] = []  # object and object-group definitions, in the order they are needed
        self.net_kind: Dict[str, str] = {}  # name -> "object" or "object-group"
        self.svc_kind: Dict[str, str] = {}
        self.by_value: Dict[Tuple[Interval, bool], str] = {}  # (addresses, as a range) -> object that holds them
        self.net_groups: Dict[Tuple[str, ...], str] = {}  # member lines -> group made for them
        self.svc_groups: Dict[Tuple[str, ...], str] = {}
        self.nat_services: Dict[Tuple[str, str, bool], str] = {}
        self.counter = {"NETWORK": 0, "SERVICE": 0, "RANGES": 0}
        self.app_services: Dict[str, str] = {}
        self.fqdn = False
        self.implied = False
        self.nat: List[str] = []
        self.tied: Set[str] = set()
        self.whole: Set[str] = set()
        # Every zone the policy knows: a rule whose destination zones are all the other ones is
        # a rule to any zone, for an ASA that never sends traffic back where it came from.
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe: List[str] = transform.dedupe(zone_names + used + list(options.zone_networks))
        self.spaces = zone_spaces(options.zone_networks)
        self.areas = zone_areas(self.universe, self.spaces)
        self.gap_used = False  # a rule was kept to its zones where the networks given leave addresses out
        self.strangers = [zone for zone in options.zone_networks if zone not in zone_names + used]
        self._define_addresses()
        self._define_services()

    # -- objects ----------------------------------------------------------

    def _new_name(self, label: str) -> str:
        return unique(self.options.object_prefix + label, self.names, ASA)

    def _auto(self, kind: str) -> str:
        self.counter[kind] += 1
        return self._new_name(f"FWSHIFT_{kind}_{self.counter[kind]}")

    def _placeholder(self, name: str, reason: str) -> None:
        self.objects += [f"object network {name}", f" host {_PLACEHOLDER_HOST}", f" description {_text(_PLACEHOLDER + reason, 200)}"]
        self.net_kind[name] = "object"

    def _define_addresses(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            if address.kind == AddressKind.UNSUPPORTED:
                self._placeholder(name, address.raw or "unsupported address type")
                continue
            description = [f" description {_text(address.description, 200)}"] if address.description.strip() else []
            if address.kind == AddressKind.FQDN:
                self.fqdn = True
                if address.fqdn_family:
                    self.objects += [f"object network {name}", f" fqdn v{address.fqdn_family} {address.value}"] + description
                    self.net_kind[name] = "object"
                    continue
                # An ASA resolves a name for one IP version per object: two objects and a group.
                members = []
                for version in (4, 6):
                    member = unique(f"{name}-v{version}", self.names, ASA)
                    self.objects += [f"object network {member}", f" fqdn v{version} {address.value}"]
                    members.append(member)
                self.objects += [f"object-group network {name}"] + description
                self.objects += [f" network-object object {member}" for member in members]
                self.net_kind[name] = "object-group"
                continue
            interval = parse_literal(address.value)
            assert interval is not None, address.value  # transform.harden saw to that
            is_range = address.kind == AddressKind.RANGE
            self.objects += [f"object network {name}", " " + self._value_line(interval, is_range)] + description
            self.net_kind[name] = "object"
            self.by_value.setdefault((interval, is_range), name)
        for group in transform.topo_groups(self.p.address_groups):
            if transform.is_placeholder_group(group):
                self._placeholder(group.name, self.taint_a.get(group.name, "unconvertible group"))
                continue
            lines = [f"object-group network {group.name}"]
            if group.description.strip():
                lines.append(f" description {_text(group.description, 200)}")
            members = transform.dedupe([line for member in group.members for line in self._member_lines(member)])
            if not members:
                # Nothing but itself, or members that are nothing: an ASA takes no group without members.
                self.taint_a[group.name] = "address group without usable members"
                self._placeholder(group.name, self.taint_a[group.name])
                continue
            self.objects += lines + [f" {member}" for member in members]
            self.net_kind[group.name] = "object-group"

    @staticmethod
    def _value_line(interval: Interval, is_range: bool) -> str:
        version, first, last = interval
        if is_range:
            return f"range {int_to_ip(version, first)} {int_to_ip(version, last)}"
        if first == last:
            return f"host {int_to_ip(version, first)}"
        network = ipaddress.ip_network(f"{int_to_ip(version, first)}/{(32 if version == 4 else 128) - (last - first).bit_length()}")
        return f"subnet {network.network_address} {network.netmask}" if version == 4 else f"subnet {network.compressed}"

    def _value_object(self, interval: Interval, is_range: bool) -> str:
        """An object for addresses that the model gives as a literal."""
        key = (interval, is_range)
        if key not in self.by_value:
            version, first, last = interval
            if is_range:
                label = f"r-{int_to_ip(version, first)}-{int_to_ip(version, last)}"
            elif first == last:
                label = f"h-{int_to_ip(version, first)}"
            else:
                bits = (32 if version == 4 else 128) - (last - first).bit_length()
                label = f"n-{int_to_ip(version, first)}_{bits}"
            name = self._new_name(label)
            self.objects += [f"object network {name}", " " + self._value_line(interval, is_range)]
            self.net_kind[name] = "object"
            self.by_value[key] = name
        return self.by_value[key]

    @staticmethod
    def _is_block(interval: Interval) -> bool:
        """Whether the addresses are one host or one subnet."""
        count = size(interval)
        return count & (count - 1) == 0 and interval[1] % count == 0

    def _inline(self, member: str) -> Optional[str]:
        """A literal as an access list entry or a group member spells it; None if it needs an object."""
        interval = parse_literal(member)
        if interval is None or ("-" in member and "/" not in member) or not self._is_block(interval):
            return None
        version, first, last = interval
        if first == last:
            return f"host {int_to_ip(version, first)}"
        if version == 4:
            return f"{int_to_ip(4, first)} {int_to_ip(4, 2**32 - 1 - (last - first))}"
        return f"{int_to_ip(6, first)}/{128 - (last - first).bit_length()}"

    def _literal_object(self, member: str) -> str:
        interval = parse_literal(member)
        assert interval is not None, member
        return self._value_object(interval, ("-" in member and "/" not in member) or not self._is_block(interval))

    def _member_lines(self, member: str) -> List[str]:
        """The lines that put a member into a network object group."""
        if member in self.net_kind:
            return [f"group-object {member}" if self.net_kind[member] == "object-group" else f"network-object object {member}"]
        if member in (ANY, ANY_V4, ANY_V6):
            lines = ["network-object 0.0.0.0 0.0.0.0", "network-object ::/0"]
            return lines if member == ANY else lines[:1] if member == ANY_V4 else lines[1:]
        if parse_literal(member) is None:
            return []  # a group that is not written yet: one that holds itself, which adds nothing to it
        inline = self._inline(member)
        return [f"network-object {inline}" if inline else f"network-object object {self._literal_object(member)}"]

    def _network_group(self, members: Sequence[str], description: str, kind: str = "NETWORK") -> str:
        """The object group for a list of addresses that a rule spells out."""
        lines = tuple(transform.dedupe([line for member in members for line in self._member_lines(member)]))
        if lines not in self.net_groups:
            name = self._auto(kind)
            self.objects += [f"object-group network {name}", f" description {_text(description, 200)}"]
            self.objects += [f" {line}" for line in lines]
            self.net_kind[name] = "object-group"
            self.net_groups[lines] = name
        return self.net_groups[lines]

    def _address(self, member: str) -> str:
        """One address, as an access list entry names it."""
        if member in self.net_kind:
            return f"{self.net_kind[member]} {member}"
        if member == ANY_V4:
            return "any4"
        if member == ANY_V6:
            return "any6"
        return self._inline(member) or f"object {self._literal_object(member)}"

    # -- services ---------------------------------------------------------

    def _define_services(self) -> None:
        for service in self.p.services.values():
            if service.builtin != "asa":  # those an access list entry spells out by itself
                self._define_service(service)
        for group in transform.topo_groups(self.p.service_groups):
            if not group.members:
                self._placeholder_service(group.name, "empty service group")
                continue
            lines = [f"object-group service {group.name}"]
            if group.description.strip():
                lines.append(f" description {_text(group.description, 200)}")
            members = [line for member in transform.dedupe(group.members) for line in self._service_member_lines(member)]
            if not members:
                self.taint_s[group.name] = "service group without usable members"
                self._placeholder_service(group.name, self.taint_s[group.name])
                continue
            self.objects += lines + [f" {line}" for line in members]
            self.svc_kind[group.name] = "object-group"

    def _placeholder_service(self, name: str, reason: str) -> None:
        self.objects += [f"object service {name}", f" service {_PLACEHOLDER_PROTOCOL}", f" description {_text(_PLACEHOLDER + reason, 200)}"]
        self.svc_kind[name] = "object"

    def _define_service(self, service: Service) -> None:
        name = service.name
        if name in self.svc_kind:
            return
        if not service.entries or service.unsupported:
            self._placeholder_service(name, service.unsupported or "unsupported or undefined service")
            return
        parts = transform.dedupe([_service_line(part) for entry in service.entries for part in _entry_parts(entry)])
        description = [f" description {_text(service.description, 200)}"] if service.description.strip() else []
        if len(parts) == 1:
            self.objects += [f"object service {name}", f" service {parts[0]}"] + description
            self.svc_kind[name] = "object"
        else:
            self.objects += [f"object-group service {name}"] + description + [f" service-object {part}" for part in parts]
            self.svc_kind[name] = "object-group"

    def _service_member_lines(self, member: str) -> List[str]:
        """Lines that put a service into a service object group."""
        service = self.p.services.get(member)
        if service is not None and service.builtin == "asa" and service.entries and not service.unsupported:
            return [f"service-object {_service_line(part)}" for entry in service.entries for part in _entry_parts(entry)]
        if service is not None:
            self._define_service(service)
        if member not in self.svc_kind:
            return []  # a group that is not written yet: one that holds itself, which adds nothing to it
        return [f"group-object {member}" if self.svc_kind[member] == "object-group" else f"service-object object {member}"]

    def _app_service(self, app: str, entries: List[ServiceEntry]) -> str:
        if app not in self.app_services:
            service = Service(self._new_name(f"app-{app}"), entries, f"well-known ports of application {app}")
            self._define_service(service)
            self.app_services[app] = service.name
        return self.app_services[app]

    def _service(self, rule: Rule, reasons: List[transform.Reason]) -> Tuple[str, str, str]:
        """(protocol or service object, source port, destination port or ICMP type) of the entry for a rule."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            names = [self._app_service(app, entries) for app, entries in lowered]
        else:
            names = list(rule.services)
        if not names or ANY in names:
            return "ip", "", ""
        if len(names) == 1:
            service = self.p.services.get(names[0])
            if service is not None and service.builtin == "asa" and len(service.entries) == 1 and not service.unsupported:
                parts = _entry_parts(service.entries[0])
                if len(parts) == 1:
                    return parts[0]
            if service is not None:
                self._define_service(service)
            return f"{self.svc_kind.get(names[0], 'object')} {names[0]}", "", ""
        lines = tuple(transform.dedupe([line for name in names for line in self._service_member_lines(name)]))
        if lines not in self.svc_groups:
            group = self._auto("SERVICE")
            self.objects += [f"object-group service {group}", f" description {_text('services of rule ' + rule.name, 200)}"]
            self.objects += [f" {line}" for line in lines]
            self.svc_kind[group] = "object-group"
            self.svc_groups[lines] = group
        return f"object-group {self.svc_groups[lines]}", "", ""

    # -- security rules ---------------------------------------------------

    def _ranges(self, left: List[Interval], description: str) -> str:
        """Address ranges, as an access list entry names them."""
        if FULL_V4 in left and FULL_V6 in left:
            return "any"
        members = [
            ANY_V4 if i == FULL_V4 else ANY_V6 if i == FULL_V6 else self._value_object(i, not self._is_block(i))
            for i in left
        ]
        if len(members) == 1:
            return self._address(members[0])
        return f"object-group {self._network_group(members, description, 'RANGES')}"

    def _side(
        self, rule: Rule, source: bool, reasons: List[transform.Reason], limit: Optional[List[Interval]] = None
    ) -> Optional[str]:
        """The source or destination of the entry for a rule; None when it can match nothing.

        ``limit`` keeps a destination to the zones of the rule: the addresses to leave out of it,
        from the networks given for the zones.
        """
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        what = "source" if source else "destination"
        everything = ANY in members or (ANY_V4 in members and ANY_V6 in members)
        resolved = [transform.known_intervals(self.p, member) for member in members]
        listed = normalize([interval for intervals, _ in resolved for interval in intervals])
        static = all(complete for _, complete in resolved) and not any(member in self.taint_a for member in members)
        if negated and not static:
            reasons.append(
                ("NEGATION_NOT_STATIC", f"negated {what} with a member that has no fixed addresses (a host name): an "
                 "access list cannot negate, and what such a list leaves cannot be written out")  # fmt: skip
            )
            return "any"
        description = f"{what} of rule {rule.name}"
        if negated:
            left = subtract([FULL_V4, FULL_V6], listed)
            description = f"everything but the {what} of rule {rule.name}"
            if left:
                self.report.add(
                    "rule",
                    rule.origin,
                    Severity.INFO,
                    "NEGATION_EXPANDED",
                    f"an access list cannot negate: the negated {what} is written as the {len(left)} address "
                    f"range{'s' if len(left) != 1 else ''} it leaves",
                )
        elif everything:
            left = [FULL_V4, FULL_V6]
        else:
            left = listed
        if limit and (negated or everything or static):
            cut = subtract(left, limit)
            if cut != normalize(left):
                left, negated = cut, True  # no longer the objects the rule names
                description += ", kept to the networks of its zones"
        if not negated:
            if everything:
                return "any"
            if len(members) == 1:
                return self._address(members[0])
            return f"object-group {self._network_group(members, description)}"
        return self._ranges(left, description) if left else None

    def _egress(
        self, rule: Rule, pairs: List[Tuple[str, List[str]]], reasons: List[transform.Reason]
    ) -> Dict[str, List[Interval]]:
        """Deal with destination zones: an access list entry cannot name the interface traffic leaves by.

        Returns, per source zone, the addresses to leave out of the destination to keep the rule to
        its zones, by the networks the user gave (--zone-network), where that is needed and can be done.

        Where the networks do not tell, the side that allows less is taken: a permit rule leaves
        out the addresses that lie in no network given, a deny rule keeps them.
        """
        if rule.egress_implied:
            self.implied = True
            return {}
        intervals = [i for member in rule.destinations for i in transform.known_intervals(self.p, member)[0]]
        complete = all(transform.known_intervals(self.p, member)[1] for member in rule.destinations)
        named = not rule.negate_destination and ANY not in rule.destinations and FULL_V4 not in intervals and FULL_V6 not in intervals
        allow = rule.action == Action.ALLOW
        areas = self.areas
        limits: Dict[str, List[Interval]] = {}
        unknown: List[str] = []
        wanted: List[str] = []
        for source, dst_zones in pairs:
            if rule.scope == RuleScope.INTRAZONE:
                reached = [source]
            elif ANY not in dst_zones:
                reached = dst_zones
            elif rule.scope == RuleScope.INTERZONE:
                reached = [zone for zone in self.universe if zone != source]
            else:
                continue
            others = [zone for zone in self.universe if zone not in reached and zone != source]
            away = normalize([i for zone in self.universe if zone not in reached for i in areas.zones.get(zone, [])])
            if not others:
                # Every other zone: an entry for any destination says the same, as the ASA does not
                # send traffic back where it came from. Where it does, the networks of the zone keep it
                # out; but only when every zone has networks, or one of them may lie inside those.
                everywhere = all(zone in areas.zones for zone in self.universe)
                if everywhere and away and complete and overlaps(intervals if named else [FULL_V4, FULL_V6], away):
                    limits[source] = away
                continue
            missing = [zone for zone in others + reached if zone not in areas.zones]
            if missing or (named and not complete):
                # Nothing is known of a zone without networks; and a host name has no addresses to compare.
                unknown += missing
                wanted += reached
                continue
            to = "zone " + ", ".join(reached)
            extra, severity = "", Severity.INFO
            if named:
                if overlaps(subtract(intervals, away), areas.nowhere):
                    self.report.add(
                        "rule",
                        rule.origin,
                        Severity.APPROX,
                        "EGRESS_INTERFACE",
                        f"the rule is for traffic to {to}, and part of its destination lies in none of the networks "
                        "given with --zone-network. An ASA access list cannot name the interface traffic leaves by: "
                        "for those addresses the entry applies by whatever interface they are reached",
                    )
                if not overlaps(intervals, away):
                    continue  # the destination lies where the rule is for as it is
                limits[source] = away
            else:
                # Any address: what nobody placed is left to the side that allows less.
                limits[source] = normalize(away + areas.nowhere) if allow else away
                if areas.nowhere:
                    self.gap_used = True
                    severity = Severity.APPROX
                    extra = (
                        ", and the addresses that lie in none of the networks given" if allow
                        else ". The addresses that lie in none of the networks given are denied by it as well"
                    )  # fmt: skip
                if not limits[source]:
                    del limits[source]
                    continue
            self.report.add(
                "rule",
                rule.origin,
                severity,
                "EGRESS_BY_NETWORKS",
                f"the rule is for traffic to {to}. An ASA access list cannot name the interface traffic leaves by: "
                f"the destination leaves out the networks given for the other zones (--zone-network){extra}",
            )
        hairpin = ""
        if rule.scope == RuleScope.INTRAZONE:
            hairpin = (
                " An ASA sends traffic back out of the interface it came in on only with 'same-security-traffic "
                "permit intra-interface'."
            )
            if not wanted:
                self.report.add("rule", rule.origin, Severity.APPROX, "EGRESS_INTERFACE", "the rule is for traffic inside one zone." + hairpin)
        if not wanted:
            return limits
        zones = ", ".join(transform.dedupe(wanted))
        inside = "inside one zone" if rule.scope == RuleScope.INTRAZONE else f"that leaves by {zones}"
        hint = ""
        if unknown:
            hint = " Or name the networks behind " + ", ".join(transform.dedupe(unknown)) + " with --zone-network."
        if named:
            self.report.add(
                "rule",
                rule.origin,
                Severity.APPROX,
                "EGRESS_INTERFACE",
                f"the rule is for traffic {inside}. An ASA access list cannot name the interface traffic leaves by: "
                "the entry applies to its destination addresses by whatever interface they are reached." + hairpin,
            )
        else:
            reasons.append(
                ("EGRESS_INTERFACE", (f"the rule is for traffic {inside}, to any address. An ASA access list cannot "
                 "name the interface traffic leaves by: give the rule the networks behind it as destination."
                 + hint + hairpin).rstrip("."))  # fmt: skip
            )
        return limits

    def _negation_leaves_nothing(self, rule: Rule) -> bool:
        if not rule.negate_destination:
            return False
        listed = [i for member in rule.destinations for i in transform.known_intervals(self.p, member)[0]]
        return ANY in rule.destinations or not subtract([FULL_V4, FULL_V6], listed)

    def _rule(self, rule: Rule) -> List[Tuple[str, List[str]]]:
        """The lines of a rule per access list it goes into: (zone, lines), with "any" for the global list."""
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(
                ("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted")
            )
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service match does not exist in an ASA access list"))
        if rule.scope == RuleScope.INTRAZONE:
            if ANY in rule.src_zones:
                reasons.append(("RULE_TYPE", "intrazone rule with 'any' zone cannot be written per interface"))
            pairs = [(zone, [zone]) for zone in rule.src_zones]
        elif rule.scope == RuleScope.INTERZONE:
            # What every ASA rule is: traffic never leaves by the interface it came in on.
            pairs = [(zone, [other for other in rule.dst_zones if other == ANY or other != zone]) for zone in rule.src_zones]
            pairs = [(zone, dst_zones) for zone, dst_zones in pairs if dst_zones]
        else:
            pairs = [(zone, rule.dst_zones) for zone in rule.src_zones]
        if not pairs:
            self.report.skip(
                "rule",
                rule.origin,
                "RULE_TYPE_EMPTY",
                "interzone rule whose zones leave no pair of different zones: it matches nothing",
                Severity.INFO,
            )
            return []
        bad = [zone for zone in rule.src_zones if zone != ANY and not valid_interface(zone)]
        if bad:
            reasons.append(
                ("INTERFACE_NAME", "'" + "', '".join(bad) + "' cannot be an interface name; map it with --zone-map")
            )
        limits = self._egress(rule, pairs, reasons)
        source = self._side(rule, True, reasons)
        zones = transform.dedupe([ANY if zone == ANY or zone in bad else zone for zone, _ in pairs])
        everywhere = (
            rule.egress_implied and rule.scope == RuleScope.INTERZONE and set(rule.src_zones) == set(self.universe)
        )  # what the parser makes of an entry in a global access list
        if ANY in zones or everywhere:
            zones = [ANY]
        destinations = {zone: self._side(rule, False, reasons, limits.get(zone)) for zone in zones}
        allow = rule.action == Action.ALLOW
        emptied = [] if self._negation_leaves_nothing(rule) else [z for z in zones if destinations[z] is None and z in limits]
        zones = [zone for zone in zones if destinations[zone] is not None]
        # Leaving a deny rule out is what a wrong network would do harm with: that is for a person to look at.
        severity = Severity.APPROX if allow else Severity.REVIEW
        nothing = "by the networks given with --zone-network no address of its destination lies behind the zones the rule is for"
        if source is not None and emptied and zones:
            self.report.add(
                "rule",
                rule.origin,
                severity,
                "EGRESS_NO_ADDRESS",
                f"from {', '.join(emptied)}: {nothing}. No entry is written for that",
            )
        elif source is not None and emptied:
            self.report.skip("rule", rule.origin, "EGRESS_NO_ADDRESS", f"{nothing}: it is left out", severity)
            return []
        if source is None or not zones:
            self.report.skip(
                "rule",
                rule.origin,
                "NO_COMMON_FAMILY",
                "a negation leaves no address: the rule matches nothing and is left out",
                Severity.INFO,
            )
            return []
        protocol, src_ports, dst_ports = self._service(rule, reasons)
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "RESET_ACTION",
                f"action {rule.action.value} becomes deny; an ASA resets denied TCP connections only with 'service "
                "resetinbound' or 'service resetoutside'",
            )
        reasons = [reason for index, reason in enumerate(reasons) if reason not in reasons[:index]]
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        # An inactive entry for a negation that could not be written would read as its opposite.
        remark_only = any(code in ("NEGATION_NOT_STATIC", "SERVICE_NEGATE") for code, _ in reasons)
        label = "" if self.native else rule.name
        remark = ": ".join(text for text in (label, _text(rule.description, 100)) if text)
        out: List[Tuple[str, List[str]]] = []
        for zone in zones:
            lines: List[str] = []
            if remark_only:
                lines.append(_text(f"remark FWSHIFT not converted, see the report: {rule.name}", 107))
            else:
                if reasons:
                    lines.append("remark FWSHIFT: inactive, see the conversion report")
                if remark:
                    lines.append(f"remark {_text(remark, 100)}")
                words = ["extended", "permit" if allow else "deny", protocol, source, src_ports, destinations[zone], dst_ports]
                if allow and (rule.log_end or rule.log_start):
                    words.append("log")
                elif not allow and not rule.log_end and not rule.log_start:
                    words.append("log disable")
                if reasons or not rule.enabled:
                    words.append("inactive")
                lines.append(" ".join(word for word in words if word))
            out.append((zone, lines))
        item.emitted_as = [self._acl(zone) for zone in zones]
        return out

    def _acl(self, zone: str) -> str:
        prefix = self.options.object_prefix
        return f"{prefix}global_access" if zone == ANY else f"{prefix}{zone}_access_in"

    def _access_lists(self) -> Tuple[List[str], List[str]]:
        """(access list lines, access-group lines)."""
        placed = [dict(self._rule(rule)) for rule in self.p.rules]
        last: Dict[str, int] = {}
        for index, by_zone in enumerate(placed):
            for zone in by_zone:
                if zone != ANY:
                    last[zone] = index
        out: List[str] = []
        groups: List[str] = []
        for zone in transform.dedupe([zone for by_zone in placed for zone in by_zone if zone != ANY]):
            # Rules for every zone that stand above a rule of this zone come first here too: the
            # ASA reads the list of the interface before the global one.
            acl = self._acl(zone)
            for by_zone in placed[: last[zone] + 1]:
                out += [f"access-list {acl} {line}" for line in by_zone.get(zone, by_zone.get(ANY, []))]
            groups.append(f"access-group {acl} in interface {zone}")
        acl = self._acl(ANY)
        out += [f"access-list {acl} {line}" for by_zone in placed for line in by_zone.get(ANY, [])]
        final = self.p.rules[-1] if self.p.rules else None
        closed = (
            final is not None and final.enabled and not final.unsupported and final.action != Action.ALLOW
            and final.scope == RuleScope.UNIVERSAL and ANY in final.src_zones and ANY in final.dst_zones
            and ANY in final.sources and ANY in final.destinations and final.services == [ANY]
            and final.applications == [ANY] and not (final.negate_source or final.negate_destination or final.negate_service)
            and not self.report.item("rule", final.origin).disabled
        )  # fmt: skip
        if self.p.default_interzone == Action.ALLOW:
            out += [f"access-list {acl} remark FWSHIFT: the source accepts what no rule matches",
                    f"access-list {acl} extended permit ip any any"]  # fmt: skip
        elif not closed:
            out += [f"access-list {acl} remark FWSHIFT: nothing else is allowed",
                    f"access-list {acl} extended deny ip any any"]  # fmt: skip
        groups.append(f"access-group {acl} global")
        return out, groups

    # -- NAT --------------------------------------------------------------

    def _nat_object(self, members: List[str]) -> Optional[str]:
        """Object or object group for the addresses of a NAT rule; None unless they are static addresses."""
        if any(transform.address_intervals(self.p, member) is None for member in members):
            return None
        if any(member not in self.net_kind and parse_literal(member) is None for member in members):
            return None  # "any" where an address has to stand
        if len(members) > 1:
            return self._network_group(members, "addresses of a NAT rule")
        member = members[0]
        if member in self.net_kind:
            address = self.p.addresses.get(member)
            return None if address is not None and address.kind == AddressKind.FQDN else member
        return self._literal_object(member)

    def _pool_object(self, members: List[str]) -> Optional[str]:
        """Hosts and ranges to translate to: a pool may not hold a subnet."""
        intervals: List[Interval] = []
        for member in members:
            resolved = transform.address_intervals(self.p, member)
            if resolved is None:
                return None
            intervals += resolved
        objects = [self._value_object(interval, size(interval) > 1) for interval in normalize(intervals)]
        if len(objects) == 1:
            return objects[0]
        return self._network_group(objects, "addresses a NAT rule translates to") if objects else None

    def _nat_service(self, protocol: str, ports: str, source: bool) -> str:
        key = (protocol, ports, source)
        if key not in self.nat_services:
            side = "source" if source else "destination"
            line = f"{protocol} {side} {_port_ops(ports)[0]}"
            existing = next(
                (name for name, service in self.p.services.items() if self.svc_kind.get(name) == "object"
                 and not service.unsupported and len(service.entries) == 1
                 and [_service_line(part) for part in _entry_parts(service.entries[0])] == [line]),
                None,
            )  # fmt: skip
            if existing is None:
                existing = self._new_name(f"{protocol}-{'src-' if source else ''}{ports}")
                self.objects += [f"object service {existing}", f" service {line}"]
                self.svc_kind[existing] = "object"
            self.nat_services[key] = existing
        return self.nat_services[key]

    def _mapped_interface(self, nat: NatRule, zone: str) -> str:
        """The interface whose address a rule translates to ("NAT to the outgoing interface"), or "" if unknown."""
        translation = nat.source_translation
        assert translation is not None
        if zone != ANY and nat.destination_translation is None:
            return zone
        for name, known in self.p.zones.items():
            if translation.interface and (translation.interface in known.interfaces or translation.interface == name):
                mapped = self.options.zone_map.get(name, name)
                if valid_interface(mapped):
                    return mapped
        # An object with the address the interface has today is no way out: an ASA refuses NAT to an
        # address of its own that is not written as "interface".
        return self.options.nat_zone

    def _interface_of(self, member: str) -> str:
        """The interface whose address an object of an ASA source stands for, as the target names it."""
        address = self.p.addresses.get(member)
        if address is None or address.builtin != "asa" or not address.raw.startswith("interface "):
            return ""
        nameif = address.raw.partition(" ")[2]
        mapped = self.options.zone_map.get(nameif, nameif)
        return mapped if valid_interface(mapped) else ""

    def nat_plan(self, nat: NatRule) -> _NatPlan:
        """The twice NAT lines for a rule, or why it cannot be written. Nothing is reported from here."""
        plan = _NatPlan()
        source, destination = nat.source_translation, nat.destination_translation

        def fail(code: str, message: str) -> _NatPlan:
            plan.problem = (code, message, Severity.REVIEW)
            return plan

        members = nat.sources + nat.destinations
        members = members + (source.addresses if source else []) + ([destination.address] if destination else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        bad = [z for z in nat.src_zones + nat.dst_zones if z != ANY and not valid_interface(z)]
        if bad:
            problems.append("'" + "', '".join(bad) + "' cannot be an interface name; map it with --zone-map")
        if problems:
            return fail("NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
        lists = [nat.sources, nat.destinations, source.addresses if source else [], [destination.address] if destination else []]
        for listed in lists:
            versions = {i[0] for member in listed if member != ANY for i in transform.address_intervals(self.p, member) or []}
            if len(versions) > 1:
                return fail("NAT_ADDRESSES", "an ASA takes no object group with IPv4 and IPv6 addresses in a NAT rule")
        everyone = ANY in nat.sources or ANY_V4 in nat.sources
        real = "any" if everyone else self._nat_object(nat.sources)
        if real is None:
            return fail("NAT_ADDRESSES", "the rule needs static addresses as source")
        # The service: one NAT line per port, each with a service object for the port before and after.
        ports: List[Tuple[str, str]] = []  # (protocol, port or range)
        if nat.service != ANY:
            entries = transform.flatten_services(self.p, nat.service) or []
            if not entries or any(e.protocol not in L4_PROTOCOLS or e.src_ports for e in entries):
                return fail("NAT_SERVICE", f"service '{nat.service}' is not a TCP, UDP or SCTP service without source ports")
            for entry in entries:
                ports += [(entry.protocol.value, part) for part in (entry.dst_ports or "0-65535").split(",")]
            ports = [pair for index, pair in enumerate(ports) if pair not in ports[:index]]
            if any(_port_ops(part) == [""] for _, part in ports):
                return fail("NAT_SERVICE", f"service '{nat.service}' covers every port of a protocol; a NAT rule names ports")
            if len(ports) > _MAX_NAT_LINES:
                return fail("NAT_SERVICE", f"service '{nat.service}' has {len(ports)} ports or ranges; write the rule by hand")
        if destination is not None and destination.port:
            if not ports:
                return fail("NAT_PORT", "a port translation needs a TCP, UDP or SCTP service on the rule")
            if any("-" in part for _, part in ports):
                return fail("NAT_PORT", "a port range cannot be translated to one port")
        pre = post = ""
        if destination is not None:
            one_address = len(nat.destinations) == 1 and ANY not in nat.destinations and destination.address != ANY
            pre_object = self._nat_object(nat.destinations) if one_address else None
            post_object = self._nat_object([destination.address]) if one_address else None
            if pre_object is None or post_object is None:
                return fail("NAT_DESTINATION", "destination NAT needs one static address object on each side")
            pre, post = pre_object, post_object
        elif ANY not in nat.destinations and ANY_V4 not in nat.destinations:
            same = self._nat_object(nat.destinations)
            if same is None:
                return fail("NAT_ADDRESSES", "the rule needs static addresses as destination")
            pre = post = same
        # A published port of a source that applies NAT rules of both directions together is written
        # the way an ASA does it: from the side of the server, so that source NAT rules still apply.
        server_side = (
            destination is not None and source is None and nat.combines and everyone and bool(ports)
        )
        plan.whole = bool(pre) and not server_side
        # The address of an interface of an ASA source: on an ASA that is the word "interface", and
        # only where the rule also translates a port and comes in on that interface.
        own_interface = self._interface_of(nat.destinations[0]) if destination is not None and ports else ""
        flags = "" if nat.enabled else " inactive"
        label = nat.description if self.native else f"{nat.name} {nat.description}"
        if label.strip():
            flags += f" description {_text(label, 200)}"
        for src_zone in nat.src_zones:
            for dst_zone in [ANY] if destination is not None else nat.dst_zones:
                mapped_if = dst_zone
                if source is None and destination is None:
                    # No translation: as an ASA writes an exemption, without answering ARP for the addresses.
                    kind, mapped = "static", real
                    tail = " no-proxy-arp" + (" route-lookup" if ANY not in (src_zone, dst_zone) else "")
                elif source is None:
                    # A static rule works both ways on an ASA; the model's translates the destination only.
                    kind, mapped, tail = "static", real, " unidirectional"
                elif source.kind == SnatKind.INTERFACE:
                    mapped_if = self._mapped_interface(nat, dst_zone)
                    if not mapped_if:
                        return fail("NAT_NOT_CONVERTED", "not converted: source NAT to the address of the outgoing "
                                    "interface, which the rule does not name; give it with --target-nat-zone")  # fmt: skip
                    kind, mapped, tail = "dynamic", "interface", ""
                else:
                    pool = source.kind in (SnatKind.DYNAMIC_PORT, SnatKind.DYNAMIC)
                    found = self._pool_object(source.addresses) if pool else self._nat_object(source.addresses)
                    if found is None or not source.addresses:
                        return fail("NAT_POOL", "the translated addresses are not static addresses")
                    intervals = [i for m in source.addresses for i in transform.address_intervals(self.p, m) or []]
                    one = sum(size(i) for i in normalize(intervals)) == 1
                    kind, tail = ("static", "") if source.kind == SnatKind.STATIC else ("dynamic", "")
                    mapped = found
                    if source.kind == SnatKind.DYNAMIC_PORT and not one:
                        mapped = f"pat-pool {found}"
                    elif source.kind == SnatKind.DYNAMIC and one:
                        plan.findings.append(
                            (Severity.APPROX, "NAT_DYNAMIC_ONE_ADDRESS", "dynamic NAT to one address: an ASA shares "
                             "that address by translating ports, where the source gave it to one host at a time")  # fmt: skip
                        )
                    if source.kind == SnatKind.STATIC and not source.bidirectional:
                        tail = " unidirectional"
                    if source.kind == SnatKind.STATIC and real != "any":
                        inside = sum(size(i) for m in nat.sources for i in transform.address_intervals(self.p, m) or [])
                        outside = sum(size(i) for i in normalize(intervals))
                        if inside != outside:
                            plan.findings.append(
                                (Severity.APPROX, "NAT_STATIC_SIZE", f"static NAT of {inside} addresses to {outside}: "
                                 "an ASA maps them in order and wraps around; check the mapping")  # fmt: skip
                            )
                seen = pre
                if own_interface and own_interface == src_zone:
                    seen, plan.interface_keyword = "interface", True
                for protocol, port in ports or [("", "")]:
                    if server_side:
                        assert destination is not None
                        real_port = destination.port or port
                        service = f" service {self._nat_service(protocol, real_port, True)} {self._nat_service(protocol, port, True)}"
                        line = f"nat (any,{src_zone}) source static {post} {seen}{service}"
                    else:
                        line = f"nat ({src_zone},{mapped_if}) source {kind} {real} {mapped}"
                        if pre:
                            line += f" destination static {seen} {post}"
                        if protocol:
                            new_port = destination.port if destination is not None and destination.port else port
                            line += f" service {self._nat_service(protocol, port, False)} {self._nat_service(protocol, new_port, False)}"
                        line += tail
                    if line + flags not in plan.lines:
                        plan.lines.append(line + flags)
        return plan

    def _nat(self, nat: NatRule) -> None:
        plan = self.nat_plan(nat)
        if plan.problem is not None:
            self.report.skip("nat", nat.origin, *plan.problem)
            return
        item = self.report.item("nat", nat.origin)
        if plan.interface_keyword:
            self.report.withdraw("nat", nat.origin, {"NAT_INTERFACE_ADDRESS"})  # it follows the interface again
        for severity, code, message in plan.findings:
            self.report.add("nat", nat.origin, severity, code, message)
        self.nat += plan.lines
        item.emitted_as.append(f"{len(plan.lines)} NAT line" + ("s" if len(plan.lines) != 1 else ""))
        if plan.whole:
            self.whole.add(nat.origin)
        if nat.destination_translation is not None and plan.whole:
            self.tied.add(nat.origin)

    # -- output -----------------------------------------------------------

    def run(self) -> str:
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=self.tied, whole=self.whole)
        access_lists, groups = self._access_lists()
        self._drop_unused_interface_objects(access_lists + self.nat)
        self._notes()
        out = [
            "! Generated by FWShift - review the conversion report before loading this.",
            "! Cisco ASA commands (9.x): objects, access lists, NAT. Interfaces are not configured here.",
            "! Rules the converter could not express are present but inactive, or are a remark only.",
        ]
        out += self.objects + access_lists + self.nat
        out += ["! Binding the access lists puts the policy in force."] + groups
        return "\n".join(out) + "\n"

    def _drop_unused_interface_objects(self, lines: List[str]) -> None:
        """An object that stood for "interface" in the NAT rules of an ASA and is not needed now that the word is back."""
        for address in list(self.p.addresses.values()):
            header = f"object network {address.name}"
            if not self._interface_of(address.name) or header not in self.objects:
                continue
            if any(address.name in line.split() for line in lines + self.objects if line != header):
                continue
            start = self.objects.index(header)
            end = start + 1
            while end < len(self.objects) and self.objects[end].startswith(" "):
                end += 1
            del self.objects[start:end]

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW,
            "ASA_LOAD",
            "the output binds its access lists with 'access-group', which replaces the lists bound to those "
            "interfaces now. Its NAT lines go to the end of section 1 of the NAT table: manual NAT rules the ASA "
            "has stay in front of them and win, only its network object NAT and after-auto rules come after "
            "them. The global access list ends the "
            "policy for every interface of the ASA, also for those the policy does not name: none of them keeps "
            "the ASA's own permit towards lower security levels. Entries of an access list that exists under the "
            "same name are added to it: load the output on an ASA without them, or remove them first",
        )
        self.report.note(
            Severity.INFO,
            "EXISTING_OBJECTS",
            "objects are created by name: an object that exists on the target under the same name is changed, and "
            "an object group that exists gets the new members next to its own. --target-prefix keeps them apart",
        )
        zones = transform.dedupe(
            self.universe + [z for r in self.p.nat_rules for z in r.src_zones + r.dst_zones if z != ANY]
        )
        if zones and not self.native:
            self.report.note(
                Severity.REVIEW,
                "INTERFACES_REQUIRED",
                "zones are written as interface names (nameif); map each zone to its interface with --zone-map: "
                + ", ".join(zones)
                + ". The access lists are written for an ASA whose interfaces are these and no others: a rule to "
                "every other zone is written as a rule to any destination, which reaches a further interface as "
                "well. They also count on the ASA not sending traffic back out of the interface it came in on: "
                "leave 'same-security-traffic permit intra-interface' off, or give the networks of every zone with "
                "--zone-network. An ASA forwards between two interfaces of the same security level only with "
                "'same-security-traffic permit inter-interface': give the interfaces different levels or set it",
            )
        areas = self.areas
        if areas.squeezed:
            versions = " and ".join(f"IPv{version}" for version in areas.full)
            self.report.note(
                Severity.REVIEW,
                "ZONE_NETWORK_INCOMPLETE",
                f"the networks given with --zone-network cover every {versions} address, and no network was given for "
                + ", ".join(areas.squeezed)
                + ". A network that takes in everything else stands for what lies behind no other zone, so every "
                "other zone needs its networks: as it is, what lies behind "
                + ", ".join(areas.squeezed)
                + " counts as lying behind another zone. Rules that had to be told apart from traffic to "
                + ("it" if len(areas.squeezed) == 1 else "them")
                + " were not kept to their zones",
            )
        if self.gap_used:
            self.report.note(
                Severity.APPROX,
                "ZONE_NETWORK_GAP",
                "the networks given with --zone-network leave out "
                + _listing(sorted(areas.nowhere, key=lambda interval: (interval not in (FULL_V4, FULL_V6), interval)))
                + ". Nobody said behind which zone those addresses lie: where a rule for any address is kept to "
                "its zones, a permit rule does not cover them and a deny rule does. Give the zone that has the "
                "default route 0.0.0.0/0 and ::/0 (a network inside another one goes before it, as with routes)",
            )
        if self.strangers:
            self.report.note(
                Severity.REVIEW,
                "ZONE_NETWORK_UNKNOWN",
                "--zone-network names zones the policy does not know: " + ", ".join(self.strangers) + ". They were "
                "taken as further interfaces of the ASA, and rules for other zones leave their networks out. Check "
                "the names: they are the names after --zone-map",
            )
        if self.implied:
            self.report.note(
                Severity.INFO,
                "SAME_SECURITY_TRAFFIC",
                "the source did not forward traffic back out of the interface it came in on or between interfaces "
                "of the same security level unless 'same-security-traffic' permitted it. The access lists rely on "
                "that: keep the security levels and the same-security-traffic settings of the source",
            )
        if self.p.default_intrazone == Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_DEFAULT",
                "the source allows traffic inside a zone unless a rule denies it. An ASA does not send traffic back "
                "out of the interface it came in on unless 'same-security-traffic permit intra-interface' is set, "
                "and then only what the access lists permit",
            )
        if self.p.default_interzone == Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTERZONE_DEFAULT",
                "the source accepts traffic between zones that no rule matches: the global access list ends with "
                "'permit ip any any', which also holds for traffic that leaves by the interface it came in on "
                "where the ASA is set to send that",
            )
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_ALLOW",
                "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                "written for that: " + ", ".join(open_zones),
            )
        if self.fqdn:
            self.report.note(
                Severity.INFO,
                "FQDN_DNS",
                "objects with a host name need name resolution on the ASA ('dns domain-lookup' and a DNS server group)",
            )
