# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco Secure Firewall emitter: neutral model -> what the managers of a Firepower Threat Defense take.

Two outputs, from one conversion:

* ``fmc``: a Python script that loads the policy into a Firewall Management Center through its REST
  API. It is ``fmc_loader.py`` with the policy as data at its end. It creates objects, a new access
  control policy and a new NAT policy, assigned to no device; it changes nothing that exists.
* ``fdm``: the file a Firewall Device Manager imports (*configuration import*): a JSON list of
  objects, rules and NAT rules that are added to what the device has.

Design rules:

* Nothing is ever widened silently. A rule whose match cannot be expressed is written disabled on
  a Management Center and left out for a Device Manager, which has no disabled rules; either way
  it is reported.
* An access rule lists zones, networks and ports and cannot negate. A negated address list is
  written as the addresses it leaves, which is exact.
* Source ports and destination ports are two conditions of a rule, of one protocol, that must
  both hold: a service with source ports gets rules of its own.
* Access rules name the real address of a translated destination: rules are rewritten to it, as
  for an ASA, and NAT is written as manual NAT in the order of the rules.
* A network group holds no FQDN object and a port group no group: rules name the parts.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import pkgutil
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union

from .. import __version__, transform
from ..appmap import FDM_ICMP6_CODES, FDM_ICMP6_TYPES, FDM_ICMP_CODES, FDM_ICMP_TYPES, FDM_PROTOCOL_NAMES
from ..errors import FwshiftError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    Action,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    SnatKind,
)
from ..names import CISCO, CISCO_FDM_RULE, CISCO_FMC_RULE, CISCO_NATIVE, NameRules, clean
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, range_text, size, subtract
from ..options import Options
from ..report import Report, Severity
from .checkpoint import _zone_names  # zone names that cannot be object names are changed, and said

_PLACEHOLDER = "FWSHIFT PLACEHOLDER, matches nothing: "
_PLACEHOLDER_SERVICE = "FWSHIFT PLACEHOLDER for a service that was not converted (TCP port 1 stands in): "
_PLACEHOLDER_HOST = "192.0.0.8"  # the IPv4 dummy address of RFC 7600: never a host, never a destination
_MAX_NAT_RULES = 16  # NAT rules one rule may become (one per port of its service)
_FDM_SCOPE = re.compile(r"FTD (\S+) on (.+)")
_FDM_REPLACE = "REPLACE WITH THE VALUE FROM AN EXPORT OF THE TARGET"
_FDM_INTERFACE = "physicalinterface"
# Objects both managers come with, as far as they are known: an object of another platform that carries
# one of these names gets another. (A Management Center is asked for its names before anything is created.)
_SYSTEM_NETWORKS: FrozenSet[str] = frozenset(name.lower() for name in (
    "any any-ipv4 any-ipv6 IPv4-Benchmark-Tests IPv4-Link-Local IPv4-Multicast IPv4-Private-10.0.0.0-8 "
    "IPv4-Private-172.16.0.0-12 IPv4-Private-192.168.0.0-16 IPv4-Private-All-RFC1918 IPv6-IPv4-Mapped IPv6-Link-Local "
    "IPv6-Private-Unique-Local-Addresses IPv6-to-IPv4-Relay-Anycast").split())  # fmt: skip
_SYSTEM_PORTS: FrozenSet[str] = frozenset(name.lower() for name in (
    "AOL Bittorrent DNS_over_TCP DNS_over_UDP FTP HTTP HTTPS IMAP LDAP NFSD-TCP NFSD-UDP NTP-TCP NTP-UDP POP-2 POP-3 "
    "RADIUS RIP SIP SMTP SMTPS SNMP SSH SYSLOG TCP_high_ports TELNET TFTP Yahoo_Messenger_Messages "
    "Yahoo_Messenger_Voice_Chat_TCP Yahoo_Messenger_Voice_Chat_UDP").split())  # fmt: skip
_ANY_OBJECT = {4: "any-ipv4", 6: "any-ipv6"}  # the predefined objects for every address of an IP version

Problem = Tuple[str, str, Severity]
Finding = Tuple[Severity, str, str]


@dataclass(frozen=True)
class _Ref:
    """A reference to an object: what kind of object, and its name on the target."""

    kind: str  # host, network, range, fqdn, netgroup, port, icmp4, icmp6, protocol, portgroup, zone, interface
    name: str


@dataclass(frozen=True)
class _Lit:
    """An IP protocol that a rule of a Management Center spells out."""

    protocol: int


PortRef = Union[_Ref, _Lit]


@dataclass(frozen=True)
class _Atom:
    """One thing a port object can say."""

    kind: str  # port, icmp4, icmp6, protocol
    protocol: str = ""  # port: tcp or udp
    port: str = ""  # port: one port or one range; empty for every port
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    number: int = 0  # protocol


@dataclass
class _Object:
    ref: _Ref
    value: str = ""
    description: str = ""
    resolution: int = 0  # fqdn: 4, 6 or 0 for both
    members: List[_Ref] = field(default_factory=list)
    atom: Optional[_Atom] = None


@dataclass
class _RuleOut:
    name: str
    enabled: bool
    action: str  # allow, trust, block, reset
    log_start: bool
    log_end: bool
    src_zones: List[str]
    dst_zones: List[str]
    sources: Optional[List[_Ref]]  # None: any
    destinations: Optional[List[_Ref]]
    src_ports: List[PortRef]
    dst_ports: List[PortRef]
    description: str = ""


@dataclass
class _NatOut:
    name: str
    enabled: bool
    static: bool
    src_if: str = ""  # zone (Management Center) or interface (Device Manager); empty for any
    dst_if: str = ""
    original_source: Optional[_Ref] = None  # None: any
    translated_source: Optional[_Ref] = None
    to_interface: bool = False  # the source is translated to the address of the destination interface
    original_destination: Optional[_Ref] = None
    translated_destination: Optional[_Ref] = None
    from_interface: bool = False  # the original destination is the address of the source interface
    original_source_port: Optional[_Ref] = None
    translated_source_port: Optional[_Ref] = None
    original_destination_port: Optional[_Ref] = None
    translated_destination_port: Optional[_Ref] = None
    unidirectional: bool = False
    no_proxy_arp: bool = False
    route_lookup: bool = False
    pat_pool: Optional[_Ref] = None
    description: str = ""


@dataclass
class _NatPlan:
    problem: Optional[Problem] = None
    rules: List[_NatOut] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    whole: bool = False  # written with a destination part: no other rule takes part in its connections
    interface_keyword: bool = False  # written as "the interface" where the model holds the address of one


def _clip(text: str, limit: int = 200) -> str:
    return " ".join(text.split())[:limit]


class _Names:
    """Names as the target takes them. Names of another platform are kept apart whatever their case."""

    def __init__(self, native: bool, fdm: bool) -> None:
        self.native = native
        self.objects: NameRules = CISCO_NATIVE if native else CISCO
        self.rules: NameRules = CISCO_NATIVE if native else (CISCO_FDM_RULE if fdm else CISCO_FMC_RULE)
        self.made: NameRules = CISCO  # for the names FWShift makes up itself, whatever the source
        self.addresses: Set[str] = set()
        self.services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.source: Dict[str, str] = {}  # name of an object here -> its name in the report

    def fold(self, name: str) -> str:
        """What two names must differ in to be two names: whether a manager tells them apart by case is not known."""
        return name.lower()

    def unique(self, name: str, taken: Set[str], rules: NameRules, suffix: str = "") -> str:
        base = clean(name, rules)
        if suffix:
            base = base[: rules.max_len - len(suffix)].rstrip() + suffix
        candidate, counter = base, 2
        while self.fold(candidate) in taken:
            tail = f"_{counter}"
            candidate = base[: rules.max_len - len(tail)].rstrip() + tail
            counter += 1
        taken.add(self.fold(candidate))
        return candidate


def _rename(p: Policy, report: Report, names: _Names, prefix: str, keep: Set[str]) -> None:
    """Give every object and rule a name the target takes, and that no other object has."""

    def plan(listed: List[Tuple[str, str]], taken: Set[str], reserved: FrozenSet[str]) -> Dict[str, str]:
        taken |= reserved
        stays: Set[str] = set()
        for name, _ in listed:
            fits = not prefix and clean(name, names.objects) == name and names.fold(name) not in taken
            if name in keep or fits:
                stays.add(name)
                taken.add(names.fold(name))
        mapping: Dict[str, str] = {}
        for name, kind in listed:
            names.source[name] = name
            if name in stays:
                continue
            new = names.unique(prefix + name, taken, names.objects)
            mapping[name] = new
            names.source[new] = name
            report.item(kind, name).emitted_as = [new]
            if new != prefix + name:
                report.add(kind, name, Severity.INFO, "RENAMED", f"renamed to '{new}' to fit the target's naming rules")
        return mapping

    foreign = not names.native
    address_map = plan(
        [(n, "address") for n in p.addresses] + [(n, "address-group") for n in p.address_groups],
        names.addresses,
        _SYSTEM_NETWORKS if foreign else frozenset(),
    )
    service_map = plan(
        [(n, "service") for n in p.services] + [(n, "service-group") for n in p.service_groups],
        names.services,
        _SYSTEM_PORTS if foreign else frozenset(),
    )
    transform.rename_objects(p, address_map, service_map)
    for rule in p.rules:
        rule.name = names.unique(rule.name, names.rule_names, names.rules)
    for nat in p.nat_rules:
        nat.name = names.unique(nat.name, names.nat_names, names.rules)


def _is_interface_object(p: Policy, name: str) -> bool:
    """An object a parser made to stand for "the address of an interface" in a NAT rule of an ASA or an FTD."""
    address = p.addresses.get(name)
    return address is not None and address.builtin in ("asa", "fmc", "fdm") and address.raw.startswith("interface ")


def _on_target(p: Policy, vendor: str) -> Set[str]:
    """Objects of a source of the same kind that the target has without their being created: the predefined ones."""
    if p.vendor != vendor:
        return set()
    return (
        {n for n, a in p.addresses.items() if a.builtin == vendor and not _is_interface_object(p, n)}
        | {n for n, g in p.address_groups.items() if g.builtin == vendor}
        | {n for n, s in p.services.items() if s.builtin == vendor}
        | {n for n, w in p.service_groups.items() if w.builtin == vendor}
    )


def _prepare(policy: Policy, report: Report, options: Options, fdm: bool) -> "_Emitter":
    vendor = "fdm" if fdm else "fmc"
    p = copy.deepcopy(policy)
    native = p.vendor == vendor
    source_zones = {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}
    options = dataclasses.replace(options, zone_map=_zone_names(p, options, source_zones, CISCO_NATIVE if native else CISCO, report))
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix
    if prefix and (CISCO.invalid.search(prefix) or len(prefix) > 20):
        raise FwshiftError("--target-prefix takes up to 20 letters, digits, periods, underscores and hyphens")
    if not fdm and clean(options.target_policy, CISCO_FMC_RULE) != options.target_policy:
        raise FwshiftError(f"--target-policy '{options.target_policy[:40]}' is not a name a Management Center takes for a policy "
                           "(up to 50 letters, digits, spaces, periods, underscores and hyphens)")  # fmt: skip
    names = _Names(native, fdm)
    _rename(p, report, names, prefix, _on_target(p, vendor))
    # Access rules see the real address of a translated destination. Rewrite the rules for the
    # translations that are really written.
    probe = _Emitter(p, Report(), options, names, source_zones, fdm, probe=True)
    written = {nat.origin for nat in p.nat_rules if probe.nat_plan(nat).problem is None}
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, names, source_zones, fdm)


def emit_fmc(policy: Policy, report: Report, options: Options) -> str:
    return _prepare(policy, report, options, fdm=False).as_fmc()


def emit_fdm(policy: Policy, report: Report, options: Options) -> str:
    return _prepare(policy, report, options, fdm=True).as_fdm()


def loader_source() -> str:
    data = pkgutil.get_data(__package__ or "fwshift.emitters", "fmc_loader.py")
    if data is None:
        raise FwshiftError("the loader for a Management Center (fmc_loader.py) is missing from this installation of FWShift")
    return data.decode("utf-8")


def _port_parts(ports: str) -> List[str]:
    """``80,8000-8010`` as single ports and ranges; empty for every port. Port 0 is no port of a connection."""
    out: List[str] = []
    for part in ports.split(",") if ports else []:
        first, _, last = part.partition("-")
        low, high = max(int(first), 1), int(last or first)
        if high >= low:
            out.append(str(low) if low == high else f"{low}-{high}")
    if out == ["1-65535"]:
        return [""]
    return out


def _has_port_zero(entry: ServiceEntry) -> bool:
    return any(part.split("-")[0].strip("0") == "" for ports in (entry.dst_ports, entry.src_ports) if ports for part in ports.split(","))


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, names: _Names, source_zones: Set[str], fdm: bool,
                 probe: bool = False) -> None:  # fmt: skip
        self.p, self.report, self.options, self.names, self.fdm = p, report, options, names, fdm
        if probe:
            # A trial run asks which NAT rules can be written: the names it would take stay free.
            self.names = copy.deepcopy(names)
        self.vendor = "fdm" if fdm else "fmc"
        self.native = names.native
        self.source_zones = source_zones  # zone and interface names of the rules before --zone-map
        self.kept = _on_target(p, self.vendor)
        self.taint_a = transform.tainted_addresses(p, keep=self.kept)
        self.taint_s: Dict[str, str] = {}
        self.objects: List[_Object] = []  # in the order they have to be created
        self.existing: List[_Ref] = []  # objects the target must have already
        self.net_refs: Dict[str, List[_Ref]] = {}  # what stands for an address or group of the model in a rule
        self.group_leaves: Dict[str, List[_Ref]] = {}  # the objects of a group, through the groups in it
        self.by_value: Dict[Tuple[Interval, bool], _Ref] = {}  # (addresses, as a range) -> object that holds them
        self.net_groups: Dict[Tuple[_Ref, ...], _Ref] = {}
        self.lazy: Dict[str, Tuple[Interval, str]] = {}  # objects that are only created when something names them
        self.atoms: Dict[_Atom, PortRef] = {}
        self.svc_atoms: Dict[str, List[Tuple[Optional[Tuple[str, str]], _Atom]]] = {}
        self.svc_plain: Dict[str, _Ref] = {}  # the one object or group that is all of a service
        self.svc_any: Set[str] = set()  # services that are every IP protocol: no port condition where a rule names them
        self.app_services: Dict[str, str] = {}
        self.rules: List[_RuleOut] = []
        self.nat: List[_NatOut] = []
        self.zones: List[str] = []
        self.tied: Set[str] = set()
        self.whole: Set[str] = set()
        self.fqdn = False
        self.code_zero = False
        self.all_ports: Set[_Ref] = set()  # port objects that are every port of their protocol
        self.by_ref: Dict[_Ref, _Object] = {}
        self.counter = 0
        self._atom_index: Dict[_Ref, Optional[_Atom]] = {}
        self._define_addresses()
        self._define_services()

    # -- addresses --------------------------------------------------------

    def _origin(self, name: str) -> str:
        return self.names.source.get(name, name)

    def _existing(self, ref: _Ref) -> _Ref:
        if ref not in self.existing:
            self.existing.append(ref)
        return ref

    def _full(self, version: int) -> _Ref:
        """The predefined object for every address of an IP version."""
        return self._existing(_Ref("network", _ANY_OBJECT[version]))

    def _add(self, obj: _Object) -> _Ref:
        self.objects.append(obj)
        self.by_ref.setdefault(obj.ref, obj)
        if obj.atom is not None and obj.atom.kind == "port" and not obj.atom.port:
            self.all_ports.add(obj.ref)
        return obj.ref

    def _placeholder(self, name: str, reason: str) -> None:
        """An object that keeps the name and matches nothing, for the rules that are written disabled."""
        if self.fdm:
            self.net_refs[name] = []  # nothing is written that names it
            return
        self.net_refs[name] = [self._add(_Object(_Ref("host", name), _PLACEHOLDER_HOST, _clip(_PLACEHOLDER + reason)))]

    def _net_object(self, name: str, interval: Interval, as_range: bool, description: str = "") -> _Ref:
        version, first, last = interval
        text = interval_text(interval)
        if first == last:
            ref = self._add(_Object(_Ref("host", name), text, _clip(description)))
        elif "/" in text and not as_range:
            ref = self._add(_Object(_Ref("network", name), text, _clip(description)))
        else:
            ref, as_range = self._add(_Object(_Ref("range", name), range_text(interval), _clip(description))), True
        self.by_value.setdefault((interval, as_range and first != last), ref)
        return ref

    def _literal(self, interval: Interval, as_range: bool = False) -> _Ref:
        """The object for addresses that a rule or a group names directly."""
        if interval in (FULL_V4, FULL_V6):
            return self._full(interval[0])
        as_range = as_range and interval[1] != interval[2]
        key = (interval, as_range or "/" not in interval_text(interval) and interval[1] != interval[2])
        if key not in self.by_value:
            text = interval_text(interval)
            if interval[1] == interval[2]:
                label = f"h-{text}"
            elif "/" in text and not as_range:
                label = "n-" + text.replace("/", "_")
            else:
                label = f"r-{range_text(interval)}"
            name = self.names.unique(self.options.object_prefix + label, self.names.addresses, self.names.made)
            self._net_object(name, interval, as_range)
        return self.by_value[key]

    def _define_addresses(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            origin = self._origin(name)
            if name in self.kept:
                interval = parse_literal(address.value) if address.kind != AddressKind.FQDN else None
                kind = "fqdn" if address.kind == AddressKind.FQDN else "range" if address.kind == AddressKind.RANGE else \
                    "host" if interval is not None and interval[1] == interval[2] else "network"  # fmt: skip
                self.net_refs[name] = [self._existing(_Ref(kind, name))]
                self.report.withdraw("address", origin, {"UNSUPPORTED_ADDRESS"})
                self.report.add("address", origin, Severity.INFO, "EXISTING_OBJECT",
                                "an object the manager comes with: referenced by name, not created")  # fmt: skip
                self.taint_a.pop(name, None)
                continue
            if address.kind == AddressKind.UNSUPPORTED:
                self._placeholder(name, address.raw or "unsupported address")
                continue
            if address.kind == AddressKind.FQDN:
                self.fqdn = True
                self.net_refs[name] = [self._add(_Object(_Ref("fqdn", name), address.value, _clip(address.description),
                                                         resolution=address.fqdn_family))]  # fmt: skip
                continue
            interval = parse_literal(address.value)
            if interval is None:
                self.taint_a[name] = "address that could not be read"
                self._placeholder(name, self.taint_a[name])
            elif interval in (FULL_V4, FULL_V6):
                self.net_refs[name] = [self._full(interval[0])]
                self.report.withdraw("address", origin, {"RENAMED"})  # no object is written that could carry the new name
                self.report.item("address", origin).emitted_as = [_ANY_OBJECT[interval[0]]]
                self.report.add("address", origin, Severity.INFO, "PREDEFINED_OBJECT",
                                f"every IPv{interval[0]} address: the predefined object '{_ANY_OBJECT[interval[0]]}' is used for it")  # fmt: skip
            elif _is_interface_object(self.p, name):
                self.lazy[name] = (interval, _clip(address.description))  # only where a rule needs the address itself
            else:
                self.net_refs[name] = [self._net_object(name, interval, address.kind == AddressKind.RANGE, address.description)]
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a) | self.kept), **self.taint_a}
        for group in transform.topo_groups(self.p.address_groups):
            self._define_group(group.name)

    def _define_group(self, name: str) -> None:
        group = self.p.address_groups[name]
        origin = self._origin(name)
        if name in self.kept:
            self.net_refs[name] = [self._existing(_Ref("netgroup", name))]
            self.group_leaves[name] = list(self.net_refs[name])
            self.report.withdraw("address-group", origin, {"UNSUPPORTED_GROUP"})
            self.report.add("address-group", origin, Severity.INFO, "EXISTING_OBJECT",
                            "an object the manager comes with: referenced by name, not created")  # fmt: skip
            return
        bad = [member for member in group.members if member in self.taint_a]
        if bad and name not in self.taint_a:
            self.taint_a[name] = f"contains '{bad[0]}' ({self.taint_a[bad[0]]})"
        if name in self.taint_a or transform.is_placeholder_group(group):
            self.taint_a.setdefault(name, "unconvertible group")
            self._placeholder(name, self.taint_a[name])
            return
        direct: List[_Ref] = []  # what the group holds itself, groups as groups
        leaves: List[_Ref] = []  # the objects it comes down to
        names: List[_Ref] = []  # host names: no group holds them, the rules name them
        for member in group.members:
            if member in self.p.address_groups:
                refs = self.net_refs.get(member, [])
                direct += [ref for ref in refs if ref.kind != "fqdn"]
                leaves += [ref for ref in self.group_leaves.get(member, []) if ref.kind != "fqdn"]
                names += [ref for ref in refs if ref.kind == "fqdn"]
            else:
                refs = self._net(member)
                direct += [ref for ref in refs if ref.kind != "fqdn"]
                leaves += [ref for ref in refs if ref.kind != "fqdn"]
                names += [ref for ref in refs if ref.kind == "fqdn"]
        # A Device Manager is given the objects themselves; a Management Center takes a group in a group.
        held: List[_Ref] = _distinct(leaves if self.fdm else direct)
        names = _distinct(names)
        if not held and not names:
            # Nothing but itself, or members that are nothing: no manager takes a group without members.
            self.taint_a[name] = "address group without usable members"
            self._placeholder(name, self.taint_a[name])
            return
        made: List[_Ref] = []
        if held:
            made.append(self._add(_Object(_Ref("netgroup", name), description=_clip(group.description), members=held)))
        self.net_refs[name] = made + names
        self.group_leaves[name] = _distinct(leaves) + names
        if names:
            self.report.add(
                "address-group", origin, Severity.INFO, "GROUP_SPLIT",
                "a network group of a Cisco Secure Firewall holds no FQDN objects: "
                + (f"group '{name}' is written without them, and the rules that use it name " if held
                   else "the group is not written, and the rules that use it name ")
                + ", ".join(f"'{ref.name}'" for ref in names) + " themselves",
            )  # fmt: skip
            if not held:
                self.report.item("address-group", origin).emitted_as = [ref.name for ref in names]

    def _net(self, member: str) -> List[_Ref]:
        """What stands for a rule member of the model: objects, in the order of the model."""
        if member in self.lazy:
            held, description = self.lazy.pop(member)
            self.net_refs[member] = [self._net_object(member, held, False, description)]
        if member in self.net_refs:
            return self.net_refs[member]
        interval = parse_literal(member)
        return [self._literal(interval, is_range_text(member))] if interval is not None else []

    def _static(self, members: List[str]) -> Optional[List[Interval]]:
        """The addresses of members, when they are all static addresses."""
        out: List[Interval] = []
        for member in members:
            found = transform.address_intervals(self.p, member)
            if found is None:
                return None
            out += found
        return out

    def _nat_object(self, members: List[str], as_range: bool = False) -> Optional[_Ref]:
        """Object or group for the addresses of a NAT rule; None unless they are static addresses."""
        if self._static(members) is None or ANY in members:
            return None
        refs = _distinct([ref for member in members for ref in self._net(member)])
        if not refs or any(ref.kind == "fqdn" for ref in refs):
            return None
        if as_range:
            return self._pool_object(members)
        return refs[0] if len(refs) == 1 else self._network_group(refs)

    def _pool_object(self, members: List[str]) -> Optional[_Ref]:
        """Hosts and ranges to translate to: a pool may not hold a subnet."""
        intervals = self._static(members)
        if not intervals:
            return None
        refs = [self._literal(interval, as_range=True) for interval in normalize(intervals)]
        return refs[0] if len(refs) == 1 else self._network_group(refs)

    def _network_group(self, refs: List[_Ref]) -> _Ref:
        key = tuple(refs)
        if key not in self.net_groups:
            self.counter += 1
            name = self.names.unique(f"{self.options.object_prefix}FWSHIFT_NETWORK_{self.counter}", self.names.addresses, self.names.made)
            self.net_groups[key] = self._add(_Object(_Ref("netgroup", name), description="addresses of a NAT rule", members=list(refs)))
        return self.net_groups[key]

    # -- services ---------------------------------------------------------

    def _entry_atoms(self, entry: ServiceEntry) -> Tuple[List[Tuple[Optional[Tuple[str, str]], _Atom]], str, bool]:
        """(what a rule needs for an entry, why the entry cannot be written, whether it is every protocol)."""
        protocol = entry.protocol
        if protocol in (Protocol.TCP, Protocol.UDP):
            targets, origins = _port_parts(entry.dst_ports), _port_parts(entry.src_ports)
            if (entry.dst_ports and not targets) or (entry.src_ports and not origins):
                return [], "port 0 and no other, which is no port of a connection", False
            out: List[Tuple[Optional[Tuple[str, str]], _Atom]] = []
            for origin in origins or [""]:
                for target in targets or [""]:
                    out.append(((protocol.value, origin) if origin else None, _Atom("port", protocol.value, target)))
            return out, "", False
        if protocol == Protocol.SCTP:
            if entry.dst_ports or entry.src_ports:
                return [], "SCTP ports, which a port object cannot name (it has ports for TCP and UDP only)", False
            return self._protocol_atoms(132)
        if protocol == Protocol.IP:
            if entry.ip_protocol is None:
                return [], "", True
            if entry.ip_protocol in (6, 17):
                return [(None, _Atom("port", "tcp" if entry.ip_protocol == 6 else "udp", ""))], "", False
            if entry.ip_protocol in (1, 58):
                return [(None, _Atom("icmp4" if entry.ip_protocol == 1 else "icmp6"))], "", False
            return self._protocol_atoms(entry.ip_protocol)
        six = protocol == Protocol.ICMP6
        label = "ICMPv6" if six else "ICMP"
        if entry.icmp_type is None and entry.icmp_code is not None:
            return [], f"{label} code {entry.icmp_code} of every type, which an ICMP object cannot say", False
        if self.fdm and entry.icmp_type is not None:
            types, codes = (FDM_ICMP6_TYPES, FDM_ICMP6_CODES) if six else (FDM_ICMP_TYPES, FDM_ICMP_CODES)
            if entry.icmp_type not in types.values():
                return [], f"{label} type {entry.icmp_type}, which a Device Manager has no name for", False
            if entry.icmp_code is not None and (entry.icmp_type, entry.icmp_code) not in codes.values():
                if entry.icmp_code != 0 or any(kind == entry.icmp_type for kind, _ in codes.values()):
                    return [], f"{label} type {entry.icmp_type} code {entry.icmp_code}, which a Device Manager has no name for", False
                # A type for which it has no codes at all: code 0 is the only one there is, and the type alone says it.
                self.code_zero = True
                return [(None, _Atom("icmp6" if six else "icmp4", icmp_type=entry.icmp_type))], "", False
        return [(None, _Atom("icmp6" if six else "icmp4", icmp_type=entry.icmp_type, icmp_code=entry.icmp_code))], "", False

    def _protocol_atoms(self, number: int) -> Tuple[List[Tuple[Optional[Tuple[str, str]], _Atom]], str, bool]:
        if self.fdm and number not in FDM_PROTOCOL_NAMES:
            return [], f"IP protocol {number}, which a Device Manager has no name for", False
        return [(None, _Atom("protocol", number=number))], "", False

    def _atoms_of(self, entries: List[ServiceEntry]) -> Tuple[List[Tuple[Optional[Tuple[str, str]], _Atom]], str, bool]:
        out: List[Tuple[Optional[Tuple[str, str]], _Atom]] = []
        for entry in entries:
            atoms, problem, everything = self._entry_atoms(entry)
            if problem or everything:
                return [], problem, everything
            out += [pair for pair in atoms if pair not in out]
        return out, "", False

    @staticmethod
    def _atom_label(atom: _Atom) -> str:
        if atom.kind == "port":
            return f"{atom.protocol}-{atom.port or 'all'}"
        if atom.kind == "protocol":
            return f"ip-{FDM_PROTOCOL_NAMES.get(atom.number, str(atom.number)).lower()}"
        label = "icmp6" if atom.kind == "icmp6" else "icmp"
        if atom.icmp_type is None:
            return f"{label}-all"
        return f"{label}-{atom.icmp_type}" + (f"-{atom.icmp_code}" if atom.icmp_code is not None else "")

    def _atom_ref(self, atom: _Atom, name: str = "", description: str = "") -> PortRef:
        """The port object for an atom: one per content, made when it is first needed."""
        if atom.kind == "protocol" and not self.fdm:
            return _Lit(atom.number)  # a rule of a Management Center spells the protocol out, by its number
        if atom not in self.atoms or name:
            new = name or self.names.unique(self.options.object_prefix + self._atom_label(atom), self.names.services, self.names.made)
            ref = self._add(_Object(_Ref(atom.kind, new), description=_clip(description), atom=atom))
            self.atoms.setdefault(atom, ref)
            return ref
        return self.atoms[atom]

    def _placeholder_service(self, name: str, reason: str) -> None:
        if not self.fdm:
            # (No port object matches nothing; this one keeps the name for the rules that are written disabled.)
            self.svc_plain[name] = self._add(_Object(_Ref("port", name), description=_clip(_PLACEHOLDER_SERVICE + reason),
                                                     atom=_Atom("port", "tcp", "1")))  # fmt: skip
        self.svc_atoms[name] = []

    def _existing_service(self, name: str, kind: str, origin: str, entries: Optional[List[ServiceEntry]]) -> None:
        atoms = self._atoms_of(entries or [])[0]
        ref_kind = "portgroup" if kind == "service-group" else (atoms[0][1].kind if len(atoms) == 1 else "port")
        if ref_kind == "protocol" and not self.fdm:
            ref_kind = "port"  # on a Management Center a protocol without ports is a port object like the others
        self.svc_plain[name] = self._existing(_Ref(ref_kind, name))
        self.svc_atoms[name] = atoms
        if len(atoms) == 1 and atoms[0][0] is None and kind == "service":
            self.atoms.setdefault(atoms[0][1], self.svc_plain[name])  # the port has an object: no second one is made for it
        self.report.add(kind, origin, Severity.INFO, "EXISTING_OBJECT", "an object the manager comes with: referenced by name, not created")

    def _define_services(self) -> None:
        bad: Dict[str, str] = {}
        several: List[Service] = []
        for service in self.p.services.values():
            name = service.name
            origin = self._origin(name)
            if name in self.kept:
                self._existing_service(name, "service", origin, service.entries)
                continue
            if not service.entries or service.unsupported:
                self._placeholder_service(name, service.unsupported or "unsupported or undefined service")
                continue
            self.code_zero = False
            atoms, problem, everything = self._atoms_of(service.entries)
            if self.code_zero and not problem:
                self.report.add("service", origin, Severity.INFO, "ICMP_CODE",
                                "code 0 of an ICMP type for which a Device Manager has no codes is written as the type alone: "
                                "0 is the only code that type has")  # fmt: skip
            if everything:
                self.svc_any.add(name)  # nothing to define: a rule without a port condition says it
                continue
            if problem:
                bad[name] = problem
                self._placeholder_service(name, problem)
                self.report.add("service", origin, Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: not written, and the rules that use it are not converted")  # fmt: skip
                continue
            if any(_has_port_zero(entry) for entry in service.entries):
                self.report.add("service", origin, Severity.INFO, "PORT_ZERO",
                                "port 0 is left out: no connection has it, and a port object starts at port 1")  # fmt: skip
            self.svc_atoms[name] = atoms
            if all(key is None and not isinstance(self._peek(atom), _Lit) for key, atom in atoms):
                if len(atoms) == 1:
                    ref = self._atom_ref(atoms[0][1], name, service.description)
                    assert isinstance(ref, _Ref)
                    self.svc_plain[name] = ref
                else:
                    several.append(service)
        # Services of several ports come after those of one: a port that has an object under a name of the
        # source is not written a second time for them.
        for service in several:
            name, origin = service.name, self._origin(service.name)
            members = [self._atom_ref(atom) for _, atom in self.svc_atoms[name]]
            self.svc_plain[name] = self._add(_Object(_Ref("portgroup", name), description=_clip(service.description),
                                                     members=[m for m in members if isinstance(m, _Ref)]))  # fmt: skip
            self.report.item("service", origin).emitted_as = [name] + [m.name for m in members if isinstance(m, _Ref)]
            self.report.add(
                "service", origin, Severity.INFO, "SERVICE_SPLIT",
                f"a port object holds one port or range of one protocol: written as port group '{name}' of "
                + ", ".join(f"'{m.name}'" for m in members if isinstance(m, _Ref)),
            )  # fmt: skip
        self.taint_s = transform.tainted_services(self.p, bad, keep=self.kept)
        for group in transform.topo_groups(self.p.service_groups):
            name = group.name
            origin = self._origin(name)
            if name in self.kept:
                self._existing_service(name, "service-group", origin, transform.flatten_services(self.p, name))
                continue
            if name in self.taint_s:
                self._placeholder_service(name, self.taint_s[name])
                continue
            if any(member in self.svc_any for member in group.members):
                self.svc_any.add(name)
                continue
            atoms = []
            for member in group.members:
                atoms += [pair for pair in self.svc_atoms.get(member, []) if pair not in atoms]
            self.svc_atoms[name] = atoms
            if atoms and all(key is None and not isinstance(self._peek(atom), _Lit) for key, atom in atoms):
                members = []
                for member in group.members:
                    plain = self.svc_plain.get(member)
                    if plain is not None and plain.kind != "portgroup":
                        members.append(plain)  # the object that carries the name of the member
                    else:
                        members += [ref for ref in (self._atom_ref(atom) for _, atom in self.svc_atoms.get(member, [])) if isinstance(ref, _Ref)]
                self.svc_plain[name] = self._add(_Object(_Ref("portgroup", name), description=_clip(group.description),
                                                         members=_distinct(members)))  # fmt: skip

    def _peek(self, atom: _Atom) -> Optional[PortRef]:
        """What an atom would be written as, without writing it."""
        return _Lit(atom.number) if atom.kind == "protocol" and not self.fdm else None

    def _app_service(self, app: str, entries: List[ServiceEntry], reasons: List[transform.Reason]) -> str:
        if app not in self.app_services:
            name = self.names.unique(f"{self.options.object_prefix}app-{app}", self.names.services, self.names.made)
            atoms, problem, everything = self._atoms_of(entries)
            if everything:
                self.svc_any.add(name)
            elif problem:
                self.taint_s[name] = problem
                self.svc_atoms[name] = []
            else:
                self.svc_atoms[name] = atoms
            self.app_services[app] = name
        name = self.app_services[app]
        if name in self.taint_s:
            reasons.append(("APP_PORTS", f"the ports of application {app} hold {self.taint_s[name]}"))
        return name

    def _rule_ports(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[Dict[Optional[Tuple[str, str]], List[PortRef]]]:
        """Destination ports of a rule per (protocol, source ports) it has to be written for; None for any service."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        services = list(rule.services) if lowered is None else [self._app_service(app, entries, reasons) for app, entries in lowered]
        if not services or ANY in services or self.svc_any & set(services):
            return None
        out: Dict[Optional[Tuple[str, str]], List[PortRef]] = {}
        every: Set[Optional[Tuple[str, str]]] = set()
        for service in services:
            plain = self.svc_plain.get(service)
            if plain is not None:
                out.setdefault(None, []).append(plain)
                continue
            for key, atom in self.svc_atoms.get(service, []):
                refs = out.setdefault(key, [])
                if key is not None and atom.kind == "port" and not atom.port:
                    every.add(key)  # every destination port of the protocol the source ports are of: no condition, no object
                else:
                    refs.append(self._atom_ref(atom))
        return {key: [] if key in every else _distinct(refs) for key, refs in out.items()}

    # -- security rules ---------------------------------------------------

    def _side(self, rule: Rule, members: List[str], negated: bool, side: str) -> Tuple[Optional[List[_Ref]], str]:
        """(objects of one address field, None for any; why the field cannot be written). No objects: no match."""
        if not negated:
            if ANY in members:
                return None, ""
            refs = _distinct([ref for member in members for ref in self._net(member)])
            if self._full(4) in refs and self._full(6) in refs:
                return None, ""
            return refs, ""
        if ANY in members:
            return [], ""
        named = self._static(members)
        if named is None:
            return None, (f"the {side} is negated, and {', '.join(members)} holds addresses that are not known here, so that "
                          "it cannot be written as the addresses that are left")  # fmt: skip
        left = subtract([FULL_V4, FULL_V6], named)
        if not left:
            return [], ""
        self.report.add(
            "rule", rule.origin, Severity.INFO, "NEGATION_AS_ADDRESSES",
            f"an access rule cannot negate: 'not {side} {', '.join(members)}' is written as the addresses that are left "
            f"({len(left)} range(s))",
        )  # fmt: skip
        if left == [FULL_V4, FULL_V6]:
            return None, ""
        return [self._literal(interval, as_range=True) for interval in left], ""

    def _rule(self, rule: Rule, added: bool = False) -> List[str]:
        item = self.report.item("rule", rule.origin) if not added else None
        if not added:
            transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        ports = self._rule_ports(rule, reasons)
        if rule.negate_service and ports is None:
            self.report.skip("rule", rule.origin, "NO_MATCH", "every service but every service: the rule matches nothing", Severity.INFO)
            return []
        if rule.negate_service:
            reasons.append(("NEGATION", "the service is negated, which an access rule cannot say"))
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as pairs of zones"))
            pairs = [(rule.src_zones, rule.dst_zones)]
        elif not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                             f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing",
                             Severity.INFO)  # fmt: skip
            return []
        sources, why_src = self._side(rule, rule.sources, rule.negate_source, "source")
        destinations, why_dst = self._side(rule, rule.destinations, rule.negate_destination, "destination")
        reasons += [("NEGATION", why) for why in (why_src, why_dst) if why]
        if why_src or why_dst or (reasons and self.fdm):
            # Written as it stands, a rule whose negation is lost would say the opposite; and a Device
            # Manager has no rule that is switched off.
            self._leave_out(rule, reasons)
            return []
        if sources == [] or destinations == []:
            self.report.skip("rule", rule.origin, "NO_MATCH",
                             "a negation that leaves no address, or a list without addresses: the rule matches nothing",
                             Severity.INFO)  # fmt: skip
            return []
        if self.fdm and not rule.enabled:
            self._leave_out(rule, reasons)
            return []
        if len(pairs) > 1:
            self.report.add("rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                            f"{rule.scope.value} rule written as {len(pairs)} rules, one per zone pair")  # fmt: skip
        classes = ports if ports is not None else {None: []}
        if len(classes) > 1:
            self.report.add(
                "rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                f"written as {len(classes)} rules: source ports and destination ports are two conditions of an access rule "
                "that must both hold, so each set of source ports gets a rule of its own",
            )  # fmt: skip
        action = self._action(rule)
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        flag = "FWSHIFT: disabled by the converter, see the report. " if reasons else ""
        names: List[str] = []
        for src_zones, dst_zones in pairs:
            for key in sorted(classes, key=lambda key: (key is not None, key or ("", ""))):
                name = rule.name if not names else self.names.unique(rule.name, self.names.rule_names, self.names.rules, f"-{len(names) + 1}")
                names.append(name)
                src_ports: List[PortRef] = [self._atom_ref(_Atom("port", key[0], key[1]))] if key is not None else []
                dst_ports = list(classes[key])
                if key is not None and any(isinstance(ref, _Ref) and self._is_all(ref) for ref in dst_ports):
                    dst_ports = []  # every destination port of the protocol the source ports are of: no condition
                for zone in list(src_zones) + list(dst_zones):
                    if zone != ANY and zone not in self.zones:
                        self.zones.append(zone)
                self.rules.append(_RuleOut(
                    name, rule.enabled and not reasons, action, rule.log_start, rule.log_end,
                    [] if ANY in src_zones else list(src_zones), [] if ANY in dst_zones else list(dst_zones),
                    sources, destinations, src_ports, dst_ports, _clip(flag + rule.description, 500),
                ))  # fmt: skip
        if item is not None:
            item.emitted_as += names
        return names

    def _is_all(self, ref: _Ref) -> bool:
        """Whether a port object is every port of its protocol: with source ports of that protocol it says nothing more."""
        return ref in self.all_ports

    def _leave_out(self, rule: Rule, reasons: List[transform.Reason]) -> None:
        if not reasons:
            self.report.skip("rule", rule.origin, "DISABLED_RULE",
                             "disabled on the source: a Device Manager has no rules that are switched off, so it is left out",
                             Severity.INFO)  # fmt: skip
            return
        tail = " The rule is left out"
        tail += ": a Device Manager has no rules that are switched off." if self.fdm else ", because without the negation it would say the opposite."
        if rule.action != Action.ALLOW and rule.enabled:
            tail += " This deny rule is NOT enforced until fixed; allow rules below it may match more traffic."
        for code, message in reasons:
            self.report.skip("rule", rule.origin, code, message + "." + tail)

    def _action(self, rule: Rule) -> str:
        if rule.action == Action.ALLOW:
            inspection = rule.handling.get("inspection", "") if self.p.vendor in ("fmc", "fdm") else ""
            if "fastpath" in inspection:
                self.report.add(
                    "rule", rule.origin, Severity.INFO, "PREFILTER_AS_TRUST",
                    "a prefilter rule of the source (Fastpath): written as an access rule with the action Trust, at the "
                    "place it had in front of the access rules",
                )  # fmt: skip
            return "trust" if inspection else "allow"
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            if self.fdm:
                self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                                f"action {rule.action.value} becomes Block, which drops without an answer: a Device Manager "
                                "has no rule that resets")  # fmt: skip
                return "block"
            if rule.action != Action.RESET_BOTH:
                self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                                f"action {rule.action.value} becomes Block with reset, which resets the connection for both sides")  # fmt: skip
            return "reset"
        return "block"

    def _intrazone_tail(self) -> None:
        """Zones of the source that pass traffic between their own interfaces: a rule each, below all others."""
        if self.p.default_intrazone == Action.ALLOW or not self.p.rules:
            return
        names: List[str] = []
        for zone in transform.intrazone_allow_zones(self.p, self.options.zone_map, self.source_zones, self.report):
            permit = Rule(
                name=self.names.unique(f"fwshift-intrazone-{zone}", self.names.rule_names, self.names.rules),
                src_zones=[zone], dst_zones=[zone], log_end=False,
                description="Added by FWShift: this zone allows traffic between its own interfaces on the source.",
            )  # fmt: skip
            names += self._rule(permit, added=True)
        if names:
            self.report.note(
                Severity.INFO, "INTRAZONE_ALLOW_ADDED",
                "appended " + ", ".join(f"'{name}'" for name in names) + ": these zones allow traffic between their own "
                "interfaces on the source, and a Cisco Secure Firewall needs a rule for it",
            )  # fmt: skip

    # -- NAT --------------------------------------------------------------

    def _mapped_zone(self, nat: NatRule, zone: str) -> str:
        """The zone whose interface address a rule translates to ("NAT to the outgoing interface"), or "" if unknown."""
        translation = nat.source_translation
        assert translation is not None
        if zone != ANY and nat.destination_translation is None:
            return zone
        for name, known in self.p.zones.items():
            if translation.interface and (translation.interface in known.interfaces or translation.interface == name):
                return self.options.zone_map.get(name, name)
        return self.options.nat_zone

    def _interface_zone(self, member: str) -> str:
        """The zone whose interface address an object of an ASA or FTD source stands for, as the target names it."""
        if not _is_interface_object(self.p, member):
            return ""
        zone = self.p.addresses[member].raw.partition(" ")[2]
        return self.options.zone_map.get(zone, zone)

    def _interfaces(self, zone: str) -> Optional[List[str]]:
        """What a NAT rule names for a zone: the zone itself on a Management Center, its interfaces on a Device Manager.

        None when the interfaces of the zone on the target are not known; ``[""]`` stands for any interface.
        """
        if zone == ANY:
            return [""]
        if not self.fdm:
            return [zone]
        zone_map, interface_map = self.options.zone_map, self.options.interface_map
        origins = [name for name in list(self.p.zones) + list(zone_map) + sorted(self.source_zones)
                   if zone_map.get(name, name) == zone] or [zone]  # fmt: skip
        out: List[str] = []
        for origin in transform.dedupe(origins):
            held = self.p.zones[origin].interfaces if origin in self.p.zones else []
            for interface in held or [origin]:
                if interface in interface_map:
                    out.append(interface_map[interface])
                elif self.native and held:
                    out.append(interface)  # the name it has on the Device Manager it was read from
                else:
                    return None
        return transform.dedupe(out)

    def nat_plan(self, nat: NatRule) -> _NatPlan:
        """The manual NAT rules for a rule of the model, or why it cannot be written. Nothing is reported from here."""
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
        if problems:
            return fail("NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
        lists = [nat.sources, nat.destinations, source.addresses if source else [], [destination.address] if destination else []]
        versions: Set[int] = set()
        for listed in lists:
            found = {i[0] for member in listed if member != ANY for i in transform.address_intervals(self.p, member) or []}
            if len(found) > 1:
                return fail("NAT_ADDRESSES", "a NAT rule takes no group with IPv4 and IPv6 addresses")
            versions |= found
        if len(versions) > 1:
            return fail("NAT_ADDRESSES", "translation between IPv4 and IPv6")
        version = 6 if versions == {6} else 4
        everyone = ANY in nat.sources or ANY_V4 in nat.sources or ANY_V6 in nat.sources
        if everyone and ANY in nat.sources and not versions and ANY in nat.destinations:
            plan.findings.append((Severity.INFO, "NAT_IP_VERSION", "the rule names no address: it is written for IPv4"))
        # "Any" source: no object on a Device Manager, the predefined object of the IP version on a Management Center.
        real: Optional[_Ref] = None
        if not everyone:
            real = self._nat_object(nat.sources)
            if real is None:
                return fail("NAT_ADDRESSES", "the rule needs static addresses as source")
        elif not self.fdm:
            real = self._full(version)
        # The service: one NAT rule per port, each with a port object for the port before and after.
        ports: List[Tuple[str, str]] = []  # (protocol, port or range)
        if nat.service != ANY:
            entries = transform.flatten_services(self.p, nat.service) or []
            if not entries or any(e.protocol not in (Protocol.TCP, Protocol.UDP) or e.src_ports for e in entries):
                return fail("NAT_SERVICE", f"service '{nat.service}' is not a TCP or UDP service without source ports")
            for entry in entries:
                parts = _port_parts(entry.dst_ports)
                if parts == [""] or not parts:
                    return fail("NAT_SERVICE", f"service '{nat.service}' covers every port of a protocol, or none; a NAT rule names ports")
                ports += [(entry.protocol.value, part) for part in parts]
            ports = [pair for index, pair in enumerate(ports) if pair not in ports[:index]]
            if len(ports) > _MAX_NAT_RULES:
                return fail("NAT_SERVICE", f"service '{nat.service}' has {len(ports)} ports or ranges; write the rule by hand")
            if self.fdm and any("-" in part for _, part in ports):
                return fail("NAT_SERVICE", f"service '{nat.service}' holds a range of ports; a NAT rule of a Device Manager names one port")
        if destination is not None and destination.port:
            if not ports:
                return fail("NAT_PORT", "a port translation needs a TCP or UDP service on the rule")
            if any("-" in part for _, part in ports):
                return fail("NAT_PORT", "a port range cannot be translated to one port")
        pre: Optional[_Ref] = None
        post: Optional[_Ref] = None
        if destination is not None:
            one_address = len(nat.destinations) == 1 and ANY not in nat.destinations and destination.address != ANY
            pre = self._nat_object(nat.destinations) if one_address else None
            post = self._nat_object([destination.address]) if one_address else None
            if pre is None or post is None:
                return fail("NAT_DESTINATION", "destination NAT needs one static address object on each side")
        elif ANY not in nat.destinations and ANY_V4 not in nat.destinations and ANY_V6 not in nat.destinations:
            pre = post = self._nat_object(nat.destinations)
            if pre is None:
                return fail("NAT_ADDRESSES", "the rule needs static addresses as destination")
        # A published port of a source that applies NAT rules of both directions together is written
        # the way the device does it: from the side of the server, so that source NAT rules still apply.
        server_side = destination is not None and source is None and nat.combines and everyone and bool(ports)
        plan.whole = pre is not None and not server_side
        # The address of an interface of an ASA or FTD source: on the device that is "the interface", and
        # only where the rule also translates a port and comes in on that interface.
        own_zone = self._interface_zone(nat.destinations[0]) if destination is not None and ports else ""
        label = nat.description if self.native else f"{nat.name} {nat.description}"
        count = 0
        for src_zone in nat.src_zones:
            src_ifs = self._interfaces(src_zone)
            for dst_zone in [ANY] if destination is not None else nat.dst_zones:
                mapped_zone = dst_zone
                rule = _NatOut("", nat.enabled, True, description=_clip(label))
                if source is None and destination is None:
                    # No translation: as the device writes an exemption, without answering ARP for the addresses.
                    rule.translated_source = real
                    rule.no_proxy_arp, rule.route_lookup = True, ANY not in (src_zone, dst_zone)
                elif source is None:
                    # A static rule works both ways on the device; the model's translates the destination only.
                    rule.translated_source, rule.unidirectional = real, True
                elif source.kind == SnatKind.INTERFACE:
                    mapped_zone = self._mapped_zone(nat, dst_zone)
                    if not mapped_zone:
                        return fail("NAT_NOT_CONVERTED", "not converted: source NAT to the address of the outgoing "
                                    "interface, which the rule does not name; give its zone with --target-nat-zone")  # fmt: skip
                    rule.static, rule.to_interface = False, True
                else:
                    pool = source.kind in (SnatKind.DYNAMIC_PORT, SnatKind.DYNAMIC)
                    mapped = self._pool_object(source.addresses) if pool else self._nat_object(source.addresses)
                    if mapped is None or not source.addresses:
                        return fail("NAT_POOL", "the translated addresses are not static addresses")
                    intervals = self._static(source.addresses) or []
                    one = sum(size(i) for i in normalize(intervals)) == 1
                    rule.static = source.kind == SnatKind.STATIC
                    if source.kind == SnatKind.DYNAMIC_PORT and not one:
                        rule.pat_pool = mapped
                    else:
                        rule.translated_source = mapped
                    if source.kind == SnatKind.DYNAMIC and one:
                        plan.findings.append(
                            (Severity.APPROX, "NAT_DYNAMIC_ONE_ADDRESS", "dynamic NAT to one address: the device shares "
                             "that address by translating ports, where the source gave it to one host at a time")  # fmt: skip
                        )
                    if source.kind == SnatKind.STATIC and not source.bidirectional:
                        rule.unidirectional = True
                    if source.kind == SnatKind.STATIC and not everyone:
                        inside = sum(size(i) for i in self._static(nat.sources) or [])
                        outside = sum(size(i) for i in normalize(intervals))
                        if inside != outside:
                            plan.findings.append(
                                (Severity.APPROX, "NAT_STATIC_SIZE", f"static NAT of {inside} addresses to {outside}: "
                                 "the device maps them in order and wraps around; check the mapping")  # fmt: skip
                            )
                dst_ifs = self._interfaces(mapped_zone)
                if src_ifs is None or dst_ifs is None:
                    unknown = src_zone if src_ifs is None else mapped_zone
                    if rule.to_interface or (own_zone and own_zone == src_zone):
                        return fail("NAT_NOT_CONVERTED", f"not converted: the rule is for the address of an interface of zone "
                                    f"'{unknown}', and the interfaces of that zone on the target are not known; name them "
                                    "with --interface-map")  # fmt: skip
                    limited = ANY not in nat.sources or ANY not in nat.destinations
                    finding = (Severity.APPROX if limited else Severity.REVIEW, "NAT_ZONES",
                               f"the rule applied to traffic {'from' if src_ifs is None else 'to'} zone {unknown} only. A NAT rule "
                               "of a Device Manager names interfaces, and the interfaces of that zone on the target are not "
                               "known: written for any interface. Name them with --interface-map")  # fmt: skip
                    if finding not in plan.findings:
                        plan.findings.append(finding)
                for src_if in src_ifs or [""]:
                    for dst_if in dst_ifs or [""]:
                        for protocol, port in ports or [("", "")]:
                            count += 1
                            if count > _MAX_NAT_RULES * 4:
                                return fail("NAT_NOT_CONVERTED", "not converted: the rule would become more than "
                                            f"{_MAX_NAT_RULES * 4} NAT rules (zones, interfaces and ports multiply)")  # fmt: skip
                            out = dataclasses.replace(rule)
                            if server_side:
                                assert destination is not None and post is not None and pre is not None
                                # nat (any,src) source static <server> <published> service <real port> <port>
                                out = _NatOut("", nat.enabled, True, "", src_if, post, pre, description=_clip(label))
                                if own_zone and own_zone == src_zone:
                                    out.translated_source, out.to_interface, plan.interface_keyword = None, True, True
                                out.original_source_port = self._port_object(protocol, destination.port or port)
                                out.translated_source_port = self._port_object(protocol, port)
                            else:
                                out.src_if, out.dst_if, out.original_source = src_if, dst_if, real
                                if pre is not None:
                                    out.original_destination, out.translated_destination = pre, post
                                    if own_zone and own_zone == src_zone:
                                        out.original_destination, out.from_interface, plan.interface_keyword = None, True, True
                                if protocol:
                                    new_port = destination.port if destination is not None and destination.port else port
                                    out.original_destination_port = self._port_object(protocol, port)
                                    out.translated_destination_port = self._port_object(protocol, new_port)
                            if out not in plan.rules:
                                plan.rules.append(out)
        return plan

    def _port_object(self, protocol: str, port: str) -> _Ref:
        ref = self._atom_ref(_Atom("port", protocol, port))
        assert isinstance(ref, _Ref)
        return ref

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
        for index, rule in enumerate(plan.rules):
            rule.name = nat.name if index == 0 else self.names.unique(nat.name, self.names.nat_names, self.names.rules, f"-{index + 1}")
            for zone in (rule.src_if, rule.dst_if):
                if zone and not self.fdm and zone not in self.zones:
                    self.zones.append(zone)
        self.nat += plan.rules
        item.emitted_as.append(f"{len(plan.rules)} NAT rule" + ("s" if len(plan.rules) != 1 else ""))
        if plan.whole:
            self.whole.add(nat.origin)
        if nat.destination_translation is not None and plan.whole:
            self.tied.add(nat.origin)

    # -- output -----------------------------------------------------------

    def run(self) -> None:
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=self.tied, whole=self.whole)
        for rule in self.p.rules:
            self._rule(rule)
        self._intrazone_tail()
        self._drop_unused_interface_objects()
        self._notes()

    def _drop_unused_interface_objects(self) -> None:
        """An object that stood for "the interface" in the NAT rules of the source and is not needed now that the word is back."""
        used: Set[_Ref] = {member for obj in self.objects for member in obj.members}
        for rule in self.rules:
            used |= set(rule.sources or []) | set(rule.destinations or [])
        for nat in self.nat:
            used |= {ref for ref in (nat.original_source, nat.translated_source, nat.original_destination,
                                     nat.translated_destination, nat.pat_pool) if ref is not None}  # fmt: skip
        self.objects = [obj for obj in self.objects if obj.ref in used or not _is_interface_object(self.p, obj.ref.name)]

    def _notes(self) -> None:
        note = self.report.note
        used = transform.dedupe([zone for rule in self.rules for zone in rule.src_zones + rule.dst_zones])
        if self.fdm:
            note(
                Severity.REVIEW, "FDM_LOAD",
                "the output is a file for the configuration import of a Firewall Device Manager (POST /action/uploadconfigfile, "
                "then /action/configimport). Its first object must say the hardware model and software version of the target: "
                + ("they are those of the export that was read. " if self._fdm_metadata()[0] != _FDM_REPLACE else
                   "copy both from the first object of an export of the target device. ")
                + "The import adds to what the device has: its access rules stay above the rules of this file and decide "
                "first, its default action stays what it is, and its NAT rules come first. Nothing is in force until the "
                "changes are deployed: look at them in the pending changes before that",
            )  # fmt: skip
            note(
                Severity.INFO, "EXISTING_OBJECTS",
                "an import changes what the device has under the same name: an object or a rule of this file replaces the "
                "one on the target. --target-prefix gives every object that is created a name of its own",
            )  # fmt: skip
            if used:
                note(
                    Severity.REVIEW, "ZONES_REQUIRED",
                    "the rules name these security zones, which must exist on the target (or be renamed with --zone-map): "
                    + ", ".join(used) + ". Zones are not written: an import would take the interfaces out of a zone that exists",
                )  # fmt: skip
            interfaces = transform.dedupe([name for rule in self.nat for name in (rule.src_if, rule.dst_if) if name])
            if interfaces:
                note(
                    Severity.REVIEW, "INTERFACES_REQUIRED",
                    "the NAT rules name these interfaces by their logical name, as physical interfaces: " + ", ".join(interfaces)
                    + ". Map the names with --interface-map. Where one is a subinterface, an EtherChannel or a VLAN interface, "
                    f"change its \"type\" in the file ({_FDM_INTERFACE})",
                )  # fmt: skip
        else:
            note(
                Severity.REVIEW, "FMC_LOAD",
                f"the output is a Python script that loads the policy into a Management Center through its REST API. It "
                f"creates the objects, a new access control policy '{self.options.target_policy}' and, when there are NAT "
                "rules, a NAT policy of the same name, and assigns them to no device: nothing is in force until the policies "
                "are assigned and deployed. It changes nothing that exists, and stops before it creates anything when a name "
                "is taken. Run it with --show and with --dry-run first. The new access control policy uses the default "
                "prefilter policy and no intrusion or file policies. The script was written from Cisco's API documentation and "
                "has not been run against a Management Center: use it first where a mistake costs nothing",
            )  # fmt: skip
            if self.zones:
                note(
                    Severity.REVIEW, "ZONES_REQUIRED",
                    "the rules name these security zones (rename them with --zone-map): " + ", ".join(self.zones) + ". A zone "
                    "that exists on the Management Center is used as it is; one that does not is created empty, and matches "
                    "no traffic until the interfaces of the devices are put in it",
                )  # fmt: skip
        same_kind = self.p.vendor in ("fmc", "fdm")  # one default action for everything, inside a zone or not
        if self.p.default_intrazone == Action.ALLOW and not same_kind:
            note(
                Severity.REVIEW, "INTRAZONE_DEFAULT",
                "the source allows traffic inside a zone unless a rule denies it; a Cisco Secure Firewall asks its access "
                "rules about traffic between the interfaces of a zone as about any other. Check zones with several interfaces",
            )  # fmt: skip
        if self.p.default_interzone == Action.ALLOW:
            note(
                Severity.REVIEW, "INTERZONE_DEFAULT",
                ("the default action of the source allows what no rule matches; " if same_kind else
                 "the source allows traffic between zones that no rule matches; ")
                + ("the default action of the device is not changed by an import" if self.fdm
                   else "the new access control policy blocks it by default")
                + ". Add a final rule that allows it if that was intended",
            )  # fmt: skip
        if self.fqdn:
            note(Severity.INFO, "FQDN_DNS", "FQDN objects need name resolution on the device (a DNS server group in its platform settings)")

    # -- a Management Center ----------------------------------------------

    _FMC_TYPES = {"host": "Host", "network": "Network", "range": "Range", "fqdn": "FQDN", "netgroup": "NetworkGroup",
                  "port": "ProtocolPortObject", "icmp4": "ICMPV4Object", "icmp6": "ICMPV6Object", "portgroup": "PortObjectGroup",
                  "zone": "SecurityZone"}  # fmt: skip
    _FMC_STEPS = (("host", "host objects", "object/hosts"), ("network", "network objects", "object/networks"),
                  ("range", "range objects", "object/ranges"), ("fqdn", "FQDN objects", "object/fqdns"),
                  ("netgroup", "network groups", "object/networkgroups"), ("port", "port objects", "object/protocolportobjects"),
                  ("icmp4", "ICMP objects", "object/icmpv4objects"), ("icmp6", "ICMPv6 objects", "object/icmpv6objects"),
                  ("portgroup", "port groups", "object/portobjectgroups"))  # fmt: skip

    def _fmc_ref(self, ref: _Ref) -> Dict[str, Any]:
        return {"@ref": self._FMC_TYPES[ref.kind], "name": ref.name}

    def _fmc_port(self, ref: PortRef) -> Dict[str, Any]:
        return self._fmc_ref(ref) if isinstance(ref, _Ref) else {"type": "PortLiteral", "protocol": str(ref.protocol)}

    def _fmc_object(self, obj: _Object) -> Dict[str, Any]:
        kind = obj.ref.kind
        out: Dict[str, Any] = {"type": self._FMC_TYPES[kind], "name": obj.ref.name}
        if obj.description:
            out["description"] = obj.description
        if kind in ("host", "network", "range", "fqdn"):
            out["value"] = obj.value
        if kind == "fqdn":
            out["dnsResolution"] = {4: "IPV4_ONLY", 6: "IPV6_ONLY"}.get(obj.resolution, "IPV4_AND_IPV6")
        if kind in ("netgroup", "portgroup"):
            out["objects"] = [self._fmc_ref(member) for member in obj.members]
        atom = obj.atom
        if atom is not None and kind == "port":
            out["protocol"] = atom.protocol.upper()
            if atom.port:
                out["port"] = atom.port
        elif atom is not None:
            if atom.icmp_type is not None:
                out["icmpType"] = str(atom.icmp_type)
            if atom.icmp_code is not None:
                out["code"] = str(atom.icmp_code)
        return out

    def _group_level(self, obj: _Object, levels: Dict[_Ref, int]) -> int:
        return 1 + max([levels.get(member, 0) for member in obj.members if member.kind == "netgroup"] or [0])

    def as_fmc(self) -> str:
        self.run()
        steps: List[Dict[str, Any]] = []
        levels: Dict[_Ref, int] = {}
        for obj in self.objects:
            if obj.ref.kind == "netgroup":
                levels[obj.ref] = self._group_level(obj, levels)
        for kind, what, path in self._FMC_STEPS:
            listed = [obj for obj in self.objects if obj.ref.kind == kind]
            # A group is created after the groups it holds: one call per level of nesting.
            for level in sorted({levels.get(obj.ref, 1) for obj in listed}) if kind == "netgroup" else [0]:
                items = [self._fmc_object(obj) for obj in listed if kind != "netgroup" or levels[obj.ref] == level]
                if items:
                    label = what if level < 2 else f"{what} that hold groups (level {level})"
                    steps.append({"what": label, "type": self._FMC_TYPES[kind], "path": path, "items": items})
        actions = {"allow": "ALLOW", "trust": "TRUST", "block": "BLOCK", "reset": "BLOCK_RESET"}
        rules: List[Dict[str, Any]] = []
        for rule in self.rules:
            blocks = rule.action in ("block", "reset")
            logs = rule.log_start or rule.log_end
            out: Dict[str, Any] = {
                "type": "AccessRule", "name": rule.name, "enabled": rule.enabled, "action": actions[rule.action],
                # A connection that is blocked has no end to log: its event is that of its beginning.
                "logBegin": logs if blocks else rule.log_start, "logEnd": False if blocks else rule.log_end,
                "sendEventsToFMC": logs, "logFiles": False,
            }  # fmt: skip
            for key, zones in (("sourceZones", rule.src_zones), ("destinationZones", rule.dst_zones)):
                if zones:
                    out[key] = {"objects": [self._fmc_ref(_Ref("zone", zone)) for zone in zones]}
            for key, refs in (("sourceNetworks", rule.sources), ("destinationNetworks", rule.destinations)):
                if refs is not None:
                    out[key] = {"objects": [self._fmc_ref(ref) for ref in refs]}
            for key, ports in (("sourcePorts", rule.src_ports), ("destinationPorts", rule.dst_ports)):
                objects = [self._fmc_port(ref) for ref in ports if isinstance(ref, _Ref)]
                literals = [self._fmc_port(ref) for ref in ports if isinstance(ref, _Lit)]
                if objects or literals:
                    out[key] = {name: value for name, value in (("objects", objects), ("literals", literals)) if value}
            if rule.description:
                out["newComments"] = [rule.description]
            rules.append(out)
        nat: List[Dict[str, Any]] = []
        for one in self.nat:
            entry: Dict[str, Any] = {
                "type": "FTDManualNatRule", "natType": "STATIC" if one.static else "DYNAMIC", "enabled": one.enabled,
                "unidirectional": one.unidirectional, "interfaceInTranslatedSource": one.to_interface,
                "interfaceInOriginalDestination": one.from_interface, "noProxyArp": one.no_proxy_arp,
                "routeLookup": one.route_lookup, "dns": False, "fallThrough": False, "netToNet": False, "interfaceIpv6": False,
            }  # fmt: skip
            if one.description:
                entry["description"] = one.description
            for key, zone in (("sourceInterface", one.src_if), ("destinationInterface", one.dst_if)):
                if zone:
                    entry[key] = self._fmc_ref(_Ref("zone", zone))
            for key, ref in (
                ("originalSource", one.original_source), ("translatedSource", one.translated_source),
                ("originalDestination", one.original_destination), ("translatedDestination", one.translated_destination),
                ("originalSourcePort", one.original_source_port), ("translatedSourcePort", one.translated_source_port),
                ("originalDestinationPort", one.original_destination_port),
                ("translatedDestinationPort", one.translated_destination_port),
            ):  # fmt: skip
                if ref is not None:
                    entry[key] = self._fmc_ref(ref)
            if one.pat_pool is not None:
                entry["patOptions"] = {"patPoolAddress": self._fmc_ref(one.pat_pool), "interfacePat": False,
                                       "includeReserve": False, "roundRobin": False, "extendedPat": False, "flatPortRange": False}  # fmt: skip
            nat.append(entry)
        plan = {
            "format": 1, "generator": f"FWShift {__version__}", "policy": self.options.target_policy or "FWShift",
            "description": "Converted by FWShift" + (f" from {self.p.vendor}" if self.p.vendor else ""),
            "default_action": "BLOCK", "zones": list(self.zones),
            "existing": [{"type": self._FMC_TYPES[ref.kind], "name": ref.name} for ref in self.existing],
            "steps": steps, "rules": rules, "nat": nat,
        }  # fmt: skip
        data = json.dumps(plan, indent=1, ensure_ascii=True)
        tail = ["", "# The policy, as data. Do not change it here: convert again.", "#"]
        return loader_source().rstrip("\n") + "\n" + "\n".join(tail + ["#: " + line for line in data.split("\n")]) + "\n"

    # -- a Device Manager -------------------------------------------------

    def _fdm_metadata(self) -> Tuple[str, str]:
        """(hardware model, software version) for the first object of the file."""
        match = _FDM_SCOPE.fullmatch(self.p.scope) if self.native else None
        return (match.group(2), match.group(1)) if match else (_FDM_REPLACE, _FDM_REPLACE)

    def _fdm_type(self, ref: _Ref) -> str:
        if ref.kind in ("host", "network", "range", "fqdn"):
            return "networkobject"
        if ref.kind == "netgroup":
            return "networkobjectgroup"
        if ref.kind == "portgroup":
            return "portobjectgroup"
        if ref.kind == "zone":
            return "securityzone"
        if ref.kind == "interface":
            return _FDM_INTERFACE
        if ref.kind in ("icmp4", "icmp6"):
            return "icmpv4portobject" if ref.kind == "icmp4" else "icmpv6portobject"
        if ref.kind == "protocol":
            return "protocolobject"
        atom = self._atom_of(ref)
        return "udpportobject" if atom is not None and atom.protocol == "udp" else "tcpportobject"

    def _atom_of(self, ref: _Ref) -> Optional[_Atom]:
        if ref not in self._atom_index:
            found = [self.by_ref[ref].atom] if ref in self.by_ref else []
            if not found and ref.name in self.p.services and len(self.p.services[ref.name].entries) == 1:
                atoms = self._entry_atoms(self.p.services[ref.name].entries[0])[0]  # an object the device has already
                found = [atoms[0][1]] if len(atoms) == 1 else []
            self._atom_index[ref] = found[0] if found else None
        return self._atom_index[ref]

    def _fdm_ref(self, ref: _Ref) -> Dict[str, Any]:
        return {"type": self._fdm_type(ref), "name": ref.name}

    def _fdm_object(self, obj: _Object) -> Dict[str, Any]:
        kind = obj.ref.kind
        out: Dict[str, Any] = {"type": self._fdm_type(obj.ref), "name": obj.ref.name}
        if obj.description:
            out["description"] = obj.description
        if kind in ("host", "network", "range", "fqdn"):
            out["subType"], out["value"] = kind.upper(), obj.value
        if kind == "fqdn":
            out["dnsResolution"] = {4: "IPV4_ONLY", 6: "IPV6_ONLY"}.get(obj.resolution, "IPV4_AND_IPV6")
        if kind in ("netgroup", "portgroup"):
            out["objects"] = [self._fdm_ref(member) for member in obj.members]
        atom = obj.atom
        if atom is None:
            return out
        if kind == "port":
            out["port"] = atom.port or "1-65535"
        elif kind == "protocol":
            out["protocol"] = FDM_PROTOCOL_NAMES[atom.number]
        else:
            six = kind == "icmp6"
            types, codes, prefix = (FDM_ICMP6_TYPES, FDM_ICMP6_CODES, "icmpv6") if six else (FDM_ICMP_TYPES, FDM_ICMP_CODES, "icmpv4")
            out[f"{prefix}Type"] = "ANY" if atom.icmp_type is None else next(n for n, v in types.items() if v == atom.icmp_type)
            if atom.icmp_code is not None:
                out[f"{prefix}Code"] = next(n for n, v in codes.items() if v == (atom.icmp_type, atom.icmp_code))
        return out

    def as_fdm(self) -> str:
        self.run()
        model, version = self._fdm_metadata()
        entries: List[Dict[str, Any]] = [{"type": "metadata", "hardwareModel": model, "softwareVersion": version,
                                          "apiVersion": "latest", "configType": "DELTA_CONFIG", "exportType": "PARTIAL_EXPORT"}]  # fmt: skip

        def wrap(data: Dict[str, Any], parent: str = "") -> None:
            wrapper: Dict[str, Any] = {"type": "identitywrapper", "action": "CREATE"}
            if parent:
                wrapper["parentName"] = parent
            wrapper["data"] = data
            entries.append(wrapper)

        for obj in self.objects:
            wrap(self._fdm_object(obj))
        for rule in self.rules:
            if rule.action in ("block", "reset"):
                log = "LOG_BOTH" if rule.log_start or rule.log_end else "LOG_NONE"
            else:
                log = "LOG_BOTH" if rule.log_start else "LOG_FLOW_END" if rule.log_end else "LOG_NONE"
            data: Dict[str, Any] = {
                "type": "accessrule", "name": rule.name,
                "ruleAction": {"allow": "PERMIT", "trust": "TRUST"}.get(rule.action, "DENY"), "eventLogAction": log,
                "sourceZones": [self._fdm_ref(_Ref("zone", zone)) for zone in rule.src_zones],
                "destinationZones": [self._fdm_ref(_Ref("zone", zone)) for zone in rule.dst_zones],
                "sourceNetworks": [self._fdm_ref(ref) for ref in rule.sources or []],
                "destinationNetworks": [self._fdm_ref(ref) for ref in rule.destinations or []],
                "sourcePorts": [self._fdm_ref(ref) for ref in rule.src_ports if isinstance(ref, _Ref)],
                "destinationPorts": [self._fdm_ref(ref) for ref in rule.dst_ports if isinstance(ref, _Ref)],
            }  # fmt: skip
            wrap(data)
        for one in self.nat:
            nat: Dict[str, Any] = {
                "type": "manualnatrule", "name": one.name, "natType": "STATIC" if one.static else "DYNAMIC",
                "enabled": one.enabled, "unidirectional": one.unidirectional,
                "interfaceInTranslatedSource": one.to_interface, "interfaceInOriginalDestination": one.from_interface,
                "noProxyArp": one.no_proxy_arp, "routeLookup": one.route_lookup, "dns": False, "netToNet": False,
                "interfaceIPv6": False,
            }  # fmt: skip
            if one.description:
                nat["description"] = one.description.replace(";", ",")
            for key, name in (("sourceInterface", one.src_if), ("destinationInterface", one.dst_if)):
                if name:
                    nat[key] = self._fdm_ref(_Ref("interface", name))
            for key, ref in (
                ("originalSource", one.original_source), ("translatedSource", one.translated_source),
                ("originalDestination", one.original_destination), ("translatedDestination", one.translated_destination),
                ("originalSourcePort", one.original_source_port), ("translatedSourcePort", one.translated_source_port),
                ("originalDestinationPort", one.original_destination_port),
                ("translatedDestinationPort", one.translated_destination_port),
            ):  # fmt: skip
                if ref is not None:
                    nat[key] = self._fdm_ref(ref)
            if one.pat_pool is not None:
                nat["patOptions"] = {"type": "patoptions", "patPoolAddress": self._fdm_ref(one.pat_pool), "interfacePat": False,
                                     "roundRobin": False, "flat": False, "extended": False, "includeReserve": False}  # fmt: skip
            wrap(nat, "NGFW-Before-Auto-NAT-Policy")
        lines = [json.dumps(entry, ensure_ascii=True) for entry in entries]
        return "[\n" + ",\n".join(lines) + "\n]\n"


def is_range_text(member: str) -> bool:
    return "-" in member and "/" not in member


def _distinct(items: Sequence[Any]) -> List[Any]:
    out: List[Any] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out
