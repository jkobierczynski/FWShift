# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Sophos Firewall emitter: neutral model -> the Entities.xml that *Backup & firmware > Import export* takes.

Design rules:

* Nothing is ever widened silently. A rule whose match cannot be expressed is written with
  ``<Status>Disable</Status>`` and reported.
* Sophos Firewall keeps a rulebase per IP version, and hosts, host groups and host names apart.
  A rule that matches both IP versions is written twice, and a group of the model becomes up to
  three groups.
* The model has a negation per field; Sophos Firewall has *exclusions*, which it applies together:
  a rule is skipped only for traffic that matches every kind of exclusion it has. One negated
  field is an exclusion. Of two, one is written as the addresses that are left.
* A firewall rule matches the destination address before destination NAT and the destination zone
  after it, as the model does. NAT rules match interfaces, not zones.
* Only element names that documentation or tools of Sophos show are written, with two exceptions
  that DEVELOPMENT.md lists: the match of a NAT rule, and the root element.
"""

from __future__ import annotations

import copy
import io
import ipaddress
import re
import tarfile
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from xml.sax.saxutils import escape

from .. import transform
from ..errors import FwshiftError
from ..appmap import (
    SOPHOS_FACTORY_SERVICE_NAMES,
    SOPHOS_ICMP6_TYPES,
    SOPHOS_ICMP_CODES,
    SOPHOS_ICMP_TYPES,
    SOPHOS_PROTOCOL_NAMES,
    SOPHOS_PROTOCOLS_CONFIRMED,
)
from ..model import (
    ANY,
    Action,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    ServiceEntry,
    SnatKind,
)
from ..names import SOPHOS, SOPHOS_NATIVE, SOPHOS_RULE, NameRules, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text, is_number, normalize, parse_literal, size, subtract
from ..options import Options
from ..parsers.sophos import PROFILE_ELEMENTS
from ..report import Report, Severity

_PLACEHOLDER = "FWSHIFT PLACEHOLDER, matches nothing: "
_DEFAULT_API = "1800.1"  # SFOS 18.0: an import is taken by the same or a later version
_ANY = "\0any"  # in a list of references: every address of the IP version, every service
_FULL = {4: "\0full4", 6: "\0full6"}  # a literal that is the whole of an IP version, as member of a group
_XML_BAD = re.compile("[^\t\n\r\x20-퟿-�\U00010000-\U0010ffff]")
_TYPES = ("TCPorUDP", "IP", "ICMP", "ICMPv6")
_SUFFIX = {"TCPorUDP": "-tcpudp", "IP": "-ip", "ICMP": "-icmp", "ICMPv6": "-icmpv6"}
_ACTIONS = {Action.ALLOW: "Accept", Action.DENY: "Drop", Action.DROP: "Drop", Action.RESET_CLIENT: "Reject",
            Action.RESET_SERVER: "Reject", Action.RESET_BOTH: "Reject"}  # fmt: skip
_FACTORY_SERVICES: FrozenSet[str] = frozenset(name.lower() for name in SOPHOS_FACTORY_SERVICE_NAMES)
# Words the format itself uses where a name can stand: an object of another platform cannot carry one.
_WORDS: FrozenSet[str] = frozenset({"any", "original", "masq", "none"})


def _x(text: str) -> str:
    return escape(_XML_BAD.sub("_", text))


def _clip(text: str, limit: int = 255) -> str:
    return " ".join(text.split())[:limit]


class _E:
    """An XML element: text, or children."""

    __slots__ = ("tag", "text", "children", "attrs")

    def __init__(self, tag: str, text: str = "", children: Optional[List["_E"]] = None, attrs: str = "") -> None:
        self.tag, self.text, self.children, self.attrs = tag, text, children, attrs

    def lines(self, depth: int = 1) -> List[str]:
        pad = "  " * depth
        if self.children is None:
            return [f"{pad}<{self.tag}{self.attrs}>{_x(self.text)}</{self.tag}>"]
        out = [f"{pad}<{self.tag}{self.attrs}>"]
        for child in self.children:
            out += child.lines(depth + 1)
        return out + [f"{pad}</{self.tag}>"]


def _entity(tag: str, children: List[_E]) -> _E:
    return _E(tag, children=children, attrs=' transactionid=""')


def _listed(tag: str, child: str, names: List[str]) -> _E:
    return _E(tag, children=[_E(child, name) for name in names])


class _Names:
    """Names as the target takes them. Names of another platform are kept apart whatever their case."""

    def __init__(self, native: bool) -> None:
        self.native = native
        self.objects: NameRules = SOPHOS_NATIVE if native else SOPHOS
        self.rules: NameRules = SOPHOS_NATIVE if native else SOPHOS_RULE
        self.addresses: Set[str] = set()
        self.services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.source: Dict[str, str] = {}  # name of an object here -> its name in the report

    def fold(self, name: str) -> str:
        return name if self.native else name.lower()

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
        _WORDS if foreign else frozenset(),
    )
    service_map = plan(
        [(n, "service") for n in p.services] + [(n, "service-group") for n in p.service_groups],
        names.services,
        (_FACTORY_SERVICES | _WORDS) if foreign else frozenset(),
    )
    transform.rename_objects(p, address_map, service_map)
    if foreign:
        names.rule_names.add("none")  # what a NAT rule that is linked to no firewall rule says
        names.nat_names.add("none")
    for rule in p.rules:
        rule.name = names.unique(rule.name, names.rule_names, names.rules)
    for nat in p.nat_rules:
        nat.name = names.unique(nat.name, names.nat_names, names.rules)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = {z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY}
    transform.apply_zone_map(p, options.zone_map)
    # "Any" in a list of zones or interfaces is every zone or interface: a name like it cannot be written.
    zones = sorted({z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY and z.lower() in _WORDS})
    if zones:
        mapped = zones[0] in options.zone_map.values()
        raise FwshiftError(
            (f"--zone-map: '{zones[0]}' is a word of the Sophos format ('Any' is every zone) and cannot be the name of a zone"
             if mapped else f"zone '{zones[0]}' carries a name that is a word of the Sophos format ('Any' is every zone): "
             f"give it another name with --zone-map {zones[0]}=NAME"))  # fmt: skip
    for interface in options.interface_map.values():
        if interface.lower() in _WORDS:
            raise FwshiftError(f"--interface-map: '{interface}' is a word of the Sophos format and cannot be the name of an interface")
    transform.ensure_references(p, report)
    native = p.vendor == "sophos"
    names = _Names(native)
    _rename(p, report, names, options.object_prefix, _on_target(p))
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, names, source_zones).run()


def _wildcard(p: Policy, name: str) -> bool:
    """A host name with a wildcard, read from a Sophos Firewall: the model has no such thing, a Sophos has."""
    address = p.addresses[name]
    return p.vendor == "sophos" and address.kind == AddressKind.UNSUPPORTED and address.value.startswith("*.")


def _on_target(p: Policy) -> Set[str]:
    """Objects of a Sophos source that a Sophos target has without their being created: its system hosts."""
    return {name for name, address in p.addresses.items() if address.builtin == "sophos"} if p.vendor == "sophos" else set()


def archive(xml: str) -> bytes:
    """The file as an import wants it: a tar that holds ``Entities.xml``."""
    data = xml.encode("utf-8")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("Entities.xml")
        info.size, info.mode = len(data), 0o644
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# -- services (no side effects) ------------------------------------------------------------------


def _sophos_ports(ports: str) -> List[str]:
    """``80,8000-8010`` as Sophos writes it. Port 0 is no port of a connection, and no port a Sophos service takes."""
    if not ports:
        return ["1:65535"]
    out: List[str] = []
    for part in ports.split(","):
        first, _, last = part.partition("-")
        low, high = max(int(first), 1), int(last or first)
        if high >= low:
            out.append(str(low) if low == high else f"{low}:{high}")
    return out


def _has_port_zero(entry: ServiceEntry) -> bool:
    return any(part.split("-")[0].strip("0") == "" for ports in (entry.dst_ports, entry.src_ports) if ports for part in ports.split(","))


def _details(entries: List[ServiceEntry]) -> Tuple[Dict[str, List[Tuple[Tuple[str, str], ...]]], str, List[str]]:
    """(details per type of Sophos service, why the service cannot be written, protocol names to check)."""
    parts: Dict[str, List[Tuple[Tuple[str, str], ...]]] = {}
    unchecked: List[str] = []

    def add(kind: str, detail: Tuple[Tuple[str, str], ...]) -> None:
        if detail not in parts.setdefault(kind, []):
            parts[kind].append(detail)

    for entry in entries:
        protocol = entry.protocol
        if protocol in (Protocol.TCP, Protocol.UDP):
            if not _sophos_ports(entry.src_ports) or not _sophos_ports(entry.dst_ports):
                return {}, "port 0 and no other, which is no port a Sophos service can name", []
            for src in _sophos_ports(entry.src_ports):
                for dst in _sophos_ports(entry.dst_ports):
                    add("TCPorUDP", (("SourcePort", src), ("DestinationPort", dst), ("Protocol", protocol.value.upper())))
        elif protocol == Protocol.SCTP:
            if entry.dst_ports or entry.src_ports:
                return {}, "SCTP ports, which a Sophos service cannot name (it has ports for TCP and UDP only)", []
            add("IP", (("ProtocolName", "SCTP"),))
        elif protocol == Protocol.IP:
            number = entry.ip_protocol
            if number is None:
                return {}, "a service for every IP protocol, which only 'any service' is on Sophos Firewall", []
            name = SOPHOS_PROTOCOL_NAMES.get(number) or (f"IPProto{number}" if 143 <= number <= 255 else "")
            if not name:
                return {}, f"IP protocol {number}, for which Sophos Firewall has no name", []
            if number not in SOPHOS_PROTOCOLS_CONFIRMED and number < 143:
                unchecked.append(name)
            add("IP", (("ProtocolName", name),))
        else:
            six = protocol == Protocol.ICMP6
            label = "ICMPv6" if six else "ICMP"
            if entry.icmp_type is None and entry.icmp_code is not None:
                return {}, f"{label} code {entry.icmp_code} of every type, which a Sophos service cannot say", []
            if entry.icmp_type is not None and entry.icmp_type not in (SOPHOS_ICMP6_TYPES if six else SOPHOS_ICMP_TYPES):
                return {}, f"{label} type {entry.icmp_type}, which is not among the types of a Sophos service", []
            if entry.icmp_code is not None and entry.icmp_code not in SOPHOS_ICMP_CODES:
                return {}, f"{label} code {entry.icmp_code}, which is not among the codes of a Sophos service", []
            kind = "-1" if entry.icmp_type is None else str(entry.icmp_type)
            code = "-1" if entry.icmp_code is None else str(entry.icmp_code)
            add(label, ((f"{label}Type", kind), (f"{label}Code", code)))
    return parts, "", unchecked


def _entry_families(entries: List[ServiceEntry]) -> Set[int]:
    """The IP versions a service can match at all: ICMP is IPv4, ICMPv6 is IPv6."""
    out: Set[int] = set()
    for entry in entries:
        if entry.protocol == Protocol.ICMP or (entry.protocol == Protocol.IP and entry.ip_protocol == 1):
            out.add(4)
        elif entry.protocol == Protocol.ICMP6 or (entry.protocol == Protocol.IP and entry.ip_protocol == 58):
            out.add(6)
        else:
            return {4, 6}
    return out or {4, 6}


@dataclass
class _Variant:
    """What a rule is for one IP version."""

    version: int
    sources: List[str]
    destinations: List[str]
    exclusions: Dict[str, List[str]] = field(default_factory=dict)


# -- emitter ------------------------------------------------------------------------------------


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, names: _Names, source_zones: Set[str]) -> None:
        self.p, self.report, self.options, self.names = p, report, options, names
        self.native = names.native
        self.source_zones = source_zones  # zone and interface names of the rules before --zone-map
        self.as_they_are = _on_target(p) | {name for name in p.addresses if _wildcard(p, name)}
        self.taint_a = transform.tainted_addresses(p, keep=self.as_they_are)
        self.taint_s: Dict[str, str] = {}
        # Entities, in the order they are written.
        self.hosts: List[_E] = []
        self.fqdn_hosts: List[_E] = []
        self.host_groups: List[_E] = []
        self.fqdn_groups: List[_E] = []
        self.services: List[_E] = []
        self.service_groups: List[_E] = []
        self.rules: List[_E] = []
        self.nat: List[_E] = []
        # What an address name is here: ("ip" | "builtin" | "full" | "fqdn" | "placeholder", IP version or 0).
        self.kind: Dict[str, Tuple[str, int]] = {_FULL[4]: ("full", 4), _FULL[6]: ("full", 6)}
        self.group_refs: Dict[str, Dict[int, List[str]]] = {}
        self.literals: Dict[Interval, str] = {}
        self.ranges: Dict[Interval, str] = {}  # hosts that are one address or one range: what a NAT rule translates to
        self.placeholders = 0
        self.svc_leaves: Dict[str, List[str]] = {}  # service or group of the model -> the services that make it up
        self.svc_families: Dict[str, Set[int]] = {}
        self.svc_any: Set[str] = set()  # services that are every IP protocol: "any service" where a rule names them
        self.app_services: Dict[str, str] = {}
        self.port_services: Dict[Tuple[Tuple[str, ...], str], str] = {}
        self.last_rule: Dict[int, str] = {}
        self.last_nat: Dict[int, str] = {}
        self.twins = 0

    # -- top level --------------------------------------------------------

    def run(self) -> str:
        self._addresses()
        self._groups()
        self._services()
        for rule in self.p.rules:
            self._rule(rule)
        self._intrazone_tail()
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "first-match")
        self._notes()
        version = self.p.scope[len("API version "):] if self.native and self.p.scope.startswith("API version ") else ""
        if not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,3}", version):
            version = _DEFAULT_API
        out = ['<?xml version="1.0" encoding="UTF-8"?>', f'<Configuration APIVersion="{version}" IPS_CAT_VER="1">']
        for entities in (self.hosts, self.fqdn_hosts, self.host_groups, self.fqdn_groups, self.services, self.service_groups,
                         self.rules, self.nat):  # fmt: skip
            for entity in entities:
                out += entity.lines()
        return "\n".join(out + ["</Configuration>"]) + "\n"

    def _notes(self) -> None:
        note = self.report.note
        note(
            Severity.REVIEW, "SOPHOS_LOAD",
            "the output is an Entities.xml. Put it in a tar archive under that name (or let FWShift do it: give -o a "
            "name that ends in .tar) and import it under Backup & firmware > Import export. Rules are added below the "
            "rules the firewall has: a firewall rule or NAT rule that is there already, such as the default source NAT "
            "rule of a new firewall, comes first. An import can stop at the first object the firewall does not take: "
            "compare the number of rules and objects with this report, on a firewall that is not in production",
        )  # fmt: skip
        note(
            Severity.INFO, "EXISTING_OBJECTS",
            "an import overwrites what the firewall has under the same name: a host, a service or a rule that is in this "
            "output replaces the one on the target. --target-prefix gives every object that is created a name of its own",
        )  # fmt: skip
        if self.twins:
            note(
                Severity.INFO, "IP_VERSION_SPLIT",
                f"{self.twins} rule(s) match IPv4 and IPv6 traffic and were written twice: Sophos Firewall keeps a rulebase "
                "per IP version. The name of the IPv6 rule ends in _v6",
            )  # fmt: skip
        if not self.native:
            zones = transform.dedupe([z for r in self.p.rules for z in r.src_zones + r.dst_zones if z != ANY]
                                     + self._intrazone_allow_zones())  # fmt: skip
            if zones:
                note(
                    Severity.REVIEW, "ZONES_REQUIRED",
                    "the rules name these zones, which must exist on the target (or be renamed with --zone-map): "
                    + ", ".join(zones) + ". Zones are not created: an import would overwrite the device access of a zone "
                    "that exists",
                )  # fmt: skip
        if self.p.default_intrazone == Action.ALLOW:
            note(
                Severity.REVIEW, "INTRAZONE_DEFAULT",
                "the source allows traffic inside a zone unless a rule denies it; Sophos Firewall drops traffic between "
                "the interfaces of a zone unless a rule allows it. Check zones with several interfaces",
            )  # fmt: skip
        if self.p.default_interzone == Action.ALLOW:
            note(
                Severity.REVIEW, "INTERZONE_DEFAULT",
                "the source allows traffic between zones that no rule matches; Sophos Firewall drops it, so add a final "
                "rule that accepts it if that was intended",
            )  # fmt: skip

    # -- addresses --------------------------------------------------------

    def _addresses(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            if name in self.as_they_are:
                self.report.withdraw("address", self.names.source.get(name, name), {"UNSUPPORTED_ADDRESS"})
            if self.native and address.builtin == "sophos":
                self.kind[name] = ("builtin", address.fqdn_family or 4)  # the target has it
                self.report.add("address", self.names.source.get(name, name), Severity.INFO, "SYSTEM_HOST",
                                "system host of the firewall: referenced by name, it must exist on the target")  # fmt: skip
            elif _wildcard(self.p, name):
                self.fqdn_hosts.append(_entity("FQDNHost", [_E("Name", name), _E("Description", _clip(address.description)),
                                                            _E("FQDN", address.value)]))  # fmt: skip
                self.kind[name] = ("fqdn", 0)
            elif address.kind == AddressKind.UNSUPPORTED:
                self._placeholder(name, address.raw or "unsupported address")
            elif address.kind == AddressKind.FQDN:
                self.fqdn_hosts.append(_entity("FQDNHost", [_E("Name", name), _E("Description", _clip(address.description)),
                                                            _E("FQDN", address.value)]))  # fmt: skip
                self.kind[name] = ("fqdn", address.fqdn_family)
            else:
                interval = parse_literal(address.value)
                if interval is None:
                    self.taint_a[name] = "address that could not be read"
                    self._placeholder(name, self.taint_a[name])
                elif interval in (FULL_V4, FULL_V6):
                    self.kind[name] = ("full", interval[0])  # "any" of its IP version: nothing to define
                else:
                    self._ip_host(name, interval, address.kind == AddressKind.RANGE)
        # A group that holds one of these cannot be converted either.
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a) | self.as_they_are), **self.taint_a}
        changed = True
        while changed:
            changed = False
            for group in self.p.address_groups.values():
                bad = [member for member in group.members if member in self.taint_a]
                if bad and group.name not in self.taint_a:
                    self.taint_a[group.name] = f"contains '{bad[0]}' ({self.taint_a[bad[0]]})"
                    changed = True

    def _placeholder(self, name: str, reason: str) -> None:
        """An object that keeps the name and matches nothing: a host name that does not exist."""
        taken = {address.value.lower() for address in self.p.addresses.values() if address.kind == AddressKind.FQDN}
        self.placeholders += 1
        while f"placeholder{self.placeholders}.fwshift.invalid" in taken:
            self.placeholders += 1
        self.fqdn_hosts.append(_entity("FQDNHost", [_E("Name", name), _E("Description", _clip(_PLACEHOLDER + reason)),
                                                    _E("FQDN", f"placeholder{self.placeholders}.fwshift.invalid")]))  # fmt: skip
        self.kind[name] = ("placeholder", 0)

    def _ip_host(self, name: str, interval: Interval, as_range: bool) -> None:
        version, first, last = interval
        children = [_E("Name", name), _E("IPFamily", f"IPv{version}")]
        networks = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
        if first == last:
            children += [_E("HostType", "IP"), _E("IPAddress", str(int_to_ip(version, first)))]
        elif len(networks) == 1 and not as_range:
            network = ipaddress.ip_network(str(networks[0]))
            subnet = str(network.netmask) if version == 4 else str(network.prefixlen)
            children += [_E("HostType", "Network"), _E("IPAddress", str(network.network_address)), _E("Subnet", subnet)]
        else:
            children += [_E("HostType", "IPRange"), _E("StartIPAddress", str(int_to_ip(version, first))),
                         _E("EndIPAddress", str(int_to_ip(version, last)))]  # fmt: skip
        self.hosts.append(_entity("IPHost", children))
        self.kind[name] = ("ip", version)
        self.literals.setdefault(interval, name)
        if children[2].text != "Network":
            self.ranges.setdefault(interval, name)

    def _literal(self, interval: Interval) -> str:
        """The host that stands for addresses a rule or a group names directly."""
        if interval not in self.literals:
            version, first, last = interval
            text = interval_text(interval)
            if first == last:
                label = f"h-{text}"
            elif "/" in text:
                label = "n-" + text.replace("/", "_")
            else:
                label = f"r-{text}"
            name = self.names.unique(self.options.object_prefix + label, self.names.addresses, self.names.objects)
            self._ip_host(name, interval, "/" not in text)
        return self.literals[interval]

    def _range_host(self, interval: Interval) -> str:
        """The host a NAT rule translates to: these addresses as one address or as a range, which every release takes."""
        if interval not in self.ranges:
            label = f"{self.options.object_prefix}r-{interval_text(interval).replace('/', '_')}"
            name = self.names.unique(label, self.names.addresses, self.names.objects)
            literal = self.literals.get(interval)
            self._ip_host(name, interval, True)
            if literal is not None:
                self.literals[interval] = literal
        return self.ranges[interval]

    def _leaves(self, group: str, seen: Set[str]) -> List[str]:
        """The hosts of a group, through the groups in it: a Sophos group holds hosts only."""
        out: List[str] = []
        for member in self.p.address_groups[group].members:
            if member in self.p.address_groups:
                if member not in seen:
                    out += self._leaves(member, seen | {member})
            elif member in self.p.addresses:
                out.append(member)
            else:
                interval = parse_literal(member)
                if interval is not None:
                    out.append(_FULL[interval[0]] if interval in (FULL_V4, FULL_V6) else self._literal(interval))
        return transform.dedupe(out)

    def _groups(self) -> None:
        for group in self.p.address_groups.values():
            name = group.name
            if name in self.taint_a:
                self._placeholder(name, self.taint_a[name])
                continue
            leaves = self._leaves(name, {name})
            full = {self.kind[leaf][1] for leaf in leaves if self.kind[leaf][0] == "full"}
            description = _clip(group.description)
            refs: Dict[int, List[str]] = {4: [], 6: []}
            made: List[str] = []

            def named(suffix: str) -> str:
                new = name if not made else self.names.unique(name, self.names.addresses, self.names.objects, suffix)
                made.append(new)
                return new

            for version in (4, 6):
                if version in full:
                    refs[version] = [_ANY]  # the group holds every address of this IP version
                    continue
                hosts = [leaf for leaf in leaves if self.kind[leaf] in (("ip", version), ("builtin", version))]
                if hosts:
                    new = named(f"_v{version}")
                    self.host_groups.append(_entity("IPHostGroup", [_E("Name", new), _E("IPFamily", f"IPv{version}"),
                                                                    _E("Description", description),
                                                                    _listed("HostList", "Host", hosts)]))  # fmt: skip
                    refs[version].append(new)
            # Host names: one group serves both IP versions unless a name is resolved for one of them only.
            fqdn = {version: [] if version in full else
                    [leaf for leaf in leaves if self.kind[leaf][0] == "fqdn" and self.kind[leaf][1] in (0, version)]
                    for version in (4, 6)}  # fmt: skip
            shared = bool(fqdn[4]) and fqdn[4] == fqdn[6]
            for version in (4, 6):
                if not fqdn[version] or (shared and version == 6):
                    continue
                new = named("_fqdn" if shared or not fqdn[10 - version] else f"_fqdn{version}")
                self.fqdn_groups.append(_entity("FQDNHostGroup", [_E("Name", new), _E("Description", description),
                                                                  _listed("FQDNHostList", "FQDNHost", fqdn[version])]))  # fmt: skip
                refs[version].append(new)
                if shared:
                    refs[6].append(new)
            self.group_refs[name] = refs
            if len(made) > 1:
                origin = self.names.source.get(name, name)
                self.report.item("address-group", origin).emitted_as = list(made)
                self.report.add(
                    "address-group", origin, Severity.INFO, "GROUP_SPLIT",
                    "Sophos Firewall keeps IPv4 hosts, IPv6 hosts and host names in groups of their own: written as "
                    + ", ".join(f"'{one}'" for one in made),
                )  # fmt: skip

    def _families(self, member: str) -> Set[int]:
        if member == ANY:
            return {4, 6}
        if member in self.kind:
            kind, version = self.kind[member]
            if kind == "placeholder":
                return {4}  # as everywhere: what cannot be converted counts as IPv4
            return {version} if version else {4, 6}
        if member in self.group_refs:
            return {version for version in (4, 6) if self.group_refs[member][version]} or {4}
        interval = parse_literal(member)
        return {interval[0]} if interval else {4}

    def _ref(self, member: str, version: int) -> List[str]:
        """What stands for a rule member in a rule of one IP version; nothing when it is of the other."""
        if member == ANY:
            return [_ANY]
        if member in self.kind:
            kind, family = self.kind[member]
            if kind == "placeholder":
                return [member] if version == 4 else []
            if family not in (0, version):
                return []
            return [_ANY] if kind == "full" else [member]
        if member in self.group_refs:
            return self.group_refs[member][version]
        interval = parse_literal(member)
        if interval is None or interval[0] != version:
            return []
        return [_ANY] if interval in (FULL_V4, FULL_V6) else [self._literal(interval)]

    def _refs(self, members: List[str], version: int) -> List[str]:
        out = transform.dedupe([ref for member in members for ref in self._ref(member, version)])
        return [_ANY] if _ANY in out else out

    def _has(self, members: List[str], version: int) -> bool:
        return any(version in self._families(member) for member in members)

    def _side(self, members: List[str], negated: bool, version: int) -> Tuple[List[str], bool]:
        """(objects, negated) of one address field for one IP version; no objects means no match."""
        if not self._has(members, version):
            return [_ANY], False  # only reached for a negated list: it excludes nothing of this version
        refs = self._refs(members, version)
        if negated and refs == [_ANY]:
            return [], False  # everything of this version is excluded
        return refs, negated

    def _complement(self, members: List[str], version: int) -> Optional[List[str]]:
        """Hosts for every address of an IP version that a list does not name; None when the list is not known."""
        named: List[Interval] = []
        for member in members:
            resolved = transform.address_intervals(self.p, member)
            if resolved is None:
                return None
            named += resolved
        left = subtract([FULL_V4 if version == 4 else FULL_V6], [interval for interval in named if interval[0] == version])
        return [self._literal(interval) for interval in left]

    # -- services ---------------------------------------------------------

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for service in self.p.services.values():
            name = service.name
            if not service.entries or service.unsupported:
                self._placeholder_service(name)
                continue
            if any(entry.protocol == Protocol.IP and entry.ip_protocol is None for entry in service.entries):
                self.svc_any.add(name)  # nothing to define: Sophos Firewall has "any service" for it
                self.svc_leaves[name], self.svc_families[name] = [], {4, 6}
                continue
            problem = self._define_service(name, service.entries)
            if problem:
                bad[name] = problem
                self._placeholder_service(name)
                self.report.add("service", self.names.source.get(name, name), Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: written as a placeholder, and the rules that use it are disabled")  # fmt: skip
        self.taint_s = transform.tainted_services(self.p, bad)
        for group in self.p.service_groups.values():
            name = group.name
            if name in self.taint_s:
                self._placeholder_service(name)
                continue
            leaves = self._service_leaves(name, {name})
            if self._holds_any(name, {name}):
                self.svc_any.add(name)
                self.svc_leaves[name], self.svc_families[name] = [], {4, 6}
                continue
            self.svc_leaves[name] = leaves
            self.svc_families[name] = {version for leaf in leaves for version in self.svc_families.get(leaf, {4, 6})}
            self.service_groups.append(_entity("ServiceGroup", [_E("Name", name), _E("Description", _clip(group.description)),
                                                                _listed("ServiceList", "Service", leaves)]))  # fmt: skip

    def _service_leaves(self, group: str, seen: Set[str]) -> List[str]:
        out: List[str] = []
        for member in self.p.service_groups[group].members:
            if member in self.p.service_groups:
                if member not in seen:
                    out += self._service_leaves(member, seen | {member})
            else:
                out += self.svc_leaves.get(member, [])
        return transform.dedupe(out)

    def _holds_any(self, group: str, seen: Set[str]) -> bool:
        members = self.p.service_groups[group].members
        return any(member in self.svc_any or (member in self.p.service_groups and member not in seen
                                              and self._holds_any(member, seen | {member})) for member in members)  # fmt: skip

    def _placeholder_service(self, name: str) -> None:
        self._write_service(name, "TCPorUDP", [(("SourcePort", "1:65535"), ("DestinationPort", "1"), ("Protocol", "TCP"))])
        self.svc_leaves[name], self.svc_families[name] = [name], {4, 6}

    def _write_service(self, name: str, kind: str, details: List[Tuple[Tuple[str, str], ...]]) -> None:
        listed = [_E("ServiceDetail", children=[_E(tag, text) for tag, text in detail]) for detail in details]
        self.services.append(_entity("Services", [_E("Name", name), _E("Type", kind), _E("ServiceDetails", children=listed)]))

    def _define_service(self, name: str, entries: List[ServiceEntry]) -> str:
        """Write a service; return why it cannot be written, if it cannot."""
        parts, problem, unchecked = _details(entries)
        if problem:
            return problem
        origin = self.names.source.get(name, name)
        if unchecked and name in self.p.services:
            self.report.add(
                "service", origin, Severity.INFO, "PROTOCOL_NAME",
                f"IP protocol written as {', '.join(transform.dedupe(unchecked))}: the name is the keyword of the IANA "
                "registry, which is what Sophos Firewall uses for the protocols its documentation shows. Check that the "
                "import took this service",
            )  # fmt: skip
        if name in self.p.services and any(_has_port_zero(entry) for entry in entries):
            self.report.add("service", origin, Severity.INFO, "PORT_ZERO",
                            "port 0 is left out: no connection has it, and a Sophos service starts at port 1")  # fmt: skip
        self.svc_families[name] = _entry_families(entries)
        kinds = [kind for kind in _TYPES if kind in parts]
        if len(kinds) == 1:
            self._write_service(name, kinds[0], parts[kinds[0]])
            self.svc_leaves[name] = [name]
            return ""
        members: List[str] = []
        for kind in kinds:
            member = self.names.unique(name, self.names.services, self.names.objects, _SUFFIX[kind])
            self._write_service(member, kind, parts[kind])
            members.append(member)
        self.svc_leaves[name] = members
        self.service_groups.append(_entity("ServiceGroup", [_E("Name", name), _E("Description", ""),
                                                            _listed("ServiceList", "Service", members)]))  # fmt: skip
        if name in self.p.services:
            self.report.item("service", origin).emitted_as = [name] + members
            self.report.add(
                "service", origin, Severity.INFO, "SERVICE_SPLIT",
                "a Sophos service holds one kind of protocol (TCP and UDP ports, IP protocols, ICMP or ICMPv6): written "
                f"as service group '{name}' of " + ", ".join(f"'{member}'" for member in members),
            )  # fmt: skip
        return ""

    def _app_service(self, app: str, entries: List[ServiceEntry], reasons: List[transform.Reason]) -> str:
        if app not in self.app_services:
            name = self.names.unique(f"{self.options.object_prefix}app-{app}", self.names.services, self.names.objects)
            problem = self._define_service(name, entries)
            if problem:
                self._placeholder_service(name)
                self.taint_s[name] = problem
            self.app_services[app] = name
        name = self.app_services[app]
        if name in self.taint_s:
            reasons.append(("APP_PORTS", f"the ports of application {app} hold {self.taint_s[name]}"))
        return name

    def _rule_services(self, rule: Rule, reasons: List[transform.Reason]) -> List[str]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is None:
            return [_ANY] if ANY in rule.services or self.svc_any & set(rule.services) else list(rule.services)
        return [self._app_service(app, entries, reasons) for app, entries in lowered] or [_ANY]

    # -- security rules ---------------------------------------------------

    def _variants(self, rule: Rule, services: List[str], reasons: List[transform.Reason]) -> List[_Variant]:
        out: List[_Variant] = []
        if rule.negate_service and services == [_ANY]:
            return out  # every service but every service
        for version in (4, 6):
            if not (rule.negate_source or self._has(rule.sources, version)):
                continue
            if not (rule.negate_destination or self._has(rule.destinations, version)):
                continue
            if services != [_ANY] and not rule.negate_service:
                if version not in {v for service in services for v in self.svc_families.get(service, {4, 6})}:
                    continue  # ICMP in a rule for IPv6, or the other way round: it matches nothing
            src, src_negated = self._side(rule.sources, rule.negate_source, version)
            dst, dst_negated = self._side(rule.destinations, rule.negate_destination, version)
            if not src or not dst:
                continue
            variant = _Variant(version, src, dst)
            sides = {"source": (src, rule.sources), "destination": (dst, rule.destinations)}
            negated = [side for side, flag in (("source", src_negated), ("destination", dst_negated)) if flag]
            # Exclusions apply together: one negated field can be one. Of more, the others are turned round.
            room = 0 if rule.negate_service else 1
            turned = {side: self._complement(sides[side][1], version) for side in negated} if len(negated) > room else {}
            nothing = False
            for side in sorted(negated, key=lambda side: turned.get(side) is not None):
                refs, members = sides[side]
                left = turned.get(side)
                if room or left is None:
                    if not room:
                        reasons.append((
                            "NEGATION",
                            f"the {side} is negated together with another field. Sophos Firewall applies exclusions "
                            f"together (it would skip the rule only for traffic that matches all of them), and {side} "
                            f"{', '.join(members)} cannot be written as the addresses that are left",
                        ))  # fmt: skip
                    room = max(room - 1, 0)
                    variant.exclusions["SourceNetworks" if side == "source" else "DestinationNetworks"] = refs
                    refs = [_ANY]
                elif not left:
                    nothing = True
                else:
                    refs = left
                    self.report.add(
                        "rule", rule.origin, Severity.INFO, "NEGATION_AS_ADDRESSES",
                        f"more than one field of the rule is negated, and Sophos Firewall applies exclusions together: "
                        f"'not {side} {', '.join(members)}' is written as the IPv{version} addresses that are left "
                        f"({len(left)} range(s))",
                    )  # fmt: skip
                if side == "source":
                    variant.sources = refs
                else:
                    variant.destinations = refs
            if nothing:
                continue
            if rule.negate_service:
                variant.exclusions["Services"] = services
            out.append(variant)
        return out

    def _rule(self, rule: Rule, added: bool = False) -> List[str]:
        item = self.report.item("rule", rule.origin) if not added else None
        if self.native and rule.profiles:
            self.report.add(
                "rule", rule.origin, Severity.INFO, "PROFILES_BY_NAME",
                "policies of the rule are referenced by name and must exist on the target: "
                + ", ".join(f"{tag}={value}" for tag, value in sorted(rule.profiles.items())),
            )  # fmt: skip
        elif not added:
            transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        services = self._rule_services(rule, reasons)
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as pairs of zones"))
            pairs = [(rule.src_zones, rule.dst_zones)]
        elif not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                             f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing",
                             Severity.INFO)  # fmt: skip
            return []
        variants = self._variants(rule, services, reasons)
        if not variants:
            self.report.skip(
                "rule", rule.origin, "NO_COMMON_FAMILY",
                "source, destination and service share no IP version, or a negation excludes everything; nothing to emit",
            )  # fmt: skip
            return []
        if len(pairs) > 1:
            self.report.add("rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                            f"{rule.scope.value} rule written as {len(pairs)} rules, one per zone pair")  # fmt: skip
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value} becomes Reject, which answers the sender only")  # fmt: skip
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        if len(variants) > 1 and not added:
            self.twins += 1
        flag = "FWSHIFT: disabled by the converter, see the report. " if reasons else ""
        names: List[str] = []
        first = True
        for src_zones, dst_zones in pairs:
            for variant in variants:
                suffix = "_v6" if variant.version == 6 and len(variants) > 1 else ""
                if first and not suffix:
                    name = rule.name  # its own name is kept for it
                else:
                    name = self.names.unique(rule.name, self.names.rule_names, self.names.rules, suffix)
                first = False
                names.append(name)
                self.rules.append(self._rule_entity(rule, name, variant, src_zones, dst_zones, services, bool(reasons), flag))
        if item is not None:
            item.emitted_as += names
        return names

    def _position(self, name: str, last: Dict[int, str], version: int) -> List[_E]:
        """Below what is there, and each rule below the one before it: the order does not hang on how a file is read."""
        before = last.get(version)
        last[version] = name
        if before is None:
            return [_E("Position", "Bottom")]
        return [_E("Position", "After"), _E("After", children=[_E("Name", before)])]

    def _rule_entity(self, rule: Rule, name: str, variant: _Variant, src_zones: List[str], dst_zones: List[str],
                     services: List[str], disabled: bool, flag: str) -> _E:  # fmt: skip
        match = [_E("Action", _ACTIONS[rule.action]), _E("LogTraffic", "Enable" if rule.log_end or rule.log_start else "Disable"),
                 _E("SkipLocalDestined", "Disable")]  # fmt: skip
        if ANY not in src_zones:
            match.append(_listed("SourceZones", "Zone", src_zones))
        if ANY not in dst_zones:
            match.append(_listed("DestinationZones", "Zone", dst_zones))
        match.append(_E("Schedule", "All The Time"))
        if variant.sources != [_ANY]:
            match.append(_listed("SourceNetworks", "Network", variant.sources))
        if variant.destinations != [_ANY]:
            match.append(_listed("DestinationNetworks", "Network", variant.destinations))
        if services != [_ANY] and not rule.negate_service:
            match.append(_listed("Services", "Service", services))
        if variant.exclusions:
            match.append(_E("Exclusions", children=[
                _listed(kind, "Service" if kind == "Services" else "Network", variant.exclusions[kind])
                for kind in ("SourceNetworks", "DestinationNetworks", "Services") if kind in variant.exclusions
            ]))  # fmt: skip
        if self.native and rule.action == Action.ALLOW:
            match += [_E(tag, rule.profiles[tag]) for tag in PROFILE_ELEMENTS if tag in rule.profiles]
        head = [_E("Name", name), _E("Description", _clip(flag + rule.description)), _E("IPFamily", f"IPv{variant.version}"),
                _E("Status", "Disable" if disabled or not rule.enabled else "Enable")]  # fmt: skip
        position = self._position(name, self.last_rule, variant.version)
        head += position[:1] + [_E("PolicyType", "Network")] + position[1:]
        return _entity("FirewallRule", head + [_E("NetworkPolicy", children=match)])

    def _intrazone_allow_zones(self) -> List[str]:
        return transform.intrazone_allow_zones(self.p, self.options.zone_map, self.source_zones, self.report)

    def _intrazone_tail(self) -> None:
        """Zones of the source that pass traffic between their own interfaces: a rule each, below all others."""
        if self.p.default_intrazone == Action.ALLOW or not self.p.rules:
            return
        names: List[str] = []
        for zone in self._intrazone_allow_zones():
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
                "interfaces on the source, and Sophos Firewall needs a rule for it",
            )  # fmt: skip

    # -- NAT --------------------------------------------------------------

    def _interfaces(self, zones: List[str]) -> Optional[List[str]]:
        """The interfaces of zones, by their names on the target; None when that is not known for one of them."""
        if ANY in zones:
            return [_ANY]
        zone_map, interface_map = self.options.zone_map, self.options.interface_map
        out: List[str] = []
        for zone in zones:
            origins = [name for name in list(self.p.zones) + list(zone_map) + sorted(self.source_zones)
                       if zone_map.get(name, name) == zone] or [zone]  # fmt: skip
            for origin in transform.dedupe(origins):
                held = self.p.zones[origin].interfaces if origin in self.p.zones else []
                for interface in held or [origin]:
                    if interface in interface_map:
                        out.append(interface_map[interface])
                    elif self.native and held:
                        out.append(interface)  # the name it has on a Sophos Firewall
                    else:
                        return None
        return transform.dedupe(out)

    def _translated(self, members: List[str], version: int, host_name: bool = False, strip: bool = False) -> Optional[str]:
        """The one object a translation is to: a host, a range, or a host name where that can be."""
        if len(members) == 1:
            member = members[0]
            if strip and member not in self.p.addresses and member not in self.p.address_groups:
                member = member.split("/")[0]  # PAN-OS writes the address of an interface with its mask
                members = [member]
            kind, family = self.kind.get(member, ("", 0))
            if (kind == "builtin" and family == version) or (kind == "fqdn" and host_name and family in (0, version)):
                return member
            if kind == "ip" and family == version and member in self.ranges.values():
                return member
        found: List[Interval] = []
        for member in members:
            resolved = transform.address_intervals(self.p, member)
            if resolved is None:
                return None
            found += resolved
        merged = normalize(found)
        if len(merged) != 1 or merged[0][0] != version or merged[0] in (FULL_V4, FULL_V6):
            return None
        return self._range_host(merged[0])

    def _port_service(self, nat: NatRule, port: str) -> Optional[str]:
        """The service a port translation is to ("Original" when the port stays); None when it cannot be said."""
        entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else None
        if not entries or not is_number(port):
            return None
        protocols: List[str] = []
        for entry in entries:
            if entry.protocol not in (Protocol.TCP, Protocol.UDP) or entry.src_ports or not is_number(entry.dst_ports):
                return None
            if entry.protocol.value.upper() not in protocols:
                protocols.append(entry.protocol.value.upper())
        if len({entry.dst_ports for entry in entries}) != 1:
            return None
        if entries[0].dst_ports == port:
            return "Original"
        key = (tuple(sorted(protocols)), port)
        wanted = sorted((protocol.lower(), port, "") for protocol in protocols)
        for service in self.p.services.values():  # one the policy has already, if it has one
            if key not in self.port_services and service.name not in self.taint_s and self.svc_leaves.get(service.name) == [service.name]:
                if sorted((entry.protocol.value, entry.dst_ports, entry.src_ports) for entry in service.entries) == wanted:
                    self.port_services[key] = service.name
        if key not in self.port_services:
            label = f"{self.options.object_prefix}{'-'.join(sorted(protocols)).lower()}-{port}"
            name = self.names.unique(label, self.names.services, self.names.objects)
            self._write_service(name, "TCPorUDP", [(("SourcePort", "1:65535"), ("DestinationPort", port), ("Protocol", protocol))
                                                   for protocol in sorted(protocols)])  # fmt: skip
            self.port_services[key] = name
        return self.port_services[key]

    def _nat(self, nat: NatRule) -> None:
        item = self.report.item("nat", nat.origin)
        source, destination = nat.source_translation, nat.destination_translation
        members = nat.sources + nat.destinations + (source.addresses if source else [])
        members = members + ([destination.address] if destination else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        if problems:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
            return
        named = [member for member in nat.sources + nat.destinations if member != ANY]
        version = 6 if named and all(self._families(member) == {6} for member in named) else 4
        src, dst = self._refs(nat.sources, version), self._refs(nat.destinations, version)
        if not src or not dst:
            self.report.skip("nat", nat.origin, "NAT_ADDRESSES",
                             "source and destination of the rule share no IP version; a Sophos NAT rule is for one")  # fmt: skip
            return
        translated_source, translated_destination, translated_service, method = "Original", "Original", "Original", ""
        if source is not None and not (source.kind == SnatKind.INTERFACE and not source.addresses):
            found = self._translated(source.addresses, version, strip=source.kind == SnatKind.INTERFACE)
            if found is None:
                problems.append(f"translated source {', '.join(source.addresses)} is not one IPv{version} address or range, "
                                "which is what a Sophos NAT rule translates to")  # fmt: skip
            else:
                translated_source = found
        elif source is not None:
            translated_source = "MASQ"
        if destination is not None:
            found = self._translated([destination.address], version, host_name=True)
            if found is None:
                problems.append(f"translated destination '{destination.address}' is not one IPv{version} address, range or "
                                "host name")  # fmt: skip
            else:
                translated_destination = found
                mapped = transform.address_intervals(self.p, destination.address)
                count = sum(size(interval) for interval in mapped) if mapped else 1
                if count > 1 and destination.spread:
                    method = "Round-robin"
                elif count > 1:
                    original = [transform.address_intervals(self.p, member) for member in nat.destinations]
                    merged = normalize([i for found_ in original for i in found_ or []]) if all(original) else []
                    if len(merged) == 1 and size(merged[0]) == count:
                        method = "OnetoOne"
                    else:
                        problems.append(f"{count} translated destination addresses for an original destination that is not "
                                        "one range of as many: not an address for address translation")  # fmt: skip
            if destination.port:
                service = self._port_service(nat, destination.port)
                if service is None:
                    problems.append(f"translation to port {destination.port} needs a service of the rule that is one TCP or "
                                    "UDP port")  # fmt: skip
                else:
                    translated_service = service
        if problems:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
            return
        other = [member for member in named if (10 - version) in self._families(member) and self.kind.get(member, ("", 0))[0] != "fqdn"]
        if other:
            self.report.add(
                "nat", nat.origin, Severity.APPROX, "NAT_IP_VERSION",
                f"written for IPv{version}: a Sophos NAT rule is for one IP version, and the IPv{10 - version} addresses of "
                f"{', '.join(other)} are left out of it",
            )  # fmt: skip
        inbound = self._interfaces(nat.src_zones)
        # Sophos Firewall asks for "any" as the outbound interface of a rule that translates the destination.
        outbound = [_ANY] if destination is not None else self._interfaces(nat.dst_zones)
        if inbound is None:
            unlimited = ANY in nat.sources and ANY in nat.destinations
            self.report.add(
                "nat", nat.origin, Severity.REVIEW if unlimited else Severity.APPROX, "NAT_ZONES",
                f"the rule applied to traffic from {', '.join(nat.src_zones)} only. A Sophos NAT rule matches interfaces, and "
                "the interfaces of that zone on the target are not known: written for any inbound interface. Name them "
                "with --interface-map",
            )  # fmt: skip
        if outbound is None:
            unlimited = ANY in nat.destinations
            self.report.add(
                "nat", nat.origin, Severity.REVIEW if unlimited else Severity.APPROX, "NAT_ZONES",
                f"the rule applied to traffic to {', '.join(nat.dst_zones)} only. A Sophos NAT rule matches interfaces, and "
                "the interfaces of that zone on the target are not known: written for any outbound interface"
                + (", so that it now translates traffic towards every other zone as well. Name the interfaces with "
                   "--interface-map, or put a rule without translation above it for the traffic that must keep its "
                   "addresses" if unlimited else ". Name them with --interface-map"),
            )  # fmt: skip
        if destination is not None and ANY not in nat.dst_zones:
            reached = [transform.address_intervals(self.p, member) for member in nat.destinations if member != ANY]
            few = ANY not in nat.destinations and all(reached) and sum(size(i) for found_ in reached for i in found_ or []) <= 256
            if not few:
                everything = ANY in nat.destinations
                self.report.add(
                    "nat", nat.origin, Severity.REVIEW if everything else Severity.APPROX, "NAT_DESTINATION_ZONE",
                    f"the rule applied to traffic on its way to zone {', '.join(nat.dst_zones)} only. A Sophos NAT rule that "
                    "translates the destination cannot say where the traffic was going: it is written without that, and "
                    + ("now translates the traffic to every destination, whatever the zone" if everything
                       else "applies to its destination addresses in whatever zone they lie"),
                )  # fmt: skip
        if source is not None and source.kind == SnatKind.DYNAMIC:
            self.report.add("nat", nat.origin, Severity.APPROX, "NAT_DYNAMIC_IP",
                            "translation to a pool without port translation becomes source NAT that shares the addresses, "
                            "with port translation")  # fmt: skip
        if source is not None and source.kind == SnatKind.STATIC and translated_source != "MASQ":
            mapped = [i for member in source.addresses for i in transform.address_intervals(self.p, member) or []]
            if sum(size(interval) for interval in mapped) > 1:
                self.report.add("nat", nat.origin, Severity.APPROX, "NAT_STATIC_RANGE",
                                "static NAT of a range becomes source NAT to a range, which does not promise that each host "
                                "keeps the same translated address")  # fmt: skip
        name = nat.name
        item.emitted_as.append(name)
        self.nat.append(self._nat_entity(nat, name, version, src, dst,
                                         [_ANY] if nat.service == ANY or nat.service in self.svc_any else [nat.service],
                                         inbound or [_ANY], outbound or [_ANY], translated_source, translated_destination,
                                         translated_service, method))  # fmt: skip
        if source is not None and source.kind == SnatKind.STATIC and source.bidirectional:
            self._reverse(nat, version)

    def _nat_entity(self, nat: NatRule, name: str, version: int, src: List[str], dst: List[str], services: List[str],
                    inbound: List[str], outbound: List[str], translated_source: str, translated_destination: str,
                    translated_service: str, method: str, description: str = "") -> _E:  # fmt: skip
        position = self._position(name, self.last_nat, version)
        children = [_E("Name", name), _E("Description", _clip(description or nat.description)), _E("IPFamily", f"IPv{version}"),
                    _E("Status", "Enable" if nat.enabled else "Disable")]  # fmt: skip
        children += position + [_E("LinkedFirewallrule", "None"), _E("TranslatedDestination", translated_destination),
                                _E("TranslatedService", translated_service)]  # fmt: skip
        for tag, child, listed in (("OriginalSourceNetworks", "Network", src), ("OriginalDestinationNetworks", "Network", dst),
                                   ("OriginalServices", "Service", services), ("InboundInterfaces", "Interface", inbound),
                                   ("OutboundInterfaces", "Interface", outbound)):  # fmt: skip
            if listed != [_ANY]:
                children.append(_listed(tag, child, listed))
        children += [_E("OverrideInterfaceNATPolicy", "Disable"), _E("TranslatedSource", translated_source)]
        if method:
            children.append(_E("NATMethod", method))
        return _entity("NATRule", children)

    def _reverse(self, nat: NatRule, version: int) -> None:
        """The inbound direction of a static NAT for both directions: on Sophos Firewall a rule of its own."""
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is None or version != 4:
            self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_BIDIRECTIONAL",
                            "bi-directional static NAT: the inbound direction could not be written as a rule and is missing")  # fmt: skip
            return
        inside, outside = pair
        name = self.names.unique(nat.name, self.names.nat_names, self.names.rules, "-in")
        self.nat.append(self._nat_entity(nat, name, 4, [_ANY], [self._literal(outside)], [_ANY], [_ANY], [_ANY], "Original",
                                         self._range_host(inside), "Original", "OnetoOne" if size(inside) > 1 else "",
                                         f"inbound direction of static NAT {nat.name}"))  # fmt: skip
        self.report.item("nat", nat.origin).emitted_as.append(name)
        self.report.add("nat", nat.origin, Severity.APPROX, "NAT_BIDIRECTIONAL",
                        f"bi-directional static NAT written as a source NAT rule plus rule '{name}' for the inbound direction")  # fmt: skip
