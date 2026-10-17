# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco ASA parser: ``show running-config`` -> neutral model.

Also reads the ASA-style configuration a Firepower Threat Defense device shows
(``access-list ... advanced``), as far as that configuration tells.

How ASA behaviour is mapped onto the neutral model:

* The interface names (``nameif``) are the zones.
* Only access lists bound with ``access-group`` are policy. The list bound
  ``in`` to an interface holds the rules for traffic arriving on it; the global
  list follows it for every interface; then everything is denied.
* An ASA does not send traffic back out of the interface it came in on, nor
  between interfaces of the same security level, unless
  ``same-security-traffic`` permits it - whatever the access lists say. Allow
  rules therefore name the interfaces their traffic can leave by.
* An interface without an access list, on an ASA without a global one, lets
  traffic out to interfaces of a lower security level. That becomes a rule.
* From 8.3 on access lists name the real address and port of a host behind NAT;
  the model wants the original ones. NAT is one ordered list: twice NAT, object
  NAT (sorted the way the ASA sorts it), twice NAT ``after-auto``. A connection
  can use one rule for its destination and another for its source.
* From 9.0 on ``any`` is both IP versions; before that it is IPv4.
* A line that is not understood in full makes its rule unusable, never wider.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple, TypeVar

from .. import transform, zonenets
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    APP_DEFAULT,
    L4_PROTOCOLS,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    Service,
    ServiceEntry,
    ServiceGroup,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import Interval, int_to_ip, intersect, is_number, netmask_to_cidr, normalize, parse_literal, range_text
from ..netutil import size, subtract
from ..report import Report, Severity

# Port, protocol and ICMP names of the ASA command line.
PORTS = {
    "aol": 5190, "bgp": 179, "biff": 512, "bootpc": 68, "bootps": 67, "chargen": 19, "cifs": 3020,
    "citrix-ica": 1494, "cmd": 514, "ctiqbe": 2748, "daytime": 13, "discard": 9, "dnsix": 195, "domain": 53,
    "echo": 7, "exec": 512, "finger": 79, "ftp": 21, "ftp-data": 20, "gopher": 70, "h323": 1720, "hostname": 101,
    "http": 80, "https": 443, "ident": 113, "imap4": 143, "irc": 194, "isakmp": 500, "kerberos": 750,
    "klogin": 543, "kshell": 544, "ldap": 389, "ldaps": 636, "login": 513, "lotusnotes": 1352, "lpd": 515,
    "mobile-ip": 434, "nameserver": 42, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ssn": 139, "nfs": 2049,
    "nntp": 119, "ntp": 123, "pcanywhere-data": 5631, "pcanywhere-status": 5632, "pim-auto-rp": 496, "pop2": 109,
    "pop3": 110, "pptp": 1723, "radius": 1645, "radius-acct": 1646, "rip": 520, "rsh": 514, "rtsp": 554,
    "secureid-udp": 5510, "sip": 5060, "smtp": 25, "snmp": 161, "snmptrap": 162, "sqlnet": 1521, "ssh": 22,
    "sunrpc": 111, "syslog": 514, "tacacs": 49, "talk": 517, "telnet": 23, "tftp": 69, "time": 37, "uucp": 540,
    "vxlan": 4789, "who": 513, "whois": 43, "www": 80, "xdmcp": 177,
}  # fmt: skip
PROTOCOLS = {
    "ah": 51, "eigrp": 88, "esp": 50, "gre": 47, "icmp": 1, "icmp6": 58, "igmp": 2, "igrp": 9, "ip": 0,
    "ipinip": 4, "ipsec": 50, "nos": 94, "ospf": 89, "pcp": 108, "pim": 103, "pptp": 47, "sctp": 132, "snp": 109,
    "tcp": 6, "udp": 17,
}  # fmt: skip
ICMP_TYPES = {
    "echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5, "alternate-address": 6, "echo": 8,
    "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11, "parameter-problem": 12,
    "timestamp-request": 13, "timestamp-reply": 14, "information-request": 15, "information-reply": 16,
    "mask-request": 17, "mask-reply": 18, "traceroute": 30, "conversion-error": 31, "mobile-redirect": 32,
}  # fmt: skip
ICMP6_TYPES = {
    "unreachable": 1, "packet-too-big": 2, "time-exceeded": 3, "parameter-problem": 4, "echo": 128,
    "echo-reply": 129, "membership-query": 130, "membership-report": 131, "membership-reduction": 132,
    "router-solicitation": 133, "router-advertisement": 134, "neighbor-solicitation": 135,
    "neighbor-advertisement": 136, "neighbor-redirect": 137, "router-renumbering": 138,
}  # fmt: skip
_PROTOCOL_LABELS = {2: "igmp", 4: "ipinip", 47: "gre", 50: "esp", 51: "ah", 88: "eigrp", 89: "ospf", 103: "pim"}
_BY_NUMBER = {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp6", 0: "ip"}
_PORT_PROTOCOLS = ("tcp", "udp", "sctp")
_OPERATORS = ("eq", "lt", "gt", "neq", "range")
_LOG_LEVELS = {
    "emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging",
    "0", "1", "2", "3", "4", "5", "6", "7",
}  # fmt: skip
_IF_PAIR = re.compile(r"\(([^,()\s]+),([^,()\s]+)\)")
_VERSION = re.compile(r"(\d+)\.(\d+)")
_FTD_REMARK = re.compile(r"rule-id (\d+): (.*)")
_RESERVED_NAMES = (ANY, APP_DEFAULT)  # words with a fixed meaning in the neutral model
_NAT_FLAGS = ("net-to-net", "dns", "unidirectional", "no-proxy-arp", "route-lookup", "inactive")
_POOL_FLAGS = ("round-robin", "extended", "flat", "include-reserve", "block-allocation")
_MAX_NESTING = 64  # object groups inside object groups
_MAX_LINES = 2_000_000

# A protocol as an access list names it: (kind, number). Kind is tcp, udp, sctp, icmp, icmp6,
# "ip" for every protocol, or "number" for the protocol with that number.
Proto = Tuple[str, int]
T = TypeVar("T")


@dataclass
class _Entry:
    """One top-level configuration line with the indented lines below it."""

    number: int
    text: str
    words: List[str]
    children: List["_Entry"] = field(default_factory=list)


class _Cursor:
    def __init__(self, words: Sequence[str]) -> None:
        self.words = list(words)
        self.index = 0

    def peek(self, offset: int = 0) -> str:
        position = self.index + offset
        return self.words[position] if position < len(self.words) else ""

    def take(self) -> str:
        word = self.peek()
        self.index += 1
        return word

    def rest(self) -> List[str]:
        out = self.words[self.index :]
        self.index = len(self.words)
        return out

    @property
    def done(self) -> bool:
        return self.index >= len(self.words)


@dataclass
class _Ace:
    """One access list entry, already in the terms of the model."""

    acl: str
    number: int  # position among the entries of its list, from 1
    action: str  # permit, deny or trust
    source: str = ANY
    destination: str = ANY
    services: List[str] = field(default_factory=lambda: [ANY])
    src_ifc: str = ""  # FTD: interface named in the entry
    dst_ifc: str = ""
    users: List[str] = field(default_factory=list)
    log: Optional[bool] = None
    log_start: bool = False
    inactive: bool = False
    schedule: str = ""
    remark: str = ""
    rule_id: str = ""
    problems: List[str] = field(default_factory=list)

    @property
    def allow(self) -> bool:
        return self.action != "deny"


@dataclass
class _PortGroup:
    kind: str  # tcp, udp or tcp-udp
    ports: List[str] = field(default_factory=list)  # model syntax
    nested: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)


@dataclass
class _Interface:
    hardware: str
    nameif: str = ""
    level: Optional[int] = None
    address: str = ""
    networks: List[Interval] = field(default_factory=list)
    management_only: bool = False
    shutdown: bool = False


def _unique(name: str, taken: Set[str], suffix: str = "") -> str:
    """Return ``name``, or a variant of it that is not in ``taken`` yet, and record it."""
    candidate = name + suffix if name in taken else name
    counter = 2
    while candidate in taken:
        candidate = f"{name}{suffix}-{counter}"
        counter += 1
    taken.add(candidate)
    return candidate


def _distinct(items: Sequence[T]) -> List[T]:
    out: List[T] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def read_entries(text: str) -> List[_Entry]:
    """Top-level lines with the indented lines that belong to them; comments are left out."""
    out: List[_Entry] = []
    for number, line in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not an ASA configuration")
        stripped = line.strip()
        if not stripped or stripped[0] in "!:":
            continue
        entry = _Entry(number, stripped, stripped.split())
        if line[0] in " \t" and out:
            out[-1].children.append(entry)
        else:
            out.append(entry)
    return out


def looks_like_asa(text: str) -> bool:
    """Whether a configuration has lines only an ASA writes this way."""
    for line in text.splitlines()[:5000]:
        if line.startswith(("ASA Version ", "PIX Version ", "NGFW Version ")):
            return True
        words = line.split()
        if len(words) < 3:
            continue
        if line.startswith("access-list ") and ("extended" in words[2:5] or "advanced" in words[2:5] or "remark" in words[2:4]):
            return True
        if line.startswith(("object network ", "object service ", "object-group network ", "object-group service ")):
            return True
        if line.startswith("access-group ") and words[2] in ("in", "out", "global"):
            return True
    return False


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    entries = read_entries(text)
    try:
        return _Builder(entries, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError) as exc:
        # Nothing above should get here; a traceback is no answer to a damaged file.
        raise ParseError(f"the configuration could not be read ({type(exc).__name__}: {exc})") from None


def _port(word: str) -> Optional[int]:
    if is_number(word):
        return int(word) if int(word) < 65536 else None
    return PORTS.get(word)


def _ports(cursor: _Cursor) -> Optional[str]:
    """Read ``eq 80``, ``range 1024 2000`` and so on; the ports in model syntax, None if unreadable."""
    operator = cursor.take()
    first = _port(cursor.take())
    if first is None:
        return None
    if operator == "eq":
        return str(first)
    if operator == "lt":
        return f"0-{first - 1}" if first > 0 else None
    if operator == "gt":
        return f"{first + 1}-65535" if first < 65535 else None
    if operator == "neq":
        parts = ([f"0-{first - 1}"] if first > 0 else []) + ([f"{first + 1}-65535"] if first < 65535 else [])
        return ",".join(parts)
    last = _port(cursor.take())
    if last is None or last < first:
        return None
    return f"{first}-{last}"


def _proto(word: str) -> Optional[Proto]:
    number: Optional[int]
    if is_number(word):
        number = int(word) if int(word) < 256 else None
    else:
        number = PROTOCOLS.get(word)
    if number is None:
        return None
    return (_BY_NUMBER[number], number) if number in _BY_NUMBER else ("number", number)


def _icmp_type(word: str, v6: bool) -> Optional[int]:
    if is_number(word):
        return int(word) if int(word) < 256 else None
    return (ICMP6_TYPES if v6 else ICMP_TYPES).get(word)


def _label(entry: ServiceEntry) -> str:
    """A name for a service that an access list entry spells out."""
    if entry.protocol in L4_PROTOCOLS:
        src, dst = entry.src_ports.replace(",", "_"), entry.dst_ports.replace(",", "_")
        if src:
            return f"{entry.protocol.value}-src-{src}" + (f"-dst-{dst}" if dst else "")
        return f"{entry.protocol.value}-{dst or 'all'}"
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        if entry.icmp_type is None:
            return f"{entry.protocol.value}-all"
        return f"{entry.protocol.value}-{entry.icmp_type}" + (f"-{entry.icmp_code}" if entry.icmp_code is not None else "")
    number = entry.ip_protocol or 0
    return _PROTOCOL_LABELS.get(number, f"proto-{number}")


def _key(entries: Sequence[ServiceEntry]) -> Tuple[Tuple[object, ...], ...]:
    return tuple((e.protocol, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code, e.ip_protocol) for e in entries)


class _Builder:
    def __init__(self, entries: List[_Entry], report: Report) -> None:
        self.entries = entries
        self.report = report
        self.p = Policy(vendor="asa", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.ftd = False
        self.modern_nat = True  # 8.3 or later: access lists name real addresses
        self.any_both = True  # 9.0 or later: "any" is IPv4 and IPv6
        self.names: Dict[str, str] = {}
        self.interfaces: Dict[str, _Interface] = {}  # by nameif
        self.nameifs: List[str] = []  # interfaces that forward traffic
        self.declared = 0  # how many of them have an interface section in the input
        self.routes: Dict[Interval, List[str]] = {}  # network -> interfaces it is reached by
        self.connected: Set[Interval] = set()
        self.dynamic_routing = False  # routing protocols or policy routing: the routes shown are not all
        self.egress_by_route = False
        self.intra = False  # same-security-traffic permit intra-interface
        self.inter = False  # same-security-traffic permit inter-interface
        self.address_names: Set[str] = set()
        self.service_names: Set[str] = set()
        self.net_objects: Dict[str, str] = {}  # name on the ASA -> name in the model
        self.net_groups: Dict[str, str] = {}
        self.svc_objects: Dict[str, str] = {}
        self.svc_groups: Dict[str, str] = {}
        self.port_groups: Dict[str, _PortGroup] = {}
        self.proto_groups: Dict[str, Tuple[List[str], List[str]]] = {}  # name -> (protocol words, nested groups)
        self.icmp_groups: Dict[str, Tuple[List[str], List[str]]] = {}
        self.other_groups: Dict[str, str] = {}  # user and security groups -> what they are
        self.object_nat: List[Tuple[str, _Entry]] = []
        self.inline: Dict[Tuple[Tuple[object, ...], ...], str] = {}
        self.acls: Dict[str, List[_Ace]] = {}
        self.ftd_rules: Dict[str, Tuple[str, str]] = {}  # rule-id -> (kind of rule, name)
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.without_effect = 0
        self.other_acls: Dict[str, str] = {}  # lists that are not rules for IP traffic through the ASA -> their kind
        self.unrouted: List[Interval] = []  # networks of interfaces that are shut down: where they lead is not known
        self.bridged = False
        self.interface_objects: Dict[str, str] = {}
        self.port_memo: Dict[str, Tuple[List[str], List[str]]] = {}
        self.port_problem_memo: Dict[str, Tuple[List[str], List[str]]] = {}
        self.port_tables: List[Dict[str, Tuple[List[str], List[str]]]] = []
        self.word_memo: Dict[int, Dict[str, Tuple[List[str], List[str]]]] = {}

    def _top(self, *first: str) -> List[_Entry]:
        return [e for e in self.entries if tuple(e.words[: len(first)]) == first]

    # -- top level --------------------------------------------------------

    def build(self) -> Policy:
        self._version()
        if self._top("context") and not self._top("access-list") and any(
            child.words[:1] == ["config-url"] for entry in self._top("context") for child in entry.children
        ):
            raise ParseError(
                "this is the system configuration of an ASA in multiple context mode; it holds no policy. "
                "Convert the configuration of each context"
            )
        self._names()
        self._interfaces()
        self._objects()
        self._groups()
        self._access_lists()
        self._rules()
        self._nat()
        p = self.p
        read = any(not nat.unsupported for nat in p.nat_rules)
        if not (p.addresses or p.address_groups or p.services or p.service_groups or self.acls or self.interfaces or read):
            raise ParseError("no Cisco ASA configuration found; expected the output of 'show running-config'")
        if self.modern_nat:
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._zone_networks()
        self._notes()
        return self.p

    def _zone_networks(self) -> None:
        """The networks behind the interfaces (the zones): their own, and the static routes that leave by them, with the
        distance of each route (zonenets). What lies behind an interface that is shut down or only manages, or a route
        to Null0, is behind no zone."""
        routes: List[zonenets.Route] = []
        for interface in self.interfaces.values():
            why = "its interface is shut down" if interface.shutdown else ""
            routes += [zonenets.Route(network, interface.nameif, connected=True, nowhere=why) for network in interface.networks]
        unread: List[str] = []
        for entry in self._top("route") + self._top("ipv6", "route"):
            words = entry.words[1:] if entry.words[0] == "route" else entry.words[2:]
            if entry.words[0] == "route":
                address, mask = (["0.0.0.0" if w == "0" else w for w in words[1:3]] + ["", ""])[:2]
                network = parse_literal(netmask_to_cidr(self._ip(address), mask) or "") if len(words) >= 3 else None
                rest = words[3:]
            else:
                network = parse_literal(words[1]) if len(words) >= 2 and "/" in words[1] else None
                rest = words[2:]
            if network is None or not words:
                unread.append(" ".join(entry.words)[:80])
                continue
            if words[0] == "Null0":
                routes.append(zonenets.Route(network, nowhere="a route to Null0"))
                continue
            if words[0] not in self.interfaces or "tunneled" in rest:
                unread.append(" ".join(entry.words)[:80] + (" (for traffic from VPN tunnels only)" if "tunneled" in rest else ""))
                continue
            distance = int(rest[1]) if len(rest) > 1 and is_number(rest[1]) else 1
            why = "its interface is shut down" if self.interfaces[words[0]].shutdown else ""
            routes.append(zonenets.Route(network, words[0], None, (distance, 0), nowhere=why))
        zone_of = {name: name for name, interface in self.interfaces.items() if not interface.management_only and name in self.p.zones}
        partial = [text for flag, text in ((self.dynamic_routing, "routing protocols or policy routing are configured"),
                                           (self.bridged, "bridge groups (transparent mode) pass traffic whose addresses are not known"))
                   if flag]  # fmt: skip
        placed = zonenets.place(routes, zone_of, self.report, unread=unread, partial="; ".join(partial))
        self.p.zone_networks, self.p.unzoned_networks = placed.zones, placed.unzoned

    def _version(self) -> None:
        version: Optional[Tuple[int, int]] = None
        for entry in self.entries:
            if entry.words[1:2] == ["Version"] and entry.words[0] in ("ASA", "PIX", "NGFW") and len(entry.words) > 2:
                found = _VERSION.match(entry.words[2])
                if entry.words[0] == "NGFW":
                    self.ftd = True
                elif found:
                    version = (int(found.group(1)), int(found.group(2)))
                self.p.scope = " ".join(entry.words[:3])
                break
        legacy = [
            e for e in self.entries
            if e.words[0] in ("static", "global") and e.words[1:2] and e.words[1].startswith("(")
            or (e.words[0] == "nat" and len(e.words) > 2 and e.words[1].startswith("(") and "," not in e.words[1])
        ]  # fmt: skip
        if version is None and not self.ftd:
            if legacy:
                version = (8, 2)
            elif any(e.words[:2] == ["ipv6", "access-list"] for e in self.entries):
                version = (8, 4)  # IPv6 rules in lists of their own: before 9.0
            else:
                self.report.note(
                    Severity.INFO,
                    "VERSION_ASSUMED",
                    "the input has no 'ASA Version' line; it was read as ASA 9.0 or later: 'any' is IPv4 and IPv6, "
                    "and access lists name the real addresses of hosts behind NAT",
                )
        if version is not None:
            self.modern_nat = version >= (8, 3)
            self.any_both = version >= (9, 0)
        self.p.lookup_after_dnat = self.modern_nat
        if legacy or not self.modern_nat:
            self.modern_nat = False
            self.p.lookup_after_dnat = False
            if legacy:
                self.report.note(
                    Severity.REVIEW,
                    "LEGACY_NAT",
                    f"{len(legacy)} NAT commands in the syntax of ASA 8.2 and earlier (static, global, nat with a "
                    "NAT id) are not converted. The access lists of that release name translated addresses and "
                    "were read as such",
                )
        v6_lists = [e for e in self.entries if e.words[:2] == ["ipv6", "access-list"]]
        for entry in v6_lists:
            if len(entry.words) > 2:
                self.other_acls.setdefault(entry.words[2], "ipv6")
        if v6_lists:
            self.report.note(
                Severity.REVIEW,
                "TABLE_NOT_CONVERTED",
                f"{len(v6_lists)} 'ipv6 access-list' lines (ASA before 9.0) are not converted: the result has no "
                "IPv6 rules",
            )

    def _names(self) -> None:
        for entry in self._top("name"):
            if len(entry.words) >= 3 and parse_literal(entry.words[1]) is not None:
                self.names[entry.words[2]] = entry.words[1]

    def _ip(self, word: str) -> str:
        return self.names.get(word, word)

    # -- interfaces -------------------------------------------------------

    def _interfaces(self) -> None:
        for entry in self._top("interface"):
            interface = _Interface(" ".join(entry.words[1:]))
            for child in entry.children:
                words = child.words
                if words[0] == "nameif" and len(words) > 1:
                    interface.nameif = words[1]
                elif words[0] == "security-level" and len(words) > 1 and is_number(words[1]):
                    interface.level = int(words[1])
                elif words[0] == "management-only":
                    interface.management_only = True
                elif words[:2] == ["ip", "address"] and len(words) >= 4:
                    network = parse_literal(netmask_to_cidr(self._ip(words[2]), words[3]) or "")
                    if network is not None and parse_literal(self._ip(words[2])) is not None:
                        interface.address = self._ip(words[2])
                        interface.networks.append(network)
                elif words[:2] == ["ipv6", "address"] and len(words) >= 3 and "/" in words[2]:
                    network = parse_literal(words[2])
                    if network is not None and network[0] == 6:
                        interface.networks.append(network)
                elif words[0] == "policy-route":
                    self.dynamic_routing = True
                elif words[0] == "shutdown":
                    interface.shutdown = True
                elif words[0] == "bridge-group":
                    self.bridged = True
            if not interface.nameif or interface.nameif in self.interfaces:
                continue
            if interface.level is None:
                interface.level = 100 if interface.nameif == "inside" else 0  # what the ASA sets by itself
            self.interfaces[interface.nameif] = interface
            if interface.shutdown:
                self.unrouted += interface.networks  # it may be brought up again: no route says where these lead
            else:
                for network in interface.networks:
                    self.routes.setdefault(network, []).append(interface.nameif)
                    self.connected.add(network)
            if interface.management_only:
                continue
            self.nameifs.append(interface.nameif)
            self.declared += 1
            self.p.zones[interface.nameif] = Zone(interface.nameif, [interface.hardware])
        for entry in self._top("route") + self._top("ipv6", "route"):
            words = entry.words[1:] if entry.words[0] == "route" else entry.words[2:]
            if entry.words[0] == "route":
                network = parse_literal(netmask_to_cidr(self._ip(words[1]), words[2]) or "") if len(words) >= 3 else None
            else:
                network = parse_literal(words[1]) if len(words) >= 2 and "/" in words[1] else None
            if network is not None and words[0] in self.interfaces and words[0] not in self.routes.setdefault(network, []):
                self.routes[network].append(words[0])
        routing = ("router",), ("ipv6", "router"), ("route-map",)
        self.dynamic_routing = self.dynamic_routing or any(self._top(*first) for first in routing)
        for entry in self._top("same-security-traffic", "permit"):
            self.intra = self.intra or entry.words[2:3] == ["intra-interface"]
            self.inter = self.inter or entry.words[2:3] == ["inter-interface"]

    @property
    def complete(self) -> bool:
        """Whether the input shows which interfaces there are."""
        return self.declared >= 2

    def _zone(self, name: str) -> str:
        """The zone for an interface name used in a rule; ``any`` is every interface."""
        if name == ANY:
            return ANY
        if name not in self.p.zones:
            self.p.zones[name] = Zone(name)
        return name

    def _routed(self, intervals: Sequence[Interval]) -> Optional[List[str]]:
        """Interfaces that addresses are routed to; None when the configuration does not tell for all of them.

        Goes by the connected networks and the static routes, the longest prefix first. With routing
        protocols or policy routing in the configuration only the connected networks are relied on.
        """
        remaining = normalize(intervals)
        if self.bridged or intersect(remaining, self.unrouted):
            return None
        zones: List[str] = []
        for network in sorted(self.routes, key=size):
            if self.dynamic_routing and network not in self.connected:
                continue
            rest = subtract(remaining, [network])
            if rest != remaining:
                zones += [nameif for nameif in self.routes[network] if nameif not in zones]
            remaining = rest
            if not remaining:
                return zones
        return None

    def _route_zone(self, member: str) -> str:
        """The one interface an address is reached by, or ``any`` when that is not known."""
        intervals = transform.address_intervals(self.p, member)
        zones = self._routed(intervals) if intervals else None
        return zones[0] if zones is not None and len(zones) == 1 and zones[0] in self.nameifs else ANY

    def _egress(self, destination: str) -> Optional[List[str]]:
        """Interfaces the traffic of a rule can leave by, going by where its destination is routed to."""
        if destination in (ANY, ANY_V4, ANY_V6):
            return None
        intervals, complete = transform.known_intervals(self.p, destination)
        zones = self._routed(intervals) if complete and intervals else None
        return [zone for zone in zones if zone in self.nameifs] if zones is not None else None

    def _blocked(self, source: str) -> Set[str]:
        """Interfaces that traffic arriving on ``source`` cannot leave by, whatever the access lists say."""
        if self.ftd:
            return set()  # an FTD has one security level and forwards between and within its interfaces
        out: Set[str] = set()
        if not self.intra:
            out.add(source)
        if not self.inter and source in self.interfaces:
            level = self.interfaces[source].level
            out |= {n for n in self.nameifs if n != source and n in self.interfaces and self.interfaces[n].level == level}
        return out

    # -- objects ----------------------------------------------------------

    def _model_name(self, kind: str, name: str, taken: Set[str], suffix: str = "") -> str:
        if name in _RESERVED_NAMES:
            new = _unique(f"{name}-object", taken)
            self.report.add(
                kind, new, Severity.INFO, "RENAMED", f"named '{name}' in the source, a reserved word; renamed to '{new}'"
            )
            return new
        return _unique(name, taken, suffix)

    def _objects(self) -> None:
        networks: Dict[str, List[_Entry]] = {}
        services: Dict[str, List[_Entry]] = {}
        for entry in self._top("object"):
            if len(entry.words) < 3:
                continue
            table = networks if entry.words[1] == "network" else services if entry.words[1] == "service" else None
            if table is not None:
                table.setdefault(entry.words[2], []).extend(entry.children)
        for name in networks:
            self.net_objects[name] = self._model_name("address", name, self.address_names)
        for name in services:
            self.svc_objects[name] = self._model_name("service", name, self.service_names)
        for name, lines in networks.items():
            self.p.addresses[self.net_objects[name]] = self._network_object(self.net_objects[name], lines)
            self.object_nat += [(name, line) for line in lines if line.words[0] == "nat"]
        for name, lines in services.items():
            neutral = self.svc_objects[name]
            service = Service(neutral, [])
            problems: List[str] = []
            for line in lines:
                if line.words[0] == "description":
                    service.description = line.text.partition(" ")[2]
                elif line.words[0] == "service":
                    service.entries += self._service_spec(line.words[1:], problems)
                else:
                    problems.append(f"line '{line.text[:40]}'")
            if problems or not service.entries:
                service.unsupported = "; ".join(problems) or "service object without a definition"
                self.report.add(
                    "service", neutral, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{service.unsupported}: not converted"
                )
            self.p.services[neutral] = service

    def _network_object(self, name: str, lines: List[_Entry]) -> Address:
        description = ""
        value: Optional[str] = None
        kind = AddressKind.NETWORK
        family = 0
        raw = ""
        for line in lines:
            words = line.words
            if words[0] == "description":
                description = line.text.partition(" ")[2]
            elif words[0] == "host" and len(words) == 2:
                interval = parse_literal(self._ip(words[1]))
                single = interval is not None and interval[1] == interval[2] and "/" not in words[1]
                value = f"{self._ip(words[1])}/{32 if interval and interval[0] == 4 else 128}" if single else None
                raw = line.text
            elif words[0] == "subnet" and len(words) in (2, 3):
                value = netmask_to_cidr(self._ip(words[1]), words[2]) if len(words) == 3 else words[1]
                if value is not None and (parse_literal(value) is None or "/" not in value or "-" in value):
                    value = None
                raw = line.text
            elif words[0] == "range" and len(words) == 3:
                kind, value = AddressKind.RANGE, f"{self._ip(words[1])}-{self._ip(words[2])}"
                if parse_literal(value) is None:
                    value = None
                raw = line.text
            elif words[0] == "fqdn" and len(words) in (2, 3):
                # Without v4 or v6 the ASA resolves the name for IPv4.
                kind, value, family = AddressKind.FQDN, words[-1], 6 if words[1] == "v6" and len(words) == 3 else 4
                raw = line.text
            elif words[0] != "nat":
                raw, value = line.text, None
                break
        if value is None:
            raw = f"network object '{raw[:60]}'" if raw else "network object without an address"
            self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
            return Address(name, AddressKind.UNSUPPORTED, "", description, raw=raw)
        return Address(name, kind, value, description, fqdn_family=family)

    def _service_spec(self, words: List[str], problems: List[str]) -> List[ServiceEntry]:
        """Entries for what follows ``service`` or ``service-object``: a protocol with ports or an ICMP type."""
        cursor = _Cursor(words)
        word = cursor.take()
        protocols = ["tcp", "udp"] if word == "tcp-udp" else [word]
        protos = [_proto(protocol) for protocol in protocols]
        if any(proto is None for proto in protos):
            problems.append(f"protocol '{word[:20]}'")
            return []
        kinds = [proto[0] for proto in protos if proto is not None]
        src = dst = ""
        types: List[Tuple[Optional[int], Optional[int]]] = [(None, None)]
        if all(kind in _PORT_PROTOCOLS for kind in kinds):
            for side in ("source", "destination"):
                if cursor.peek() == side and cursor.peek(1) in _OPERATORS:
                    cursor.take()
                    ports = _ports(cursor)
                    if ports is None:
                        problems.append(f"{side} port in '{' '.join(words)[:40]}'")
                        return []
                    if side == "source":
                        src = ports
                    else:
                        dst = ports
        elif kinds[0] in ("icmp", "icmp6") and not cursor.done:
            icmp_type = _icmp_type(cursor.take(), kinds[0] == "icmp6")
            code: Optional[int] = None
            if not cursor.done and is_number(cursor.peek()) and int(cursor.peek()) < 256:
                code = int(cursor.take())
            if icmp_type is None:
                problems.append(f"ICMP type in '{' '.join(words)[:40]}'")
                return []
            types = [(icmp_type, code)]
        if not cursor.done:
            problems.append(f"'{' '.join(cursor.rest())[:40]}' in a service")
            return []
        return self._entries([proto for proto in protos if proto is not None], src, dst, types)

    @staticmethod
    def _entries(
        protos: List[Proto], src: str, dst: str, types: List[Tuple[Optional[int], Optional[int]]]
    ) -> List[ServiceEntry]:
        out: List[ServiceEntry] = []
        for kind, number in protos:
            if kind in _PORT_PROTOCOLS:
                out.append(ServiceEntry(Protocol(kind), dst_ports=dst, src_ports=src))
            elif kind in ("icmp", "icmp6"):
                out += [ServiceEntry(Protocol(kind), icmp_type=icmp_type, icmp_code=code) for icmp_type, code in types]
            elif kind == "ip":
                out.append(ServiceEntry(Protocol.IP))
            else:
                out.append(ServiceEntry(Protocol.IP, ip_protocol=number))
        return out

    def _inline_service(self, entries: List[ServiceEntry], hint: str = "") -> str:
        """The service object for protocols and ports that an access list entry or a NAT rule spells out."""
        key = _key(entries)
        if key not in self.inline:
            protocols = transform.dedupe([e.protocol.value for e in entries])
            if hint:
                label = hint
            elif len(entries) == 1:
                label = _label(entries[0])
            elif len({_key([e])[0][1:] for e in entries}) == 1:
                label = "-".join(protocols) + _label(entries[0])[len(protocols[0]) :]  # tcp-udp-53
            else:
                label = "-".join([_label(e) for e in entries[:2]] + (["etc"] if len(entries) > 2 else []))
            name = _unique(label, self.service_names)
            # One protocol with one port specification is what an access list entry says by itself.
            self.p.services[name] = Service(name, list(entries), builtin="asa" if len(entries) == 1 and not hint else "")
            self.inline[key] = name
        return self.inline[key]

    # -- object groups ----------------------------------------------------

    def _groups(self) -> None:
        networks: Dict[str, List[_Entry]] = {}
        services: Dict[str, List[_Entry]] = {}
        for entry in self._top("object-group"):
            words = entry.words
            if len(words) < 3:
                continue
            kind, name = words[1], words[2]
            if kind == "network":
                networks.setdefault(name, []).extend(entry.children)
            elif kind == "service" and len(words) > 3:
                group = self.port_groups.setdefault(name, _PortGroup(words[3]))
                if words[3] not in ("tcp", "udp", "tcp-udp"):
                    group.problems.append(f"port group of type '{words[3][:20]}'")
                self._port_group(group, entry.children)
            elif kind == "service":
                services.setdefault(name, []).extend(entry.children)
            elif kind in ("protocol", "icmp-type"):
                table = self.proto_groups if kind == "protocol" else self.icmp_groups
                member = "protocol-object" if kind == "protocol" else "icmp-object"
                items, nested = table.setdefault(name, ([], []))
                for child in entry.children:
                    if child.words[0] == member and len(child.words) == 2:
                        items.append(child.words[1])
                    elif child.words[0] == "group-object" and len(child.words) == 2:
                        nested.append(child.words[1])
                    elif child.words[0] != "description":
                        items.append("?")  # unreadable: makes every use of the group unusable
            else:
                self.other_groups[name] = "TrustSec security" if kind == "security" else kind
        for name in networks:
            self.net_groups[name] = self._model_name("address-group", name, self.address_names, "-group")
        for name in services:
            self.svc_groups[name] = self._model_name("service-group", name, self.service_names, "-group")
        for name, lines in networks.items():
            self._network_group(self.net_groups[name], lines)
        for name, lines in services.items():
            self._service_group(self.svc_groups[name], lines)
        for deep in self._too_deep({name: group.nested for name, group in self.port_groups.items()}):
            self.port_groups[deep].nested = []
            self.port_groups[deep].problems.append(f"port groups nested more than {_MAX_NESTING} deep")
        for table in (self.proto_groups, self.icmp_groups):
            for deep in self._too_deep({name: nested for name, (_, nested) in table.items()}):
                table[deep] = (table[deep][0] + ["?deep"], [])  # unreadable: every use of the group is reported
        for deep in self._too_deep({name: group.members for name, group in self.p.address_groups.items()}):
            cut = self.p.address_groups[deep]
            cut.members = [member for member in cut.members if member not in self.p.address_groups]
            cut.unsupported = f"object groups nested more than {_MAX_NESTING} deep"
            self.report.add("address-group", deep, Severity.REVIEW, "UNSUPPORTED_GROUP", cut.unsupported)
        for deep in self._too_deep({name: sgroup.members for name, sgroup in self.p.service_groups.items()}):
            # Without members a service group cannot be converted, and rules that use it are switched off.
            self.p.service_groups[deep].members = []
            reason = f"object groups nested more than {_MAX_NESTING} deep: not converted"
            self.report.add("service-group", deep, Severity.REVIEW, "UNSUPPORTED_SERVICE", reason)

    @staticmethod
    def _too_deep(groups: Dict[str, List[str]]) -> List[str]:
        """Groups at which nesting passes the limit; every pass over the model below them stays shallow."""
        depth: Dict[str, int] = {}
        out: List[str] = []
        for start in groups:
            stack = [(start, iter(groups[start]))]
            path = {start}
            while stack:
                name, members = stack[-1]
                nested = next((m for m in members if m in groups and m not in depth and m not in path), None)
                if nested is not None:
                    stack.append((nested, iter(groups[nested])))
                    path.add(nested)
                    continue
                stack.pop()
                path.discard(name)
                if name in depth:
                    continue
                depth[name] = 1 + max((depth.get(m, 0) for m in groups[name] if m in groups), default=0)
                if depth[name] > _MAX_NESTING:
                    out.append(name)
                    depth[name] = 1  # cut here: what uses this group starts counting again
        return out

    def _port_group(self, group: _PortGroup, lines: List[_Entry]) -> None:
        for line in lines:
            words = line.words
            if words[0] == "port-object" and words[1:2] and words[1] in _OPERATORS:
                cursor = _Cursor(words[1:])
                ports = _ports(cursor)
                if ports is None or not cursor.done:
                    group.problems.append(f"'{line.text[:40]}'")
                else:
                    group.ports.append(ports)
            elif words[0] == "group-object" and len(words) == 2:
                group.nested.append(words[1])
            elif words[0] != "description":
                group.problems.append(f"'{line.text[:40]}'")

    def _network_group(self, name: str, lines: List[_Entry]) -> None:
        group = AddressGroup(name)
        problems: List[str] = []
        for line in lines:
            words = line.words
            if words[0] == "description":
                group.description = line.text.partition(" ")[2]
            elif words[0] == "group-object" and len(words) == 2:
                group.members.append(self.net_groups.get(words[1], words[1]))
            elif words[0] == "network-object" and len(words) == 3 and words[1] == "object":
                group.members.append(self.net_objects.get(words[2], words[2]))
            elif words[0] == "network-object" and len(words) in (2, 3):
                cursor = _Cursor(words[1:])
                member = self._address(cursor, problems, in_group=True)
                if cursor.done and member != ANY:
                    group.members.append(member)
                elif not problems:
                    problems.append(f"'{line.text[:40]}'")
            else:
                problems.append(f"'{line.text[:40]}'")
        if problems:
            group.unsupported = "member that could not be read: " + "; ".join(problems[:3])
            self.report.add("address-group", name, Severity.REVIEW, "UNSUPPORTED_GROUP", group.unsupported)
        group.members = transform.dedupe(group.members)
        self.p.address_groups[name] = group

    def _service_group(self, name: str, lines: List[_Entry]) -> None:
        entries: List[ServiceEntry] = []
        members: List[str] = []
        problems: List[str] = []
        description = ""
        for line in lines:
            words = line.words
            if words[0] == "description":
                description = line.text.partition(" ")[2]
            elif words[0] == "group-object" and len(words) == 2:
                if words[1] in self.svc_groups:
                    members.append(self.svc_groups[words[1]])
                else:
                    problems.append(f"group '{words[1][:40]}', which is not a service group")
            elif words[0] == "service-object" and len(words) == 3 and words[1] == "object":
                members.append(self.svc_objects.get(words[2], words[2]))
            elif words[0] == "service-object" and len(words) > 1:
                entries += self._service_spec(words[1:], problems)
            else:
                problems.append(f"'{line.text[:40]}'")
        reason = ("member that could not be read: " + "; ".join(problems[:3])) if problems else ""
        if not members:
            service = Service(name, entries, description, unsupported=reason)
            if not entries and not reason:
                service.unsupported = "empty service group"
            self.p.services[name] = service
        else:
            if entries or reason:
                inline = _unique(f"{name}-inline", self.service_names)
                self.p.services[inline] = Service(inline, entries, f"entries of group {name}", unsupported=reason)
                members.append(inline)
            self.p.service_groups[name] = ServiceGroup(name, transform.dedupe(members), description)
        if reason:
            kind = "service-group" if members else "service"
            self.report.add(kind, name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{reason}: not converted")

    def _group_ports(self, name: str, problems: List[str]) -> List[str]:
        """The ports of a port group and of the groups inside it."""
        if not self.port_tables:
            groups = self.port_groups.items()
            self.port_tables = [{n: (g.ports, g.nested) for n, g in groups}, {n: (g.problems, g.nested) for n, g in groups}]
        found, own = self._walk(name, self.port_tables[0], self.port_memo, ())
        unreadable, _ = self._walk(name, self.port_tables[1], self.port_problem_memo, ())
        problems += own + unreadable
        return found

    def _group_words(self, table: Dict[str, Tuple[List[str], List[str]]], name: str, problems: List[str]) -> List[str]:
        """The protocols or ICMP types of a group and of the groups inside it."""
        memo = self.word_memo.setdefault(id(table), {})
        found, own = self._walk(name, table, memo, ())
        problems += own
        return found

    def _walk(
        self,
        name: str,
        table: Dict[str, Tuple[List[str], List[str]]],
        memo: Dict[str, Tuple[List[str], List[str]]],
        path: Tuple[str, ...],
    ) -> Tuple[List[str], List[str]]:
        """(items of a group and the groups inside it, what could not be followed); each group is read once."""
        if name not in memo:
            items, nested_groups = table[name]
            found, problems = list(items), []
            for nested in nested_groups:
                if nested not in table or nested == name or nested in path:
                    problems.append(f"group '{nested[:40]}' inside '{name[:40]}'")
                else:
                    more, trouble = self._walk(nested, table, memo, path + (name,))
                    found += more
                    problems += trouble
            memo[name] = (transform.dedupe(found), transform.dedupe(problems))
        return memo[name]

    # -- access lists -----------------------------------------------------

    def _address(self, cursor: _Cursor, problems: List[str], in_group: bool = False) -> str:
        """Read one address specification; ``any`` (with a problem recorded) where it cannot be read."""
        word = cursor.take()
        if not in_group:
            if word == "any":
                return ANY if self.any_both else ANY_V4
            if word == "any4":
                return ANY_V4
            if word == "any6":
                return ANY_V6
            if word == "object":
                name = cursor.take()
                return self.net_objects.get(name, name)
            if word == "object-group":
                name = cursor.take()
                if name in self.other_groups:
                    problems.append(f"{self.other_groups[name]} group '{name[:40]}'")
                    return ANY
                return self.net_groups.get(name, name)
            if word == "interface":
                problems.append(f"the address of interface '{cursor.take()[:40]}'")
                return ANY
        if word == "host":
            address = self._ip(cursor.take())
            interval = parse_literal(address)
            if interval is None or interval[1] != interval[2] or "/" in address or "-" in address:
                problems.append(f"host address '{address[:40]}'")
                return ANY
            return address
        if ":" in word:
            interval = parse_literal(word) if "/" in word and "-" not in word else None
            if interval is None or interval[0] != 6:
                problems.append(f"address '{word[:40]}'")
                return ANY
            return ANY_V6 if size(interval) == 2**128 else f"{int_to_ip(6, interval[1])}/{word.rpartition('/')[2]}"
        mask = cursor.take()
        network = netmask_to_cidr(self._ip(word), mask) if "-" not in word and "/" not in word else None
        if network is None:
            problems.append(f"address '{word[:40]} {mask[:20]}'")
            return ANY
        if network == ANY_V4:
            return ANY_V4
        return network[:-3] if network.endswith("/32") else network

    def _access_lists(self) -> None:
        pending: Dict[str, List[str]] = {}
        for entry in self._top("access-list"):
            words = entry.words
            if len(words) < 3:
                continue
            acl, rest = words[1], words[2:]
            if rest[0] == "line" and len(rest) > 2:
                rest = rest[2:]
            if rest[0] == "remark":
                text = entry.text.partition(" remark ")[2].strip()
                found = _FTD_REMARK.fullmatch(text)
                if found:
                    kind, _, name = found.group(2).partition(": ")
                    if kind.endswith("RULE") and name:
                        self.ftd_rules[found.group(1)] = (kind, name.strip())
                elif text:
                    pending.setdefault(acl, []).append(text)
                continue
            if rest[0] in ("standard", "ethertype", "webtype"):
                self.other_acls.setdefault(acl, rest[0])
                continue
            if rest[0] == "rename":
                continue
            if rest[0] in ("extended", "advanced"):
                rest = rest[1:]
            if not rest or rest[0] not in ("permit", "deny", "trust"):
                continue
            aces = self.acls.setdefault(acl, [])
            ace = self._ace(acl, len(aces) + 1, rest)
            ace.remark = " / ".join(pending.pop(acl, []))
            aces.append(ace)
            # Entries that name their interfaces and carry a rule id are written by an FTD manager.
            self.ftd = self.ftd or bool(ace.rule_id or ace.src_ifc or ace.dst_ifc)

    def _identity(self, cursor: _Cursor, ace: _Ace) -> None:
        """User and security-group conditions in front of an address."""
        while True:
            word = cursor.peek()
            if word == "user":
                cursor.take()
                name = cursor.take()
                if name in ("any", "none"):
                    ace.problems.append(f"match on 'user {name}'")
                else:
                    ace.users.append(name)
            elif word in ("user-group", "object-group-user"):
                cursor.take()
                ace.users.append(cursor.take())
            elif word == "security-group":
                cursor.take()
                ace.problems.append(f"TrustSec security group {cursor.take()} {cursor.take()[:40]}")
            elif word == "object-group-security":
                cursor.take()
                ace.problems.append(f"TrustSec security group '{cursor.take()[:40]}'")
            else:
                return

    def _ace(self, acl: str, number: int, words: List[str]) -> _Ace:
        cursor = _Cursor(words)
        ace = _Ace(acl, number, cursor.take())
        problems = ace.problems
        protos: List[Proto] = []
        services: Optional[List[str]] = None
        word = cursor.take()
        if word == "object":
            name = cursor.take()
            services = [self.svc_objects.get(name, name)]
        elif word == "object-group":
            name = cursor.take()
            if name in self.proto_groups:
                for item in self._group_words(self.proto_groups, name, problems):
                    proto = _proto(item)
                    if item == "?deep":
                        problems.append(f"protocol groups nested more than {_MAX_NESTING} deep (group '{name[:40]}')")
                    elif item == "?":
                        problems.append(f"line that could not be read in protocol group '{name[:40]}'")
                    elif proto is None:
                        problems.append(f"protocol '{item[:20]}' in group '{name[:40]}'")
                    elif proto not in protos:
                        protos.append(proto)
                if not protos and not problems:
                    problems.append(f"empty protocol group '{name[:40]}'")
            elif name in self.svc_groups:
                services = [self.svc_groups[name]]
            else:
                problems.append(f"'{name[:40]}', which is not a protocol or service group")
        else:
            proto = _proto(word)
            if proto is None:
                problems.append(f"protocol '{word[:20]}'")
            else:
                protos = [proto]
        with_ports = bool(protos) and all(name in _PORT_PROTOCOLS for name, _ in protos)

        hints: List[str] = []

        def ports(side: str) -> str:
            if cursor.peek() in _OPERATORS:
                found = _ports(cursor)
                if found is None or not with_ports:
                    problems.append(f"{side} port")
                return found or ""
            if cursor.peek() == "object-group" and cursor.peek(1) in self.port_groups:
                cursor.take()
                group = cursor.take()
                kind = self.port_groups[group].kind
                allowed = {"tcp": ["tcp"], "udp": ["udp"], "tcp-udp": ["tcp", "udp"]}.get(kind, [])
                if not with_ports or any(name not in allowed for name, _ in protos):
                    problems.append(f"port group '{group[:40]}' ({kind[:20]}) on this protocol")
                found_ports = self._group_ports(group, problems)
                if not found_ports:
                    problems.append(f"empty port group '{group[:40]}'")
                # A group of destination ports gives the service its name.
                partial = len(allowed) > len(protos)
                hints.append((group + ("-" + protos[0][0] if partial and protos else "")) if side == "destination" else "")
                return ",".join(transform.dedupe(found_ports))
            return ""

        self._identity(cursor, ace)
        if cursor.peek() == "ifc":
            cursor.take()
            ace.src_ifc = cursor.take()
        ace.source = self._address(cursor, problems)
        src_ports = ports("source")
        self._identity(cursor, ace)
        if cursor.peek() == "ifc":
            cursor.take()
            ace.dst_ifc = cursor.take()
        ace.destination = self._address(cursor, problems)
        dst_ports = ports("destination")
        types: List[Tuple[Optional[int], Optional[int]]] = [(None, None)]
        trailing = ("log", "time-range", "inactive", "rule-id", "event-log", "")
        if protos and all(name in ("icmp", "icmp6") for name, _ in protos) and cursor.peek() not in trailing:
            v6 = protos[0][0] == "icmp6"
            if cursor.peek() == "object-group" and cursor.peek(1) in self.icmp_groups:
                cursor.take()
                group = cursor.take()
                names = self._group_words(self.icmp_groups, group, problems)
                numbers = [_icmp_type(name, v6) for name in names]
                if "?deep" in names:
                    problems.append(f"ICMP type groups nested more than {_MAX_NESTING} deep (group '{group[:40]}')")
                elif not numbers or any(number is None for number in numbers):
                    problems.append(f"ICMP type that could not be read in group '{group[:40]}'")
                else:
                    types = [(number, None) for number in _distinct(numbers)]
                    hints.append(group)
            else:
                icmp_type = _icmp_type(cursor.take(), v6)
                code: Optional[int] = None
                if is_number(cursor.peek()) and int(cursor.peek()) < 256:
                    code = int(cursor.take())
                if icmp_type is None or len(protos) > 1:
                    problems.append("ICMP type")
                else:
                    types = [(icmp_type, code)]
        while not cursor.done:
            word = cursor.take()
            if word == "log":
                ace.log = True
                if cursor.peek() == "disable":
                    cursor.take()
                    ace.log = False
                elif cursor.peek() == "default":
                    cursor.take()
                else:
                    if cursor.peek() in _LOG_LEVELS:
                        cursor.take()
                    if cursor.peek() == "interval":
                        cursor.take()
                        cursor.take()
            elif word == "time-range" and not cursor.done:
                ace.schedule = cursor.take()
            elif word == "inactive":
                ace.inactive = True
            elif word == "rule-id" and not cursor.done:
                ace.rule_id = cursor.take()
            elif word == "event-log" and cursor.peek() in ("flow-start", "flow-end", "both"):
                events = cursor.take()
                ace.log_start = events in ("flow-start", "both")
                ace.log = events in ("flow-end", "both")
            else:
                problems.append(f"'{' '.join([word] + cursor.rest())[:40]}' at the end of the entry")
        if services is not None:
            ace.services = services
            if src_ports or dst_ports:
                problems.append("ports next to a service object")
        elif protos and not any(name == "ip" for name, _ in protos):
            entries = self._entries(protos, src_ports, dst_ports, types)
            ace.services = [self._inline_service(entries, hints[0] if len(hints) == 1 else "")]
        return ace

    # -- security rules ---------------------------------------------------

    def _new_rule(self, ace: _Ace, name: str, src: List[str], dst: List[str], scope: RuleScope) -> Rule:
        rule = Rule(name=_unique(name, self.rule_names), src_zones=list(src), dst_zones=list(dst), scope=scope)
        rule.origin = rule.name
        rule.sources, rule.destinations, rule.services = [ace.source], [ace.destination], list(ace.services)
        rule.action = Action.ALLOW if ace.allow else Action.DROP
        rule.enabled = not ace.inactive
        rule.schedule = ace.schedule
        # Without "log" an ASA still reports what an entry denies (message 106023).
        rule.log_end = ace.log if ace.log is not None else (not ace.allow and not self.ftd)
        rule.log_start = ace.log_start
        rule.description = ace.remark
        rule.users = transform.dedupe(ace.users) or [ANY]
        rule.unsupported = ["access list entry with " + problem for problem in transform.dedupe(ace.problems)]
        return rule

    def _place(self, ace: _Ace, src: List[str], dst: List[str]) -> List[Tuple[List[str], List[str], RuleScope, bool]]:
        """Zones for the rules an entry becomes: (source zones, destination zones, rule type, zones worked out).

        An entry of an ASA names no outgoing interface. Its traffic leaves where the destination
        is routed to, and never by an interface the ASA does not forward to from where it came in.
        A deny needs none of that: it denies what would be dropped anyway.
        """
        universal = RuleScope.UNIVERSAL
        if not ace.allow or not self.complete:
            return [(src, dst, universal, False)]
        sources = self.nameifs if ANY in src else src
        blocked = {source: self._blocked(source) for source in sources}
        # Before 8.3 an entry names the translated address, which says nothing about the way out.
        routed = self._egress(ace.destination) if ANY in dst and self.modern_nat else None
        if routed is None:
            if not any(blocked.values()) or (ANY not in dst and not any(blocked[source] & set(dst) for source in sources)):
                return [(src, dst, universal, False)]
            if ANY in dst and all(blocked[source] == {source} for source in sources) and len(sources) > 1:
                # "Between any two different interfaces" is what an interzone rule says.
                return [(list(sources), list(self.nameifs), RuleScope.INTERZONE, True)]
        else:
            self.egress_by_route = True
        candidates = routed if routed is not None else self.nameifs if ANY in dst else dst
        leaving: Dict[Tuple[str, ...], List[str]] = {}
        for source in sources:
            leaving.setdefault(tuple(n for n in candidates if n not in blocked[source]), []).append(source)
        out: List[Tuple[List[str], List[str], RuleScope, bool]] = []
        for leaves, members in leaving.items():
            if leaves:
                everywhere = ANY in src and len(members) == len(self.nameifs)
                out.append(([ANY] if everywhere else members, list(leaves), universal, ANY in dst))
        return out

    def _add_rules(self, ace: _Ace, name: str, src: List[str], dst: List[str]) -> None:
        placed = self._place(ace, src, dst)
        if not placed:
            self.without_effect += 1
        for src_zones, dst_zones, scope, implied in placed:
            rule = self._new_rule(ace, name, src_zones, dst_zones, scope)
            rule.egress_implied = implied
            self.p.rules.append(rule)

    def _rules(self) -> None:
        inbound: Dict[str, List[str]] = {}  # access list -> interfaces it is bound to, inbound
        outbound: Dict[str, List[str]] = {}
        has_inbound: Set[str] = set()
        v6_only: Set[str] = set()  # interfaces with a list for IPv6 alone (before 9.0), which is not converted
        global_acl = ""
        skipped: List[str] = []
        for entry in self._top("access-group"):
            words = entry.words
            other = self.other_acls.get(words[1], "") if len(words) > 1 and words[1] not in self.acls else ""
            if len(words) == 3 and words[2] == "global":
                global_acl = "" if other else words[1]
            elif len(words) >= 5 and words[2] in ("in", "out") and words[3] == "interface":
                if "control-plane" in words[5:]:
                    continue  # traffic to the ASA itself
                if other:
                    # An EtherType list says nothing about IP traffic; an IPv6 list nothing about IPv4.
                    if other == "ipv6" and words[2] == "in":
                        v6_only.add(words[4])
                    continue
                if words[4] in self.interfaces and self.interfaces[words[4]].management_only:
                    skipped.append(words[4])
                    continue
                if "per-user-override" in words[5:]:
                    self.report.note(
                        Severity.APPROX,
                        "PER_USER_OVERRIDE",
                        f"access list '{words[1]}' on interface '{words[4]}' can be overridden per user by an access "
                        "list that the authentication server sends; such lists are not in the configuration",
                    )
                zone = self._zone(words[4])
                if zone not in self.nameifs:
                    self.nameifs.append(zone)
                (inbound if words[2] == "in" else outbound).setdefault(words[1], []).append(zone)
                if words[2] == "in":
                    has_inbound.add(zone)
        if skipped:
            self.report.note(
                Severity.INFO,
                "MANAGEMENT_INTERFACE",
                "management-only interfaces forward no traffic; their access lists were left out: "
                + ", ".join(transform.dedupe(skipped)),
            )
        bound = set(inbound) | set(outbound) | ({global_acl} if global_acl else set())
        missing = sorted(name for name in bound if name not in self.acls)
        if missing:
            self.report.note(
                Severity.REVIEW,
                "ACL_MISSING",
                "access-group binds access lists that are not in the input: " + ", ".join(missing) + ". An "
                "interface with such a list was read as passing nothing; check that the input is complete",
            )
        self._outbound(outbound)
        for acl, zones in inbound.items():
            self._acl_rules(acl, transform.dedupe(zones))
        if not global_acl and not self.ftd:
            self._implicit_permits(has_inbound, v6_only)
        if global_acl:
            self._acl_rules(global_acl, [ANY])
        unbound = sorted(name for name in self.acls if name not in bound)
        if self.acls and not bound:
            self.report.note(
                Severity.REVIEW,
                "NO_ACCESS_GROUP",
                "no 'access-group' line binds an access list to an interface: no security rules were read. "
                f"Access lists in the input: {', '.join(unbound[:8])}" + (" ..." if len(unbound) > 8 else ""),
            )
        elif unbound:
            self.report.note(
                Severity.INFO,
                "UNBOUND_ACL",
                f"{len(unbound)} access lists are not bound with access-group (they serve NAT, VPN or class maps) "
                "and are not security rules: " + ", ".join(unbound[:8]) + (" ..." if len(unbound) > 8 else ""),
            )

    def _acl_rules(self, acl: str, zones: List[str]) -> None:
        """Rules for an access list that applies to traffic arriving on ``zones``."""
        aces = self.acls.get(acl, [])
        if any(ace.rule_id or ace.src_ifc or ace.dst_ifc for ace in aces):
            self._ftd_rules(aces, zones)
            return
        for ace in aces:
            self._add_rules(ace, f"{acl}-{ace.number}", zones, [ANY])

    def _implicit_permits(self, has_inbound: Set[str], v6_only: Set[str]) -> None:
        if not self.complete:
            return
        for nameif in self.nameifs:
            if nameif in has_inbound or nameif not in self.interfaces:
                continue
            level = self.interfaces[nameif].level
            leaves: List[str] = []
            for other in self.nameifs:
                other_level = self.interfaces[other].level if other in self.interfaces else None
                if other == nameif:
                    lower = self.intra
                elif other_level is None or level is None:
                    lower = False
                else:
                    lower = other_level < level or (other_level == level and self.inter)
                if lower:
                    leaves.append(other)
            if not leaves:
                continue
            rule = Rule(name=_unique(f"implicit-{nameif}", self.rule_names), src_zones=[nameif], dst_zones=leaves)
            rule.origin = rule.name
            rule.log_end = False
            if nameif in v6_only:
                rule.sources, rule.destinations = [ANY_V4], [ANY_V4]  # its IPv6 traffic has a list, which is not converted
            rule.description = "ASA implicit rule: traffic to interfaces of a lower security level is permitted"
            self.p.rules.append(rule)
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "IMPLICIT_PERMIT",
                f"interface '{nameif}' (security level {level}) has no access list: the ASA lets its traffic out "
                "by the interfaces its security level and 'same-security-traffic' allow, here "
                + ", ".join(leaves) + ". This rule says so",
            )

    def _outbound(self, outbound: Dict[str, List[str]]) -> None:
        """Access lists bound ``out``: a connection has to pass them as well.

        A first-match rulebase can say that for a list that only denies and then
        permits everything: its denies go in front. Any other list is reported.
        """
        everything = ANY if self.any_both else ANY_V4
        for acl, zones in outbound.items():
            aces = [ace for ace in self.acls.get(acl, []) if not ace.inactive]
            last = aces[-1] if aces else None
            passes_rest = (
                last is not None and last.allow and last.services == [ANY] and last.source == everything
                and last.destination == everything and not last.problems and not last.schedule and not last.users
            )  # fmt: skip
            if aces and passes_rest and all(not ace.allow for ace in aces[:-1]):
                for ace in self.acls[acl]:
                    if not ace.allow:
                        self._add_rules(ace, f"{acl}-{ace.number}", [ANY], transform.dedupe(zones))
                continue
            self.report.note(
                Severity.REVIEW,
                "OUTBOUND_ACL",
                f"access list '{acl}' is bound outbound to {', '.join(transform.dedupe(zones))}: traffic leaving by "
                "that interface has to pass it as well as the inbound list. It is not converted, so the result "
                "allows traffic towards that interface that this list stops. Add its restrictions by hand",
            )

    def _ftd_rules(self, aces: List[_Ace], zones: List[str]) -> None:
        """Entries an FTD wrote: they name their interfaces, and one rule of the manager is several entries.

        Entries with the same rule id that differ in their interfaces only become one rule,
        named after the remark that carries the name of the rule.
        """
        for rule_id, run in itertools.groupby(aces, key=lambda ace: ace.rule_id):
            kind, name = self.ftd_rules.get(rule_id, ("", f"rule-{rule_id}" if rule_id else "rule"))
            merged: Dict[Tuple[object, ...], List[_Ace]] = {}
            for ace in run:
                if kind.startswith("L7"):
                    ace.problems.append(
                        "application, URL or user conditions (an FTD 'L7 rule'): they are not in the device configuration"
                    )
                elif name == "DEFAULT TUNNEL ACTION RULE":
                    ace.problems.append(
                        "the FTD prefilter default for tunnels, which hands the traffic inside them to the access rules"
                    )
                key = (ace.action, ace.source, ace.destination, tuple(ace.services), ace.inactive, tuple(ace.problems),
                       ace.log, ace.log_start, ace.schedule, tuple(ace.users))  # fmt: skip
                merged.setdefault(key, []).append(ace)
            for group in merged.values():
                pairs = _distinct(
                    [
                        (source, ace.dst_ifc or ANY)
                        for ace in group
                        for source in ([ace.src_ifc] if ace.src_ifc else zones)
                        if ANY in zones or source in zones
                    ]
                )
                if not pairs:
                    self.without_effect += 1  # bound to other interfaces than the entry names
                    continue
                sources = transform.dedupe([source for source, _ in pairs])
                targets = transform.dedupe([target for _, target in pairs])
                if len(pairs) == len(sources) * len(targets):
                    combined = [(sources, targets)]
                else:
                    combined = [([s], [target for source, target in pairs if source == s]) for s in sources]
                for src, dst in combined:
                    src_zones = [ANY] if ANY in src else [self._zone(zone) for zone in src]
                    dst_zones = [ANY] if ANY in dst else [self._zone(zone) for zone in dst]
                    self._add_rules(group[0], name, src_zones, dst_zones)

    # -- NAT --------------------------------------------------------------

    def _nat(self) -> None:
        if not self.modern_nat:
            return
        before: List[NatRule] = []
        after: List[NatRule] = []
        for entry in self._top("nat"):
            words = entry.words[1:]
            real_if = mapped_if = ANY  # the interfaces may be left out: every interface
            if words and words[0].startswith("("):
                pair = _IF_PAIR.fullmatch(words[0])
                real_if, mapped_if = (pair.group(1), pair.group(2)) if pair else ("", "")
                words = words[1:]
            after_auto = "after-auto" in words[:2]
            name = _unique(f"nat-after-auto-{len(after) + 1}" if after_auto else f"nat-{len(before) + 1}", self.nat_names)
            if real_if:
                nat = self._twice_nat(name, real_if, mapped_if, words)
            else:
                nat = NatRule(name=name, unsupported=[f"NAT line '{entry.text[:60]}'"])
            (after if after_auto else before).append(nat)
        automatic: List[Tuple[Tuple[int, int, int, str], NatRule]] = []
        for name, entry in self.object_nat:
            pair = _IF_PAIR.fullmatch(entry.words[1]) if len(entry.words) > 2 else None
            neutral = self.net_objects[name]
            nat_name = _unique(f"nat-{neutral}", self.nat_names)
            if pair is None:
                nat = NatRule(name=nat_name, sources=[neutral])
                nat.unsupported.append(f"NAT line '{entry.text[:40]}'")
            else:
                nat = self._object_nat(nat_name, neutral, pair.group(1), pair.group(2), entry.words[2:])
            intervals = transform.address_intervals(self.p, neutral) or []
            # The ASA sorts object NAT: static before dynamic, then the fewest real addresses,
            # then the lowest address, then the name.
            key = (
                0 if entry.words[2:3] == ["static"] else 1,
                sum(size(i) for i in intervals) if intervals else 2**129,
                intervals[0][1] if intervals else 0,
                name,
            )
            automatic.append((key, nat))
        automatic.sort(key=lambda item: item[0])
        self.p.nat_rules = before + [nat for _, nat in automatic] + after
        for nat in self.p.nat_rules:
            nat.origin = nat.name
            nat.combines = True  # one rule can translate the destination and another the source

    def _nat_ref(self, word: str, problems: List[str]) -> str:
        if word in self.net_objects:
            return self.net_objects[word]
        if word in self.net_groups:
            return self.net_groups[word]
        problems.append(f"object '{word[:40]}', which is not defined")
        return word

    def _families(self, member: str) -> Set[int]:
        return {4, 6} if member == ANY else transform.families(self.p, member)

    def _dynamic(
        self, cursor: _Cursor, nat: NatRule, mapped_if: str, ignored: List[str], inline_ok: bool
    ) -> Optional[SourceNat]:
        """Read what follows ``dynamic <real>``: an address object, a PAT pool or the interface."""
        problems = nat.unsupported
        translation: Optional[SourceNat] = None
        if cursor.peek() == "pat-pool":
            cursor.take()
            translation = SourceNat(SnatKind.DYNAMIC_PORT, [self._nat_ref(cursor.take(), problems)])
            while cursor.peek() in _POOL_FLAGS:
                ignored.append(cursor.take())
        elif cursor.peek() != "interface":
            word = cursor.take()
            literal = parse_literal(self._ip(word))
            if word not in self.net_objects and word not in self.net_groups and inline_ok and literal is not None:
                member = self._ip(word)
            else:
                member = self._nat_ref(word, problems)
            intervals = transform.address_intervals(self.p, member) or []
            one = len(intervals) == 1 and size(intervals[0]) == 1
            # One address is port address translation; a range is handed out address by address.
            translation = SourceNat(SnatKind.DYNAMIC_PORT if one else SnatKind.DYNAMIC, [member])
        if cursor.peek() == "interface":
            cursor.take()
            v6 = cursor.peek() == "ipv6"
            if v6:
                cursor.take()
            if translation is not None:
                ignored.append("interface (as fallback)")
            elif v6:
                problems.append("port address translation to the IPv6 address of the interface")
            elif mapped_if == ANY:
                problems.append("port address translation to the interface address without a mapped interface")
            else:
                translation = self._interface_pat(mapped_if)
        return translation

    def _interface_pat(self, nameif: str) -> SourceNat:
        interface = self.interfaces.get(nameif)
        if interface is None:
            return SourceNat(SnatKind.INTERFACE, interface=nameif)
        return SourceNat(SnatKind.INTERFACE, interface=interface.hardware, interface_address=interface.address)

    def _interface_address(self, nat: NatRule, nameif: str) -> str:
        """The object that stands for the address of an interface, where a NAT rule says ``interface``."""
        interface = self.interfaces.get(nameif)
        if interface is None or not interface.address:
            nat.unsupported.append(f"the address of interface '{nameif[:40]}', which is not in the configuration")
            return ANY
        if nameif not in self.interface_objects:
            name = _unique(f"{nameif}-interface", self.address_names)
            # On an ASA this is the keyword "interface", not an object: the emitter for ASA writes it so again.
            self.p.addresses[name] = Address(
                name, AddressKind.NETWORK, f"{interface.address}/32",
                f"address of interface {nameif} when the configuration was read", raw=f"interface {nameif}", builtin="asa",
            )  # fmt: skip
            self.interface_objects[nameif] = name
        self.report.add(
            "nat",
            nat.name,
            Severity.APPROX,
            "NAT_INTERFACE_ADDRESS",
            f"the rule is for the address of interface '{nameif}', whatever that is at the time. It is converted "
            f"with the address the interface has in the configuration, {interface.address}",
        )
        return self.interface_objects[nameif]

    def _finish_nat(self, nat: NatRule, ignored: List[str]) -> NatRule:
        sides: List[Tuple[List[str], List[str]]] = []
        if nat.source_translation is not None and nat.source_translation.addresses:
            sides.append((nat.sources, nat.source_translation.addresses))
        if nat.destination_translation is not None:
            sides.append((nat.destinations, [nat.destination_translation.address]))
        for before, after in sides:
            old: Set[int] = set().union(*[self._families(member) for member in before])
            new: Set[int] = set().union(*[self._families(member) for member in after])
            if not old & new:
                nat.unsupported.append("translation between IPv4 and IPv6")
        nat.unsupported = transform.dedupe(nat.unsupported)
        if ignored:
            self.report.add(
                "nat",
                nat.name,
                Severity.INFO,
                "ATTRIBUTES_IGNORED",
                "NAT options without an equivalent were ignored: " + ", ".join(transform.dedupe(ignored)),
            )
        return nat

    def _service_port(self, word: str, problems: List[str]) -> Optional[ServiceEntry]:
        """The single TCP, UDP or SCTP entry of a service object named in a NAT rule."""
        name = self.svc_objects.get(word, "")
        service = self.p.services.get(name)
        if service is None or service.unsupported or len(service.entries) != 1 or service.entries[0].protocol not in L4_PROTOCOLS:
            problems.append(f"service '{word[:40]}', which is not a service object for one TCP, UDP or SCTP port")
            return None
        return service.entries[0]

    def _twice_nat(self, name: str, real_if: str, mapped_if: str, words: List[str]) -> NatRule:
        cursor = _Cursor(words)
        nat = NatRule(name=name)
        problems = nat.unsupported
        ignored: List[str] = []
        real_zone, mapped_zone = self._zone(real_if), self._zone(mapped_if)
        nat.src_zones, nat.dst_zones = [real_zone], [mapped_zone]
        while cursor.peek() == "after-auto" or is_number(cursor.peek()):
            cursor.take()
        kind = cursor.peek(1)
        if cursor.take() != "source" or cursor.take() not in ("static", "dynamic") or cursor.done:
            problems.append(f"NAT line '{' '.join(words)[:60]}'")
            return self._finish_nat(nat, ignored)
        real = cursor.take()
        nat.sources = [ANY] if real == "any" else [self._nat_ref(real, problems)]
        static_to = ""  # what a static rule maps the source to: an object, "interface", or nothing
        if kind == "dynamic":
            nat.source_translation = self._dynamic(cursor, nat, mapped_zone, ignored, inline_ok=False)
            if nat.source_translation is None and not problems:
                problems.append("dynamic NAT without a translated address")
        else:
            mapped = cursor.take()
            if mapped == "interface":
                static_to = "interface"
                if cursor.peek() == "ipv6":
                    cursor.take()
                    problems.append("static NAT to the IPv6 address of the interface")
            elif mapped == "any":
                if real != "any":
                    problems.append("static NAT of an object to 'any'")
            elif mapped:
                static_to = self._nat_ref(mapped, problems)
            else:
                problems.append("static NAT without a translated address")
        destination: Optional[Tuple[str, str]] = None  # (address in the packet, real address)
        services: Optional[Tuple[str, str]] = None
        flags: Set[str] = set()
        while not cursor.done:
            word = cursor.take()
            if word == "destination" and cursor.peek() == "static" and destination is None:
                cursor.take()
                seen = cursor.take()
                if seen == "interface":
                    if cursor.peek() == "ipv6":
                        cursor.take()
                        problems.append("the IPv6 address of the interface as destination")
                    seen_ref = self._interface_address(nat, real_if)
                    destination = (seen_ref, self._nat_ref(cursor.take(), problems))
                else:
                    destination = (self._nat_ref(seen, problems), self._nat_ref(cursor.take(), problems))
            elif word == "service" and services is None:
                services = (cursor.take(), cursor.take())
            elif word in _NAT_FLAGS:
                flags.add(word)
            elif word == "description":
                nat.description = " ".join(cursor.rest())
            else:
                problems.append(f"'{' '.join([word] + cursor.rest())[:40]}' in a NAT rule")
        nat.enabled = "inactive" not in flags
        ignored += [flag for flag in ("dns", "net-to-net") if flag in flags]
        first = second = None
        if services is not None:
            first, second = self._service_port(services[0], problems), self._service_port(services[1], problems)
            if first is None or second is None:
                return self._finish_nat(nat, ignored)
            if first.protocol != second.protocol:
                problems.append("service translation between two protocols")
                return self._finish_nat(nat, ignored)
        reverse = first is not None and second is not None and bool(first.src_ports) and bool(second.src_ports)
        if reverse and first is not None and second is not None:
            # Written from the side of the server: its port (the source port of its replies) is published.
            # For a connection that is the destination, coming in on the mapped interface.
            if first.dst_ports or second.dst_ports:
                problems.append("service translation of source and destination ports at once")
            if kind != "static" or "unidirectional" in flags or real == "any":
                problems.append("translation of a source port")
            if destination is not None and destination[0] != destination[1]:
                problems.append("port forwarding with a destination translation as well")
            if static_to == "interface":
                published = self._interface_address(nat, mapped_if)
            else:
                published = static_to or nat.sources[0]
            server = nat.sources[0]
            nat.sources = [destination[1]] if destination is not None else [ANY]
            nat.destinations = [published]
            nat.service = self._inline_service([ServiceEntry(second.protocol, dst_ports=second.src_ports)])
            port = "" if first.src_ports == second.src_ports else first.src_ports
            nat.destination_translation = DestNat(server, port)
            nat.src_zones = [mapped_zone]
            nat.dst_zones = [mapped_zone if mapped_zone != ANY else self._route_zone(published)]
            return self._finish_nat(nat, ignored)
        if static_to == "interface":
            problems.append("static NAT to the interface address without a service")
        elif kind == "static" and static_to and static_to != nat.sources[0]:
            two_way = "unidirectional" not in flags
            nat.source_translation = SourceNat(SnatKind.STATIC, [static_to], bidirectional=two_way and destination is None)
            if two_way and destination is not None:
                self.report.add(
                    "nat",
                    name,
                    Severity.APPROX,
                    "NAT_REVERSE_DIRECTION",
                    f"the rule also translates connections opened in the other direction, from '{destination[1]}' to "
                    f"'{static_to}'. That direction is not converted",
                )
        if destination is not None:
            nat.destinations = [destination[0]]
            if destination[0] != destination[1]:
                nat.destination_translation = DestNat(destination[1])
        if first is not None and second is not None:
            if first.src_ports or second.src_ports:
                problems.append("service translation with a source port on one side only")
            nat.service = self.svc_objects[services[0]] if services else ANY
            if first.dst_ports != second.dst_ports:
                if destination is None:
                    problems.append("port translation without a destination address")
                elif nat.destination_translation is None:
                    nat.destination_translation = DestNat(destination[1], second.dst_ports)
                else:
                    nat.destination_translation.port = second.dst_ports
        if nat.destination_translation is not None:
            # The model wants the zone the original destination is reached in; the rule names the
            # interface behind which the real one is.
            nat.dst_zones = [self._route_zone(nat.destinations[0])]
            if nat.dst_zones != [ANY] and nat.dst_zones != [mapped_zone]:
                self._zone_note(nat, nat.destinations[0])
        return self._finish_nat(nat, ignored)

    def _zone_note(self, nat: NatRule, address: str) -> None:
        self.report.add(
            "nat",
            nat.name,
            Severity.INFO,
            "NAT_ZONE_BY_ROUTE",
            f"the zone of the original destination '{address}' ({nat.dst_zones[0]}) was taken from the interface "
            "addresses and static routes in the configuration",
        )

    def _object_nat(self, name: str, neutral: str, real_if: str, mapped_if: str, words: List[str]) -> NatRule:
        cursor = _Cursor(words)
        nat = NatRule(name=name, sources=[neutral])
        problems = nat.unsupported
        ignored: List[str] = []
        real_zone, mapped_zone = self._zone(real_if), self._zone(mapped_if)
        nat.src_zones, nat.dst_zones = [real_zone], [mapped_zone]
        kind = cursor.take()
        if kind == "dynamic":
            nat.source_translation = self._dynamic(cursor, nat, mapped_zone, ignored, inline_ok=True)
            if nat.source_translation is None and not problems:
                problems.append("dynamic NAT without a translated address")
        elif kind != "static" or cursor.done:
            problems.append(f"NAT line '{' '.join(words)[:60]}'")
            return self._finish_nat(nat, ignored)
        mapped = ""
        if kind == "static":
            word = cursor.take()
            if word == "interface":
                mapped = "interface"
                if cursor.peek() == "ipv6":
                    cursor.take()
                    problems.append("static NAT to the IPv6 address of the interface")
            elif word in self.net_objects or word in self.net_groups:
                mapped = self._nat_ref(word, problems)
            else:
                mapped = self._same_size(neutral, self._ip(word), problems)
        port: Optional[Tuple[Protocol, str, str]] = None
        while not cursor.done:
            word = cursor.take()
            if word == "service" and kind == "static" and port is None:
                protocol, real_port, mapped_port = cursor.take(), _port(cursor.take()), _port(cursor.take())
                if protocol not in _PORT_PROTOCOLS or real_port is None or mapped_port is None:
                    problems.append(f"'{' '.join(words)[:60]}': a service that could not be read")
                else:
                    port = (Protocol(protocol), str(real_port), str(mapped_port))
            elif word in ("dns", "net-to-net"):
                ignored.append(word)
            elif word not in ("no-proxy-arp", "route-lookup"):
                problems.append(f"'{' '.join([word] + cursor.rest())[:40]}' in a NAT rule")
        if kind != "static":
            return self._finish_nat(nat, ignored)
        if port is not None:
            # A published port: connections come in on the mapped interface, for the mapped address.
            published = self._interface_address(nat, mapped_if) if mapped == "interface" else mapped
            nat.sources = [ANY]
            nat.destinations = [published]
            nat.service = self._inline_service([ServiceEntry(port[0], dst_ports=port[2])])
            nat.destination_translation = DestNat(neutral, "" if port[1] == port[2] else port[1])
            nat.src_zones = [mapped_zone]
            nat.dst_zones = [mapped_zone if mapped_zone != ANY else self._route_zone(published)]
        elif mapped == "interface":
            problems.append("static NAT to the interface address without a service")
        else:
            nat.source_translation = SourceNat(SnatKind.STATIC, [mapped], bidirectional=True)
        return self._finish_nat(nat, ignored)

    def _same_size(self, real: str, address: str, problems: List[str]) -> str:
        """The mapped addresses of ``static <address>``: as many as the object has, starting there."""
        start = parse_literal(address)
        intervals = transform.address_intervals(self.p, real)
        if start is None or start[1] != start[2] or "/" in address or "-" in address or not intervals or len(intervals) != 1:
            problems.append(f"translated address '{address[:40]}'")
            return address if start is not None else ANY
        count = size(intervals[0])
        if count == 1:
            return address
        if start[1] + count - 1 > (2**32 - 1 if start[0] == 4 else 2**128 - 1):
            problems.append(f"translated address '{address[:40]}'")
            return address
        mapped = (start[0], start[1], start[1] + count - 1)
        value = self.p.addresses[real].value if real in self.p.addresses else ""
        bits = 32 if start[0] == 4 else 128
        if "/" in value and count & (count - 1) == 0 and start[1] % count == 0:
            return f"{address}/{bits - count.bit_length() + 1}"
        return range_text(mapped)

    # -- what else to tell ------------------------------------------------

    def _passes_icmp(self, rule: Rule) -> bool:
        if ANY in rule.services:
            return True
        entries = [entry for name in rule.services for entry in transform.flatten_services(self.p, name) or []]
        return any(e.protocol in (Protocol.ICMP, Protocol.ICMP6) or (e.protocol == Protocol.IP and not e.ip_protocol) for e in entries)

    def _notes(self) -> None:
        if self.p.rules and not self.complete:
            self.report.note(
                Severity.REVIEW,
                "NO_INTERFACES",
                "the input does not show the interfaces of the ASA (fewer than two 'nameif' lines). An ASA does not "
                "send traffic back out of the interface it came in on, nor between interfaces of the same security "
                "level, unless 'same-security-traffic' permits it; the rules were read without that limit",
            )
        if self.egress_by_route:
            self.report.note(
                Severity.INFO,
                "EGRESS_BY_ROUTE",
                "an ASA access list names no outgoing interface. For permit entries with destination addresses the "
                "destination zone was taken from the interface addresses and static routes in the configuration",
            )
        if self.without_effect:
            self.report.note(
                Severity.INFO,
                "RULE_WITHOUT_EFFECT",
                f"{self.without_effect} permit entries can match no traffic the ASA forwards (same interface or same "
                "security level, without 'same-security-traffic') and were left out",
            )
        if self.bridged:
            self.report.note(
                Severity.REVIEW,
                "BRIDGE_GROUPS",
                "the configuration has bridge groups. Their member interfaces are read as zones of their own: that "
                "the members of a group share one network is not modelled, and no destination zone was worked "
                "out from routes. Check the rules between such interfaces",
            )
        allows_icmp = any(rule.enabled and rule.action == Action.ALLOW and self._passes_icmp(rule) for rule in self.p.rules)
        inspected = any(
            child.words == ["inspect", "icmp"] for entry in self._top("policy-map") for child in entry.children
        )
        if allows_icmp and not inspected and not self.ftd:
            self.report.note(
                Severity.APPROX,
                "ICMP_STATELESS",
                "the ASA does not inspect ICMP ('inspect icmp' is not in a policy map): the reply to a permitted "
                "ICMP request got through only where an access list permitted the reply too. Every target lets "
                "the replies to a permitted request through by itself",
            )
        if self.ftd:
            self.report.note(
                Severity.REVIEW,
                "FTD_CONFIGURATION",
                "this is the configuration of a Firepower Threat Defense device. It shows the access rules as far "
                "as addresses, ports and interfaces go. Rules with application, URL or user conditions are in it "
                "without those conditions and are converted disabled; intrusion and file policies are not in it",
            )
        vpn = any(e.words[:2] == ["crypto", "map"] or e.words[0] in ("tunnel-group", "webvpn") for e in self.entries)
        bypass_off = any(e.words[:4] == ["no", "sysopt", "connection", "permit-vpn"] for e in self.entries)
        if vpn and not bypass_off and not self.ftd and self.p.rules:
            self.report.note(
                Severity.APPROX,
                "VPN_BYPASS",
                "the ASA lets traffic that arrives through its VPN tunnels past the interface access lists "
                "('sysopt connection permit-vpn' is on by default). The converted rules do not allow that "
                "traffic; add rules for it on the target",
            )

