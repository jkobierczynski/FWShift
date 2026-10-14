# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco IOS and IOS XE parser: ``show running-config`` of a router -> neutral model.

What is read: interfaces (addresses, ``ip access-group``, ``ipv6 traffic-filter``, ``zone-member security``,
``ip nat inside``/``outside``), access lists (numbered and named, standard and extended, IPv6), object groups, the
zone-based policy firewall (zones, zone pairs, inspect policy maps and class maps) and NAT (``ip nat inside source``).

How IOS decides forwarded traffic, and how that is mapped onto the neutral model:

* A packet that arrives on interface A and leaves by interface B passes the list bound ``in`` to A (as it arrives,
  before NAT), then NAT, then the list bound ``out`` to B (after NAT), then the zone-based firewall for the zones of A
  and B. An interface without a list, or with one that is not defined or holds no entries, passes everything; a list
  with entries ends in an implicit deny.
* Zone-based firewall: interfaces of different zones pass what the inspect policy of their zone pair lets through
  (its classes in order, then ``class-default``, which drops); without a zone pair nothing passes. Inside a zone
  everything passes unless a zone pair from the zone to itself says otherwise; between an interface in a zone and one
  in none nothing passes; between two interfaces in no zone everything does. Traffic to and from the router itself
  (the ``self`` zone) is not policy here.
* The zones of the model are the interfaces, or a zone of the zone-based firewall when all its interfaces have the
  same lists. The model is one first-match list: for each zone the entries of its inbound list, and where an outbound
  list or the zone-based firewall decides as well, the three lists composed for each pair of zones.
* The model's rules name addresses as they arrive. An outbound list sees them after NAT, and the zone-based firewall
  is read as seeing the inside addresses: their entries are rewritten through the static translations and, for
  sources, dynamic port translation; what that cannot say exactly is not converted.
* Access lists are stateless; the model is stateful. A connection the converted policy allows is one whose first
  packet the lists pass; the replies are allowed with it. An entry that matches only replies (``established``,
  ``evaluate``) is left out.
* What is not understood in full makes its entry not converted, never wider: nothing is read as any address or port.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    Action,
    AddressGroup,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, intersect, normalize, parse_literal, subtract
from ..report import Report, Severity

Box = regions.Box

_MAX_LINES = 2_000_000
_MAX_PIECES = 256  # intervals a non-contiguous wildcard mask may stand for
_MAX_COMPOSED = 5000  # rules for one pair of zones
_MAX_RULES = 100_000  # rules of the whole policy, before the pairs of zones left are blocked
_MAX_NESTING = 32

# Port names as IOS XE accepts them (Cisco-IOS-XE-types, 17.15): one table per protocol, as the same number has
# different names (TCP 514 cmd, UDP 514 syslog).
TCP_PORTS = {
    "bgp": 179, "chargen": 19, "cmd": 514, "daytime": 13, "discard": 9, "domain": 53, "drip": 3949, "echo": 7, "exec": 512,
    "finger": 79, "ftp": 21, "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113, "irc": 194, "klogin": 543,
    "kshell": 544, "login": 513, "lpd": 515, "msrpc": 135, "nntp": 119, "onep-plain": 15001, "onep-tls": 15002,
    "pim-auto-rp": 496, "pop2": 109, "pop3": 110, "smtp": 25, "sunrpc": 111, "tacacs": 49, "tacacs-ds": 49, "talk": 517,
    "telnet": 23, "time": 37, "uucp": 540, "whois": 43, "www": 80,
}  # fmt: skip
UDP_PORTS = {
    "biff": 512, "bootpc": 68, "bootps": 67, "discard": 9, "dnsix": 195, "domain": 53, "echo": 7, "isakmp": 500,
    "mobile-ip": 434, "nameserver": 42, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ss": 139, "non500-isakmp": 4500,
    "ntp": 123, "pim-auto-rp": 496, "rip": 520, "ripv6": 521, "snmp": 161, "snmptrap": 162, "sunrpc": 111, "syslog": 514,
    "tacacs": 49, "tacacs-ds": 49, "talk": 517, "tftp": 69, "time": 37, "who": 513, "xdmcp": 177,
}  # fmt: skip
# ICMP message names: (type, code); code None for every code of the type.
ICMP4 = {
    "echo-reply": (0, None), "unreachable": (3, None), "net-unreachable": (3, 0), "host-unreachable": (3, 1),
    "protocol-unreachable": (3, 2), "port-unreachable": (3, 3), "packet-too-big": (3, 4), "source-route-failed": (3, 5),
    "network-unknown": (3, 6), "host-unknown": (3, 7), "host-isolated": (3, 8), "dod-net-prohibited": (3, 9),
    "dod-host-prohibited": (3, 10), "net-tos-unreachable": (3, 11), "host-tos-unreachable": (3, 12),
    "administratively-prohibited": (3, 13), "host-precedence-unreachable": (3, 14), "precedence-unreachable": (3, 15),
    "source-quench": (4, None), "redirect": (5, None), "net-redirect": (5, 0), "host-redirect": (5, 1),
    "net-tos-redirect": (5, 2), "host-tos-redirect": (5, 3), "alternate-address": (6, None), "echo": (8, None),
    "router-advertisement": (9, None), "router-solicitation": (10, None), "time-exceeded": (11, None),
    "ttl-exceeded": (11, 0), "reassembly-timeout": (11, 1), "parameter-problem": (12, None),
    "general-parameter-problem": (12, 0), "option-missing": (12, 1), "no-room-for-option": (12, 2),
    "timestamp-request": (13, None), "timestamp-reply": (14, None), "information-request": (15, None),
    "information-reply": (16, None), "mask-request": (17, None), "mask-reply": (18, None), "traceroute": (30, None),
    "conversion-error": (31, None), "mobile-redirect": (32, None),
}  # fmt: skip
ICMP6 = {
    "unreachable": (1, None), "destination-unreachable": (1, None), "no-route": (1, 0), "no-admin": (1, 1),
    "beyond-scope": (1, 2), "port-unreachable": (1, 4), "source-policy": (1, 5), "reject-route": (1, 6),
    "packet-too-big": (2, None), "time-exceeded": (3, None), "hop-limit": (3, 0), "reassembly-timeout": (3, 1),
    "parameter-problem": (4, None), "header": (4, 0), "next-header": (4, 1), "parameter-option": (4, 2),
    "echo-request": (128, None), "echo-reply": (129, None), "mld-query": (130, None), "mld-report": (131, None),
    "mld-reduction": (132, None), "router-solicitation": (133, None), "router-advertisement": (134, None),
    "nd-ns": (135, None), "nd-na": (136, None), "redirect": (137, None), "router-renumbering": (138, None),
    "dhaad-request": (144, None), "dhaad-reply": (145, None), "mpd-solicitation": (146, None),
    "mpd-advertisement": (147, None),
}  # fmt: skip
PROTOCOLS4 = {"ip": -1, "icmp": 1, "igmp": 2, "ipinip": 4, "tcp": 6, "igrp": 9, "udp": 17, "gre": 47, "esp": 50, "ahp": 51,
              "eigrp": 88, "ospf": 89, "nos": 94, "pim": 103, "pcp": 108}  # fmt: skip
PROTOCOLS6 = {"ipv6": -1, "icmp": 58, "tcp": 6, "udp": 17, "sctp": 132, "esp": 50, "ahp": 51, "pcp": 108}
# The system table of Port-to-Application Mapping for ``match protocol`` (Cisco's PAM documentation), with the common
# names of later releases: (protocol, ports). A name not here is not converted.
PAM: Dict[str, List[Tuple[str, str]]] = {
    "http": [("tcp", "80")], "https": [("tcp", "443")], "ftp": [("tcp", "21")], "ssh": [("tcp", "22")],
    "telnet": [("tcp", "23")], "smtp": [("tcp", "25")], "dns": [("tcp", "53"), ("udp", "53")], "pop3": [("tcp", "110")],
    "imap": [("tcp", "143")], "imap3": [("tcp", "220")], "pop3s": [("tcp", "995")], "imaps": [("tcp", "993")],
    "ntp": [("udp", "123")], "snmp": [("udp", "161")], "tftp": [("udp", "69")], "sip": [("tcp", "5060"), ("udp", "5060")],
    "h323": [("tcp", "1720")], "sqlnet": [("tcp", "1521")], "ldap": [("tcp", "389")], "ldaps": [("tcp", "636")],
    "bgp": [("tcp", "179")], "msrpc": [("tcp", "135")], "sunrpc": [("tcp", "111"), ("udp", "111")],
    "exec": [("tcp", "512")], "login": [("tcp", "513")], "shell": [("tcp", "514")], "rtsp": [("tcp", "554")],
    "netshow": [("tcp", "1755")], "mgcp": [("udp", "2427")], "syslog": [("udp", "514")], "isakmp": [("udp", "500")],
    "nntp": [("tcp", "119")], "finger": [("tcp", "79")], "kerberos": [("tcp", "88"), ("udp", "88")],
    "radius": [("udp", "1812"), ("udp", "1813")], "tacacs": [("tcp", "49")], "microsoft-ds": [("tcp", "445")],
    "netbios-ns": [("udp", "137")], "netbios-dgm": [("udp", "138")], "netbios-ssn": [("tcp", "139")],
    "tcp": [("tcp", "")], "udp": [("udp", "")], "icmp": [("icmp", "")],
}  # fmt: skip
_QUALIFIERS = ("dscp", "precedence", "tos", "ttl", "option", "fragments", "match-any", "match-all", "ack", "fin", "psh",
               "rst", "syn", "urg", "hbh", "flow-label", "routing", "routing-type", "dest-option", "mobility", "auth",
               "undetermined-transport", "packet-length")  # fmt: skip


def looks_like_ios(text: str) -> bool:
    """A configuration of IOS or IOS XE: lines only they write, and none only an ASA writes."""
    found = False
    for line in text.splitlines()[:20000]:
        if line.startswith(("ASA Version ", "PIX Version ", "NGFW Version ", "access-group ")) or line.strip().startswith("nameif "):
            return False
        if line.startswith(("ip access-list standard ", "ip access-list extended ", "ipv6 access-list ", "zone security ",
                            "zone-pair security ", "ip nat inside source ", "class-map type inspect ",
                            "policy-map type inspect ")):  # fmt: skip
            found = True
        elif line.startswith(" ip access-group ") or line.startswith(" ipv6 traffic-filter ") or line.startswith(" zone-member security "):
            found = True
        elif re.match(r"access-list \d+ (permit|deny|dynamic) ", line):
            found = True
        elif re.match(r"version 1[2-7]\.\d+\s*$", line):
            found = True
    return found


@dataclass
class _Line:
    number: int
    words: List[str]
    children: List["_Line"] = field(default_factory=list)


def read_lines(text: str) -> List[_Line]:
    """Top-level lines with the lines indented below them, at any depth; comments (``!``) left out."""
    out: List[_Line] = []
    stack: List[Tuple[int, _Line]] = []
    banner = ""  # the delimiter of a banner being skipped
    for number, line in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a router")
        if banner:
            if banner in line:
                banner = ""
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        words = stripped.split()
        if words[0] == "banner" and len(words) >= 3 and not line[0].isspace():
            text_part = stripped.split(None, 2)[2]
            delimiter = "^C" if text_part.startswith("^C") else text_part[0]
            if delimiter not in text_part[len(delimiter):]:
                banner = delimiter  # (the banner goes on until the delimiter comes again)
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        entry = _Line(number, stripped.split())
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            stack[-1][1].children.append(entry)
        else:
            out.append(entry)
        stack.append((indent, entry))
    return out


def wildcard_intervals(address: str, wildcard: str) -> Optional[List[Interval]]:
    """The addresses an address and a wildcard mask match (bits set in the mask are ignored); None when the mask
    cannot be read or stands for more than ``_MAX_PIECES`` intervals."""
    try:
        base, wild = int(ipaddress.IPv4Address(address)), int(ipaddress.IPv4Address(wildcard))
    except ValueError:
        return None
    trailing = 0
    while trailing < 32 and wild >> trailing & 1:
        trailing += 1
    high = [bit for bit in range(trailing, 32) if wild >> bit & 1]
    if len(high) > 8:
        return None
    base &= ~wild & 0xFFFFFFFF
    low = (1 << trailing) - 1
    out = []
    for combo in range(1 << len(high)):
        value = base
        for index, bit in enumerate(high):
            if combo >> index & 1:
                value |= 1 << bit
        out.append((4, value, value | low))
    return normalize(out)


def _port_map(words: List[str]) -> Optional[Tuple[str, Tuple[str, str]]]:
    """``ip port-map APP port [tcp|udp] (N | from A to B) [description TEXT]``: (application, (protocol, ports))."""
    app, rest = words[2], words[3:]
    if not rest or rest[0] != "port":
        return None
    rest = rest[1:]
    protocol = "tcp"
    if rest and rest[0] in ("tcp", "udp"):
        protocol, rest = rest[0], rest[1:]
    if "description" in rest:
        rest = rest[: rest.index("description")]
    numbers = [w for w in rest if w.isascii() and w.isdigit()]
    if any(int(n) > 65535 for n in numbers):
        return None
    if len(rest) == 1 and len(numbers) == 1:
        return app, (protocol, numbers[0])
    if len(rest) == 4 and rest[0] == "from" and rest[2] == "to" and len(numbers) == 2 and int(numbers[0]) <= int(numbers[1]):
        return app, (protocol, f"{numbers[0]}-{numbers[1]}")
    return None  # (a list of hosts, or a form not read)


def _ports_text(ranges: Sequence[Tuple[int, int]]) -> str:
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in regions.merge_ranges(ranges))


@dataclass
class _Ace:
    """One entry of an access list."""

    acl: str
    seq: int
    line: int
    action: str  # permit, deny
    version: int
    src: Optional[List[Interval]] = None
    dst: Optional[List[Interval]] = None
    entries: List[ServiceEntry] = field(default_factory=list)  # empty: every protocol
    service_name: str = ANY  # the model service that stands for ``entries``
    problems: List[str] = field(default_factory=list)
    log: bool = False
    remark: str = ""
    skip: str = ""  # the entry matches no packet that opens a connection: left out, with this reason
    reflect: bool = False

    def boxes(self) -> Optional[List[Box]]:
        if self.problems or self.src is None or self.dst is None:
            return None
        services = regions.service_set(self.entries) if self.entries else regions.ALL_SERVICES
        if services is None:
            return None
        return [(self.version, self.src, self.dst, services)] if self.src and self.dst else []


@dataclass
class _Acl:
    name: str
    kind: str  # standard, extended, ipv6
    aces: List[_Ace] = field(default_factory=list)
    line: int = 0


@dataclass
class _Interface:
    name: str
    line: int
    addresses: List[Interval] = field(default_factory=list)  # the interface's own addresses
    networks: List[Interval] = field(default_factory=list)
    acls: Dict[Tuple[str, int], str] = field(default_factory=dict)  # (in|out, IP version) -> list
    zone: str = ""
    nat: str = ""  # inside, outside
    shutdown: bool = False
    dhcp: bool = False
    vrf: str = ""
    inspect: List[str] = field(default_factory=list)


@dataclass
class _Item:
    """One entry of an evaluation list."""

    name: str
    action: str  # allow, deny
    boxes: Optional[List[Box]]
    service_names: List[str]
    problems: List[str] = field(default_factory=list)
    log: bool = False
    description: str = ""
    ids: Dict[str, str] = field(default_factory=dict)
    findings: List[Tuple[str, str]] = field(default_factory=list)  # (code, message) for the rules made of it
    drop: bool = False  # the zone-based firewall drops silently
    named: Optional[regions.Services] = None  # the services ``service_names`` stand for
    sides: Optional[Tuple[List[str], List[str]]] = None  # what is known of the two sides, when the boxes are not


def _same(a: regions.Services, b: regions.Services) -> bool:
    return a.minus(b).empty() and b.minus(a).empty()


def _everything(name: str, action: str, description: str = "", versions: Sequence[int] = (4, 6)) -> _Item:
    boxes: List[Box] = [(v, [regions.full(v)], [regions.full(v)], regions.ALL_SERVICES) for v in versions]
    return _Item(name, action, boxes, [ANY], description=description, named=regions.ALL_SERVICES)


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    lines = read_lines(text)
    try:
        return _Builder(lines, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None


class _Builder:
    def __init__(self, lines: List[_Line], report: Report) -> None:
        self.lines, self.report = lines, report
        self.p = Policy(vendor="ios")
        self.acls: Dict[str, _Acl] = {}
        self.interfaces: Dict[str, _Interface] = {}
        self.net_groups: Dict[str, Tuple[List[Interval], List[str], List[str], int]] = {}  # name -> (own, nested, problems, version)
        self.svc_groups: Dict[str, Tuple[List[ServiceEntry], List[str], List[str]]] = {}  # name -> (own, nested, problems)
        self.zones: Dict[str, str] = {}  # zone -> description
        self.zone_pairs: Dict[Tuple[str, str], Tuple[str, str]] = {}  # (source, destination) -> (pair name, policy map)
        self.policy_maps: Dict[str, List[Tuple[str, str, bool]]] = {}  # name -> [(class, action, log)]
        self.class_maps: Dict[str, Tuple[bool, List[List[str]]]] = {}  # name -> (match-all, criteria)
        self.port_map: Dict[str, List[Tuple[str, str]]] = {k: list(v) for k, v in PAM.items()}
        self.port_map_problems: Dict[str, str] = {}
        self.pools: Optional[Dict[str, Optional[Interval]]] = None
        self.taken: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.services: Dict[str, str] = {}  # key of entries -> model service
        self.named: Dict[Tuple[Interval, ...], str] = {}
        self.notes: Dict[str, List[str]] = {}
        self.units: Dict[str, List[str]] = {}  # model zone -> interfaces
        self.unit_of: Dict[str, str] = {}  # interface -> model zone
        self.statics: List[Tuple[List[Interval], List[Interval]]] = []  # (inside local, inside global), address for address
        self.port_statics: List[Tuple[str, Interval, int, Interval, int]] = []  # (protocol, local, port, global, port)
        self.dynamic: List[Tuple[List[Interval], List[Interval], str]] = []  # (sources, translated addresses, name)
        self.nat_unread: List[str] = []  # NAT that is not read: it may translate what the lists after it see
        self.nat_names: Set[str] = set()
        self.used_acls: Set[str] = set()
        self.zbfw = False
        self.layer7: Set[Tuple[str, str]] = set()  # (policy map, class) with a layer-7 policy under it

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def _unique(self, name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _top(self, *first: str) -> List[_Line]:
        return [line for line in self.lines if tuple(line.words[: len(first)]) == first]

    # -- reading ---------------------------------------------------------------------------

    def build(self) -> Policy:
        self._object_groups()
        self._access_lists()
        self._interfaces()
        self._zbfw()
        if not self.interfaces and not self.acls:
            raise ParseError("no interfaces and no access lists: not the running configuration of an IOS or IOS XE router")
        self._units()
        self._nat()
        self._rules()
        self._notes()
        return self.p

    def _address4(self, words: List[str], index: int, problems: List[str], standard: bool = False) -> Tuple[Optional[List[Interval]], int, str]:
        """An address of an IPv4 entry at ``words[index]``: (intervals, next index, object group or "")."""
        word = words[index] if index < len(words) else ""
        if word == "any":
            return [FULL_V4], index + 1, ""
        if word == "host" and index + 1 < len(words):
            found = parse_literal(words[index + 1])
            if found is None or found[0] != 4 or found[1] != found[2]:
                problems.append(f"host '{words[index + 1][:40]}' is not an IPv4 address")
                return None, index + 2, ""
            return [found], index + 2, ""
        if word == "object-group" and index + 1 < len(words):
            name = words[index + 1]
            return self._network_group(name, problems, 4), index + 2, name
        found = parse_literal(word) if word and "/" not in word and "-" not in word else None
        if found is None or found[0] != 4:
            problems.append(f"address '{word[:40]}' cannot be read")
            return None, index + 1, ""
        if standard and (index + 1 >= len(words) or parse_literal(words[index + 1]) is None):
            return [found], index + 1, ""  # (a standard entry without a mask: one address)
        if index + 1 >= len(words):
            problems.append(f"address '{word[:40]}' without a wildcard mask")
            return None, index + 1, ""
        pieces = wildcard_intervals(word, words[index + 1])
        if pieces is None:
            problems.append(f"wildcard mask '{words[index + 1][:20]}' cannot be read, or stands for too many ranges")
            return None, index + 2, ""
        return pieces, index + 2, ""

    def _address6(self, words: List[str], index: int, problems: List[str]) -> Tuple[Optional[List[Interval]], int, str]:
        word = words[index] if index < len(words) else ""
        if word == "any":
            return [FULL_V6], index + 1, ""
        if word == "host" and index + 1 < len(words):
            found = parse_literal(words[index + 1])
            if found is None or found[0] != 6 or found[1] != found[2]:
                problems.append(f"host '{words[index + 1][:40]}' is not an IPv6 address")
                return None, index + 2, ""
            return [found], index + 2, ""
        if word == "object-group" and index + 1 < len(words):
            name = words[index + 1]
            return self._network_group(name, problems, 6), index + 2, name
        found = parse_literal(word) if "/" in word else None
        if found is None or found[0] != 6:
            problems.append(f"address '{word[:40]}' cannot be read")
            return None, index + 1, ""
        return [found], index + 1, ""

    @staticmethod
    def _port(word: str, protocol: str) -> Optional[int]:
        if word.isascii() and word.isdigit():
            number = int(word)
            return number if number <= 65535 else None
        table = TCP_PORTS if protocol == "tcp" else UDP_PORTS if protocol == "udp" else {}
        return table.get(word)

    def _port_spec(self, words: List[str], index: int, protocol: str, problems: List[str]) -> Tuple[str, int]:
        """A port operator at ``words[index]``, if there is one: (ports as the model writes them, next index)."""
        word = words[index] if index < len(words) else ""
        if word not in ("eq", "neq", "lt", "gt", "range"):
            return "", index
        if protocol not in ("tcp", "udp", "sctp"):
            problems.append(f"ports with protocol {protocol}")
            return "", index + 1
        index += 1
        if word == "range":
            first = self._port(words[index], protocol) if index < len(words) else None
            last = self._port(words[index + 1], protocol) if index + 1 < len(words) else None
            if first is None or last is None or first > last:
                problems.append("a port range that cannot be read")
                return "", index + 2
            return _ports_text([(first, last)]), index + 2
        found: List[int] = []
        while index < len(words):
            number = self._port(words[index], protocol)
            if number is None:
                break
            found.append(number)
            index += 1
            if word in ("lt", "gt"):
                break
        if not found:
            problems.append(f"port '{(words[index] if index < len(words) else '')[:20]}' cannot be read")
            return "", index + 1
        if word == "eq":
            return _ports_text([(n, n) for n in found]), index
        if word == "lt":
            return (_ports_text([(0, found[0] - 1)]) if found[0] > 0 else "!none"), index
        if word == "gt":
            return (_ports_text([(found[0] + 1, 65535)]) if found[0] < 65535 else "!none"), index
        keep: List[Tuple[int, int]] = []
        start = 0
        for number in sorted(set(found)):
            if number > start:
                keep.append((start, number - 1))
            start = number + 1
        if start <= 65535:
            keep.append((start, 65535))
        return (_ports_text(keep) if keep else "!none"), index

    def _service_name(self, entries: List[ServiceEntry], label: str = "") -> str:
        if not entries:
            return ANY
        key = json.dumps([[e.protocol.value, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code, e.ip_protocol] for e in entries])
        if key in self.services:
            return self.services[key]
        if not label:
            parts = []
            for entry in entries[:3]:
                text = entry.protocol.value if entry.protocol != Protocol.IP else f"ip-{entry.ip_protocol}"
                if entry.dst_ports:
                    text += "-" + entry.dst_ports.replace(",", "_")
                if entry.src_ports:
                    text += "-from-" + entry.src_ports.replace(",", "_")
                if entry.icmp_type is not None:
                    text += f"-{entry.icmp_type}" + ("" if entry.icmp_code is None else f"-{entry.icmp_code}")
                parts.append(text)
            label = "_".join(parts)[:60] + ("_more" if len(entries) > 3 else "")
        name = self._unique(label, self.taken_services)
        self.p.services[name] = Service(name, list(entries))
        self.services[key] = name
        return name

    def _ace(self, acl: str, kind: str, seq: int, line: int, words: List[str], remark: str) -> _Ace:
        problems: List[str] = []
        if words and words[0] == "dynamic":
            problems.append("a dynamic (lock-and-key) entry")
            index = 2
            if index < len(words) and words[index] == "timeout":
                index += 2
            words = words[index:]
        action = words[0] if words else ""
        ace = _Ace(acl, seq, line, action, 6 if kind == "ipv6" else 4, remark=remark)
        if action not in ("permit", "deny"):
            ace.problems.append(f"'{action[:20]}' is not permit or deny")
            return ace
        if kind == "standard":
            ace.src, index, group = self._address4(words, 1, problems, standard=True)
            ace.dst = [FULL_V4]
            self._qualifiers(ace, words, index, "ip", problems)
            ace.problems += problems
            return ace
        protocol = words[1] if len(words) > 1 else ""
        index = 2
        table = PROTOCOLS6 if kind == "ipv6" else PROTOCOLS4
        group_service = ""
        number: Optional[int] = None
        if protocol == "object-group" and len(words) > 2:
            group_service = words[2]
            index = 3
        elif protocol in table:
            number = table[protocol]
        elif protocol.isascii() and protocol.isdigit() and int(protocol) <= 255:
            number = int(protocol)
            protocol = {6: "tcp", 17: "udp", 132: "sctp"}.get(number, protocol)
            if number == 0:
                problems.append("protocol 0, which IOS may read as every protocol")
        else:
            problems.append(f"protocol '{protocol[:20]}' cannot be read")
            ace.problems += problems
            return ace
        address = self._address6 if kind == "ipv6" else self._address4
        ace.src, index, _ = address(words, index, problems)
        src_ports, index = self._port_spec(words, index, protocol, problems)
        ace.dst, index, _ = address(words, index, problems)
        dst_ports, index = self._port_spec(words, index, protocol, problems)
        if "!none" in (src_ports, dst_ports):
            ace.skip = "a port operator that matches no port"
        icmp: Optional[Tuple[int, Optional[int]]] = None
        names = ICMP6 if kind == "ipv6" else ICMP4
        if protocol == "icmp" and index < len(words):
            if words[index] in names:
                icmp = names[words[index]]
                index += 1
            elif words[index].isascii() and words[index].isdigit():
                kind_number = int(words[index])
                code: Optional[int] = None
                index += 1
                if index < len(words) and words[index].isascii() and words[index].isdigit():
                    code = int(words[index])
                    index += 1
                if kind_number > 255 or (code is not None and code > 255):
                    problems.append("an ICMP type or code above 255")
                icmp = (kind_number, code)
        if group_service:
            entries = self._service_group(group_service, problems)
            ace.entries = entries
            ace.service_name = group_service if group_service in self.p.services else self._service_name(entries)
        elif number == -1:
            ace.entries = []
        elif number in (6, 17, 132):
            kind_of = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[number]
            ace.entries = [ServiceEntry(kind_of, dst_ports=dst_ports if dst_ports != "!none" else "", src_ports=src_ports if src_ports != "!none" else "")]
        elif number in (1, 58):
            ace.entries = [ServiceEntry(Protocol.ICMP if number == 1 else Protocol.ICMP6, icmp_type=icmp[0] if icmp else None,
                                        icmp_code=icmp[1] if icmp else None)]  # fmt: skip
        elif number is not None:
            ace.entries = [ServiceEntry(Protocol.IP, ip_protocol=number)]
        if not group_service and ace.entries:
            ace.service_name = self._service_name(ace.entries)
        self._qualifiers(ace, words, index, protocol, problems)
        ace.problems += problems
        return ace

    def _qualifiers(self, ace: _Ace, words: List[str], index: int, protocol: str, problems: List[str]) -> None:
        while index < len(words):
            word = words[index]
            index += 1
            if word in ("log", "log-input"):
                ace.log = True
                if index < len(words) and words[index].startswith("("):
                    while index < len(words) and not words[index - 1].endswith(")"):
                        index += 1  # (log (tag = name))
                elif index < len(words) and words[index] not in _QUALIFIERS and words[index] not in ("sequence", "time-range"):
                    index += 1  # (a cookie)
            elif word == "established" and protocol == "tcp":
                if ace.action == "permit":
                    ace.skip = "established: it matches replies only"
                else:
                    problems.append("deny established: it blocks replies, which the model cannot say")
            elif word == "time-range" and index < len(words):
                problems.append(f"time-range {words[index][:40]}: active only part of the time")
                index += 1
            elif word == "reflect" and index < len(words):
                ace.reflect = True
                index += 1
                if index < len(words) and words[index] == "timeout":
                    index += 2
            elif word == "sequence" and index < len(words) and ace.version == 6:
                if words[index].isascii() and words[index].isdigit():
                    ace.seq = int(words[index])
                index += 1
            elif word in _QUALIFIERS:
                problems.append(f"'{word}' is not converted")
                while index < len(words) and words[index] not in _QUALIFIERS and words[index] not in ("log", "log-input", "time-range", "sequence"):
                    index += 1
            else:
                problems.append(f"'{word[:30]}' cannot be read")

    # -- object groups ----------------------------------------------------------------------

    def _object_groups(self) -> None:
        for line in self.lines:
            if len(line.words) < 3 or line.words[0] != "object-group":
                continue
            kind, name = line.words[1], line.words[2]
            if kind in ("network", "v6-network"):
                own: List[Interval] = []
                nested: List[str] = []
                problems: List[str] = []
                version = 6 if kind == "v6-network" else 4
                for child in line.children:
                    words = child.words
                    if words[0] == "description":
                        continue
                    if words[0] == "group-object" and len(words) == 2:
                        nested.append(words[1])
                    elif words[0] == "host" and len(words) == 2:
                        found = parse_literal(words[1])
                        if found is None or found[1] != found[2]:
                            problems.append(f"host '{words[1][:40]}' is not an address (a host name is not resolved)")
                        else:
                            own.append(found)
                    elif words[0] == "range" and len(words) == 3:
                        found = parse_literal(f"{words[1]}-{words[2]}")
                        if found is None:
                            problems.append(f"range {words[1][:40]} {words[2][:40]} cannot be read")
                        else:
                            own.append(found)
                    elif words[0] == "any" and len(words) == 1:
                        own.append(regions.full(version))
                    elif len(words) == 2 and words[1].startswith("/"):
                        found = parse_literal(words[0] + words[1])
                        if found is None:
                            problems.append(f"'{' '.join(words)[:60]}' cannot be read")
                        else:
                            own.append(found)
                    elif len(words) == 2:
                        found = parse_literal(f"{words[0]}/{words[1]}")  # (a subnet mask here, not a wildcard)
                        if found is None:
                            problems.append(f"'{' '.join(words)[:60]}' cannot be read (a network and a subnet mask)")
                        else:
                            own.append(found)
                    elif len(words) == 1 and "/" in words[0]:
                        found = parse_literal(words[0])
                        if found is None:
                            problems.append(f"'{words[0][:60]}' cannot be read")
                        else:
                            own.append(found)
                    else:
                        problems.append(f"'{' '.join(words)[:60]}' cannot be read")
                self.net_groups[name] = (own, nested, problems, version)
            elif kind in ("service", "v6-service"):
                entries: List[ServiceEntry] = []
                nested = []
                problems = []
                for child in line.children:
                    words = child.words
                    if words[0] == "description":
                        continue
                    if words[0] == "group-object" and len(words) == 2:
                        nested.append(words[1])
                        continue
                    entries += self._service_line(words, problems)
                self.svc_groups[name] = (entries, nested, problems)
        for name in self.net_groups:
            problems = []
            resolved = self._network_group(name, problems, 0)
            members = [interval_text(i) for i in resolved] if resolved is not None else []
            group = AddressGroup(name, members, unsupported="; ".join(problems)[:200] if problems else "")
            self.p.address_groups[name] = group
            if resolved:
                self.named.setdefault(tuple(resolved), name)
            self.taken.add(name.lower())
        for name in self.svc_groups:
            problems = []
            entries = self._service_group(name, problems)
            if problems:
                continue
            key = json.dumps([[e.protocol.value, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code, e.ip_protocol] for e in entries])
            if entries and key not in self.services:
                service_name = self._unique(name, self.taken_services)
                self.p.services[service_name] = Service(service_name, entries)
                self.services[key] = service_name

    def _service_line(self, words: List[str], problems: List[str]) -> List[ServiceEntry]:
        """A line of an object group of services: ``tcp eq www``, ``tcp-udp range 1 2``, ``tcp source eq 1 eq 2``,
        ``icmp echo``, ``esp``, ``47``."""
        protocol = words[0]
        rest = words[1:]
        if protocol in ("tcp", "udp", "tcp-udp", "sctp"):
            source = ""
            if rest and rest[0] == "source":
                rest = rest[1:]
                source, used = self._port_spec(rest, 0, "tcp" if protocol != "udp" else "udp", problems)
                rest = rest[used:]
            if rest and rest[0] not in ("eq", "neq", "lt", "gt", "range"):
                rest = ["eq"] + rest  # (no operator: equal)
            check = "udp" if protocol == "udp" else "tcp"
            ports, used = self._port_spec(rest, 0, check, problems) if rest else ("", 0)
            if used < len(rest):
                problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            if "!none" in (ports, source):
                return []
            kinds = [Protocol.TCP, Protocol.UDP] if protocol == "tcp-udp" else [{"tcp": Protocol.TCP, "udp": Protocol.UDP, "sctp": Protocol.SCTP}[protocol]]
            return [ServiceEntry(kind, dst_ports=ports, src_ports=source) for kind in kinds]
        if protocol == "icmp":
            if not rest:
                return [ServiceEntry(Protocol.ICMP)]
            if rest[0] in ICMP4 and len(rest) == 1:
                kind, code = ICMP4[rest[0]]
                return [ServiceEntry(Protocol.ICMP, icmp_type=kind, icmp_code=code)]
            if rest[0].isascii() and rest[0].isdigit() and len(rest) == 1 and int(rest[0]) <= 255:
                return [ServiceEntry(Protocol.ICMP, icmp_type=int(rest[0]))]
            problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            return []
        number = PROTOCOLS4.get(protocol, int(protocol) if protocol.isascii() and protocol.isdigit() and int(protocol) <= 255 else None)
        if number is None or rest:
            problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            return []
        if number == -1:
            problems.append("protocol ip in an object group of services")
            return []
        return [ServiceEntry(Protocol.IP, ip_protocol=number)]

    def _network_group(self, name: str, problems: List[str], version: int, depth: int = 0) -> Optional[List[Interval]]:
        if depth > _MAX_NESTING:
            problems.append(f"object group {name[:40]} is nested too deeply, or in itself")
            return None
        if name not in self.net_groups:
            problems.append(f"object group {name[:40]} is not in the configuration")
            return None
        own, nested, found_problems, group_version = self.net_groups[name]
        if found_problems:
            problems.extend(f"object group {name[:40]}: {p}" for p in found_problems)
            return None
        if version and group_version != version:
            problems.append(f"object group {name[:40]} is of the other IP version")
            return None
        out = list(own)
        for inner in nested:
            got = self._network_group(inner, problems, version or group_version, depth + 1)
            if got is None:
                return None
            out += got
        return normalize(out)

    def _service_group(self, name: str, problems: List[str], depth: int = 0) -> List[ServiceEntry]:
        if depth > _MAX_NESTING or name not in self.svc_groups:
            problems.append(f"object group {name[:40]} of services is not in the configuration, or nested in itself")
            return []
        own, nested, found_problems = self.svc_groups[name]
        if found_problems:
            problems.extend(f"object group {name[:40]}: {p}" for p in found_problems)
        out = list(own)
        for inner in nested:
            out += self._service_group(inner, problems, depth + 1)
        if not out and not problems:
            problems.append(f"object group {name[:40]} of services is empty")
        return out

    # -- access lists ------------------------------------------------------------------------

    def _access_lists(self) -> None:
        numbered: Dict[str, List[Tuple[_Line, List[str]]]] = {}
        for line in self.lines:
            words = line.words
            if words[0] == "access-list" and len(words) >= 3 and words[1].isascii() and words[1].isdigit():
                numbered.setdefault(words[1], []).append((line, words[2:]))
        for number, entries in numbered.items():
            value = int(number)
            kind = "standard" if value < 100 or 1300 <= value <= 1999 else "extended"
            if not (1 <= value <= 199 or 1300 <= value <= 2699):
                continue  # (other kinds of numbered list: MAC, protocol type)
            acl = self.acls.setdefault(number, _Acl(number, kind, line=entries[0][0].number))
            remark: List[str] = []
            for line, words in entries:
                if words[0] == "remark":
                    remark.append(" ".join(words[1:]))
                    continue
                acl.aces.append(self._ace(number, kind, (len(acl.aces) + 1) * 10, line.number, words, " ".join(remark)))
                remark = []
        for line in self.lines:
            words = line.words
            if len(words) >= 4 and words[:2] == ["ip", "access-list"] and words[2] in ("standard", "extended"):
                self._named(words[3], words[2], line)
            elif len(words) >= 3 and words[:2] == ["ipv6", "access-list"]:
                self._named(words[2], "ipv6", line)

    def _named(self, name: str, kind: str, line: _Line) -> None:
        acl = self.acls.get(name)
        if acl is None:
            acl = self.acls[name] = _Acl(name, kind, line=line.number)
        elif acl.kind != kind and not (acl.kind in ("standard", "extended") and kind in ("standard", "extended")):
            raise ParseError(f"line {line.number}: access list {name[:40]} is an IPv4 and an IPv6 list")
        remark: List[str] = []
        found: List[_Ace] = []
        for child in line.children:
            words = list(child.words)
            seq: Optional[int] = None
            if words and words[0].isascii() and words[0].isdigit():
                seq = int(words[0])
                words = words[1:]
            elif len(words) > 2 and words[0] == "sequence" and words[1].isascii() and words[1].isdigit():
                seq = int(words[1])
                words = words[2:]
            if not words:
                continue
            if words[0] == "remark":
                remark.append(" ".join(words[1:]))
                continue
            if words[0] == "evaluate":
                self._say("IOS_REFLEXIVE", f"{name}: evaluate {' '.join(words[1:2])[:40]}")
                held = _Ace(name, seq if seq is not None else 0, child.number, "permit", 6 if kind == "ipv6" else 4)
                held.skip = "evaluate: the replies of reflected connections only"
                if seq is None:
                    held.seq = (max([a.seq for a in acl.aces + found] or [0]) // 10 + 1) * 10
                found.append(held)  # (an entry: the list is not empty, and ends in its implicit deny)
                remark = []
                continue
            ace = self._ace(name, kind, seq if seq is not None else 0, child.number, words, " ".join(remark))
            if seq is None and ace.seq == 0:
                ace.seq = (max([a.seq for a in acl.aces + found] or [0]) // 10 + 1) * 10
            found.append(ace)
            remark = []
        acl.aces += found
        acl.aces.sort(key=lambda a: a.seq)

    # -- interfaces --------------------------------------------------------------------------

    def _interfaces(self) -> None:
        for line in self._top("interface"):
            if len(line.words) < 2:
                continue
            name = line.words[1]
            item = _Interface(name, line.number)
            for child in line.children:
                words = child.words
                if words[:2] == ["ip", "address"] and len(words) >= 4:
                    found = parse_literal(f"{words[2]}/{words[3]}")
                    host = parse_literal(words[2])
                    if found is not None and host is not None and found[0] == 4:
                        item.networks.append(found)
                        item.addresses.append(host)
                elif words[:2] == ["ip", "address"] and len(words) >= 3 and words[2] in ("dhcp", "negotiated"):
                    item.dhcp = True
                elif words[:2] == ["ipv6", "address"] and len(words) >= 3 and "/" in words[2]:
                    found = parse_literal(words[2])
                    host = parse_literal(words[2].split("/")[0])
                    if found is not None and host is not None and found[0] == 6:
                        item.networks.append(found)
                        item.addresses.append(host)
                elif words[:2] == ["ip", "access-group"] and len(words) == 4 and words[3] in ("in", "out"):
                    item.acls[(words[3], 4)] = words[2]
                elif words[:2] == ["ipv6", "traffic-filter"] and len(words) == 4 and words[3] in ("in", "out"):
                    item.acls[(words[3], 6)] = words[2]
                elif words[:2] in (["ip", "access-group"], ["ipv6", "traffic-filter"]):
                    direction = "out" if words[-1] == "out" else "in"
                    item.acls[(direction, 6 if words[0] == "ipv6" else 4)] = "\0" + " ".join(words)[:80]
                    self._say("IOS_ACL_NOT_READ", f"{name}: {' '.join(words)[:80]}")
                elif words[:2] == ["zone-member", "security"] and len(words) == 3:
                    item.zone = words[2]
                elif words[:2] == ["ip", "nat"] and len(words) == 3 and words[2] in ("inside", "outside"):
                    item.nat = words[2]
                elif words[:2] == ["ip", "nat"] and len(words) == 3 and words[2] == "enable":
                    self._say("IOS_NVI", name)
                elif words == ["shutdown"]:
                    item.shutdown = True
                elif words[:2] in (["vrf", "forwarding"], ["ip", "vrf"]) and len(words) >= 3:
                    item.vrf = words[-1]
                elif words[:2] == ["ip", "inspect"] and len(words) == 4:
                    item.inspect.append(f"{words[2]} {words[3]}")
            self.interfaces[name] = item

    # -- zone-based firewall -------------------------------------------------------------------

    def _zbfw(self) -> None:
        for line in self.lines:
            words = line.words
            if words[:2] == ["zone", "security"] and len(words) == 3:
                self.zones[words[2]] = " ".join(c for child in line.children if child.words[0] == "description" for c in child.words[1:])
            elif words[:2] == ["zone-pair", "security"] and len(words) == 7 and words[3] == "source" and words[5] == "destination":
                policy = ""
                for child in line.children:
                    if child.words[:3] == ["service-policy", "type", "inspect"] and len(child.words) == 4:
                        policy = child.words[3]
                if "self" in (words[4], words[6]):
                    self._say("IOS_SELF_ZONE", words[2])
                    continue
                self.zone_pairs[(words[4], words[6])] = (words[2], policy)
            elif words[:3] == ["policy-map", "type", "inspect"] and len(words) == 4:
                classes: List[Tuple[str, str, bool]] = []
                for child in line.children:
                    if child.words[:3] == ["class", "type", "inspect"] and len(child.words) == 4:
                        target = child.words[3]
                    elif child.words == ["class", "class-default"]:
                        target = "class-default"
                    else:
                        continue
                    action, log = "", False
                    for grand in child.children:
                        if grand.words[0] in ("inspect", "pass", "drop"):
                            action = grand.words[0]
                            log = "log" in grand.words[1:]
                        elif grand.words[0] == "service-policy":
                            self.layer7.add((words[3], target))
                        elif grand.words[0] != "police":
                            action = action or "?" + grand.words[0]
                    classes.append((target, action, log))
                self.policy_maps[words[3]] = classes
            elif words[:3] == ["class-map", "type", "inspect"] and len(words) in (4, 5):
                match_all = len(words) == 4 or words[3] == "match-all"
                criteria = [child.words[1:] for child in line.children if child.words[0] == "match"]
                self.class_maps[words[-1]] = (match_all, criteria)
            elif words[:2] == ["ip", "port-map"] and len(words) >= 5:
                found = _port_map(words)
                if found is None:
                    self.port_map_problems[words[2]] = f"ip port-map {' '.join(words[3:])[:60]} is not read"
                    continue
                app, entry = found
                self.port_map.setdefault(app, [])
                self.port_map[app] = self.port_map[app] + [entry]
                self._say("IOS_PORT_MAP", app)
        self.zbfw = any(i.zone for i in self.interfaces.values()) or "default" in self.zones

    # -- zones of the model --------------------------------------------------------------------

    def _units(self) -> None:
        left_out = []
        candidates = []
        for name, item in self.interfaces.items():
            lower = name.lower()
            if lower.startswith(("loopback", "null", "nve", "vasileft", "vasiright")) or not (item.networks or item.zone or item.acls or item.dhcp or item.nat):
                left_out.append(name)
                continue
            candidates.append(item)
            if item.vrf:
                self._say("IOS_VRF", f"{name} (vrf {item.vrf})")
            if item.inspect:
                self._say("IOS_CBAC", f"{name}: ip inspect {', '.join(item.inspect)}")
            if item.dhcp:
                self._say("IOS_DHCP_ADDRESS", name)
        if left_out:
            self._say("IOS_INTERFACES_LEFT_OUT", ", ".join(left_out[:12]) + (" ..." if len(left_out) > 12 else ""))
        by_zone: Dict[str, List[_Interface]] = {}
        for item in candidates:
            zone = item.zone or ("default" if "default" in self.zones and self.zbfw else "")
            by_zone.setdefault(zone, []).append(item)
        taken: Set[str] = set()
        for zone, members in by_zone.items():
            same = len({tuple(sorted(m.acls.items())) for m in members}) == 1 and len({m.nat for m in members}) == 1
            if zone and same:
                unit = self._unique(zone, taken)
                self.units[unit] = [m.name for m in members]
            else:
                if zone and not same:
                    self._say("IOS_ZONE_SPLIT", zone)
                for member in members:
                    self.units[self._unique(member.name, taken)] = [member.name]
        for unit, names in self.units.items():
            for name in names:
                self.unit_of[name] = unit
            self.p.zones[unit] = Zone(unit, interfaces=list(names))

    def _first(self, unit: str) -> _Interface:
        return self.interfaces[self.units[unit][0]]

    def _zone_of(self, unit: str) -> str:
        item = self._first(unit)
        return item.zone or ("default" if "default" in self.zones and self.zbfw else "")

    # -- NAT ----------------------------------------------------------------------------------

    def _units_where(self, role: str) -> List[str]:
        return [u for u in self.units if self._first(u).nat == role]

    def _nat(self) -> None:
        inside, outside = self._units_where("inside") or [ANY], self._units_where("outside") or [ANY]
        for line in self.lines:
            words = line.words
            if words[:3] == ["ip", "nat", "outside"] or (words[:2] == ["ip", "nat"] and len(words) > 2 and words[2] == "source"):
                self._nat_unsupported(line, "outside source NAT or NAT of an NVI" if words[2] != "source" else "NAT of an NVI (ip nat source)")
                continue
            if words[:4] == ["ip", "nat", "inside", "destination"]:
                self._nat_unsupported(line, "destination NAT of a list (ip nat inside destination)")
                continue
            if words[:4] != ["ip", "nat", "inside", "source"] or len(words) < 6:
                continue
            name = self._unique(f"nat-{line.number}", self.nat_names)
            rest = words[4:]
            flags = {"extendable", "no-alias", "no-payload"}
            if any(w in ("route-map", "vrf", "redundancy", "mapping-id", "reversible", "match-in-vrf") for w in rest):
                self._nat_unsupported(line, "route-map, vrf or redundancy")
                continue
            rest = [w for w in rest if w not in flags]
            if rest[0] == "static":
                self._static(name, line, rest[1:], inside, outside)
            elif rest[0] == "list" and len(rest) >= 4:
                self._dynamic(name, line, rest, inside, outside)
            else:
                self._nat_unsupported(line, "a form not read")

    def _nat_unsupported(self, line: _Line, why: str) -> None:
        nat = NatRule(self._unique(f"nat-{line.number}", self.nat_names))
        nat.origin = nat.name
        nat.description = " ".join(line.words)[:200]
        nat.unsupported.append(why)
        self.p.nat_rules.append(nat)
        self.nat_unread.append(f"line {line.number}: {why}")

    def _global_address(self, words: List[str], index: int) -> Tuple[Optional[Interval], int]:
        if words[index] == "interface" and index + 1 < len(words):
            item = self.interfaces.get(words[index + 1])
            own = [a for a in (item.addresses if item else []) if a[0] == 4]
            return (own[0] if own else None), index + 2
        found = parse_literal(words[index])
        return (found if found is not None and found[0] == 4 and found[1] == found[2] else None), index + 1

    def _static(self, name: str, line: _Line, words: List[str], inside: List[str], outside: List[str]) -> None:
        nat = NatRule(name, src_zones=list(inside), dst_zones=list(outside))
        nat.origin = name
        nat.description = " ".join(line.words)[:200]
        if words and words[0] in ("tcp", "udp") and len(words) >= 5:
            local = parse_literal(words[1])
            if local is None or local[1] != local[2] or local[0] != 4 or not words[2].isascii() or not words[2].isdigit() or int(words[2]) > 65535:
                return self._nat_unsupported(line, "a port translation that cannot be read")
            global_, index = self._global_address(words, 3)
            if global_ is None or index >= len(words) or not words[index].isascii() or not words[index].isdigit() or int(words[index]) > 65535 \
                    or index + 1 != len(words):
                return self._nat_unsupported(line, "a port translation whose outside address or port is not known")
            nat.src_zones, nat.dst_zones = list(outside), [ANY]
            nat.destinations = [interval_text(global_)]
            nat.service = self._service_name([ServiceEntry(Protocol.TCP if words[0] == "tcp" else Protocol.UDP, dst_ports=words[index])])
            nat.destination_translation = DestNat(interval_text(local), words[2])
            self.port_statics.append((words[0], local, int(words[2]), global_, int(words[index])))
            self.p.nat_rules.append(nat)
            return
        if words and words[0] == "network" and len(words) >= 4:
            length = words[3][1:] if words[3].startswith("/") else str(transform_mask(words[3]))
            local, global_ = parse_literal(f"{words[1]}/{length}"), parse_literal(f"{words[2]}/{length}")
            if local is None or global_ is None or local[0] != 4:
                return self._nat_unsupported(line, "a network translation that cannot be read")
        elif len(words) == 2:
            local = parse_literal(words[0])
            global_, _ = self._global_address(words, 1)
            if local is None or global_ is None or local[1] != local[2]:
                return self._nat_unsupported(line, "a static translation whose addresses cannot be read")
        elif len(words) == 3 and words[1] == "interface":
            local = parse_literal(words[0])
            global_, _ = self._global_address(words, 1)
            if local is None or global_ is None:
                return self._nat_unsupported(line, "a static translation to an interface whose address is not known")
        else:
            return self._nat_unsupported(line, "a static translation that cannot be read")
        nat.sources = [interval_text(local)]
        nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(global_)], bidirectional=True)
        self.statics.append(([local], [global_]))
        self.p.nat_rules.append(nat)

    def _dynamic(self, name: str, line: _Line, words: List[str], inside: List[str], outside: List[str]) -> None:
        acl = self.acls.get(words[1])
        self.used_acls.add(words[1])
        overload = "overload" in words
        target: List[Interval] = []
        nat = NatRule(name, src_zones=list(inside), dst_zones=list(outside))
        nat.origin = name
        nat.description = " ".join(line.words)[:200]
        if words[2] == "interface" and len(words) >= 4:
            item = self.interfaces.get(words[3])
            found = [a for a in (item.addresses if item else []) if a[0] == 4]
            unit = self.unit_of.get(words[3], "")
            nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=unit or words[3], interface_address=interval_text(found[0]) if found else "")
            if unit:
                nat.dst_zones = [unit]
            target = found[:1]
        elif words[2] == "pool" and len(words) >= 4:
            pool = self._pool(words[3])
            if pool is None:
                return self._nat_unsupported(line, f"pool {words[3][:40]} is not in the configuration or cannot be read")
            nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT if overload else SnatKind.DYNAMIC, [interval_text(pool)])
            target = [pool]
        else:
            return self._nat_unsupported(line, "a dynamic translation that cannot be read")
        sources = self._acl_sources(acl, words[1])
        if sources is None:
            nat.unsupported.append(f"access list {words[1][:40]} says more than which sources (or cannot be read)")
            self.nat_unread.append(f"line {line.number}: access list {words[1][:40]}")
        else:
            nat.sources = [interval_text(i) for i in sources] or ["0.0.0.0/32"]
            if not target:
                self.nat_unread.append(f"line {line.number}: the address of the interface is not known")
            else:
                self.dynamic.append((sources, target, name))
        self.p.nat_rules.append(nat)

    def _pool(self, name: str) -> Optional[Interval]:
        if self.pools is None:
            self.pools = {}
            for line in self.lines:
                words = line.words
                if words[:3] == ["ip", "nat", "pool"] and len(words) >= 5:
                    self.pools[words[3]] = parse_literal(f"{words[4]}-{words[5]}") if len(words) >= 6 else None
        return self.pools.get(name)

    def _acl_sources(self, acl: Optional[_Acl], name: str) -> Optional[List[Interval]]:
        """The sources an access list of a NAT rule permits; None when it says more (destinations, ports) or cannot be
        read."""
        if acl is None or acl.kind == "ipv6":
            return None
        permitted: List[Interval] = []
        denied: List[Interval] = []
        for ace in acl.aces:
            if ace.problems or ace.src is None or ace.skip:
                return None
            if ace.dst != [FULL_V4] or ace.entries:
                return None
            if ace.action == "permit":
                permitted += subtract(ace.src, denied)
            else:
                denied += ace.src
        return normalize(permitted)

    # -- evaluation lists ------------------------------------------------------------------------

    def _acl_items(self, unit: str, direction: str) -> List[_Item]:
        """The list of one direction of a zone: the entries of its lists, the implicit denies, then everything else."""
        item = self._first(unit)
        out: List[_Item] = []
        versions_left = [4, 6]
        for version in (4, 6):
            name = item.acls.get((direction, version))
            if not name:
                continue
            if name.startswith("\0"):
                versions_left.remove(version)
                out.append(_Item(f"{unit} ({direction}): {name[1:40]}", "deny", None, [ANY], [f"'{name[1:80]}' is not read"],
                                 description=f"a list bound in a way FWShift does not read: {name[1:80]}"))  # fmt: skip
                continue
            self.used_acls.add(name)
            acl = self.acls.get(name)
            if acl is None:
                self._say("IOS_ACL_UNDEFINED", f"{name} ({direction} on {', '.join(self.units[unit])})")
                continue
            if (acl.kind == "ipv6") != (version == 6):
                self._say("IOS_ACL_UNDEFINED", f"{name} ({direction} on {', '.join(self.units[unit])}: a list of the other IP version)")
                continue
            if not acl.aces:
                self._say("IOS_ACL_EMPTY", f"{name} ({direction} on {', '.join(self.units[unit])})")
                continue
            versions_left.remove(version)
            for ace in acl.aces:
                if ace.skip:
                    self._say("IOS_SKIPPED_ENTRIES", f"{name} {ace.seq}: {ace.skip}")
                    continue
                if ace.reflect:
                    self._say("IOS_REFLEXIVE", f"{name} {ace.seq}: reflect")
                named = regions.service_set(ace.entries) if ace.entries else regions.ALL_SERVICES
                sides = (self._side(ace.src) if ace.src else [ANY], self._side(ace.dst) if ace.dst else [ANY])
                out.append(_Item(f"{name}-{ace.seq}", "allow" if ace.action == "permit" else "deny", ace.boxes(),
                                 [ace.service_name], list(ace.problems), log=ace.log, description=ace.remark,
                                 ids={"ios.acl": name, "ios.sequence": str(ace.seq), "ios.line": str(ace.line)}, named=named,
                                 sides=sides))  # fmt: skip
            out.append(_Item(f"{name} implicit deny", "deny", [(version, [regions.full(version)], [regions.full(version)], regions.ALL_SERVICES)],
                             [ANY], description=f"the end of access list {name}: what no entry permits is denied",
                             ids={"ios.acl": name}, named=regions.ALL_SERVICES))  # fmt: skip
        if versions_left:
            name = f"{unit} ({direction}): no access list" if direction == "in" else "no outbound access list"
            out.append(_everything(name, "allow", f"no {direction} access list on {', '.join(self.units[unit])}", versions_left))
        return out

    def _class_boxes(self, name: str, problems: List[str], depth: int = 0) -> Optional[List[Box]]:
        if depth > _MAX_NESTING or name not in self.class_maps:
            problems.append(f"class map {name[:40]} is not in the configuration, or nested in itself")
            return None
        match_all, criteria = self.class_maps[name]
        sets: List[List[Box]] = []
        for words in criteria:
            found: Optional[List[Box]] = None
            if words[:2] == ["access-group", "name"] and len(words) == 3 or (words[:1] == ["access-group"] and len(words) == 2):
                found = self._acl_set(words[-1], problems)
            elif words[:1] == ["protocol"] and len(words) == 2:
                found = self._protocol_set(words[1], problems)
            elif words[:1] == ["class-map"] and len(words) == 2:
                found = self._class_boxes(words[1], problems, depth + 1)
            else:
                problems.append(f"match {' '.join(words)[:60]} is not converted")
            if found is None:
                return None
            sets.append(found)
        if not sets:
            problems.append(f"class map {name[:40]} has no match statement")
            return None
        if not match_all:
            return [box for found in sets for box in found]
        out = sets[0]
        for found in sets[1:]:
            out = [box for box in (regions.box_and(a, b) for a in out for b in found) if box is not None]
        return out

    def _acl_set(self, name: str, problems: List[str]) -> Optional[List[Box]]:
        """What an access list permits, as boxes (its denies taken out of the permits below them)."""
        self.used_acls.add(name)
        acl = self.acls.get(name)
        if acl is None:
            problems.append(f"access list {name[:40]} is not in the configuration")
            return None
        if not acl.aces:
            problems.append(f"access list {name[:40]} holds no entries")
            return None
        out: List[Box] = []
        denied: List[Box] = []
        for ace in acl.aces:
            if ace.skip:
                continue
            boxes = ace.boxes()
            if boxes is None:
                problems.append(f"access list {name[:40]} entry {ace.seq}: " + "; ".join(ace.problems or ["cannot be read"]))
                return None
            if ace.action == "deny":
                denied += boxes
                continue
            pieces = regions.minus_all(boxes, denied, limit=2000)
            if pieces is None:
                problems.append(f"access list {name[:40]}: what its denies take away is too complex to work out")
                return None
            out += pieces
        return out

    def _protocol_set(self, name: str, problems: List[str]) -> Optional[List[Box]]:
        if name in self.port_map_problems:
            problems.append(f"match protocol {name}: {self.port_map_problems[name]}")
            return None
        if name not in self.port_map:
            problems.append(f"match protocol {name[:40]}: an application FWShift does not know the ports of")
            return None
        entries: List[ServiceEntry] = []
        for protocol, ports in self.port_map[name]:
            if protocol == "icmp":
                entries += [ServiceEntry(Protocol.ICMP), ServiceEntry(Protocol.ICMP6)]
            else:
                entries.append(ServiceEntry(Protocol.TCP if protocol == "tcp" else Protocol.UDP, dst_ports=ports))
        services = regions.service_set(entries)
        assert services is not None
        if name not in ("tcp", "udp", "icmp"):
            self._say("IOS_PORT_MAP", name)
        return [(v, [regions.full(v)], [regions.full(v)], services) for v in (4, 6)]

    def _zbfw_items(self, source: str, destination: str) -> List[_Item]:
        """What the zone-based firewall decides between two zones of it ("" for an interface in no zone)."""
        if not self.zbfw:
            return [_everything("no zone-based firewall", "allow")]
        if not source and not destination:
            return [_everything("between interfaces in no zone", "allow")]
        if not source or not destination:
            return [_everything(f"between zone {source or destination} and an interface in no zone", "deny",
                                "the zone-based firewall drops traffic between an interface in a zone and one in none")]  # fmt: skip
        pair = self.zone_pairs.get((source, destination))
        if pair is None:
            if source == destination:
                return [_everything(f"inside zone {source}", "allow", "traffic inside a zone passes when no zone pair says otherwise")]
            return [_everything(f"no zone pair from {source} to {destination}", "deny",
                                "the zone-based firewall drops traffic between two zones without a zone pair")]  # fmt: skip
        pair_name, policy = pair
        classes = self.policy_maps.get(policy)
        if classes is None:
            self._say("IOS_POLICY_MISSING", f"{pair_name}: {policy or 'no service-policy'}")
            return [_everything(f"zone pair {pair_name} without a policy", "deny", "a zone pair without its inspect policy passes nothing")]
        out: List[_Item] = []
        has_default = False
        for target, action, log in classes:
            problems: List[str] = []
            ids = {"ios.zone-pair": pair_name, "ios.policy-map": policy, "ios.class": target}
            if target == "class-default":
                has_default = True
                act = action or "drop"
                item = _everything(f"{pair_name} class-default", "allow" if act == "pass" else "deny")
                if act not in ("pass", "drop"):
                    item.problems.append(f"class-default action '{act.lstrip('?')}' is not converted")
                item.ids, item.log = ids, log
                item.drop = act == "drop"
                if act == "pass":
                    item.findings.append(("IOS_PASS", "pass lets one direction through; the replies need a pass the other way"))
                out.append(item)
                continue
            boxes = self._class_boxes(target, problems)
            if action not in ("inspect", "pass", "drop"):
                problems.append(f"action '{action.lstrip('?') or 'none'}' is not converted")
            item = _Item(f"{pair_name} {target}", "deny" if action == "drop" else "allow", boxes if not problems else None, [],
                         problems, log=log, ids=ids, drop=action == "drop")  # fmt: skip
            if (policy, target) in self.layer7:
                item.findings.append(("IOS_LAYER7", "a layer-7 policy under this class (service-policy) drops or resets part of what it "
                                      "inspects; it is not converted, and the converted rule allows more"))  # fmt: skip
            if action == "pass":
                item.findings.append(("IOS_PASS", "pass lets one direction through; the replies need a pass the other way"))
            out.append(item)
        if not has_default:
            item = _everything(f"{pair_name} class-default", "deny")
            item.drop = True
            item.ids = {"ios.zone-pair": pair_name, "ios.policy-map": policy, "ios.class": "class-default"}
            out.append(item)
        return out

    # -- NAT and the addresses lists see -----------------------------------------------------------

    def _after_nat(self, items: List[_Item], source_unit: str, destination_unit: str, outbound_list: bool) -> List[_Item]:
        """Rewrite the boxes of a list that sees addresses after NAT (an outbound list; the zone-based firewall, which is
        read as seeing inside addresses) into the addresses as they arrive, for traffic between two zones."""
        a, b = self._first(source_unit).nat, self._first(destination_unit).nat
        inbound = a == "outside" and b == "inside"
        outbound = a == "inside" and b == "outside" and outbound_list
        if not (inbound or outbound) or not (self.statics or self.port_statics or self.nat_unread or (outbound and self.dynamic)):
            return items
        out: List[_Item] = []
        for item in items:
            if item.boxes is None:
                out.append(item)
                continue
            problems: List[str] = []
            boxes: List[Box] = []
            for box in item.boxes:
                boxes += self._box_before_nat(box, inbound, problems)
            copy = _Item(item.name, item.action, None if problems else boxes, item.service_names, item.problems + problems, item.log,
                         item.description, dict(item.ids), list(item.findings), item.drop, item.named, item.sides)  # fmt: skip
            out.append(copy)
        return out

    def _box_before_nat(self, box: Box, inbound: bool, problems: List[str]) -> List[Box]:
        version, src, dst, services = box
        if version != 4:
            return [box]
        if inbound:
            # Arriving on the outside for an inside address: a translated destination arrives as the outside address.
            if self.nat_unread and dst != [FULL_V4]:
                problems.append("NAT that FWShift does not read may translate the destination before this list")
            globals_ = [i for pair in self.statics for i in pair[1]]
            new_dst = subtract(dst, globals_)
            for local, global_ in self.statics:
                for piece in intersect(dst, local):
                    new_dst.append((4, global_[0][1] + piece[1] - local[0][1], global_[0][1] + piece[2] - local[0][1]))
            out: List[Box] = [(4, src, normalize(new_dst), services)] if new_dst else []
            for protocol, _, _, global_ip, global_port in self.port_statics:
                # (what arrives for the outside address and port of a port translation is translated: not this address)
                arriving = regions.service_set([ServiceEntry(Protocol.TCP if protocol == "tcp" else Protocol.UDP, dst_ports=str(global_port))])
                assert arriving is not None
                out = [piece for kept in out for piece in regions.box_minus(kept, (4, [regions.full(4)], [global_ip], arriving))]
            for protocol, local_ip, local_port, global_ip, global_port in self.port_statics:
                probe_services = regions.service_set([ServiceEntry(Protocol.TCP if protocol == "tcp" else Protocol.UDP, dst_ports=str(local_port))])
                assert probe_services is not None
                hit = regions.box_and(box, (4, [regions.full(4)], [local_ip], probe_services))
                if hit is None:
                    continue
                number = 6 if protocol == "tcp" else 17
                mapped = regions.Services({number: [(r[0], r[1], global_port, global_port) for r in hit[3].of(number)]}, False)
                out.append((4, hit[1], [global_ip], mapped))
            return out
        # Leaving by the outside from an inside address: a translated source leaves as its outside address.
        if src == [FULL_V4]:
            return [box]  # (every source before NAT is a source after it)
        new_src = subtract(src, [i for pair in self.statics for i in pair[0]])
        for local, global_ in self.statics:
            for piece in intersect(src, global_):
                new_src.append((4, local[0][1] + piece[1] - global_[0][1], local[0][1] + piece[2] - global_[0][1]))
        if any(overlaps_one(src, global_ip) != overlaps_one(src, local_ip) for _, local_ip, _, global_ip, _ in self.port_statics):
            problems.append("names the inside or the outside address of a port translation as a source, not both")
        if self.nat_unread:
            problems.append("NAT that FWShift does not read may translate the source before this list")
        statics = [i for pair in self.statics for i in pair[0]]
        for sources, target, name in self.dynamic:
            translated = subtract(sources, statics)
            if not translated:
                continue
            covered = intersect(src, target)
            if covered and normalize(covered) == normalize(target):
                new_src += translated
                if any((r[0], r[1]) != (0, 65535) for n in (6, 17, 132) for r in services.of(n)):
                    problems.append(f"source ports after dynamic NAT {name}, which may change them")
            elif covered:
                problems.append(f"names part of the addresses of dynamic NAT {name}")
            else:
                new_src = subtract(new_src, translated)
        new_src = normalize(new_src)
        return [(4, new_src, dst, services)] if new_src else []

    # -- the rules ---------------------------------------------------------------------------------

    def _compose(self, first: List[_Item], second: List[_Item], label: str) -> Tuple[List[_Item], bool]:
        """Two lists a connection has to pass, as one: (items, complete)."""
        if len(second) == 1 and second[0].action == "allow" and second[0].boxes is not None and _covers_all(second[0].boxes):
            return first, True
        out: List[_Item] = []
        for a in first:
            if a.action != "allow" or a.boxes is None:
                out.append(a)
                continue
            taken: List[Box] = []  # (what the entries of the second list above took of this one: rules for it would never match)
            for b in second:
                if b.boxes is None:
                    out.append(_Item(f"{a.name} + {b.name}", b.action, None, b.service_names, list(b.problems) or ["not worked out"],
                                     b.log, b.description, dict(b.ids), list(b.findings), b.drop))  # fmt: skip
                    continue
                both = [x for x in (regions.box_and(p, q) for p in a.boxes for q in b.boxes) if x is not None and not regions.empty(x)]
                left = regions.minus_all(both, taken, limit=64) if taken else both
                taken += both
                if not both or (left is not None and all(regions.empty(x) for x in left)):
                    continue  # (written as it is otherwise: the order says the rest)
                names, named = ([], None)
                for side in (a, b):
                    other = b if side is a else a
                    if side.named is not None and (other.named is None or _same(side.named.and_(other.named), side.named)):
                        names, named = side.service_names, side.named
                        break
                out.append(_Item(f"{a.name} + {b.name}", b.action, both, names, [], a.log or b.log,
                                 " / ".join(d for d in (a.description, b.description) if d), {**a.ids, **b.ids},
                                 a.findings + b.findings, b.drop, named))  # fmt: skip
                if len(out) > _MAX_COMPOSED:
                    self._say("IOS_COMPOSED_LEFT_OUT", label)
                    return out, False
        return out, True

    def _rules(self) -> None:
        units = list(self.units)
        inbound = {u: self._acl_items(u, "in") for u in units}
        outbound = {u: self._acl_items(u, "out") for u in units}
        composed = 0
        for a in units:
            pairs = []
            for b in units:
                zbfw = self._zbfw_items(self._zone_of(a), self._zone_of(b))
                pairs.append((b, self._after_nat(outbound[b], a, b, True), self._after_nat(zbfw, a, b, False)))
            if all(_trivial(second) and _trivial(third) for _, second, third in pairs):
                for item in inbound[a]:
                    self._emit(item, [a], [ANY])
                continue
            groups: Dict[str, Tuple[List[str], List[_Item], List[_Item]]] = {}
            for b, second, third in pairs:
                key = json.dumps([_key(second), _key(third)], default=str)
                groups.setdefault(key, ([], second, third))[0].append(b)
            for members, second, third in groups.values():
                label = f"{a} to {', '.join(members[:3])}" + (" ..." if len(members) > 3 else "")
                composed += 1
                found: List[_Item] = []
                if len(self.p.rules) > _MAX_RULES:
                    self._say("IOS_COMPOSED_LEFT_OUT", label)
                    complete = False
                else:
                    rest, complete = self._compose(second, third, label)
                    found, complete = self._compose(inbound[a], rest, label) if complete else ([], False)
                if not complete:
                    blocker = Rule(self._unique(f"{label}: the rest", self.rule_names), src_zones=[a], dst_zones=list(members), action=Action.DENY)
                    blocker.origin = blocker.name
                    blocker.description = "more combinations of the lists than are converted: blocked"
                    self.p.rules.append(blocker)
                    continue
                for item in found:
                    self._emit(item, [a], members)
        if composed:
            self._say("IOS_COMPOSED", str(composed))

    def _side(self, intervals: List[Interval]) -> List[str]:
        key = tuple(normalize(intervals))
        if key in self.named:
            return [self.named[key]]
        whole = {FULL_V4: ANY_V4, FULL_V6: ANY_V6}
        out = [whole.get(i, interval_text(i)) for i in key]
        return [ANY] if set(out) == {ANY_V4, ANY_V6} else out

    def _emit(self, item: _Item, src_zones: List[str], dst_zones: List[str]) -> None:
        action = Action.DROP if item.drop and item.action == "deny" else Action.ALLOW if item.action == "allow" else Action.DENY
        if item.boxes is None:
            sources, destinations = item.sides or ([ANY], [ANY])
            rule = self._rule(item, src_zones, dst_zones, sources, destinations, item.service_names or [ANY], action)
            if not rule.unsupported:
                rule.unsupported.append("not worked out")
            return
        groups: List[Tuple[regions.Services, List[Box]]] = []
        for box in item.boxes:
            if regions.empty(box):
                continue
            for svc, members in groups:
                if _same(svc, box[3]):
                    members.append(box)
                    break
            else:
                groups.append((box[3], [box]))
        for svc, same in groups:
            versions = [b[0] for b in same]
            batches = [same] if len(versions) == len(set(versions)) else [[b] for b in same]
            for batch in batches:
                found = self._service_names(svc, item, batch[0][0] if len(batch) == 1 else 0)
                sources = transform.dedupe([s for b in batch for s in self._side(b[1])])
                destinations = transform.dedupe([d for b in batch for d in self._side(b[2])])
                if set(sources) == {ANY_V4, ANY_V6}:
                    sources = [ANY]
                if set(destinations) == {ANY_V4, ANY_V6}:
                    destinations = [ANY]
                rule = self._rule(item, src_zones, dst_zones, sources, destinations, found[0] if found else [ANY], action)
                if found is None:
                    rule.unsupported.append("the services left after the lists before it cannot be written as services")
                else:
                    rule.negate_service = found[1]

    def _service_names(self, svc: regions.Services, item: _Item, version: int) -> Optional[Tuple[List[str], bool]]:
        if item.named is not None and item.service_names and _same(svc, item.named):
            return item.service_names, False
        if _same(svc, regions.ALL_SERVICES):
            return [ANY], False
        found = regions.entries_of(svc, version or 4)
        if found is None:
            return None
        entries, negated = found
        if version == 0:
            other = regions.entries_of(svc, 6)
            if other is None or other[1] != negated:
                return None
            entries = entries + [e for e in other[0] if e not in entries]
        if not entries:
            return ([ANY], False) if negated else None
        return [self._service_name(entries)], negated

    def _rule(self, item: _Item, src_zones: List[str], dst_zones: List[str], sources: List[str], destinations: List[str],
              services: List[str], action: Action) -> Rule:  # fmt: skip
        base = item.name if src_zones == [ANY] or dst_zones == [ANY] else f"{item.name} ({src_zones[0]} to {dst_zones[0]}" + (" ..." if len(dst_zones) > 1 else "") + ")"
        rule = Rule(self._unique(base[:200], self.rule_names), src_zones=list(src_zones), dst_zones=list(dst_zones), sources=sources,
                    destinations=destinations, services=services, action=action)  # fmt: skip
        rule.origin = rule.name
        rule.log_end = item.log
        rule.description = item.description
        rule.source_ids = dict(item.ids)
        rule.unsupported = list(dict.fromkeys(item.problems))
        self.p.rules.append(rule)
        for code, message in item.findings:
            self.report.add("rule", rule.origin, Severity.REVIEW, code, message)
        return rule

    # -- notes -----------------------------------------------------------------------------------

    def _notes(self) -> None:
        bound = {name for item in self.interfaces.values() for name in item.acls.values() if not name.startswith("\0")}
        self.report.note(Severity.INFO, "IOS_SOURCE",
                         f"{len(self.units)} zones ({', '.join(list(self.units)[:8])}{' ...' if len(self.units) > 8 else ''}) from the "
                         f"interfaces{' and the zones of the zone-based firewall' if self.zbfw else ''}; {len(bound)} access lists bound to "
                         "interfaces. A connection passes the inbound list of the interface it arrives on, the outbound list of the "
                         "one it leaves by" + (" and the zone-based firewall" if self.zbfw else "") + ". Traffic to and from the "
                         "router itself is not converted")  # fmt: skip
        if bound:
            self.report.note(Severity.REVIEW, "IOS_STATELESS",
                             "access lists are stateless: on the router a connection also needs its replies let through by the "
                             "lists of the other direction (established entries, reflexive lists, inspection). The converted policy "
                             "is stateful and allows the replies of what it allows: where the router's lists did not let the "
                             "replies through, it allows connections that did not work there")  # fmt: skip
        if self.zbfw and (self.statics or self.dynamic or self.port_statics):
            self.report.note(Severity.REVIEW, "IOS_ZBFW_NAT",
                             "the zone-based firewall was read as seeing the inside addresses of NAT (the destination after "
                             "translation for connections from outside, the source before it for connections to outside). Cisco "
                             "does not document this; check its class maps against the converted rules")  # fmt: skip
        unbound = sorted(name for name in self.acls if name not in bound and name not in self.used_acls)
        if unbound:
            self._say("IOS_UNBOUND_ACL", ", ".join(unbound[:12]) + (" ..." if len(unbound) > 12 else ""))
        texts = {
            "IOS_ACL_UNDEFINED": (Severity.REVIEW, "access lists bound to an interface are not in the configuration (or are of "
                                  "the other IP version): IOS passes everything through such an interface, and so does the "
                                  "converted policy"),
            "IOS_ACL_EMPTY": (Severity.REVIEW, "access lists bound to an interface hold no entries: IOS passes everything, and "
                              "so does the converted policy"),
            "IOS_SKIPPED_ENTRIES": (Severity.INFO, "entries that match no packet that opens a connection were left out (the "
                                    "model allows the replies of what it allows)"),
            "IOS_REFLEXIVE": (Severity.INFO, "reflexive access lists: reflect permits like an entry of a stateful firewall, "
                              "and evaluate (the replies) is what the model does by itself"),
            "IOS_UNBOUND_ACL": (Severity.INFO, "access lists bound to no interface (used for NAT, routing, management or not at "
                                "all) are not security rules"),
            "IOS_SELF_ZONE": (Severity.INFO, "zone pairs with the self zone filter traffic to and from the router itself and "
                              "were not read"),
            "IOS_ZONE_SPLIT": (Severity.INFO, "zones whose interfaces have different access lists or NAT roles: each interface "
                               "is a zone of the converted policy"),
            "IOS_POLICY_MISSING": (Severity.REVIEW, "zone pairs whose inspect policy is not in the configuration: nothing passes "
                                   "them"),
            "IOS_PORT_MAP": (Severity.INFO, "match protocol was read as the ports of Port-to-Application Mapping (the system "
                             "table, and ip port-map); the router inspects the application as well, the converted rules match "
                             "the ports"),
            "IOS_VRF": (Severity.REVIEW, "interfaces in VRFs: the converted policy has one routing table, and does not know "
                        "which zones reach each other"),
            "IOS_CBAC": (Severity.INFO, "classic inspection (ip inspect) lets the replies of inspected connections through the "
                         "lists of the other direction; the converted policy is stateful anyway"),
            "IOS_DHCP_ADDRESS": (Severity.INFO, "interfaces whose address comes from DHCP or PPP: not known here"),
            "IOS_NVI": (Severity.REVIEW, "NAT of the NAT virtual interface (ip nat enable) is not read"),
            "IOS_INTERFACES_LEFT_OUT": (Severity.INFO, "interfaces that forward no traffic of their own (loopbacks, interfaces "
                                        "without an address) are not zones"),
            "IOS_COMPOSED": (Severity.INFO, "pairs of zones where an outbound list or the zone-based firewall decides as well: "
                             "the lists composed into one, for each pair"),
            "IOS_COMPOSED_LEFT_OUT": (Severity.REVIEW, f"more than {_MAX_COMPOSED} combinations of the lists of a pair of zones, "
                                      f"or more than {_MAX_RULES} rules in all: the rest is blocked"),
            "IOS_ACL_NOT_READ": (Severity.REVIEW, "lines that bind an access list in a way FWShift does not read (a common list, a "
                                 "form it does not know): the rules for that interface are not converted"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def transform_mask(mask: str) -> int:
    found = parse_literal(f"0.0.0.0/{mask}")
    if found is None:
        return 99
    return 32 - (found[2] - found[1]).bit_length()


def overlaps_one(intervals: List[Interval], interval: Interval) -> bool:
    return bool(intersect(intervals, [interval]))


def _covers_all(boxes: List[Box]) -> bool:
    versions = {b[0] for b in boxes if b[1] == [regions.full(b[0])] and b[2] == [regions.full(b[0])] and b[3].everything()}
    return versions == {4, 6}


def _trivial(items: List[_Item]) -> bool:
    return len(items) == 1 and items[0].action == "allow" and items[0].boxes is not None and _covers_all(items[0].boxes)


def _key(items: List[_Item]) -> List[object]:
    return [[i.name, i.action, i.problems, None if i.boxes is None else [[b[0], b[1], b[2], sorted(b[3].protocols.items()), b[3].rest] for b in i.boxes]]
            for i in items]  # fmt: skip
