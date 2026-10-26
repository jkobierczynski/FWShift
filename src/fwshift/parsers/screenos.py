# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Juniper ScreenOS parser: ``get config`` of a NetScreen, SSG or ISG (ScreenOS 5.x and 6.x) -> neutral model.

How ScreenOS behaviour is mapped onto the neutral model:

* The security zones are the zones (Global aside). Policies are kept per pair of zones (from, to), first match, in
  the order the configuration lists them: ``get config`` prints them in the order the device evaluates them, which
  ``set policy move`` changes; a script's ``move``, ``top`` and ``before`` are carried out. Global policies
  (``from "Global" to "Global"``) are looked at after the policies of the pair, first match; what none matches, the
  default policy decides: deny, or permit with ``set policy default-permit-all``.
* Traffic inside one zone meets policies only when the zone blocks intra-zone traffic (``set zone "X" block``; the
  Untrust, MGT and VLAN zones do unless ``unset zone "X" block``). Otherwise it passes without a policy (assumed, from
  documentation and community answers): an allow rule for the zone goes first, and its intra-zone policies are written
  disabled.
* A policy between a zone and the Global zone matches nothing (the title of a Juniper knowledge base article; its text
  could not be read); it is written disabled.
* An address name is looked up in the address book of the zone of its side, then in the book of the Global zone. The
  same name can mean different addresses in two zones: such objects are kept apart (``name (zone)``). ``Any`` is every
  address of both IP versions, ``Any-IPv4`` and ``Any-IPv6`` one version.
* A policy names the destination before NAT: a MIP or VIP as ``MIP(...)`` or ``VIP(...)``, a policy with ``nat dst``
  its original destination; its destination zone is the zone of the host behind it. That is the model.
* NAT: policy-based NAT (``nat src [dip-id N]``, ``nat dst ip A [port P]``) applies to what its policy matches, so the
  NAT rules follow the policies, in their order, each for the services of its policy; then the MIPs (static, both
  ways), the VIPs (ports published) and the interfaces in NAT mode (the source of what goes to the Untrust zone becomes
  the address of the outgoing interface). That order is assumed.
* Predefined services (HTTP, ANY, ...) are not in the configuration: those FWShift knows are taken from a table (from
  memory, not confirmed on a device); the others, and those that limit more than ports (FTP-Get, RPC services), make
  their policies not converted.
* What cannot be converted (a VPN tunnel action, authentication, a keyword the parser does not know) makes its policy
  not converted, never wider.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import transform, zonenets
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
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
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, is_number, netmask_to_cidr, overlaps, parse_literal, size
from ..netutil import within
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_MAX_NESTING = 64
_POLICY_LINE = re.compile(rb'^set policy (global )?(id \d+ )?(name "[^"\n]*" )?(top |before \d+ )?from "[^"\n]+" to "[^"\n]+"', re.M)
_ADDRESS_LINE = re.compile(rb'^set address "[^"\n]+" "[^"\n]+" (\d{1,3}\.){3}\d{1,3}[ /]', re.M)
_ZONE_LINE = re.compile(rb'^set interface "?[A-Za-z][\w/.:-]*"? zone "[^"\n]+"', re.M)
_GLOBAL = "Global"
_BLOCKED_BY_DEFAULT = ("Untrust", "MGT", "VLAN")
_NOT_ZONES = ("Global", "Null", "Self", "HA")
_ACTIONS = {"permit": Action.ALLOW, "deny": Action.DROP, "reject": Action.RESET_CLIENT, "tunnel": Action.ALLOW}
_PROFILE_WORDS = ("url-filter", "av", "attack", "di", "idp", "scan-mgr", "anti-spam", "content-filter")
_IGNORED_WORDS = ("count", "alert", "no-session-backup", "no-hw-sess", "log")

# Predefined services: (protocol, destination ports) or (icmp, type, code) or (ip, protocol number). From memory of
# 'get service pre-defined' and documentation where it could be read; not confirmed on a device (DEVELOPMENT.md).
_T, _U, _I = Protocol.TCP, Protocol.UDP, Protocol.ICMP
PREDEFINED: Dict[str, List[Tuple[Protocol, str, Optional[int], Optional[int], Optional[int]]]] = {
    "TCP-ANY": [(_T, "", None, None, None)], "UDP-ANY": [(_U, "", None, None, None)], "ICMP-ANY": [(_I, "", None, None, None)],
    "HTTP": [(_T, "80", None, None, None)], "HTTPS": [(_T, "443", None, None, None)], "FTP": [(_T, "21", None, None, None)],
    "SSH": [(_T, "22", None, None, None)], "TELNET": [(_T, "23", None, None, None)], "SMTP": [(_T, "25", None, None, None)],
    "MAIL": [(_T, "25", None, None, None)], "DNS": [(_T, "53", None, None, None), (_U, "53", None, None, None)],
    "TFTP": [(_U, "69", None, None, None)], "GOPHER": [(_T, "70", None, None, None)], "FINGER": [(_T, "79", None, None, None)],
    "POP3": [(_T, "110", None, None, None)], "IDENT": [(_T, "113", None, None, None)], "NNTP": [(_T, "119", None, None, None)],
    "IMAP": [(_T, "143", None, None, None)], "BGP": [(_T, "179", None, None, None)], "WAIS": [(_T, "210", None, None, None)],
    "LDAP": [(_T, "389", None, None, None)], "IKE": [(_U, "500", None, None, None)],
    "IKE-NAT": [(_U, "500", None, None, None), (_U, "4500", None, None, None)], "REXEC": [(_T, "512", None, None, None)],
    "RLOGIN": [(_T, "513", None, None, None)], "RSH": [(_T, "514", None, None, None)], "SYSLOG": [(_U, "514", None, None, None)],
    "LPR": [(_T, "515", None, None, None)], "RIP": [(_U, "520", None, None, None)], "RTSP": [(_T, "554", None, None, None)],
    "NBNAME": [(_U, "137", None, None, None)], "NBDS": [(_U, "138", None, None, None)],
    "SMB": [(_T, "139", None, None, None), (_T, "445", None, None, None)], "MS-SQL": [(_T, "1433", None, None, None)],
    "WINFRAME": [(_T, "1494", None, None, None)], "SQL*Net V2": [(_T, "1521", None, None, None)],
    "L2TP": [(_U, "1701", None, None, None)], "PPTP": [(_T, "1723", None, None, None)],
    "RADIUS": [(_U, "1812-1813", None, None, None)], "SIP": [(_U, "5060", None, None, None), (_T, "5060", None, None, None)],
    "X-WINDOWS": [(_T, "6000-6063", None, None, None)], "IRC": [(_T, "6660-6669", None, None, None)],
    "MS-RPC-EPM": [(_T, "135", None, None, None), (_U, "135", None, None, None)],
    "GRE": [(Protocol.IP, "", None, None, 47)], "OSPF": [(Protocol.IP, "", None, None, 89)],
    "PING": [(_I, "", 8, None, None)], "ICMP-INFO": [(_I, "", 15, None, None), (_I, "", 16, None, None)],
    "ICMP-TIMESTAMP": [(_I, "", 13, None, None), (_I, "", 14, None, None)],
    "ICMP Address Mask": [(_I, "", 17, None, None), (_I, "", 18, None, None)],
    "ICMP Dest Unreachable": [(_I, "", 3, None, None)], "ICMP Fragment Needed": [(_I, "", 3, 4, None)],
    "ICMP Fragment Reassembly": [(_I, "", 11, 1, None)], "ICMP Host Unreachable": [(_I, "", 3, 1, None)],
    "ICMP Parameter Problem": [(_I, "", 12, None, None)], "ICMP Port Unreachable": [(_I, "", 3, 3, None)],
    "ICMP Protocol Unreach": [(_I, "", 3, 2, None)], "ICMP Redirect": [(_I, "", 5, None, None)],
    "ICMP Redirect Host": [(_I, "", 5, 1, None)], "ICMP Redirect TOS & Host": [(_I, "", 5, 3, None)],
    "ICMP Redirect TOS & Net": [(_I, "", 5, 2, None)], "ICMP Source Quench": [(_I, "", 4, None, None)],
    "ICMP Time Exceeded": [(_I, "", 11, None, None)],
}  # fmt: skip
# Predefined services whose definition is not certain enough, or that match more than ports: not converted.
_DOUBTFUL = {
    "FTP-Get": "FTP limited to downloads, a restriction of the FTP helper FWShift cannot write",
    "FTP-Put": "FTP limited to uploads, a restriction of the FTP helper FWShift cannot write",
    "HTTP-EXT": "its ports are not known for certain", "NTP": "its protocols are not known for certain",
    "SNMP": "its protocols and ports are not known for certain", "H.323": "its ports are not known for certain",
    "TRACEROUTE": "its definition is not known for certain", "TALK": "its ports are not known for certain",
    "VNC": "its ports are not known for certain", "UUCP": "its protocol is not known for certain",
    "NS Global": "its ports are not known for certain", "NS Global PRO": "its ports are not known for certain",
}  # fmt: skip
_RPC = ("MS-RPC-", "MS-EXCHANGE-", "MS-AD-", "MS-IIS-", "MS-FRS-", "MS-WIN-", "SUN-RPC")

Word = Tuple[str, bool]  # (the word, whether it was in double quotes)


def looks_like_screenos(data: bytes) -> bool:
    """``get config`` of ScreenOS: a policy line ``set policy ... from "Z" to "Z"``, an address line ``set address "Z"
    "N" A M``, or ``set interface I zone "Z"``. PAN-OS set commands and Junos write none of these."""
    head = data[:2_000_000]
    return bool(_POLICY_LINE.search(head) or _ADDRESS_LINE.search(head) or _ZONE_LINE.search(head))


def _split(line: str) -> Optional[List[Word]]:
    """The words of a line; a double-quoted string is one word; a ``!`` in front of a word is a word of its own.
    None when a quote is not closed."""
    out: List[Word] = []
    position, length = 0, len(line)
    while position < length:
        char = line[position]
        if char in " \t":
            position += 1
        elif char == '"':
            end = line.find('"', position + 1)
            if end < 0:
                return None
            out.append((line[position + 1 : end], True))
            position = end + 1
        elif char == "!":
            out.append(("!", False))
            position += 1
        else:
            end = position
            while end < length and line[end] not in ' \t"':
                end += 1
            out.append((line[position:end], False))
            position = end
    return out


def _short(text: str, limit: int = 40) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass
class _Interface:
    name: str
    zone: str = ""
    address: str = ""  # its IPv4 address
    networks: List[Interval] = field(default_factory=list)
    mode: str = ""  # nat, route, or not said


@dataclass
class _Nat:
    """What a policy translates."""

    dip: str = ""  # nat src dip-id N
    src: bool = False
    dst: str = ""
    dst_port: str = ""
    problems: List[str] = field(default_factory=list)


@dataclass
class _Pol:
    number: int
    line: int
    name: str = ""
    src_zone: str = ""
    dst_zone: str = ""
    sources: List[str] = field(default_factory=list)
    destinations: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    negate_source: bool = False
    negate_destination: bool = False
    action: str = ""
    log: bool = False
    schedule: str = ""
    disabled: bool = False
    application: str = ""
    nat: Optional[_Nat] = None
    profiles: Dict[str, str] = field(default_factory=dict)
    handling: Dict[str, str] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)


@dataclass
class _Vip:
    interface: str
    address: str  # the VIP's address, or "" for the interface's
    port: int
    service: str
    host: str
    problems: List[str] = field(default_factory=list)


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    lines: List[Tuple[int, List[Word]]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not a ScreenOS configuration")
        stripped = raw.strip()
        if not stripped:
            continue
        words = _split(stripped)
        if words is None:
            raise ParseError(f"line {number}: a quoted string that is not closed")
        if words:
            lines.append((number, words))
    reader = _Reader(report)
    try:
        reader.read(lines)
        return reader.build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ParseError(f"the configuration could not be read ({type(exc).__name__}: {exc})") from None


class _Reader:
    def __init__(self, report: Report) -> None:
        self.report = report
        self.p = Policy(vendor="screenos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.zone_names: Dict[str, str] = {}  # lower case -> as the configuration writes it
        self.blocked: Dict[str, bool] = {}  # zone -> intra-zone blocking, where the configuration says
        self.interfaces: Dict[str, _Interface] = {}
        self.books: Dict[str, Dict[str, List[str]]] = {}  # zone -> address name -> its value words
        self.book_comments: Dict[Tuple[str, str], str] = {}
        self.groups: Dict[str, Dict[str, List[str]]] = {}  # zone -> group -> members
        self.services: Dict[str, List[List[str]]] = {}
        self.service_groups: Dict[str, List[str]] = {}
        self.policies: Dict[int, _Pol] = {}
        self.order: List[int] = []
        self.mips: List[Tuple[str, str, str, str]] = []  # (interface, mapped, host, netmask)
        self.vips: List[_Vip] = []
        self.dips: Dict[str, Tuple[str, str, str, List[str]]] = {}  # id -> (interface, first, last, problems)
        self.routes: List[Tuple[str, str, str, int]] = []  # (network, interface, gateway, preference)
        self.default_permit = False
        self.moved = 0
        self.not_read: List[str] = []
        self.vsys: List[str] = []
        self.made: Dict[Tuple[str, str], str] = {}  # (zone, name) -> model name
        self.resolving: Set[Tuple[str, str]] = set()
        self.split_names: Set[str] = set()
        self.svc_resolving: Set[str] = set()
        self.nat_objects: Dict[str, str] = {}  # MIP(...)/VIP(...) -> model name
        self.predefined_used: Set[str] = set()
        self.missing: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()

    # -- reading ----------------------------------------------------------------------------------

    def zone(self, name: str) -> str:
        """The name of a zone as the configuration writes it; zone names are not case-sensitive."""
        return self.zone_names.setdefault(name.lower(), name)

    def read(self, lines: List[Tuple[int, List[Word]]]) -> None:
        stack: List[Tuple[str, str]] = []  # contexts: ("policy", id), ("vrouter", name), ("vsys", name), ("other", ...)
        for number, tagged in lines:
            words = [word for word, _ in tagged]
            head = words[0].lower()
            if head == "exit" and len(words) == 1:
                if stack:
                    stack.pop()
                continue
            context = stack[-1] if stack else ("", "")
            if context[0] in ("vsys", "protocol", "other"):
                # Skipped, with the contexts inside it, which end with an exit of their own.
                low = [word.lower() for word in words]
                if low[0] == "set" and (low[1:3] == ["policy", "id"] and len(low) == 4 or low[1:2] in (["vrouter"], ["vsys"])
                                        and len(low) == 3 or low[1:2] == ["protocol"]):  # fmt: skip
                    stack.append(("other", ""))
                continue
            if context[0] == "policy":
                self._policy_context(int(context[1]), words, tagged)
                continue
            if head not in ("set", "unset") or len(words) < 2:
                continue
            key = words[1].lower()
            if head == "set" and key == "policy" and len(words) == 4 and words[2].lower() == "id" and is_number(words[3]):
                if int(words[3]) not in self.policies:
                    self.not_read.append(f"line {number}: 'set policy id {words[3]}' for a policy that is not defined")
                stack.append(("policy", words[3]))
                continue
            if head == "set" and key == "vrouter" and len(words) == 3:
                stack.append(("vrouter", words[2]))
                continue
            if head == "set" and key == "vsys" and len(words) >= 3:
                self.vsys.append(words[2])
                stack.append(("vsys", words[2]))
                continue
            if context[0] == "vrouter" and head == "set" and key == "protocol" and len(words) >= 3:
                stack.append(("protocol", words[2]))
                continue
            if context[0] == "vrouter" and head == "set" and key == "route":
                self._route(words[2:], context[1])
                continue
            try:
                self._line(head, key, words, tagged, number)
            except _Unread as problem:
                self.not_read.append(f"line {number}: {problem}")

    def _line(self, head: str, key: str, words: List[str], tagged: List[Word], number: int) -> None:
        if key == "zone":
            self._zone_line(head, words)
        elif key == "interface" and head == "set" and len(words) >= 4:
            self._interface_line(words)
        elif key == "address" and head == "set":
            self._address_line(words)
        elif key == "group" and head == "set" and len(words) >= 4:
            self._group_line(words)
        elif key == "service" and head == "set" and len(words) >= 4:
            self.services.setdefault(words[2], []).append(words[3:])
        elif key == "policy":
            self._policy_line(head, words, tagged, number)
        elif key == "route" and head == "set":
            self._route(words[2:], "")
        elif key == "vrouter" and head == "set" and len(words) >= 4 and words[3].lower() == "route":
            self._route(words[4:], words[2])

    def _zone_line(self, head: str, words: List[str]) -> None:
        if len(words) >= 5 and words[2].lower() == "id" and is_number(words[3]):
            self.zone(words[4])
            return
        if len(words) < 3:
            return
        zone = self.zone(words[2])
        if len(words) >= 4 and words[3].lower() == "block":
            self.blocked[zone] = head == "set"

    def _interface_line(self, words: List[str]) -> None:
        interface = self.interfaces.setdefault(words[2], _Interface(words[2]))
        what = words[3].lower()
        rest = words[4:]
        if what == "zone" and rest:
            interface.zone = self.zone(rest[0])
        elif what == "tag" and len(rest) >= 3 and rest[1].lower() == "zone":
            interface.zone = self.zone(rest[2])
        elif what == "ip" and rest and rest[0].lower() not in ("manageable", "unnumbered"):
            text = rest[0] if "/" in rest[0] else netmask_to_cidr(rest[0], rest[1]) if len(rest) > 1 else None
            network = parse_literal(text or "")
            address = parse_literal(rest[0].split("/")[0])
            if network is None or address is None or network[0] != 4:
                raise _Unread(f"the address of interface '{_short(words[2])}'")
            interface.address = rest[0].split("/")[0]
            interface.networks.append(network)
        elif what == "ipv6" and len(rest) >= 2 and rest[0].lower() == "ip":
            network = parse_literal(rest[1])
            if network is not None and network[0] == 6:
                interface.networks.append(network)
        elif what in ("nat", "route") and not rest:
            interface.mode = what
        elif what == "mip" and len(rest) >= 3 and rest[1].lower() == "host":
            netmask = rest[rest.index("netmask") + 1] if "netmask" in rest[:-1] else "255.255.255.255"
            self.mips.append((words[2], rest[0], rest[2], netmask))
        elif what == "vip":
            self._vip(words[2], rest)
        elif what == "dip" or (what == "ext" and "dip" in rest):
            self._dip(words[2], rest[rest.index("dip") + 1 :] if what == "ext" else rest)

    def _vip(self, interface: str, rest: List[str]) -> None:
        if not rest:
            raise _Unread("a VIP without an address")
        address = "" if rest[0].lower() == "interface-ip" else rest[0]
        rest = rest[1:]
        if rest and rest[0] == "+":
            rest = rest[1:]
        if len(rest) < 3 or not is_number(rest[0]) or parse_literal(rest[2]) is None:
            raise _Unread(f"the VIP of interface '{_short(interface)}'")
        vip = _Vip(interface, address, int(rest[0]), rest[1], rest[2])
        if len(rest) > 3 and rest[3:] != ["manual"]:
            vip.problems.append(f"'{_short(' '.join(rest[3:]))}' in a VIP")
        self.vips.append(vip)

    def _dip(self, interface: str, rest: List[str]) -> None:
        if rest[:1] and rest[0].lower() == "interface-ip":
            return  # (the address of the interface as a DIP for incoming traffic)
        if len(rest) < 2 or not is_number(rest[0]):
            raise _Unread(f"a DIP pool of interface '{_short(interface)}'")
        problems: List[str] = []
        if rest[1].lower() == "shift-from":
            self.dips[rest[0]] = (interface, "", "", ["a DIP pool that shifts addresses one to one (shift-from)"])
            return
        first = rest[1]
        two = len(rest) > 2 and parse_literal(rest[2]) is not None
        last, extra = (rest[2], rest[3:]) if two else (first, rest[2:])
        one, other = parse_literal(first), parse_literal(last)
        if one is None or other is None or one[1] != one[2] or other[1] != other[2] or one[0] != 4 or other[1] < one[1]:
            raise _Unread(f"a DIP pool of interface '{_short(interface)}'")
        for word in extra:
            if word.lower() == "fix-port":
                problems.append("fix-port")  # (no port translation: read where the pool is used)
            elif word.lower() not in ("random-port", "incoming"):
                problems.append(f"'{_short(word, 20)}' in a DIP pool")
        self.dips[rest[0]] = (interface, first, last, problems)

    def _address_line(self, words: List[str]) -> None:
        if len(words) < 5:
            raise _Unread(f"address line '{_short(' '.join(words), 60)}'")
        zone, name, values = self.zone(words[2]), words[3], words[4:]
        book = self.books.setdefault(zone, {})
        if values[0].lower() == "comment":
            self.book_comments[(zone, name)] = " ".join(values[1:])
            return
        # An address with a dotted mask, an address with a prefix length, or a host name; then an optional comment.
        if len(values) >= 2 and parse_literal(values[1]) is not None and "." in values[1] and "/" not in values[0]:
            value, comment = [values[0], values[1]], values[2:]
        else:
            value, comment = [values[0]], values[1:]
        book.setdefault(name, []).append(" ".join(value))
        if comment:
            self.book_comments[(zone, name)] = " ".join(comment)

    def _group_line(self, words: List[str]) -> None:
        kind = words[2].lower()
        if kind == "address" and len(words) >= 5:
            zone, name = self.zone(words[3]), words[4]
            members = self.groups.setdefault(zone, {}).setdefault(name, [])
            if len(words) >= 7 and words[5].lower() == "add":
                members.append(words[6])
        elif kind == "service":
            members = self.service_groups.setdefault(words[3], [])
            if len(words) >= 6 and words[4].lower() == "add":
                members.append(words[5])

    def _route(self, words: List[str], vrouter: str) -> None:
        if not words or parse_literal(words[0]) is None:
            return
        interface = words[words.index("interface") + 1] if "interface" in words[:-1] else ""
        gateway = words[words.index("gateway") + 1] if "gateway" in words[:-1] else ""
        preference = int(words[words.index("preference") + 1]) if "preference" in words[:-1] and is_number(words[words.index("preference") + 1]) else 20
        self.routes.append((words[0], interface, gateway, preference))

    # -- policies ---------------------------------------------------------------------------------

    def _policy_line(self, head: str, words: List[str], tagged: List[Word], number: int) -> None:
        if head == "unset":
            if len(words) >= 4 and words[2].lower() == "id" and is_number(words[3]):
                if len(words) == 4:
                    self.policies.pop(int(words[3]), None)
                    self.order = [n for n in self.order if n != int(words[3])]
                elif words[4].lower() == "disable" and int(words[3]) in self.policies:
                    self.policies[int(words[3])].disabled = False
            elif words[2:3] == ["default-permit-all"]:
                self.default_permit = False
            return
        rest = tagged[2:]
        if not rest:
            return
        first = rest[0][0].lower()
        if first == "default-permit-all":
            self.default_permit = True
            return
        if first == "move" and len(rest) == 4 and is_number(rest[1][0]) and rest[2][0].lower() in ("before", "after") and is_number(rest[3][0]):
            self._move(int(rest[1][0]), rest[2][0].lower(), int(rest[3][0]), number)
            return
        policy_id: Optional[int] = None
        is_global = False
        if first == "global":
            is_global, rest = True, rest[1:]
        if rest and rest[0][0].lower() == "id" and len(rest) > 1 and is_number(rest[1][0]):
            policy_id, rest = int(rest[1][0]), rest[2:]
        if policy_id is not None and policy_id in self.policies and rest and rest[0][0].lower() in ("disable", "application", "name"):
            policy = self.policies[policy_id]
            if rest[0][0].lower() == "disable":
                policy.disabled = True
            elif rest[0][0].lower() == "application" and len(rest) > 1:
                policy.application = rest[1][0]
            elif len(rest) > 1 and not any(w.lower() in ("from", "to") for w, _ in rest):
                policy.name = rest[1][0]
            else:
                self._define(policy_id, rest, is_global, number)
            return
        if policy_id is None:
            policy_id = max(self.policies, default=0) + 1
        self._define(policy_id, rest, is_global, number)

    def _move(self, moved: int, where: str, anchor: int, number: int) -> None:
        if moved not in self.policies or anchor not in self.policies or moved == anchor:
            self.not_read.append(f"line {number}: 'set policy move {moved} {where} {anchor}' for a policy that is not defined")
            return
        self.order.remove(moved)
        position = self.order.index(anchor) + (1 if where == "after" else 0)
        self.order.insert(position, moved)
        self.moved += 1

    def _define(self, policy_id: int, rest: List[Word], is_global: bool, number: int) -> None:
        policy = _Pol(policy_id, number)
        place: Optional[Tuple[str, int]] = None
        index = 0

        def word(offset: int = 0) -> str:
            return rest[index + offset][0] if index + offset < len(rest) else ""

        while index < len(rest) and word().lower() in ("name", "top", "before"):
            key = word().lower()
            if key == "name":
                policy.name, index = word(1), index + 2
            elif key == "top":
                place, index = ("top", 0), index + 1
            elif is_number(word(1)):
                place, index = ("before", int(word(1))), index + 2
            else:
                break
        if is_global and word().lower() != "from":
            policy.src_zone = policy.dst_zone = _GLOBAL
        else:
            if word().lower() != "from" or word(2).lower() != "to" or not word(3):
                raise _Unread(f"policy {policy_id}: no 'from ZONE to ZONE'")
            policy.src_zone, policy.dst_zone = self.zone(word(1)), self.zone(word(3))
            index += 4
        for side in ("source", "destination"):
            negate = word() == "!"
            if negate:
                index += 1
            if not word():
                raise _Unread(f"policy {policy_id}: no {side} address")
            (policy.sources if side == "source" else policy.destinations).append(word())
            if side == "source":
                policy.negate_source = negate
            else:
                policy.negate_destination = negate
            index += 1
        if not word():
            raise _Unread(f"policy {policy_id}: no service")
        policy.services.append(word())
        index += 1
        while index < len(rest):
            key = word().lower()
            if key == "nat":
                index = self._nat_words(policy, rest, index + 1)
                continue
            if key in _ACTIONS and not policy.action:
                policy.action = key
                index += 1
                if key == "tunnel":
                    policy.problems.append("a policy-based VPN (tunnel): the traffic is allowed into a VPN tunnel only")
                    break
                continue
            if key == "log":
                policy.log = True
            elif key == "schedule" and word(1):
                policy.schedule = word(1)
                index += 1
            elif key == "alarm" and is_number(word(1)):
                index += 2 if is_number(word(2)) else 1
            elif key in _IGNORED_WORDS:
                pass
            elif key == "traffic":
                policy.handling["traffic"] = " ".join(w for w, _ in rest[index + 1 :])
                break
            elif key in _PROFILE_WORDS:
                policy.profiles[key] = word(1) or "yes"
                index += 1
            elif key in ("auth", "webauth"):
                policy.problems.append(f"user authentication ('{key}'), which is not converted")
                break
            elif key == "pair-policy":
                index += 1
            else:
                policy.problems.append(f"'{_short(' '.join(w for w, _ in rest[index:]), 40)}', which this parser does not read")
                break
            index += 1
        if not policy.action:
            policy.problems.append("the policy has no action (permit, deny or reject)")
        if policy_id in self.policies:
            self.not_read.append(f"line {number}: policy {policy_id} defined twice; the later definition was read")
            old = self.policies[policy_id]
            policy.disabled, policy.application = old.disabled, old.application
        else:
            if place is None:
                self.order.append(policy_id)
            elif place[0] == "top":
                self.order.insert(0, policy_id)
            elif place[1] in self.order:
                self.order.insert(self.order.index(place[1]), policy_id)
                self.moved += 1
            else:
                self.order.append(policy_id)
                policy.problems.append(f"placed before policy {place[1]}, which is not defined")
        self.policies[policy_id] = policy

    def _nat_words(self, policy: _Pol, rest: List[Word], index: int) -> int:
        nat = policy.nat or _Nat()
        policy.nat = nat
        while index < len(rest):
            key = rest[index][0].lower()
            if key == "src":
                nat.src = True
                index += 1
                if index + 1 < len(rest) and rest[index][0].lower() == "dip-id":
                    nat.dip = rest[index + 1][0]
                    index += 2
            elif key == "dst" and index + 2 < len(rest) and rest[index + 1][0].lower() == "ip":
                nat.dst = rest[index + 2][0]
                if parse_literal(nat.dst) is None or "/" in nat.dst:
                    nat.problems.append(f"translated destination '{_short(nat.dst, 30)}'")
                index += 3
                if index + 1 < len(rest) and rest[index][0].lower() == "to":
                    nat.problems.append("a range of translated destinations (nat dst ip ... to ...)")
                    index += 2
                if index + 1 < len(rest) and rest[index][0].lower() == "port":
                    nat.dst_port = rest[index + 1][0]
                    if not is_number(nat.dst_port) or not 0 < int(nat.dst_port) < 65536:
                        nat.problems.append(f"translated port '{_short(nat.dst_port, 20)}'")
                    index += 2
            else:
                break
        if not nat.src and not nat.dst:
            policy.problems.append("'nat' without src or dst")
        return index

    def _policy_context(self, policy_id: int, words: List[str], tagged: List[Word]) -> None:
        policy = self.policies.get(policy_id)
        if policy is None or len(words) < 2:
            return
        head, key = words[0].lower(), words[1].lower()
        values = words[2:]
        if head == "set" and key in ("src-address", "dst-address", "service") and values:
            if values[0].lower() == "negate" and len(values) == 1 and key != "service":
                if key == "src-address":
                    policy.negate_source = True
                else:
                    policy.negate_destination = True
                return
            target = {"src-address": policy.sources, "dst-address": policy.destinations, "service": policy.services}[key]
            if values[0] not in target:
                target.append(values[0])
        elif head == "unset" and key in ("src-address", "dst-address", "service") and values:
            target = {"src-address": policy.sources, "dst-address": policy.destinations, "service": policy.services}[key]
            if values[0] in target and len(target) > 1:
                target.remove(values[0])
        elif head == "set" and key == "log":
            policy.log = True
        elif head == "set" and key in ("count", "alarm"):
            return
        elif head == "set" and key == "application" and values:
            policy.application = values[0]
        else:
            policy.problems.append(f"'{_short(' '.join(words), 40)}' in the policy, which this parser does not read")

    # -- objects ----------------------------------------------------------------------------------

    def _definition(self, zone: str, name: str) -> Tuple[object, ...]:
        if name in self.books.get(zone, {}):
            return ("address", tuple(self.books[zone][name]))
        return ("group", tuple(self.groups.get(zone, {}).get(name, [])))

    def _model_name(self, zone: str, name: str) -> str:
        defined = [z for z in list(self.books) + list(self.groups)
                   if name in self.books.get(z, {}) or name in self.groups.get(z, {})]  # fmt: skip
        alike = len({self._definition(z, name) for z in defined}) <= 1 and all(name in self.books.get(z, {}) for z in defined)
        base = name if alike or len(set(defined)) <= 1 else f"{name} ({zone})"
        if base != name and name not in self.split_names:
            self.split_names.add(name)
            self.report.note(Severity.INFO, "SCREENOS_ZONE_OBJECT",
                             f"the address name '{_short(name)}' stands for different addresses in the books of zones "
                             f"{', '.join(sorted(set(defined)))}; each is kept as '{_short(name)} (zone)'")  # fmt: skip
        if parse_literal(base) is not None or base.lower() in (ANY, "application-default"):
            base = f"{base} (object)"
        return base

    def address(self, name: str, zone: str) -> Optional[str]:
        """The model name for an address name a policy uses on the side of ``zone``; None when it is not defined."""
        low = name.lower()
        if low == "any":
            return ANY
        if low == "any-ipv4":
            return ANY_V4
        if low == "any-ipv6":
            return ANY_V6
        if name in self.nat_objects:
            return self.nat_objects[name]
        for book in ([zone] if zone != _GLOBAL else []) + [_GLOBAL]:
            if name in self.books.get(book, {}) or name in self.groups.get(book, {}):
                return self._make(book, name, 0)
        return None

    def _make(self, zone: str, name: str, depth: int) -> str:
        key = (zone, name)
        if key in self.made:
            return self.made[key]
        model = self._model_name(zone, name)
        self.made[key] = model
        if model in self.p.addresses or model in self.p.address_groups:
            return model  # (the same definition in another zone's book)
        if name in self.books.get(zone, {}):
            self.p.addresses[model] = self._value(model, self.books[zone][name], self.book_comments.get(key, ""))
            return model
        if depth > _MAX_NESTING or key in self.resolving:
            self.p.address_groups[model] = AddressGroup(model, [], unsupported="address groups nested more than 64 deep, or in a circle")
            return model
        self.resolving.add(key)
        members: List[str] = []
        problem = ""
        for member in self.groups[zone][name]:
            if member in self.books.get(zone, {}) or member in self.groups.get(zone, {}):
                members.append(self._make(zone, member, depth + 1))
            elif member.lower() == "any":
                problem = "it holds 'Any'"
            else:
                problem = f"it holds '{_short(member)}', which is not in the address book of zone '{zone}'"
                self.missing.add(member)
        self.resolving.discard(key)
        self.p.address_groups[model] = AddressGroup(model, [] if problem else transform.dedupe(members),
                                                    unsupported=problem or ("" if members else "an address group without members"))  # fmt: skip
        if problem or not members:
            self.report.add("address-group", model, Severity.REVIEW, "UNSUPPORTED_GROUP", self.p.address_groups[model].unsupported)
        return model

    def _value(self, name: str, values: List[str], comment: str) -> Address:
        if len(values) != 1:
            raw = "an address defined twice" if values else "an address without a value"
            self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
            return Address(name, AddressKind.UNSUPPORTED, "", comment, raw=raw)
        words = values[0].split()
        if len(words) == 2:
            network = netmask_to_cidr(words[0], words[1])
            start = parse_literal(words[0])
            if network is not None and start is not None and start[0] == 4:
                return Address(name, AddressKind.NETWORK, network, comment)
            raw = f"address '{_short(values[0])}' (a wildcard mask, or not an address)"
        else:
            interval = parse_literal(words[0])
            if interval is not None and "-" not in words[0]:
                text = words[0] if "/" in words[0] else f"{words[0]}/{32 if interval[0] == 4 else 128}"
                return Address(name, AddressKind.NETWORK, interval_text(interval) if "/" in words[0] else text, comment)
            if re.fullmatch(r"[A-Za-z0-9*]([A-Za-z0-9.*-]*[A-Za-z0-9])?", words[0]) and "." in words[0] and "*" not in words[0]:
                return Address(name, AddressKind.FQDN, words[0], comment)
            raw = f"address '{_short(values[0])}'"
        self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
        return Address(name, AddressKind.UNSUPPORTED, "", comment, raw=raw)

    def service(self, name: str) -> Optional[str]:
        """The model name of a service a policy names; None when it is not defined anywhere."""
        if name.upper() == "ANY":
            return ANY
        if name in self.p.services or name in self.p.service_groups:
            return name
        if name in self.services:
            entries, problem = self._service_entries(self.services[name])
            self.p.services[name] = Service(name, entries, unsupported=problem)
            if problem:
                self.report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{problem}: not converted")
            return name
        if name in self.service_groups:
            if name in self.svc_resolving or len(self.svc_resolving) > _MAX_NESTING:
                return None
            self.svc_resolving.add(name)
            members: List[str] = []
            problem = ""
            for member in self.service_groups[name]:
                found = self.service(member)
                if found is None or found == ANY:
                    problem = f"it holds '{_short(member)}', which " + ("is 'ANY'" if found == ANY else "is not defined, or holds the group")
                    break
                members.append(found)
            self.svc_resolving.discard(name)
            if not members and not problem:
                problem = "a service group without members"
            if problem:
                self.p.services[name] = Service(name, [], unsupported=problem)
                self.report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{problem}: not converted")
            else:
                self.p.service_groups[name] = ServiceGroup(name, transform.dedupe(members))
            return name
        known = name if name in PREDEFINED or name in _DOUBTFUL else next((k for k in list(PREDEFINED) + list(_DOUBTFUL) if k.lower() == name.lower()), "")
        if known in _DOUBTFUL or any(name.upper().startswith(prefix) for prefix in _RPC):
            why = _DOUBTFUL.get(known, "it matches remote procedure calls by program or UUID, which FWShift cannot write")
            self.p.services[name] = Service(name, [], builtin="screenos", unsupported=f"the predefined service {name}: {why}")
            self.predefined_used.add(name)
            return name
        if known in PREDEFINED:
            entries = [ServiceEntry(protocol, ports, icmp_type=kind, icmp_code=code, ip_protocol=number)
                       for protocol, ports, kind, code, number in PREDEFINED[known]]  # fmt: skip
            self.p.services[name] = Service(name, entries, builtin="screenos")
            self.predefined_used.add(name)
            return name
        return None

    @staticmethod
    def _ports(text: str) -> Optional[str]:
        """``0-65535`` -> "" (every port), ``80-80`` -> "80"; None when it is no port range."""
        first, _, last = text.partition("-")
        last = last or first
        if not (is_number(first) and is_number(last)) or int(first) > int(last) or int(last) > 65535:
            return None
        if int(first) == 0 and int(last) == 65535:
            return ""
        return first if first == last else f"{first}-{last}"

    def _service_entries(self, lines: List[List[str]]) -> Tuple[List[ServiceEntry], str]:
        entries: List[ServiceEntry] = []
        for words in lines:
            key = words[0].lower()
            if key in ("timeout", "group", "comment"):
                continue
            if key not in ("protocol", "+") or len(words) < 2:
                return [], f"'{_short(' '.join(words), 40)}', which this parser does not read"
            protocol, rest = words[1].lower(), words[2:]
            values: Dict[str, str] = {}
            index = 0
            while index + 1 < len(rest):
                values[rest[index].lower()] = rest[index + 1]
                index += 2
            if index < len(rest):
                return [], f"'{_short(' '.join(rest), 40)}' in a service"
            unknown = set(values) - {"src-port", "dst-port", "type", "code"}
            if unknown:
                return [], f"'{_short(sorted(unknown)[0], 30)}' in a service, which this parser does not read"
            if protocol in ("tcp", "udp"):
                src = self._ports(values.get("src-port", "0-65535"))
                dst = self._ports(values.get("dst-port", "0-65535"))
                if src is None or dst is None or "type" in values:
                    return [], f"ports that could not be read in '{_short(' '.join(words), 40)}'"
                entries.append(ServiceEntry(Protocol(protocol), dst_ports=dst, src_ports=src))
            elif protocol in ("icmp", "icmpv6", "icmp6"):
                icmp_type = values.get("type")
                code = values.get("code")
                if (icmp_type is not None and (not is_number(icmp_type) or int(icmp_type) > 255)) or (
                    code is not None and (not is_number(code) or int(code) > 255)):  # fmt: skip
                    return [], f"an ICMP type or code that could not be read in '{_short(' '.join(words), 40)}'"
                kind = Protocol.ICMP if protocol == "icmp" else Protocol.ICMP6
                entries.append(ServiceEntry(kind, icmp_type=int(icmp_type) if icmp_type is not None else None,
                                            icmp_code=int(code) if code is not None and icmp_type is not None else None))  # fmt: skip
            elif is_number(protocol) and int(protocol) < 256:
                if any(self._ports(values.get(side, "0-65535")) != "" for side in ("src-port", "dst-port")):
                    return [], f"ports on protocol {protocol}"
                number = int(protocol)
                entries.append(ServiceEntry({6: Protocol.TCP, 17: Protocol.UDP, 1: Protocol.ICMP}.get(number, Protocol.IP),
                                            ip_protocol=number if number not in (1, 6, 17) else None))  # fmt: skip
            else:
                return [], f"protocol '{_short(protocol, 20)}' (remote procedure calls and the like), which this parser does not read"
        if not entries:
            return [], "a service without a protocol"
        return entries, ""

    # -- building the model -----------------------------------------------------------------------

    def build(self) -> Policy:
        p = self.p
        if not (self.policies or self.books or self.interfaces or self.services):
            raise ParseError("no ScreenOS configuration found; expected the output of 'get config'")
        if self.default_permit:
            p.default_interzone = p.default_intrazone = Action.ALLOW
        self._zones()
        self._nat_objects()
        rules: List[Rule] = []
        globals_: List[Rule] = []
        infos: List[Tuple[_Pol, Rule]] = []
        for number in self.order:
            policy = self.policies[number]
            rule = self._rule(policy)
            infos.append((policy, rule))
            (globals_ if policy.src_zone == _GLOBAL and policy.dst_zone == _GLOBAL else rules).append(rule)
        p.rules = self._intrazone(rules, globals_) + rules + globals_
        self._nat(infos)
        self._zone_networks()
        self._notes()
        return p

    def _zones(self) -> None:
        for interface in self.interfaces.values():
            if interface.zone and interface.zone not in _NOT_ZONES:
                zone = self.p.zones.setdefault(interface.zone, Zone(interface.zone, []))
                zone.interfaces.append(interface.name)
        for policy in self.policies.values():
            for name in (policy.src_zone, policy.dst_zone):
                if name and name not in _NOT_ZONES:
                    self.p.zones.setdefault(name, Zone(name, []))
        for zone in self.p.zones.values():
            zone.intrazone_allow = not self._blocks(zone.name) or self.default_permit

    def _blocks(self, zone: str) -> bool:
        return self.blocked.get(zone, zone in _BLOCKED_BY_DEFAULT)

    def _zone_of_address(self, address: str) -> str:
        """The zone an address lies in: of the interface whose network holds it, else of the interface of the most
        specific route to it; ``any`` when that is not known."""
        found = parse_literal(address)
        if found is None:
            return ANY
        zones = {i.zone for i in self.interfaces.values() for n in i.networks if i.zone and within([found], [n])}
        if len(zones) == 1:
            return zones.pop()
        if zones:
            return ANY
        best: Optional[Tuple[int, str]] = None
        for network, interface, _, _ in self.routes:
            route = parse_literal(network)
            if route is None or not within([found], [route]):
                continue
            if best is None or size(route) < best[0]:
                best = (size(route), interface)
        if best is not None and best[1] in self.interfaces and self.interfaces[best[1]].zone:
            return self.interfaces[best[1]].zone
        return ANY

    def _nat_objects(self) -> None:
        """Objects for the MIPs, VIPs and DIPs, which policies name and NAT rules translate to."""
        for interface, mapped, host, netmask in self.mips:
            name = f"MIP({mapped})"
            network = netmask_to_cidr(mapped, netmask)
            if network is None or parse_literal(mapped) is None:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"MIP {mapped} netmask {netmask}")
            else:
                self.p.addresses[name] = Address(name, AddressKind.NETWORK, network, f"MIP on {interface}: {host}", builtin="screenos")
            self.nat_objects[name] = name
        for vip in self.vips:
            address = vip.address or self.interfaces.get(vip.interface, _Interface(vip.interface)).address
            name = f"VIP({vip.address or vip.interface})"
            if name in self.p.addresses:
                continue
            if address and parse_literal(address) is not None:
                self.p.addresses[name] = Address(name, AddressKind.NETWORK, f"{address}/32", f"VIP on {vip.interface}", builtin="screenos")
            else:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"the VIP of interface {vip.interface}, whose address is not known")
            self.nat_objects[name] = name

    def _rule(self, policy: _Pol) -> Rule:
        label = policy.name if policy.name and policy.name not in self.rule_names else f"policy-{policy.number}"
        label = label if label not in self.rule_names else f"policy-{policy.number}"
        self.rule_names.add(label)
        rule = Rule(name=label, origin=label, log_end=policy.log, schedule=policy.schedule)
        rule.source_ids = {"screenos.policy_id": str(policy.number)}
        rule.description = policy.name if policy.name and policy.name != label else ""
        rule.action = _ACTIONS.get(policy.action, Action.DROP)
        rule.enabled = not policy.disabled
        rule.profiles = dict(policy.profiles)
        rule.handling = dict(policy.handling)
        problems = list(policy.problems)
        src, dst = policy.src_zone, policy.dst_zone
        is_global = src == _GLOBAL and dst == _GLOBAL
        if is_global:
            rule.src_zones = rule.dst_zones = [ANY]
        elif _GLOBAL in (src, dst):
            # It decides nothing on ScreenOS: written disabled, as a disabled rule decides nothing either.
            rule.src_zones = [ANY] if src == _GLOBAL else [src]
            rule.dst_zones = [ANY] if dst == _GLOBAL else [dst]
            if rule.enabled:
                rule.enabled = False
                self.report.add("rule", label, Severity.REVIEW, "SCREENOS_GLOBAL_ZONE",
                                f"the policy is from zone '{src}' to zone '{dst}': a policy between a zone and the Global zone "
                                "matches no traffic (global policies are from Global to Global). It is written disabled")  # fmt: skip
        else:
            rule.src_zones, rule.dst_zones = [src], [dst]
        for name in (src, dst):
            if name.lower() == ANY:
                problems.append("a zone named 'any', which cannot be told from every zone")
        rule.sources = self._names(policy.sources, src if not is_global else _GLOBAL, problems)
        rule.destinations = self._names(policy.destinations, dst if not is_global else _GLOBAL, problems)
        services: List[str] = []
        for name in policy.services:
            found = self.service(name)
            if found is None:
                problems.append(f"service '{_short(name)}' is not in the configuration or in FWShift's table of predefined services")
                self.missing.add(name)
            else:
                services.append(found)
        rule.services = [ANY] if ANY in services or not services else transform.dedupe(services)
        rule.negate_source, rule.negate_destination = policy.negate_source, policy.negate_destination
        if (rule.negate_source and ANY in rule.sources) or (rule.negate_destination and ANY in rule.destinations):
            problems.append("a negated 'Any', which matches nothing")
        if policy.nat is not None:
            rule.handling["nat"] = "policy-based NAT"
        if policy.application:
            rule.handling["application"] = policy.application
            self.report.add("rule", label, Severity.INFO, "SCREENOS_APPLICATION",
                            f"the policy hands its traffic to the application layer gateway '{_short(policy.application)}'; "
                            "that is not converted (the targets choose their helpers by port)")  # fmt: skip
        for member in rule.destinations:
            for vip in self.vips:
                if member == f"VIP({vip.address or vip.interface})" and self._vip_port(vip) not in (str(vip.port), None):
                    self.report.add("rule", label, Severity.REVIEW, "SCREENOS_VIP_PORT",
                                    f"{member} maps port {vip.port} to the port of service '{_short(vip.service)}' on "
                                    f"{vip.host}; whether the services of this policy are matched before or after that "
                                    "translation is not known. The rule keeps its services as they are")  # fmt: skip
        rule.unsupported = transform.dedupe(problems)
        rule.scope = RuleScope.UNIVERSAL
        return rule

    def _names(self, names: Sequence[str], zone: str, problems: List[str]) -> List[str]:
        out: List[str] = []
        for name in names:
            found = self.address(name, zone)
            if found is None:
                problems.append(f"address '{_short(name)}' is not in the address book of zone '{zone}' or of the Global zone")
                self.missing.add(name)
            else:
                out.append(found)
        if ANY in out:
            return [ANY]
        return transform.dedupe(out) or [ANY]

    def _intrazone(self, rules: List[Rule], globals_: List[Rule]) -> List[Rule]:
        """Rules for the zones that do not block traffic inside them: it passes without a policy."""
        out: List[Rule] = []
        global_deny = any(r.enabled and r.action != Action.ALLOW for r in globals_)
        for zone in self.p.zones.values():
            if self._blocks(zone.name):
                continue
            own = [r for r in rules if r.src_zones == [zone.name] and r.dst_zones == [zone.name]]
            for rule in own:
                if rule.enabled:
                    rule.enabled = False
                    self.report.add("rule", rule.origin, Severity.REVIEW, "SCREENOS_INTRAZONE_IGNORED",
                                    f"zone '{zone.name}' does not block traffic inside it ('set zone \"{zone.name}\" block' is not "
                                    "set): ScreenOS passes that traffic without looking at policies, so this policy decides "
                                    "nothing. It is written disabled")  # fmt: skip
            if not own and not global_deny:
                continue
            name = f"intrazone-{zone.name}"
            while name in self.rule_names:
                name += "-2"
            self.rule_names.add(name)
            rule = Rule(name=name, origin=name, src_zones=[zone.name], dst_zones=[zone.name], log_end=False,
                        description=f"ScreenOS: traffic inside zone {zone.name}, which does not block it, passes without a policy")  # fmt: skip
            out.append(rule)
            self.report.add("rule", name, Severity.INFO, "SCREENOS_INTRAZONE_ALLOW",
                            f"zone '{zone.name}' does not block traffic inside it: ScreenOS passes it without a policy. This "
                            "rule, ahead of the others, says so")  # fmt: skip
        return out

    # -- NAT --------------------------------------------------------------------------------------

    def _vip_port(self, vip: _Vip) -> Optional[str]:
        """The port a VIP sends its traffic to: the destination port of its service, when that is one port."""
        found = self.service(vip.service)
        if found is None or found == ANY:
            return None
        service = self.p.services.get(found)
        if service is None or service.unsupported or len({(e.protocol, e.dst_ports) for e in service.entries}) != 1:
            return None
        entry = service.entries[0]
        if entry.protocol not in (Protocol.TCP, Protocol.UDP) or not is_number(entry.dst_ports):
            return None
        return entry.dst_ports

    def _dip_object(self, number: str) -> str:
        """The object for the addresses of a DIP pool, made where a policy uses it."""
        interface, first, last, _ = self.dips[number]
        name = f"DIP({number})"
        if name not in self.p.addresses:
            if not first:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"DIP pool {number} on {interface}")
            else:
                self.p.addresses[name] = Address(name, AddressKind.RANGE if first != last else AddressKind.NETWORK,
                                                 f"{first}-{last}" if first != last else f"{first}/32", f"DIP pool {number} on {interface}")  # fmt: skip
        return name

    def _egress(self, zone: str) -> SourceNat:
        members = [i for i in self.interfaces.values() if i.zone == zone]
        if len(members) != 1:
            return SourceNat(SnatKind.INTERFACE)
        return SourceNat(SnatKind.INTERFACE, interface=members[0].name, interface_address=members[0].address)

    def _new_nat(self, name: str, **fields: object) -> NatRule:
        base, counter = name, 2
        while name in self.nat_names:
            name, counter = f"{base}-{counter}", counter + 1
        self.nat_names.add(name)
        nat = NatRule(name=name, **fields)  # type: ignore[arg-type]
        nat.origin = name
        nat.combines = True  # a MIP or VIP for the destination and a policy's nat src for the source can both apply
        return nat

    def _nat(self, infos: List[Tuple[_Pol, Rule]]) -> None:
        static: List[NatRule] = self._mip_rules() + self._vip_rules() + self._mode_rules()
        policy_rules: List[NatRule] = []
        for position, (policy, rule) in enumerate(infos):
            if policy.nat is None:
                continue
            made = self._policy_nat(policy, rule)
            for nat in made:
                exempt = self._earlier(infos, position, rule, nat, bool(static))
                policy_rules += exempt
            policy_rules += made
        self.p.nat_rules = policy_rules + static

    def _policy_nat(self, policy: _Pol, rule: Rule) -> List[NatRule]:
        nat_spec = policy.nat
        assert nat_spec is not None
        problems = list(nat_spec.problems)
        if rule.unsupported:
            problems.append(f"the policy it belongs to ({rule.name}) is not converted")
        if rule.negate_source or rule.negate_destination:
            problems.append("NAT of a policy with a negated address")
        if rule.action != Action.ALLOW:
            return []  # (NAT on a policy that does not permit translates nothing)
        source: Optional[SourceNat] = None
        if nat_spec.src:
            if nat_spec.dip:
                dip = self.dips.get(nat_spec.dip)
                if dip is None:
                    problems.append(f"DIP pool {nat_spec.dip}, which is not in the configuration")
                else:
                    interface, first, last, dip_problems = dip
                    problems += [p for p in dip_problems if p != "fix-port"]
                    one = first == last
                    kind = SnatKind.DYNAMIC if "fix-port" in dip_problems and not one else SnatKind.DYNAMIC_PORT
                    source = SourceNat(kind, [self._dip_object(nat_spec.dip)])
            else:
                source = self._egress(policy.dst_zone) if policy.dst_zone != _GLOBAL else SourceNat(SnatKind.INTERFACE)
        destination = DestNat(nat_spec.dst, nat_spec.dst_port) if nat_spec.dst else None
        out: List[NatRule] = []
        for service in rule.services:
            nat = self._new_nat(f"nat-{rule.name}", src_zones=list(rule.src_zones), dst_zones=list(rule.dst_zones),
                                sources=list(rule.sources), destinations=list(rule.destinations), service=service,
                                source_translation=source, destination_translation=destination, enabled=rule.enabled,
                                description=f"policy-based NAT of {rule.name}")  # fmt: skip
            nat.unsupported = transform.dedupe(problems)
            out.append(nat)
        return out

    def _earlier(self, infos: List[Tuple[_Pol, Rule]], position: int, rule: Rule, nat: NatRule, other_nat: bool) -> List[NatRule]:
        """No-NAT rules for the policies above that permit part of this traffic without NAT: they take it first."""
        out: List[NatRule] = []
        for policy, earlier in infos[:position]:
            if policy.nat is not None or earlier.action != Action.ALLOW or not earlier.enabled or earlier.unsupported:
                continue
            if earlier.src_zones != rule.src_zones and ANY not in earlier.src_zones:
                continue
            if earlier.dst_zones != rule.dst_zones and ANY not in earlier.dst_zones:
                continue
            if not self._meet(earlier.sources, nat.sources) or not self._meet(earlier.destinations, nat.destinations):
                continue
            if other_nat or earlier.negate_source or earlier.negate_destination:
                self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_OVERLAP",
                                f"policy '{earlier.name}' above passes part of this traffic without NAT. A no-NAT rule for it "
                                "would also stop the MIPs and interfaces in NAT mode from translating it: none was added, so "
                                "this rule translates that traffic too")  # fmt: skip
                continue
            for service in earlier.services:
                exempt = self._new_nat(f"nonat-{earlier.name}", src_zones=list(earlier.src_zones), dst_zones=list(earlier.dst_zones),
                                       sources=list(earlier.sources), destinations=list(earlier.destinations), service=service,
                                       enabled=earlier.enabled, description=f"policy {earlier.name} passes this without NAT")  # fmt: skip
                self.report.add("nat", exempt.origin, Severity.INFO, "NAT_EXEMPTION",
                                f"policy '{earlier.name}' passes this traffic without NAT ahead of the policy with NAT "
                                f"'{rule.name}': a no-NAT rule says so")  # fmt: skip
                out.append(exempt)
        return out

    def _meet(self, a: List[str], b: List[str]) -> bool:
        sets: List[List[Interval]] = []
        for members in (a, b):
            intervals: List[Interval] = []
            for member in members:
                found = [FULL_V4, FULL_V6] if member == ANY else transform.address_intervals(self.p, member)
                if found is None:
                    return True
                intervals += found
            sets.append(intervals)
        return overlaps(sets[0], sets[1])

    def _mip_rules(self) -> List[NatRule]:
        out: List[NatRule] = []
        for interface, mapped, host, netmask in self.mips:
            name = f"MIP({mapped})"
            zone = self.interfaces[interface].zone if interface in self.interfaces and self.interfaces[interface].zone else ANY
            real = netmask_to_cidr(host, netmask)
            nat = self._new_nat(f"mip-{mapped}", src_zones=[self._zone_of_address(host)], dst_zones=[zone],
                                description=f"MIP {mapped} on {interface}")  # fmt: skip
            start = parse_literal(host)
            if real is None or start is None or start[0] != 4 or (parse_literal(real) or start)[1] != start[1]:
                nat.unsupported.append(f"MIP host '{_short(host, 30)}' with netmask '{_short(netmask, 20)}'")
            else:
                nat.sources = [host if real.endswith("/32") else real]
                nat.source_translation = SourceNat(SnatKind.STATIC, [name], bidirectional=True)
            if zone == ANY:
                nat.unsupported.append(f"the MIP's interface '{_short(interface)}' is in no zone")
            out.append(nat)
        return out

    def _vip_rules(self) -> List[NatRule]:
        out: List[NatRule] = []
        for vip in self.vips:
            name = f"VIP({vip.address or vip.interface})"
            zone = self.interfaces[vip.interface].zone if vip.interface in self.interfaces else ""
            # The VIP's address is on its interface: that zone is where the original destination is reached.
            nat = self._new_nat(f"vip-{vip.address or vip.interface}-{vip.port}", src_zones=[zone or ANY],
                                dst_zones=[zone or ANY], destinations=[name],
                                description=f"VIP {vip.address or vip.interface} port {vip.port} to {vip.service} on {vip.host}")  # fmt: skip
            nat.unsupported += vip.problems
            found = self.service(vip.service)
            service = self.p.services.get(found or "")
            protocols = {e.protocol for e in service.entries} if service is not None else set()
            port = self._vip_port(vip)
            if service is None or service.unsupported or len(protocols) != 1 or port is None:
                nat.unsupported.append(f"the VIP maps to service '{_short(vip.service)}', which is not one TCP or UDP port")
            else:
                protocol = protocols.pop()
                label = f"{protocol.value}-{vip.port}"
                if label not in self.p.services:
                    self.p.services[label] = Service(label, [ServiceEntry(protocol, dst_ports=str(vip.port))], "virtual port of a VIP")
                nat.service = label
                nat.destination_translation = DestNat(vip.host, "" if port == str(vip.port) else port)
            if not zone:
                nat.unsupported.append(f"the VIP's interface '{_short(vip.interface)}' is in no zone")
            out.append(nat)
        return out

    def _mode_rules(self) -> List[NatRule]:
        """Interfaces in NAT mode: what arrives on them and leaves by the Untrust zone gets the outgoing interface's address."""
        out: List[NatRule] = []
        untrust = self.zone("Untrust")
        done: Set[str] = set()
        for interface in self.interfaces.values():
            if interface.mode != "nat" or not interface.zone or interface.zone in done or interface.zone == untrust:
                continue
            done.add(interface.zone)
            nat = self._new_nat(f"nat-mode-{interface.zone}", src_zones=[interface.zone], dst_zones=[untrust],
                                source_translation=self._egress(untrust),
                                description=f"interfaces of zone {interface.zone} in NAT mode")  # fmt: skip
            others = [i.name for i in self.interfaces.values() if i.zone == interface.zone and i.mode != "nat"]
            if others:
                nat.unsupported.append(f"zone {interface.zone} has interfaces in NAT mode and others ({', '.join(others[:3])}): "
                                       "the model cannot tell traffic from one from traffic from the other")  # fmt: skip
            self.report.add("nat", nat.origin, Severity.INFO, "SCREENOS_NAT_MODE",
                            f"interface '{interface.name}' is in NAT mode: ScreenOS translates the source of what it receives "
                            "and sends to the Untrust zone to the address of the outgoing interface, unless a policy or a "
                            "MIP translates it")  # fmt: skip
            out.append(nat)
        return out

    # -- zone networks and notes ------------------------------------------------------------------

    def _zone_networks(self) -> None:
        routes: List[zonenets.Route] = []
        for interface in self.interfaces.values():
            routes += [zonenets.Route(network, interface.name, connected=True) for network in interface.networks]
        unread: List[str] = []
        for network, name, gateway, preference in self.routes:
            found = parse_literal(network)
            if found is None:
                continue
            if name:
                routes.append(zonenets.Route(found, name, parse_literal(gateway) if gateway else None, (preference, 0)))
            elif gateway and parse_literal(gateway) is not None:
                routes.append(zonenets.Route(found, "", parse_literal(gateway), (preference, 0)))
            else:
                unread.append(network)
        zone_of = {i.name: i.zone for i in self.interfaces.values() if i.zone and i.zone in self.p.zones}
        if not routes:
            return
        placed = zonenets.place(routes, zone_of, self.report, unread=unread)
        self.p.zone_networks, self.p.unzoned_networks = placed.zones, placed.unzoned

    def _notes(self) -> None:
        report = self.report
        if self.predefined_used:
            report.note(Severity.INFO, "SCREENOS_PREDEFINED",
                        "predefined services are not in the configuration; FWShift took these from its table: "
                        + ", ".join(sorted(self.predefined_used)))  # fmt: skip
        if self.missing:
            report.note(Severity.REVIEW, "OBJECTS_MISSING",
                        "names that policies or groups use are not in the configuration; what uses them is not converted: "
                        + ", ".join(sorted(self.missing)[:10]) + (" ..." if len(self.missing) > 10 else ""))  # fmt: skip
        if self.default_permit:
            report.note(Severity.INFO, "SCREENOS_DEFAULT_PERMIT",
                        "the default policy permits (set policy default-permit-all): what no policy matches is allowed")
        if self.moved:
            report.note(Severity.INFO, "SCREENOS_POLICY_ORDER",
                        f"{self.moved} policies were placed by 'set policy move', 'top' or 'before'; the rules are in the "
                        "order that results")  # fmt: skip
        if self.not_read:
            report.note(Severity.REVIEW, "SCREENOS_NOT_READ",
                        f"{len(self.not_read)} lines could not be read: " + "; ".join(self.not_read[:5])
                        + (" ..." if len(self.not_read) > 5 else ""))  # fmt: skip
        if self.vsys:
            report.note(Severity.REVIEW, "SCREENOS_VSYS",
                        "the configuration has virtual systems (" + ", ".join(self.vsys[:5]) + "); only the root system was "
                        "read. Export each one with 'enter vsys NAME' and 'get config'")  # fmt: skip
        mixed = [z.name for z in self.p.zones.values() if z.name in _BLOCKED_BY_DEFAULT and z.name not in self.blocked]
        if mixed:
            report.note(Severity.INFO, "SCREENOS_ZONE_BLOCK",
                        "these zones block traffic inside them by default, and the configuration does not say otherwise: "
                        + ", ".join(mixed))  # fmt: skip


class _Unread(Exception):
    """A line of a kind the parser reads, which it could not read."""
