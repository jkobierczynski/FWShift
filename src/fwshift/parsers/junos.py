# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Juniper parser: the configuration of an SRX (Junos OS) -> neutral model.

Reads ``show configuration | display set`` (``set`` and ``deactivate`` lines) or the configuration
in braces (``show configuration``), which is first flattened to the same lines.

How Junos differs from the model, and what is done about it:

* Security policies are kept per pair of zones (from-zone, to-zone), first match; global policies
  are looked at after the policies of the pair, first match; what none matches, the default policy
  decides (deny-all unless it says otherwise). Traffic inside one zone is a pair as well.
* Policies are looked up after static and destination NAT: they name the translated destination and
  the zone it is routed to. They are brought back to the original destination, as the model has it.
* Static and destination NAT come before the policy, source NAT after it; a connection can get one
  of each. Within a kind, the rule set of the most specific context (interface, then zone) applies,
  and in it the first rule that matches.
* An address name is looked up in the address book of the zone (a book attached to it, or the
  address book of the zone itself), then in the global one. The same name can mean different
  addresses in two zones: such objects are kept apart.
* Predefined applications (``junos-*``) are not in the configuration: those FWShift knows are taken
  from a table, and the report says so.
* What a ``deactivate`` line names is not in force.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import ANY, ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol, Rule
from ..model import RuleScope, Service, ServiceEntry, ServiceGroup, SnatKind, SourceNat, Zone
from ..netutil import interval_text, is_number, parse_literal
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_MAX_NESTING = 64
_TOP = ("system", "interfaces", "security", "applications", "routing-options", "protocols", "policy-options", "groups",
        "apply-groups", "snmp", "chassis", "version", "routing-instances", "firewall", "logical-systems", "schedulers",
        "services", "access", "forwarding-options", "class-of-service", "tenants", "event-options", "vlans")  # fmt: skip
_PROMPT = re.compile(r"^[ \t]*\{(primary|secondary|master|backup)(:node\d+|:\d+)?\}[ \t]*$", re.M)
_SET_LINE = re.compile(rb"^(set|deactivate) (" + b"|".join(word.encode() for word in _TOP) + rb")( |$)", re.M)
_BRACE = re.compile(rb"^(version [^;\n]+;|(system|security|interfaces|applications) \{)", re.M)

# Ports Junos knows by name (Batfish's list, with their numbers).
_PORTS = {"afs": 1483, "bgp": 179, "biff": 512, "bootpc": 68, "bootps": 67, "cmd": 514, "cvspserver": 2401, "dhcp": 67,
          "domain": 53, "eklogin": 2105, "ekshell": 2106, "exec": 512, "finger": 79, "ftp": 21, "ftp-data": 20, "http": 80,
          "https": 443, "ident": 113, "imap": 143, "kerberos-sec": 88, "klogin": 543, "kpasswd": 761, "krb-prop": 754,
          "krbupdate": 760, "kshell": 544, "ldap": 389, "ldp": 646, "login": 513, "mobileip-agent": 434, "mobilip-mn": 435,
          "msdp": 639, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ssn": 139, "nfsd": 2049, "nntp": 119, "ntalk": 518,
          "ntp": 123, "pop3": 110, "pptp": 1723, "printer": 515, "radacct": 1813, "radius": 1812, "rip": 520, "rkinit": 2108,
          "smtp": 25, "snmp": 161, "snmptrap": 162, "snpp": 444, "socks": 1080, "ssh": 22, "sunrpc": 111, "syslog": 514,
          "tacacs": 49, "tacacs-ds": 65, "talk": 517, "telnet": 23, "tftp": 69, "timed": 525, "who": 513, "xdmcp": 177}  # fmt: skip
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "icmpv6": 58, "gre": 47, "esp": 50, "ah": 51, "ospf": 89,
              "sctp": 132, "igmp": 2, "pim": 103, "vrrp": 112, "ipip": 4, "egp": 8, "rsvp": 46}  # fmt: skip
_ICMP_TYPES = {"echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5, "echo-request": 8,
               "router-advertisement": 9, "router-solicit": 10, "time-exceeded": 11, "parameter-problem": 12, "timestamp": 13,
               "timestamp-reply": 14, "info-request": 15, "info-reply": 16, "mask-request": 17, "mask-reply": 18}  # fmt: skip
_ICMP6_TYPES = {"destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3, "parameter-problem": 4, "echo-request": 128,
                "echo-reply": 129, "membership-query": 130, "membership-report": 131, "membership-termination": 132,
                "router-solicit": 133, "router-advertisement": 134, "neighbor-solicit": 135, "neighbor-advertisement": 136,
                "redirect": 137}  # fmt: skip
# The predefined applications FWShift takes as Juniper documents them: (protocol, destination ports, ICMP type).
JUNOS_APPLICATIONS: Dict[str, List[Tuple[Protocol, str, Optional[int], Optional[int]]]] = {
    "junos-http": [(Protocol.TCP, "80", None, None)], "junos-https": [(Protocol.TCP, "443", None, None)],
    "junos-ssh": [(Protocol.TCP, "22", None, None)], "junos-telnet": [(Protocol.TCP, "23", None, None)],
    "junos-ftp": [(Protocol.TCP, "21", None, None)], "junos-ftp-data": [(Protocol.TCP, "20", None, None)],
    "junos-tftp": [(Protocol.UDP, "69", None, None)], "junos-smtp": [(Protocol.TCP, "25", None, None)],
    "junos-pop3": [(Protocol.TCP, "110", None, None)], "junos-imap": [(Protocol.TCP, "143", None, None)],
    "junos-imaps": [(Protocol.TCP, "993", None, None)], "junos-dns-udp": [(Protocol.UDP, "53", None, None)],
    "junos-dns-tcp": [(Protocol.TCP, "53", None, None)], "junos-ntp": [(Protocol.UDP, "123", None, None)],
    "junos-syslog": [(Protocol.UDP, "514", None, None)], "junos-ldap": [(Protocol.TCP, "389", None, None)],
    "junos-ms-sql": [(Protocol.TCP, "1433", None, None)], "junos-ike": [(Protocol.UDP, "500", None, None)],
    "junos-ike-nat": [(Protocol.UDP, "4500", None, None)], "junos-radius": [(Protocol.UDP, "1812", None, None)],
    "junos-radacct": [(Protocol.UDP, "1813", None, None)], "junos-bgp": [(Protocol.TCP, "179", None, None)],
    "junos-ospf": [(Protocol.IP, "89", None, None)], "junos-gre": [(Protocol.IP, "47", None, None)],
    "junos-icmp-all": [(Protocol.ICMP, "", None, None)], "junos-icmp-ping": [(Protocol.ICMP, "", 8, None)],
    "junos-icmp6-all": [(Protocol.ICMP6, "", None, None)], "junos-tcp-any": [(Protocol.TCP, "", None, None)],
    "junos-udp-any": [(Protocol.UDP, "", None, None)], "junos-pptp": [(Protocol.TCP, "1723", None, None)],
    "junos-l2tp": [(Protocol.UDP, "1701", None, None)], "junos-nbname": [(Protocol.UDP, "137", None, None)],
    "junos-nbds": [(Protocol.UDP, "138", None, None)], "junos-netbios-session": [(Protocol.TCP, "139", None, None)],
    "junos-smb-session": [(Protocol.TCP, "445", None, None)],
}  # fmt: skip
JUNOS_SETS = {"junos-cifs": ["junos-netbios-session", "junos-smb-session"]}
# Applications whose definition differs between the sources FWShift was written from: not used.
_DOUBTFUL = {"junos-ping": "Juniper describes it as ICMP echo, other readers of Junos as every ICMP type"}


def looks_like_junos(data: bytes) -> bool:
    head = data[:2_000_000]
    return bool(_SET_LINE.search(head)) or bool(_BRACE.search(head))


def _words(line: str, number: int) -> List[str]:
    """The words of a set line; a quoted string is one word."""
    out: List[str] = []
    position, length = 0, len(line)
    while position < length:
        char = line[position]
        if char in " \t":
            position += 1
            continue
        if char == '"':
            position += 1
            word = []
            while position < length and line[position] != '"':
                if line[position] == "\\" and position + 1 < length:
                    position += 1
                word.append(line[position])
                position += 1
            if position >= length:
                raise ParseError(f"line {number}: a quoted string that is not closed")
            position += 1
            out.append("".join(word))
            continue
        start = position
        while position < length and line[position] not in " \t":
            position += 1
        out.append(line[start:position])
    return out


def _flatten(text: str) -> List[Tuple[int, List[str]]]:
    """The configuration in braces as set and deactivate lines (number of the line it came from, words)."""
    tokens: List[Tuple[int, str, bool]] = []  # (line, token, quoted)
    text = _PROMPT.sub("", text)
    position, length, number = 0, len(text), 1
    while position < length:
        char = text[position]
        if char == "\n":
            number += 1
            position += 1
        elif char in " \t\r":
            position += 1
        elif text.startswith("/*", position):
            end = text.find("*/", position + 2)
            if end < 0:
                raise ParseError(f"line {number}: a comment that is not closed")
            number += text.count("\n", position, end)
            position = end + 2
        elif char == "#":
            end = text.find("\n", position)
            position = length if end < 0 else end
        elif char in "{};[]":
            tokens.append((number, char, False))
            position += 1
        elif char == '"':
            position += 1
            chars: List[str] = []
            while position < length and text[position] != '"':
                if text[position] == "\\" and position + 1 < length:
                    position += 1
                if text[position] == "\n":
                    number += 1
                chars.append(text[position])
                position += 1
            if position >= length:
                raise ParseError(f"line {number}: a quoted string that is not closed")
            position += 1
            tokens.append((number, "".join(chars), True))
        else:
            start = position
            while position < length and text[position] not in " \t\r\n{};[]\"":
                position += 1
            tokens.append((number, text[start:position], False))
    out: List[Tuple[int, List[str]]] = []
    stack: List[Tuple[int, int]] = []  # (how many words the block adds to the path, how many lines there were when it opened)
    prefix: List[str] = []
    words: List[str] = []
    listed: Optional[List[str]] = None
    inactive = False
    line = 1
    for line, token, quoted in tokens:
        if len(out) > _MAX_LINES:
            raise ParseError(f"the configuration holds more than {_MAX_LINES} statements")
        if not quoted and token in ("inactive:", "protect:", "active:", "replace:", "delete:") and not words and listed is None:
            inactive = inactive or token == "inactive:"
            if token == "delete:":
                raise ParseError(f"line {line}: 'delete:' belongs to a file for 'load update', not to a configuration")
            continue
        if not quoted and token == "[":
            if listed is not None:
                raise ParseError(f"line {line}: a list inside a list")
            listed = []
            continue
        if not quoted and token == "]":
            if listed is None:
                raise ParseError(f"line {line}: ']' without '['")
            if any(word.startswith("\0LIST\0") for word in words):
                raise ParseError(f"line {line}: two lists in one statement")
            words.append("\0LIST\0" + "\0".join(listed))
            listed = None
            continue
        if listed is not None:
            listed.append(token)
            continue
        if not quoted and token == "{":
            if not words:
                raise ParseError(f"line {line}: '{{' without a statement")
            if any(word.startswith("\0LIST\0") for word in words):
                raise ParseError(f"line {line}: a list before '{{'")
            if len(stack) >= _MAX_NESTING:
                raise ParseError(f"line {line}: blocks nested more than {_MAX_NESTING} deep")
            if inactive:
                out.append((line, ["deactivate"] + prefix + words))
            stack.append((len(words), len(out)))
            prefix += words
            words, inactive = [], False
            continue
        if not quoted and token == "}":
            if words or not stack:
                raise ParseError(f"line {line}: '}}' where a statement is not finished")
            if not any(item[1][0] == "set" for item in out[stack[-1][1]:]):
                out.append((line, ["set"] + prefix))  # an empty block
            added, _ = stack.pop()
            del prefix[len(prefix) - added:]
            continue
        if not quoted and token == ";":
            if not words:
                continue
            expanded: List[List[str]] = [[]]
            for word in words:
                if word.startswith("\0LIST\0"):
                    items = [item for item in word[len("\0LIST\0"):].split("\0") if item]
                    expanded = [done + [item] for done in expanded for item in items] or expanded
                else:
                    expanded = [done + [word] for done in expanded]
            for item in expanded:
                out.append((line, ["set"] + prefix + item))
                if inactive:
                    out.append((line, ["deactivate"] + prefix + item))
            words, inactive = [], False
            continue
        words.append(token)
    if stack or words or listed is not None:
        raise ParseError(f"line {line}: the configuration ends inside a statement (a '{{' without '}}', or no ';')")
    return out


def _lines(data: bytes) -> List[Tuple[int, List[str]]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    if "\0" in text:
        raise ParseError("the configuration holds a NUL character: it is not a text file")
    set_form = any(re.match(r"(set|deactivate|delete|insert|activate) ", line) for line in text.splitlines()[:5000] if line.strip())
    if not set_form:
        return _flatten(text)
    out: List[Tuple[int, List[str]]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or re.fullmatch(r"\{(primary|secondary|master|backup)(:node\d+|:\d+)?\}", line):
            continue
        words = _words(line, number)
        if words[0] in ("set", "deactivate"):
            out.append((number, words))
        elif words[0] in ("delete", "insert", "activate", "rename", "replace", "copy"):
            raise ParseError(f"line {number}: '{words[0]}' belongs to a file of commands, not to the output of 'display set'")
        elif words[0] == "protect":
            continue
        else:
            raise ParseError(f"line {number}: not a line of 'show configuration | display set' (it starts with "
                             f"'{_short(words[0], 20)}')")  # fmt: skip
        if len(out) > _MAX_LINES:
            raise ParseError(f"the configuration holds more than {_MAX_LINES} lines")
    return out


def _short(text: str, limit: int = 40) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass
class _Policy:
    context: str  # "from to" or "global"
    name: str
    src_zone: str
    dst_zone: str
    lines: List[List[str]] = field(default_factory=list)  # words after "policy NAME"
    inactive: bool = False
    first: int = 0


@dataclass
class _NatRule:
    kind: str  # static, destination, source
    rule_set: str
    name: str
    lines: List[List[str]] = field(default_factory=list)
    inactive: bool = False


class _Reader:
    def __init__(self, lines: List[Tuple[int, List[str]]], report: Report) -> None:
        self.report = report
        self.p = Policy(vendor="junos", scope="root", default_intrazone=Action.DENY, default_interzone=Action.DENY, lookup_after_dnat=True)
        self.sets: List[List[str]] = []
        self.inactive: Set[Tuple[str, ...]] = set()
        for _, words in lines:
            if words[0] == "set":
                self.sets.append(words[1:])
            else:
                self.inactive.add(tuple(words[1:]))
        self.depths = sorted({len(path) for path in self.inactive})
        self.interface_zone: Dict[str, str] = {}
        self.books: Dict[str, Dict[str, List[str]]] = {}  # book -> address name -> its value words
        self.book_sets: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}  # book -> set -> [(kind, member)]
        self.attached: Dict[str, str] = {}  # zone -> book
        self.made: Dict[Tuple[str, str], str] = {}  # (book, name) -> model name
        self.apps: Dict[str, List[List[str]]] = {}
        self.app_sets: Dict[str, List[Tuple[str, str]]] = {}
        self.predefined_used: Set[str] = set()
        self.missing: Set[str] = set()
        self.not_read: List[str] = []
        self.host_policies: List[str] = []
        self.resolving: Set[Tuple[str, str]] = set()
        self.backs: List[Tuple[NatRule, NatRule]] = []

    def off(self, path: Sequence[str], start: int = 1) -> bool:
        """Whether a statement is not in force: it, or a level above it (from ``start`` words on), is deactivated."""
        return any(start <= k <= len(path) and tuple(path[:k]) in self.inactive for k in self.depths)

    # -- groups and parts not read ----------------------------------------------------------------

    def check_groups(self) -> None:
        applied = any(words[-2:-1] == ["apply-groups"] or words[:1] == ["apply-groups"] for words in self.sets)
        touching = sorted({words[1] for words in self.sets if words[:1] == ["groups"] and len(words) > 2
                           and words[2] in ("security", "applications")})  # fmt: skip
        inline = {tuple(words) for words in self.sets if words[:1] != ["groups"]}
        shown = all(tuple(words[2:]) in inline for words in self.sets
                    if words[:1] == ["groups"] and len(words) > 2 and words[2] in ("security", "applications"))  # fmt: skip
        if applied and touching and not shown:
            raise ParseError(
                f"the configuration takes parts of its security policy or applications from groups ({', '.join(touching[:4])}) "
                "with apply-groups. Export it with 'show configuration | display inheritance no-comments | display set', "
                "which writes them where they apply"
            )
        for words in self.sets:
            if words[:1] in (["logical-systems"], ["tenants"]) and "security" in words[2:4]:
                self.not_read.append(f"{words[0]} {words[1]}")
        self.not_read = sorted(set(self.not_read))

    # -- zones and address books ------------------------------------------------------------------

    def zones(self) -> None:
        for words in self.sets:
            if words[:3] != ["security", "zones", "security-zone"] or len(words) < 4 or self.off(words):
                continue
            zone = words[3]
            if zone not in self.p.zones:
                self.p.zones[zone] = Zone(zone, [])
            if len(words) >= 6 and words[4] == "interfaces":
                if words[5] not in self.p.zones[zone].interfaces:
                    self.p.zones[zone].interfaces.append(words[5])
                self.interface_zone[words[5]] = zone
            if len(words) >= 7 and words[4] == "address-book":
                self._book_line(f"zone {zone}", words[5:], words)
                self.attached[zone] = f"zone {zone}"

    def address_books(self) -> None:
        for words in self.sets:
            if words[:2] != ["security", "address-book"] or len(words) < 4 or self.off(words):
                continue
            book = words[2]
            if words[3] == "attach" and len(words) >= 6 and words[4] == "zone":
                if words[5] in self.attached:
                    raise ParseError(f"zone '{_short(words[5])}' has two address books besides the global one")
                self.attached[words[5]] = book
                continue
            self._book_line(book, words[3:], words)

    def _book_line(self, book: str, words: List[str], whole: List[str]) -> None:
        if len(words) < 3:
            return
        if words[0] == "address":
            values = self.books.setdefault(book, {}).setdefault(words[1], [])
            if words[2] != "description":
                values.append(" ".join(words[2:]))
        elif words[0] == "address-set" and len(words) >= 4 and words[2] in ("address", "address-set"):
            self.book_sets.setdefault(book, {}).setdefault(words[1], []).append((words[2], words[3]))
        elif words[0] == "address-set" and words[2] == "description":
            self.book_sets.setdefault(book, {}).setdefault(words[1], [])

    def address(self, name: str, zone: str, global_only: bool = False) -> Optional[str]:
        """The model name for an address name a policy uses in a zone; None when it is not defined."""
        if name == "any":
            return ANY
        if name == "any-ipv4":
            return ANY_V4
        if name == "any-ipv6":
            return ANY_V6
        books = ([] if global_only or zone not in self.attached else [self.attached[zone]]) + ["global"]
        for book in books:
            if name in self.books.get(book, {}) or name in self.book_sets.get(book, {}):
                return self._make(book, name, 0)
        return None

    @staticmethod
    def _model_name(book: str, name: str) -> str:
        """The name of an object in the model: a name that looks like an address must not be read as one, and objects of
        two books are kept apart (a book of a zone is told from a book of the same name)."""
        if book != "global":
            return f"{name} ({book})"
        return f"{name} (object)" if parse_literal(name) is not None else name

    def _make(self, book: str, name: str, depth: int) -> str:
        key = (book, name)
        if key in self.made:
            return self.made[key]
        model = self._model_name(book, name)
        self.made[key] = model
        if depth > _MAX_NESTING or key in self.resolving:
            self.p.address_groups[model] = AddressGroup(model, [], unsupported="address sets nested more than 64 deep, or in a circle")
            return model
        if name in self.books.get(book, {}):
            values = self.books[book][name]
            self.p.addresses[model] = self._value(model, values)
            return model
        self.resolving.add(key)
        members: List[str] = []
        problem = ""
        for kind, member in self.book_sets[book][name]:
            if member in self.books.get(book, {}) or member in self.book_sets.get(book, {}):
                members.append(self._make(book, member, depth + 1))
            elif book != "global" and (member in self.books.get("global", {}) or member in self.book_sets.get("global", {})):
                problem = f"it holds '{_short(member)}', which is in the global address book, not in its own"
            else:
                problem = f"it holds '{_short(member)}', which is not in the configuration"
                self.missing.add(member)
        self.resolving.discard(key)
        self.p.address_groups[model] = AddressGroup(model, [] if problem else members,
                                                    unsupported=problem or ("" if members else "an address set without members"))  # fmt: skip
        return model

    @staticmethod
    def _value(name: str, values: List[str]) -> Address:
        if len(values) != 1:
            return Address(name, AddressKind.UNSUPPORTED, "", raw="an address with " + ("no value" if not values else "two values"))
        words = values[0].split()
        if len(words) == 1:
            interval = parse_literal(words[0])
            start = parse_literal(words[0].split("/")[0])
            if interval is None or start is None or ("/" in words[0] and start[1] != interval[1]):
                return Address(name, AddressKind.UNSUPPORTED, "", raw=f"address '{_short(words[0])}' that could not be read")
            return Address(name, AddressKind.NETWORK, interval_text(interval) if "/" in words[0] else words[0])
        if words[0] == "range-address" and len(words) == 4 and words[2] == "to":
            interval = parse_literal(f"{words[1]}-{words[3]}")
            if interval is None:
                return Address(name, AddressKind.UNSUPPORTED, "", raw="a range that could not be read")
            return Address(name, AddressKind.RANGE, f"{words[1]}-{words[3]}")
        if words[0] == "dns-name" and len(words) in (2, 3):
            family = {"ipv4-only": 4, "ipv6-only": 6}.get(words[2], -1) if len(words) == 3 else 0
            if family < 0:
                return Address(name, AddressKind.UNSUPPORTED, "", raw=f"a DNS name with '{_short(words[2], 20)}'")
            return Address(name, AddressKind.FQDN, words[1], fqdn_family=family)
        if words[0] == "wildcard-address":
            return Address(name, AddressKind.UNSUPPORTED, "", raw="a wildcard address")
        return Address(name, AddressKind.UNSUPPORTED, "", raw=f"an address of the form '{_short(values[0], 40)}'")

    # -- applications -----------------------------------------------------------------------------

    def applications(self) -> None:
        for words in self.sets:
            if words[:1] != ["applications"] or len(words) < 3 or self.off(words):
                continue
            if words[1] == "application":
                self.apps.setdefault(words[2], []).append(words[3:])
            elif words[1] == "application-set":
                if len(words) >= 5 and words[3] in ("application", "application-set"):
                    self.app_sets.setdefault(words[2], []).append((words[3], words[4]))
                else:
                    self.app_sets.setdefault(words[2], [])

    def application(self, name: str, depth: int = 0) -> Optional[str]:
        """The model name of an application or application set a policy names; None when it is not there."""
        if name == "any":
            return ANY
        if name in self.p.services or name in self.p.service_groups:
            return name
        if name in self.apps:
            entries, problem = self._app_entries(self.apps[name])
            self.p.services[name] = Service(name, entries, unsupported=problem)
            return name
        if name in self.app_sets:
            if depth > _MAX_NESTING:
                self.p.services[name] = Service(name, [], unsupported="application sets nested more than 64 deep, or in a circle")
                return name
            self.p.service_groups[name] = ServiceGroup(name, [])
            members: List[str] = []
            for _, member in self.app_sets[name]:
                found = self.application(member, depth + 1)
                if found is None or found == ANY:
                    del self.p.service_groups[name]
                    reason = "is not in the configuration" if found is None else "is 'any'"
                    self.p.services[name] = Service(name, [], unsupported=f"it holds '{_short(member)}', which {reason}")
                    return name
                members.append(found)
            self.p.service_groups[name].members = members
            if not members:
                del self.p.service_groups[name]
                self.p.services[name] = Service(name, [], unsupported="an application set without members")
            return name
        if name in _DOUBTFUL:
            self.p.services[name] = Service(name, [], builtin="junos", unsupported=f"the predefined application {name}: {_DOUBTFUL[name]}")
            self.predefined_used.add(name)
            return name
        if name in JUNOS_APPLICATIONS:
            entries = []
            for protocol, ports, kind, code in JUNOS_APPLICATIONS[name]:
                if protocol == Protocol.IP:
                    entries.append(ServiceEntry(Protocol.IP, ip_protocol=int(ports)))
                else:
                    entries.append(ServiceEntry(protocol, ports, icmp_type=kind, icmp_code=code))
            self.p.services[name] = Service(name, entries, builtin="junos")
            self.predefined_used.add(name)
            return name
        if name in JUNOS_SETS:
            members = [found for member in JUNOS_SETS[name] for found in [self.application(member)] if found]
            self.p.service_groups[name] = ServiceGroup(name, members, builtin="junos")
            self.predefined_used.add(name)
            return name
        if name.startswith("junos-"):
            self.p.services[name] = Service(name, [], builtin="junos", unsupported=f"the predefined application {name}, which is "
                                            "not in FWShift's table of them")  # fmt: skip
            self.predefined_used.add(name)
            return name
        return None

    def _app_entries(self, lines: List[List[str]]) -> Tuple[List[ServiceEntry], str]:
        terms: Dict[str, Dict[str, str]] = {}
        for words in lines:
            if not words:
                continue
            if words[0] == "term":
                if len(words) < 3:
                    continue
                term, pairs = words[1], words[2:]
            else:
                term, pairs = "", words
            if pairs[0] == "description":
                continue
            values = terms.setdefault(term, {})
            for index in range(0, len(pairs), 2):
                key = pairs[index]
                if index + 1 >= len(pairs):
                    return [], f"'{_short(key, 30)}' without a value"
                value = pairs[index + 1]
                if key in ("inactivity-timeout", "application-protocol", "alg"):
                    continue
                if key not in ("protocol", "destination-port", "source-port", "icmp-type", "icmp-code", "icmp6-type", "icmp6-code"):
                    return [], f"'{_short(key, 30)}', which this parser does not read"
                if key in values and values[key] != value:
                    return [], f"two values of '{key}'"
                values[key] = value
        if "" in terms and len(terms) > 1:
            return [], "statements of its own and terms at once"
        entries: List[ServiceEntry] = []
        for values in terms.values():
            found, problem = _term(values)
            if problem:
                return [], problem
            assert found is not None
            entries.append(found)
        if not entries:
            return [], "an application without a protocol"
        return entries, ""

    # -- policies ---------------------------------------------------------------------------------

    def policies(self) -> List[_Policy]:
        found: Dict[Tuple[str, str], _Policy] = {}
        for index, words in enumerate(self.sets):
            if words[:2] != ["security", "policies"] or len(words) < 3:
                continue
            if words[2] == "default-policy" and len(words) >= 4:
                if not self.off(words):
                    action = Action.ALLOW if words[3] == "permit-all" else Action.DENY if words[3] == "deny-all" else None
                    if action is None:
                        raise ParseError(f"default-policy '{_short(words[3], 20)}', which this parser does not know")
                    self.p.default_interzone = self.p.default_intrazone = action
                continue
            if words[2] == "from-zone" and len(words) >= 8 and words[4] == "to-zone" and words[6] == "policy":
                key, policy_name, rest, path = (f"{words[3]} {words[5]}", words[7]), words[7], words[8:], words[:8]
                src, dst = words[3], words[5]
            elif words[2] == "global" and len(words) >= 5 and words[3] == "policy":
                key, policy_name, rest, path = ("global", words[4]), words[4], words[5:], words[:5]
                src = dst = ANY
            else:
                if words[2] not in ("policy-rematch", "lookup-intact-on-commit", "pre-id-default-policy", "traceoptions",
                                    "stateful-firewall-rule-set", "policy-stats"):  # fmt: skip
                    self.not_read.append(f"security policies {words[2]}")
                continue
            policy = found.get(key)
            if policy is None:
                policy = found[key] = _Policy(key[0], policy_name, src, dst, first=index)
                policy.inactive = self.off(path)
            if rest and not self.off(words, len(path) + 1):
                policy.lines.append(rest)
        return sorted(found.values(), key=lambda item: (item.context == "global", item.first))

    def rule(self, policy: _Policy, names: Set[str]) -> Optional[Rule]:
        label = policy.name if policy.name not in names else f"{policy.name} ({policy.context})"
        names.add(label)
        problems: List[str] = []
        sources: List[str] = []
        destinations: List[str] = []
        applications: List[str] = []
        from_zones: List[str] = []
        to_zones: List[str] = []
        negate_source = negate_destination = False
        action: Optional[Action] = None
        rule = Rule(name=label, origin=label, log_end=False)
        description = ""
        for words in policy.lines:
            head = words[0]
            if head == "description":
                description = " ".join(words[1:])
            elif head == "scheduler-name" and len(words) > 1:
                rule.schedule = words[1]
            elif head == "match" and len(words) >= 2:
                for key, value in _pairs(words[1:]):
                    self._match(key, value, policy, rule, problems, sources, destinations, applications, from_zones, to_zones)
                    if key == "source-address-excluded":
                        negate_source = True
                    elif key == "destination-address-excluded":
                        negate_destination = True
            elif head == "then" and len(words) >= 2:
                kind = words[1]
                if kind in ("permit", "deny", "reject"):
                    found = {"permit": Action.ALLOW, "deny": Action.DROP, "reject": Action.RESET_CLIENT}[kind]
                    if action is not None and action != found:
                        problems.append("two actions")
                    action = found
                    extra = words[2:]
                    if kind == "permit" and extra:
                        if extra[0] == "tunnel":
                            problems.append("a policy-based VPN (permit tunnel): the traffic is allowed into a tunnel only")
                        elif extra[0] == "application-services":
                            rule.profiles["application-services"] = " ".join(extra[1:3]) or "yes"
                        elif extra[0] in ("services-offload", "tcp-options", "destination-address", "firewall-authentication"):
                            if extra[0] in ("destination-address", "firewall-authentication"):
                                problems.append(f"'then permit {extra[0]}', which this parser does not read")
                        else:
                            problems.append(f"'then permit {_short(extra[0], 30)}', which this parser does not read")
                elif kind == "log":
                    if "session-init" in words[2:]:
                        rule.log_start = True
                    if "session-close" in words[2:]:
                        rule.log_end = True
                elif kind == "count":
                    continue
                else:
                    problems.append(f"'then {_short(kind, 30)}', which this parser does not read")
            else:
                problems.append(f"'{_short(head, 30)}', which this parser does not read")
        if policy.context != "global" and "junos-host" in (policy.src_zone, policy.dst_zone):
            self.host_policies.append(policy.name)
            return None
        if action is None:
            problems.append("the policy has no action (permit, deny or reject)")
            action = Action.DROP
        for side, values in (("source-address", sources), ("destination-address", destinations), ("application", applications)):
            if not values:
                problems.append(f"the policy names no {side}")
        rule.action, rule.enabled, rule.description = action, not policy.inactive, description
        if policy.context == "global":
            rule.src_zones = list(dict.fromkeys(from_zones)) or [ANY]
            rule.dst_zones = list(dict.fromkeys(to_zones)) or [ANY]
            src_book = dst_book = ""
        else:
            rule.src_zones, rule.dst_zones = [policy.src_zone], [policy.dst_zone]
            src_book, dst_book = policy.src_zone, policy.dst_zone
        named = [policy.src_zone, policy.dst_zone] if policy.context != "global" else from_zones + to_zones
        if "any" in named:
            problems.append("a zone named 'any', which this parser cannot tell from every zone")
        for zone in rule.src_zones + rule.dst_zones:
            if zone != ANY and zone not in self.p.zones:
                problems.append(f"zone '{_short(zone)}' is not in the configuration")
        rule.sources = self._names(sources, src_book, problems) if sources else [ANY]
        rule.destinations = self._names(destinations, dst_book, problems) if destinations else [ANY]
        resolved: List[str] = []
        for value in applications:
            found_app = self.application(value)
            if found_app is None:
                problems.append(f"application '{_short(value)}' is not in the configuration")
                self.missing.add(value)
            else:
                resolved.append(found_app)
        rule.services = [ANY] if ANY in resolved or not resolved else list(dict.fromkeys(resolved))
        rule.negate_source, rule.negate_destination = negate_source, negate_destination
        if (negate_source and ANY in rule.sources) or (negate_destination and ANY in rule.destinations):
            problems.append("a negated 'any', which Junos does not accept")
        rule.unsupported = list(dict.fromkeys(problems))
        rule.scope = RuleScope.UNIVERSAL
        return rule

    @staticmethod
    def _match(key: str, value: str, policy: _Policy, rule: Rule, problems: List[str], sources: List[str], destinations: List[str],
               applications: List[str], from_zones: List[str], to_zones: List[str]) -> None:  # fmt: skip
        if key in ("source-address", "destination-address", "application", "from-zone", "to-zone", "source-identity",
                   "dynamic-application", "url-category") and not value:  # fmt: skip
            problems.append(f"'match {key}' without a value")
        elif key == "source-address":
            sources.append(value)
        elif key == "destination-address":
            destinations.append(value)
        elif key == "application":
            applications.append(value)
        elif key in ("source-address-excluded", "destination-address-excluded"):
            return
        elif key == "from-zone" and policy.context == "global":
            from_zones.append(value)
        elif key == "to-zone" and policy.context == "global":
            to_zones.append(value)
        elif key == "source-identity":
            if value != "any":
                rule.users = [*([] if rule.users == [ANY] else rule.users), value]
        elif key == "dynamic-application":
            if value not in ("none", "any"):
                problems.append(f"dynamic application '{_short(value, 30)}' (a unified policy), which is not converted")
        elif key == "url-category":
            if value not in ("none", "any"):
                rule.url_categories = [*([] if rule.url_categories == [ANY] else rule.url_categories), value]
        else:
            problems.append(f"'match {_short(key, 30)}', which this parser does not read")

    def _names(self, values: List[str], zone: str, problems: List[str]) -> List[str]:
        out: List[str] = []
        for value in values:
            found = self.address(value, zone, global_only=not zone)
            if found is None:
                problems.append(f"address '{_short(value)}' is not in the address books of zone '{zone}'" if zone
                                else f"address '{_short(value)}' is not in the global address book")  # fmt: skip
                self.missing.add(value)
                continue
            out.append(found)
        if ANY in out:
            return [ANY]
        return list(dict.fromkeys(out)) or [ANY]

    # -- NAT --------------------------------------------------------------------------------------

    def nat(self) -> None:
        pools: Dict[Tuple[str, str], List[List[str]]] = {}
        contexts: Dict[Tuple[str, str], Dict[str, List[str]]] = {}
        rules: Dict[Tuple[str, str, str], _NatRule] = {}
        order: List[Tuple[str, str, str]] = []
        for words in self.sets:
            if words[:2] != ["security", "nat"] or len(words) < 4:
                continue
            kind = words[2]
            if kind == "proxy-arp" or kind == "proxy-ndp":
                continue
            if kind not in ("static", "destination", "source"):
                if not self.off(words):
                    self.not_read.append(f"security nat {kind}")
                continue
            if words[3] == "pool":
                if len(words) >= 6 and not self.off(words):
                    pools.setdefault((kind, words[4]), []).append(words[5:])
                continue
            if words[3] != "rule-set" or len(words) < 6:
                if not self.off(words) and words[3] not in ("address-persistent", "pool-utilization-alarm", "port-randomization",
                                                            "interface", "pool-default-port-range"):  # fmt: skip
                    self.not_read.append(f"security nat {kind} {words[3]}")
                continue
            rule_set = words[4]
            if words[5] in ("from", "to") and len(words) >= 8:
                if not self.off(words):
                    contexts.setdefault((kind, rule_set), {}).setdefault(f"{words[5]} {words[6]}", []).append(words[7])
                continue
            if words[5] == "rule" and len(words) >= 7:
                key = (kind, rule_set, words[6])
                if key not in rules:
                    rules[key] = _NatRule(kind, rule_set, words[6], inactive=self.off(words[:7]))
                    order.append(key)
                if len(words) > 7 and not self.off(words):
                    rules[key].lines.append(words[7:])
        made: Dict[str, List[NatRule]] = {"static": [], "destination": [], "source": []}
        for key in order:
            found = rules[key]
            context = contexts.get((found.kind, found.rule_set), {})
            nat = self._nat_rule(found, context, pools)
            made[found.kind].append(nat)
        # The rule sets of the most specific context first, within each kind: interface, then zone. The outbound half
        # of a static NAT comes before source NAT, as Junos applies it.
        for kind in ("static", "destination", "back", "source"):
            if kind == "back":
                for nat, back in self.backs:
                    back.unsupported = list(nat.unsupported)
                    self.p.nat_rules.append(back)
                continue
            ranked = sorted(made[kind], key=lambda n: (0 if n.description == "interface" else 1))
            for nat in ranked:
                nat.description = ""
                self.p.nat_rules.append(nat)

    def _nat_rule(self, found: _NatRule, context: Dict[str, List[str]], pools: Dict[Tuple[str, str], List[List[str]]]) -> NatRule:
        name = f"{found.rule_set} {found.name}"
        nat = NatRule(name=name, origin=name, enabled=not found.inactive, combines=True)
        problems: List[str] = []
        specific = "zone"
        for side in ("from", "to"):
            zones: List[str] = []
            for where, values in context.items():
                kind, _, scope = where.partition(" ")
                if kind != side:
                    continue
                for value in values:
                    if scope == "zone":
                        zones.append(value)
                    elif scope == "interface":
                        specific = "interface" if side == "from" else specific
                        zone = self.interface_zone.get(value)
                        if zone is None:
                            problems.append(f"interface '{_short(value)}', which is in no zone of the configuration")
                        else:
                            zones.append(zone)
                            if len(self.p.zones[zone].interfaces) > 1:
                                problems.append(f"a rule set for interface {value}, whose zone {zone} has other interfaces as well")
                    else:
                        problems.append(f"a rule set for routing instance '{_short(value)}', which is not read")
            if side == "from":
                nat.src_zones = list(dict.fromkeys(zones)) or [ANY]
                if not zones:
                    problems.append("a rule set that does not say where its traffic comes from")
            elif found.kind == "source":
                nat.dst_zones = list(dict.fromkeys(zones)) or [ANY]
                if not zones:
                    problems.append("a source NAT rule set that does not say where its traffic goes")
        nat.description = specific
        sources: List[str] = []
        destinations: List[str] = []
        ports: List[str] = []
        protocols: List[str] = []
        then: List[str] = []
        for words in found.lines:
            if words[0] == "description":
                continue
            if words[0] == "match" and len(words) >= 3:
                key, given = words[1], words[2:]
                if key in ("source-address", "destination-address"):
                    literal = parse_literal(given[0])
                    if literal is None:
                        problems.append(f"address '{_short(given[0])}' that could not be read")
                    else:
                        (sources if key == "source-address" else destinations).append(given[0] if "/" not in given[0] else interval_text(literal))
                elif key in ("source-address-name", "destination-address-name"):
                    model = self.address(given[0], "", global_only=True)
                    if model is None:
                        problems.append(f"address '{_short(given[0])}' is not in the global address book")
                        self.missing.add(given[0])
                    else:
                        (sources if key == "source-address-name" else destinations).append(model)
                elif key == "destination-port":
                    if len(given) == 3 and given[1] == "to":
                        ports.append(f"{given[0]}-{given[2]}")
                    elif len(given) == 1:
                        ports.append(given[0])
                    else:
                        problems.append("a destination port that could not be read")
                elif key == "protocol":
                    protocols.append(given[0])
                elif key == "application":
                    problems.append("'match application' in a NAT rule, which this parser does not read")
                else:
                    problems.append(f"'match {_short(key, 30)}', which this parser does not read")
            elif words[0] == "then":
                then = _merge(then, words[1:])
            else:
                problems.append(f"'{_short(words[0], 30)}', which this parser does not read")
        nat.sources = list(dict.fromkeys(sources)) or [ANY]
        nat.destinations = list(dict.fromkeys(destinations)) or [ANY]
        if ports or protocols:
            entries, problem = _nat_service(ports, protocols)
            service = f"NAT {name}"
            self.p.services[service] = Service(service, entries, unsupported=problem)
            nat.service = service
        self._translation(found, nat, then, pools, problems)
        nat.unsupported = list(dict.fromkeys(p for p in problems if p))
        return nat

    def _translation(self, found: _NatRule, nat: NatRule, then: List[str], pools: Dict[Tuple[str, str], List[List[str]]],
                     problems: List[str]) -> None:  # fmt: skip
        kind = found.kind
        if not then:
            problems.append("the rule has no action")
            return
        if kind == "static":
            if then[:1] != ["static-nat"] or len(then) < 3:
                problems.append(f"'then {_short(' '.join(then), 30)}', which this parser does not read")
                return
            if then[1] == "prefix":
                target: Optional[str] = then[2] if parse_literal(then[2]) else None
                if target and "/" in target:
                    literal = parse_literal(target)
                    assert literal is not None
                    target = interval_text(literal)
            elif then[1] == "prefix-name":
                target = self.address(then[2], "", global_only=True)
            else:
                problems.append(f"'static-nat {_short(then[1], 20)}', which this parser does not read")
                return
            if target is None:
                problems.append(f"translated address '{_short(then[2])}' that could not be read")
                return
            rest = then[3:]
            port = ""
            if rest[:1] == ["mapped-port"] and len(rest) >= 2:
                port = rest[1] if len(rest) < 4 else f"{rest[1]}-{rest[3]}"
                rest = rest[4:] if len(rest) >= 4 and rest[2] == "to" else rest[2:]
            if rest:
                problems.append(f"'{_short(' '.join(rest), 30)}' in a static NAT rule, which this parser does not read")
            nat.destination_translation = DestNat(target, port)
            if len(nat.destinations) == 1 and nat.destinations[0] != ANY:
                # Static NAT works both ways: the inside address leaves as the outside one, whatever its way out.
                back = NatRule(name=f"{nat.name} (outbound)", origin=f"{nat.name} (outbound)", sources=[target], enabled=nat.enabled,
                               source_translation=SourceNat(SnatKind.STATIC, [nat.destinations[0]]), combines=True)  # fmt: skip
                self.backs.append((nat, back))
            return
        if kind == "destination":
            if then[:1] != ["destination-nat"] or len(then) < 2:
                problems.append(f"'then {_short(' '.join(then), 30)}', which this parser does not read")
                return
            if then[1] == "off":
                return
            if then[1] != "pool" or len(then) < 3:
                problems.append(f"'destination-nat {_short(then[1], 20)}', which this parser does not read")
                return
            lines = pools.get(("destination", then[2]))
            if not lines:
                problems.append(f"destination pool '{_short(then[2])}' is not in the configuration")
                return
            address, port, spread = "", "", False
            for words in lines:
                if words[0] == "address" and len(words) >= 2:
                    if address:
                        problems.append("a destination pool of two addresses")
                    if len(words) >= 4 and words[2] == "to":
                        address, spread = f"{words[1].split('/')[0]}-{words[3].split('/')[0]}", True
                        rest = words[4:]
                    else:
                        address, rest = words[1], words[2:]
                    if rest[:1] == ["port"] and len(rest) == 2:
                        port = rest[1]
                    elif rest:
                        problems.append(f"'{_short(' '.join(rest), 30)}' in a destination pool, which this parser does not read")
                elif words[0] not in ("description",):
                    problems.append(f"'{_short(words[0], 30)}' in a destination pool, which this parser does not read")
            literal = parse_literal(address)
            if literal is None:
                problems.append(f"destination pool '{_short(then[2])}' holds no address that could be read")
                return
            nat.destination_translation = DestNat(interval_text(literal) if not spread else address, port, spread=spread and literal[1] != literal[2])
            return
        if then[:1] != ["source-nat"] or len(then) < 2:
            problems.append(f"'then {_short(' '.join(then), 30)}', which this parser does not read")
            return
        if then[1] == "off":
            return
        if then[1] == "interface":
            nat.source_translation = SourceNat(SnatKind.INTERFACE)
            if len(then) > 2 and then[2] != "persistent-nat":
                problems.append(f"'source-nat interface {_short(then[2], 20)}', which this parser does not read")
            return
        if then[1] != "pool" or len(then) < 3:
            problems.append(f"'source-nat {_short(then[1], 20)}', which this parser does not read")
            return
        lines = pools.get(("source", then[2]))
        if not lines:
            problems.append(f"source pool '{_short(then[2])}' is not in the configuration")
            return
        addresses: List[str] = []
        static_ports = False
        for words in lines:
            if words[0] == "address" and len(words) >= 2:
                if len(words) >= 4 and words[2] == "to":
                    literal = parse_literal(f"{words[1].split('/')[0]}-{words[3].split('/')[0]}")
                else:
                    literal = parse_literal(words[1])
                if literal is None:
                    problems.append("a pool address that could not be read")
                else:
                    addresses.append(interval_text(literal))
            elif words[:2] == ["port", "no-translation"]:
                static_ports = True
            elif words[0] in ("description", "port", "address-persistent", "pool-utilization-alarm"):
                if words[0] == "port" and words[1:2] not in (["range"], ["port-overloading-factor"]):
                    problems.append(f"'port {_short(' '.join(words[1:]), 20)}' in a source pool, which this parser does not read")
            else:
                problems.append(f"'{_short(words[0], 30)}' in a source pool, which this parser does not read")
        if not addresses:
            problems.append(f"source pool '{_short(then[2])}' holds no address")
            return
        nat.source_translation = SourceNat(SnatKind.DYNAMIC if static_ports else SnatKind.DYNAMIC_PORT, addresses)



_FLAGS = ("source-address-excluded", "destination-address-excluded")


def _pairs(words: List[str]) -> List[Tuple[str, str]]:
    """The statements of a 'match' line: keywords with their value, flags alone."""
    out: List[Tuple[str, str]] = []
    index = 0
    while index < len(words):
        key = words[index]
        if key in _FLAGS:
            out.append((key, ""))
            index += 1
            continue
        out.append((key, words[index + 1] if index + 1 < len(words) else ""))
        index += 2
    return out


def _merge(first: List[str], more: List[str]) -> List[str]:
    """Two 'then' lines of one rule as one: what the second adds after the words they share."""
    if not first:
        return list(more)
    shared = 0
    while shared < min(len(first), len(more)) and first[shared] == more[shared]:
        shared += 1
    return first + more[shared:]


def _term(values: Dict[str, str]) -> Tuple[Optional[ServiceEntry], str]:
    protocol_text = values.get("protocol", "")
    if not protocol_text:
        return None, "a term without a protocol"
    number = _PROTOCOLS.get(protocol_text.lower(), int(protocol_text) if is_number(protocol_text) and int(protocol_text) <= 255 else -1)
    if number < 0:
        return None, f"protocol '{_short(protocol_text, 20)}' that could not be read"
    if number in (6, 17):
        if "destination-port" not in values:
            return None, "a TCP or UDP application without a destination port"
        ports = _port_range(values["destination-port"])
        source = _port_range(values["source-port"]) if "source-port" in values else ""
        if ports is None or source is None:
            return None, "ports that could not be read"
        if any(key.startswith("icmp") for key in values):
            return None, "an ICMP type in a TCP or UDP application"
        return ServiceEntry(Protocol.TCP if number == 6 else Protocol.UDP, ports, source), ""
    if "destination-port" in values or "source-port" in values:
        if number == 132:
            return None, "SCTP ports"
        return None, f"ports for protocol {number}"
    if number in (1, 58):
        prefix = "icmp" if number == 1 else "icmp6"
        other = "icmp6" if number == 1 else "icmp"
        if f"{other}-type" in values or f"{other}-code" in values:
            return None, "the ICMP type of the other IP version"
        kind = values.get(f"{prefix}-type")
        code = values.get(f"{prefix}-code")
        names = _ICMP_TYPES if number == 1 else _ICMP6_TYPES
        kind_number = names.get(kind, int(kind) if kind and is_number(kind) and int(kind) < 256 else -1) if kind else None
        code_number = (int(code) if is_number(code) and int(code) < 256 else -1) if code else None
        if kind_number == -1 or code_number == -1:
            return None, "an ICMP type or code that could not be read"
        if code_number is not None and kind_number is None:
            return None, "an ICMP code without a type"
        return ServiceEntry(Protocol.ICMP if number == 1 else Protocol.ICMP6, icmp_type=kind_number, icmp_code=code_number), ""
    if any(key.startswith("icmp") for key in values):
        return None, f"an ICMP type for protocol {number}"
    if number == 0:
        return None, "protocol 0"
    return ServiceEntry(Protocol.IP, ip_protocol=number), ""


def _port_range(text: str) -> Optional[str]:
    """``80``, ``80-81`` or a port name, as the model writes it ("" for every port)."""
    low_text, _, high_text = text.partition("-")
    low = int(low_text) if is_number(low_text) else _PORTS.get(low_text)
    high = (int(high_text) if is_number(high_text) else _PORTS.get(high_text)) if high_text else low
    if low is None or high is None or low > high or high > 65535:
        return None
    if low == 0 and high == 65535:
        return ""
    if low == 0:
        return None
    return str(low) if low == high else f"{low}-{high}"


def _nat_service(ports: List[str], protocols: List[str]) -> Tuple[List[ServiceEntry], str]:
    kinds: List[Tuple[Protocol, Optional[int]]] = []
    for text in protocols or ["tcp", "udp"]:
        number = _PROTOCOLS.get(text.lower(), int(text) if is_number(text) and int(text) <= 255 else -1)
        if number < 0:
            return [], f"protocol '{_short(text, 20)}' that could not be read"
        kinds.append((Protocol.TCP, None) if number == 6 else (Protocol.UDP, None) if number == 17
                     else (Protocol.ICMP, None) if number == 1 else (Protocol.IP, number))  # fmt: skip
    found: List[str] = []
    for text in ports:
        port = _port_range(text)
        if port is None:
            return [], f"destination port '{_short(text, 20)}' that could not be read"
        found.append(port)
    entries: List[ServiceEntry] = []
    for protocol, ip_protocol in kinds:
        if protocol in (Protocol.TCP, Protocol.UDP):
            entries.append(ServiceEntry(protocol, "" if "" in found else ",".join(found)))
        elif found:
            return [], "destination ports with a protocol that has none"
        elif protocol == Protocol.ICMP:
            entries.append(ServiceEntry(Protocol.ICMP))
        else:
            entries.append(ServiceEntry(Protocol.IP, ip_protocol=ip_protocol))
    return entries, ""


def parse(data: bytes, report: Report) -> Policy:
    lines = _lines(data)
    if not lines:
        raise ParseError("the configuration is empty")
    reader = _Reader(lines, report)
    reader.check_groups()
    if not any(words[:1] in (["security"], ["applications"]) for words in reader.sets):
        raise ParseError("no 'security' part found: not the configuration of an SRX, or not all of it")
    reader.zones()
    reader.address_books()
    reader.applications()
    names: Set[str] = set()
    for policy in reader.policies():
        rule = reader.rule(policy, names)
        if rule is not None:
            reader.p.rules.append(rule)
    reader.nat()
    _notes(reader)
    transform.rewrite_destinations(reader.p, report, to_post_nat=False)
    return reader.p


def _notes(reader: _Reader) -> None:
    report = reader.report
    report.note(Severity.INFO, "JUNOS_FORMAT",
                f"read {len(reader.p.rules)} security policies and {len(reader.p.nat_rules)} NAT rules of the root system. "
                "Policies are looked up after static and destination NAT; they were brought back to the original "
                "destination, as the model has it")  # fmt: skip
    if reader.predefined_used:
        report.note(Severity.INFO, "PREDEFINED_APPLICATIONS",
                    "predefined applications are not in the configuration; these were taken from FWShift's table of them: "
                    + ", ".join(sorted(reader.predefined_used)))  # fmt: skip
    if reader.missing:
        names = sorted(reader.missing)
        report.note(Severity.REVIEW, "OBJECTS_MISSING",
                    "names the policies or NAT rules use and the configuration does not define: "
                    + ", ".join(f"'{_short(n)}'" for n in names[:10]) + (f" and {len(names) - 10} more" if len(names) > 10 else "")
                    + ". The rules that use them are not used")  # fmt: skip
    if reader.host_policies:
        report.note(Severity.INFO, "HOST_POLICIES",
                    "policies for the zone junos-host (traffic to and from the firewall itself) are not read: "
                    + ", ".join(f"'{_short(n)}'" for n in reader.host_policies[:10]))  # fmt: skip
    if reader.not_read:
        report.note(Severity.REVIEW, "PARTS_NOT_READ",
                    "parts of the security configuration this parser does not read: " + ", ".join(reader.not_read[:10]))
