# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""pf parser: a ``pf.conf`` of OpenBSD (and of FreeBSD, with its older NAT rules) -> neutral model.

How pf decides, after pf.conf(5) of OpenBSD and of FreeBSD, and how that maps onto the model:

* Macros (``name = "value"``) are expanded where ``$name`` stands outside quotes, as pfctl does; a
  value is read again where it is used, so a macro may hold a list or other macros.
* Filter rules are last match: every rule is looked at, and the last one that matches decides,
  unless a rule that matches is ``quick``, which decides at once. Without a matching rule a packet
  passes. That is exactly "the first quick rule that matches, else the last other rule that
  matches", so the model, which is first match, gets the quick rules in their order and then the
  others in reverse order. The model's default is to allow.
* A forwarded packet is filtered twice: when it comes in on one interface and when it goes out on
  another, each time against the rules for that direction (a rule without ``in`` or ``out`` is for
  both). It passes when both pass it. Interfaces (and interface groups) are the zones. The rules for
  arriving traffic become rules of their source zone, for any destination zone. Of the rules for
  leaving traffic only the ones that block matter, less what an earlier deciding rule for leaving
  traffic passes; they become rules of their destination zone, from any zone, at the top of the
  model, where the boxes of ``regions.py`` cut out what such pass rules let out. Where that cannot
  be worked out, the rule is not converted.
* ``match`` rules decide nothing. Their translations (``nat-to``, ``rdr-to``, ``binat-to``) are
  applied at once, so the rules after them see the translated packet; the translations of a
  ``pass`` rule apply when it decides. Rules that see a translated destination are rewritten to
  the original one (the model matches before NAT). The older NAT rules of FreeBSD (``nat``,
  ``rdr``, ``binat``) are applied before any filter rule: every filter rule sees what they made.
* A list is expanded by pfctl into one rule per element. ``! { a b }`` is therefore "not a" or
  "not b", which is every address unless a and b overlap; it becomes one rule per element here too.
* Rules are stateful by default (``keep state``, ``flags S/SA`` for TCP): the model is about the
  packet that opens a connection. ``no state`` is reported.
* What the file does not hold is not guessed: tables loaded from a ``file``, tables filled at run
  time, the addresses of interfaces (``(em0)``, ``em0:network``, ``self``; they can be given with
  ``--interface-address``), anchors, ``tagged``. A rule that depends on one is not converted.
* Whether a word is an interface or an interface group follows ifconfig(8) of OpenBSD: a group name
  does not end in a digit. Which interfaces a group holds is not in pf.conf.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from .. import regions, transform
from ..errors import FwshiftError, ParseError
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
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, range_text, subtract
from ..report import Report, Severity
from .pfsense import ICMP6_TYPES, ICMP_TYPES, SERVICE_PORTS

IPInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
Host = Tuple[str, bool]  # (member of the model, negated)

# Protocol names pfctl takes (from /etc/protocols), with their numbers.
PROTOCOL_NUMBERS = {
    "ip": 0, "icmp": 1, "igmp": 2, "ggp": 3, "ipencap": 4, "ipip": 4, "st": 5, "tcp": 6, "egp": 8, "igp": 9, "pup": 12,
    "udp": 17, "hmp": 20, "xns-idp": 22, "rdp": 27, "ipv6": 41, "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45,
    "rsvp": 46, "gre": 47, "esp": 50, "ah": 51, "skip": 57, "ipv6-icmp": 58, "icmp6": 58, "ipv6-nonxt": 59,
    "ipv6-opts": 60, "rspf": 73, "vmtp": 81, "eigrp": 88, "ospf": 89, "ospfigp": 89, "ax.25": 93, "ipx-in-ip": 94,
    "etherip": 97, "encap": 98, "pim": 103, "ipcomp": 108, "vrrp": 112, "carp": 112, "l2tp": 115, "isis": 124,
    "sctp": 132, "fc": 133, "mpls-in-ip": 137, "pfsync": 240, "divert": 258,
}  # fmt: skip
# ICMP codes by the names pfctl gives them (pfctl_parser.c): (type, code).
ICMP_CODES = {
    "net-unr": (3, 0), "host-unr": (3, 1), "proto-unr": (3, 2), "port-unr": (3, 3), "needfrag": (3, 4),
    "srcfail": (3, 5), "net-unk": (3, 6), "host-unk": (3, 7), "isolate": (3, 8), "net-prohib": (3, 9),
    "host-prohib": (3, 10), "net-tos": (3, 11), "host-tos": (3, 12), "filter-prohib": (3, 13),
    "host-preced": (3, 14), "cutoff-preced": (3, 15), "redir-net": (5, 0), "redir-host": (5, 1),
    "redir-tos-net": (5, 2), "redir-tos-host": (5, 3), "normal-adv": (9, 0), "common-adv": (9, 16),
    "transit": (11, 0), "reassemb": (11, 1), "badhead": (12, 0), "optmiss": (12, 1), "badlen": (12, 2),
}  # fmt: skip
ICMP6_CODES = {
    "admin-unr": (1, 1), "noroute-unr": (1, 0), "beyond-unr": (1, 2), "addr-unr": (1, 3), "port-unr": (1, 4),
    "transit": (3, 0), "reassemb": (3, 1), "badhead": (4, 0), "nxthdr": (4, 1), "redironlink": (137, 0),
    "redirrouter": (137, 1),
}  # fmt: skip
# The first words of the statements of pf.conf this parser reads or reports.
_STATEMENTS = {
    "set", "table", "pass", "block", "match", "antispoof", "anchor", "nat-anchor", "rdr-anchor", "binat-anchor",
    "load", "nat", "rdr", "binat", "no", "scrub", "altq", "queue", "ether", "include",
}  # fmt: skip
_POOL_TYPES = {"bitmask", "least-states", "random", "round-robin", "source-hash", "sticky-address"}
# Options of a rule that change how traffic is handled, not what the rule matches.
_HANDLING_WORDS = {"allow-opts", "set", "prio", "queue", "rtable", "label", "tag", "max-mss", "ridentifier",
                   "dnpipe", "dnqueue", "set-tos"}  # fmt: skip
# Words that end the address part of a rule: the options that may follow.
_OPTION_WORDS = {
    "flags", "icmp-type", "icmp6-type", "tos", "keep", "modulate", "synproxy", "no", "sloppy", "fragment", "allow-opts",
    "once", "label", "tag", "tagged", "user", "group", "probability", "rtable", "max-pkt-rate", "nat-to", "rdr-to",
    "binat-to", "af-to", "route-to", "reply-to", "dup-to", "received-on", "divert-to", "divert-reply", "divert-packet",
    "scrub", "set", "prio", "queue", "max-mss", "ridentifier", "dnpipe", "dnqueue", "os", "!", "port", "to", "from",
}  # fmt: skip
_LOOPBACK = re.compile(r"lo[0-9]*")
_INTERFACE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,14}")
_HOST_NAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)+\.?")
_MACRO = re.compile(r"\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$")
_TOKEN = re.compile(
    r"""
      "(?:[^"\\]|\\.)*"
    | '(?:[^'\\]|\\.)*'
    | ->
    | <[A-Za-z0-9_][A-Za-z0-9_.:-]*>
    | != | <= | >= | >< | <>
    | [{}(),!<>=]
    | [^\s{}(),!<>="']+
    """,
    re.X,
)
_PF_LINE = re.compile(
    r"\s*(pass|block|match)(\s+(drop|return|return-rst|return-icmp|return-icmp6))?(\s+(in|out))?(\s+log\b(\s*\([^)]*\))?)?"
    r"(\s+quick)?\s+(on|from|to|all|proto|inet6?|any|quick|log|in|out)\b"
)
_MAX_PIECES = 256  # model rules one rule of pf may expand into


def looks_like_pf(data: bytes) -> bool:
    """A pf.conf: lines of pf rules (pass, block or match followed by words of pf), and nothing of the other text formats."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if head[:1] in (b"<", b"{", b"["):
        return False
    text = head.decode("utf-8", errors="replace")
    rules = 0
    for raw in text.splitlines()[:20000]:
        line = raw.strip()
        if line.startswith(("*", "-A ", ":INPUT", ":FORWARD", "config ", "access-list ", "/ip ", "/ipv6 ", "table inet ",
                            "table ip ", "table ip6 ", "chain ", "security-policy", "firewall zone", "COMMIT")):
            return False
        if _PF_LINE.match(line):
            rules += 1
    return rules > 0


def parse(data: bytes, report: Report, interface_addresses: Sequence[str] = ()) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    statements = _statements(text)
    return _Reader(statements, report, interface_addresses).build()


# -- reading the file ---------------------------------------------------------------------------


@dataclass
class _Stmt:
    line: int
    tokens: List[str]
    text: str


def _strip_comment(line: str) -> str:
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#":
            return line[:index]
    return line


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """Lines with comments taken out and a backslash at the end joined to the next line."""
    out: List[Tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).rstrip()
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        out.append((start, buffer + line))
        buffer = ""
    if buffer.strip():
        out.append((start, buffer))
    return out


def _expand(line: str, macros: Dict[str, str], number: int) -> str:
    """``$name`` outside quotes replaced by the value of the macro, again and again (a value is read anew)."""
    for _ in range(32):
        parts = re.split(r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", line)
        changed = False
        for index in range(0, len(parts), 2):

            def value(match: "re.Match[str]") -> str:
                name = match.group(1)
                if name not in macros:
                    raise ParseError(f"line {number}: macro '{name}' is not defined")
                return macros[name]

            new = re.sub(r"\$([A-Za-z0-9_]+)", value, parts[index])
            changed = changed or new != parts[index]
            parts[index] = new
        line = "".join(parts)
        if not changed:
            return line
    raise ParseError(f"line {number}: macros that expand into each other")


def _tokenize(line: str, number: int) -> List[str]:
    tokens: List[str] = []
    position = 0
    while position < len(line):
        if line[position].isspace():
            position += 1
            continue
        match = _TOKEN.match(line, position)
        if match is None:
            raise ParseError(f"line {number}: cannot read '{line[position:position + 30]}'")
        tokens.append(match.group(0))
        position = match.end()
    return tokens


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] in "\"'" and token[-1] == token[0]:
        return re.sub(r"\\(.)", r"\1", token[1:-1])
    return token


def _statements(text: str) -> List[_Stmt]:
    macros: Dict[str, str] = {}
    out: List[_Stmt] = []
    current: List[str] = []
    raw: List[str] = []
    depth = 0
    start = 0
    for number, line in _logical_lines(text):
        if not line.strip():
            continue
        if depth == 0 and not current:
            match = _MACRO.fullmatch(line)
            if match and match.group(1) not in _STATEMENTS:
                tokens = _tokenize(_expand(match.group(2), macros, number), number)
                macros[match.group(1)] = " ".join(_unquote(token) for token in tokens)
                continue
        tokens = _tokenize(_expand(line, macros, number), number)
        if not tokens:
            continue
        if not current:
            start = number
        current += tokens
        raw.append(" ".join(line.split()))
        depth += tokens.count("{") - tokens.count("}")
        if depth < 0:
            raise ParseError(f"line {number}: '}}' without '{{'")
        if depth == 0:
            out.append(_Stmt(start, current, " ".join(raw)))
            current, raw = [], []
    if current:
        raise ParseError(f"line {start}: '{{' without '}}'")
    return out


class _Cursor:
    def __init__(self, stmt: _Stmt) -> None:
        self.tokens, self.line, self.index = stmt.tokens, stmt.line, 0

    def peek(self, ahead: int = 0) -> str:
        position = self.index + ahead
        return self.tokens[position] if position < len(self.tokens) else ""

    def take(self) -> str:
        token = self.peek()
        if not token:
            raise ParseError(f"line {self.line}: the statement ends too early")
        self.index += 1
        return token

    def accept(self, *words: str) -> str:
        if self.peek() in words:
            return self.take()
        return ""

    def expect(self, word: str) -> None:
        if self.take() != word:
            raise ParseError(f"line {self.line}: '{word}' expected")

    def done(self) -> bool:
        return self.index >= len(self.tokens)

    def rest(self) -> List[str]:
        out = self.tokens[self.index :]
        self.index = len(self.tokens)
        return out

    def skip_value(self) -> str:
        """One value: a word, or what stands between brackets (with them)."""
        token = self.take()
        if token not in ("(", "{"):
            return token
        closing = ")" if token == "(" else "}"
        depth, words = 1, [token]
        while depth:
            word = self.take()
            depth += 1 if word == token else -1 if word == closing else 0
            words.append(word)
        return " ".join(words)


# -- what one rule says -------------------------------------------------------------------------


@dataclass
class _Side:
    hosts: List[Host] = field(default_factory=lambda: [(ANY, False)])
    ports: str = ""
    has_ports: bool = False


@dataclass
class _Trans:
    kind: str  # nat-to, rdr-to, binat-to (also the older nat, rdr, binat)
    hosts: List[Host] = field(default_factory=list)
    interface: str = ""  # nat-to (em0) or nat-to em0: the address of the interface
    port: str = ""
    pool: str = ""
    static_port: bool = False
    problems: List[str] = field(default_factory=list)


@dataclass
class _Rule:
    line: int
    text: str
    action: str  # pass, block, match; for the older NAT rules: nat, rdr, binat
    block: Action = Action.DROP
    direction: str = "both"
    quick: bool = False
    log: bool = False
    interfaces: List[Tuple[str, bool]] = field(default_factory=list)  # empty: every interface
    af: int = 0
    protos: List[str] = field(default_factory=list)
    src: _Side = field(default_factory=_Side)
    dst: _Side = field(default_factory=_Side)
    icmp: List[Tuple[Optional[int], Optional[int]]] = field(default_factory=list)
    icmp_word: str = ""
    flags: Optional[str] = None
    state: str = "keep"
    label: str = ""
    tag: str = ""
    trans: List[_Trans] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)
    handling: Dict[str, str] = field(default_factory=dict)
    findings: List[Tuple[Severity, str, str]] = field(default_factory=list)
    name: str = ""
    passes: bool = False  # older NAT rules: "pass"
    no: bool = False  # older NAT rules: "no nat", "no rdr"
    kind: str = "rule"  # rule, antispoof
    service: str = ""  # the service object, once worked out


@dataclass
class _Piece:
    """One model rule a rule of pf expands into (before zones are given)."""

    source: _Rule
    rule: Rule
    zones: List[str]


class _Reader:
    def __init__(self, statements: List[_Stmt], report: Report, interface_addresses: Sequence[str]) -> None:
        self.statements, self.report = statements, report
        self.p = Policy(vendor="pf", default_intrazone=Action.ALLOW, default_interzone=Action.ALLOW)
        self.given = _given(interface_addresses)
        self.block_policy = Action.DROP
        self.rules: List[_Rule] = []
        self.legacy: List[_Rule] = []
        self.tables: Dict[str, str] = {}  # name -> why it cannot be converted, "" when it can
        self.skip: List[str] = []
        self.anchors: List[str] = []
        self.interfaces: List[str] = []  # names used as interfaces or groups, in order of appearance
        self.names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.notes: Dict[str, List[str]] = {}
        self.host_names: List[str] = []
        self.order: Dict[int, int] = {}  # id of a deciding rule -> its place in first-match order
        self.seen_by: Dict[str, Tuple[int, str]] = {}  # model rule origin -> (line of its rule, "in" or "out")
        self.dnat_legacy: Set[str] = set()  # destination NAT of the older rules: every filter rule sees what it made
        self.dnat_match: List[Tuple[int, str, str]] = []  # (line, direction, origin) of match rules that translate destinations
        self.dnat_pass: List[str] = []  # pass rules that translate destinations: the rules for leaving traffic see it

    # -- statements ------------------------------------------------------------------------

    def build(self) -> Policy:
        self._prescan()
        for stmt in self.statements:
            self._statement(stmt)
        for rule in self.rules + self.legacy:
            for name, _ in rule.interfaces:
                if name not in self.interfaces:
                    self.interfaces.append(name)
        for name in self.interfaces:
            self.p.zones[name] = Zone(name, [name] if _is_interface(name) else [])
        self._name_rules()
        model, nat = self._compose()
        self.p.rules = model
        self.p.nat_rules = nat
        self._rewrite()
        self._notes()
        return self.p

    def _prescan(self) -> None:
        """The names rules are "on": a word that names one of them in an address is that interface or group."""
        for stmt in self.statements:
            tokens = stmt.tokens
            if tokens[0] == "set":
                continue
            for index, token in enumerate(tokens[:-1]):
                if token not in ("on", "for"):
                    continue
                following = tokens[index + 1 : tokens.index("}", index) if tokens[index + 1] == "{" and "}" in tokens[index:] else index + 3]
                for word in following:
                    word = _unquote(word)
                    if word in ("{", "}", ",", "!", "any", "rdomain") or word.startswith("<") or parse_literal(word) is not None:
                        continue
                    if _INTERFACE.fullmatch(word) and word not in self.interfaces and word not in _OPTION_WORDS | {"inet", "inet6", "proto", "all", "quick", "log"}:
                        self.interfaces.append(word)
                    if tokens[index + 1] != "{":
                        break

    def _statement(self, stmt: _Stmt) -> None:
        word = stmt.tokens[0]
        if word not in _STATEMENTS:
            raise ParseError(f"line {stmt.line}: '{word[:30]}' does not start a statement of pf.conf FWShift reads")
        cur = _Cursor(stmt)
        if word in ("pass", "block", "match"):
            self.rules.append(self._rule(cur, stmt))
        elif word == "set":
            self._set(cur)
        elif word == "table":
            self._table(cur)
        elif word == "antispoof":
            self._antispoof(cur, stmt)
        elif word in ("nat", "rdr", "binat") or (word == "no" and stmt.tokens[1:2] in (["nat"], ["rdr"], ["binat"])):
            self.legacy.append(self._legacy(cur, stmt))
        elif word in ("anchor", "nat-anchor", "rdr-anchor", "binat-anchor", "load"):
            name = _unquote(stmt.tokens[2] if word == "load" and len(stmt.tokens) > 2 else stmt.tokens[1] if len(stmt.tokens) > 1 else "")
            inline = "{" in stmt.tokens
            self.anchors.append(f"'{name[:40]}' (line {stmt.line}{', rules written inline' if inline else ''})")
        elif word == "scrub":
            self.notes.setdefault("scrub", []).append(str(stmt.line))
        elif word in ("altq", "queue"):
            self.notes.setdefault("queue", []).append(str(stmt.line))
        elif word == "ether":
            self.notes.setdefault("ether", []).append(str(stmt.line))
        elif word == "include":
            self.notes.setdefault("include", []).append(f"{_unquote(stmt.tokens[1]) if len(stmt.tokens) > 1 else ''} (line {stmt.line})")
        else:
            raise ParseError(f"line {stmt.line}: 'no' is followed by nat, rdr or binat")

    def _set(self, cur: _Cursor) -> None:
        cur.expect("set")
        option = cur.take()
        if option == "skip":
            cur.expect("on")
            for name, negated in self._interface_list(cur):
                if negated:
                    raise ParseError(f"line {cur.line}: 'set skip on' takes no '!'")
                self.skip.append(name)
        elif option == "block-policy":
            value = cur.take()
            self.block_policy = Action.DENY if value == "return" else Action.DROP
        # The other options (timeouts, limits, optimization, state-policy, ...) decide nothing about which traffic passes.

    def _table(self, cur: _Cursor) -> None:
        cur.expect("table")
        token = cur.take()
        if not (token.startswith("<") and token.endswith(">")):
            raise ParseError(f"line {cur.line}: a table name is written <name>")
        name = token[1:-1]
        flags: List[str] = []
        entries: List[Tuple[str, bool]] = []
        files: List[str] = []
        while not cur.done():
            word = cur.take()
            if word in ("persist", "const", "counters"):
                flags.append(word)
            elif word == "file":
                files.append(_unquote(cur.take()))
            elif word == "{":
                while True:
                    item = cur.take()
                    if item == "}":
                        break
                    if item == ",":
                        continue
                    negated = item == "!"
                    if negated:
                        item = cur.take()
                    entries.append((_unquote(item), negated))
            else:
                raise ParseError(f"line {cur.line}: '{word[:30]}' in the definition of table <{name}>")
        self._table_group(name, entries, files, flags, cur.line)

    def _table_group(self, name: str, entries: List[Tuple[str, bool]], files: List[str], flags: List[str], line: int) -> None:
        why = ""
        members: List[str] = []
        if files:
            why = "its addresses are read from " + ", ".join(f"'{f[:60]}'" for f in files) + " when the rules are loaded, which is not in pf.conf"
        elif not entries and "const" not in flags:
            why = "it has no addresses in pf.conf: they are added at run time (pfctl -T add, overload)"
        literal: List[Tuple[Interval, bool]] = []
        other: List[str] = []
        for text, negated in entries:
            interval = parse_literal(text)
            if interval is not None and "-" not in text:
                literal.append((interval, negated))
            elif negated:
                other.append(text)
            else:
                member, problem = self._word_address(text, line)
                if problem:
                    why = why or f"entry '{text[:40]}': {problem}"
                else:
                    members.append(member)
        if other and not why:
            why = "it leaves out " + ", ".join(f"'{t[:40]}'" for t in other) + ", whose addresses are not in pf.conf"
        if any(negated for _, negated in literal) and members and not why:
            why = "it leaves addresses out and holds names whose addresses are not in pf.conf"
        if not why:
            # The most specific entry decides (a table is a radix tree): from the widest entry to the narrowest.
            ordered = sorted(literal, key=lambda item: (item[0][2] - item[0][1]), reverse=True)
            covered: List[Interval] = []
            for interval, negated in ordered:
                covered = subtract(covered, [interval]) if negated else normalize(covered + [interval])
            members = [interval_text(i) for i in _as_networks(covered)] + members
        group = AddressGroup(name, transform.dedupe(members), f"pf table <{name}>" + (f" ({' '.join(flags)})" if flags else ""))
        group.unsupported = why
        if why:
            self.report.add("address-group", name, Severity.REVIEW, "PF_TABLE_UNKNOWN", f"table <{name}> cannot be converted: {why}")
        self.p.address_groups[name] = group
        self.tables[name] = why

    def _antispoof(self, cur: _Cursor, stmt: _Stmt) -> None:
        cur.expect("antispoof")
        log = bool(cur.accept("log"))
        if log and cur.peek() == "(":
            cur.skip_value()
        quick = bool(cur.accept("quick"))
        cur.expect("for")
        interfaces = self._interface_list(cur)
        af = 4 if cur.accept("inet") else 6 if cur.accept("inet6") else 0
        label = ""
        while not cur.done():
            word = cur.take()
            if word == "label":
                label = _unquote(cur.take())
            else:
                raise ParseError(f"line {cur.line}: '{word[:30]}' in antispoof")
        for name, negated in interfaces:
            if negated:
                raise ParseError(f"line {cur.line}: antispoof for '!' an interface")
            # antispoof for X expands to: block in on ! X from X:network, and block in from the addresses of X.
            for others, member, what in (
                (True, self._interface_address(f"{name}:network", stmt.line), "network"),
                (False, self._interface_address(name, stmt.line), "address"),
            ):
                rule = _Rule(stmt.line, stmt.text, "block", block=self.block_policy, direction="in", quick=quick, log=log, af=af,
                             label=label, kind="antispoof")  # fmt: skip
                rule.interfaces = [(name, True)] if others else []
                rule.src = _Side([(member, False)])
                rule.name = f"antispoof {name} {what}"
                self.rules.append(rule)
                if name not in self.interfaces:
                    self.interfaces.append(name)

    # -- one filter rule ---------------------------------------------------------------------

    def _rule(self, cur: _Cursor, stmt: _Stmt) -> _Rule:
        rule = _Rule(stmt.line, stmt.text, cur.take())
        if rule.action == "block":
            rule.block = self.block_policy
            word = cur.accept("drop", "return", "return-rst", "return-icmp", "return-icmp6")
            if word == "drop":
                rule.block = Action.DROP
            elif word == "return-rst":
                rule.block = Action.RESET_CLIENT
            elif word:
                rule.block = Action.DENY
            if word and word != "drop" and cur.peek() == "(":
                cur.skip_value()
        rule.direction = cur.accept("in", "out") or "both"
        self._head(cur, rule)
        self._hosts(cur, rule)
        self._options(cur, rule)
        self._check(rule)
        return rule

    def _head(self, cur: _Cursor, rule: _Rule) -> None:
        """log, quick, on, the routing options of older pf, af, proto."""
        while True:
            if cur.accept("log"):
                rule.log = True
                if cur.peek() == "(":
                    rule.handling["log"] = cur.skip_value()
            elif cur.accept("quick"):
                rule.quick = True
            elif cur.accept("on"):
                if cur.accept("rdomain"):
                    rule.unsupported.append(f"routing domain {cur.take()}")
                else:
                    rule.interfaces = self._interface_list(cur)
            elif cur.peek() in ("route-to", "reply-to", "dup-to", "fastroute"):
                self._routing(cur, rule)
            elif cur.accept("inet"):
                rule.af = 4
            elif cur.accept("inet6"):
                rule.af = 6
            elif cur.accept("proto"):
                rule.protos = self._protocols(cur, rule)
            else:
                return

    def _interface_list(self, cur: _Cursor) -> List[Tuple[str, bool]]:
        out: List[Tuple[str, bool]] = []
        if cur.accept("{"):
            while not cur.accept("}"):
                if cur.accept(","):
                    continue
                negated = bool(cur.accept("!"))
                out.append((_unquote(cur.take()), negated))
            return out
        negated = bool(cur.accept("!"))
        name = _unquote(cur.take())
        if name == "any":
            return []
        return [(name, negated)]

    def _protocols(self, cur: _Cursor, rule: _Rule) -> List[str]:
        words: List[str] = []
        if cur.accept("{"):
            while not cur.accept("}"):
                if not cur.accept(","):
                    words.append(cur.take())
        else:
            words.append(cur.take())
        out: List[str] = []
        for word in words:
            name = _unquote(word).lower()
            number = int(name) if name.isdigit() and int(name) < 256 else PROTOCOL_NUMBERS.get(name)
            if number is None:
                rule.unsupported.append(f"protocol '{name[:30]}'")
                continue
            canonical = {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp6"}.get(number, str(number))
            if number == 0:
                rule.unsupported.append("protocol 0 (ip)")
                continue
            if canonical not in out:
                out.append(canonical)
        return out

    def _routing(self, cur: _Cursor, rule: _Rule) -> None:
        word = cur.take()
        values: List[str] = []
        if word != "fastroute":
            values.append(cur.skip_value())
            while cur.peek() in _POOL_TYPES:
                values.append(cur.take())
                if cur.peek() == "(":
                    values.append(cur.skip_value())
        rule.handling[word] = " ".join(values) or "on"
        rule.findings.append((Severity.REVIEW, "PF_ROUTE_TO", f"the rule sends what it matches elsewhere ({word} {' '.join(values)[:60]}); "
                              "the converted rule decides only whether it passes, and the traffic takes the route the target chooses"))  # fmt: skip

    def _hosts(self, cur: _Cursor, rule: _Rule) -> None:
        if cur.accept("all"):
            return
        if cur.accept("from"):
            rule.src = self._side(cur, rule, "source")
            if cur.accept("os"):
                rule.unsupported.append(f"operating system of the sender (os {cur.skip_value()[:30]})")
        if cur.accept("to"):
            rule.dst = self._side(cur, rule, "destination")

    def _side(self, cur: _Cursor, rule: _Rule, what: str) -> _Side:
        side = _Side(self._host_list(cur, rule)) if cur.peek() != "port" else _Side()
        if cur.accept("port"):
            ports = self._port_list(cur, rule)
            side.has_ports = True
            if ports is None:
                rule.unsupported.append(f"{what} port that cannot be read")
            elif not ports:
                rule.unsupported.append(f"{what} port that matches no port")
            else:
                side.ports = "" if ports == "0-65535" else ports
        return side

    def _host_list(self, cur: _Cursor, rule: _Rule) -> List[Host]:
        if cur.accept("{"):
            out: List[Host] = []
            while not cur.accept("}"):
                if cur.accept(","):
                    continue
                out += self._host_list(cur, rule)
            if not out:
                raise ParseError(f"line {cur.line}: an empty list")
            return out
        negated = bool(cur.accept("!"))
        token = cur.take()
        if token == "(":
            name = _unquote(cur.take())
            cur.expect(")")
            member, problem = self._interface_address(name, cur.line), ""
        elif token in ("no-route", "urpf-failed"):
            member, problem = "", f"'{token}', which depends on the routing table"
        elif token == "route":
            member, problem = "", f"addresses of routes labelled '{_unquote(cur.take())[:30]}'"
        elif token.startswith("<") and token.endswith(">"):
            member, problem = self._table_member(token[1:-1], cur.line), ""
        else:
            text = _unquote(token)
            if cur.peek() == "-" and parse_literal(text) is not None and parse_literal(cur.peek(1)) is not None:
                cur.take()
                last = cur.take()
                interval = parse_literal(f"{text}-{last}")
                if interval is None:
                    member, problem = "", f"range '{text} - {last}'"
                else:
                    member, problem = range_text(interval), ""
            else:
                member, problem = self._word_address(text, cur.line)
        if problem:
            rule.unsupported.append(problem)
            return [(ANY, False)]
        return [(member, negated)]

    def _word_address(self, text: str, line: int) -> Tuple[str, str]:
        """(member, problem) for an address written as a word: a literal, an interface, self or a host name."""
        if text == "any":
            return ANY, ""
        interval = parse_literal(text)
        if interval is not None:
            if interval in (FULL_V4, FULL_V6):
                return (ANY_V4 if interval[0] == 4 else ANY_V6), ""
            if "/" in text:
                try:
                    return str(ipaddress.ip_network(text, strict=False)), ""
                except ValueError:
                    return "", f"address '{text[:40]}'"
            return range_text(interval), ""
        if text == "self" or text.startswith("self:"):
            return self._interface_address(text, line), ""
        base, _, modifier = text.partition(":")
        if modifier and modifier not in ("network", "broadcast", "peer", "0"):
            return "", f"address '{text[:40]}'"
        if base in self.interfaces or _is_interface(base) and "." not in base:
            return self._interface_address(text, line), ""
        if modifier == "0" and _HOST_NAME.fullmatch(base):
            text = base
        if _HOST_NAME.fullmatch(text):
            if text not in self.p.addresses:
                self.p.addresses[text] = Address(text, AddressKind.FQDN, text.rstrip("."), "host name, resolved by pfctl when the rules are loaded")
                self.host_names.append(text)
            return text, ""
        return "", f"'{text[:40]}' is an interface group or a host name without a domain, which pf.conf does not tell apart"

    def _table_member(self, name: str, line: int) -> str:
        if name not in self.p.address_groups:
            group = AddressGroup(name, [], f"pf table <{name}>, not defined in pf.conf")
            group.unsupported = "the table is not defined in pf.conf: pfctl creates it empty, and its addresses are added at run time"
            self.report.add("address-group", name, Severity.REVIEW, "PF_TABLE_UNKNOWN", f"table <{name}> cannot be converted: {group.unsupported}")
            self.p.address_groups[name] = group
            self.tables[name] = group.unsupported
        return name

    def _interface_address(self, text: str, line: int) -> str:
        """The group for the addresses of an interface (or of every interface: self), with the given addresses if any."""
        base, _, modifier = text.partition(":")
        name = "self" if base == "self" else f"{base} {'address' if modifier in ('', '0') else modifier}"
        if name in self.p.address_groups:
            return name
        given = self.given.get(base.lower(), []) if base != "self" else [a for values in self.given.values() for a in values]
        members: List[str] = []
        for address in given:
            if modifier == "network":
                members.append(str(address.network))
            elif modifier == "broadcast":
                if address.version == 4 and address.network.prefixlen < 31:
                    members.append(str(address.network.broadcast_address))
            elif modifier in ("", "0"):
                members.append(str(address.ip))
        what = "the firewall's own addresses (self)" if base == "self" else f"the {modifier or 'address'} of {base}"
        group = AddressGroup(name, transform.dedupe(members), f"pf: {what}")
        if modifier == "peer":
            group.unsupported = f"the address of the peer of {base}, which is not in pf.conf"
        elif base == "self" and given:
            self.report.add("address-group", name, Severity.APPROX, "PF_SELF",
                            "self holds every address of the firewall; here it holds the addresses given with --interface-address")  # fmt: skip
        elif not given:
            group.unsupported = (f"{what} {'are' if base == 'self' else 'is'} not in pf.conf; give "
                                 + ("them" if base == "self" else "it") + " with --interface-address INTERFACE=ADDRESS/BITS")  # fmt: skip
        elif not members:
            group.unsupported = f"{what}: the given address has none"
        self.p.address_groups[name] = group
        return name

    def _port_list(self, cur: _Cursor, rule: _Rule) -> Optional[str]:
        ranges: List[Tuple[int, int]] = []
        if cur.accept("{"):
            while not cur.accept("}"):
                if cur.accept(","):
                    continue
                found = self._port_item(cur)
                if found is None:
                    return None
                ranges += found
        else:
            found = self._port_item(cur)
            if found is None:
                return None
            ranges = found
        merged = regions.merge_ranges(ranges)
        return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in merged)

    def _port_item(self, cur: _Cursor) -> Optional[List[Tuple[int, int]]]:
        operator = cur.accept("=", "!=", "<", "<=", ">", ">=")
        first = _port_number(_unquote(cur.take()))
        if first is None:
            return None
        if operator:
            low, high = first
            if low != high:
                return None
            value = low
            return {
                "=": [(value, value)],
                "!=": [(0, value - 1), (value + 1, 65535)],
                "<": [(0, value - 1)],
                "<=": [(0, value)],
                ">": [(value + 1, 65535)],
                ">=": [(value, 65535)],
            }[operator]
        binary = cur.accept("><", "<>", ":")
        if binary:
            second = _port_number(_unquote(cur.take()))
            if second is None or first[0] != first[1] or second[0] != second[1]:
                return None
            low, high = first[0], second[0]
            if binary == "><":
                return [(low + 1, high - 1)]
            if binary == "<>":
                return [(0, low - 1), (high + 1, 65535)]
            return [(low, high)]
        return [first]

    # -- the options after the addresses -----------------------------------------------------

    def _options(self, cur: _Cursor, rule: _Rule) -> None:
        while not cur.done():
            word = cur.take()
            if word == "flags":
                value = cur.take()
                rule.flags = value if value != "any" else "any"
            elif word in ("icmp-type", "icmp6-type"):
                rule.icmp_word = word
                rule.icmp += self._icmp_list(cur, rule, word == "icmp6-type")
            elif word in ("keep", "modulate", "synproxy"):
                cur.expect("state")
                rule.state = word
                if cur.peek() == "(":
                    options = cur.skip_value()
                    rule.handling["state"] = options
                    if "overload" in options.split():
                        rule.handling["overload"] = options
            elif word == "no":
                cur.expect("state")
                rule.state = "no"
            elif word == "sloppy":
                cur.accept("state")
                rule.handling["state"] = "sloppy"
            elif word in ("label", "tag"):
                value = _unquote(cur.take())
                setattr(rule, word, value)
                rule.handling[word] = value
            elif word == "!" and cur.peek() == "tagged":
                cur.take()
                rule.unsupported.append(f"a mark set by another rule (! tagged {_unquote(cur.take())[:30]})")
            elif word == "tagged":
                rule.unsupported.append(f"a mark set by another rule (tagged {_unquote(cur.take())[:30]})")
            elif word in ("user", "group"):
                rule.unsupported.append(f"the {word} of the socket ({word} {cur.skip_value()[:30]}), which only traffic of the firewall itself has")
                self._skip_operator_value(cur)
            elif word in ("probability", "max-pkt-rate", "tos", "fragment", "once", "received-on"):
                value = "" if word in ("fragment", "once") else cur.skip_value()
                if word == "received-on" and value == "!":
                    value += " " + cur.take()
                rule.unsupported.append(f"{word} {value}".strip()[:60])
            elif word in ("nat-to", "rdr-to", "binat-to"):
                rule.trans.append(self._translation(cur, rule, word))
            elif word == "af-to":
                rule.unsupported.append("translation to the other IP version (af-to)")
                cur.rest()
            elif word in ("route-to", "reply-to", "dup-to", "fastroute"):
                cur.index -= 1
                self._routing(cur, rule)
            elif word in ("divert-to", "divert-reply", "divert-packet"):
                rule.unsupported.append(f"traffic handed to a program on the firewall ({word})")
                cur.rest()
            elif word == "scrub":
                rule.handling["scrub"] = cur.skip_value() if cur.peek() == "(" else "on"
            elif word == "allow-opts":
                rule.handling["allow-opts"] = "on"
            elif word == "set":
                what = cur.take()
                rule.handling[f"set {what}"] = cur.skip_value()
            elif word in ("prio", "queue", "rtable", "max-mss", "ridentifier", "dnpipe", "dnqueue"):
                rule.handling[word] = cur.skip_value()
            else:
                rule.unsupported.append(f"option '{word[:30]}' that FWShift does not read")
                cur.rest()

    @staticmethod
    def _skip_operator_value(cur: _Cursor) -> None:
        while cur.peek() in ("=", "!=", "<", "<=", ">", ">=", "><", "<>"):
            cur.take()
            cur.take()

    def _icmp_list(self, cur: _Cursor, rule: _Rule, six: bool) -> List[Tuple[Optional[int], Optional[int]]]:
        out: List[Tuple[Optional[int], Optional[int]]] = []
        if cur.accept("{"):
            while not cur.accept("}"):
                if cur.accept(","):
                    continue
                out.append(self._icmp_item(cur, rule, six))
        else:
            out.append(self._icmp_item(cur, rule, six))
        return out

    def _icmp_item(self, cur: _Cursor, rule: _Rule, six: bool) -> Tuple[Optional[int], Optional[int]]:
        names = ICMP6_TYPES if six else ICMP_TYPES
        word = _unquote(cur.take()).lower()
        kind = int(word) if word.isdigit() and int(word) < 256 else names.get(word)
        code: Optional[int] = None
        if cur.accept("code"):
            text = _unquote(cur.take()).lower()
            codes = ICMP6_CODES if six else ICMP_CODES
            if text.isdigit() and int(text) < 256:
                code = int(text)
            elif text in codes and (kind is None or codes[text][0] == kind):
                kind, code = codes[text]
            else:
                rule.unsupported.append(f"ICMP code '{text[:30]}'")
        if kind is None:
            rule.unsupported.append(f"ICMP type '{word[:30]}'")
        return kind, code

    def _translation(self, cur: _Cursor, rule: _Rule, kind: str) -> _Trans:
        trans = _Trans(kind)
        if cur.peek() == "(":
            cur.take()
            trans.interface = _unquote(cur.take())
            cur.expect(")")
        else:
            hosts = self._host_list(cur, rule)
            if len(hosts) == 1 and not hosts[0][1] and hosts[0][0].endswith(" address"):
                trans.interface = hosts[0][0][: -len(" address")]
            elif any(negated for _, negated in hosts):
                trans.problems.append("a translated address with '!'")
            else:
                trans.hosts = hosts
        if trans.interface.endswith(":0"):
            trans.interface = trans.interface[:-2]  # the first address of the interface, not its aliases
        while True:
            if cur.accept("port"):
                words: List[str] = []
                while not cur.done() and cur.peek() not in _OPTION_WORDS | _POOL_TYPES | {"static-port"}:
                    words.append(cur.take())
                trans.port = "".join(words)
                if not words:
                    trans.problems.append("a port that cannot be read")
            elif cur.peek() in _POOL_TYPES:
                trans.pool = cur.take()
                if cur.peek() == "(":
                    trans.problems.append(f"pool option of {trans.pool}")
                    cur.skip_value()
            elif cur.accept("static-port"):
                trans.static_port = True
            else:
                return trans

    def _check(self, rule: _Rule) -> None:
        """What a rule says that changes its meaning for the model."""
        if rule.action == "match":
            return
        if rule.flags is not None and rule.flags != "any":
            given, _, mask = rule.flags.partition("/")
            if not set(given + mask) <= set("FSRPAUEW") or not rule.flags:
                rule.unsupported.append(f"TCP flags '{rule.flags[:20]}'")
            else:
                opening = {"S"} & set(mask or "FSRPAUEW")
                if set(given) != opening:
                    rule.unsupported.append(f"TCP flags {rule.flags} that the packet which opens a connection does not have")
        if rule.state == "no" and rule.action == "pass":
            rule.findings.append((Severity.APPROX, "PF_NO_STATE", "the rule passes packets without keeping state (no state): the "
                                  "replies need a rule of their own on pf. The converted rule allows the connection, replies included"))  # fmt: skip
        if rule.trans and rule.action == "block":
            rule.unsupported.append("a translation on a rule that blocks")

    # -- the older NAT rules of FreeBSD --------------------------------------------------------

    def _legacy(self, cur: _Cursor, stmt: _Stmt) -> _Rule:
        no = bool(cur.accept("no"))
        word = cur.take()
        rule = _Rule(stmt.line, stmt.text, word, no=no, direction={"nat": "out", "rdr": "in"}.get(word, "both"))
        if cur.accept("pass"):
            rule.passes = True
            if cur.accept("log"):
                rule.log = True
                if cur.peek() == "(":
                    cur.skip_value()
        if cur.accept("on"):
            rule.interfaces = self._interface_list(cur)
        while True:
            if cur.accept("inet"):
                rule.af = 4
            elif cur.accept("inet6"):
                rule.af = 6
            elif cur.accept("proto"):
                rule.protos = self._protocols(cur, rule)
            else:
                break
        self._hosts(cur, rule)
        while not cur.done():
            token = cur.take()
            if token in ("tag",):
                rule.handling["tag"] = _unquote(cur.take())
            elif token == "tagged" or (token == "!" and cur.peek() == "tagged"):
                if token == "!":
                    cur.take()
                rule.unsupported.append(f"a mark set by another rule (tagged {_unquote(cur.take())[:30]})")
            elif token == "->":
                if no:
                    raise ParseError(f"line {stmt.line}: 'no {word}' translates nothing")
                rule.trans.append(self._translation(cur, rule, word))
            else:
                rule.unsupported.append(f"option '{token[:30]}' that FWShift does not read")
                cur.rest()
        if not no and not rule.trans:
            raise ParseError(f"line {stmt.line}: '{word}' without '->'")
        return rule

    # -- names ----------------------------------------------------------------------------

    def _unique(self, name: str, taken: Set[str]) -> str:
        name = " ".join(name.split()) or "unnamed"
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name} {counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    def _name_rules(self) -> None:
        for rule in self.rules:
            base = rule.name or rule.label or f"line {rule.line}"
            rule.name = self._unique(base, self.names)
        for rule in self.legacy:
            rule.name = rule.label or f"line {rule.line} {'no ' if rule.no else ''}{rule.action}"  # (made unique with the NAT rule)

    # -- the model ---------------------------------------------------------------------------

    def _zones(self, rule: _Rule) -> Tuple[List[str], str]:
        """(zones of a rule, problem). ``!`` of an interface becomes the other zones the ruleset names."""
        if not rule.interfaces:
            return [ANY], ""
        plain = [name for name, negated in rule.interfaces if not negated]
        negated = [name for name, negated in rule.interfaces if negated]
        zones = list(plain)
        for name in negated:
            zones += [zone for zone in self.interfaces if zone != name]
            severity = Severity.APPROX if rule.action == "pass" else Severity.REVIEW
            rule.findings.append((severity, "PF_NEGATED_INTERFACE",
                                  f"'on ! {name}' is every interface but {name}; it is written for the other interfaces this "
                                  "ruleset names, " + (", ".join(z for z in self.interfaces if z != name) or "none") +
                                  ", and not for interfaces it does not name"))  # fmt: skip
        zones = transform.dedupe(zones)
        if not zones:
            return [], "it is for no interface the ruleset names"
        return zones, ""

    def _service(self, rule: _Rule) -> str:
        """The service object of a rule (created when needed); ANY for every protocol."""
        if not rule.service:
            rule.service = self._make_service(rule)
        return rule.service

    def _make_service(self, rule: _Rule) -> str:
        problems = rule.unsupported
        icmp_proto = "icmp6" if rule.icmp_word == "icmp6-type" else "icmp"
        if not rule.protos:
            if rule.src.has_ports or rule.dst.has_ports:
                problems.append("a port without 'proto tcp' or 'proto udp'")
            if rule.icmp:
                problems.append(f"{rule.icmp_word} without 'proto {icmp_proto}'")
            return ANY
        entries: List[ServiceEntry] = []
        for proto in rule.protos:
            if proto in ("tcp", "udp", "sctp"):
                entries.append(ServiceEntry(Protocol(proto), rule.dst.ports, rule.src.ports))
                continue
            if rule.src.has_ports or rule.dst.has_ports:
                problems.append(f"a port with protocol {proto}")
            if proto in ("icmp", "icmp6"):
                protocol = Protocol.ICMP if proto == "icmp" else Protocol.ICMP6
                if (proto == "icmp" and rule.af == 6) or (proto == "icmp6" and rule.af == 4):
                    problems.append(f"protocol {proto} in a rule for IPv{rule.af}")
                if rule.icmp and proto == icmp_proto:
                    entries += [ServiceEntry(protocol, icmp_type=kind, icmp_code=code) for kind, code in rule.icmp]
                else:
                    entries.append(ServiceEntry(protocol))
            else:
                entries.append(ServiceEntry(Protocol.IP, ip_protocol=int(proto)))
        if rule.icmp and icmp_proto not in rule.protos:
            problems.append(f"{rule.icmp_word} without 'proto {icmp_proto}'")
        return self._service_object(entries)

    def _service_object(self, entries: List[ServiceEntry]) -> str:
        parts: List[str] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                parts.append(f"{entry.protocol.value}-{entry.dst_ports or 'any'}" + (f"-from-{entry.src_ports}" if entry.src_ports else ""))
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                parts.append(entry.protocol.value + ("" if entry.icmp_type is None else f"-{entry.icmp_type}")
                             + ("" if entry.icmp_code is None else f"-{entry.icmp_code}"))  # fmt: skip
            else:
                parts.append(f"ip-{entry.ip_protocol}")
        name = "+".join(transform.dedupe(parts))
        if len(name) > 60:
            name = f"pf-service-{len(self.p.services) + 1}"
        if name not in self.p.services:
            self.p.services[name] = Service(name, entries, "pf: protocols and ports of a rule")
        return name

    def _member_family(self, member: str) -> int:
        if member in (ANY_V4, ANY_V6):
            return 4 if member == ANY_V4 else 6
        interval = parse_literal(member)
        return interval[0] if interval else 0

    def _pieces(self, rule: _Rule) -> List[Tuple[List[str], bool, List[str], bool, int]]:
        """The combinations pfctl expands a rule into, with ! of one element each on its own:
        (sources, negated, destinations, negated, IP version or 0)."""

        def splits(hosts: List[Host]) -> List[Tuple[List[str], bool]]:
            plain = [member for member, negated in hosts if not negated]
            out = [(transform.dedupe(plain), False)] if plain else []
            out += [([member], True) for member, negated in hosts if negated]
            return out

        out: List[Tuple[List[str], bool, List[str], bool, int]] = []
        for sources, source_negated in splits(rule.src.hosts):
            for destinations, destination_negated in splits(rule.dst.hosts):
                # pfctl takes the IP version of the rule from an address where the rule names none.
                family = rule.af
                if not family:
                    negated_families = {self._member_family(m) for m in (sources if source_negated else []) + (destinations if destination_negated else [])} - {0}
                    if len(negated_families) == 1:
                        family = negated_families.pop()
                    elif len(negated_families) > 1:
                        continue  # a combination of the two IP versions: pfctl skips it
                kept_sources, kept_destinations = sources, destinations
                if family:
                    every = ANY_V4 if family == 4 else ANY_V6
                    kept_sources = [every if m == ANY else m for m in sources if self._member_family(m) in (0, family)]
                    kept_destinations = [every if m == ANY else m for m in destinations if self._member_family(m) in (0, family)]
                    if not kept_sources or not kept_destinations:
                        continue
                out.append((kept_sources, source_negated, kept_destinations, destination_negated, family))
        return out

    def _model_rules(self, rule: _Rule, service: str) -> List[Rule]:
        out: List[Rule] = []
        pieces = self._pieces(rule)
        unsupported = list(rule.unsupported)
        if not pieces:
            unsupported.append("its addresses expand to no combination of one IP version, which pfctl refuses")
            pieces = [([ANY], False, [ANY], False, 0)]
        if len(pieces) > _MAX_PIECES:
            unsupported.append(f"'!' of list elements expands to {len(pieces)} rules")
            pieces = pieces[:1]
        negated_lists = [side for side, hosts in (("source", rule.src.hosts), ("destination", rule.dst.hosts))
                         if len(hosts) > 1 and any(negated for _, negated in hosts)]  # fmt: skip
        for index, (sources, source_negated, destinations, destination_negated, family) in enumerate(pieces):
            name = rule.name if index == 0 else self._unique(f"{rule.name}.{index + 1}", self.names)
            model = Rule(name=name, sources=sources, destinations=destinations, services=[service])
            model.origin = name
            model.negate_source, model.negate_destination = source_negated, destination_negated
            problems: List[str] = []
            if family:
                # The model has no IP version of its own: one side has to keep the rule to it. A table of both versions
                # on a side that is not negated becomes its part of this version.
                every = ANY_V4 if family == 4 else ANY_V6
                if not source_negated:
                    model.sources = sources = [self._family_part(m, family) for m in sources]
                if not destination_negated:
                    model.destinations = destinations = [self._family_part(m, family) for m in destinations]

                def keeps(members: List[str], negated: bool) -> bool:
                    return not negated and all(transform.families(self.p, m) == {family} for m in members)

                if keeps(sources, source_negated) and destinations == [every] and not destination_negated:
                    model.destinations = [ANY]
                elif keeps(destinations, destination_negated) and sources == [every] and not source_negated:
                    model.sources = [ANY]
                elif not keeps(sources, source_negated) and not keeps(destinations, destination_negated):
                    problems.append(f"it is for IPv{family} only, which no side of it keeps it to (a negation, or a table "
                                    "that holds addresses of both IP versions)")  # fmt: skip
            model.action = Action.ALLOW if rule.action == "pass" else rule.block
            if model.action == Action.RESET_CLIENT and rule.protos != ["tcp"]:
                model.action = Action.DENY  # pf answers what is not TCP with ICMP
            model.log_start, model.log_end = rule.log, False
            model.description = f"pf line {rule.line}: {rule.text[:160]}"
            model.unsupported = unsupported + problems
            model.handling = dict(rule.handling)
            model.source_ids = {"pf.line": str(rule.line)}
            if rule.label:
                model.source_ids["pf.label"] = rule.label
            out.append(model)
        if negated_lists:
            for model in out:
                self.report.add("rule", model.origin, Severity.INFO, "PF_NEGATED_LIST",
                                f"'!' before an element of the {' and '.join(negated_lists)} list: pfctl makes a rule of each "
                                "element, so the rule matches every address that one of them leaves out (every address, "
                                "unless they overlap); converted as pf reads it, a rule per element")  # fmt: skip
        return out

    def _family_part(self, member: str, family: int) -> str:
        """A group of both IP versions as the group of its addresses of one version; any other member as it is."""
        if member not in self.p.address_groups or transform.families(self.p, member) <= {family}:
            return member
        intervals, complete = transform.known_intervals(self.p, member)
        if not complete:
            return member
        name = f"{member} (IPv{family})"
        if name not in self.p.address_groups:
            kept = [interval_text(i) for i in _as_networks(normalize([i for i in intervals if i[0] == family]))]
            self.p.address_groups[name] = AddressGroup(name, kept, f"pf: the IPv{family} addresses of {member}, for a rule of IPv{family}")
        return name

    def _compose(self) -> Tuple[List[Rule], List[NatRule]]:
        decided = [r for r in self.rules if r.action in ("pass", "block")]
        ordered = [r for r in decided if r.quick] + list(reversed([r for r in decided if not r.quick]))
        self.order = {id(rule): index for index, rule in enumerate(ordered)}
        pieces_in: List[_Piece] = []
        pieces_out: List[_Piece] = []
        for rule in ordered:
            service = self._service(rule)
            zones, problem = self._zones(rule)
            if problem:
                rule.unsupported.append(problem)
                zones = [ANY]
            models = self._model_rules(rule, service)
            for model in models:
                for severity, code, message in rule.findings:
                    self.report.add("rule", model.origin, severity, code, message)
            if rule.direction in ("in", "both"):
                pieces_in += [_Piece(rule, model, zones) for model in models]
            if rule.direction in ("out", "both"):
                pieces_out += [_Piece(rule, model, zones) for model in models]
        out_rules = self._leaving(pieces_out, both={id(p.source) for p in pieces_in})
        in_rules: List[Rule] = []
        for piece in pieces_in:
            piece.rule.src_zones, piece.rule.dst_zones = list(piece.zones), [ANY]
            named = piece.rule.negate_source or any(m not in (ANY, ANY_V4, ANY_V6) for m in piece.rule.sources)
            for other in self.rules:
                # nat-to on arriving traffic by a match rule above: the rules after it see the translated source.
                if (named and other.action == "match" and other.direction == "in" and other.line < _line_of(piece)
                        and any(t.kind in ("nat-to", "binat-to") for t in other.trans) and _zones_meet(self._zones(other)[0], piece.zones)):  # fmt: skip
                    piece.rule.unsupported.append(f"it matches the source of arriving traffic, which is the source after the translation of '{other.name}'")
                    break
            self.seen_by[piece.rule.origin] = (piece.source.line, "in")
            in_rules.append(piece.rule)
        skipped = self._skipped()
        nat, passing = self._nat(ordered)
        return out_rules + passing + skipped + in_rules, nat

    def _skipped(self) -> List[Rule]:
        """set skip on an interface: what arrives there is not filtered."""
        out: List[Rule] = []
        for name in self.skip:
            if _LOOPBACK.fullmatch(name):
                continue
            rule = Rule(name=self._unique(f"set skip on {name}", self.names), src_zones=[name], dst_zones=[ANY])
            rule.origin = rule.name
            rule.log_end = False
            rule.description = f"pf: traffic that arrives on {name} is not filtered (set skip on {name})"
            if name not in self.p.zones:
                self.p.zones[name] = Zone(name, [name] if _is_interface(name) else [])
            out.append(rule)
        return out

    # -- traffic that leaves --------------------------------------------------------------------

    def _boxes(self, rule: Rule) -> Optional[List[regions.Box]]:
        """What a rule matches as boxes; None when that cannot be known."""
        if rule.unsupported:
            return None
        if rule.services == [ANY]:
            services = regions.ALL_SERVICES
        else:
            entries = [e for s in rule.services for e in (transform.flatten_services(self.p, s) or [])]
            found = regions.service_set(entries) if entries else None
            if found is None:
                return None
            services = found
        if rule.negate_service:
            services = regions.ALL_SERVICES.minus(services)
        out: List[regions.Box] = []
        sides: List[List[Interval]] = []
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            intervals: List[Interval] = []
            for member in members:
                resolved = transform.address_intervals(self.p, member)
                if resolved is None:
                    return None
                intervals += resolved
            intervals = normalize(intervals)
            sides.append(subtract([FULL_V4, FULL_V6], intervals) if negated else intervals)
        for version in (4, 6):
            src = regions.addresses(sides[0], version)
            dst = regions.addresses(sides[1], version)
            if src and dst and not services.empty():
                out.append((version, src, dst, services))
        return out

    def _leaving(self, pieces: List[_Piece], both: Set[int]) -> List[Rule]:
        """The rules for traffic that leaves: what blocks, less what an earlier deciding rule passes."""
        out: List[Rule] = []
        passes: List[Tuple[_Piece, Optional[List[regions.Box]]]] = []
        for piece in pieces:
            boxes = self._boxes(piece.rule)
            if piece.rule.action == Action.ALLOW:
                passes.append((piece, boxes))
                continue
            rule = piece.rule
            name = f"{rule.name} out" if id(piece.source) in both else rule.name
            snat = self._translated_source(piece)
            relevant = [(other, other_boxes) for other, other_boxes in passes
                        if _zones_meet(other.zones, piece.zones)
                        and (other_boxes is None or boxes is None or any(regions.box_and(a, b) for a in boxes for b in other_boxes))]  # fmt: skip
            template = _copy_rule(rule, self._unique(name, self.names) if name != rule.name else name)
            if snat:
                template.unsupported.append(snat)
            if not relevant:
                template.src_zones, template.dst_zones = [ANY], list(piece.zones)
                self._out_finding(template, piece, "")
                out.append(template)
                continue
            cutters = ", ".join(f"'{other.source.name}'" for other, _ in relevant[:4]) + (" and more" if len(relevant) > 4 else "")
            blocked = [other for other, _ in relevant if self._translated_source(other)]
            if boxes is None or any(other_boxes is None for _, other_boxes in relevant) or blocked:
                template.src_zones, template.dst_zones = [ANY], list(piece.zones)
                template.unsupported.append(f"it blocks traffic that leaves, except what a rule before it passes ({cutters}), "
                                            "which cannot be worked out")  # fmt: skip
                self._out_finding(template, piece, "")
                out.append(template)
                continue
            specific = any(ANY not in other.zones for other, _ in relevant)
            targets = list(piece.zones) if ANY not in piece.zones else ([z for z in self.interfaces if z not in self.skip] if specific else [ANY])
            made: List[Rule] = []
            failed = False
            for zone in targets:
                cuts = [b for other, other_boxes in relevant if ANY in other.zones or zone == ANY or zone in other.zones
                        for b in (other_boxes or [])]  # fmt: skip
                left = regions.minus_all(list(boxes), cuts)
                if left is None:
                    failed = True
                    break
                everything = [(4, [FULL_V4], [FULL_V4], regions.ALL_SERVICES), (6, [FULL_V6], [FULL_V6], regions.ALL_SERVICES)]
                if len(left) == 2 and all(any(_same_box(box, whole) for box in left) for whole in everything):
                    whole_rule = _copy_rule(template, template.name if not made else self._unique(f"{template.name}.{len(made) + 1}", self.names))
                    whole_rule.src_zones, whole_rule.dst_zones = [ANY], [zone]
                    whole_rule.sources, whole_rule.destinations, whole_rule.services = [ANY], [ANY], [ANY]
                    whole_rule.negate_source = whole_rule.negate_destination = whole_rule.negate_service = False
                    made.append(whole_rule)
                    continue
                for box in left:
                    made.append(self._box_rule(template, box, zone, len(made)))
            if failed or any(m.unsupported for m in made):
                template.src_zones, template.dst_zones = [ANY], list(piece.zones)
                template.unsupported.append(f"it blocks traffic that leaves, except what a rule before it passes ({cutters}); "
                                            "that is more than FWShift writes as rules")  # fmt: skip
                self._out_finding(template, piece, "")
                out.append(template)
                continue
            if not made:
                self.report.skip("rule", template.origin, "PF_OUT_SHADOWED",
                                 f"the rule blocks traffic that leaves, but the rules before it that decide ({cutters}) pass all of "
                                 "it: it decides nothing for forwarded traffic and is not converted for that direction", Severity.INFO)  # fmt: skip
                continue
            for model in made:
                self._out_finding(model, piece, cutters)
                if ANY in piece.zones and specific:
                    self.report.add("rule", model.origin, Severity.REVIEW, "PF_OUT_UNNAMED",
                                    "the rule blocks what leaves by any interface, less what rules for some interfaces pass; it is "
                                    "written for the interfaces this ruleset names, and traffic that leaves by another interface "
                                    "is not blocked by it")  # fmt: skip
            out += made
        return out

    def _out_finding(self, rule: Rule, piece: _Piece, cutters: str) -> None:
        self.seen_by[rule.origin] = (piece.source.line, "out")
        for severity, code, text in piece.source.findings:
            self.report.add("rule", rule.origin, severity, code, text)
        where = "every interface" if ANY in piece.zones else ", ".join(piece.zones)
        message = (f"the rule blocks traffic when it leaves by {where}: written as a rule for that destination zone from every zone, "
                   "ahead of the rules for arriving traffic")  # fmt: skip
        if cutters:
            message += f", less what the rules before it that decide pass ({cutters})"
        self.report.add("rule", rule.origin, Severity.INFO, "PF_OUT_BLOCK", message)

    def _box_rule(self, template: Rule, box: regions.Box, zone: str, index: int) -> Rule:
        version, src, dst, svc = box
        every = ANY_V4 if version == 4 else ANY_V6
        name = template.name if index == 0 else f"{template.name}.{index + 1}"
        rule = _copy_rule(template, name if index == 0 else self._unique(name, self.names))
        rule.src_zones, rule.dst_zones = [ANY], [zone]
        rule.sources = [every] if src == [regions.full(version)] else [interval_text(i) for i in _as_networks(src)]
        rule.destinations = [every] if dst == [regions.full(version)] else [interval_text(i) for i in _as_networks(dst)]
        rule.negate_source = rule.negate_destination = rule.negate_service = False
        found = regions.entries_of(svc, version)
        if found is None:
            rule.unsupported.append("the services it is left with are too many to write")
            return rule
        entries, negated = found
        if entries:
            rule.services, rule.negate_service = [self._service_object(entries)], negated
        else:
            rule.services = [ANY]
        return rule

    def _translated_source(self, piece: _Piece) -> str:
        """Why a rule for leaving traffic that names a source cannot be read: a source NAT applied before it."""
        rule = piece.rule
        if not rule.negate_source and all(m in (ANY, ANY_V4, ANY_V6) for m in rule.sources):
            return ""
        for other in self.legacy:
            if other.action in ("nat", "binat") and not other.no and _zones_meet(self._zones(other)[0], piece.zones):
                return f"it matches the source of traffic that leaves, which is the source after NAT rule '{other.name}'"
        for other in self.rules:
            if not any(t.kind in ("nat-to", "binat-to") for t in other.trans):
                continue
            # Translated when it arrives (by a match rule, or by the pass rule that decides), or by a match rule for
            # leaving traffic above this one. A pass rule for leaving traffic translates when it decides: after.
            arriving = other.direction == "in"
            above = other.action == "match" and other.line < piece.source.line and _zones_meet(self._zones(other)[0], piece.zones)
            if arriving or above:
                return f"it matches the source of traffic that leaves, which can be the source after the translation of '{other.name}'"
        return ""

    # -- NAT ------------------------------------------------------------------------------------

    def _nat(self, ordered: List[_Rule]) -> Tuple[List[NatRule], List[Rule]]:
        """The NAT rules in the order the model reads them, and allow rules for what rdr pass lets in."""
        legacy = sorted(self.legacy, key=lambda r: ({"binat": 0, "rdr": 1, "nat": 2}[r.action], r.line))
        out: List[NatRule] = []
        passing: List[Rule] = []
        for rule in legacy:
            nat = self._legacy_nat(rule)
            out.append(nat)
            if rule.action in ("rdr", "binat") and not rule.no:
                self.dnat_legacy.add(nat.origin)
            if rule.passes and rule.action == "rdr" and not nat.unsupported:
                allow = Rule(name=self._unique(f"{rule.name} pass", self.names), src_zones=list(nat.src_zones), dst_zones=[ANY],
                             sources=list(nat.sources), destinations=list(nat.destinations), services=[nat.service])  # fmt: skip
                allow.origin = allow.name
                allow.log_end, allow.log_start = False, rule.log
                allow.description = f"pf line {rule.line}: rdr pass lets what it translates in without the filter rules"
                allow.source_ids = {"pf.line": str(rule.line)}
                passing.append(allow)
            elif rule.passes:
                self.report.add("nat", nat.origin, Severity.REVIEW, "PF_NAT_PASS",
                                f"'{rule.action} pass' lets what it translates through without the filter rules for that direction; "
                                "the converted policy decides it by its rules")  # fmt: skip
        matching = [r for r in self.rules if r.action == "match" and r.trans]
        deciding = [r for r in ordered if r.trans and r.action == "pass"]
        for rule in matching + deciding:
            for trans in rule.trans:
                nat = self._filter_nat(rule, trans)
                out.append(nat)
                if trans.kind in ("rdr-to", "binat-to"):
                    if rule.action == "match":
                        self.dnat_match.append((rule.line, rule.direction, nat.origin))
                    else:
                        self.dnat_pass.append(nat.origin)
                if rule.action == "pass" and trans.kind == "rdr-to":
                    before = [other for other in ordered[: self.order[id(rule)]] if other.action == "pass" and not other.trans
                              and other.direction in ("in", "both") and _rules_meet(other, rule)]  # fmt: skip
                    if before:
                        self.report.add("nat", nat.origin, Severity.REVIEW, "PF_NAT_ON_PASS_RULE",
                                        f"the translation applies when rule '{rule.name}' decides; "
                                        + ", ".join(f"'{o.name}'" for o in before[:3])
                                        + " can decide first for part of its traffic, which then passes untranslated. The converted "
                                        "NAT rule translates all of it")  # fmt: skip
        return out, passing

    def _nat_base(self, rule: _Rule, name: str) -> NatRule:
        nat = NatRule(name=self._unique(name, self.nat_names))
        nat.origin = nat.name
        nat.combines = True  # a connection can be translated when it arrives and again when it leaves
        nat.description = f"pf line {rule.line}: {rule.text[:160]}"
        nat.unsupported = list(rule.unsupported)
        sources = [m for m, negated in rule.src.hosts if not negated]
        destinations = [m for m, negated in rule.dst.hosts if not negated]
        if len(sources) != len(rule.src.hosts) or len(destinations) != len(rule.dst.hosts):
            nat.unsupported.append("an address with '!' in a NAT rule")
        nat.sources = transform.dedupe(sources) or [ANY]
        nat.destinations = transform.dedupe(destinations) or [ANY]
        if rule.af == 6:
            nat.sources = [ANY_V6 if m == ANY else m for m in nat.sources]
        elif rule.af == 4:
            nat.sources = [ANY_V4 if m == ANY else m for m in nat.sources]
        nat.service = self._service(rule)
        return nat

    def _filter_nat(self, rule: _Rule, trans: _Trans) -> NatRule:
        suffix = {"nat-to": "nat", "rdr-to": "rdr", "binat-to": "binat"}[trans.kind]
        nat = self._nat_base(rule, f"{rule.name} {suffix}")
        zones, problem = self._zones(rule)
        if problem:
            nat.unsupported.append(problem)
            zones = [ANY]
        if rule.state == "no":
            nat.unsupported.append("no state: pf translates only with state")
        if trans.kind == "rdr-to":
            if rule.direction == "out":
                nat.unsupported.append("rdr-to on traffic that leaves")
            nat.src_zones = zones
            nat.destination_translation = self._dest_nat(nat, trans)
        elif trans.kind == "nat-to":
            if rule.direction == "in":
                nat.src_zones = zones
            else:
                nat.dst_zones = zones
                if rule.direction == "both":
                    nat.unsupported.append("nat-to on a rule for both directions, which also translates what arrives")
            nat.source_translation = self._source_nat(nat, trans, zones)
        else:
            nat.dst_zones = zones
            nat.source_translation = self._static_nat(nat, trans, rule)
        if rule.action == "match":
            nat.description += " (match: applied whenever it matches)"
        return nat

    def _legacy_nat(self, rule: _Rule) -> NatRule:
        nat = self._nat_base(rule, rule.name)
        zones, problem = self._zones(rule)
        if problem:
            nat.unsupported.append(problem)
            zones = [ANY]
        if rule.action == "rdr":
            nat.src_zones = zones
            if rule.no:
                nat.unsupported.append("exception from rdr only (no rdr); the rdr rules below it are converted without this exception")
            else:
                nat.destination_translation = self._dest_nat(nat, rule.trans[0])
        elif rule.action == "nat":
            nat.dst_zones = zones
            if not rule.no:
                nat.source_translation = self._source_nat(nat, rule.trans[0], zones)
        else:
            nat.dst_zones = zones
            if rule.no:
                nat.unsupported.append("exception from binat (no binat)")
            else:
                nat.source_translation = self._static_nat(nat, rule.trans[0], rule)
        return nat

    def _single(self, nat: NatRule, hosts: List[Host]) -> str:
        if len(hosts) != 1:
            nat.unsupported.append("a translation to several addresses (a pool)")
            return ""
        return hosts[0][0]

    def _dest_nat(self, nat: NatRule, trans: _Trans) -> Optional[DestNat]:
        nat.unsupported += trans.problems
        if trans.interface:
            nat.unsupported.append(f"a translation to the address of interface {trans.interface}")
            return None
        address = self._single(nat, trans.hosts)
        if not address:
            return None
        port = ""
        if trans.port.endswith(":*"):
            entries = transform.flatten_services(self.p, nat.service) or []
            original = {e.dst_ports for e in entries}
            start = _port_text(trans.port[:-2])
            if len(original) == 1 and start and "-" not in start:
                single = original.pop()
                if single and "," not in single and "-" not in single:
                    port = start
                else:
                    nat.unsupported.append(f"a port range translated to a range (port {trans.port})")
            else:
                nat.unsupported.append(f"a port range translated to a range (port {trans.port})")
        elif trans.port:
            port = _port_text(trans.port) or ""
            if not port or "-" in port:
                nat.unsupported.append(f"translated port '{trans.port[:30]}'")
                port = ""
        if trans.pool and trans.pool not in ("bitmask", "round-robin", "random"):
            nat.unsupported.append(f"pool type {trans.pool}")
        intervals = transform.address_intervals(self.p, address) or []
        spread = trans.pool != "bitmask" and any(first != last for _, first, last in intervals)
        return DestNat(address, port, spread=spread)

    def _source_nat(self, nat: NatRule, trans: _Trans, zones: List[str]) -> Optional[SourceNat]:
        nat.unsupported += trans.problems
        if trans.port:
            self.report.add("nat", nat.origin, Severity.INFO, "PF_NAT_PORTS",
                            f"the translated source ports are kept to {trans.port[:30]} on pf; that is not converted")  # fmt: skip
        if trans.interface:
            interface = trans.interface
            if ":" in interface:
                nat.unsupported.append(f"a translation to ({interface})")
            given = self.given.get(interface.lower(), [])
            address = next((str(a.ip) for a in given if a.version == 4), "")
            return SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=address)
        if not trans.hosts:
            return None
        addresses = [m for m, _ in trans.hosts]
        if trans.pool == "bitmask":
            return SourceNat(SnatKind.STATIC, addresses=addresses)
        if trans.pool and trans.pool not in ("round-robin", "random"):
            nat.unsupported.append(f"pool type {trans.pool}")
        return SourceNat(SnatKind.DYNAMIC if trans.static_port else SnatKind.DYNAMIC_PORT, addresses=addresses)

    def _static_nat(self, nat: NatRule, trans: _Trans, rule: _Rule) -> Optional[SourceNat]:
        nat.unsupported += trans.problems
        address = self._single(nat, trans.hosts)
        if len(nat.sources) != 1 or nat.sources[0] in (ANY, ANY_V4, ANY_V6):
            nat.unsupported.append("binat of other than one address or network")
        if not address:
            return None
        return SourceNat(SnatKind.STATIC, addresses=[address], bidirectional=True)

    # -- destinations after translation --------------------------------------------------------

    def _rewrite(self) -> None:
        """Rules that see a translated destination get the original one (the model matches before NAT)."""
        groups: Dict[Tuple[str, ...], List[Rule]] = {}
        for model in self.p.rules:
            if model.origin not in self.seen_by:
                continue  # (what rdr pass lets in names the original destination)
            line, direction = self.seen_by[model.origin]
            seen = set(self.dnat_legacy)
            for at, where, origin in self.dnat_match:
                # A match rule translates at once: the rules after it, and every rule for leaving traffic if it
                # translated what arrived, see the new destination.
                if (direction == "out" and where != "out") or at < line and (where == "out") == (direction == "out"):
                    seen.add(origin)
            if direction == "out":
                seen |= set(self.dnat_pass)
            if seen:
                groups.setdefault(tuple(sorted(seen)), []).append(model)
        for key, rules in groups.items():
            view = Policy(vendor="pf", addresses=self.p.addresses, address_groups=self.p.address_groups, services=self.p.services,
                          service_groups=self.p.service_groups, zones=self.p.zones, rules=rules, nat_rules=self.p.nat_rules)  # fmt: skip
            transform.rewrite_destinations(view, self.report, to_post_nat=False, only=set(key))
        translated = self.dnat_legacy | {origin for _, _, origin in self.dnat_match} | set(self.dnat_pass)
        self.p.lookup_after_dnat = bool(translated) and translated == self.dnat_legacy

    # -- notes ----------------------------------------------------------------------------------

    def _notes(self) -> None:
        late = [r for r in self.rules if r.action in ("pass", "block") and not r.quick]
        if late:
            self.report.note(Severity.INFO, "PF_LAST_MATCH",
                             f"{len(late)} rule{'s are' if len(late) != 1 else ' is'} not quick: pf decides by the last rule that "
                             "matches unless a quick rule matches first. The model is first match: the quick rules come first, in "
                             "their order, then the others, the last one first")  # fmt: skip
        self.report.note(Severity.INFO, "PF_DEFAULT_PASS", "pf passes what no rule matches; the model records that as its default action")
        if self.anchors:
            self.report.note(Severity.REVIEW, "PF_ANCHOR",
                             "the rules of these anchors are not converted: " + ", ".join(self.anchors[:6])
                             + (" and more" if len(self.anchors) > 6 else "") + ". Rules loaded into an anchor decide where the "
                             "anchor stands, before or after any converted rule; add them to the file to convert them")  # fmt: skip
        groups = [name for name in self.interfaces if not _is_interface(name)]
        if groups:
            self.report.note(Severity.REVIEW, "PF_INTERFACE_GROUPS",
                             "these are interface groups, whose interfaces are not in pf.conf: " + ", ".join(groups[:8])
                             + ". Each is a zone of its own here; an interface that is also named on its own is another zone, "
                             "although pf applies the rules of both to it")  # fmt: skip
        others = [name for name in self.skip if not _LOOPBACK.fullmatch(name)]
        if others:
            self.report.note(Severity.REVIEW, "PF_SKIP_INTERFACE",
                             "pf does not filter on " + ", ".join(others) + " (set skip on): what arrives there is allowed by a rule "
                             "at the top of the rules for arriving traffic; rules that block what leaves by every interface are "
                             "written for that interface as well")  # fmt: skip
        if "scrub" in self.notes:
            self.report.note(Severity.INFO, "PF_SCRUB", "scrub rules (lines " + ", ".join(self.notes["scrub"][:10]) + ") normalise packets "
                             "and decide nothing about which traffic passes; they are not converted")  # fmt: skip
        if "queue" in self.notes:
            self.report.note(Severity.INFO, "PF_QUEUE", "queues (lines " + ", ".join(self.notes["queue"][:10]) + ") shape traffic and "
                             "are not converted")  # fmt: skip
        if "ether" in self.notes:
            self.report.note(Severity.REVIEW, "PF_ETHER", "layer 2 rules (ether, lines " + ", ".join(self.notes["ether"][:10]) + ") are "
                             "not converted; they are evaluated before the rules of pf.conf and can block what those pass")  # fmt: skip
        if "include" in self.notes:
            self.report.note(Severity.REVIEW, "PF_INCLUDE", "included files are not read: " + ", ".join(self.notes["include"][:6])
                             + ". Their rules are missing from the converted policy")  # fmt: skip
        if self.host_names:
            self.report.note(Severity.INFO, "PF_HOST_NAMES", "pfctl resolves host names once, when the rules are loaded: "
                             + ", ".join(self.host_names[:6]) + ". They are host name objects here")  # fmt: skip
        overload = sorted({r.name for r in self.rules if "overload" in r.handling})
        if overload:
            self.report.note(Severity.INFO, "PF_OVERLOAD", "rules that add addresses to a table when they exceed a limit (overload): "
                             + ", ".join(f"'{n}'" for n in overload[:6]) + ". The table they fill is empty in pf.conf")  # fmt: skip


# -- helpers --------------------------------------------------------------------------------------


def _line_of(piece: _Piece) -> int:
    return piece.source.line


def _is_interface(name: str) -> bool:
    """An interface (a name that ends in a digit) rather than an interface group; ifconfig(8) of OpenBSD."""
    return bool(name) and name[-1].isdigit()


def _zones_meet(a: List[str], b: List[str]) -> bool:
    return ANY in a or ANY in b or bool(set(a) & set(b))


def _rules_meet(a: _Rule, b: _Rule) -> bool:
    """Whether two rules can match one packet, as far as their interfaces, protocols and IP versions tell."""

    def interfaces(rule: _Rule) -> List[str]:
        if not rule.interfaces or any(negated for _, negated in rule.interfaces):
            return [ANY]
        return [name for name, _ in rule.interfaces]

    if not _zones_meet(interfaces(a), interfaces(b)):
        return False
    if a.protos and b.protos and not set(a.protos) & set(b.protos):
        return False
    return not (a.af and b.af and a.af != b.af)


def _same_box(a: regions.Box, b: regions.Box) -> bool:
    return a[0] == b[0] and normalize(a[1]) == normalize(b[1]) and normalize(a[2]) == normalize(b[2]) and a[3].minus(b[3]).empty() and b[3].minus(a[3]).empty()


def _copy_rule(rule: Rule, name: str) -> Rule:
    import copy

    out = copy.deepcopy(rule)
    out.name = out.origin = name
    return out


def _as_networks(intervals: List[Interval]) -> List[Interval]:
    """Intervals split where they are no single network, so that each can be a literal of the model (and of a table)."""
    out: List[Interval] = []
    for version, first, last in intervals:
        make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        for net in ipaddress.summarize_address_range(make(first), make(last)):
            out.append((version, int(net.network_address), int(net.broadcast_address)))
    return out


def _port_number(text: str) -> Optional[Tuple[int, int]]:
    if ":" in text:
        first, _, last = text.partition(":")
        a, b = _port_number(first), _port_number(last)
        if a is None or b is None or a[0] != a[1] or b[0] != b[1] or a[0] > b[0]:
            return None
        return a[0], b[0]
    if text.isdigit():
        value = int(text)
        return (value, value) if value <= 65535 else None
    if text.lower() in SERVICE_PORTS:
        value = SERVICE_PORTS[text.lower()]
        return value, value
    return None


def _port_text(text: str) -> Optional[str]:
    found = _port_number(text)
    if found is None:
        return None
    return str(found[0]) if found[0] == found[1] else f"{found[0]}-{found[1]}"


def _given(values: Sequence[str]) -> Dict[str, List[IPInterface]]:
    out: Dict[str, List[IPInterface]] = {}
    for value in values:
        name, sep, text = value.partition("=")
        try:
            if not sep or not name.strip() or "/" not in text:
                raise ValueError
            address = ipaddress.ip_interface(text.strip())
        except ValueError:
            raise FwshiftError(
                f"--interface-address: '{value[:60]}' is not INTERFACE=ADDRESS/BITS (for example em0=198.51.100.2/24)"
            ) from None
        given = out.setdefault(name.strip().lower(), [])
        if any(other.version == address.version for other in given):
            raise FwshiftError(f"--interface-address: two IPv{address.version} addresses for '{name.strip()[:30]}'")
        given.append(address)
    return out
