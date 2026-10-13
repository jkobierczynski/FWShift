# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""nftables parser: ``nft list ruleset`` or ``nft -j list ruleset`` output -> neutral model.

How nftables behaviour is mapped onto the neutral model:

* Only forwarded traffic is policy: the base chains of type ``filter`` at the ``forward`` hook of the ``ip``,
  ``ip6`` and ``inet`` tables become the security rules. Chains at other hooks, and the tables of the ``bridge``,
  ``arp`` and ``netdev`` families, are reported, not converted.
* Every base chain at the forward hook sees a packet, in the order of their priority, whatever table it is in.
  An accept ends one base chain and the packet goes on to the next; a drop is final. A packet is forwarded only
  if each base chain accepts it: the chains are combined into one list of rules.
* Interfaces (``iifname``, ``oifname``) are the zones.
* nftables filters packets, the model connections. A rule that accepts established and related packets is what
  every stateful platform does by itself and is left out; the remaining rules describe new connections.
* Regular chains are flattened into the rule that jumps to them. A set, a verdict map or a NAT map becomes the
  alternatives it lists.
* A family without a base chain at the forward hook is not filtered at all. When only one IP version has one,
  the policy is for that version, as an iptables ruleset is.
* The forward hook sees packets after destination NAT in ``prerouting``, so its rules name the translated
  address; the model wants the original one.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..appmap import valid_ports
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
from ..netutil import FULL_V4, FULL_V6, Interval, intersect, interval_text, is_number, normalize, parse_literal, range_text
from ..netutil import subtract
from ..report import Report, Severity

_MAX_EFFECTIVE_RULES = 50000
_STATES = frozenset({"NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"})
_ALL_PORTS = [(0, 65535)]
_PROTOCOLS = {
    "tcp": 6, "udp": 17, "sctp": 132, "icmp": 1, "icmpv6": 58, "ipv6-icmp": 58, "udplite": 136, "dccp": 33,
    "gre": 47, "esp": 50, "ah": 51, "igmp": 2, "ipip": 4, "ipencap": 4, "egp": 8, "ipv6": 41, "rsvp": 46, "ospf": 89,
    "ospfigp": 89, "pim": 103, "vrrp": 112, "l2tp": 115, "comp": 108, "ipcomp": 108, "eigrp": 88, "etherip": 97,
    "encap": 98, "isis": 124, "mpls-in-ip": 137, "hopopt": 0,
}  # fmt: skip
_PORT_PROTOCOLS = {"tcp": 6, "udp": 17, "sctp": 132, "udplite": 136, "dccp": 33}
_PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "bootps": 67, "bootpc": 68,
    "tftp": 69, "http": 80, "www": 80, "kerberos": 88, "pop3": 110, "sunrpc": 111, "ntp": 123, "netbios-ns": 137,
    "netbios-dgm": 138, "netbios-ssn": 139, "imap": 143, "imap2": 143, "snmp": 161, "snmp-trap": 162, "ldap": 389,
    "https": 443, "microsoft-ds": 445, "isakmp": 500, "syslog": 514, "submission": 587, "ldaps": 636, "imaps": 993,
    "pop3s": 995, "openvpn": 1194, "ms-sql-s": 1433, "radius": 1812, "nfs": 2049, "mysql": 3306,
    "ms-wbt-server": 3389, "ipsec-nat-t": 4500, "sip": 5060, "postgresql": 5432, "http-alt": 8080,
}  # fmt: skip
_ICMP_TYPES = {
    "echo-reply": 0, "destination-unreachable": 3, "source-quench": 4, "redirect": 5, "echo-request": 8,
    "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11, "parameter-problem": 12,
    "timestamp-request": 13, "timestamp-reply": 14, "info-request": 15, "info-reply": 16,
    "address-mask-request": 17, "address-mask-reply": 18,
}  # fmt: skip
_ICMP6_TYPES = {
    "destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3, "parameter-problem": 4,
    "echo-request": 128, "echo-reply": 129, "mld-listener-query": 130, "mld-listener-report": 131,
    "mld-listener-done": 132, "mld-listener-reduction": 132, "nd-router-solicit": 133, "nd-router-advert": 134,
    "nd-neighbor-solicit": 135, "nd-neighbor-advert": 136, "nd-redirect": 137, "router-renumbering": 138,
    "ind-neighbor-solicit": 141, "ind-neighbor-advert": 142, "mld2-listener-report": 143,
}  # fmt: skip
_ICMP_CODES = {
    "net-unreachable": 0, "host-unreachable": 1, "prot-unreachable": 2, "port-unreachable": 3, "frag-needed": 4,
    "net-prohibited": 9, "host-prohibited": 10, "admin-prohibited": 13,
}  # fmt: skip
_ICMP6_CODES = {
    "no-route": 0, "admin-prohibited": 1, "addr-unreachable": 3, "port-unreachable": 4, "policy-fail": 5,
    "reject-route": 6,
}  # fmt: skip
# Header expressions: a protocol word and a field.
_HEADS = {
    "ip", "ip6", "tcp", "udp", "udplite", "sctp", "dccp", "th", "icmp", "icmpv6", "igmp", "ah", "esp", "comp",
    "ether", "vlan", "arp", "gre", "geneve", "vxlan", "gretap", "auth", "hbh", "rt0", "rt2", "srh", "frag", "dst",
    "mh", "ipsec", "osf", "socket", "rt", "numgen", "jhash", "symhash", "exthdr", "dccp", "cgroupv2", "tunnel",
}  # fmt: skip
# Meta keys nft prints without the word meta.
_BARE_META = {
    "iif", "oif", "iifname", "oifname", "iiftype", "oiftype", "mark", "skuid", "skgid", "rtclassid", "ibrname",
    "obrname", "ibriport", "obriport", "ibrpvid", "ibrvproto", "pkttype", "cpu", "iifgroup", "oifgroup", "cgroup",
    "nftrace", "sdif", "sdifname", "time", "day", "hour", "iifkind", "oifkind", "secpath", "broute",
}  # fmt: skip
_OPS = {"==": "==", "eq": "==", "!=": "!=", "ne": "!=", "!": "!=", "<": "<", "lt": "<", ">": ">", "gt": ">",
        "<=": "<=", "le": "<=", ">=": ">=", "ge": ">="}  # fmt: skip
_VERDICT_WORDS = {"accept", "drop", "continue", "return", "jump", "goto", "reject", "queue"}
_STATEMENT_WORDS = _VERDICT_WORDS | {
    "counter", "log", "limit", "comment", "dnat", "snat", "masquerade", "redirect", "xt", "#xt", "notrack", "flow",
    "quota", "fwd", "dup", "tproxy", "synproxy", "meta", "ct",
}  # fmt: skip
_NAT_FLAGS = {"random", "fully-random", "persistent", "netmap"}
_OPTION_FIELDS = {
    "size", "kind", "length", "value", "type", "flags", "tsval", "tsecr", "count", "left", "right", "addr", "ptr",
    "nexthdr", "hdrlength", "reserved", "id", "more-fragments", "frag-off", "seg-left", "last-entry", "tag", "subtype",
}  # fmt: skip
# Words that are never the value of a match: where one stands, the match before it had none that could be read.
_NOT_VALUES = _VERDICT_WORDS | {"vmap", "counter", "log", "comment", "limit", "quota", "meter"}
_PRIORITIES = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}
_BRIDGE_PRIORITIES = {"dstnat": -300, "filter": -200, "out": 100, "srcnat": 300}
_HOOKS_TO_CONVERT = ("forward", "prerouting", "postrouting")


# -- what was read ----------------------------------------------------------


@dataclass
class _Verdict:
    kind: str  # accept, drop, reject, jump, goto, return, continue, unknown
    target: str = ""  # the chain of a jump or goto
    reset: bool = False  # reject with tcp reset
    why: str = ""  # unknown: what the statement was


@dataclass
class _Nat:
    kind: str  # dnat, snat, masquerade, redirect
    family: str = ""  # ip, ip6 or "" as written
    address: str = ""
    port: str = ""
    prefix: bool = False
    problem: str = ""  # non-empty: what could not be read


@dataclass
class _Elem:
    key: Tuple[str, ...]
    data: Any = None  # _Verdict for a verdict map, a tuple of strings for a NAT map


@dataclass
class _Match:
    keys: Tuple[str, ...]
    op: str = "=="
    elems: List[_Elem] = field(default_factory=list)
    ref: str = ""  # name of a set or map, without the @


@dataclass
class _NRule:
    number: int
    matches: List[_Match] = field(default_factory=list)
    verdict: Optional[_Verdict] = None
    vmap: Optional[_Match] = None
    nat: Optional[_Nat] = None
    nat_map: Optional[_Match] = None  # with the template of the translation in nat
    log: bool = False
    log_group: str = ""  # log group N: the lines go to nflog, not to the kernel log
    limited: bool = False  # a limit statement: what the rule matches depends on a rate
    comment: str = ""
    unsupported: List[str] = field(default_factory=list)
    xt: bool = False
    misread: bool = False  # part of it could not be read: a verdict may have been in it


@dataclass
class _Set:
    name: str
    is_map: bool = False
    data_type: str = ""
    elems: List[_Elem] = field(default_factory=list)
    unknown: str = ""  # non-empty: why its contents are not known (filled at run time)


@dataclass
class _Chain:
    name: str
    display: str = ""
    type: str = ""
    hook: str = ""
    priority: int = 0
    policy: str = "accept"
    rules: List[_NRule] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.display or self.name


@dataclass
class _Table:
    family: str
    name: str
    chains: Dict[str, _Chain] = field(default_factory=dict)
    sets: Dict[str, _Set] = field(default_factory=dict)
    order: int = 0  # the order the tables were read in
    dormant: bool = False  # flags dormant: none of its chains is attached to a hook

    def chain(self, name: str) -> _Chain:
        if name not in self.chains:
            self.chains[name] = _Chain(name)
        return self.chains[name]


@dataclass
class _Ruleset:
    tables: Dict[Tuple[str, str], _Table] = field(default_factory=dict)
    iptables_nft: bool = False  # a table is managed by iptables-nft

    def table(self, family: str, name: str) -> _Table:
        key = (family, name)
        if key not in self.tables:
            self.tables[key] = _Table(family, name, order=len(self.tables))
        return self.tables[key]


def _priority(text: str, family: str, hook: str) -> Optional[int]:
    """``filter``, ``filter + 10``, ``dstnat - 5`` or a number -> the number; None if it is none of these."""
    words = text.replace("+", " + ").replace(" - ", " -  ").split()
    if len(words) == 1 and re.fullmatch(r"-?\d+", words[0]):
        return int(words[0])
    names = _BRIDGE_PRIORITIES if family == "bridge" else _PRIORITIES
    if not words or words[0] not in names:
        return None
    base = names[words[0]]
    if len(words) == 1:
        return base
    if len(words) == 3 and words[1] in ("+", "-") and words[2].isdigit():
        return base + int(words[2]) if words[1] == "+" else base - int(words[2])
    if len(words) == 2 and re.fullmatch(r"-\d+", words[1]):
        return base + int(words[1])
    return None


# -- text: the tokens ---------------------------------------------------------


@dataclass
class _Tok:
    text: str
    line: int
    quoted: bool = False


def _tokens(text: str) -> List[_Tok]:
    out: List[_Tok] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            out.append(_Tok("\n", line))
            line += 1
            i += 1
        elif c in " \t\r\f\v":
            i += 1
        elif c == "\\" and text[i + 1 : i + 2] == "\n":
            i += 2
            line += 1
        elif c == "#":
            end = text.find("\n", i)
            end = n if end < 0 else end
            comment = text[i + 1 : end].strip()
            if re.match(r"xt_\w+", comment):  # nft up to 1.0.2 writes the iptables extension as a comment
                out.append(_Tok("#xt", line))
                out.append(_Tok(comment[3:].split()[0], line, quoted=True))
            elif "managed by iptables-nft" in comment:
                out.append(_Tok("#iptables-nft", line))
            i = end
        elif c == '"':
            end = text.find('"', i + 1)
            if end < 0:
                raise ParseError(f"line {line}: a quoted string is not closed")
            value = text[i + 1 : end]
            out.append(_Tok(value, line, quoted=True))
            line += value.count("\n")
            i = end + 1
        elif c in "{};,":
            out.append(_Tok(c, line))
            i += 1
        else:
            j = i
            while j < n and text[j] not in ' \t\r\f\v\n{};"#':
                j += 1
            word = text[i:j]
            i = j
            if word.endswith(",") and len(word) > 1:
                out.append(_Tok(word.rstrip(","), line))
                out.append(_Tok(",", line))
            elif word:
                out.append(_Tok(word, line))
    return out


def _substitute(tokens: List[_Tok]) -> List[_Tok]:
    """Apply ``define NAME = value`` to ``$NAME``: what an input file may hold, never ``nft list ruleset``."""
    out: List[_Tok] = []
    defines: Dict[str, List[_Tok]] = {}
    i = 0
    at_start = True
    while i < len(tokens):
        tok = tokens[i]
        if at_start and not tok.quoted and tok.text in ("define", "redefine") and i + 2 < len(tokens):
            name = tokens[i + 1].text
            j = i + 2
            if tokens[j].text == "=":
                j += 1
            value: List[_Tok] = []
            depth = 0
            while j < len(tokens) and not (tokens[j].text == "\n" and depth == 0 and not tokens[j].quoted):
                if not tokens[j].quoted:
                    depth += {"{": 1, "}": -1}.get(tokens[j].text, 0)
                value.append(tokens[j])
                j += 1
            defines[name] = _expand(value, defines)
            i = j
            continue
        at_start = tok.text in ("\n", ";") and not tok.quoted
        if not tok.quoted and tok.text.startswith("$"):
            name = tok.text[1:]
            if name not in defines:
                raise ParseError(f"line {tok.line}: ${name} is not defined")
            out += [dataclasses.replace(t, line=tok.line) for t in defines[name]]
        else:
            out.append(tok)
        i += 1
    return out


def _expand(value: List[_Tok], defines: Dict[str, List[_Tok]]) -> List[_Tok]:
    out: List[_Tok] = []
    for tok in value:
        if not tok.quoted and tok.text.startswith("$") and tok.text[1:] in defines:
            out += defines[tok.text[1:]]
        else:
            out.append(tok)
    return out


# -- text: the structure ------------------------------------------------------

_FAMILIES = ("ip", "ip6", "inet", "arp", "bridge", "netdev")
_OBJECTS = {"counter", "quota", "limit", "ct", "secmark", "synproxy", "flowtable", "tunnel"}


class _TextReader:
    def __init__(self, tokens: List[_Tok]) -> None:
        self.t = tokens
        self.i = 0
        self.ruleset = _Ruleset()
        self.anonymous = 0

    # helpers

    def peek(self, ahead: int = 0) -> Optional[_Tok]:
        index = self.i + ahead
        return self.t[index] if index < len(self.t) else None

    def word(self, ahead: int = 0) -> str:
        tok = self.peek(ahead)
        return "" if tok is None or tok.quoted else tok.text

    def take(self) -> _Tok:
        tok = self.peek()
        if tok is None:
            raise ParseError("the input ends in the middle of a block")
        self.i += 1
        return tok

    def expect(self, text: str) -> None:
        tok = self.take()
        if tok.quoted or tok.text != text:
            raise ParseError(f"line {tok.line}: expected '{text}', got '{tok.text[:40]}'")

    def line_number(self) -> int:
        tok = self.peek()
        return tok.line if tok else (self.t[-1].line if self.t else 0)

    def statement(self) -> List[_Tok]:
        """The tokens up to the end of the statement (a new line or ';' outside braces), which is consumed;
        a closing brace of the block is left in place."""
        out: List[_Tok] = []
        depth = 0
        while self.peek() is not None:
            tok = self.t[self.i]
            if not tok.quoted:
                if tok.text in ("\n", ";") and depth == 0:
                    self.i += 1
                    break
                if tok.text == "}" and depth == 0:
                    break
                depth += {"{": 1, "}": -1}.get(tok.text, 0)
            out.append(tok)
            self.i += 1
        return out

    def skip_block(self) -> None:
        """From an opening brace to its closing brace."""
        self.expect("{")
        depth = 1
        while depth:
            tok = self.take()
            if not tok.quoted:
                depth += {"{": 1, "}": -1}.get(tok.text, 0)

    # the file

    def run(self) -> _Ruleset:
        while self.peek() is not None:
            tok = self.take()
            if tok.quoted:
                raise ParseError(f"line {tok.line}: unexpected string '{tok.text[:40]}'")
            text = tok.text
            if text in ("\n", ";"):
                continue
            if text == "#iptables-nft":
                self.ruleset.iptables_nft = True
                continue
            if text == "add" and self.word() == "table":
                text = self.take().text
            if text == "table":
                self.table()
            elif text == "flush" and self.word() == "ruleset":
                self.take()
                family = self.word() if self.word() in _FAMILIES else ""
                self.statement()
                for key in [k for k in self.ruleset.tables if not family or k[0] == family]:
                    del self.ruleset.tables[key]
            elif text in ("delete", "destroy", "flush") and self.word() == "table":
                self.take()
                family, name = self.table_name()
                self.statement()
                if text == "flush":
                    for chain in self.ruleset.table(family, name).chains.values():
                        chain.rules = []
                else:
                    self.ruleset.tables.pop((family, name), None)
            elif text == "include":
                raise ParseError(f"line {tok.line}: include is not followed; give FWShift the output of 'nft list ruleset'")
            elif text in ("add", "insert", "create", "replace", "delete", "destroy", "flush", "list", "reset", "rename",
                          "monitor", "describe", "export", "import"):  # fmt: skip
                raise ParseError(
                    f"line {tok.line}: '{text} {self.word()}' is a command; FWShift reads the ruleset as "
                    "'nft list ruleset' (or 'nft -j list ruleset') prints it"
                )
            else:
                raise ParseError(f"line {tok.line}: unexpected '{text[:40]}'; expected the output of 'nft list ruleset'")
        return self.ruleset

    def table_name(self) -> Tuple[str, str]:
        first = self.take()
        if not first.quoted and first.text in _FAMILIES and self.peek() is not None and self.word() not in ("{", "\n", ";", ""):
            return first.text, self.take().text
        return "ip", first.text  # the family nft takes when none is given

    def table(self) -> None:
        family, name = self.table_name()
        table = self.ruleset.table(family, name)
        if self.word() != "{":
            self.statement()  # "table inet t" alone: the table exists, with what it holds
            return
        self.take()
        while True:
            tok = self.take()
            text = "" if tok.quoted else tok.text
            if text in ("\n", ";"):
                continue
            if text == "}":
                return
            if text == "flags":
                if "dormant" in {f for w in self.statement() for f in w.text.split(",")}:
                    table.dormant = True
            elif text == "comment":
                self.statement()
            elif text == "chain":
                self.chain(table, self.take().text)
            elif text in ("set", "map"):
                self.set(table, self.take().text, text == "map")
            elif text in _OBJECTS:
                while self.word() not in ("{", "\n", ";", "}") and self.peek() is not None:
                    self.take()
                if self.word() == "{":
                    self.skip_block()
            else:
                raise ParseError(f"line {tok.line}: unexpected '{tok.text[:40]}' in table {name}")

    def chain(self, table: _Table, name: str) -> None:
        chain = table.chain(name)
        self.expect("{")
        self.body(table, chain)

    def body(self, table: _Table, chain: _Chain) -> None:
        """The lines of a chain up to and with its closing brace."""
        while True:
            tok = self.peek()
            if tok is None:
                raise ParseError(f"chain {chain.label} is not closed")
            if not tok.quoted and tok.text in ("\n", ";"):
                self.i += 1
                continue
            if not tok.quoted and tok.text == "}":
                self.i += 1
                return
            line = tok.line
            words = self.statement()
            if not words:
                continue
            head = "" if words[0].quoted else words[0].text
            if head == "type":
                self.chain_type(table, chain, words, line)
            elif head == "policy":
                if len(words) < 2 or words[1].text not in ("accept", "drop"):
                    raise ParseError(f"line {line}: unexpected chain policy")
                chain.policy = words[1].text
            elif head in ("comment", "flags", "devices", "device"):
                continue
            else:
                chain.rules.append(_RuleText(self, table, chain, words, len(chain.rules) + 1).parse())

    def chain_type(self, table: _Table, chain: _Chain, words: List[_Tok], line: int) -> None:
        texts = [w.text for w in words]
        try:
            chain.type, chain.hook = texts[1], texts[texts.index("hook") + 1]
            at = texts.index("priority")
        except (ValueError, IndexError):
            raise ParseError(f"line {line}: a chain type without its hook or priority") from None
        priority = _priority(" ".join(texts[at + 1 :]), table.family, chain.hook)
        if priority is None:
            raise ParseError(f"line {line}: priority '{' '.join(texts[at + 1:])}' cannot be read")
        chain.priority = priority

    def set(self, table: _Table, name: str, is_map: bool) -> None:
        item = table.sets.setdefault(name, _Set(name, is_map))
        self.expect("{")
        while True:
            tok = self.peek()
            if tok is None:
                raise ParseError(f"set {name} is not closed")
            if not tok.quoted and tok.text in ("\n", ";"):
                self.i += 1
                continue
            if not tok.quoted and tok.text == "}":
                self.i += 1
                return
            words = self.statement()
            head = "" if words[0].quoted else words[0].text
            if head in ("type", "typeof"):
                texts = [w.text for w in words]
                if ":" in texts:
                    item.data_type = " ".join(texts[texts.index(":") + 1 :])
            elif head == "flags":
                flags = {f for w in words[1:] for f in w.text.split(",") if f}
                if flags & {"dynamic", "timeout"}:
                    item.unknown = "flags " + ",".join(sorted(flags & {"dynamic", "timeout"}))
            elif head == "elements":
                at = next((index for index, w in enumerate(words) if w.text == "{" and not w.quoted), -1)
                if at < 0:
                    raise ParseError(f"line {words[0].line}: elements of set {name} without braces")
                elems = _elements(words[at + 1 : -1], is_map)
                for elem in elems if is_map else []:
                    if item.data_type == "verdict":
                        elem.data = _verdict_words(elem.data)
                    else:
                        elem.data = tuple(_value(v) for v in _split(elem.data, "."))
                item.elems += elems
            elif head in ("timeout", "gc-interval"):
                item.unknown = item.unknown or "a timeout"


def _split(tokens: Sequence[_Tok], separator: str) -> List[List[_Tok]]:
    """Tokens split at a separator outside braces."""
    out: List[List[_Tok]] = [[]]
    depth = 0
    for tok in tokens:
        if not tok.quoted:
            if tok.text == separator and depth == 0:
                out.append([])
                continue
            depth += {"{": 1, "}": -1}.get(tok.text, 0)
        out[-1].append(tok)
    return [part for part in out if part]


_ELEMENT_OPTIONS = {"timeout": 1, "expires": 1, "comment": 1, "counter": 0, "packets": 1, "bytes": 1}


def _elements(tokens: Sequence[_Tok], is_map: bool) -> List[_Elem]:
    """``a, b . c, d : e`` inside braces -> elements; new lines do not count."""
    tokens = [t for t in tokens if t.quoted or t.text != "\n"]
    out: List[_Elem] = []
    for part in _split(tokens, ","):
        pieces = _split(part, ":") if is_map else [part]
        key = _strip_options(pieces[0])
        data: Any = None
        if is_map:
            data = [t for t in pieces[1]] if len(pieces) > 1 else []
            data = _strip_options(data)
        values = _split(key, ".")
        # Words joined by commas without a space ("80,443") are elements of their own.
        if len(values) == 1 and len(values[0]) == 1 and not values[0][0].quoted and "," in values[0][0].text:
            for text in values[0][0].text.split(","):
                if text:
                    out.append(_Elem((text,), data))
            continue
        out.append(_Elem(tuple(_value(v) for v in values), data))
    return out


def _strip_options(tokens: Sequence[_Tok]) -> List[_Tok]:
    out: List[_Tok] = []
    skip = 0
    for tok in tokens:
        if skip:
            skip -= 1
            continue
        if not tok.quoted and tok.text in _ELEMENT_OPTIONS:
            skip = _ELEMENT_OPTIONS[tok.text]
            continue
        out.append(tok)
    return out


def _value(tokens: Sequence[_Tok]) -> str:
    return " ".join(t.text for t in tokens)


class _RuleText:
    """The statements of one rule, read from words."""

    def __init__(self, reader: _TextReader, table: _Table, chain: _Chain, words: List[_Tok], number: int) -> None:
        self.reader, self.table, self.chain = reader, table, chain
        self.w = words
        self.i = 0
        self.rule = _NRule(number)

    def peek(self, ahead: int = 0) -> str:
        index = self.i + ahead
        if index >= len(self.w):
            return ""
        tok = self.w[index]
        return '"' + tok.text if tok.quoted else tok.text

    def take(self) -> str:
        text = self.peek()
        self.i += 1
        return text

    def unsupported(self, text: str) -> None:
        if text not in self.rule.unsupported:
            self.rule.unsupported.append(text)

    def parse(self) -> _NRule:
        while self.i < len(self.w):
            word = self.peek()
            if word in _VERDICT_WORDS:
                self.verdict()
            elif word == "counter":
                self.take()
                if self.peek() == "name":
                    self.i += 2
                while self.peek() in ("packets", "bytes"):
                    self.i += 2
            elif word == "log":
                self.take()
                self.rule.log = True
                while self.peek() in ("prefix", "level", "group", "snaplen", "queue-threshold", "flags"):
                    if self.peek() == "group":
                        self.rule.log_group = self.peek(1)
                    if self.take() == "flags":  # flags tcp sequence,options / ip options / skuid / ether / all
                        while self.peek() in ("tcp", "ip", "skuid", "ether", "all"):
                            if self.take() in ("tcp", "ip"):
                                self.take()
                    else:
                        self.take()
            elif word == "limit":
                self.limit()
            elif word == "quota":
                self.take()
                self.rule.limited = True
                self.unsupported("quota")
                if self.peek() == "name":
                    self.i += 2
                else:  # quota [over|until] 25 mbytes [used 0 bytes]
                    if self.peek() in ("over", "until"):
                        self.take()
                    self.i += 2
                    if self.peek() == "used":
                        self.i += 3
            elif word == "meter":
                self.take()
                self.unsupported("meter")
                self.rule.limited = True
                while self.peek() and self.peek() != "{":
                    self.take()
                if self.peek() == "{":
                    self.skip_braces()
            elif word == "vmap":
                # A verdict map on an expression that could not be read: what it decides is not known.
                self.take()
                if self.peek() == "{":
                    self.skip_braces()
                else:
                    self.take()
                self.rule.verdict = _Verdict("unknown", why="a verdict map on an expression that cannot be read")
                self.unsupported("a verdict map on an expression that cannot be read")
            elif word == "comment":
                self.take()
                self.rule.comment = self.take().lstrip('"')
            elif word in ("dnat", "snat", "masquerade", "redirect"):
                self.nat()
            elif word in ("xt", "#xt"):
                self.take()
                if self.peek() in ("match", "target", "watcher"):
                    kind = self.take()
                else:
                    kind = "extension"
                name = self.take().lstrip('"')
                if kind == "extension" and name[:1].isupper():
                    kind = "target"  # iptables writes its targets in capitals
                self.rule.xt = True
                self.unsupported(f"iptables extension {kind} {name} (xt), which nft cannot show")
                if kind == "target":
                    self.rule.verdict = _Verdict("unknown", why=f"iptables target {name}")
            elif word in ("notrack", "flow", "fwd", "dup", "tproxy", "synproxy"):
                self.take()
                if word == "fwd":
                    self.rule.verdict = _Verdict("unknown", why="fwd")
                if word in ("tproxy", "synproxy"):
                    self.unsupported(word)
                self.skip_operands()
            elif word in ("add", "update", "delete") and self.peek(1).startswith("@"):
                self.i += 2
                if self.peek() == "{":
                    start = self.i
                    self.skip_braces()
                    if any(t.text == "limit" for t in self.w[start : self.i]):
                        self.unsupported(f"{word} @set with a limit")
            else:
                self.expression()
        return self.rule

    def skip_operands(self) -> None:
        while self.peek() and self.peek() not in _STATEMENT_WORDS:
            if self.peek() == "{":
                self.skip_braces()
            else:
                self.take()

    def skip_braces(self) -> List[_Tok]:
        """From an opening brace to its closing brace; the tokens inside."""
        start = self.i + 1
        depth = 0
        while self.i < len(self.w):
            tok = self.w[self.i]
            self.i += 1
            if not tok.quoted:
                depth += {"{": 1, "}": -1}.get(tok.text, 0)
                if depth == 0:
                    return self.w[start : self.i - 1]
        raise ParseError(f"line {self.w[0].line}: a brace is not closed")

    def verdict(self) -> None:
        word = self.take()
        if word in ("jump", "goto"):
            if self.peek() == "{":
                line = self.w[self.i].line
                inner = self.skip_braces()
                self.reader.anonymous += 1
                name = f"\x00anonymous{self.reader.anonymous}"
                chain = self.table.chain(name)
                chain.display = "anonymous"
                sub = _TextReader(inner + [_Tok("}", line)])
                sub.anonymous = self.reader.anonymous
                sub.body(self.table, chain)
                self.reader.anonymous = sub.anonymous
                self.rule.verdict = _Verdict(word, name)
            else:
                self.rule.verdict = _Verdict(word, self.take().lstrip('"'))
        elif word == "reject":
            reset = False
            if self.peek() == "with":
                self.take()
                kind = self.take()
                if kind == "tcp":
                    self.take()  # reset
                    reset = True
                else:
                    if self.peek() == "type":
                        self.take()
                    self.take()
            self.rule.verdict = _Verdict("reject", reset=reset)
        elif word == "queue":
            self.skip_operands()
            self.rule.verdict = _Verdict("unknown", why="queue to user space")
        else:
            self.rule.verdict = _Verdict(word)

    def limit(self) -> None:
        self.take()
        self.rule.limited = True
        text = "rate limit"
        if self.peek() == "name":
            self.take()
            text += " " + self.take().lstrip('"')
        elif self.peek() == "rate":
            self.take()
            if self.peek() == "over":
                text += " over"
                self.take()
            text += " " + self.take()
            if "/" in self.peek():
                text += " " + self.take()
            if self.peek() == "burst":
                self.take()
                self.take()
                if self.peek() in ("packets", "bytes", "kbytes", "mbytes"):
                    self.take()
        self.unsupported(text)

    def selector(self) -> Tuple[str, bool]:
        """One expression that is matched against: (key, known)."""
        word = self.take()
        if word == "meta":
            return f"meta {self.take()}", True
        if word in _BARE_META:
            return f"meta {word}", True
        if word == "ct":
            parts = ["ct"]
            if self.peek() in ("original", "reply"):
                parts.append(self.take())
                if self.peek() in ("ip", "ip6"):
                    parts.append(self.take())
            if self.peek() == "count":
                self.take()
                if self.peek() == "over":
                    self.take()
                return "ct count", False
            parts.append(self.take())
            return " ".join(parts), True
        if word == "fib":
            self.take()  # the first flag
            while self.peek() == ".":
                self.take()
                self.take()
            self.take()  # the result: oif, oifname or type
            return "fib", False
        if word in _HEADS:
            if word in ("tcp", "ip", "ip6", "sctp") and self.peek() in ("option", "chunk") or word == "exthdr":
                # tcp option maxseg [size], ip option rr [ptr], sctp chunk data [flags], exthdr hbh [nexthdr]
                parts = [word] + ([self.take()] if word != "exthdr" else []) + [self.take()]
                if self.peek() in _OPTION_FIELDS:
                    parts.append(self.take())
                return " ".join(parts), False
            if word == "rt":
                if self.peek() in ("ip", "ip6"):
                    self.take()
                return f"rt {self.take()}", False
            if word in ("socket", "osf", "ipsec", "numgen", "jhash", "symhash", "tunnel"):
                return word, False
            return f"{word} {self.take()}", True
        if word.startswith("@"):
            return word, False
        return word, False

    def expression(self) -> None:
        start = self.i
        keys: List[str] = []
        known = True
        key, ok = self.selector()
        keys.append(key)
        known = known and ok
        while self.peek() == ".":
            self.take()
            key, ok = self.selector()
            keys.append(key)
            known = known and ok
        word = self.peek()
        if word == "set":
            self.take()  # a statement that changes the packet or its connection: decides nothing
            self.skip_value()
            return
        if word in ("&", "|", "^", "<<", ">>"):
            self.unsupported(f"{' '.join(keys)} {word} ... (a bit operation)")
            self.take()
            self.skip_value()
            if self.peek() in _OPS:
                self.take()
            self.skip_value()
            return
        if word == "vmap":
            self.take()
            match = _Match(tuple(keys))
            self.rhs(match, True)
            self.rule.vmap = match
            if not known:
                self.unsupported(f"verdict map on {' . '.join(keys)}")
            return
        op = "=="
        if word in _OPS:
            op = _OPS[self.take()]
        if self.i >= len(self.w) or (self.peek() in _NOT_VALUES and not self.w[self.i].quoted):
            what = " ".join(t.text for t in self.w[start : self.i])
            self.unsupported(f"'{what}' (a match that cannot be read)")
            self.rule.misread = True
            return
        match = _Match(tuple(keys), op)
        self.rhs(match, False)
        if not known:
            self.unsupported(f"match on {' . '.join(keys)}")
            if keys[0] not in _KNOWN_UNKNOWN and not keys[0].split(" ")[0] in ("tcp", "ip", "ip6", "sctp", "exthdr", "rt"):
                self.rule.misread = True  # (a key nft has, read in full, is no misread)
            return
        self.rule.matches.append(match)

    def skip_value(self) -> None:
        """A value or an expression that gives one (``meta mark``, ``ip saddr map { ... }``)."""
        if self.peek() == "{":
            self.skip_braces()
            return
        word = self.peek()
        if word in _HEADS or word in _BARE_META or word in ("meta", "ct", "fib"):
            self.selector()
        else:
            self.take()
        while self.peek() in (".", "map", "&", "|", "^"):
            self.take()
            if self.peek() == "{":
                self.skip_braces()
                return
            word = self.peek()
            if word in _HEADS or word in _BARE_META or word in ("meta", "ct"):
                self.selector()
            else:
                self.take()

    def rhs(self, match: _Match, is_map: bool) -> None:
        word = self.peek()
        if word == "{":
            match.elems = _elements(self.skip_braces(), is_map)
            for elem in match.elems:
                if is_map:
                    elem.data = _verdict_words(elem.data)
            return
        if word.startswith("@"):
            match.ref = self.take()[1:]
            return
        values = [self.take().lstrip('"')]
        while self.peek() == ".":  # a concatenation of values
            self.take()
            values.append(self.take().lstrip('"'))
        if len(values) == 1 and "," in values[0] and not self.w[self.i - 1].quoted:
            match.elems = [_Elem((part,)) for part in values[0].split(",") if part]  # flags: established,related
        else:
            match.elems = [_Elem(tuple(values))]

    def nat(self) -> None:
        kind = self.take()
        nat = _Nat(kind)
        if self.peek() in ("ip", "ip6") and self.peek(1) in ("to", "prefix"):
            nat.family = self.take()
        if self.peek() == "prefix":
            self.take()
            nat.prefix = True
        if self.peek() == "to":
            self.take()
            word = self.peek()
            if word in _HEADS or word in _BARE_META or word in ("meta", "ct"):
                keys = [self.selector()[0]]
                while self.peek() == ".":
                    self.take()
                    keys.append(self.selector()[0])
                if self.peek() != "map":
                    nat.problem = "a translation that is an expression"
                    self.skip_value()
                else:
                    self.take()
                    match = _Match(tuple(keys))
                    if self.peek() == "{":
                        match.elems = _elements(self.skip_braces(), True)
                        for elem in match.elems:
                            elem.data = tuple(_value(v) for v in _split(elem.data, "."))
                    elif self.peek().startswith("@"):
                        match.ref = self.take()[1:]
                    self.rule.nat_map = match
            else:
                target = self.take()
                if target.startswith(":"):
                    nat.port = target[1:]
                elif target.startswith("["):
                    address, _, port = target[1:].partition("]")
                    nat.address, nat.port = address, port.lstrip(":")
                elif target.count(":") == 1:
                    nat.address, _, nat.port = target.partition(":")
                else:
                    nat.address = target
        while self.peek() and all(flag in _NAT_FLAGS for flag in self.peek().split(",")):
            self.take()
        self.rule.nat = nat
        self.rule.verdict = _Verdict("accept")  # a NAT statement ends the chain as an accept does


def _verdict_words(tokens: Any) -> _Verdict:
    words = [t.text for t in tokens] if tokens else []
    if not words:
        return _Verdict("unknown", why="a verdict that cannot be read")
    if words[0] in ("jump", "goto") and len(words) > 1:
        return _Verdict(words[0], words[1])
    if words[0] in ("accept", "drop", "continue", "return"):
        return _Verdict(words[0])
    if words[0] == "reject":
        return _Verdict("reject", reset="reset" in words)
    return _Verdict("unknown", why=" ".join(words))


# -- JSON ---------------------------------------------------------------------------


def _json_atom(value: Any) -> str:
    if isinstance(value, bool):
        raise ValueError("a boolean")
    if isinstance(value, (int, str)):
        return str(value)
    if isinstance(value, dict):
        if "prefix" in value:
            return f"{value['prefix']['addr']}/{value['prefix']['len']}"
        if "range" in value:
            first, last = value["range"]
            return f"{_json_atom(first)}-{_json_atom(last)}"
        if "elem" in value:
            return _json_atom(value["elem"]["val"])
    raise ValueError(f"value {json.dumps(value)[:60]}")


def _json_key(value: Any) -> Tuple[str, ...]:
    if isinstance(value, dict) and "elem" in value:
        value = value["elem"]["val"]
    if isinstance(value, dict) and "concat" in value:
        return tuple(_json_atom(v) for v in value["concat"])
    return (_json_atom(value),)


def _json_selector(expr: Any) -> Tuple[Tuple[str, ...], bool]:
    """(keys, known) of an expression that is matched against."""
    if isinstance(expr, dict) and "concat" in expr:
        keys: List[str] = []
        known = True
        for part in expr["concat"]:
            more, ok = _json_selector(part)
            keys += more
            known = known and ok
        return tuple(keys), known
    if isinstance(expr, dict) and len(expr) == 1:
        kind, body = next(iter(expr.items()))
        if kind == "payload" and isinstance(body, dict) and "protocol" in body:
            return (f"{body['protocol']} {body['field']}",), True
        if kind == "meta" and isinstance(body, dict):
            return (f"meta {body.get('key')}",), True
        if kind == "ct" and isinstance(body, dict):
            parts = ["ct"] + [str(body[k]) for k in ("dir", "family") if k in body] + [str(body.get("key"))]
            return (" ".join(parts),), True
        return (str(kind),), False
    return (json.dumps(expr)[:40],), False


def _json_verdict(statement: Dict[str, Any]) -> Optional[_Verdict]:
    for kind in ("accept", "drop", "continue", "return"):
        if kind in statement:
            return _Verdict(kind)
    for kind in ("jump", "goto"):
        if kind in statement:
            target = statement[kind].get("target") if isinstance(statement[kind], dict) else None
            if not isinstance(target, str):
                return _Verdict("unknown", why=f"{kind} to an anonymous chain")
            return _Verdict(kind, target)
    if "reject" in statement:
        body = statement["reject"] or {}
        return _Verdict("reject", reset=body.get("type") == "tcp reset")
    return None


def _json_limit(value: Any) -> str:
    """The words nft lists a limit statement with: ``rate limit over 5/minute``."""
    if not isinstance(value, dict):
        return f"rate limit {value}" if isinstance(value, str) else "rate limit"
    text = "rate limit" + (" over" if value.get("inv") else "")
    unit = value.get("rate_unit", "")
    rate = f"{value.get('rate')} {unit}/{value.get('per')}" if unit and unit != "packets" else f"{value.get('rate')}/{value.get('per')}"
    return f"{text} {rate}"


class _JsonReader:
    def __init__(self, document: Any) -> None:
        self.document = document
        self.ruleset = _Ruleset()

    def run(self) -> _Ruleset:
        items = self.document.get("nftables") if isinstance(self.document, dict) else None
        if not isinstance(items, list):
            raise ParseError("JSON without an 'nftables' list; expected the output of 'nft -j list ruleset'")
        numbers: Dict[Tuple[str, str, str], int] = {}
        for item in items:
            if not isinstance(item, dict) or len(item) != 1:
                continue
            kind, body = next(iter(item.items()))
            if not isinstance(body, dict):
                continue
            try:
                if kind == "table":
                    table = self.ruleset.table(str(body["family"]), str(body["name"]))
                    flags = body.get("flags", [])
                    table.dormant = "dormant" in ([flags] if isinstance(flags, str) else flags)
                elif kind == "chain":
                    chain = self.ruleset.table(str(body["family"]), str(body["table"])).chain(str(body["name"]))
                    if "hook" in body:
                        chain.type, chain.hook = str(body.get("type", "filter")), str(body["hook"])
                        chain.priority = int(body.get("prio", 0))
                        chain.policy = str(body.get("policy", "accept"))
                elif kind in ("set", "map"):
                    self.set(body, kind == "map")
                elif kind == "rule":
                    key = (str(body["family"]), str(body["table"]), str(body["chain"]))
                    numbers[key] = numbers.get(key, 0) + 1
                    table = self.ruleset.table(key[0], key[1])
                    table.chain(key[2]).rules.append(self.rule(body, numbers[key]))
                elif kind == "metainfo":
                    continue
            except (KeyError, TypeError, ValueError) as error:
                raise ParseError(f"a {kind} that cannot be read: {error}") from None
        return self.ruleset

    def set(self, body: Dict[str, Any], is_map: bool) -> None:
        table = self.ruleset.table(str(body["family"]), str(body["table"]))
        item = table.sets.setdefault(str(body["name"]), _Set(str(body["name"]), is_map))
        flags = body.get("flags", [])
        flags = [flags] if isinstance(flags, str) else flags
        if set(flags) & {"dynamic", "timeout"}:
            item.unknown = "flags " + ",".join(sorted(set(flags) & {"dynamic", "timeout"}))
        if "timeout" in body:
            item.unknown = item.unknown or "a timeout"
        if is_map:
            item.data_type = str(body.get("map", ""))
        elems = body.get("elem", [])
        elems = elems if isinstance(elems, list) else [elems]
        for elem in elems:
            if is_map:
                key, data = elem
                item.elems.append(_Elem(_json_key(key), self.map_data(data, item.data_type)))
            else:
                item.elems.append(_Elem(_json_key(elem)))

    @staticmethod
    def map_data(data: Any, data_type: str) -> Any:
        if data_type == "verdict" or (isinstance(data, dict) and _json_verdict(data) is not None):
            verdict = _json_verdict(data) if isinstance(data, dict) else None
            return verdict or _Verdict("unknown", why="a verdict that cannot be read")
        return _json_key(data)

    def rule(self, body: Dict[str, Any], number: int) -> _NRule:
        rule = _NRule(number)
        rule.comment = str(body.get("comment", ""))
        for statement in body.get("expr", []):
            if not isinstance(statement, dict) or len(statement) != 1:
                # nft writes some statements as their text: a jump to an anonymous chain has no JSON form.
                text = statement if isinstance(statement, str) else json.dumps(statement)[:60]
                rule.unsupported.append(f"a statement nft writes no JSON for ({' '.join(text.split())[:60]})")
                rule.misread = True
                if text.lstrip().startswith(("jump", "goto")):
                    rule.verdict = _Verdict("unknown", why="a jump to an anonymous chain the JSON does not show")
                continue
            kind, value = next(iter(statement.items()))
            verdict = _json_verdict(statement)
            if verdict is not None:
                rule.verdict = verdict
            elif kind == "match":
                self.match(rule, value)
            elif kind == "vmap":
                keys, known = _json_selector(value["key"])
                match = _Match(keys)
                data = value["data"]
                if isinstance(data, str) and data.startswith("@"):
                    match.ref = data[1:]
                else:
                    items = data["set"] if isinstance(data, dict) else data
                    items = items if isinstance(items, list) else [items]
                    match.elems = [_Elem(_json_key(k), self.map_data(v, "verdict")) for k, v in items]
                rule.vmap = match
                if not known:
                    rule.unsupported.append(f"verdict map on {' . '.join(keys)}")
            elif kind in ("counter", "notrack", "flow", "mangle", "set", "comment"):
                if kind == "set" and isinstance(value, dict) and any("limit" in json.dumps(s) for s in value.get("stmt", [])):
                    rule.unsupported.append("set update with a limit")
            elif kind == "log":
                rule.log = True
                if isinstance(value, dict) and "group" in value:
                    rule.log_group = str(value["group"])
            elif kind in ("limit", "quota"):
                rule.limited = True
                rule.unsupported.append(_json_limit(value) if kind == "limit" else "quota")
            elif kind in ("dnat", "snat", "masquerade", "redirect"):
                self.nat(rule, kind, value or {})
            elif kind == "xt":
                name = value.get("name", "") if isinstance(value, dict) else ""
                xt_kind = value.get("type", "extension") if isinstance(value, dict) else "extension"
                rule.xt = True
                rule.unsupported.append(f"iptables extension {xt_kind} {name} (xt), which nft cannot show".replace("  ", " "))
                if xt_kind == "target":
                    rule.verdict = _Verdict("unknown", why=f"iptables target {name}")
            elif kind == "queue":
                rule.verdict = _Verdict("unknown", why="queue to user space")
            elif kind == "fwd":
                rule.verdict = _Verdict("unknown", why="fwd")
            else:
                rule.unsupported.append(f"statement {kind}")
                rule.misread = True
        return rule

    @staticmethod
    def match(rule: _NRule, value: Dict[str, Any]) -> None:
        keys, known = _json_selector(value["left"])
        op = {"in": "=="}.get(value.get("op", "=="), value.get("op", "=="))
        if op not in ("==", "!=", "<", ">", "<=", ">="):
            rule.unsupported.append(f"{' . '.join(keys)} {op} ... (a bit operation)")
            return
        if not known:
            rule.unsupported.append(f"match on {' . '.join(keys)}")
            return
        right = value["right"]
        match = _Match(keys, op)
        if isinstance(right, str) and right.startswith("@"):
            match.ref = right[1:]
        else:
            if isinstance(right, dict) and "set" in right:
                items = right["set"] if isinstance(right["set"], list) else [right["set"]]
            elif isinstance(right, list):
                items = right  # flags: ["established", "related"]
            else:
                items = [right]
            try:
                match.elems = [_Elem(_json_key(item)) for item in items]
            except ValueError as error:
                rule.unsupported.append(f"match on {' . '.join(keys)} with {error}")
                return
        rule.matches.append(match)

    @staticmethod
    def nat(rule: _NRule, kind: str, value: Dict[str, Any]) -> None:
        nat = _Nat(kind, family=str(value.get("family", "")))
        if "prefix" in value.get("flags", []) or value.get("type_flags") == "prefix":
            nat.prefix = True
        address = value.get("addr")
        if isinstance(address, dict) and "map" in address:
            keys, _ = _json_selector(address["map"]["key"])
            match = _Match(keys)
            data = address["map"]["data"]
            if isinstance(data, str) and data.startswith("@"):
                match.ref = data[1:]
            else:
                items = data["set"] if isinstance(data, dict) else data
                match.elems = [_Elem(_json_key(k), _json_key(v)) for k, v in items]
            rule.nat_map = match
        elif address is not None:
            try:
                nat.address = _json_atom(address)
            except ValueError:
                nat.problem = "a translation that is an expression"
        if "port" in value:
            try:
                nat.port = _json_atom(value["port"])
            except ValueError:
                nat.problem = "a translated port that is an expression"
        rule.nat = nat
        rule.verdict = _Verdict("accept")


# -- what a rule matches --------------------------------------------------------------

Show = Optional[Tuple[Tuple[str, ...], bool]]  # how a side was written: its members, negated


@dataclass(frozen=True)
class _Cond:
    """What a packet has to be for a rule (and the rules that led to it) to match. None: anything."""

    families: FrozenSet[int] = frozenset({4, 6})
    iif: Optional[FrozenSet[str]] = None
    oif: Optional[FrozenSet[str]] = None
    src: Optional[Tuple[Interval, ...]] = None
    dst: Optional[Tuple[Interval, ...]] = None
    proto: Optional[FrozenSet[int]] = None
    dport: Optional[Tuple[Tuple[int, int], ...]] = None
    sport: Optional[Tuple[Tuple[int, int], ...]] = None
    icmp: Optional[FrozenSet[Tuple[int, int]]] = None  # (1 or 58, type)
    codes: Optional[FrozenSet[int]] = None
    states: Optional[FrozenSet[str]] = None
    unsupported: Tuple[str, ...] = ()
    src_show: Show = None
    dst_show: Show = None
    comment: str = ""

    def trivial(self) -> bool:
        return self == _Cond(families=self.families, comment=self.comment) and self.families == frozenset({4, 6})


TRUE = _Cond()


def _ranges(items: Sequence[Tuple[int, int]]) -> Tuple[Tuple[int, int], ...]:
    out: List[Tuple[int, int]] = []
    for low, high in sorted(items):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return tuple(out)


def _range_meet(a: Sequence[Tuple[int, int]], b: Sequence[Tuple[int, int]]) -> Tuple[Tuple[int, int], ...]:
    return _ranges([(max(x[0], y[0]), min(x[1], y[1])) for x in a for y in b if max(x[0], y[0]) <= min(x[1], y[1])])


def _range_complement(a: Sequence[Tuple[int, int]], top: int) -> Tuple[Tuple[int, int], ...]:
    out: List[Tuple[int, int]] = []
    low = 0
    for first, last in _ranges(a):
        if first > low:
            out.append((low, first - 1))
        low = last + 1
    if low <= top:
        out.append((low, top))
    return tuple(out)


def _meet_side(
    a: Optional[Tuple[Interval, ...]], a_show: Show, b: Optional[Tuple[Interval, ...]], b_show: Show
) -> Tuple[Optional[Tuple[Interval, ...]], Show, bool]:
    """(addresses in both, how to show them, possible)."""
    if a is None:
        return b, b_show, True
    if b is None:
        return a, a_show, True
    both = tuple(intersect(a, b))
    if not both:
        return None, None, False
    if list(both) == normalize(a):
        return both, a_show, True
    if list(both) == normalize(b):
        return both, b_show, True
    return both, None, True


def _meet_set(a: Optional[FrozenSet[Any]], b: Optional[FrozenSet[Any]]) -> Tuple[Optional[FrozenSet[Any]], bool]:
    if a is None:
        return b, True
    if b is None:
        return a, True
    both = a & b
    return both, bool(both)


def _meet_ranges(
    a: Optional[Tuple[Tuple[int, int], ...]], b: Optional[Tuple[Tuple[int, int], ...]]
) -> Tuple[Optional[Tuple[Tuple[int, int], ...]], bool]:
    if a is None:
        return b, True
    if b is None:
        return a, True
    both = _range_meet(a, b)
    return both, bool(both)


def _meet(a: _Cond, b: _Cond) -> Optional[_Cond]:
    """Both conditions at once; None if no packet meets both."""
    families = a.families & b.families
    iif, ok1 = _meet_set(a.iif, b.iif)
    oif, ok2 = _meet_set(a.oif, b.oif)
    src, src_show, ok3 = _meet_side(a.src, a.src_show, b.src, b.src_show)
    dst, dst_show, ok4 = _meet_side(a.dst, a.dst_show, b.dst, b.dst_show)
    proto, ok5 = _meet_set(a.proto, b.proto)
    dport, ok6 = _meet_ranges(a.dport, b.dport)
    sport, ok7 = _meet_ranges(a.sport, b.sport)
    icmp, ok8 = _meet_set(a.icmp, b.icmp)
    codes, ok9 = _meet_set(a.codes, b.codes)
    states, ok10 = _meet_set(a.states, b.states)
    if not (families and ok1 and ok2 and ok3 and ok4 and ok5 and ok6 and ok7 and ok8 and ok9 and ok10):
        return None
    unsupported = a.unsupported + tuple(text for text in b.unsupported if text not in a.unsupported)
    out = _Cond(families, iif, oif, src, dst, proto, dport, sport, icmp, codes, states, unsupported, src_show, dst_show,
                b.comment or a.comment)  # fmt: skip
    return _settle(out)


def _settle(c: _Cond) -> Optional[_Cond]:
    """Make the parts agree: addresses and ICMP of one IP version keep the condition to that version."""
    families = set(c.families)
    for side in (c.src, c.dst):
        if side is not None:
            families &= {interval[0] for interval in side}
    proto = c.proto
    if proto is not None:
        if 4 not in families:
            proto = proto - {1}
        if 6 not in families:
            proto = proto - {58}
        if not proto:
            return None
        if proto <= {1}:
            families &= {4}
        elif proto <= {58}:
            families &= {6}
    icmp = c.icmp
    if icmp is not None:
        icmp = frozenset(item for item in icmp if proto is None or item[0] in proto)
        icmp = frozenset(item for item in icmp if (4 if item[0] == 1 else 6) in families)
        if not icmp:
            return None
    if not families:
        return None
    src = None if c.src is None else tuple(i for i in c.src if i[0] in families)
    dst = None if c.dst is None else tuple(i for i in c.dst if i[0] in families)
    if src == () or dst == ():
        return None
    src_show = c.src_show if src == c.src else None
    dst_show = c.dst_show if dst == c.dst else None
    return dataclasses.replace(c, families=frozenset(families), proto=proto, icmp=icmp, src=src, dst=dst,
                               src_show=src_show, dst_show=dst_show)  # fmt: skip


def _with_problem(c: _Cond, text: str) -> _Cond:
    return c if text in c.unsupported else dataclasses.replace(c, unsupported=c.unsupported + (text,))


def _port(text: str) -> Optional[Tuple[int, int]]:
    first, sep, last = text.partition("-")
    values = []
    for part in (first, last) if sep else (first,):
        if is_number(part):
            values.append(int(part))
        elif part in _PORT_NAMES:
            values.append(_PORT_NAMES[part])
        else:
            return None
    low, high = values[0], values[-1]
    return (low, high) if low <= high <= 65535 else None


def _number(text: str, names: Dict[str, int], top: int) -> Optional[Tuple[int, int]]:
    """A name, a number or a range of numbers -> (first, last)."""
    if text in names:
        return names[text], names[text]
    first, sep, last = text.partition("-")
    if is_number(first) and (not sep or is_number(last)):
        low, high = int(first), int(last or first)
        if low <= high <= top:
            return low, high
    return None


def _addresses(values: Sequence[str], family: int) -> Optional[List[Interval]]:
    out: List[Interval] = []
    for text in values:
        interval = parse_literal(text)
        if interval is None or interval[0] != family:
            return None
        out.append(interval)
    return normalize(out)


def _shown(values: Sequence[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for text in values:
        interval = parse_literal(text)
        out.append(interval_text(interval) if interval is not None else text)
    return tuple(out)


def constrain(c: _Cond, key: str, op: str, values: Sequence[str], show: Optional[Tuple[str, ...]] = None) -> Optional[_Cond]:
    """The condition with one more match: ``key op values`` (any of the values). None if nothing can match."""
    negated = op == "!="
    what = f"{key} {op} {', '.join(values)[:60]}"
    if op in ("<", ">", "<=", ">="):
        ports = key.split()[-1] in ("dport", "sport") and key.split()[0] in _PORT_PROTOCOLS.keys() | {"th"}
        if not ports or len(values) != 1 or _port(values[0]) is None:
            return _with_problem(c, f"comparison {what}")
        value = _port(values[0])
        assert value is not None
        low, high = {"<": (0, value[0] - 1), ">": (value[1] + 1, 65535), "<=": (0, value[1]), ">=": (value[0], 65535)}[op]
        if low > high:
            return None
        return _meet(c, _port_cond(key, ((low, high),)))
    if key in ("meta iifname", "meta oifname", "meta iif", "meta oif"):
        if negated or any(v.endswith("*") for v in values) or not values:
            return _with_problem(c, f"interface match {what}")
        interfaces = frozenset(values)
        return _meet(c, _Cond(iif=interfaces) if key in ("meta iifname", "meta iif") else _Cond(oif=interfaces))
    if key in ("ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr"):
        family = 4 if key.startswith("ip ") else 6
        intervals = _addresses(values, family)
        if intervals is None:
            return _with_problem(c, f"address match {what}")
        full = FULL_V4 if family == 4 else FULL_V6
        if negated:
            intervals = subtract([full], intervals)
            if not intervals:
                return None
        members = show if show is not None else _shown(values)
        side_show: Show = (members, negated)
        part = (_Cond(families=frozenset({family}), src=tuple(intervals), src_show=side_show) if key.endswith("saddr")
                else _Cond(families=frozenset({family}), dst=tuple(intervals), dst_show=side_show))  # fmt: skip
        return _meet(c, part)
    if key in ("meta l4proto", "ip protocol", "ip6 nexthdr"):
        numbers: Set[int] = set()
        for text in values:
            item = _number(text, _PROTOCOLS, 255)
            if item is None:
                return _with_problem(c, f"protocol match {what}")
            numbers |= set(range(item[0], item[1] + 1))
        if negated:
            numbers = set(range(256)) - numbers
        families = {"ip protocol": frozenset({4}), "ip6 nexthdr": frozenset({6})}.get(key, frozenset({4, 6}))
        return _meet(c, _Cond(families=families, proto=frozenset(numbers)))
    head, _, field_name = key.partition(" ")
    if field_name in ("dport", "sport") and head in _PORT_PROTOCOLS.keys() | {"th"}:
        ranges: List[Tuple[int, int]] = []
        for text in values:
            item = _port(text)
            if item is None:
                return _with_problem(c, f"port match {what}")
            ranges.append(item)
        result = _range_complement(ranges, 65535) if negated else _ranges(ranges)
        if not result:
            return None
        return _meet(c, _port_cond(key, result))
    if key in ("icmp type", "icmpv6 type", "icmp code", "icmpv6 code"):
        v6 = key.startswith("icmpv6")
        code = key.endswith("code")
        names = (_ICMP6_CODES if v6 else _ICMP_CODES) if code else (_ICMP6_TYPES if v6 else _ICMP_TYPES)
        found: Set[int] = set()
        for text in values:
            item = _number(text, names, 255)
            if item is None:
                return _with_problem(c, f"ICMP match {what}")
            found |= set(range(item[0], item[1] + 1))
        if negated:
            found = set(range(256)) - found
        proto = 58 if v6 else 1
        part = _Cond(families=frozenset({6 if v6 else 4}), proto=frozenset({proto}))
        part = dataclasses.replace(part, codes=frozenset(found)) if code else dataclasses.replace(
            part, icmp=frozenset((proto, t) for t in found))  # fmt: skip
        return _meet(c, part)
    if key in ("meta nfproto", "meta protocol"):
        families_found: Set[int] = set()
        for text in values:
            if text in ("ipv4", "ip", "2", "0x0800"):
                families_found.add(4)
            elif text in ("ipv6", "ip6", "10", "0x86dd"):
                families_found.add(6)
            elif key == "meta nfproto":
                return _with_problem(c, f"match {what}")
        if negated:
            families_found = {4, 6} - families_found
        return _meet(c, _Cond(families=frozenset(families_found)))
    if key == "ct state":
        numeric = {"0x1": "invalid", "0x2": "established", "0x4": "related", "0x8": "new", "0x40": "untracked"}  # (nft -n)
        states = frozenset(numeric.get(v.lower(), v).upper() for v in values)
        if not states <= _STATES:
            return _with_problem(c, f"connection state match {what}")
        return _meet(c, _Cond(states=_STATES - states if negated else states))
    return _with_problem(c, f"match {what}")


def _port_cond(key: str, ranges: Tuple[Tuple[int, int], ...]) -> _Cond:
    head, _, field_name = key.partition(" ")
    proto = None if head == "th" else frozenset({_PORT_PROTOCOLS[head]})
    return _Cond(proto=proto, dport=ranges) if field_name == "dport" else _Cond(proto=proto, sport=ranges)


_FIELDS = ("families", "iif", "oif", "src", "dst", "proto", "dport", "sport", "icmp", "codes", "states")


def _without(context: _Cond, taken: _Cond) -> Any:
    """What is left of ``context`` once the packets of ``taken`` (a part of it) are gone: a condition, None when
    nothing is left, False when one condition cannot say it (the two differ in more than one part)."""
    if taken.unsupported != context.unsupported:
        return False
    differ = [name for name in _FIELDS if getattr(context, name) != getattr(taken, name)]
    if "families" in differ and len(differ) == 2:
        # An address of one IP version keeps a match to that version: no difference of its own.
        side = taken.src if "src" in differ else taken.dst if "dst" in differ else None
        if side is not None and taken.families == frozenset(i[0] for i in side) and taken.families < context.families:
            differ.remove("families")
    if len(differ) != 1:
        return False if differ else None
    name = differ[0]
    have, gone = getattr(context, name), getattr(taken, name)
    if name in ("src", "dst"):
        universe = [FULL_V4, FULL_V6] if have is None else list(have)
        universe = [i for i in universe if i[0] in context.families]
        left: Any = tuple(subtract(universe, gone))
        if not left:
            return None
        show_name = name + "_show"
        gone_show = getattr(taken, show_name)
        show = (gone_show[0], not gone_show[1]) if have is None and gone_show is not None else None  # "not those"
        return _settle(dataclasses.replace(context, **{name: left, show_name: show}))
    if name in ("dport", "sport"):
        left = _range_meet(_ALL_PORTS if have is None else have, _range_complement(gone, 65535))
    elif name == "families":
        left = have - gone
    elif name == "proto":
        left = (frozenset(range(256)) if have is None else have) - gone
    elif name == "states":
        left = (_STATES if have is None else have) - gone
    elif name == "codes":
        left = (frozenset(range(256)) if have is None else have) - gone
    elif name == "icmp" and have is not None:
        left = have - gone
    else:
        return False  # interfaces: "not these" is no list of names
    if not left:
        return None
    return _settle(dataclasses.replace(context, **{name: left}))


# -- following the chains -------------------------------------------------------------


@dataclass
class _Entry:
    """One rule as a packet meets it: what it matches, and what it does."""

    cond: _Cond
    action: str  # accept, drop, reject, reset, unknown, log (decides nothing), nat
    where: str
    log: bool = False
    nat: Optional[_Nat] = None
    why: str = ""  # unknown: what the verdict was
    via: Tuple[str, ...] = ()  # the rules of earlier base chains that accepted it
    limited: bool = False  # a log statement with a rate limit
    table: str = ""
    log_group: str = ""  # the nflog group its log statement writes to


class _Walker:
    """Turns a base chain and the chains it jumps to into one ordered list of entries."""

    def __init__(self, resolver: "_Builder", table: _Table, prefix: str) -> None:
        self.resolver, self.table, self.prefix = resolver, table, prefix
        self.out: List[_Entry] = []
        self.policy = "accept"

    def run(self, chain: _Chain, context: _Cond) -> List[_Entry]:
        self.policy = chain.policy
        self._walk(chain, context, (chain.name,), self.prefix, True)
        return self.out

    def _count(self) -> None:
        self.resolver.visited += 1
        if self.resolver.visited > _MAX_EFFECTIVE_RULES:
            raise ParseError("the chains expand to more than 50000 rules; refusing to continue")

    def _walk(self, chain: _Chain, context: _Cond, stack: Tuple[str, ...], prefix: str, to_policy: bool) -> bool:
        """Walk one chain; True when it ends for every packet (an unconditional return or goto)."""
        poisoned = ""
        for rule in chain.rules:
            where = f"{prefix}{chain.label}-{rule.number}"
            for cond, verdict, nat in self.resolver.alternatives(rule, self.table):
                own_trivial = cond.trivial()
                merged = _meet(context, cond)
                if merged is None:
                    continue  # can never match where this chain is reached
                if poisoned:
                    merged = _with_problem(merged, poisoned)
                self._count()
                if verdict is None and rule.misread:
                    # Part of the rule could not be read, and no verdict was found: one may have been in it.
                    self.out.append(_Entry(merged, "unknown", where, why="a rule that cannot be read", table=self.table.name))
                    continue
                if verdict is None or verdict.kind == "continue":
                    if rule.log:
                        self.out.append(_Entry(merged, "log", where, limited=rule.limited, table=self.table.name,
                                               log_group=rule.log_group))  # fmt: skip
                    continue
                kind = verdict.kind
                if kind == "return":
                    if to_policy:
                        self.out.append(_Entry(merged, self.policy, where + "-return", table=self.table.name))
                        if own_trivial and not merged.unsupported:
                            return True
                        continue
                    if own_trivial:
                        return True
                    rest = _without(context, merged)
                    if rest is None:
                        return True  # nothing is left for the rules below
                    if rest is not False:
                        context = rest  # exact: the rules below see what did not return
                        continue
                    poisoned = f"follows a conditional return in chain {chain.label}, which cannot be expressed"
                    continue
                if kind in ("jump", "goto"):
                    target = self.table.chains.get(verdict.target)
                    if target is None:
                        self.out.append(_Entry(_with_problem(merged, f"{kind} to chain {verdict.target}, which does not exist"),
                                               "unknown", where, why=kind, table=self.table.name))  # fmt: skip
                        continue
                    if target.name in stack:
                        self.out.append(_Entry(_with_problem(merged, f"jump loop through chain {target.label}"), "unknown", where,
                                               why=kind, table=self.table.name))  # fmt: skip
                        continue
                    if target.type:
                        self.out.append(_Entry(_with_problem(merged, f"{kind} to base chain {target.label}"), "unknown", where,
                                               why=kind, table=self.table.name))  # fmt: skip
                        continue
                    inner_prefix = where + "."
                    if kind == "jump":
                        self._walk(target, merged, stack + (target.name,), inner_prefix, False)
                        continue
                    # goto: the end of the other chain returns to where this chain would have returned to.
                    ended = self._walk(target, merged, stack + (target.name,), inner_prefix, to_policy)
                    if to_policy:
                        # What the other chain does not decide meets the policy of the base chain.
                        if not ended:
                            self.out.append(_Entry(merged, self.policy, where + "-goto-end", table=self.table.name))
                        if own_trivial:
                            return True
                        continue
                    if own_trivial:
                        return True
                    # The packets that took the goto never come back to this chain: they go on after the jump to it.
                    rest = _without(context, merged)
                    if rest is None:
                        return True
                    if rest is not False:
                        context = rest
                        continue
                    poisoned = f"follows a conditional goto in chain {chain.label}, which cannot be expressed"
                    continue
                if kind == "accept" and nat is not None:
                    self.out.append(_Entry(merged, "nat", where, log=rule.log, nat=nat, table=self.table.name))
                    continue
                action = {"accept": "accept", "drop": "drop", "reject": "reset" if verdict.reset else "reject"}.get(kind, "unknown")
                self.out.append(_Entry(merged, action, where, log=rule.log, why=verdict.why, table=self.table.name,
                                       log_group=rule.log_group))  # fmt: skip
        return False


# -- building the model -----------------------------------------------------------------


def looks_like_nftables(data: bytes) -> bool:
    """``nft list ruleset`` output or an nft input file (starts with a table, flush ruleset or define), or the JSON
    of ``nft -j list ruleset``."""
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"{"):
        return re.match(rb'\{\s*"nftables"\s*:', head) is not None
    for line in head.splitlines()[:50]:
        line = line.strip()
        if not line or line.startswith(b"#"):
            continue
        return re.match(rb"(table|flush\s+ruleset|define|add\s+table)\b", line) is not None
    return False


def read(data: bytes) -> _Ruleset:
    text = data.decode("utf-8-sig", errors="replace")
    if text.lstrip().startswith("{"):
        try:
            document = json.loads(text)
        except ValueError as error:
            raise ParseError(f"the JSON cannot be read: {error}") from None
        return _JsonReader(document).run()
    return _TextReader(_substitute(_tokens(text))).run()


def parse(data: bytes, report: Report) -> Policy:
    return _Builder(read(data), report).build()


class _Builder:
    def __init__(self, ruleset: _Ruleset, report: Report) -> None:
        self.ruleset, self.report = ruleset, report
        self.p = Policy(vendor="nftables", lookup_after_dnat=True)
        self.names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.visited = 0
        self.groups: Dict[str, str] = {}  # "@family table set" -> address group
        self.prefix_tables = False
        self.empty_sets: Set[str] = set()
        self.unknown_sets: Set[str] = set()
        self.xt = False

    # -- the alternatives of a rule ------------------------------------------

    def elements(self, match: _Match, table: _Table, c: _Cond) -> Tuple[Optional[List[_Elem]], Optional[str], _Cond]:
        """(elements, the name of the group the set stands for, condition): None elements if they are unknown."""
        if not match.ref:
            return match.elems, None, c
        item = table.sets.get(match.ref)
        if item is None:
            return None, None, _with_problem(c, f"set @{match.ref}, which does not exist")
        if item.unknown:
            self.unknown_sets.add(f"@{match.ref} ({item.unknown})")
            return None, None, _with_problem(c, f"set @{match.ref}, which is filled at run time ({item.unknown})")
        if not item.elems:
            self.empty_sets.add(f"@{match.ref}")
        return item.elems, f"@{table.family} {table.name} {match.ref}", c

    def alternatives(self, rule: _NRule, table: _Table) -> List[Tuple[_Cond, Optional[_Verdict], Optional[_Nat]]]:
        base = TRUE
        for text in rule.unsupported:
            base = _with_problem(base, text)
        if rule.comment:
            base = dataclasses.replace(base, comment=rule.comment)
        if rule.xt:
            self.xt = True
        alternatives: List[_Cond] = [base]
        for match in rule.matches:
            alternatives = [out for c in alternatives for out in self.apply(c, match, table)]
            if len(alternatives) > _MAX_EFFECTIVE_RULES:
                raise ParseError("a rule expands to more than 50000 alternatives; refusing to continue")
        result: List[Tuple[_Cond, Optional[_Verdict], Optional[_Nat]]] = []
        if rule.vmap is not None:
            for c in alternatives:
                elems, _, c = self.elements(rule.vmap, table, c)
                if elems is None or any(k not in _KNOWN_KEYS for k in rule.vmap.keys):
                    result.append((c, _Verdict("unknown", why="a verdict map that cannot be followed"), None))
                    continue
                for elem in elems:
                    verdict = elem.data if isinstance(elem.data, _Verdict) else _Verdict("unknown", why="a map")
                    more = self.apply_values(c, rule.vmap.keys, elem.key)
                    if more is not None:
                        result.append((more, verdict, None))
            return result
        if rule.nat_map is not None and rule.nat is not None:
            for c in alternatives:
                elems, _, c = self.elements(rule.nat_map, table, c)
                if elems is None or any(k not in _KNOWN_KEYS for k in rule.nat_map.keys):
                    result.append((c, rule.verdict, dataclasses.replace(rule.nat, problem="a NAT map that cannot be followed")))
                    continue
                for elem in elems:
                    more = self.apply_values(c, rule.nat_map.keys, elem.key)
                    if more is None:
                        continue
                    data = tuple(elem.data) if isinstance(elem.data, tuple) else ()
                    nat = dataclasses.replace(rule.nat, address=data[0] if data else "", port=data[1] if len(data) > 1 else "")
                    if not data or len(data) > 2:
                        nat.problem = "a NAT map entry that cannot be read"
                    result.append((more, rule.verdict, nat))
            return result
        return [(c, rule.verdict, rule.nat) for c in alternatives]

    def apply(self, c: _Cond, match: _Match, table: _Table) -> List[_Cond]:
        elems, group, c = self.elements(match, table, c)
        if elems is None:
            # What the set holds is not known; the IP version of what it is matched against is.
            families = {"ip": frozenset({4}), "ip6": frozenset({6})}.get(match.keys[0].split(" ")[0]) if len(match.keys) == 1 else None
            if families is not None:
                return [out for out in [_meet(c, _Cond(families=families))] if out is not None]
            return [c]
        if len(match.keys) == 1:
            values = [elem.key[0] for elem in elems if len(elem.key) == 1]
            if len(values) != len(elems):
                return [_with_problem(c, f"set @{match.ref} that does not fit {match.keys[0]}")]
            if not values and match.op == "==":
                return []  # an empty set matches nothing
            show = None
            key = match.keys[0]
            if group is not None and key in ("ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr"):
                if _addresses(values, 4 if key.startswith("ip ") else 6) is not None:
                    show = (group,)
                    self.remember_group(group, values)
            out = constrain(c, key, match.op, values, show)
            return [out] if out is not None else []
        if match.op != "==":
            return [_with_problem(c, f"negated match on {' . '.join(match.keys)}")]
        result = []
        for elem in elems:
            if len(elem.key) != len(match.keys):
                return [_with_problem(c, f"elements that do not fit {' . '.join(match.keys)}")]
            more = self.apply_values(c, match.keys, elem.key)
            if more is not None:
                result.append(more)
        return result

    @staticmethod
    def apply_values(c: _Cond, keys: Sequence[str], values: Sequence[str]) -> Optional[_Cond]:
        if len(keys) != len(values):
            return _with_problem(c, f"elements that do not fit {' . '.join(keys)}")
        out: Optional[_Cond] = c
        for key, value in zip(keys, values):
            if out is None:
                return None
            out = constrain(out, key, "==", [value])
        return out

    def remember_group(self, group: str, values: Sequence[str]) -> None:
        _, table, name = group.split(" ", 2)
        if group in self.groups:
            return
        candidate, counter = name, 2
        taken = set(self.p.address_groups) | set(self.p.addresses)
        while candidate in taken:
            candidate = f"{table}-{name}" if counter == 2 else f"{table}-{name}-{counter}"
            counter += 1
        self.groups[group] = candidate
        self.p.address_groups[candidate] = AddressGroup(
            candidate, list(transform.dedupe(list(_shown(values)))), description=f"nftables set @{name} of table {table}"
        )

    def group_name(self, member: str) -> str:
        if member.startswith("@"):
            return self.groups.get(member, member.split(" ", 2)[-1])
        return member

    # -- the policy ----------------------------------------------------------------

    def base_chains(self, hook: str, kind: str) -> Dict[int, List[Tuple[_Table, _Chain]]]:
        """Per IP version: the base chains at a hook, in the order a packet meets them."""
        out: Dict[int, List[Tuple[_Table, _Chain]]] = {4: [], 6: []}
        for table in sorted(self.ruleset.tables.values(), key=lambda t: t.order):
            if table.family not in ("ip", "ip6", "inet") or table.dormant:
                continue
            for chain in table.chains.values():
                if chain.hook != hook or chain.type != kind:
                    continue
                for family in (4, 6):
                    if table.family == "inet" or table.family == ("ip" if family == 4 else "ip6"):
                        out[family].append((table, chain))
        for family in out:
            out[family].sort(key=lambda item: item[1].priority)  # stable: equal priorities stay in the order read
        return out

    def build(self) -> Policy:
        chains = self.base_chains("forward", "filter")
        # A base chain that accepts everything changes nothing.
        for family in chains:
            chains[family] = [(t, c) for t, c in chains[family] if c.rules or c.policy != "accept"]
        tables = {t.name for family in chains for t, _ in chains[family]}
        self.prefix_tables = len(tables) > 1 or any(
            len({c.name for _, c in chains[f]}) != len(chains[f]) for f in chains
        )  # fmt: skip
        entries: List[_Entry] = []
        defaults: Dict[int, str] = {}
        if [id(c) for _, c in chains[4]] == [id(c) for _, c in chains[6]]:
            if chains[4]:
                found, defaults[4] = self.combine(chains[4], TRUE)
                defaults[6] = defaults[4]
                entries += found
        else:
            for family in (4, 6):
                if chains[family]:
                    found, defaults[family] = self.combine(chains[family], _Cond(families=frozenset({family})))
                    entries += found
        self.p.scope = ""
        if 4 in defaults and 6 in defaults:
            if defaults[4] == defaults[6]:
                default = defaults[4]
            else:
                default = "drop"
                for family in (4, 6):
                    if defaults[family] == "accept":
                        entries.append(_Entry(_Cond(families=frozenset({family})), "accept", f"IPv{family} policy"))
        elif defaults:
            only = next(iter(defaults))
            default = defaults[only]
            self.p.scope = f"IPv{only}"
            other = 6 if only == 4 else 4
            self.report.note(
                Severity.REVIEW,
                "NO_IPV6_CHAIN" if other == 6 else "NO_IPV4_CHAIN",
                f"no base chain at the forward hook filters IPv{other}: the kernel forwards IPv{other} traffic "
                f"unfiltered (where forwarding is on for it). The conversion covers IPv{only} only",
            )
        else:
            default = "accept"
            self.report.note(
                Severity.REVIEW,
                "NO_FORWARD_CHAIN",
                "no base chain of type filter at the forward hook: this ruleset does not filter forwarded traffic, and "
                "the converted policy has no security rules",
            )
        action = Action.ALLOW if default == "accept" else Action.DENY
        self.p.default_interzone = self.p.default_intrazone = action
        self.forward(entries)
        self.nat()
        for interface in transform.dedupe(
            [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        ):
            self.p.zones[interface] = Zone(interface, [interface])
        # The forward hook sees the translated destination; the model matches the original one.
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self.notes(chains)
        return self.p

    def where(self, table: _Table, chain: _Chain) -> str:
        return f"{table.name}:" if self.prefix_tables else ""

    def combine(self, chains: List[Tuple[_Table, _Chain]], context: _Cond) -> Tuple[List[_Entry], str]:
        """The entries of several base chains in a row, and the action for what none of them decides.

        An accept sends the packet on to the next base chain; a drop is final.
        """
        walked = []
        for table, chain in chains:
            entries = _Walker(self, table, self.where(table, chain)).run(chain, context)
            walked.append((entries, chain.policy, self.where(table, chain) + chain.label))
        default = ["accept"]

        def sequence(index: int, c: _Cond, via: Tuple[str, ...], top: bool) -> List[_Entry]:
            entries, policy, label = walked[index]
            out: List[_Entry] = []
            last = index + 1 == len(walked)
            remaining = c  # what no entry above decided yet, where one condition can say it
            for entry in entries:
                merged = _meet(c, entry.cond)
                if merged is None:
                    continue
                self.visited += 1
                if self.visited > _MAX_EFFECTIVE_RULES:
                    raise ParseError("the base chains combine to more than 50000 rules; refusing to continue")
                if entry.action == "accept" and not last:
                    out += sequence(index + 1, merged, via + (entry.where,), False)
                else:
                    out.append(dataclasses.replace(entry, cond=merged, via=via))
                if entry.action == "log":
                    continue
                decided = _meet(remaining, merged)
                rest: Any = _without(remaining, decided) if decided is not None else False
                if rest is None:
                    return out  # the entries so far decided all of it: nothing reaches the policy
                if rest is not False:
                    remaining = rest
            if policy == "drop":
                if top:
                    default[0] = "drop"
                else:
                    out.append(_Entry(c, "drop", f"{label} policy", via=via))
            elif not last:
                out += sequence(index + 1, c, via, top)
            elif not top:
                out.append(_Entry(c, "accept", f"{label} policy", via=via))
            return out

        found = sequence(0, context, (), True)
        return found, default[0]

    def forward(self, effective: List[_Entry]) -> None:
        accepts_established = False
        decided: Dict[int, FrozenSet[str]] = {4: frozenset(), 6: frozenset()}  # per IP version: states a rule decided
        early_drops: List[str] = []
        logged: Optional[Tuple[object, ...]] = None
        logged_group = ""
        everything: List[Tuple[Optional[FrozenSet[str]], str]] = []  # log rules that match everything: states, nflog group
        passive = 0
        packets = False
        accepts = 0
        for entry in effective:
            c = entry.cond
            key = self.match_key(c)
            if entry.action == "log":
                passive += 1
                logged, logged_group = (key, entry.log_group) if not entry.limited else (None, "")
                if not entry.limited and self.logs_all(c):
                    everything.append((c.states, entry.log_group))
                if not accepts_established and (c.states is None or c.states - {"NEW"}):
                    packets = True
                continue
            groups = [entry.log_group] if entry.log else []
            groups += [logged_group] if logged == key else []
            groups += [group for s, group in everything if self.logs_what(s, c.states, accepts_established)]
            log = bool(groups)
            logged = None
            if entry.log and not accepts_established and (c.states is None or c.states - {"NEW"}):
                packets = True
            states = c.states
            if states is not None and all(states <= decided[f] for f in c.families):
                continue  # a rule above decided every packet in these states: none reaches this one
            # Only for every packet in that state: a match on more (an interface, an address) is a rule of its own.
            plain = dataclasses.replace(c, states=None, comment="", families=frozenset({4, 6})).trivial()
            if states is not None and "NEW" not in states and not c.unsupported and plain:
                if entry.action == "accept" and states <= {"ESTABLISHED", "RELATED"}:
                    accepts_established = accepts_established or "ESTABLISHED" in states
                    decided.update({f: decided[f] | states for f in c.families})
                    continue
                if entry.action in ("drop", "reject", "reset") and states <= {"INVALID", "UNTRACKED"}:
                    decided.update({f: decided[f] | states for f in c.families})
                    continue
            rule = self.rule(entry)
            if rule is None:
                continue
            rule.log_start = log
            if log and all(groups):
                rule.source_ids["nftables.log_group"] = groups[0]  # (its lines go to ulogd, not to the kernel log)
            if states is not None and "NEW" not in states:
                rule.unsupported.append("match on connection state " + ",".join(sorted(states)) + " without NEW")
            if rule.action == Action.ALLOW:
                accepts += 1
            elif not accepts_established and (states is None or states & {"ESTABLISHED", "RELATED"}):
                early_drops.append(rule.origin)
            self.p.rules.append(rule)
        if passive:
            self.report.note(
                Severity.INFO,
                "PASSIVE_STATEMENTS",
                f"{passive} rule{'s' if passive != 1 else ''} at the forward hook only log{'' if passive != 1 else 's'} and "
                "decide nothing; left out. A log rule directly before a rule with the same match, or one that matches "
                "everything, sets the logging of the rules it logs for",
            )
        if packets:
            self.report.note(
                Severity.INFO,
                "LOG_EVERY_PACKET",
                "a log statement ahead of the rule that accepts established connections (or in a ruleset without one) "
                "logs packets of connections already open, not only the first of each: fwshift usage leaves out the "
                "TCP packets that open no connection, and counts the lines of other protocols as possible only",
            )
        if not accepts_established and accepts:
            self.report.note(
                Severity.REVIEW,
                "STATELESS_RULESET",
                "no rule at the forward hook accepts established and related packets, so the source filters every "
                "packet on its own. The converted rules are connection-based: an allow rule also admits the replies, "
                "and a deny rule no longer stops the replies of connections opened from the other side",
            )
        elif accepts_established:
            for origin in early_drops:
                self.report.add(
                    "rule",
                    origin,
                    Severity.REVIEW,
                    "DROP_BEFORE_ESTABLISHED",
                    "this rule comes before the rule that accepts established connections, so on the source it "
                    "also drops the replies of connections opened from the other side. The converted rule only "
                    "blocks new connections in its own direction; add the mirror rule if that mattered",
                )

    @staticmethod
    def logs_all(c: _Cond) -> bool:
        return dataclasses.replace(c, states=None, comment="").trivial() and (c.states is None or c.states == {"NEW"})

    @staticmethod
    def logs_what(log_states: Optional[FrozenSet[str]], states: Optional[FrozenSet[str]], established: bool) -> bool:
        if log_states is None:
            return True
        if log_states != frozenset({"NEW"}):
            return False
        return states == frozenset({"NEW"}) or (states is None and established)

    @staticmethod
    def match_key(c: _Cond) -> Tuple[object, ...]:
        return dataclasses.astuple(dataclasses.replace(c, comment=""))

    def unique(self, name: str, taken: Set[str]) -> str:
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    def rule(self, entry: _Entry) -> Optional[Rule]:
        c = entry.cond
        rule = Rule(name=self.unique(c.comment or entry.where, self.names))
        rule.origin = rule.name
        description = f"nftables rule {entry.where}"
        if entry.via:
            description += " (after " + ", ".join(entry.via) + " accepted it)"
        rule.description = "" if c.comment == rule.name and not entry.via else description
        rule.src_zones = sorted(c.iif) if c.iif else [ANY]
        rule.dst_zones = sorted(c.oif) if c.oif else [ANY]
        rule.unsupported = list(c.unsupported)
        rule.log_end = False
        self.addresses(rule, c)
        services, negated = self.services(c, rule.unsupported)
        rule.services = services
        rule.negate_service = negated
        action = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.DENY, "reset": Action.RESET_CLIENT}
        if entry.action in action:
            rule.action = action[entry.action]
        else:
            rule.action = Action.DROP  # what the source did is not known: nothing is allowed on a guess
            if not any("goto" in text or "jump" in text or "loop" in text for text in rule.unsupported):
                rule.unsupported.append(f"verdict {entry.why or entry.action}, which the model has no place for")
        return rule

    def side(self, intervals: Optional[Tuple[Interval, ...]], show: Show) -> Tuple[List[str], bool]:
        assert intervals is not None
        if show is not None:
            return [self.group_name(m) for m in show[0]], show[1]
        return [interval_text(i) for i in intervals], False

    def addresses(self, rule: Rule, c: _Cond) -> None:
        """Sources and destinations; a condition kept to one IP version keeps that in what it writes."""
        family_any = ANY if c.families == frozenset({4, 6}) else (ANY_V4 if 4 in c.families else ANY_V6)
        if c.src is not None and c.dst is not None and c.src_show and c.dst_show and c.src_show[1] and c.dst_show[1]:
            c = dataclasses.replace(c, src_show=None)  # negation covers both IP versions: one side is written out
        rule.sources, rule.negate_source = self.side(c.src, c.src_show) if c.src is not None else ([family_any], False)
        rule.destinations, rule.negate_destination = (
            self.side(c.dst, c.dst_show) if c.dst is not None else ([family_any], False)
        )
        # Plain "any" is enough where the other side keeps the rule to its IP version.
        if c.src is None and c.dst is None:
            rule.destinations = [ANY]
        elif c.src is None and not rule.negate_destination:
            rule.sources = [ANY]
        elif c.dst is None and not rule.negate_source:
            rule.destinations = [ANY]

    def services(self, c: _Cond, problems: List[str]) -> Tuple[List[str], bool]:
        """Names of the services standing for the protocols and ports of a condition, and whether they are negated."""
        proto = c.proto
        if proto is None:
            if c.dport is not None or c.sport is not None:
                problems.append("port match without a protocol (th)")
            if c.codes is not None:
                problems.append("ICMP code without a type")
            return [ANY], False
        negated = False
        numbers = sorted(proto)
        if len(numbers) > 128 and c.dport is None and c.sport is None and c.icmp is None and c.codes is None:
            numbers = sorted(set(range(1, 256)) - set(proto))  # (0 is no protocol meta l4proto can be)
            numbers = [n for n in numbers if not (n == 1 and 4 not in c.families) and not (n == 58 and 6 not in c.families)]
            negated = True
            if not numbers:
                return [ANY], False
        entries: List[ServiceEntry] = []
        dports = _port_text(c.dport)
        sports = _port_text(c.sport)
        for number in numbers:
            if number in (6, 17, 132):
                entries.append(ServiceEntry(Protocol({6: "tcp", 17: "udp", 132: "sctp"}[number]), dports, sports))
            elif number in (1, 58):
                protocol = Protocol.ICMP if number == 1 else Protocol.ICMP6
                if c.dport is not None or c.sport is not None:
                    problems.append(f"port match on {protocol.value}")
                types: List[Optional[int]] = [None]
                if c.icmp is not None:
                    types = [t for t in sorted(t for p, t in c.icmp if p == number)]
                if c.codes is not None and c.icmp is None:
                    problems.append("ICMP code without a type")
                for kind in types:
                    codes: List[Optional[int]] = list(sorted(c.codes)) if c.codes is not None and kind is not None else [None]
                    for code in codes:
                        entries.append(ServiceEntry(protocol, icmp_type=kind, icmp_code=code))
            else:
                if c.dport is not None or c.sport is not None:
                    problems.append(f"port match on protocol {number}")
                if number == 0:
                    problems.append("protocol 0")
                    continue
                entries.append(ServiceEntry(Protocol.IP, ip_protocol=number))
        if not entries:
            return [ANY], False
        name = "+".join(_entry_name(entry) for entry in entries)
        if len(name) > 60:
            name = f"{len(entries)}-protocols"
        candidate, counter = name, 2
        while candidate in self.p.services and self.p.services[candidate].entries != entries:
            candidate = f"{name}-{counter}"
            counter += 1
        self.p.services[candidate] = Service(candidate, entries)
        return [candidate], negated

    # -- nat ----------------------------------------------------------------------

    def nat(self) -> None:
        destination: List[NatRule] = []
        source: List[NatRule] = []
        for hook, out in (("prerouting", destination), ("postrouting", source)):
            chains = self.base_chains(hook, "nat")
            seen: Set[int] = set()
            ordered = sorted({id(c): (t, c) for f in chains for t, c in chains[f]}.values(), key=lambda tc: tc[1].priority)
            for table, chain in ordered:
                if id(chain) in seen:
                    continue
                seen.add(id(chain))
                families = frozenset({4, 6}) if table.family == "inet" else frozenset({4 if table.family == "ip" else 6})
                walker = _Walker(self, table, f"{table.name}:" if len(ordered) > 1 else "")
                for entry in walker.run(chain, _Cond(families=families)):
                    nat = self.nat_rule(entry, hook, table)
                    if nat is not None:
                        out.append(nat)
        self.p.nat_rules = destination + source

    def nat_rule(self, entry: _Entry, hook: str, table: _Table) -> Optional[NatRule]:
        if entry.action == "log":
            return None
        c = entry.cond
        nat = NatRule(name=self.unique(c.comment or entry.where, self.nat_names))
        nat.origin = nat.name
        nat.combines = True  # one prerouting rule and one postrouting rule apply to a connection
        nat.description = "" if c.comment == nat.name else f"nftables nat rule {entry.where}"
        nat.unsupported = list(c.unsupported)
        translation = entry.nat
        families = c.families
        if translation is not None and translation.family:
            families = families & {4 if translation.family == "ip" else 6}
        if translation is not None and translation.address and parse_literal(translation.address.split("/")[0]):
            literal = parse_literal(translation.address.split("/")[0])
            assert literal is not None
            families = families & {literal[0]}
        if not families:
            return None
        c = dataclasses.replace(c, families=frozenset(families))
        if c.src_show and c.src_show[1] or c.dst_show and c.dst_show[1]:
            nat.unsupported.append("negated address in a NAT rule")
        nat.sources = self.side(c.src, None)[0] if c.src is not None else [ANY]
        nat.destinations = self.side(c.dst, None)[0] if c.dst is not None else [ANY]
        if c.src is not None and c.src_show is not None and not c.src_show[1]:
            nat.sources = [self.group_name(m) for m in c.src_show[0]]
        if c.dst is not None and c.dst_show is not None and not c.dst_show[1]:
            nat.destinations = [self.group_name(m) for m in c.dst_show[0]]
        services, negated = self.services(c, nat.unsupported)
        if len(services) != 1 or negated:
            nat.unsupported.append("NAT limited to protocols the model cannot say")
        nat.service = services[0] if services else ANY
        if nat.service != ANY and any(
            e.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.SCTP) for e in self.p.services[nat.service].entries
        ):
            nat.unsupported.append("NAT limited to a protocol other than TCP, UDP or SCTP")
        if c.states is not None:
            nat.unsupported.append("connection state match in a NAT rule")
        if 4 not in families:
            nat.unsupported.append("IPv6 NAT")
        elif 6 in families and translation is not None and translation.kind in ("masquerade", "redirect"):
            self.report.add(
                "nat",
                nat.origin,
                Severity.INFO,
                "NAT_IPV6_NOT_CONVERTED",
                "the rule is in an inet table and translates IPv6 connections as well; IPv6 NAT is not converted",
            )
        if hook == "prerouting":
            nat.src_zones = nat.dst_zones = sorted(c.iif) if c.iif else [ANY]
            if c.oif:
                nat.unsupported.append("output interface in prerouting")
            if translation is None:
                if entry.action == "accept":
                    nat.unsupported.append(
                        "exception from destination NAT only (an accept in prerouting); the destination NAT rules "
                        "below it are converted without this exception"
                    )
                else:
                    nat.unsupported.append(f"verdict {entry.action} in a NAT chain")
            elif translation.kind == "dnat":
                address, port = self.translation(translation)
                if address is None:
                    nat.unsupported.append("destination NAT that could not be read" + (f": {translation.problem}" if translation.problem else ""))
                else:
                    nat.destination_translation = DestNat(address, port, spread="-" in address)
            else:
                nat.unsupported.append(f"{translation.kind} in prerouting" + (" (to the host itself)" if translation.kind == "redirect" else ""))
        else:
            nat.dst_zones = sorted(c.oif) if c.oif else [ANY]
            if c.iif:
                nat.unsupported.append("input interface in postrouting")
            if translation is None:
                if entry.action != "accept":
                    nat.unsupported.append(f"verdict {entry.action} in a NAT chain")
            elif translation.kind == "masquerade":
                if translation.port:
                    nat.unsupported.append("masquerade to a port range")
                interface = sorted(c.oif)[0] if c.oif and len(c.oif) == 1 else ""
                nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=interface)
            elif translation.kind == "snat":
                address, port = self.translation(translation)
                if address is None:
                    nat.unsupported.append("source NAT that could not be read" + (f": {translation.problem}" if translation.problem else ""))
                else:
                    if port:
                        nat.unsupported.append("source NAT to a port")
                    nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [address])
            else:
                nat.unsupported.append(f"{translation.kind} in postrouting")
        return nat

    @staticmethod
    def translation(nat: _Nat) -> Tuple[Optional[str], str]:
        if nat.problem or nat.prefix or not nat.address:
            return None, ""
        interval = parse_literal(nat.address)  # (nft lists an aligned range as a prefix: the same addresses)
        if interval is None or interval[0] != 4:
            return None, ""
        if nat.port and not valid_ports(nat.port):
            return None, ""
        return range_text(interval), nat.port

    # -- notes -------------------------------------------------------------------

    def notes(self, chains: Dict[int, List[Tuple[_Table, _Chain]]]) -> None:
        if self.xt or self.ruleset.iptables_nft:
            self.report.note(
                Severity.REVIEW,
                "IPTABLES_NFT",
                "tables managed by iptables-nft: rules that use iptables extensions are not converted where nft shows "
                "them as 'xt' statements (always in the JSON listing; in the text listing where nft cannot translate "
                "them), so the two listings can give different results. Convert the output of iptables-nft-save with "
                "--from iptables for those tables",
            )
        for table in sorted(self.ruleset.tables.values(), key=lambda t: t.order):
            if table.dormant:
                self.report.note(
                    Severity.REVIEW,
                    "TABLE_DORMANT",
                    f"table {table.family} {table.name} is dormant (flags dormant): none of its chains filters or translates "
                    "anything, and none was converted. If it is switched on, convert again",
                )
                continue
            if table.family not in ("ip", "ip6", "inet"):
                count = sum(len(chain.rules) for chain in table.chains.values())
                if count or any(c.policy == "drop" for c in table.chains.values() if c.type):
                    self.report.note(
                        Severity.REVIEW,
                        "TABLE_NOT_CONVERTED",
                        f"table {table.family} {table.name} ({count} rules) filters {table.family} traffic and is not "
                        "converted",
                    )
                continue
            for chain in table.chains.values():
                if not chain.type:
                    continue
                if chain.type == "filter" and chain.hook in ("input", "output"):
                    if chain.rules or chain.policy != "accept":
                        self.report.note(
                            Severity.REVIEW,
                            "HOST_CHAIN_NOT_CONVERTED",
                            f"chain {chain.label} of table {table.family} {table.name} ({len(chain.rules)} rules, "
                            f"policy {chain.policy}) filters traffic of the host itself, not forwarded traffic, and is "
                            "not converted",
                        )
                elif chain.type == "nat" and chain.hook in ("input", "output"):
                    if chain.rules:
                        self.report.note(
                            Severity.REVIEW,
                            "HOST_CHAIN_NOT_CONVERTED",
                            f"nat chain {chain.label} of table {table.family} {table.name} ({len(chain.rules)} rules) "
                            "translates traffic of the host itself and is not converted",
                        )
                elif chain.type == "filter" and chain.hook in ("prerouting", "postrouting", "ingress"):
                    if self.decides(table, chain) or chain.policy == "drop":
                        self.report.note(
                            Severity.REVIEW,
                            "CHAIN_NOT_CONVERTED",
                            f"chain {chain.label} of table {table.family} {table.name} at the {chain.hook} hook "
                            f"(priority {chain.priority}, policy {chain.policy}) can drop forwarded traffic as well and "
                            "is not converted",
                        )
                elif chain.type == "route" and chain.rules:
                    self.report.note(
                        Severity.INFO,
                        "CHAIN_NOT_CONVERTED",
                        f"route chain {chain.label} of table {table.family} {table.name} reroutes traffic of the host "
                        "itself and is not converted",
                    )
        for family in (4, 6):
            listed = chains[family]
            if len(listed) > 1:
                names = ", ".join(f"{t.family} {t.name} {c.label} ({c.priority})" for t, c in listed)
                if family == 4 or [id(c) for _, c in listed] != [id(c) for _, c in chains[4]]:
                    self.report.note(
                        Severity.INFO,
                        "SEVERAL_BASE_CHAINS",
                        f"IPv{family} traffic passes {len(listed)} base chains at the forward hook: {names}. It is "
                        "forwarded only if each of them accepts it; they were combined into one list of rules",
                    )
                priorities = [c.priority for _, c in listed]
                if len(set(priorities)) != len(priorities):
                    self.report.note(
                        Severity.INFO,
                        "EQUAL_PRIORITY",
                        "base chains at the forward hook with the same priority run in an order the kernel does not "
                        "define; they were read in the order listed. What is forwarded does not depend on it, which "
                        "rule logs a packet may",
                    )
        if self.unknown_sets:
            self.report.note(
                Severity.REVIEW,
                "DYNAMIC_SET",
                "sets filled at run time decide what their rules match; those rules are not converted: "
                + ", ".join(sorted(self.unknown_sets)),
            )
        if self.empty_sets:
            self.report.note(
                Severity.REVIEW,
                "EMPTY_SET",
                "sets that were empty when the ruleset was listed: a rule that names one matches nothing here. "
                "Elements a script or a service adds later (fail2ban, for one) are not in the conversion: "
                + ", ".join(sorted(self.empty_sets)),
            )
        if self.p.default_interzone == Action.ALLOW and any(chains.values()):
            self.report.note(
                Severity.INFO,
                "FORWARD_POLICY_ACCEPT",
                "the forward hook accepts what no rule matches; the model records that as its default action",
            )

    def decides(self, table: _Table, chain: _Chain) -> bool:
        """Whether a chain (or one it jumps to) has a rule that drops or rejects."""
        seen: Set[str] = set()
        todo = [chain]
        while todo:
            current = todo.pop()
            if current.name in seen:
                continue
            seen.add(current.name)
            for rule in current.rules:
                verdicts = [rule.verdict] if rule.verdict else []
                if rule.vmap is not None:
                    verdicts += [e.data for e in rule.vmap.elems if isinstance(e.data, _Verdict)]
                    if rule.vmap.ref:
                        return True
                for verdict in verdicts:
                    if verdict.kind in ("drop", "reject", "unknown"):
                        return True
                    if verdict.kind in ("jump", "goto") and verdict.target in table.chains:
                        todo.append(table.chains[verdict.target])
        return False


# Keys the reader takes in full although the model has no place for them.
_KNOWN_UNKNOWN = {"fib", "ct count", "socket", "osf", "ipsec", "numgen", "jhash", "symhash", "tunnel"}
_KNOWN_KEYS = {
    "meta iifname", "meta oifname", "meta iif", "meta oif", "ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr",
    "meta l4proto", "ip protocol", "ip6 nexthdr", "tcp dport", "tcp sport", "udp dport", "udp sport", "sctp dport",
    "sctp sport", "udplite dport", "udplite sport", "dccp dport", "dccp sport", "th dport", "th sport", "icmp type",
    "icmpv6 type", "icmp code", "icmpv6 code", "meta nfproto", "meta protocol", "ct state",
}  # fmt: skip


def _port_text(ranges: Optional[Tuple[Tuple[int, int], ...]]) -> str:
    if ranges is None or list(ranges) == _ALL_PORTS:
        return ""
    return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in ranges)


def _entry_name(entry: ServiceEntry) -> str:
    if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
        return f"{entry.protocol.value}-{entry.dst_ports or 'any'}" + (f"-from-{entry.src_ports}" if entry.src_ports else "")
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        kind = "any" if entry.icmp_type is None else str(entry.icmp_type)
        return f"{entry.protocol.value}-{kind}" + (f"-{entry.icmp_code}" if entry.icmp_code is not None else "")
    return f"ip-{entry.ip_protocol}"
