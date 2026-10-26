# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VyOS parser: the configuration of a VyOS router -> neutral model.

Reads ``show configuration commands`` (set lines) or the configuration in braces (``show configuration``,
``/config/config.boot``) of VyOS 1.4 and later and, as a dialect of its own, of VyOS 1.3, Vyatta and Ubiquiti
EdgeOS. The report says which of the two was read.

How VyOS behaviour is mapped onto the neutral model:

* Only forwarded traffic is policy: the base chain ``firewall ipv4|ipv6 forward filter``, the named chains it jumps
  to, and the zone-based firewall (``firewall zone``). ``input`` and ``output`` filter traffic of the router itself and
  are reported, not converted; so are ``prerouting raw`` and the bridge firewall.
* The rules of a chain are taken in the order of their numbers, first match. A base chain ends with its
  ``default-action`` (accept unless it says drop); a named chain with its own (drop unless it says otherwise;
  ``return`` goes on after the rule that jumped). ``return`` in a base chain accepts: the nftables chain VyOS makes has
  the policy accept, and the default-action is a rule of its own after the others. A disabled rule is not in the
  chain at all; it is kept in the model, disabled, where it stood.
* The forward filter and the zones are two base chains at the forward hook, the forward filter first: a packet is
  forwarded only when both accept it. The zone of the outgoing interface decides, with the rule-set it names for the
  zone of the incoming interface (``from``); inside one zone traffic is accepted unless ``intra-zone-filtering`` says
  otherwise; from a zone without a rule-set for the IP version, and from an interface in no zone, traffic is dropped
  (the zone's ``default-action``); traffic to an interface in no zone is left to the forward filter. All of this as
  the nftables templates of VyOS (vyos-1x, ``nftables-zone.j2``) write it.
* The interfaces are the zones of the model, except that an interface of a zone of the zone-based firewall is that
  zone, where no rule names a part of it. Wildcards (``eth*``) and negations (``!eth0``) are resolved against the
  interfaces the configuration names. Without its ``interfaces`` part, the interfaces the configuration does not name
  (which a negation, or the default of a zone, reaches) are one zone of the model without interfaces.
* VyOS filters packets, the model connections. A rule that accepts established and related packets (and
  ``global-options state-policy``) is what every stateful platform does by itself and is left out; the remaining rules
  describe new connections.
* Named chains are flattened into the rule that jumps to them; a ``return`` that one condition can take away from the
  rules below it is followed exactly.
* Destination NAT is done before the forward hook, so the rules name the translated destination; the model wants the
  original one. ``connection-status nat destination`` stands for what the destination NAT rules translate.
* VyOS 1.3, Vyatta and EdgeOS (``firewall name``, ``interfaces ... firewall in|out``, ``zone-policy``, ``service nat``)
  are read the way VyOS's own migration to 1.4 rewrites them (the migration scripts firewall 6-to-7, 7-to-8 and
  10-to-11 of vyos-1x): a rule-set bound to an interface ``in`` or ``out`` is a jump from a forward filter that accepts
  what none decides, the ``in`` rule-sets before the ``out`` ones; ``accept`` in a rule-set is ``return``, so that the
  rule-set of the other interface still decides; the zone policy is the zone-based firewall. A port list there is
  negated as a whole by a ``!`` in front of it, where VyOS 1.4 negates each port that has one.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import ANY, ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Rule
from ..model import SnatKind, SourceNat, Zone
from ..netutil import interval_text, is_number, parse_literal, range_text, size
from ..report import Report, Severity
from . import nftables as _nft
from .nftables import _Cond, _meet, _with_problem, _without, constrain

_MAX_LINES = 2_000_000
_MAX_EFFECTIVE_RULES = 50000
_MAX_NESTING = 64
OTHER = "\x00other"  # an interface of the router that the configuration does not name

_FIREWALL_WORDS = ("ipv4", "ipv6", "group", "name", "ipv6-name", "zone", "global-options", "state-policy", "interface",
                   "flowtable", "bridge")  # fmt: skip
_SET_HEAD = re.compile(
    r"^set (firewall (" + "|".join(_FIREWALL_WORDS) + r")\s|nat (destination|source|static|cgnat)\s|nat66 |"
    r"zone-policy |service nat rule |interfaces (ethernet|bonding|bridge|pppoe|wireguard|loopback|openvpn|tunnel|vti|"
    r"dummy|pseudo-ethernet|switch|wireless|vxlan|l2tpv3|geneve|macsec|input|virtual-ethernet|sstpc|wwan) )",
    re.M,
)
_BRACE_HEAD = re.compile(r"^(firewall|nat|zone-policy|interfaces|service|system) \{[ \t]*$", re.M)
_BRACE_INNER = re.compile(r"^[ \t]+(ipv4|ipv6|group|global-options|state-policy|(name|ipv6-name|zone) \S+|ethernet eth\d+|"
                          r"(destination|source) \{\s*rule \d+) \{[ \t]*$", re.M)  # fmt: skip
_VERSION_LINE = re.compile(r"(vyos|vyatta)-config-version")
_RELEASE = re.compile(r"Release version: *(\S+)")

# Protocol names VyOS takes (/etc/protocols), with their numbers.
_PROTOCOLS = dict(_nft._PROTOCOLS)
_PROTOCOLS.update({"icmpv6": 58, "ipv6-icmp": 58, "ip": 0, "ipencap": 4, "st": 5, "egp": 8, "igp": 9, "pup": 12,
                   "hmp": 20, "xns-idp": 22, "rdp": 27, "iso-tp4": 29, "xtp": 36, "ddp": 37, "idpr-cmtp": 38,
                   "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45, "skip": 57, "ipv6-nonxt": 59, "ipv6-opts": 60,
                   "rspf": 73, "vmtp": 81, "ax.25": 93, "ipip": 94, "pim": 103, "carp": 112, "pgm": 113, "isis": 124,
                   "udplite": 136, "mpls-in-ip": 137, "manet": 138, "hip": 139, "shim6": 140, "wesp": 141, "rohc": 142,
                   "ethernet": 143})  # fmt: skip
# Port names VyOS takes from /etc/services: the common ones.
_PORT_NAMES = dict(_nft._PORT_NAMES)
_PORT_NAMES.update({"ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "time": 37, "whois": 43, "tacacs": 49,
                    "domain": 53, "bootps": 67, "bootpc": 68, "tftp": 69, "gopher": 70, "finger": 79, "http": 80,
                    "kerberos": 88, "pop3": 110, "sunrpc": 111, "auth": 113, "nntp": 119, "ntp": 123, "epmap": 135,
                    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139, "imap2": 143, "snmp": 161,
                    "snmp-trap": 162, "bgp": 179, "irc": 194, "ldap": 389, "https": 443, "microsoft-ds": 445,
                    "kpasswd": 464, "submissions": 465, "isakmp": 500, "syslog": 514, "printer": 515, "rtsp": 554,
                    "submission": 587, "ipp": 631, "ldaps": 636, "rsync": 873, "ftps-data": 989, "ftps": 990,
                    "telnets": 992, "imaps": 993, "pop3s": 995, "socks": 1080, "openvpn": 1194, "ms-sql-s": 1433,
                    "ms-sql-m": 1434, "l2tp": 1701, "pptp": 1723, "radius": 1812, "radius-acct": 1813, "nfs": 2049,
                    "squid": 3128, "mysql": 3306, "ms-wbt-server": 3389, "ipsec-nat-t": 4500, "sip": 5060,
                    "sip-tls": 5061, "xmpp-client": 5222, "postgresql": 5432, "x11": 6000, "http-alt": 8080})  # fmt: skip
# VyOS 1.3 and Vyatta names of ICMP types, as the migration to 1.4 (firewall 6-to-7) translates them.
_LEGACY_ICMP: Dict[str, Tuple[str, Optional[int]]] = {
    "ping": ("echo-request", None), "pong": ("echo-reply", None), "ttl-exceeded": ("time-exceeded", None),
    "network-unreachable": ("3", 0), "host-unreachable": ("3", 1), "protocol-unreachable": ("3", 2),
    "port-unreachable": ("3", 3), "fragmentation-needed": ("3", 4), "source-route-failed": ("3", 5),
    "network-unknown": ("3", 6), "host-unknown": ("3", 7), "network-prohibited": ("3", 9), "host-prohibited": ("3", 10),
    "TOS-network-unreachable": ("3", 11), "TOS-host-unreachable": ("3", 12), "communication-prohibited": ("3", 13),
    "host-precedence-violation": ("3", 14), "precedence-cutoff": ("3", 15), "network-redirect": ("5", 0),
    "host-redirect": ("5", 1), "TOS-network-redirect": ("5", 2), "TOS-host-redirect": ("5", 3),
    "ttl-zero-during-transit": ("11", 0), "ttl-zero-during-reassembly": ("11", 1), "ip-header-bad": ("12", 0),
    "required-option-missing": ("12", 1), "timestamp-request": ("13", None), "timestamp-reply": ("14", None),
}  # fmt: skip
_LEGACY_ICMP6: Dict[str, Tuple[str, Optional[int]]] = {
    "ping": ("echo-request", None), "pong": ("echo-reply", None), "no-route": ("1", 0),
    "communication-prohibited": ("1", 1), "address-unreachable": ("1", 3), "address-unreachble": ("1", 3),
    "port-unreachable": ("1", 4), "redirect": ("nd-redirect", None), "router-solicitation": ("nd-router-solicit", None),
    "router-advertisement": ("nd-router-advert", None), "neighbour-solicitation": ("nd-neighbor-solicit", None),
    "neighbor-solicitation": ("nd-neighbor-solicit", None), "neighbour-advertisement": ("nd-neighbor-advert", None),
    "neighbor-advertisement": ("nd-neighbor-advert", None), "ttl-zero-during-transit": ("3", 0),
    "ttl-zero-during-reassembly": ("3", 1), "bad-header": ("4", 0), "unknown-header-type": ("4", 1),
    "unknown-option": ("4", 2),
}  # fmt: skip
# Matches the model has no place for, and what they test.
_UNSUPPORTED = {
    "mac-address": "a MAC address", "geoip": "the country of an address", "address-mask": "an address under a mask",
    "fragment": "fragments", "limit": "a rate limit", "recent": "recent connections of a source", "ttl": "the TTL",
    "hop-limit": "the hop limit", "packet-length": "the length of packets", "packet-length-exclude": "the length of packets",
    "packet-type": "the type of packets", "dscp": "the DSCP field", "dscp-exclude": "the DSCP field",
    "ipsec": "IPsec traffic", "mark": "a mark set elsewhere", "connection-mark": "a connection mark",
    "conntrack-helper": "connections a helper relates to another one", "gre": "GRE fields", "vlan": "VLAN fields",
    "ethernet-type": "the ethernet type", "fib": "a route lookup", "add-address-to-group": "an address put into a group",
    "p2p": "peer-to-peer traffic", "application": "an application (deep packet inspection)", "tcp-mss": "the TCP MSS",
    "mac-group": "MAC addresses", "dynamic-address-group": "a group filled while the router runs",
    "remote-group": "a list fetched from a URL",
}  # fmt: skip
_PASSING_STATEMENTS = {"description", "log-options", "log-level", "set", "queue", "queue-options", "synproxy",
                       "offload-target", "jump-target", "action", "disable", "log"}  # fmt: skip


# -- reading the text -----------------------------------------------------------------


def looks_like_vyos(data: bytes) -> bool:
    """Set lines of VyOS (words no other vendor writes after 'set'), or a configuration in braces with the version line
    of VyOS or Vyatta, or with nodes only they have and without the semicolons of Junos."""
    head = data[:2_000_000].decode("utf-8", errors="replace")
    if _SET_HEAD.search(head):
        return True
    if not _BRACE_HEAD.search(head):
        return False
    if _VERSION_LINE.search(head):
        return True
    return bool(_BRACE_INNER.search(head)) and not re.search(r";[ \t]*$", head[:200_000], re.M)


def _words(line: str, number: int) -> List[str]:
    """The words of a set line: '...' is taken as it is, "..." with backslash escapes."""
    out: List[str] = []
    word: List[str] = []
    quoted = False
    position, length = 0, len(line)
    while position < length:
        char = line[position]
        if char in " \t":
            if word or quoted:
                out.append("".join(word))
                word, quoted = [], False
            position += 1
        elif char == "'":
            end = line.find("'", position + 1)
            if end < 0:
                raise ParseError(f"line {number}: a quoted value that is not closed")
            word.append(line[position + 1 : end])
            quoted, position = True, end + 1
        elif char == '"':
            position += 1
            while position < length and line[position] != '"':
                if line[position] == "\\" and position + 1 < length:
                    position += 1
                word.append(line[position])
                position += 1
            if position >= length:
                raise ParseError(f"line {number}: a quoted value that is not closed")
            quoted, position = True, position + 1
        elif char == "\\" and position + 1 < length:
            word.append(line[position + 1])
            position += 2
        else:
            word.append(char)
            position += 1
    if word or quoted:
        out.append("".join(word))
    return out


def _flatten(text: str) -> List[Tuple[int, List[str]]]:
    """The configuration in braces as the paths of its leaves, as set lines without 'set'."""
    tokens: List[Tuple[int, str, bool]] = []
    position, length, number = 0, len(text), 1
    at_start = True
    while position < length:
        char = text[position]
        if char == "\n":
            tokens.append((number, "\n", False))
            number += 1
            position += 1
            at_start = True
            continue
        if char in " \t\r":
            position += 1
            continue
        if text.startswith("/*", position):
            end = text.find("*/", position + 2)
            if end < 0:
                raise ParseError(f"line {number}: a comment that is not closed")
            number += text.count("\n", position, end)
            position = end + 2
            continue
        if at_start and text.startswith("//", position):
            end = text.find("\n", position)
            position = length if end < 0 else end
            continue
        at_start = False
        if char in "{}":
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
                raise ParseError(f"line {number}: a quoted value that is not closed")
            position += 1
            tokens.append((number, "".join(chars), True))
        else:
            start = position
            while position < length and text[position] not in " \t\r\n{}\"":
                position += 1
            tokens.append((number, text[start:position], False))
    out: List[Tuple[int, List[str]]] = []
    stack: List[Tuple[int, int]] = []  # (words the block adds, statements before it)
    prefix: List[str] = []
    words: List[str] = []
    line = 1
    for line, token, quoted in tokens:
        if len(out) > _MAX_LINES:
            raise ParseError(f"the configuration holds more than {_MAX_LINES} statements")
        if not quoted and token == "{":
            if not words:
                raise ParseError(f"line {line}: '{{' without a node")
            if len(stack) >= _MAX_NESTING:
                raise ParseError(f"line {line}: blocks nested more than {_MAX_NESTING} deep")
            stack.append((len(words), len(out)))
            prefix += words
            words = []
        elif not quoted and token == "}":
            if words:
                out.append((line, prefix + words))
                words = []
            if not stack:
                raise ParseError(f"line {line}: '}}' without '{{'")
            added, before = stack.pop()
            if len(out) == before:
                out.append((line, list(prefix)))  # an empty node
            del prefix[len(prefix) - added :]
        elif not quoted and token == "\n":
            if words:
                out.append((line, prefix + words))
                words = []
        else:
            words.append(token)
    if words:
        out.append((line, prefix + words))
    if stack:
        raise ParseError(f"line {line}: the configuration ends inside a node (a '{{' without '}}')")
    return out


def _lines(text: str) -> Tuple[List[Tuple[int, List[str]]], bool]:
    """(paths, whether the text is set lines)."""
    if "\0" in text:
        raise ParseError("the configuration holds a NUL character: it is not a text file")
    head = [line.strip() for line in text.splitlines()[:5000] if line.strip() and not line.strip().startswith("#")]
    if not any(line.startswith("set ") for line in head[:200]):
        return _flatten(text), False
    out: List[Tuple[int, List[str]]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = _words(line, number)
        if not words:
            continue
        if words[0] == "set":
            if len(words) > 1:
                out.append((number, words[1:]))
        elif words[0] in ("configure", "commit", "save", "exit", "commit-confirm", "confirm", "compare", "end"):
            continue  # (the commands around set lines in a script)
        elif words[0] in ("delete", "rename", "copy", "insert", "edit", "comment", "load", "merge"):
            raise ParseError(f"line {number}: '{words[0]}' belongs to a file of commands, not to a configuration")
        else:
            raise ParseError(f"line {number}: not a line of 'show configuration commands' (it starts with "
                             f"'{_short(words[0], 20)}')")  # fmt: skip
        if len(out) > _MAX_LINES:
            raise ParseError(f"the configuration holds more than {_MAX_LINES} lines")
    return out, True


def _short(text: str, limit: int = 40) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _neg(value: str) -> Tuple[bool, str]:
    return (True, value[1:]) if value.startswith("!") else (False, value)


# -- what was read ------------------------------------------------------------------------


Statements = Dict[Tuple[str, ...], List[str]]


def _statements(lines: List[List[str]]) -> Statements:
    """The statements of a rule: path -> values; a word alone (``disable``) has the value ""."""
    out: Statements = {}
    for words in lines:
        if not words:
            continue
        if len(words) == 1:
            out.setdefault((words[0],), []).append("")
        else:
            out.setdefault(tuple(words[:-1]), []).append(words[-1])
    return out


@dataclass
class _RawChain:
    family: int
    hook: str  # forward, input, output, prerouting, name
    name: str
    default: str = ""
    default_target: str = ""
    default_log: bool = False
    rules: Dict[int, List[List[str]]] = field(default_factory=dict)
    legacy: bool = False  # VyOS 1.3 or EdgeOS: accept is return
    unread: List[str] = field(default_factory=list)


@dataclass
class _VRule:
    """One rule of a chain, with what it matches as conditions (alternatives that together are its match)."""

    family: int
    chain: str
    number: int
    action: str  # accept, drop, reject, return, jump, continue, queue, synproxy, offload, ""
    label: str  # how the source names it: "ipv4 name WAN_IN rule 20"
    step: str  # its part of a path through the chains: "WAN_IN-20"
    target: str = ""
    log: bool = False
    disabled: bool = False
    description: str = ""
    conds: List[_Cond] = field(default_factory=list)
    accept_was: str = ""  # legacy: the action as written, where it was turned into return


@dataclass
class _Chain:
    family: int
    name: str
    label: str
    rules: List[_VRule] = field(default_factory=list)
    default: str = "drop"  # accept, drop, reject, return, jump, queue
    default_target: str = ""
    default_log: bool = False


@dataclass
class _Entry:
    cond: _Cond
    action: str  # accept, drop, reject, unknown, log, nat
    rule: Optional[_VRule]
    where: str
    label: str
    log: bool = False
    why: str = ""
    disabled: bool = False
    via: Tuple[str, ...] = ()


@dataclass
class _Frame:
    """Where a walk through the chains is: a chain, the rule to go on at, and what called it."""

    chain: _Chain
    start: int
    stack: Tuple[str, ...]
    prefix: str
    base: bool
    parent: Optional["_Frame"] = None
    inline: bool = False  # a copy of the rest of a chain, put where a packet returns to it: it decides everything
    returned: str = ""  # for such a copy: where the packets returned, and the rule that returned them
    returned_label: str = ""
    returned_rule: Optional[_VRule] = None


@dataclass
class _Zone:
    name: str
    interfaces: List[str] = field(default_factory=list)
    local: bool = False
    default: str = "drop"
    default_log: bool = False
    froms: Dict[str, Dict[str, str]] = field(default_factory=dict)  # from zone -> {"name": chain, "ipv6-name": chain}
    intra_action: str = ""  # accept or drop
    intra_names: Dict[str, str] = field(default_factory=dict)  # "name" / "ipv6-name" -> chain
    default_names: Dict[str, str] = field(default_factory=dict)  # default-firewall (later VyOS)


@dataclass
class _NatEntry:
    kind: str  # destination or source
    number: int
    statements: Statements
    line: int


# -- the reader ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, paths: List[Tuple[int, List[str]]], report: Report, text: str) -> None:
        self.report = report
        self.paths = paths
        self.p = Policy(vendor="vyos", lookup_after_dnat=True, default_intrazone=Action.ALLOW, default_interzone=Action.ALLOW)
        self.helper = _nft._Builder(_nft._Ruleset(), report)
        self.helper.p = self.p
        self.legacy = any(self._is_legacy(words) for _, words in paths)
        self.modern = any(words[:2] in (["firewall", "ipv4"], ["firewall", "ipv6"], ["firewall", "zone"],
                                        ["firewall", "global-options"]) for _, words in paths)  # fmt: skip
        if self.legacy and self.modern:
            raise ParseError("the configuration holds the firewall of VyOS 1.4 and later (firewall ipv4, ipv6, zone) and "
                             "that of VyOS 1.3 or EdgeOS (firewall name, zone-policy, firewall on interfaces) at once: "
                             "give FWShift one of them")  # fmt: skip
        self.edgeos = self.legacy and (
            any(words[:2] == ["service", "nat"] for _, words in paths)
            or "vyatta-config-version" in text and ("ubnt" in text or "Release version: v" in text)
            or any(words[:2] in (["system", "offload"], ["service", "gui"], ["service", "ubnt-discover"]) for _, words in paths)
        )  # fmt: skip
        found = _RELEASE.search(text)
        self.release = found.group(1).strip('"') if found else ""
        self.groups: Dict[str, Dict[str, Dict[str, List[str]]]] = {}  # type -> name -> key -> values
        self.chains: Dict[Tuple[int, str, str], _RawChain] = {}
        self.zones: Dict[str, _Zone] = {}
        self.state_policy: Dict[str, Dict[str, str]] = {}
        self.nat: List[_NatEntry] = []
        self.interfaces: List[str] = []  # interfaces of the configuration
        self.excluded: Set[str] = set()  # ports of bridges and bonds: no routed traffic arrives by them
        self.has_interfaces = False
        self.other_zone = ""  # without the interfaces part: the zone of the model for interfaces the configuration does not name
        self.bindings: List[Tuple[str, str, str, str]] = []  # legacy: (direction, family word, interface, rule-set)
        self.named: List[str] = []  # interface names the firewall and NAT name
        self.not_read: List[str] = []
        self.host_chains: List[str] = []
        self.missing: Set[str] = set()
        self.empty_groups: Set[str] = set()
        self.wildcards: List[str] = []
        self.made_groups: Dict[Tuple[str, str], str] = {}
        self.fqdn_groups: Set[str] = set()
        self.names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.visited = 0
        self.passive = 0
        self.disabled_flow = 0
        self.pending: List[Tuple[int, List[Rule]]] = []
        self.dnat_entries: List[Tuple[_Cond, NatRule, bool]] = []  # (pre-NAT match, rule, whether it translates)
        self.universe: FrozenSet[str] = frozenset()
        self.known: List[str] = []
        self.zone_of: Dict[str, str] = {}
        self.zone_members: Dict[str, List[str]] = {}
        self.split_zones: List[str] = []
        self.compiled: Dict[Tuple[int, str], _Chain] = {}
        self.offload = False
        self.queue: List[str] = []

    @staticmethod
    def _is_legacy(words: List[str]) -> bool:
        if words[:1] == ["zone-policy"] or words[:2] in (["service", "nat"], ["firewall", "name"], ["firewall", "ipv6-name"],
                                                          ["firewall", "state-policy"], ["firewall", "interface"]):  # fmt: skip
            return True
        if words[:1] == ["interfaces"] and "firewall" in words:
            at = words.index("firewall")
            return len(words) > at + 1 and words[at + 1] in ("in", "out", "local")
        return False

    # -- the parts of the configuration -------------------------------------------------------

    def read(self) -> None:
        for line, words in self.paths:
            head = words[0]
            if head == "firewall":
                self._firewall(words[1:], line)
            elif head == "nat" and len(words) >= 4 and words[1] in ("destination", "source") and words[2] == "rule":
                self._nat_line(words[1], words[3], words[4:], line)
            elif head == "nat" and len(words) >= 2 and words[1] in ("static", "cgnat"):
                self.not_read.append(f"nat {words[1]}")
            elif head == "nat66":
                self.not_read.append("nat66")
            elif head == "zone-policy" and len(words) >= 3 and words[1] == "zone":
                self._zone_line(words[2], words[3:], legacy=True)
            elif head == "service" and len(words) >= 4 and words[1] == "nat" and words[2] == "rule":
                self._edgeos_nat(words[3], words[4:], line)
            elif head == "interfaces":
                self._interface_line(words[1:])
            elif head == "port-forward":
                self.not_read.append("port-forward (EdgeOS)")
        self.not_read = list(dict.fromkeys(self.not_read))

    def _chain(self, family: int, hook: str, name: str, legacy: bool = False) -> _RawChain:
        key = (family, hook, name)
        if key not in self.chains:
            self.chains[key] = _RawChain(family, hook, name, legacy=legacy)
        return self.chains[key]

    def _firewall(self, words: List[str], line: int) -> None:
        if not words:
            return
        head = words[0]
        if head in ("ipv4", "ipv6") and len(words) >= 2:
            family = 4 if head == "ipv4" else 6
            hook = words[1]
            if hook == "name" and len(words) >= 3:
                self._chain_line(self._chain(family, "name", words[2]), words[3:], line)
            elif hook in ("forward", "input", "output", "prerouting") and len(words) >= 3:
                if words[2] == "filter" and hook in ("forward", "input", "output"):
                    self._chain_line(self._chain(family, hook, "filter"), words[3:], line)
                else:
                    self._chain_line(self._chain(family, hook, words[2]), words[3:], line)
        elif head in ("name", "ipv6-name") and len(words) >= 2:
            family = 4 if head == "name" else 6
            self._chain_line(self._chain(family, "name", words[1], legacy=True), words[2:], line)
        elif head == "group" and len(words) >= 3:
            kind, name = words[1], words[2]
            entry = self.groups.setdefault(kind, {}).setdefault(name, {})
            if len(words) >= 5:
                entry.setdefault(words[3], []).append(words[4])
            elif len(words) == 4:
                entry.setdefault(words[3], [])
        elif head == "zone" and len(words) >= 2:
            self._zone_line(words[1], words[2:], legacy=False)
        elif head == "global-options" and len(words) >= 4 and words[1] == "state-policy":
            self.state_policy.setdefault(words[2], {})[words[3]] = words[4] if len(words) > 4 else ""
        elif head == "state-policy" and len(words) >= 3:
            self.state_policy.setdefault(words[1], {})[words[2]] = words[3] if len(words) > 3 else ""
        elif head == "interface" and len(words) >= 5 and words[2] in ("in", "out", "local"):
            self.bindings.append((words[2], words[3], words[1], words[4]))
        elif head == "flowtable":
            self.offload = True
        elif head == "bridge":
            self.not_read.append("firewall bridge")

    def _chain_line(self, chain: _RawChain, words: List[str], line: int) -> None:
        if not words:
            return
        if words[0] == "rule" and len(words) >= 2:
            if not is_number(words[1]):
                raise ParseError(f"line {line}: rule '{_short(words[1], 20)}', which is not a number")
            chain.rules.setdefault(int(words[1]), [])
            if len(words) > 2:
                chain.rules[int(words[1])].append(words[2:])
        elif words[0] == "default-action" and len(words) >= 2:
            chain.default = words[1]
        elif words[0] == "default-jump-target" and len(words) >= 2:
            chain.default_target = words[1]
        elif words[0] in ("default-log", "enable-default-log"):
            chain.default_log = True
        elif words[0] in ("description", "disable-conntrack"):
            if words[0] == "disable-conntrack":
                chain.unread.append("disable-conntrack")

    def _zone_line(self, name: str, words: List[str], legacy: bool) -> None:
        zone = self.zones.setdefault(name, _Zone(name))
        if not words:
            return
        head = words[0]
        if head == "interface" and len(words) >= 2:
            value = words[1].replace("+", "*") if legacy else words[1]
            zone.interfaces.append(value)
        elif head == "member" and len(words) >= 3 and words[1] == "interface":
            zone.interfaces.append(words[2])
        elif head == "member" and len(words) >= 3 and words[1] == "vrf":
            self.not_read.append(f"zone {name} member vrf")
        elif head == "local-zone":
            zone.local = True
        elif head == "default-action" and len(words) >= 2:
            zone.default = words[1]
        elif head in ("default-log", "enable-default-log"):
            zone.default_log = True
        elif head == "from" and len(words) >= 5 and words[2] == "firewall" and words[3] in ("name", "ipv6-name"):
            zone.froms.setdefault(words[1], {})[words[3]] = words[4]
        elif head == "from" and len(words) >= 2:
            zone.froms.setdefault(words[1], {})
        elif head == "intra-zone-filtering" and len(words) >= 3:
            if words[1] == "action":
                zone.intra_action = words[2]
            elif words[1] == "firewall" and len(words) >= 4:
                zone.intra_names[words[2]] = words[3]
        elif head == "default-firewall" and len(words) >= 3:
            zone.default_names[words[1]] = words[2]

    def _interface_line(self, words: List[str]) -> None:
        if len(words) < 2:
            return
        self.has_interfaces = True
        kind, name = words[0], words[1]
        rest = words[2:]
        interface = name
        found = [name]
        while rest and rest[0] in ("vif", "vif-s", "vif-c", "pppoe") and len(rest) >= 2:
            interface = f"pppoe{rest[1]}" if rest[0] == "pppoe" else f"{interface}.{rest[1]}"
            found.append(interface)
            rest = rest[2:]
        for each in found:
            if each not in self.interfaces and kind != "loopback" and each != "lo":
                self.interfaces.append(each)
        if kind in ("bridge", "bonding") and rest[:2] == ["member", "interface"] and len(rest) >= 3:
            self.excluded.add(rest[2])
        if rest[:1] in (["bridge-group"], ["bond-group"]):
            self.excluded.add(interface)
        if "firewall" in rest:
            at = rest.index("firewall")
            tail = rest[at + 1 :]
            if len(tail) >= 3 and tail[0] in ("in", "out", "local") and tail[1] in ("name", "ipv6-name"):
                self.bindings.append((tail[0], tail[1], interface, tail[2]))

    def _nat_line(self, kind: str, number: str, words: List[str], line: int) -> None:
        if not is_number(number):
            raise ParseError(f"line {line}: NAT rule '{_short(number, 20)}', which is not a number")
        found = next((n for n in self.nat if n.kind == kind and n.number == int(number)), None)
        if found is None:
            found = _NatEntry(kind, int(number), {}, line)
            self.nat.append(found)
        if words:
            key = tuple(words[:-1]) if len(words) > 1 else (words[0],)
            found.statements.setdefault(key, []).append(words[-1] if len(words) > 1 else "")

    def _edgeos_nat(self, number: str, words: List[str], line: int) -> None:
        """A rule of ``service nat`` (EdgeOS) as a rule of ``nat destination`` or ``nat source``."""
        if not is_number(number):
            raise ParseError(f"line {line}: NAT rule '{_short(number, 20)}', which is not a number")
        found = next((n for n in self.nat if n.kind == "edgeos" and n.number == int(number)), None)
        if found is None:
            found = _NatEntry("edgeos", int(number), {}, line)
            self.nat.append(found)
        if words:
            key = tuple(words[:-1]) if len(words) > 1 else (words[0],)
            found.statements.setdefault(key, []).append(words[-1] if len(words) > 1 else "")

    def finish_edgeos_nat(self) -> None:
        out: List[_NatEntry] = []
        for entry in self.nat:
            if entry.kind != "edgeos":
                out.append(entry)
                continue
            s = entry.statements
            kind = (s.get(("type",)) or [""])[0]
            new: Statements = {}
            for key, values in s.items():
                if key in (("type",),):
                    continue
                if key[:1] == ("inside-address",) and len(key) == 2:
                    new[("translation", key[1])] = values
                elif key[:1] == ("outside-address",) and len(key) == 2:
                    new[("translation", key[1])] = values
                elif key in (("log",),):
                    if values != ["disable"]:
                        new[key] = [""]
                else:
                    new[key] = values
            if kind == "masquerade":
                new[("translation", "address")] = ["masquerade"]
                out.append(_NatEntry("source", entry.number, new, entry.line))
            elif kind == "source":
                out.append(_NatEntry("source", entry.number, new, entry.line))
            elif kind == "destination":
                out.append(_NatEntry("destination", entry.number, new, entry.line))
            else:
                new[("\x00problem",)] = [f"type '{kind}', which this parser does not know" if kind else "a rule without a type"]
                out.append(_NatEntry("destination", entry.number, new, entry.line))
        self.nat = sorted(out, key=lambda n: (n.kind != "destination", n.number))

    # -- the legacy firewall as VyOS 1.4 has it ---------------------------------------------------

    def migrate(self) -> None:
        """A rule-set on an interface becomes a jump from the forward filter (the in ones before the out ones), as the
        migration of VyOS to 1.4 writes it; the forward filter then accepts what no rule-set decides."""
        number = {4: 5, 6: 5}
        for direction in ("in", "out", "local"):
            for found, word, interface, ruleset in self.bindings:
                if found != direction:
                    continue
                family = 4 if word == "name" else 6
                if direction == "local":
                    self.host_chains.append(f"{'ipv4' if family == 4 else 'ipv6'} rule-set {ruleset} on {interface} local")
                    continue
                chain = self._chain(family, "forward", "filter")
                chain.default = "accept"
                side = "inbound-interface" if direction == "in" else "outbound-interface"
                chain.rules[number[family]] = [[side, "name", interface], ["action", "jump"], ["jump-target", ruleset]]
                number[family] += 5

    # -- interfaces -----------------------------------------------------------------------------

    def collect_interfaces(self) -> None:
        named: List[str] = []
        for chain in self.chains.values():
            for lines in chain.rules.values():
                for words in lines:
                    if words[:1] in (["inbound-interface"], ["outbound-interface"]) and len(words) >= 2:
                        value = words[-1]
                        if len(words) == 2 or words[1] in ("name", "interface-name"):
                            named.append(_neg(value)[1])
        for zone in self.zones.values():
            named += zone.interfaces
        for members in self.groups.get("interface-group", {}).values():
            named += [_neg(v)[1] for v in members.get("interface", [])]
        for entry in self.nat:
            for key, values in entry.statements.items():
                if key[:1] in (("inbound-interface",), ("outbound-interface",)) and (len(key) == 1 or key[1] in ("name", "interface-name")):
                    named += [_neg(v)[1] for v in values if v != "any"]
        for name in named:
            if "*" not in name and name not in self.named:
                self.named.append(name)
        known = list(dict.fromkeys(self.interfaces + self.named))
        self.known = [i for i in known if i != "lo"]
        self.universe = frozenset(i for i in self.known if i not in self.excluded) | {OTHER}

    def _interfaces(self, value: str) -> Tuple[FrozenSet[str], str]:
        """The interfaces of a name, a wildcard or their negation: (interfaces, problem)."""
        negated, name = _neg(value)
        if "*" in name:
            if not name.endswith("*") or name.count("*") > 1:
                return frozenset(), f"interface '{_short(value, 30)}' with a '*' that is not at its end"
            stem = name[:-1]
            matched = {i for i in self.known if i.startswith(stem)}
            if not matched:
                matched = {name}
                if name not in self.wildcards:
                    self.wildcards.append(name)
        else:
            matched = {name}
        if negated:
            return self.universe - frozenset(matched), ""
        return frozenset(matched), ""

    def _interface_group(self, value: str, stack: Tuple[str, ...] = ()) -> Tuple[Optional[FrozenSet[str]], str]:
        negated, name = _neg(value)
        group = self.groups.get("interface-group", {}).get(name)
        if group is None:
            self.missing.add(name)
            return None, f"interface-group '{_short(name)}' is not in the configuration"
        if name in stack or len(stack) > _MAX_NESTING:
            return None, f"interface-group '{_short(name)}' includes itself"
        out: Set[str] = set()
        for member in group.get("interface", []):
            found, problem = self._interfaces(member)
            if problem:
                return None, problem
            out |= found
        for other in group.get("include", []):
            inner, problem = self._interface_group(other, stack + (name,))
            if inner is None:
                return None, problem
            out |= inner
        result = frozenset(out)
        return (self.universe - result if negated else result), ""

    # -- groups of addresses and ports ------------------------------------------------------------

    def _group_values(self, kind: str, name: str, key: str, stack: Tuple[str, ...] = ()) -> Optional[List[str]]:
        group = self.groups.get(kind, {}).get(name)
        if group is None or name in stack or len(stack) > _MAX_NESTING:
            return None
        out = list(group.get(key, []))
        for other in group.get("include", []):
            inner = self._group_values(kind, other, key, stack + (name,))
            if inner is None:
                return None
            out += inner
        return list(dict.fromkeys(out))

    def _model_group(self, kind: str, name: str, members: List[str], fqdn: bool = False) -> str:
        key = (kind, name)
        if key in self.made_groups:
            return self.made_groups[key]
        taken = set(self.p.address_groups) | set(self.p.addresses)
        candidate = name
        if candidate in taken or parse_literal(candidate) is not None:
            candidate = f"{name}-{kind}"
        counter = 2
        base = candidate
        while candidate in taken:
            candidate = f"{base}-{counter}"
            counter += 1
        self.made_groups[key] = candidate
        includes = self.groups.get(kind, {}).get(name, {}).get("include", [])
        description = f"VyOS firewall group {kind} {name}" + (" (with " + ", ".join(includes) + ")" if includes else "")
        self.p.address_groups[candidate] = AddressGroup(candidate, list(members), description=description)
        if fqdn:
            self.fqdn_groups.add(candidate)
        return candidate

    # -- one rule as conditions ---------------------------------------------------------------

    def compile_rule(self, family: int, chain: _RawChain, number: int, lines: List[List[str]]) -> _VRule:
        s = _statements(lines)
        legacy = chain.legacy
        label = self._chain_label(chain) + f" rule {number}"
        step = f"{chain.name if chain.hook == 'name' else chain.hook}-{number}"
        action = (s.get(("action",)) or [""])[-1]
        rule = _VRule(family, chain.name, number, action, label, step)
        rule.target = (s.get(("jump-target",)) or [""])[-1]
        rule.description = " ".join((s.get(("description",)) or [""])[-1].split())
        rule.disabled = ("disable",) in s
        log = s.get(("log",)) or []
        rule.log = bool(log) and log[-1] in ("", "enable")
        if legacy and action == "accept":
            rule.action, rule.accept_was = "return", "accept"
        rule.conds = self._conds(family, s, legacy, rule)
        return rule

    def _chain_label(self, chain: _RawChain) -> str:
        fam = "ipv4" if chain.family == 4 else "ipv6"
        if chain.hook == "name":
            if chain.legacy:
                return f"firewall {'name' if chain.family == 4 else 'ipv6-name'} {chain.name}"
            return f"{fam} name {chain.name}"
        return f"{fam} {chain.hook} {chain.name}"

    def _conds(self, family: int, s: Statements, legacy: bool, rule: _VRule) -> List[_Cond]:
        c: Optional[_Cond] = _Cond(families=frozenset({family}))
        assert c is not None
        for key, values in s.items():
            head = key[0]
            if head in _PASSING_STATEMENTS:
                if head in ("queue", "queue-options", "synproxy") and rule.action not in ("queue", "synproxy"):
                    c = _with_problem(c, f"'{' '.join(key)}' on a rule of action {rule.action or 'none'}")
                continue
            if head in ("source", "destination"):
                if len(key) >= 2 and key[1] in _UNSUPPORTED:
                    c = _with_problem(c, f"{' '.join(key)} {_short(values[0], 30)} (a match on {_UNSUPPORTED[key[1]]})")
                elif len(key) >= 3 and key[1] == "group" and key[2] in _UNSUPPORTED:
                    c = _with_problem(c, f"{' '.join(key)} {_short(values[0], 30)} (a match on {_UNSUPPORTED[key[2]]})")
                elif not (len(key) == 2 and key[1] in ("address", "port", "fqdn")) and not (
                        len(key) == 3 and key[1] == "group" and key[2] in ("address-group", "network-group", "port-group",
                                                                        "domain-group", "ipv6-address-group",
                                                                        "ipv6-network-group")):  # fmt: skip
                    c = _with_problem(c, f"'{' '.join(key)}', which FWShift does not read")
                continue
            if head in _UNSUPPORTED:
                c = _with_problem(c, f"{' '.join(key)} {_short(values[0], 30)} (a match on {_UNSUPPORTED[head]})")
                continue
            if head in ("protocol", "state", "icmp", "icmpv6", "inbound-interface", "outbound-interface",
                        "connection-status", "tcp", "time"):  # fmt: skip
                continue
            c = _with_problem(c, f"'{' '.join(key)}', which FWShift does not read")
        for side in ("inbound-interface", "outbound-interface"):
            c = self._interface_cond(c, s, side)
            if c is None:
                return []
        protocol = (s.get(("protocol",)) or [""])[-1]
        negated, proto = _neg(protocol)
        port_group = any(key[:3] in (("source", "group", "port-group"), ("destination", "group", "port-group")) for key in s)
        if legacy and proto == "all" and port_group:
            proto = "tcp_udp"  # (as the migration of VyOS to 1.4 rewrites it)
        head = ""
        if proto and proto != "all":
            if proto == "tcp_udp":
                c = constrain(c, "meta l4proto", "!=" if negated else "==", ["6", "17"])
                head = "" if negated else "th"
            else:
                number = _PROTOCOLS.get(proto.lower(), int(proto) if is_number(proto) and int(proto) <= 255 else None)
                if number is None or (number == 58 and family == 4) or (number == 1 and family == 6):
                    return [_with_problem(c, f"protocol {_short(protocol, 20)}")]
                c = constrain(c, "meta l4proto", "!=" if negated else "==", [str(number)])
                head = "" if negated else {6: "tcp", 17: "udp"}.get(number, "")
            if c is None:
                return []
        for side, word in (("source", "saddr"), ("destination", "daddr")):
            address = s.get((side, "address"))
            if address:
                c = self._address_cond(c, family, word, address[-1])
                if c is None:
                    return []
            for kind in ("address-group", "network-group", "ipv6-address-group", "ipv6-network-group"):
                found = s.get((side, "group", kind))
                if found:
                    c = self._group_cond(c, family, side, kind, found[-1])
                    if c is None:
                        return []
            for kind, key in (("domain-group", (side, "group", "domain-group")), ("fqdn", (side, "fqdn"))):
                found = s.get(key)
                if found:
                    c = self._fqdn_cond(c, family, side, kind, found[-1])
            ports = s.get((side, "port"))
            group = s.get((side, "group", "port-group"))
            field_word = "sport" if side == "source" else "dport"
            if ports or group:
                if not head:
                    c = _with_problem(c, f"{side} port without protocol tcp, udp or tcp_udp")
                    continue
                if ports:
                    c = self._port_cond(c, f"{head} {field_word}", ports[-1], legacy)
                else:
                    negated_group, name = _neg(group[-1]) if group else (False, "")
                    found_ports = self._group_values("port-group", name, "port")
                    if found_ports is None:
                        self.missing.add(name)
                        c = _with_problem(c, f"port-group '{_short(name)}' is not in the configuration")
                        continue
                    c = self._port_values(c, f"{head} {field_word}", found_ports, negated_group)
                if c is None:
                    return []
        for word in ("icmp", "icmpv6"):
            c = self._icmp_cond(c, s, word, family, legacy)
            if c is None:
                return []
        states = self._states(s)
        if states:
            c = constrain(c, "ct state", "==", states)
            if c is None:
                return []
        status = s.get(("connection-status", "nat"))
        if status:
            if status[-1] == "destination":
                c = _with_problem(c, "\x00ctdnat")
            else:
                c = _with_problem(c, f"connection-status nat {_short(status[-1], 20)} (connections whose source is "
                                  "translated, which a new connection is not yet at the forward hook)")  # fmt: skip
        c = self._tcp_flags(c, s)
        if c is None:
            return []
        times = [f"{' '.join(key[1:])} {values[-1]}" for key, values in s.items() if key[:1] == ("time",)]
        if times:
            c = _with_problem(c, "\x00schedule:" + ", ".join(times))
        return [c]

    def _interface_cond(self, c: _Cond, s: Statements, side: str) -> Optional[_Cond]:
        value: Optional[str] = None
        problem = ""
        found: Optional[FrozenSet[str]] = None
        for key, values in s.items():
            if key[:1] != (side,):
                continue
            text = values[-1]
            if len(key) == 1 or key[1] in ("name", "interface-name"):
                value = text
                found, problem = self._interfaces(text)
            elif key[1] in ("group", "interface-group"):
                value = text
                found, problem = self._interface_group(text)
            else:
                problem = f"'{' '.join(key)}', which FWShift does not read"
        if value is None and not problem:
            return c
        if problem or found is None or value is None:
            return _with_problem(c, problem)
        if value.startswith("!"):
            c = _with_problem(c, f"\x00negif:{'in' if side.startswith('in') else 'out'}")
        return _meet(c, _Cond(iif=found) if side.startswith("in") else _Cond(oif=found))

    def _address_cond(self, c: _Cond, family: int, word: str, value: str) -> Optional[_Cond]:
        negated, text = _neg(value)
        interval = parse_literal(text)
        key = f"{'ip' if family == 4 else 'ip6'} {word}"
        if interval is None or interval[0] != family:
            return _with_problem(c, f"address {_short(value, 40)}" + (", of the other IP version" if interval else ""))
        return constrain(c, key, "!=" if negated else "==", [interval_text(interval) if "/" in text else text])

    def _group_cond(self, c: _Cond, family: int, side: str, kind: str, value: str) -> Optional[_Cond]:
        negated, name = _neg(value)
        if family == 6 and not kind.startswith("ipv6-"):
            kind = f"ipv6-{kind}"  # (a rule of an IPv6 chain names the IPv6 group of that name)
        elif family == 4 and kind.startswith("ipv6-"):
            return _with_problem(c, f"{kind} '{_short(name)}' in a rule for IPv4")
        key = "network" if kind.endswith("network-group") else "address"
        values = self._group_values(kind, name, key)
        if values is not None and kind.startswith("ipv6-"):
            values += self._group_values(kind, name, f"ipv6-{key}") or []  # (EdgeOS: ipv6-network, ipv6-address)
        if values is None:
            self.missing.add(name)
            return _with_problem(c, f"{kind} '{_short(name)}' is not in the configuration")
        literals: List[str] = []
        for text in values:
            interval = parse_literal(text)
            if interval is None or interval[0] != family:
                return _with_problem(c, f"{kind} '{_short(name)}' holds '{_short(text)}', which FWShift cannot read")
            literals.append(interval_text(interval) if "/" in text else text)
        group = self._model_group(kind, name, literals)
        if not literals:
            self.empty_groups.add(f"{kind} {name}")
        word = "saddr" if side == "source" else "daddr"
        return constrain(c, f"{'ip' if family == 4 else 'ip6'} {word}", "!=" if negated else "==", literals, (group,))

    def _fqdn_cond(self, c: _Cond, family: int, side: str, kind: str, value: str) -> _Cond:
        negated, name = _neg(value)
        if kind == "domain-group":
            hosts = self._group_values("domain-group", name, "address")
            if hosts is None:
                self.missing.add(name)
                return _with_problem(c, f"domain-group '{_short(name)}' is not in the configuration")
            members = [self._fqdn_address(host, family) for host in hosts]
            target = self._model_group("domain-group" if family == 4 else "domain-group-ipv6", name, members, fqdn=True)
        else:
            target = self._fqdn_address(name, family)
        return _with_problem(c, f"\x00addr:{'src' if side == 'source' else 'dst'}:{'!' if negated else ''}{target}")

    def _fqdn_address(self, host: str, family: int) -> str:
        name = host if family == 4 else f"{host}-ipv6"
        if name not in self.p.addresses:
            self.p.addresses[name] = Address(name, AddressKind.FQDN, host, description="host name in a VyOS rule or domain-group",
                                             fqdn_family=family)  # fmt: skip
        return name

    def _port_cond(self, c: _Cond, key: str, value: str, legacy: bool) -> Optional[_Cond]:
        items = [item for item in value.split(",") if item]
        if legacy:
            # VyOS 1.3 and Vyatta negate the whole list with a '!' in front of it.
            negated = bool(items) and items[0].startswith("!")
            plain = [item.lstrip("!") for item in items]
            if any(item.startswith("!") for item in items[1:]):
                return _with_problem(c, f"port list {_short(value, 40)} with a '!' inside it")
            return self._port_values(c, key, plain, negated)
        positive = [item for item in items if not item.startswith("!")]
        negative = [item[1:] for item in items if item.startswith("!")]
        out: Optional[_Cond] = c
        if positive:
            out = self._port_values(c, key, positive, False)
        if negative and out is not None:
            out = self._port_values(out, key, negative, True)
        return out

    @staticmethod
    def _port_values(c: _Cond, key: str, values: Sequence[str], negated: bool) -> Optional[_Cond]:
        numbers: List[str] = []
        for text in values:
            first, sep, last = text.partition("-")
            low = int(first) if is_number(first) else _PORT_NAMES.get(first)
            high = (int(last) if is_number(last) else _PORT_NAMES.get(last)) if sep else low
            if low is None or high is None or low > high or high > 65535:
                return _with_problem(c, f"port '{_short(text, 20)}', which FWShift cannot read")
            numbers.append(f"{low}-{high}" if low != high else str(low))
        return constrain(c, key, "!=" if negated else "==", numbers)

    def _icmp_cond(self, c: _Cond, s: Statements, word: str, family: int, legacy: bool) -> Optional[_Cond]:
        if not any(key[:1] == (word,) for key in s):
            return c
        if (word == "icmp") != (family == 4):
            return _with_problem(c, f"'{word}' in a rule for IPv{family}")
        kind: Optional[str] = (s.get((word, "type")) or [""])[-1] or None
        code: Optional[str] = (s.get((word, "code")) or [""])[-1] or None
        name: Optional[str] = (s.get((word, "type-name")) or [""])[-1] or None
        if name is not None:
            table = _LEGACY_ICMP if word == "icmp" else _LEGACY_ICMP6
            if name == "any":
                return constrain(c, "meta l4proto", "==", ["1" if family == 4 else "58"])
            if name in table and (legacy or name not in (_nft._ICMP_TYPES if word == "icmp" else _nft._ICMP6_TYPES)):
                kind, code_number = table[name]
                code = str(code_number) if code_number is not None else code
            else:
                kind = name
        elif kind is not None and not is_number(kind) and legacy:
            table = _LEGACY_ICMP if word == "icmp" else _LEGACY_ICMP6
            if kind in table:
                kind, code_number = table[kind]
                code = str(code_number) if code_number is not None else code
        for key in s:
            if key[:1] == (word,) and key[1:] not in (("type",), ("code",), ("type-name",)):
                c = _with_problem(c, f"'{' '.join(key)}', which FWShift does not read")
        out: Optional[_Cond] = c
        nft = "icmp" if word == "icmp" else "icmpv6"
        if kind is not None:
            out = constrain(c, f"{nft} type", "==", [kind])
        elif code is not None:
            return _with_problem(c, f"{word} code without a type")
        if out is not None and code is not None:
            out = constrain(out, f"{nft} code", "==", [code])
        return out

    @staticmethod
    def _states(s: Statements) -> List[str]:
        out: List[str] = []
        for value in s.get(("state",), []):
            if value:
                out.append(value)
        for state in ("established", "related", "new", "invalid"):
            values = s.get(("state", state))
            if values and values[-1] == "enable":
                out.append(state)
        return list(dict.fromkeys(out))

    @staticmethod
    def _tcp_flags(c: _Cond, s: Statements) -> Optional[_Cond]:
        flags = [v.lower() for v in s.get(("tcp", "flags"), [])]
        not_flags = [v.lower() for v in s.get(("tcp", "flags", "not"), [])]
        for key in s:
            if key[:1] == ("tcp",) and key not in (("tcp", "flags"), ("tcp", "flags", "not")):
                c = _with_problem(c, f"'{' '.join(key)}', which FWShift does not read")
        if not flags and not not_flags:
            return c
        if len(flags) == 1 and "," in flags[0]:  # VyOS 1.3: SYN,!ACK
            parts = flags[0].split(",")
            flags = [p for p in parts if not p.startswith("!")]
            not_flags = [p[1:] for p in parts if p.startswith("!")]
        if flags == ["syn"] and set(not_flags) <= {"ack", "rst", "fin", "urg", "psh"}:
            # A SYN opens a TCP connection: nothing more than TCP is left to say.
            return constrain(c, "meta l4proto", "==", ["6"])
        return _with_problem(c, "tcp flags " + ",".join(flags + ["!" + f for f in not_flags]))

    # -- the chains ---------------------------------------------------------------------------

    def compile(self) -> None:
        for (family, hook, name), raw in self.chains.items():
            if hook == "name":
                chain = _Chain(family, name, self._chain_label(raw))
                chain.default = raw.default or ("drop" if not raw.legacy else "drop")
                if raw.legacy and chain.default == "accept":
                    chain.default = "return"  # (as the migration of VyOS to 1.4 rewrites it)
            elif hook == "forward" and name == "filter":
                chain = _Chain(family, "\x00forward", self._chain_label(raw))
                chain.default = raw.default or "accept"
                if chain.default not in ("accept", "drop"):
                    self.not_read.append(f"{chain.label} default-action {chain.default}")
                    chain.default = "accept"
                chain.rules += self._state_rules(family, "forward")
            else:
                if raw.rules or raw.default:
                    fam = "ipv4" if family == 4 else "ipv6"
                    if hook in ("input", "output"):
                        self.host_chains.append(f"{fam} {hook} {name} ({len(raw.rules)} rules)")
                    else:
                        self.not_read.append(f"{fam} {hook} {name} ({len(raw.rules)} rules)")
                continue
            chain.default_target = raw.default_target
            chain.default_log = raw.default_log
            for unread in raw.unread:
                self.not_read.append(f"{chain.label} {unread}")
            for number in sorted(raw.rules):
                chain.rules.append(self.compile_rule(family, raw, number, raw.rules[number]))
            self.compiled[(family, chain.name)] = chain

    def zone_chains(self, family: int) -> Optional[_Chain]:
        """The base chain the zone-based firewall adds at the forward hook, and the chains it jumps to, as VyOS writes
        them (``VYOS_ZONE_FORWARD`` and ``VZONE_<zone>``)."""
        zones = [z for z in self.zones.values() if not z.local]
        if not zones:
            return None
        fam = "ipv4" if family == 4 else "ipv6"
        word = "name" if family == 4 else "ipv6-name"
        legacy = "zone-policy zone" if self.legacy else "zone"
        base = _Chain(family, "\x00zones", f"{fam} zones", default="accept")
        base.rules += self._state_rules(family, "zones")
        for zone in zones:
            members = self._zone_interfaces(zone)
            label = f"{legacy} {zone.name}"
            dispatch = _VRule(family, base.name, 0, "jump", f"{label} (by its interfaces)", f"zone-{zone.name}",
                              target=f"\x00zone:{zone.name}", conds=[_Cond(families=frozenset({family}), oif=members)])  # fmt: skip
            base.rules.append(dispatch)
            chain = _Chain(family, f"\x00zone:{zone.name}", label, default="reject" if zone.default == "reject" else "drop",
                           default_log=zone.default_log)  # fmt: skip
            inside = _Cond(families=frozenset({family}), iif=members)
            intra = zone.intra_names.get(word)
            if zone.intra_action == "drop":
                chain.rules.append(_VRule(family, chain.name, 0, "drop", f"{label} intra-zone-filtering action drop", "intra",
                                          conds=[inside]))  # fmt: skip
            elif intra and (zone.intra_action == "" ):
                chain.rules.append(_VRule(family, chain.name, 0, "jump", f"{label} intra-zone-filtering firewall {word} {intra}",
                                          "intra", target=intra, conds=[inside]))  # fmt: skip
                if not self._decides_all(family, intra):
                    chain.rules.append(_VRule(family, chain.name, 0, "return", f"{label} intra-zone-filtering", "intra-end",
                                              conds=[inside]))  # fmt: skip
            else:
                chain.rules.append(_VRule(family, chain.name, 0, "return", f"{label} (inside the zone)", "intra",
                                          conds=[inside]))  # fmt: skip
            for source, names in zone.froms.items():
                other = self.zones.get(source)
                if other is None:
                    self.missing.add(source)
                    continue
                if other.local or word not in names:
                    continue
                incoming = _Cond(families=frozenset({family}), iif=self._zone_interfaces(other))
                chain.rules.append(_VRule(family, chain.name, 0, "jump", f"{label} from {source} firewall {word} {names[word]}",
                                          f"from-{source}", target=names[word], conds=[incoming]))  # fmt: skip
                if not self._decides_all(family, names[word]):
                    chain.rules.append(_VRule(family, chain.name, 0, "return", f"{label} from {source} (what {names[word]} "
                                              "returns)", f"from-{source}-end", conds=[incoming]))  # fmt: skip
            fallback = zone.default_names.get(word)
            if fallback:
                chain.rules.append(_VRule(family, chain.name, 0, "jump", f"{label} default-firewall {word} {fallback}",
                                          "default-firewall", target=fallback, conds=[_Cond(families=frozenset({family}))]))  # fmt: skip
                if not self._decides_all(family, fallback):
                    chain.rules.append(_VRule(family, chain.name, 0, "return", f"{label} default-firewall", "default-firewall-end",
                                              conds=[_Cond(families=frozenset({family}))]))  # fmt: skip
            self.compiled[(family, chain.name)] = chain
        return base

    def _decides_all(self, family: int, name: str, depth: int = 0) -> bool:
        """Whether nothing comes back from a named chain: no rule returns, and its default-action decides (or jumps to a
        chain that does)."""
        chain = self.compiled.get((family, name))
        if chain is None or depth > _MAX_NESTING:
            return True  # (the jump is not followed: nothing comes back)
        if any(rule.action == "return" and not rule.disabled for rule in chain.rules):
            return False
        if chain.default in ("accept", "drop", "reject"):
            return True
        return chain.default == "jump" and self._decides_all(family, chain.default_target, depth + 1)

    def _zone_interfaces(self, zone: _Zone) -> FrozenSet[str]:
        out: Set[str] = set()
        for value in zone.interfaces:
            found, _ = self._interfaces(value)
            out |= found
        return frozenset(out)

    def _state_rules(self, family: int, where: str) -> List[_VRule]:
        """``global-options state-policy`` (``state-policy`` in VyOS 1.3): a chain every base chain jumps to first."""
        out: List[_VRule] = []
        for state in ("established", "invalid", "related"):
            conf = self.state_policy.get(state)
            if conf is None:
                continue
            action = conf.get("action", "")
            states = _Cond(families=frozenset({family}), states=frozenset({state.upper()}))
            out.append(_VRule(family, f"\x00state-{where}", 0, action or "continue", f"global-options state-policy {state}",
                              f"state-policy-{state}", log="log" in conf, conds=[states]))  # fmt: skip
        return out

    # -- following the chains -----------------------------------------------------------------

    def _split(self, context: _Cond, taken: _Cond) -> Optional[List[_Cond]]:
        """What is left of ``context`` once the packets of ``taken`` (a part of it) are gone, as conditions that do not
        overlap; None when that cannot be said. Interfaces are taken away within the interfaces of the router."""
        if taken.unsupported != context.unsupported:
            return None
        differ = [name for name in _nft._FIELDS if getattr(context, name) != getattr(taken, name)]
        if "families" in differ:
            return None
        out: List[_Cond] = []
        base = context
        for name in differ:
            changes: Dict[str, Any] = {name: getattr(taken, name)}
            if name in ("src", "dst"):
                changes[name + "_show"] = getattr(taken, name + "_show")
            step = dataclasses.replace(base, **changes)
            if name in ("iif", "oif"):
                have = getattr(base, name)
                left = (self.universe if have is None else have) - getattr(taken, name)
                piece: Any = None
                if left:
                    piece = dataclasses.replace(base, iif=frozenset(left)) if name == "iif" else dataclasses.replace(base, oif=frozenset(left))
            else:
                piece = _without(base, step)
                if piece is False:
                    return None
            if piece is not None:
                out.append(piece)
            base = step
        return out

    def walk(self, frame: "_Frame", contexts: List[_Cond], out: List[_Entry]) -> None:
        """Walk a chain from a rule on, for the packets of ``contexts``. A ``return`` in a chain that was jumped to puts the
        rest of the calling chain there, for what returns: those packets are decided where they return, in the order of
        the source, and the rules below never see them."""
        chain = frame.chain
        for index in range(frame.start, len(chain.rules)):
            rule = chain.rules[index]
            where = f"{frame.prefix}{rule.step}"
            if rule.disabled:
                if frame.inline:
                    continue  # (kept once, where the chain is walked in full)
                if rule.action in ("accept", "drop", "reject") or rule.accept_was:
                    verdict = "accept" if rule.accept_was else rule.action
                    for context in contexts:
                        for cond in rule.conds:
                            merged = _meet(context, cond)
                            if merged is not None:
                                out.append(_Entry(merged, verdict, rule, where, rule.label, log=rule.log, disabled=True))
                else:
                    self.disabled_flow += 1
                continue
            action = rule.action
            following: List[_Cond] = []
            for context in contexts:
                pieces = [context]
                for cond in rule.conds:
                    merged = _meet(context, cond)
                    if merged is None:
                        continue
                    self.visited += 1
                    if self.visited > _MAX_EFFECTIVE_RULES:
                        raise ParseError("the chains expand to more than 50000 rules; refusing to continue")
                    if action in ("continue", "offload"):
                        if rule.log:
                            out.append(_Entry(merged, "log", rule, where, rule.label))
                        if not frame.inline:
                            self.passive += 1
                        if action == "offload":
                            self.offload = True
                    elif action == "return" and frame.base:
                        out.append(_Entry(merged, "accept", rule, where + "-return", rule.label, log=rule.log))
                    elif action == "return" and rule.accept_was and _replies_only(cond):
                        # The accept of established and related packets of a rule-set of VyOS 1.3 or EdgeOS: what every
                        # stateful platform does by itself (a rule-set of the other interface could still drop them).
                        out.append(_Entry(merged, "accept", rule, where, rule.label, log=rule.log))
                    elif action == "return":
                        cut = self._cut(pieces, cond) if not frame.inline and not rule.accept_was else None
                        if cut is not None:
                            pieces = cut  # the rules below see what did not return; the caller goes on with it
                        else:
                            self._resume(frame, merged, where, rule.label, out, rule)
                    elif action == "jump":
                        self._jump(rule, rule.target, merged, frame, index + 1, where, out)
                    elif action in ("accept", "drop", "reject"):
                        out.append(_Entry(merged, action, rule, where, rule.label, log=rule.log))
                    else:
                        why = f"action {action}" if action else "a rule without an action"
                        if action == "queue" and rule.label not in self.queue:
                            self.queue.append(rule.label)
                        out.append(_Entry(_with_problem(merged, why), "unknown", rule, where, rule.label, why=why))
                following += pieces
            contexts = following
            if not contexts:
                return
        self._end(frame, contexts, out)

    def _cut(self, pieces: List[_Cond], cond: _Cond) -> Optional[List[_Cond]]:
        """The pieces without the packets of a return, where each stays one condition; None otherwise."""
        out: List[_Cond] = []
        for piece in pieces:
            taken = _meet(piece, cond)
            if taken is None:
                out.append(piece)
                continue
            left = self._split(piece, taken)
            if left is None or len(left) > 1:
                return None
            out += left
        return out

    def _resume(self, frame: "_Frame", contexts: Any, where: str, label: str, out: List[_Entry],
                rule: Optional[_VRule] = None) -> None:  # fmt: skip
        """Put the rest of the calling chain where packets return from a chain: they are decided there."""
        assert frame.parent is not None
        parent = dataclasses.replace(frame.parent, prefix=f"{where}>", returned=where, returned_label=label, returned_rule=rule)
        self.walk(parent, contexts if isinstance(contexts, list) else [contexts], out)

    def _jump(self, rule: _VRule, target_name: str, merged: _Cond, frame: "_Frame", resume: int, where: str,
              out: List[_Entry], parent: Optional["_Frame"] = None) -> None:  # fmt: skip
        target = self.compiled.get((rule.family, target_name))
        name = target_name.replace("\x00zone:", "zone ")
        why = ""
        if target is None:
            self.missing.add(target_name)
            why = f"jump to chain {name}, which is not in the configuration"
        elif target_name in frame.stack:
            why = f"jump loop through chain {name}"
        elif len(frame.stack) > _MAX_NESTING:
            why = "jumps nested too deep"
        if why or target is None:
            out.append(_Entry(_with_problem(merged, why), "unknown", rule, where, rule.label, why="jump"))
            return
        if parent is None:
            parent = _Frame(frame.chain, resume, frame.stack, frame.prefix, frame.base, frame.parent, inline=True)
        child = _Frame(target, 0, frame.stack + (target_name,), where + ".", False, parent)
        self.walk(child, [merged], out)

    def _end(self, frame: "_Frame", contexts: List[_Cond], out: List[_Entry]) -> None:
        """What falls off the end of a chain. A base chain's own end is left to ``combine``, except in a copy put where a
        packet returns: that copy decides everything."""
        chain = frame.chain
        if not contexts:
            return
        action = chain.default
        label = f"{chain.label} default-action {action}"
        where = f"{frame.prefix}default"
        if frame.base:
            if frame.inline:
                then = f"{frame.returned_label}, then {label}" if frame.returned_label else label
                for context in contexts:
                    rule = frame.returned_rule
                    out.append(_Entry(context, action, rule, frame.returned or where, then,
                                      log=chain.default_log or (rule is not None and rule.log)))  # fmt: skip
            return
        assert frame.parent is not None
        if action in ("return", "continue"):
            if frame.inline:
                self._resume(frame, contexts, where, label, out)
            return
        if action == "jump":
            fake = _VRule(chain.family, chain.name, 0, "jump", label, "default", target=chain.default_target)
            for context in contexts:
                self._jump(fake, chain.default_target, context, frame, len(chain.rules), where, out, parent=frame.parent)
            if frame.inline:
                self._resume(frame, contexts, where, label, out)
            return
        for context in contexts:
            if action in ("accept", "drop", "reject"):
                out.append(_Entry(context, action, None, where, label, log=chain.default_log))
            else:
                why = f"default-action {action}"
                out.append(_Entry(_with_problem(context, why), "unknown", None, where, label, why=why))

    def base_entries(self, family: int) -> Tuple[List[Tuple[List[_Entry], str, str]], bool]:
        """(each base chain at the forward hook: its entries, its default, its label), whether any filters."""
        prefix = "" if family == 4 else "ipv6-"
        chains: List[Tuple[List[_Entry], str, str]] = []
        forward = self.compiled.get((family, "\x00forward"))
        start = _Cond(families=frozenset({family}))
        if forward is not None:
            entries: List[_Entry] = []
            self.walk(_Frame(forward, 0, ("\x00forward",), prefix, True), [start], entries)
            chains.append((entries, forward.default, f"{prefix}forward"))
        zones = self.zone_chains(family)
        if zones is not None:
            entries = []
            self.walk(_Frame(zones, 0, ("\x00zones",), prefix, True), [start], entries)
            chains.append((entries, "accept", f"{prefix}zones"))
        return chains, bool(chains)

    def combine(self, walked: List[Tuple[List[_Entry], str, str]], context: _Cond) -> Tuple[List[_Entry], str]:
        """The entries of several base chains in a row, and the action for what none of them decides. An accept sends
        the packet on to the next base chain; a drop is final."""
        default = ["accept"]

        def sequence(index: int, c: _Cond, via: Tuple[str, ...], top: bool) -> List[_Entry]:
            entries, policy, label = walked[index]
            out: List[_Entry] = []
            last = index + 1 == len(walked)
            remaining = c
            for entry in entries:
                merged = _meet(c, entry.cond)
                if merged is None:
                    continue
                self.visited += 1
                if self.visited > _MAX_EFFECTIVE_RULES:
                    raise ParseError("the base chains combine to more than 50000 rules; refusing to continue")
                if entry.disabled or entry.action == "log":
                    out.append(dataclasses.replace(entry, cond=merged, via=via))
                    continue
                if entry.action == "accept" and not last:
                    out += sequence(index + 1, merged, via + (entry.where,), False)
                else:
                    out.append(dataclasses.replace(entry, cond=merged, via=via))
                decided = _meet(remaining, merged)
                if decided is None:
                    continue
                rest = self._split(remaining, decided)
                if rest == []:
                    return out  # the entries so far decided all of it: nothing reaches what follows
                if rest is not None and len(rest) == 1:
                    remaining = rest[0]
            if policy == "drop":
                if top:
                    default[0] = "drop"
                else:
                    out.append(_Entry(c, "drop", None, f"{label}.default", "forward filter default-action drop", via=via))
            elif not last:
                out += sequence(index + 1, c, via, top)
            elif not top:
                out.append(_Entry(c, "accept", None, f"{label}.default", "traffic to an interface in no zone, which the zones "
                                  "accept", via=via))  # fmt: skip
            return out

        found = sequence(0, context, (), True)
        return found, default[0]

    # -- NAT ----------------------------------------------------------------------------------

    def nat_cond(self, entry: _NatEntry) -> _Cond:
        s = entry.statements
        c: Optional[_Cond] = _Cond(families=frozenset({4}))
        assert c is not None
        side = "inbound-interface" if entry.kind == "destination" else "outbound-interface"
        for key, values in s.items():
            head = key[0]
            if head == "\x00problem":
                c = _with_problem(c, values[0])
            elif head in ("description", "disable", "exclude", "log", "translation", "protocol", side):
                continue
            elif head in ("source", "destination") and len(key) >= 2 and key[1] in ("address", "port", "group"):
                continue
            elif head == "load-balance":
                c = _with_problem(c, "load-balance (several translated addresses by weight)")
            elif head in ("inbound-interface", "outbound-interface"):
                c = _with_problem(c, f"{head} in a {entry.kind} NAT rule")
            else:
                c = _with_problem(c, f"'{' '.join(key)}', which FWShift does not read")
        assert c is not None
        for key, values in s.items():
            if key[:1] != (side,):
                continue
            text = values[-1]
            if text == "any":
                continue
            interfaces: FrozenSet[str] = frozenset()
            if len(key) == 1 or key[1] in ("name", "interface-name"):
                interfaces, problem = self._interfaces(text)
            elif key[1] in ("group", "interface-group"):
                found_group, problem = self._interface_group(text)
                interfaces = found_group or frozenset()
            else:
                problem = f"'{' '.join(key)}', which FWShift does not read"
            if problem:
                c = _with_problem(c, problem)
                continue
            if text.startswith("!"):
                c = _with_problem(c, f"\x00negif:{'in' if side.startswith('in') else 'out'}")
            merged = _meet(c, _Cond(iif=interfaces) if side.startswith("in") else _Cond(oif=interfaces))
            c = merged if merged is not None else _with_problem(c, "an interface match that leaves no interface")
        protocol = (s.get(("protocol",)) or ["all"])[-1]
        negated, proto = _neg(protocol)
        head = ""
        if proto not in ("all", ""):
            if proto == "tcp_udp":
                c = constrain(c, "meta l4proto", "!=" if negated else "==", ["6", "17"]) or c
                head = "" if negated else "th"
            else:
                number = _PROTOCOLS.get(proto.lower(), int(proto) if is_number(proto) and int(proto) <= 255 else None)
                if number is None:
                    c = _with_problem(c, f"protocol {_short(protocol, 20)}")
                else:
                    c = constrain(c, "meta l4proto", "!=" if negated else "==", [str(number)]) or _with_problem(c, "no protocol")
                    head = "" if negated else {6: "tcp", 17: "udp"}.get(number, "")
        found: Optional[_Cond]
        for where, word in (("source", "saddr"), ("destination", "daddr")):
            address = s.get((where, "address"))
            if address:
                if address[-1].startswith("!"):
                    c = _with_problem(c, "negated address in a NAT rule")
                found = self._address_cond(c, 4, word, address[-1].lstrip("!"))
                c = found if found is not None else _with_problem(c, "an address that leaves nothing")
            for kind in ("address-group", "network-group"):
                group = s.get((where, "group", kind))
                if group:
                    if group[-1].startswith("!"):
                        c = _with_problem(c, "negated group in a NAT rule")
                    found = self._group_cond(c, 4, where, kind, group[-1].lstrip("!"))
                    c = found if found is not None else _with_problem(c, f"{kind} without addresses")
            for key in s:
                if key[:2] == (where, "group") and len(key) == 3 and key[2] not in ("address-group", "network-group", "port-group"):
                    c = _with_problem(c, f"{' '.join(key)} in a NAT rule")
            ports = s.get((where, "port"))
            group = s.get((where, "group", "port-group"))
            field_word = "sport" if where == "source" else "dport"
            if ports or group:
                if not head:
                    c = _with_problem(c, f"{where} port without protocol tcp, udp or tcp_udp")
                    continue
                if ports:
                    negated_ports, text = _neg(ports[-1])
                    found = self._port_values(c, f"{head} {field_word}", text.split(","), negated_ports)
                else:
                    negated_group, name = _neg(group[-1]) if group else (False, "")
                    found_ports = self._group_values("port-group", name, "port")
                    if found_ports is None:
                        self.missing.add(name)
                        c = _with_problem(c, f"port-group '{_short(name)}' is not in the configuration")
                        continue
                    found = self._port_values(c, f"{head} {field_word}", found_ports, negated_group)
                c = found if found is not None else _with_problem(c, "a port match that leaves nothing")
        return c

    def nat_rule(self, entry: _NatEntry) -> NatRule:
        s = entry.statements
        c = self.nat_cond(entry)
        description = " ".join((s.get(("description",)) or [""])[-1].split())
        where = f"{'destination' if entry.kind == 'destination' else 'source'}-{entry.number}"
        name = self._unique(description or where, self.nat_names)
        nat = NatRule(name=name, origin=name, combines=True, enabled=("disable",) not in s)
        nat.description = "" if name == where else f"VyOS nat {entry.kind} rule {entry.number}"
        tags = [text[1:] for text in c.unsupported if text.startswith("\x00")]
        nat.unsupported = [text for text in c.unsupported if not text.startswith("\x00")]
        for tag in tags:
            if tag.startswith("negif:") and not self.other_zone:
                self._interfaces_resolved("nat", nat.origin, tag.split(":", 1)[1])
        nat.sources = self.helper.side(c.src, None)[0] if c.src is not None else [ANY]
        nat.destinations = self.helper.side(c.dst, None)[0] if c.dst is not None else [ANY]
        if c.src is not None and c.src_show is not None and not c.src_show[1]:
            nat.sources = [self.helper.group_name(m) for m in c.src_show[0]]
        if c.dst is not None and c.dst_show is not None and not c.dst_show[1]:
            nat.destinations = [self.helper.group_name(m) for m in c.dst_show[0]]
        services, negated = self.helper.services(c, nat.unsupported)
        if len(services) != 1 or negated:
            nat.unsupported.append("NAT limited to protocols the model cannot say")
        nat.service = services[0] if services else ANY
        if nat.service != ANY and any(e.protocol.value not in ("tcp", "udp", "sctp") for e in self.p.services[nat.service].entries):
            nat.unsupported.append("NAT limited to a protocol other than TCP, UDP or SCTP")
        address = (s.get(("translation", "address")) or [""])[-1]
        port = (s.get(("translation", "port")) or [""])[-1]
        excluded = ("exclude",) in s
        for key in s:
            if key[:1] == ("translation",) and key[1:2] not in (("address",), ("port",), ("options",)):
                nat.unsupported.append(f"'{' '.join(key)}' in a NAT rule" + (" (to the router itself)" if key[1:2] == ("redirect",) else ""))
        zones = self._zone_names(c.iif if entry.kind == "destination" else c.oif, "nat", nat.origin)
        if entry.kind == "destination":
            nat.src_zones = nat.dst_zones = zones
            if not excluded:
                self._dnat(nat, c, address, port)
            self.dnat_entries.append((c, nat, not excluded and nat.destination_translation is not None))
        else:
            nat.dst_zones = zones
            if not excluded:
                self._snat(nat, c, address, port)
        if not excluded and not address and not nat.unsupported and nat.destination_translation is None and nat.source_translation is None:
            nat.unsupported.append("a NAT rule that translates nothing it says (no translation address)")
        return nat

    def _dnat(self, nat: NatRule, c: _Cond, address: str, port: str) -> None:
        if port and not _ports_ok(port):
            nat.unsupported.append(f"translation port {_short(port, 20)}, which FWShift cannot read")
            return
        if not address:
            nat.unsupported.append("a translation of the port only")
            return
        interval = parse_literal(address)
        if interval is None or interval[0] != 4:
            nat.unsupported.append(f"translation address {_short(address, 40)}, which FWShift cannot read")
            return
        if "/" in address and size(interval) > 1:
            same = c.dst is not None and len(c.dst) == 1 and size(c.dst[0]) == size(interval)
            if not same:
                nat.unsupported.append("a prefix translation whose addresses do not map one for one")
                return
            nat.destination_translation = DestNat(interval_text(interval), port)
            return
        nat.destination_translation = DestNat(range_text(interval), port, spread=size(interval) > 1)

    def _snat(self, nat: NatRule, c: _Cond, address: str, port: str) -> None:
        if address == "masquerade":
            interfaces = sorted(i for i in (c.oif or ()) if i != OTHER)
            nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=interfaces[0] if len(interfaces) == 1 else "")
        elif address:
            interval = parse_literal(address)
            if interval is None or interval[0] != 4:
                nat.unsupported.append(f"translation address {_short(address, 40)}, which FWShift cannot read")
                return
            if "/" in address and size(interval) > 1:
                same = c.src is not None and len(c.src) == 1 and size(c.src[0]) == size(interval)
                if same:
                    nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(interval)])
                else:
                    nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [range_text(interval)])
            else:
                nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [range_text(interval)])
        if port and nat.source_translation is not None:
            self.report.add("nat", nat.origin, Severity.APPROX, "VYOS_NAT_PORTS",
                            f"translation port {port}: the source ports the translation picks from are not converted")  # fmt: skip

    # -- zones of the model ---------------------------------------------------------------------

    def model_zones(self, entries: List[_Entry], nat_conds: List[_Cond]) -> None:
        """Interfaces as zones, a zone of the zone-based firewall as one where no rule names a part of it."""
        sets: List[FrozenSet[str]] = []
        other = False
        for c in [e.cond for e in entries] + nat_conds:
            for found in (c.iif, c.oif):
                if found is not None:
                    sets.append(found - {OTHER})
                    other = other or OTHER in found
        zones = [z for z in self.zones.values() if not z.local]
        if other and not self.has_interfaces:
            # Without the interfaces part, the interfaces the configuration does not name are not known; a negated
            # interface, or the default of a zone, reaches them. They become a zone of the model without interfaces.
            name, counter = "other-interfaces", 2
            while name in self.zones or name in self.known:
                name, counter = f"other-interfaces-{counter}", counter + 1
            self.other_zone = name
            self.zone_of[OTHER] = name
            self.zone_members[name] = []
        members = {z.name: sorted(self._zone_interfaces(z) - {OTHER}) for z in zones}
        taken: Set[str] = set()
        for zone in zones:
            interfaces = members[zone.name]
            whole = bool(interfaces) and all(not (set(interfaces) & s) or set(interfaces) <= s for s in sets)
            if whole:
                self.zone_members[zone.name] = interfaces
                taken.add(zone.name)
                for interface in interfaces:
                    self.zone_of[interface] = zone.name
            elif interfaces:
                self.split_zones.append(zone.name)
        for interface in self._interfaces_in(sets):
            if interface in self.zone_of:
                continue
            name = interface
            if name in taken:
                name = f"{interface}-interface"
            taken.add(name)
            self.zone_of[interface] = name
            self.zone_members[name] = [interface]

    def _interfaces_in(self, sets: List[FrozenSet[str]]) -> List[str]:
        seen: List[str] = []
        for interface in self.known + sorted({i for s in sets for i in s}):
            if interface in seen or interface == OTHER:
                continue
            if any(interface in s for s in sets) or any(interface in self._zone_interfaces(z) for z in self.zones.values()):
                seen.append(interface)
        return seen

    def _zone_names(self, interfaces: Optional[FrozenSet[str]], kind: str, origin: str) -> List[str]:
        if interfaces is None:
            return [ANY]
        names = sorted({self.zone_of[i] for i in interfaces if i in self.zone_of})  # (OTHER only with other_zone)
        return names or [ANY]  # (a match that leaves no interface the configuration names is not converted)

    # -- the policy ---------------------------------------------------------------------------

    def build(self) -> Policy:
        everything: List[_Entry] = []
        defaults: Dict[int, str] = {}
        filtered: Dict[int, bool] = {}
        for family in (4, 6):
            walked, filtered[family] = self.base_entries(family)
            if walked:
                found, defaults[family] = self.combine(walked, _Cond(families=frozenset({family})))
                everything += found
            else:
                defaults[family] = "accept"
        nat_rules: List[Tuple[_NatEntry, _Cond]] = [(entry, self.nat_cond(entry)) for entry in self.nat]
        self.model_zones(everything, [c for _, c in nat_rules])
        if defaults[4] == defaults[6]:
            default = defaults[4]
        else:
            default = "drop"
            for family in (4, 6):
                if defaults[family] == "accept":
                    everything.append(_Entry(_Cond(families=frozenset({family})), "accept", None, f"ipv{family} default",
                                             f"IPv{family}: what no rule decides is accepted"))  # fmt: skip
        action = Action.ALLOW if default == "accept" else Action.DENY
        self.p.default_interzone = self.p.default_intrazone = action
        for entry in self.nat:
            self.p.nat_rules.append(self.nat_rule(entry))
        self.forward(everything)
        for zone in transform.dedupe([z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
                                     + [z.name for z in self.zones.values() if z.name in self.zone_members]):  # fmt: skip
            self.p.zones[zone] = Zone(zone, list(self.zone_members.get(zone, [zone])))
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        for position, rules in sorted(self.pending, key=lambda item: -item[0]):
            self.p.rules[position:position] = rules
        self.notes(filtered)
        return self.p

    def forward(self, entries: List[_Entry]) -> None:
        accepts_established = bool(self.state_policy.get("established", {}).get("action") == "accept")
        decided: Dict[int, FrozenSet[str]] = {4: frozenset(), 6: frozenset()}
        early_drops: List[str] = []
        logged: Optional[Tuple[object, ...]] = None
        accepts = denies = 0
        for entry in entries:
            c = entry.cond
            if entry.disabled:
                if c.states is not None and "NEW" not in c.states:
                    continue
                rule = self.rule(entry)
                rule.enabled = False
                self.p.rules.append(rule)
                continue
            key = _nft._Builder.match_key(c)
            if entry.action == "log":
                logged = key
                continue
            log = entry.log or logged == key
            logged = None
            states = c.states
            if states is not None and all(states <= decided[f] for f in c.families):
                continue
            # (a negated interface only marks the interfaces, which a rule of replies or invalid packets does not need)
            rest = dataclasses.replace(c, states=None, comment="", families=frozenset({4, 6}), iif=None, oif=None,
                                       unsupported=tuple(t for t in c.unsupported if not t.startswith("\x00negif:")))  # fmt: skip
            if states is not None and "NEW" not in states and not rest.unsupported and rest.trivial():
                plain = c.iif is None and c.oif is None
                if entry.action == "accept" and states <= {"ESTABLISHED", "RELATED", "UNTRACKED"}:
                    accepts_established = accepts_established or "ESTABLISHED" in states
                    if plain:
                        decided.update({f: decided[f] | states for f in c.families})
                    continue
                if entry.action in ("drop", "reject") and states <= {"INVALID", "UNTRACKED"}:
                    if plain:
                        decided.update({f: decided[f] | states for f in c.families})
                    continue
            rule = self.rule(entry)
            rule.log_start = log
            if states is not None and "NEW" not in states:
                rule.unsupported.append("match on connection state " + ",".join(sorted(states)).lower() + " without new")
            if "\x00ctdnat" in c.unsupported:
                if self._dnat_status(rule, entry):
                    continue
            if rule.action == Action.ALLOW:
                accepts += 1
            else:
                denies += 1
            if rule.action != Action.ALLOW and not accepts_established and (states is None or states & {"ESTABLISHED", "RELATED"}):
                early_drops.append(rule.origin)
            self.p.rules.append(rule)
        if not accepts_established and accepts and denies:
            self.report.note(
                Severity.REVIEW, "STATELESS_RULESET",
                "no forward rule accepts established and related packets, so the rules that block also block replies. "
                "The converted rules are connection-based: an allow rule also admits the replies, and a deny rule no "
                "longer stops the replies of connections opened from the other side",
            )  # fmt: skip
        elif accepts_established:
            for origin in early_drops:
                self.report.add(
                    "rule", origin, Severity.REVIEW, "DROP_BEFORE_ESTABLISHED",
                    "this rule comes before the rule that accepts established connections, so on the source it also "
                    "drops the replies of connections opened from the other side. The converted rule only blocks new "
                    "connections in its own direction; add the mirror rule if that mattered",
                )  # fmt: skip

    def _unique(self, name: str, taken: Set[str]) -> str:
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    def rule(self, entry: _Entry) -> Rule:
        c = entry.cond
        vrule = entry.rule
        description = vrule.description if vrule is not None and vrule.number else ""
        rule = Rule(name=self._unique(description or entry.where, self.names))
        rule.origin = rule.name
        path = entry.label + "".join(f", after {v}" for v in entry.via) if entry.via else entry.label
        rule.description = f"VyOS {path}" + (f" ({entry.where})" if rule.name != entry.where else "")
        rule.source_ids["vyos.rule"] = entry.label
        rule.source_ids["vyos.path"] = entry.where
        tags = [text for text in c.unsupported if text.startswith("\x00")]
        c = dataclasses.replace(c, unsupported=tuple(text for text in c.unsupported if not text.startswith("\x00")))
        rule.src_zones = self._zone_names(c.iif, "rule", rule.origin)
        rule.dst_zones = self._zone_names(c.oif, "rule", rule.origin)
        rule.unsupported = list(c.unsupported)
        rule.log_end = False
        for side, found in (("in", c.iif), ("out", c.oif)):
            if found is not None and OTHER in found and not self.other_zone:
                self._interfaces_resolved("rule", rule.origin, side)
            if found is not None and not (found - {OTHER}) and not self.other_zone:
                rule.unsupported.append(f"{side}put interface match that leaves none of the interfaces the configuration names")
        self.helper.addresses(rule, c)
        services, negated = self.helper.services(c, rule.unsupported)
        rule.services, rule.negate_service = services, negated
        self._tags(rule, c, tags)
        actions = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.DENY}
        if entry.action in actions:
            rule.action = actions[entry.action]
        else:
            rule.action = Action.DROP  # what the source did is not known: nothing is allowed on a guess
            if not any("jump" in text or "action" in text for text in rule.unsupported):
                rule.unsupported.append(f"{entry.why or 'an action'}, which the model has no place for")
        return rule

    def _interfaces_resolved(self, kind: str, origin: str, side: str) -> None:
        """A negated or wildcard interface, with the interfaces part. (Without it, the interfaces the configuration does
        not name are the zone ``other_zone``: see VYOS_OTHER_INTERFACES.)"""
        self.report.add(kind, origin, Severity.INFO, "VYOS_INTERFACES_RESOLVED",
                        f"a negated or wildcard {side}put interface was resolved against the interfaces of the "
                        "configuration; an interface the router adds while it runs (a PPP session, a tunnel) is not "
                        "covered")  # fmt: skip

    def _tags(self, rule: Rule, c: _Cond, tags: List[str]) -> None:
        family_any = ANY_V4 if 4 in c.families else ANY_V6
        for tag in tags:
            kind, _, value = tag[1:].partition(":")
            if kind == "schedule":
                rule.schedule = value
            elif kind == "addr":
                side, _, target = value.partition(":")
                negated, target = _neg(target)
                if (c.src if side == "src" else c.dst) is not None:
                    rule.unsupported.append(f"host names together with another {'source' if side == 'src' else 'destination'} "
                                            "address match")  # fmt: skip
                    continue
                if side == "src":
                    rule.sources, rule.negate_source = [target], negated
                    if rule.destinations == [ANY]:
                        rule.destinations = [family_any]
                else:
                    rule.destinations, rule.negate_destination = [target], negated
                    if rule.sources == [ANY]:
                        rule.sources = [family_any]
                if rule.negate_source and rule.negate_destination:
                    rule.unsupported.append("source and destination both negated")

    def _dnat_status(self, rule: Rule, entry: _Entry) -> bool:
        """``connection-status nat destination``: the rule is for connections a destination NAT rule translated. Exact
        when it matches on interfaces and states only and every destination NAT rule can be read: then it is a rule for
        what each of them translates, as the model names it (before the translation). True when it was replaced."""
        c = entry.cond
        if any(getattr(c, name) is not None for name in ("src", "dst", "proto", "dport", "sport", "icmp", "codes")):
            rule.unsupported.append("connection-status nat destination together with an address or service match")
            return False
        if any(not text.startswith("\x00") for text in c.unsupported):
            return False
        enabled = [(d, nat, translates) for d, nat, translates in self.dnat_entries if nat.enabled]
        bad = [nat for _, nat, _ in enabled if nat.unsupported]
        if bad:
            rule.unsupported.append(f"connection-status nat destination, and destination NAT rule '{bad[0].name}' cannot be read")
            return False
        if any(not translates for _, _, translates in enabled):
            rule.unsupported.append("connection-status nat destination, and a destination NAT rule excludes traffic from "
                                    "translation")  # fmt: skip
            return False
        base = dataclasses.replace(c, states=None, unsupported=tuple(t for t in c.unsupported if t != "\x00ctdnat"))
        made: List[Rule] = []
        for d, nat, _ in enabled:
            pre = _meet(base, dataclasses.replace(d, unsupported=()))
            if pre is None:
                continue
            new = self.rule(dataclasses.replace(entry, cond=pre))
            self.names.discard(new.name)
            new.name = new.origin = self._unique(f"{rule.name} ({nat.name})", self.names)
            if nat.destinations != [ANY] and new.destinations == nat.destinations and not new.negate_destination:
                # The rule names the destination of the NAT rule itself, as a FortiOS policy names a virtual IP: a target
                # that looks rules up after the translation then writes the translated address in its place.
                new.destinations = nat.destinations = [self._translated(nat)]
                self.p.named_translations = True
            elif nat.destinations == [ANY]:
                self.report.add("rule", new.origin, Severity.REVIEW, "VYOS_DNAT_STATUS_ANY",
                                f"destination NAT rule '{nat.name}' translates whatever the destination: this rule names the "
                                "connections as they arrive, which a target that looks rules up after destination NAT (VyOS, "
                                "iptables, nftables, RouterOS, FortiOS, Junos) no longer sees after the translation. There, "
                                "write it for the translated address and port")  # fmt: skip
            new.description = f"{rule.description}: what destination NAT rule '{nat.name}' translates"
            new.log_start = rule.log_start
            self.report.add("rule", new.origin, Severity.INFO, "VYOS_DNAT_STATUS",
                            "connection-status nat destination: the rule is for the connections the destination NAT rules "
                            f"translate, and was written as a rule for each of them, as they arrive; this one for '{nat.name}'")  # fmt: skip
            made.append(new)
        if not made:
            rule.unsupported.append("connection-status nat destination, and no destination NAT rule translates traffic it can "
                                    "match: it matches nothing")  # fmt: skip
            return False
        self.names.discard(rule.name)
        self.pending.append((len(self.p.rules), made))
        return True

    def _translated(self, nat: NatRule) -> str:
        """An object for the destination of a destination NAT rule, which the rules of connection-status name."""
        if len(nat.destinations) == 1 and (nat.destinations[0] in self.p.address_groups or nat.destinations[0] in self.p.addresses):
            return nat.destinations[0]
        taken = set(self.p.addresses) | set(self.p.address_groups)
        name = self._unique(f"{nat.name} destination", taken)
        description = f"the destination of VyOS destination NAT rule '{nat.name}'"
        if len(nat.destinations) == 1:
            literal = parse_literal(nat.destinations[0])
            assert literal is not None
            kind = AddressKind.NETWORK if "-" not in nat.destinations[0] else AddressKind.RANGE
            self.p.addresses[name] = Address(name, kind, nat.destinations[0], description=description)
        else:
            self.p.address_groups[name] = AddressGroup(name, list(nat.destinations), description=description)
        return name

    # -- notes ----------------------------------------------------------------------------------

    def notes(self, filtered: Dict[int, bool]) -> None:
        report = self.report
        if self.legacy:
            dialect = "EdgeOS (Vyatta)" if self.edgeos else "VyOS 1.3 (Vyatta)"
            report.note(Severity.INFO, "VYOS_FORMAT",
                        f"read as the configuration of {dialect}" + (f", release {self.release}" if self.release else "")
                        + ": rule-sets on interfaces, accept in a rule-set and the zone policy were read as VyOS 1.4 has "
                        "them after its own migration (a jump from the forward filter for each rule-set on an interface, "
                        "the in ones first; accept as return, so that the rule-set of the other interface still decides)")  # fmt: skip
        else:
            report.note(Severity.INFO, "VYOS_FORMAT", "read as the configuration of VyOS 1.4 or later"
                        + (f", release {self.release}" if self.release else ""))  # fmt: skip
        for family in (4, 6):
            if not filtered[family]:
                report.note(Severity.INFO, "VYOS_NOT_FILTERED",
                            f"the configuration has no IPv{family} forward filter and no zones: the router forwards IPv{family} "
                            "as no rule says otherwise, and the converted policy allows it")  # fmt: skip
        if self.other_zone and self.other_zone in self.p.zones:
            report.note(Severity.INFO, "VYOS_OTHER_INTERFACES",
                        "the configuration has no interfaces part: the interfaces of the router it does not name, which a "
                        "negated interface or the default of a zone reaches, are zone "
                        f"{self.other_zone} of the converted policy, a zone without interfaces (on a target, give it "
                        "interfaces with --zone-map or --interface-map)")  # fmt: skip
        for chain in self.host_chains:
            report.note(Severity.REVIEW, "HOST_CHAIN_NOT_CONVERTED",
                        f"{chain} filters traffic of the router itself, not forwarded traffic, and is not converted")  # fmt: skip
        if self.not_read:
            report.note(Severity.REVIEW, "PARTS_NOT_READ",
                        "parts of the configuration this parser does not read: " + ", ".join(self.not_read[:12]))  # fmt: skip
        if self.missing:
            names = sorted(self.missing)
            report.note(Severity.REVIEW, "OBJECTS_MISSING",
                        "names the rules use and the configuration does not define: "
                        + ", ".join(f"'{_short(n)}'" for n in names[:10]) + (f" and {len(names) - 10} more" if len(names) > 10 else "")
                        + ". The rules that use them are not used")  # fmt: skip
        if self.empty_groups:
            report.note(Severity.REVIEW, "VYOS_EMPTY_GROUP",
                        "groups without a member: a rule that names one matches nothing (VyOS warns about them and takes "
                        "them): " + ", ".join(sorted(self.empty_groups)))  # fmt: skip
        if self.fqdn_groups:
            report.note(Severity.INFO, "VYOS_FQDN",
                        "host names (domain-group, fqdn), which the router resolves while it runs: converted as host "
                        "name objects (" + ", ".join(sorted(self.fqdn_groups)) + ")")  # fmt: skip
        if self.wildcards:
            report.note(Severity.REVIEW, "VYOS_INTERFACE_WILDCARD",
                        "interface wildcards that match no interface the configuration names, kept as names of their own: "
                        + ", ".join(self.wildcards))  # fmt: skip
        if self.split_zones:
            report.note(Severity.INFO, "VYOS_ZONE_SPLIT",
                        "rules name some interfaces of these zones and not the others, so their interfaces are zones of "
                        "their own in the model: " + ", ".join(self.split_zones))  # fmt: skip
        if self.passive:
            report.note(Severity.INFO, "VYOS_PASSIVE",
                        f"{self.passive} rule{'s' if self.passive != 1 else ''} with action continue (or offload) decide "
                        "nothing and were left out; a rule with log before a rule with the same match sets its logging")  # fmt: skip
        if self.disabled_flow:
            report.note(Severity.INFO, "VYOS_DISABLED_JUMP",
                        f"{self.disabled_flow} disabled rule{'s' if self.disabled_flow != 1 else ''} that would jump, return "
                        "or continue were left out")  # fmt: skip
        if self.offload:
            report.note(Severity.INFO, "VYOS_OFFLOAD",
                        "flow offloading (firewall flowtable): packets of offloaded connections bypass the rules; the "
                        "conversion is of the rules, which decide new connections")  # fmt: skip
        if self.queue:
            report.note(Severity.REVIEW, "VYOS_QUEUE",
                        "rules hand packets to a program (action queue), which decides them: " + ", ".join(self.queue[:8]))  # fmt: skip
        zones = [z for z in self.zones.values() if not z.local]
        if zones:
            report.note(Severity.INFO, "VYOS_ZONES",
                        "the zone-based firewall was read after the forward filter, as a second chain at the forward hook: "
                        "traffic into a zone from an interface in no zone, or from a zone without a rule-set for its IP "
                        "version, is dropped; traffic to an interface in no zone is decided by the forward filter alone")  # fmt: skip
        if any(z.local for z in self.zones.values()):
            report.note(Severity.INFO, "VYOS_LOCAL_ZONE",
                        "the local zone (traffic to and from the router itself) is not converted")  # fmt: skip
        if self.p.default_interzone == Action.ALLOW:
            report.note(Severity.INFO, "FORWARD_POLICY_ACCEPT",
                        "VyOS accepts what no rule of the forward filter decides unless its default-action is drop; the model "
                        "records that as its default action")  # fmt: skip


def _replies_only(c: _Cond) -> bool:
    """A match on established or related packets and nothing else."""
    rest = dataclasses.replace(c, states=None, families=frozenset({4, 6}))
    return c.states is not None and bool(c.states) and c.states <= {"ESTABLISHED", "RELATED"} and rest.trivial()


def _ports_ok(port: str) -> bool:
    first, _, last = port.partition("-")
    return first.isdigit() and (not last or last.isdigit()) and 0 < int(first) <= int(last or first) <= 65535


def parse(data: bytes, report: Report) -> Policy:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    paths, _ = _lines(text)
    if not paths:
        raise ParseError("the configuration is empty")
    reader = _Reader(paths, report, text)
    reader.read()
    if not reader.chains and not reader.zones and not reader.nat and not reader.bindings:
        raise ParseError("no firewall or nat part found: not the configuration of a VyOS router, or not all of it")
    reader.finish_edgeos_nat()
    reader.migrate()
    reader.collect_interfaces()
    reader.compile()
    return reader.build()
