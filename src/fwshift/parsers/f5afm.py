# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""F5 BIG-IP AFM parser: the tmsh configuration of a BIG-IP with the Advanced Firewall Manager -> neutral model.

Reads what ``tmsh list`` prints for the network firewall and for the objects its policies are attached to (the commands
of the manual, section 3), or ``bigip_base.conf`` and ``bigip.conf`` put together. Names are taken with their partition
(``/Common/x``), and also as tmsh prints them relative to ``/`` or to ``/Common``.

How AFM behaviour is mapped onto the neutral model:

* A packet meets up to three firewall contexts, in this order (F5, "AFM Network Firewall"): the policy enforced in the
  global context (``security firewall global-rules``), the policy of its route domain (``net route-domain``, which the
  VLAN the packet came in on decides), and the policy of the virtual server it is for (``ltm virtual``). Each policy is
  a first-match list; a rule list in it stands for its rules, in their place. ``accept`` ends the context and the packet
  goes on to the next one; ``accept-decisively`` lets it through with no later context; ``drop`` and ``reject`` end it.
  What no rule of a context decides goes on to the next one. After the virtual server, the default action of the
  virtual server and self IP contexts decides: accept in ADC mode, drop or reject in Firewall mode (``sys db
  tm.fw.defaultaction``). A packet for no virtual server is dropped or rejected whatever the rules say: the BIG-IP has
  no listener for it, and the global default applies to it (F5 bug 429885 describes that traffic as matching "no
  virtual server or Self IP").
* All of it becomes one first-match list: the global rules; the rules of each route domain, kept to the VLANs of that
  route domain; then for each virtual server, in the order in which the BIG-IP picks one (the longest destination
  mask, then the longest source mask, a port before any port), its rules kept to the traffic it takes, ended by the
  default action for that traffic. An ``accept`` in the global or a route domain context becomes, in its place, the
  later contexts kept to what it matches, so that what it matches skips the rest of its own context. Every allow is
  kept to the traffic of a virtual server, and what reaches none ends at the model's default, the global default.
  A virtual server that rejects (type reject) or is disabled takes its traffic and lets none of it through.
* Without virtual servers in the input, every packet is taken as having one (a forwarding virtual server for
  everything), and the default of the virtual server context is the model's default; a finding says so.
* The zones of the model are the VLANs (and VLAN groups and tunnels). A rule names VLANs as ``source vlans`` and AFM
  zones (``security zone``, a list of VLANs) as ``source zones``: both become source zones. Destination zones are read as
  the VLANs a packet leaves on, which is not confirmed.
* Traffic to the BIG-IP itself (self IP contexts, the management port) is not policy for traffic through it, and is
  reported, not converted. So are staged policies, which change no traffic.
* AFM looks a packet up as it arrives, before the virtual server translates it: rules name addresses before NAT, as
  the model does. NAT (virtual servers with pools, SNAT, ``security nat`` policies, CGNAT) is not read.
* ICMP rules in the virtual server context are ignored by the BIG-IP (F5, "Firewall rules and rule lists"), and here.

Assumptions not confirmed on a device are listed in the manual and DEVELOPMENT.md: the order of virtual servers, that a
disabled virtual server takes its traffic, that an address without a route domain matches in every route domain, the
reading of destination zones, and that the global default follows ``tm.rejectunmatched``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union

from .. import transform
from ..errors import ParseError
from ..model import ANY, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry, Zone
from ..netutil import Interval, intersect, interval_text, normalize, overlaps, parse_literal
from ..report import Report, Severity

_MAX_RULES = 50000
_MAX_NESTING = 32

# Stanzas whose body is Tcl or other text in braces, which are skipped by counting braces only.
_RAW_STANZAS = (("ltm", "rule"), ("gtm", "rule"), ("sys", "application", "template"), ("cli", "script"),
                ("sys", "icall", "script"), ("sys", "application", "apl-script"))  # fmt: skip
_DETECT = re.compile(r"^(security firewall (policy|rule-list|address-list|port-list|global-rules|management-ip-rules)|"
                     r"ltm virtual|net (vlan|self|route-domain)) [^\n{}]*\{[ \t]*\}?[ \t]*$", re.M)  # fmt: skip

# IP protocols by the names tmsh prints (/etc/protocols of the BIG-IP), with their numbers.
PROTOCOLS: Dict[str, int] = {
    "icmp": 1, "igmp": 2, "ggp": 3, "ipencap": 4, "ipip": 4, "st": 5, "tcp": 6, "egp": 8, "igp": 9, "pup": 12, "udp": 17,
    "hmp": 20, "xns-idp": 22, "rdp": 27, "iso-tp4": 29, "xtp": 36, "ddp": 37, "idpr-cmtp": 38, "ipv6": 41,
    "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45, "rsvp": 46, "gre": 47, "esp": 50, "ah": 51, "skip": 57,
    "ipv6-icmp": 58, "icmpv6": 58, "ipv6-nonxt": 59, "ipv6-opts": 60, "rspf": 73, "vmtp": 81, "eigrp": 88, "ospf": 89,
    "ax.25": 93, "etherip": 97, "encap": 98, "pim": 103, "ipcomp": 108, "vrrp": 112, "l2tp": 115, "isis": 124,
    "sctp": 132, "fc": 133, "udplite": 136, "mpls-in-ip": 137,
}  # fmt: skip
# Port names tmsh prints (/etc/services of the BIG-IP): the common ones.
PORTS: Dict[str, int] = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "time": 37, "whois": 43, "tacacs": 49, "domain": 53,
    "bootps": 67, "bootpc": 68, "tftp": 69, "gopher": 70, "finger": 79, "http": 80, "kerberos": 88, "pop3": 110,
    "sunrpc": 111, "auth": 113, "nntp": 119, "ntp": 123, "epmap": 135, "netbios-ns": 137, "netbios-dgm": 138,
    "netbios-ssn": 139, "imap": 143, "snmp": 161, "snmp-trap": 162, "bgp": 179, "irc": 194, "ldap": 389, "https": 443,
    "microsoft-ds": 445, "kpasswd": 464, "isakmp": 500, "syslog": 514, "printer": 515, "rtsp": 554, "submission": 587,
    "ipp": 631, "ldaps": 636, "rsync": 873, "ftps-data": 989, "ftps": 990, "telnets": 992, "imaps": 993, "pop3s": 995,
    "socks": 1080, "ms-sql-s": 1433, "ms-sql-m": 1434, "radius": 1812, "radius-acct": 1813, "nfs": 2049, "mysql": 3306,
    "ms-wbt-server": 3389, "sip": 5060, "sip-tls": 5061, "postgresql": 5432, "x11": 6000, "http-alt": 8080,
}  # fmt: skip
_ICMP_NAMES = {"echo-reply": 0, "destination-unreachable": 3, "unreachable": 3, "source-quench": 4, "redirect": 5,
               "echo": 8, "echo-request": 8, "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11,
               "parameter-problem": 12, "timestamp": 13, "timestamp-request": 13, "timestamp-reply": 14}  # fmt: skip
_ICMP6_NAMES = {"destination-unreachable": 1, "unreachable": 1, "packet-too-big": 2, "time-exceeded": 3,
                "parameter-problem": 4, "echo-request": 128, "echo": 128, "echo-reply": 129, "router-solicitation": 133,
                "router-advertisement": 134, "neighbor-solicitation": 135, "neighbor-advertisement": 136, "redirect": 137}  # fmt: skip
_L4 = (6, 17, 132)
_RULE_KEYS = {"action", "status", "schedule", "rule-list", "ip-protocol", "icmp", "source", "destination", "irule",
              "irule-sample-rate", "log", "description", "uuid", "service-policy", "protocol-inspection-profile",
              "ips-profile", "classification-policy", "virtual-server", "app-service", "place-before", "place-after"}  # fmt: skip
_SIDE_KEYS = {"addresses", "address-lists", "fqdns", "geo", "ipi-category", "port-lists", "ports", "vlans", "zones",
              "identity", "subscriber-groups"}  # fmt: skip


# -- reading the configuration text ------------------------------------------------------------------------------------


class _Brace:
    """A brace of the syntax, as opposed to a brace in a quoted string."""

    def __init__(self, char: str) -> None:
        self.char = char


_OPEN, _CLOSE, _NL = _Brace("{"), _Brace("}"), _Brace("\n")
Atom = Union[str, "Block"]
Statement = List[Atom]
Block = List[Statement]
_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"?|([{}])|(\n)|([^\s{}"]+)|[ \t\r\f\v]+', re.S)


def _tokens(text: str) -> List[Union[str, _Brace]]:
    out: List[Union[str, _Brace]] = []
    for match in _TOKEN.finditer(text):
        quoted, brace, newline, word = match.groups()
        if quoted is not None:
            out.append(re.sub(r"\\(.)", r"\1", quoted))
        elif brace:
            out.append(_OPEN if brace == "{" else _CLOSE)
        elif newline:
            out.append(_NL)
        elif word is not None:
            out.append(word)
    return out


def _block(tokens: Sequence[Union[str, _Brace]], start: int, depth: int = 0) -> Tuple[Block, int]:
    """The statements of a block that starts after its opening brace, and the position of its closing brace."""
    if depth > 64:
        raise ParseError("the configuration nests braces more than 64 deep")
    statements: Block = []
    current: Statement = []
    index = start
    while index < len(tokens):
        token = tokens[index]
        if token is _NL:
            if current:
                statements.append(current)
                current = []
        elif token is _OPEN:
            inner, index = _block(tokens, index + 1, depth + 1)
            current.append(inner)
        elif token is _CLOSE:
            if current:
                statements.append(current)
            return statements, index
        else:
            assert isinstance(token, str)
            current.append(token)
        index += 1
    if current:
        statements.append(current)
    return statements, index


@dataclass
class _Stanza:
    header: List[str]
    body: Block
    line: int


def _stanzas(text: str) -> List[_Stanza]:
    """The top-level stanzas: a line at the left margin with an opening brace, up to the brace that closes it."""
    lines = text.split("\n")
    out: List[_Stanza] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line or line[0] in " \t#}" or "{" not in line:
            index += 1
            continue
        head = line.split("{", 1)[0].split()
        raw = any(tuple(head[: len(prefix)]) == prefix for prefix in _RAW_STANZAS)
        depth, start, end = 0, index, index
        while end < len(lines):
            depth += _brace_balance(lines[end], raw)
            if depth <= 0:
                break
            end += 1
        if raw:
            index = end + 1
            continue
        chunk = "\n".join(lines[start:end + 1])
        tokens = _tokens(chunk)
        try:
            opening = next(i for i, t in enumerate(tokens) if t is _OPEN)
        except StopIteration:
            index = end + 1
            continue
        header = [t for t in tokens[:opening] if isinstance(t, str)]
        body, _ = _block(tokens, opening + 1)
        out.append(_Stanza(header, body, start + 1))
        index = end + 1
    return out


def _brace_balance(line: str, raw: bool) -> int:
    """Opening minus closing braces of a line: outside quoted strings, or (raw text, Tcl) all that are not escaped."""
    count, quoted, escaped = 0, False, False
    for char in line:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == '"' and not raw:
            quoted = not quoted
        elif not quoted and char == "{":
            count += 1
        elif not quoted and char == "}":
            count -= 1
    return count


def _props(block: Block) -> Dict[str, List[Atom]]:
    """A block of properties: the first word of each statement is the key, the rest its value."""
    out: Dict[str, List[Atom]] = {}
    for statement in block:
        if statement and isinstance(statement[0], str):
            out[statement[0]] = statement[1:]
    return out


def _entries(value: Sequence[Atom]) -> List[Tuple[str, Optional[Block]]]:
    """The members of a set as tmsh writes it: ``{ a { } b }`` or one per line, each with its block if it has one."""
    atoms: List[Atom] = []
    if len(value) == 1 and isinstance(value[0], list):
        for statement in value[0]:
            atoms += statement
    else:
        atoms = list(value)
    out: List[Tuple[str, Optional[Block]]] = []
    for position, atom in enumerate(atoms):
        if isinstance(atom, str):
            following = atoms[position + 1] if position + 1 < len(atoms) else None
            out.append((atom, following if isinstance(following, list) else None))
    return out


def _word(value: Sequence[Atom]) -> str:
    return value[0] if value and isinstance(value[0], str) else ""


def _sub(value: Sequence[Atom]) -> Block:
    return value[0] if value and isinstance(value[0], list) else []


def full_name(name: str) -> str:
    """A name as tmsh writes it, with its partition: ``x`` is in /Common; ``P/x`` is relative to /, unless P is a folder
    of an application service (``app.app/x``, relative to /Common)."""
    if name.startswith("/"):
        return name
    first = name.split("/", 1)[0]
    if "/" in name and not first.endswith(".app"):
        return "/" + name
    return "/Common/" + name


def model_name(name: str) -> str:
    """The name in the model: without /Common/, and without the leading slash for other partitions."""
    name = full_name(name)
    return name[len("/Common/"):] if name.startswith("/Common/") else name.lstrip("/")


def _mask_length(mask: str, version: int) -> Optional[int]:
    """The prefix length of a mask of a virtual server: ``any``, ``any6``, or a mask of the address's IP version."""
    if mask in ("any", "any6"):
        return 0
    try:
        value = int(ipaddress.ip_address(mask))
    except ValueError:
        return None
    bits = 32 if version == 4 else 128
    if ipaddress.ip_address(mask).version != version:
        return None
    inverted = value ^ ((1 << bits) - 1)
    if inverted & (inverted + 1):
        return None
    return bits - inverted.bit_length()


def looks_like_f5afm(data: bytes) -> bool:
    """Stanzas of tmsh: a line at the left margin that starts with words only a BIG-IP configuration has."""
    return bool(_DETECT.search(data[:2_000_000].decode("utf-8", errors="replace")))


# -- the algebra of matches ----------------------------------------------------------------------------------------------

Ranges = Tuple[Tuple[int, int], ...]


def _merge(ranges: Sequence[Tuple[int, int]]) -> Ranges:
    out: List[Tuple[int, int]] = []
    for low, high in sorted(ranges):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return tuple(out)


def _ranges_and(a: Optional[Ranges], b: Optional[Ranges]) -> Optional[Ranges]:
    """None is every port; () is none."""
    if a is None:
        return b
    if b is None:
        return a
    return _merge([(max(x[0], y[0]), min(x[1], y[1])) for x in a for y in b if x[0] <= y[1] and y[0] <= x[1]])


def ports_text(ranges: Ranges) -> str:
    return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in ranges)


@dataclass(frozen=True)
class _Addr:
    members: Tuple[str, ...]  # model members (object names, literals)
    intervals: Optional[Tuple[Interval, ...]]  # what they hold; None when that cannot be known (a host name, a country)


@dataclass(frozen=True)
class _Svc:
    proto: Optional[int] = None  # None: every protocol
    dports: Optional[Ranges] = None  # None: every port
    sports: Optional[Ranges] = None
    icmp: Optional[Tuple[Tuple[int, Optional[int]], ...]] = None  # None: every type
    parts: Tuple[Tuple[str, Ranges], ...] = ()  # the port lists (and "" for ports of the rule) the destination ports are


@dataclass(frozen=True)
class _Match:
    vlans: Optional[FrozenSet[str]] = None  # None: every VLAN
    dvlans: Optional[FrozenSet[str]] = None
    src: Optional[_Addr] = None  # None: every address
    dst: Optional[_Addr] = None
    svc: _Svc = _Svc()
    problems: Tuple[str, ...] = ()


_EMPTY = object()


def _vlans_and(a: Optional[FrozenSet[str]], b: Optional[FrozenSet[str]]) -> Optional[FrozenSet[str]]:
    if a is None:
        return b
    if b is None:
        return a
    return a & b


def _addr_and(a: Optional[_Addr], b: Optional[_Addr], side: str) -> Tuple[object, str]:
    """(the addresses in both, or _EMPTY; a problem): a host name cannot be cut to an address."""
    if a is None:
        return b, ""
    if b is None or a == b:
        return a, ""
    if a.intervals is None or b.intervals is None:
        return a, f"the {side} holds a host name or a country, which cannot be kept to the addresses of {', '.join(b.members[:3])}"
    left, right = normalize(list(a.intervals)), normalize(list(b.intervals))
    both = intersect(left, right)
    if not both:
        return _EMPTY, ""
    if both == left:
        return a, ""
    if both == right:
        return b, ""
    return _Addr(tuple(interval_text(i) for i in both), tuple(both)), ""


def _icmp_and(a: Optional[Tuple[Tuple[int, Optional[int]], ...]],
              b: Optional[Tuple[Tuple[int, Optional[int]], ...]]) -> Optional[Tuple[Tuple[int, Optional[int]], ...]]:  # fmt: skip
    if a is None:
        return b
    if b is None:
        return a
    out: List[Tuple[int, Optional[int]]] = []
    for kind, code in a:
        for other_kind, other_code in b:
            if kind != other_kind or (code is not None and other_code is not None and code != other_code):
                continue
            found = (kind, code if code is not None else other_code)
            if found not in out:
                out.append(found)
    return tuple(out)


def _svc_and(a: _Svc, b: _Svc) -> Optional[_Svc]:
    if a.proto is not None and b.proto is not None and a.proto != b.proto:
        return None
    proto = a.proto if a.proto is not None else b.proto
    dports = _ranges_and(a.dports, b.dports)
    sports = _ranges_and(a.sports, b.sports)
    icmp = _icmp_and(a.icmp, b.icmp)
    if dports == () or sports == () or icmp == ():
        return None
    if (a.dports is not None or b.dports is not None or a.sports is not None or b.sports is not None) and proto not in _L4 + (None,):
        return None  # ports of a protocol without ports
    if (a.icmp is not None or b.icmp is not None) and proto not in (1, 58):
        return None
    parts = a.parts if b.dports is None else b.parts if a.dports is None else ()
    return _Svc(proto, dports, sports, icmp, parts)


def match_and(a: _Match, b: _Match) -> Optional[_Match]:
    """What two matches have in common, or None when nothing."""
    vlans, dvlans = _vlans_and(a.vlans, b.vlans), _vlans_and(a.dvlans, b.dvlans)
    if vlans == frozenset() or dvlans == frozenset():
        return None
    src, src_problem = _addr_and(a.src, b.src, "source")
    dst, dst_problem = _addr_and(a.dst, b.dst, "destination")
    if src is _EMPTY or dst is _EMPTY:
        return None
    svc = _svc_and(a.svc, b.svc)
    if svc is None:
        return None
    if isinstance(src, _Addr) and isinstance(dst, _Addr) and src.intervals is not None and dst.intervals is not None:
        if not {i[0] for i in src.intervals} & {i[0] for i in dst.intervals}:
            return None  # a source of one IP version and a destination of the other
    problems = tuple(dict.fromkeys(a.problems + b.problems + tuple(p for p in (src_problem, dst_problem) if p)))
    assert src is None or isinstance(src, _Addr)
    assert dst is None or isinstance(dst, _Addr)
    return _Match(vlans, dvlans, src, dst, svc, problems)


def _may_overlap(a: _Match, b: _Match) -> bool:
    """False only when the two certainly have nothing in common."""
    for x, y in ((a.vlans, b.vlans), (a.dvlans, b.dvlans)):
        if x is not None and y is not None and not x & y:
            return False
    for p, q in ((a.src, b.src), (a.dst, b.dst)):
        if p is not None and q is not None and p.intervals is not None and q.intervals is not None:
            if not overlaps(p.intervals, q.intervals):
                return False
    return _svc_and(a.svc, b.svc) is not None


# -- what was read -------------------------------------------------------------------------------------------------------


@dataclass
class _Entry:
    """A rule of a policy (one of a rule list counts in its place): where it stands and what it matches."""

    name: str  # the base of the names of the model rules made of it
    context: str
    policy: str
    path: List[str]
    action: str  # accept, accept-decisively, drop, reject
    enabled: bool
    schedule: str
    match: _Match
    log: bool = False
    description: str = ""
    profiles: Dict[str, str] = field(default_factory=dict)
    handling: Dict[str, str] = field(default_factory=dict)
    findings: List[Tuple[Severity, str, str]] = field(default_factory=list)
    icmp: bool = False  # an ICMP rule: ignored in the virtual server context
    allow_problems: Tuple[str, ...] = ()  # what makes an allow that follows from the rule uncertain (an iRule)


@dataclass
class _Listener:
    name: str
    pieces: List[_Match]
    passing: bool  # lets traffic through (not of type reject, not disabled)
    key: Tuple[int, int, int, int]
    policy: str = ""
    entries: List[_Entry] = field(default_factory=list)


class _Reader:
    def __init__(self, stanzas: List[_Stanza], report: Report, policy: str) -> None:
        self.report = report
        self.wanted = policy
        self.p = Policy(vendor="f5-afm")
        self.address_lists: Dict[str, Block] = {}
        self.port_lists: Dict[str, Block] = {}
        self.rule_lists: Dict[str, Block] = {}
        self.policies: Dict[str, Block] = {}
        self.zones_afm: Dict[str, List[str]] = {}
        self.vlans: List[str] = []  # model names of VLANs, VLAN groups and tunnels the configuration defines
        self.route_domains: List[Tuple[str, Dict[str, List[Atom]]]] = []
        self.virtuals: List[Tuple[str, Dict[str, List[Atom]]]] = []
        self.selfs: List[Tuple[str, Dict[str, List[Atom]]]] = []
        self.global_rules: Optional[Dict[str, List[Atom]]] = None
        self.management = False
        self.db: Dict[str, str] = {}
        self.nat_seen: List[str] = []
        self.port_cache: Dict[str, Optional[Ranges]] = {}
        self.names: Set[str] = set()
        self.listeners: List[_Listener] = []
        self.universal = False
        self.levels: List[List[_Entry]] = [[], []]
        self.vs_default = Action.ALLOW
        self.global_default = Action.DENY
        self.icmp_ignored: List[str] = []
        self.rd_vlans: Dict[int, FrozenSet[str]] = {}
        self._staged: Set[str] = set()
        self._rd0_open = True
        self.taint: Optional[Dict[str, str]] = None
        for stanza in stanzas:
            self._take(stanza)

    def _take(self, stanza: _Stanza) -> None:
        head = stanza.header
        words = tuple(head)
        name = full_name(head[-1]) if len(head) >= 2 else ""
        if words[:3] == ("security", "firewall", "address-list") and len(head) == 4:
            self.address_lists[name] = stanza.body
        elif words[:3] == ("security", "firewall", "port-list") and len(head) == 4:
            self.port_lists[name] = stanza.body
        elif words[:3] == ("security", "firewall", "rule-list") and len(head) == 4:
            self.rule_lists[name] = stanza.body
        elif words[:3] == ("security", "firewall", "policy") and len(head) == 4:
            self.policies[name] = stanza.body
        elif words == ("security", "firewall", "global-rules"):
            self.global_rules = _props(stanza.body)
        elif words == ("security", "firewall", "management-ip-rules"):
            self.management = bool(_props(stanza.body).get("rules"))
        elif words[:2] == ("security", "zone") and len(head) == 3:
            self.zones_afm[name] = [full_name(v) for v, _ in _entries(_props(stanza.body).get("vlans", []))]
        elif words[:2] in (("net", "vlan"), ("net", "vlan-group")) and len(head) == 3:
            self.vlans.append(model_name(name))
        elif words[:3] == ("net", "tunnels", "tunnel") and len(head) == 4:
            self.vlans.append(model_name(name))
        elif words[:2] == ("net", "route-domain") and len(head) == 3:
            self.route_domains.append((name, _props(stanza.body)))
        elif words[:2] == ("net", "self") and len(head) == 3:
            self.selfs.append((name, _props(stanza.body)))
        elif words[:2] == ("ltm", "virtual") and len(head) == 3:
            self.virtuals.append((name, _props(stanza.body)))
        elif words[:2] == ("sys", "db") and len(head) == 3:
            self.db[head[2]] = _word(_props(stanza.body).get("value", [])).lower()
        elif words[:2] in (("security", "nat"), ("ltm", "snat"), ("ltm", "snatpool"), ("ltm", "nat"), ("ltm", "lsn-pool")):
            self.nat_seen.append(" ".join(head[:3]))

    # -- objects --------------------------------------------------------------------------------------------------------

    def objects(self) -> None:
        for name, body in self.address_lists.items():
            props = _props(body)
            group = AddressGroup(model_name(name), description=_word(props.get("description", [])))
            for key in props:
                if key not in ("addresses", "address-lists", "fqdns", "geo", "description", "app-service", "partition"):
                    group.unsupported = f"an address list with '{key}', which FWShift does not read"
            for value, _ in _entries(props.get("addresses", [])):
                literal = self._literal(value, f"address list '{model_name(name)}'", ("address-group", model_name(name)))
                group.members.append(literal if literal else self._bad_address(value))
            for value, _ in _entries(props.get("address-lists", [])):
                group.members.append(self._list_ref(value))
            for value, _ in _entries(props.get("fqdns", [])):
                group.members.append(self._fqdn(value))
            for value, _ in _entries(props.get("geo", [])):
                group.members.append(self._geo(value))
            self.p.address_groups[group.name] = group
        for vlan in self.vlans:
            self.p.zones.setdefault(vlan, Zone(vlan, [vlan]))

    def _literal(self, text: str, where: str, item: Tuple[str, str]) -> str:
        """An address of AFM as a literal of the model, without its route domain; "" when it is none."""
        found = re.fullmatch(r"([^%/]+)(?:%(\d+))?(/\d+)?", text.strip())
        if not found:
            return ""
        literal = found.group(1) + (found.group(3) or "")
        if parse_literal(literal) is None:
            return ""
        if found.group(2) and found.group(2) != "0":
            self.report.add(item[0], item[1], Severity.REVIEW, "F5AFM_ROUTE_DOMAIN",
                            f"{text} in {where}: the route domain %{found.group(2)} is not kept; the address is read as "
                            "matching in every route domain, which may be more than the BIG-IP matches")  # fmt: skip
        return literal

    def _bad_address(self, value: str) -> str:
        name = f"unreadable:{value[:60]}"
        self.p.addresses.setdefault(name, Address(name, AddressKind.UNSUPPORTED, "", raw=f"'{value[:60]}', which is not an address"))
        return name

    def _list_ref(self, value: str) -> str:
        name = full_name(value)
        model = model_name(name)
        if name not in self.address_lists and model not in self.p.addresses:
            self.p.addresses[model] = Address(model, AddressKind.UNSUPPORTED, "", raw="an address list that is not in the input")
        return model

    def _fqdn(self, value: str) -> str:
        name = value.strip().rstrip(".").lower()
        if name not in self.p.addresses:
            self.p.addresses[name] = Address(name, AddressKind.FQDN, name, description="resolved by the global FQDN resolver of AFM")
        return name

    def _geo(self, value: str) -> str:
        name = f"geo:{value}"
        if name not in self.p.addresses:
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "",
                                             raw=f"the geolocation {value} (a country or region), which FWShift cannot write as addresses")  # fmt: skip
        return name

    def _ports(self, value: Sequence[Atom], problems: List[str]) -> List[Tuple[int, int]]:
        out: List[Tuple[int, int]] = []
        for text, _ in _entries(value):
            low, _, high = text.partition("-")
            first, last = PORTS.get(low, int(low) if low.isdigit() else -1), PORTS.get(high, int(high) if high.isdigit() else -1)
            if not high:
                last = first
            if not (0 <= first <= last <= 65535):
                problems.append(f"the port '{text[:30]}', which FWShift cannot read")
                continue
            out.append((first, last))
        return out

    def _port_list(self, name: str, seen: FrozenSet[str] = frozenset()) -> Optional[Ranges]:
        if name in self.port_cache:
            return self.port_cache[name]
        if name not in self.port_lists or name in seen or len(seen) > _MAX_NESTING:
            return None
        props = _props(self.port_lists[name])
        problems: List[str] = []
        ranges = self._ports(props.get("ports", []), problems)
        result: Optional[Ranges] = None
        if not problems and all(key in ("ports", "port-lists", "description", "app-service") for key in props):
            result = _merge(ranges)
            for inner, _ in _entries(props.get("port-lists", [])):
                found = self._port_list(full_name(inner), seen | {name})
                if found is None:
                    result = None
                    break
                result = _merge(list(result) + list(found))
        self.port_cache[name] = result
        return result

    # -- rules ----------------------------------------------------------------------------------------------------------

    def _expand(self, policy: str, context: str, label: str) -> List[_Entry]:
        """The rules of a policy in order, the rules of a rule list in its place."""
        body = self.policies.get(policy)
        if body is None:
            self.report.note(Severity.REVIEW, "F5AFM_POLICY_MISSING",
                             f"the {context} enforces the policy {policy}, which is not in the input: nothing of it is converted, "
                             "and traffic is read as if no rule of that context matched")  # fmt: skip
            return []
        out: List[_Entry] = []
        for rule_name, block in _entries(_props(body).get("rules", [])):
            props = _props(block or [])
            reference = _word(props.get("rule-list", []))
            status = _word(props.get("status", [])) or "enabled"
            schedule = model_name(_word(props.get("schedule", []))) if status == "scheduled" else ""
            if reference:
                listed = full_name(reference)
                inner = self.rule_lists.get(listed)
                if inner is None:
                    self.report.note(Severity.REVIEW, "F5AFM_RULE_LIST_MISSING",
                                     f"rule {rule_name} of policy {policy} refers to the rule list {listed}, which is not in the input: "
                                     "its rules are not converted")  # fmt: skip
                    continue
                for inner_name, inner_block in _entries(_props(inner).get("rules", [])):
                    entry = self._entry(policy, context, f"{label}/{rule_name}/{inner_name}", [rule_name, inner_name], _props(inner_block or []))
                    if status == "disabled":
                        entry.enabled = False
                    if schedule and not entry.schedule:
                        entry.schedule = schedule
                    out.append(entry)
                continue
            out.append(self._entry(policy, context, f"{label}/{rule_name}", [rule_name], props))
        return out

    def _entry(self, policy: str, context: str, name: str, path: List[str], props: Dict[str, List[Atom]]) -> _Entry:
        problems: List[str] = []
        findings: List[Tuple[Severity, str, str]] = []
        profiles: Dict[str, str] = {}
        handling: Dict[str, str] = {}
        action = _word(props.get("action", []))
        if _word(props.get("rule-list", [])):
            problems.append("a rule list inside a rule list")
        if action not in ("accept", "accept-decisively", "drop", "reject"):
            problems.append(f"the action '{action[:30]}'" if action else "a rule without an action")
            action = "drop"
        status = _word(props.get("status", [])) or "enabled"
        if status not in ("enabled", "disabled", "scheduled"):
            problems.append(f"the status '{status[:30]}'")
        schedule = model_name(_word(props.get("schedule", []))) if status == "scheduled" else ""
        if status == "scheduled" and not schedule:
            problems.append("a scheduled rule without a schedule")
        for key in props:
            if key not in _RULE_KEYS:
                problems.append(f"the property '{key}', which FWShift does not read")
        protocol_word = _word(props.get("ip-protocol", [])).lower()
        proto: Optional[int] = None
        if protocol_word and protocol_word != "any":
            proto = PROTOCOLS.get(protocol_word, int(protocol_word) if protocol_word.isdigit() and int(protocol_word) < 256 else -1)
            if proto < 0:
                problems.append(f"the protocol '{protocol_word[:30]}', which FWShift cannot read")
                proto = None
        icmp = self._icmp(props.get("icmp", []), proto, problems)
        src_props, dst_props = _props(_sub(props.get("source", []))), _props(_sub(props.get("destination", [])))
        vlans: Optional[Set[str]] = None
        dvlans: Optional[Set[str]] = None
        for side, side_props in (("source", src_props), ("destination", dst_props)):
            for key in side_props:
                if key not in _SIDE_KEYS or (side == "destination" and key in ("vlans", "identity")):
                    problems.append(f"the {side} property '{key}', which FWShift does not read")
        listed = [model_name(v) for v, _ in _entries(src_props.get("vlans", []))]
        if listed:
            vlans = set(listed)
        for side, side_props in (("source", src_props), ("destination", dst_props)):
            zone_names = [full_name(v) for v, _ in _entries(side_props.get("zones", []))]
            if not zone_names:
                continue
            members: Set[str] = set()
            for zone in zone_names:
                if zone not in self.zones_afm:
                    problems.append(f"the zone {zone}, which is not in the input")
                members |= {model_name(v) for v in self.zones_afm.get(zone, [])}
            if side == "source":
                vlans = members if vlans is None else vlans & members
            else:
                dvlans = members
                findings.append((Severity.REVIEW, "F5AFM_DESTINATION_ZONE",
                                 "the rule names destination zones; they are read as the VLANs the packet leaves on, which is not "
                                 "confirmed"))  # fmt: skip
        if src_props.get("identity"):
            problems.append("users or groups of users (identity)")
        if src_props.get("subscriber-groups"):
            problems.append("subscriber groups")
        for side, side_props in (("source", src_props), ("destination", dst_props)):
            if side_props.get("ipi-category"):
                problems.append(f"an IP intelligence category of the {side}")
        src = self._side(src_props, name, problems)
        dst = self._side(dst_props, name, problems)
        dports, sports, parts = self._side_ports(dst_props, problems), self._side_ports(src_props, problems), self._parts(dst_props)
        if (dports is not None or sports is not None) and proto not in _L4:
            problems.append("ports without the protocol TCP, UDP or SCTP")
            dports = sports = None
        svc = _Svc(proto, dports, sports, icmp, parts if dports is not None and sports is None else ())
        irule = _word(props.get("irule", []))
        if irule:
            handling["irule"] = model_name(irule)
            if action not in ("accept", "accept-decisively"):
                findings.append((Severity.INFO, "F5AFM_IRULE", f"the iRule {model_name(irule)} of the rule is not converted"))
        if _word(props.get("virtual-server", [])):
            problems.append(f"sending the traffic to the virtual server {model_name(_word(props['virtual-server']))}")
        for key, label in (("service-policy", "service policy"), ("protocol-inspection-profile", "protocol inspection profile"),
                           ("ips-profile", "protocol inspection profile"), ("classification-policy", "classification policy")):  # fmt: skip
            if _word(props.get(key, [])):
                profiles[label] = model_name(_word(props[key]))
        match = _Match(frozenset(vlans) if vlans is not None else None, frozenset(dvlans) if dvlans is not None else None,
                       src, dst, svc, tuple(dict.fromkeys(problems)))  # fmt: skip
        entry = _Entry(name, context, policy, path, action, status != "disabled", schedule, match,
                       log=_word(props.get("log", [])) == "yes", description=_word(props.get("description", [])),
                       profiles=profiles, handling=handling, findings=findings, icmp=proto in (1, 58))  # fmt: skip
        if irule and action in ("accept", "accept-decisively"):
            entry.allow_problems = (f"the iRule {model_name(irule)} of rule {name}, which runs on FLOW_INIT and may drop what the rule "
                                    "accepts",)  # fmt: skip
        return entry

    def _icmp(self, value: Sequence[Atom], proto: Optional[int], problems: List[str]) -> Optional[Tuple[Tuple[int, Optional[int]], ...]]:
        entries = _entries(value)
        if not entries:
            return None
        if proto not in (1, 58):
            problems.append("ICMP types without the protocol ICMP or IPv6-ICMP")
            return None
        names = _ICMP_NAMES if proto == 1 else _ICMP6_NAMES
        out: List[Tuple[int, Optional[int]]] = []
        for text, _ in entries:
            kind_text, _, code_text = text.partition(":")
            kind = names.get(kind_text, int(kind_text) if kind_text.isdigit() else -1)
            code: Optional[int] = None if code_text in ("", "any") else int(code_text) if code_text.isdigit() else -1
            if not 0 <= kind <= 255 or (code is not None and not 0 <= code <= 255):
                problems.append(f"the ICMP type '{text[:30]}', which FWShift cannot read")
                continue
            out.append((kind, code))
        return tuple(out) if out else None

    def _side(self, props: Dict[str, List[Atom]], rule: str, problems: List[str]) -> Optional[_Addr]:
        members: List[str] = []
        for value, _ in _entries(props.get("addresses", [])):
            literal = self._literal(value, "the rule", ("rule", rule))
            members.append(literal if literal else self._bad_address(value))
        for value, _ in _entries(props.get("address-lists", [])):
            members.append(self._list_ref(value))
        for value, _ in _entries(props.get("fqdns", [])):
            members.append(self._fqdn(value))
        for value, _ in _entries(props.get("geo", [])):
            members.append(self._geo(value))
        if not members:
            return None
        members = transform.dedupe(members)
        intervals: Optional[List[Interval]] = []
        for member in members:
            found = transform.address_intervals(self.p, member)
            if found is None or intervals is None:
                intervals = None
                continue
            intervals += found
        return _Addr(tuple(members), tuple(normalize(intervals)) if intervals is not None else None)

    def _side_ports(self, props: Dict[str, List[Atom]], problems: List[str]) -> Optional[Ranges]:
        """The ports of a side; None for every port, and where they cannot be read (the rule is not converted then)."""
        mine: List[str] = []
        ranges = self._ports(props.get("ports", []), mine)
        lists = [full_name(v) for v, _ in _entries(props.get("port-lists", []))]
        for name in lists:
            found = self._port_list(name)
            if found is None:
                mine.append(f"the port list {name}, which is not in the input or cannot be read")
                continue
            ranges += list(found)
        problems += mine
        if mine or (not ranges and not lists):
            return None
        return _merge(ranges)

    def _parts(self, props: Dict[str, List[Atom]]) -> Tuple[Tuple[str, Ranges], ...]:
        out: List[Tuple[str, Ranges]] = []
        for name in [full_name(v) for v, _ in _entries(props.get("port-lists", []))]:
            found = self._port_list(name)
            if found:
                out.append((model_name(name), found))
        inline = self._ports(props.get("ports", []), [])
        if inline:
            out.append(("", _merge(inline)))
        return tuple(out)

    # -- contexts -------------------------------------------------------------------------------------------------------

    def contexts(self) -> None:
        mode = self.db.get("tm.fw.defaultaction", "")
        self.vs_default = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.DENY}.get(mode or "accept", Action.ALLOW)
        if mode and mode not in ("accept", "drop", "reject", "default"):
            self.report.note(Severity.REVIEW, "F5AFM_MODE", f"sys db tm.fw.defaultaction has the value '{mode[:30]}', which FWShift "
                             "does not know: read as accept (ADC mode)")  # fmt: skip
        elif not mode:
            self.report.note(Severity.REVIEW, "F5AFM_MODE",
                             "the input does not say the default action of the virtual server and self IP contexts (sys db "
                             "tm.fw.defaultaction): read as accept, ADC mode, which is the default of a BIG-IP. Add the output of "
                             "'list sys db tm.fw.defaultaction' if the BIG-IP runs in Firewall mode")  # fmt: skip
        else:
            label = "ADC mode: traffic for a virtual server that no rule decides is accepted" if self.vs_default == Action.ALLOW else \
                f"Firewall mode: traffic for a virtual server that no rule decides is {'dropped' if mode == 'drop' else 'rejected'}"
            self.report.note(Severity.INFO, "F5AFM_MODE", f"sys db tm.fw.defaultaction is {mode}: {label}")
        self.global_default = Action.DROP if self.db.get("tm.rejectunmatched") == "false" else Action.DENY
        self._route_domain_vlans()
        enforced: List[str] = []
        if self.wanted:
            policy = full_name(self.wanted)
            if policy not in self.policies:
                raise ParseError(f"--policy: there is no firewall policy {policy} in the input (it has "
                                 f"{', '.join(sorted(self.policies)[:10]) or 'none'})")  # fmt: skip
            self.levels[0] = self._expand(policy, "global context", "global")
            self.report.note(Severity.INFO, "F5AFM_POLICY_SELECTED",
                             f"--policy: the policy {policy} is read as if it were enforced in the global context; the policies of "
                             "the contexts of the input are not read")  # fmt: skip
            enforced.append(policy)
        else:
            enforced += self._attached()
            if not enforced and len(self.policies) == 1:
                policy = next(iter(self.policies))
                self.levels[0] = self._expand(policy, "global context", "global")
                enforced.append(policy)
                self.report.note(Severity.REVIEW, "F5AFM_POLICY_NOT_ATTACHED",
                                 f"no context enforces a policy; the one policy of the input, {policy}, is read as if it were enforced "
                                 "in the global context")  # fmt: skip
            elif not enforced:
                self.report.note(Severity.REVIEW, "F5AFM_NO_POLICY",
                                 "no context enforces a firewall policy" + (f" (the input has {len(self.policies)}; choose one with --policy)"
                                                                            if self.policies else "") +
                                 ": the converted policy holds only what the BIG-IP does without one")  # fmt: skip
        self._listeners()
        unused = [name for name in self.policies if name not in enforced and name not in self._staged]
        if unused:
            self.report.note(Severity.INFO, "F5AFM_UNUSED_POLICY", "policies that no context enforces, not converted: " + ", ".join(unused[:20]))

    def _route_domain_vlans(self) -> None:
        assigned: Set[str] = set()
        zero: Optional[FrozenSet[str]] = None
        for _, props in self.route_domains:
            ident = _word(props.get("id", []))
            vlans = frozenset(model_name(v) for v, _ in _entries(props.get("vlans", [])))
            if not ident.isdigit():
                continue
            self.rd_vlans[int(ident)] = vlans
            if ident == "0":
                zero = vlans if props.get("vlans") else None
            else:
                assigned |= vlans
        if 0 not in self.rd_vlans or zero is None:
            # Route domain 0 holds the VLANs no other route domain holds.
            self.rd_vlans[0] = frozenset(v for v in self.vlans if v not in assigned)
            self._rd0_open = True
        else:
            self._rd0_open = False

    def _attached(self) -> List[str]:
        enforced: List[str] = []
        self._staged = set()
        if self.global_rules is not None:
            policy = _word(self.global_rules.get("enforced-policy", []))
            if policy and policy != "none":
                enforced.append(full_name(policy))
                self.levels[0] = self._expand(full_name(policy), "global context", "global")
            staged = _word(self.global_rules.get("staged-policy", []))
            if staged and staged != "none":
                self._note_staged("the global context", staged)
        for name, props in self.route_domains:
            ident = _word(props.get("id", []))
            policy = _word(props.get("fw-enforced-policy", []))
            staged = _word(props.get("fw-staged-policy", []))
            if staged and staged != "none":
                self._note_staged(f"route domain {model_name(name)}", staged)
            if not policy or policy == "none":
                continue
            enforced.append(full_name(policy))
            vlans: Optional[FrozenSet[str]] = self.rd_vlans.get(int(ident)) if ident.isdigit() else None
            label = f"rd{ident or model_name(name)}"
            entries = self._expand(full_name(policy), f"route domain {model_name(name)}", label)
            if ident == "0" and self._rd0_open and not self.route_domains_other():
                vlans = None  # route domain 0 is every VLAN when there is no other
            if vlans is not None and not vlans:
                self.report.note(Severity.INFO, "F5AFM_ROUTE_DOMAIN_EMPTY",
                                 f"route domain {model_name(name)} holds no VLAN the input names: its policy matches nothing")  # fmt: skip
                continue
            for entry in entries:
                if vlans is not None:
                    cut = match_and(entry.match, _Match(vlans=vlans))
                    if cut is None:
                        continue
                    entry.match = cut
                self.levels[1].append(entry)
        for name, props in self.selfs:
            policy = _word(props.get("fw-enforced-policy", []))
            staged = _word(props.get("fw-staged-policy", []))
            if (policy and policy != "none") or (staged and staged != "none"):
                self.report.note(Severity.INFO, "F5AFM_SELF_IP",
                                 f"self IP {model_name(name)} has a firewall policy: it filters traffic to the BIG-IP itself, which "
                                 "is not converted")  # fmt: skip
                if policy and policy != "none":
                    enforced.append(full_name(policy))
        for name, props in self.virtuals:
            staged = _word(props.get("fw-staged-policy", []))
            if staged and staged != "none":
                self._note_staged(f"virtual server {model_name(name)}", staged)
            policy = _word(props.get("fw-enforced-policy", []))
            if policy and policy != "none":
                enforced.append(full_name(policy))
        return enforced

    def route_domains_other(self) -> bool:
        return any(ident != 0 and vlans for ident, vlans in self.rd_vlans.items())

    def _note_staged(self, where: str, policy: str) -> None:
        self._staged.add(full_name(policy))
        self.report.note(Severity.INFO, "F5AFM_STAGED",
                         f"{where} stages the policy {full_name(policy)}: a staged policy only counts and logs, and is not converted")  # fmt: skip

    def _listeners(self) -> None:
        if not self.virtuals:
            self.universal = True
            self.report.note(Severity.REVIEW, "F5AFM_NO_VIRTUAL_SERVERS",
                             "the input holds no virtual servers (ltm virtual): every packet is read as having one that lets it "
                             "through, as a forwarding virtual server for every address would. On the BIG-IP, traffic for which "
                             "there is no virtual server is dropped whatever the firewall rules say")  # fmt: skip
            return
        unread: List[str] = []
        for name, props in self.virtuals:
            label = model_name(name)
            if "internal" in props or "dhcp-relay" in props:
                self.report.note(Severity.INFO, "F5AFM_VIRTUAL_SKIPPED",
                                 f"virtual server {label} is of type internal or DHCP relay and takes no forwarded traffic: left out")  # fmt: skip
                continue
            listener = self._listener(label, props)
            if listener is None:
                unread.append(label)
                continue
            policy = _word(props.get("fw-enforced-policy", []))
            if policy and policy != "none" and not self.wanted:
                listener.policy = full_name(policy)
                for entry in self._expand(full_name(policy), f"virtual server {label}", label):
                    if entry.icmp:
                        self.icmp_ignored.append(entry.name)
                        continue
                    listener.entries.append(entry)
            self.listeners.append(listener)
        if unread:
            self.report.note(Severity.REVIEW, "F5AFM_VIRTUAL_UNREAD",
                             "virtual servers whose destination, mask, source or VLANs FWShift cannot read, left out: the converted "
                             "policy lets no traffic through to them: " + ", ".join(unread[:20]))  # fmt: skip
        if self.icmp_ignored:
            self.report.note(Severity.INFO, "F5AFM_ICMP_IGNORED",
                             "ICMP rules in the virtual server context, which the BIG-IP ignores, are not converted: "
                             + ", ".join(self.icmp_ignored[:20]))  # fmt: skip
        self.listeners.sort(key=lambda listener: listener.key)
        skipped = [listener.name for listener in self.listeners if not listener.passing]
        if skipped:
            self.report.note(Severity.INFO, "F5AFM_VIRTUAL_REFUSES",
                             "virtual servers that are disabled or of type reject take their traffic and let none of it through: "
                             + ", ".join(skipped[:20]))  # fmt: skip
        translating = [model_name(name) for name, props in self.virtuals
                       if _word(props.get("pool", [])) not in ("", "none") or props.get("source-address-translation")
                       or _word(props.get("translate-address", [])) == "enabled"]  # fmt: skip
        if translating or self.nat_seen:
            self.report.note(Severity.REVIEW, "F5AFM_NAT_NOT_READ",
                             "NAT of the BIG-IP is not read: virtual servers that send traffic to a pool or translate the source (" +
                             (", ".join(translating[:10]) or "none") + ")" +
                             (", and " + ", ".join(sorted(set(self.nat_seen))) if self.nat_seen else "") +
                             ". The rules name addresses as they arrive, before NAT, which is what the model holds")  # fmt: skip

    def _listener(self, label: str, props: Dict[str, List[Atom]]) -> Optional[_Listener]:
        destination = _word(props.get("destination", []))
        if not destination:
            return None
        last = full_name(destination).rsplit("/", 1)[-1]
        if last.count(":") > 1:
            address, _, port_text = last.rpartition(".")
        else:
            address, _, port_text = last.rpartition(":")
        found = re.fullmatch(r"([^%]+)(?:%(\d+))?", address)
        if not found:
            return None
        try:
            ip = ipaddress.ip_address(found.group(1))
        except ValueError:
            return None
        rd = int(found.group(2) or 0)
        mask = _word(props.get("mask", [])) or ("255.255.255.255" if ip.version == 4 else "ffff:" * 7 + "ffff")
        found_length = _mask_length(mask, ip.version)
        if found_length is None:
            return None
        length = found_length
        network = ipaddress.ip_network(f"{ip}/{length}", strict=False)
        port: Optional[int]
        if port_text in ("any", "0", "*"):
            port = None
        else:
            port = PORTS.get(port_text, int(port_text) if port_text.isdigit() else -1)
            if not 0 < port < 65536:
                return None
        source_text = _word(props.get("source", [])) or ("0.0.0.0/0" if ip.version == 4 else "::/0")
        source_text = re.sub(r"%\d+", "", source_text)
        try:
            source = ipaddress.ip_network(source_text, strict=False)
        except ValueError:
            return None
        protocol_word = _word(props.get("ip-protocol", [])).lower() or "any"
        proto: Optional[int] = None if protocol_word == "any" else PROTOCOLS.get(protocol_word, int(protocol_word) if protocol_word.isdigit() else -1)
        if proto is not None and proto < 0:
            return None
        named = [model_name(v) for v, _ in _entries(props.get("vlans", []))]
        vlans: Optional[FrozenSet[str]] = None
        if "vlans-enabled" in props:
            vlans = frozenset(named)
        elif named:
            if not self.vlans:
                return None  # all VLANs but these: which the others are, the input does not say
            vlans = frozenset(v for v in self.vlans if v not in named)
        if rd and rd in self.rd_vlans:
            vlans = self.rd_vlans[rd] if vlans is None else vlans & self.rd_vlans[rd]
        dst = _Addr((str(network),), ((network.version, int(network.network_address), int(network.broadcast_address)),))
        src = None if source.prefixlen == 0 and source.version == ip.version else _Addr(
            (str(source),), ((source.version, int(source.network_address), int(source.broadcast_address)),))  # fmt: skip
        pieces: List[_Match] = []
        if vlans is not None and not vlans:
            protocols: List[Optional[int]] = []  # enabled on no VLAN: it takes nothing
        elif port is not None and proto is None:
            protocols = list(_L4)
        else:
            protocols = [proto]
        for each in protocols:
            ports = ((port, port),) if port is not None and each in _L4 else None
            pieces.append(_Match(vlans, None, src, dst, _Svc(each, ports)))
        passing = "disabled" not in props and "reject" not in props
        key = (-length, -source.prefixlen, 0 if port is not None else 1, 0 if proto is not None else 1)
        return _Listener(label, pieces, passing, key)

    # -- one list --------------------------------------------------------------------------------------------------------

    def flatten(self) -> None:
        self._run(0, None, "", True, "", (), ())
        default = self.vs_default if self.universal else self.global_default
        self.p.default_interzone = self.p.default_intrazone = default

    def _run(self, level: int, restrict: Optional[_Match], trail: str, top: bool, schedule: str, inherited: Tuple[str, ...],
             allow: Tuple[str, ...]) -> None:  # fmt: skip
        """The rules of the contexts from ``level`` on, kept to ``restrict``; ``inherited`` makes them all not converted,
        ``allow`` the ones that allow."""
        if level < 2:
            blind: List[_Entry] = []
            for entry in self.levels[level]:
                self._entry_out(level, entry, restrict, trail, top, schedule, inherited, allow, blind)
            self._run(level + 1, restrict, trail, top, schedule, inherited, allow)
            return
        if self.universal:
            if not top:
                self._out(None, restrict or _Match(), self.vs_default, f"{trail}(default)", schedule=schedule, extra=inherited,
                          allow=allow)  # fmt: skip
            return
        for listener in self.listeners:
            for index, piece in enumerate(listener.pieces):
                region = match_and(piece, restrict) if restrict is not None else piece
                if region is None:
                    continue
                suffix = f"#{index + 1}" if len(listener.pieces) > 1 else ""
                if not listener.passing:
                    self._out(None, region, Action.DENY, f"{trail}{listener.name}{suffix}/(refused)", schedule=schedule, extra=inherited,
                              context=f"virtual server {listener.name}")  # fmt: skip
                    continue
                for entry in listener.entries:
                    if not entry.enabled and not top:
                        continue
                    cut = match_and(entry.match, region)
                    if cut is None:
                        continue
                    action = Action.ALLOW if entry.action in ("accept", "accept-decisively") else self._deny(entry.action)
                    self._out(entry, cut, action, f"{trail}{entry.name}{suffix}", enabled=entry.enabled,
                              schedule=self._schedules(schedule, entry.schedule, cut), extra=inherited,
                              allow=allow + entry.allow_problems)  # fmt: skip
                self._out(None, region, self.vs_default, f"{trail}{listener.name}{suffix}/(default)", schedule=schedule, extra=inherited,
                          context=f"virtual server {listener.name}", allow=allow)  # fmt: skip

    def _tainted(self, match: _Match) -> bool:
        """Whether a match names an object that cannot be converted (a country, a list that is not in the input)."""
        if self.taint is None:
            self.taint = transform.tainted_addresses(self.p)
        members = (match.src.members if match.src else ()) + (match.dst.members if match.dst else ())
        return any(member in self.taint for member in members)

    @staticmethod
    def _deny(action: str) -> Action:
        return Action.RESET_CLIENT if action == "reject" else Action.DROP

    @staticmethod
    def _schedules(outer: str, own: str, match: _Match) -> str:
        if outer and own and outer != own:
            return outer + "+" + own
        return outer or own

    def _entry_out(self, level: int, entry: _Entry, restrict: Optional[_Match], trail: str, top: bool, schedule: str,
                   inherited: Tuple[str, ...], allow: Tuple[str, ...], blind: List[_Entry]) -> None:  # fmt: skip
        if not entry.enabled:
            if top:
                action = Action.ALLOW if entry.action in ("accept", "accept-decisively") else self._deny(entry.action)
                self._out(entry, entry.match, action, f"{trail}{entry.name}", enabled=False, schedule=entry.schedule, extra=inherited,
                          allow=allow + entry.allow_problems)  # fmt: skip
            return
        cut = match_and(entry.match, restrict) if restrict is not None else entry.match
        if cut is None:
            return
        extra = inherited + tuple(f"below the accept rule {other.name} of the same context, whose match cannot be worked out"
                                  for other in blind if _may_overlap(other.match, cut))  # fmt: skip
        sched = self._schedules(schedule, entry.schedule, cut)
        allow = allow + entry.allow_problems
        if entry.action in ("drop", "reject"):
            self._out(entry, cut, self._deny(entry.action), f"{trail}{entry.name}", schedule=sched, extra=extra)
        elif entry.action == "accept-decisively":
            if self.universal:
                self._out(entry, cut, Action.ALLOW, f"{trail}{entry.name}", schedule=sched, extra=extra, allow=allow)
            else:
                for listener in self.listeners:
                    for index, piece in enumerate(listener.pieces):
                        region = match_and(cut, piece)
                        if region is None:
                            continue
                        suffix = f"#{index + 1}" if len(listener.pieces) > 1 else ""
                        self._out(entry, region, Action.ALLOW if listener.passing else Action.DENY,
                                  f"{trail}{entry.name}@{listener.name}{suffix}", schedule=sched, extra=extra, allow=allow)  # fmt: skip
        else:  # accept: the later contexts, for what it matches
            if cut.problems or entry.match.problems or self._tainted(entry.match):
                blind.append(entry)
            self._run(level + 1, cut, f"{trail}{entry.name}>", False, sched, extra + entry.match.problems, allow)

    def _out(self, entry: Optional[_Entry], match: _Match, action: Action, name: str, enabled: bool = True, schedule: str = "",
             extra: Tuple[str, ...] = (), context: str = "", allow: Tuple[str, ...] = ()) -> None:  # fmt: skip
        if len(self.p.rules) >= _MAX_RULES:
            raise ParseError(f"the contexts of the configuration make more than {_MAX_RULES} rules of one list: not converted")
        base, counter = name, 2
        while name in self.names:
            name = f"{base}~{counter}"
            counter += 1
        self.names.add(name)
        rule = Rule(name=name, action=action, enabled=enabled)
        rule.src_zones = sorted(match.vlans) if match.vlans is not None else [ANY]
        rule.dst_zones = sorted(match.dvlans) if match.dvlans is not None else [ANY]
        if match.vlans is not None and not match.vlans:
            rule.src_zones = [ANY]
            rule.unsupported.append("no VLAN")
        rule.sources = list(match.src.members) if match.src is not None else [ANY]
        rule.destinations = list(match.dst.members) if match.dst is not None else [ANY]
        rule.services = self._services(match.svc)
        rule.schedule = schedule
        rule.unsupported += list(dict.fromkeys(match.problems + extra + (allow if action == Action.ALLOW else ())))
        rule.origin = name
        rule.log_end = entry.log if entry is not None else False
        if entry is not None:
            rule.description = entry.description
            rule.profiles = dict(entry.profiles)
            rule.handling = dict(entry.handling)
            rule.source_ids = {"f5afm.context": entry.context, "f5afm.policy": entry.policy, "f5afm.rule": "/".join(entry.path)}
            for severity, code, message in entry.findings:
                self.report.add("rule", name, severity, code, message)
        else:
            rule.description = "the default action" if name.endswith("(default)") else "what the virtual server takes and lets nothing through"
            rule.source_ids = {"f5afm.context": context or "default"}
        self.p.rules.append(rule)

    def _services(self, svc: _Svc) -> List[str]:
        if svc.proto is None:
            return [ANY]
        if svc.proto in _L4:
            protocol = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[svc.proto]
            if svc.sports is None and svc.parts and svc.dports is not None:
                names: List[str] = []
                for label, ranges in svc.parts:
                    entry = ServiceEntry(protocol, ports_text(ranges))
                    base = label if label else f"{protocol.value}-{ports_text(ranges)}"
                    if label and protocol != Protocol.TCP:
                        base = f"{label}-{protocol.value}"
                    names.append(self._service(base, [entry]))
                return transform.dedupe(names)
            entry = ServiceEntry(protocol, ports_text(svc.dports) if svc.dports is not None else "",
                                 ports_text(svc.sports) if svc.sports is not None else "")  # fmt: skip
            label = f"{protocol.value}-{entry.dst_ports or 'any'}" + (f"-from-{entry.src_ports}" if entry.src_ports else "")
            return [self._service(label, [entry])]
        if svc.proto in (1, 58):
            protocol = Protocol.ICMP if svc.proto == 1 else Protocol.ICMP6
            if svc.icmp is None:
                return [self._service(protocol.value, [ServiceEntry(protocol)])]
            entries = [ServiceEntry(protocol, icmp_type=kind, icmp_code=code) for kind, code in svc.icmp]
            label = protocol.value + "-" + "+".join(f"{kind}" + (f"-{code}" if code is not None else "") for kind, code in svc.icmp)
            return [self._service(label, entries)]
        return [self._service(f"ip-{svc.proto}", [ServiceEntry(Protocol.IP, ip_protocol=svc.proto)])]

    def _service(self, label: str, entries: List[ServiceEntry]) -> str:
        if len(label) > 60:
            label = label[:50] + f"~{len(self.p.services) + 1}"
        name, counter = label, 2
        while name in self.p.services and self.p.services[name].entries != entries:
            name = f"{label}~{counter}"
            counter += 1
        if name not in self.p.services:
            self.p.services[name] = Service(name, entries, "AFM: protocol and ports of a rule")
        return name

    def notes(self) -> None:
        if self.management:
            self.report.note(Severity.INFO, "F5AFM_MANAGEMENT_RULES",
                             "the rules of the management port (security firewall management-ip-rules) filter traffic to the BIG-IP "
                             "itself and are not converted")  # fmt: skip
        if self.route_domains_other():
            self.report.note(Severity.REVIEW, "F5AFM_ROUTE_DOMAINS",
                             "the BIG-IP has route domains other than 0. An address without a route domain (%ID) is read as matching "
                             "in every route domain, which is not confirmed; where the same addresses are used in several route "
                             "domains, a rule may match more here than on the BIG-IP")  # fmt: skip
        counts = [f"global context {len(self.levels[0])} rules", f"route domain contexts {len(self.levels[1])}",
                  f"virtual server contexts {sum(len(listener.entries) for listener in self.listeners)} rules for "
                  f"{sum(1 for listener in self.listeners if listener.policy)} virtual servers"]  # fmt: skip
        self.report.note(Severity.INFO, "F5AFM_CONTEXTS",
                         "read as one first-match list: " + "; ".join(counts) + f"; {len(self.p.rules)} rules of the model"
                         + (f", for {len(self.listeners)} virtual servers in the order the BIG-IP picks them" if self.listeners else ""))  # fmt: skip


def parse(data: bytes, report: Report, policy: str = "") -> Policy:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    text = text.replace("\r\n", "\n")
    stanzas = _stanzas(text)
    if not stanzas:
        raise ParseError("no tmsh stanza found: not the configuration of a BIG-IP")
    reader = _Reader(stanzas, report, policy)
    if not (reader.policies or reader.rule_lists or reader.address_lists or reader.global_rules is not None or reader.virtuals):
        raise ParseError("no firewall policy, rule list, address list or virtual server found: give FWShift the output of the "
                         "tmsh commands of the manual (section 3)")  # fmt: skip
    reader.objects()
    reader.contexts()
    reader.flatten()
    reader.notes()
    return reader.p
