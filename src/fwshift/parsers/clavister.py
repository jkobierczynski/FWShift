# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Clavister cOS Core parser: the configuration as a CLI script (what ``script -create`` writes, or ``add``/``set``/``cc``
commands as they are typed) -> neutral model.

The input is the CLI script, not the backup: a backup (``.bak``) is a packed file whose format Clavister does not
publish, while the CLI and its objects are documented object by object in the CLI Reference Guide, and ``script -create
[[<Category>] <Type> [<Identifier>]] [-name=<Name>]`` writes a configuration script of what it is given (CLI Reference
Guide 2.4.8). The script is fetched from the ``/script`` folder over SCP, or shown with ``script -show``.

How cOS Core decides, from Clavister's Administration Guide (14.00, 15.00) and CLI Reference Guide, and how it is mapped:

* **Rule sets.** ``main`` always exists and is searched first; other rule sets are reached only by a Goto rule
  (``GotoRule``), which jumps to the start of the named set. A Return rule (``ReturnRule``) resumes after the last Goto.
  "If the target set has no match, the connection is dropped", and a Return without a Goto drops. Folders
  (``IPRuleFolder``) only organise: the set is one flat list. A Goto becomes the rules of its set, each kept to what
  the Goto matches, in its place, followed by a rule that drops what the Goto matches (the end of the set). A Return
  that matches only some of that traffic cannot be said in one list: the rules after it that it may take traffic from,
  and the drop at the end, are reported (``CLAVISTER_RETURN``).
* **First match.** Entries are scanned top to bottom; "the first matching entry's action is then performed". What no
  entry matches is dropped without a log (the drop-all of the rule set; the model's default is DROP).
* **IP rules** (``IPRule``): ``Allow``, ``NAT`` (allow and translate the source, by default to the address of the
  outgoing interface), ``FwdFast`` (allow, stateless: the model is stateful, which is reported), ``Drop``, ``Reject``
  (a reset or ICMP error to the sender), ``SAT`` and ``SLB_SAT``. A SAT rule "only defines the translation"; cOS Core
  "does not terminate rule set lookups after finding a matching SAT rule", and the second rule, an Allow, NAT or FwdFast
  rule, "must trigger on the old, untranslated IP address"; the route lookup on the translated address comes after it
  (Administration Guide 14.00, 8.4). So a SAT rule is remembered and the next matching Allow, NAT or FwdFast rule
  completes it, with the addresses before translation. **Assumed** (from the older guides, not found in 14.00 or 15.00):
  of several matching SAT rules, the first one for each address (source, destination) is the one carried out, and a
  Drop or Reject rule after a SAT rule ends the lookup.
* **IP policies** (``IPPolicy``, 12.00 and later): Allow or Deny (``Reject=Yes`` answers the sender), with the
  translation in the policy itself (``SourceAddressTranslation`` None, NAT, SAT or Auto; ``DestAddressTranslation``
  None or SAT). ``StatelessPolicy`` is FwdFast.
* **Interfaces are the zones.** ``SourceInterface`` is the interface a packet arrives on; ``DestinationInterface`` the
  one the route lookup of the destination *before* translation gives: ``core`` for an address of the firewall itself.
  Interface groups are their members. The model names the zone a packet leaves by *after* translation, so the part of
  a rule that completes a SAT is a rule of its own, for the translated traffic only, with the zone the translated
  address is routed to (from the networks of the interfaces and the routes of the script); a rule to ``core`` that
  translates nothing is traffic to the firewall itself and is not converted.
* **Addresses** are those before translation in every rule, as in the model. The NAT rules of the model are built from
  the rules that complete translations, in the order of the rule set, with exemptions for allowing rules above them.
* **IPv6**: ``IP6Address``, ``IP6Group``, ``all-nets6``. An entry is IPv4 or IPv6, never both; NAT and SAT do not
  take IPv6.

Anything that narrows a match and is not modelled (users, application control, geolocation, a schedule, an ALG on a
service, an IP policy's inspection options) is reported; a field that is not understood makes its rule not converted,
never wider. Assumptions not confirmed on a device are listed in DEVELOPMENT.md and in the notes of the report.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
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
    Service,
    ServiceEntry,
    ServiceGroup,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, size
from ..netutil import intersect as intersect_intervals
from ..netutil import within as within_intervals
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_MAX_DEPTH = 16  # Goto rules inside rule sets reached by Goto rules
CORE = "core"
CATEGORIES = {"address", "interface", "service", "policy", "routing", "objects", "system", "user", "authentication"}
ADDRESS_TYPES = {"IP4Address", "IP6Address", "IP4Group", "IP6Group", "FQDNAddress", "FQDNGroup", "IP4HAAddress",
                 "IP6HAAddress", "EthernetAddress", "EthernetAddressGroup"}  # fmt: skip
INTERFACE_TYPES = {"Ethernet", "VLAN", "LoopbackInterface", "IPsecTunnel", "GRETunnel", "PPPoETunnel", "L2TPClient",
                   "L2TPServer", "PPTPClient", "PPTPServer", "SSLVPNInterface", "LinkAggregation", "IPIPTunnel",
                   "Bridge", "Wireless"}  # fmt: skip
SERVICE_TYPES = {"ServiceTCPUDP", "ServiceICMP", "ServiceICMPv6", "ServiceIPProto", "ServiceGroup"}
RULE_TYPES = {"IPRule", "IPPolicy", "StatelessPolicy", "GotoRule", "ReturnRule", "SLBPolicy", "MulticastPolicy",
              "FallbackPolicy", "ReverseProxyPolicy"}  # fmt: skip
# Objects every cOS Core has (Administration Guide 3.1, 3.2, 3.6.1).
PREDEFINED_ADDRESSES = {"all-nets": "0.0.0.0/0", "all-nets6": "::/0", "localhost": "127.0.0.1", "localhost6": "::1"}
# Predefined services as FWShift reads them where the script does not define them. **From memory of the default
# configuration, not confirmed**: a script that defines them is read as it says.
PREDEFINED_SERVICES: Dict[str, List[ServiceEntry]] = {
    "all_tcpudp": [ServiceEntry(Protocol.TCP), ServiceEntry(Protocol.UDP)],
    "all_tcp": [ServiceEntry(Protocol.TCP)],
    "all_udp": [ServiceEntry(Protocol.UDP)],
    "all_icmp": [ServiceEntry(Protocol.ICMP)],
    "all_icmpv6": [ServiceEntry(Protocol.ICMP6)],
    "http": [ServiceEntry(Protocol.TCP, "80")],
    "https": [ServiceEntry(Protocol.TCP, "443")],
    "http-all": [ServiceEntry(Protocol.TCP, "80,443")],
    "ssh": [ServiceEntry(Protocol.TCP, "22")],
    "telnet": [ServiceEntry(Protocol.TCP, "23")],
    "smtp": [ServiceEntry(Protocol.TCP, "25")],
    "dns-all": [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")],
    "ntp": [ServiceEntry(Protocol.UDP, "123")],
    "ping-inbound": [ServiceEntry(Protocol.ICMP, icmp_type=8)],
    "ping-outbound": [ServiceEntry(Protocol.ICMP, icmp_type=8)],
    "ping6-inbound": [ServiceEntry(Protocol.ICMP6, icmp_type=128)],
    "ping6-outbound": [ServiceEntry(Protocol.ICMP6, icmp_type=128)],
}
ALL_SERVICES = "all_services"
# ServiceICMP and ServiceICMPv6: the message types the CLI Reference Guide names, and their numbers (IANA).
ICMP_TYPES = {"EchoReply": 0, "DestinationUnreachable": 3, "SourceQuenching": 4, "Redirect": 5, "EchoRequest": 8,
              "TimeExceeded": 11, "ParameterProblem": 12}  # fmt: skip
ICMP6_TYPES = {"DestinationUnreachable": 1, "PacketTooBig": 2, "TimeExceeded": 3, "ParameterProblem": 4, "EchoRequest": 128,
               "EchoReply": 129}  # fmt: skip
_TRUE = {"yes", "true", "1", "on", "enable", "enabled"}
_FALSE = {"no", "false", "0", "off", "disable", "disabled"}
_PROMPT = re.compile(r"^[\w.@-]*:/[\w./-]*>\s*")
# Properties of a rule that are only identification, logging or what the model reads elsewhere.
_RULE_KNOWN = {"index", "name", "action", "sourceinterface", "destinationinterface", "sourcenetwork", "destinationnetwork",
               "service", "schedule", "logenabled", "logseverity", "comments", "attribute", "ruleset", "reject",
               "natsenderaddress", "nataction", "natpool", "sattranslate", "sattranslatetoip", "sattranslatetoport",
               "satalltoone", "sourceusergroup", "destinationusergroup", "appcontrol", "sourceaddresstranslation",
               "natsourceaddressaction", "satsourceaddressaction", "sourcenewip", "sourcebaseip", "sourcenatpool",
               "sourceportaction", "sourcenewsingleport", "sourcebaseport", "destaddresstranslation", "destaddressaction",
               "destnewip", "destbaseip", "destportaction", "destnewsingleport", "destbaseport", "drop"}  # fmt: skip
# Options of an IP policy that inspect traffic after the policy allowed it: reported, not converted.
_PROFILE_KEYS = {"antivirus": "anti-virus", "av_mode": "anti-virus", "webcontentfiltering": "web content filtering",
                 "wcf_mode": "web content filtering", "filecontrol": "file control", "fc_mode": "file control",
                 "emailcontrol": "email control", "idp": "IDP", "trafficshaping": "traffic shaping", "pipe": "traffic shaping",
                 "dnsfiltering": "DNS filtering", "ac_mode": "application control"}  # fmt: skip


def looks_like_clavister(data: bytes) -> bool:
    """A cOS Core script: add/set commands with the object types of cOS Core and its Name=Value properties."""
    text = data[:2_000_000].decode("utf-8", errors="replace")
    score = 0
    for line in text.splitlines()[:50000]:
        line = _PROMPT.sub("", line.strip())
        if re.match(r"(add|set) (Address )?(IP4Address|IP6Address|IP4Group|IP6Group)\b\s*\S*\s+\w+=", line):
            score += 1
        elif re.match(r"(add|set) (Service )?(ServiceTCPUDP|ServiceICMP|ServiceIPProto|ServiceGroup)\b", line):
            score += 1
        elif re.match(r"(add|set) (IPRule|IPPolicy|GotoRule|StatelessPolicy)\b.*\b(Action|SourceInterface|DestinationNetwork)=", line):
            score += 2
        elif re.match(r"cc (IPRuleSet|IPRuleFolder|AddressFolder|RoutingTable)\b", line):
            score += 2
        if score >= 3:
            return True
    return False


def split_words(text: str) -> List[str]:
    """Words of a command; ``Key="a b"`` and ``"a b"`` are one word, without the quotes; ``\\"`` and ``\\$`` are the
    characters themselves."""
    words: List[str] = []
    current: List[str] = []
    quoted = False
    started = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in '"$\\':
            current.append(text[index + 1])
            started = True
            index += 2
            continue
        if char == '"':
            quoted = not quoted
            started = True
        elif char.isspace() and not quoted:
            if started:
                words.append("".join(current))
                current, started = [], False
        else:
            current.append(char)
            started = True
        index += 1
    if started:
        words.append("".join(current))
    return words


# -- matches, as the parser and the emitter need them ---------------------------------------------------------------


@dataclass
class Match:
    """What an entry of a rule set matches: interfaces (expanded, [ANY] for any; ``core`` is the firewall), addresses
    before translation (members of the model), and one service (a name of the model, or ANY)."""

    src_if: List[str]
    dst_if: List[str]
    sources: List[str]
    destinations: List[str]
    service: str
    problems: List[str] = field(default_factory=list)


def _zones_and(a: List[str], b: List[str]) -> List[str]:
    if ANY in a:
        return list(b)
    if ANY in b:
        return list(a)
    return [z for z in a if z in b]


def zones_cover(outer: List[str], inner: List[str]) -> bool:
    return ANY in outer or (ANY not in inner and set(inner) <= set(outer))


def _intervals_of(p: Policy, members: List[str]) -> Optional[List[Interval]]:
    out: List[Interval] = []
    for member in members:
        found = transform.address_intervals(p, member)
        if found is None:
            return None
        out += found
    return normalize(out)


def _literal(interval: Interval) -> str:
    return interval_text(interval)


def addresses_and(p: Policy, a: List[str], b: List[str]) -> Tuple[Optional[List[str]], str]:
    """(the members for the addresses in both lists, or None when there are none; why it is not exact, or "")."""
    if ANY in a:
        return list(b), ""
    if ANY in b:
        return list(a), ""
    if a == b:
        return list(a), ""
    first, second = _intervals_of(p, a), _intervals_of(p, b)
    if first is None or second is None:
        return list(b), f"the addresses {', '.join(a)[:60]} and {', '.join(b)[:60]} cannot both be read"
    both = intersect_intervals(first, second)
    if not both:
        return None, ""
    if both == second:
        return list(b), ""
    if both == first:
        return list(a), ""
    return [_literal(i) for i in both], ""


def addresses_cover(p: Policy, outer: List[str], inner: List[str]) -> bool:
    if ANY in outer:
        return True
    if ANY in inner:
        return False
    if outer == inner:
        return True
    first, second = _intervals_of(p, outer), _intervals_of(p, inner)
    return first is not None and second is not None and within_intervals(second, first)


def _entry_covers(outer: ServiceEntry, inner: ServiceEntry) -> bool:
    if outer.protocol == Protocol.IP and outer.ip_protocol is None:
        return True
    if outer.protocol != inner.protocol:
        if outer.protocol == Protocol.IP and outer.ip_protocol is not None:
            numbers = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132, Protocol.ICMP: 1, Protocol.ICMP6: 58}
            return numbers.get(inner.protocol) == outer.ip_protocol
        return False
    if outer.protocol == Protocol.IP:
        return outer.ip_protocol == inner.ip_protocol
    if outer.protocol in (Protocol.ICMP, Protocol.ICMP6):
        if outer.icmp_type is None:
            return True
        return outer.icmp_type == inner.icmp_type and (outer.icmp_code is None or outer.icmp_code == inner.icmp_code)
    return _ports_cover(outer.dst_ports, inner.dst_ports) and _ports_cover(outer.src_ports, inner.src_ports)


def _ranges(ports: str) -> List[Tuple[int, int]]:
    if not ports:
        return [(0, 65535)]
    out = []
    for part in ports.split(","):
        first, _, last = part.partition("-")
        out.append((int(first), int(last or first)))
    return out


def _ports_cover(outer: str, inner: str) -> bool:
    return all(any(a <= c and d <= b for a, b in _ranges(outer)) for c, d in _ranges(inner))


def _ports_meet(a: str, b: str) -> bool:
    return any(x <= w and v <= y for x, y in _ranges(a) for v, w in _ranges(b))


def _entries_meet(a: ServiceEntry, b: ServiceEntry) -> bool:
    if _entry_covers(a, b) or _entry_covers(b, a):
        return True
    if a.protocol != b.protocol or a.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
        return False
    return _ports_meet(a.dst_ports, b.dst_ports) and _ports_meet(a.src_ports, b.src_ports)


def services_and(p: Policy, a: str, b: str) -> Tuple[Optional[str], str]:
    """(the service in both, None when none; why it is not exact, or "")."""
    if a == ANY:
        return b, ""
    if b == ANY or a == b:
        return a, ""
    first, second = transform.flatten_services(p, a), transform.flatten_services(p, b)
    if first is None or second is None:
        return b, f"the services {a} and {b} cannot both be read"
    if all(any(_entry_covers(o, i) for o in first) for i in second):
        return b, ""
    if all(any(_entry_covers(o, i) for o in second) for i in first):
        return a, ""
    if not any(_entries_meet(x, y) for x in first for y in second):
        return None, ""
    return b, f"the services {a} and {b} overlap in part, which one service of the model cannot say"


def services_cover(p: Policy, outer: str, inner: str) -> bool:
    if outer == ANY or outer == inner:
        return True
    if inner == ANY:
        return False
    first, second = transform.flatten_services(p, outer), transform.flatten_services(p, inner)
    return first is not None and second is not None and all(any(_entry_covers(o, i) for o in first) for i in second)


def match_and(p: Policy, a: Match, b: Match) -> Optional[Match]:
    """The traffic both match: None when there is none; ``problems`` say where that could not be worked out exactly."""
    src_if, dst_if = _zones_and(a.src_if, b.src_if), _zones_and(a.dst_if, b.dst_if)
    if not src_if or not dst_if:
        return None
    sources, why_s = addresses_and(p, a.sources, b.sources)
    destinations, why_d = addresses_and(p, a.destinations, b.destinations)
    service, why_v = services_and(p, a.service, b.service)
    if sources is None or destinations is None or service is None:
        return None
    problems = list(dict.fromkeys(a.problems + b.problems + [w for w in (why_s, why_d, why_v) if w]))
    return Match(src_if, dst_if, sources, destinations, service, problems)


def match_covers(p: Policy, outer: Match, inner: Match) -> bool:
    return (zones_cover(outer.src_if, inner.src_if) and zones_cover(outer.dst_if, inner.dst_if)
            and addresses_cover(p, outer.sources, inner.sources) and addresses_cover(p, outer.destinations, inner.destinations)
            and services_cover(p, outer.service, inner.service))  # fmt: skip


# -- reading the script ---------------------------------------------------------------------------------------------


@dataclass
class _Item:
    """An object of a rule set (a rule, a policy, a Goto, a folder) as the script left it."""

    type: str
    props: Dict[str, str]
    line: int
    enabled: bool = True
    children: List["_Item"] = field(default_factory=list)  # a folder's entries

    def get(self, key: str, default: str = "") -> str:
        return self.props.get(key.lower(), default)


@dataclass
class _Object:
    type: str
    name: str
    props: Dict[str, str]
    folder: str = ""


@dataclass
class _Sat:
    """A translation that waits for the rule that completes it."""

    name: str
    match: Match
    destination: bool  # translates the destination (else the source)
    translated: str  # the member of the model it translates to
    port: str
    post_zones: Optional[List[str]]  # where the translated destination is routed; None: not known
    problems: List[str]
    kind: str = "SAT"
    used: bool = False


@dataclass
class _Entry:
    kind: str  # allow, nat, fwdfast, drop, reject, sat, policy, stateless, unsupported
    match: Match
    item: Optional[_Item]
    name: str
    ruleset: str
    enabled: bool = True
    implicit: str = ""  # why the entry is not a rule of the script (the end of a rule set)
    findings: List[Tuple[Severity, str, str]] = field(default_factory=list)


class _Builder:
    def __init__(self, text: str, report: Report) -> None:
        self.text, self.report = text, report
        self.p = Policy(vendor="clavister", default_intrazone=Action.DROP, default_interzone=Action.DROP)
        self.objects: Dict[str, _Object] = {}
        self.interfaces: Dict[str, _Object] = {}
        self.if_groups: Dict[str, List[str]] = {}
        self.rulesets: Dict[str, List[_Item]] = {"main": []}
        self.routes: List[Tuple[str, str]] = []
        self.notes: Dict[str, List[str]] = {}
        self.names: Set[str] = set()
        self.referenced_if: List[str] = []
        self.alg: Dict[str, str] = {}
        self.service_flags: Dict[str, Dict[str, str]] = {}
        self.predefined_used: List[str] = []
        self.counter = 0

    def note(self, code: str, text: str) -> None:
        items = self.notes.setdefault(code, [])
        if text not in items:
            items.append(text)

    # -- commands -----------------------------------------------------------------------------------------------

    def _commands(self) -> List[Tuple[int, List[str]]]:
        out: List[Tuple[int, List[str]]] = []
        pending = ""
        start = 0
        joined = False  # the line before ended in a backslash
        for number, raw in enumerate(self.text.splitlines(), 1):
            if number > _MAX_LINES:
                raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
            stripped = raw.strip()
            if not stripped or (stripped.startswith("#") and not joined):
                joined = False
                continue
            stripped = _PROMPT.sub("", stripped)
            first = stripped.split(None, 1)[0] if stripped else ""
            # A property on a line of its own continues the command above (commands as the guides print them).
            if pending and (joined or (raw[:1].isspace() and "=" in first and not first.startswith("-"))):
                pending += " " + stripped
            else:
                if pending:
                    out.append((start, split_words(pending)))
                pending, start = stripped, number
            joined = pending.endswith("\\")
            if joined:
                pending = pending[:-1]
        if pending:
            out.append((start, split_words(pending)))
        return out

    def read(self) -> None:
        context: List[Tuple[str, str]] = []
        seen = False
        for number, words in self._commands():
            if not words:
                continue
            verb = words[0]
            if verb == "cc":
                context = self._cc(context, words[1:], number)
                continue
            if verb not in ("add", "set", "delete"):
                if verb not in ("activate", "commit", "script", "show", "echo"):
                    self.note("CLAVISTER_UNREAD", " ".join(words)[:80])
                continue
            rest = words[1:]
            if rest and rest[0].lower() in CATEGORIES and len(rest) > 1 and "=" not in rest[1] and not rest[1].startswith("-"):
                rest = rest[1:]
            if not rest:
                continue
            kind = rest[0]
            identifier = ""
            props: Dict[str, str] = {}
            flags: Set[str] = set()
            for word in rest[1:]:
                if word.startswith("-") and "=" not in word:
                    flags.add(word.lower())
                elif "=" in word:
                    key, _, value = word.partition("=")
                    props[key.lower()] = value
                elif not identifier:
                    identifier = word
                else:
                    self.note("CLAVISTER_UNREAD", " ".join(words)[:80])
            if not identifier and "name" in props and kind not in RULE_TYPES and kind != "IPRuleFolder":
                identifier = props["name"]
            seen = self._object(verb, kind, identifier, props, flags, context, number) or seen
        if not seen:
            raise ParseError("no address, service, interface or rule objects: not a CLI script of a cOS Core firewall")

    def _cc(self, context: List[Tuple[str, str]], words: List[str], number: int) -> List[Tuple[str, str]]:
        if not words or words[0] == "/":
            return []
        if words[0] == "..":
            return context[:-1]
        if words[0].startswith("-"):
            return context
        if words[0].lower() in CATEGORIES and len(words) > 1:
            words = words[1:]
        if len(words) < 2:
            self.note("CLAVISTER_UNREAD", "cc " + " ".join(words)[:60])
            return context
        kind, identifier = words[0], words[1]
        if kind == "IPRuleSet":
            self.rulesets.setdefault(identifier, [])
            return [(kind, identifier)]
        if kind == "IPRuleFolder":
            if not context or context[-1][0] not in ("IPRuleSet", "IPRuleFolder"):
                context = [("IPRuleSet", "main")]
            return context + [(kind, identifier)]
        if kind in ("AddressFolder", "RoutingTable"):
            return context + [(kind, identifier)] if kind == "AddressFolder" else [(kind, identifier)]
        self.note("CLAVISTER_UNREAD", "cc " + " ".join(words)[:60])
        return context + [(kind, identifier)]

    def _list(self, context: List[Tuple[str, str]], number: int) -> Optional[List[_Item]]:
        """The list the rule set entries of the current context go into (a rule set, or a folder of one)."""
        ruleset = "main"
        folders: List[str] = []
        for kind, identifier in context:
            if kind == "IPRuleSet":
                ruleset = identifier
            elif kind == "IPRuleFolder":
                folders.append(identifier)
            elif kind in ("AddressFolder", "RoutingTable"):
                return None
        items = self.rulesets.setdefault(ruleset, [])
        for folder in folders:
            found = _find(items, "IPRuleFolder", folder)
            if found is None:
                self.note("CLAVISTER_UNREAD", f"a folder '{folder[:30]}' that was not created first (line {number})")
                return None
            items = found.children
        return items

    def _object(self, verb: str, kind: str, identifier: str, props: Dict[str, str], flags: Set[str],
                context: List[Tuple[str, str]], number: int) -> bool:  # fmt: skip
        enabled: Optional[bool] = False if flags & {"-disable", "-disabled"} else (True if "-enable" in flags else None)
        if kind in RULE_TYPES or kind == "IPRuleFolder":
            items = self._list(context, number)
            if items is None:
                return False
            if verb == "delete":
                found = _find(items, kind, identifier)
                if found is not None:
                    items.remove(found)
                return True
            if verb == "set":
                found = _find(items, kind, identifier)
                if found is None:
                    self.note("CLAVISTER_UNREAD", f"set {kind} {identifier[:20]} of an entry that was not added (line {number})")
                    return True
                found.props.update(props)
                if enabled is not None:
                    found.enabled = enabled
                if "index" in props and props["index"].isdigit():
                    items.remove(found)
                    items.insert(max(0, int(props["index"]) - 1), found)
                return True
            item = _Item(kind, dict(props), number, enabled is not False)
            if identifier and "name" not in item.props:
                item.props["name"] = identifier
            index = props.get("index", "")
            if index.isdigit() and 0 < int(index) <= len(items):
                items.insert(int(index) - 1, item)
            else:
                items.append(item)
            return True
        if kind == "IPRuleSet":
            if identifier:
                self.rulesets.setdefault(identifier, [])
            return True
        if kind in ("Route", "Route6"):
            interface, network = props.get("interface", ""), props.get("network", "")
            if interface and network and verb == "add":
                self.routes.append((interface, network))
            return False
        if kind in ADDRESS_TYPES or kind == "AddressFolder" or kind in INTERFACE_TYPES or kind == "InterfaceGroup" or kind in SERVICE_TYPES:
            if not identifier:
                self.note("CLAVISTER_UNREAD", f"{verb} {kind} without a name (line {number})")
                return False
            if kind == "AddressFolder":
                return False
            folder = "/".join(i for k, i in context if k == "AddressFolder")
            if verb == "delete":
                self.objects.pop(identifier, None)
                self.interfaces.pop(identifier, None)
                self.if_groups.pop(identifier, None)
                return True
            if kind in INTERFACE_TYPES:
                existing = self.interfaces.get(identifier)
                if existing is not None and verb == "set":
                    existing.props.update(props)
                else:
                    self.interfaces[identifier] = _Object(kind, identifier, dict(props))
                return True
            if kind == "InterfaceGroup":
                members = props.get("members")
                if members is not None or identifier not in self.if_groups:
                    self.if_groups[identifier] = _split(members or "")
                if props.get("equivalent", "").lower() in _TRUE:
                    self.note("CLAVISTER_EQUIVALENT", identifier)
                return True
            key = identifier.split("/")[-1] if "/" in identifier else identifier
            if "/" in identifier and not folder:
                folder = identifier.rsplit("/", 1)[0]
            existing_object = self.objects.get(key)
            if existing_object is not None and verb == "set":
                existing_object.props.update(props)
            else:
                if existing_object is not None and existing_object.folder != folder:
                    self.note("CLAVISTER_SAME_NAME", key)
                self.objects[key] = _Object(kind, key, dict(props), folder)
            return True
        if kind in ("ARP", "ARPPublish", "NATPool", "ScheduleProfile", "Schedule", "RemoteMgmtSSH", "RemoteMgmtHTTP",
                    "RemoteMgmtSNMP", "RoutingTable", "DHCPServer", "IPsecTunnel", "SAT", "Pipe", "PipeRule"):  # fmt: skip
            return False
        if verb != "set":
            self.note("CLAVISTER_NOT_READ", kind)
        return False

    # -- objects ------------------------------------------------------------------------------------------------

    def _build_objects(self) -> None:
        for name, obj in self.objects.items():
            if obj.type in SERVICE_TYPES:
                self._service(obj)
            else:
                self._address(obj)

    def _address(self, obj: _Object) -> None:
        name, kind, props = obj.name, obj.type, obj.props
        description = props.get("comments", "")
        if props.get("userauthgroups") or props.get("noauthgroups"):
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description,
                                             raw="an address for authenticated users only (UserAuthGroups)")  # fmt: skip
            return
        if kind in ("IP4Group", "IP6Group", "FQDNGroup"):
            listed = _split(props.get("members", ""))
            self.p.address_groups[name] = AddressGroup(name, listed, description)
            if not listed:
                self.p.address_groups[name].unsupported = "an empty group"
            return
        if kind == "FQDNAddress":
            value = props.get("address", "")
            if not value:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description, raw="an FQDN address without a name")
            else:
                self.p.addresses[name] = Address(name, AddressKind.FQDN, value, description, fqdn_family=4)
                self.note("CLAVISTER_FQDN", name)
            return
        if kind not in ("IP4Address", "IP6Address"):
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description, raw=f"{kind}, which is not converted")
            return
        family = 4 if kind == "IP4Address" else 6
        values = _split(props.get("address", ""))
        members: List[Tuple[AddressKind, str]] = []
        for value in values:
            interval = parse_literal(value.replace(" ", ""))
            if interval is None or interval[0] != family:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description,
                                                 raw=f"{kind} with the address '{value[:40]}', which cannot be read")  # fmt: skip
                return
            text = value.replace(" ", "")
            if "-" in text:
                members.append((AddressKind.RANGE, f"{ipaddress.ip_address(text.split('-')[0])}-{ipaddress.ip_address(text.split('-')[1])}"))
            else:
                members.append((AddressKind.NETWORK, str(ipaddress.ip_network(text, strict=False))))
        if not members:
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description, raw=f"{kind} without an address")
            return
        if len(members) == 1:
            self.p.addresses[name] = Address(name, members[0][0], members[0][1], description)
            return
        names = []
        for index, (member_kind, value) in enumerate(members, 1):
            member = f"{name}#{index}"
            self.p.addresses[member] = Address(member, member_kind, value)
            names.append(member)
        self.p.address_groups[name] = AddressGroup(name, names, description or f"{kind} with a list of addresses")

    def _service(self, obj: _Object) -> None:
        name, kind, props = obj.name, obj.type, obj.props
        description = props.get("comments", "")
        if props.get("alg"):
            self.alg[name] = props["alg"]
        if props.get("protocol"):
            self.alg.setdefault(name, "protocol " + props["protocol"])
        if kind == "ServiceGroup":
            members = _split(props.get("members", ""))
            self.p.service_groups[name] = ServiceGroup(name, members, description)
            return
        service = Service(name, description=description)
        self.p.services[name] = service
        if kind == "ServiceTCPUDP":
            types = {"TCP": [Protocol.TCP], "UDP": [Protocol.UDP], "TCPUDP": [Protocol.TCP, Protocol.UDP]}
            kind_text = props.get("type", "TCP").upper().replace("/", "")
            if kind_text not in types:
                service.unsupported = f"type '{props.get('type', '')[:20]}' cannot be read"
                return
            if "destinationports" not in props:
                service.unsupported = "no destination ports"
                return
            dst, src = _ports(props["destinationports"]), _ports(props.get("sourceports", "0-65535"))
            if dst is None or src is None:
                service.unsupported = "ports that cannot be read"
                return
            service.entries = [ServiceEntry(protocol, dst, src) for protocol in types[kind_text]]
            return
        if kind in ("ServiceICMP", "ServiceICMPv6"):
            protocol, table = (Protocol.ICMP, ICMP_TYPES) if kind == "ServiceICMP" else (Protocol.ICMP6, ICMP6_TYPES)
            if props.get("messagetypes", "All").lower() == "all":
                service.entries = [ServiceEntry(protocol)]
                return
            for key in props:
                base = next((t for t in table if t.lower() == key), None)
                if base is None and key.endswith("codes"):
                    continue
                if base is None and key not in ("messagetypes", "comments", "alg", "forwardicmperrors", "enableipv4pathmtudiscovery",
                                                "passicmpreturn", "maxsessions", "usecustomtimeouts", "initialtimeout",
                                                "establishtimeout", "closingtimeout", "attribute", "name"):  # fmt: skip
                    service.unsupported = f"the ICMP property '{key[:30]}', which FWShift does not read"
                    return
            for type_name, number in table.items():
                if props.get(type_name.lower(), "no").lower() not in _TRUE:
                    continue
                codes = props.get(type_name.lower() + "codes", "0-255").replace(" ", "")
                if codes in ("0-255", ""):
                    service.entries.append(ServiceEntry(protocol, icmp_type=number))
                    continue
                parsed = _ports(codes, 255)
                if parsed is None:
                    service.unsupported = f"ICMP codes '{codes[:20]}' cannot be read"
                    return
                values = [n for part in parsed.split(",") for n in _expand(part)]
                if len(values) > 32:
                    service.unsupported = f"more than 32 single ICMP codes ({codes[:20]})"
                    return
                service.entries += [ServiceEntry(protocol, icmp_type=number, icmp_code=code) for code in values]
            if not service.entries:
                service.unsupported = "an ICMP service without a message type"
            return
        if kind == "ServiceIPProto":
            text = props.get("ipproto", "0-255").replace(" ", "")
            parsed = _ports(text, 255)
            if parsed is None:
                service.unsupported = f"IP protocols '{text[:20]}' cannot be read"
                return
            if parsed == "":
                service.entries = [ServiceEntry(Protocol.IP)]
                return
            numbers = [n for part in parsed.split(",") for n in _expand(part)]
            service.entries = [ServiceEntry(Protocol.IP, ip_protocol=n) for n in numbers]
            return

    def _resolve_service(self, name: str, problems: List[str]) -> str:
        if not name:
            problems.append("no Service")
            return ANY
        if name == ALL_SERVICES:
            return ANY
        if name in self.p.services or name in self.p.service_groups:
            self._check_service_members(name)
            return name
        if name in PREDEFINED_SERVICES:
            self.p.services[name] = Service(name, list(PREDEFINED_SERVICES[name]), "predefined service of cOS Core", builtin="clavister")
            if name not in self.predefined_used:
                self.predefined_used.append(name)
            return name
        self.p.services[name] = Service(name, unsupported="a service that is not in the script")
        self.note("CLAVISTER_MISSING_OBJECT", name)
        return name

    def _check_service_members(self, name: str, seen: Tuple[str, ...] = ()) -> None:
        group = self.p.service_groups.get(name)
        if group is None or name in seen:
            return
        for member in group.members:
            if member not in self.p.services and member not in self.p.service_groups:
                self._resolve_service(member, [])
            self._check_service_members(member, seen + (name,))

    def _resolve_address(self, text: str, problems: List[str]) -> List[str]:
        """The members of the model for a SourceNetwork or DestinationNetwork value."""
        if not text:
            problems.append("no network")
            return [ANY]
        out: List[str] = []
        for value in _split(text):
            out.append(self._address_member(value))
        return out

    def _address_member(self, value: str) -> str:
        if value in self.p.addresses or value in self.p.address_groups:
            self._check_group_members(value)
            return value
        if "/" in value and parse_literal(value) is None:
            short = value.split("/")[-1]
            if short in self.p.addresses or short in self.p.address_groups:
                self._check_group_members(short)
                return short
        if value in PREDEFINED_ADDRESSES:
            literal = PREDEFINED_ADDRESSES[value]
            if literal in (ANY_V4, ANY_V6):
                return literal
            self.p.addresses[value] = Address(value, AddressKind.NETWORK, literal + ("/32" if ":" not in literal else "/128"),
                                              "predefined address of cOS Core", builtin="clavister")  # fmt: skip
            return value
        interval = parse_literal(value)
        if interval is not None:
            return interval_text(interval) if "-" in value else str(ipaddress.ip_network(value, strict=False))
        name = value.split("/")[-1] if "/" in value else value
        self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw="an address that is not in the script")
        self.note("CLAVISTER_MISSING_OBJECT", value)
        return name

    def _check_group_members(self, name: str, seen: Tuple[str, ...] = ()) -> None:
        group = self.p.address_groups.get(name)
        if group is None or name in seen:
            return
        group.members = [self._address_member(m) if m not in self.p.addresses and m not in self.p.address_groups else m
                         for m in group.members]  # fmt: skip
        for member in group.members:
            self._check_group_members(member, seen + (name,))

    def _interfaces(self, text: str, problems: List[str], source: bool) -> List[str]:
        if not text:
            problems.append("no " + ("SourceInterface" if source else "DestinationInterface"))
            return [ANY]
        out: List[str] = []
        for value in _split(text):
            if value == ANY:
                return [ANY]
            if value == CORE and source:
                problems.append("traffic from the firewall itself (core as the source interface)")
            out += self._expand_interface(value, ())
        return list(dict.fromkeys(out))

    def _expand_interface(self, name: str, seen: Tuple[str, ...]) -> List[str]:
        if name in self.if_groups and name not in seen:
            out: List[str] = []
            for member in self.if_groups[name]:
                out += self._expand_interface(member, seen + (name,))
            return out
        if name != CORE and name not in self.referenced_if:
            self.referenced_if.append(name)
        return [name]

    # -- zones and networks -------------------------------------------------------------------------------------

    def _network_of(self, value: str) -> List[Interval]:
        if not value:
            return []
        if value in PREDEFINED_ADDRESSES:
            interval = parse_literal(PREDEFINED_ADDRESSES[value])
            return [interval] if interval else []
        member = self._address_member(value) if value not in self.p.addresses else value
        found = transform.address_intervals(self.p, member)
        return found or []

    def _zones(self) -> None:
        names = list(self.interfaces)
        for name in self.referenced_if:
            if name not in names:
                names.append(name)
        missing = [n for n in self.referenced_if if n not in self.interfaces]
        if missing and self.interfaces:
            self.note("CLAVISTER_INTERFACE_UNKNOWN", ", ".join(missing[:8]))
        self.networks: List[Tuple[Interval, str]] = []
        self.addresses_of: List[Tuple[Interval, str]] = []
        for name in names:
            self.p.zones[name] = Zone(name, [name])
            obj = self.interfaces.get(name)
            if obj is None:
                continue
            nets: List[str] = []
            for key in ("network", "ipv6network"):
                for interval in self._network_of(obj.props.get(key, "")):
                    self.networks.append((interval, name))
                    nets.append(interval_text(interval))
            for key in ("ip", "ipv6ip"):
                for interval in self._network_of(obj.props.get(key, "")):
                    self.addresses_of.append((interval, name))
            if nets:
                self.p.zone_networks[name] = nets
        for interface, network in self.routes:
            for interval in self._network_of(network):
                if interface == CORE:
                    self.addresses_of.append((interval, CORE))  # (a core route: an address of the firewall itself)
                    continue
                self.networks.append((interval, interface))
                if interface in self.p.zones and interval not in (FULL_V4, FULL_V6):
                    self.p.zone_networks.setdefault(interface, []).append(interval_text(interval))

    def routed_to(self, member: str) -> Optional[List[str]]:
        """The zone the addresses of a member are routed to (the longest network of an interface or a route that holds
        them all); None when that cannot be told."""
        found = transform.address_intervals(self.p, member)
        if not found:
            return None
        zones: List[str] = []
        for interval in found:
            best: Optional[Tuple[int, str]] = None
            for network, zone in self.networks:
                if network[0] == interval[0] and network[1] <= interval[1] and interval[2] <= network[2]:
                    if best is None or size(network) < best[0]:
                        best = (size(network), zone)
            if best is None or best[1] not in self.p.zones:
                return None
            zones.append(best[1])
        return list(dict.fromkeys(zones))

    def _arrival(self, members: List[str]) -> Optional[List[str]]:
        """The interfaces the route lookup before translation gives for these destinations (core for an address of the
        firewall); None when that cannot be told."""
        found = _intervals_of(self.p, members)
        if not found:
            return None
        out: List[str] = []
        for interval in found:
            if any(a[0] == interval[0] and a[1] <= interval[1] and interval[2] <= a[2] for a, _ in self.addresses_of):
                if not all(any(a[0] == interval[0] and a[1] == a[2] == x for a, _ in self.addresses_of)
                           for x in range(interval[1], min(interval[2], interval[1] + 256) + 1)) or size(interval) > 256:  # fmt: skip
                    return None
                out.append(CORE)
                continue
            if any(a[0] == interval[0] and interval[1] <= a[1] <= interval[2] for a, _ in self.addresses_of):
                return None  # (some of them are the firewall's own)
            zones = self.routed_to(interval_text(interval))
            if zones is None:
                return None
            out += zones
        return list(dict.fromkeys(out))

    def _owner(self, members: List[str]) -> Optional[str]:
        """The interface whose own address is the destination (traffic to core)."""
        for member in members:
            found = transform.address_intervals(self.p, member) or []
            for interval in found:
                for address, zone in self.addresses_of:
                    if address[0] == interval[0] and interval[1] <= address[1] and address[2] <= interval[2] and zone != CORE:
                        return zone
        return None

    # -- rule sets ----------------------------------------------------------------------------------------------

    def _unique(self, base: str) -> str:
        base = base or "rule"
        name, counter = base, 2
        while name in self.names:
            name = f"{base}-{counter}"
            counter += 1
        self.names.add(name)
        return name

    def _match_of(self, item: _Item) -> Match:
        problems: List[str] = []
        src_if = self._interfaces(item.get("sourceinterface"), problems, True)
        dst_if = self._interfaces(item.get("destinationinterface"), problems, False)
        sources = self._resolve_address(item.get("sourcenetwork"), problems)
        destinations = self._resolve_address(item.get("destinationnetwork"), problems)
        service = self._resolve_service(item.get("service"), problems) if item.type != "ReturnRule" or item.get("service") else ANY
        if len(sources) > 1 or len(destinations) > 1:
            pass  # (a list of networks in one value: read as its members)
        return Match(src_if, dst_if, sources, destinations, service, problems)

    @staticmethod
    def _flat(items: List[_Item]) -> List[_Item]:
        out: List[_Item] = []
        for item in items:
            if item.type == "IPRuleFolder":
                if item.enabled:
                    out += _Builder._flat(item.children)
            else:
                out.append(item)
        return out

    def _expand(self, ruleset: str, restriction: Optional[Match], via: str, stack: Tuple[str, ...]) -> List[_Entry]:
        entries: List[_Entry] = []
        returned: Optional[Match] = None  # a Return that takes some of this traffic back
        stopped = False
        for position, item in enumerate(self._flat(self.rulesets.get(ruleset, [])), 1):
            label = item.get("name") or f"{ruleset}-{position}"
            name = self._unique(f"{via}/{label}" if via else label)
            own = self._match_of(item)
            match = own if restriction is None else match_and(self.p, restriction, own)
            if stopped or match is None:
                why = ("after a Return that takes back all the traffic the Goto sends here: never reached" if stopped else
                       f"matches none of the traffic the Goto rule {via} sends to rule set {ruleset}: never reached")  # fmt: skip
                unreached = self._entry(item, own, name, ruleset) if item.type not in ("GotoRule", "ReturnRule") else \
                    _Entry("unsupported", own, item, name, ruleset)
                unreached.enabled = False
                unreached.findings.append((Severity.INFO, "CLAVISTER_UNREACHED", why))
                if item.type != "ReturnRule":
                    entries.append(unreached)
                continue
            if returned is not None and _meets(self.p, returned, match):
                match.problems.append("a Return rule above it in the rule set sends some of this traffic back to the rule set "
                                      "that called it, which one list of rules cannot say")  # fmt: skip
            if item.type == "GotoRule":
                if not item.enabled:
                    entries.append(_Entry("unsupported", own, item, name, ruleset, False,
                                          findings=[(Severity.INFO, "CLAVISTER_GOTO_DISABLED", "a disabled Goto rule")]))  # fmt: skip
                    continue
                target = item.get("ruleset")
                if target not in self.rulesets or target == "main" or target in stack or len(stack) > _MAX_DEPTH:
                    why = ("a Goto to the main rule set" if target == "main" else
                           "a Goto into a loop of rule sets" if target in stack or len(stack) > _MAX_DEPTH else
                           f"a Goto to the rule set '{target[:30]}', which is not in the script")  # fmt: skip
                    match.problems.append(why)
                    entries.append(_Entry("drop", match, item, name, ruleset))
                    continue
                entries += self._expand(target, match, name, stack + (target,))
                continue
            if item.type == "ReturnRule":
                if not item.enabled:
                    continue
                if not via:
                    entries.append(_Entry("drop", match, item, name, ruleset, findings=[(Severity.INFO, "CLAVISTER_RETURN_MAIN",
                                          "a Return rule in the main rule set: what it matches is dropped")]))  # fmt: skip
                    continue
                if restriction is not None and match_covers(self.p, own, restriction) and not own.problems:
                    stopped = True
                else:
                    returned = match if returned is None else returned
                continue
            entries.append(self._entry(item, match, name, ruleset))
        if restriction is not None and not stopped:
            end = dataclasses.replace(restriction, problems=[])
            findings = [(Severity.INFO, "CLAVISTER_GOTO_END", f"what no rule of the rule set {ruleset} matches is dropped (the end "
                         "of a rule set reached by a Goto rule)")]  # fmt: skip
            if returned is not None:
                findings.append((Severity.REVIEW, "CLAVISTER_RETURN", "a Return rule in the rule set sends some of this traffic "
                                 "back to the rule set that called it; here it is dropped, which is narrower than the source"))  # fmt: skip
            entries.append(_Entry("drop", end, None, self._unique(f"{via}/end"), ruleset, implicit="the end of a rule set",
                                  findings=findings))  # fmt: skip
        return entries

    def _entry(self, item: _Item, match: Match, name: str, ruleset: str) -> _Entry:
        kind = item.type
        if kind == "IPRule":
            action = item.get("action").lower()
            known = {"allow": "allow", "nat": "nat", "fwdfast": "fwdfast", "drop": "drop", "reject": "reject", "sat": "sat",
                     "slb_sat": "slbsat", "slbsat": "slbsat", "multiplexsat": "unsupported", "multiplex_sat": "unsupported"}  # fmt: skip
            if action not in known:
                match.problems.append(f"action '{item.get('action')[:20]}' cannot be read" if action else "no Action")
                return _Entry("unsupported", match, item, name, ruleset, item.enabled)
            if known[action] == "unsupported":
                match.problems.append("a Multiplex SAT rule (multicast), which is not converted")
            return _Entry(known[action], match, item, name, ruleset, item.enabled)
        if kind in ("IPPolicy", "StatelessPolicy"):
            return _Entry("policy" if kind == "IPPolicy" else "stateless", match, item, name, ruleset, item.enabled)
        match.problems.append(f"a {kind}, which is not converted")
        return _Entry("unsupported", match, item, name, ruleset, item.enabled)

    # -- the walk: rules and NAT --------------------------------------------------------------------------------

    def _rule(self, entry: _Entry, name: str, match: Match, dst_zones: List[str], action: Action) -> Rule:
        item = entry.item
        rule = Rule(name, src_zones=list(match.src_if), dst_zones=list(dst_zones), sources=list(match.sources),
                    destinations=list(match.destinations), services=[match.service], action=action)  # fmt: skip
        rule.origin = name
        rule.enabled = entry.enabled
        problems = list(match.problems)
        if item is not None:
            log = item.get("logenabled", "Yes").lower() not in _FALSE
            rule.log_start, rule.log_end = False, log
            rule.description = item.get("comments")
            rule.source_ids = {"clavister.ruleset": entry.ruleset}
            if item.get("name"):
                rule.source_ids["clavister.name"] = item.get("name")
            if item.get("schedule"):
                rule.schedule = item.get("schedule")
            if item.get("sourceusergroup"):
                rule.users = _split(item.get("sourceusergroup"))
            if item.get("destinationusergroup"):
                problems.append(f"destination user group {item.get('destinationusergroup')[:30]}")
            if item.get("appcontrol").lower() in _TRUE:
                problems.append("application control (AppControl=Yes)")
            for key in ("sourcegeofilter", "destinationgeofilter"):
                if item.get(key):
                    problems.append(f"a geolocation filter ({key} {item.get(key)[:30]})")
            for key, label in _PROFILE_KEYS.items():
                value = item.get(key)
                if value and value.lower() not in _FALSE and value.lower() not in ("none", "off"):
                    rule.profiles[label] = value
            for key, value in item.props.items():
                if key not in _RULE_KNOWN and key not in _PROFILE_KEYS and key not in ("sourcegeofilter", "destinationgeofilter"):
                    rule.handling[key] = value
            if match.service in self.alg:
                rule.profiles["alg"] = f"{match.service}: {self.alg[match.service]}"
        else:
            rule.log_end = False
        rule.unsupported = list(dict.fromkeys(problems))
        return rule

    def _sat_of(self, entry: _Entry, match: Match) -> _Sat:
        item = entry.item
        assert item is not None
        problems: List[str] = []
        destination = item.get("sattranslate", "DestinationIP").lower() != "sourceip"
        target = item.get("sattranslatetoip")
        if not target:
            problems.append("no SATTranslateToIP")
            target = "0.0.0.0"
        translated = self._address_member(target)
        all_to_one = item.get("satalltoone", "No").lower() in _TRUE
        port = item.get("sattranslatetoport")
        if entry.kind == "slbsat":
            problems.append("SLB SAT (server load balancing over several servers), which is not converted")
        return self._make_sat(entry.name, match, destination, translated, all_to_one, port, problems)

    def _make_sat(self, name: str, match: Match, destination: bool, translated: str, all_to_one: bool, port: str,
                  problems: List[str]) -> _Sat:  # fmt: skip
        original = match.destinations if destination else match.sources
        before = _intervals_of(self.p, original)
        after = transform.address_intervals(self.p, translated)
        if not after or len(after) != 1 or size(after[0]) != 1:
            problems.append(f"the address it translates to ({translated[:40]}) is not one address")
        elif after[0][0] == 6 or (before and any(i[0] == 6 for i in before)):
            problems.append("SAT of IPv6, which cOS Core does not do")
        elif before is None:
            problems.append("the addresses it translates cannot be read")
        elif not all_to_one and size(after[0]) == 1 and sum(size(i) for i in before) > 1 and destination:
            if len(before) != 1 or before[0] in (FULL_V4,):
                problems.append("a many-to-many translation (transposed) of several ranges")
            else:
                first = after[0][1]
                translated = interval_text((4, first, first + size(before[0]) - 1))
                if first + size(before[0]) - 1 > 2**32 - 1:
                    problems.append("a transposed translation beyond the end of the IPv4 addresses")
        if port:
            if not port.isdigit() or not 0 < int(port) <= 65535:
                problems.append(f"SATTranslateToPort '{port[:20]}' cannot be read")
                port = ""
            else:
                entries = transform.flatten_services(self.p, match.service) if match.service != ANY else None
                ports = {e.dst_ports for e in entries or []}
                if not entries or len(ports) != 1 or not re.fullmatch(r"\d+", next(iter(ports))):
                    problems.append("a port translation of a service that is not one single port (a range is moved as a "
                                    "block, which the model cannot say)")  # fmt: skip
        post = self.routed_to(translated) if destination else None
        return _Sat(name, match, destination, translated, port, post, problems)

    def _policy_sats(self, entry: _Entry, match: Match) -> List[_Sat]:
        item = entry.item
        assert item is not None
        out: List[_Sat] = []
        if item.get("destaddresstranslation", "None").lower() == "sat":
            problems: List[str] = []
            action = item.get("destaddressaction", "SingleIP").lower()
            target = item.get("destnewip") if action != "transposed" else item.get("destbaseip")
            if not target:
                problems.append("no DestNewIP")
                target = "0.0.0.0"
            port = ""
            port_action = item.get("destportaction", "None").lower()
            if port_action in ("singleport", "single"):
                port = item.get("destnewsingleport")
            elif port_action not in ("none", ""):
                problems.append(f"DestPortAction {item.get('destportaction')[:20]} (the port range moved as a block)")
            out.append(self._make_sat(entry.name, match, True, self._address_member(target), action != "transposed", port, problems))
        if item.get("sourceaddresstranslation", "None").lower() == "sat":
            problems = []
            action = item.get("satsourceaddressaction", "SingleIP").lower()
            target = item.get("sourcenewip") if action != "transposed" else item.get("sourcebaseip")
            if not target:
                problems.append("no SourceNewIP")
                target = "0.0.0.0"
            if action == "transposed":
                problems.append("a transposed source translation")
            out.append(self._make_sat(entry.name, match, False, self._address_member(target), True, "", problems))
        return out

    def _source_nat(self, entry: _Entry, dst_if: List[str], problems: List[str]) -> Optional[SourceNat]:
        """The source translation of an entry that allows and translates the source (NAT, or an IP policy with NAT)."""
        item = entry.item
        assert item is not None
        interface = dst_if[0] if len(dst_if) == 1 and dst_if[0] not in (ANY, CORE) else ""
        known = self.interfaces.get(interface)
        address = ""
        if known is not None:
            found = self._network_of(known.props.get("ip", ""))
            address = interval_text(found[0]) if len(found) == 1 and size(found[0]) == 1 else ""
        if entry.kind == "nat":
            action = item.get("nataction", "UseInterfaceAddress").lower()
            if item.get("natpool"):
                problems.append(f"NAT pool {item.get('natpool')[:30]}, which is not converted")
                return SourceNat(SnatKind.DYNAMIC_PORT, [])
            if action in ("useinterfaceaddress", "interfaceaddress", "interface"):
                return SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=address)
            sender = item.get("natsenderaddress")
            if not sender:
                problems.append(f"NATAction {item.get('nataction')[:30]} without NATSenderAddress")
                return SourceNat(SnatKind.DYNAMIC_PORT, [])
            return SourceNat(SnatKind.DYNAMIC_PORT, [self._address_member(sender)])
        kind = item.get("sourceaddresstranslation", "None").lower()
        if kind == "auto":
            problems.append("SourceAddressTranslation Auto (NAT or none, chosen by whether the addresses are private)")
            return SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=address)
        action = item.get("natsourceaddressaction", "OutgoingInterfaceIP").lower()
        if action in ("outgoinginterfaceip", "interfaceaddress"):
            return SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=address)
        if action in ("natpool", "pool") or item.get("sourcenatpool"):
            problems.append(f"NAT pool {item.get('sourcenatpool')[:30]}, which is not converted")
            return SourceNat(SnatKind.DYNAMIC_PORT, [])
        new = item.get("sourcenewip")
        if not new:
            problems.append(f"NATSourceAddressAction {item.get('natsourceaddressaction')[:30]} without SourceNewIP")
            return SourceNat(SnatKind.DYNAMIC_PORT, [])
        return SourceNat(SnatKind.DYNAMIC_PORT, [self._address_member(new)])

    def _verdict(self, entry: _Entry) -> Tuple[Action, bool, bool]:
        """(action, whether it allows, whether it translates the source by NAT)."""
        item = entry.item
        if entry.kind in ("allow", "fwdfast", "stateless"):
            if entry.kind == "stateless" and item is not None and item.get("action", "Allow").lower() == "deny":
                return Action.DROP, False, False
            return Action.ALLOW, True, False
        if entry.kind == "nat":
            return Action.ALLOW, True, True
        if entry.kind == "reject":
            return Action.RESET_CLIENT, False, False
        if entry.kind == "policy" and item is not None:
            action = item.get("action", "Allow").lower()
            if action == "deny":
                return (Action.RESET_CLIENT if item.get("reject", "No").lower() in _TRUE else Action.DROP), False, False
            if action != "allow":
                entry.match.problems.append(f"action '{item.get('action')[:20]}' cannot be read")
                return Action.DROP, False, False
            nat = item.get("sourceaddresstranslation", "None").lower() in ("nat", "auto")
            return Action.ALLOW, True, nat
        return Action.DROP, False, False

    def walk(self, entries: List[_Entry]) -> None:
        dest_sats: List[_Sat] = []
        src_sats: List[_Sat] = []
        nat_candidates: List[Tuple[NatRule, bool]] = []  # (rule, an exemption that is kept only if needed)
        sat_items: Dict[str, _Sat] = {}
        for entry in entries:
            match = entry.match
            if entry.kind in ("sat", "slbsat"):
                sat = self._sat_of(entry, match)
                sat.problems = list(dict.fromkeys(match.problems + sat.problems))
                sat_items[entry.name] = sat
                if entry.enabled:
                    (dest_sats if sat.destination else src_sats).append(sat)
                continue
            action, allows, nats = self._verdict(entry)
            local = self._policy_sats(entry, match) if entry.kind in ("policy", "stateless") and entry.enabled else []
            local_dest = [s for s in local if s.destination]
            local_src = [s for s in local if not s.destination]
            if local_dest and not allows:
                local_dest = []
            if entry.kind == "unsupported":
                self._add_rule(self._rule(entry, entry.name, match, match.dst_if, Action.DROP), entry)
                continue
            parts: List[Rule] = []
            covered = False  # the remainder of the rule is not written: its parts say all of it
            translated = False  # a SAT translates all the traffic of the rule
            dst_zones = list(match.dst_if)
            remainder_problems: List[str] = []
            if CORE in dst_zones:
                rest = [z for z in dst_zones if z != CORE]
                if not rest:
                    remainder_problems.append("traffic to the firewall itself (core as the destination interface)")
                    rest = [ANY]
                else:
                    entry.findings.append((Severity.INFO, "CLAVISTER_CORE", "the firewall itself (core) is left out of the "
                                           "destination interfaces"))  # fmt: skip
                dst_zones = rest
            dests = dest_sats + local_dest if entry.enabled else []
            for sat in dests:
                inter = match_and(self.p, sat.match, match)
                if inter is None:
                    continue
                problems = list(inter.problems)
                arrival = self._arrival(inter.destinations)
                if arrival is not None and ANY not in match.dst_if and not set(arrival) & set(match.dst_if):
                    continue  # (the translated traffic arrives for an interface the rule does not name: it never matches)
                arrives = zones_cover(match.dst_if, sat.match.dst_if) or (arrival is not None and zones_cover(match.dst_if, arrival))
                if not arrives:
                    problems.append(f"matches the traffic SAT rule {sat.name} translates only where it arrives for "
                                    f"{', '.join(match.dst_if)} before translation, which the model cannot say")  # fmt: skip
                if local_dest and sat not in local_dest:
                    problems.append("an IP policy with its own SAT below a SAT rule that already translates some of its "
                                    "traffic: which of the two cOS Core carries out is not known")  # fmt: skip
                if sat.problems and allows:
                    problems += [f"SAT {sat.name}: {p}" for p in sat.problems]
                post = sat.post_zones
                whole = sat in local_dest or (match_covers(self.p, sat.match, match) and not inter.problems)
                # The rule as it stands decides the translated traffic the same way where it names every zone after
                # translation; else a part of its own, for that traffic, with the zone after translation.
                needed = not (arrives and not remainder_problems and not problems
                              and (ANY in dst_zones or (post is not None and zones_cover(dst_zones, post))))  # fmt: skip
                part_name = entry.name
                if needed:
                    part_name = entry.name if sat in local_dest else self._unique(f"{entry.name}+{sat.name}")
                    part = self._rule(entry, part_name, dataclasses.replace(inter, problems=problems), post or [ANY], action)
                    if post is None:
                        entry.findings.append((Severity.APPROX, "CLAVISTER_SAT_ZONE",
                                               f"the zone the address {sat.translated} is routed to after translation is not "
                                               "known from the script (no interface network or route holds it): any zone"))  # fmt: skip
                    if sat not in local_dest:
                        self.report.add("rule", part_name, Severity.INFO, "CLAVISTER_SAT_PART",
                                        f"the part of rule {entry.name} for the traffic SAT rule {sat.name} translates to "
                                        f"{sat.translated}: the destinations before translation, the zone after it "
                                        f"({', '.join(post or [ANY])})")  # fmt: skip
                    parts.append(part)
                sat.used = sat.used or allows
                if allows and entry.enabled:
                    nat_name = part_name if needed else self._unique(f"{entry.name}+{sat.name}")
                    for src_sat in src_sats + local_src:
                        both = match_and(self.p, src_sat.match, inter)
                        if both is not None:
                            nat_candidates.append((self._nat(entry, self._unique(f"{nat_name}+{src_sat.name}"), both, sat, src_sat,
                                                             nats, problems), False))  # fmt: skip
                            src_sat.used = True
                    nat_candidates.append((self._nat(entry, nat_name, inter, sat, None, nats, problems), False))
                if whole:
                    translated = True
                    covered = needed
                    break
            for rule in parts:
                self._add_rule(rule, entry)
            if covered:
                continue
            # The rule itself, for traffic no SAT translated.
            if remainder_problems:
                self.report.skip("rule", entry.name, "CLAVISTER_CORE_RULE",
                                 "a rule for traffic to the firewall itself (core as the destination interface)"
                                 + (", apart from the traffic SAT rules translate (written above)" if parts else "")
                                 + ": not converted", Severity.INFO)  # fmt: skip
                continue
            rule = self._rule(entry, entry.name, match, dst_zones, action)
            for sat in dest_sats:
                if not entry.enabled or not _meets(self.p, sat.match, dataclasses.replace(match, dst_if=[ANY])):
                    continue
                if zones_cover(match.dst_if, sat.match.dst_if) or ANY in match.dst_if:
                    continue
                if sat.post_zones is None or set(sat.post_zones) & set(dst_zones):
                    self.report.add("rule", entry.name, Severity.REVIEW, "CLAVISTER_SAT_TRANSLATED_MATCH",
                                    f"in the model the rule also matches traffic SAT rule {sat.name} translates (to the zone "
                                    f"{', '.join(sat.post_zones or [ANY])}); on the firewall it does not, as that traffic arrives "
                                    f"for {', '.join(sat.match.dst_if)} before translation")  # fmt: skip
            self._add_rule(rule, entry)
            if entry.kind == "fwdfast" or entry.kind == "stateless":
                self.report.add("rule", entry.name, Severity.APPROX, "CLAVISTER_FWDFAST",
                                "FwdFast (a stateless policy): the source passes packets one by one and needs a rule for the "
                                "replies; the converted rule is stateful and lets the replies of what it allows through")  # fmt: skip
            if allows and entry.enabled and not remainder_problems and not translated:
                for src_sat in src_sats + local_src:
                    both = match_and(self.p, src_sat.match, match)
                    if both is not None:
                        nat_candidates.append((self._nat(entry, self._unique(f"{entry.name}+{src_sat.name}"), both, None, src_sat, nats, []),
                                               False))
                        src_sat.used = True
                if nats:
                    nat_candidates.append((self._nat(entry, entry.name, match, None, None, True, []), False))
                else:
                    nat_candidates.append((self._nat(entry, entry.name, match, None, None, False, []), True))
        for name, sat in sat_items.items():
            if not sat.used:
                nat = NatRule(name, src_zones=list(sat.match.src_if), dst_zones=self._pre_zones(sat.match),
                              sources=list(sat.match.sources), destinations=list(sat.match.destinations), service=sat.match.service,
                              enabled=False, origin=name)  # fmt: skip
                if sat.destination:
                    nat.destination_translation = DestNat(sat.translated, sat.port)
                else:
                    nat.source_translation = SourceNat(SnatKind.STATIC, [sat.translated])
                nat.unsupported = list(sat.problems)
                nat_candidates.append((nat, False))
                self.report.add("nat", name, Severity.INFO, "CLAVISTER_SAT_UNUSED",
                                "a SAT rule that no Allow, NAT or FwdFast rule below it completes: it translates nothing "
                                "(read as disabled)")  # fmt: skip
        self._nat_rules(nat_candidates)

    def _add_rule(self, rule: Rule, entry: _Entry) -> None:
        self.p.rules.append(rule)
        for severity, code, message in entry.findings:
            self.report.add("rule", rule.origin, severity, code, message)

    def _pre_zones(self, match: Match) -> List[str]:
        """The zones of the destination before translation, for a NAT rule: ``core`` is the interface that owns the address."""
        out: List[str] = []
        for zone in match.dst_if:
            if zone == ANY:
                return [ANY]
            if zone == CORE:
                owner = self._owner(match.destinations)
                if owner is None:
                    return [ANY]
                out.append(owner)
            else:
                out.append(zone)
        return list(dict.fromkeys(out)) or [ANY]

    def _nat(self, entry: _Entry, name: str, match: Match, dest: Optional[_Sat], src: Optional[_Sat], nats: bool,
             problems: List[str]) -> NatRule:  # fmt: skip
        problems = list(problems) + list(match.problems)
        nat = NatRule(name, src_zones=list(match.src_if), dst_zones=self._pre_zones(match) if dest else [z for z in match.dst_if if z != CORE] or [ANY],
                      sources=list(match.sources), destinations=list(match.destinations), service=match.service, origin=name)  # fmt: skip
        if dest is not None:
            translated = dest.translated
            part, whole = _intervals_of(self.p, match.destinations), _intervals_of(self.p, dest.match.destinations)
            if not dest.problems and part != whole:
                after = transform.address_intervals(self.p, translated) or []
                if after and size(after[0]) > 1:
                    # The part of a transposed translation: the same part of the translated range.
                    if part is None or whole is None or len(part) != 1 or len(whole) != 1:
                        problems.append("a part of a transposed translation of several ranges")
                    else:
                        first = after[0][1] + part[0][1] - whole[0][1]
                        translated = interval_text((after[0][0], first, first + size(part[0]) - 1))
            nat.destination_translation = DestNat(translated, dest.port)
            problems += dest.problems
        if src is not None:
            nat.source_translation = SourceNat(SnatKind.STATIC, [src.translated])
            problems += src.problems
            sources = _intervals_of(self.p, src.match.sources)
            translated_to = transform.address_intervals(self.p, src.translated)
            if sources is None or not translated_to or sum(size(i) for i in sources) != size(translated_to[0]):
                problems.append("a source SAT of several addresses to one, or of ranges of different sizes")
            if nats:
                problems.append("a NAT rule that completes a source SAT: both translate the source, and which cOS Core "
                                "carries out is not known")  # fmt: skip
        elif nats:
            out_zones = (dest.post_zones or [ANY]) if dest is not None else [z for z in match.dst_if]
            nat.source_translation = self._source_nat(entry, out_zones, problems)
        if (nat.source_translation is not None or nat.destination_translation is not None) and any(
                6 in transform.families(self.p, m) and transform.families(self.p, m) == {6} for m in match.sources + match.destinations):
            problems.append("NAT of IPv6, which cOS Core does not do")
        nat.unsupported = list(dict.fromkeys(problems))
        if entry.item is not None:
            nat.description = entry.item.get("comments")
        return nat

    def _nat_rules(self, candidates: List[Tuple[NatRule, bool]]) -> None:
        kept: List[NatRule] = []
        for index, (nat, exemption) in enumerate(candidates):
            if exemption:
                needed = any(not later_ex and (later.source_translation or later.destination_translation) and later.enabled
                             and _nat_meets(self.p, nat, later) for later, later_ex in candidates[index + 1:])  # fmt: skip
                if not needed:
                    continue
                self.report.add("nat", nat.origin, Severity.INFO, "CLAVISTER_NO_NAT",
                                "an allowing rule without translation above rules that translate: a NAT rule that translates "
                                "nothing keeps its traffic untranslated, as on the firewall")  # fmt: skip
            kept.append(nat)
        self.p.nat_rules = kept

    # -- the whole ----------------------------------------------------------------------------------------------

    def build(self) -> Policy:
        self.read()
        self._build_objects()
        entries = self._expand("main", None, "", ("main",))
        self._zones()
        self.walk(entries)
        self._notes()
        return self.p

    def _notes(self) -> None:
        sets = [name for name, items in self.rulesets.items() if items]
        self.report.note(Severity.INFO, "CLAVISTER_SOURCE",
                         f"read from the CLI script: rule sets {', '.join(sets[:6]) or 'main'} (main first, the others "
                         "where Goto rules send traffic); interfaces are the zones; what no rule matches is dropped "
                         "without a log")  # fmt: skip
        if any(n.destination_translation for n in self.p.nat_rules):
            self.report.note(Severity.INFO, "CLAVISTER_SAT_ORDER",
                             "a SAT rule is completed by the next Allow, NAT or FwdFast rule that matches the untranslated "
                             "addresses; of several SAT rules the first one for each address is carried out (from the older "
                             "guides, not confirmed for 14.00 and 15.00)")  # fmt: skip
        if self.predefined_used:
            self.report.note(Severity.INFO, "CLAVISTER_PREDEFINED_SERVICE",
                             "predefined services the script does not define, read as FWShift knows them (not confirmed): "
                             + ", ".join(self.predefined_used[:12]))  # fmt: skip
        texts = {
            "CLAVISTER_UNREAD": (Severity.REVIEW, "commands that were not read"),
            "CLAVISTER_NOT_READ": (Severity.INFO, "objects of types that are not converted"),
            "CLAVISTER_MISSING_OBJECT": (Severity.REVIEW, "rules name addresses or services the script does not define (an "
                                         "interface address of the InterfaceAddresses folder, or a predefined service FWShift "
                                         "does not know, for instance); their rules are not converted: add those objects to "
                                         "the script"),
            "CLAVISTER_INTERFACE_UNKNOWN": (Severity.INFO, "interfaces the rules name and the script does not define, read as "
                                            "zones of their own"),
            "CLAVISTER_SAME_NAME": (Severity.REVIEW, "objects of the same name in different address folders; the last one is "
                                    "read"),
            "CLAVISTER_EQUIVALENT": (Severity.INFO, "interface groups marked security equivalent (connections may move between "
                                     "their interfaces); read as their members"),
            "CLAVISTER_FQDN": (Severity.INFO, "FQDN addresses, read as resolved for IPv4 (not confirmed)"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def _meets(p: Policy, a: Match, b: Match) -> bool:
    return match_and(p, a, b) is not None


def _nat_meets(p: Policy, a: NatRule, b: NatRule) -> bool:
    first = Match(a.src_zones, a.dst_zones, a.sources, a.destinations, a.service)
    second = Match(b.src_zones, b.dst_zones, b.sources, b.destinations, b.service)
    return _meets(p, first, second)


def _find(items: List[_Item], kind: str, identifier: str) -> Optional[_Item]:
    if identifier.isdigit():
        index = int(identifier) - 1
        return items[index] if 0 <= index < len(items) else None
    match = re.fullmatch(r"(\d+)\((.*)\)", identifier)
    if match:
        index = int(match.group(1)) - 1
        return items[index] if 0 <= index < len(items) else None
    for item in items:
        if item.get("name") == identifier and (item.type == kind or kind in ("IPRule", "IPPolicy")):
            return item
    return None


def _split(text: str) -> List[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


def _expand(part: str) -> List[int]:
    first, _, last = part.partition("-")
    return list(range(int(first), int(last or first) + 1))


def _ports(text: str, top: int = 65535) -> Optional[str]:
    """A port (or protocol, code) list as the model writes it; "" for every value; None when it cannot be read."""
    parts: List[Tuple[int, int]] = []
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        found = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not found:
            return None
        first, last = int(found.group(1)), int(found.group(2) or found.group(1))
        if not first <= last <= top:
            return None
        parts.append((first, last))
    if not parts:
        return None
    merged: List[Tuple[int, int]] = []
    for first, last in sorted(parts):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    if merged == [(0, top)]:
        return ""
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in merged)


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    try:
        return _Builder(text, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None

