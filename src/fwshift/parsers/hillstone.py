# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hillstone StoneOS parser: ``show configuration`` of an E-, T- or X-series firewall or a CloudEdge (StoneOS 5.x;
the zone-pair policies of 4.x as far as they go) -> neutral model.

How StoneOS decides forwarded traffic, and how that is mapped onto the neutral model:

* Zones are the zones; an interface is bound to one by a ``zone`` line in its block. The rules of the policy
  (``rule id N`` blocks, at the top level or in ``policy-global``) are first match in the order the configuration
  lists them, which is the order ``show policy`` queries them in; the id says nothing about the order. ``move`` lines
  and ``top``/``before``/``after`` on a rule are carried out. In a rule the values of one field are ORed and the
  fields ANDed; a rule that names no zone matches every zone.
* What no rule matches is denied, between zones and inside one ("all interfaces, even in the same zone, cannot
  communicate"); ``default-action permit`` permits both. Both defaults are the model's defaults.
* The predefined address ``Any`` is read as every IPv4 address and ``IPv6-any`` as every IPv6 address (assumed from
  how configurations use them; not stated by Hillstone).
* NAT: a DNAT rule is looked up before the route (which takes the translated address, so the zone the policy sees is
  the zone after DNAT), SNAT after it, then the policy. Hillstone's troubleshooting guide shows the rules naming the
  address before DNAT, as the model does; one of its configuration examples names the server's own address instead.
  FWShift reads rules as naming the address before DNAT and flags a rule that names the address a DNAT rule
  translates to (HILLSTONE_DNAT_INSIDE). Since StoneOS 5.0 an SNAT rule matches the destination before DNAT as well.
  DNAT rules and SNAT rules are two lists, each first match; one of each applies to a connection.
* Objects: address entries (``ip``, ``range``, ``host``, ``member``, ``exclude``), services (``tcp``/``udp`` ports,
  ``icmp`` types, protocol numbers), service groups, and the predefined services FWShift knows the ports of. What is
  not understood makes its rule not converted, never wider. Application identification, schedules, users and VPN
  actions are not converted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_MAX_NESTING = 32
_MAX_ENTRIES = 10_000
# Zones every StoneOS has (CLI User Guide, Firewall: "9 predefined security zones").
PREDEFINED_ZONES = ("trust", "untrust", "dmz", "l2-trust", "l2-untrust", "l2-dmz", "mgt", "vpnhub", "ha")
# The predefined services as FWShift reads them: Hillstone names them in upper case and does not publish their ports in
# the documentation FWShift could read; these are the well-known ports, to be checked with "show service predefined".
PREDEFINED: Dict[str, List[ServiceEntry]] = {
    "HTTP": [ServiceEntry(Protocol.TCP, "80")], "HTTPS": [ServiceEntry(Protocol.TCP, "443")], "FTP": [ServiceEntry(Protocol.TCP, "21")],
    "SSH": [ServiceEntry(Protocol.TCP, "22")], "TELNET": [ServiceEntry(Protocol.TCP, "23")], "SMTP": [ServiceEntry(Protocol.TCP, "25")],
    "DNS": [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")], "TFTP": [ServiceEntry(Protocol.UDP, "69")],
    "POP3": [ServiceEntry(Protocol.TCP, "110")], "NTP": [ServiceEntry(Protocol.UDP, "123")], "IMAP": [ServiceEntry(Protocol.TCP, "143")],
    "SNMP": [ServiceEntry(Protocol.UDP, "161")], "SNMP-TRAP": [ServiceEntry(Protocol.UDP, "162")], "BGP": [ServiceEntry(Protocol.TCP, "179")],
    "LDAP": [ServiceEntry(Protocol.TCP, "389")], "SYSLOG": [ServiceEntry(Protocol.UDP, "514")], "IKE": [ServiceEntry(Protocol.UDP, "500")],
    "RIP": [ServiceEntry(Protocol.UDP, "520")], "L2TP": [ServiceEntry(Protocol.UDP, "1701")], "PPTP": [ServiceEntry(Protocol.TCP, "1723")],
    "RDP": [ServiceEntry(Protocol.TCP, "3389")], "SQLNET": [ServiceEntry(Protocol.TCP, "1521")], "RTSP": [ServiceEntry(Protocol.TCP, "554")],
    "H323": [ServiceEntry(Protocol.TCP, "1720")], "SIP": [ServiceEntry(Protocol.UDP, "5060")], "IMAPS": [ServiceEntry(Protocol.TCP, "993")],
    "POP3S": [ServiceEntry(Protocol.TCP, "995")], "SMTPS": [ServiceEntry(Protocol.TCP, "465")],
    "ICMP": [ServiceEntry(Protocol.ICMP)], "PING": [ServiceEntry(Protocol.ICMP, icmp_type=8)],
    "GRE": [ServiceEntry(Protocol.IP, ip_protocol=47)], "ESP": [ServiceEntry(Protocol.IP, ip_protocol=50)],
    "AH": [ServiceEntry(Protocol.IP, ip_protocol=51)], "OSPF": [ServiceEntry(Protocol.IP, ip_protocol=89)],
}  # fmt: skip
_PREDEFINED_FOLDED = {name.lower(): name for name in PREDEFINED}
# Keywords of a rule that attach a profile or a marking: they do not narrow what the rule matches.
_PROFILE_WORDS = {"av", "ips", "url", "url-profile", "antispam", "sandbox", "file-filter", "content-filter", "behavior",
                  "ssl-proxy", "qos-tag", "nbc", "data-security", "wbl", "spam-filter", "iot"}  # fmt: skip
# Lines of a rule that say nothing about what it matches.
_QUIET_WORDS = {"hit-count", "session-timeout", "tcp-mss", "track", "group"}
_ACTIONS = ("permit", "deny", "reject", "tunnel", "fromtunnel", "webauth")


def looks_like_hillstone(text: str) -> bool:
    """A configuration of StoneOS: lines only it writes at the start of a line."""
    signals: Set[str] = set()
    for line in text.splitlines()[:20000]:
        stripped = line.strip()
        if stripped == "policy-global":
            signals.add("policy-global")
        elif re.match(r"(snatrule|dnatrule|bnatrule)( id \d+)? (from|ingress-interface|from-zone|top|before|after)\b", stripped):
            signals.add("nat")
        elif re.match(r'servgroup "', stripped):
            signals.add("servgroup")
        elif re.match(r'rule id \d+\s*$', stripped):
            signals.add("rule")
        elif re.match(r'(src|dst)-(zone|addr) "', stripped):
            signals.add("field")
        elif re.match(r'ip vrouter "?[\w.-]+"?\s*$', stripped):
            signals.add("vrouter")
        elif re.match(r'address (id \d+ )?"[^"]*"( ipv6)?\s*$', stripped):
            signals.add("address")
        elif re.match(r'zone +"[^"]*"\s*$', stripped) and line[:1] in (" ", "\t"):
            signals.add("binding")
        if len(signals) >= 2:
            return True
    return False


def split_words(line: str) -> List[str]:
    """Words of a line; a name in double quotes is one word."""
    out: List[str] = []
    for quoted, plain in re.findall(r'"((?:[^"\\]|\\.)*)"|(\S+)', line):
        out.append(quoted.replace('\\"', '"') if quoted or not plain else plain)
    return out


@dataclass
class _Node:
    number: int
    words: List[str]
    indent: int
    children: List["_Node"] = field(default_factory=list)
    open_flat: bool = False  # a known block whose lines may come at its own indent, until its exit


def _is_block(words: List[str], parent: List[str]) -> bool:
    """Commands that open a block of their own even when what follows is not indented (typed, or pasted): at the top
    level, and a rule in a policy."""
    head = words[0] if words else ""
    if parent:
        return head == "rule" and (parent == ["policy-global"] or parent[:2] == ["policy", "from"]) \
            and not any(word in _ACTIONS for word in words[1:])
    if head in ("address", "service", "servgroup", "zone", "interface", "schedule", "policy-global", "policy-group"):
        return True
    if words[:2] == ["ip", "vrouter"] or words[:2] == ["policy", "from"]:
        return True
    if head == "rule":
        return not any(word in _ACTIONS for word in words[1:])  # (a rule in one line is complete)
    return False


def read_tree(text: str) -> List[_Node]:
    """The lines as a tree: a line holds the lines below it that are indented deeper, up to its ``exit``. An ``exit``
    closes the block it stands under; ``end`` closes all of them."""
    root = _Node(0, [], -1)
    stack = [root]
    for number, line in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")) or re.match(r"^(Building configuration|Running configuration|Current configuration)", stripped):
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        words = split_words(stripped)
        if not words:
            continue
        if words[0] in ("configure", "config", "save") and len(words) <= 2 and indent == 0:
            continue
        if words == ["end"]:
            del stack[1:]
            continue
        if words == ["exit"]:
            while len(stack) > 1 and (stack[-1].indent > indent or (stack[-1].indent == indent and not stack[-1].children
                                                                     and not stack[-1].open_flat)):
                stack.pop()  # (lines that held nothing)
            if len(stack) > 1:
                stack.pop()  # (the block this exit closes)
            continue
        while len(stack) > 1 and (stack[-1].indent > indent or (stack[-1].indent == indent and not stack[-1].open_flat)):
            stack.pop()
        node = _Node(number, words, indent)
        parent = stack[-1]
        if parent is not root and parent.open_flat and indent > parent.indent:
            parent.open_flat = False  # (its lines are indented: a line at its indent ends it)
        parent.children.append(node)
        node.open_flat = _is_block(words, parent.words)
        stack.append(node)
    return root.children


@dataclass
class _Entry:
    """An address entry as written: its members and what it takes out."""

    family: int
    nets: List[Interval] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    members: List[str] = field(default_factory=list)
    excluded: List[Interval] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class _RuleText:
    """A rule of the policy as the configuration writes it, before it is read."""

    key: str
    number: int
    lines: List[List[str]] = field(default_factory=list)
    zones: Tuple[str, str] = ("", "")  # a rule of a zone-pair policy (StoneOS 4.x)


def _address_literal(words: List[str], index: int) -> Tuple[Optional[Interval], int, str]:
    """``A/LEN``, ``A MASK``, ``A`` at ``words[index]``: (interval, next index, problem)."""
    if index >= len(words):
        return None, index, "an address is missing"
    word = words[index]
    if "/" in word:
        found = parse_literal(word)
        return found, index + 1, "" if found else f"address '{word[:40]}' cannot be read"
    if index + 1 < len(words) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", words[index + 1]) and ":" not in word:
        found = parse_literal(f"{word}/{words[index + 1]}")
        return found, index + 2, "" if found else f"address '{word[:40]} {words[index + 1][:20]}' cannot be read"
    found = parse_literal(word)
    if found is not None and found[1] == found[2]:
        return found, index + 1, ""
    return None, index + 1, f"address '{word[:40]}' cannot be read"


def _range(words: List[str], index: int) -> Tuple[Optional[Interval], int, str]:
    """``A B`` or ``A`` (one address) at ``words[index]``."""
    if index >= len(words):
        return None, index, "a range without addresses"
    if index + 1 < len(words) and parse_literal(words[index + 1]) is not None:
        found = parse_literal(f"{words[index]}-{words[index + 1]}")
        return found, index + 2, "" if found else f"range {words[index][:40]} {words[index + 1][:40]} cannot be read"
    found = parse_literal(words[index])
    if found is not None and found[1] == found[2]:
        return found, index + 1, ""
    return None, index + 1, f"range '{words[index][:40]}' cannot be read"


def _number(word: str, top: int) -> Optional[int]:
    return int(word) if word.isascii() and word.isdigit() and int(word) <= top else None


class _Builder:
    def __init__(self, tree: List[_Node], report: Report) -> None:
        self.tree, self.report = tree, report
        self.p = Policy(vendor="hillstone", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.zone_of: Dict[str, str] = {}
        self.entries: Dict[str, _Entry] = {}
        self.entry_cache: Dict[str, Tuple[Optional[List[Interval]], List[str]]] = {}
        self.visiting: Set[str] = set()
        self.groups_text: Dict[str, List[str]] = {}
        self.rule_names: Set[str] = set()
        self.notes: Dict[str, List[str]] = {}
        self.ipv6 = False
        self.vrouters: List[str] = []
        self.dnat_inside: List[Tuple[List[Interval], str]] = []

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _all(self) -> List[_Node]:
        out: List[_Node] = []
        todo = list(reversed(self.tree))
        while todo:
            node = todo.pop()
            out.append(node)
            todo.extend(reversed(node.children))
        return out

    def build(self) -> Policy:
        heads = {tuple(node.words[:2]) for node in self.tree} | {(node.words[0],) for node in self.tree}
        if not ({("policy-global",), ("rule",), ("zone",), ("address",), ("ip", "vrouter"), ("policy", "from")} & heads):
            raise ParseError("no rule, zone, address or virtual router: not a configuration of Hillstone StoneOS")
        for node in self._all():
            if node.words[:1] in (["vsys"], ["enter-vsys"]):
                self._say("HILLSTONE_VSYS", " ".join(node.words)[:60])
        self._zones()
        self._addresses()
        self._services()
        self._nat()
        self._policy()
        self._notes()
        return self.p

    # -- zones and interfaces ------------------------------------------------------------------

    def _zone(self, name: str) -> str:
        """A zone of a rule by its name; 'any' is every zone."""
        if name.lower() == "any":
            return ANY
        if name not in self.p.zones:
            self.p.zones[name] = Zone(name)
        return name

    def _zones(self) -> None:
        for node in self.tree:
            words = node.words
            if words[:1] == ["zone"] and len(words) >= 2:
                self.p.zones.setdefault(words[1], Zone(words[1]))  # (its block holds its virtual router and attack defence)
                if len(words) > 2 and words[2] in ("l2", "tap"):
                    self._say("HILLSTONE_L2_ZONE", f"{words[1]} ({words[2]})")
            elif words[:1] == ["interface"] and len(words) >= 2:
                name = words[1]
                for child in node.children:
                    if child.words[:1] == ["zone"] and len(child.words) == 2:
                        zone = self.p.zones.setdefault(child.words[1], Zone(child.words[1]))
                        if name not in zone.interfaces:
                            zone.interfaces.append(name)
                        self.zone_of[name] = child.words[1]
                    elif child.words[:2] == ["ipv6", "address"] or child.words[:2] == ["ipv6", "enable"]:
                        self.ipv6 = True

    # -- addresses -------------------------------------------------------------------------------

    def _addresses(self) -> None:
        for node in self.tree:
            words = node.words
            if words[:1] != ["address"] or len(words) < 2:
                continue
            rest = words[1:]
            if rest[:1] == ["id"] and len(rest) >= 3:
                rest = rest[2:]  # (the id later releases print)
            name = rest[0]
            family = 6 if rest[1:2] == ["ipv6"] else 4
            if family == 6:
                self.ipv6 = True
            entry = _Entry(family)
            for child in node.children:
                self._entry_line(entry, child.words)
            if name in self.entries:
                entry.problems.append("the entry is written twice")
            self.entries[name] = entry
        for name, entry in self.entries.items():
            if entry.excluded or entry.problems:
                found: List[str] = []
                resolved = self._resolve(name, found)
                group = AddressGroup(name, [interval_text(i) for i in resolved] if resolved is not None else [],
                                     description=entry.description, unsupported="; ".join(found)[:200])  # fmt: skip
                if resolved is not None and not resolved and not found:
                    group.unsupported = "an address entry that holds no address once its exclusions are taken out"
                self.p.address_groups[name] = group
                continue
            if len(entry.nets) == 1 and not entry.hosts and not entry.members:
                literal = interval_text(entry.nets[0])
                kind = AddressKind.RANGE if "-" in literal else AddressKind.NETWORK
                self.p.addresses[name] = Address(name, kind, literal if kind == AddressKind.RANGE or "/" in literal else
                                                 f"{literal}/{32 if entry.nets[0][0] == 4 else 128}", description=entry.description)  # fmt: skip
                continue
            if len(entry.hosts) == 1 and not entry.nets and not entry.members:
                self.p.addresses[name] = Address(name, AddressKind.FQDN, entry.hosts[0], description=entry.description,
                                                 fqdn_family=entry.family)  # fmt: skip
                continue
            members = [interval_text(i) for i in entry.nets]
            for host in entry.hosts:
                host_name = self._unique(f"{name}/{host}", {n.lower() for n in list(self.entries) + list(self.p.addresses)})
                self.p.addresses[host_name] = Address(host_name, AddressKind.FQDN, host, fqdn_family=entry.family)
                members.append(host_name)
            for member in entry.members:
                members.append(self._member_name(member))
            members = list(dict.fromkeys(members))
            self.p.address_groups[name] = AddressGroup(name, members, description=entry.description,
                                                       unsupported="" if members else "an address entry without members")  # fmt: skip

    @staticmethod
    def _member_name(member: str) -> str:
        if member.lower() == "any":
            return ANY_V4
        if member.lower() == "ipv6-any":
            return ANY_V6
        return member

    def _entry_line(self, entry: _Entry, words: List[str]) -> None:
        head = words[0]
        if head == "description":
            entry.description = " ".join(words[1:])[:255]
            return
        if head == "exclude" and len(words) >= 2:
            if words[1] in ("ip", "range"):
                found, after, problem = (_address_literal if words[1] == "ip" else _range)(words, 2)
                if found is None or after != len(words):
                    entry.problems.append(problem or f"'{' '.join(words)[:60]}' cannot be read")
                else:
                    entry.excluded.append(found)
                return
            entry.problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            return
        if head == "ip" and len(words) >= 2:
            found, after, problem = _address_literal(words, 1)
            if found is None or after != len(words):
                entry.problems.append(problem or f"'{' '.join(words)[:60]}' cannot be read")
            else:
                entry.nets.append(found)
                self.ipv6 = self.ipv6 or found[0] == 6
            return
        if head == "range" and len(words) >= 2:
            found, after, problem = _range(words, 1)
            if found is None or after != len(words):
                entry.problems.append(problem or f"'{' '.join(words)[:60]}' cannot be read")
            else:
                entry.nets.append(found)
            return
        if head == "host" and len(words) >= 2:
            if len(words) > 2:
                entry.problems.append(f"host {words[1][:40]} with '{' '.join(words[2:])[:30]}', which is not read")
            entry.hosts.append(words[1])
            return
        if head == "member" and len(words) == 2:
            entry.members.append(words[1])
            return
        if head == "wildcard":
            entry.problems.append(f"wildcard address '{' '.join(words[1:])[:40]}'")
            return
        if head == "country":
            entry.problems.append(f"country {' '.join(words[1:])[:20]}, which the configuration does not resolve to addresses")
            return
        entry.problems.append(f"'{' '.join(words)[:60]}' cannot be read")

    def _resolve(self, name: str, problems: List[str]) -> Optional[List[Interval]]:
        """The addresses of an entry with its members and exclusions (each entry resolved once); None if any part cannot
        be read, or holds a host name (which an exclusion cannot be taken from)."""
        if name.lower() == "any":
            return [FULL_V4]
        if name.lower() == "ipv6-any":
            return [FULL_V6]
        if name in self.entry_cache:
            result, found = self.entry_cache[name]
            problems.extend(found)
            return result
        if name in self.visiting or name not in self.entries or len(self.visiting) > _MAX_NESTING:
            problems.append(f"address entry {name[:40]} is not in the configuration, holds itself or is nested too deep")
            return None
        entry = self.entries[name]
        found = [f"address entry {name[:40]}: {p}" for p in entry.problems]
        if entry.hosts and entry.excluded:
            found.append(f"address entry {name[:40]}: host names with exclusions")
        out: Optional[List[Interval]] = None if found or entry.hosts else list(entry.nets)
        self.visiting.add(name)
        for member in dict.fromkeys(entry.members):
            got = self._resolve(member, found)
            out = None if got is None or out is None else out + got
        self.visiting.discard(name)
        result = normalize(subtract(out, entry.excluded)) if out is not None else None
        self.entry_cache[name] = (result, found)
        problems.extend(found)
        return result

    # -- services --------------------------------------------------------------------------------

    def _ports(self, words: List[str], index: int, problems: List[str]) -> Tuple[str, int]:
        """``MIN [MAX]`` after dst-port or src-port."""
        first = _number(words[index], 65535) if index < len(words) else None
        if first is None:
            problems.append("ports that cannot be read")
            return "", index + 1
        last = first
        index += 1
        if index < len(words) and _number(words[index], 65535) is not None:
            last = int(words[index])
            index += 1
        if last < first:
            problems.append(f"ports {first} to {last} cannot be read")
        if (first, last) == (0, 65535):
            return "", index
        return (str(first) if first == last else f"{first}-{last}"), index

    def _service_line(self, words: List[str], problems: List[str]) -> List[ServiceEntry]:
        head = words[0]
        if head in ("tcp", "udp", "sctp"):
            source, destination, index = "", "", 1
            while index < len(words):
                if words[index] == "dst-port":
                    destination, index = self._ports(words, index + 1, problems)
                elif words[index] == "src-port":
                    source, index = self._ports(words, index + 1, problems)
                elif words[index] in ("timeout", "timeout-day") and index + 1 < len(words):
                    index += 2  # (how long an idle session lives: not what the service matches)
                elif words[index] == "application" and index + 1 < len(words):
                    index += 2  # (the application type the device assumes on these ports, for its ALGs)
                else:
                    problems.append(f"'{words[index][:30]}' cannot be read")
                    break
            kind = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "sctp": Protocol.SCTP}[head]
            return [ServiceEntry(kind, dst_ports=destination, src_ports=source)]
        if head in ("icmp", "icmpv6"):
            kind = Protocol.ICMP if head == "icmp" else Protocol.ICMP6
            if len(words) == 1:
                return [ServiceEntry(kind)]
            if words[1] != "type" or len(words) < 3 or _number(words[2], 255) is None:
                problems.append(f"'{' '.join(words)[:60]}' cannot be read")
                return []
            icmp_type = int(words[2])
            index = 3
            codes: List[Optional[int]] = [None]
            if index < len(words) and words[index] == "code":
                low = _number(words[index + 1], 255) if index + 1 < len(words) else None
                high = _number(words[index + 2], 255) if index + 2 < len(words) else None
                if low is None:
                    problems.append(f"'{' '.join(words)[:60]}' cannot be read")
                    return []
                index += 3 if high is not None else 2
                high = low if high is None else high
                if high < low:
                    problems.append(f"ICMP codes {low} to {high} cannot be read")
                    return []
                codes = list(range(low, high + 1))
            while index + 1 < len(words) and words[index] in ("timeout", "timeout-day"):
                index += 2
            if index != len(words):
                problems.append(f"'{' '.join(words)[:60]}' cannot be read")
                return []
            return [ServiceEntry(kind, icmp_type=icmp_type, icmp_code=code) for code in codes]
        if head in ("protocol", "other") and len(words) >= 2:
            number = _number(words[1], 255)
            if number is None or number == 0:
                problems.append(f"protocol '{words[1][:20]}' cannot be read (0 may stand for every protocol)")
                return []
            if len(words) > 2 and words[2] not in ("timeout", "timeout-day"):
                problems.append(f"'{' '.join(words)[:60]}' cannot be read")
                return []
            if number in (6, 17):
                return [ServiceEntry(Protocol.TCP if number == 6 else Protocol.UDP)]
            if number in (1, 58):
                return [ServiceEntry(Protocol.ICMP if number == 1 else Protocol.ICMP6)]
            return [ServiceEntry(Protocol.IP, ip_protocol=number)]
        problems.append(f"'{' '.join(words)[:60]}' cannot be read")
        return []

    def _services(self) -> None:
        for node in self.tree:
            words = node.words
            if words[:1] == ["service"] and len(words) >= 2:
                entries: List[ServiceEntry] = []
                problems: List[str] = []
                for child in node.children:
                    if child.words[0] == "description":
                        continue
                    entries += self._service_line(child.words, problems)
                if len(entries) > _MAX_ENTRIES:
                    problems.append(f"more than {_MAX_ENTRIES} entries")
                if not entries and not problems:
                    problems.append("a service without entries")
                description = next((" ".join(c.words[1:]) for c in node.children if c.words[0] == "description"), "")
                self.p.services[words[1]] = Service(words[1], entries, description=description[:255], unsupported="; ".join(problems)[:200])
            elif words[:1] == ["servgroup"] and len(words) >= 2:
                members = [c.words[1] for c in node.children if c.words[:1] == ["service"] and len(c.words) == 2]
                odd = [c for c in node.children if not (c.words[:1] == ["service"] and len(c.words) == 2) and c.words[0] != "description"]
                self.groups_text[words[1]] = members
                self.p.service_groups[words[1]] = ServiceGroup(words[1], [])
                if odd:
                    self.p.service_groups.pop(words[1], None)
                    self.p.services[words[1]] = Service(words[1], [], unsupported=f"'{' '.join(odd[0].words)[:60]}' cannot be read")
        for name, members in self.groups_text.items():
            if name in self.p.service_groups:
                self.p.service_groups[name].members = [self._service(member, []) for member in members]

    def _service(self, name: str, problems: List[str]) -> str:
        """The model service for a name a rule or a group gives: a service, a group, or a predefined service."""
        if name in self.p.services or name in self.p.service_groups:
            return name
        canonical = _PREDEFINED_FOLDED.get(name.lower())
        if canonical is not None:
            if canonical not in self.p.services:
                self.p.services[canonical] = Service(canonical, list(PREDEFINED[canonical]), builtin="hillstone")
            self._say("HILLSTONE_PREDEFINED", canonical)
            return canonical
        problems.append(f"service {name[:40]}: a predefined service FWShift does not know the ports of, or not in the configuration")
        return name

    # -- the policy ------------------------------------------------------------------------------

    def _rule_texts(self) -> List[_RuleText]:
        """The rules in the order the firewall queries them: rules of zone-pair policies (4.x), then the global ones
        (top level, or in policy-global), with what moves them carried out. A later block of the same id edits it."""
        pairs: List[_RuleText] = []
        order: List[_RuleText] = []
        by_key: Dict[str, _RuleText] = {}
        by_name: Dict[str, str] = {}
        counter = [0]

        def place(text: _RuleText, words: List[str], where: List[_RuleText]) -> None:
            for index, word in enumerate(words):
                if word == "top":
                    where.insert(0, text)
                    return
                if word in ("before", "after") and index + 1 < len(words):
                    target = words[index + 1]
                    if target == "name" and index + 2 < len(words):
                        target = by_name.get(words[index + 2], "")
                    for position, other in enumerate(where):
                        if other.key == target:
                            where.insert(position + (word == "after"), text)
                            return
                    self._say("HILLSTONE_MOVE", f"rule {text.key}: {word} {target[:20]}, which is not in the configuration")
            where.append(text)

        def rule(node: _Node, where: List[_RuleText], zones: Tuple[str, str]) -> None:
            words = node.words
            key = ""
            if words[1:2] == ["id"] and len(words) >= 3:
                key = words[2]
            if not key:
                counter[0] += 1
                key = f"auto{counter[0]}"
            lines = [words[1:]] if any(word in _ACTIONS for word in words[1:]) else []
            if key in by_key and not lines:
                by_key[key].lines += [child.words for child in node.children]  # (an edit of a rule there is)
                return
            text = _RuleText(key, node.number, lines + [child.words for child in node.children], zones)
            if key in by_key:
                self._say("HILLSTONE_RULE_TWICE", key)
                key = text.key = f"{key}-{node.number}"
            by_key[key] = text
            for line in text.lines:
                if line[:1] == ["name"] and len(line) >= 2:
                    by_name[line[1]] = key
            for index, word in enumerate(words):
                if word == "name" and index + 1 < len(words):
                    by_name[words[index + 1]] = key
            place(text, words[3:] if words[1:2] == ["id"] else words[1:], where)

        def move(words: List[str]) -> None:
            rest = words[1:]
            key = ""
            if rest[:1] == ["name"] and len(rest) >= 2:
                key, rest = by_name.get(rest[1], ""), rest[2:]
            elif rest:
                key, rest = rest[0], rest[1:]
            text = by_key.get(key)
            if text is None or text not in order or not rest:
                self._say("HILLSTONE_MOVE", f"move {' '.join(words[1:])[:40]}: a rule that is not in the configuration")
                return
            order.remove(text)
            if rest[0] == "bottom":
                order.append(text)
            else:
                place(text, rest, order)

        for node in self.tree:
            words = node.words
            if words[:1] == ["rule"]:
                rule(node, order, ("", ""))
            elif words == ["policy-global"]:
                for child in node.children:
                    if child.words[:1] == ["rule"]:
                        rule(child, order, ("", ""))
                    elif child.words[:1] == ["move"]:
                        move(child.words)
                    elif child.words == ["default-action", "permit"]:
                        self.p.default_interzone = self.p.default_intrazone = Action.ALLOW
            elif words[:2] == ["policy", "from"] and len(words) >= 5 and words[3] == "to":
                self._say("HILLSTONE_ZONE_PAIR", f"{words[2]} -> {words[4]}")
                for child in node.children:
                    if child.words[:1] == ["rule"]:
                        rule(child, pairs, (words[2], words[4]))
            elif words[:1] == ["move"]:
                move(words)
            elif words == ["default-action", "permit"]:
                self.p.default_interzone = self.p.default_intrazone = Action.ALLOW
        return pairs + order

    def _policy(self) -> None:
        for text in self._rule_texts():
            self._rule(text)
        self._say("HILLSTONE_DEFAULTS", "permit" if self.p.default_interzone == Action.ALLOW else "deny")

    def _side(self, values: List[Tuple[str, List[str]]], side: str, problems: List[str]) -> List[str]:
        members: List[str] = []
        for kind, rest in values:
            if kind == "addr":
                if len(rest) != 1:
                    problems.append(f"{side} address '{' '.join(rest)[:60]}' cannot be read")
                    continue
                name = rest[0]
                if name.lower() in ("any", "ipv6-any"):
                    members.append(self._member_name(name))
                    continue
                if name not in self.entries:
                    problems.append(f"address entry {name[:40]} is not in the configuration")
                members.append(name)
            elif kind == "ip":
                found, after, problem = _address_literal(rest, 0)
                if found is None or after != len(rest):
                    problems.append(problem or f"{side} '{' '.join(rest)[:60]}' cannot be read")
                    continue
                members.append(interval_text(found))
            elif kind == "range":
                found, after, problem = _range(rest, 0)
                if found is None or after != len(rest):
                    problems.append(problem or f"{side} range '{' '.join(rest)[:60]}' cannot be read")
                    continue
                members.append(interval_text(found))
            elif kind == "host":
                if len(rest) != 1:
                    problems.append(f"{side} host '{' '.join(rest)[:60]}' cannot be read")
                    continue
                name = rest[0]
                if name not in self.p.addresses:
                    self.p.addresses[name] = Address(name, AddressKind.FQDN, name)
                members.append(name)
        return members

    @staticmethod
    def _one_line(words: List[str], problems: List[str]) -> List[List[str]]:
        """``rule [id N] [name X] [top|before|after ...] [role|user|user-group ...] from A to B [from-zone Z to-zone Z]
        service S [application A] ACTION [TUNNEL]`` as the lines of a block."""
        out: List[List[str]] = []
        index = 0
        while index < len(words):
            word = words[index]
            nxt = words[index + 1] if index + 1 < len(words) else ""
            if word == "id" and nxt:
                index += 2
            elif word == "top":
                index += 1
            elif word in ("before", "after") and nxt:
                index += 3 if nxt == "name" else 2
            elif word == "name" and nxt:
                out.append(["name", nxt])
                index += 2
            elif word == "from" and nxt:
                out.append(["src-addr", nxt])
                index += 2
            elif word == "to" and nxt:
                out.append(["dst-addr", nxt])
                index += 2
            elif word == "from-zone" and nxt:
                out.append(["src-zone", nxt])
                index += 2
            elif word == "to-zone" and nxt:
                out.append(["dst-zone", nxt])
                index += 2
            elif word in ("service", "application", "role") and nxt:
                out.append([word, nxt])
                index += 2
            elif word in ("user", "user-group") and index + 2 < len(words):
                out.append([word, words[index + 1], words[index + 2]])
                index += 3
            elif word in ("tunnel", "fromtunnel") and nxt:
                out.append(["action", word, nxt])
                index += 2
            elif word in ("permit", "deny", "reject", "webauth"):
                out.append(["action", word])
                index += 1
            else:
                problems.append(f"'{word[:30]}' in the rule cannot be read")
                index += 1
        return out

    def _rule(self, text: _RuleText) -> None:
        problems: List[str] = []
        lines: List[List[str]] = []
        for words in text.lines:
            if words and words[0] in ("id", "from", "to", "name", "top", "before", "after", "user", "role", "user-group", "from-zone") \
                    and any(word in _ACTIONS for word in words):
                lines += self._one_line(words, problems)
            else:
                lines.append(words)
        given = next((line[1] for line in lines if line[:1] == ["name"] and len(line) >= 2), "")
        rule = Rule(self._unique(given or f"rule {text.key}", self.rule_names), action=Action.DENY)
        rule.origin = rule.name
        rule.log_end = False
        rule.source_ids = {"hillstone.rule_id": text.key} if not text.key.startswith("auto") else {}
        rule.source_ids["hillstone.line"] = str(text.number)
        src_zones: List[str] = [text.zones[0]] if text.zones[0] else []
        dst_zones: List[str] = [text.zones[1]] if text.zones[1] else []
        sources: List[Tuple[str, List[str]]] = []
        destinations: List[Tuple[str, List[str]]] = []
        services: List[str] = []
        action = ""
        users: List[str] = []
        schedules: List[str] = []
        for words in lines:
            if not words:
                continue
            head, rest = words[0], words[1:]
            if head in ("src-zone", "dst-zone") and len(rest) == 1:
                (src_zones if head == "src-zone" else dst_zones).append(rest[0])
            elif head.startswith(("src-", "dst-")) and head[4:] in ("addr", "ip", "range", "host"):
                (sources if head.startswith("src") else destinations).append((head[4:], rest))
            elif head == "service" and len(rest) == 1:
                services.append(rest[0])
            elif head == "action" and rest[:1] and rest[0] in _ACTIONS:
                action = rest[0]
                if action in ("tunnel", "fromtunnel"):
                    problems.append(f"action {' '.join(rest)[:40]}: traffic of a VPN tunnel only")
                elif action == "webauth":
                    problems.append("action webauth: users who have signed in through the web only")
            elif head in ("disable", "enable") and not rest:
                rule.enabled = head == "enable"
            elif head == "name" and rest:
                continue
            elif head == "description":
                rule.description = " ".join(rest)[:255]
            elif head == "log" and len(rest) == 1 and rest[0] in ("policy-deny", "session-start", "session-end"):
                if rest[0] == "session-start":
                    rule.log_start = True
                else:
                    rule.log_end = True
            elif head == "application" and len(rest) == 1:
                if rest[0].lower() != "any":
                    problems.append(f"application {rest[0][:40]}: application identification narrows the match")
            elif head == "schedule" and len(rest) == 1:
                schedules.append(rest[0])
            elif head in ("role", "user", "user-group") and rest:
                users.append(" ".join(words))
            elif head in _PROFILE_WORDS and rest:
                rule.profiles[head] = " ".join(rest)[:100]
            elif head in _QUIET_WORDS:
                continue
            else:
                problems.append(f"'{' '.join(words)[:60]}' is not converted")
        if not action:
            problems.append("a rule without an action")
        rule.action = {"permit": Action.ALLOW, "reject": Action.RESET_CLIENT}.get(action, Action.DENY)
        if action in ("tunnel", "fromtunnel", "webauth"):
            rule.action = Action.ALLOW
        if action == "reject":
            self._say("HILLSTONE_REJECT", rule.name)
        rule.src_zones = list(dict.fromkeys(self._zone(z) for z in src_zones)) or [ANY]
        rule.dst_zones = list(dict.fromkeys(self._zone(z) for z in dst_zones)) or [ANY]
        if ANY in rule.src_zones:
            rule.src_zones = [ANY]
        if ANY in rule.dst_zones:
            rule.dst_zones = [ANY]
        rule.sources = list(dict.fromkeys(self._side(sources, "source", problems))) or [ANY]
        rule.destinations = list(dict.fromkeys(self._side(destinations, "destination", problems))) or [ANY]
        if not sources or not destinations:
            problems.append("a rule without a source or a destination address")
        if services:
            rule.services = list(dict.fromkeys(ANY if s.lower() == "any" else self._service(s, problems) for s in services))
            if ANY in rule.services:
                rule.services = [ANY]
        else:
            problems.append("a rule without a service")
        if users:
            rule.users = users
        if schedules:
            rule.schedule = ", ".join(schedules)
            self._say("HILLSTONE_SCHEDULE", f"{rule.name}: {rule.schedule[:40]}")
        if rule.action != Action.ALLOW and self.ipv6 and any(m == ANY_V4 for m in rule.sources + rule.destinations) \
                and not any(m == ANY_V6 for m in rule.sources + rule.destinations):
            self.report.add("rule", rule.origin, Severity.REVIEW, "HILLSTONE_ANY_IPV4",
                            "a blocking rule that names Any, read as every IPv4 address; the configuration has IPv6: if Any "
                            "takes in IPv6 addresses on the firewall, the converted rule blocks less")  # fmt: skip
        for member in rule.destinations:
            intervals = self._intervals(member)
            if not intervals or any(i[1] == 0 and i[2] >= 2**32 - 1 for i in intervals):
                continue  # (every address: the rule takes the translated connections either way)
            hit = [origin for inside, origin in self.dnat_inside
                   if any(i[0] == j[0] and i[1] <= j[2] and j[1] <= i[2] for i in intervals for j in inside)]  # fmt: skip
            if hit:
                self.report.add("rule", rule.origin, Severity.REVIEW, "HILLSTONE_DNAT_INSIDE",
                                f"names {member}, which holds an address that {', '.join(hit[:4])} translate(s) to: read as "
                                "the address a packet has before DNAT; if the firewall matches rules after DNAT, the rule "
                                "also matches the connections translated to it")  # fmt: skip
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)

    def _intervals(self, member: str) -> List[Interval]:
        literal = parse_literal(member)
        if literal is not None:
            return [literal]
        if member in self.entries:
            return self._resolve(member, []) or []
        return []

    # -- NAT -------------------------------------------------------------------------------------

    def _nat(self) -> None:
        dnat: List[_Node] = []
        snat: List[_Node] = []
        for node in self.tree:
            words = node.words
            holders: List[_Node] = []
            if words[:2] == ["ip", "vrouter"] and len(words) >= 3:
                holders = list(node.children)
                if any(c.words[:1] in (["snatrule"], ["dnatrule"], ["bnatrule"]) for c in node.children) and words[2] not in self.vrouters:
                    self.vrouters.append(words[2])
            elif words == ["nat"]:
                holders = list(node.children)
            elif words[:1] in (["snatrule"], ["dnatrule"], ["bnatrule"]):
                holders = [node]
            for child in holders:
                head = child.words[0]
                if head == "dnatrule":
                    self._place(dnat, child)
                elif head == "snatrule":
                    self._place(snat, child)
                elif head == "bnatrule":
                    nat = NatRule(self._unique(f"bnatrule {self._id(child.words) or child.number}", {n.name.lower() for n in self.p.nat_rules}))
                    nat.origin = nat.name
                    nat.unsupported = ["a BNAT rule (bidirectional NAT), which is not converted"]
                    nat.description = " ".join(child.words)[:200]
                    self.p.nat_rules.append(nat)
        for child in dnat:
            self._dnat(child)
        for child in snat:
            self._snat(child)
        if len(self.vrouters) > 1:
            self._say("HILLSTONE_VROUTER", ", ".join(self.vrouters[:8]))
        for nat in self.p.nat_rules:
            nat.combines = True  # (one DNAT and one SNAT rule apply to a connection)

    @staticmethod
    def _id(words: List[str]) -> str:
        for index, word in enumerate(words[:-1]):
            if word == "id":
                return words[index + 1]
        return ""

    def _place(self, where: List[_Node], item: _Node) -> None:
        words = item.words
        for index, word in enumerate(words[1:5], 1):
            if word == "top":
                where.insert(0, item)
                return
            if word in ("before", "after") and index + 1 < len(words):
                for position, other in enumerate(where):
                    if self._id(other.words) == words[index + 1]:
                        where.insert(position + (word == "after"), item)
                        return
        where.append(item)

    def _nat_address(self, words: List[str], index: int, problems: List[str]) -> Tuple[str, int]:
        """An address of a NAT rule: ``address-book X``, ``ip A[/M]``, ``range A B``, or a name (an address entry, a
        literal, Any)."""
        if index >= len(words):
            problems.append("an address is missing")
            return ANY, index
        word = words[index]
        if word == "address-book" and index + 1 < len(words):
            word, index = words[index + 1], index + 1
        elif word == "ip" and index + 1 < len(words):
            found, after, problem = _address_literal(words, index + 1)
            if found is None:
                problems.append(problem)
                return ANY, after
            return interval_text(found), after
        elif word == "range" and index + 1 < len(words):
            found, after, problem = _range(words, index + 1)
            if found is None:
                problems.append(problem)
                return ANY, after
            return interval_text(found), after
        if word.lower() == "any":
            return ANY, index + 1
        if word.lower() == "ipv6-any":
            return ANY_V6, index + 1
        if word in self.entries:
            return word, index + 1
        literal = parse_literal(word)
        if literal is not None:
            return interval_text(literal), index + 1
        problems.append(f"address entry {word[:40]} is not in the configuration")
        return word, index + 1

    def _nat_common(self, words: List[str], kind: str) -> Tuple[NatRule, Dict[str, str], List[str]]:
        """The words both kinds share; the rest is returned as keyword -> value."""
        problems: List[str] = []
        ident = self._id(words)
        nat = NatRule(self._unique(f"{kind} {ident}" if ident else kind, {n.name.lower() for n in self.p.nat_rules}))
        nat.origin = nat.name
        nat.description = " ".join(words)[:200]
        extra: Dict[str, str] = {}
        index = 1
        while index < len(words):
            word = words[index]
            nxt = words[index + 1] if index + 1 < len(words) else ""
            if word == "id" and nxt:
                index += 2
            elif word == "top":
                index += 1
            elif word in ("before", "after") and nxt:
                index += 2
            elif word == "from":
                address, index = self._nat_address(words, index + 1, problems)
                nat.sources = [address]
            elif word == "to":
                address, index = self._nat_address(words, index + 1, problems)
                nat.destinations = [address]
            elif word == "service" and nxt:
                nat.service = ANY if nxt.lower() == "any" else self._service(nxt, problems)
                index += 2
            elif word == "trans-to" and nxt:
                if nxt == "eif-ip":
                    extra["trans-to"], index = "eif-ip", index + 2
                else:
                    address, index = self._nat_address(words, index + 1, problems)
                    extra["trans-to"] = address
            elif word in ("ingress-interface", "eif", "evr", "mode", "port", "from-zone", "to-zone", "track-tcp", "group", "description",
                          "slb-server-pool") and nxt:
                extra[word] = nxt
                index += 2
            elif word == "disable":
                nat.enabled = False
                index += 1
            elif word in ("log", "sticky", "track-ping", "enable"):
                index += 1
            elif word in ("no-trans", "load-balance", "v4-mapped", "v6-mapped"):
                extra[word] = "1"
                index += 1
            else:
                problems.append(f"'{word[:30]}' cannot be read")
                index += 1
        if "ingress-interface" in extra or "from-zone" in extra:
            zone = extra.get("from-zone") or self.zone_of.get(extra["ingress-interface"], "")
            if zone:
                nat.src_zones = [zone]
                self._zone(zone)
            else:
                problems.append(f"ingress interface {extra['ingress-interface'][:40]} is in no zone")
        if "to-zone" in extra:
            nat.dst_zones = [extra["to-zone"]]
            self._zone(extra["to-zone"])
        if "evr" in extra:
            problems.append(f"to the virtual router {extra['evr'][:40]}, which is not converted")
        if "slb-server-pool" in extra:
            problems.append("a server pool, which is not converted")
        return nat, extra, problems

    def _families_differ(self, a: List[str], b: str) -> bool:
        def family(member: str) -> Set[int]:
            if member == ANY:
                return {4}
            return {i[0] for i in self._intervals(member)}

        left = set().union(*(family(m) for m in a)) if a else set()
        right = family(b)
        return bool(left and right and not (left & right))

    def _dnat(self, node: _Node) -> None:
        nat, extra, problems = self._nat_common(node.words, "dnatrule")
        if "v4-mapped" in extra or "v6-mapped" in extra:
            problems.append("NAT between IPv4 and IPv6, which is not converted")
        elif "no-trans" in extra:
            pass  # (an exemption: no translation)
        elif "trans-to" not in extra or extra["trans-to"] == "eif-ip":
            problems.append("a DNAT rule without the address it translates to")
        else:
            target = extra["trans-to"]
            port = extra.get("port", "")
            if port and _number(port, 65535) is None:
                problems.append(f"port '{port[:20]}' cannot be read")
                port = ""
            if self._families_differ(nat.destinations, target):
                problems.append("NAT between IPv4 and IPv6, which is not converted")
            nat.destination_translation = DestNat(target, port, spread="load-balance" in extra)
            inside = self._intervals(target)
            if inside:
                self.dnat_inside.append((inside, nat.name))
        nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(nat)

    def _snat(self, node: _Node) -> None:
        nat, extra, problems = self._nat_common(node.words, "snatrule")
        if "eif" in extra:
            zone = self.zone_of.get(extra["eif"], "")
            if zone:
                nat.dst_zones = [zone]
                self._zone(zone)
            else:
                problems.append(f"egress interface {extra['eif'][:40]} is in no zone")
        if "no-trans" in extra:
            pass
        elif "trans-to" not in extra:
            problems.append("an SNAT rule without the address it translates to")
        elif extra["trans-to"] == "eif-ip":
            if "eif" not in extra:
                problems.append("trans-to eif-ip without an egress interface")
            nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=extra.get("eif", ""))
        else:
            mode = extra.get("mode", "")
            kinds = {"static": SnatKind.STATIC, "dynamicip": SnatKind.DYNAMIC, "dynamicport": SnatKind.DYNAMIC_PORT}
            if mode and mode not in kinds:
                problems.append(f"mode {mode[:20]} cannot be read")
            if not mode:
                self.report.add("nat", nat.origin, Severity.APPROX, "HILLSTONE_SNAT_MODE",
                                "a translation to addresses without a mode: read as dynamicport (many addresses to one, ports "
                                "translated)")  # fmt: skip
            if self._families_differ(nat.sources, extra["trans-to"]):
                problems.append("NAT between IPv4 and IPv6, which is not converted")
            nat.source_translation = SourceNat(kinds.get(mode, SnatKind.DYNAMIC_PORT), [extra["trans-to"]])
        nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(nat)

    # -- notes ----------------------------------------------------------------------------------

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "HILLSTONE_SOURCE",
                         f"{len(self.p.zones)} zones ({', '.join(list(self.p.zones)[:8])}{' ...' if len(self.p.zones) > 8 else ''}); "
                         f"{len(self.p.rules)} rules of the policy, first match in the order of the configuration (not by id)")  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.REVIEW, "HILLSTONE_NAT_ORDER",
                             "DNAT is looked up before the route and the policy, SNAT after the route; the rules were read as "
                             "naming the destination before DNAT and the zone after it, which is what Hillstone's troubleshooting "
                             "guide shows (one of its configuration examples names the translated address instead): check the "
                             "rules for translated traffic on the firewall")  # fmt: skip
        self.report.note(Severity.INFO, "HILLSTONE_ANY",
                         "the address Any is read as every IPv4 address and IPv6-any as every IPv6 address")
        texts = {
            "HILLSTONE_DEFAULTS": (Severity.INFO, "what no rule matches, between zones and inside a zone (default-action)"),
            "HILLSTONE_PREDEFINED": (Severity.REVIEW, "predefined services read with the ports FWShift knows for them; check them "
                                     "with show service predefined"),
            "HILLSTONE_SCHEDULE": (Severity.INFO, "rules with a schedule: schedules are not converted, a target writes these rules "
                                   "disabled"),
            "HILLSTONE_ZONE_PAIR": (Severity.REVIEW, "zone-pair policies (StoneOS 4.x): their rules were put before the global "
                                    "rules, in the order of the configuration"),
            "HILLSTONE_MOVE": (Severity.REVIEW, "a rule is to be moved next to one the configuration does not have: left where "
                               "it is"),
            "HILLSTONE_RULE_TWICE": (Severity.REVIEW, "a rule id written twice with a one-line rule: both are read, as two rules"),
            "HILLSTONE_VROUTER": (Severity.REVIEW, "NAT rules of several virtual routers: the converted policy has one routing "
                                  "table, and their rules are one list"),
            "HILLSTONE_VSYS": (Severity.REVIEW, "virtual systems: their configuration is read as if it were the root system's"),
            "HILLSTONE_L2_ZONE": (Severity.INFO, "layer-2 and tap zones: read as zones"),
            "HILLSTONE_REJECT": (Severity.INFO, "action reject: read as a deny that answers the client"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    tree = read_tree(text)
    try:
        return _Builder(tree, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None
