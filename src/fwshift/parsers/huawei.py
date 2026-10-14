# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Huawei USG parser: ``display current-configuration`` of a USG6000, USG6000E or USG9500 (VRP V500 and V600, the
``security-policy`` generation) -> neutral model.

How a USG decides forwarded traffic, and how that is mapped onto the neutral model:

* The security zones (``firewall zone``) are the zones; ``local`` is the firewall itself, whose rules are not
  converted. The rules of ``security-policy`` are first match, top to bottom; in a rule the conditions are ANDed and
  the values of one condition ORed; a condition that is not given is any. What no rule matches meets the default
  policy: deny between zones (``default action permit`` changes it), permit inside a zone unless
  ``default packet-filter intrazone enable`` puts that under the default policy too. That permit is an explicit rule
  at the end of the converted policy.
* Destination NAT (``nat server``) is done before the security policy, which names the inside address and port; the
  model names the address as it arrives, so rules are rewritten for it as for FortiOS. Source NAT (``nat-policy``)
  is done after it, on the original source.
* Objects: address sets (masks, wildcard masks, ranges, nested sets), service sets (ports, ICMP types, protocols,
  nested sets) and the predefined services FWShift knows the ports of. What is not understood makes its rule not
  converted, never wider.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import (
    ANY,
    Action,
    AddressGroup,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import Interval, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_MAX_NESTING = 32
_MAX_ENTRIES = 10_000
_PREDEFINED_ZONES = {"local": 100, "trust": 85, "dmz": 50, "untrust": 5}
# The predefined services as FWShift reads them (Huawei documents the names; the ports are the well-known ones and are
# to be checked with display predefined-service): name -> entries.
PREDEFINED: Dict[str, List[ServiceEntry]] = {
    "http": [ServiceEntry(Protocol.TCP, "80")], "https": [ServiceEntry(Protocol.TCP, "443")], "ftp": [ServiceEntry(Protocol.TCP, "21")],
    "ssh": [ServiceEntry(Protocol.TCP, "22")], "telnet": [ServiceEntry(Protocol.TCP, "23")], "smtp": [ServiceEntry(Protocol.TCP, "25")],
    "dns": [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")], "tftp": [ServiceEntry(Protocol.UDP, "69")],
    "pop3": [ServiceEntry(Protocol.TCP, "110")], "ntp": [ServiceEntry(Protocol.UDP, "123")], "imap": [ServiceEntry(Protocol.TCP, "143")],
    "snmp": [ServiceEntry(Protocol.UDP, "161")], "snmptrap": [ServiceEntry(Protocol.UDP, "162")], "bgp": [ServiceEntry(Protocol.TCP, "179")],
    "ldap": [ServiceEntry(Protocol.TCP, "389")], "ils": [ServiceEntry(Protocol.TCP, "1002")], "isakmp": [ServiceEntry(Protocol.UDP, "500")],
    "rip": [ServiceEntry(Protocol.UDP, "520")], "l2tp": [ServiceEntry(Protocol.UDP, "1701")], "pptp": [ServiceEntry(Protocol.TCP, "1723")],
    "sqlnet": [ServiceEntry(Protocol.TCP, "1521")], "rtsp": [ServiceEntry(Protocol.TCP, "554")], "h323": [ServiceEntry(Protocol.TCP, "1720")],
    "sip": [ServiceEntry(Protocol.UDP, "5060")], "icmp": [ServiceEntry(Protocol.ICMP)], "icmpv6": [ServiceEntry(Protocol.ICMP6)],
    "ospf": [ServiceEntry(Protocol.IP, ip_protocol=89)], "gre": [ServiceEntry(Protocol.IP, ip_protocol=47)],
    "esp": [ServiceEntry(Protocol.IP, ip_protocol=50)], "ah": [ServiceEntry(Protocol.IP, ip_protocol=51)],
}  # fmt: skip
# Port keywords VRP prints in nat server lines.
PORT_NAMES = {"ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "tftp": 69, "www": 80, "http": 80, "pop3": 110,
              "ntp": 123, "imap": 143, "snmp": 161, "https": 443}  # fmt: skip
_PROTOCOLS = {"tcp": 6, "udp": 17, "sctp": 132, "icmp": 1, "icmpv6": 58, "gre": 47, "esp": 50, "ah": 51, "ospf": 89}


def looks_like_huawei(text: str) -> bool:
    """A configuration of a Huawei USG: lines only it writes at the start of a line."""
    found = 0
    for line in text.splitlines()[:20000]:
        if line.startswith(("security-policy", "nat-policy")) and line.strip() in ("security-policy", "nat-policy"):
            found += 2
        elif line.startswith(("firewall zone ", "ip address-set ", "ip service-set ", "nat address-group ", "policy interzone ")):
            found += 1
        elif line.startswith(("sysname ", " sysname ")):
            found += 1
        if found >= 2:
            return True
    return False


def split_words(line: str) -> List[str]:
    """Words of a line; a name in double quotes is one word."""
    out: List[str] = []
    for quoted, plain in re.findall(r'"([^"]*)"|(\S+)', line):
        out.append(quoted if quoted or not plain else plain)
    return out


@dataclass
class _Line:
    number: int
    words: List[str]
    indent: int
    children: List["_Line"] = field(default_factory=list)


# The words a line of a rule starts with: a policy keeps them, whatever their indent.
_RULE_WORDS = {"rule", "source-zone", "destination-zone", "source-address", "source-address-exclude", "destination-address",
               "destination-address-exclude", "service", "action", "disable", "enable", "description", "policy", "session",
               "application", "user", "time-range", "profile", "parent-group", "long-link", "egress-interface"}  # fmt: skip


def read_lines(text: str) -> List[_Line]:
    """Top-level lines with the lines below them; ``#`` and ``!`` lines, ``quit``, ``return`` and ``system-view`` left
    out. A line is top-level at the start of a line or right after a ``#`` line (VRP prints commands of the system view
    with one space, ``#`` between blocks), and ``nat server`` always (it is never part of a block). In
    ``security-policy`` and ``nat-policy`` every indented line, and every line that starts as a line of a rule does,
    stays in the policy."""
    out: List[_Line] = []
    after_hash = True
    for number, line in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
        stripped = line.strip()
        if not stripped or stripped in ("quit", "return", "system-view"):
            continue
        if stripped.startswith(("#", "!")):
            after_hash = True
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        entry = _Line(number, split_words(stripped), indent)
        in_policy = bool(out) and out[-1].words in (["security-policy"], ["nat-policy"])
        if entry.words[:2] == ["nat", "server"]:
            child = False
        elif in_policy:
            child = bool(indent) or (not after_hash and (entry.words[0] in _RULE_WORDS or entry.words[:2] == ["default", "action"]))
        else:
            child = bool(indent) and bool(out) and not after_hash
        if child:
            out[-1].children.append(entry)
        else:
            if entry.words[:2] == ["rule", "name"]:
                raise ParseError(f"line {number}: a rule outside security-policy and nat-policy")
            entry.indent = 0
            out.append(entry)
        after_hash = False
    return out


def _address(words: List[str], index: int) -> Tuple[Optional[Interval], int, str]:
    """An address of a rule or a set at ``words[index]``: ``A LEN``, ``A mask M``, ``A WILDCARD`` (sets only),
    ``A/LEN``, ``range A B``; (interval or None, next index, problem)."""
    if index >= len(words):
        return None, index, "an address is missing"
    word = words[index]
    if word == "range" and index + 2 < len(words):
        found = parse_literal(f"{words[index + 1]}-{words[index + 2]}")
        return found, index + 3, "" if found else f"range {words[index + 1][:40]} {words[index + 2][:40]} cannot be read"
    if "/" in word:
        found = parse_literal(word)
        return found, index + 1, "" if found else f"address '{word[:40]}' cannot be read"
    if index + 1 < len(words) and words[index + 1] == "mask" and index + 2 < len(words):
        found = parse_literal(f"{word}/{words[index + 2]}")
        return found, index + 3, "" if found else f"address '{word[:40]} mask {words[index + 2][:20]}' cannot be read"
    if index + 1 < len(words) and words[index + 1].isascii() and words[index + 1].isdigit():
        if int(words[index + 1]) == 0:
            return None, index + 2, f"address '{word[:40]} 0': a mask length of 0 or a wildcard of 0, which cannot be told apart"
        found = parse_literal(f"{word}/{words[index + 1]}")
        return found, index + 2, "" if found else f"address '{word[:40]} {words[index + 1]}' cannot be read"
    if index + 1 < len(words) and parse_literal(words[index + 1]) is not None and ":" not in word:
        return None, index + 2, "wildcard"  # (the caller reads it)
    found = parse_literal(word)
    if found is not None and found[1] == found[2]:
        return found, index + 1, ""
    return None, index + 1, f"address '{word[:40]}' cannot be read"


def _wildcard(address: str, wildcard: str) -> Optional[List[Interval]]:
    try:
        base, wild = int(ipaddress.IPv4Address(address)), int(ipaddress.IPv4Address(wildcard))
    except ValueError:
        return None
    if wild & (wild + 1) or wild == 0xFFFFFFFF:
        return None  # (not contiguous; or every address, which a mask written without the mask keyword looks like too)
    base &= ~wild & 0xFFFFFFFF
    return [(4, base, base | wild)]


def _every_line(lines: List[_Line]) -> List[_Line]:
    return [line for top in lines for line in [top] + top.children]


class _Builder:
    def __init__(self, lines: List[_Line], report: Report, version: str = "") -> None:
        self.lines, self.report, self.version = lines, report, version
        self.p = Policy(vendor="huawei", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.zones: Dict[str, List[str]] = {}
        self.zone_of: Dict[str, str] = {}
        self.interfaces: Dict[str, List[Interval]] = {}
        self.sets: Dict[str, Tuple[List[Interval], List[str], List[str]]] = {}  # address set -> (own, nested, problems)
        self.service_sets: Dict[str, Tuple[List[ServiceEntry], List[str], List[str]]] = {}
        self.pools: Dict[str, Tuple[List[Interval], bool]] = {}  # name -> (sections, pat)
        self.rule_names: Set[str] = set()
        self.taken: Set[str] = set()
        self.notes: Dict[str, List[str]] = {}
        self.inline_services: Dict[str, str] = {}
        self.set_cache: Dict[str, Tuple[Optional[List[Interval]], List[str]]] = {}
        self.visiting: Set[str] = set()
        self.service_cache: Dict[str, Tuple[Optional[List[ServiceEntry]], List[str]]] = {}
        self.visiting_services: Set[str] = set()

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

    def build(self) -> Policy:
        for index, line in enumerate(self.lines):
            if any(found.words[:2] == ["switch", "vsys"] for found in line.children):
                raise ParseError(f"line {line.number}: switch vsys inside another block; where the root system ends cannot be told")
            if line.words[:2] == ["switch", "vsys"]:
                self._say("HUAWEI_VSYS", " ".join(line.words)[:60])
                self.lines = self.lines[:index]  # (what follows is the configuration of a virtual system)
                break
        if any(line.words[:2] == ["policy", "interzone"] for line in self.lines):
            raise ParseError("a configuration of an older USG (USG2000, USG5000, USG5500: policy interzone); FWShift reads the "
                             "security-policy of USG6000, USG6000E and USG9500")  # fmt: skip
        if any(line.words[:2] == ["firewall", "interzone"] or line.words[:3] == ["firewall", "packet-filter", "default"] for line in self.lines):
            raise ParseError("packet filters between zones (firewall interzone, firewall packet-filter default): a router or an older "
                             "USG; FWShift reads the security-policy of USG6000, USG6000E and USG9500")  # fmt: skip
        if not any(line.words[:1] in (["security-policy"], ["firewall"], ["nat-policy"]) for line in self.lines):
            raise ParseError("no security-policy and no security zones: not a configuration of a Huawei USG")
        self._interfaces()
        self._zones()
        self._address_sets()
        self._service_sets()
        self._pools()
        self._security_policy()
        self._nat()
        self._other()
        if self.p.nat_rules:
            self.p.lookup_after_dnat = True
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes()
        return self.p

    # -- interfaces and zones --------------------------------------------------------------

    def _interfaces(self) -> None:
        for line in self.lines:
            if line.words[:1] != ["interface"] or len(line.words) < 2:
                continue
            name = "".join(line.words[1:])
            found: List[Interval] = []
            for child in line.children:
                words = child.words
                if words[:2] == ["ip", "address"] and len(words) >= 4:
                    host = parse_literal(words[2])
                    if host is not None:
                        found.append(host)
                elif words[:2] == ["ipv6", "address"] and len(words) >= 3:
                    host = parse_literal(words[2].split("/")[0])
                    if host is not None and host[0] == 6:
                        found.append(host)
                elif words[:3] == ["ip", "binding", "vpn-instance"]:
                    self._say("HUAWEI_VPN_INSTANCE", name)
            self.interfaces[name] = found

    def _zones(self) -> None:
        for line in self.lines:
            words = line.words
            if words[:2] != ["firewall", "zone"] or len(words) < 3:
                continue
            name = words[3] if words[2] == "name" and len(words) >= 4 else words[2]
            members: List[str] = []
            for child in line.children:
                if child.words[:2] == ["add", "interface"] and len(child.words) >= 3:
                    interface = "".join(child.words[2:])
                    members.append(interface)
                    self.zone_of[interface] = name
            self.zones[name] = members
        for name, members in self.zones.items():
            if name != "local":
                self.p.zones[name] = Zone(name, interfaces=members)

    # -- objects ------------------------------------------------------------------------------

    def _address_sets(self) -> None:
        for line in self.lines:
            words = line.words
            if words[:2] != ["ip", "address-set"] or len(words) < 3:
                continue
            name = words[2]
            own: List[Interval] = []
            nested: List[str] = []
            problems: List[str] = []
            for child in line.children:
                entry = child.words
                if entry[0] == "description":
                    continue
                if entry[0] != "address":
                    problems.append(f"'{' '.join(entry)[:60]}' cannot be read")
                    continue
                index = 2 if len(entry) > 2 and entry[1].isascii() and entry[1].isdigit() else 1
                if index < len(entry) and entry[index] == "address-set" and index + 1 < len(entry):
                    nested.append(entry[index + 1])
                    continue
                if index < len(entry) and re.fullmatch(r"[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}", entry[index]):
                    problems.append(f"MAC address {entry[index]}")
                    continue
                found, after, problem = _address(entry, index)
                if problem == "wildcard":
                    pieces = _wildcard(entry[index], entry[index + 1])
                    if pieces is None:
                        problems.append(f"wildcard mask {entry[index + 1][:20]} that is not contiguous, or of every address")
                    else:
                        own += pieces
                    continue
                if found is None or after != len(entry):
                    problems.append(problem or f"'{' '.join(entry)[:60]}' cannot be read")
                    continue
                own.append(found)
            self.sets[name] = (own, nested, problems)
        for name in self.sets:
            found_problems: List[str] = []
            resolved = self._set(name, found_problems)
            group = AddressGroup(name, [interval_text(i) for i in resolved] if resolved is not None else [],
                                 unsupported="; ".join(found_problems)[:200] if found_problems else "")  # fmt: skip
            self.p.address_groups[name] = group
            self.taken.add(name.lower())

    def _set(self, name: str, problems: List[str]) -> Optional[List[Interval]]:
        """The addresses of a set and its nested sets (each set resolved once); None if any part cannot be read."""
        if name in self.set_cache:
            result, found = self.set_cache[name]
            problems.extend(found)
            return result
        if name in self.visiting or name not in self.sets or len(self.visiting) > _MAX_NESTING:
            problems.append(f"address set {name[:40]} is not in the configuration, nested in itself or nested too deep")
            return None
        own, nested, own_problems = self.sets[name]
        found = [f"address set {name[:40]}: {p}" for p in own_problems]
        out: Optional[List[Interval]] = None if found else list(own)
        self.visiting.add(name)
        for inner in dict.fromkeys(nested):
            if out is None:
                break
            got = self._set(inner, found)
            out = None if got is None else out + got
        self.visiting.discard(name)
        result = normalize(out) if out is not None else None
        self.set_cache[name] = (result, found)
        problems.extend(found)
        return result

    def _ports(self, words: List[str], index: int, problems: List[str]) -> Tuple[str, int]:
        """Ports after source-port or destination-port: ``P``, ``P to Q``, several of them."""
        parts: List[str] = []
        while index < len(words) and words[index].isascii() and words[index].isdigit():
            first = int(words[index])
            last = first
            index += 1
            if index + 1 < len(words) and words[index] == "to" and words[index + 1].isascii() and words[index + 1].isdigit():
                last = int(words[index + 1])
                index += 2
            if first > last or last > 65535:
                problems.append(f"ports {first} to {last} cannot be read")
            parts.append(str(first) if first == last else f"{first}-{last}")
        if not parts:
            problems.append("ports that cannot be read")
        return ",".join(parts) if parts != ["0-65535"] else "", index

    def _service_line(self, words: List[str], problems: List[str]) -> List[ServiceEntry]:
        """``protocol tcp [source-port ...] [destination-port ...]``, ``protocol icmp [icmp-type T [C]]``,
        ``protocol N``."""
        if not words or words[0] != "protocol" or len(words) < 2:
            problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            return []
        protocol = words[1]
        number = _PROTOCOLS.get(protocol, int(protocol) if protocol.isascii() and protocol.isdigit() and int(protocol) <= 255 else None)
        if number is None or number == 0:
            problems.append(f"protocol '{protocol[:20]}' cannot be read (0 may stand for every protocol)")
            return []
        index = 2
        if number in (6, 17, 132):
            source, destination = "", ""
            while index < len(words):
                if words[index] == "source-port":
                    source, index = self._ports(words, index + 1, problems)
                elif words[index] == "destination-port":
                    destination, index = self._ports(words, index + 1, problems)
                else:
                    problems.append(f"'{words[index][:30]}' cannot be read")
                    break
            kind = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[number]
            return [ServiceEntry(kind, dst_ports=destination, src_ports=source)]
        if number in (1, 58):
            kind = Protocol.ICMP if number == 1 else Protocol.ICMP6
            if index < len(words) and words[index] == "icmp-type":
                values = [int(w) for w in words[index + 1: index + 3] if w.isascii() and w.isdigit()]
                if not values or len(words) > index + 1 + len(values) or any(v > 255 for v in values):
                    problems.append(f"'{' '.join(words)[:60]}' cannot be read (an ICMP type by name, or more)")
                    return []
                return [ServiceEntry(kind, icmp_type=values[0], icmp_code=values[1] if len(values) > 1 else None)]
            if index < len(words):
                problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            return [ServiceEntry(kind)]
        if index < len(words):
            problems.append(f"'{' '.join(words)[:60]}' cannot be read")
        return [ServiceEntry(Protocol.IP, ip_protocol=number)]

    def _service_sets(self) -> None:
        for line in self.lines:
            words = line.words
            if words[:2] != ["ip", "service-set"] or len(words) < 3:
                continue
            name = words[2]
            own: List[ServiceEntry] = []
            nested: List[str] = []
            problems: List[str] = []
            for child in line.children:
                entry = child.words
                if entry[0] == "description":
                    continue
                if entry[0] != "service":
                    problems.append(f"'{' '.join(entry)[:60]}' cannot be read")
                    continue
                index = 2 if len(entry) > 2 and entry[1].isascii() and entry[1].isdigit() else 1
                if index < len(entry) and entry[index] == "service-set" and index + 1 < len(entry):
                    nested.append(entry[index + 1])
                    continue
                own += self._service_line(entry[index:], problems)
            self.service_sets[name] = (own, nested, problems)
        for name in self.service_sets:
            entries, found = self._service_entries(name)
            self.p.services[name] = Service(name, entries or [], unsupported="; ".join(found)[:200])

    def _service_entries(self, name: str) -> Tuple[Optional[List[ServiceEntry]], List[str]]:
        """The entries of a service set with its nested sets, flattened (each set resolved once), and its problems."""
        if name in self.service_cache:
            return self.service_cache[name]
        if name not in self.service_sets and name in PREDEFINED:
            self._say("HUAWEI_PREDEFINED", name)
            return list(PREDEFINED[name]), []
        if name in self.visiting_services or name not in self.service_sets or len(self.visiting_services) > _MAX_NESTING:
            return None, [f"service set {name[:40]} is not in the configuration, nested in itself or nested too deep"]
        own, nested, own_problems = self.service_sets[name]
        found = [f"service set {name[:40]}: {p}" for p in own_problems]
        entries: Dict[str, ServiceEntry] = {repr(e): e for e in own}
        self.visiting_services.add(name)
        for inner in dict.fromkeys(nested):
            got, problems = self._service_entries(inner)
            found += problems
            entries.update((repr(e), e) for e in got or [])
        self.visiting_services.discard(name)
        if len(entries) > _MAX_ENTRIES:
            found.append(f"service set {name[:40]}: more than {_MAX_ENTRIES} entries")
        result = (None if found else list(entries.values()), found)
        self.service_cache[name] = result
        return result

    def taken_services(self) -> Set[str]:
        return {n.lower() for n in self.p.services}

    def _service(self, name: str, problems: List[str]) -> str:
        """The model service for a name of a rule: a service set, or a predefined service."""
        if name in self.service_sets:
            problems += self._service_entries(name)[1]
            return name
        if name in PREDEFINED:
            if name not in self.p.services:
                self.p.services[name] = Service(name, list(PREDEFINED[name]), builtin="huawei")
            self._say("HUAWEI_PREDEFINED", name)
            return name
        problems.append(f"service {name[:40]}: a predefined service FWShift does not know the ports of, or not in the configuration")
        return name

    def _pools(self) -> None:
        for line in self.lines:
            words = line.words
            if words[:2] != ["nat", "address-group"] or len(words) < 3:
                continue
            sections: List[Interval] = []
            pat = True
            for child in line.children:
                entry = child.words
                if entry[0] == "section":
                    rest = entry[2:] if len(entry) > 3 else entry[1:]
                    found = parse_literal(f"{rest[0]}-{rest[1]}") if len(rest) >= 2 else None
                    if found is not None:
                        sections.append(found)
                elif entry[:2] == ["mode", "no-pat"]:
                    pat = False
            self.pools[words[2]] = (normalize(sections), pat)

    # -- the security policy ---------------------------------------------------------------------

    def _blocks(self, keyword: str) -> List[_Line]:
        return [line for line in self.lines if line.words == [keyword]]

    def _rules_of(self, block: _Line) -> List[Tuple[str, int, List[List[str]]]]:
        """(rule name, line, the lines of the rule) in order."""
        out: List[Tuple[str, int, List[List[str]]]] = []
        rule_indent = 0
        for child in block.children:
            if child.words[:2] == ["rule", "name"] and len(child.words) >= 3:
                out.append((child.words[2], child.number, []))
                rule_indent = child.indent
                continue
            if out and (child.indent > rule_indent or child.words[:1] not in (["default"], ["rule"])):
                out[-1][2].append(child.words)  # (a line of the rule; block lines come before the first rule)
        return out

    def _side(self, values: List[List[str]], side: str, problems: List[str]) -> Tuple[List[str], List[str]]:
        """The members of one side of a rule, and its exclusions."""
        members: List[str] = []
        excluded: List[str] = []
        for words in values:
            target = excluded if words[0].endswith("-exclude") else members
            rest = words[1:]
            if not rest:
                problems.append(f"{words[0]} without a value")
                continue
            if rest[0] == "address-set" and len(rest) == 2:
                if rest[1] not in self.sets:
                    problems.append(f"address set {rest[1][:40]} is not in the configuration")
                else:
                    found_problems: List[str] = []
                    self._set(rest[1], found_problems)
                    problems += found_problems
                target.append(rest[1])
                continue
            if rest[0] in ("domain-set", "geo-location", "geo-location-set"):
                problems.append(f"{side} {rest[0]} {' '.join(rest[1:])[:40]}, which the configuration does not resolve to addresses")
                continue
            if rest == ["any"]:
                target.append(ANY)
                continue
            found, after, problem = _address(rest, 0)
            if found is None or after != len(rest):
                problems.append(problem if problem and problem != "wildcard" else f"{side} '{' '.join(rest)[:60]}' cannot be read")
                continue
            target.append(interval_text(found))
        return members, excluded

    def _security_policy(self) -> None:
        blocks = self._blocks("security-policy")
        # (looked for at every depth: VRP prints it with a space, after other commands of the system view)
        self.intrazone_policed = any(line.words == ["default", "packet-filter", "intrazone", "enable"] for line in _every_line(self.lines))
        if re.match(r"V100R", self.version):
            self.intrazone_policed = True
            self._say("HUAWEI_V100", self.version)
        for block in blocks:
            for child in block.children:
                if child.words == ["default", "action", "permit"]:
                    self.p.default_interzone = Action.ALLOW
            for name, number, body in self._rules_of(block):
                self._rule(name, number, body)
        default_intra = self.p.default_interzone if self.intrazone_policed else Action.ALLOW
        if default_intra != self.p.default_interzone:
            rule = Rule(self._unique("intrazone default", self.rule_names), scope=RuleScope.INTRAZONE, action=default_intra)
            rule.origin = rule.name
            rule.log_end = False
            rule.description = ("traffic inside a zone that no rule matches passes (default packet-filter intrazone enable is not set)"
                                if default_intra == Action.ALLOW else "traffic inside a zone that no rule matches meets the default policy")  # fmt: skip
            self.p.rules.append(rule)
        self.p.default_intrazone = self.p.default_interzone
        self._say("HUAWEI_DEFAULTS", ("between zones " + ("permit" if self.p.default_interzone == Action.ALLOW else "deny"))
                  + ", inside a zone " + ("permit" if default_intra == Action.ALLOW else "deny"))

    def _rule(self, name: str, number: int, body: List[List[str]]) -> None:
        problems: List[str] = []
        rule = Rule(self._unique(name, self.rule_names), action=Action.DENY)
        rule.origin = rule.name
        rule.log_end = False
        rule.source_ids = {"huawei.rule": name, "huawei.line": str(number)}
        src_zones: List[str] = []
        dst_zones: List[str] = []
        sources: List[List[str]] = []
        destinations: List[List[str]] = []
        services: List[str] = []
        action = ""
        for words in body:
            head = words[0]
            if head == "source-zone":
                src_zones += words[1:]
            elif head == "destination-zone":
                dst_zones += words[1:]
            elif head in ("source-address", "source-address-exclude"):
                sources.append(words)
            elif head in ("destination-address", "destination-address-exclude"):
                destinations.append(words)
            elif head == "service":
                if len(words) > 1 and words[1] == "protocol":
                    entries = self._service_line(words[1:], problems)
                    key = " ".join(words[1:])
                    if key not in self.inline_services and entries:
                        service_name = self._unique("-".join(words[2:])[:60] or "service", self.taken_services())
                        self.p.services[service_name] = Service(service_name, entries)
                        self.inline_services[key] = service_name
                    if key in self.inline_services:
                        services.append(self.inline_services[key])
                else:
                    services += [self._service(word, problems) for word in words[1:]]
            elif head == "action" and len(words) == 2 and words[1] in ("permit", "deny"):
                action = words[1]
            elif head == "disable":
                rule.enabled = False
            elif head == "enable":
                rule.enabled = True
            elif head == "description":
                rule.description = " ".join(words[1:])
            elif head in ("policy", "session") and words[1:] == ["logging"]:
                rule.log_end = True
            elif head == "application" and len(words) >= 3 and words[1] == "app":
                rule.applications = [a for a in rule.applications if a != ANY] + words[2:]
            elif head == "user":
                rule.users = [u for u in rule.users if u != ANY] + words[1:]
            elif head == "time-range" and len(words) == 2:
                rule.schedule = words[1]
            elif head == "profile" and len(words) >= 3:
                rule.profiles[words[1]] = words[2]
            elif head == "parent-group":
                self._say("HUAWEI_RULE_GROUP", f"{name}: {' '.join(words[1:])[:40]}")
            elif head == "long-link":
                continue
            else:
                problems.append(f"'{' '.join(words)[:60]}' is not converted")
        if not action:
            problems.append("a rule without an action")
        rule.action = Action.ALLOW if action == "permit" else Action.DENY
        if "local" in src_zones or "local" in dst_zones:
            others_src = [z for z in src_zones if z != "local"]
            others_dst = [z for z in dst_zones if z != "local"]
            if (src_zones and not others_src) or (dst_zones and not others_dst):
                self.report.skip("rule", rule.origin, "HUAWEI_LOCAL_RULE", "a rule for traffic to or from the firewall itself (the local zone): "
                                 "not converted", Severity.INFO)  # fmt: skip
                self.rule_names.discard(rule.name.lower())
                return
            self._say("HUAWEI_LOCAL_ZONE", name)
            src_zones, dst_zones = others_src, others_dst
        for zone in src_zones + dst_zones:
            if zone not in self.zones and zone not in _PREDEFINED_ZONES:
                problems.append(f"zone {zone[:40]} is not in the configuration")
            if zone not in self.p.zones:
                self.p.zones[zone] = Zone(zone)
        rule.src_zones = transform.dedupe(src_zones) or [ANY]
        rule.dst_zones = transform.dedupe(dst_zones) or [ANY]
        for values, side in ((sources, "source"), (destinations, "destination")):
            members, excluded = self._side(values, side, problems)
            if ANY in excluded:
                problems.append(f"{side} addresses that exclude every address: the rule matches no packet")
            if excluded and members and ANY not in members:
                left = self._minus(members, excluded, problems)
                if not left:
                    problems.append(f"the {side} addresses leave nothing once the excluded ones are taken out: the rule matches no packet")
                members, excluded = [interval_text(i) for i in left], []
            if side == "source":
                rule.sources, rule.negate_source = (transform.dedupe(excluded), True) if excluded else (transform.dedupe(members) or [ANY], False)
            else:
                rule.destinations, rule.negate_destination = (transform.dedupe(excluded), True) if excluded else (transform.dedupe(members) or [ANY], False)
        rule.services = transform.dedupe(services) or [ANY]
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)

    def _minus(self, members: List[str], excluded: List[str], problems: List[str]) -> List[Interval]:
        def intervals(names: List[str]) -> List[Interval]:
            out: List[Interval] = []
            for name in names:
                literal = parse_literal(name)
                found = self._set(name, problems) if name in self.sets else ([literal] if literal is not None else None)
                out += found or []
            return out

        return subtract(intervals(members), intervals(excluded))

    # -- NAT ------------------------------------------------------------------------------------

    def _nat(self) -> None:
        for line in self.lines:
            if line.words[:2] == ["nat", "server"]:
                self._nat_server(line)  # (before the security policy)
        for block in self._blocks("nat-policy"):
            for name, number, body in self._rules_of(block):
                self._nat_rule(name, number, body)  # (after it)
        for nat in self.p.nat_rules:
            nat.combines = True  # a nat server and a rule of nat-policy apply to one connection

    def _nat_rule(self, name: str, number: int, body: List[List[str]]) -> None:
        problems: List[str] = []
        nat = NatRule(self._unique(name, {n.name.lower() for n in self.p.nat_rules}))
        nat.origin = nat.name
        src_zones: List[str] = []
        dst_zones: List[str] = []
        sources: List[List[str]] = []
        destinations: List[List[str]] = []
        action: List[str] = []
        for words in body:
            head = words[0]
            if head == "source-zone":
                src_zones += words[1:]
            elif head == "destination-zone":
                dst_zones += words[1:]
            elif head == "egress-interface" and len(words) >= 2:
                interface = "".join(words[1:])
                zone = self.zone_of.get(interface)
                if zone is None:
                    problems.append(f"egress interface {interface[:40]} is in no zone")
                else:
                    dst_zones.append(zone)
            elif head in ("source-address", "source-address-exclude"):
                sources.append(words)
            elif head in ("destination-address", "destination-address-exclude"):
                destinations.append(words)
            elif head == "service":
                if len(words) > 1 and words[1] != "protocol":
                    nat.service = self._service(words[1], problems)
                    if len(words) > 2:
                        problems.append("several services")
                else:
                    problems.append("a service written in the rule")
            elif head == "action":
                action = words[1:]
            elif head == "disable":
                nat.enabled = False
            elif head == "description":
                nat.description = " ".join(words[1:])
            else:
                problems.append(f"'{' '.join(words)[:60]}' is not converted")
        nat.src_zones = transform.dedupe(src_zones) or [ANY]
        nat.dst_zones = transform.dedupe(dst_zones) or [ANY]
        for values, side in ((sources, "source"), (destinations, "destination")):
            members, excluded = self._side(values, side, problems)
            if excluded:
                problems.append(f"a {side} exclusion")
            if side == "source":
                nat.sources = transform.dedupe(members) or [ANY]
            else:
                nat.destinations = transform.dedupe(members) or [ANY]
        if action and action[0] in ("source-nat", "nat"):
            action = action[1:]
        if action == ["easy-ip"]:
            interface = ""
            if len(nat.dst_zones) == 1 and nat.dst_zones[0] != ANY:
                interface = nat.dst_zones[0]
            nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=interface)
        elif len(action) == 2 and action[0] == "address-group":
            pool = self.pools.get(action[1])
            if pool is None or not pool[0]:
                problems.append(f"address group {action[1][:40]} is not in the configuration, or has no section")
            else:
                sections, pat = pool
                nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT if pat else SnatKind.DYNAMIC, [interval_text(i) for i in sections])
        elif action in (["no-nat"],):
            pass  # (an exemption: no translation)
        else:
            problems.append(f"action {' '.join(action)[:40] or 'none'} is not converted")
        nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(nat)

    def _port(self, word: str) -> Optional[int]:
        if word.isascii() and word.isdigit():
            return int(word) if int(word) <= 65535 else None
        return PORT_NAMES.get(word)

    def _nat_server(self, line: _Line) -> None:
        words = line.words[2:]
        problems: List[str] = []
        label = ""
        index = 0
        keywords = {"zone", "protocol", "global", "inside", "no-reverse", "unr-route", "vrrp", "description", "vpn-instance"}
        if index < len(words) and words[index] not in keywords:
            label = words[index]
            index += 1
        if index < len(words) and words[index].isascii() and words[index].isdigit() and words[index] not in keywords:
            index += 1  # (the id display adds)
        zone, protocol = "", ""
        outer: List[str] = []
        inner: List[str] = []
        reverse = True
        current: Optional[List[str]] = None
        while index < len(words):
            word = words[index]
            if word == "zone" and index + 1 < len(words):
                zone, index, current = words[index + 1], index + 2, None
                continue
            if word == "protocol" and index + 1 < len(words):
                protocol, index, current = words[index + 1], index + 2, None
                continue
            if word in ("global", "inside"):
                current = outer if word == "global" else inner
                index += 1
                continue
            if word == "no-reverse":
                reverse, index, current = False, index + 1, None
                continue
            if word in ("unr-route",):
                index += 1
                continue
            if word in ("vrrp", "description", "vpn-instance"):
                if word != "description":
                    problems.append(f"{word} is not converted")
                break
            if current is None:
                problems.append(f"'{word[:30]}' cannot be read")
                break
            current.append(word)
            index += 1
        name = self._unique(f"nat-server-{label}" if label else f"nat-server-{line.number}", {n.name.lower() for n in self.p.nat_rules})
        nat = NatRule(name, src_zones=[zone] if zone else [ANY])
        nat.origin = name
        nat.description = " ".join(line.words)[:200]

        def side(values: List[str]) -> Tuple[Optional[Interval], Optional[int]]:
            if values[:1] == ["interface"] and len(values) >= 2:
                found = [a for a in self.interfaces.get(values[1], []) if a[0] == 4]
                address = found[0] if found else None
                rest = values[2:]
            else:
                address = parse_literal(values[0]) if values else None
                rest = values[1:]
            if address is None or address[1] != address[2] or len(rest) > 1:
                problems.append(f"'{' '.join(values)[:60]}': an address range, a port range or an address that is not known")
                return None, None
            port = self._port(rest[0]) if rest else None
            if rest and port is None:
                problems.append(f"port '{rest[0][:20]}' cannot be read")
            return address, port

        outside, outside_port = side(outer) if outer else (None, None)
        local, local_port = side(inner) if inner else (None, None)
        if outside is None or local is None:
            problems.append("a nat server without its global and inside address")
            nat.unsupported = list(dict.fromkeys(problems))
            self.p.nat_rules.append(nat)
            return
        number = _PROTOCOLS.get(protocol, int(protocol) if protocol.isascii() and protocol.isdigit() and int(protocol) <= 255 else None) if protocol else None
        if protocol and number is None:
            problems.append(f"protocol {protocol[:20]} cannot be read")
        if (outside_port is None) != (local_port is None) or (outside_port is not None and number not in (6, 17)):
            problems.append("ports on one side only, or with a protocol other than TCP and UDP")
        if outside_port is not None and local_port is not None and number in (6, 17):
            nat.destinations = [interval_text(outside)]
            nat.service = self._nat_service(Protocol.TCP if number == 6 else Protocol.UDP, str(outside_port))
            nat.destination_translation = DestNat(interval_text(local), str(local_port))
        elif protocol or not reverse:
            nat.destinations = [interval_text(outside)]
            if number is not None:
                nat.service = self._nat_service(number, "")
            nat.destination_translation = DestNat(interval_text(local))
        else:
            nat.sources = [interval_text(local)]
            nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(outside)], bidirectional=True)
        if reverse and nat.destination_translation is not None and nat.destination_translation.port:
            self._say("HUAWEI_NAT_REVERSE", name)
        nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(nat)

    def _nat_service(self, kind: object, port: str) -> str:
        if isinstance(kind, int):
            entries = [{1: ServiceEntry(Protocol.ICMP), 58: ServiceEntry(Protocol.ICMP6)}.get(kind, ServiceEntry(Protocol.IP, ip_protocol=kind))]
            label = f"proto-{kind}"
        else:
            assert isinstance(kind, Protocol)
            entries = [ServiceEntry(kind, dst_ports=port)]
            label = f"{kind.value}-{port}"
        for name, service in self.p.services.items():
            if service.entries == entries:
                return name
        name = self._unique(label, self.taken_services())
        self.p.services[name] = Service(name, entries)
        return name

    # -- the rest ---------------------------------------------------------------------------------

    def _other(self) -> None:
        for line in _every_line(self.lines):
            words = line.words
            if words[:1] == ["vsys"] or words[:2] == ["switch", "vsys"]:
                self._say("HUAWEI_VSYS", " ".join(words)[:60])
            elif words == ["undo", "firewall", "packet-filter", "basic-protocol", "enable"]:
                self._say("HUAWEI_BASIC_PROTOCOL", "undo firewall packet-filter basic-protocol enable")

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "HUAWEI_SOURCE",
                         f"{len(self.p.zones)} zones ({', '.join(list(self.p.zones)[:8])}{' ...' if len(self.p.zones) > 8 else ''}); "
                         f"{len(self.p.rules)} rules of the security policy, first match. The local zone (the firewall itself) is "
                         "not converted")  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.INFO, "HUAWEI_NAT_ORDER",
                             "destination NAT (nat server) is done before the security policy, which names the inside address; "
                             "the rules were rewritten for the address as it arrives. Source NAT (nat-policy) is done after it")  # fmt: skip
        texts = {
            "HUAWEI_DEFAULTS": (Severity.INFO, "what no rule matches"),
            "HUAWEI_PREDEFINED": (Severity.REVIEW, "predefined services read with the ports FWShift knows for them; check them with "
                                  "display predefined-service"),
            "HUAWEI_LOCAL_ZONE": (Severity.INFO, "rules that also name the local zone (the firewall itself): converted for their other "
                                  "zones"),
            "HUAWEI_RULE_GROUP": (Severity.REVIEW, "rules in a rule group: read in the order of the configuration; a group that is "
                                  "disabled is not seen"),
            "HUAWEI_VSYS": (Severity.REVIEW, "virtual systems: only the configuration of the root system (public) was read, up to the "
                            "first switch vsys"),
            "HUAWEI_V100": (Severity.REVIEW, "a USG6000 of V100R001, where traffic inside a zone meets the default policy: read so"),
            "HUAWEI_BASIC_PROTOCOL": (Severity.INFO, "routing protocols to and from the firewall pass without a rule; that is not "
                                      "converted"),
            "HUAWEI_VPN_INSTANCE": (Severity.REVIEW, "interfaces bound to a VPN instance: the converted policy has one routing table"),
            "HUAWEI_NAT_REVERSE": (Severity.INFO, "nat server with ports and without no-reverse also translates the server's own "
                                   "connections from that port; only the inbound half is converted"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    lines = read_lines(text)
    version = re.search(r"^\W*Software Version (V\d{3}R\w+)", text[:20000], re.MULTILINE)
    try:
        return _Builder(lines, report, version.group(1) if version else "").build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None


