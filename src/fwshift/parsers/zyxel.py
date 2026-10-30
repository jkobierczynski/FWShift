# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Zyxel ZLD parser: the configuration file (``startup-config.conf``, ``show running-config``) of a USG FLEX, ATP,
VPN or ZyWALL/USG with ZLD 4.x or 5.x -> neutral model. ZLD 3.x ``firewall`` rules are read the same way.

How ZLD decides forwarded traffic, and how that is mapped onto the neutral model:

* Zones (``zone NAME`` with ``interface``, ``crypto`` and ``sslvpn`` members) are the zones. ``ZyWALL`` (``Device`` in
  the web console of 5.x) is the firewall itself: rules to or from it are not converted. An interface in no zone is
  matched by ``from any`` / ``to any`` only.
* The security policy (``secure-policy N``, in ZLD 3.x ``firewall N``) is one list, first match, in the order of its
  numbers. A rule matches its from/to zone, source, destination, service, user and schedule; a field that is not
  given is any (the CLI Reference Guide: the ``no`` form of each "resets it to any"). Action ``allow``, ``deny``
  (silent) or ``reject`` (TCP RST or ICMP unreachable). What no rule matches meets ``secure-policy default-rule``,
  deny when it is not set. IPv4 and IPv6 (``secure-policy6``) are two lists with defaults of their own: a rule of the
  IPv4 list matches IPv4 only, so its "any" is 0.0.0.0/0 in the model.
* ``block`` in a zone blocks traffic between its members whatever the rules say. **Assumed** (the CLI Reference
  Guide says only "blocks intra-zone traffic"): it is a rule at the top of the model that denies inside that zone.
  Without it, traffic between interfaces of one zone meets the security policy like any other.
* NAT: Zyxel's User's Guide says destination NAT is applied before the security policy, whose rules name the inside
  address. The model names the address as it arrives, so rules are rewritten for it, as for FortiOS. A virtual server
  (``ip virtual-server``) is destination NAT for traffic that arrives on its interface; with ``nat-1-1-map`` and
  ``map-type any`` it is a 1:1 NAT, which also translates the inside host's own connections. Source NAT is a
  policy route with ``snat`` (first match, before routing); the default SNAT of the WAN trunk is not read.
* Objects: address objects (hosts, ranges, subnets, the address or subnet of an interface with a static address),
  address groups (nested), service objects (TCP and UDP ports, ICMP types, IP protocols) and service groups. What is
  not understood makes its rule not converted, never wider.

Assumptions not confirmed on a device are listed in DEVELOPMENT.md and in the notes of the report.
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
from ..netutil import Interval, interval_text, mask_length, parse_literal, range_text
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_DEVICE = {"zywall", "device"}  # (the zone that is the firewall itself, in any case)
# Zones a ZLD firewall comes with (USG FLEX, ATP, VPN); a rule may name them without the configuration listing them.
SYSTEM_ZONES = ("LAN1", "LAN2", "DMZ", "WAN", "OPT", "SSL_VPN", "IPSec_VPN", "TUNNEL", "WLAN", "LAN", "GUEST")
# ICMP and ICMPv6 type keywords of service-object. The CLI Reference Guide shows <0..255>, echo, echo-reply,
# unreachable and redirect "and others"; the numbers are those of the IANA registry (an assumption for the rest).
ICMP_TYPES = {"echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5, "alternate-address": 6, "echo": 8,
              "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11, "parameter-problem": 12,
              "timestamp-request": 13, "timestamp-reply": 14, "information-request": 15, "information-reply": 16,
              "mask-request": 17, "mask-reply": 18, "conversion-error": 31, "mobile-redirect": 32}  # fmt: skip
ICMP6_TYPES = {"destination-unreachable": 1, "unreachable": 1, "packet-too-big": 2, "time-exceeded": 3, "parameter-problem": 4,
               "echo": 128, "echo-request": 128, "echo-reply": 129, "router-solicitation": 133, "router-advertisement": 134,
               "neighbor-solicitation": 135, "neighbor-advertisement": 136, "redirect": 137}  # fmt: skip

# Commands that open a block of sub-commands, and the words of their sub-commands.
_RULE_WORDS = {"name", "description", "from", "to", "sourceip", "sourceip6", "destinationip", "destinationip6", "service", "user",
               "schedule", "action", "log", "activate", "deactivate", "no", "sourceport", "ctmatch", "cf-profile", "as-profile",
               "av-profile", "idp-profile", "app-profile", "ips-profile", "sslinsp-profile", "ssl-policy", "device", "sandboxing-profile",
               "reputation-profile", "session", "connlimit", "exit"}  # fmt: skip
_ROUTE_WORDS = {"description", "interface", "tunnel", "sslvpn", "source", "destination", "service", "user", "schedule", "snat",
                "next-hop", "deactivate", "activate", "no", "dscp", "dscp-marking", "srcport", "auto-destination", "auto-disable",
                "conn-check", "bandwidth", "exit"}  # fmt: skip
_SUBS = {
    "zone": {"interface", "crypto", "sslvpn", "block", "description", "no", "exit"},
    "address-group": {"address-object", "address6-object", "object-group", "description", "no", "exit"},
    "service-group": {"service-object", "object-group", "description", "no", "exit"},
    "rule": _RULE_WORDS,
    "route": _ROUTE_WORDS,
}
# First words of commands of configuration mode (a line that starts with one, at the start of a line, ends a block
# that has no exit, unless the block takes the word as a sub-command).
_TOP = {"zone", "interface", "address-object", "address6-object", "service-object", "object-group", "secure-policy", "secure-policy6",
        "firewall", "firewall6", "ip", "ipv6", "policy", "policy6", "schedule-object", "username", "groupname", "hostname",
        "configure", "write", "aaa", "app", "bwm", "connlimit", "crypto", "isakmp", "dns", "ntp", "snmp-server", "logging",
        "service-register", "sslvpn", "users", "end"}  # fmt: skip


def looks_like_zyxel(data: bytes) -> bool:
    """A ZLD configuration: commands only ZLD writes at the start of a line (secure-policy, object-group address,
    service objects with eq or range, ip virtual-server, address objects of an interface)."""
    text = data[:2_000_000].decode("utf-8", errors="replace")
    found: Set[str] = set()
    for line in text.splitlines()[:50000]:
        if re.match(r"(secure-policy6?|firewall) (\d+|insert \d+|append|default-rule)\b", line):
            found.add("policy")
        elif re.match(r"object-group (address6?|service) \S+\s*$", line):
            found.add("group")
        elif re.match(r"service-object \S+ (tcp|udp) (eq \d+|range \d+ \d+)\s*$", line):
            found.add("service")
        elif re.match(r"address-object \S+ (interface-(ip|subnet|gateway) \S+|\d+\.\d+\.\d+\.\d+(/\d+|-\d+\.\d+\.\d+\.\d+)?)\s*$", line):
            found.add("address")
        elif line.startswith("ip virtual-server ") and " map-to " in line:
            found.add("nat")
        if len(found) >= 2 and ("policy" in found or "nat" in found or len(found) >= 3):
            return True
    return False


def split_words(line: str) -> List[str]:
    """Words of a line; text in double quotes is one word."""
    return [quoted if quoted or not plain else plain for quoted, plain in re.findall(r'"([^"]*)"|(\S+)', line)]


@dataclass
class _Line:
    number: int
    words: List[str]
    children: List["_Line"] = field(default_factory=list)


def _kind(words: List[str]) -> str:
    """The kind of block a top-level command opens; '' for a command without sub-commands."""
    head = words[0]
    if head == "zone" and len(words) == 2:
        return "zone"
    if head == "object-group" and len(words) == 3:
        return {"address": "address-group", "address6": "address-group", "service": "service-group"}.get(words[1], "")
    if head in ("secure-policy", "secure-policy6", "firewall", "firewall6"):
        rest = words[1:]
        if (len(rest) == 1 and (rest[0].isdigit() or rest[0] == "append")) or (len(rest) == 2 and rest[0] == "insert"):
            return "rule"
        if len(rest) >= 3 and (rest[2].isdigit() or rest[2] == "append" or rest[2] == "insert"):
            return "rule"
        return ""
    if head in ("policy", "policy6"):
        rest = words[1:]
        if (len(rest) == 1 and (rest[0].isdigit() or rest[0] in ("append", "default-route"))) or (len(rest) == 2 and rest[0] == "insert"):
            return "route"
        return ""
    if head == "interface" and len(words) == 2:
        return "interface"
    return "other" if head in ("ip", "ipv6") and len(words) >= 3 and words[1] in ("dhcp", "dns") else ""


def read_lines(text: str) -> List[_Line]:
    """Top-level commands with the sub-commands below them. A block ends at ``exit``, at a line of ``!`` alone, or at an
    unindented command of configuration mode that the block does not take as a sub-command. ``#`` and ``!`` start a
    comment (the CLI Reference Guide, configuration files)."""
    out: List[_Line] = []
    current: Optional[_Line] = None
    kind = ""
    for number, raw in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(("#", "!")):
            if stripped.strip("!") == "":
                current, kind = None, ""  # (a line of ! alone leaves the block; a comment does not)
            continue
        words = split_words(stripped)
        if not words:
            continue
        if words == ["exit"] or words == ["end"]:
            current, kind = None, ""
            continue
        indented = raw[:1] in (" ", "\t")
        if current is not None:
            head = words[0]
            subs = _SUBS.get(kind)
            two = words[:2]
            if two in (["ip", "virtual-server"], ["ip", "route"]):
                child = False
            elif indented:
                child = True
            elif subs is not None:
                child = head in subs or head not in _TOP
            else:
                child = head not in _TOP or (kind == "interface" and head in ("ip", "ipv6") and two != ["ip", "virtual-server"])
            if child:
                current.children.append(_Line(number, words))
                continue
        entry = _Line(number, words)
        out.append(entry)
        kind = _kind(words)
        current = entry if kind else None
    return out


@dataclass
class _RuleText:
    family: int
    number: int  # the line of the header
    header: List[str]
    body: List[List[str]] = field(default_factory=list)
    from_zone: str = ""
    to_zone: str = ""


@dataclass
class _Route:
    number: int
    body: List[List[str]] = field(default_factory=list)


class _Builder:
    def __init__(self, lines: List[_Line], report: Report) -> None:
        self.lines, self.report = lines, report
        self.p = Policy(vendor="zyxel", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.interfaces: Dict[str, Tuple[Optional[Interval], Optional[Interval], str]] = {}  # name -> (host, subnet, why not)
        self.zone_of: Dict[str, str] = {}
        self.blocked: List[str] = []
        self.v4: Dict[str, str] = {}  # address-object name -> model name
        self.v6: Dict[str, str] = {}
        self.groups: Dict[str, str] = {}  # object-group address name -> model name
        self.services: Dict[str, str] = {}  # service-object or service group name -> model name
        self.schedules: Set[str] = set()
        self.users: Set[str] = set()
        self.notes: Dict[str, List[str]] = {}
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.defaults: Dict[int, Tuple[Action, str]] = {4: (Action.DENY, ""), 6: (Action.DENY, "")}
        self.inactive: Set[int] = set()
        self.address_taken: Set[str] = set()
        self.service_taken: Set[str] = set()
        self.bad_groups: Dict[str, str] = {}  # service group -> why it cannot be read

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

    def build(self) -> Policy:
        if not any(line.words[0] in ("secure-policy", "secure-policy6", "firewall", "zone", "address-object", "ip") for line in self.lines):
            raise ParseError("no security policy, zones or address objects: not a configuration of a Zyxel firewall (ZLD)")
        self._interfaces()
        self._zones()
        self._addresses()
        self._address_groups()
        self._services()
        self._service_groups()
        self._others()
        self._policy()
        self._nat()
        if any(n.destination_translation is not None or (n.source_translation is not None and n.source_translation.bidirectional)
               for n in self.p.nat_rules if not n.unsupported):  # fmt: skip
            self.p.lookup_after_dnat = True
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes()
        return self.p

    # -- interfaces and zones --------------------------------------------------------------------------------

    def _interfaces(self) -> None:
        for line in self.lines:
            if line.words[0] != "interface" or len(line.words) != 2:
                continue
            host: Optional[Interval] = None
            subnet: Optional[Interval] = None
            why = "the interface has no static IPv4 address in the configuration"
            for child in line.children:
                words = child.words
                if words[:2] == ["ip", "address"] and len(words) >= 3:
                    if words[2] in ("dhcp", "pppoe"):
                        why = f"the interface gets its address by {words[2]}"
                        continue
                    text = words[2] if "/" in words[2] or len(words) < 4 else f"{words[2]}/{words[3]}"
                    address, _, _ = text.partition("/")
                    found, single = parse_literal(text), parse_literal(address)
                    if found is not None and single is not None and found[0] == 4:
                        host, subnet = single, found
            self.interfaces[line.words[1]] = (host, subnet, why)

    def _zones(self) -> None:
        for line in self.lines:
            if line.words[0] != "zone" or len(line.words) != 2:
                continue
            name = line.words[1]
            members: List[str] = []
            for child in line.children:
                words = child.words
                if words[0] in ("interface", "crypto", "sslvpn") and len(words) == 2:
                    members.append(words[1])
                    self.zone_of[words[1]] = name
                elif words == ["block"]:
                    self.blocked.append(name)
                elif words == ["no", "block"]:
                    self.blocked = [z for z in self.blocked if z != name]
            if name.lower() in _DEVICE:
                continue
            zone = self.p.zones.setdefault(name, Zone(name))
            zone.interfaces = transform.dedupe(zone.interfaces + members)
        unzoned = [name for name in self.interfaces if name not in self.zone_of]
        if unzoned and self.p.zones:
            self._say("ZYXEL_UNZONED", ", ".join(unzoned[:8]) + (" ..." if len(unzoned) > 8 else ""))

    def _zone(self, name: str, problems: List[str]) -> str:
        if name.lower() == "any":
            return ANY
        if name not in self.p.zones:
            self.p.zones[name] = Zone(name)
            if name not in SYSTEM_ZONES:
                self._say("ZYXEL_ZONE_NOT_DEFINED", name[:40])
        return name

    # -- addresses -------------------------------------------------------------------------------------------

    def _interface_address(self, kind: str, interface: str) -> Tuple[str, str]:
        """(value, problem) of an address object of an interface."""
        host, subnet, why = self.interfaces.get(interface, (None, None, "the interface is not in the configuration"))
        if kind == "interface-gateway":
            return "", f"the gateway of interface {interface[:30]}, which the configuration does not hold as an address"
        found = host if kind == "interface-ip" else subnet
        if found is None:
            return "", f"{kind} of {interface[:30]}: {why}"
        self._say("ZYXEL_INTERFACE_OBJECT", f"{kind} {interface}")
        return interval_text(found), ""

    def _object_value(self, family: int, rest: List[str]) -> Tuple[AddressKind, str, str]:
        """(kind, value, raw) of an address object's definition."""
        raw = " ".join(rest)[:120]
        if not rest:
            return AddressKind.UNSUPPORTED, "", "no address"
        if rest[0] in ("interface-ip", "interface-subnet", "interface-gateway") and len(rest) >= 2:
            if family == 6:
                return AddressKind.UNSUPPORTED, "", f"an IPv6 address of an interface ({raw}), which the configuration does not hold"
            if len(rest) != 2:
                return AddressKind.UNSUPPORTED, "", raw
            value, problem = self._interface_address(rest[0], rest[1])
            return (AddressKind.UNSUPPORTED, "", f"{raw}: {problem}") if problem else (AddressKind.NETWORK, value, raw)
        if rest[0] == "fqdn" and len(rest) == 2 and family == 4:
            return AddressKind.FQDN, rest[1].lower(), raw
        if rest[0] in ("geography", "geo", "mac", "fqdn", "user", "dynamic"):
            return AddressKind.UNSUPPORTED, "", f"{raw}: not an address FWShift can read"
        text = rest[0]
        if len(rest) == 2 and family == 4 and mask_length(rest[1]) is not None:
            text = f"{rest[0]}/{rest[1]}"
        elif len(rest) != 1:
            return AddressKind.UNSUPPORTED, "", f"'{raw}' cannot be read"
        found = parse_literal(text)
        if found is None or found[0] != family:
            return AddressKind.UNSUPPORTED, "", f"'{raw}' is not an IPv{family} address, range or subnet"
        if "-" in text and "/" not in text:
            return AddressKind.RANGE, range_text(found), raw
        network = ipaddress.ip_network(text, strict=False)
        return AddressKind.NETWORK, str(network), raw

    def _addresses(self) -> None:
        taken = self.address_taken
        for line in self.lines:
            words = line.words
            if words[0] not in ("address-object", "address6-object") or len(words) < 3 or words[1] == "rename":
                continue
            family = 4 if words[0] == "address-object" else 6
            rest = words[2:]
            description = ""
            if "description" in rest:
                index = rest.index("description")
                description, rest = " ".join(rest[index + 1:]), rest[:index]
            kind, value, raw = self._object_value(family, rest)
            name = self._unique(words[1], taken)
            address = Address(name, kind, value, description=description, raw=raw if kind == AddressKind.UNSUPPORTED else "")
            if kind == AddressKind.FQDN:
                address.fqdn_family = 4
                self._say("ZYXEL_FQDN", words[1])
            self.p.addresses[name] = address
            (self.v4 if family == 4 else self.v6)[words[1]] = name

    def _address_groups(self) -> None:
        blocks = [line for line in self.lines if line.words[0] == "object-group" and len(line.words) == 3 and line.words[1] in ("address", "address6")]
        for line in blocks:
            self.groups[line.words[2]] = self._unique(line.words[2], self.address_taken)
        for line in blocks:
            name = self.groups[line.words[2]]
            group = AddressGroup(name)
            problems: List[str] = []
            for child in line.children:
                words = child.words
                if words[0] == "description":
                    group.description = " ".join(words[1:])
                elif words[0] in ("address-object", "address6-object", "object-group") and len(words) == 2:
                    table = {"address-object": self.v4, "address6-object": self.v6, "object-group": self.groups}[words[0]]
                    member = table.get(words[1]) or (self.v6.get(words[1]) if words[0] == "address-object" else None)
                    if member is None:
                        problems.append(f"{words[0]} {words[1][:40]} is not in the configuration")
                    else:
                        group.members.append(member)
                else:
                    problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            group.members = transform.dedupe(group.members)
            group.unsupported = "; ".join(problems)[:200]
            self.p.address_groups[name] = group

    def _address_ref(self, name: str, family: int, problems: List[str], side: str) -> str:
        """The model member for an address object or group named in a rule of one IP version."""
        if name.lower() == "any":
            return ANY_V4 if family == 4 else ANY_V6
        found = (self.v4 if family == 4 else self.v6).get(name) or self.groups.get(name) or (self.v6 if family == 4 else self.v4).get(name)
        if found is None:
            problems.append(f"{side} {name[:40]} is not in the configuration")
            return name
        versions = transform.families(self.p, found)
        if versions and family not in versions:
            problems.append(f"{side} {name[:40]} holds no IPv{family} address: the rule matches nothing")
        elif len(versions) > 1:
            self._say("ZYXEL_MIXED_GROUP", f"{name}")
        return found

    # -- services --------------------------------------------------------------------------------------------

    @staticmethod
    def _port(word: str) -> Optional[int]:
        return int(word) if word.isascii() and word.isdigit() and 1 <= int(word) <= 65535 else None

    def _service_entries(self, rest: List[str]) -> Tuple[List[ServiceEntry], str]:
        """The entries of a service object's definition, and a problem."""
        raw = " ".join(rest)[:80]
        if not rest:
            return [], "no protocol"
        protocol = rest[0].lower()
        if protocol in ("tcp", "udp"):
            kind = Protocol.TCP if protocol == "tcp" else Protocol.UDP
            if len(rest) == 3 and rest[1] == "eq" and self._port(rest[2]) is not None:
                return [ServiceEntry(kind, rest[2])], ""
            if len(rest) == 4 and rest[1] == "range":
                first, last = self._port(rest[2]), self._port(rest[3])
                if first is not None and last is not None and first <= last:
                    ports = "" if (first, last) == (1, 65535) else (str(first) if first == last else f"{first}-{last}")
                    return [ServiceEntry(kind, ports)], ""
            return [], f"'{raw}' cannot be read"
        if protocol in ("icmp", "icmpv6"):
            kind = Protocol.ICMP if protocol == "icmp" else Protocol.ICMP6
            table = ICMP_TYPES if protocol == "icmp" else ICMP6_TYPES
            if len(rest) == 1 or rest[1:] == ["any"]:
                return [ServiceEntry(kind)], ""
            if len(rest) == 2:
                value = table.get(rest[1].lower())
                if value is None and rest[1].isascii() and rest[1].isdigit() and int(rest[1]) <= 255:
                    value = int(rest[1])
                if value is not None:
                    if not rest[1].isdigit():
                        self._say("ZYXEL_ICMP_NAMES", rest[1])
                    return [ServiceEntry(kind, icmp_type=value)], ""
            return [], f"'{raw}': an ICMP type FWShift does not know"
        if protocol == "protocol" and len(rest) == 2 and rest[1].isascii() and rest[1].isdigit() and 1 <= int(rest[1]) <= 255:
            number = int(rest[1])
            if number == 1:
                return [ServiceEntry(Protocol.ICMP)], ""
            if number == 58:
                return [ServiceEntry(Protocol.ICMP6)], ""
            if number in (6, 17):
                return [ServiceEntry(Protocol.TCP if number == 6 else Protocol.UDP)], ""
            return [ServiceEntry(Protocol.IP, ip_protocol=number)], ""
        return [], f"'{raw}' cannot be read"

    def _services(self) -> None:
        taken = self.service_taken
        for line in self.lines:
            words = line.words
            if words[0] != "service-object" or len(words) < 3 or words[1] == "rename":
                continue
            entries, problem = self._service_entries(words[2:])
            name = self._unique(words[1], taken)
            self.p.services[name] = Service(name, entries, unsupported=problem)
            self.services[words[1]] = name

    def _service_groups(self) -> None:
        blocks = [line for line in self.lines if line.words[0] == "object-group" and len(line.words) == 3 and line.words[1] == "service"]
        groups: Dict[str, str] = {}
        for line in blocks:
            groups[line.words[2]] = self._unique(line.words[2], self.service_taken)
        problems_of: Dict[str, List[str]] = {}
        for line in blocks:
            name = groups[line.words[2]]
            group = ServiceGroup(name)
            problems: List[str] = []
            for child in line.children:
                words = child.words
                if words[0] == "description":
                    group.description = " ".join(words[1:])
                elif words[0] in ("service-object", "object-group") and len(words) == 2:
                    member = self.services.get(words[1]) if words[0] == "service-object" else groups.get(words[1])
                    if member is None:
                        problems.append(f"{words[0]} {words[1][:40]} is not in the configuration")
                    else:
                        group.members.append(member)
                else:
                    problems.append(f"'{' '.join(words)[:60]}' cannot be read")
            group.members = transform.dedupe(group.members)
            self.p.service_groups[name] = group
            problems_of[name] = problems
        for original, name in groups.items():
            self.services.setdefault(original, name)
            if problems_of[name]:
                # (a group the model cannot hold as it is: the rules that name it are not converted)
                self.p.service_groups[name].members = []
                self.bad_groups[name] = "; ".join(problems_of[name])[:200]

    # -- the rest of what rules refer to ----------------------------------------------------------------------

    def _others(self) -> None:
        for line in self.lines:
            words = line.words
            if words[0] == "schedule-object" and len(words) >= 2:
                self.schedules.add(words[1])
            elif words[0] == "username" and len(words) >= 2:
                self.users.add(words[1])
            elif words[0] in ("secure-policy", "secure-policy6", "firewall", "firewall6") or words[:2] == ["no", "secure-policy"] \
                    or words[:2] == ["no", "secure-policy6"] or words[:2] == ["no", "firewall"]:  # fmt: skip
                self._policy_setting(words)

    def _policy_setting(self, words: List[str]) -> None:
        negated = words[0] == "no"
        if negated:
            words = words[1:]
        family = 6 if words[0].endswith("6") else 4
        rest = words[1:]
        if rest == ["activate"]:
            if negated:
                self.inactive.add(family)
            else:
                self.inactive.discard(family)
        elif rest[:2] == ["default-rule", "action"] and len(rest) >= 3 and not negated:
            action = {"allow": Action.ALLOW, "deny": Action.DENY, "reject": Action.RESET_CLIENT}.get(rest[2])
            if action is not None:
                self.defaults[family] = (action, rest[2])
            else:
                self._say("ZYXEL_UNREAD", " ".join(words)[:60])
        elif rest[:1] == ["asymmetrical-route"]:
            if not negated and rest[1:] == ["activate"]:
                self._say("ZYXEL_ASYMMETRICAL", f"IPv{family}")
        elif rest[:1] in (["delete"], ["move"], ["flush"]):
            self._say("ZYXEL_EDIT_COMMANDS", " ".join(words)[:60])

    # -- the security policy ---------------------------------------------------------------------------------

    def _rule_texts(self) -> List[_RuleText]:
        lists: Dict[int, List[_RuleText]] = {4: [], 6: []}
        for line in self.lines:
            words = line.words
            if _kind(words) != "rule":
                continue
            family = 6 if words[0].endswith("6") else 4
            rules = lists[family]
            rest = words[1:]
            from_zone = to_zone = ""
            if len(rest) >= 3:
                from_zone, to_zone, rest = rest[0], rest[1], rest[2:]
            text = _RuleText(family, line.number, words, [c.words for c in line.children], from_zone, to_zone)
            if rest[0] == "append":
                rules.append(text)
            elif rest[0] == "insert":
                position = int(rest[1]) if rest[1].isdigit() else len(rules) + 1
                rules.insert(max(position - 1, 0), text)
            else:
                position = int(rest[0])
                same = [r for r in rules if (r.from_zone, r.to_zone) == (from_zone, to_zone)] if from_zone else rules
                if 1 <= position <= len(same):
                    same[position - 1].body += text.body
                else:
                    rules.append(text)
        return lists[4] + lists[6]

    def _policy(self) -> None:
        texts = self._rule_texts()
        for text in texts:
            self._rule(text)
        top: List[Rule] = []
        for zone in transform.dedupe(self.blocked):
            if zone.lower() in _DEVICE:
                continue
            self.p.zones.setdefault(zone, Zone(zone))
            rule = Rule(self._unique(f"block intra-zone {zone}", self.rule_names), src_zones=[zone], dst_zones=[zone], action=Action.DROP,
                        scope=RuleScope.INTRAZONE, log_end=False)  # fmt: skip
            rule.origin = rule.name
            rule.description = f"zone {zone} blocks traffic between its members (block)"
            top.append(rule)
        self.p.rules = top + self.p.rules
        for family in (4, 6):
            if family in self.inactive:
                for rule in self.p.rules:
                    if rule.source_ids.get("zyxel.list") == ("secure-policy6" if family == 6 else "secure-policy"):
                        rule.enabled = False
                self.defaults[family] = (Action.ALLOW, "the security policy is not active")
                self._say("ZYXEL_POLICY_OFF", f"IPv{family}")
        v4, why4 = self.defaults[4]
        v6, why6 = self.defaults[6]
        model = Action.ALLOW if v4 == Action.ALLOW else Action.DENY
        self.p.default_interzone = self.p.default_intrazone = model
        if v4 == Action.RESET_CLIENT:
            self._say("ZYXEL_DEFAULT_REJECT", "IPv4")
        six = Action.ALLOW if v6 == Action.ALLOW else Action.DENY
        if v6 == Action.RESET_CLIENT:
            self._say("ZYXEL_DEFAULT_REJECT", "IPv6")
        if six != model:
            action = Action.DROP if v6 == Action.DENY else v6  # (deny drops silently)
            rule = Rule(self._unique("IPv6 default-rule", self.rule_names), sources=[ANY_V6], destinations=[ANY_V6], action=action, log_end=False)
            rule.origin = rule.name
            rule.description = "what no rule of secure-policy6 matches: " + (why6 or v6.value)
            self.p.rules.append(rule)
        self._say("ZYXEL_DEFAULTS", f"IPv4 {why4 or 'deny'}, IPv6 {why6 or 'deny'}")

    def _rule(self, text: _RuleText) -> None:
        family = text.family
        problems: List[str] = []
        listing = "secure-policy6" if family == 6 else "secure-policy"
        if text.header[0].startswith("firewall"):
            listing = "firewall6" if family == 6 else "firewall"
            self._say("ZYXEL_FIREWALL", "ZLD 3.x firewall rules")
        name = ""
        description = ""
        from_zone, to_zone = text.from_zone or "any", text.to_zone or "any"
        source = destination = service = user = "any"
        schedule = "none"
        action = ""
        log = False
        state: Optional[bool] = None
        sourceport: Optional[List[str]] = None
        profiles: Dict[str, str] = {}
        for words in text.body:
            head = words[0]
            if head == "no" and len(words) >= 2:
                what = words[1]
                if what == "activate":
                    state = False
                elif what == "log":
                    log = False
                elif what in ("from", "to", "sourceip", "sourceip6", "destinationip", "destinationip6", "service", "user", "schedule",
                              "description", "sourceport", "ctmatch") or what.endswith("-profile") or what == "ssl-policy":  # fmt: skip
                    if what == "from":
                        from_zone = "any"
                    elif what == "to":
                        to_zone = "any"
                    elif what in ("sourceip", "sourceip6"):
                        source = "any"
                    elif what in ("destinationip", "destinationip6"):
                        destination = "any"
                    elif what == "service":
                        service = "any"
                    elif what == "user":
                        user = "any"
                    elif what == "schedule":
                        schedule = "none"
                    elif what == "description":
                        description = ""
                    elif what == "sourceport":
                        sourceport = None
                else:
                    problems.append(f"'{' '.join(words)[:60]}' is not converted")
                continue
            value = words[1] if len(words) == 2 else ""
            if head == "name" and value:
                name = value
            elif head == "description":
                description = " ".join(words[1:])
            elif head == "from" and value:
                from_zone = value
            elif head == "to" and value:
                to_zone = value
            elif head in ("sourceip", "sourceip6") and value:
                source = value
            elif head in ("destinationip", "destinationip6") and value:
                destination = value
            elif head == "service" and value:
                service = value
            elif head == "user" and value:
                user = value
            elif head == "schedule" and value:
                schedule = value
            elif head == "action" and value in ("allow", "deny", "reject"):
                action = value
            elif head == "log" and words[1:] in ([], ["alert"]):
                log = True
            elif head == "activate" and len(words) == 1:
                state = True
            elif head == "deactivate" and len(words) == 1:
                state = False
            elif head == "sourceport" and len(words) >= 4 and words[1] in ("tcp", "udp"):
                sourceport = words[1:]
            elif head == "ctmatch" and value in ("dnat", "snat"):
                problems.append(f"ctmatch {value}: matches only connections that a "
                                + ("virtual server translated" if value == "dnat" else "1:1 NAT translated"))
            elif (head.endswith("-profile") or head == "ssl-policy") and len(words) >= 2:
                if "deactivate" not in words:
                    profiles[head] = words[1]
            elif head == "device" and value == "any":
                continue
            else:
                problems.append(f"'{' '.join(words)[:60]}' is not converted")
        number = text.header[-1] if text.header[-1].isdigit() else ""
        base = name or (f"{listing} {number}" if number else f"{listing} line {text.number}")
        rule = Rule(self._unique(base, self.rule_names), log_end=log)
        rule.origin = rule.name
        rule.description = description
        rule.source_ids = {"zyxel.list": listing, "zyxel.line": str(text.number)}
        if name:
            rule.source_ids["zyxel.name"] = name
        if number:
            rule.source_ids["zyxel.rule"] = number
        if from_zone.lower() in _DEVICE or to_zone.lower() in _DEVICE:
            self.report.skip("rule", rule.origin, "ZYXEL_DEVICE_RULE",
                             f"a rule for traffic {'to' if to_zone.lower() in _DEVICE else 'from'} the firewall itself "
                             f"({from_zone} to {to_zone}): not converted", Severity.INFO)  # fmt: skip
            self.rule_names.discard(rule.name.lower())
            return
        rule.src_zones = [self._zone(from_zone, problems)]
        rule.dst_zones = [self._zone(to_zone, problems)]
        rule.sources = [self._address_ref(source, family, problems, "source")]
        rule.destinations = [self._address_ref(destination, family, problems, "destination")]
        if service.lower() != "any":
            found = self.services.get(service)
            if found is None:
                problems.append(f"service {service[:40]} is not in the configuration")
                rule.services = [service]
            else:
                rule.services = [found]
                bad = self.bad_groups.get(found)
                if bad:
                    problems.append(f"service group {service[:40]}: {bad}")
        if sourceport is not None:
            self._source_port(rule, sourceport, problems)
        if user.lower() != "any":
            rule.users = [user]
        if schedule.lower() != "none":
            rule.schedule = schedule
        rule.profiles = profiles
        if not action:
            problems.append("a rule without an action")
        rule.action = {"allow": Action.ALLOW, "deny": Action.DROP, "reject": Action.RESET_CLIENT}.get(action, Action.DENY)
        if state is None:
            self._say("ZYXEL_ACTIVATE_UNSAID", rule.name)
        rule.enabled = state is not False
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)

    def _source_port(self, rule: Rule, words: List[str], problems: List[str]) -> None:
        """``sourceport tcp|udp eq P | range A B``: the services of the rule, kept to that protocol and those source ports."""
        kind = Protocol.TCP if words[0] == "tcp" else Protocol.UDP
        ports = ""
        if len(words) == 3 and words[1] == "eq" and self._port(words[2]) is not None:
            ports = words[2]
        elif len(words) == 4 and words[1] == "range" and self._port(words[2]) is not None and self._port(words[3]) is not None:
            ports = f"{words[2]}-{words[3]}" if words[2] != words[3] else words[2]
        else:
            problems.append(f"sourceport {' '.join(words)[:40]} cannot be read")
            return
        if rule.services == [ANY]:
            entries: Optional[List[ServiceEntry]] = [ServiceEntry(kind)]
        else:
            entries = transform.flatten_services(self.p, rule.services[0])
            if entries is None:
                return  # (the service cannot be read: said already)
        kept = [ServiceEntry(e.protocol, e.dst_ports, ports) for e in entries or [] if e.protocol == kind and not e.src_ports]
        kept += [ServiceEntry(kind, "", ports) for e in entries or [] if e.protocol == Protocol.IP and e.ip_protocol is None]
        label = f"{rule.services[0] if rule.services != [ANY] else kind.value}-sourceport-{ports}"
        name = self._unique(label[:60], self.service_taken)
        self.p.services[name] = Service(name, kept, description=f"the service of rule {rule.name} with its source port")
        if not kept:
            problems.append(f"sourceport {words[0]} and a service without {words[0]}: the rule matches nothing")
        rule.services = [name]

    # -- NAT ----------------------------------------------------------------------------------------------------

    def _nat(self) -> None:
        routes: List[_Route] = []
        for line in self.lines:
            words = line.words
            if words[:2] == ["ip", "virtual-server"] and len(words) >= 3 and words[2] not in ("activate", "deactivate", "delete", "flush", "rename"):
                self._virtual_server(line)
            elif _kind(words) == "route" and words[0] == "policy":
                rest = words[1:]
                route = _Route(line.number, [c.words for c in line.children])
                if rest[0] == "insert" and rest[1].isdigit():
                    routes.insert(max(int(rest[1]) - 1, 0), route)
                elif rest[0].isdigit() and 1 <= int(rest[0]) <= len(routes):
                    routes[int(rest[0]) - 1].body += route.body
                elif rest[0] != "default-route":
                    routes.append(route)
            elif words[0] == "policy6" and _kind(words) == "route":
                self._say("ZYXEL_POLICY6", f"line {line.number}")
        snat = [index for index, route in enumerate(routes) if any(w[0] == "snat" and len(w) >= 2 for w in route.body)]
        last = max(snat) if snat else -1
        for index, route in enumerate(routes[: last + 1]):
            self._route(index + 1, route)
        transit = [n for n in self.p.nat_rules if n.destination_translation is not None or n.source_translation is not None]
        if any(n.destination_translation is not None for n in transit) and any(n.source_translation is not None and not n.source_translation.bidirectional
                                                                                for n in transit):  # fmt: skip
            for nat in self.p.nat_rules:
                nat.combines = True  # (a virtual server and a policy route with SNAT apply to one connection)

    def _interface_zone(self, interface: str, problems: List[str]) -> List[str]:
        if interface.lower() == "any":
            return [ANY]
        zone = self.zone_of.get(interface)
        if zone is None:
            # (an interface in no zone is matched by rules from any only: a zone of its own that no rule names is exactly that)
            self.p.zones.setdefault(interface, Zone(interface, [interface]))
            self._say("ZYXEL_NAT_UNZONED", interface)
            return [interface]
        if zone.lower() in _DEVICE:
            problems.append(f"interface {interface} is in the zone of the firewall itself")
        return [zone]

    def _nat_address(self, word: str, problems: List[str], what: str) -> str:
        if word.lower() == "any":
            return ANY_V4
        literal = parse_literal(word)
        if literal is not None:
            if literal[0] != 4:
                problems.append(f"{what} {word[:40]} is not an IPv4 address")
            return interval_text(literal)
        found = self.v4.get(word) or self.groups.get(word)
        if found is None:
            problems.append(f"{what} {word[:40]} is not in the configuration")
            return word
        return found

    def _nat_service(self, kinds: List[Protocol], ports: str) -> str:
        entries = [ServiceEntry(kind, ports) for kind in kinds]
        for name, service in self.p.services.items():
            if service.entries == entries and not service.unsupported:
                return name
        label = ("tcp-udp" if len(kinds) == 2 else kinds[0].value) + f"-{ports}"
        name = self._unique(label, self.service_taken)
        self.p.services[name] = Service(name, entries)
        return name

    def _virtual_server(self, line: _Line) -> None:
        words = line.words[2:] + [w for c in line.children for w in c.words]
        label = words[0]
        nat = NatRule(self._unique(f"virtual-server {label}", self.nat_names))
        nat.origin = nat.name
        nat.description = " ".join(line.words)[:200]
        problems: List[str] = []
        values: Dict[str, str] = {}
        flags: Set[str] = set()
        index = 1
        keyed = {"interface", "original-ip", "map-to", "map-type", "protocol", "original-port", "mapped-port", "original-port-begin",
                 "original-port-end", "mapped-port-begin", "original-service", "mapped-service", "source-ip", "description"}  # fmt: skip
        while index < len(words):
            word = words[index]
            if word in keyed and index + 1 < len(words):
                values[word] = words[index + 1]
                index += 2
            elif word in ("nat-loopback", "nat-1-1-map", "deactivate", "activate"):
                flags.add(word)
                index += 1
            else:
                problems.append(f"'{word[:30]}' cannot be read")
                index += 1
        if "interface" not in values or "original-ip" not in values or "map-to" not in values or "map-type" not in values:
            problems.append("a virtual server without its interface, original IP, mapped IP or mapping type")
            nat.unsupported = problems
            self.p.nat_rules.append(nat)
            return
        nat.enabled = "deactivate" not in flags
        zones = self._interface_zone(values["interface"], problems)
        original = self._nat_address(values["original-ip"], problems, "original IP")
        mapped = self._nat_address(values["map-to"], problems, "mapped IP")
        if mapped == ANY_V4:
            problems.append("a virtual server that maps to any address")
        if values.get("source-ip", "any").lower() != "any":
            nat.sources = [self._nat_address(values["source-ip"], problems, "source IP")]
        mapping = values["map-type"]
        kinds = {"tcp": [Protocol.TCP], "udp": [Protocol.UDP], "any": [Protocol.TCP, Protocol.UDP]}.get(values.get("protocol", ""), [])
        port = ""
        if mapping == "any":
            if any(k in values for k in ("protocol", "original-port", "original-service")):
                problems.append("map-type any with ports or a protocol")
        elif mapping == "port":
            first, second = self._port(values.get("original-port", "")), self._port(values.get("mapped-port", ""))
            if not kinds or first is None or second is None:
                problems.append("map-type port without a protocol, an original port or a mapped port that can be read")
            else:
                nat.service = self._nat_service(kinds, str(first))
                port = "" if first == second else str(second)
        elif mapping == "ports":
            first, last = self._port(values.get("original-port-begin", "")), self._port(values.get("original-port-end", ""))
            target = self._port(values.get("mapped-port-begin", ""))
            if not kinds or first is None or last is None or target is None or first > last:
                problems.append("map-type ports without a protocol or ports that can be read")
            else:
                nat.service = self._nat_service(kinds, f"{first}-{last}" if first != last else str(first))
                if target != first:
                    if first == last:
                        port = str(target)
                    else:
                        problems.append(f"ports {first}-{last} translated to the ports from {target} on (a shifted range)")
        elif mapping == "service":
            problems.append("map-type service (an original and a mapped service object)")
        else:
            problems.append(f"map-type {mapping[:20]} cannot be read")
        if "nat-loopback" in flags:
            self.report.add("nat", nat.origin, Severity.APPROX, "ZYXEL_NAT_LOOPBACK",
                            "nat-loopback: hosts behind the firewall that use the original address are translated as well (and their source "
                            "is translated to the firewall); only the translation for traffic that arrives on the interface is converted")  # fmt: skip
        one_to_one = "nat-1-1-map" in flags
        if one_to_one and mapping == "any" and original != ANY_V4:
            pre, post = transform.address_intervals(self.p, original), transform.address_intervals(self.p, mapped)
            if pre is not None and post is not None and (len(pre) != 1 or len(post) != 1 or pre[0][2] - pre[0][1] != post[0][2] - post[0][1]):
                problems.append("a many 1:1 NAT whose original and mapped addresses are not ranges of the same size")
            nat.sources = [mapped]
            nat.dst_zones = zones
            nat.source_translation = SourceNat(SnatKind.STATIC, [original], bidirectional=True)
        else:
            if one_to_one:
                self.report.add("nat", nat.origin, Severity.APPROX, "ZYXEL_ONE_TO_ONE_PORTS",
                                "nat-1-1-map of ports (or of any original address): only the inbound translation is converted, not the "
                                "translation of the inside host's own connections")  # fmt: skip
            nat.src_zones = zones
            nat.destinations = [original]
            nat.destination_translation = DestNat(mapped, port)
        nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(nat)

    def _route(self, number: int, route: _Route) -> None:
        nat = NatRule(self._unique(f"policy-route {number}", self.nat_names))
        nat.origin = nat.name
        problems: List[str] = []
        snat: List[str] = []
        for words in route.body:
            head, value = words[0], (words[1] if len(words) == 2 else "")
            if head == "description":
                nat.description = " ".join(words[1:])
            elif head == "interface" and value:
                nat.src_zones = self._interface_zone(value, problems)
            elif head in ("tunnel", "sslvpn") and value:
                zone = self.zone_of.get(value)
                nat.src_zones = [zone] if zone else [ANY]
                if zone is None:
                    problems.append(f"incoming {head} {value[:40]} is in no zone")
            elif head in ("source", "destination") and value:
                member = self._nat_address(value, problems, head) if value.lower() != "any" else ANY
                if head == "source":
                    nat.sources = [member]
                else:
                    nat.destinations = [member]
            elif head == "service" and value:
                if value.lower() != "any":
                    found = self.services.get(value)
                    if found is None:
                        problems.append(f"service {value[:40]} is not in the configuration")
                    nat.service = found or value
            elif head in ("user", "schedule", "srcport") and value and value.lower() not in ("any", "none"):
                problems.append(f"{head} {value[:40]}")
            elif head == "dscp" and words[1:] != ["any"]:
                problems.append(f"'{' '.join(words)[:40]}'")
            elif head == "snat" and len(words) >= 2:
                snat = words[1:]
            elif head == "next-hop" and len(words) >= 2:
                # (to an interface or a tunnel: the zone it is in; auto, a gateway or a trunk: wherever routing sends it)
                zone = self.zone_of.get(words[2]) if words[1] in ("interface", "tunnel") and len(words) == 3 else None
                nat.dst_zones = [zone] if zone else [ANY]
            elif head == "deactivate" and len(words) == 1:
                nat.enabled = False
            elif words in (["no", "deactivate"], ["activate"]):
                nat.enabled = True
            elif head in ("dscp-marking", "auto-destination", "auto-disable", "conn-check", "bandwidth", "no"):
                continue  # (what the route does to the packet besides NAT)
            else:
                problems.append(f"'{' '.join(words)[:60]}' cannot be read")
        if snat == ["outgoing-interface"]:
            nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=nat.dst_zones[0] if nat.dst_zones != [ANY] else "")
        elif len(snat) == 2 and snat[0] == "pool":
            pool = self._nat_address(snat[1], problems, "SNAT pool")
            nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [pool])
            self.report.add("nat", nat.origin, Severity.INFO, "ZYXEL_SNAT_POOL",
                            f"SNAT to the addresses of {snat[1]}, read as translation with port translation (the documentation does not say)")  # fmt: skip
        elif snat:
            problems.append(f"snat {' '.join(snat)[:40]} cannot be read")
        else:
            self.report.add("nat", nat.origin, Severity.INFO, "ZYXEL_ROUTE_NO_SNAT",
                            "a policy route without SNAT above one with SNAT: kept as a rule that translates nothing, so that the SNAT of "
                            "the routes below it does not apply to its traffic")  # fmt: skip
        nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(nat)

    # -- notes --------------------------------------------------------------------------------------------------

    def _notes(self) -> None:
        zones = list(self.p.zones)
        self.report.note(Severity.INFO, "ZYXEL_SOURCE",
                         f"{len(zones)} zones ({', '.join(zones[:8])}{' ...' if len(zones) > 8 else ''}); {len(self.p.rules)} rules of "
                         "the security policy, first match, IPv4 and IPv6 lists one after the other. Rules to and from the firewall "
                         "itself (ZyWALL) are not converted")  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.INFO, "ZYXEL_NAT_ORDER",
                             "virtual servers and 1:1 NAT are done before the security policy, which names the inside address; the rules "
                             "were rewritten for the address as it arrives. Source NAT of policy routes is done after it")  # fmt: skip
        if any(zone.upper() == "WAN" for zone in self.p.zones):
            self.report.note(Severity.REVIEW, "ZYXEL_DEFAULT_SNAT",
                             "the default SNAT of the WAN trunk (connections from internal interfaces leave with the address of the WAN "
                             "interface) is not a rule of the configuration and is not converted: give the target the source NAT it needs")  # fmt: skip
        if self.blocked:
            self.report.note(Severity.REVIEW, "ZYXEL_BLOCK_INTRAZONE",
                             "zones that block traffic between their members: read as a rule at the top that denies inside the zone, "
                             "whatever the rules say (not confirmed on a device): " + ", ".join(transform.dedupe(self.blocked)))  # fmt: skip
        texts = {
            "ZYXEL_DEFAULTS": (Severity.INFO, "what no rule matches (secure-policy default-rule)"),
            "ZYXEL_UNZONED": (Severity.INFO, "interfaces in no zone, which only rules from any or to any match"),
            "ZYXEL_ZONE_NOT_DEFINED": (Severity.INFO, "zones the rules name that the configuration does not define"),
            "ZYXEL_INTERFACE_OBJECT": (Severity.INFO, "address objects of an interface, read with the static address the configuration "
                                       "gives the interface"),
            "ZYXEL_FQDN": (Severity.REVIEW, "address objects of a host name (fqdn), read as names resolved for IPv4; the form is not in "
                           "the CLI Reference Guide FWShift could read"),
            "ZYXEL_MIXED_GROUP": (Severity.INFO, "address groups with addresses of both IP versions, named in rules of one: the rule matches "
                                  "its own version only, as the other side of the rule says"),
            "ZYXEL_ICMP_NAMES": (Severity.INFO, "ICMP types by name, read with the numbers of the IANA registry"),
            "ZYXEL_UNREAD": (Severity.REVIEW, "settings of the security policy that were not read"),
            "ZYXEL_ASYMMETRICAL": (Severity.INFO, "asymmetrical routes are allowed; that is not converted"),
            "ZYXEL_EDIT_COMMANDS": (Severity.REVIEW, "commands that delete, move or flush rules: not carried out; the rules are read as listed"),
            "ZYXEL_POLICY_OFF": (Severity.REVIEW, "the security policy is not active (no secure-policy activate): everything passes; its "
                                 "rules were read disabled"),
            "ZYXEL_DEFAULT_REJECT": (Severity.INFO, "the default rule rejects (TCP reset or ICMP unreachable): read as deny"),
            "ZYXEL_FIREWALL": (Severity.INFO, "the firewall rules of ZLD 3.x were read as the security policy of ZLD 4.x"),
            "ZYXEL_ACTIVATE_UNSAID": (Severity.REVIEW, "rules whose configuration says neither activate nor no activate: read as active"),
            "ZYXEL_POLICY6": (Severity.INFO, "IPv6 policy routes (policy6) are not converted"),
            "ZYXEL_NAT_UNZONED": (Severity.INFO, "interfaces in no zone that virtual servers or policy routes name: read as zones of their own, "
                                  "which only rules from any match"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    lines = read_lines(text)
    try:
        return _Builder(lines, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None
