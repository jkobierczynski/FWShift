# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Moxa industrial secure router parser: the CLI-based configuration file (``.ini``) that *System > Config
Import/Export* (or ``copy running-config tftp ...``) writes, or ``show running-config``, of a router with Moxa's classic
router firmware: EDR-810 (3.4 and later), EDR-G902/G903 and TN-4900 -> neutral model.

Since firmware 3.4 of the EDR-810 the exported configuration file is "CLI-based text" (Moxa's release notes), the
same commands as ``show running-config`` prints, headed ``! ---------- MODEL ----------``. FWShift reads the commands
of Moxa's *Industrial Secure Router CLI Command Set* manual. How the router decides, and how that is mapped:

* The Layer 3 policy (``firewall N`` with its sub-commands ``action``, ``mode``, ``protocol``, ``src-ip``, ``dst-ip``,
  ``src-port``, ``dst-port``, ``src-mac``, ``interface FROM TO``) is one list, checked from index 1: the first policy a
  packet matches accepts or drops it (Moxa's user manuals: "It starts by checking the packet with the first policy
  (Index=1)"). A field that is not given is ``all``, the action ``accept`` and the mode ``IP`` (the CLI manual's
  defaults). ``firewall N disable`` switches a policy off, ``no firewall N`` deletes it.
* Zones: the interface words of a policy, ``lan``, ``wan1`` and ``wan2`` (``all`` is any). Each is a zone of the model
  with the interface of that name. Another word is read as a zone of its own (``MOXA_INTERFACE_WORD``).
* What no policy matches passes: the classic firmware has no default action FWShift could find in its documentation;
  MX-ROS documents a global default action that applies only when it is enforced, and enforcement is off as it leaves
  the factory. **Assumed** (``MOXA_DEFAULT_ACCEPT``). Traffic inside one interface does not pass the router.
* Addresses are IPv4 (``single`` or ``range``); ``all`` is every IPv4 address (``0.0.0.0/0``). IPv6 is not read.
* ``mode MAC`` and ``src-mac`` match the source MAC address, which the model cannot hold: such a policy is not converted.
  A sub-command FWShift does not know (``session-limit``, ...) makes its policy not converted, never wider.
* NAT (``ip nat ...``): ``static inside lan A outside wan N B`` is a 1-to-1 NAT, which works both ways; ``dynamic inside
  lan A B outside wan N|auto`` is N-to-1 NAT (the source becomes the address of the WAN interface, with ports); ``static
  tcp|udp|all inside lan A P outside wan N Q`` forwards port Q of the WAN interface's address to A:P (``all`` read as TCP
  and UDP, assumed). NAT rules are first match by index; a rule with an index is inserted there, one without it is
  appended (the CLI manual). The router is Linux-based; FWShift assumes that, as with iptables, destination NAT is done
  before the Layer 3 policy, whose policies name the inside address, and source NAT after it (``MOXA_NAT_ORDER``,
  **assumed**): the policies are rewritten for the address as it arrives.
* The Layer 2 policy (``l2-filter``), the Modbus filter (``modbus-filter``, DPI), DoS defence (``dos``) and trusted
  access (``interface trusted-access``, which protects the router itself) are reported, not converted.

A configuration of MX-ROS (EDR-G9010, EDR-G9004, EDR-8010, the TN-4900 with MX-ROS) has an object-based Layer 3-7
policy whose commands FWShift could not read in Moxa's documentation: it is refused rather than guessed.

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
    Action,
    Address,
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
from ..report import Report, Severity

_MAX_LINES = 2_000_000
INTERFACE_WORDS = ("lan", "wan1", "wan2")
# Models that run MX-ROS, whose Layer 3-7 policy FWShift does not read.
_MXROS = re.compile(r"\b(EDR-G90\d\d|EDR-80\d\d|NAT-108)", re.I)
_HEADER = re.compile(r"^!\s*-{3,}\s*(\S.*?)\s*-{3,}\s*$")

# Sub-commands of a policy (config-firewall), of a Modbus filter and of an interface (config-if).
_FIREWALL_WORDS = {"action", "mode", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "src-mac", "interface", "log", "no"}
_MODBUS_WORDS = {"action", "protocol", "src-ip", "dst-ip", "function", "uid", "address", "interface", "no"}
_INTERFACE_WORDS = {"mode", "dmz", "no", "name-server", "ip", "type", "pptp"}
# First words of commands of global configuration mode.
_TOP = {"hostname", "interface", "firewall", "modbus-filter", "l2-filter", "ip", "no", "dos", "settingcheck", "username", "password",
        "clock", "ntp", "logging", "snmp-server", "router", "vlan", "copy", "configure", "end", "spanning-tree", "turbo-ring",
        "relay-warning", "dhcp", "vrrp", "crypto", "l2tp", "traffic", "proxy-arp"}  # fmt: skip


def looks_like_moxa(data: bytes) -> bool:
    """The configuration file of a Moxa router: the header line ``! ---------- MODEL ----------`` of a Moxa router (EDR,
    TN-49xx) with commands of its CLI, or two of the commands only its CLI writes (``firewall N`` with ``interface lan
    wan1``, ``ip nat static|dynamic inside lan``, ``interface wan N``, ``modbus-filter N``)."""
    text = data[:2_000_000].decode("utf-8", errors="replace")
    found: Set[str] = set()
    for number, line in enumerate(text.splitlines()[:50000]):
        stripped = line.strip()
        match = _HEADER.match(stripped)
        if match and number < 5 and re.match(r"(EDR|TN-49|NAT-108)", match.group(1), re.I):
            found.add("header")
        elif re.match(r"ip nat (static|dynamic) (all |tcp |udp )?inside lan \d", stripped):
            found.add("nat")
        elif re.match(r"interface (all|lan|wan[12]) (all|lan|wan[12])$", stripped):
            found.add("policy")
        elif re.match(r"(firewall|modbus-filter) \d+$", line):
            found.add("block")
        elif re.match(r"interface wan [12]$", line):
            found.add("wan")
        elif re.match(r"(src|dst)-ip (single \d|range \d|all$)", stripped):
            found.add("address")
        if ("header" in found and len(found) >= 2) or len(found - {"header"}) >= 3:
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
    """The kind of block a command of global configuration mode opens; '' for one without sub-commands."""
    if len(words) == 2 and words[0] in ("firewall", "modbus-filter") and words[1].isascii() and words[1].isdigit():
        return words[0]
    if words[0] == "interface" and (words[1:] == ["lan"] or (len(words) == 3 and words[1] == "wan") or words[1:] == ["bridge"]):
        return "interface"
    return ""


def _child(kind: str, words: List[str], indented: bool) -> bool:
    """Whether a line belongs to the open block."""
    head = words[0]
    if kind == "interface":
        if head == "ip":
            return words[1:2] == ["address"]
        return indented or head in _INTERFACE_WORDS - {"no"} or (head == "no" and len(words) >= 2 and words[1] in _INTERFACE_WORDS)
    if head == "interface":
        # (the interfaces of a policy, "interface lan wan1", and not a command of its own: "interface wan 1")
        return indented or (len(words) == 3 and words[1] not in ("wan", "trusted-access", "bridge"))
    if indented:
        return True
    words_of = _FIREWALL_WORDS if kind == "firewall" else _MODBUS_WORDS
    if head == "no":
        return len(words) >= 2 and words[1] in words_of and words[1] not in _TOP
    return head in words_of or head not in _TOP


def read_lines(text: str) -> List[_Line]:
    """Commands of global configuration mode with the sub-commands below them. A block ends at ``exit``, at a line of
    ``!`` alone, or at a command of global configuration mode that the block does not take. ``!`` starts a comment."""
    out: List[_Line] = []
    current: Optional[_Line] = None
    kind = ""
    for number, raw in enumerate(text.splitlines(), 1):
        if number > _MAX_LINES:
            raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a router")
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("!"):
            if stripped.strip("!") == "":
                current, kind = None, ""
            continue
        words = split_words(stripped)
        if not words:
            continue
        if words in (["exit"], ["end"]):
            current, kind = None, ""
            continue
        indented = raw[:1] in (" ", "\t")
        if current is not None and _child(kind, words, indented):
            current.children.append(_Line(number, words))
            continue
        entry = _Line(number, words)
        out.append(entry)
        kind = _kind(words)
        current = entry if kind else None
    return out


@dataclass
class _Policy:
    index: int
    line: int
    body: List[List[str]] = field(default_factory=list)
    enabled: bool = True


def _port(word: str) -> Optional[int]:
    return int(word) if word.isascii() and word.isdigit() and 0 <= int(word) <= 65535 else None


def _address(word: str) -> Optional[str]:
    try:
        return str(ipaddress.IPv4Address(word))
    except ValueError:
        return None


class _Builder:
    def __init__(self, lines: List[_Line], report: Report, header: str) -> None:
        self.lines, self.report, self.header = lines, report, header
        self.p = Policy(vendor="moxa", default_intrazone=Action.ALLOW, default_interzone=Action.ALLOW)
        self.wan: Dict[str, Tuple[str, str]] = {}  # wan1 -> (address, why not)
        self.notes: Dict[str, List[str]] = {}
        self.service_taken: Set[str] = set()
        self.unknown_words: List[str] = []

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def build(self) -> Policy:
        policies = self._policies()
        nat_lines = [line for line in self.lines if line.words[:2] == ["ip", "nat"] or line.words[:3] == ["no", "ip", "nat"]]
        if not policies and not nat_lines:
            if self.header and _MXROS.search(self.header):
                raise ParseError(f"the configuration of {self.header[:40]}, which runs MX-ROS: FWShift reads the Layer 3 policy of "
                                 "Moxa's classic router firmware (EDR-810, EDR-G902/G903, TN-4900), not the object-based Layer 3-7 "
                                 "policy of MX-ROS, whose commands it could not read in Moxa's documentation")  # fmt: skip
            raise ParseError("no Layer 3 policy (firewall N) and no NAT (ip nat): not a configuration of a Moxa router as FWShift reads it")
        for name in INTERFACE_WORDS:
            self.p.zones[name] = Zone(name, [name])
        self._interfaces()
        for policy in policies:
            self._rule(policy)
        self._nat(nat_lines)
        self._others()
        if any(n.destination_translation is not None or (n.source_translation is not None and n.source_translation.bidirectional)
               for n in self.p.nat_rules if not n.unsupported):  # fmt: skip
            self.p.lookup_after_dnat = True
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes()
        return self.p

    # -- interfaces -------------------------------------------------------------------------------------------

    def _interfaces(self) -> None:
        for line in self.lines:
            words = line.words
            if words[0] != "interface" or len(words) != 3 or words[1] != "wan" or words[2] not in ("1", "2"):
                continue
            name = f"wan{words[2]}"
            address, why = "", "the configuration gives the interface no static address"
            for child in line.children:
                w = child.words
                if w[:2] == ["type", "static"] and len(w) >= 4:
                    address = _address(w[2]) or ""
                elif w[:3] == ["ip", "address", "static"] and len(w) >= 5:
                    address = _address(w[3]) or ""
                elif w[:1] == ["type"] and len(w) >= 2 and w[1] in ("dhcp", "pppoe"):
                    address, why = "", f"the interface gets its address by {w[1]}"
                elif w == ["mode", "disable"]:
                    why = "the interface is disabled"
                    address = ""
            self.wan[name] = (address, why)
            if address:
                key = f"{name}-address"
                self.p.addresses[key] = Address(key, AddressKind.NETWORK, f"{address}/32", description=f"the address of interface WAN {words[2]}",
                                                raw=f"interface wan {words[2]}", builtin="moxa")  # fmt: skip

    # -- the Layer 3 policy -----------------------------------------------------------------------------------

    def _policies(self) -> List[_Policy]:
        by_index: Dict[int, _Policy] = {}
        for line in self.lines:
            words = line.words
            if _kind(words) == "firewall":
                index = int(words[1])
                found = by_index.get(index)
                if found is None:
                    by_index[index] = _Policy(index, line.number, [c.words for c in line.children])
                else:
                    found.body += [c.words for c in line.children]  # (the policy entered again: its settings change)
            elif words[0] == "firewall" and len(words) == 3 and words[1].isdigit() and words[2] in ("enable", "disable"):
                index = int(words[1])
                if index in by_index:
                    by_index[index].enabled = words[2] == "enable"
                else:
                    self._say("MOXA_UNREAD", " ".join(words)[:60] + " (no such policy)")
            elif words[:2] == ["no", "firewall"] and len(words) == 3 and words[2].isdigit():
                by_index.pop(int(words[2]), None)
                self._say("MOXA_EDIT_COMMANDS", " ".join(words)[:60])
            elif words[0] == "firewall" or words[:2] == ["no", "firewall"]:
                self._say("MOXA_UNREAD", " ".join(words)[:60])
        return [by_index[index] for index in sorted(by_index)]

    def _zone(self, word: str) -> str:
        word = word.lower()
        if word == "all":
            return ANY
        if word not in self.p.zones:
            self.p.zones[word] = Zone(word, [word])
            self._say("MOXA_INTERFACE_WORD", word[:30])
        return word

    def _side(self, words: List[str], what: str, problems: List[str]) -> str:
        if words == ["all"]:
            return ANY_V4
        if len(words) == 2 and words[0] == "single" and _address(words[1]):
            return str(_address(words[1]))
        if len(words) == 3 and words[0] == "range" and _address(words[1]) and _address(words[2]):
            first, last = ipaddress.IPv4Address(words[1]), ipaddress.IPv4Address(words[2])
            if first <= last:
                return str(first) if first == last else f"{first}-{last}"
        problems.append(f"{what} '{' '.join(words)[:40]}' cannot be read")
        return ANY_V4

    @staticmethod
    def _ports(words: List[str]) -> Optional[str]:
        """'' for all, the PAN-OS syntax for one port or a range; None when it cannot be read."""
        if words == ["all"]:
            return ""
        if len(words) == 2 and words[0] == "single" and _port(words[1]) is not None:
            return str(_port(words[1]))
        if len(words) == 3 and words[0] == "range":
            first, last = _port(words[1]), _port(words[2])
            if first is not None and last is not None and first <= last:
                if (first, last) in ((0, 65535), (1, 65535)):
                    return ""
                return str(first) if first == last else f"{first}-{last}"
        return None

    def _service(self, protocol: str, src: str, dst: str) -> str:
        kind = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "icmp": Protocol.ICMP}[protocol]
        entries = [ServiceEntry(kind, dst, src)]
        for name, service in self.p.services.items():
            if service.entries == entries:
                return name
        label = protocol + (f"-{dst}" if dst else "") + (f"-from-{src}" if src else "")
        name, counter = label, 2
        while name in self.service_taken:
            name = f"{label}-{counter}"
            counter += 1
        self.service_taken.add(name)
        self.p.services[name] = Service(name, entries)
        return name

    def _rule(self, policy: _Policy) -> None:
        problems: List[str] = []
        action, mode, protocol = "accept", "ip", "all"
        sides = {"src-ip": ANY_V4, "dst-ip": ANY_V4}
        ports: Dict[str, Optional[str]] = {"src-port": "", "dst-port": ""}
        port_words: Dict[str, List[str]] = {}
        zones = (ANY, ANY)
        log: Optional[bool] = None
        for words in policy.body:
            head, rest = words[0], words[1:]
            if head == "action" and rest in (["accept"], ["drop"]):
                action = rest[0]
            elif head == "mode" and len(rest) == 1 and rest[0].lower() in ("ip", "mac"):
                mode = rest[0].lower()
            elif head == "protocol" and len(rest) == 1 and rest[0].lower() in ("all", "tcp", "udp", "icmp"):
                protocol = rest[0].lower()
            elif head in sides and rest:
                sides[head] = self._side(rest, head, problems)
            elif head in ports and rest:
                ports[head] = self._ports(rest)
                port_words[head] = rest
                if ports[head] is None:
                    problems.append(f"{head} '{' '.join(rest)[:40]}' cannot be read")
            elif head == "src-mac" and rest:
                problems.append(f"source MAC address {rest[0][:20]}, which the model cannot match")
            elif head == "interface" and len(rest) == 2:
                zones = (self._zone(rest[0]), self._zone(rest[1]))
            elif head == "log" and rest in ([], ["enable"]):
                log = True
                self._say("MOXA_LOG_WORDS", " ".join(words))
            elif words in (["no", "log"], ["log", "disable"]):
                log = False
                self._say("MOXA_LOG_WORDS", " ".join(words))
            else:
                problems.append(f"'{' '.join(words)[:60]}' is not converted")
                self.unknown_words.append(head)
        name = f"firewall {policy.index}"
        rule = Rule(name, log_end=bool(log))
        rule.origin = name
        rule.source_ids = {"moxa.index": str(policy.index)}
        rule.enabled = policy.enabled
        rule.action = Action.ALLOW if action == "accept" else Action.DROP
        rule.src_zones, rule.dst_zones = [zones[0]], [zones[1]]
        rule.sources, rule.destinations = [sides["src-ip"]], [sides["dst-ip"]]
        if mode == "mac":
            problems.append("mode MAC: the policy filters by source MAC address, which the model cannot match")
        src, dst = ports["src-port"], ports["dst-port"]
        if protocol in ("tcp", "udp"):
            if src is not None and dst is not None:
                if src or dst:
                    rule.services = [self._service(protocol, src, dst)]
                else:
                    rule.services = [self._service(protocol, "", "")]
        elif protocol == "icmp":
            rule.services = [self._service("icmp", "", "")]
            if src or dst:
                problems.append(f"ports with protocol icmp ({' '.join(port_words.get('src-port', []) + port_words.get('dst-port', []))[:40]})")
        elif src or dst:
            problems.append("ports with protocol all, whose meaning the documentation does not give")
        if zones[0] != ANY and zones[0] == zones[1]:
            self._say("MOXA_SAME_INTERFACE", name)
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)

    # -- NAT ---------------------------------------------------------------------------------------------------

    def _wan_zones(self, word: str, problems: List[str]) -> Tuple[List[str], str]:
        """(zones, interface) of the WAN of a NAT rule: '1', '2' or 'auto'."""
        if word == "auto":
            return ["wan1", "wan2"], ""
        if word in ("1", "2"):
            return [f"wan{word}"], f"wan{word}"
        problems.append(f"WAN '{word[:20]}' cannot be read")
        return [ANY], ""

    def _nat_service(self, kinds: List[Protocol], port: int) -> str:
        entries = [ServiceEntry(kind, str(port)) for kind in kinds]
        for name, service in self.p.services.items():
            if service.entries == entries:
                return name
        label = ("tcp-udp" if len(kinds) == 2 else kinds[0].value) + f"-{port}"
        name, counter = label, 2
        while name in self.service_taken:
            name = f"{label}-{counter}"
            counter += 1
        self.service_taken.add(name)
        self.p.services[name] = Service(name, entries)
        return name

    def _nat_rule(self, words: List[str], number: int) -> Tuple[NatRule, Optional[int], List[Tuple[str, str]]]:
        """One ``ip nat static|dynamic ...`` line, the index it names (None: appended), and its findings (INFO)."""
        found: List[Tuple[str, str]] = []
        nat = NatRule(f"ip nat line {number}")
        nat.description = " ".join(words)[:200]
        problems: List[str] = []
        rest = words[2:]
        index: Optional[int] = None

        def take_index(expected: int) -> None:
            nonlocal index
            if len(rest) == expected + 1 and rest[-1].isdigit():
                index = int(rest[-1])
            elif len(rest) != expected:
                problems.append(f"'{' '.join(words)[:80]}' cannot be read")

        if rest[:3] == ["static", "inside", "lan"] and len(rest) >= 8 and rest[4:6] == ["outside", "wan"]:
            # 1-to-1: ip nat static inside lan A outside wan N B [index]
            take_index(8)
            inside, outside = _address(rest[3]), _address(rest[7])
            zones, _ = self._wan_zones(rest[6], problems)
            if inside is None or outside is None:
                problems.append("an inside or outside address that cannot be read")
            nat.sources = [inside or ANY_V4]
            nat.dst_zones = zones
            nat.source_translation = SourceNat(SnatKind.STATIC, [outside or ANY_V4], bidirectional=True)
        elif rest[:1] == ["dynamic"] and rest[1:3] == ["inside", "lan"] and len(rest) >= 8 and rest[5:7] == ["outside", "wan"]:
            # N-to-1: ip nat dynamic inside lan A B outside wan N|auto [index]
            take_index(8)
            first, last = _address(rest[3]), _address(rest[4])
            zones, interface = self._wan_zones(rest[7], problems)
            if first is None or last is None or ipaddress.IPv4Address(first) > ipaddress.IPv4Address(last):
                problems.append("an inside range that cannot be read")
                nat.sources = [ANY_V4]
            else:
                nat.sources = [first if first == last else f"{first}-{last}"]
            nat.src_zones = ["lan"]
            nat.dst_zones = zones
            address = self.wan.get(interface, ("", ""))[0] if interface else ""
            nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=address)
            if not interface:
                found.append(("MOXA_NAT_AUTO", "outside wan auto: the address of whichever WAN interface the traffic leaves by"))
        elif rest[:1] == ["static"] and len(rest) >= 10 and rest[1] in ("all", "tcp", "udp") and rest[2:4] == ["inside", "lan"] \
                and rest[6:8] == ["outside", "wan"]:  # fmt: skip
            # port forwarding: ip nat static all|tcp|udp inside lan A P outside wan N Q [index]
            take_index(10)
            inside, inner = _address(rest[4]), _port(rest[5])
            outer = _port(rest[9])
            zones, interface = self._wan_zones(rest[8], problems)
            if inside is None or inner is None or outer is None or not inner or not outer:
                problems.append("an inside address or a port that cannot be read")
            kinds = {"tcp": [Protocol.TCP], "udp": [Protocol.UDP], "all": [Protocol.TCP, Protocol.UDP]}[rest[1]]
            if rest[1] == "all":
                self._say("MOXA_NAT_ALL", nat.name)
            nat.src_zones = zones
            address, why = self.wan.get(interface, ("", "the interface is not in the configuration"))
            if address:
                nat.destinations = [f"{interface}-address"]
            else:
                problems.append(f"the port forward is for the address of {interface or 'a WAN interface'}, which is not known: {why}")
                nat.destinations = [ANY_V4]
            nat.service = self._nat_service(kinds, outer or 1)
            nat.destination_translation = DestNat(inside or "0.0.0.0", str(inner) if inner and inner != outer else "")
        else:
            problems.append(f"'{' '.join(words)[:80]}' cannot be read")
        nat.unsupported = list(dict.fromkeys(problems))
        return nat, index, found

    def _nat(self, lines: List[_Line]) -> None:
        ordered: List[NatRule] = []
        findings: Dict[int, List[Tuple[str, str]]] = {}
        for line in lines:
            words = line.words
            if words[:2] == ["ip", "nat"] and len(words) == 4 and words[2].isdigit() and words[3] in ("enable", "disable"):
                position = int(words[2])
                if 1 <= position <= len(ordered):
                    ordered[position - 1].enabled = words[3] == "enable"
                else:
                    self._say("MOXA_UNREAD", " ".join(words)[:60] + " (no such NAT rule)")
            elif words[:3] == ["no", "ip", "nat"] and len(words) == 4 and words[3].isdigit():
                position = int(words[3])
                if 1 <= position <= len(ordered):
                    del ordered[position - 1]
                self._say("MOXA_EDIT_COMMANDS", " ".join(words)[:60])
            elif words[:2] == ["ip", "nat"] and len(words) >= 3 and words[2] in ("static", "dynamic"):
                nat, index, found = self._nat_rule(words, line.number)
                findings[id(nat)] = found
                if index is not None and 1 <= index <= len(ordered):
                    ordered.insert(index - 1, nat)
                else:
                    ordered.append(nat)
            else:
                self._say("MOXA_UNREAD", " ".join(words)[:60])
        for position, nat in enumerate(ordered, 1):
            nat.name = nat.origin = f"ip nat {position}"
            for code, message in findings.get(id(nat), []):
                self.report.add("nat", nat.origin, Severity.INFO, code, message)
            self.p.nat_rules.append(nat)

    # -- what is reported, not converted ----------------------------------------------------------------------

    def _others(self) -> None:
        for line in self.lines:
            words = line.words
            text = " ".join(words)[:60]
            if _kind(words) == "modbus-filter" or (words[0] == "modbus-filter" and len(words) >= 2):
                self._say("MOXA_DPI", text)
            elif words[0] == "l2-filter" or words[:2] == ["no", "l2-filter"]:
                self._say("MOXA_L2_POLICY", text)
            elif words[0] == "dos":
                self._say("MOXA_DOS", " ".join(words[1:])[:40])
            elif words[:2] == ["interface", "trusted-access"]:
                self._say("MOXA_TRUSTED_ACCESS", " ".join(words[2:])[:60])

    def _notes(self) -> None:
        rules = len(self.p.rules)
        self.report.note(Severity.INFO, "MOXA_SOURCE",
                         f"{self.header or 'a Moxa router'}: {rules} policies of the Layer 3 policy, first match by index; zones are the "
                         "interfaces lan, wan1 and wan2. IPv4 only")  # fmt: skip
        self.report.note(Severity.REVIEW, "MOXA_DEFAULT_ACCEPT",
                         "what no policy matches is read as passing: the configuration names no default action, and FWShift found "
                         "none for the classic firmware in Moxa's documentation (not confirmed on a device). If the router drops it, "
                         "add a policy at the end of the converted policy that drops everything")  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.REVIEW, "MOXA_NAT_ORDER",
                             "port forwarding and 1-to-1 NAT are read as done before the Layer 3 policy, whose policies name the inside "
                             "address (as iptables does it on Linux; Moxa's documentation does not say, not confirmed): the policies "
                             "were rewritten for the address as it arrives. N-to-1 NAT is done after it")  # fmt: skip
        texts = {
            "MOXA_INTERFACE_WORD": (Severity.INFO, "interface words of policies other than lan, wan1, wan2 and all, read as zones of their own"),
            "MOXA_SAME_INTERFACE": (Severity.INFO, "policies from an interface to the same interface, which only traffic the router routes "
                                    "back out of it meets"),
            "MOXA_UNREAD": (Severity.REVIEW, "commands of the firewall and NAT that were not read"),
            "MOXA_EDIT_COMMANDS": (Severity.REVIEW, "commands that delete policies or NAT rules; carried out in the order of the file"),
            "MOXA_LOG_WORDS": (Severity.INFO, "logging of a policy read from words the CLI manual FWShift could read does not show (assumed)"),
            "MOXA_NAT_ALL": (Severity.INFO, "port forwards of protocol all, read as TCP and UDP (assumed)"),
            "MOXA_DPI": (Severity.REVIEW, "the Modbus filter (DPI) checks Modbus TCP traffic beyond addresses and ports; not converted"),
            "MOXA_L2_POLICY": (Severity.REVIEW, "the Layer 2 policy filters bridged traffic before the Layer 3 policy; not converted"),
            "MOXA_DOS": (Severity.INFO, "DoS defence settings; not converted"),
            "MOXA_TRUSTED_ACCESS": (Severity.INFO, "trusted access, which limits who reaches the router itself; not converted"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def _header(text: str) -> str:
    for line in text.splitlines()[:5]:
        match = _HEADER.match(line.strip())
        if match:
            return match.group(1)
    return ""


def parse(data: bytes, report: Report) -> Policy:
    if sum(c < 9 or 13 < c < 32 for c in data[:512]) > 16:
        raise ParseError("the configuration file is encrypted or binary: export it from the router without encryption (System > "
                         "Config Import/Export, file encryption off), or give FWShift the output of show running-config")  # fmt: skip
    text = data.decode("utf-8-sig", errors="replace")
    lines = read_lines(text)
    try:
        return _Builder(lines, report, _header(text)).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None

