# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Siemens SCALANCE parser: the CLI configuration (``show running-config``, or a script of the same commands) of a
SCALANCE SC-600 (SC622-2C, SC626-2C, SC632-2C, SC636-2C, SC642-2C, SC646-2C) or a SCALANCE S615 -> neutral model.

How the device decides forwarded traffic, and how that is mapped onto the neutral model:

* The interfaces of the firewall rules are the zones: the VLAN interfaces (``vlan 1`` becomes the zone ``vlan1``),
  the VPN interfaces (``ipsecALL``, ``ipsec N``, ``sinemarcall``, OpenVPN) and the mobile ones of an S615 (``ppp 0``,
  ``usb 0``). ``device`` is the firewall itself: a rule to or from it is its own access and is not converted, nor
  are the predefined rules (``prerule``), which only open services of the device.
* The IP rules (``ipv4rule``, ``ipv6rule`` in FIREWALL configuration mode) name one interface each way, one source
  and one destination (an address, a range, a subnet, ``0.0.0.0/0`` for all), at most one service (none: every
  protocol), an action (``acc``, ``drop``, ``rej``), a log level and a priority (``prior``). Siemens's Web Based
  Management manual of the SC-600 says the precedence "defines the sequence in which the IP rules of the firewall are
  processed (ascending from 0 ... 999)": rules are read in ascending priority. **Assumed**: the first rule that
  matches decides (the CLI is a front end of netfilter), rules of equal priority keep the order in which they were
  created (their index), and a rule that gives no priority has priority 0.
* What no rule matches is dropped between interfaces (Siemens: the firewall is a whitelist, "unsolicited inbound frames
  are dropped if no firewall rule matches"). Traffic inside one VLAN is switched and does not pass the IP firewall
  (**assumed**): the default inside a zone is allow. ``shutdown`` in FIREWALL mode switches the firewall off: every
  rule is read disabled and the default is allow.
* The firewall is stateful: one rule per connection, in the direction it is opened.
* NAT (FIREWALL NAT mode): the WBM manual says destination NAT is done before the firewall, whose rules name the
  translated destination, and source NAT after it, on the original source. Rules are rewritten for the address as it
  arrives, as for FortiOS. NAPT (port forwarding) and NETMAP of the destination are destination NAT; source NAT,
  NETMAP of the source and masquerading translate the source. **Assumed**: of each direction one rule applies to a
  connection, NAPT before NETMAP and source NAT before NETMAP and masquerading (the order is not documented).
* Objects: IP services (TCP or UDP with source and destination ports), ICMP services (type and code), IP protocols
  (a number). There are no address objects: addresses are written in the rules. A rule assigned to a rule set (user
  or digital-input firewall) applies only while the set is active and is not converted.

The format is taken from Siemens's CLI configuration manuals of the S615 (V4) and the SC-600 (V1) and the WBM manual
of the SC-600 (V2); ``ipv6rule`` and ``icmp ... ver ipv6`` are read as the IPv4 forms with IPv6 addresses, which no
manual FWShift could read shows. Assumptions are listed in DEVELOPMENT.md.
"""

from __future__ import annotations

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
from ..netutil import Interval, interval_text, mask_length, parse_literal, size
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_ACTIONS = {"acc": Action.ALLOW, "accept": Action.ALLOW, "drop": Action.DROP, "rej": Action.RESET_CLIENT, "reject": Action.RESET_CLIENT}
_LOGS = {"no": False, "none": False, "info": True, "war": True, "warning": True, "cri": True, "critical": True}
_MODES = {"firewall": "fw", "firewallnat": "nat", "firewall-mac": "mac"}
# Words that start a command of FIREWALL mode FWShift reads, or knows to be no policy.
_FW_IGNORED = {"idle", "show", "do", "icmp-show", "no"}


def split_words(line: str) -> List[str]:
    """Words of a line; a name in double quotes is one word."""
    return [quoted if quoted or not plain else plain for quoted, plain in re.findall(r'"([^"]*)"|(\S+)', line)]


def looks_like_scalance(data: bytes) -> bool:
    """A CLI configuration of a SCALANCE: two kinds of the lines only its firewall and NAT modes have, one of them a rule
    or a NAT rule."""
    text = data[:2_000_000].decode("utf-8", errors="replace")
    signs: Set[str] = set()
    for line in text.splitlines()[:50000]:
        words = line.split()
        if not words:
            continue
        head = words[0]
        if head in ("ipv4rule", "ipv6rule") and len(words) > 3 and words[1] in ("from", "idx"):
            signs.add("rule")
        elif words[:2] == ["service", "name"] and len(words) > 3 and words[3] in ("proto", "set"):
            signs.add("service")
        elif words[:2] == ["icmp", "name"] and "type" in words and "code" in words:
            signs.add("icmp")
        elif words[:2] == ["proto", "name"] and "num" in words:
            signs.add("proto")
        elif head == "prerule" and ("ipv4" in words or "ipv6" in words):
            signs.add("prerule")
        elif words == ["firewallnat"]:
            signs.add("firewallnat")
        elif head in ("napt", "src-nat") and "srcint" in words:
            signs.add("nat")
        elif words[:2] in (["netmap", "destination"], ["netmap", "source"]) and "srcint" in words:
            signs.add("nat")
        elif words == ["firewall"]:
            signs.add("firewall")
        if len(signs) >= 2 and signs & {"rule", "nat", "prerule"}:
            return True
    return False


def zone_name(words: List[str], index: int) -> Tuple[str, int]:
    """The interface at ``words[index]`` (``vlan 1``, ``vlan1``, ``ipsec 2``, ``ipsecALL``, ``device``) as a zone name,
    and the index after it."""
    word = words[index]
    if index + 1 < len(words) and re.fullmatch(r"[A-Za-z]+", word) and words[index + 1].isascii() and words[index + 1].isdigit():
        return normal_zone(word + words[index + 1]), index + 2
    return normal_zone(word), index + 1


def normal_zone(name: str) -> str:
    found = re.fullmatch(r"(?i)(vlan|ipsec|ppp|usb)(\d+)", name)
    if found:
        return f"{found.group(1).lower()}{int(found.group(2))}"
    if name.lower() in ("device", "ipsecall", "sinemarcall"):
        return {"device": "device", "ipsecall": "ipsecALL", "sinemarcall": "sinemarcall"}[name.lower()]
    return name


@dataclass
class _Raw:
    family: int
    index: int
    line: int
    from_if: str = ""
    to_if: str = ""
    source: str = ""
    destination: str = ""
    action: str = ""
    service: str = ""
    log: str = ""
    prior: Optional[int] = None
    problems: List[str] = field(default_factory=list)
    ruleset: str = ""
    deleted: bool = False


@dataclass
class _ServiceDef:
    kind: str  # service, icmp, proto
    line: int
    protocol: str = ""  # tcp or udp
    src: str = ""
    dst: str = ""
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    version: int = 4
    number: Optional[int] = None
    problems: List[str] = field(default_factory=list)


class _Builder:
    def __init__(self, text: str, report: Report) -> None:
        self.text, self.report = text, report
        self.p = Policy(vendor="scalance", default_intrazone=Action.ALLOW, default_interzone=Action.DROP)
        self.vlans: Dict[str, str] = {}  # zone -> name
        self.addresses: Dict[str, List[Tuple[Interval, Interval]]] = {}  # zone -> (address, network)
        self.routes: List[Tuple[Interval, Interval]] = []  # (network, gateway)
        self.services: Dict[str, _ServiceDef] = {}
        self.twice: Set[str] = set()
        self.raws: List[_Raw] = []
        self.counters = {4: 0, 6: 0}
        self.nat_lines: List[Tuple[int, List[str]]] = []
        self.notes: Dict[str, List[str]] = {}
        self.firewall_off = False
        self.taken: Set[str] = set()

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    # -- reading the lines -----------------------------------------------------------------------

    def build(self) -> Policy:
        self._read()
        if not self.raws and not self.nat_lines and not self.services:
            raise ParseError("no firewall rules, IP services or NAT rules: not a CLI configuration of a SCALANCE firewall")
        self._zones()
        self._services()
        self._rules()
        self._nat()
        if self.p.nat_rules:
            self.p.lookup_after_dnat = True
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes()
        return self.p

    def _read(self) -> None:
        stack: List[str] = []
        current_if = ""
        for number, raw_line in enumerate(self.text.splitlines(), 1):
            if number > _MAX_LINES:
                raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
            line = raw_line.strip()
            if not line or line.startswith(("!", "#")):
                continue
            words = split_words(line)
            if not words:
                continue
            head = words[0]
            mode = stack[-1] if stack else ""
            if words in (["configure", "terminal"], ["conf", "t"], ["write", "startup-config"]) or head == "write":
                continue
            if words == ["end"]:
                stack, current_if = [], ""
                continue
            if words == ["exit"]:
                if stack:
                    stack.pop()
                current_if = ""
                continue
            if not mode or mode in ("fw", "nat") and head in _MODES:
                if head in _MODES and len(words) == 1:
                    stack = [_MODES[head]]
                    if head == "firewall-mac":
                        self._say("SCALANCE_MAC_FIREWALL", "firewall-mac")
                    continue
                if head == "vlan" and len(words) == 2 and words[1].isascii() and words[1].isdigit():
                    stack = ["vlan:" + normal_zone("vlan" + words[1])]
                    self.vlans.setdefault(normal_zone("vlan" + words[1]), "")
                    continue
                if head == "interface" and len(words) >= 2:
                    current_if = zone_name(words, 1)[0] if len(words) > 2 or words[1].lower().startswith("vlan") else words[1]
                    stack = ["if"]
                    continue
                if words[:2] == ["ip", "route"]:
                    self._route(words)
                    continue
            if mode.startswith("vlan:"):
                if head == "name" and len(words) >= 2:
                    self.vlans[mode[5:]] = " ".join(words[1:])
                continue
            if mode == "if":
                if words[:2] == ["ip", "address"] and current_if.startswith("vlan"):
                    self._interface_address(current_if, words[2:])
                continue
            if mode == "mac":
                continue
            if mode == "nat" or (not mode and head in ("masquerading", "napt", "src-nat", "netmap")):
                self._nat_line(number, words)
                continue
            if mode == "fw" or (not mode and head in ("ipv4rule", "ipv6rule", "service", "icmp", "proto", "prerule")):
                self._firewall_line(number, words, bool(mode))
                continue

    def _route(self, words: List[str]) -> None:
        rest = words[2:]
        network: Optional[Interval] = None
        gateway: Optional[Interval] = None
        if len(rest) >= 3 and mask_length(rest[1]) is not None:
            network, gateway = parse_literal(f"{rest[0]}/{rest[1]}"), parse_literal(rest[2])
        elif len(rest) >= 2 and "/" in rest[0]:
            network, gateway = parse_literal(rest[0]), parse_literal(rest[1])
        if network is not None and gateway is not None and gateway[1] == gateway[2]:
            self.routes.append((network, gateway))

    def _interface_address(self, zone: str, rest: List[str]) -> None:
        if not rest:
            return
        if len(rest) >= 2 and mask_length(rest[1]) is not None:
            host, network = parse_literal(rest[0]), parse_literal(f"{rest[0]}/{rest[1]}")
        else:
            host, network = parse_literal(rest[0].split("/")[0]), parse_literal(rest[0])
        if host is not None and network is not None and host[1] == host[2]:
            self.addresses.setdefault(zone, []).append((host, network))

    # -- FIREWALL mode ---------------------------------------------------------------------------

    def _firewall_line(self, number: int, words: List[str], in_mode: bool) -> None:
        head = words[0]
        if head in ("ipv4rule", "ipv6rule"):
            self._rule_line(4 if head == "ipv4rule" else 6, number, words)
        elif words[:2] == ["service", "name"] and len(words) >= 3:
            self._service_line(number, words)
        elif words[:2] == ["icmp", "name"] and len(words) >= 3:
            self._icmp_line(number, words)
        elif words[:2] == ["proto", "name"] and len(words) >= 3:
            self._proto_line(number, words)
        elif head == "prerule":
            if words[-1] in ("enabled", "disabled") and "show-int" not in words:
                self._say("SCALANCE_PRERULE", " ".join(words[1:])[:60])
        elif head == "shutdown" and in_mode:
            self.firewall_off = True
        elif words[:2] == ["no", "shutdown"]:
            self.firewall_off = False
        elif head in ("ruleset", "useraccount", "di-input"):
            self._say("SCALANCE_RULESET", " ".join(words)[:60])
        elif words[:2] in (["no", "ipv4rule"], ["no", "ipv6rule"], ["no", "ipv4"], ["no", "ipv6"]):
            self._delete(words, number)
        elif head in ("service", "icmp", "proto") and len(words) >= 2 and words[1] in ("show-names", "show-types-codes"):
            return
        elif head in _FW_IGNORED or words[:2] in (["no", "service"], ["no", "icmp"], ["no", "proto"]):
            if head == "no":
                self._say("SCALANCE_EDIT_COMMANDS", " ".join(words)[:60])
        else:
            self._say("SCALANCE_UNREAD", " ".join(words)[:60])

    def _delete(self, words: List[str], number: int) -> None:
        """``no ipv4rule idx N`` (the form is not in the manuals FWShift could read): the rule is taken out."""
        self._say("SCALANCE_EDIT_COMMANDS", " ".join(words)[:60])
        family = 6 if "6" in words[1] else 4
        found = [int(w) for w in words[2:] if w.isascii() and w.isdigit()]
        if found:
            for raw in self.raws:
                if raw.family == family and raw.index == found[-1]:
                    raw.deleted = True

    def _rule_line(self, family: int, number: int, words: List[str]) -> None:
        if len(words) >= 2 and words[1] in ("show-rules", "show"):
            return
        if len(words) >= 3 and words[1] == "idx":
            self._rule_change(family, number, words)
            return
        if len(words) >= 2 and words[1] == "del":
            self._say("SCALANCE_RULESET", " ".join(words)[:60])
            return
        if len(words) < 2 or words[1] != "from":
            self._say("SCALANCE_UNREAD", " ".join(words)[:60])
            return
        self.counters[family] += 1
        raw = _Raw(family, self.counters[family], number)
        index = 1
        while index < len(words):
            key = words[index]
            index += 1
            if index >= len(words):
                raw.problems.append(f"'{key[:20]}' without a value")
                break
            if key in ("from", "to"):
                zone, index = zone_name(words, index)
                if key == "from":
                    raw.from_if = zone
                else:
                    raw.to_if = zone
            elif key in ("srcip", "dstip"):
                value, index = self._address_words(words, index)
                if key == "srcip":
                    raw.source = value
                else:
                    raw.destination = value
            elif key == "action":
                raw.action, index = words[index], index + 1
            elif key == "service":
                raw.service, index = words[index], index + 1
            elif key == "log":
                raw.log, index = words[index], index + 1
            elif key == "prior":
                value = words[index]
                index += 1
                if value.isascii() and value.isdigit():
                    raw.prior = int(value)
                else:
                    raw.problems.append(f"priority '{value[:20]}' cannot be read")
            elif key == "ruleset":
                raw.ruleset, index = words[index], index + 1
            else:
                raw.problems.append(f"'{' '.join(words[index - 1:])[:60]}' is not read")
                break
        self.raws.append(raw)

    @staticmethod
    def _address_words(words: List[str], index: int) -> Tuple[str, int]:
        """An address of a rule: one word, or ``A - B`` (a range as the manuals print it)."""
        if index + 2 < len(words) and words[index + 1] == "-" and parse_literal(words[index]) is not None:
            return f"{words[index]}-{words[index + 2]}", index + 3
        return words[index], index + 1

    def _rule_change(self, family: int, number: int, words: List[str]) -> None:
        """``ipv4rule idx N set FIELD VALUE``."""
        if not (words[2].isascii() and words[2].isdigit()) or len(words) < 6 or words[3] != "set":
            self._say("SCALANCE_UNREAD", " ".join(words)[:60])
            return
        index = int(words[2])
        raw = next((r for r in self.raws if r.family == family and r.index == index and not r.deleted), None)
        if raw is None:
            self._say("SCALANCE_UNREAD", f"{' '.join(words)[:60]} (no such rule)")
            return
        key, value = words[4], words[5:]
        if key in ("from", "to"):
            zone = zone_name(value, 0)[0]
            if key == "from":
                raw.from_if = zone
            else:
                raw.to_if = zone
        elif key in ("srcip", "dstip"):
            text = self._address_words(value, 0)[0]
            if key == "srcip":
                raw.source = text
            else:
                raw.destination = text
        elif key == "action":
            raw.action = value[0]
        elif key == "service":
            raw.service = value[0]
        elif key == "log":
            raw.log = value[0]
        elif key == "prior" and value[0].isascii() and value[0].isdigit():
            raw.prior = int(value[0])
        elif key == "ruleset":
            raw.ruleset = value[0]
        else:
            raw.problems.append(f"'{' '.join(words)[:60]}' is not read")

    @staticmethod
    def _ports(words: List[str], index: int, problems: List[str]) -> Tuple[str, int]:
        """``all``, ``port N`` or ``range A - B`` -> (model port list, next index)."""
        if index >= len(words):
            problems.append("ports are missing")
            return "", index
        if words[index] == "all":
            return "", index + 1
        if words[index] == "port" and index + 1 < len(words) and words[index + 1].isdigit():
            port = int(words[index + 1])
            if port > 65535:
                problems.append(f"port {port} cannot be read")
            return str(port), index + 2
        if words[index] == "range" and index + 1 < len(words):
            text = words[index + 1]
            after = index + 2
            if index + 3 < len(words) and words[index + 2] == "-":
                text, after = f"{words[index + 1]}-{words[index + 3]}", index + 4
            first, _, last = text.partition("-")
            if first.isdigit() and last.isdigit() and int(first) <= int(last) <= 65535:
                return ("" if (int(first), int(last)) == (0, 65535) else (first if first == last else f"{int(first)}-{int(last)}")), after
            problems.append(f"port range '{text[:20]}' cannot be read")
            return "", after
        problems.append(f"ports '{words[index][:20]}' cannot be read")
        return "", index + 1

    def _define(self, name: str, definition: _ServiceDef) -> _ServiceDef:
        known = self.services.get(name)
        if known is not None and known.kind != definition.kind:
            self.twice.add(name)
        if known is None or known.kind != definition.kind:
            self.services[name] = definition
            return definition
        return known

    def _service_line(self, number: int, words: List[str]) -> None:
        name = words[2]
        rest = words[3:]
        if rest[:1] == ["set"]:
            known = self.services.get(name)
            if known is None or known.kind != "service" or len(rest) < 3:
                self._say("SCALANCE_UNREAD", " ".join(words)[:60])
                return
            if rest[1] in ("prot", "proto") and rest[2] in ("tcp", "udp"):
                known.protocol = rest[2]
            elif rest[1] in ("src", "dst"):
                value, _ = self._ports(rest, 2, known.problems)
                if rest[1] == "src":
                    known.src = value
                else:
                    known.dst = value
            else:
                known.problems.append(f"'{' '.join(rest)[:40]}' is not read")
            return
        definition = self._define(name, _ServiceDef("service", number, protocol="tcp"))
        index = 0
        while index < len(rest):
            key = rest[index]
            if key in ("proto", "prot") and index + 1 < len(rest):
                if rest[index + 1] not in ("tcp", "udp"):
                    definition.problems.append(f"protocol '{rest[index + 1][:20]}' cannot be read")
                definition.protocol = rest[index + 1]
                index += 2
            elif key in ("src", "dst"):
                value, index = self._ports(rest, index + 1, definition.problems)
                if key == "src":
                    definition.src = value
                else:
                    definition.dst = value
            else:
                definition.problems.append(f"'{' '.join(rest[index:])[:40]}' is not read")
                break

    def _icmp_line(self, number: int, words: List[str]) -> None:
        name = words[2]
        rest = words[3:]
        changing = rest[:1] == ["set"]
        if changing:
            known = self.services.get(name)
            if known is None or known.kind != "icmp":
                self._say("SCALANCE_UNREAD", " ".join(words)[:60])
                return
            definition = known
            rest = rest[1:]
        else:
            definition = self._define(name, _ServiceDef("icmp", number))
        index = 0
        while index + 1 < len(rest):
            key, value = rest[index], rest[index + 1]
            index += 2
            if key in ("type", "code"):
                if not (value.isascii() and value.isdigit()) or int(value) > 255:
                    definition.problems.append(f"ICMP {key} '{value[:10]}' is not a type or code FWShift knows the meaning of")
                    continue
                if key == "type":
                    definition.icmp_type = int(value)
                else:
                    definition.icmp_code = int(value)
            elif key == "ver" and value in ("ipv4", "ipv6"):
                definition.version = 4 if value == "ipv4" else 6
            else:
                definition.problems.append(f"'{key[:20]} {value[:20]}' is not read")
        if index < len(rest):
            definition.problems.append(f"'{rest[index][:20]}' is not read")

    def _proto_line(self, number: int, words: List[str]) -> None:
        definition = self._define(words[2], _ServiceDef("proto", number, number=254))  # (254 when no number is given)
        rest = words[3:]
        if rest[:1] == ["set"]:
            rest = rest[1:]
        if len(rest) >= 2 and rest[0] == "num" and rest[1].isascii() and rest[1].isdigit() and 1 <= int(rest[1]) <= 254:
            definition.number = int(rest[1])
        elif rest:
            definition.problems.append(f"'{' '.join(rest)[:40]}' is not read")

    # -- FIREWALL NAT mode -----------------------------------------------------------------------

    def _nat_line(self, number: int, words: List[str]) -> None:
        head = words[0]
        if head == "no" or words[-1] in ("show-idx", "show-int") or head == "ipsec":
            if head == "no":
                self._say("SCALANCE_EDIT_COMMANDS", " ".join(words)[:60])
            return
        if head in ("masquerading", "napt", "src-nat", "netmap"):
            self.nat_lines.append((number, words))
        else:
            self._say("SCALANCE_UNREAD", " ".join(words)[:60])

    # -- the model -------------------------------------------------------------------------------

    def _zones(self) -> None:
        for zone, name in self.vlans.items():
            self.p.zones[zone] = Zone(zone, interfaces=[zone])
        for zone in self.addresses:
            self.p.zones.setdefault(zone, Zone(zone, interfaces=[zone]))
        for zone, found in self.addresses.items():
            networks = [interval_text(network) for _, network in found]
            for network, gateway in self.routes:
                if any(n[0] == gateway[0] and n[1] <= gateway[1] <= n[2] for _, n in found):
                    networks.append(interval_text(network))
            self.p.zone_networks[zone] = transform.dedupe(networks)

    def _zone(self, zone: str) -> str:
        if zone and zone != "device" and zone not in self.p.zones:
            self.p.zones[zone] = Zone(zone, interfaces=[zone])
        return zone

    def _services(self) -> None:
        for name, definition in self.services.items():
            if name == ANY:
                continue  # (a rule that names it is not converted)
            problems = list(definition.problems)
            if name in self.twice:
                problems.append("the name is given to services of two kinds (IP service, ICMP service, IP protocol)")
            entries: List[ServiceEntry] = []
            if definition.kind == "service":
                if definition.protocol in ("tcp", "udp"):
                    entries = [ServiceEntry(Protocol(definition.protocol), definition.dst, definition.src)]
            elif definition.kind == "icmp":
                if definition.icmp_type is None:
                    problems.append("an ICMP service without a type")
                kind = Protocol.ICMP if definition.version == 4 else Protocol.ICMP6
                entries = [ServiceEntry(kind, icmp_type=definition.icmp_type, icmp_code=definition.icmp_code)]
            else:
                number = definition.number or 254
                entries = [{1: ServiceEntry(Protocol.ICMP), 58: ServiceEntry(Protocol.ICMP6), 6: ServiceEntry(Protocol.TCP),
                            17: ServiceEntry(Protocol.UDP), 132: ServiceEntry(Protocol.SCTP)}.get(number, ServiceEntry(Protocol.IP, ip_protocol=number))]  # fmt: skip
            self.p.services[name] = Service(name, entries, description=f"{definition.kind} line {definition.line}",
                                            unsupported="; ".join(problems)[:200])  # fmt: skip
            self.taken.add(name.lower())

    def _side(self, value: str, family: int, problems: List[str], side: str) -> List[str]:
        if not value:
            problems.append(f"no {side} address")
            return [ANY]
        if value.upper() == "DYNAMIC":
            problems.append(f"{side} DYNAMIC: the address of the user who activates the rule set, or of the digital input")
            return [ANY]
        found = parse_literal(value)
        if found is None:
            problems.append(f"{side} address '{value[:40]}' cannot be read")
            return [ANY]
        if found[0] != family:
            problems.append(f"{side} address {value[:40]} is not of the IP version of the rule (IPv{family})")
            return [ANY]
        if size(found) == (2**32 if family == 4 else 2**128):
            return [ANY_V4 if family == 4 else ANY_V6]
        return [interval_text(found)]

    def _rules(self) -> None:
        names: Set[str] = set()
        for family in (4, 6):
            raws = [r for r in self.raws if r.family == family and not r.deleted]
            raws.sort(key=lambda r: (r.prior if r.prior is not None else 0, r.index))
            for raw in raws:
                self._rule(raw, names)
        if self.firewall_off:
            for rule in self.p.rules:
                rule.enabled = False
            self.p.default_interzone = Action.ALLOW

    def _rule(self, raw: _Raw, names: Set[str]) -> None:
        label = f"ipv{raw.family}rule {raw.index}"
        rule = Rule(label, action=Action.DENY)
        rule.origin = label
        names.add(label)
        rule.source_ids = {"scalance.list": f"ipv{raw.family}rule", "scalance.idx": str(raw.index), "scalance.line": str(raw.line)}
        if raw.prior is not None:
            rule.source_ids["scalance.prior"] = str(raw.prior)
        problems = list(raw.problems)
        if "device" in (raw.from_if, raw.to_if):
            self.report.skip("rule", rule.origin, "SCALANCE_DEVICE_RULE", "a rule for traffic to or from the firewall itself "
                             "(device): its own access, not converted", Severity.INFO)  # fmt: skip
            return
        if not raw.from_if or not raw.to_if:
            problems.append("a rule without its two interfaces")
        rule.src_zones = [self._zone(raw.from_if)] if raw.from_if else [ANY]
        rule.dst_zones = [self._zone(raw.to_if)] if raw.to_if else [ANY]
        rule.sources = self._side(raw.source, raw.family, problems, "source")
        rule.destinations = self._side(raw.destination, raw.family, problems, "destination")
        action = _ACTIONS.get(raw.action)
        if action is None:
            problems.append(f"action '{raw.action[:20]}' cannot be read" if raw.action else "a rule without an action")
        rule.action = action or Action.DENY
        if raw.log and raw.log not in _LOGS:
            problems.append(f"log '{raw.log[:20]}' cannot be read")
        rule.log_end = _LOGS.get(raw.log, False)
        if raw.service and raw.service != "all":
            rule.services = [raw.service]
            definition = self.services.get(raw.service)
            if raw.service == ANY:
                problems.append("a service named any, which the model reads as every service")
            elif definition is None:
                problems.append(f"service {raw.service[:40]} is not in the configuration")
            elif definition.problems or raw.service in self.twice:
                problems.append(f"service {raw.service[:40]} cannot be read")
            elif definition.kind == "icmp" and definition.version != raw.family:
                problems.append(f"ICMP service {raw.service[:40]} of the other IP version: the rule matches no packet")
        if raw.ruleset:
            problems.append(f"assigned to the rule set {raw.ruleset[:40]}: it applies only while the set is activated (by a user "
                            "or a digital input)")
        if raw.from_if and raw.from_if == raw.to_if:
            self.report.add("rule", rule.origin, Severity.INFO, "SCALANCE_SAME_INTERFACE",
                            f"from and to {raw.from_if}: traffic inside one VLAN is switched and does not pass the IP firewall, "
                            "so the rule matches only what is routed between subnets of that interface")  # fmt: skip
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)

    # -- NAT ---------------------------------------------------------------------------------------

    def _interface_ip(self, zone: str, problems: List[str]) -> str:
        found = [host for host, _ in self.addresses.get(zone, []) if host[0] == 4]
        if not found:
            problems.append(f"'auto': the address of {zone}, which the configuration does not give")
            return ""
        return interval_text(found[0])

    def _nat_fields(self, words: List[str], start: int, problems: List[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        index = start
        while index < len(words):
            key = words[index]
            index += 1
            if index >= len(words):
                problems.append(f"'{key[:20]}' without a value")
                break
            if key in ("srcint", "dstint"):
                out[key], index = zone_name(words, index)
            elif key in ("dstport", "transport"):
                value = words[index]
                index += 1
                if index + 1 < len(words) and words[index] == "-":
                    value, index = f"{value}-{words[index + 1]}", index + 2
                out[key] = value
            elif key in ("srcip", "dstip", "transip"):
                out[key], index = self._address_words(words, index)
            elif key in ("proto", "type"):
                out[key], index = words[index], index + 1
            else:
                problems.append(f"'{' '.join(words[index - 1:])[:60]}' is not read")
                break
        if out.get("type", "ipv4") != "ipv4":
            problems.append(f"type {out['type'][:10]}: only IPv4 NAT is read")
        return out

    def _nat_address(self, value: str, zone: str, problems: List[str], what: str) -> str:
        if value == "auto":
            return self._interface_ip(zone, problems) or ANY
        found = parse_literal(value)
        if found is None or found[0] != 4:
            problems.append(f"{what} '{value[:40]}' cannot be read")
            return ANY
        return ANY if size(found) == 2**32 else interval_text(found)

    def _nat_service(self, protocol: str, ports: str) -> str:
        entries = [ServiceEntry(Protocol(protocol), ports)]
        for name, service in self.p.services.items():
            if service.entries == entries and not service.unsupported:
                return name
        name, counter = f"{protocol}-{ports}", 2
        while name.lower() in self.taken:
            name, counter = f"{protocol}-{ports}-{counter}", counter + 1
        self.taken.add(name.lower())
        self.p.services[name] = Service(name, entries)
        return name

    def _nat(self) -> None:
        groups: Dict[str, List[NatRule]] = {"napt": [], "dnetmap": [], "snetmap": [], "src-nat": [], "masquerading": []}
        counters: Dict[str, int] = {}
        for number, words in self.nat_lines:
            head = words[0]
            kind = head if head != "netmap" else ("dnetmap" if words[1:2] == ["destination"] else "snetmap")
            counters[kind] = counters.get(kind, 0) + 1
            label = {"dnetmap": "netmap destination", "snetmap": "netmap source"}.get(kind, kind)
            nat = NatRule(f"{label} {counters[kind]}")
            nat.origin = nat.name
            nat.combines = True  # (one rule of each direction applies to a connection, as in netfilter)
            nat.description = " ".join(words)[:200]
            problems: List[str] = []
            if kind == "masquerading":
                if len(words) < 2:
                    problems.append("masquerading without an interface")
                else:
                    zone = self._zone(zone_name(words, 1)[0])
                    nat.dst_zones = [zone]
                    nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=zone,
                                                       interface_address=self._interface_ip(zone, []))  # fmt: skip
            else:
                fields = self._nat_fields(words, 1 if kind in ("napt", "src-nat") else 2, problems)
                src_if, dst_if = fields.get("srcint", ""), fields.get("dstint", "")
                if not src_if or (kind != "napt" and not dst_if):
                    problems.append("an interface is missing")
                if kind == "napt":
                    self._napt(nat, fields, src_if, problems)
                elif kind == "src-nat":
                    nat.src_zones, nat.dst_zones = [self._zone(src_if) or ANY], [self._zone(dst_if) or ANY]
                    nat.sources = [self._nat_address(fields.get("srcip", "0.0.0.0/0"), src_if, problems, "source")]
                    nat.destinations = [self._nat_address(fields.get("dstip", "0.0.0.0/0"), dst_if, problems, "destination")]
                    translated = fields.get("transip", "")
                    if translated == "auto":
                        nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=dst_if,
                                                           interface_address=self._interface_ip(dst_if, []))  # fmt: skip
                    else:
                        address = self._nat_address(translated, dst_if, problems, "translated address")
                        nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [address])
                else:
                    self._netmap(nat, kind, fields, src_if, dst_if, problems)
            nat.unsupported = list(dict.fromkeys(problems))
            groups[kind].append(nat)
        self.p.nat_rules = [nat for kind in ("napt", "dnetmap", "snetmap", "src-nat", "masquerading") for nat in groups[kind]]

    def _napt(self, nat: NatRule, fields: Dict[str, str], src_if: str, problems: List[str]) -> None:
        zone = self._zone(src_if) or ANY
        nat.src_zones = nat.dst_zones = [zone]
        protocol = fields.get("proto", "")
        if protocol not in ("tcp", "udp"):
            problems.append(f"protocol '{protocol[:10]}' cannot be read")
            protocol = "tcp"
        nat.destinations = [self._nat_address(fields.get("dstip", ""), src_if, problems, "destination")]
        inner = parse_literal(fields.get("transip", ""))
        if inner is None or inner[0] != 4 or inner[1] != inner[2]:
            problems.append("the translated address is not one IPv4 address")
        outer_ports, inner_ports = fields.get("dstport", ""), fields.get("transport", "")
        outer = self._range(outer_ports)
        translated = self._range(inner_ports)
        if outer is None or translated is None:
            problems.append(f"ports '{outer_ports[:20]}' to '{inner_ports[:20]}' cannot be read")
            outer, translated = outer or (1, 1), translated or (1, 1)
        if outer == translated:
            port = ""
        elif translated[0] == translated[1]:
            port = str(translated[0])  # (one port, or a range to one port: n to 1)
        else:
            port = ""
            problems.append("a port range translated to another range, which the model has no form for")
        nat.service = self._nat_service(protocol, str(outer[0]) if outer[0] == outer[1] else f"{outer[0]}-{outer[1]}")
        nat.destination_translation = DestNat(interval_text(inner) if inner is not None else "0.0.0.0", port)

    @staticmethod
    def _range(text: str) -> Optional[Tuple[int, int]]:
        first, _, last = text.partition("-")
        last = last or first
        if not (first.isascii() and first.isdigit() and last.isascii() and last.isdigit()) or int(first) > int(last) or int(last) > 65535:
            return None
        return int(first), int(last)

    def _netmap(self, nat: NatRule, kind: str, fields: Dict[str, str], src_if: str, dst_if: str, problems: List[str]) -> None:
        source = self._nat_address(fields.get("srcip", "0.0.0.0/0"), src_if, problems, "source")
        destination = self._nat_address(fields.get("dstip", "0.0.0.0/0"), dst_if, problems, "destination")
        translated = parse_literal(fields.get("transip", ""))
        mapped = parse_literal(destination if kind == "dnetmap" else source) if (destination if kind == "dnetmap" else source) != ANY else None
        if translated is None or translated[0] != 4 or mapped is None or size(mapped) != size(translated):
            problems.append("NETMAP between subnets of different sizes, or of an address that cannot be read")
        nat.sources, nat.destinations = [source], [destination]
        if kind == "dnetmap":
            zone = self._zone(src_if) or ANY
            nat.src_zones = nat.dst_zones = [zone]
            nat.destination_translation = DestNat(interval_text(translated) if translated is not None else "0.0.0.0")
            if dst_if:
                self._say("SCALANCE_NETMAP_DSTINT", f"{nat.name}: {dst_if}")
        else:
            nat.src_zones, nat.dst_zones = [self._zone(src_if) or ANY], [self._zone(dst_if) or ANY]
            nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(translated) if translated is not None else "0.0.0.0"])

    # -- notes ---------------------------------------------------------------------------------------

    def _notes(self) -> None:
        rules = [r for r in self.p.rules]
        self.report.note(Severity.INFO, "SCALANCE_SOURCE",
                         f"{len(self.p.zones)} interfaces as zones ({', '.join(list(self.p.zones)[:8])}{' ...' if len(self.p.zones) > 8 else ''}); "
                         f"{len(rules)} IP rules, in ascending priority (prior), equal priorities in the order they were created; "
                         "the IPv4 rules, then the IPv6 rules. Rules of the firewall itself (device) and the predefined rules are "
                         "not converted")  # fmt: skip
        self.report.note(Severity.INFO, "SCALANCE_DEFAULTS",
                         "what no rule matches between interfaces is dropped; traffic inside one VLAN does not pass the IP firewall"
                         + (" (the firewall is switched off: everything passes)" if self.firewall_off else ""))  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.INFO, "SCALANCE_NAT_ORDER",
                             "destination NAT (NAPT, NETMAP of the destination) is done before the firewall, whose rules name the "
                             "translated address: the rules were rewritten for the address as it arrives. Source NAT, NETMAP of the "
                             "source and masquerading are done after it. Read in the order NAPT, NETMAP destination, NETMAP source, "
                             "source NAT, masquerading, one rule of each direction per connection (assumed)")  # fmt: skip
        if self.firewall_off:
            self.report.note(Severity.REVIEW, "SCALANCE_FIREWALL_OFF",
                             "the firewall is switched off (shutdown in FIREWALL mode): it filters nothing; the rules were read "
                             "disabled and the default as allow")  # fmt: skip
        texts = {
            "SCALANCE_PRERULE": (Severity.INFO, "predefined rules (access to services of the firewall itself) are not converted; those "
                                 "the configuration does not list are at their factory setting"),
            "SCALANCE_RULESET": (Severity.REVIEW, "rule sets (user or digital-input firewall): rules assigned to one apply only while it "
                                 "is active and are not converted; check which rules belong to a set"),
            "SCALANCE_EDIT_COMMANDS": (Severity.REVIEW, "commands that delete (no ...): rules named by index were taken out, assuming "
                                       "that the index numbers of the others do not change"),
            "SCALANCE_UNREAD": (Severity.REVIEW, "commands of the FIREWALL or FIREWALL NAT mode that were not read"),
            "SCALANCE_MAC_FIREWALL": (Severity.INFO, "the MAC firewall (layer 2 rules of an SC-600) is not converted"),
            "SCALANCE_NETMAP_DSTINT": (Severity.INFO, "the destination interface of a NETMAP rule of the destination is not a condition of "
                                       "the converted rule"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    try:
        return _Builder(text, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None
