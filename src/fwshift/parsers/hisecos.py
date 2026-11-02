# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Belden/Hirschmann HiSecOS parser: the CLI script of an EAGLE40, EAGLE20 or EAGLE30 (``show running-config script``, or
the script file *Load/Save > Save running-config as script* writes) -> neutral model, routed firewall mode.

What Belden documents, and how it is mapped onto the neutral model:

* **The packet filter** (``packet-filter l3``) holds rules by index (1 to 2048). A rule has a source and a destination
  (``any``, an IPv4 address, a CIDR network, the name of an asset; a ``!`` in front of the source is its complement), a
  protocol (icmp, igmp, ipip, tcp, udp, esp, ah, icmpv6, any), source and destination ports (``any``, ports, ranges,
  lists of up to 15), parameters (``type=`` and ``code=`` of ICMP, ``flags=`` of TCP, ``state=``, ``mac=``,
  ``frag=``), an action (accept, drop, reject, or one of the enforcers of deep packet inspection), log and trap
  (HM2-FW-MIB, hm2L3RuleTable).
* A rule does nothing until it is assigned to a routing interface (a port with routing on, or a VLAN routing interface
  ``vlan/N``) for ``ingress``, ``egress`` or ``both``, with a priority. "If an ingress and an egress interface are given,
  ... the rule shall apply to packets arriving on the ingress interface AND to-be leaving on the egress interface. A
  rule without ingress interface matches on all packets going out to the egress interface given, and vice versa";
  ``both`` applies it "to packets coming in and going out on this interface". Priorities are taken in ascending order;
  rules of the same priority have no defined order (HM2-FW-MIB, hm2L3RuleIfMappingTable). The device applies "the
  action specified in the first rule applying on the data stream"; what no rule matches meets the default policy,
  accept unless set (GUI reference manual, Packet Filter; hm2DefaultPolicy, DEFVAL accept). The filter is stateful.
* So the model is one list, first match, in the order of the priorities of the assignments (then the rule index, an
  assumption for rules of equal priority, which is reported where their actions differ). An assignment for ingress is
  the source zone, for egress the destination zone, both together the pair. **Assumed** (the MIB does not say how the
  assignments of different interfaces are ordered against each other): one order across all interfaces; a policy
  that mixes rules assigned for ingress only with rules assigned for egress only is reported. A ``both`` assignment is
  two placements: in on the interface to anywhere, and from anywhere out on it.
* Zones are the routing interfaces (``1/1`` is zone ``port1_1``, ``vlan/20`` is ``vlan20``), with the networks of their
  addresses. HiSecOS routes and filters IPv4 (its CLI reference has no chapter on IPv6, and the MIB shows IPv4 forms
  only): ``any`` is 0.0.0.0/0 and a rule for ICMPv6 or an IPv6 address is not converted.
* NAT: destination NAT (``nat dnat``, assigned for ingress), masquerading (``nat masq``, assigned for egress), 1:1 NAT
  (``nat 1to1nat``, with its ingress and egress interface) and double NAT (``nat doublenat``) (HM2-NAT-MIB). HiSecOS
  is built on Linux netfilter (hm2ConnTrackValidateCheckSum: "connection tracking in the Linux kernel"): **assumed**
  that destination NAT is done before the packet filter, which names the translated address, as in iptables, and that
  masquerading is done after it. The rules are rewritten to the address as it arrives, as for iptables. 1:1 NAT is read
  as a static translation in both directions, double NAT as two rules (one per direction); both are assumptions.
* Deep packet inspection (Modbus, OPC, DNP3, IEC 104, EtherNet/IP enforcers), the user firewall, the transparent
  mode's ``packet-filter l2`` rules, VPN, and the device's own management access are reported, not converted. A rule
  whose action hands traffic to an enforcer is not converted.

The words of the commands are FWShift's reading of the MIB names and of the command list of the CLI reference
(``packet-filter l3 addrule``, ``addif``, ``nat dnat add``, ...): the Format lines of those commands could not be read,
so the keywords (``srcip``, ``dstport``, ``direction``, ``priority``, ...) are **not confirmed** by documentation. A word
FWShift does not know makes its rule not converted, never wider. Assumptions not confirmed on a device are listed in
DEVELOPMENT.md and in the notes of the report.
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
from ..netutil import mask_length, parse_literal
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_INTERFACE = re.compile(r"^(\d+/\d+|vlan/\d+)$")
# hm2L3Proto: the protocols a rule takes by name, and what they are in the model.
PROTOCOLS: Dict[str, Optional[int]] = {"tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "ipip": 4, "esp": 50, "ah": 51, "icmpv6": 58, "any": None}
ACTIONS = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.DENY}
ENFORCERS = {"enforce-modbus": "Modbus", "enforce-opc": "OPC", "enforce-iec104": "IEC 104", "enforce-ethernetip": "EtherNet/IP",
             "enforce-dnp3": "DNP3"}  # fmt: skip
# The words of a rule (packet-filter l3 addrule/modifyrule) and what each sets; the spellings FWShift reads.
RULE_WORDS = {"srcip": "src", "src-ip": "src", "srcport": "sport", "src-port": "sport", "dstip": "dst", "dst-ip": "dst",
              "dstport": "dport", "dst-port": "dport", "proto": "proto", "protocol": "proto", "param": "param",
              "params": "param", "action": "action", "log": "log", "trap": "trap", "description": "description",
              "profile": "profile", "dpiprofile": "profile", "dpi-profile": "profile"}  # fmt: skip
DNAT_WORDS = {"srcip": "src", "src-ip": "src", "srcport": "sport", "src-port": "sport", "dstip": "dst", "dst-ip": "dst",
              "dstport": "dport", "dst-port": "dport", "proto": "proto", "protocol": "proto", "newdstip": "newdst",
              "new-dstip": "newdst", "newdstport": "newport", "new-dstport": "newport", "param": "param", "log": "log",
              "trap": "trap", "description": "description"}  # fmt: skip
MASQ_WORDS = {"srcip": "src", "src-ip": "src", "srcport": "sport", "src-port": "sport", "proto": "proto", "protocol": "proto",
              "param": "param", "log": "log", "trap": "trap", "description": "description", "ipsec-exempt": "ipsec"}  # fmt: skip
ONE_WORDS = {"dstip": "dst", "dst-ip": "dst", "newdstip": "newdst", "new-dstip": "newdst", "ingress-if": "ingress",
             "egress-if": "egress", "priority": "priority", "prio": "priority", "param": "param", "log": "log", "trap": "trap",
             "description": "description"}  # fmt: skip
DOUBLE_WORDS = {"local-internal": "li", "local-external": "le", "remote-internal": "ri", "remote-external": "re", "param": "param",
                "log": "log", "trap": "trap", "description": "description"}  # fmt: skip
_MAP_WORDS = {"rule", "index", "priority", "prio", "direction", "dir", "interface", "port", "if"}
_TRUE = {"enable", "true", "yes", "1", "on"}
_FALSE = {"disable", "false", "no", "0", "off"}
# First words of commands whose settings are reported and not converted.
_REPORTED = {"dpi": "deep packet inspection (enforcer profiles)", "user-firewall": "the user firewall",
             "userfw": "the user firewall", "vpn": "VPN connections", "ids": "the intrusion detection system",
             "flm": "the firewall learning mode"}  # fmt: skip


def looks_like_hisecos(data: bytes) -> bool:
    """A HiSecOS script: commands of the packet filter or of NAT that only HiSecOS (and HiOS-3S) writes, at the start of
    a line."""
    text = data[:2_000_000].decode("utf-8", errors="replace")
    found = 0
    for line in text.splitlines()[:50000]:
        if re.match(r"\s*packet-filter l3 (addrule|modifyrule|addif|defaultpolicy|enablerule|disablerule|commit)\b", line):
            found += 2
        elif re.match(r"\s*nat (dnat|masq|1to1nat|doublenat) (add|modify|commit|if add)\b", line):
            found += 1
        if found >= 2:
            return True
    return False


def split_words(line: str) -> List[str]:
    """Words of a line; text in double quotes is one word."""
    return [quoted if quoted or not plain else plain for quoted, plain in re.findall(r'"([^"]*)"|(\S+)', line)]


@dataclass
class _Entry:
    """A rule of one of the tables (packet filter, NAT): its index, its fields as written, and what could not be read."""

    index: int
    fields: Dict[str, str] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)
    enabled: Optional[bool] = None  # None: neither enabled nor disabled by a command
    line: int = 0


@dataclass
class _Mapping:
    interface: str
    direction: str  # ingress, egress, both
    index: int
    priority: Optional[int]
    enabled: bool = True


@dataclass
class _Interface:
    name: str
    networks: List[str] = field(default_factory=list)
    address: str = ""
    routing: bool = False


@dataclass
class _Placement:
    entry: _Entry
    src: List[str]
    dst: List[str]
    priority: int
    order: int


class _Builder:
    def __init__(self, text: str, report: Report) -> None:
        self.text, self.report = text, report
        self.p = Policy(vendor="hisecos", scope="IPv4", lookup_after_dnat=True)
        self.rules: Dict[int, _Entry] = {}
        self.maps: Dict[Tuple[str, str, int], _Mapping] = {}
        self.default = ""
        self.interfaces: Dict[str, _Interface] = {}
        self.assets: Dict[str, List[str]] = {}
        self.tables: Dict[str, Dict[int, _Entry]] = {"dnat": {}, "masq": {}, "1to1nat": {}, "doublenat": {}}
        self.nat_maps: Dict[str, Dict[Tuple[str, str, int], _Mapping]] = {"dnat": {}, "masq": {}, "doublenat": {}}
        self.notes: Dict[str, List[str]] = {}
        self.enable_words = False
        self.services: Dict[Tuple[str, str, str, str], str] = {}

    def note(self, code: str, text: str) -> None:
        items = self.notes.setdefault(code, [])
        if text not in items:
            items.append(text)

    # -- reading the script ---------------------------------------------------------------------------------------

    def read(self) -> None:
        mode, current = "", ""
        seen = False
        for number, raw in enumerate(self.text.splitlines(), 1):
            if number > _MAX_LINES:
                raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
            line = raw.strip()
            if not line or line.startswith(("!", "#")):
                continue
            words = split_words(line)
            if not words:
                continue
            head = words[0]
            if head in ("exit", "end"):
                mode, current = "", ""
                continue
            if head in ("enable", "configure"):
                continue
            if head == "interface" and len(words) == 2:
                mode, current = "interface", words[1]
                self.interfaces.setdefault(current, _Interface(current))
                continue
            if words[:2] == ["vlan", "database"]:
                mode, current = "vlan", ""
                continue
            if mode == "vlan" and words[:2] == ["routing", "add"] and len(words) == 3 and words[2].isdigit():
                name = f"vlan/{int(words[2])}"
                self.interfaces.setdefault(name, _Interface(name)).routing = True
                continue
            if mode == "interface" and head == "ip":
                self._interface_line(current, words)
                continue
            if head == "packet-filter":
                seen = True
                self._packet_filter(words, number)
            elif head == "nat" and len(words) >= 3:
                seen = True
                self._nat(words, number)
            elif head == "asset" and len(words) >= 2:
                self._asset(words)
            elif words[:3] == ["network", "management", "access"]:
                if len(words) > 4 and words[3] == "add":
                    self.note("HISECOS_MANAGEMENT", f"entry {words[4][:20]}")
            elif head in _REPORTED:
                self.note("HISECOS_NOT_CONVERTED", _REPORTED[head])
        if not seen:
            raise ParseError("no packet filter or NAT commands: not a CLI script of a HiSecOS firewall")

    def _interface_line(self, name: str, words: List[str]) -> None:
        interface = self.interfaces[name]
        if words[1:2] == ["routing"]:
            interface.routing = True
        elif len(words) >= 5 and words[1] == "address" and words[2] in ("primary", "secondary"):
            length = mask_length(words[4])
            try:
                network = ipaddress.ip_network(f"{words[3]}/{length}", strict=False) if length is not None else None
            except ValueError:
                network = None
            if network is not None:
                interface.networks.append(str(network))
                if words[2] == "primary":
                    interface.address = words[3]

    def _asset(self, words: List[str]) -> None:
        if words[1] == "delete" and len(words) >= 3:
            for asset, held in list(self.assets.items()):
                if held and held[0] == f"#{words[2]}":
                    del self.assets[asset]
            return
        if words[1] not in ("add", "modify") or len(words) < 3:
            return
        rest = words[3:]
        name = ""
        ips: List[str] = [f"#{words[2]}"]  # (the index first, for delete)
        for key, value in zip(rest[0::2], rest[1::2]):
            if key == "name":
                name = value
            elif re.fullmatch(r"ip\d*", key) and value != "any":
                ips.append(value)
        if not name:
            name = next((n for n, i in self.assets.items() if i and i[0] == f"#{words[2]}"), "")
            if not name:
                return
            ips = self.assets[name] + ips[1:]
        self.assets[name] = ips

    def _pairs(self, entry: _Entry, rest: List[str], words: Dict[str, str]) -> None:
        index = 0
        while index < len(rest):
            key = rest[index].lower()
            if key not in words:
                entry.problems.append(f"the word '{rest[index][:40]}' is not one FWShift reads")
                index += 1
                continue
            if index + 1 >= len(rest):
                entry.problems.append(f"'{key}' without a value")
                break
            entry.fields[words[key]] = rest[index + 1]
            index += 2

    def _packet_filter(self, words: List[str], number: int) -> None:
        if len(words) < 3:
            return
        if words[1] == "l2":
            self.note("HISECOS_NOT_CONVERTED", "the rules of the transparent mode (packet-filter l2)")
            return
        if words[1] != "l3":
            return
        command = words[2]
        rest = words[3:]
        if command == "defaultpolicy" and rest:
            self.default = rest[0].lower()
        elif command in ("addrule", "modifyrule") and rest and rest[0].isdigit():
            index = int(rest[0])
            if command == "addrule" or index not in self.rules:
                if command == "modifyrule":
                    self.note("HISECOS_EDITS", f"modifyrule {index} of a rule not added before (read as added there)")
                self.rules[index] = _Entry(index, line=number)
            self._pairs(self.rules[index], rest[1:], RULE_WORDS)
        elif command == "delrule" and rest and rest[0].isdigit():
            self.rules.pop(int(rest[0]), None)
            self.note("HISECOS_EDITS", f"delrule {rest[0]}")
        elif command in ("enablerule", "disablerule") and rest and rest[0].isdigit():
            entry = self.rules.get(int(rest[0]))
            if entry is not None:
                entry.enabled = command == "enablerule"
            self.enable_words = self.enable_words or command == "enablerule"
        elif command in ("addif", "delif", "enableif", "disableif"):
            mapping = self._mapping(rest, "")
            if mapping is None:
                self.note("HISECOS_UNREAD", " ".join(words)[:80])
                return
            key = (mapping.interface, mapping.direction, mapping.index)
            if command == "addif":
                self.maps[key] = mapping
            elif command == "delif":
                self.maps.pop(key, None)
            elif key in self.maps:
                self.maps[key].enabled = command == "enableif"
        elif command in ("commit", "logmode", "checksum-validation"):
            return
        else:
            self.note("HISECOS_UNREAD", " ".join(words)[:80])

    def _mapping(self, rest: List[str], direction: str) -> Optional[_Mapping]:
        """An assignment: an interface, a direction, a rule index and a priority, in any order, with or without their
        keywords (rule, direction or dir, priority or prio)."""
        interface = ""
        index: Optional[int] = None
        priority: Optional[int] = None
        i = 0
        while i < len(rest):
            word = rest[i].lower()
            value = rest[i + 1] if i + 1 < len(rest) else ""
            if word in ("rule", "index") and value.isdigit():
                index, i = int(value), i + 2
                continue
            if word in ("priority", "prio") and value.isdigit():
                priority, i = int(value), i + 2
                continue
            if word in ("direction", "dir") and value.lower() in ("ingress", "egress", "both"):
                direction, i = value.lower(), i + 2
                continue
            if word in ("interface", "port", "if") and value:
                interface, i = value, i + 2
                continue
            if word in ("ingress", "egress", "both"):
                direction = word
            elif _INTERFACE.match(rest[i]) or (not interface and not word.isdigit() and word not in _MAP_WORDS):
                interface = rest[i]
            elif word.isdigit():
                if index is None:
                    index = int(word)
                elif priority is None:
                    priority = int(word)
                else:
                    return None
            else:
                return None
            i += 1
        if not interface or index is None or not direction:
            return None
        return _Mapping(interface, direction, index, priority)

    def _nat(self, words: List[str], number: int) -> None:
        kind = words[1]
        if kind not in self.tables:
            return
        command = words[2]
        table = self.tables[kind]
        if command == "if" and len(words) >= 4 and kind in self.nat_maps:
            implied = {"dnat": "ingress", "masq": "egress"}.get(kind, "")
            mapping = self._mapping(words[4:], implied)
            if mapping is None:
                self.note("HISECOS_UNREAD", " ".join(words)[:80])
                return
            key = (mapping.interface, mapping.direction, mapping.index)
            if words[3] == "add":
                self.nat_maps[kind][key] = mapping
            elif words[3] == "delete":
                self.nat_maps[kind].pop(key, None)
            return
        rest = words[3:]
        if command in ("add", "modify") and rest and rest[0].isdigit():
            index = int(rest[0])
            if command == "add" or index not in table:
                table[index] = _Entry(index, line=number)
            names = {"dnat": DNAT_WORDS, "masq": MASQ_WORDS, "1to1nat": ONE_WORDS, "doublenat": DOUBLE_WORDS}[kind]
            self._pairs(table[index], rest[1:], names)
        elif command == "delete" and rest and rest[0].isdigit():
            table.pop(int(rest[0]), None)
        elif command == "state" and rest:
            if rest[0].lower() in _FALSE:
                self.note("HISECOS_NAT_OFF", kind)
        elif command not in ("commit", "logtrap", "ipsec-exempt"):
            self.note("HISECOS_UNREAD", " ".join(words)[:80])

    # -- members ----------------------------------------------------------------------------------------------------

    def _address(self, text: str, problems: List[str], negatable: bool = True) -> Tuple[str, bool]:
        """A source or destination as a member of the model, and whether it is negated."""
        negated = text.startswith("!")
        if negated:
            text = text[1:]
            if not negatable:
                problems.append(f"'!{text}' is a complement, which this field does not take")
        if text.lower() == "any":
            if negated:
                problems.append("'!any' matches nothing")
            return ANY_V4, negated
        if text.startswith("$"):
            problems.append(f"netobject '{text}' is not read")
            return text, negated
        interval = parse_literal(text)
        if interval is not None and "-" not in text:
            if interval[0] != 4:
                problems.append(f"IPv6 address '{text}': HiSecOS filters IPv4, and IPv6 is not read")
            return _network_text(text), negated
        if interval is not None:
            problems.append(f"address range '{text[:40]}', which is not among the documented forms")
            return text, negated
        if re.fullmatch(r"[A-Za-z0-9_.-]+", text) and not re.fullmatch(r"[0-9.]+", text):
            return self._asset_member(text, problems), negated
        problems.append(f"address '{text[:40]}' cannot be read")
        return text, negated

    def _asset_member(self, name: str, problems: List[str]) -> str:
        if name in self.p.addresses or name in self.p.address_groups:
            return name
        ips = self.assets.get(name)
        if ips is None:
            problems.append(f"'{name}' is not an asset of the configuration")
            return name
        members: List[str] = []
        for number, ip in enumerate(ips[1:], 1):
            interval = parse_literal(ip.lstrip("!"))
            if interval is None or ip.startswith("!") or interval[0] != 4:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"asset with address '{ip}'")
                return name
            member = f"{name}#{number}"
            self.p.addresses[member] = Address(member, AddressKind.NETWORK, _network_text(ip))
            members.append(member)
        if not members:
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw="asset without an IP address")
            return name
        if len(members) == 1:
            address = self.p.addresses.pop(members[0])
            self.p.addresses[name] = Address(name, address.kind, address.value, description="asset")
            return name
        self.p.address_groups[name] = AddressGroup(name, members, description="asset")
        return name

    def _ports(self, text: str, problems: List[str]) -> str:
        if text.lower() == "any":
            return ""
        parts: List[str] = []
        for part in text.split(","):
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
            if not match or int(match.group(1)) > 65535 or (match.group(2) and not int(match.group(1)) <= int(match.group(2)) <= 65535):
                problems.append(f"ports '{text[:40]}' cannot be read")
                return ""
            parts.append(part.strip())
        return ",".join(parts)

    def _service(self, entry: _Entry, problems: List[str]) -> List[str]:
        """The service of a rule (protocol, ports, ICMP type): [ANY] or the name of a service object."""
        proto = entry.fields.get("proto", "any").lower()
        dports = self._ports(entry.fields.get("dport", "any"), problems)
        sports = self._ports(entry.fields.get("sport", "any"), problems)
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None
        for key, value in self._params(entry, problems).items():
            if key in ("type", "code") and proto == "icmp" and value.isdigit() and int(value) <= 255:
                if key == "type":
                    icmp_type = int(value)
                else:
                    icmp_code = int(value)
            elif key == "state" and value.lower() == "new":
                continue  # (the model decides new connections; replies pass as on the stateful filter)
            else:
                problems.append(f"parameter {key}={value[:30]} is not converted")
        if icmp_code is not None and icmp_type is None:
            problems.append("an ICMP code without a type is not converted")
        if proto not in PROTOCOLS:
            problems.append(f"protocol '{proto[:30]}' (of the protocol table, or unknown) is not converted")
            return [ANY]
        if proto == "icmpv6":
            problems.append("ICMPv6: HiSecOS filters IPv4, and IPv6 is not read")
            return [ANY]
        if (dports or sports) and proto not in ("tcp", "udp"):
            problems.append(f"ports with protocol {proto}, which has none")
            return [ANY]
        if proto == "any":
            return [ANY]
        service_key = (proto, dports, sports, f"{icmp_type}/{icmp_code}")
        if service_key in self.services:
            return [self.services[service_key]]
        name = proto
        if dports:
            name += "-" + dports.replace(",", "_")
        if sports:
            name += "-from-" + sports.replace(",", "_")
        if icmp_type is not None:
            name += f"-type{icmp_type}" + (f"-code{icmp_code}" if icmp_code is not None else "")
        if proto in ("tcp", "udp"):
            service_entry = ServiceEntry(Protocol(proto), dports, sports)
        elif proto == "icmp":
            service_entry = ServiceEntry(Protocol.ICMP, icmp_type=icmp_type, icmp_code=icmp_code)
        else:
            service_entry = ServiceEntry(Protocol.IP, ip_protocol=PROTOCOLS[proto])
        self.p.services[name] = Service(name, [service_entry])
        self.services[service_key] = name
        return [name]

    def _params(self, entry: _Entry, problems: List[str]) -> Dict[str, str]:
        text = entry.fields.get("param", "")
        if not text or text.lower() == "none":
            return {}
        out: Dict[str, str] = {}
        for part in text.split(","):
            key, equals, value = part.partition("=")
            if not equals or "|" in value:
                problems.append(f"parameter '{part[:30]}' is not converted")
                continue
            out[key.strip().lower()] = value.strip()
        return out

    @staticmethod
    def _flag(value: str) -> bool:
        return value.lower() in _TRUE

    # -- the packet filter --------------------------------------------------------------------------------------------

    def _placements(self) -> Tuple[List[_Placement], List[_Entry]]:
        placements: List[_Placement] = []
        unassigned: List[_Entry] = []
        order = 0
        for index in sorted(self.rules):
            entry = self.rules[index]
            maps = [m for m in self.maps.values() if m.index == index and m.enabled]
            if not maps:
                unassigned.append(entry)
                continue
            for mapping in maps:
                if mapping.priority is None:
                    self.note("HISECOS_NO_PRIORITY", f"rule {index} on {mapping.interface}")
            ingress = sorted((m for m in maps if m.direction == "ingress"), key=lambda m: m.interface)
            egress = sorted((m for m in maps if m.direction == "egress"), key=lambda m: m.interface)
            both = sorted((m for m in maps if m.direction == "both"), key=lambda m: m.interface)

            def prio(m: _Mapping) -> int:
                return m.priority or 0

            groups: List[Tuple[int, List[str], List[str]]] = []
            if both and (ingress or egress):
                entry.problems.append("assigned for both directions on one interface and for one direction on another; what "
                                      "that matches is not documented")  # fmt: skip
                groups.append((min(prio(m) for m in maps), [ANY], [ANY]))
            elif both:
                for mapping in both:
                    groups.append((prio(mapping), [mapping.interface], [ANY]))
                    groups.append((prio(mapping), [ANY], [mapping.interface]))
            elif ingress and egress:
                priorities = {prio(m) for m in maps}
                if len(priorities) > 1:
                    self.note("HISECOS_PRIORITIES_DIFFER", f"rule {index}")
                groups.append((min(priorities), _dedupe([m.interface for m in ingress]), _dedupe([m.interface for m in egress])))
            else:
                side = ingress or egress
                by_priority: Dict[int, List[str]] = {}
                for mapping in side:
                    by_priority.setdefault(prio(mapping), []).append(mapping.interface)
                for priority, names in sorted(by_priority.items()):
                    names = _dedupe(names)
                    groups.append((priority, names, [ANY]) if ingress else (priority, [ANY], names))
            for priority, src, dst in groups:
                placements.append(_Placement(entry, _zones(src), _zones(dst), priority, order))
                order += 1
        placements.sort(key=lambda pl: (pl.priority, pl.entry.index, pl.order))
        return placements, unassigned

    def _rule(self, entry: _Entry, name: str) -> Rule:
        problems = list(entry.problems)
        rule = Rule(name)
        rule.origin = name
        rule.source_ids = {"hisecos.rule": str(entry.index)}
        source, rule.negate_source = self._address(entry.fields.get("src", "any"), problems)
        destination, rule.negate_destination = self._address(entry.fields.get("dst", "any"), problems)
        if rule.negate_destination:
            self.note("HISECOS_NEGATED_DESTINATION", f"rule {entry.index}")
        rule.sources, rule.destinations = [source], [destination]
        rule.services = self._service(entry, problems)
        action = entry.fields.get("action", "")
        if action.lower() in ACTIONS:
            rule.action = ACTIONS[action.lower()]
        elif action.lower() in ENFORCERS:
            rule.action = Action.ALLOW
            profile = entry.fields.get("profile", "")
            problems.append(f"traffic it matches is handed to the {ENFORCERS[action.lower()]} enforcer (deep packet inspection"
                            + (f", profile {profile}" if profile else "") + "), which forwards or drops it by content")  # fmt: skip
            rule.handling["dpi"] = action.lower() + (f" profile {profile}" if profile else "")
        else:
            problems.append(f"action '{action[:30]}' cannot be read" if action else "the rule has no action")
            rule.action = Action.DROP
        log = self._flag(entry.fields.get("log", "disable"))
        rule.log_start, rule.log_end = log, log
        if self._flag(entry.fields.get("trap", "disable")):
            rule.handling["trap"] = "enable"
        rule.description = entry.fields.get("description", "")
        if entry.enabled is None and self.enable_words:
            self.note("HISECOS_STATE_UNSAID", f"rule {entry.index}")
        rule.enabled = entry.enabled is not False
        rule.unsupported = _dedupe(problems)
        return rule

    def _packet_filter_rules(self) -> None:
        placements, unassigned = self._placements()
        count: Dict[int, int] = {}
        for placement in placements:
            index = placement.entry.index
            count[index] = count.get(index, 0) + 1
            name = f"rule-{index}" if count[index] == 1 else f"rule-{index}-{count[index]}"
            rule = self._rule(placement.entry, name)
            rule.src_zones, rule.dst_zones = list(placement.src), list(placement.dst)
            self.p.rules.append(rule)
            if count[index] > 1:
                self.report.add("rule", name, Severity.INFO, "HISECOS_SPLIT",
                                f"rule {index} is assigned at more than one place in the order (interfaces, directions or "
                                f"priorities); this is its placement number {count[index]}")  # fmt: skip
        # Rules of equal priority whose actions differ: the device keeps no defined order between them.
        by_priority: Dict[int, List[_Placement]] = {}
        for placement in placements:
            by_priority.setdefault(placement.priority, []).append(placement)
        for priority, tied in by_priority.items():
            entries = sorted({pl.entry.index for pl in tied})
            actions = {self.rules[i].fields.get("action", "").lower() for i in entries}
            if len(entries) > 1 and len(actions) > 1:
                names = ", ".join(str(i) for i in entries)
                for rule in self.p.rules:
                    if int(rule.source_ids["hisecos.rule"]) in entries:
                        self.report.add("rule", rule.origin, Severity.REVIEW, "HISECOS_PRIORITY_TIE",
                                        f"rules {names} have priority {priority} and different actions; the device keeps no "
                                        "defined order between them, and they are read in the order of their indexes")  # fmt: skip
        directions = {("in" if pl.src != [ANY] else "") + ("out" if pl.dst != [ANY] else "") for pl in placements}
        if "in" in directions and "out" in directions:
            self.note("HISECOS_DIRECTION_ORDER", "rules assigned for ingress only and rules assigned for egress only")
        for entry in unassigned:
            rule = self._rule(entry, f"rule-{entry.index}")
            rule.enabled = False
            self.p.rules.append(rule)
            self.report.add("rule", rule.origin, Severity.INFO, "HISECOS_NOT_ASSIGNED",
                            f"rule {entry.index} is assigned to no interface, so it applies to no traffic: read as disabled, "
                            "at the end")  # fmt: skip

    # -- NAT --------------------------------------------------------------------------------------------------------

    def _nat_member(self, text: str, problems: List[str], what: str) -> str:
        member, negated = self._address(text, problems)
        if negated:
            problems.append(f"the {what} '!{text[1:] if text.startswith('!') else text}' is a complement, which a NAT rule "
                            "of the model cannot hold")  # fmt: skip
        return member

    def _nat_service(self, entry: _Entry, problems: List[str]) -> str:
        services = self._service(entry, problems)
        return services[0]

    def _grouped(self, kind: str, index: int) -> List[Tuple[int, List[str]]]:
        by_priority: Dict[int, List[str]] = {}
        for mapping in self.nat_maps[kind].values():
            if mapping.index == index and mapping.enabled:
                by_priority.setdefault(mapping.priority or 0, []).append(mapping.interface)
        return sorted((priority, _dedupe(names)) for priority, names in by_priority.items())

    def _nat_rules(self) -> None:
        ordered: List[Tuple[int, int, int, NatRule]] = []  # (kind, priority, index, rule)
        for index, entry in sorted(self.tables["1to1nat"].items()):
            problems = list(entry.problems)
            target = self._nat_member(entry.fields.get("dst", "any"), problems, "target address")
            new = self._nat_member(entry.fields.get("newdst", "any"), problems, "new target address")
            ingress, egress = entry.fields.get("ingress", ""), entry.fields.get("egress", "")
            pre, post = parse_literal(target), parse_literal(new)
            if target == ANY_V4 or new == ANY_V4 or pre is None or post is None or pre[2] - pre[1] != post[2] - post[1]:
                problems.append("1:1 NAT needs a target and a new target address of the same size")
            name = f"1to1nat-{index}"
            nat = NatRule(name, src_zones=_zones([egress]) if _INTERFACE.match(egress) else [ANY],
                          dst_zones=_zones([ingress]) if _INTERFACE.match(ingress) else [ANY], sources=[new],
                          source_translation=SourceNat(SnatKind.STATIC, [target], bidirectional=True))  # fmt: skip
            if not _INTERFACE.match(ingress) or not _INTERFACE.match(egress):
                problems.append("1:1 NAT without its ingress and egress interface")
            self._finish_nat(nat, entry, problems)
            ordered.append((0, _int(entry.fields.get("priority", "0")), index, nat))
            self.report.add("nat", name, Severity.INFO, "HISECOS_1TO1",
                            "1:1 NAT read as a static translation in both directions: the new target addresses leave as the "
                            "target addresses, and connections to the target addresses reach the new ones (not confirmed)")  # fmt: skip
        for index, entry in sorted(self.tables["doublenat"].items()):
            groups = self._grouped("doublenat", index)
            maps = [m for m in self.nat_maps["doublenat"].values() if m.index == index and m.enabled]
            firsts = _dedupe([m.interface for m in maps if m.direction in ("ingress", "both")])
            seconds = _dedupe([m.interface for m in maps if m.direction in ("egress", "both")])
            for direction, (first, second) in enumerate(((("li", "le"), ("ri", "re")), (("ri", "re"), ("li", "le")))):
                problems = list(entry.problems)
                inside = self._nat_member(entry.fields.get(first[0], "any"), problems, "address")
                outside = self._nat_member(entry.fields.get(first[1], "any"), problems, "address")
                peer_inside = self._nat_member(entry.fields.get(second[0], "any"), problems, "address")
                peer_outside = self._nat_member(entry.fields.get(second[1], "any"), problems, "address")
                if ANY_V4 in (inside, outside, peer_inside, peer_outside):
                    problems.append("double NAT with 'any' is not converted")
                name = f"doublenat-{index}" + ("" if direction == 0 else "-reverse")
                from_zones, to_zones = (firsts, seconds) if direction == 0 else (seconds, firsts)
                nat = NatRule(name, src_zones=_zones(from_zones) or [ANY], dst_zones=_zones(to_zones) or [ANY], sources=[inside],
                              destinations=[peer_outside], source_translation=SourceNat(SnatKind.STATIC, [outside]),
                              destination_translation=DestNat(peer_inside))  # fmt: skip
                if not groups:
                    nat.enabled = False
                self._finish_nat(nat, entry, problems)
                ordered.append((1, groups[0][0] if groups else 0, index, nat))
                self.report.add("nat", name, Severity.INFO, "HISECOS_DOUBLE_NAT",
                                "double NAT read as two rules, one for each direction, each translating the source and the "
                                "destination (not confirmed)")  # fmt: skip
        for index, entry in sorted(self.tables["dnat"].items()):
            groups = self._grouped("dnat", index) or [(0, [])]
            for number, (priority, names) in enumerate(groups, 1):
                problems = list(entry.problems)
                name = f"dnat-{index}" + ("" if number == 1 else f"-{number}")
                new = entry.fields.get("newdst", "")
                port = entry.fields.get("newport", "any")
                if not new or parse_literal(new) is None or "/" in new or "-" in new:
                    problems.append(f"new target address '{new[:40]}' is not one IPv4 address")
                if port.lower() != "any" and not (port.isdigit() and int(port) <= 65535):
                    problems.append(f"new target port '{port[:20]}' is not one port")
                nat = NatRule(name, src_zones=_zones(names) or [ANY],
                              sources=[self._nat_member(entry.fields.get("src", "any"), problems, "source")],
                              destinations=[self._nat_member(entry.fields.get("dst", "any"), problems, "destination")],
                              service=self._nat_service(entry, problems),
                              destination_translation=DestNat(new or "0.0.0.0", "" if port.lower() == "any" else port))  # fmt: skip
                if not names:
                    nat.enabled = False
                self._finish_nat(nat, entry, problems)
                ordered.append((2, priority, index, nat))
        for index, entry in sorted(self.tables["masq"].items()):
            groups = self._grouped("masq", index) or [(0, [])]
            for priority, names in groups:
                for interface in names or [""]:
                    problems = list(entry.problems)
                    if self._flag(entry.fields.get("ipsec", "false")):
                        problems.append("ipsec-exempt: IPsec traffic is not masqueraded, which the model cannot say")
                    name = f"masq-{index}" + (f"-{interface}" if len(names) > 1 else "")
                    known = self.interfaces.get(interface)
                    nat = NatRule(name, dst_zones=_zones([interface]) if interface else [ANY],
                                  sources=[self._nat_member(entry.fields.get("src", "any"), problems, "source")],
                                  service=self._nat_service(entry, problems),
                                  source_translation=SourceNat(SnatKind.INTERFACE, interface=interface,
                                                               interface_address=known.address if known else ""))  # fmt: skip
                    if not interface:
                        nat.enabled = False
                    self._finish_nat(nat, entry, problems)
                    ordered.append((3, priority, index, nat))
        ordered.sort(key=lambda item: (item[0], item[1], item[2]))
        self.p.nat_rules = [nat for _, _, _, nat in ordered]

    def _finish_nat(self, nat: NatRule, entry: _Entry, problems: List[str]) -> None:
        nat.origin = nat.name
        nat.description = entry.fields.get("description", "")
        nat.unsupported = _dedupe(problems)
        nat.combines = True  # (a translation before the filter and one after it apply to a connection together)
        if not nat.enabled:
            self.report.add("nat", nat.name, Severity.INFO, "HISECOS_NOT_ASSIGNED",
                            "the NAT rule is assigned to no interface, so it applies to no traffic: read as disabled")  # fmt: skip

    # -- the whole --------------------------------------------------------------------------------------------------

    def build(self) -> Policy:
        self.read()
        named: Set[str] = set()
        for (interface, _, _) in list(self.maps) + [k for maps in self.nat_maps.values() for k in maps]:
            named.add(interface)
        for entry in self.tables["1to1nat"].values():
            named.update(v for v in (entry.fields.get("ingress", ""), entry.fields.get("egress", "")) if _INTERFACE.match(v))
        for name in sorted(set(self.interfaces) | named, key=_interface_key):
            known = self.interfaces.get(name)
            if known is not None and not known.networks and name not in named and not known.routing:
                continue
            zone = zone_name(name)
            self.p.zones[zone] = Zone(zone, [name])
            if known is not None and known.networks:
                self.p.zone_networks[zone] = list(known.networks)
        default = self.default or "accept"
        if default not in ACTIONS:
            self.note("HISECOS_UNREAD", f"packet-filter l3 defaultpolicy {default}")
            default = "drop"
        self.p.default_interzone = self.p.default_intrazone = ACTIONS[default]
        self._packet_filter_rules()
        self._nat_rules()
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes(default)
        return self.p

    def _notes(self, default: str) -> None:
        assigned = sum(1 for rule in self.p.rules if rule.enabled)
        self.report.note(Severity.INFO, "HISECOS_SOURCE",
                         f"{len(self.rules)} rules of the packet filter, {assigned} of them assigned and enabled, in the order of "
                         f"their priorities; zones are the routing interfaces ({', '.join(list(self.p.zones)[:8])}"
                         f"{' ...' if len(self.p.zones) > 8 else ''}); IPv4 only. The keywords of the commands are FWShift's "
                         "reading of the MIB and the command list of the CLI reference, not confirmed by its Format lines")  # fmt: skip
        if not self.default:
            self.report.note(Severity.REVIEW, "HISECOS_DEFAULT_ASSUMED",
                             "the script sets no default policy (packet-filter l3 defaultpolicy): read as accept, the default "
                             "of the MIB and of the GUI reference manual. If the script was saved without default values, "
                             "check the default on the device (show packet-filter l3 defaultpolicy)")  # fmt: skip
        else:
            self.report.note(Severity.INFO, "HISECOS_DEFAULT", f"what no rule matches meets the default policy, {default} "
                             "(packet-filter l3 defaultpolicy)")  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.INFO, "HISECOS_NAT_ORDER",
                             "destination NAT and 1:1 NAT are read as done before the packet filter, whose rules name the "
                             "translated address (HiSecOS is built on netfilter; not confirmed): the rules were rewritten for "
                             "the address as it arrives. Masquerading is done after it. The NAT rules are read in the order 1:1 "
                             "NAT, double NAT, destination NAT, masquerading, each by priority (an assumption)")  # fmt: skip
        texts = {
            "HISECOS_NOT_CONVERTED": (Severity.REVIEW, "settings that change what passes and are not converted"),
            "HISECOS_MANAGEMENT": (Severity.INFO, "the device's own management access (network management access) is not "
                                   "converted; entries"),
            "HISECOS_DIRECTION_ORDER": (Severity.REVIEW, "the policy mixes assignments for ingress only with assignments for "
                                        "egress only; the MIB does not say how they are ordered against each other, and "
                                        "they are read as one order by priority"),
            "HISECOS_PRIORITIES_DIFFER": (Severity.REVIEW, "rules assigned for ingress and egress with different priorities: "
                                          "read at the lowest of them"),
            "HISECOS_NO_PRIORITY": (Severity.REVIEW, "assignments without a priority, read as priority 0"),
            "HISECOS_STATE_UNSAID": (Severity.REVIEW, "the script enables rules with enablerule, and says nothing about these: "
                                     "read as enabled"),
            "HISECOS_NEGATED_DESTINATION": (Severity.INFO, "a '!' before a destination, which the MIB documents for sources "
                                            "only: read as the complement"),
            "HISECOS_EDITS": (Severity.INFO, "commands that change or delete rules, carried out in the order of the script"),
            "HISECOS_UNREAD": (Severity.REVIEW, "commands of the packet filter or NAT that were not read"),
            "HISECOS_NAT_OFF": (Severity.REVIEW, "NAT functions switched off (state disable); their rules were read as they are"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def zone_name(interface: str) -> str:
    """The zone of a routing interface: ``1/1`` is ``port1_1``, ``vlan/20`` is ``vlan20`` (names other platforms take)."""
    match = re.fullmatch(r"(\d+)/(\d+)", interface)
    if match:
        return f"port{match.group(1)}_{match.group(2)}"
    match = re.fullmatch(r"vlan/(\d+)", interface)
    if match:
        return f"vlan{match.group(1)}"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", interface) or "unnamed"


def _zones(interfaces: List[str]) -> List[str]:
    return [zone if zone == ANY else zone_name(zone) for zone in interfaces]


def _dedupe(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))


def _network_text(text: str) -> str:
    """An address or network as the model writes it: a network with host bits set is the network they are in."""
    if "/" not in text:
        return text
    return str(ipaddress.ip_network(text, strict=False))


def _int(text: str) -> int:
    return int(text) if text.isdigit() else 0


def _interface_key(name: str) -> Tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)/(\d+)", name)
    if match:
        return (0, int(match.group(1)), int(match.group(2)))
    match = re.fullmatch(r"vlan/(\d+)", name)
    return (1, int(match.group(1)), 0) if match else (2, 0, 0)


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    try:
        return _Builder(text, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None

