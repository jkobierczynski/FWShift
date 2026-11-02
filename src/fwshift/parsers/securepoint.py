# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Securepoint UTM parser (v12, v14): the commands of its CLI (``spcli``) that build the packet filter -> neutral model.

What FWShift reads, and why: the export of the web interface (*Configuration > Export*) is a ``.utm`` file whose format
Securepoint does not document, and its import asks for the password it was encrypted with. What Securepoint documents is
its CLI (wiki: *Securepoint UTM CLI*, the pages of the commands ``node``, ``service`` and ``rule``): ``node new``,
``node group new``, ``service new``, ``service group new``, ``rule group new``, ``rule new``, and ``interface zone new``
and ``interface address new`` for the zones and the networks behind them. FWShift reads a text of those commands: a
script, or the configuration as the UTM keeps it, which the community shows written in the same commands (``service new
name ... proto "tcp" ct_helper "" dst-ports [ ... ] src-ports [ ]``). Other commands (``extc``, ``interface new``, ...)
are left alone; lines that start with ``#`` are comments.

How the UTM decides, and how that is mapped onto the model:

* The packet filter checks its rules "from top to bottom"; "if a rule applies, the check of the set of rules is
  terminated and the configured action is executed" (wiki, Packetfilter). First match. Every rule belongs to a rule group;
  the groups are in the order they were created and a rule is added at the end of its group (**assumed**: the CLI
  reference shows no position parameter). What no rule matches is dropped ("Default Drop").
* A rule has one source, one destination and one service (a network object or group, a service or service group), an
  action (``ACCEPT``, ``DROP``, ``REJECT``, ``QOS``, ``STATELESS``), logging (``LOG``: the first three entries a minute;
  ``LOG_ALL``: all) and NAT (``HIDENAT``, ``HIDENAT_EXCLUDE``, ``DESTNAT``, ``NETMAP``, ``FULLCONENAT``) in its ``flags``,
  and for NAT a network object (``nat_node``) and a service (``nat_service``).
* A rule names no interfaces: every network object carries a **zone**, and a zone is bound to an interface. "The zone
  concept defines through which interface an object (host or network) reaches" the UTM; a rule applies only where the
  connection comes in and goes out on the interfaces of the zones of its objects (wiki, Zone settings). So the zones of a
  rule are the zones of its objects. A group whose members lie in several zones is several rules, one per pair of zones,
  each with the members of its zones, which together match what the rule matches.
* Zones with the flag ``INTERFACE`` (named ``firewall-...``) are the UTM's own interfaces: a rule to or from an object of
  such a zone is for the UTM's own services, handled in a table of its own. It is not converted (the part of a group in
  such a zone is left out of the rule). VPN zones (``vpn-...``) are zones like any other.
* IPv6: since v12.4 a zone holds both IP versions, and the IP version of the objects decides whether a rule is written to
  iptables or ip6tables.
* NAT is part of a rule. ``HIDENAT`` is source NAT behind the address of ``nat_node`` (the external interface: the
  address of that interface), ``HIDENAT_EXCLUDE`` an exception from it. ``DESTNAT``: the rule names the server and the
  port the traffic reaches (destination and service) and ``nat_node``/``nat_service`` the address and port it was sent to
  (wiki, Port forwarding). The UTM is built on netfilter: destination NAT happens before the packet filter, which sees the
  translated destination, and source NAT after it. So the model is read as for iptables: a DESTNAT rule becomes a NAT rule
  and a rule for the traffic it translates (pre-NAT destination and port, the zone of the server), and the other rules
  are rewritten for the destination as it arrives. **Assumed**: the NAT of a rule applies to the connections it matches
  whatever its action, as a netfilter NAT table does; a DESTNAT rule allows the traffic it translates, and is not read
  as also allowing traffic sent to the server directly. ``NETMAP`` (two networks mapped onto each other) is not
  converted; ``FULLCONENAT`` is read as ``HIDENAT``, and reported.
* The UTM's implicit rules (*Firewall > Implied rules*: its own services, VPN, the threat intelligence filter) come
  before the packet filter. ``rule implied ...`` commands are reported, not converted.

What is not documented and is read as stated (listed in DEVELOPMENT.md and in the notes of the report): the forms of a
network object's address beyond an address, a network and an interface (a range ``a-b``, a host name); the ICMP types of
a service as numbers or the names iptables knows; the parameters of ``rule new`` beyond ``group``, ``src``, ``dst``,
``service``, ``comment``, ``flags``, ``nat_node`` and ``nat_service``. A word FWShift does not know makes its rule not
converted, never wider.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

from .. import transform
from ..errors import ParseError
from ..model import (
    ANY,
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
from ..netutil import parse_literal
from ..report import Report, Severity

_MAX_LINES = 2_000_000
_MAX_NESTING = 64
Value = Union[str, List[str]]

# The commands FWShift reads (the longest first) and the parameters each takes.
COMMANDS: Dict[Tuple[str, ...], Set[str]] = {
    ("interface", "zone", "new"): {"name", "interface", "flags"},
    ("interface", "address", "new"): {"device", "address", "flags"},
    ("node", "group", "new"): {"name", "nodes", "descr", "comment"},
    ("node", "group", "add"): {"name", "id", "nodes"},
    ("node", "new"): {"name", "address", "zone", "descr", "comment", "type"},
    ("service", "group", "new"): {"name", "services", "descr", "comment"},
    ("service", "group", "add"): {"name", "id", "services"},
    ("service", "new"): {"name", "proto", "dst-ports", "src-ports", "icmp-types", "icmp-type", "ct_helper", "descr", "comment"},
    ("rule", "group", "new"): {"name", "descr", "comment"},
    ("rule", "new"): {"group", "src", "dst", "service", "comment", "flags", "nat_node", "nat_service", "qos", "route",
                      "timeprofile", "time_profile", "log_alias", "id"},  # fmt: skip
}
# Commands that change or delete what was created, which FWShift does not carry out: their effect is not read.
_EDITS = {("node", "set"), ("node", "delete"), ("node", "group", "set"), ("node", "group", "rem"), ("node", "group", "delete"),
          ("service", "set"), ("service", "delete"), ("service", "group", "set"), ("service", "group", "rem"),
          ("service", "group", "delete"), ("rule", "set"), ("rule", "delete"), ("rule", "group", "set"),
          ("rule", "group", "delete"), ("rule", "move")}  # fmt: skip
ACTIONS = {"ACCEPT": Action.ALLOW, "DROP": Action.DROP, "REJECT": Action.DENY, "QOS": Action.ALLOW, "STATELESS": Action.ALLOW}
LOGS = {"LOG", "LOG_ALL"}
NATS = {"HIDENAT", "HIDENAT_EXCLUDE", "DESTNAT", "NETMAP", "FULLCONENAT"}
# Protocols of a service other than tcp, udp, icmp and icmpv6, by the names iptables takes, and their numbers.
PROTOCOLS = {"gre": 47, "esp": 50, "ah": 51, "igmp": 2, "ipip": 4, "ospf": 89, "vrrp": 112, "l2tp": 115, "pim": 103, "ipv6": 41,
             "ipcomp": 108}  # fmt: skip
# ICMP type names iptables knows (iptables -p icmp -h), for a service that names a type by name.
ICMP_NAMES = {"any": None, "echo-reply": 0, "pong": 0, "destination-unreachable": 3, "source-quench": 4, "redirect": 5,
              "echo-request": 8, "ping": 8, "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11,
              "ttl-exceeded": 11, "parameter-problem": 12, "timestamp-request": 13, "timestamp-reply": 14,
              "address-mask-request": 17, "address-mask-reply": 18}  # fmt: skip
ICMP6_NAMES = {"any": None, "destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3, "parameter-problem": 4,
               "echo-request": 128, "ping": 128, "echo-reply": 129, "pong": 129, "router-solicitation": 133,
               "router-advertisement": 134, "neighbour-solicitation": 135, "neighbor-solicitation": 135,
               "neighbour-advertisement": 136, "neighbor-advertisement": 136, "redirect": 137}  # fmt: skip
# Services a UTM comes with, used where a rule names one the input does not define. The names are those Securepoint's
# documentation and forum show; the ports are the IANA ports of the same names (the factory list is not published).
FACTORY_SERVICES: Dict[str, List[ServiceEntry]] = {
    "http": [ServiceEntry(Protocol.TCP, "80")], "https": [ServiceEntry(Protocol.TCP, "443")],
    "ssh": [ServiceEntry(Protocol.TCP, "22")], "ftp": [ServiceEntry(Protocol.TCP, "21")],
    "smtp": [ServiceEntry(Protocol.TCP, "25")], "smtps": [ServiceEntry(Protocol.TCP, "465")],
    "submission": [ServiceEntry(Protocol.TCP, "587")], "imap": [ServiceEntry(Protocol.TCP, "143")],
    "imap-ssl": [ServiceEntry(Protocol.TCP, "993")], "pop3": [ServiceEntry(Protocol.TCP, "110")],
    "pop3s": [ServiceEntry(Protocol.TCP, "995")], "domain-udp": [ServiceEntry(Protocol.UDP, "53")],
    "domain-tcp": [ServiceEntry(Protocol.TCP, "53")], "ntp-udp": [ServiceEntry(Protocol.UDP, "123")],
    "ntp-tcp": [ServiceEntry(Protocol.TCP, "123")], "ms-rdp": [ServiceEntry(Protocol.TCP, "3389")],
    "icmp-echo-req": [ServiceEntry(Protocol.ICMP, icmp_type=8)],
}  # fmt: skip
_ZONE_FLAGS = {"INTERFACE", "POLICY_IPSEC", "PPP_VPN"}
_START = re.compile(r"^\s*(node new name|node group new name|service new name|service group new name|rule new group|"
                    r"rule group new name|interface zone new name)\s", re.MULTILINE)  # fmt: skip


def looks_like_securepoint(data: bytes) -> bool:
    """Commands of the Securepoint CLI that build the packet filter, at the start of lines: a rule or a network object,
    and one more of them."""
    text = data[:2_000_000].decode("utf-8", errors="replace")
    found = [match.group(1) for match in _START.finditer(text, 0, 2_000_000)][:50]
    return len(found) >= 2 and any(word in ("rule new group", "node new name") for word in found)


def split_words(line: str) -> List[str]:
    """The tokens of a line: a word, a string in double quotes (backslash escapes the next character), ``[`` and ``]``.
    Raises ValueError for a string that does not end."""
    out: List[str] = []
    i, n = 0, len(line)
    while i < n:
        char = line[i]
        if char.isspace():
            i += 1
        elif char in "[]":
            out.append(char)
            i += 1
        elif char == '"':
            i += 1
            text: List[str] = []
            while i < n and line[i] != '"':
                if line[i] == "\\" and i + 1 < n:
                    i += 1
                text.append(line[i])
                i += 1
            if i >= n:
                raise ValueError("a string in double quotes does not end")
            out.append('"' + "".join(text))  # (a leading quote marks a quoted string; it is taken off below)
            i += 1
        else:
            start = i
            while i < n and not line[i].isspace() and line[i] not in '[]"':
                i += 1
            out.append(line[start:i])
    return out


def _plain(token: str) -> str:
    return token[1:] if token.startswith('"') else token


@dataclass
class _Command:
    path: Tuple[str, ...]
    params: Dict[str, Value]
    problems: List[str]
    line: int


def parse_command(line: str, number: int = 0) -> Optional[_Command]:
    """A command FWShift reads, with its parameters; None for any other command."""
    tokens = split_words(line)
    words = [t for t in tokens[:3]]
    path: Optional[Tuple[str, ...]] = None
    for candidate in sorted(COMMANDS, key=len, reverse=True):
        if tuple(words[: len(candidate)]) == candidate:
            path = candidate
            break
    if path is None:
        return None
    params: Dict[str, Value] = {}
    problems: List[str] = []
    rest = tokens[len(path):]
    i = 0
    while i < len(rest):
        key = rest[i]
        if key.startswith('"') or key in "[]":
            problems.append(f"'{_plain(key)[:40]}' where a parameter name was expected")
            i += 1
            continue
        if i + 1 >= len(rest):
            problems.append(f"parameter '{key[:30]}' without a value")
            break
        value: Value
        if rest[i + 1] == "[":
            items: List[str] = []
            j = i + 2
            while j < len(rest) and rest[j] != "]":
                if rest[j] == "[":
                    raise ValueError("a list inside a list")
                items.append(_plain(rest[j]))
                j += 1
            if j >= len(rest):
                raise ValueError("a list that does not end")
            value, i = items, j + 1
        elif rest[i + 1] == "]":
            raise ValueError("a ']' without '['")
        else:
            value, i = _plain(rest[i + 1]), i + 2
        if key in params:
            problems.append(f"parameter '{key[:30]}' given twice")
        if key not in COMMANDS[path]:
            problems.append(f"parameter '{key[:30]}' is not one FWShift reads")
        params[key] = value
    return _Command(path, params, problems, number)


def _text(value: Optional[Value]) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else " ".join(value)


def _items(value: Optional[Value]) -> List[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


@dataclass
class _Zone:
    name: str
    interfaces: List[str] = field(default_factory=list)
    flags: Set[str] = field(default_factory=set)

    @property
    def own(self) -> bool:
        """The UTM's own interfaces (the flag INTERFACE)."""
        return "INTERFACE" in self.flags


@dataclass
class _Node:
    name: str
    address: str
    zone: str


@dataclass
class _Part:
    """One rule of the model a rule of the UTM becomes: the members of one source zone and one destination zone."""

    src_zone: str
    dst_zone: str
    sources: List[str]
    destinations: List[str]


class _Builder:
    def __init__(self, text: str, report: Report) -> None:
        self.text, self.report = text, report
        # lookup_after_dnat stays False: a DESTNAT rule is read for the pre-NAT destination and port, which a target of the
        # same kind cannot take back by what the parser added (Rule.nat_added); every target rewrites as for a pre-NAT source.
        self.p = Policy(vendor="securepoint", default_intrazone=Action.DROP, default_interzone=Action.DROP)
        self.zones: Dict[str, _Zone] = {}
        self.addresses: Dict[str, List[str]] = {}  # interface -> addresses with prefix (interface address new)
        self.nodes: Dict[str, _Node] = {}
        self.groups: Dict[str, List[str]] = {}
        self.services: Dict[str, Tuple[List[ServiceEntry], str, str]] = {}  # name -> (entries, why not, description)
        self.service_groups: Dict[str, List[str]] = {}
        self.rule_groups: List[str] = []
        self.rules: List[_Command] = []
        self.notes: Dict[str, List[str]] = {}
        self.object_problems: Dict[str, str] = {}
        self.local_skipped = 0
        self.destnat_rules: Set[str] = set()

    def note(self, code: str, text: str) -> None:
        items = self.notes.setdefault(code, [])
        if text not in items:
            items.append(text)

    # -- reading ------------------------------------------------------------------------------------------------------

    def read(self) -> None:
        seen = False
        for number, raw in enumerate(self.text.splitlines(), 1):
            if number > _MAX_LINES:
                raise ParseError(f"more than {_MAX_LINES} lines; not a configuration of a firewall")
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                command = parse_command(line, number)
            except ValueError as error:
                raise ParseError(f"line {number}: {error}") from None
            if command is None:
                words = line.split()
                if tuple(words[:2]) == ("rule", "implied"):
                    self.note("SECUREPOINT_IMPLIED", " ".join(words[2:8])[:60])
                elif tuple(words[:3]) in _EDITS or tuple(words[:2]) in _EDITS:
                    self.note("SECUREPOINT_EDITS", f"line {number}: {' '.join(words[:3])}")
                continue
            seen = True
            self._command(command)
        if not seen:
            raise ParseError("no commands of the Securepoint CLI that build the packet filter (node new, rule new, ...)")

    def _command(self, command: _Command) -> None:
        params, path = command.params, command.path
        name = _text(params.get("name"))
        if path == ("rule", "new"):
            self.rules.append(command)
            group = _text(params.get("group"))
            if group and group not in self.rule_groups:
                self.rule_groups.append(group)
                self.note("SECUREPOINT_GROUP_IMPLIED", group)
            return
        if not name and path != ("interface", "address", "new"):
            self.note("SECUREPOINT_UNREAD", f"line {command.line}: {' '.join(path)} without a name")
            return
        if command.problems and path not in (("node", "new"), ("service", "new")):
            self.note("SECUREPOINT_UNREAD", f"line {command.line}: {'; '.join(command.problems)[:80]}")
        if path == ("interface", "zone", "new"):
            interfaces = [i for i in _items(params.get("interface")) if i]
            flags = {f.upper() for f in _items(params.get("flags"))}
            self.zones[name] = _Zone(name, interfaces, flags)
            for flag in flags - _ZONE_FLAGS:
                self.note("SECUREPOINT_UNREAD", f"zone {name[:30]}: flag {flag[:20]}")
        elif path == ("interface", "address", "new"):
            device, address = _text(params.get("device")), _text(params.get("address"))
            if device and parse_literal(address) is not None:
                self.addresses.setdefault(device, []).append(address)
        elif path == ("node", "new"):
            if name in self.nodes or name in self.groups:
                self.note("SECUREPOINT_DUPLICATE", name)
            self.nodes[name] = _Node(name, _text(params.get("address")), _text(params.get("zone")))
            if command.problems:
                self.object_problems[name] = "; ".join(command.problems)
            if _text(params.get("type")):
                self.note("SECUREPOINT_NODE_TYPE", f"{name[:30]}: {_text(params.get('type'))[:20]}")
        elif path == ("node", "group", "new"):
            self.groups[name] = [m for m in _items(params.get("nodes")) if m]
        elif path == ("node", "group", "add"):
            self.groups.setdefault(name, []).extend(m for m in _items(params.get("nodes")) if m)
        elif path == ("service", "new"):
            self.services[name] = self._service(params, command.problems)
        elif path == ("service", "group", "new"):
            self.service_groups[name] = [m for m in _items(params.get("services")) if m]
        elif path == ("service", "group", "add"):
            self.service_groups.setdefault(name, []).extend(m for m in _items(params.get("services")) if m)
        elif path == ("rule", "group", "new"):
            if name not in self.rule_groups:
                self.rule_groups.append(name)

    # -- services -------------------------------------------------------------------------------------------------------

    @staticmethod
    def _ports(values: List[str]) -> Tuple[str, str]:
        """Ports in the model's form, or why they cannot be read."""
        parts: List[str] = []
        for value in values:
            for part in re.split(r"[,\s]+", value.strip()):
                if not part:
                    continue
                match = re.fullmatch(r"(\d+)(?:[-:](\d+))?", part)
                if not match:
                    return "", f"port '{part[:20]}' cannot be read"
                first, last = int(match.group(1)), int(match.group(2) or match.group(1))
                if not 0 <= first <= last <= 65535 or (first == 0 and last == 0):
                    return "", f"port '{part[:20]}' cannot be read"
                parts.append(str(first) if first == last else f"{first}-{last}")
        return ",".join(dict.fromkeys(parts)), ""

    def _service(self, params: Dict[str, Value], problems: List[str]) -> Tuple[List[ServiceEntry], str, str]:
        proto = _text(params.get("proto")).lower()
        why = "; ".join(problems)
        description = _text(params.get("descr")) or _text(params.get("comment"))
        helper = _text(params.get("ct_helper"))
        if helper:
            description = (description + "; " if description else "") + f"connection tracking helper {helper}"
        dst, why_dst = self._ports(_items(params.get("dst-ports")))
        src, why_src = self._ports(_items(params.get("src-ports")))
        types = _items(params.get("icmp-types")) + _items(params.get("icmp-type"))
        if proto in ("tcp", "udp"):
            if why_dst or why_src:
                return [], why_dst or why_src, description
            if types:
                why = why or "ICMP types in a service of protocol " + proto
            return [ServiceEntry(Protocol(proto), dst, src)], why, description
        if (dst or src) and proto not in ("tcp", "udp"):
            why = why or f"ports in a service of protocol {proto or '(none)'}"
        if proto in ("icmp", "icmpv6", "ipv6-icmp", "icmp6"):
            six = proto != "icmp"
            names = ICMP6_NAMES if six else ICMP_NAMES
            entries: List[ServiceEntry] = []
            for item in types or ["any"]:
                value = item.strip().lower()
                if value.isdigit() and int(value) <= 255:
                    number: Optional[int] = int(value)
                elif value in names:
                    number = names[value]
                else:
                    return [], f"ICMP type '{item[:20]}' cannot be read", description
                entries.append(ServiceEntry(Protocol.ICMP6 if six else Protocol.ICMP, icmp_type=number))
            if any(e.icmp_type is None for e in entries):
                entries = [ServiceEntry(Protocol.ICMP6 if six else Protocol.ICMP)]
            return entries, why, description
        if proto in PROTOCOLS:
            return [ServiceEntry(Protocol.IP, ip_protocol=PROTOCOLS[proto])], why, description
        if proto == "sctp":
            if why_dst or why_src:
                return [], why_dst or why_src, description
            return [ServiceEntry(Protocol.SCTP, dst, src)], "", description
        if proto.isdigit() and int(proto) <= 255:
            return [ServiceEntry(Protocol.IP, ip_protocol=int(proto))], why, description
        if proto in ("any", "all", "ip"):
            return [ServiceEntry(Protocol.IP)], why, description
        return [], f"protocol '{proto[:20]}' cannot be read" if proto else "a service without a protocol", description

    def _build_services(self, used: Set[str]) -> None:
        for name, (entries, why, description) in self.services.items():
            service = Service(name, entries if not why else [], description=description)
            if why:
                service.unsupported = why
            self.p.services[name] = service
        for name, members in self.service_groups.items():
            self.p.service_groups[name] = ServiceGroup(name, list(members))
        for name in sorted(used):
            if name == ANY or name in self.p.services or name in self.p.service_groups:
                continue
            if name in FACTORY_SERVICES:
                self.p.services[name] = Service(name, list(FACTORY_SERVICES[name]), builtin="securepoint",
                                                description="a service the UTM comes with")  # fmt: skip
                self.report.add("service", name, Severity.INFO, "SECUREPOINT_FACTORY_SERVICE",
                                "not defined in the input: read as the service of that name a UTM comes with, with the IANA "
                                "port of the name (Securepoint does not publish the list; assumed)")  # fmt: skip

    # -- addresses and zones ----------------------------------------------------------------------------------------------

    def _zone(self, name: str) -> _Zone:
        if name not in self.zones:
            self.zones[name] = _Zone(name, [], {"INTERFACE"} if name.startswith("firewall-") else set())
            if name:
                self.note("SECUREPOINT_ZONE_UNDEFINED", name)
        return self.zones[name]

    def _interface_of(self, text: str) -> bool:
        """Whether a node's address names an interface (one the zones or addresses name, or of the form of one)."""
        if text in self.addresses or any(text in z.interfaces for z in self.zones.values()):
            return True
        return bool(re.fullmatch(r"(eth|lan|wan|A|B|wlan|ppp|tun|tap|wg|vlan|br|bond|lo)\d+([.:]\d+)?", text))

    def _build_addresses(self) -> None:
        for node in self.nodes.values():
            name, text = node.name, node.address.strip()
            zone = self._zone(node.zone)
            problem = self.object_problems.get(node.name, "")
            if problem:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=problem)
                continue
            if not node.zone:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw="network object without a zone")
                continue
            interval = parse_literal(text) if text else None
            if interval is not None and "-" not in text:
                self.p.addresses[name] = Address(name, AddressKind.NETWORK, _network_text(text))
            elif interval is not None:
                self.p.addresses[name] = Address(name, AddressKind.RANGE, text.replace(" ", ""))
                self.note("SECUREPOINT_RANGE", name)
            elif text and self._interface_of(text):
                known = self.addresses.get(text, [])
                if zone.own:
                    values = [a.split("/")[0] for a in known]
                    what = f"the address of interface {text}"
                else:
                    values = [_network_text(a) for a in known]
                    what = f"the networks of interface {text}"
                if not values:
                    self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"{what}, which the input does not hold",
                                                     builtin="securepoint")  # fmt: skip
                elif len(values) == 1:
                    self.p.addresses[name] = Address(name, AddressKind.NETWORK, _network_text(values[0]), description=what)
                else:
                    members = []
                    for number, value in enumerate(values, 1):
                        member = f"{name}#{number}"
                        self.p.addresses[member] = Address(member, AddressKind.NETWORK, _network_text(value), description=what)
                        members.append(member)
                    self.p.address_groups[name] = AddressGroup(name, members, description=what)
            elif re.fullmatch(r"(?=.*[A-Za-z])[A-Za-z0-9*]([A-Za-z0-9*.-]*[A-Za-z0-9])?\.?", text) and "." in text:
                self.p.addresses[name] = Address(name, AddressKind.FQDN, text.rstrip("."))
            else:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "",
                                                 raw=f"address '{text[:40]}' is not a form FWShift reads" if text else "no address")  # fmt: skip
        for name, members in self.groups.items():
            if name in self.p.addresses:
                continue
            group = AddressGroup(name, list(members))
            for member in members:
                if member not in self.nodes and member not in self.groups and member != ANY:
                    group.unsupported = f"member '{member[:40]}' is not a network object of the input"
            self.p.address_groups[name] = group

    def _leaves(self, ref: str, depth: int = 0, seen: Tuple[str, ...] = ()) -> List[Tuple[str, str]]:
        """The network objects a reference stands for, with their zones; ("", "") for what is not known."""
        if ref == ANY and ref not in self.nodes and ref not in self.groups:
            return [(ANY, ANY)]
        if ref in self.nodes:
            return [(ref, self.nodes[ref].zone)]
        if ref in self.groups and depth < _MAX_NESTING and ref not in seen:
            out: List[Tuple[str, str]] = []
            for member in self.groups[ref]:
                out += self._leaves(member, depth + 1, seen + (ref,))
            return list(dict.fromkeys(out))
        return [(ref, "")]

    def _side(self, ref: str, problems: List[str], what: str) -> Dict[str, List[str]]:
        """Zone -> the members of the model for one side of a rule; the zones of the UTM's own interfaces under "*own"."""
        if not ref:
            problems.append(f"the rule names no {what}")
            return {ANY: [ref or "(none)"]}
        leaves = self._leaves(ref)
        if any(zone == "" for _, zone in leaves):
            missing = [leaf for leaf, zone in leaves if zone == ""]
            problems.append(f"{what} '{missing[0][:40]}' is not a network object of the input")
            return {ANY: [ref]}
        zones = list(dict.fromkeys(zone for _, zone in leaves))
        out: Dict[str, List[str]] = {}
        if len(zones) == 1:
            key = "*own" if zones[0] != ANY and self._zone(zones[0]).own else zones[0]
            return {key: [ref]}
        for leaf, zone in leaves:
            key = "*own" if zone != ANY and self._zone(zone).own else zone
            out.setdefault(key, []).append(leaf)
        return out

    def _network_zone(self, zone: str) -> str:
        """The zone of the networks on the interfaces of one of the UTM's own zones (firewall-external -> external)."""
        own = self.zones.get(zone)
        if own is None:
            return ANY
        if zone.startswith("firewall-") and zone[len("firewall-"):] in self.zones and not self.zones[zone[len("firewall-"):]].own:
            return zone[len("firewall-"):]
        for other in self.zones.values():
            if not other.own and set(other.interfaces) & set(own.interfaces):
                return other.name
        return ANY

    # -- rules --------------------------------------------------------------------------------------------------------

    def _ordered(self) -> List[Tuple[int, _Command]]:
        numbered = list(enumerate(self.rules, 1))
        position = {group: index for index, group in enumerate(self.rule_groups)}
        return sorted(numbered, key=lambda item: (position.get(_text(item[1].params.get("group")), len(position)), item[0]))

    def _rules(self) -> None:
        for number, command in self._ordered():
            self._rule(number, command)

    def _rule(self, number: int, command: _Command) -> None:
        params = command.params
        base = f"rule-{number}"
        group = _text(params.get("group"))
        problems = list(command.problems)
        if not group:
            problems.append("the rule names no rule group")
        flags = [f.upper() for f in _items(params.get("flags"))]
        actions = [f for f in flags if f in ACTIONS]
        nats = [f for f in flags if f in NATS]
        logs = [f for f in flags if f in LOGS]
        for flag in flags:
            if flag not in ACTIONS and flag not in NATS and flag not in LOGS:
                problems.append(f"flag '{flag[:30]}' is not one FWShift reads")
        findings: List[Tuple[Severity, str, str]] = []
        if len(actions) > 1:
            problems.append("more than one action: " + ", ".join(actions))
        if len(nats) > 1:
            problems.append("more than one kind of NAT: " + ", ".join(nats))
        action_flag = actions[0] if actions else ""
        if not actions:
            findings.append((Severity.REVIEW, "SECUREPOINT_NO_ACTION", "the rule has no action in its flags: read as ACCEPT, the "
                             "action the web interface proposes (assumed)"))  # fmt: skip
            action_flag = "ACCEPT"
        nat = nats[0] if nats else ""
        src_ref, dst_ref = _text(params.get("src")), _text(params.get("dst"))
        service = _text(params.get("service")) or ANY
        nat_node, nat_service = _text(params.get("nat_node")), _text(params.get("nat_service"))
        handling: Dict[str, str] = {}
        if action_flag == "QOS":
            handling["qos"] = _text(params.get("qos")) or "QoS profile"
            findings.append((Severity.INFO, "SECUREPOINT_QOS", "action QOS: read as ACCEPT; the bandwidth limit of its QoS profile "
                             "is not converted"))  # fmt: skip
        if action_flag == "STATELESS":
            handling["stateless"] = "yes"
            findings.append((Severity.APPROX, "SECUREPOINT_STATELESS", "action STATELESS allows packets whatever the state of their "
                             "connection, and lets no replies through by itself; the model is stateful and allows the replies "
                             "of what it allows"))  # fmt: skip
        if _text(params.get("route")):
            handling["route"] = _text(params.get("route"))
            findings.append((Severity.INFO, "SECUREPOINT_RULE_ROUTING", f"rule routing (out via {_text(params.get('route'))[:30]}) "
                             "is not converted; it does not change what the rule matches"))  # fmt: skip
        schedule = _text(params.get("timeprofile")) or _text(params.get("time_profile"))
        for flag in logs:
            handling["log"] = "short (the first three entries a minute)" if flag == "LOG" else "long"
        if nat:
            handling["nat"] = nat + (f" {nat_node}" if nat_node else "") + (f" {nat_service}" if nat_service else "")
        src = self._side(src_ref, problems, "source")
        dst = self._side(dst_ref, problems, "destination")
        services = self._rule_services(service, problems)
        # DESTNAT: the destination and service the traffic is sent to are the NAT fields; the rule names the server.
        nat_dst: Dict[str, List[str]] = {}
        if nat == "DESTNAT":
            if not nat_node:
                problems.append("DESTNAT without the network object the traffic is sent to (nat_node)")
            else:
                nat_dst = self._side(nat_node, problems, "NAT network object")
        own_src, own_dst = src.pop("*own", []), dst.pop("*own", [])
        if (own_src or own_dst) and not (src and dst):
            self.local_skipped += 1
            self.report.skip("rule", base, "SECUREPOINT_LOCAL_RULE", "a rule for the UTM's own services (an object in a zone of its "
                             "own interfaces, firewall-...): not converted", Severity.INFO)  # fmt: skip
            return
        pairs = [(sz, dz) for sz in src for dz in dst]
        for index, (src_zone, dst_zone) in enumerate(pairs, 1):
            name = base if index == 1 else f"{base}-{index}"
            rule = Rule(name, src_zones=[src_zone], dst_zones=[dst_zone], sources=list(src[src_zone]),
                        destinations=list(dst[dst_zone]), services=list(services))  # fmt: skip
            rule.origin = name
            rule.action = ACTIONS[action_flag] if action_flag in ACTIONS else Action.DROP
            rule.log_start, rule.log_end = False, bool(logs)
            rule.description = _text(params.get("comment"))
            rule.schedule = schedule
            rule.handling = dict(handling)
            rule.source_ids = {"securepoint.rule": str(number), "securepoint.group": group}
            rule.unsupported = list(dict.fromkeys(problems))
            if nat:
                self._nat(rule, nat, nat_node, nat_service, nat_dst, service)
            self.p.rules.append(rule)
            for severity, code, message in findings:
                self.report.add("rule", name, severity, code, message)
            if own_src or own_dst:
                self.report.add("rule", name, Severity.INFO, "SECUREPOINT_LOCAL_PART",
                                "the members of the rule's groups in a zone of the UTM's own interfaces are left out: that "
                                "part of the rule is for the UTM's own services")  # fmt: skip
            if len(pairs) > 1:
                self.report.add("rule", name, Severity.INFO, "SECUREPOINT_SPLIT",
                                f"rule {number} names members of several zones; it is one rule per pair of zones, each with the "
                                f"members of its zones, which together match what it matches (this is part {index} of {len(pairs)})")  # fmt: skip

    def _rule_services(self, service: str, problems: List[str]) -> List[str]:
        if service == ANY:
            return [ANY]
        if service not in self.services and service not in self.service_groups and service not in FACTORY_SERVICES:
            problems.append(f"service '{service[:40]}' is not a service of the input")
        return [service]

    # -- NAT ----------------------------------------------------------------------------------------------------------

    def _nat(self, rule: Rule, nat: str, nat_node: str, nat_service: str, nat_dst: Dict[str, List[str]], service: str) -> None:
        name = rule.name + "-nat"
        problems: List[str] = []
        rule_nat = NatRule(name, src_zones=list(rule.src_zones), dst_zones=list(rule.dst_zones), sources=list(rule.sources),
                           destinations=list(rule.destinations), service=service)  # fmt: skip
        rule_nat.origin = name
        rule_nat.combines = True  # (destination NAT before the filter and source NAT after it apply to a connection together)
        rule_nat.description = f"{nat} of {rule.name}"
        if nat in ("HIDENAT", "FULLCONENAT"):
            rule_nat.source_translation = self._hide(rule, nat_node, problems)
            if nat == "FULLCONENAT":
                self.report.add("nat", name, Severity.REVIEW, "SECUREPOINT_FULL_CONE",
                                "FULLCONENAT: read as HIDENAT. Full cone NAT keeps the port, and lets other hosts send to the "
                                "translated address and port as well, which is not converted")  # fmt: skip
            if nat_service:
                problems.append(f"a NAT service ({nat_service[:30]}) with {nat}")
        elif nat == "HIDENAT_EXCLUDE":
            if nat_node or nat_service:
                self.report.add("nat", name, Severity.INFO, "SECUREPOINT_NAT_FIELDS", "HIDENAT_EXCLUDE: its NAT network object and "
                                "service are not used")  # fmt: skip
        elif nat == "NETMAP":
            problems.append("NETMAP (a network mapped onto another of the same size, both ways) is not converted")
            rule.unsupported.append("NETMAP on the rule: which addresses its packet filter rule names is not documented")
        elif nat == "DESTNAT":
            self._destnat(rule, rule_nat, nat_node, nat_service, nat_dst, service, problems)
        rule_nat.unsupported = list(dict.fromkeys(problems))
        self.p.nat_rules.append(rule_nat)

    def _hide(self, rule: Rule, nat_node: str, problems: List[str]) -> SourceNat:
        zone = self.zones.get(rule.dst_zones[0]) if rule.dst_zones != [ANY] else None
        if not nat_node:
            interface = zone.interfaces[0] if zone is not None and len(zone.interfaces) == 1 else ""
            return SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=self._first_address(interface))
        node = self.nodes.get(nat_node)
        if node is None:
            problems.append(f"NAT network object '{nat_node[:40]}' is not a network object of the input")
            return SourceNat(SnatKind.INTERFACE)
        if self._interface_of(node.address.strip()) and parse_literal(node.address) is None:
            interface = node.address.strip()
            return SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=self._first_address(interface))
        address = self.p.addresses.get(nat_node)
        interval = parse_literal(address.value) if address is not None and address.kind == AddressKind.NETWORK else None
        if interval is None or interval[1] != interval[2]:
            problems.append(f"NAT network object '{nat_node[:40]}' is not one address or an interface")
        return SourceNat(SnatKind.DYNAMIC_PORT, addresses=[nat_node])

    def _first_address(self, interface: str) -> str:
        known = self.addresses.get(interface, [])
        return known[0].split("/")[0] if known else ""

    def _destnat(self, rule: Rule, nat: NatRule, nat_node: str, nat_service: str, nat_dst: Dict[str, List[str]], service: str,
                 problems: List[str]) -> None:  # fmt: skip
        """The rule named the server and the port the traffic reaches; the model names what it was sent to."""
        server = rule.destinations
        target = None
        if len(server) == 1 and server[0] in self.p.addresses:
            address = self.p.addresses[server[0]]
            interval = parse_literal(address.value) if address.kind == AddressKind.NETWORK else None
            if interval is not None and interval[1] == interval[2]:
                target = server[0]
        if target is None:
            problems.append(f"the destination of a DESTNAT rule ({', '.join(server)[:40]}) is not one address")
        port = ""
        if nat_service and nat_service != service:
            entries = transform.flatten_services(self.p, service) if service != ANY else None
            ports = {e.dst_ports for e in entries or []}
            if not entries or len(ports) != 1 or not next(iter(ports)).isdigit() or any(e.protocol not in (Protocol.TCP, Protocol.UDP) for e in entries):
                problems.append(f"service '{service[:30]}' of a DESTNAT rule with a NAT service is not one TCP or UDP port")
            else:
                port = next(iter(ports))
        zones = [z for z in nat_dst if z != "*own"]
        own = nat_dst.get("*own", [])
        members = [m for z in zones for m in nat_dst[z]] + own
        nat_zones = [self._network_zone(self.nodes[m].zone) if m in self.nodes else ANY for m in own] + zones
        nat.destinations = members or [nat_node or "(none)"]
        nat.dst_zones = list(dict.fromkeys(nat_zones)) if nat_zones and ANY not in nat_zones else [ANY]
        nat.service = nat_service or service
        nat.destination_translation = DestNat(target or (server[0] if server else "0.0.0.0"), port)
        # The rule of the model: the traffic the translation takes to the server, as it arrives.
        rule.destinations = list(nat.destinations)
        rule.services = [nat.service]
        self.destnat_rules.add(rule.origin)
        self.report.add("rule", rule.origin, Severity.INFO, "SECUREPOINT_DESTNAT",
                        f"a DESTNAT rule: read for the traffic it translates, sent to {', '.join(nat.destinations)[:60]} "
                        f"({nat.service}) and taken to {', '.join(server)[:40]}; that it also allows traffic sent to the server "
                        "directly is not documented and is not read")  # fmt: skip

    # -- the whole ----------------------------------------------------------------------------------------------------------

    def build(self) -> Policy:
        self.read()
        used = {_text(c.params.get("service")) for c in self.rules} | {_text(c.params.get("nat_service")) for c in self.rules}
        used |= {m for members in self.service_groups.values() for m in members}
        self._build_addresses()
        self._build_services({u for u in used if u})
        for zone in list(self.zones.values()):
            if zone.own or not zone.name:
                continue
            self.p.zones[zone.name] = Zone(zone.name, list(zone.interfaces))
            networks = [_network_text(a) for i in zone.interfaces for a in self.addresses.get(i, [])]
            if networks:
                self.p.zone_networks[zone.name] = list(dict.fromkeys(networks))
        self._rules()
        for rule in self.p.rules:
            for name in rule.src_zones + rule.dst_zones:
                if name != ANY and name not in self.p.zones:
                    self.p.zones[name] = Zone(name)
        # The packet filter sees the destination after DESTNAT: the other rules are rewritten for it as it arrives. The
        # rules of the DESTNAT rules are already read for what they translate.
        others = [rule for rule in self.p.rules if rule.origin not in self.destnat_rules]
        everything = self.p.rules
        self.p.rules = others
        try:
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        finally:
            self.p.rules = everything
        self._notes()
        return self.p

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "SECUREPOINT_SOURCE",
                         f"{len(self.rules)} rules of the packet filter in {len(self.rule_groups)} rule groups, first match in the order "
                         "of the groups; zones from the network objects; what no rule matches is dropped (Default Drop)")  # fmt: skip
        self.report.note(Severity.INFO, "SECUREPOINT_IMPLIED_RULES",
                         "the UTM's implicit rules (Firewall > Implied rules: its own services, VPN, the threat intelligence "
                         "filter) come before the packet filter and are not converted")  # fmt: skip
        if self.local_skipped:
            self.report.note(Severity.INFO, "SECUREPOINT_LOCAL_RULES", f"{self.local_skipped} rules for the UTM's own services (to or "
                             "from objects in zones of its own interfaces) are not converted")  # fmt: skip
        if self.p.nat_rules:
            self.report.note(Severity.INFO, "SECUREPOINT_NAT_ORDER",
                             "NAT is part of the rules: each rule with NAT became a NAT rule, in the order of the rules. DESTNAT is "
                             "done before the packet filter and HIDENAT after it (netfilter); a rule's NAT is read as applying "
                             "whatever its action (assumed)")  # fmt: skip
        texts = {
            "SECUREPOINT_IMPLIED": (Severity.REVIEW, "commands that change the implicit rules are not converted"),
            "SECUREPOINT_EDITS": (Severity.REVIEW, "commands that change or delete objects or rules were not carried out; what they "
                                  "do is not in the model"),
            "SECUREPOINT_UNREAD": (Severity.REVIEW, "commands or parameters that were not read"),
            "SECUREPOINT_ZONE_UNDEFINED": (Severity.INFO, "zones the network objects name that no 'interface zone new' defines (read "
                                           "as zones without interfaces; firewall-... as the UTM's own)"),
            "SECUREPOINT_GROUP_IMPLIED": (Severity.INFO, "rule groups no 'rule group new' creates, placed where their first rule is"),
            "SECUREPOINT_DUPLICATE": (Severity.REVIEW, "names created twice: the last one is read"),
            "SECUREPOINT_RANGE": (Severity.INFO, "network objects with an address range a-b (a form FWShift reads, not documented)"),
            "SECUREPOINT_NODE_TYPE": (Severity.INFO, "network objects with a type parameter, read by their address"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def _network_text(text: str) -> str:
    """An address or network as the model writes it: a network with host bits set is the network they are in."""
    text = text.strip()
    if "/" not in text:
        return text
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    try:
        return _Builder(text, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None
