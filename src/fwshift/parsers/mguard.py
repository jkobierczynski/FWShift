# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Phoenix Contact mGuard parser: a configuration profile (``.atv``, as Management >> Configuration Profiles saves it,
or ``gaiconfig --get-all`` prints it) of an FL/TC MGUARD with mGuard firmware 8.x, 9.x or 10.x -> neutral model.

The file: a ``#version`` line, then variables (``NAME = "value"``); a table is ``NAME = { {row} {row} }`` with the
variables of each row inside, a row that other rows refer to starts with ``{ rid = "ID" }``, and a reference is
``FIELD = { rowref = "ID" }``. Phoenix Contact's gaiconfig User Guides (mGuard 8.6 to 10.4) name the variables and
their values and show the tables in this form; the rest of the syntax (``#`` lines, ``//`` comments, ``rid``,
``rowref``, ``value``, escapes) is not published by Phoenix and is taken from the reader of a public tool
(GriffinPlus mguard-config-tool). **Assumed** where Phoenix is silent.

How the mGuard decides forwarded traffic, and how that is mapped onto the neutral model:

* Zones: ``internal`` (the LAN port, ``int``), ``external`` (WAN, ``ext1``), ``external2`` (the serial or modem
  interface of older models, ``ext2``, only where the profile names it) and ``dmz`` (``dmz0``, FL MGUARD 4305, only
  where the profile uses it). In stealth mode the mGuard sits in the wire between the client (``internal``) and the
  network (``external``); the same zones are used.
* The packet filter is a table per direction, each first match from the top: ``FW_INCOMING`` (connections opened from
  outside, WAN -> LAN; ``EXT_IF`` picks External, External 2 or both), ``FW_OUTGOING`` (LAN -> WAN, and from one VLAN
  of the LAN side to another), and on the 4305 the DMZ tables ``FW_INCOMING_WAN_DMZ``, ``FW_INCOMING_DMZ_LAN``,
  ``FW_OUTGOING_DMZWAN`` and ``FW_OUTGOING_LANDMZ``. The tables decide disjoint pairs of zones, so they are one list
  in the model. A rule has one protocol (tcp, udp, icmp, gre or all), one source and one destination (an address, a
  network, or an IP group), one source and one destination port (a port, ``a:b``, a service name or a port group; for
  tcp and udp only, otherwise they are ignored), and Accept, Reject, Drop or a rule set. ``FW_INCOMING_GLOBAL`` and
  ``FW_OUTGOING_GLOBAL`` (accept, drop, ping, rules) decide whether the table is used at all. What no rule matches is
  dropped (Phoenix: incoming connections are discarded by default, outgoing ones are allowed by a default *rule*;
  that a table without a matching row drops is **assumed**). The packet filter is stateful.
* A rule set (``FW_RULESETS``) is entered by a rule whose action names it: its rules, first match, limited to what the
  rule matches, in the place of the rule. **Assumed**: when none of them matches, the next rule of the table decides.
  A set that is switched by a button, a CMD input, a VPN connection or a timeout is read, but its rules are not
  converted (they apply only while it is active); a disabled set has no influence.
* NAT (router mode only): port forwarding (``FW_PORTFORWARDING``) is done before the packet filter and **skips it**
  (Phoenix: "Any existing firewall rules ... are not taken into consideration"): each becomes a destination NAT rule
  and an allow rule at the top of the model for what it forwards. 1:1 NAT (``FW_1TO1_NAT``) maps a real network to a
  virtual one; the incoming rules name the real address (Phoenix's configuration example), so they are rewritten for
  the address as it arrives, as for FortiOS. IP masquerading (``FW_NAT``) is source NAT to the address of the
  interface the traffic leaves by.
* IPv4 only: the profile has no IPv6 variables, and an address of a rule is IPv4. ``0.0.0.0/0`` is every IPv4 address.
* Not converted, but reported: the user firewall (templates of rules for users who log in), the firewall of VPN
  connections, the MAC filter of stealth mode, and access to the mGuard itself (HTTPS, SSH, SNMP, ICMP).

Assumptions not confirmed on a device are listed in DEVELOPMENT.md and in the notes of the report.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

from .. import transform, zonenets
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

_MAX_BYTES = 64 * 1024 * 1024
_MAX_DEPTH = 32
INTERNAL, EXTERNAL, EXTERNAL2, DMZ = "internal", "external", "external2", "dmz"
INTERFACE_OF = {INTERNAL: "int", EXTERNAL: "ext1", EXTERNAL2: "ext2", DMZ: "dmz0"}
FORWARD_TAG = "fwshift:mguard-port-forwarding"  # an allow rule a port forwarding implies (it skips the packet filter)
EXTERN = "%extern"
# The tables of the packet filter: (variable, name of the rules, source side, destination side).
TABLES = (
    ("FW_INCOMING", "incoming", "ext", INTERNAL),
    ("FW_OUTGOING", "outgoing", INTERNAL, "ext"),
    ("FW_INCOMING_WAN_DMZ", "wan-dmz", "ext", DMZ),
    ("FW_INCOMING_DMZ_LAN", "dmz-lan", DMZ, INTERNAL),
    ("FW_OUTGOING_DMZWAN", "dmz-wan", DMZ, "ext"),
    ("FW_OUTGOING_LANDMZ", "lan-dmz", INTERNAL, DMZ),
)
_RULE_FIELDS = {"EXT_IF", "PROTO", "FROM_IP", "FROM_PORT", "IN_IP", "IN_PORT", "TARGET_REF", "COMMENT", "LOG"}
_PROTOCOLS = {"tcp", "udp", "icmp", "gre", "all"}
# Service names a port field takes (the web interface: "110 for pop3 or pop3 for 110"); the numbers of the IANA
# registry. Which names the mGuard knows is not published: a name not in this table is not converted.
SERVICE_NAMES = {"ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "bootps": 67, "bootpc": 68,
                 "tftp": 69, "http": 80, "www": 80, "pop3": 110, "sunrpc": 111, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138,
                 "netbios-ssn": 139, "imap": 143, "snmp": 161, "snmp-trap": 162, "ldap": 389, "https": 443, "microsoft-ds": 445,
                 "isakmp": 500, "syslog": 514, "submission": 587, "ldaps": 636, "imaps": 993, "pop3s": 995, "openvpn": 1194,
                 "ms-sql-s": 1433, "radius": 1812, "mysql": 3306, "ms-wbt-server": 3389, "sip": 5060, "vnc": 5900}  # fmt: skip
_MANAGEMENT = ("HTTPS_REMOTE_ACCESS_RULES", "SSH_REMOTE_ACCESS_RULES", "SNMP_ACCESS_RULES", "NTP_ACCESS_RULES")


# -- the file -------------------------------------------------------------------------------------------------------


@dataclass
class Row:
    rid: str = ""
    items: Dict[str, "Node"] = field(default_factory=dict)
    line: int = 0


@dataclass
class Node:
    """A variable: a value (``text``), a reference to a row (``ref``), or a table (``rows``)."""

    name: str
    line: int
    text: Optional[str] = None
    ref: str = ""
    rows: Optional[List[Row]] = None
    attrs: Dict[str, str] = field(default_factory=dict)


Token = Tuple[str, str, int]  # kind, text, line


def _tokens(text: str) -> List[Token]:
    out: List[Token] = []
    i, line, n = 0, 1, len(text)
    at_start = True
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            at_start = True
            continue
        if c in " \t\r\f\v﻿":
            i += 1
            continue
        if c == "#" and at_start:
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(("pragma", text[i + 1 : end].strip(), line))
            i = end
            continue
        at_start = False
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if c in "{}=":
            out.append((c, c, line))
            i += 1
            continue
        if c == '"':
            j, chars, start = i + 1, [], line
            while True:
                if j >= n:
                    raise ParseError(f"line {start}: a string that does not end")
                d = text[j]
                if d == "\\" and j + 1 < n:
                    nxt = text[j + 1]
                    if nxt in '"\\':
                        chars.append(nxt)
                    else:
                        chars.append("\\" + nxt)  # (only a quote and a backslash are escaped)
                    if nxt == "\n":
                        line += 1
                    j += 2
                    continue
                if d == '"':
                    break
                if d == "\n":
                    line += 1
                chars.append(d)
                j += 1
            out.append(("string", "".join(chars), start))
            i = j + 1
            continue
        found = re.compile(r"[A-Za-z][A-Za-z0-9._]*").match(text, i)
        if not found:
            raise ParseError(f"line {line}: unexpected character {c!r}; not an mGuard configuration profile (.atv)")
        out.append(("ident", found.group(0), line))
        i = found.end()
    return out


class _Reader:
    def __init__(self, tokens: List[Token]) -> None:
        self.tokens, self.pos = tokens, 0

    def peek(self, offset: int = 0) -> Optional[Token]:
        index = self.pos + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def take(self, kind: str) -> Token:
        token = self.peek()
        if token is None:
            raise ParseError(f"the profile ends where {kind!r} was expected")
        if token[0] != kind:
            raise ParseError(f"line {token[2]}: {kind!r} expected, found {token[1]!r}")
        self.pos += 1
        return token

    def setting(self, depth: int) -> Node:
        if depth > _MAX_DEPTH:
            raise ParseError("tables nested too deeply")
        name = self.take("ident")
        self.take("=")
        token = self.peek()
        if token is not None and token[0] == "string":
            self.pos += 1
            return Node(name[1], name[2], text=token[1])
        self.take("{")
        node = Node(name[1], name[2])
        while True:  # attributes: key = "value"
            a, b, c = self.peek(), self.peek(1), self.peek(2)
            if a and b and c and a[0] == "ident" and b[0] == "=" and c[0] == "string":
                node.attrs[a[1]] = c[1]
                self.pos += 3
                continue
            break
        rows: List[Row] = []
        while self.peek() is not None and self.peek()[0] == "{":  # type: ignore[index]
            rows.append(self.row(depth + 1))
        self.take("}")
        if not rows and "rowref" in node.attrs:
            node.ref = node.attrs["rowref"]
        elif not rows and "value" in node.attrs:
            node.text = node.attrs["value"]
        else:
            node.rows = rows
        return node

    def row(self, depth: int) -> Row:
        start = self.take("{")
        row = Row(line=start[2])
        a, b, c, d, e = (self.peek(k) for k in range(5))
        if a and b and c and d and e and a[0] == "{" and b[0] == "ident" and b[1] == "rid" and c[0] == "=" and d[0] == "string" and e[0] == "}":
            row.rid = d[1]
            self.pos += 5
        while True:
            token = self.peek()
            if token is None:
                raise ParseError(f"line {start[2]}: a row that does not end")
            if token[0] == "}":
                self.pos += 1
                return row
            node = self.setting(depth)
            row.items[node.name] = node


def read_profile(text: str) -> Tuple[Dict[str, str], Dict[str, Node]]:
    """(pragmas, variables) of a configuration profile; a variable given twice is the later one (mdm's includes)."""
    reader = _Reader(_tokens(text))
    pragmas: Dict[str, str] = {}
    variables: Dict[str, Node] = {}
    while reader.peek() is not None:
        token = reader.peek()
        assert token is not None
        if token[0] == "pragma":
            name, _, value = token[1].partition(" ")
            pragmas.setdefault(name, value.strip())
            reader.pos += 1
            continue
        node = reader.setting(0)
        variables[node.name] = node
    return pragmas, variables


def looks_like_mguard(data: bytes) -> bool:
    """A configuration profile: a ``#version`` line of three numbers near the top, and variables of the mGuard (names
    in capitals, ``= "`` or ``= {``), of which at least one only an mGuard has."""
    head = data[:1_000_000].decode("utf-8", errors="replace").lstrip("﻿")
    lines = head.splitlines()[:400]
    if not any(re.match(r"\s*#version\s+\d+\.\d+\.\d+", line) for line in lines[:20]):
        return False
    variables = [line for line in lines if re.match(r'\s*[A-Z][A-Z0-9_]* = ("|\{)', line)]
    return len(variables) >= 2 and bool(re.search(r"^\s*(NETWORKMODE|FW_INCOMING|FW_OUTGOING|MY_LOCAL_IP|ROUTER_MODE|FW_RULESETS|FW_GROUP_IP) = ",
                                                    head, re.MULTILINE))  # fmt: skip


# -- the policy -----------------------------------------------------------------------------------------------------


@dataclass
class _Port:
    """The ports of one field: '' every port, else a PAN-OS port list; why it cannot be read."""

    ports: str = ""
    label: str = "any"
    problem: str = ""


@dataclass
class _Match:
    proto: str
    source: Union[str, None]  # a model member; None when it cannot be read
    destination: Union[str, None]
    src_port: _Port
    dst_port: _Port
    problems: List[str] = field(default_factory=list)


class _Builder:
    def __init__(self, pragmas: Dict[str, str], variables: Dict[str, Node], report: Report) -> None:
        self.pragmas, self.vars, self.report = pragmas, variables, report
        self.p = Policy(vendor="mguard", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.rows: Dict[str, Tuple[str, Row]] = {}  # rid -> (table, row)
        self.ip_groups: Dict[str, str] = {}  # NAME -> model name
        self.port_groups: Dict[str, Tuple[str, str]] = {}  # NAME -> (ports, why not)
        self.bad_ip_groups: Dict[str, str] = {}
        self.rulesets: Dict[str, Row] = {}  # FRIENDLY_NAME -> row
        self.names: Set[str] = set()
        self.notes: Dict[str, List[str]] = {}
        self.router = True
        self.zone_names: List[str] = []
        self.externals: List[str] = [EXTERNAL]
        self.extern_address = ""
        self.internal_routed = False

    # -- helpers -------------------------------------------------------------------------------------------------

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def _unique(self, name: str) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in self.names:
            candidate = f"{name}-{counter}"
            counter += 1
        self.names.add(candidate.lower())
        return candidate

    def _value(self, name: str) -> str:
        node = self.vars.get(name)
        return node.text.strip() if node is not None and node.text is not None else ""

    def _table(self, name: str, row: Optional[Row] = None) -> List[Row]:
        node = (row.items if row is not None else self.vars).get(name)
        return node.rows if node is not None and node.rows is not None else []

    @staticmethod
    def _field(row: Row, name: str) -> Optional[Node]:
        return row.items.get(name)

    @staticmethod
    def _text(row: Row, name: str) -> Optional[str]:
        node = row.items.get(name)
        return node.text.strip() if node is not None and node.text is not None else None

    def _index_rows(self, rows: List[Row], table: str, depth: int = 0) -> None:
        for row in rows:
            if row.rid:
                self.rows.setdefault(row.rid, (table, row))
            for node in row.items.values():
                if node.rows is not None and depth < _MAX_DEPTH:
                    self._index_rows(node.rows, f"{table}.{node.name}", depth + 1)

    # -- build ---------------------------------------------------------------------------------------------------

    def build(self) -> Policy:
        if "version" not in self.pragmas and not any(name.startswith("FW_") for name in self.vars):
            raise ParseError("no #version line and no packet filter (FW_ variables): not an mGuard configuration profile")
        for node in self.vars.values():
            if node.rows is not None:
                self._index_rows(node.rows, node.name)
        mode = self._value("NETWORKMODE").lower() or "router"
        if not self._value("NETWORKMODE"):
            self._say("MGUARD_MODE", "NETWORKMODE is not in the profile: read as router, the factory setting")
        self.router = mode != "stealth"
        if mode not in ("router", "stealth"):
            self._say("MGUARD_MODE", f"NETWORKMODE {mode[:20]} is not known: read as router")
        self._zones()
        self._ip_groups()
        self._port_groups()
        for row in self._table("FW_RULESETS"):
            name = self._text(row, "FRIENDLY_NAME") or ""
            if name:
                self.rulesets.setdefault(name, row)
        forwards: List[Rule] = []
        if self.router:
            forwards = self._nat()
        elif any(self._table(t) for t in ("FW_PORTFORWARDING", "FW_1TO1_NAT", "FW_NAT")):
            self.report.note(Severity.INFO, "MGUARD_NAT_STEALTH",
                             "the profile is for stealth mode, in which the mGuard does no NAT: its tables of port forwarding, 1:1 NAT "
                             "and masquerading are not read")  # fmt: skip
        self.p.rules += forwards
        for table, label, src, dst in TABLES:
            self._packet_filter(table, label, src, dst)
        if any(n.source_translation is not None and n.source_translation.bidirectional for n in self.p.nat_rules if not n.unsupported):
            self.p.lookup_after_dnat = True
            static = {n.origin for n in self.p.nat_rules if n.source_translation is not None and n.source_translation.bidirectional}
            # 1:1 NAT translates what arrives on the external side (Phoenix's example); rules for traffic from elsewhere keep
            # their addresses.
            every = self.p.rules
            self.p.rules = [r for r in every if set(r.src_zones) & set(self.externals) and FORWARD_TAG not in r.tags]
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False, only=static)
            self.p.rules = every
        for rule in self.p.rules:
            if rule.unsupported and not any(f.code == "MGUARD_RULESET_SWITCHED" for f in self.report.item("rule", rule.origin).findings):
                self.report.add("rule", rule.origin, Severity.REVIEW, "MGUARD_UNREAD", "not converted: " + "; ".join(rule.unsupported)[:300])
        if self.router:
            self._zone_networks()
        self._notes()
        return self.p

    # -- zones ---------------------------------------------------------------------------------------------------

    def _uses_ext2(self) -> bool:
        tables = [self._table(t) for t, _, _, _ in TABLES] + [self._table("FW_NAT")]
        return any(self._text(row, "EXT_IF") == "ext2" for rows in tables for row in rows)

    def _uses_dmz(self) -> bool:
        if any(self._table(t) for t, _, src, dst in TABLES if DMZ in (src, dst)):
            return True
        return bool(self._table("DMZ_ALIASES")) or any(self._text(row, "EXT_IF") == "dmz0" for row in self._table("FW_NAT"))

    def _zones(self) -> None:
        names = [INTERNAL, EXTERNAL]
        if self._uses_ext2():
            names.append(EXTERNAL2)
            self.externals = [EXTERNAL, EXTERNAL2]
        if self._uses_dmz():
            names.append(DMZ)
        for name in names:
            self.p.zones[name] = Zone(name, [INTERFACE_OF[name]])
        self.zone_names = names
        self.internal_routed = bool(self._table("LOCAL_ALIASES"))

    def _side(self, side: str) -> List[str]:
        return list(self.externals) if side == "ext" else [side]

    # -- objects -------------------------------------------------------------------------------------------------

    def _ip_groups(self) -> None:
        for index, row in enumerate(self._table("FW_GROUP_IP")):
            name = self._text(row, "NAME") or f"ip-group-{index + 1}"
            model = self._unique(name)
            members: List[str] = []
            problem = ""
            for entry_index, entry in enumerate(self._table("ENTRY", row)):
                value = self._text(entry, "IP")
                if value is None:
                    problem = f"entry {entry_index + 1} has no IP"
                    continue
                literal = self._literal(value, ranges=True)
                if literal:
                    members.append(literal)
                elif re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*", value) and not value.isdigit():
                    host = self._unique(value)
                    self.p.addresses[host] = Address(host, AddressKind.FQDN, value, fqdn_family=4)
                    members.append(host)
                    self._say("MGUARD_HOSTNAME", f"{name[:30]}: {value[:60]}")
                else:
                    problem = f"entry {value[:40]!r} is not an address, a range, a network or a host name"
            group = AddressGroup(model, members, self._text(row, "COMMENT") or "")
            if problem or not members:
                group.unsupported = problem or "the IP group has no entries"
                self.bad_ip_groups[model] = group.unsupported
            self.p.address_groups[model] = group
            self.ip_groups.setdefault(name, model)
            if row.rid:
                self.ip_groups.setdefault("\0" + row.rid, model)

    def _port_groups(self) -> None:
        for index, row in enumerate(self._table("FW_GROUP_PORT")):
            name = self._text(row, "NAME") or f"port-group-{index + 1}"
            ports: List[str] = []
            problem = ""
            for entry in self._table("ENTRY", row):
                value = self._text(entry, "PORT") or ""
                found = self._port_text(value.replace(":", "-"), allow_names=True)
                if found is None:
                    problem = f"entry {value[:30]!r} is not a port or a range of ports"
                else:
                    ports.append(found)
            if not ports and not problem:
                problem = "the port group has no entries"
            entry_text = ",".join(dict.fromkeys(ports))
            self.port_groups.setdefault(name, (entry_text, problem))
            if row.rid:
                self.port_groups.setdefault("\0" + row.rid, (entry_text, problem))
                self.port_groups.setdefault("\1" + row.rid, (name, ""))

    @staticmethod
    def _port_text(value: str, allow_names: bool = False) -> Optional[str]:
        value = value.strip().lower()
        if allow_names and value in SERVICE_NAMES:
            return str(SERVICE_NAMES[value])
        first, dash, last = value.partition("-")
        if not first.isdigit() or (dash and not last.isdigit()):
            return None
        low, high = int(first), int(last or first)
        if not 0 <= low <= high <= 65535:
            return None
        return str(low) if low == high else f"{low}-{high}"

    @staticmethod
    def _literal(value: str, ranges: bool = False) -> str:
        """An IPv4 address, network (or range, in an IP group) as the model writes it; '' if it is none."""
        text = value.strip()
        if not text or text.count("/") > 1 or (not ranges and "-" in text):
            return ""
        found = parse_literal(text)
        if found is None or found[0] != 4:
            return ""
        if text == "0.0.0.0/0":
            return ANY_V4
        if "-" in text:
            first, last = (part.strip() for part in text.split("-", 1))
            return f"{ipaddress.IPv4Address(first)}-{ipaddress.IPv4Address(last)}"
        net = ipaddress.ip_network(text, strict=False)
        return str(net.network_address) if net.prefixlen == 32 else str(net)

    def _address(self, row: Row, name: str, where: str, problems: List[str]) -> Optional[str]:
        node = self._field(row, name)
        if node is None:
            problems.append(f"{name} is not in the row")
            return None
        if node.ref:
            model = self.ip_groups.get("\0" + node.ref)
            if model is None:
                problems.append(f"{name} refers to row {node.ref[:24]}, which is not an IP group of the profile")
                return None
            return model
        if node.text is None:
            problems.append(f"{name} is a table")
            return None
        literal = self._literal(node.text)
        if literal:
            return literal
        if node.text.strip() in self.ip_groups:
            return self.ip_groups[node.text.strip()]
        problems.append(f"{name} {node.text.strip()[:40]!r} is not an IPv4 address, a network or an IP group")
        return None

    def _port(self, row: Row, name: str) -> _Port:
        node = self._field(row, name)
        if node is None:
            return _Port(problem=f"{name} is not in the row")
        if node.ref:
            found = self.port_groups.get("\0" + node.ref)
            if found is None:
                return _Port(problem=f"{name} refers to row {node.ref[:24]}, which is not a port group of the profile")
            label = self.port_groups["\1" + node.ref][0]
            return _Port(found[0], label, f"port group {label}: {found[1]}" if found[1] else "")
        text = (node.text or "").strip()
        if text.lower() in ("", "any"):
            return _Port()
        found_text = self._port_text(text.replace(":", "-"), allow_names=True)
        if found_text is not None:
            return _Port(found_text, found_text)
        if text in self.port_groups:
            ports, problem = self.port_groups[text]
            return _Port(ports, text, f"port group {text}: {problem}" if problem else "")
        return _Port(problem=f"{name} {text[:30]!r} is not a port, a range, a service name FWShift knows or a port group")

    def _service(self, proto: str, src: _Port, dst: _Port) -> str:
        """The model service of a protocol and its ports."""
        if proto == "all":
            return ANY
        if proto == "icmp":
            entries = [ServiceEntry(Protocol.ICMP)]
            label = "icmp"
        elif proto == "gre":
            entries = [ServiceEntry(Protocol.IP, ip_protocol=47)]
            label = "gre"
        else:
            entries = [ServiceEntry(Protocol(proto), dst.ports, src.ports)]
            label = f"{proto}-{dst.label}" + (f"-from-{src.label}" if src.ports else "")
        for name, service in self.p.services.items():
            if service.entries == entries:
                return name
        name = self._unique(label)
        self.p.services[name] = Service(name, entries)
        return name

    # -- the packet filter ---------------------------------------------------------------------------------------

    def _match(self, row: Row, where: str) -> _Match:
        problems: List[str] = []
        proto = (self._text(row, "PROTO") or "").lower()
        if proto not in _PROTOCOLS:
            problems.append(f"protocol {proto[:20]!r} is not known" if proto else "PROTO is not in the row")
            proto = "all"
        source = self._address(row, "FROM_IP", where, problems)
        destination = self._address(row, "IN_IP", where, problems)
        src_port, dst_port = self._port(row, "FROM_PORT"), self._port(row, "IN_PORT")
        if proto in ("tcp", "udp"):
            problems += [p.problem for p in (src_port, dst_port) if p.problem]
        elif src_port.ports or dst_port.ports or src_port.problem or dst_port.problem:
            self._say("MGUARD_PORTS_IGNORED", where)
            src_port, dst_port = _Port(), _Port()
        return _Match(proto, source, destination, src_port, dst_port, problems)

    def _packet_filter(self, table: str, label: str, src: str, dst: str) -> None:
        rows = self._table(table)
        src_zones, dst_zones = self._side(src), self._side(dst)
        if table == "FW_OUTGOING" and self.internal_routed:
            dst_zones = dst_zones + [INTERNAL]
        overridden = ""
        if table in ("FW_INCOMING", "FW_OUTGOING"):
            overridden = self._global(table, label, src_zones, dst_zones)
        for index, row in enumerate(rows):
            name = f"{label}-{index + 1}"
            where = f"{table} row {index + 1}"
            zones = list(src_zones)
            ext_if = self._text(row, "EXT_IF")
            if table == "FW_INCOMING":
                if ext_if == "ext1":
                    zones = [EXTERNAL]
                elif ext_if == "ext2":
                    zones = [EXTERNAL2]
                elif ext_if is not None and ext_if != "all":
                    zones = list(self.externals)
                    self._say("MGUARD_UNREAD", f"{where}: EXT_IF {ext_if[:20]}")
            rules = self._row_rules(row, name, where, zones, dst_zones)
            for rule in rules:
                if overridden:
                    rule.enabled = False
                    self.report.add("rule", rule.origin, Severity.INFO, "MGUARD_GLOBAL_POLICY",
                                    f"not in use: {table}_GLOBAL is {overridden}, not 'Use the firewall ruleset below'")  # fmt: skip
                self.p.rules.append(rule)

    def _global(self, table: str, label: str, src_zones: List[str], dst_zones: List[str]) -> str:
        """The rule ``*_GLOBAL`` stands for, where it is not ``rules``; returns its value then, '' otherwise."""
        value = self._value(f"{table}_GLOBAL").lower()
        if value in ("", "rules"):
            return ""
        name = self._unique(f"{label}-global")
        rule = Rule(name, src_zones=list(src_zones), dst_zones=list(dst_zones), sources=[ANY_V4], destinations=[ANY_V4], origin=name)
        rule.log_end = False
        if value == "accept":
            rule.description = f"{table}_GLOBAL accept: every connection"
        elif value == "drop":
            rule.action, rule.description = Action.DROP, f"{table}_GLOBAL drop: no connection"
        elif value == "ping":
            ping = self._unique("ping")
            self.p.services[ping] = Service(ping, [ServiceEntry(Protocol.ICMP, icmp_type=8)])
            rule.services, rule.description = [ping], f"{table}_GLOBAL ping: ICMP echo requests only"
            self.p.rules.append(rule)
            self.report.add("rule", name, Severity.INFO, "MGUARD_GLOBAL_POLICY", f"{table}_GLOBAL is ping: echo requests pass, nothing else")
            name = self._unique(f"{label}-global-drop")
            rule = Rule(name, src_zones=list(src_zones), dst_zones=list(dst_zones), sources=[ANY_V4], destinations=[ANY_V4],
                        action=Action.DROP, origin=name, description=f"{table}_GLOBAL ping: everything else")  # fmt: skip
            rule.log_end = False
        else:
            rule.enabled = False
            rule.unsupported.append(f"{table}_GLOBAL {value[:20]} is not known")
            self.report.add("rule", name, Severity.REVIEW, "MGUARD_UNREAD", f"{table}_GLOBAL {value[:20]!r} is not known; the rows are read")
            self.p.rules.append(rule)
            return ""
        self.p.rules.append(rule)
        self.report.add("rule", name, Severity.INFO, "MGUARD_GLOBAL_POLICY",
                        f"{table}_GLOBAL is {value}: the rows of {table} are not in use")  # fmt: skip
        return value

    def _row_rules(self, row: Row, name: str, where: str, src_zones: List[str], dst_zones: List[str]) -> List[Rule]:
        match = self._match(row, where)
        rule = Rule(self._unique(name), src_zones=list(src_zones), dst_zones=list(dst_zones))
        rule.origin = rule.name
        rule.description = self._text(row, "COMMENT") or ""
        log = (self._text(row, "LOG") or "no").lower()
        rule.log_end = log == "yes"
        unknown = sorted(set(row.items) - _RULE_FIELDS)
        if unknown:
            rule.unsupported.append("fields FWShift does not know: " + ", ".join(u[:20] for u in unknown[:6]))
        rule.sources = [match.source or ANY_V4]
        rule.destinations = [match.destination or ANY_V4]
        if match.source is None or match.destination is None or match.problems:
            rule.unsupported += match.problems
        rule.services = [self._service(match.proto, match.src_port, match.dst_port)] if not match.problems else [ANY]
        for member in rule.sources + rule.destinations:
            if member in self.bad_ip_groups:
                rule.unsupported.append(f"IP group {member}: {self.bad_ip_groups[member]}")
        target = self._field(row, "TARGET_REF")
        if target is None:
            rule.unsupported.append("TARGET_REF is not in the row")
            rule.action = Action.DROP
            return [rule]
        if target.ref or (target.text is not None and target.text.strip() in self.rulesets):
            ruleset: Optional[Row] = None
            if target.ref:
                table, found = self.rows.get(target.ref, ("", Row()))
                ruleset = found if table == "FW_RULESETS" else None
            else:
                ruleset = self.rulesets[(target.text or "").strip()]
            if ruleset is None:
                rule.unsupported.append(f"the action refers to row {target.ref[:24]}, which is not a rule set of the profile")
                rule.action = Action.DROP
                return [rule]
            return self._ruleset(rule, match, ruleset, where)
        action = (target.text or "").strip().upper()
        if action == "ACCEPT":
            rule.action = Action.ALLOW
        elif action == "DROP":
            rule.action = Action.DROP
        elif action == "REJECT":
            rule.action = Action.RESET_BOTH
            self._say("MGUARD_REJECT", where)
        else:
            rule.action = Action.DROP
            rule.unsupported.append(f"action {action[:20]!r} is not known")
        return [rule]

    @staticmethod
    def _meet(outer: Optional[str], inner: Optional[str]) -> Tuple[Optional[str], str]:
        """The members of one side of a rule set's rule, limited to what the rule that enters the set names."""
        if outer is None or inner is None:
            return None, "a side cannot be read"
        if outer == ANY_V4:
            return inner, ""
        if inner == ANY_V4 or inner == outer:
            return outer, ""
        return None, f"the rule that enters the set and the rule of the set both narrow it ({outer[:30]}, {inner[:30]})"

    def _ruleset(self, entering: Rule, match: _Match, ruleset: Row, where: str) -> List[Rule]:
        label = self._text(ruleset, "FRIENDLY_NAME") or "rule set"
        state = (self._text(ruleset, "SET_ACTIVE") or "active").lower()
        control = (self._text(ruleset, "CONTROL") or "none").lower()
        control_node = self._field(ruleset, "CONTROL")
        if control_node is not None and control_node.ref:
            control = "a VPN connection"
        timeout = self._text(ruleset, "TIMEOUT") or "0"
        switched = control != "none" or (timeout.isdigit() and int(timeout) > 0)
        if state == "disabled" or (state == "inactive" and not switched):
            entering.enabled = False
            entering.description = (entering.description + " " if entering.description else "") + f"(rule set {label})"
            self.report.add("rule", entering.origin, Severity.INFO, "MGUARD_RULESET",
                            f"enters rule set {label}, which is {state} and has no influence: read as a disabled rule")  # fmt: skip
            return [entering]
        out: List[Rule] = []
        rows = self._table("SET", ruleset)
        for index, row in enumerate(rows):
            inner = self._match(row, f"{where}, rule set {label} rule {index + 1}")
            rule = Rule(self._unique(f"{entering.name}.{label}-{index + 1}"), src_zones=list(entering.src_zones),
                        dst_zones=list(entering.dst_zones))  # fmt: skip
            rule.origin = rule.name
            rule.description = self._text(row, "COMMENT") or ""
            rule.log_end = (self._text(row, "LOG") or "no").lower() == "yes"
            rule.unsupported += entering.unsupported + inner.problems
            protos = {match.proto, inner.proto} - {"all"}
            if len(protos) > 1:
                self.report.skip("rule", rule.origin, "MGUARD_RULESET",
                                 f"rule {index + 1} of rule set {label} is for {inner.proto}, the rule that enters the set for "
                                 f"{match.proto}: it matches nothing", Severity.INFO)  # fmt: skip
                self.names.discard(rule.name.lower())
                continue
            proto = protos.pop() if protos else "all"
            source, why_s = self._meet(match.source, inner.source)
            destination, why_d = self._meet(match.destination, inner.destination)
            rule.unsupported += [w for w in (why_s, why_d) if w]
            rule.sources, rule.destinations = [source or ANY_V4], [destination or ANY_V4]
            ports: List[_Port] = []
            for outer_port, inner_port in ((match.src_port, inner.src_port), (match.dst_port, inner.dst_port)):
                if proto not in ("tcp", "udp") or not outer_port.ports:
                    ports.append(inner_port if proto in ("tcp", "udp") else _Port())
                elif not inner_port.ports or inner_port.ports == outer_port.ports:
                    ports.append(outer_port)
                else:
                    rule.unsupported.append("the rule that enters the set and the rule of the set both narrow the ports")
                    ports.append(outer_port)
            rule.services = [self._service(proto, ports[0], ports[1])]
            for member in rule.sources + rule.destinations:
                if member in self.bad_ip_groups:
                    rule.unsupported.append(f"IP group {member}: {self.bad_ip_groups[member]}")
            target = self._field(row, "TARGET_REF")
            action = (target.text or "").strip().upper() if target is not None and target.text is not None else ""
            if action in ("ACCEPT", "DROP", "REJECT"):
                rule.action = {"ACCEPT": Action.ALLOW, "DROP": Action.DROP, "REJECT": Action.RESET_BOTH}[action]
            else:
                rule.action = Action.DROP
                rule.unsupported.append("the action of a rule of a rule set is not Accept, Drop or Reject")
            if switched:
                how = control if control != "none" else f"a timeout of {timeout} s"
                rule.unsupported.append(f"rule set {label} is switched on and off ({how}); its rules apply only while it is active")
                self.report.add("rule", rule.origin, Severity.REVIEW, "MGUARD_RULESET_SWITCHED",
                                f"a rule of rule set {label}, which {how} switches on and off: not converted")  # fmt: skip
            else:
                self.report.add("rule", rule.origin, Severity.INFO, "MGUARD_RULESET",
                                f"rule {index + 1} of rule set {label}, which {entering.name} enters: in its place, limited to what "
                                "that rule matches")  # fmt: skip
            out.append(rule)
        if not out:
            self.report.skip("rule", entering.origin, "MGUARD_RULESET",
                             f"enters rule set {label}, which has no rules: nothing is decided there", Severity.INFO)
        else:
            self.names.discard(entering.name.lower())
        return out

    # -- NAT -----------------------------------------------------------------------------------------------------

    def _extern(self) -> str:
        """The address object of %extern: the first external address, where the profile holds it."""
        if self.extern_address:
            return self.extern_address
        name = self._unique("mguard-extern")
        ip = self._value("MY_ROUTER_IP")
        mode = self._value("ROUTER_MODE").lower() or "static"
        if mode == "static" and self._literal(ip):
            self.p.addresses[name] = Address(name, AddressKind.NETWORK, self._literal(ip), "the external address of the mGuard",
                                             raw=EXTERN, builtin="mguard")  # fmt: skip
        else:
            why = f"ROUTER_MODE {mode[:12]}" if mode != "static" else "MY_ROUTER_IP is not an address"
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", "the external address of the mGuard",
                                             raw=f"{EXTERN} (the external address; {why}: the profile does not hold it)", builtin="mguard")  # fmt: skip
        self.extern_address = name
        return name

    def _zone_of(self, address: str) -> List[str]:
        """The zone a forwarded connection goes to: dmz where the DMZ's networks hold the address, else internal."""
        found = parse_literal(address)
        if found is not None and DMZ in self.p.zones:
            for row in self._table("DMZ_ALIASES") + self._table("DMZ_ROUTES"):
                ip, mask, net = self._text(row, "DMZ_IP"), self._text(row, "DMZ_NET"), self._text(row, "NETWORK")
                text = net or (f"{ip}/{mask_length(mask)}" if ip and mask and mask_length(mask) is not None else "")
                span = parse_literal(text) if text else None
                if span is not None and span[0] == 4 and span[1] <= found[1] <= span[2]:
                    return [DMZ]
        return [INTERNAL]

    def _nat(self) -> List[Rule]:
        forwards: List[Rule] = []
        for index, row in enumerate(self._table("FW_PORTFORWARDING")):
            name = self._unique(f"portforward-{index + 1}")
            problems: List[str] = []
            proto = (self._text(row, "PROTO") or "").lower()
            if proto not in ("tcp", "udp", "gre"):
                problems.append(f"protocol {proto[:20]!r} (port forwarding takes tcp, udp and gre)")
                proto = "tcp"
            source = self._address(row, "SRC_IP", name, problems) or ANY_V4
            src_port = self._port(row, "SRC_PORT") if proto != "gre" else _Port()
            in_ip = self._text(row, "IN_IP") or ""
            if in_ip == EXTERN:
                destination = self._extern()
            else:
                destination = self._literal(in_ip)
                if not destination or "/" in destination:
                    problems.append(f"IN_IP {in_ip[:30]!r} is not an address or %extern")
                    destination = "0.0.0.0/32"
            out_ip = self._literal(self._text(row, "OUT_IP") or "")
            if not out_ip or "/" in out_ip:
                problems.append("OUT_IP is not an address")
                out_ip = "0.0.0.0"
            in_port = _Port()
            out_port = ""
            if proto != "gre":
                in_port = self._port(row, "IN_PORT")
                target = self._port_text(self._text(row, "OUT_PORT") or "")
                if not in_port.ports or "-" in in_port.ports or "," in in_port.ports:
                    problems.append("IN_PORT is not one port")
                if target is None or "-" in target:
                    problems.append("OUT_PORT is not one port")
                elif target != in_port.ports:
                    out_port = target
                problems += [p.problem for p in (src_port, in_port) if p.problem]
            service = self._service(proto, src_port, in_port)
            dst_zones = self._zone_of(out_ip)
            nat = NatRule(name, src_zones=list(self.externals), dst_zones=list(dst_zones), sources=[source], destinations=[destination],
                          service=service, destination_translation=DestNat(out_ip, out_port), origin=name, combines=True,
                          description=self._text(row, "COMMENT") or "")  # fmt: skip
            nat.unsupported += problems
            self.p.nat_rules.append(nat)
            rule = Rule(name, src_zones=list(self.externals), dst_zones=list(dst_zones), sources=[source], destinations=[destination],
                        services=[service], origin=name, tags=[FORWARD_TAG],
                        description=f"port forwarding {name}: it skips the packet filter")  # fmt: skip
            rule.log_end = (self._text(row, "LOG") or "no").lower() == "yes"
            rule.unsupported += problems
            self.report.add("rule", name, Severity.INFO, "MGUARD_PORT_FORWARDING",
                            "port forwarding is done before the packet filter and skips it: an allow rule at the top for what it "
                            "forwards")  # fmt: skip
            forwards.append(rule)
        for index, row in enumerate(self._table("FW_1TO1_NAT")):
            name = self._unique(f"1to1-{index + 1}")
            problems = []
            mask_text = self._text(row, "MASK") or ""
            mask = int(mask_text) if mask_text.isdigit() and int(mask_text) <= 32 else None
            local, remote = self._text(row, "LOCAL_NET") or "", self._text(row, "REMOTE_NET") or ""
            nets: List[str] = []
            for value in (local, remote):
                try:
                    if mask is None:
                        raise ValueError
                    nets.append(str(ipaddress.IPv4Network(f"{value}/{mask}", strict=False)))
                except ValueError:
                    problems.append(f"{value[:30]!r}/{mask_text[:4]} is not an IPv4 network")
                    nets.append("0.0.0.0/32")
            nat = NatRule(name, src_zones=[INTERNAL], dst_zones=list(self.externals), sources=[nets[0]],
                          source_translation=SourceNat(SnatKind.STATIC, [nets[1]], bidirectional=True), origin=name, combines=True,
                          description=self._text(row, "COMMENT") or "")  # fmt: skip
            nat.unsupported += problems
            if (self._text(row, "ENABLE_ARP") or "yes").lower() == "no":
                self._say("MGUARD_1TO1_ARP", name)
            self.p.nat_rules.append(nat)
        for index, row in enumerate(self._table("FW_NAT")):
            name = self._unique(f"masquerade-{index + 1}")
            problems = []
            ext_if = (self._text(row, "EXT_IF") or "").lower()
            zones = {"ext1": [EXTERNAL], "ext2": [EXTERNAL2], "dmz0": [DMZ], "int": [INTERNAL], "all": list(self.externals)}.get(ext_if)
            if zones is None:
                problems.append(f"EXT_IF {ext_if[:20]!r} is not known")
                zones = [EXTERNAL]
            source = self._address(row, "IN_IP", name, problems) or ANY_V4
            interface = INTERFACE_OF[zones[0]] if len(zones) == 1 else ""
            address = self._literal(self._value("MY_ROUTER_IP")) if interface == "ext1" and (self._value("ROUTER_MODE") or "static") == "static" else ""
            nat = NatRule(name, src_zones=[ANY], dst_zones=zones, sources=[source],
                          source_translation=SourceNat(SnatKind.INTERFACE, interface=interface, interface_address=address), origin=name,
                          combines=True, description=self._text(row, "COMMENT") or "")  # fmt: skip
            nat.unsupported += problems
            self.p.nat_rules.append(nat)
        for nat in self.p.nat_rules:
            for member in nat.sources:
                if member in self.bad_ip_groups:
                    nat.unsupported.append(f"IP group {member}: {self.bad_ip_groups[member]}")
            if nat.unsupported:
                self.report.add("nat", nat.origin, Severity.REVIEW, "MGUARD_UNREAD", "not converted: " + "; ".join(nat.unsupported)[:300])
        return forwards

    # -- networks ------------------------------------------------------------------------------------------------

    def _zone_networks(self) -> None:
        routes: List[zonenets.Route] = []

        def connected(ip: Optional[str], mask: Optional[str], interface: str) -> None:
            length = mask_length(mask or "")
            if ip and length is not None:
                found = parse_literal(f"{ip}/{length}")
                if found is not None and found[0] == 4:
                    routes.append(zonenets.Route(found, interface, connected=True))

        def routed(rows: List[Row], interface: str) -> None:
            for row in rows:
                found = parse_literal(self._text(row, "NETWORK") or "")
                gateway = parse_literal(self._text(row, "GATEWAY") or "")
                if found is not None and found[0] == 4:
                    routes.append(zonenets.Route(found, interface if gateway is None else "", gateway))

        connected(self._value("MY_LOCAL_IP"), self._value("MY_LOCAL_NET"), "int")
        for row in self._table("LOCAL_ALIASES"):
            connected(self._text(row, "LOCAL_IP"), self._text(row, "LOCAL_NET"), "int")
        static = (self._value("ROUTER_MODE") or "static").lower() == "static"
        if static:
            connected(self._value("MY_ROUTER_IP"), self._value("MY_ROUTER_NET"), "ext1")
            for row in self._table("EXTERN_ALIASES"):
                connected(self._text(row, "EXTERN_IP"), self._text(row, "EXTERN_NET"), "ext1")
        for row in self._table("DMZ_ALIASES"):
            connected(self._text(row, "DMZ_IP"), self._text(row, "DMZ_NET"), "dmz0")
        routed(self._table("LOCAL_ROUTES"), "int")
        routed(self._table("EXTERN_ROUTES"), "ext1")
        routed(self._table("DMZ_ROUTES"), "dmz0")
        gateway = parse_literal(self._value("DEFAULT_GW"))
        if gateway is not None and static:
            routes.append(zonenets.Route((4, 0, 2**32 - 1), "", gateway))
        elif not static:
            routes.append(zonenets.Route((4, 0, 2**32 - 1), "ext1"))  # (the default route by the external interface, DHCP)
        if not routes:
            return
        zone_of = {INTERFACE_OF[zone]: zone for zone in self.p.zones}
        placed = zonenets.place(routes, zone_of, self.report)
        self.p.zone_networks, self.p.unzoned_networks = placed.zones, placed.unzoned

    # -- notes ---------------------------------------------------------------------------------------------------

    def _notes(self) -> None:
        version = self.pragmas.get("version", "")
        tables = [t for t, _, _, _ in TABLES if self._table(t)]
        self.report.note(Severity.INFO, "MGUARD_SOURCE",
                         f"mGuard profile {version[:30] or '(no version line)'}, {'router' if self.router else 'stealth'} mode; zones "
                         f"{', '.join(self.p.zones)}; tables read: {', '.join(tables) or 'none'}. Each table is first match; what no "
                         "rule matches is dropped; port forwarding skips the packet filter")  # fmt: skip
        if self.internal_routed:
            self.report.note(Severity.INFO, "MGUARD_INTERNAL_ROUTED",
                             "the internal side has more than one network (LOCAL_ALIASES): the outgoing rules also decide connections from "
                             "one of them to another, so they are read for internal -> internal as well")  # fmt: skip
        self.report.note(Severity.INFO, "MGUARD_IPV4_ONLY",
                         "the packet filter of the mGuard is IPv4: 0.0.0.0/0 is read as every IPv4 address, and the rules match no IPv6")
        defaults = [name for name in ("LOG_DEFAULT_INCOMING", "LOG_DEFAULT_OUTGOING", "LOG_DEFAULT_INCOMING_WAN_DMZ", "LOG_DEFAULT_INCOMING_DMZ_LAN",
                                      "LOG_DEFAULT_OUTGOING_DMZ_WAN", "LOG_DEFAULT_OUTGOING_LAN_DMZ") if self._value(name).lower() == "yes"]  # fmt: skip
        if defaults:
            self.report.note(Severity.INFO, "MGUARD_DEFAULT_LOG",
                             "connection attempts no rule covers are logged (" + ", ".join(defaults) + "); the model has no place for that")
        if self._value("USERFW_ENABLE").lower() == "yes" or self._table("USERFW_TEMPLATE"):
            templates = [self._text(row, "TEMPLATE_NAME") or f"template {i + 1}" for i, row in enumerate(self._table("USERFW_TEMPLATE"))]
            self.report.note(Severity.REVIEW, "MGUARD_USER_FIREWALL",
                             "the user firewall is " + ("on" if self._value("USERFW_ENABLE").lower() == "yes" else "off")
                             + f", with {len(templates)} templates ({', '.join(t[:30] for t in templates[:6])}): rules that apply to users "
                             "who log in; not converted. With it on, the mGuard lets through more than the converted policy")  # fmt: skip
        vpn = [row for row in self._table("VPN_CONNECTION") + self._table("OPENVPN_CONNECTION")
               if self._table("FW_INCOMING", row) or self._table("FW_OUTGOING", row)]  # fmt: skip
        if vpn:
            self.report.note(Severity.REVIEW, "MGUARD_VPN_FIREWALL",
                             f"{len(vpn)} VPN connections have firewall rules of their own (FW_INCOMING, FW_OUTGOING of the connection): "
                             "not converted, nor the VPN traffic they decide")  # fmt: skip
        access = []
        for table in _MANAGEMENT:
            rows = self._table(table)
            if rows:
                access.append(f"{table} ({len(rows)} rows)")
        for name in ("HTTPS_REMOTE_ENABLE", "SSH_REMOTE_ENABLE", "SNMP_ENABLE_V1"):
            if self._value(name).lower() == "yes":
                access.append(f"{name} yes")
        icmp = [f"{n} {self._value(n)}" for n in ("FW_ICMP", "FW_ICMP_EXT2", "FW_ICMP_DMZ0") if self._value(n)]
        if access or icmp:
            self.report.note(Severity.INFO, "MGUARD_MANAGEMENT_ACCESS",
                             "access to the mGuard itself is not converted (it protects the device, not forwarded traffic): "
                             + "; ".join(access + icmp))  # fmt: skip
        mac = [name for name, node in self.vars.items() if "MAC" in name and name.startswith(("FW_", "MAC_")) and node.rows]
        if mac:
            self.report.note(Severity.INFO, "MGUARD_MAC_FILTER", "the MAC filter (stealth mode, stateless) is not converted: " + ", ".join(mac[:6]))
        texts = {
            "MGUARD_MODE": (Severity.INFO, "network mode"),
            "MGUARD_HOSTNAME": (Severity.INFO, "host names in IP groups, resolved by the DNS settings of the mGuard; read as names resolved "
                                "for IPv4"),
            "MGUARD_PORTS_IGNORED": (Severity.INFO, "ports in rules for a protocol other than tcp and udp, which the mGuard ignores"),
            "MGUARD_REJECT": (Severity.INFO, "Reject: the mGuard sends the packets back and tells the sender; read as reset-both"),
            "MGUARD_UNREAD": (Severity.REVIEW, "values that were not understood"),
            "MGUARD_1TO1_ARP": (Severity.INFO, "1:1 NAT without ARP answers for the virtual addresses: read as translating"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report) -> Policy:
    if len(data) > _MAX_BYTES:
        raise ParseError("the profile is larger than 64 MB; not a configuration profile of an mGuard")
    text = data.decode("utf-8-sig", errors="replace")
    try:
        pragmas, variables = read_profile(text)
        return _Builder(pragmas, variables, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the profile could not be read ({type(error).__name__}: {str(error)[:120]})") from None
