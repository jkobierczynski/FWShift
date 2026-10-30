# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""F5 BIG-IP AFM both ways.

``Device`` decides packets as a BIG-IP with AFM does, as F5's documentation describes it: the global context, the route
domain context, then the context of the virtual server the packet is for (picked by the longest destination mask, then a
port before any port); ``accept`` hands the packet on to the next context, ``accept-decisively`` lets it through, ``drop``
and ``reject`` end it; after the virtual server its default action (ADC or Firewall mode) decides; a packet for no
virtual server is dropped; ICMP rules in the virtual server context are ignored. ``read_tmsh`` reads a tmsh file into a
``Device`` strictly (every list a rule names defined before it, names given once, only the keywords of the tmsh
reference); it shares no code with the parser. Both are written from the same reading of F5's documentation as the code
they check: they find where the code disagrees with that reading, not where the reading is wrong.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.emitters import f5afm as emit_f5afm
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import Action, Address, AddressKind, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import f5afm as parse_f5afm
from fwshift.report import Report, Severity

VLANS = ["eth0", "eth1", "eth2"]
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "sctp": 132, "gre": 47}
PKT_PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
Ranges = List[Tuple[int, int]]


# -- the device -----------------------------------------------------------------------------------------------------------


@dataclass
class JRule:
    name: str
    action: str = "accept"
    enabled: bool = True
    proto: Optional[int] = None
    src: Optional[List[str]] = None  # literals and /Common/ names of address lists; None: every address
    dst: Optional[List[str]] = None
    sports: Optional[Ranges] = None
    dports: Optional[Ranges] = None
    dport_lists: List[str] = field(default_factory=list)
    vlans: Optional[List[str]] = None
    icmp: Optional[List[Tuple[int, Optional[int]]]] = None
    rule_list: str = ""


@dataclass
class JVirtual:
    name: str
    network: str
    port: Optional[int] = None
    proto: Optional[int] = None
    vlans: Optional[List[str]] = None  # None: every VLAN
    disabled_on: bool = False  # vlans-disabled
    passing: bool = True
    disabled: bool = False
    policy: str = ""


@dataclass
class Device:
    lists: Dict[str, Tuple[List[str], List[str]]] = field(default_factory=dict)
    port_lists: Dict[str, Tuple[Ranges, List[str]]] = field(default_factory=dict)
    rule_lists: Dict[str, List[JRule]] = field(default_factory=dict)
    policies: Dict[str, List[JRule]] = field(default_factory=dict)
    global_policy: str = ""
    rd_policy: str = ""
    virtuals: Optional[List[JVirtual]] = None  # None: one that takes everything
    mode: str = "accept"

    # -- deciding --

    def _in_list(self, name: str, address: str, depth: int = 0) -> bool:
        assert depth < 10
        literals, nested = self.lists[name]
        return any(_in(address, literal) for literal in literals) or any(self._in_list(n, address, depth + 1) for n in nested)

    def _side(self, members: Optional[List[str]], address: str) -> bool:
        if members is None:
            return True
        return any(self._in_list(m, address) if m.startswith("/") else _in(address, m) for m in members)

    def _ports(self, name: str, depth: int = 0) -> Ranges:
        assert depth < 10
        ranges, nested = self.port_lists[name]
        return list(ranges) + [r for n in nested for r in self._ports(n, depth + 1)]

    def _rule_matches(self, rule: JRule, pkt: Packet, vs_context: bool) -> bool:
        number = PKT_PROTO.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        if vs_context and rule.proto in (1, 58):
            return False  # ignored by the BIG-IP in the virtual server context
        if rule.vlans is not None and pkt.in_if not in rule.vlans:
            return False
        if rule.proto is not None and rule.proto != number:
            return False
        if not self._side(rule.src, pkt.src) or not self._side(rule.dst, pkt.dst):
            return False
        if rule.dports is not None or rule.dport_lists:
            ranges = list(rule.dports or []) + [r for n in rule.dport_lists for r in self._ports(n)]
            if not any(low <= pkt.dport <= high for low, high in ranges):
                return False
        if rule.sports is not None and not any(low <= pkt.sport <= high for low, high in rule.sports):
            return False
        if rule.icmp is not None and not any(kind == pkt.icmp_type for kind, _ in rule.icmp):
            return False  # (the packets carry no ICMP code, nor does the model compare one)
        return True

    def _first(self, policy: str, pkt: Packet, vs_context: bool) -> Optional[str]:
        for rule in self.policies[policy]:
            rules = self.rule_lists[rule.rule_list] if rule.rule_list else [rule]
            if rule.rule_list and not rule.enabled:
                continue
            for each in rules:
                if each.enabled and self._rule_matches(each, pkt, vs_context):
                    return each.action
        return None

    def listener(self, pkt: Packet) -> Optional[JVirtual]:
        if self.virtuals is None:
            return JVirtual("everything", "0.0.0.0/0")
        number = PKT_PROTO.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        candidates = []
        for virtual in self.virtuals:
            net = ipaddress.ip_network(virtual.network)
            address = ipaddress.ip_address(pkt.dst)
            if address.version != net.version or address not in net:
                continue
            if virtual.proto is not None and virtual.proto != number:
                continue
            if virtual.port is not None and (number not in (6, 17, 132) or pkt.dport != virtual.port):
                continue
            if virtual.vlans is not None and (pkt.in_if in virtual.vlans) == virtual.disabled_on:
                continue
            candidates.append((-net.prefixlen, 0 if virtual.port is not None else 1, 0 if virtual.proto is not None else 1, virtual))
        if not candidates:
            return None
        candidates.sort(key=lambda c: c[:3])
        if len(candidates) > 1:
            assert candidates[0][:3] != candidates[1][:3], "the generator made two virtual servers the BIG-IP cannot tell apart"
        return candidates[0][3]

    def allows(self, pkt: Packet) -> bool:
        listener = self.listener(pkt)
        passing = listener is not None and listener.passing and not listener.disabled
        for policy in (self.global_policy, self.rd_policy):
            if not policy:
                continue
            action = self._first(policy, pkt, False)
            if action == "accept-decisively":
                return passing
            if action in ("drop", "reject"):
                return False
        if not passing:
            return False
        assert listener is not None
        action = self._first(listener.policy, pkt, True) if listener.policy else None
        if action is not None:
            return action in ("accept", "accept-decisively")
        return self.mode == "accept"

    # -- writing it as tmsh prints it --

    def render(self) -> str:
        out = [f"sys db tm.fw.defaultaction {{\n    value \"{self.mode}\"\n}}"]
        out += [f"net vlan /Common/{v} {{\n    tag {4000 + i}\n}}" for i, v in enumerate(VLANS)]
        for name, (literals, nested) in self.lists.items():
            body = ""
            if literals:
                body += "    addresses {\n" + "".join(f"        {a} {{ }}\n" for a in literals) + "    }\n"
            if nested:
                body += "    address-lists {\n" + "".join(f"        {n}\n" for n in nested) + "    }\n"
            out.append(f"security firewall address-list {name} {{\n{body}}}")
        for name, (ranges, nested) in self.port_lists.items():
            body = ""
            if ranges:
                body += "    ports {\n" + "".join(f"        {_range(r)} {{ }}\n" for r in ranges) + "    }\n"
            if nested:
                body += "    port-lists {\n" + "".join(f"        {n}\n" for n in nested) + "    }\n"
            out.append(f"security firewall port-list {name} {{\n{body}}}")
        for name, rules in self.rule_lists.items():
            out.append(f"security firewall rule-list {name} {{\n    rules {{\n" + "".join(_rule_text(r) for r in rules) + "    }\n}")
        for name, rules in self.policies.items():
            out.append(f"security firewall policy {name} {{\n    rules {{\n" + "".join(_rule_text(r) for r in rules) + "    }\n}")
        if self.global_policy:
            out.append(f"security firewall global-rules {{\n    enforced-policy {self.global_policy}\n}}")
        rd = f"    fw-enforced-policy {self.rd_policy}\n" if self.rd_policy else ""
        out.append(f"net route-domain /Common/0 {{\n{rd}    id 0\n    vlans {{\n" + "".join(f"        /Common/{v}\n" for v in VLANS) + "    }\n}")
        for virtual in self.virtuals or []:
            net = ipaddress.ip_network(virtual.network)
            port = "any" if virtual.port is None else str(virtual.port)
            destination = f"{net.network_address}{':' if net.version == 4 else '.'}{port}"
            mask = ("any" if net.version == 4 else "any6") if net.prefixlen == 0 else str(net.netmask)
            lines = [f"ltm virtual /Common/{virtual.name} {{", f"    destination /Common/{destination}"]
            if virtual.disabled:
                lines.append("    disabled")
            if virtual.policy:
                lines.append(f"    fw-enforced-policy {virtual.policy}")
            if virtual.proto is not None:
                lines.append(f"    ip-protocol {next(k for k, v in PROTO.items() if v == virtual.proto)}")
            lines.append(f"    mask {mask}")
            if not virtual.passing:
                lines.append("    reject")
            lines.append(f"    source {'0.0.0.0/0' if net.version == 4 else '::/0'}")
            if virtual.vlans is not None:
                lines += ["    vlans {"] + [f"        /Common/{v}" for v in virtual.vlans] + ["    }"]
                lines.append("    vlans-disabled" if virtual.disabled_on else "    vlans-enabled")
            lines.append("}")
            out.append("\n".join(lines))
        return "\n".join(out) + "\n"


def _in(address: str, literal: str) -> bool:
    probe = ipaddress.ip_address(address)
    if "-" in literal:
        first, last = (ipaddress.ip_address(x) for x in literal.split("-"))
        return probe.version == first.version and first <= probe <= last  # type: ignore[operator]
    net = ipaddress.ip_network(literal, strict=False)
    return probe.version == net.version and probe in net


def _range(r: Tuple[int, int]) -> str:
    return str(r[0]) if r[0] == r[1] else f"{r[0]}-{r[1]}"


def _rule_text(rule: JRule) -> str:
    lines = [f"        {rule.name} {{"]
    if rule.rule_list:
        lines.append(f"            rule-list {rule.rule_list}")
    else:
        lines.append(f"            action {rule.action}")
        if rule.icmp is not None:
            lines += ["            icmp {"] + [f"                {k}{'' if c is None else f':{c}'} {{ }}" for k, c in rule.icmp] + ["            }"]
        if rule.proto is not None:
            lines.append(f"            ip-protocol {next(k for k, v in PROTO.items() if v == rule.proto)}")
        source: List[str] = []
        if rule.src is not None:
            lists = [m for m in rule.src if m.startswith("/")]
            literals = [m for m in rule.src if not m.startswith("/")]
            if lists:
                source += ["                address-lists {"] + [f"                    {m}" for m in lists] + ["                }"]
            if literals:
                source += ["                addresses {"] + [f"                    {m} {{ }}" for m in literals] + ["                }"]
        if rule.sports is not None:
            source += ["                ports {"] + [f"                    {_range(r)} {{ }}" for r in rule.sports] + ["                }"]
        if rule.vlans is not None:
            source += ["                vlans {"] + [f"                    /Common/{v}" for v in rule.vlans] + ["                }"]
        if source:
            lines += ["            source {"] + source + ["            }"]
        dest: List[str] = []
        if rule.dst is not None:
            lists = [m for m in rule.dst if m.startswith("/")]
            literals = [m for m in rule.dst if not m.startswith("/")]
            if lists:
                dest += ["                address-lists {"] + [f"                    {m}" for m in lists] + ["                }"]
            if literals:
                dest += ["                addresses {"] + [f"                    {m} {{ }}" for m in literals] + ["                }"]
        if rule.dport_lists:
            dest += ["                port-lists {"] + [f"                    {m}" for m in rule.dport_lists] + ["                }"]
        if rule.dports is not None:
            dest += ["                ports {"] + [f"                    {_range(r)} {{ }}" for r in rule.dports] + ["                }"]
        if dest:
            lines += ["            destination {"] + dest + ["            }"]
    if not rule.enabled:
        lines.append("            status disabled")
    lines.append("        }")
    return "\n".join(lines) + "\n"


# -- a strict reader of what the emitter writes ----------------------------------------------------------------------------

_NAME = re.compile(r"/Common/[A-Za-z][A-Za-z0-9_.-]{0,127}")
_TOKENS = re.compile(r'"(?:[^"\\]|\\.)*"|[{}]|\n|[^\s{}"]+')
Node = Union[str, List["Node"]]


def _parse_tree(text: str) -> List[List[Node]]:
    """Statements of words and blocks, one per line, as tmsh writes a configuration file."""
    tokens = [t for t in _TOKENS.findall("\n".join(line for line in text.split("\n") if not line.startswith("#")))]

    def block(position: int) -> Tuple[List[List[Node]], int]:
        statements: List[List[Node]] = []
        current: List[Node] = []
        while position < len(tokens):
            token = tokens[position]
            if token == "\n":
                if current:
                    statements.append(current)
                current = []
            elif token == "{":
                inner, position = block(position + 1)
                current.append(inner)  # type: ignore[arg-type]
            elif token == "}":
                if current:
                    statements.append(current)
                return statements, position
            else:
                current.append(token)
            position += 1
        if current:
            statements.append(current)
        return statements, position

    tree, end = block(0)
    assert end >= len(tokens), "a closing brace too many"
    return tree


def _set(node: List[List[Node]]) -> List[str]:
    """The members of a set: one per line, each a word, optionally with an empty block."""
    out: List[str] = []
    for statement in node:
        assert isinstance(statement[0], str), statement
        assert len(statement) == 1 or (len(statement) == 2 and statement[1] == []), f"a member with properties: {statement}"
        assert statement[0] not in out, f"{statement[0]} given twice"
        out.append(statement[0])
    assert out, "an empty set"
    return out


def _props_of(node: List[List[Node]], allowed: set) -> Dict[str, List[Node]]:
    out: Dict[str, List[Node]] = {}
    for statement in node:
        key = statement[0]
        assert isinstance(key, str) and key in allowed, f"the keyword {key!r} is not one of {sorted(allowed)}"
        assert key not in out, f"{key} given twice"
        out[key] = statement[1:]
    return out


def _ranges_of(members: List[str]) -> Ranges:
    out: Ranges = []
    for member in members:
        low, _, high = member.partition("-")
        assert low.isdigit() and (not high or high.isdigit()), member
        out.append((int(low), int(high or low)))
        assert 0 <= out[-1][0] <= out[-1][1] <= 65535
    return out


def read_tmsh(text: str) -> Device:
    """What the emitter wrote, read as a merge would take it; every reference to something defined above it."""
    device = Device()
    for statement in _parse_tree(text):
        words = [w for w in statement if isinstance(w, str)]
        body = statement[-1]
        assert isinstance(body, list), statement
        kind, name = " ".join(words[:3]), words[3] if len(words) > 3 else ""
        assert len(words) == 4 and _NAME.fullmatch(name), f"not a stanza the emitter writes: {words}"
        if kind == "security firewall address-list":
            props = _props_of(body, {"addresses", "address-lists", "fqdns", "description"})
            assert name not in device.lists
            literals = _set(props["addresses"][0]) if "addresses" in props else []  # type: ignore[arg-type]
            for literal in literals:
                assert "%" not in literal
                ipaddress.ip_network(literal, strict=False) if "-" not in literal else None
            nested = _set(props["address-lists"][0]) if "address-lists" in props else []  # type: ignore[arg-type]
            for member in nested:
                assert member in device.lists, f"address list {member} used before it is defined"
            fqdns = _set(props["fqdns"][0]) if "fqdns" in props else []  # type: ignore[arg-type]
            assert literals or nested or fqdns, f"{name} is empty"
            device.lists[name] = (literals, nested)
        elif kind == "security firewall port-list":
            props = _props_of(body, {"ports", "port-lists", "description"})
            assert name not in device.port_lists
            ranges = _ranges_of(_set(props["ports"][0])) if "ports" in props else []  # type: ignore[arg-type]
            assert ranges
            device.port_lists[name] = (ranges, [])
        elif kind in ("security firewall rule-list", "security firewall policy"):
            target = device.rule_lists if kind.endswith("rule-list") else device.policies
            assert name not in device.rule_lists and name not in device.policies
            props = _props_of(body, {"rules", "description"})
            rules: List[JRule] = []
            names: set = set()
            for rule_statement in props["rules"][0]:  # type: ignore[union-attr]
                rule_name, rule_body = rule_statement[0], rule_statement[1]
                assert isinstance(rule_name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", rule_name), rule_name
                assert rule_name not in names, f"rule {rule_name} given twice"
                names.add(rule_name)
                rules.append(_read_rule(device, rule_name, rule_body, kind.endswith("policy")))  # type: ignore[arg-type]
            target[name] = rules
        else:
            raise AssertionError(f"not a stanza the emitter writes: {kind}")
    return device


def _read_rule(device: Device, name: str, body: List[List[Node]], in_policy: bool) -> JRule:
    props = _props_of(body, {"action", "ip-protocol", "icmp", "source", "destination", "status", "description", "log", "rule-list"})
    rule = JRule(name)
    if "rule-list" in props:
        assert in_policy and set(props) <= {"rule-list", "status"}
        reference = props["rule-list"][0]
        assert isinstance(reference, str) and reference in device.rule_lists, f"rule list {reference} used before it is defined"
        rule.rule_list = reference
        return rule
    action = props["action"][0]
    assert action in ("accept", "accept-decisively", "drop", "reject"), action
    rule.action = str(action)
    if "status" in props:
        assert props["status"] == ["disabled"]
        rule.enabled = False
    if "log" in props:
        assert props["log"] == ["yes"]
    if "ip-protocol" in props:
        word = props["ip-protocol"][0]
        assert isinstance(word, str)
        rule.proto = PROTO[word] if word in PROTO else int(word) if word.isdigit() else parse_f5afm.PROTOCOLS[word]
    if "icmp" in props:
        assert rule.proto in (1, 58), "ICMP types without the protocol ICMP"
        entries = []
        for member in _set(props["icmp"][0]):  # type: ignore[arg-type]
            kind, _, code = member.partition(":")
            entries.append((int(kind), int(code) if code else None))
        rule.icmp = entries
    sides = {"source": {"address-lists", "addresses", "ports", "vlans"}, "destination": {"address-lists", "addresses", "ports", "port-lists"}}
    for side, allowed in sides.items():
        if side not in props:
            continue
        side_props = _props_of(props[side][0], allowed)  # type: ignore[arg-type]
        members: List[str] = []
        for member in _set(side_props["address-lists"][0]) if "address-lists" in side_props else []:  # type: ignore[arg-type]
            assert member in device.lists, f"address list {member} used before it is defined"
            members.append(member)
        for literal in _set(side_props["addresses"][0]) if "addresses" in side_props else []:  # type: ignore[arg-type]
            ipaddress.ip_network(literal, strict=False)
            members.append(literal)
        if members:
            if side == "source":
                rule.src = members
            else:
                rule.dst = members
        if "ports" in side_props or "port-lists" in side_props:
            assert rule.proto in (6, 17, 132), "ports of a rule that is not for TCP, UDP or SCTP"
        if "ports" in side_props:
            ranges = _ranges_of(_set(side_props["ports"][0]))  # type: ignore[arg-type]
            if side == "source":
                rule.sports = ranges
            else:
                rule.dports = ranges
        if "port-lists" in side_props:
            lists = _set(side_props["port-lists"][0])  # type: ignore[arg-type]
            assert all(member in device.port_lists for member in lists), "a port list used before it is defined"
            rule.dport_lists = lists
        if "vlans" in side_props:
            vlans = _set(side_props["vlans"][0])  # type: ignore[arg-type]
            assert all(_NAME.fullmatch(v) for v in vlans)
            rule.vlans = [v[len("/Common/"):] for v in vlans]
    return rule


def emitted_device(text: str, mode: str = "drop") -> Device:
    device = read_tmsh(text)
    assert len(device.policies) == 1, "one policy"
    device.global_policy = next(iter(device.policies))
    device.mode = mode
    return device


# -- random devices ---------------------------------------------------------------------------------------------------------

LITERALS = ["10.0.1.0/24", "10.0.2.0/25", "10.0.2.17", "10.0.0.0/16", "10.0.3.0/24", "10.0.0.17", "2001:db8:1::/48",
            "10.0.2.100-10.0.2.200", "10.0.4.0/22"]  # fmt: skip
VIRTUALS = [
    JVirtual("vs_all4", "0.0.0.0/0"), JVirtual("vs_all6", "::/0"), JVirtual("vs_net", "10.0.1.0/24"),
    JVirtual("vs_web", "10.0.2.17/32", 80, 6), JVirtual("vs_dns", "10.0.2.17/32", 53, 17), JVirtual("vs_tcp", "10.0.2.34/32", None, 6),
    JVirtual("vs_port", "10.0.3.0/24", 53), JVirtual("vs_host", "10.0.0.17/32"),
]  # fmt: skip
DESTINATIONS = ["10.0.1.17", "10.0.1.34", "10.0.2.17", "10.0.2.34", "10.0.3.17", "10.0.0.17", "10.0.4.17", "10.0.2.136",
                "2001:db8:1::1", "2001:db8:2::2"]  # fmt: skip


def random_rule(rng: random.Random, name: str, lists: List[str], port_lists: List[str]) -> JRule:
    rule = JRule(name, rng.choice(["accept", "accept", "accept-decisively", "drop", "reject"]))
    rule.proto = rng.choice([None, None, 6, 6, 17, 1, 47])
    pool = LITERALS + lists
    if rng.random() < 0.5:
        rule.src = rng.sample(pool, rng.randint(1, 2))
    if rng.random() < 0.5:
        rule.dst = rng.sample(pool, rng.randint(1, 2))
    if rule.proto in (6, 17):
        if rng.random() < 0.6:
            rule.dports = rng.sample([(53, 53), (80, 80), (443, 443), (8000, 8010), (22, 22)], rng.randint(1, 2))
        if rng.random() < 0.2 and port_lists:
            rule.dport_lists = [rng.choice(port_lists)]
        if rng.random() < 0.15:
            rule.sports = [(1024, 2000)]
    if rule.proto == 1 and rng.random() < 0.6:
        rule.icmp = [(rng.choice([8, 13]), rng.choice([None, 0]))]
    if rng.random() < 0.4:
        rule.vlans = rng.sample(VLANS, rng.randint(1, 2))
    rule.enabled = rng.random() > 0.1
    return rule


def random_device(rng: random.Random) -> Device:
    device = Device(mode=rng.choice(["accept", "drop", "reject"]))
    device.lists["/Common/al_a"] = (rng.sample(LITERALS, 2), [])
    device.lists["/Common/al_b"] = (rng.sample(LITERALS, 1), ["/Common/al_a"])
    device.port_lists["/Common/pl_a"] = ([(80, 80), (8080, 8080)], [])
    device.port_lists["/Common/pl_b"] = ([(53, 53)], ["/Common/pl_a"])
    lists, port_lists = list(device.lists), list(device.port_lists)
    counter = [0]

    def rules(count: int) -> List[JRule]:
        out = []
        for _ in range(count):
            counter[0] += 1
            out.append(random_rule(rng, f"r{counter[0]}", lists, port_lists))
        return out

    device.rule_lists["/Common/rl"] = rules(rng.randint(1, 3))
    device.policies["/Common/global"] = rules(rng.randint(0, 6))
    if rng.random() < 0.4:
        position = rng.randint(0, len(device.policies["/Common/global"]))
        device.policies["/Common/global"].insert(position, JRule("use_list", rule_list="/Common/rl", enabled=rng.random() > 0.15))
    device.global_policy = "/Common/global" if rng.random() < 0.85 else ""
    if rng.random() < 0.6:
        device.policies["/Common/rd"] = rules(rng.randint(1, 4))
        device.rd_policy = "/Common/rd"
    if rng.random() < 0.85:
        device.virtuals = []
        for template in rng.sample(VIRTUALS, rng.randint(1, len(VIRTUALS))):
            virtual = copy.deepcopy(template)
            if rng.random() < 0.3:
                virtual.vlans = rng.sample(VLANS, rng.randint(1, 2))
                virtual.disabled_on = rng.random() < 0.4
            virtual.passing = rng.random() > 0.1
            virtual.disabled = rng.random() < 0.08
            if rng.random() < 0.5:
                name = f"/Common/p_{virtual.name}"
                device.policies[name] = rules(rng.randint(1, 3))
                virtual.policy = name
            device.virtuals.append(virtual)
    return device


def random_device_packet(rng: random.Random) -> Packet:
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47", "sctp"])
    dst = rng.choice(DESTINATIONS)
    src = rng.choice(["2001:db8:1::5", "2001:db8:9::5"] if ":" in dst else ["10.0.1.17", "10.0.2.150", "10.0.0.17", "10.0.3.3", "10.9.0.1"])
    if proto == "icmp" and ":" in dst:
        proto = "icmp6"
    return Packet(rng.choice(VLANS), rng.choice(VLANS), src, dst, proto, rng.choice([1024, 1500, 40000]),
                  rng.choice([22, 53, 80, 443, 8005, 8080, 9000]), rng.choice([0, 8, 13]))  # fmt: skip


@pytest.mark.parametrize("seed", range(60))
def test_parsed_device_decides_like_the_device(seed: int) -> None:
    """Random BIG-IPs: contexts, accept and accept-decisively, rule lists, virtual servers of every kind and the two
    modes. The model read from the tmsh text decides every packet as the device does."""
    rng = random.Random(seed)
    device = random_device(rng)
    text = device.render()
    report = Report()
    model = parse_f5afm.parse(text.encode(), report)
    assert not [r.name for r in model.rules if r.unsupported], text
    for _ in range(300):
        pkt = random_device_packet(rng)
        assert model_allows(model, pkt) == device.allows(pkt), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(40))
def test_emitted_policy_decides_like_the_model(seed: int) -> None:
    """Random models: negations, ranges, nested groups, services of several protocols and with source ports, ICMP, GRE;
    zones as VLANs, destination zones as the networks behind them. Read strictly and attached to the global context of a
    device in either mode, the policy decides every packet as the model does; rules the emitter writes disabled are left
    out of the model's side (the report says so)."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL  # (a rule type is written for its pairs of zones: covered below)
    report = Report()
    text = emit_f5afm.emit(model, report, Options(zone_networks=ZONES_AT))
    device = emitted_device(text, rng.choice(["accept", "drop"]))
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        assert device.allows(pkt) == model_allows(compared, pkt), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(20))
def test_roundtrip_of_random_devices(seed: int) -> None:
    """A random BIG-IP read, written and read again decides every packet as the device does."""
    rng = random.Random(9000 + seed)
    device = random_device(rng)
    model = parse_f5afm.parse(device.render().encode(), Report())
    report = Report()
    text = emit_f5afm.emit(model, report, Options())
    again = emitted_device(text)
    back = parse_f5afm.parse(text.encode(), Report())
    for _ in range(200):
        pkt = random_device_packet(rng)
        assert again.allows(pkt) == device.allows(pkt) == model_allows(back, pkt), (seed, pkt, text)


# -- the sample -------------------------------------------------------------------------------------------------------------


def _rules(model: Policy) -> Dict[str, Rule]:
    return {rule.name: rule for rule in model.rules}


def _codes(report: Report) -> List[str]:
    return [note.code for note in report.notes]


def test_f5afm_sample_reads_the_contexts_in_order() -> None:
    model, report = load("f5afm_sample.conf")
    rules = _rules(model)
    names = list(rules)
    assert model.vendor == "f5-afm" and model.default_interzone == Action.DENY
    assert set(model.zones) == {"external", "internal", "dmz"}
    # The global rules come first, the route domain rules next, then the virtual servers, most specific first.
    assert names[0] == "global/block_bad" and rules["global/block_bad"].action == Action.DROP
    assert names.index("rd0/dmz_no_inside") < names.index("vs_inbound_dmz/(default)") < names.index("vs_outbound/(default)")
    assert names.index("vs_web/web_in") < names.index("vs_outbound/(default)")
    # Firewall mode: what a virtual server takes and no rule decides is dropped there.
    assert rules["vs_web/(default)"].action == Action.DROP and rules["vs_web/(default)"].destinations == ["203.0.113.10/32"]
    assert rules["vs_web/(default)"].services == ["tcp-443"] and rules["vs_web/(default)"].src_zones == ["external"]
    assert "F5AFM_MODE" in _codes(report)


def test_accept_hands_on_to_the_later_contexts() -> None:
    """admins_continue accepts: what it matches skips the rest of the global rules and meets the route domain and the
    virtual servers; in Firewall mode the default of the virtual server still drops it."""
    model, _ = load("f5afm_sample.conf")
    rules = _rules(model)
    assert "global/admins_continue" not in rules
    sub = [name for name in rules if name.startswith("global/admins_continue>")]
    assert "global/admins_continue>rd0/outbound/allow_web_out@vs_outbound" in sub
    assert "global/admins_continue>vs_web/(default)" in sub
    assert all(rules[name].sources == ["admins"] for name in sub)
    assert rules["global/admins_continue>vs_web/(default)"].action == Action.DROP
    # They stand before reject_telnet, which admins therefore never meet.
    names = list(rules)
    assert max(names.index(n) for n in sub) < names.index("global/reject_telnet")


def test_accept_decisively_needs_a_virtual_server() -> None:
    """ping_in lets ICMP through to the web servers, but only a virtual server that takes ICMP gets it there."""
    model, _ = load("f5afm_sample.conf")
    rules = _rules(model)
    pings = [name for name in rules if name.startswith("global/ping_in")]
    assert pings == ["global/ping_in@vs_outbound"]
    assert rules[pings[0]].src_zones == ["dmz", "internal"] and rules[pings[0]].destinations == ["203.0.113.10"]
    assert rules[pings[0]].services == ["icmp-8-0"]
    # To a virtual server of type reject, accept-decisively still lets nothing through.
    assert rules["global/partners_in@vs_web_http"].action == Action.DENY
    assert rules["vs_web_http/(refused)"].action == Action.DENY and rules["vs_old_app/(refused)"].action == Action.DENY


def test_sample_states_schedules_irules_and_lists() -> None:
    model, report = load("f5afm_sample.conf")
    rules = _rules(model)
    assert not rules["global/old_rule"].enabled
    assert rules["global/office_ssh@vs_outbound"].schedule == "office_hours"
    # An iRule may drop what the rule accepts: what is allowed after it is not converted; what is blocked stays.
    irule = [r for n, r in rules.items() if n.startswith("global/inspect_irule>")]
    assert irule and all(not r.unsupported for r in irule if r.action != Action.ALLOW)
    assert rules["rd0/outbound/allow_web_out@vs_outbound"].services == ["web_ports"]
    assert rules["global/partners_in@vs_inbound_dmz"].services == ["mgmt_ports"]
    assert model.services["mgmt_ports"].entries == [ServiceEntry(Protocol.TCP, "22,80,443,8443")]
    assert model.address_groups["inside"].members == ["10.10.0.0/16", "admins"]
    assert model.addresses["partner.example.com"].kind == AddressKind.FQDN
    assert model.addresses["geo:NL"].kind == AddressKind.UNSUPPORTED
    assert model.address_groups["blocklist"].members == ["198.51.100.0/24", "203.0.113.200-203.0.113.220"]
    codes = _codes(report)
    for code in ("F5AFM_STAGED", "F5AFM_SELF_IP", "F5AFM_MANAGEMENT_RULES", "F5AFM_ICMP_IGNORED", "F5AFM_NAT_NOT_READ",
                 "F5AFM_VIRTUAL_REFUSES", "F5AFM_CONTEXTS"):  # fmt: skip
        assert code in codes, code
    assert not any(name.startswith("vs_web/ping_vs") for name in rules)
    assert "test_only" not in " ".join(rules)  # the staged policy


def test_ipv6_virtual_server_and_family() -> None:
    model, _ = load("f5afm_sample.conf")
    rules = _rules(model)
    assert rules["vs_web6/web6_in"].sources == ["2001:db8:ff::/48"]
    assert rules["vs_web6/web6_in"].destinations == ["2001:db8:203::10/128"]
    assert "vs_web/web6_in" not in rules  # an IPv6 source never reaches an IPv4 virtual server


# -- the traps one by one -----------------------------------------------------------------------------------------------------

BASE = """sys db tm.fw.defaultaction {
    value "%s"
}
net vlan /Common/outside {
    tag 10
}
net vlan /Common/inside {
    tag 20
}
"""


def _parse(text: str, mode: str = "accept", **kwargs: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_f5afm.parse(((BASE % mode) + text).encode(), report, **kwargs), report


def _decide(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 80, vlan: str = "outside") -> bool:
    return model_allows(model, Packet(vlan, "inside", src, dst, proto, 40000, dport, 8))


GLOBAL = """security firewall policy /Common/g {
    rules {
%s    }
}
security firewall global-rules {
    enforced-policy /Common/g
}
"""
FORWARD = """ltm virtual /Common/fwd {
    destination /Common/0.0.0.0:any
    ip-forward
    mask any
    source 0.0.0.0/0
}
"""


def _rule(name: str, body: str) -> str:
    return f"        {name} {{\n" + "".join(f"            {line}\n" for line in body.strip().split("\n")) + "        }\n"


def test_firewall_mode_needs_an_allow_where_adc_mode_lets_through() -> None:
    accept = _rule("a", "action accept\nip-protocol tcp")
    for mode, expected in (("accept", True), ("drop", False), ("reject", False)):
        model, _ = _parse(GLOBAL % accept + FORWARD, mode)
        assert _decide(model, "192.0.2.1", "198.51.100.1") is expected, mode
    decisive = _rule("a", "action accept-decisively\nip-protocol tcp")
    model, _ = _parse(GLOBAL % decisive + FORWARD, "drop")
    assert _decide(model, "192.0.2.1", "198.51.100.1") and not _decide(model, "192.0.2.1", "198.51.100.1", "udp")


def test_traffic_for_no_virtual_server_is_dropped() -> None:
    web = """ltm virtual /Common/web {
    destination /Common/198.51.100.10:443
    ip-protocol tcp
    mask 255.255.255.255
    source 0.0.0.0/0
}
"""
    model, _ = _parse(GLOBAL % _rule("a", "action accept-decisively") + web, "accept")
    assert _decide(model, "192.0.2.1", "198.51.100.10", dport=443)
    assert not _decide(model, "192.0.2.1", "198.51.100.10", dport=80)
    assert not _decide(model, "192.0.2.1", "198.51.100.11", dport=443)
    assert model.default_interzone == Action.DENY


def test_without_virtual_servers_every_packet_has_one() -> None:
    model, report = _parse(GLOBAL % _rule("d", "action drop\nip-protocol udp"), "accept")
    assert "F5AFM_NO_VIRTUAL_SERVERS" in _codes(report)
    assert model.default_interzone == Action.ALLOW
    assert _decide(model, "192.0.2.1", "198.51.100.1") and not _decide(model, "192.0.2.1", "198.51.100.1", "udp")
    model, _ = _parse(GLOBAL % _rule("a", "action accept\nip-protocol udp"), "drop")
    assert model.default_interzone == Action.DROP and not _decide(model, "192.0.2.1", "198.51.100.1", "udp")


def test_accept_skips_the_rest_of_its_context_only() -> None:
    rules = _rule("a", "action accept\nsource {\n    addresses {\n        192.0.2.0/24 { }\n    }\n}")
    rules += _rule("b", "action drop\nip-protocol tcp")
    vs_policy = """security firewall policy /Common/v {
    rules {
        no_ssh {
            action drop
            ip-protocol tcp
            destination {
                ports {
                    22 { }
                }
            }
        }
    }
}
"""
    forward = FORWARD.replace("    ip-forward\n", "    fw-enforced-policy /Common/v\n    ip-forward\n")
    model, _ = _parse(GLOBAL % rules + vs_policy + forward, "accept")
    assert _decide(model, "192.0.2.1", "198.51.100.1")  # skips b
    assert not _decide(model, "192.0.2.1", "198.51.100.1", dport=22)  # but not the virtual server's rules
    assert not _decide(model, "203.0.113.1", "198.51.100.1")  # b


def test_an_accept_that_cannot_be_worked_out_taints_the_rules_below_it() -> None:
    rules = _rule("a", "action accept\nsource {\n    geo {\n        NL { }\n    }\n}")
    rules += _rule("b", "action drop\nip-protocol tcp")
    rules += _rule("c", "action drop\nip-protocol udp\nsource {\n    vlans {\n        /Common/inside\n    }\n}")
    model, _ = _parse(GLOBAL % rules + FORWARD, "accept")
    by_name = _rules(model)
    assert any("geo" in text or "accept rule" in text for text in by_name["global/b"].unsupported)
    assert by_name["global/c"].unsupported  # it may overlap: never read as certain


def test_route_domains_keep_rules_to_their_vlans() -> None:
    text = """net route-domain /Common/0 {
    id 0
    vlans {
        /Common/outside
    }
}
net route-domain /Common/rd2 {
    fw-enforced-policy /Common/r
    id 2
    vlans {
        /Common/inside
    }
}
security firewall policy /Common/r {
    rules {
        x {
            action drop
            destination {
                addresses {
                    10.2.0.0%2/16 { }
                }
            }
        }
    }
}
""" + FORWARD
    model, report = _parse(text, "accept")
    rule = _rules(model)["rd2/x"]
    assert rule.src_zones == ["inside"] and rule.destinations == ["10.2.0.0/16"]
    assert "F5AFM_ROUTE_DOMAINS" in _codes(report)
    assert any(f.code == "F5AFM_ROUTE_DOMAIN" for f in report.item("rule", "rd2/x").findings)


def test_virtual_server_order_vlans_and_types() -> None:
    text = """security firewall policy /Common/v {
    rules {
        only_inside {
            action accept
            source {
                vlans {
                    /Common/inside
                }
            }
        }
        icmp_here {
            action accept
            ip-protocol icmp
        }
    }
}
ltm virtual /Common/net {
    destination /Common/198.51.100.0:any
    fw-enforced-policy /Common/v
    ip-forward
    mask 255.255.255.0
    source 0.0.0.0/0
    vlans {
        /Common/inside
    }
    vlans-disabled
}
ltm virtual /Common/host {
    destination /Common/198.51.100.7:https
    ip-protocol tcp
    mask 255.255.255.255
    source 0.0.0.0/0
}
""" + FORWARD
    model, report = _parse(text, "drop")
    names = [r.name for r in model.rules]
    assert names.index("host/(default)") < names.index("net/(default)") < names.index("fwd/(default)")
    net_default = _rules(model)["net/(default)"]
    assert net_default.src_zones == ["outside"]
    assert "net/icmp_here" not in names and "F5AFM_ICMP_IGNORED" in _codes(report)
    # vlans-disabled inside: from inside the network virtual server takes nothing, the forwarding one does.
    assert not _decide(model, "192.0.2.1", "198.51.100.9", vlan="inside")


def test_names_as_tmsh_prints_them_in_a_folder() -> None:
    """From /Common, tmsh prints names without their partition; from /, with it and without the leading slash."""
    text = """security firewall address-list al {
    addresses {
        192.0.2.0/24 { }
    }
}
security firewall policy Common/g {
    rules {
        a {
            action accept-decisively
            source {
                address-lists {
                    al
                }
            }
        }
    }
}
security firewall global-rules {
    enforced-policy g
}
"""
    model, _ = _parse(text, "drop")
    assert _rules(model)["global/a"].sources == ["al"]
    assert parse_f5afm.full_name("app.app/x") == "/Common/app.app/x" and parse_f5afm.full_name("Tenant/x") == "/Tenant/x"
    assert parse_f5afm.model_name("/Tenant/x") == "Tenant/x"


def test_policy_option_and_unattached_policies() -> None:
    text = """security firewall policy /Common/one {
    rules {
        a {
            action drop
            ip-protocol tcp
        }
    }
}
"""
    model, report = _parse(text, "accept")
    assert "F5AFM_POLICY_NOT_ATTACHED" in _codes(report) and _rules(model)["global/a"].action == Action.DROP
    two = text + text.replace("/Common/one", "/Common/two").replace("action drop", "action reject")
    model, report = _parse(two, "accept")
    assert not model.rules and "F5AFM_NO_POLICY" in _codes(report)
    model, report = _parse(two, "accept", policy="two")
    assert _rules(model)["global/a"].action == Action.RESET_CLIENT and "F5AFM_POLICY_SELECTED" in _codes(report)
    with pytest.raises(ParseError):
        _parse(two, "accept", policy="three")


def test_what_cannot_be_read_is_never_read_as_any() -> None:
    rules = _rule("a", "action accept-decisively\nip-protocol tcp\nsource {\n    ipi-category {\n        botnets { }\n    }\n}")
    rules += _rule("b", "action accept-decisively\nnew-thing yes")
    rules += _rule("c", "action accept-decisively\nsource {\n    identity {\n        users {\n            bob { }\n        }\n    }\n}")
    rules += _rule("d", "action accept-decisively\nip-protocol tcp\nvirtual-server /Common/fwd")
    rules += _rule("e", "action accept-decisively\nsource {\n    ports {\n        80 { }\n    }\n}")
    rules += _rule("f", "ip-protocol tcp")
    rules += _rule("g", "action accept-decisively\ndestination {\n    port-lists {\n        /Common/missing\n    }\n}\nip-protocol tcp")
    model, _ = _parse(GLOBAL % rules + FORWARD, "drop")
    for name in "abcdefg":
        found = [r for r in model.rules if r.name in (f"global/{name}", f"global/{name}@fwd")]
        assert found and all(r.unsupported for r in found), name


def test_zones_of_afm_are_vlans() -> None:
    text = """security zone /Common/z_in {
    vlans {
        /Common/inside { }
    }
}
""" + GLOBAL % _rule("a", "action accept-decisively\nsource {\n    zones {\n        /Common/z_in\n    }\n}\ndestination {\n    zones {\n        /Common/z_in\n    }\n}") + FORWARD
    model, report = _parse(text, "drop")
    rule = _rules(model)["global/a@fwd"]
    assert rule.src_zones == ["inside"] and rule.dst_zones == ["inside"]
    assert any(f.code == "F5AFM_DESTINATION_ZONE" for f in report.item("rule", rule.name).findings)


def test_tcl_bodies_and_one_line_sets_are_skipped_or_read() -> None:
    text = """ltm rule /Common/x {
when FLOW_INIT {
    if { 1 } { log local0. "a \\} b" }
}
}
security firewall address-list /Common/al {
    addresses { 192.0.2.0/24 { } 192.0.2.128/25 { description "x { y" } }
}
""" + GLOBAL % _rule("a", "action accept-decisively\nsource {\n    address-lists {\n        /Common/al\n    }\n}") + FORWARD
    model, _ = _parse(text, "drop")
    assert model.address_groups["al"].members == ["192.0.2.0/24", "192.0.2.128/25"]
    assert _rules(model)["global/a@fwd"].sources == ["al"]


def test_input_errors_and_detection() -> None:
    with pytest.raises(ParseError):
        parse_f5afm.parse(b"just some text\n", Report())
    with pytest.raises(ParseError):
        parse_f5afm.parse(b"net vlan /Common/x {\n    tag 1\n}\n", Report())
    data = (DATA / "f5afm_sample.conf").read_bytes()
    assert cli.detect_format(data) == "f5-afm" and parse_f5afm.looks_like_f5afm(data)
    for other in DATA.glob("*_sample.*"):
        if other.name != "f5afm_sample.conf":
            assert not parse_f5afm.looks_like_f5afm(other.read_bytes()), other.name


# -- the emitter ----------------------------------------------------------------------------------------------------------------


def test_emitted_file_objects_rule_list_and_policy() -> None:
    model, report = load("f5afm_sample.conf")
    text = cli.convert(model, "f5-afm", report)
    device = read_tmsh(text)
    assert list(device.policies) == ["/Common/FWShift"]
    assert device.policies["/Common/FWShift"][0].rule_list == "/Common/FWShift_rules"
    rules = device.rule_lists["/Common/FWShift_rules"]
    assert rules[-1].name == "fwshift_default" and rules[-1].action == "drop" and rules[-1].src is None
    assert all(rule.action != "accept" for rule in rules)  # allow is accept-decisively
    assert "/Common/web_ports" in device.port_lists and device.lists["/Common/inside"][1] == ["/Common/admins"]
    assert not re.search(r"^(?!#).*(enforced-policy|sys db|ltm virtual)", text, re.M)
    codes = _codes(report)
    assert "F5AFM_LOAD" in codes and "F5AFM_VLANS_REQUIRED" in codes and "F5AFM_FQDN_RESOLVER" in codes


def test_emitter_splits_protocols_and_keeps_order() -> None:
    p = Policy(vendor="panos")
    p.services["mix"] = Service("mix", [ServiceEntry(Protocol.TCP, "80,443"), ServiceEntry(Protocol.UDP, "53"),
                                        ServiceEntry(Protocol.TCP, "22", "1024-65535"), ServiceEntry(Protocol.ICMP, icmp_type=8)])  # fmt: skip
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "8080")])
    p.rules = [Rule("r1", services=["mix", "web"], src_zones=["eth0"], origin="r1"), Rule("r2", action=Action.DROP, origin="r2")]
    report = Report()
    device = read_tmsh(emit_f5afm.emit(p, report, Options()))
    rules = device.rule_lists["/Common/FWShift_rules"]
    first = [r for r in rules if r.name.startswith("r1")]
    assert len(first) == 4 and rules.index(first[-1]) < [r.name for r in rules].index("r2")
    tcp = next(r for r in first if r.proto == 6 and r.sports is None)
    assert tcp.dports == [(80, 80), (443, 443)] and tcp.dport_lists == ["/Common/web"] and tcp.vlans == ["eth0"]
    assert any(f.code == "RULE_SPLIT" for f in report.item("rule", "r1").findings)


def test_emitter_never_widens_silently() -> None:
    p = Policy(vendor="panos")
    p.addresses["h"] = Address("h", AddressKind.FQDN, "www.example.com")
    p.rules = [
        Rule("neg_svc", services=["web"], negate_service=True, origin="neg_svc"),
        Rule("to_zone", dst_zones=["eth1"], origin="to_zone"),
        Rule("block_zone", dst_zones=["eth1"], action=Action.DROP, origin="block_zone"),
        Rule("user", users=["bob"], origin="user"),
        Rule("neg_host", sources=["h"], negate_source=True, origin="neg_host"),
        Rule("sched", schedule="nights", origin="sched"),
    ]
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80")])
    report = Report()
    device = read_tmsh(emit_f5afm.emit(p, report, Options()))
    by_name = {r.name: r for r in device.rule_lists["/Common/FWShift_rules"]}
    for name in ("neg_svc", "to_zone", "user", "neg_host", "sched"):
        assert not by_name[name].enabled and report.item("rule", name).disabled, name
    assert by_name["block_zone"].enabled
    assert any(f.code == "ZONE_WIDENED" for f in report.item("rule", "block_zone").findings)
    # With the networks of the zones, the destination zone is written as its networks.
    report = Report()
    device = read_tmsh(emit_f5afm.emit(p, report, Options(zone_networks=ZONES_AT)))
    to_zone = {r.name: r for r in device.rule_lists["/Common/FWShift_rules"]}["to_zone"]
    assert to_zone.enabled and to_zone.dst == ["10.0.2.0/23", "2001:db8:2::/48"]


def test_nat_is_not_written_and_defaults() -> None:
    model, report = load("fortios_sample.conf")
    text = cli.convert(model, "f5-afm", report)
    assert all(report.item("nat", nat.origin).skipped for nat in model.nat_rules)
    assert any(f.code == "F5AFM_NAT_NOT_CONVERTED" for nat in model.nat_rules for f in report.item("nat", nat.origin).findings)
    assert "security nat" not in text and "snat" not in text.lower().replace("fwshift", "")
    p = Policy(vendor="iptables", default_interzone=Action.ALLOW, default_intrazone=Action.ALLOW)
    report = Report()
    device = read_tmsh(emit_f5afm.emit(p, report, Options()))
    assert device.rule_lists["/Common/FWShift_rules"][-1].action == "accept-decisively"
    assert "F5AFM_DEFAULT_ALLOW" in _codes(report)


def test_names_target_policy_and_prefix() -> None:
    p = Policy(vendor="panos")
    p.addresses["_sys_x"] = Address("_sys_x", AddressKind.NETWORK, "192.0.2.0/24")
    p.addresses["1st net"] = Address("1st net", AddressKind.NETWORK, "192.0.2.0/25")
    p.rules = [Rule("allow web!", sources=["_sys_x", "1st net"], origin="allow web!")]
    report = Report()
    text = emit_f5afm.emit(p, report, Options(target_policy="Migrated", object_prefix="m_"))
    device = read_tmsh(text)
    assert list(device.policies) == ["/Common/Migrated"] and "/Common/Migrated_rules" in device.rule_lists
    assert set(device.lists) == {"/Common/m__sys_x", "/Common/m_1st_net"}
    assert [r.name for r in device.rule_lists["/Common/Migrated_rules"]] == ["allow_web_", "fwshift_default"]
    # Without a prefix a name starts with a letter: none can be mistaken for one of the BIG-IP's own (_sys_...).
    assert set(read_tmsh(emit_f5afm.emit(p, Report(), Options())).lists) == {"/Common/x_sys_x", "/Common/x1st_net"}
    with pytest.raises(FwshiftError):
        emit_f5afm.emit(Policy(vendor="panos", rules=[Rule("r", src_zones=["bad zone"], origin="r")]), Report(), Options())


def test_intrazone_default_with_networks() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    p.rules = [Rule("r", src_zones=["eth0"], dst_zones=["eth1"], action=Action.DROP, origin="r")]
    report = Report()
    device = read_tmsh(emit_f5afm.emit(p, report, Options(zone_networks=ZONES_AT)))
    names = [r.name for r in device.rule_lists["/Common/FWShift_rules"]]
    assert "fwshift_intrazone_eth0" in names and names[-1] == "fwshift_default"
    assert "INTRAZONE_WRITTEN" in _codes(report)
    report = Report()
    emit_f5afm.emit(p, report, Options())
    assert "INTRAZONE_DEFAULT" in _codes(report)


def test_sample_round_trip() -> None:
    """The sample written and read back decides every packet as the sample does, but for the rules the emitter writes
    disabled (a country, a schedule, an iRule), which the report names."""
    model, report = load("f5afm_sample.conf")
    text = cli.convert(copy.deepcopy(model), "f5-afm", report)
    back = parse_f5afm.parse(text.encode(), Report())
    assert back.vendor == "f5-afm" and len([r for r in back.rules if r.name.startswith("global/FWShift_rules/")]) == len(back.rules)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    rng = random.Random(4)
    sources = ["198.51.100.7", "10.10.5.9", "10.10.6.10", "10.10.9.9", "192.0.2.8", "203.0.113.210"]
    destinations = ["203.0.113.10", "203.0.113.53", "203.0.113.60", "192.168.50.4", "10.10.1.1", "198.51.100.1"]
    for _ in range(600):
        pkt = Packet(rng.choice(["external", "internal", "dmz"]), "external", rng.choice(sources), rng.choice(destinations),
                     rng.choice(["tcp", "udp", "icmp"]), 40000, rng.choice([22, 23, 53, 80, 443, 8080, 8443]), 8)  # fmt: skip
        assert model_allows(back, pkt) == model_allows(compared, pkt), pkt


def test_emitted_findings_are_in_the_manual() -> None:
    manual = (DATA.parent.parent / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    model, report = load("f5afm_sample.conf")
    cli.convert(model, "f5-afm", report)
    codes = set(_codes(report)) | {f.code for item in report.items.values() for f in item.findings}
    for code in sorted(c for c in codes if c.startswith("F5AFM_")):
        assert f"`{code}`" in manual, code
    assert any(f.severity == Severity.REVIEW for f in report.notes)
