# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VyOS: parser, emitter, and packet-level equivalence between configurations and the model.

The two judges below decide forwarded packets the way a router does, written from VyOS's documentation and the
nftables templates of vyos-1x, apart from the parser and the emitter, sharing no code with them:

* ``Router`` reads set commands of VyOS 1.4 and later: the forward filter, the named chains it jumps to (first match,
  ``return``, the default-action of each), then the zone-based firewall as a second chain at the forward hook.
* ``Legacy`` reads set commands of VyOS 1.3 and EdgeOS as those releases decide: the rule-set of the incoming interface
  (``in``), then the one of the outgoing interface (``out``), each accepting by letting the packet go on, then the zone
  policy. It is not written as the migration the parser follows: it is the behaviour that migration preserves.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import shlex
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load, run
from test_iptables import Packet, model_verdict, random_model

from fwshift import cli
from fwshift.emitters import vyos as emit_vyos
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope, Service
from fwshift.model import ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import vyos as parse_vyos
from fwshift.report import Report

# -- the judges ------------------------------------------------------------------------------------

_PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "icmpv6": 58, "icmp6": 58, "gre": 47, "sctp": 132, "esp": 50}
_PORTS = {"http": 80, "https": 443, "ssh": 22, "smtp": 25, "domain": 53, "telnet": 23, "ftp": 21, "ntp": 123}
_ICMP_NAMES = {"echo-request": 8, "echo-reply": 0, "destination-unreachable": 3, "time-exceeded": 11}
_ICMP6_NAMES = {"echo-request": 128, "echo-reply": 129, "destination-unreachable": 1}
_VALUELESS = {"disable", "log", "local-zone", "exclude"}

Tree = Dict[str, Any]


def read_tree(text: str) -> Tree:
    """Set lines as a tree whose keys are the words, values included: a leaf with two values has two keys."""
    tree: Tree = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("set "):
            continue
        node = tree
        for word in shlex.split(line)[1:]:
            node = node.setdefault(word, {})
    return tree


def _value(node: Optional[Tree], *path: str) -> Optional[str]:
    for word in path:
        if node is None or word not in node:
            return None
        node = node[word]
    if node is None or not node:
        return None
    assert len(node) == 1, (path, node)
    return next(iter(node))


def _values(node: Optional[Tree], *path: str) -> List[str]:
    for word in path:
        if node is None or word not in node:
            return []
        node = node[word]
    return list(node or {})


def _has(node: Optional[Tree], *path: str) -> bool:
    for word in path:
        if node is None or word not in node:
            return False
        node = node[word]
    return True


def _in(address: str, literal: str) -> bool:
    a = ipaddress.ip_address(address)
    if "-" in literal:
        first, last = (ipaddress.ip_address(x) for x in literal.split("-"))
        return a.version == first.version and first <= a <= last
    net = ipaddress.ip_network(literal, strict=False)
    return a.version == net.version and a in net


def _port(text: str) -> Tuple[int, int]:
    first, _, last = text.partition("-")
    low = int(first) if first.isdigit() else _PORTS[first]
    high = (int(last) if last.isdigit() else _PORTS[last]) if last else low
    return low, high


def _pkt_proto(pkt: Packet) -> int:
    return _PROTO.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)


def _iface(name: str, value: str) -> bool:
    return name.startswith(value[:-1]) if value.endswith("*") else name == value


class Router:
    """A VyOS 1.4 router: what it does with a forwarded packet, from set commands."""

    def __init__(self, text: str, legacy_ports: bool = False) -> None:
        self.tree = read_tree(text)
        self.fw: Tree = self.tree.get("firewall", {})
        self.legacy_ports = legacy_ports

    def group(self, kind: str, name: str, key: str) -> List[str]:
        node = self.fw.get("group", {}).get(kind, {}).get(name)
        assert node is not None, (kind, name)
        out = _values(node, key)
        for other in _values(node, "include"):
            out += self.group(kind, other, key)
        return out

    def _ports(self, value: str, proto: Optional[str], port: int) -> bool:
        assert proto in ("tcp", "udp", "tcp_udp")
        items = value.split(",")
        if self.legacy_ports:
            negated = items[0].startswith("!")
            hit = any(_port(i.lstrip("!"))[0] <= port <= _port(i.lstrip("!"))[1] for i in items)
            return hit != negated
        positive = [i for i in items if not i.startswith("!")]
        negative = [i[1:] for i in items if i.startswith("!")]
        if positive and not any(_port(i)[0] <= port <= _port(i)[1] for i in positive):
            return False
        return not any(_port(i)[0] <= port <= _port(i)[1] for i in negative)

    def matches(self, rule: Tree, pkt: Packet, family: int) -> bool:
        proto = _value(rule, "protocol")
        for key in rule:
            if key not in ("action", "description", "disable", "log", "jump-target", "protocol", "source", "destination", "state",
                           "icmp", "icmpv6", "inbound-interface", "outbound-interface"):  # fmt: skip
                raise AssertionError(f"the judge does not know {key}")
        if proto and proto != "all":
            negated = proto.startswith("!")
            name = proto.lstrip("!")
            hit = _pkt_proto(pkt) in ((6, 17) if name == "tcp_udp" else (_PROTO.get(name, int(name) if name.isdigit() else -2),))
            if hit == negated:
                return False
        for side in ("source", "destination"):
            node = rule.get(side)
            if node is None:
                continue
            address = pkt.src if side == "source" else pkt.dst
            port = pkt.sport if side == "source" else pkt.dport
            for key in node:
                if key not in ("address", "group", "port"):
                    raise AssertionError(f"the judge does not know {side} {key}")
            value = _value(node, "address")
            if value is not None:
                negated = value.startswith("!")
                if _in(address, value.lstrip("!")) == negated:
                    return False
            for kind in ("address-group", "network-group"):
                name = _value(node, "group", kind)
                if name is not None:
                    negated = name.startswith("!")
                    real = kind if family == 4 else f"ipv6-{kind}"
                    members = self.group(real, name.lstrip("!"), "network" if "network" in kind else "address")
                    if any(_in(address, m) for m in members) == negated:
                        return False
            value = _value(node, "port")
            if value is not None:
                if _pkt_proto(pkt) not in (6, 17) or not self._ports(value, proto, port):
                    return False
            name = _value(node, "group", "port-group")
            if name is not None:
                negated = name.startswith("!")
                members = self.group("port-group", name.lstrip("!"), "port")
                hit = _pkt_proto(pkt) in (6, 17) and any(_port(m)[0] <= port <= _port(m)[1] for m in members)
                if hit == negated:
                    return False
        for word, names in (("icmp", _ICMP_NAMES), ("icmpv6", _ICMP6_NAMES)):
            node = rule.get(word)
            if node is None:
                continue
            if _pkt_proto(pkt) != (1 if word == "icmp" else 58):
                return False
            kind = _value(node, "type-name")
            wanted = names[kind] if kind is not None else (int(_value(node, "type") or -1) if _value(node, "type") else None)
            if wanted is not None and pkt.icmp_type != wanted:
                return False
            if _value(node, "code") is not None and int(_value(node, "code") or 0) != 0:
                return False  # (the packets of the tests carry code 0)
        states = _values(rule, "state")
        if states and pkt.state.lower() not in states:
            return False
        for side, name in (("inbound-interface", pkt.in_if), ("outbound-interface", pkt.out_if)):
            node = rule.get(side)
            if node is None:
                continue
            value = _value(node, "name")
            if value is not None:
                negated = value.startswith("!")
                if _iface(name, value.lstrip("!")) == negated:
                    return False
            group = _value(node, "group")
            if group is not None:
                negated = group.startswith("!")
                members = self.group("interface-group", group.lstrip("!"), "interface")
                if any(_iface(name, m) for m in members) == negated:
                    return False
        return True

    def chain(self, family: int, node: Tree, pkt: Packet, base: bool, depth: int = 0) -> Optional[str]:
        """A verdict, or None when the packet goes back to the chain that jumped (or, for a base chain, on)."""
        assert depth < 20
        fam = "ipv4" if family == 4 else "ipv6"
        for number in sorted(node.get("rule", {}), key=int):
            rule = node["rule"][number]
            if "disable" in rule or not self.matches(rule, pkt, family):
                continue
            action = _value(rule, "action")
            if action in ("accept", "drop", "reject"):
                return action
            if action == "return":
                return "accept" if base else None
            if action == "jump":
                target = self.fw[fam]["name"][_value(rule, "jump-target")]
                verdict = self.chain(family, target, pkt, False, depth + 1)
                if verdict is not None:
                    return verdict
                continue
            if action == "continue":
                continue
            raise AssertionError(f"the judge does not know action {action}")
        default = _value(node, "default-action") or ("accept" if base else "drop")
        if default in ("return", "continue"):
            return "accept" if base else None
        return default

    def zones(self, family: int, pkt: Packet) -> str:
        zones: Tree = self.fw.get("zone", {})
        fam = "ipv4" if family == 4 else "ipv6"
        word = "name" if family == 4 else "ipv6-name"

        def members(zone: str) -> List[str]:
            return _values(zones[zone], "interface") + _values(zones[zone], "member", "interface")

        for zone, conf in zones.items():
            if "local-zone" in conf or not any(_iface(pkt.out_if, m) for m in members(zone)):
                continue
            if any(_iface(pkt.in_if, m) for m in members(zone)):
                intra = conf.get("intra-zone-filtering", {})
                action = _value(intra, "action")
                if action == "drop":
                    return "drop"
                chain = _value(intra, "firewall", word)
                if chain is not None and action is None:
                    verdict = self.chain(family, self.fw[fam]["name"][chain], pkt, False)
                    if verdict is not None:
                        return verdict
                return "accept"
            for source, from_conf in conf.get("from", {}).items():
                if "local-zone" in zones.get(source, {}) or not any(_iface(pkt.in_if, m) for m in members(source)):
                    continue
                chain = _value(from_conf, "firewall", word)
                if chain is None:
                    continue
                verdict = self.chain(family, self.fw[fam]["name"][chain], pkt, False)
                return verdict if verdict is not None else "accept"
            return _value(conf, "default-action") or "drop"
        return "accept"

    def allows(self, pkt: Packet) -> bool:
        family = 6 if ":" in pkt.src else 4
        fam = "ipv4" if family == 4 else "ipv6"
        forward = self.fw.get(fam, {}).get("forward", {}).get("filter")
        if forward is not None:
            if self.chain(family, forward, pkt, True) != "accept":
                return False
        return self.zones(family, pkt) == "accept"


class Legacy(Router):
    """A VyOS 1.3 or EdgeOS router: the rule-set of the incoming interface, then that of the outgoing one, then the zone
    policy. An accept lets the packet go on to the next of these."""

    def __init__(self, text: str) -> None:
        super().__init__(text, legacy_ports=True)
        self.bindings: Dict[Tuple[str, str], str] = {}  # (direction, interface) -> rule-set
        for kind, node in self.tree.get("interfaces", {}).items():
            for name, conf in node.items():
                for direction in ("in", "out"):
                    chain = _value(conf, "firewall", direction, "name")
                    if chain is not None:
                        self.bindings[(direction, name)] = chain

    def ruleset(self, name: str, pkt: Packet) -> str:
        node = self.fw["name"][name]
        for number in sorted(node.get("rule", {}), key=int):
            rule = node["rule"][number]
            if "disable" in rule:
                continue
            rule = {k: v for k, v in rule.items()}
            if "state" in rule:
                rule["state"] = {s: {} for s, flag in rule["state"].items() if "enable" in flag}
            if "log" in rule:
                del rule["log"]
            if not self.matches(rule, pkt, 4):
                continue
            return _value(rule, "action") or "drop"
        return _value(node, "default-action") or "drop"

    def allows(self, pkt: Packet) -> bool:
        for direction, interface in (("in", pkt.in_if), ("out", pkt.out_if)):
            chain = self.bindings.get((direction, interface))
            if chain is not None and self.ruleset(chain, pkt) != "accept":
                return False
        zones: Tree = self.tree.get("zone-policy", {}).get("zone", {})
        for zone, conf in zones.items():
            if pkt.out_if not in _values(conf, "interface"):
                continue
            if pkt.in_if in _values(conf, "interface"):
                return _value(conf, "intra-zone-filtering", "action") != "drop"
            for source, from_conf in conf.get("from", {}).items():
                if pkt.in_if in _values(zones.get(source, {}), "interface"):
                    chain = _value(from_conf, "firewall", "name")
                    if chain is not None:
                        return self.ruleset(chain, pkt) == "accept"
            return False
        return True


def zone_of(p: Policy, interface: str) -> str:
    for zone in p.zones.values():
        if interface in zone.interfaces:
            return zone.name
    if "other-interfaces" in p.zones and interface not in p.zones:
        return "other-interfaces"  # (read without the interfaces part: the interfaces the configuration does not name)
    return interface


def model_allows(p: Policy, pkt: Packet) -> bool:
    """The model's verdict for a packet that comes in and goes out by interfaces (not zones)."""
    moved = copy.copy(pkt)
    moved.in_if, moved.out_if = zone_of(p, pkt.in_if), zone_of(p, pkt.out_if)
    verdict = model_verdict(p, moved)
    if verdict is None:
        inside = moved.in_if == moved.out_if
        zone = p.zones.get(moved.in_if)
        if inside and zone is not None and zone.intrazone_allow is not None:
            return zone.intrazone_allow
        return (p.default_intrazone if inside else p.default_interzone) == Action.ALLOW
    return verdict


def parse_text(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_vyos.parse(text.encode(), report), report


# -- random configurations ------------------------------------------------------------------------

INTERFACES = ["eth0", "eth1", "eth2", "eth3"]
ADDRESSES = ["10.0.0.5", "10.0.0.17", "10.0.1.130", "10.0.2.150", "10.0.3.20", "10.0.4.1"]
ADDRESSES6 = ["2001:db8:0::5", "2001:db8:1::17", "2001:db8:2::1"]
PORTS = [22, 53, 80, 443, 8000, 8080]

PROLOGUE = """\
set interfaces ethernet eth0 address '192.0.2.1/24'
set interfaces ethernet eth1 address '10.0.0.1/24'
set interfaces ethernet eth2 address '10.0.2.1/24'
set interfaces ethernet eth3 address '10.0.4.1/24'
set firewall group address-group A address '10.0.0.17'
set firewall group address-group A address '10.0.2.100-10.0.3.50'
set firewall group network-group N network '10.0.1.128/25'
set firewall group network-group N include 'M'
set firewall group network-group M network '10.0.4.0/24'
set firewall group ipv6-network-group N network '2001:db8:1::/48'
set firewall group port-group P port '80'
set firewall group port-group P port '8000-8080'
set firewall group interface-group INSIDE interface 'eth1'
set firewall group interface-group INSIDE interface 'eth2'
"""


def _match(rng: random.Random, family: int, chain_rule: bool) -> List[str]:
    parts: List[str] = []
    bang = lambda: "!" if rng.random() < 0.25 else ""  # noqa: E731
    if chain_rule and rng.random() < 0.35:
        if rng.random() < 0.3:
            parts.append(f"inbound-interface group '{bang()}INSIDE'")
        else:
            parts.append(f"inbound-interface name '{bang()}{rng.choice(INTERFACES + ['eth*'])}'")
    if chain_rule and rng.random() < 0.25:
        parts.append(f"outbound-interface name '{bang()}{rng.choice(INTERFACES)}'")
    if family == 4:
        roll = rng.random()
        if roll < 0.25:
            parts.append(f"source address '{bang()}{rng.choice(['10.0.0.0/24', '10.0.1.128/25', '10.0.2.100-10.0.3.50', '10.0.0.17'])}'")
        elif roll < 0.4:
            parts.append(f"source group address-group '{bang()}A'")
        roll = rng.random()
        if roll < 0.25:
            parts.append(f"destination address '{bang()}{rng.choice(['10.0.0.0/24', '10.0.1.0/24', '10.0.4.1'])}'")
        elif roll < 0.4:
            parts.append(f"destination group network-group '{bang()}N'")
    elif rng.random() < 0.4:
        parts.append(f"destination group network-group '{bang()}N'")
    roll = rng.random()
    if roll < 0.45:
        proto = rng.choice(["tcp", "udp", "tcp_udp"])
        parts.append(f"protocol '{proto}'")
        if rng.random() < 0.5:
            ports = ",".join(str(p) for p in rng.sample(PORTS, rng.randint(1, 3)))
            if rng.random() < 0.3:
                ports = "8000-8080,!8005"
            parts.append(f"destination port '{ports}'")
        elif rng.random() < 0.3:
            parts.append(f"destination group port-group '{bang()}P'")
    elif roll < 0.55:
        if family == 4:
            parts += ["protocol 'icmp'", "icmp type-name 'echo-request'"]
        else:
            parts += ["protocol 'ipv6-icmp'", "icmpv6 type '128'"]
    elif roll < 0.62:
        parts.append(rng.choice(["protocol '!tcp'", "protocol '47'"]))
    if rng.random() < 0.1:
        parts.append(rng.choice(["state 'new'", "state 'established'"]))
    return parts


def random_config(rng: random.Random, zones: bool = False) -> str:
    lines = [PROLOGUE]
    if rng.random() < 0.5:
        lines += ["set firewall global-options state-policy established action 'accept'",
                  "set firewall global-options state-policy related action 'accept'"]  # fmt: skip

    def rules(head: str, count: int, family: int, custom: bool) -> None:
        for number in range(1, count + 1):
            roll = rng.random()
            if roll < 0.2:
                action = "return"
            elif roll < 0.35 and not custom:
                action = "jump"
            else:
                action = rng.choice(["accept", "accept", "drop", "reject", "continue"])
            where = f"{head} rule {number * 10}"
            lines.append(f"{where} action '{action}'")
            if action == "jump":
                lines.append(f"{where} jump-target '{rng.choice(['C1', 'C2'])}'")
            for part in _match(rng, family, True):
                lines.append(f"{where} {part}")
            if action in ("accept", "drop") and rng.random() < 0.1:
                lines.append(f"{where} disable")

    for family in (4, 6):
        fam = "ipv4" if family == 4 else "ipv6"
        if zones and rng.random() < 0.5:
            pass
        else:
            if rng.random() < 0.6:
                lines.append(f"set firewall {fam} forward filter default-action '{rng.choice(['accept', 'drop'])}'")
            rules(f"set firewall {fam} forward filter", rng.randint(1, 6), family, False)
        for name in ("C1", "C2"):
            lines.append(f"set firewall {fam} name {name} default-action '{rng.choice(['accept', 'drop', 'return', 'reject'])}'")
            rules(f"set firewall {fam} name {name}", rng.randint(0, 4), family, True)
        if zones:
            for name in ("Z1", "Z2"):
                lines.append(f"set firewall {fam} name {name} default-action '{rng.choice(['accept', 'drop', 'return'])}'")
                rules(f"set firewall {fam} name {name}", rng.randint(0, 3), family, True)
    if zones:
        lines += ["set firewall zone LAN interface 'eth1'", "set firewall zone LAN interface 'eth2'",
                  "set firewall zone WAN interface 'eth0'"]  # fmt: skip
        if rng.random() < 0.5:
            lines.append("set firewall zone DMZ interface 'eth3'")
            lines.append(f"set firewall zone DMZ from LAN firewall name '{rng.choice(['Z1', 'Z2'])}'")
        lines.append(f"set firewall zone WAN from LAN firewall name '{rng.choice(['Z1', 'Z2'])}'")
        if rng.random() < 0.7:
            lines.append(f"set firewall zone WAN from LAN firewall ipv6-name '{rng.choice(['Z1', 'Z2'])}'")
        lines.append(f"set firewall zone LAN from WAN firewall name '{rng.choice(['Z1', 'Z2'])}'")
        if rng.random() < 0.4:
            lines.append(f"set firewall zone LAN intra-zone-filtering action '{rng.choice(['accept', 'drop'])}'")
        elif rng.random() < 0.3:
            lines.append("set firewall zone LAN intra-zone-filtering firewall name 'Z1'")
        if rng.random() < 0.3:
            lines.append("set firewall zone WAN default-action 'reject'")
    return "\n".join(lines) + "\n"


def random_packet(rng: random.Random, family: int = 0) -> Packet:
    family = family or rng.choice([4, 4, 6])
    pool = ADDRESSES if family == 4 else ADDRESSES6
    proto = rng.choice(["tcp", "tcp", "udp", "icmp" if family == 4 else "icmp6", "47"])
    return Packet(rng.choice(INTERFACES), rng.choice(INTERFACES), rng.choice(pool), rng.choice(pool), proto,
                  rng.choice([1024, 40000]), rng.choice(PORTS + [8005]), rng.choice([0, 8, 128]))  # fmt: skip


@pytest.mark.parametrize("seed", range(60))
def test_parsed_rules_decide_like_the_router(seed: int) -> None:
    """Jumps, returns that one condition cannot take away, negated interfaces and groups, both IP versions, zones: the
    model gives the router's verdict for every packet that opens a connection."""
    rng = random.Random(seed)
    text = random_config(rng, zones=seed % 3 == 2)
    policy, _ = parse_text(text)
    router = Router(text)
    assert not [r.name for r in policy.rules if r.unsupported and r.enabled and not any("state" in u for u in r.unsupported)], (
        text, [(r.name, r.unsupported) for r in policy.rules if r.unsupported])
    for _ in range(300):
        pkt = random_packet(rng)
        if any("state" in u for r in policy.rules for u in r.unsupported):
            break
        assert model_allows(policy, pkt) == router.allows(pkt), (seed, pkt, text)


def random_legacy(rng: random.Random) -> str:
    lines = [line.replace("set firewall group ipv6-network-group N network '2001:db8:1::/48'", "")
             for line in PROLOGUE.splitlines()]  # fmt: skip
    lines = [line for line in lines if line and "interface-group" not in line and "include" not in line]
    for name in ("IN1", "IN2", "OUT1", "Z1"):
        lines.append(f"set firewall name {name} default-action '{rng.choice(['accept', 'drop', 'reject'])}'")
        for number in range(1, rng.randint(1, 5) + 1):
            where = f"set firewall name {name} rule {number * 10}"
            lines.append(f"{where} action '{rng.choice(['accept', 'accept', 'drop', 'reject'])}'")
            for part in _match(rng, 4, False):
                part = part.replace("state 'new'", "state new enable").replace("state 'established'", "state established enable")
                if "port '" in part and "8000-8080,!8005" in part:
                    part = part.replace("8000-8080,!8005", "!8000-8080,22")
                lines.append(f"{where} {part}")
            if rng.random() < 0.1:
                lines.append(f"{where} log enable")
    lines.append(f"set interfaces ethernet eth0 firewall in name '{rng.choice(['IN1', 'IN2'])}'")
    if rng.random() < 0.6:
        lines.append(f"set interfaces ethernet eth1 firewall in name '{rng.choice(['IN1', 'IN2'])}'")
    if rng.random() < 0.6:
        lines.append("set interfaces ethernet eth2 firewall out name 'OUT1'")
    if rng.random() < 0.4:
        lines += ["set zone-policy zone LAN interface 'eth3'", "set zone-policy zone WAN interface 'eth2'",
                  "set zone-policy zone LAN from WAN firewall name 'Z1'"]  # fmt: skip
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("seed", range(40))
def test_legacy_rulesets_decide_like_the_router(seed: int) -> None:
    """VyOS 1.3 and EdgeOS: a rule-set on the way in and one on the way out both decide, accept goes on, a port list is
    negated as a whole. The model gives the verdict the old router gives."""
    rng = random.Random(seed)
    text = random_legacy(rng)
    policy, report = parse_text(text)
    router = Legacy(text)
    assert any(n.code == "VYOS_FORMAT" and "1.3" in n.message for n in report.notes)
    for _ in range(300):
        pkt = random_packet(rng, 4)
        assert model_allows(policy, pkt) == router.allows(pkt), (seed, pkt, text)


def _emitted(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    report = Report()
    return emit_vyos.emit(model, report, options or Options()), report


@pytest.mark.parametrize("seed", range(40))
def test_emitted_commands_decide_like_the_model(seed: int) -> None:
    """Whatever the groups, negations, rule types and IP versions: the zones and chains written give the model's verdict.
    Zones that are interfaces (even seeds) become one chain that matches the interfaces; other zones (odd seeds) the
    zone-based firewall, with a chain for traffic to interfaces in no zone. eth9 is an interface in no zone."""
    rng = random.Random(seed)
    model = random_model(rng)
    from test_iptables import ZONES
    from test_iptables import random_packet as packet

    zone_based = seed % 2 == 1
    for zone in ZONES:
        model.zones[zone] = Zone(zone, [] if zone_based else [zone])
    model.default_interzone, model.default_intrazone = rng.choice([(Action.DENY, Action.DENY), (Action.ALLOW, Action.DENY),
                                                                   (Action.DENY, Action.ALLOW), (Action.ALLOW, Action.ALLOW)])  # fmt: skip
    text, _ = _emitted(model)
    assert ("set firewall zone" in text) == zone_based
    router = Router(text)
    for _ in range(300):
        pkt = packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.3:
            pkt.in_if = "eth9"
        elif rng.random() < 0.3:
            pkt.out_if = "eth9"
        if pkt.in_if == "eth9" and (pkt.out_if == "eth9" or zone_based):
            continue  # (VyOS drops what comes from an interface in no zone into a zone; eth9 to itself is no zone's)
        check = copy.copy(pkt)
        assert router.allows(pkt) == model_allows(model, check), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(15))
def test_emitted_chain_without_zones_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = random_model(rng)
    from test_iptables import random_packet as packet

    for rule in model.rules:
        rule.src_zones, rule.dst_zones, rule.scope = [ANY], [ANY], RuleScope.UNIVERSAL
    model.default_interzone = model.default_intrazone = rng.choice([Action.DENY, Action.ALLOW])
    text, _ = _emitted(model)
    assert "firewall zone" not in text and "forward filter rule 10000 jump-target 'FWS-FORWARD'" in text
    router = Router(text)
    for _ in range(200):
        pkt = packet(rng, rng.choice([4, 6]))
        assert router.allows(pkt) == model_allows(model, pkt), (seed, pkt)


@pytest.mark.parametrize("seed", range(25))
def test_roundtrip_keeps_every_decision(seed: int) -> None:
    """A configuration read, written as commands and read back decides as the configuration did."""
    rng = random.Random(seed)
    text = random_config(rng, zones=seed % 2 == 1)
    policy, _ = parse_text(text)
    if any(r.unsupported for r in policy.rules):
        return
    out, _ = _emitted(policy)
    back, _ = parse_text(out)
    original = Router(text)
    written = Router(out)
    for _ in range(300):
        pkt = random_packet(rng)
        assert written.allows(pkt) == original.allows(pkt), (seed, pkt, out)
        assert model_allows(back, pkt) == original.allows(pkt), (seed, pkt, out)


# -- the reader ------------------------------------------------------------------------------------


def _rule(p: Policy, name: str) -> Rule:
    return next(r for r in p.rules if r.name == name)


def _nat(p: Policy, name: str) -> NatRule:
    return next(n for n in p.nat_rules if n.name == name)


def _pkt(src: str, dst: str, proto: str = "tcp", dport: int = 443, in_if: str = "eth1", out_if: str = "eth0") -> Packet:
    return Packet(in_if, out_if, src, dst, proto, 40000, dport, 8)


BRACES = """\
firewall {
    group {
        network-group INSIDE {
            network 10.0.0.0/24
        }
    }
    ipv4 {
        forward {
            filter {
                default-action drop
                rule 10 {
                    action accept
                    description "inside out"
                    inbound-interface {
                        name eth1
                    }
                    source {
                        group {
                            network-group INSIDE
                        }
                    }
                }
                rule 20 {
                    action accept
                    state "established"
                    state "related"
                }
            }
        }
    }
}
interfaces {
    ethernet eth0 {
        address 192.0.2.1/24
    }
    ethernet eth1 {
        address 10.0.0.1/24
    }
}
// Warning: Do not remove the following line.
// vyos-config-version: "firewall@15:nat@8:system@27"
// Release version: 1.4.0
"""

SETS = """\
set interfaces ethernet eth0 address '192.0.2.1/24'
set interfaces ethernet eth1 address '10.0.0.1/24'
set firewall group network-group INSIDE network '10.0.0.0/24'
set firewall ipv4 forward filter default-action 'drop'
set firewall ipv4 forward filter rule 10 action 'accept'
set firewall ipv4 forward filter rule 10 description 'inside out'
set firewall ipv4 forward filter rule 10 inbound-interface name 'eth1'
set firewall ipv4 forward filter rule 10 source group network-group 'INSIDE'
set firewall ipv4 forward filter rule 20 action 'accept'
set firewall ipv4 forward filter rule 20 state 'established'
set firewall ipv4 forward filter rule 20 state 'related'
"""


def test_set_lines_and_braces_read_the_same() -> None:
    a, report_a = parse_text(SETS)
    b, report_b = parse_text(BRACES)
    assert a.to_dict() == b.to_dict()
    assert [r.name for r in a.rules] == ["inside out", "ipv6 default"]  # (no IPv6 forward filter: IPv6 is forwarded)
    assert a.default_interzone == Action.DENY
    assert any("release 1.4.0" in n.message for n in report_b.notes if n.code == "VYOS_FORMAT")


def test_quotes_comments_and_script_commands() -> None:
    text = ("# a comment\nconfigure\n" + SETS.replace("'inside out'", '"inside \\"out\\""') + "commit\nsave\nexit\n")
    p, _ = parse_text(text)
    assert p.rules[0].name == 'inside "out"'


def test_command_files_and_mixed_firewalls_are_refused() -> None:
    with pytest.raises(ParseError, match="belongs to a file of commands"):
        parse_text(SETS + "delete firewall ipv4 forward filter rule 10\n")
    with pytest.raises(ParseError, match="at once"):
        parse_text(SETS + "set firewall name OLD default-action 'drop'\n")
    with pytest.raises(ParseError, match="no firewall or nat part"):
        parse_text("set system host-name 'x'\n")
    with pytest.raises(ParseError, match="not closed"):
        parse_text("set firewall ipv4 name X description 'open\n")
    with pytest.raises(ParseError, match="without"):
        parse_text("firewall {\n    ipv4 {\n")


def test_detection() -> None:
    assert cli.detect_format((DATA / "vyos_sample.conf").read_bytes()) == "vyos"
    assert cli.detect_format((DATA / "edgeos_sample.conf").read_bytes()) == "vyos"
    assert cli.detect_format(BRACES.encode()) == "vyos"
    for name in ("junos_sample.conf", "fortios_sample.conf", "routeros_sample.rsc", "iptables_sample.rules", "ios_sample.cfg"):
        assert not parse_vyos.looks_like_vyos((DATA / name).read_bytes()), name
    assert not parse_vyos.looks_like_vyos(b"set firewall family inet filter F term T then accept\n")
    assert not parse_vyos.looks_like_vyos(b"interfaces {\n    ge-0/0/0 {\n        unit 0;\n    }\n}\n")


def test_return_in_the_forward_filter_accepts_whatever_its_default() -> None:
    p, _ = parse_text("set firewall ipv4 forward filter default-action 'drop'\n"
                      "set firewall ipv4 forward filter rule 10 action 'return'\n"
                      "set firewall ipv4 forward filter rule 10 destination address '10.0.0.5'\n")  # fmt: skip
    assert model_allows(p, _pkt("10.0.1.1", "10.0.0.5")) is True
    assert model_allows(p, _pkt("10.0.1.1", "10.0.0.6")) is False


def test_named_chain_defaults_to_drop_and_return_goes_on() -> None:
    text = ("set firewall ipv4 forward filter rule 10 action 'jump'\n"
            "set firewall ipv4 forward filter rule 10 jump-target 'A'\n"
            "set firewall ipv4 forward filter rule 20 action 'drop'\n"
            "set firewall ipv4 forward filter rule 20 destination address '10.0.0.6'\n"
            "set firewall ipv4 name A rule 10 action 'return'\n"
            "set firewall ipv4 name A rule 10 destination group network-group 'N'\n"
            "set firewall group network-group N network '10.0.0.0/24'\n")  # fmt: skip
    p, _ = parse_text(text)
    router = Router(text)
    for dst in ("10.0.0.5", "10.0.0.6", "10.0.1.1"):
        assert model_allows(p, _pkt("10.0.9.9", dst)) == router.allows(_pkt("10.0.9.9", dst))
    assert model_allows(p, _pkt("10.0.9.9", "10.0.1.1")) is False  # (A's default: drop)
    assert model_allows(p, _pkt("10.0.9.9", "10.0.0.6")) is False  # (returned, then rule 20)
    assert model_allows(p, _pkt("10.0.9.9", "10.0.0.5")) is True


def test_legacy_accept_goes_on_to_the_rule_set_of_the_other_interface() -> None:
    text = ("set interfaces ethernet eth0 firewall in name 'WAN_IN'\n"
            "set interfaces ethernet eth1 firewall out name 'LAN_OUT'\n"
            "set firewall name WAN_IN default-action 'drop'\n"
            "set firewall name WAN_IN rule 10 action 'accept'\n"
            "set firewall name WAN_IN rule 10 protocol 'tcp'\n"
            "set firewall name LAN_OUT default-action 'accept'\n"
            "set firewall name LAN_OUT rule 10 action 'drop'\n"
            "set firewall name LAN_OUT rule 10 destination port '22'\n"
            "set firewall name LAN_OUT rule 10 protocol 'tcp'\n")  # fmt: skip
    p, report = parse_text(text)
    assert model_allows(p, _pkt("192.0.2.9", "10.0.0.5", dport=443, in_if="eth0", out_if="eth1")) is True
    assert model_allows(p, _pkt("192.0.2.9", "10.0.0.5", dport=22, in_if="eth0", out_if="eth1")) is False
    assert model_allows(p, _pkt("192.0.2.9", "10.0.0.5", dport=22, in_if="eth0", out_if="eth2")) is True
    assert model_allows(p, _pkt("192.0.2.9", "10.0.0.5", "udp", in_if="eth0", out_if="eth2")) is False
    note = next(n for n in report.notes if n.code == "VYOS_FORMAT")
    assert "VyOS 1.3" in note.message and "return" in note.message


def test_port_negation_differs_between_the_dialects() -> None:
    modern = ("set firewall ipv4 forward filter default-action 'drop'\n"
              "set firewall ipv4 forward filter rule 10 action 'accept'\n"
              "set firewall ipv4 forward filter rule 10 protocol 'tcp'\n"
              "set firewall ipv4 forward filter rule 10 destination port '!22,80'\n")  # fmt: skip
    p, _ = parse_text(modern)
    assert [model_allows(p, _pkt("10.0.0.1", "10.0.0.2", dport=port)) for port in (22, 80, 443)] == [False, True, False]
    legacy = ("set interfaces ethernet eth1 firewall in name 'IN'\n"
              "set firewall name IN default-action 'drop'\n"
              "set firewall name IN rule 10 action 'accept'\n"
              "set firewall name IN rule 10 protocol 'tcp'\n"
              "set firewall name IN rule 10 destination port '!22,80'\n")  # fmt: skip
    p, _ = parse_text(legacy)
    assert [model_allows(p, _pkt("10.0.0.1", "10.0.0.2", dport=port)) for port in (22, 80, 443)] == [False, False, True]


ZONES = """\
set interfaces ethernet eth0 address '192.0.2.1/24'
set interfaces ethernet eth1 address '10.0.0.1/24'
set interfaces ethernet eth2 address '10.0.2.1/24'
set interfaces ethernet eth3 address '10.0.4.1/24'
set firewall ipv4 name LAN-WAN default-action 'accept'
set firewall ipv4 name WAN-LAN default-action 'drop'
set firewall ipv4 name WAN-LAN rule 10 action 'accept'
set firewall ipv4 name WAN-LAN rule 10 destination address '10.0.0.80'
set firewall zone LAN interface 'eth1'
set firewall zone LAN interface 'eth2'
set firewall zone WAN interface 'eth0'
set firewall zone WAN from LAN firewall name 'LAN-WAN'
set firewall zone LAN from WAN firewall name 'WAN-LAN'
"""


def test_zones_drop_what_has_no_rule_set_and_leave_other_interfaces_alone() -> None:
    p, report = parse_text(ZONES)
    assert set(p.zones) >= {"LAN", "WAN"} and p.zones["LAN"].interfaces == ["eth1", "eth2"]
    router = Router(ZONES)
    cases = [("eth1", "eth0", True), ("eth0", "eth1", False), ("eth1", "eth2", True), ("eth3", "eth1", False),
             ("eth1", "eth3", True)]  # fmt: skip
    for in_if, out_if, allowed in cases:
        pkt = _pkt("10.0.0.5", "10.0.0.6", in_if=in_if, out_if=out_if)
        assert router.allows(pkt) == allowed, (in_if, out_if)
        assert model_allows(p, pkt) == allowed, (in_if, out_if)
    assert model_allows(p, _pkt("192.0.2.9", "10.0.0.80", in_if="eth0", out_if="eth1")) is True
    six = Packet("eth1", "eth0", "2001:db8::1", "2001:db8:1::1", "tcp", 40000, 443)
    assert model_allows(p, six) is False  # (from LAN to WAN without an ipv6-name: dropped)
    assert any(n.code == "VYOS_ZONES" for n in report.notes)


def test_zone_split_where_a_rule_names_part_of_it() -> None:
    text = ZONES + ("set firewall ipv4 forward filter rule 10 action 'drop'\n"
                    "set firewall ipv4 forward filter rule 10 inbound-interface name 'eth2'\n")  # fmt: skip
    p, report = parse_text(text)
    assert "LAN" not in p.zones and {"eth1", "eth2", "WAN"} <= set(p.zones)
    assert any(n.code == "VYOS_ZONE_SPLIT" and "LAN" in n.message for n in report.notes)


def test_intra_zone_filtering_and_the_forward_filter_before_the_zones() -> None:
    text = ZONES + ("set firewall zone LAN intra-zone-filtering action 'drop'\n"
                    "set firewall ipv4 forward filter rule 10 action 'drop'\n"
                    "set firewall ipv4 forward filter rule 10 destination address '192.0.2.66'\n")  # fmt: skip
    p, _ = parse_text(text)
    assert model_allows(p, _pkt("10.0.0.5", "10.0.2.6", in_if="eth1", out_if="eth2")) is False
    assert model_allows(p, _pkt("10.0.0.5", "192.0.2.66", in_if="eth1", out_if="eth0")) is False
    assert model_allows(p, _pkt("10.0.0.5", "192.0.2.67", in_if="eth1", out_if="eth0")) is True


def test_groups_include_and_empty_groups() -> None:
    text = ("set firewall group network-group A network '10.0.0.0/24'\n"
            "set firewall group network-group A include 'B'\n"
            "set firewall group network-group B network '10.0.5.0/24'\n"
            "set firewall group address-group E description 'nothing'\n"
            "set firewall ipv4 forward filter default-action 'drop'\n"
            "set firewall ipv4 forward filter rule 10 action 'accept'\n"
            "set firewall ipv4 forward filter rule 10 source group network-group 'A'\n"
            "set firewall ipv4 forward filter rule 20 action 'accept'\n"
            "set firewall ipv4 forward filter rule 20 source group address-group 'E'\n")  # fmt: skip
    p, report = parse_text(text)
    assert p.address_groups["A"].members == ["10.0.0.0/24", "10.0.5.0/24"]
    assert "B" in p.address_groups["A"].description
    assert model_allows(p, _pkt("10.0.5.9", "10.9.9.9")) is True
    assert [r.name for r in p.rules] == ["forward-10", "ipv6 default"]
    assert any(n.code == "VYOS_EMPTY_GROUP" for n in report.notes)


def test_unknown_and_unmodelled_matches_are_never_any() -> None:
    text = ("set firewall ipv4 forward filter default-action 'drop'\n"
            "set firewall ipv4 forward filter rule 10 action 'accept'\n"
            "set firewall ipv4 forward filter rule 10 source mac-address '00:53:00:00:00:01'\n"
            "set firewall ipv4 forward filter rule 20 action 'accept'\n"
            "set firewall ipv4 forward filter rule 20 packet-length '100'\n"
            "set firewall ipv4 forward filter rule 30 action 'accept'\n"
            "set firewall ipv4 forward filter rule 30 frobnicate 'yes'\n"
            "set firewall ipv4 forward filter rule 40 action 'queue'\n"
            "set firewall ipv4 forward filter rule 50 action 'jump'\n"
            "set firewall ipv4 forward filter rule 50 jump-target 'NOWHERE'\n")  # fmt: skip
    p, report = parse_text(text)
    assert all(r.unsupported for r in p.rules if r.name != "ipv6 default")
    assert _rule(p, "forward-40").action == Action.DROP
    assert any(n.code == "OBJECTS_MISSING" and "NOWHERE" in n.message for n in report.notes)
    assert any(n.code == "VYOS_QUEUE" for n in report.notes)


def test_disabled_rules_stay_disabled_where_they_were() -> None:
    p, _ = parse_text("set firewall ipv4 forward filter rule 10 action 'drop'\n"
                      "set firewall ipv4 forward filter rule 10 disable\n"
                      "set firewall ipv4 forward filter rule 20 action 'drop'\n"
                      "set firewall ipv4 forward filter rule 20 protocol 'udp'\n")  # fmt: skip
    assert [(r.name, r.enabled) for r in p.rules] == [("forward-10", False), ("forward-20", True)]


def test_interfaces_wildcards_negation_and_groups() -> None:
    text = ("set interfaces ethernet eth0 address '192.0.2.1/24'\n"
            "set interfaces ethernet eth1 vif 10 address '10.0.0.1/24'\n"
            "set interfaces wireguard wg0 address '10.9.0.1/24'\n"
            "set interfaces bridge br0 member interface 'eth3'\n"
            "set firewall ipv4 forward filter rule 10 action 'drop'\n"
            "set firewall ipv4 forward filter rule 10 inbound-interface name '!eth0'\n"
            "set firewall ipv4 forward filter rule 20 action 'drop'\n"
            "set firewall ipv4 forward filter rule 20 outbound-interface name 'eth*'\n")  # fmt: skip
    p, report = parse_text(text)
    # (eth3 is a port of a bridge: routed traffic comes in by the bridge)
    assert _rule(p, "forward-10").src_zones == ["br0", "eth1", "eth1.10", "wg0"]
    assert _rule(p, "forward-20").dst_zones == ["eth0", "eth1", "eth1.10"]
    assert report.items[("rule", "forward-10")].findings[0].code == "VYOS_INTERFACES_RESOLVED"
    bare, report = parse_text("set firewall ipv4 forward filter rule 10 action 'drop'\n"
                              "set firewall ipv4 forward filter rule 10 inbound-interface name '!eth0'\n"
                              "set firewall ipv4 forward filter rule 20 action 'accept'\n"
                              "set firewall ipv4 forward filter rule 20 inbound-interface name 'eth1'\n")  # fmt: skip
    # (without the interfaces part, the interfaces the configuration does not name are a zone without interfaces)
    assert _rule(bare, "forward-10").src_zones == ["eth1", "other-interfaces"] and not _rule(bare, "forward-10").unsupported
    assert bare.zones["other-interfaces"].interfaces == [] and ("rule", "forward-10") not in report.items
    assert "VYOS_OTHER_INTERFACES" in [n.code for n in report.notes]


def test_connection_status_nat_destination_stands_for_what_is_translated() -> None:
    text = ("set interfaces ethernet eth0 address '203.0.113.2/24'\n"
            "set interfaces ethernet eth1 address '10.0.0.1/24'\n"
            "set firewall ipv4 forward filter default-action 'drop'\n"
            "set firewall ipv4 forward filter rule 10 action 'accept'\n"
            "set firewall ipv4 forward filter rule 10 connection-status nat 'destination'\n"
            "set firewall ipv4 forward filter rule 10 inbound-interface name 'eth0'\n"
            "set nat destination rule 10 inbound-interface name 'eth0'\n"
            "set nat destination rule 10 destination address '203.0.113.10'\n"
            "set nat destination rule 10 protocol 'tcp'\n"
            "set nat destination rule 10 destination port '443'\n"
            "set nat destination rule 10 translation address '10.0.0.10'\n")  # fmt: skip
    p, report = parse_text(text)
    assert [r.name for r in p.rules] == ["forward-10 (destination-10)", "ipv6 default"]
    rule = p.rules[0]
    assert rule.src_zones == ["eth0"] and rule.action == Action.ALLOW
    # The rule and the NAT rule name one object for the destination, which stands for what the NAT rule translates.
    assert rule.destinations == p.nat_rules[0].destinations == ["destination-10 destination"] and p.named_translations
    assert p.addresses["destination-10 destination"].value == "203.0.113.10"
    assert p.services[rule.services[0]].entries == [ServiceEntry(Protocol.TCP, "443")]
    assert report.items[("rule", rule.origin)].findings[0].code == "VYOS_DNAT_STATUS"
    out, _ = _emitted(p)  # (a target that looks rules up after NAT: the translated address)
    assert "destination address '10.0.0.10'" in out and "destination address '203.0.113.10'" not in out.split("set nat")[0]
    excluded = text + ("set nat destination rule 5 exclude\n"
                       "set nat destination rule 5 destination address '203.0.113.11'\n")  # fmt: skip
    p, _ = parse_text(excluded)
    assert p.rules[0].unsupported and "excludes" in p.rules[0].unsupported[0]


def test_forward_rules_name_the_translated_destination() -> None:
    text = ("set firewall ipv4 forward filter default-action 'drop'\n"
            "set firewall ipv4 forward filter rule 10 action 'accept'\n"
            "set firewall ipv4 forward filter rule 10 destination address '10.0.0.10'\n"
            "set nat destination rule 10 destination address '203.0.113.10'\n"
            "set nat destination rule 10 translation address '10.0.0.10'\n")  # fmt: skip
    p, _ = parse_text(text)
    assert p.lookup_after_dnat and "203.0.113.10" in p.rules[0].destinations
    nat = p.nat_rules[0]
    assert nat.destination_translation == DestNat("10.0.0.10") and nat.combines


def test_nat_shapes() -> None:
    text = ("set nat source rule 10 outbound-interface name 'eth0'\n"
            "set nat source rule 10 translation address 'masquerade'\n"
            "set nat source rule 20 outbound-interface name 'eth0'\n"
            "set nat source rule 20 source address '10.0.1.0/24'\n"
            "set nat source rule 20 translation address '198.51.100.0/24'\n"
            "set nat source rule 30 outbound-interface interface-name 'eth0'\n"
            "set nat source rule 30 translation address '198.51.100.7-198.51.100.9'\n"
            "set nat source rule 30 translation port '1024-2048'\n"
            "set nat destination rule 10 inbound-interface 'eth0'\n"
            "set nat destination rule 10 destination port '8080'\n"
            "set nat destination rule 10 protocol 'tcp_udp'\n"
            "set nat destination rule 10 translation address '10.0.0.5'\n"
            "set nat destination rule 10 translation port '80'\n"
            "set nat destination rule 20 translation redirect port '3128'\n"
            "set nat destination rule 30 load-balance backend 10.0.0.7 weight '50'\n"
            "set nat destination rule 30 translation address '10.0.0.7'\n")  # fmt: skip
    p, report = parse_text(text)
    names = [n.name for n in p.nat_rules]
    assert names == ["destination-10", "destination-20", "destination-30", "source-10", "source-20", "source-30"]
    assert _nat(p, "source-10").source_translation == SourceNat(SnatKind.INTERFACE, interface="eth0")
    assert _nat(p, "source-20").source_translation == SourceNat(SnatKind.STATIC, ["198.51.100.0/24"])
    assert _nat(p, "source-30").source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.7-198.51.100.9"])
    assert report.items[("nat", "source-30")].findings[0].code == "VYOS_NAT_PORTS"
    dnat = _nat(p, "destination-10")
    assert dnat.destination_translation == DestNat("10.0.0.5", "80") and dnat.src_zones == ["eth0"]
    assert len(p.services[dnat.service].entries) == 2
    assert _nat(p, "destination-20").unsupported and _nat(p, "destination-30").unsupported


def test_icmp_names_states_and_protocols() -> None:
    text = ("set firewall ipv4 forward filter default-action 'drop'\n"
            "set firewall ipv4 forward filter rule 10 action 'accept'\n"
            "set firewall ipv4 forward filter rule 10 protocol 'icmp'\n"
            "set firewall ipv4 forward filter rule 10 icmp type-name 'echo-request'\n"
            "set firewall ipv4 forward filter rule 20 action 'accept'\n"
            "set firewall ipv4 forward filter rule 20 protocol 'icmp'\n"
            "set firewall ipv4 forward filter rule 20 icmp type '3'\n"
            "set firewall ipv4 forward filter rule 20 icmp code '4'\n"
            "set firewall ipv4 forward filter rule 30 action 'accept'\n"
            "set firewall ipv4 forward filter rule 30 protocol 'ipv6-icmp'\n"
            "set firewall ipv4 forward filter rule 40 action 'accept'\n"
            "set firewall ipv4 forward filter rule 40 state 'new'\n"
            "set firewall ipv4 forward filter rule 40 protocol 'gre'\n")  # fmt: skip
    p, _ = parse_text(text)
    assert p.services[_rule(p, "forward-10").services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    assert p.services[_rule(p, "forward-20").services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]
    assert _rule(p, "forward-30").unsupported  # (ICMPv6 in a chain for IPv4)
    assert p.services[_rule(p, "forward-40").services[0]].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    legacy = ("set interfaces ethernet eth1 firewall in name 'IN'\n"
              "set firewall name IN rule 10 action 'accept'\n"
              "set firewall name IN rule 10 protocol 'icmp'\n"
              "set firewall name IN rule 10 icmp type-name 'port-unreachable'\n")  # fmt: skip
    p, _ = parse_text(legacy)
    allow = [r for r in p.rules if r.action == Action.ALLOW][0]
    assert p.services[allow.services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=3)]


def test_sample_rules_and_notes() -> None:
    p, report = load("vyos_sample.conf")
    assert {"WAN", "LAN", "GUEST", "DMZ", "VPN"} <= set(p.zones)
    assert _rule(p, "drop the blocklist").sources == ["BLOCKLIST"]
    assert p.address_groups["BLOCKLIST"].members == ["198.51.100.0/24", "203.0.113.128/25"]
    spoofed = _rule(p, "spoofed inside sources")
    assert spoofed.sources == ["INSIDE-NETS"] and spoofed.negate_source and spoofed.log_start
    assert _rule(p, "office hours only").schedule
    assert any("rate limit" in u for u in _rule(p, "zone-DMZ.from-WAN.WAN-DMZ-50").unsupported)
    assert _rule(p, "zone-WAN.from-LAN.LAN-WAN-20").destinations == ["UPDATES"]
    assert _rule(p, "zone-DMZ.from-WAN.WAN-DMZ-20 (https to web1)").destinations == ["https to web1 destination"]
    assert not _rule(p, "forward-30").enabled
    codes = {n.code for n in report.notes}
    assert {"VYOS_FORMAT", "VYOS_EMPTY_GROUP", "VYOS_QUEUE", "HOST_CHAIN_NOT_CONVERTED", "VYOS_ZONES", "VYOS_LOCAL_ZONE"} <= codes
    assert _nat(p, "source-100").source_translation == SourceNat(SnatKind.INTERFACE, interface="eth0")
    assert not _nat(p, "destination-30").enabled


def test_edgeos_sample() -> None:
    p, report = load("edgeos_sample.conf")
    assert set(p.zones) == {"pppoe0", "eth1", "eth1.10"}
    assert next(n for n in report.notes if n.code == "VYOS_FORMAT").message.startswith("read as the configuration of EdgeOS")
    assert _rule(p, "plex to the media box").src_zones == ["pppoe0"]
    assert _rule(p, "no media from the guests-3").dst_zones == ["eth1"]
    assert p.services[_rule(p, "ping the nas").services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    assert p.services[_rule(p, "Allow IPv6 ping").services[0]].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=128)]
    assert not _rule(p, "old rule").enabled
    assert _nat(p, "masquerade for WAN").source_translation == SourceNat(SnatKind.INTERFACE, interface="pppoe0")
    assert _nat(p, "web on 8443 to the nas").destination_translation == DestNat("192.168.1.20", "443")
    assert any(n.code == "PARTS_NOT_READ" and "port-forward" in n.message for n in report.notes)
    assert any(n.code == "HOST_CHAIN_NOT_CONVERTED" and "WAN_LOCAL" in n.message for n in report.notes)


# -- the emitter -----------------------------------------------------------------------------------


def _policy(*rules: Rule, zones: Tuple[str, ...] = ("lan", "wan")) -> Policy:
    p = Policy(vendor="panos")
    for zone in zones:
        p.zones[zone] = Zone(zone, [])
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def test_commands_only_add() -> None:
    out, report = run("vyos_sample.conf", "vyos")
    lines = [line for line in out.splitlines() if line and not line.startswith("#")]
    assert all(line.startswith("set ") for line in lines)
    assert not any(word in out for word in ("delete ", "\ncommit", "\nsave"))
    assert any(n.code == "VYOS_LOAD" for n in report.notes)
    for line in lines:
        words = shlex.split(line)
        if words[1:3] in (["firewall", "group"],):
            assert words[4].startswith("FWS-"), line
        if words[1:3] in (["firewall", "ipv4"], ["firewall", "ipv6"]) and words[3] == "name":
            assert words[4].startswith("FWS-"), line


def test_zones_pairs_and_intra_zone_filtering() -> None:
    allow = Rule("web", src_zones=["lan"], dst_zones=["wan"], destinations=["198.51.100.10"])
    p = _policy(allow)
    p.default_intrazone = Action.DENY
    out, report = _emitted(p, Options(interface_map={}))
    assert "set firewall zone wan from lan firewall name 'FWS-lan-wan'" in out
    assert "set firewall zone lan intra-zone-filtering action 'drop'" in out
    assert "set firewall ipv4 name FWS-wan-lan default-action 'drop'" in out  # (the replies of web)
    assert "ipv6 name FWS-lan-wan" not in out  # (no IPv6 rule, a default that drops, no replies to let through)
    assert "set firewall zone lan interface 'lan'" in out
    assert any(n.code == "INTERFACES_REQUIRED" for n in report.notes)
    p.zones["lan"].interfaces = ["ethernet1/2"]
    out, report = _emitted(p, Options(interface_map={"ethernet1/2": "eth2"}))
    assert "set firewall zone lan interface 'eth2'" in out


def test_flat_chain_and_rule_number() -> None:
    rule = Rule("r1", sources=["10.0.0.0/24"])
    p = _policy(rule, zones=())
    out, report = _emitted(p, Options(policy_id_start=77))
    assert "set firewall ipv4 forward filter rule 77 jump-target 'FWS-FORWARD'" in out
    assert "set firewall ipv6 forward filter rule 77" in out
    assert any(n.code == "VYOS_LOAD" and "rule 77" in n.message for n in report.notes)


def test_interfaces_in_no_zone_and_zones_that_are_interfaces() -> None:
    spoof = Rule("spoof", src_zones=["lan"], dst_zones=[ANY], sources=["10.0.0.0/24"], negate_source=True, action=Action.DROP)
    web = Rule("web", src_zones=["lan"], dst_zones=["wan"], destinations=["198.51.100.10"])
    out, report = _emitted(_policy(spoof, web))
    # From a zone to an interface in no zone: the rules for any destination in a chain jumped to from the forward filter.
    assert "set firewall ipv4 forward filter rule 10000 jump-target 'FWS-NO-ZONE'" in out
    assert "set firewall ipv4 forward filter rule 10000 outbound-interface group '!FWS-ZONES'" in out
    assert "set firewall group interface-group FWS-ZONES interface 'lan'" in out
    assert "set firewall ipv4 name FWS-NO-ZONE default-action 'drop'" in out
    assert "set firewall ipv4 name FWS-NO-ZONE rule 10 inbound-interface name 'lan'" in out
    assert "set firewall ipv4 name FWS-NO-ZONE rule 10 source address '!10.0.0.0/24'" in out
    assert "FWS-NO-ZONE rule 20" not in out  # (web goes to a zone)
    assert any(n.code == "VYOS_NO_ZONE" for n in report.notes)
    # Zones that are interfaces (iptables, rule-sets of VyOS 1.3 on interfaces): one chain whose rules match them.
    p = _policy(Rule("web", src_zones=["eth1"], dst_zones=["eth0"], destinations=["198.51.100.10"]),
                Rule("in", src_zones=["eth1"], dst_zones=["eth1"], scope=RuleScope.INTRAZONE), zones=())  # fmt: skip
    for zone in ("eth0", "eth1"):
        p.zones[zone] = Zone(zone, [zone])
    p.default_intrazone = Action.ALLOW
    out, report = _emitted(p)
    assert "set firewall zone" not in out and "set firewall ipv4 forward filter rule 10000 jump-target 'FWS-FORWARD'" in out
    assert "set firewall ipv4 name FWS-FORWARD rule 10 inbound-interface name 'eth1'" in out
    assert "set firewall ipv4 name FWS-FORWARD rule 10 outbound-interface name 'eth0'" in out
    assert "set firewall ipv4 name FWS-FORWARD rule 20 outbound-interface name 'eth1'" in out
    assert "set firewall ipv4 name FWS-FORWARD rule 30 action 'accept'" in out  # (inside eth0, as the policy's default)
    assert "set firewall ipv4 name FWS-FORWARD rule 30 inbound-interface name 'eth0'" in out
    assert any(n.code == "VYOS_LOAD" and "zones of the policy are interfaces" in n.message for n in report.notes)
    out, report = run("edgeos_sample.conf", "vyos")
    assert "set firewall zone" not in out and "inbound-interface name 'pppoe0'" in out


def test_services_protocols_and_negation() -> None:
    p = _policy(zones=())
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80"), ServiceEntry(Protocol.TCP, "443")])
    p.rules += [Rule("dns", services=["dns"], origin="dns"), Rule("sctp", services=["sctp"], origin="sctp"),
                Rule("not-gre", services=["gre"], negate_service=True, origin="not-gre", action=Action.DROP),
                Rule("not-web", services=["web"], negate_service=True, origin="not-web", action=Action.RESET_CLIENT),
                Rule("web", services=["web"], origin="web")]  # fmt: skip
    out, report = _emitted(p)
    assert "rule 10 protocol 'tcp_udp'" in out and "rule 10 destination port '53'" in out
    assert "protocol '!gre'" in out
    assert "destination port '80,443'" in out
    assert report.items[("rule", "sctp")].disabled
    assert "set firewall ipv4 name FWS-not-web-not default-action 'reject'" in out
    assert any(f.code == "VYOS_NEGATED_SERVICE" for f in report.items[("rule", "not-web")].findings)
    assert any(f.code == "RESET_ACTION" for f in report.items[("rule", "not-web")].findings)


def test_addresses_groups_and_host_names() -> None:
    p = _policy(zones=())
    p.addresses["a"] = Address("a", AddressKind.NETWORK, "10.0.0.0/24")
    p.addresses["b"] = Address("b", AddressKind.RANGE, "10.0.1.5-10.0.1.9")
    p.addresses["c"] = Address("c", AddressKind.NETWORK, "2001:db8::/64")
    p.addresses["h"] = Address("h", AddressKind.FQDN, "updates.example.com")
    from fwshift.model import AddressGroup

    p.address_groups["g"] = AddressGroup("g", ["a", "b", "c"])
    p.rules += [Rule("to-g", destinations=["g"], origin="to-g"), Rule("not-a", sources=["a"], negate_source=True, origin="not-a"),
                Rule("to-h", destinations=["h"], origin="to-h")]  # fmt: skip
    out, report = _emitted(p)
    assert "set firewall group address-group FWS-g address '10.0.0.0-10.0.0.255'" in out
    assert "set firewall group address-group FWS-g address '10.0.1.5-10.0.1.9'" in out
    assert "set firewall ipv6 name FWS-FORWARD rule 10 destination address '2001:db8::/64'" in out
    assert "source address '!10.0.0.0/24'" in out
    assert "destination fqdn 'updates.example.com'" in out
    assert any(n.code == "VYOS_FQDN" for n in report.notes)


def test_nat_written_as_vyos_nat_rules() -> None:
    p = _policy(zones=("wan", "dmz"))
    p.zones["wan"].interfaces = ["eth0"]
    p.zones["dmz"].interfaces = ["eth2", "eth3"]
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.nat_rules += [NatRule("web", src_zones=["wan"], dst_zones=["wan"], destinations=["203.0.113.10"], service="https",
                            destination_translation=DestNat("10.0.2.10", "8443"), origin="web"),
                    NatRule("out", dst_zones=["wan"], sources=["10.0.2.0/24"],
                            source_translation=SourceNat(SnatKind.INTERFACE), origin="out"),
                    NatRule("in", src_zones=["dmz"], dst_zones=["dmz"], destinations=["203.0.113.20"],
                            destination_translation=DestNat("10.0.2.20"), origin="in"),
                    NatRule("v6", destinations=["2001:db8::1"], destination_translation=DestNat("2001:db8::2"), origin="v6")]  # fmt: skip
    out, report = _emitted(p)
    assert "set nat destination rule 10000 inbound-interface name 'eth0'" in out
    assert "set nat destination rule 10000 translation port '8443'" in out
    assert "set nat source rule 10000 translation address 'masquerade'" in out
    assert "set nat destination rule 10010 inbound-interface group 'FWS-dmz-interfaces'" in out
    assert "set firewall group interface-group FWS-dmz-interfaces interface 'eth3'" in out
    assert report.items[("nat", "v6")].skipped


def test_sample_to_every_target_and_back() -> None:
    for target in cli.EMITTERS:
        out, report = run("vyos_sample.conf", target)
        assert out
    out, _ = run("vyos_sample.conf", "vyos")
    back, _ = parse_text(out)
    assert {"WAN", "LAN", "DMZ", "GUEST", "VPN"} <= set(back.zones)
