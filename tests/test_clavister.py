# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Clavister cOS Core: parser, emitter, and packet-level equivalence with a judge of its own.

``Gateway`` reads a cOS Core CLI script strictly, as the reading of Clavister's CLI Reference Guide and Administration
Guide would take it (every object defined once, whatever its case, and before it is used; only the properties of each
type; the entries of a rule set added in the order of their indexes; an IP rule of one IP version; SAT of IPv4 only), and
decides connections: ``main`` first, top to bottom, first match; a SAT rule is remembered (the first one for each
address) and the next matching Allow, NAT or FwdFast rule completes it, with the addresses before translation and the
interface the destination is routed to before translation (``core`` for an address of the firewall); a Drop or Reject
rule ends the lookup; a Goto jumps to its rule set, a Return goes back after it, and the end of a rule set reached by a
Goto drops; what nothing matches is dropped. The world (interfaces, their networks and addresses, the routes) is given to
it apart from the script, as the firewall has it. None of it shares code with the parser or the emitter.

The model's side is decided by ``ModelNat``: the first NAT rule that matches the connection as it arrives, then the first
security rule that matches the addresses before translation and the zone after it.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import ZONES as MODEL_ZONES
from test_iptables import Packet, _entry_matches, _member_matches, model_allows, random_model, random_packet

from fwshift import cli, transform
from fwshift.errors import ParseError
from fwshift.model import (
    ANY,
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
from fwshift.options import Options
from fwshift.parsers import clavister as parse_clavister
from fwshift.report import Report

PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}
ICMP = {"EchoReply": 0, "DestinationUnreachable": 3, "SourceQuenching": 4, "Redirect": 5, "EchoRequest": 8, "TimeExceeded": 11,
        "ParameterProblem": 12}  # fmt: skip
ICMP6 = {"DestinationUnreachable": 1, "PacketTooBig": 2, "TimeExceeded": 3, "ParameterProblem": 4, "EchoRequest": 128,
         "EchoReply": 129}  # fmt: skip
PROPERTIES = {
    "IP4Address": {"Address", "Comments"}, "IP6Address": {"Address", "Comments"}, "IP4Group": {"Members", "Comments"},
    "IP6Group": {"Members", "Comments"}, "InterfaceGroup": {"Members", "Equivalent", "Comments"},
    "ServiceTCPUDP": {"Type", "DestinationPorts", "SourcePorts", "Comments"}, "ServiceIPProto": {"IPProto", "Comments"},
    "ServiceICMP": {"MessageTypes", "Comments"} | set(ICMP) | {t + "Codes" for t in ICMP},
    "ServiceICMPv6": {"MessageTypes", "Comments"} | set(ICMP6) | {t + "Codes" for t in ICMP6},
    "ServiceGroup": {"Members", "Comments"}, "IPRuleSet": {"Comments"},
    "IPRule": {"Index", "Name", "Action", "SourceInterface", "SourceNetwork", "DestinationInterface", "DestinationNetwork",
               "Service", "LogEnabled", "Comments", "SATTranslate", "SATTranslateToIP", "SATTranslateToPort", "SATAllToOne",
               "NATAction", "NATSenderAddress"},
    "GotoRule": {"Index", "Name", "SourceInterface", "SourceNetwork", "DestinationInterface", "DestinationNetwork", "Service",
                 "RuleSet", "LogEnabled", "Comments"},
    "ReturnRule": {"Index", "Name", "SourceInterface", "SourceNetwork", "DestinationInterface", "DestinationNetwork", "Service",
                   "LogEnabled", "Comments"},
}  # fmt: skip
FILTER = ("SourceInterface", "SourceNetwork", "DestinationInterface", "DestinationNetwork", "Service")


def codes(report: Report) -> set:
    return {f.code for f in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def _interval(text: str) -> Tuple[int, int, int]:
    if "-" in text:
        first, last = (ipaddress.ip_address(t) for t in text.split("-"))
        assert first.version == last.version and int(first) <= int(last), text
        return first.version, int(first), int(last)
    net = ipaddress.ip_network(text, strict=False)
    return net.version, int(net.network_address), int(net.broadcast_address)


def _ranges(text: str, top: int) -> List[Tuple[int, int]]:
    out = []
    for part in text.split(","):
        first, _, last = part.strip().partition("-")
        assert first.isdigit() and (not last or last.isdigit()), text
        out.append((int(first), int(last or first)))
        assert out[-1][0] <= out[-1][1] <= top, text
    return out


def _words(line: str) -> List[str]:
    return [quoted or plain for quoted, plain in re.findall(r'(\S+="[^"]*")|(\S+)', line)]


# -- the world and the gateway ------------------------------------------------------------------------------------


@dataclass
class World:
    """What the firewall knows besides its rules: interfaces with their networks and own address, routes."""

    networks: Dict[str, List[str]]
    own: Dict[str, str] = field(default_factory=dict)  # an address of the firewall -> its interface
    routes: List[Tuple[str, str]] = field(default_factory=list)  # (network, interface)

    def routed(self, address: str) -> Optional[str]:
        """The interface a destination is routed to (core for an address of the firewall); None when none."""
        if address in self.own:
            return "core"
        best: Optional[Tuple[int, str]] = None
        probe = _interval(address)
        for interface, nets in list(self.networks.items()) + [(i, [n]) for n, i in self.routes]:
            for net in nets:
                version, first, last = _interval(net)
                if version == probe[0] and first <= probe[1] <= last and (best is None or last - first < best[0]):
                    best = (last - first, interface)
        return best[1] if best else None


@dataclass
class Verdict:
    allowed: bool
    destination: str = ""  # after translation
    source_nat: bool = False


class Gateway:
    """A cOS Core of the reading of the documentation: it takes a script line by line and decides connections."""

    def __init__(self, text: str, world: World, interfaces: Optional[List[str]] = None) -> None:
        self.world = world
        self.interfaces = set(interfaces if interfaces is not None else world.networks)
        self.addresses: Dict[str, List[Tuple[int, int, int]]] = {"all-nets": [_interval("0.0.0.0/0")], "all-nets6": [_interval("::/0")]}
        self.groups: Dict[str, List[str]] = {}
        self.services: Dict[str, List[Tuple[str, Dict[str, str]]]] = {"all_services": [("all", {})]}
        self.names = {"all-nets", "all-nets6", "all_services", "any", "core"}
        self.rulesets: Dict[str, List[Dict[str, str]]] = {"main": []}
        self.context = ""
        for line in text.splitlines():
            assert line == line.strip() and line, repr(line)
            self._line(line)

    def _define(self, name: str) -> None:
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", name), name
        assert name.lower() not in {n.lower() for n in self.names}, f"{name} defined twice"
        self.names.add(name)

    def _props(self, kind: str, words: List[str]) -> Dict[str, str]:
        props: Dict[str, str] = {}
        for word in words:
            key, equals, value = word.partition("=")
            assert equals and key in PROPERTIES[kind] and key not in props, (kind, word)
            if value.startswith('"'):
                assert value.endswith('"') and len(value) >= 2 and '"' not in value[1:-1] and "$" not in value, value
                value = value[1:-1]
            props[key] = value
        return props

    def _line(self, line: str) -> None:
        words = _words(line)
        if words == ["cc"]:
            self.context = ""
            return
        if words[0] == "cc":
            assert words[1] == "IPRuleSet" and words[2] in self.rulesets and len(words) == 3, line
            self.context = words[2]
            return
        if words[0] == "set":
            assert words[1] in ("IPRule", "GotoRule") and words[3] == "-disable" and len(words) == 4 and self.context, line
            entry = self.rulesets[self.context][int(words[2]) - 1]
            assert entry["_kind"] == words[1] and entry.get("_enabled") != "no", line
            entry["_enabled"] = "no"
            return
        assert words[0] == "add", line
        rest = words[1:]
        if rest[0] in ("Address", "Service"):
            rest = rest[1:]
        kind = rest[0]
        if kind in ("IPRule", "GotoRule", "ReturnRule"):
            assert self.context, line
            props = self._props(kind, rest[1:])
            entries = self.rulesets[self.context]
            assert props["Index"] == str(len(entries) + 1) or (self.context == "main" and int(props["Index"]) <= len(entries) + 1), line
            for key in FILTER:
                assert key in props, (key, line)
            self._check_filter(props, line)
            entry = dict(props, _kind=kind)
            entries.insert(int(props["Index"]) - 1, entry)
            if kind == "IPRule":
                assert props["Action"] in ("Allow", "NAT", "FwdFast", "Drop", "Reject", "SAT"), line
                if props["Action"] == "SAT":
                    assert props["SATTranslate"] in ("DestinationIP", "SourceIP"), line
                    target = self._resolve(props["SATTranslateToIP"])
                    assert len(target) == 1 and target[0][0] == 4, line
                    assert self._family(props) == 4, ("SAT of IPv6", line)
                else:
                    assert not any(k.startswith("SAT") for k in props), line
                if props["Action"] == "NAT":
                    assert self._family(props) == 4, ("NAT of IPv6", line)
                    if "NATAction" in props:
                        assert props["NATAction"] == "UseSenderAddress" and len(self._resolve(props["NATSenderAddress"])) == 1, line
                else:
                    assert "NATAction" not in props and "NATSenderAddress" not in props, line
            if kind == "GotoRule":
                assert props["RuleSet"] in self.rulesets and props["RuleSet"] != "main", line
            return
        assert not self.context, line
        name = rest[1]
        props = self._props(kind, rest[2:])
        if kind == "IPRuleSet":
            self._define(name)
            self.rulesets[name] = []
            return
        self._define(name)
        if kind in ("IP4Address", "IP6Address"):
            interval = _interval(props["Address"])
            assert interval[0] == (4 if kind == "IP4Address" else 6), line
            self.addresses[name] = [interval]
        elif kind in ("IP4Group", "IP6Group"):
            members = props["Members"].split(",")
            family = 4 if kind == "IP4Group" else 6
            for member in members:
                assert member in self.addresses or member in self.groups, (member, line)
                assert all(i[0] == family for i in self._resolve(member)), line
            self.groups[name] = members
        elif kind == "InterfaceGroup":
            members = props["Members"].split(",")
            assert members and all(m in self.interfaces for m in members), line
            self.groups[name] = members
            self.interfaces.add(name)
        elif kind == "ServiceGroup":
            members = props["Members"].split(",")
            assert all(m in self.services for m in members), line
            self.services[name] = [e for m in members for e in self.services[m]]
        else:
            if kind == "ServiceTCPUDP":
                assert props["Type"] in ("TCP", "UDP", "TCPUDP") and "DestinationPorts" in props, line
            if kind in ("ServiceICMP", "ServiceICMPv6"):
                assert props["MessageTypes"] in ("All", "Specific"), line
            self.services[name] = [(kind, props)]

    def _resolve(self, name: str) -> List[Tuple[int, int, int]]:
        if name in self.addresses:
            return self.addresses[name]
        if name in self.groups:
            return [i for m in self.groups[name] for i in self._resolve(m)]
        raise AssertionError(f"address {name} is not defined")

    def _family(self, props: Dict[str, str]) -> int:
        families = {i[0] for i in self._resolve(props["SourceNetwork"])} | {i[0] for i in self._resolve(props["DestinationNetwork"])}
        assert len(families) == 1, ("an IP rule of both IP versions", props)
        return families.pop()

    def _check_filter(self, props: Dict[str, str], line: str) -> None:
        for key in ("SourceInterface", "DestinationInterface"):
            assert props[key] in self.interfaces or props[key] == "any" or (key == "DestinationInterface" and props[key] == "core"), line
        self._family(props)
        assert props["Service"] in self.services, line

    # -- deciding ---------------------------------------------------------------------------------------------------

    def _iface(self, value: str, interface: str) -> bool:
        if value == "any":
            return True
        if value in self.groups and value not in self.addresses:
            return interface in self.groups[value]
        return value == interface

    def _has(self, name: str, address: str) -> bool:
        probe = _interval(address)
        return any(v == probe[0] and a <= probe[1] <= b for v, a, b in self._resolve(name))

    def _service(self, name: str, pkt: Packet) -> bool:
        number = PROTOCOL_NUMBERS.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        for kind, props in self.services[name]:
            if kind == "all":
                return True
            if kind == "ServiceTCPUDP":
                protocols = {"TCP": {"tcp"}, "UDP": {"udp"}, "TCPUDP": {"tcp", "udp"}}[props["Type"]]
                if pkt.proto in protocols and any(a <= pkt.dport <= b for a, b in _ranges(props["DestinationPorts"], 65535)) \
                        and any(a <= pkt.sport <= b for a, b in _ranges(props.get("SourcePorts", "0-65535"), 65535)):
                    return True
            elif kind in ("ServiceICMP", "ServiceICMPv6"):
                proto, table = ("icmp", ICMP) if kind == "ServiceICMP" else ("icmp6", ICMP6)
                if pkt.proto == proto and (props["MessageTypes"] == "All" or any(
                        props.get(t) == "Yes" and n == pkt.icmp_type and any(a <= 0 <= b for a, b in _ranges(props.get(t + "Codes", "0-255"), 255))
                        for t, n in table.items())):  # fmt: skip
                    return True
            elif kind == "ServiceIPProto":
                if any(a <= number <= b for a, b in _ranges(props["IPProto"], 255)):
                    return True
        return False

    def _matches(self, entry: Dict[str, str], pkt: Packet, arrives: str) -> bool:
        return (self._iface(entry["SourceInterface"], pkt.in_if) and self._iface(entry["DestinationInterface"], arrives)
                and self._has(entry["SourceNetwork"], pkt.src) and self._has(entry["DestinationNetwork"], pkt.dst)
                and self._service(entry["Service"], pkt))  # fmt: skip

    def decide(self, pkt: Packet) -> Verdict:
        arrives = self.world.routed(pkt.dst) or "none"
        sats: Dict[str, Dict[str, str]] = {}

        def walk(ruleset: str, called: bool) -> Optional[Tuple[str, Dict[str, str]]]:
            for entry in self.rulesets[ruleset]:
                if entry.get("_enabled") == "no" or not self._matches(entry, pkt, arrives):
                    continue
                kind = entry["_kind"]
                if kind == "GotoRule":
                    found = walk(entry["RuleSet"], True)
                    if found is not None and found[0] == "return":
                        continue
                    return found or ("drop", entry)
                if kind == "ReturnRule":
                    return ("return", entry) if called else ("drop", entry)
                action = entry["Action"]
                if action == "SAT":
                    sats.setdefault(entry["SATTranslate"], entry)
                    continue
                return action, entry
            return ("drop", {}) if called else None

        found = walk("main", False)
        if found is None or found[0] in ("Drop", "Reject", "drop", "return"):
            return Verdict(False)
        action, _ = found
        destination = pkt.dst
        sat = sats.get("DestinationIP")
        if sat is not None:
            target = self._resolve(sat["SATTranslateToIP"])[0]
            if sat.get("SATAllToOne") == "Yes":
                offset = 0
            else:
                offset = _interval(pkt.dst)[1] - self._resolve(sat["DestinationNetwork"])[0][1]
            destination = str(ipaddress.ip_address(target[1] + offset))
        return Verdict(True, destination, action == "NAT" or "SourceIP" in sats)


class ModelNat:
    """The model's verdict on a connection: the first NAT rule that matches it, then the first security rule."""

    def __init__(self, p: Policy, world: World, zone: Dict[str, str]) -> None:
        self.p, self.world, self.zone = p, world, zone  # zone: interface -> zone of the model

    def _pre_zone(self, address: str) -> str:
        if address in self.world.own:
            return self.zone[self.world.own[address]]
        return self.zone.get(self.world.routed(address) or "", "none")

    def decide(self, pkt: Packet) -> Verdict:
        p = self.p
        nat: Optional[NatRule] = None
        for rule in p.nat_rules:
            if not rule.enabled or rule.unsupported:
                continue
            if ANY not in rule.src_zones and pkt.in_if not in rule.src_zones:
                continue
            if ANY not in rule.dst_zones and self._pre_zone(pkt.dst) not in rule.dst_zones:
                continue
            if not any(_member_matches(p, m, pkt.src) for m in rule.sources):
                continue
            if not any(_member_matches(p, m, pkt.dst) for m in rule.destinations):
                continue
            if rule.service != ANY and not any(_entry_matches(e, pkt) for e in transform.flatten_services(p, rule.service) or []):
                continue
            nat = rule
            break
        destination = pkt.dst
        if nat is not None and nat.destination_translation is not None:
            after = transform.address_intervals(p, nat.destination_translation.address) or []
            before = [i for m in nat.destinations for i in (transform.address_intervals(p, m) or [])]
            offset = 0
            if after[0][2] > after[0][1]:
                offset = _interval(pkt.dst)[1] - before[0][1]
            destination = str(ipaddress.ip_address(after[0][1] + offset))
        if self.world.routed(destination) == "core":
            return Verdict(False, "core")  # (to the firewall itself: no policy of the model; what the firewall does is its own)
        out = self.zone.get(self.world.routed(destination) or "", "none")
        probe = Packet(pkt.in_if, out, pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        verdict = None
        for rule in p.rules:
            if not rule.enabled or rule.unsupported:
                continue
            if (ANY not in rule.src_zones and probe.in_if not in rule.src_zones) or (ANY not in rule.dst_zones and out not in rule.dst_zones):
                continue
            if any(_member_matches(p, m, probe.src) for m in rule.sources) == rule.negate_source:
                continue
            if any(_member_matches(p, m, probe.dst) for m in rule.destinations) == rule.negate_destination:
                continue
            if rule.services != [ANY]:
                entries = [e for s in rule.services for e in (transform.flatten_services(p, s) or [])]
                if any(_entry_matches(e, probe) for e in entries) == rule.negate_service:
                    continue
            verdict = rule.action == Action.ALLOW
            break
        if verdict is None:
            verdict = p.default_interzone == Action.ALLOW
        if not verdict:
            return Verdict(False)
        return Verdict(True, destination, nat is not None and nat.source_translation is not None)


# -- helpers ------------------------------------------------------------------------------------------------------


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_clavister.parse(text.encode("utf-8"), report), report


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import clavister as emit_clavister

    for item in list(model.rules) + list(model.nat_rules):
        item.origin = item.origin or item.name
    report = Report()
    return emit_clavister.emit(model, report, options or Options()), report


def sample() -> Tuple[Policy, Report]:
    return parse((DATA / "clavister_sample.sgs").read_text())


def rule_named(model: Policy, name: str) -> Rule:
    return next(r for r in model.rules if r.name == name)


def disabled_as_written(model: Policy, report: Report) -> Policy:
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for nat in model.nat_rules:
        if report.item("nat", nat.origin).skipped:
            nat.enabled = False
    return model


# -- the emitter against the model, without NAT --------------------------------------------------------------------

PLAIN = World({z: [] for z in MODEL_ZONES})


def plain_gateway(text: str) -> Gateway:
    return Gateway(text, PLAIN)


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = random_model(rng)
    for zone in MODEL_ZONES:
        model.zones[zone] = Zone(zone, [zone])
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW
    text, report = emit(model)
    gateway = plain_gateway(text)
    judged = disabled_as_written(model, report)
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 4, 6]))
        world = World({pkt.out_if: ["0.0.0.0/0", "::/0"]})
        gateway.world = world
        assert gateway.decide(pkt).allowed == model_allows(judged, pkt), (seed, pkt, text)


# -- the emitter against the model, with NAT -----------------------------------------------------------------------

NAT_WORLD = World({"eth0": ["10.0.0.0/24"], "eth1": ["10.0.1.0/24"], "eth2": ["198.51.100.0/24"]},
                  own={"198.51.100.1": "eth2"}, routes=[("0.0.0.0/0", "eth2")])  # fmt: skip
NAT_ZONES = {"eth0": "eth0", "eth1": "eth1", "eth2": "eth2"}
PUBLIC = ["198.51.100.1", "198.51.100.7", "198.51.100.8"]
INSIDE = ["10.0.0.5", "10.0.0.9", "10.0.1.5", "10.0.1.20"]


def nat_model(rng: random.Random) -> Policy:
    p = Policy(vendor="test", default_intrazone=Action.DROP, default_interzone=Action.DROP)
    for zone, nets in NAT_WORLD.networks.items():
        p.zones[zone] = Zone(zone, [zone])
        p.zone_networks[zone] = list(nets)
    p.addresses["pub1"] = Address("pub1", AddressKind.NETWORK, "198.51.100.1/32")
    p.addresses["pub7"] = Address("pub7", AddressKind.NETWORK, "198.51.100.7/32")
    p.addresses["pubs"] = Address("pubs", AddressKind.RANGE, "198.51.100.7-198.51.100.8")
    p.addresses["srv5"] = Address("srv5", AddressKind.NETWORK, "10.0.0.5/32")
    p.addresses["srvs"] = Address("srvs", AddressKind.RANGE, "10.0.1.5-10.0.1.6")
    p.addresses["lan0"] = Address("lan0", AddressKind.NETWORK, "10.0.0.0/24")
    p.addresses["lan1"] = Address("lan1", AddressKind.NETWORK, "10.0.1.0/24")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.UDP, "53")])
    zones = list(NAT_ZONES)
    for index in range(rng.randint(1, 3)):
        kind = rng.random()
        src_zone = [rng.choice(zones)] if rng.random() < 0.7 else [ANY]
        if kind < 0.5:
            pre, post = rng.choice([("pub1", "srv5"), ("pub7", "srv5"), ("pubs", "srvs"), ("pubs", "srv5")])
            nat = NatRule(f"dnat{index}", src_zones=src_zone, destinations=[pre], service=rng.choice([ANY, "web"]),
                          destination_translation=DestNat(post))  # fmt: skip
            if rng.random() < 0.3:
                nat.source_translation = SourceNat(SnatKind.INTERFACE)
        elif kind < 0.8:
            nat = NatRule(f"snat{index}", src_zones=src_zone, dst_zones=[rng.choice([ANY, "eth2"])],
                          sources=[rng.choice([ANY, "lan0", "lan1"])], source_translation=SourceNat(SnatKind.INTERFACE))  # fmt: skip
        else:
            nat = NatRule(f"none{index}", src_zones=src_zone, sources=[rng.choice(["lan0", "lan1"])], service=rng.choice([ANY, "dns"]))
        nat.origin = nat.name
        p.nat_rules.append(nat)
    for index in range(rng.randint(2, 7)):
        rule = Rule(f"r{index}", src_zones=[rng.choice(zones + [ANY])], dst_zones=[rng.choice(zones + [ANY, ANY])],
                    sources=[rng.choice([ANY, "lan0", "lan1", "198.51.100.0/24"])],
                    destinations=[rng.choice([ANY, "pub1", "pub7", "pubs", "srv5", "lan1", "198.51.100.0/24"])],
                    services=[rng.choice([ANY, "web", "dns"])], action=rng.choice([Action.ALLOW, Action.ALLOW, Action.DROP]))  # fmt: skip
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def nat_packet(rng: random.Random) -> Packet:
    proto = rng.choice(["tcp", "tcp", "udp", "icmp"])
    return Packet(rng.choice(list(NAT_ZONES)), "", rng.choice(INSIDE + PUBLIC + ["203.0.113.9"]), rng.choice(INSIDE + PUBLIC + ["203.0.113.9"]),
                  proto, 40000, rng.choice([80, 53, 22]), 8)  # fmt: skip


@pytest.mark.parametrize("seed", range(40))
def test_emitted_nat_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = nat_model(rng)
    text, report = emit(model)
    gateway = Gateway(text, NAT_WORLD)
    judged = disabled_as_written(model, report)
    oracle = ModelNat(judged, NAT_WORLD, NAT_ZONES)
    review = {o for (kind, o), item in report.items.items() if kind == "rule" and any(f.code in ("CLAVISTER_DNAT_ZONE", "CLAVISTER_NAT_PART") for f in item.findings)}
    order = any(f.code.startswith("NAT_ORDER") or f.code.startswith("NAT_") and f.code != "NAT_DISABLED"
                for item in report.items.values() for f in item.findings)  # fmt: skip
    if review or order:
        pytest.skip("the report says where the script differs")  # (the tests below require that most seeds do not)
    for _ in range(300):
        pkt = nat_packet(rng)
        mine, theirs = gateway.decide(pkt), oracle.decide(pkt)
        if theirs.destination == "core":
            continue
        assert (mine.allowed, mine.destination, mine.source_nat) == (theirs.allowed, theirs.destination, theirs.source_nat), \
            (seed, pkt, mine, theirs, text)


def test_most_nat_models_are_written_without_findings_that_say_they_differ() -> None:
    clean = 0
    for seed in range(40):
        model = nat_model(random.Random(seed))
        _, report = emit(model)
        if not any(f.severity >= 2 and f.code not in ("CLAVISTER_LOAD", "INTERFACES_REQUIRED")
                   for f in list(report.notes) + [f for i in report.items.values() for f in i.findings]):  # fmt: skip
            clean += 1
    assert clean >= 20


# -- random cOS Core configurations: the parser against the gateway ------------------------------------------------

ADDRESSES = {"lan0": "10.0.0.0/24", "lan1": "10.0.1.0/24", "srv5": "10.0.0.5", "srvb": "10.0.1.5", "srvs": "10.0.1.5-10.0.1.6", "pub1": "198.51.100.1",
             "pubs": "198.51.100.7-198.51.100.8", "half": "10.0.0.0/25"}  # fmt: skip
SERVICES = {"web": "add Service ServiceTCPUDP web Type=TCP DestinationPorts=80",
            "dns": "add Service ServiceTCPUDP dns Type=UDP DestinationPorts=53",
            "wd": "add Service ServiceTCPUDP wd Type=TCPUDP DestinationPorts=53,80",
            "ping": "add Service ServiceICMP ping MessageTypes=Specific EchoRequest=Yes"}  # fmt: skip


WORLD_LINES = ["set Interface Ethernet eth0 IP=10.0.0.1 Network=10.0.0.0/24", "set Interface Ethernet eth1 IP=10.0.1.1 Network=10.0.1.0/24",
               "set Interface Ethernet eth2 IP=198.51.100.1 Network=198.51.100.0/24", "cc RoutingTable main",
               "add Route Interface=eth2 Network=all-nets", "cc"]  # fmt: skip


def random_script(rng: random.Random) -> str:
    """The rule part of a random script: objects and rule sets (the gateway reads it; the parser reads WORLD_LINES first)."""
    lines = [f"add Address IP4Address {n} Address={v}" for n, v in ADDRESSES.items()] + list(SERVICES.values())
    lines += ["add InterfaceGroup inside Members=eth0,eth1"]
    interfaces = ["eth0", "eth1", "eth2", "inside", "any"]

    def entry(kind: str, index: int, action: str = "") -> str:
        dst_if = rng.choice(["eth0", "eth1", "eth2", "any", "core", "core"])
        words = [f"add {kind} Index={index} Name=e{rng.randrange(10**6)}"] + ([f"Action={action}"] if action else [])
        words += [f"SourceInterface={rng.choice(interfaces)}", f"SourceNetwork={rng.choice(['all-nets', 'lan0', 'lan1', 'half'])}",
                  f"DestinationInterface={dst_if}",
                  f"DestinationNetwork={rng.choice(['all-nets', 'pub1', 'pubs', 'lan1', 'srv5'])}",
                  f"Service={rng.choice(['all_services', 'web', 'dns', 'wd', 'ping'])}"]  # fmt: skip
        if action == "SAT":
            words += ["SATTranslate=DestinationIP", f"SATTranslateToIP={rng.choice(['srv5', 'srvb'])}"]
            if rng.random() < 0.5:
                words.append("SATAllToOne=Yes")
        return " ".join(words)

    sub = rng.random() < 0.4
    if sub:
        lines += ["add IPRuleSet extra", "cc IPRuleSet extra"]
        for index in range(1, rng.randint(2, 4)):
            lines.append(entry("IPRule", index, rng.choice(["Allow", "NAT", "Drop", "SAT"])))
        if rng.random() < 0.5:
            lines.append(entry("ReturnRule", index + 1))
        lines.append("cc")
    lines.append("cc IPRuleSet main")
    count = rng.randint(3, 9)
    for index in range(1, count + 1):
        if sub and rng.random() < 0.15:
            lines.append(entry("GotoRule", index) + " RuleSet=extra")
        else:
            lines.append(entry("IPRule", index, rng.choice(["Allow", "NAT", "FwdFast", "Drop", "Reject", "SAT", "SAT", "Allow"])))
    lines.append("cc")
    return "\n".join(lines) + "\n"


SCRIPT_WORLD = World({"eth0": ["10.0.0.0/24"], "eth1": ["10.0.1.0/24"], "eth2": ["198.51.100.0/24"]}, own={"198.51.100.1": "eth2"},
                     routes=[("0.0.0.0/0", "eth2")])  # fmt: skip


def test_parsed_configurations_decide_like_the_gateway() -> None:
    rng = random.Random(11)
    checked = clean = 0
    for seed in range(120):
        text = random_script(random.Random(seed))
        model, report = parse("\n".join(WORLD_LINES) + "\n" + text)
        core = "traffic to the firewall itself (core as the destination interface)"
        flagged = any(set(r.unsupported) - {core} for r in model.rules if r.enabled) or any(n.unsupported for n in model.nat_rules if n.enabled)
        flagged = flagged or any(f.severity >= 2 for i in report.items.values() for f in i.findings)
        if flagged:
            continue
        clean += 1
        gateway = Gateway(text.strip(), SCRIPT_WORLD)
        oracle = ModelNat(model, SCRIPT_WORLD, {"eth0": "eth0", "eth1": "eth1", "eth2": "eth2"})
        for _ in range(150):
            pkt = nat_packet(rng)
            mine, theirs = gateway.decide(pkt), oracle.decide(pkt)
            if theirs.destination == "core":
                continue
            assert (mine.allowed, mine.destination, mine.source_nat) == (theirs.allowed, theirs.destination, theirs.source_nat), \
                (seed, pkt, mine, theirs, text)
            checked += 1
    assert clean >= 50, clean


@pytest.mark.parametrize("seed", range(12))
def test_a_configuration_read_and_written_again_decides_the_same(seed: int) -> None:
    text = random_script(random.Random(seed))
    model, report = parse("\n".join(WORLD_LINES) + "\n" + text)
    core = "traffic to the firewall itself (core as the destination interface)"
    if any(set(r.unsupported) - {core} for r in model.rules if r.enabled) or any(n.unsupported for n in model.nat_rules if n.enabled) \
            or any(f.severity >= 2 for i in report.items.values() for f in i.findings):
        pytest.skip("the parser said what it could not read")
    out, out_report = emit(model)
    if any(f.code in ("CLAVISTER_DNAT_ZONE", "CLAVISTER_NAT_PART") or f.code.startswith("NAT_ORDER")
           for i in out_report.items.values() for f in i.findings):  # fmt: skip
        pytest.skip("the report says where the script differs")
    source = Gateway(text.strip(), SCRIPT_WORLD)
    written = Gateway(out, SCRIPT_WORLD)
    rng = random.Random(seed + 100)
    for _ in range(300):
        pkt = nat_packet(rng)
        mine, theirs = written.decide(pkt), source.decide(pkt)
        if SCRIPT_WORLD.routed(pkt.dst) == "core" and (not theirs.allowed or theirs.destination == pkt.dst):
            continue  # (traffic to the firewall itself, which the rules of core decide and which is not converted)
        assert (mine.allowed, mine.destination, mine.source_nat) == (theirs.allowed, theirs.destination, theirs.source_nat), \
            (seed, pkt, mine, theirs, out)


# -- the sample ---------------------------------------------------------------------------------------------------


def test_detection_and_errors() -> None:
    assert cli.detect_format((DATA / "clavister_sample.sgs").read_bytes()) == "clavister"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and "_sample." in path.name and path.name != "clavister_sample.sgs":
            assert not parse_clavister.looks_like_clavister(path.read_bytes()), path.name
    with pytest.raises(ParseError):
        parse("hello\nworld\n")


def test_sample_objects_and_zones() -> None:
    model, report = sample()
    assert list(model.zones) == ["lan", "dmz", "wan", "guest"]
    assert model.zone_networks["dmz"] == ["172.16.20.0/24", "172.16.0.0/16"]
    assert model.addresses["lan_net"].value == "192.168.10.0/24"  # (in the folder InterfaceAddresses)
    assert model.address_groups["admin_hosts"].members == ["admin_hosts#1", "admin_hosts#2", "admin_hosts#3"]
    assert model.addresses["pub_pool"].kind == AddressKind.RANGE
    assert model.addresses["updates"].kind == AddressKind.FQDN
    assert [(e.protocol, e.dst_ports) for e in model.services["dns-both"].entries] == [(Protocol.TCP, "53"), (Protocol.UDP, "53")]
    assert model.services["syslog"].entries[0].src_ports == "1024-65535"
    assert (model.services["echo-only"].entries[0].icmp_type, model.services["echo-only"].entries[0].icmp_code) == (8, 0)
    assert model.services["echo6"].entries[0].protocol == Protocol.ICMP6
    assert model.services["gre"].entries[0].ip_protocol == 47
    assert model.services["http-all"].builtin == "clavister"
    assert model.services["netbios-all"].unsupported
    assert "CLAVISTER_MISSING_OBJECT" in codes(report) and "CLAVISTER_PREDEFINED_SERVICE" in codes(report)


def test_sample_rules_in_order() -> None:
    model, report = sample()
    names = [r.name for r in model.rules]
    assert names[:3] == ["drop_netbios", "allow_web+sat_web", "block_bad_mail+sat_mail"]
    assert names.index("to_guest/guest_dns") < names.index("admin_mgmt") < names.index("lan_to_dmz") < names.index("DropAll")
    web = rule_named(model, "allow_web+sat_web")
    assert (web.src_zones, web.dst_zones, web.destinations) == (["wan"], ["dmz"], ["wan_ip"])  # (the zone after translation)
    mail = rule_named(model, "nat_mail+sat_mail")
    assert mail.src_zones == ["lan", "guest"]  # (the interface group inside)
    assert rule_named(model, "block_bad_mail+sat_mail").action == Action.RESET_CLIENT
    assert not rule_named(model, "old_rule").enabled
    assert rule_named(model, "gre_tunnel").schedule == "office_hours"
    assert "ping_fw" not in names and report.item("rule", "ping_fw").skipped  # (to core: the firewall itself, not converted, said)
    assert rule_named(model, "lan6_ping").destinations == ["::/0"]
    assert rule_named(model, "pol_dmz_out").profiles == {"web content filtering": "Yes"}
    assert rule_named(model, "old_rule").profiles["alg"].startswith("ftp-alg")
    assert not rule_named(model, "to_guest/guest_never").enabled  # (after a Return that takes everything back)
    assert "sat_web" not in names and "sat_unused" not in names  # (a SAT rule decides nothing)


def test_sample_nat() -> None:
    model, report = sample()
    nat = {n.name: n for n in model.nat_rules}
    assert nat["allow_web+sat_web"].destination_translation == DestNat("web_srv", "")
    assert nat["allow_web+sat_web"].dst_zones == ["wan"]  # (core: the interface that owns wan_ip)
    both = nat["nat_mail+sat_mail"]
    assert both.destination_translation.address == "mail_srv" and both.source_translation.kind == SnatKind.INTERFACE
    assert both.source_translation.interface == "dmz"  # (the interface after translation)
    assert nat["allow_pool+sat_pool"].destination_translation.address == "172.16.20.100/30"  # (transposed)
    assert nat["lan_web"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.11/32"])
    assert nat["lan_dns"].source_translation.interface_address == "203.0.113.10"
    assert nat["pol_dmz_https"].destination_translation == DestNat("web_srv", "8443")
    assert not nat["sat_unused"].enabled and "CLAVISTER_SAT_UNUSED" in codes(report)
    assert "block_bad_mail+sat_mail" not in nat  # (a Reject completes nothing)


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "clavister_sample.sgs").read_bytes()
    for target in cli.VENDORS:
        report = Report()
        policy = cli.load(data, "clavister", report)
        assert cli.convert(policy, target, report), target


# -- the traps, one by one ----------------------------------------------------------------------------------------

HEAD = """add Address IP4Address lan Address=10.1.0.0/24
add Address IP4Address pub Address=203.0.113.5
add Address IP4Address srv Address=10.2.0.10
add Address IP4Address srv2 Address=10.2.0.20
add Service ServiceTCPUDP web Type=TCP DestinationPorts=80
set Interface Ethernet lan IP=10.1.0.1 Network=lan
set Interface Ethernet dmz IP=10.2.0.1 Network=10.2.0.0/24
set Interface Ethernet wan IP=pub Network=203.0.113.0/24
cc IPRuleSet main
"""


def rules(*lines: str) -> Tuple[Policy, Report]:
    return parse(HEAD + "\n".join(lines) + "\ncc\n")


def test_first_match_and_the_silent_default() -> None:
    model, report = rules("add IPRule Name=a Action=Drop SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz "
                          "DestinationNetwork=srv Service=web",
                          "add IPRule Name=b Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz "
                          "DestinationNetwork=all-nets Service=all_services")  # fmt: skip
    assert [r.name for r in model.rules] == ["a", "b"]
    assert model.default_interzone == Action.DROP and model.default_intrazone == Action.DROP
    assert model_allows(model, Packet("lan", "dmz", "10.1.0.4", "10.2.0.10", "tcp", 1, 80)) is False
    assert model_allows(model, Packet("lan", "dmz", "10.1.0.4", "10.2.0.10", "tcp", 1, 81)) is True
    assert model_allows(model, Packet("dmz", "lan", "10.2.0.10", "10.1.0.4", "tcp", 1, 81)) is False


def test_a_sat_is_completed_by_the_next_allow_with_the_untranslated_address() -> None:
    model, _ = rules("add IPRule Name=s Action=SAT SourceInterface=wan SourceNetwork=all-nets DestinationInterface=core "
                     "DestinationNetwork=pub Service=web SATTranslateToIP=srv",
                     "add IPRule Name=wrong Action=Allow SourceInterface=wan SourceNetwork=all-nets DestinationInterface=dmz "
                     "DestinationNetwork=srv Service=web",
                     "add IPRule Name=a Action=Allow SourceInterface=wan SourceNetwork=all-nets DestinationInterface=core "
                     "DestinationNetwork=pub Service=web")  # fmt: skip
    oracle = ModelNat(model, World({"lan": ["10.1.0.0/24"], "dmz": ["10.2.0.0/24"], "wan": ["203.0.113.0/24"]}, own={"203.0.113.5": "wan"}),
                      {"lan": "lan", "dmz": "dmz", "wan": "wan"})  # fmt: skip
    verdict = oracle.decide(Packet("wan", "", "198.51.100.9", "203.0.113.5", "tcp", 1, 80))
    assert (verdict.allowed, verdict.destination) == (True, "10.2.0.10")
    # The rule that names the translated address does not complete it: it is the "common mistake" of the guide.
    assert rule_named(model, "wrong").destinations == ["srv"] and rule_named(model, "wrong").dst_zones == ["dmz"]
    assert [n.name for n in model.nat_rules] == ["a+s"] or [n.name for n in model.nat_rules][0].startswith("a")


def test_a_drop_after_a_sat_ends_the_lookup_and_the_first_sat_wins() -> None:
    model, _ = rules("add IPRule Name=s1 Action=SAT SourceInterface=any SourceNetwork=all-nets DestinationInterface=core "
                     "DestinationNetwork=pub Service=web SATTranslateToIP=srv",
                     "add IPRule Name=s2 Action=SAT SourceInterface=wan SourceNetwork=all-nets DestinationInterface=core "
                     "DestinationNetwork=pub Service=web SATTranslateToIP=srv2",
                     "add IPRule Name=d Action=Drop SourceInterface=wan SourceNetwork=198.51.100.0/24 DestinationInterface=core "
                     "DestinationNetwork=pub Service=web",
                     "add IPRule Name=a Action=Allow SourceInterface=any SourceNetwork=all-nets DestinationInterface=core "
                     "DestinationNetwork=pub Service=web")  # fmt: skip
    world = World({"lan": ["10.1.0.0/24"], "dmz": ["10.2.0.0/24"], "wan": ["203.0.113.0/24"]}, own={"203.0.113.5": "wan"})
    oracle = ModelNat(model, world, {"lan": "lan", "dmz": "dmz", "wan": "wan"})
    assert oracle.decide(Packet("wan", "", "198.51.100.9", "203.0.113.5", "tcp", 1, 80)).allowed is False
    verdict = oracle.decide(Packet("wan", "", "192.0.2.9", "203.0.113.5", "tcp", 1, 80))
    assert (verdict.allowed, verdict.destination) == (True, "10.2.0.10")  # (s1, not s2)


def test_a_goto_drops_at_the_end_of_its_rule_set_and_a_return_goes_back() -> None:
    text = ("cc\nadd IPRuleSet sub\ncc IPRuleSet sub\n"
            "add IPRule Name=x Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz DestinationNetwork=srv Service=web\n"
            "cc\ncc IPRuleSet main\n"
            "add GotoRule Name=g SourceInterface=lan SourceNetwork=lan DestinationInterface=any DestinationNetwork=all-nets "
            "Service=all_services RuleSet=sub\n"
            "add IPRule Name=after Action=Allow SourceInterface=any SourceNetwork=all-nets DestinationInterface=any "
            "DestinationNetwork=all-nets Service=all_services")  # fmt: skip
    model, report = rules(text)
    assert [r.name for r in model.rules] == ["g/x", "g/end", "after"]
    assert rule_named(model, "g/end").action == Action.DROP and rule_named(model, "g/end").sources == ["lan"]
    assert model_allows(model, Packet("lan", "dmz", "10.1.0.4", "10.2.0.11", "tcp", 1, 80)) is False  # (dropped at the end of sub)
    assert model_allows(model, Packet("dmz", "lan", "10.2.0.11", "10.1.0.4", "tcp", 1, 80)) is True
    with_return = text.replace("cc\ncc IPRuleSet main", "add ReturnRule Name=r SourceInterface=any SourceNetwork=all-nets "
                               "DestinationInterface=any DestinationNetwork=all-nets Service=all_services\ncc\ncc IPRuleSet main")  # fmt: skip
    model, _ = rules(with_return)
    assert [r.name for r in model.rules] == ["g/x", "after"]
    partial = text.replace("cc\ncc IPRuleSet main", "add ReturnRule Name=r SourceInterface=any SourceNetwork=10.1.0.0/25 "
                           "DestinationInterface=any DestinationNetwork=all-nets Service=all_services\ncc\ncc IPRuleSet main")  # fmt: skip
    model, report = rules(partial)
    assert "CLAVISTER_RETURN" in codes(report)  # (the end drops what the Return sends back: narrower, and said)


def test_folders_indexes_and_continued_lines() -> None:
    model, _ = rules("add IPRule Index=1 Name=second Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz "
                     "DestinationNetwork=srv Service=web",
                     "add IPRuleFolder Index=1 Name=f",
                     "cc IPRuleFolder f",
                     "Device:/main> add IPRule Name=first Action=Drop",
                     "\t\tSourceInterface=lan SourceNetwork=lan",
                     "\t\tDestinationInterface=dmz DestinationNetwork=srv Service=web",
                     "cc ..")  # fmt: skip
    assert [r.name for r in model.rules] == ["first", "second"]
    assert rule_named(model, "first").action == Action.DROP and not rule_named(model, "first").unsupported


def test_fwdfast_core_ipv6_and_what_is_never_read_wider() -> None:
    model, report = rules(
        "add IPRule Name=ff Action=FwdFast SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz DestinationNetwork=srv Service=web",
        "add IPRule Name=fw Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=core DestinationNetwork=10.1.0.1 Service=web",
        "add IPRule Name=odd Action=Bounce SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz DestinationNetwork=srv Service=web",
        "add IPRule Name=nosvc Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz DestinationNetwork=srv",
        "add IPRule Name=ghost Action=Allow SourceInterface=lan SourceNetwork=lan_net9 DestinationInterface=dmz DestinationNetwork=srv Service=web",
        "add IPRule Name=users Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=dmz DestinationNetwork=srv Service=web "
        "AppControl=Yes",
        "add IPRule Name=v6 Action=Allow SourceInterface=lan SourceNetwork=all-nets6 DestinationInterface=dmz DestinationNetwork=all-nets6 "
        "Service=all_services")  # fmt: skip
    assert "CLAVISTER_FWDFAST" in {f.code for f in report.item("rule", "ff").findings}
    assert "fw" not in [r.name for r in model.rules] and "CLAVISTER_CORE_RULE" in codes(report)
    assert rule_named(model, "odd").unsupported and rule_named(model, "nosvc").unsupported
    assert model.addresses["lan_net9"].kind == AddressKind.UNSUPPORTED
    assert rule_named(model, "users").unsupported
    assert rule_named(model, "v6").sources == ["::/0"]


def test_ip_policies_translate_themselves() -> None:
    model, report = rules(
        "add IPPolicy Name=in Action=Allow SourceInterface=wan SourceNetwork=all-nets DestinationInterface=core DestinationNetwork=pub "
        "Service=web DestAddressTranslation=SAT DestAddressAction=SingleIP DestNewIP=srv",
        "add IPPolicy Name=out Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=wan DestinationNetwork=all-nets "
        "Service=all_services SourceAddressTranslation=NAT",
        "add IPPolicy Name=no Action=Deny Reject=Yes SourceInterface=any SourceNetwork=all-nets DestinationInterface=dmz "
        "DestinationNetwork=srv2 Service=all_services",
        "add IPPolicy Name=auto Action=Allow SourceInterface=dmz SourceNetwork=10.2.0.0/24 DestinationInterface=wan "
        "DestinationNetwork=all-nets Service=web SourceAddressTranslation=Auto")  # fmt: skip
    assert rule_named(model, "in").dst_zones == ["dmz"]
    nat = {n.name: n for n in model.nat_rules}
    assert nat["in"].destination_translation.address == "srv" and nat["out"].source_translation.kind == SnatKind.INTERFACE
    assert rule_named(model, "no").action == Action.RESET_CLIENT
    assert nat["auto"].unsupported  # (Auto: chosen by the addresses, not converted)


def test_an_allow_above_a_nat_rule_is_an_exemption() -> None:
    model, report = rules(
        "add IPRule Name=keep Action=Allow SourceInterface=lan SourceNetwork=lan DestinationInterface=wan DestinationNetwork=203.0.113.0/24 "
        "Service=all_services",
        "add IPRule Name=hide Action=NAT SourceInterface=lan SourceNetwork=lan DestinationInterface=wan DestinationNetwork=all-nets "
        "Service=all_services")  # fmt: skip
    nat = [n for n in model.nat_rules]
    assert [n.name for n in nat] == ["keep", "hide"]
    assert nat[0].source_translation is None and nat[0].destination_translation is None
    assert "CLAVISTER_NO_NAT" in codes(report)


# -- the emitter ---------------------------------------------------------------------------------------------------


def small() -> Policy:
    p = Policy(vendor="test", default_intrazone=Action.DROP, default_interzone=Action.DROP)
    for zone in ("inside", "outside", "dmz"):
        p.zones[zone] = Zone(zone, [zone])
    p.addresses["net"] = Address("net", AddressKind.NETWORK, "10.1.0.0/24")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8:1::/64")
    p.addresses["host"] = Address("host", AddressKind.FQDN, "www.example.com")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["odd"] = Service("odd", [ServiceEntry(Protocol.ICMP, icmp_type=13)])
    return p


def test_emitter_writes_objects_rules_goto_and_return() -> None:
    p = small()
    p.rules = [Rule("a", ["inside"], ["outside"], ["net", "six"], [ANY], ["web"]),
               Rule("b", ["inside"], ["dmz"], [ANY], ["host"], ["web"], action=Action.DROP),
               Rule("c", ["inside"], ["dmz"], ["net"], [ANY], ["odd"]),
               Rule("d", ["dmz"], ["inside"], ["net"], [ANY], [ANY], negate_source=True, action=Action.RESET_CLIENT)]  # fmt: skip
    text, report = emit(p)
    gateway = Gateway(text, World({z: [] for z in p.zones}))
    lines = text.splitlines()
    assert lines[-5:-3] == ["cc", "cc IPRuleSet main"] and lines[-1] == "cc" and lines[-3].startswith("add GotoRule Index=1 Name=fws_goto ")
    assert "RuleSet=fws_rules" in lines[-3] and "SourceInterface=fws_zones" in lines[-3] and "all-nets6" in lines[-2]
    entries = gateway.rulesets["fws_rules"]
    assert [e["Name"] for e in entries][:3] == ["fws_a", "fws_a_v6", "fws_b"]
    assert entries[-1]["_kind"] == "ReturnRule" and entries[-2]["_kind"] == "ReturnRule"
    assert entries[2].get("_enabled") == "no" and report.item("rule", "b").disabled  # (a host name)
    assert report.item("rule", "c").disabled  # (ICMP type 13 has no name in a ServiceICMP)
    assert entries[-4]["Name"] == "fws_default" and entries[-4]["DestinationInterface"] == "fws_zones"
    assert not any(" delete " in f" {line} " or line in ("activate", "commit") for line in lines)
    assert "INTERFACES_REQUIRED" in codes(report) and "CLAVISTER_LOAD" in codes(report)
    d = next(e for e in entries if e["Name"] == "fws_d")
    assert d["Action"] == "Reject" and d["SourceNetwork"].startswith("fws_d_src_not")


def test_emitter_nat_is_sat_at_the_top_and_nat_actions_in_place() -> None:
    p = small()
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.5/32")
    p.addresses["srv"] = Address("srv", AddressKind.NETWORK, "10.3.0.10/32")
    p.zone_networks = {"inside": ["10.1.0.0/24"], "dmz": ["10.3.0.0/24"], "outside": ["0.0.0.0/0"]}
    p.nat_rules = [NatRule("pf", ["outside"], [ANY], [ANY], ["pub"], "web", destination_translation=DestNat("srv"), origin="pf"),
                   NatRule("hide", ["inside"], ["outside"], ["net"], [ANY], ANY, SourceNat(SnatKind.INTERFACE), origin="hide"),
                   NatRule("v6", ["inside"], ["outside"], ["six"], [ANY], ANY, SourceNat(SnatKind.INTERFACE), origin="v6")]  # fmt: skip
    p.rules = [Rule("in", ["outside"], ["dmz"], [ANY], ["pub"], ["web"]),
               Rule("out", ["inside"], ["outside"], ["net"], [ANY], [ANY])]  # fmt: skip
    text, report = emit(p)
    world = World({"inside": ["10.1.0.0/24"], "dmz": ["10.3.0.0/24"], "outside": ["203.0.113.0/24"]}, own={"203.0.113.5": "outside"},
                  routes=[("0.0.0.0/0", "outside")])  # fmt: skip
    gateway = Gateway(text, world)
    entries = gateway.rulesets["fws_rules"]
    assert entries[0]["Action"] == "SAT" and entries[0]["DestinationInterface"] == "any"
    verdict = gateway.decide(Packet("outside", "", "198.51.100.4", "203.0.113.5", "tcp", 1, 443))
    assert (verdict.allowed, verdict.destination, verdict.source_nat) == (True, "10.3.0.10", False)
    verdict = gateway.decide(Packet("inside", "", "10.1.0.4", "192.0.2.1", "udp", 1, 53))
    assert (verdict.allowed, verdict.source_nat) == (True, True)
    assert report.item("nat", "v6").skipped and "CLAVISTER_IPV4_NAT" in codes(report)


def test_emitter_prefix_and_its_rules() -> None:
    p = small()
    p.rules = [Rule("a", ["inside"], ["outside"], ["net"], [ANY], ["web"])]
    text, _ = emit(p, Options(object_prefix="cv-"))
    assert "add IPRuleSet cv-rules" in text and "Name=cv-a " in text
    with pytest.raises(Exception):
        emit(p, Options(object_prefix="1bad"))


def test_emitter_without_zones_says_so() -> None:
    p = small()
    p.zones = {}
    p.rules = [Rule("a", [ANY], [ANY], ["net"], [ANY], ["web"])]
    text, report = emit(p)
    assert "CLAVISTER_NO_ZONES" in codes(report)
    assert "SourceInterface=any" in text and "fws_default" not in text


def test_the_parser_reads_what_the_emitter_writes() -> None:
    model, _ = sample()
    text, _ = emit(model)
    back, report = parse(text)
    names = [r.name for r in back.rules]
    assert names[0].startswith("fws_goto/") and any(n.endswith("fws_lan_to_dmz") for n in names)
    lan_to_dmz = next(r for r in back.rules if r.name.endswith("fws_lan_to_dmz"))
    assert (lan_to_dmz.src_zones, lan_to_dmz.dst_zones, lan_to_dmz.sources) == (["lan"], ["dmz"], ["fws_lan_net"])
    assert any(n.destination_translation is not None for n in back.nat_rules)


def test_same_vendor_round_trip_of_the_sample() -> None:
    model, _ = sample()
    text, report = emit(model)
    world = World({"lan": ["192.168.10.0/24"], "dmz": ["172.16.0.0/16"], "wan": ["203.0.113.0/24"], "guest": ["10.30.0.0/24"]},
                  own={"203.0.113.10": "wan", "203.0.113.12": "wan", "192.168.10.1": "lan"}, routes=[("0.0.0.0/0", "wan")])  # fmt: skip
    judged = disabled_as_written(model, report)
    oracle = ModelNat(judged, world, {z: z for z in ("lan", "dmz", "wan", "guest")})
    gateway = _sample_gateway(text, world)
    rng = random.Random(5)
    for _ in range(3000):
        src = rng.choice(["192.168.10.7", "10.30.0.9", "172.16.20.9", "198.51.100.3", "203.0.113.99"])
        dst = rng.choice(["203.0.113.10", "203.0.113.12", "203.0.113.21", "172.16.20.80", "172.16.20.25", "192.168.10.50",
                          "198.51.100.7", "203.0.113.88"])  # fmt: skip
        pkt = Packet(rng.choice(["lan", "dmz", "wan", "guest"]), "", src, dst, rng.choice(["tcp", "udp", "icmp", "47"]),
                     rng.choice([1500, 40000]), rng.choice([25, 53, 80, 443, 514, 8080, 21]), 8)  # fmt: skip
        mine, theirs = gateway.decide(pkt), oracle.decide(pkt)
        if theirs.destination == "core":
            continue
        assert mine.allowed == theirs.allowed and (not mine.allowed or mine.destination == theirs.destination), (pkt, mine, theirs)


def _sample_gateway(text: str, world: World) -> Gateway:
    """The gateway for the sample's output, with the predefined services it names defined as the parser reads them."""
    defined = ["add Service ServiceTCPUDP http-all Type=TCP DestinationPorts=80,443",
               "add Service ServiceTCPUDP https Type=TCP DestinationPorts=443",
               "add Service ServiceTCPUDP dns-all Type=TCPUDP DestinationPorts=53",
               "add Service ServiceTCPUDP ssh Type=TCP DestinationPorts=22"]  # fmt: skip
    gateway = Gateway("\n".join(defined), world, interfaces=list(world.networks))
    gateway.names -= {"http-all", "https", "dns-all", "ssh"}
    for line in text.splitlines():
        gateway._line(line)
    return gateway
