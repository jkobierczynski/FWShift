# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Belden/Hirschmann HiSecOS: parser, emitter, and packet-level equivalence with judges of their own.

``Eagle`` reads the script the emitter writes strictly, as a device of the reading of Belden's HM2-FW-MIB and HM2-NAT-MIB
would take it (every rule index once and from 1 to 2048, one source and one destination of the documented forms, a
``!`` before a source only, ports only with tcp and udp and at most 15 per field, ICMP parameters only with icmp, an
assignment only of a rule that exists), and decides packets: the rules with an enabled assignment that fits the
interface the packet arrives on and the one it leaves by ("arriving on the ingress interface AND to-be leaving on the
egress interface"; a rule without one of them for every interface of that direction), in the order of their
priorities, first match, then the device's default policy.

A random HiSecOS configuration is a plain description that ``render`` writes as a script and ``Judge`` decides packets
from with the same reading (``both`` as two placements, a rule assigned for ingress only at the priority of each of its
assignments). None of it shares code with the parser or the emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import re
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import ZONES as MODEL_ZONES
from test_iptables import Packet, model_allows, random_model

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.model import (
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
    SnatKind,
    SourceNat,
    Zone,
)
from fwshift.options import Options
from fwshift.parsers import hisecos as parse_hisecos
from fwshift.report import Report

NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "ipip": 4, "esp": 50, "ah": 51}
INTERFACE = re.compile(r"^(\d+/\d+|vlan/\d+)$")
PORTS = (1, 65535)


def codes(report: Report) -> set:
    return {f.code for f in report.notes} | {f.code for item in report.items.values() for f in item.findings}


# -- the reader of the emitted script ---------------------------------------------------------------------------


def _address_ok(text: str, source: bool) -> bool:
    if text == "any":
        return True
    if text.startswith("!"):
        if not source:
            return False
        text = text[1:]
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        return False
    return network.version == 4 and ("/" in text or network.prefixlen == 32)


def _ports(text: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    slots = 0
    for part in text.split(","):
        first, _, last = part.partition("-")
        assert first.isdigit() and (not last or last.isdigit()), text
        out.append((int(first), int(last or first)))
        assert out[-1][0] <= out[-1][1] <= 65535, text
        slots += 2 if last else 1
    assert slots <= 15, text
    return out


class Eagle:
    """A device as the documentation reads: rules, assignments, NAT rules."""

    WORDS = {"srcip", "dstip", "srcport", "dstport", "proto", "param", "action", "log", "trap", "description"}

    def __init__(self, text: str, default: str = "accept") -> None:
        self.rules: Dict[int, Dict[str, Any]] = {}
        self.maps: List[Dict[str, Any]] = []
        self.nat: Dict[Tuple[str, int], Dict[str, str]] = {}
        self.nat_maps: List[Tuple[str, str, int, str, int]] = []
        self.default = default
        for line in text.splitlines():
            assert line == line.strip() and line, repr(line)
            words = line.split()
            if words[:2] == ["packet-filter", "l3"]:
                self._filter(words[2:], line)
            elif words[0] == "nat":
                self._nat(words[1:], line)
            else:
                raise AssertionError(f"a command the reader does not take: {line}")

    def _pairs(self, words: List[str], allowed: set, line: str) -> Dict[str, str]:
        assert len(words) % 2 == 0, line
        fields: Dict[str, str] = {}
        for key, value in zip(words[0::2], words[1::2]):
            assert key in allowed and key not in fields, line
            fields[key] = value
        return fields

    def _filter(self, words: List[str], line: str) -> None:
        command = words[0]
        if command == "addrule":
            index = int(words[1])
            assert 1 <= index <= 2048 and index not in self.rules, line
            fields = self._pairs(words[2:], self.WORDS, line)
            assert _address_ok(fields.get("srcip", "any"), True) and _address_ok(fields.get("dstip", "any"), False), line
            proto = fields.get("proto", "any")
            assert proto in NUMBERS or proto == "any", line
            for key in ("srcport", "dstport"):
                if key in fields:
                    assert proto in ("tcp", "udp"), line
                    _ports(fields[key])
            if "param" in fields:
                assert proto == "icmp" and re.fullmatch(r"type=\d+(,code=\d+)?", fields["param"]), line
            assert fields["action"] in ("accept", "drop", "reject"), line
            assert fields["log"] in ("enable", "disable") and fields["trap"] in ("enable", "disable"), line
            assert 1 <= len(fields["description"]) <= 32 and re.fullmatch(r"[A-Za-z0-9._-]+", fields["description"]), line
            self.rules[index] = {"fields": fields, "enabled": None}
        elif command in ("enablerule", "disablerule"):
            index = int(words[1])
            assert len(words) == 2 and index in self.rules and self.rules[index]["enabled"] is None, line
            self.rules[index]["enabled"] = command == "enablerule"
        elif command == "addif":
            assert len(words) == 8 and words[2] == "rule" and words[4] == "direction" and words[6] == "priority", line
            index = int(words[3])
            assert index in self.rules and words[5] in ("ingress", "egress"), line
            self.maps.append({"if": words[1], "index": index, "dir": words[5], "prio": int(words[7])})
        else:
            raise AssertionError(line)

    def _nat(self, words: List[str], line: str) -> None:
        kind = words[0]
        assert kind in ("dnat", "masq", "1to1nat"), line
        if words[1] == "add":
            index = int(words[2])
            assert (kind, index) not in self.nat and 1 <= index <= (128 if kind == "masq" else 255), line
            allowed = {"dnat": {"srcip", "srcport", "dstip", "dstport", "proto", "newdstip", "newdstport", "description"},
                       "masq": {"srcip", "srcport", "proto", "description"},
                       "1to1nat": {"dstip", "newdstip", "ingress-if", "egress-if", "priority", "description"}}[kind]  # fmt: skip
            self.nat[(kind, index)] = self._pairs(words[3:], allowed, line)
        else:
            assert words[1:3] == ["if", "add"] and kind in ("dnat", "masq") and len(words) == 10, line
            index = int(words[5])
            assert (kind, index) in self.nat and words[7] == ("ingress" if kind == "dnat" else "egress"), line
            self.nat_maps.append((kind, words[3], index, words[7], int(words[9])))

    # -- deciding ---------------------------------------------------------------------------------------------------

    @staticmethod
    def _in(address: str, spec: str) -> bool:
        if spec == "any":
            return True
        negated = spec.startswith("!")
        inside = ipaddress.ip_address(address) in ipaddress.ip_network(spec.lstrip("!"))
        return inside != negated

    def _matches(self, fields: Dict[str, str], pkt: Packet) -> bool:
        if ":" in pkt.src or ":" in pkt.dst:
            return False  # (the device forwards IPv4)
        if not self._in(pkt.src, fields.get("srcip", "any")) or not self._in(pkt.dst, fields.get("dstip", "any")):
            return False
        proto = fields.get("proto", "any")
        if proto != "any" and str(NUMBERS[proto]) != str(NUMBERS.get(pkt.proto, pkt.proto)):
            return False
        if "dstport" in fields and not any(a <= pkt.dport <= b for a, b in _ports(fields["dstport"])):
            return False
        if "srcport" in fields and not any(a <= pkt.sport <= b for a, b in _ports(fields["srcport"])):
            return False
        if "param" in fields:
            params = dict(part.split("=") for part in fields["param"].split(","))
            if int(params["type"]) != pkt.icmp_type:
                return False
        return True

    def allows(self, pkt: Packet, ingress: str, egress: str) -> bool:
        order: List[Tuple[int, int]] = []
        for index, rule in self.rules.items():
            maps = [m for m in self.maps if m["index"] == index]
            if not rule["enabled"] or not maps:
                continue
            ins = {m["if"] for m in maps if m["dir"] == "ingress"}
            outs = {m["if"] for m in maps if m["dir"] == "egress"}
            assert len({m["prio"] for m in maps}) == 1  # (the emitter gives a rule one priority)
            if (not ins or ingress in ins) and (not outs or egress in outs):
                order.append((maps[0]["prio"], index))
        for _, index in sorted(order):
            if self._matches(self.rules[index]["fields"], pkt):
                return bool(self.rules[index]["fields"]["action"] == "accept")
        return self.default == "accept"


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import hisecos as emit_hisecos

    for item in list(model.rules) + list(model.nat_rules):
        item.origin = item.origin or item.name  # (the report is keyed by origin, as cli.convert sees to)
    report = Report()
    return emit_hisecos.emit(model, report, options or Options()), report


IFACES = {"eth0": "1/1", "eth1": "1/2", "eth2": "vlan/30"}


def zoned(model: Policy) -> Policy:
    for zone in MODEL_ZONES:
        model.zones[zone] = Zone(zone, [IFACES[zone]])
    return model


def ipv4_packet(rng: random.Random) -> Packet:
    src = f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}"
    dst = f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}"
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47", "50"])
    pkt = Packet(rng.choice(MODEL_ZONES), rng.choice(MODEL_ZONES), src, dst, proto, rng.choice([1024, 40000, 1500]),
                 rng.choice([22, 53, 80, 443, 8000, 8005, 8080, 9000, 7999, 8011]), rng.choice([0, 8, 13]))  # fmt: skip
    if rng.random() < 0.2:
        pkt.dport = rng.choice([79, 81, 442, 444, 8010, 8012, 0, 65535])
    return pkt


def compare(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    """The emitted script against the model (zones eth0, eth1, eth2 on 1/1, 1/2, vlan/30), on IPv4 packets."""
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (written disabled, and said)
    count = 0
    for default in ("accept", "drop"):
        device = Eagle(text, default)  # (whatever the device's default, the script decides)
        for _ in range(packets // 2):
            pkt = ipv4_packet(rng)
            verdict = device.allows(pkt, IFACES[pkt.in_if], IFACES[pkt.out_if])
            assert verdict == model_allows(model, pkt), (seed, default, pkt, text)
            count += 1
    return count


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = zoned(random_model(rng))
    for rule in model.rules:
        rule.log_start = rng.random() < 0.2
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW  # (the model's judge knows one default)
    text, report = emit(model)
    assert compare(model, report, text, rng, seed) == 400


# -- random HiSecOS configurations ------------------------------------------------------------------------------

DEVICE_IFS = ["1/1", "1/2", "1/3", "vlan/20"]
NETS = ["10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/25", "10.0.2.16/28", "10.0.0.17", "10.0.0.0/16", "10.0.3.0/24"]


def random_conf(rng: random.Random) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    for number in range(rng.randint(3, 10)):
        rule: Dict[str, Any] = {"index": rng.randint(1, 60) * 10 + number, "action": rng.choice(["accept", "accept", "drop", "reject"])}
        rule["src"] = rng.choice(["any"] + NETS + ["!" + n for n in NETS[:3]])
        rule["dst"] = rng.choice(["any"] + NETS)
        kind = rng.random()
        if kind < 0.4:
            rule["proto"] = rng.choice(["tcp", "udp"])
            if rng.random() < 0.7:
                rule["dport"] = rng.choice(["80", "22,80,443", "8000-8010", "53", "8000-8005,9000"])
            if rng.random() < 0.2:
                rule["sport"] = rng.choice(["1024-65535", "1500"])
        elif kind < 0.55:
            rule["proto"] = "icmp"
            if rng.random() < 0.5:
                rule["param"] = f"type={rng.choice([0, 8, 13])}"
        elif kind < 0.65:
            rule["proto"] = rng.choice(["esp", "igmp"])
        else:
            rule["proto"] = "any"
        rule["enabled"] = rng.random() > 0.1
        shape = rng.random()
        ifs = rng.sample(DEVICE_IFS, rng.randint(1, 2))
        prio = rng.randint(1, 30)
        if shape < 0.45:
            rule["maps"] = [(i, "ingress", rng.choice([prio, prio, rng.randint(1, 30)])) for i in ifs]
        elif shape < 0.6:
            rule["maps"] = [(i, "egress", prio) for i in ifs]
        elif shape < 0.8:
            out = rng.choice(DEVICE_IFS)
            rule["maps"] = [(i, "ingress", prio) for i in ifs] + [(out, "egress", prio)]
        elif shape < 0.92:
            rule["maps"] = [(ifs[0], "both", prio)]
        else:
            rule["maps"] = []
        rules.append(rule)
    seen: Dict[int, int] = {}
    for rule in rules:  # (indexes once)
        while rule["index"] in seen:
            rule["index"] += 1
        seen[rule["index"]] = 1
    return {"default": rng.choice(["accept", "drop", None]), "rules": rules}


def render(conf: Dict[str, Any], rng: random.Random) -> str:
    lines = ["!synthetic", "vlan database", "vlan add 20", "routing add 20", "exit", "interface 1/1",
             "ip address primary 10.0.0.1 255.255.255.0", "ip routing", "exit", "interface 1/2", "ip routing", "exit",
             "interface 1/3", "ip routing", "exit"]  # (every routing interface: the script decides for those it knows)
    if conf["default"]:
        lines.append(f"packet-filter l3 defaultpolicy {conf['default']}")
    for rule in rng.sample(conf["rules"], len(conf["rules"])):
        words = [f"packet-filter l3 addrule {rule['index']}", f"srcip {rule['src']}", f"dstip {rule['dst']}"]
        if rng.random() < 0.5 or rule["proto"] != "any":
            words.append(f"proto {rule['proto']}")
        for key, word in (("dport", "dstport"), ("sport", "srcport"), ("param", "param")):
            if key in rule:
                words.append(f"{word} {rule[key]}")
        words.append(f"action {rule['action']}")
        if rng.random() < 0.5:
            words.append(f'description "rule {rule["index"]}"')
        lines.append(" ".join(words))
        if not rule["enabled"]:
            lines.append(f"packet-filter l3 disablerule {rule['index']}")
    for rule in conf["rules"]:
        for interface, direction, prio in rule["maps"]:
            lines.append(f"packet-filter l3 addif {interface} rule {rule['index']} direction {direction} priority {prio}")
    return "\n".join(lines) + "\n"


class Judge:
    """Decides packets from a random configuration as the MIB reads."""

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.default = conf["default"] or "accept"
        self.order: List[Tuple[int, int, int, set, set, Dict[str, Any]]] = []
        for rule in conf["rules"]:
            if not rule["enabled"] or not rule["maps"]:
                continue
            ins = [(i, p) for i, d, p in rule["maps"] if d == "ingress"]
            outs = [(i, p) for i, d, p in rule["maps"] if d == "egress"]
            both = [(i, p) for i, d, p in rule["maps"] if d == "both"]
            if both:
                for interface, prio in both:
                    self.order.append((prio, rule["index"], 0, {interface}, set(), rule))
                    self.order.append((prio, rule["index"], 1, set(), {interface}, rule))
            elif ins and outs:
                self.order.append((min(p for _, p in ins + outs), rule["index"], 0, {i for i, _ in ins}, {i for i, _ in outs}, rule))
            else:
                for number, (interface, prio) in enumerate(ins or outs):
                    self.order.append((prio, rule["index"], number, {interface} if ins else set(), set() if ins else {interface}, rule))
        self.order.sort(key=lambda item: item[:3])

    @staticmethod
    def _matches(rule: Dict[str, Any], pkt: Packet) -> bool:
        def inside(address: str, spec: str) -> bool:
            if spec == "any":
                return True
            negated = spec.startswith("!")
            return (ipaddress.ip_address(address) in ipaddress.ip_network(spec.lstrip("!"))) != negated

        if not inside(pkt.src, rule["src"]) or not inside(pkt.dst, rule["dst"]):
            return False
        if rule["proto"] != "any" and str(NUMBERS[rule["proto"]]) != str(NUMBERS.get(pkt.proto, pkt.proto)):
            return False
        for key, value in (("dport", pkt.dport), ("sport", pkt.sport)):
            if key in rule and not any(int(p.split("-")[0]) <= value <= int(p.split("-")[-1]) for p in rule[key].split(",")):
                return False
        if "param" in rule and int(rule["param"].split("=")[1]) != pkt.icmp_type:
            return False
        return True

    def allows(self, pkt: Packet, ingress: str, egress: str) -> bool:
        for _, _, _, ins, outs, rule in self.order:
            if (not ins or ingress in ins) and (not outs or egress in outs) and self._matches(rule, pkt):
                return bool(rule["action"] == "accept")
        return self.default == "accept"


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_hisecos.parse(text.encode("utf-8"), report), report


def test_parsed_configurations_decide_like_the_judge() -> None:
    rng = random.Random(7)
    zone = {i: parse_hisecos.zone_name(i) for i in DEVICE_IFS}
    checked = 0
    for seed in range(60):
        conf = random_conf(random.Random(seed))
        model, report = parse(render(conf, rng))
        judge = Judge(conf)
        for rule in model.rules:
            assert not rule.unsupported, (seed, rule)
        for _ in range(200):
            pkt = ipv4_packet(rng)
            ingress, egress = rng.choice(DEVICE_IFS), rng.choice(DEVICE_IFS)
            pkt.in_if, pkt.out_if = zone[ingress], zone[egress]
            assert model_allows(model, pkt) == judge.allows(pkt, ingress, egress), (seed, pkt, conf)
            checked += 1
    assert checked == 12000


@pytest.mark.parametrize("seed", range(10))
def test_a_configuration_read_and_written_again_decides_the_same(seed: int) -> None:
    rng = random.Random(seed)
    conf = random_conf(rng)
    conf["default"] = conf["default"] or "drop"
    model, _ = parse(render(conf, rng))
    text, report = emit(model)
    judge = Judge(conf)
    for default in ("accept", "drop"):
        device = Eagle(text, default)
        for _ in range(300):
            pkt = ipv4_packet(rng)
            ingress, egress = rng.choice(DEVICE_IFS), rng.choice(DEVICE_IFS)
            assert device.allows(pkt, ingress, egress) == judge.allows(pkt, ingress, egress), (seed, pkt, text)


def test_the_parser_reads_what_the_emitter_writes() -> None:
    model, _ = sample()
    text, _ = emit(model)
    back, report = parse(text)
    assert [r.description for r in back.rules if r.enabled][:3] == ["rule-30", "rule-10", "rule-10"]
    assert not any(r.unsupported for r in back.rules)
    assert back.default_interzone == Action.ALLOW  # (the script does not set the default; its last rule decides)
    assert "HISECOS_DEFAULT_ASSUMED" in codes(report)


# -- the sample ---------------------------------------------------------------------------------------------------


def sample() -> Tuple[Policy, Report]:
    return parse((DATA / "hisecos_sample.cli").read_text())


def rule_named(model: Policy, name: str) -> Rule:
    return next(r for r in model.rules if r.name == name)


def verdict(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "port1_1", egress: str = "port1_3",
            icmp_type: int = 0, sport: int = 40000) -> bool:  # fmt: skip
    return model_allows(model, Packet(ingress, egress, src, dst, proto, sport, dport, icmp_type))


def test_detection_and_errors() -> None:
    assert cli.detect_format((DATA / "hisecos_sample.cli").read_bytes()) == "hisecos"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and "_sample." in path.name and path.name != "hisecos_sample.cli":
            assert not parse_hisecos.looks_like_hisecos(path.read_bytes()), path.name
    with pytest.raises(ParseError):
        parse("system name x\ninterface 1/1\nexit\n")
    assert not parse_hisecos.looks_like_hisecos(b"nat dnat add 1 srcip any\n")  # (one NAT line is not enough)
    assert parse_hisecos.looks_like_hisecos(b"packet-filter l3 addrule 1 srcip any dstip any action accept\n")


def test_sample_zones_order_and_names() -> None:
    model, report = sample()
    assert list(model.zones) == ["port1_1", "port1_2", "port1_3", "vlan20"]
    assert model.zones["vlan20"].interfaces == ["vlan/20"]
    assert model.zone_networks["port1_3"] == ["10.30.0.0/24", "10.30.1.0/24"]
    assert model.scope == "IPv4" and model.lookup_after_dnat
    # Priority order (5, 10, 15, 20, 20, 25, 30, 35, 40, 40, 45, 50, 60), then the rule assigned to nothing.
    names = [r.name for r in model.rules]
    assert names == ["rule-30", "rule-10", "rule-20", "rule-40", "rule-40-2", "rule-100", "rule-50", "rule-130", "rule-60", "rule-110",
                     "rule-150", "rule-70", "rule-90", "rule-80"]  # fmt: skip
    assert "rule-140" not in names  # (deleted)
    assert model.default_interzone == model.default_intrazone == Action.DROP
    assert {"HISECOS_SOURCE", "HISECOS_DEFAULT", "HISECOS_NOT_CONVERTED", "HISECOS_MANAGEMENT", "HISECOS_DIRECTION_ORDER"} <= codes(report)


def test_sample_rules() -> None:
    model, report = sample()
    spoof = rule_named(model, "rule-30")
    assert spoof.src_zones == ["port1_2"] and spoof.negate_source and spoof.sources == ["10.10.0.0/24"] and spoof.action == Action.DROP
    both_in, both_out = rule_named(model, "rule-40"), rule_named(model, "rule-40-2")
    assert (both_in.src_zones, both_in.dst_zones, both_out.src_zones, both_out.dst_zones) == (["port1_3"], [ANY], [ANY], ["port1_3"])
    assert model.services[both_in.services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    dns = rule_named(model, "rule-50")
    assert (dns.src_zones, dns.dst_zones, dns.log_start) == (["port1_2"], ["port1_1"], True)  # (modifyrule set log)
    assert model.services[dns.services[0]].entries == [ServiceEntry(Protocol.UDP, "53", "1024-65535")]
    assert rule_named(model, "rule-20").unsupported and "Modbus" in rule_named(model, "rule-20").unsupported[0]
    assert rule_named(model, "rule-100").unsupported == ["parameter flags=SYN is not converted"]
    assert not rule_named(model, "rule-70").enabled and not rule_named(model, "rule-80").enabled
    assert rule_named(model, "rule-90").action == Action.DENY and rule_named(model, "rule-110").action == Action.DROP
    assert rule_named(model, "rule-150").dst_zones == [ANY]  # (its egress assignment is disabled)
    historian = rule_named(model, "rule-130")
    assert historian.destinations == ["historian"] and model.addresses["historian"].value == "10.20.0.50"
    assert rule_named(model, "rule-60").destinations == ["10.30.0.10", "192.0.2.10"]  # (destination NAT before the filter)
    tie = report.item("rule", "rule-60").findings
    assert any(f.code == "HISECOS_PRIORITY_TIE" for f in tie)
    assert any(f.code == "HISECOS_NOT_ASSIGNED" for f in report.item("rule", "rule-80").findings)
    # What passes: the DNS rule only from 1/2 out of 1/1; the anti-spoofing rule first.
    assert verdict(model, "10.10.0.5", "198.51.100.53", "udp", 53, "port1_2", "port1_1", sport=2000)
    assert not verdict(model, "10.10.0.5", "198.51.100.53", "udp", 53, "port1_2", "port1_3", sport=2000)
    assert not verdict(model, "10.99.0.5", "198.51.100.53", "udp", 53, "port1_2", "port1_1", sport=2000)
    assert verdict(model, "198.51.100.7", "10.30.0.10", "tcp", 443, "port1_1", "port1_3")  # (rule 60 before 110 at priority 40)


def test_sample_nat() -> None:
    model, report = sample()
    nat = {n.name: n for n in model.nat_rules}
    assert list(nat) == ["1to1nat-1", "doublenat-1", "doublenat-1-reverse", "dnat-1", "masq-1"]
    one = nat["1to1nat-1"]
    assert (one.src_zones, one.dst_zones, one.sources) == (["port1_3"], ["port1_1"], ["10.30.0.64/28"])
    assert one.source_translation == SourceNat(SnatKind.STATIC, ["192.0.2.64/28"], bidirectional=True)
    dnat = nat["dnat-1"]
    assert dnat.src_zones == ["port1_1"] and dnat.destinations == ["192.0.2.10"] and dnat.destination_translation == DestNat("10.30.0.10", "80")
    assert model.services[dnat.service].entries == [ServiceEntry(Protocol.TCP, "8080")]
    masq = nat["masq-1"]
    assert masq.dst_zones == ["port1_1"] and masq.source_translation is not None
    assert (masq.source_translation.kind, masq.source_translation.interface_address) == (SnatKind.INTERFACE, "192.0.2.1")
    double = nat["doublenat-1"]
    assert (double.src_zones, double.dst_zones, double.sources, double.destinations) == (["port1_2"], ["vlan20"], ["10.10.0.30"], ["172.16.20.40"])
    assert double.destination_translation == DestNat("10.20.0.40")
    assert all(n.combines for n in model.nat_rules)
    assert "HISECOS_NAT_ORDER" in codes(report)


# -- traps one by one ---------------------------------------------------------------------------------------------


def conf(*lines: str) -> str:
    return "\n".join(["interface 1/1", "ip address primary 10.0.0.1 255.255.255.0", "exit"] + list(lines)) + "\n"


def test_no_default_is_accept_and_said() -> None:
    model, report = parse(conf("packet-filter l3 addrule 1 srcip 10.0.0.0/24 dstip any action drop",
                               "packet-filter l3 addif 1/1 rule 1 direction ingress priority 1"))  # fmt: skip
    assert model.default_interzone == Action.ALLOW and "HISECOS_DEFAULT_ASSUMED" in codes(report)


def test_what_is_never_read_wider() -> None:
    lines = [
        "packet-filter l3 addrule 1 srcip any dstip any proto tcp dstport 80 action accept colour blue",
        "packet-filter l3 addrule 2 srcip 2001:db8::1 dstip any action accept",
        "packet-filter l3 addrule 3 srcip any dstip any proto icmpv6 action accept",
        "packet-filter l3 addrule 4 srcip any dstip any proto any dstport 80 action accept",
        "packet-filter l3 addrule 5 srcip any dstip $servers action accept",
        "packet-filter l3 addrule 6 srcip any dstip nobody action accept",
        "packet-filter l3 addrule 7 srcip any dstip any proto modbus-custom action accept",
        "packet-filter l3 addrule 8 srcip any dstip any proto tcp param state=est action accept",
        "packet-filter l3 addrule 9 srcip any dstip any proto tcp action",
        "packet-filter l3 addrule 10 srcip 10.0.0.1-10.0.0.5 dstip any action accept",
    ]
    lines += [f"packet-filter l3 addif 1/1 rule {n} direction ingress priority {n}" for n in range(1, 11)]
    model, _ = parse(conf(*lines))
    assert all(rule.unsupported for rule in model.rules), [r.name for r in model.rules if not r.unsupported]


def test_state_new_and_icmp_code_are_exact() -> None:
    model, _ = parse(conf("packet-filter l3 addrule 1 srcip any dstip any proto tcp param state=new action accept",
                          "packet-filter l3 addrule 2 srcip any dstip any proto icmp param type=3,code=4 action drop",
                          "packet-filter l3 addif 1/1 rule 1 direction ingress priority 1",
                          "packet-filter l3 addif 1/1 rule 2 direction ingress priority 2"))  # fmt: skip
    assert not any(r.unsupported for r in model.rules)
    assert model.services[model.rules[1].services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]


def test_enablerule_in_the_script_makes_unsaid_rules_a_finding() -> None:
    model, report = parse(conf("packet-filter l3 addrule 1 srcip any dstip any action accept",
                               "packet-filter l3 addrule 2 srcip any dstip any action drop", "packet-filter l3 enablerule 1",
                               "packet-filter l3 addif 1/1 rule 1 direction ingress priority 1",
                               "packet-filter l3 addif 1/1 rule 2 direction ingress priority 2"))  # fmt: skip
    assert "HISECOS_STATE_UNSAID" in codes(report) and all(r.enabled for r in model.rules)


def test_assignment_forms_and_mixed_both() -> None:
    model, report = parse(conf("packet-filter l3 addrule 1 srcip any dstip any action accept",
                               "packet-filter l3 addif 1/1 1 ingress 7",  # (positional)
                               "packet-filter l3 addrule 2 srcip any dstip any action drop",
                               "packet-filter l3 addif 1/1 rule 2 direction both priority 3",
                               "packet-filter l3 addif 1/2 rule 2 direction ingress priority 3",
                               "packet-filter l3 addrule 3 srcip any dstip any action drop",
                               "packet-filter l3 addif 1/1 rule 3 direction ingress priority 1",
                               "packet-filter l3 addif 1/2 rule 3 direction egress priority 9"))  # fmt: skip
    assert [r.name for r in model.rules] == ["rule-3", "rule-2", "rule-1"]
    assert rule_named(model, "rule-1").src_zones == ["port1_1"]
    assert rule_named(model, "rule-2").unsupported  # (both on one interface, ingress on another: not documented)
    assert "HISECOS_PRIORITIES_DIFFER" in codes(report)


def test_assets_and_netobjects() -> None:
    model, _ = parse(conf("asset add 1 name cell ip 10.1.0.0/24 ip2 10.2.0.5",
                          "asset add 2 name bad ip !10.3.0.0/24",
                          "packet-filter l3 addrule 1 srcip cell dstip any action accept",
                          "packet-filter l3 addrule 2 srcip bad dstip any action accept",
                          "packet-filter l3 addif 1/1 rule 1 direction ingress priority 1",
                          "packet-filter l3 addif 1/1 rule 2 direction ingress priority 2"))  # fmt: skip
    assert model.address_groups["cell"] == AddressGroup("cell", ["cell#1", "cell#2"], description="asset")
    assert model.addresses["bad"].kind == AddressKind.UNSUPPORTED


def test_nat_forms_not_read() -> None:
    model, _ = parse(conf("packet-filter l3 addrule 1 srcip any dstip any action accept",
                          "packet-filter l3 addif 1/1 rule 1 direction ingress priority 1",
                          "nat dnat add 1 srcip !10.0.0.0/8 dstip 192.0.2.5 proto tcp dstport 80 newdstip 10.0.0.5",
                          "nat dnat if add 1/1 rule 1 priority 1",
                          "nat dnat add 2 srcip any dstip 192.0.2.6 newdstip 10.0.0.0/24",
                          "nat dnat if add 1/1 rule 2 priority 2",
                          "nat masq add 1 srcip 10.0.0.0/24 ipsec-exempt true",
                          "nat masq if add 1/1 rule 1 priority 1",
                          "nat dnat add 3 srcip any dstip 192.0.2.7 newdstip 10.0.0.7"))  # fmt: skip
    nat = {n.name: n for n in model.nat_rules}
    assert nat["dnat-1"].unsupported and nat["dnat-2"].unsupported and nat["masq-1"].unsupported
    assert not nat["dnat-3"].enabled  # (assigned to no interface)


# -- the emitter --------------------------------------------------------------------------------------------------


def named(p: Policy) -> Policy:
    for zone, interface in (("inside", "1/2"), ("outside", "1/1"), ("dmz", "vlan/30")):
        p.zones[zone] = Zone(zone, [interface])
    return p


def test_emitter_ranges_negation_ports_and_order() -> None:
    p = named(Policy(vendor="panos"))
    p.addresses["span"] = Address("span", AddressKind.RANGE, "10.0.0.6-10.0.0.9")
    p.services["many"] = Service("many", [ServiceEntry(Protocol.TCP, ",".join(str(n) for n in range(1000, 1020)))])
    p.rules.append(Rule("range", src_zones=["inside"], dst_zones=["outside"], sources=["span"], services=["many"]))
    p.rules.append(Rule("not-dst", src_zones=["inside"], destinations=["10.0.0.0/8"], negate_destination=True, action=Action.DROP))
    p.rules.append(Rule("not-src", src_zones=[ANY], sources=["10.1.0.0/16"], negate_source=True, action=Action.RESET_BOTH))
    text, report = emit(p, Options(policy_id_start=100))
    device = Eagle(text)
    first = device.rules[100]["fields"]
    assert (first["srcip"], first["dstport"]) == ("10.0.0.6/31", ",".join(str(n) for n in range(1000, 1015)))
    assert sorted(device.rules)[0] == 100
    srcs = [r["fields"]["srcip"] for r in device.rules.values() if r["fields"]["description"] == "range"]
    assert srcs == ["10.0.0.6/31", "10.0.0.6/31", "10.0.0.8/31", "10.0.0.8/31"]
    complement = [r["fields"]["dstip"] for r in device.rules.values() if r["fields"]["description"] == "not-dst"]
    assert complement[:2] == ["0.0.0.0/5", "8.0.0.0/7"] and "10.0.0.0/8" not in complement
    assert [r["fields"]["srcip"] for r in device.rules.values() if r["fields"]["description"] == "not-src"] == ["!10.1.0.0/16"]
    assert any(f.code == "RESET_ACTION" for f in report.item("rule", "not-src").findings)
    ingress = {m["if"] for m in device.maps if device.rules[m["index"]]["fields"]["description"] == "not-src"}
    assert ingress == {"1/1", "1/2", "vlan/30"}  # (any: every interface the policy knows)
    assert "HISECOS_LOAD" in codes(report)


def test_emitter_defaults_and_intrazone() -> None:
    p = named(Policy(vendor="fortios", default_intrazone=Action.ALLOW, default_interzone=Action.DENY))
    p.rules.append(Rule("web", src_zones=["inside"], dst_zones=["outside"], services=[ANY]))
    text, _ = emit(p)
    device = Eagle(text, "accept")
    tail = [device.rules[i]["fields"] for i in sorted(device.rules)][1:]
    assert [f["description"] for f in tail] == ["fwshift-inside-inside", "fwshift-inside-outside", "fwshift-inside-dmz", "fwshift-default"]
    assert [f["action"] for f in tail] == ["accept", "accept", "accept", "drop"]
    pkt = Packet("x", "y", "10.0.0.1", "10.0.0.2", "tcp", 1, 80)
    assert device.allows(pkt, "1/2", "1/2") and not device.allows(pkt, "1/1", "1/2") and device.allows(pkt, "1/2", "1/1")


def test_emitter_what_it_cannot_write() -> None:
    p = named(Policy(vendor="panos"))
    p.addresses["name"] = Address("name", AddressKind.FQDN, "www.example.com")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8::/32")
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "9899")])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.rules.append(Rule("fqdn", src_zones=["inside"], destinations=["name"]))
    p.rules.append(Rule("v6", src_zones=["inside"], destinations=["six"]))
    p.rules.append(Rule("sctp", src_zones=["inside"], services=["sctp"]))
    p.rules.append(Rule("gre", src_zones=["inside"], services=["gre"], action=Action.DROP))
    p.rules.append(Rule("notsvc", src_zones=["inside"], services=["gre"], negate_service=True))
    p.rules.append(Rule("mixed", src_zones=["inside"], destinations=["six", "10.0.0.0/24"]))
    text, report = emit(p)
    device = Eagle(text)
    by_name = {r["fields"]["description"]: r for r in device.rules.values()}
    for name in ("fqdn", "sctp", "gre", "notsvc"):
        assert report.item("rule", name).disabled and by_name[name]["enabled"] is False, name
        assert by_name[name]["fields"]["srcip"] == "0.0.0.0"  # (a placeholder)
    assert report.item("rule", "v6").skipped
    assert by_name["mixed"]["fields"]["dstip"] == "10.0.0.0/24" and "HISECOS_IPV4_ONLY" in codes(report)


def test_emitter_interfaces_must_be_the_devices() -> None:
    p = Policy(vendor="panos")
    p.zones["trust"] = Zone("trust", ["ethernet1/1"])
    p.rules.append(Rule("r", src_zones=["trust"]))
    text, report = emit(p)
    assert "INTERFACES_REQUIRED" in codes(report)
    text, report = emit(p, Options(interface_map={"ethernet1/1": "1/4"}))
    assert "INTERFACES_REQUIRED" not in codes(report) and "addif 1/4 rule 1001" in text


def test_emitter_runs_out_of_indexes() -> None:
    p = named(Policy(vendor="panos"))
    for n in range(5):
        p.rules.append(Rule(f"r{n}", src_zones=["inside"], destinations=[f"10.0.{n}.0/24"]))
    text, report = emit(p, Options(policy_id_start=2046))
    assert sorted(Eagle(text).rules) == [2046, 2047, 2048]
    assert report.item("rule", "r4").skipped and "HISECOS_TOO_MANY_RULES" in codes(report)


def test_emitter_nat() -> None:
    p = named(Policy(vendor="panos"))
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "8080")])
    p.nat_rules.append(NatRule("in", src_zones=["outside"], destinations=["192.0.2.10"], service="web",
                               destination_translation=DestNat("10.0.0.10", "80")))  # fmt: skip
    p.nat_rules.append(NatRule("out", src_zones=["inside"], dst_zones=["outside"], sources=["10.0.0.0/24"],
                               source_translation=SourceNat(SnatKind.INTERFACE, interface="1/1")))  # fmt: skip
    p.nat_rules.append(NatRule("map", src_zones=["dmz"], dst_zones=["outside"], sources=["10.3.0.0/28"],
                               source_translation=SourceNat(SnatKind.STATIC, ["192.0.2.64/28"], bidirectional=True)))  # fmt: skip
    p.nat_rules.append(NatRule("pool", src_zones=["inside"], dst_zones=["outside"],
                               source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["192.0.2.99"])))  # fmt: skip
    p.rules.append(Rule("web", src_zones=["outside"], dst_zones=["inside"], destinations=["192.0.2.10"], services=["web"]))
    text, report = emit(p)
    device = Eagle(text)
    assert device.nat[("dnat", 201)]["newdstip"] == "10.0.0.10" and device.nat[("dnat", 201)]["newdstport"] == "80"
    assert ("dnat", "1/1", 201, "ingress", 201) in device.nat_maps
    assert device.nat[("masq", 101)]["srcip"] == "10.0.0.0/24" and ("masq", "1/1", 101, "egress", 101) in device.nat_maps
    one = device.nat[("1to1nat", 202)]
    assert (one["dstip"], one["newdstip"], one["ingress-if"], one["egress-if"]) == ("192.0.2.64/28", "10.3.0.0/28", "1/1", "vlan/30")
    assert report.item("nat", "pool").skipped
    web = next(r["fields"] for r in device.rules.values() if r["fields"]["description"] == "web")
    assert (web["dstip"], web["dstport"]) == ("10.0.0.10", "80")  # (the filter sees the translated destination)


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "hisecos_sample.cli").read_bytes()
    for target in cli.VENDORS:
        report = Report()
        policy = cli.load(data, "hisecos", report)
        assert cli.convert(policy, target, report), target


def test_same_vendor_round_trip_of_the_sample() -> None:
    model, _ = sample()
    text, report = emit(model)
    device = Eagle(text, "accept")
    rng = random.Random(3)
    zones = {parse_hisecos.zone_name(i): i for i in ("1/1", "1/2", "1/3", "vlan/20")}
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for _ in range(2000):
        src = rng.choice(["10.10.0.5", "10.20.0.7", "10.30.0.10", "10.30.0.70", "198.51.100.9", "203.0.113.4", "10.99.0.1"])
        dst = rng.choice(["10.10.0.20", "10.20.0.50", "10.30.0.10", "198.51.100.53", "192.0.2.200", "10.30.0.20"])
        pkt = Packet(rng.choice(list(zones)), rng.choice(list(zones)), src, dst, rng.choice(["tcp", "udp", "icmp", "50"]),
                     rng.choice([2000, 40000]), rng.choice([22, 53, 80, 443, 502, 1433, 8005]), rng.choice([0, 8]))  # fmt: skip
        assert device.allows(pkt, zones[pkt.in_if], zones[pkt.out_if]) == model_allows(model, pkt), pkt
