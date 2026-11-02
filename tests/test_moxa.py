# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Moxa industrial secure routers (classic router firmware): parser, emitter, and packet-level checks with a judge of
its own.

``MoxaCli`` reads the CLI commands of the Layer 3 policy and NAT strictly, as Moxa's *Industrial Secure Router CLI
Command Set* manual writes them (``firewall N`` with ``action``, ``mode``, ``protocol``, ``src-ip``, ``dst-ip``,
``src-port``, ``dst-port``, ``interface FROM TO``; ``firewall N disable``; the three forms of ``ip nat``), and decides
a packet as Moxa's user manuals describe it: the policies from index 1, the first that matches accepts or drops, and
what none matches passes (the default FWShift assumes). It shares no code with the parser or the emitter. It judges
the emitter's output for random models, and random configurations rendered as text against what the parser makes of
them.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows, random_model

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, DestNat, NatRule, Policy, Protocol, Rule, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import moxa as parse_moxa
from fwshift.report import Report

WORDS = ("lan", "wan1", "wan2")


# -- the judge ---------------------------------------------------------------------------------------------------


def _ip(word: str) -> int:
    return int(ipaddress.IPv4Address(word))


@dataclass
class Policy3:
    index: int
    action: str = "accept"
    mode: str = "IP"
    protocol: str = "all"
    src: Tuple[int, int] = (0, 2**32 - 1)
    dst: Tuple[int, int] = (0, 2**32 - 1)
    sport: Tuple[int, int] = (0, 65535)
    dport: Tuple[int, int] = (0, 65535)
    ifaces: Tuple[str, str] = ("all", "all")
    mac: str = ""
    enabled: bool = True
    ported: bool = False  # a port was given


@dataclass
class MoxaCli:
    policies: Dict[int, Policy3] = field(default_factory=dict)
    nat: List[List[str]] = field(default_factory=list)

    @staticmethod
    def _range(words: List[str], parse: Any) -> Tuple[int, int]:
        if words == ["all"]:
            return (0, 2**32 - 1) if parse is _ip else (0, 65535)
        if len(words) == 2 and words[0] == "single":
            value = parse(words[1])
            return value, value
        assert len(words) == 3 and words[0] == "range", words
        first, last = parse(words[1]), parse(words[2])
        assert first <= last, words
        return first, last

    @staticmethod
    def _port(word: str) -> int:
        value = int(word)
        assert 0 <= value <= 65535 and word == str(value), word
        return value

    @classmethod
    def read(cls, text: str, script: bool = True) -> "MoxaCli":
        """A script of the emitter (``configure`` first, ``exit`` last), or with ``script=False`` a configuration file."""
        out = cls()
        lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("!")]
        if script:
            assert lines[0] == "configure" and lines[-1] == "exit", (lines[:1], lines[-1:])
            lines = lines[1:-1]
        current: Optional[Policy3] = None
        for raw in lines:
            words = raw.split()
            if current is not None:
                if words == ["exit"]:
                    current = None
                    continue
                head, rest = words[0], words[1:]
                if head == "action":
                    assert rest in (["accept"], ["drop"]), raw
                    current.action = rest[0]
                elif head == "mode":
                    assert rest in (["IP"], ["MAC"]), raw
                    current.mode = rest[0]
                elif head == "protocol":
                    assert rest in (["all"], ["tcp"], ["udp"], ["icmp"]), raw
                    current.protocol = rest[0]
                elif head in ("src-ip", "dst-ip"):
                    value = out._range(rest, _ip)
                    if head == "src-ip":
                        current.src = value
                    else:
                        current.dst = value
                elif head in ("src-port", "dst-port"):
                    value = out._range(rest, out._port)
                    current.ported = current.ported or rest != ["all"]
                    if head == "src-port":
                        current.sport = value
                    else:
                        current.dport = value
                elif head == "src-mac":
                    current.mac = rest[0]
                elif head == "interface":
                    assert len(rest) == 2 and all(word in ("all",) + WORDS for word in rest), raw
                    current.ifaces = (rest[0], rest[1])
                elif not script:
                    current.mode = "unknown"  # (a configuration file may hold what the manual does not show)
                else:
                    raise AssertionError(raw)
                continue
            if words[0] == "firewall" and len(words) == 2:
                index = int(words[1])
                assert index >= 1
                if script:
                    assert index not in out.policies, f"firewall {index} entered twice: it would change the policy"
                current = out.policies.setdefault(index, Policy3(index))
            elif words[0] == "firewall" and len(words) == 3 and words[2] in ("enable", "disable"):
                out.policies[int(words[1])].enabled = words[2] == "enable"
            elif words[:2] == ["ip", "nat"]:
                rest = words[2:]
                if rest[:3] == ["static", "inside", "lan"]:
                    assert len(rest) == 8 and rest[4:6] == ["outside", "wan"] and rest[6] in ("1", "2"), raw
                    _ip(rest[3]), _ip(rest[7])
                elif rest[:1] == ["dynamic"]:
                    assert len(rest) == 8 and rest[1:3] == ["inside", "lan"] and rest[5:7] == ["outside", "wan"], raw
                    assert rest[7] in ("1", "2", "auto") and _ip(rest[3]) <= _ip(rest[4]), raw
                elif len(rest) >= 2 and rest[0] == "static" and rest[1] in ("all", "tcp", "udp"):
                    assert len(rest) == 10 and rest[2:4] == ["inside", "lan"] and rest[6:8] == ["outside", "wan"], raw
                    _ip(rest[4]), MoxaCli._port(rest[5]), MoxaCli._port(rest[9])
                else:
                    raise AssertionError(raw)
                out.nat.append(rest)
            elif not script:
                continue
            else:
                raise AssertionError(raw)
        for policy in out.policies.values():
            if policy.ported:
                assert policy.protocol in ("tcp", "udp"), f"ports with protocol {policy.protocol}"
        return out

    def allows(self, pkt: Packet) -> bool:
        for index in sorted(self.policies):
            policy = self.policies[index]
            if not policy.enabled:
                continue
            if policy.ifaces[0] not in ("all", pkt.in_if) or policy.ifaces[1] not in ("all", pkt.out_if):
                continue
            if policy.protocol != "all" and policy.protocol != pkt.proto:
                continue
            if not (policy.src[0] <= _ip(pkt.src) <= policy.src[1] and policy.dst[0] <= _ip(pkt.dst) <= policy.dst[1]):
                continue
            if policy.protocol in ("tcp", "udp"):
                if not (policy.sport[0] <= pkt.sport <= policy.sport[1] and policy.dport[0] <= pkt.dport <= policy.dport[1]):
                    continue
            return policy.action == "accept"
        return True


# -- helpers -----------------------------------------------------------------------------------------------------


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_moxa.parse(text.encode("utf-8"), report), report


def codes(report: Report) -> set:
    return {f.code for f in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(model, "moxa", report, options), report


def rule_named(model: Policy, name: str) -> Rule:
    return next(rule for rule in model.rules if rule.name == name)


def verdict(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "lan", egress: str = "wan1",
            sport: int = 40000) -> bool:  # fmt: skip
    return model_allows(model, Packet(ingress, egress, src, dst, proto, sport, dport))


HEAD = "! ---------- EDR-810-2GSFP ----------\n"


# -- the parser ----------------------------------------------------------------------------------------------------


def test_detection_and_errors() -> None:
    data = (DATA / "moxa_sample.ini").read_bytes()
    assert cli.detect_format(data) == "moxa" and parse_moxa.looks_like_moxa(data)
    for other in DATA.glob("*_sample.*"):
        if other.name != "moxa_sample.ini":
            assert not parse_moxa.looks_like_moxa(other.read_bytes()), other.name
    with pytest.raises(ParseError, match="MX-ROS"):
        parse("! ---------- EDR-G9010-VPN-2MGSFP ----------\nhostname r\ninterface lan\n ip address static 10.0.0.1 255.255.255.0\n")
    with pytest.raises(ParseError, match="no Layer 3 policy"):
        parse(HEAD + "hostname r\n")
    with pytest.raises(ParseError, match="encrypted"):
        parse_moxa.parse(bytes(range(256)) * 4, Report())


def test_sample_policies_in_index_order_with_the_defaults() -> None:
    model, report = parse((DATA / "moxa_sample.ini").read_text(encoding="utf-8"))
    assert [r.name for r in model.rules] == [f"firewall {n}" for n in range(1, 11)]  # (the file lists 2 before 1)
    assert model.default_interzone == Action.ALLOW and model.default_intrazone == Action.ALLOW
    assert set(model.zones) == set(WORDS)
    one = rule_named(model, "firewall 1")
    assert one.src_zones == ["lan"] and one.dst_zones == ["wan1"] and one.sources == ["192.168.127.10-192.168.127.20"]
    assert model.services[one.services[0]].entries == [ServiceEntry(Protocol.TCP, "502")]
    two = rule_named(model, "firewall 2")
    assert two.action == Action.DROP and two.sources == ["0.0.0.0/0"] and two.destinations == ["0.0.0.0/0"]
    four = rule_named(model, "firewall 4")
    assert model.services[four.services[0]].entries == [ServiceEntry(Protocol.UDP, "20000-20010", "1024-65535")]
    five = rule_named(model, "firewall 5")
    assert five.dst_zones == [ANY] and model.services[five.services[0]].entries == [ServiceEntry(Protocol.ICMP)]
    six = rule_named(model, "firewall 6")
    assert not six.enabled and six.services == [ANY]  # (firewall 6 disable; protocol all by default)
    assert rule_named(model, "firewall 7").unsupported  # (mode MAC, src-mac)
    assert any("session-limit" in text for text in rule_named(model, "firewall 8").unsupported)
    assert not any(rule.log_end for rule in model.rules)
    found = codes(report)
    assert {"MOXA_SOURCE", "MOXA_DEFAULT_ACCEPT", "MOXA_NAT_ORDER", "MOXA_DPI", "MOXA_L2_POLICY", "MOXA_DOS", "MOXA_TRUSTED_ACCESS"} <= found


def test_sample_nat_and_the_rules_rewritten_for_the_address_as_it_arrives() -> None:
    model, report = parse((DATA / "moxa_sample.ini").read_text(encoding="utf-8"))
    forward, one, many, auto = model.nat_rules
    assert forward.src_zones == ["wan1"] and forward.destinations == ["wan1-address"]
    assert model.addresses["wan1-address"].value == "203.0.113.2/32" and model.addresses["wan1-address"].builtin == "moxa"
    assert forward.destination_translation == DestNat("192.168.127.50", "443")
    assert model.services[forward.service].entries == [ServiceEntry(Protocol.TCP, "8443")]
    assert one.sources == ["192.168.127.60"] and one.dst_zones == ["wan2"]
    assert one.source_translation == SourceNat(SnatKind.STATIC, ["198.51.100.60"], bidirectional=True)
    assert many.source_translation is not None and many.source_translation.kind == SnatKind.INTERFACE
    assert many.source_translation.interface_address == "203.0.113.2" and many.src_zones == ["lan"]
    assert auto.dst_zones == ["wan1", "wan2"] and not auto.enabled  # (ip nat 4 disable)
    assert model.lookup_after_dnat
    # The policy for the forwarded server names its inside address; the model names the address as it arrives too.
    three = rule_named(model, "firewall 3")
    assert "wan1-address" in three.destinations and "NAT_PORT_TRANSLATION" in codes(report)
    assert verdict(model, "198.51.100.7", "203.0.113.2", dport=8443, ingress="wan1", egress="lan")
    assert verdict(model, "198.51.100.7", "198.51.100.60", dport=22, ingress="wan2", egress="lan")


def test_blocks_without_exit_and_the_two_interface_commands() -> None:
    text = HEAD + "\n".join([
        "firewall 1", "action drop", "protocol udp", "dst-port single 53", "interface lan wan1",
        "interface wan 1", " type static 203.0.113.9 255.255.255.0 203.0.113.1",
        "firewall 2", "interface wan2 lan", "firewall 3", " src-ip range 10.0.0.9 10.0.0.1", "exit",
    ])  # fmt: skip
    model, _ = parse(text)
    one, two, three = model.rules
    assert one.action == Action.DROP and one.dst_zones == ["wan1"]  # ("interface lan wan1" belongs to the policy)
    assert two.src_zones == ["wan2"] and two.action == Action.ALLOW  # ("interface wan 1" was a command of its own)
    assert three.unsupported  # (a range whose ends are the wrong way round)
    assert not verdict(model, "10.0.0.1", "10.0.0.2", "udp", 53)
    assert verdict(model, "10.0.0.1", "10.0.0.2", "tcp", 53)


def test_edit_commands_unknown_words_and_ports_without_tcp_or_udp() -> None:
    text = HEAD + "\n".join([
        "firewall 1", " action drop", " protocol all", " dst-port single 80", " exit",
        "firewall 2", " protocol icmp", " src-port single 7", " exit",
        "firewall 3", " action drop", " exit", "no firewall 3",
        "firewall 4", " protocol tcp", " dst-port single 22", " exit", "firewall 4", " action drop", " exit",
        "firewall 5", " interface dmz lan", " log", " exit",
        "firewall 9 disable", "firewall default-action drop",
    ])  # fmt: skip
    model, report = parse(text)
    assert [r.name for r in model.rules] == ["firewall 1", "firewall 2", "firewall 4", "firewall 5"]
    assert all(rule.unsupported for rule in model.rules[:2])
    assert rule_named(model, "firewall 4").action == Action.DROP  # (entered again: its settings change)
    five = rule_named(model, "firewall 5")
    assert five.src_zones == ["dmz"] and five.log_end and "dmz" in model.zones
    found = codes(report)
    assert {"MOXA_EDIT_COMMANDS", "MOXA_UNREAD", "MOXA_INTERFACE_WORD", "MOXA_LOG_WORDS"} <= found


def test_nat_index_insert_append_delete_and_what_is_not_read() -> None:
    text = HEAD + "\n".join([
        "interface wan 2", " type dhcp", " exit",
        "ip nat dynamic inside lan 10.0.0.1 10.0.0.50 outside wan 1",
        "ip nat static inside lan 10.0.0.5 outside wan 1 203.0.113.5 1",
        "ip nat static udp inside lan 10.0.0.6 161 outside wan 2 1161",
        "ip nat static all inside lan 10.0.0.7 80 outside wan 3 80",
        "ip nat dynamic inside lan 10.0.0.60 10.0.0.70 outside wan 1",
        "no ip nat 4",
        "ip nat 2 disable",
    ])  # fmt: skip
    model, report = parse(text)
    names = [(n.name, n.description.split(" inside")[0]) for n in model.nat_rules]
    assert names == [("ip nat 1", "ip nat static"), ("ip nat 2", "ip nat dynamic"), ("ip nat 3", "ip nat static udp"),
                     ("ip nat 4", "ip nat dynamic")]  # fmt: skip
    assert not model.nat_rules[1].enabled
    forward = model.nat_rules[2]
    assert any("dhcp" in text for text in forward.unsupported)  # (the address of WAN 2 is not known)
    assert model.nat_rules[3].sources == ["10.0.0.60-10.0.0.70"]
    assert "MOXA_EDIT_COMMANDS" in codes(report)


# -- random configurations against the parser -----------------------------------------------------------------------


def random_text(rng: random.Random) -> str:
    lines = [HEAD.rstrip()]
    for index in rng.sample(range(1, 30), rng.randint(3, 12)):
        body = []
        if rng.random() < 0.8:
            body.append(f"action {rng.choice(['accept', 'drop'])}")
        protocol = rng.choice(["all", "tcp", "tcp", "udp", "icmp", None])
        if protocol:
            body.append(f"protocol {protocol}")
        for side in ("src-ip", "dst-ip"):
            choice = rng.random()
            if choice < 0.3:
                body.append(f"{side} single 10.0.{rng.randrange(4)}.{rng.randrange(0, 256, 17)}")
            elif choice < 0.6:
                first = rng.randrange(0, 900)
                body.append(f"{side} range 10.0.{first // 256}.{first % 256} 10.0.{(first + 300) // 256}.{(first + 300) % 256}")
            elif choice < 0.7:
                body.append(f"{side} all")
        if protocol in ("tcp", "udp"):
            for side in ("src-port", "dst-port"):
                if rng.random() < 0.5:
                    first = rng.choice([22, 53, 80, 443, 1024, 8000])
                    body.append(f"{side} single {first}" if rng.random() < 0.5 else f"{side} range {first} {first + rng.randrange(0, 2000)}")
        if rng.random() < 0.85:
            body.append(f"interface {rng.choice(('all',) + WORDS)} {rng.choice(('all',) + WORDS)}")
        if rng.random() < 0.05:
            body.append("mode MAC")
            body.append("src-mac 00:90:e8:00:00:02")
        rng.shuffle(body)
        lines += [f"firewall {index}"] + [" " + line for line in body] + [" exit"]
        if rng.random() < 0.15:
            lines.append(f"firewall {index} disable")
    return "\n".join(lines) + "\n"


def random_packet(rng: random.Random) -> Packet:
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47"])
    return Packet(rng.choice(WORDS), rng.choice(WORDS), f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}",
                  f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}", proto, rng.choice([22, 1024, 3000, 40000]),
                  rng.choice([22, 53, 80, 443, 1024, 2000, 8000, 9999]))  # fmt: skip


@pytest.mark.parametrize("seed", range(40))
def test_parsed_configuration_decides_like_the_judge(seed: int) -> None:
    rng = random.Random(seed)
    text = random_text(rng)
    judge = MoxaCli.read(text, script=False)
    model, _ = parse(text)
    unread = {int(rule.source_ids["moxa.index"]) for rule in model.rules if rule.unsupported}
    assert unread == {i for i, p in judge.policies.items() if p.mode != "IP"}
    for index in unread:
        judge.policies[index].enabled = False
        rule_named(model, f"firewall {index}").enabled = False
    for _ in range(300):
        pkt = random_packet(rng)
        assert judge.allows(pkt) == model_allows(model, pkt), (seed, pkt, text)


# -- the emitter -----------------------------------------------------------------------------------------------------

ZONE_MAP = {"eth0": "lan", "eth1": "wan1", "eth2": "wan2"}


def compare(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    judge = MoxaCli.read(text)
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (written disabled, and said)
    back = {word: zone for zone, word in ZONE_MAP.items()}
    count = 0
    while count < packets:
        pkt = random_packet(rng)
        if pkt.in_if == pkt.out_if:
            continue  # (traffic inside one interface does not pass the router)
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        if rng.random() < 0.2:
            pkt.icmp_type = 8 if pkt.proto == "icmp" else 0
        theirs = Packet(back[pkt.in_if], back[pkt.out_if], pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        assert judge.allows(pkt) == model_allows(model, theirs), (seed, pkt, text)
        count += 1
    return count


def zoned(model: Policy) -> Policy:
    for zone in ZONE_MAP:
        model.zones.setdefault(zone, Zone(zone))
    return model


@pytest.mark.parametrize("seed", range(40))
def test_emitted_commands_decide_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = zoned(random_model(rng))
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW
    text, report = emit(model, Options(zone_map=dict(ZONE_MAP)))
    assert compare(model, report, text, rng, seed) == 400


@pytest.mark.parametrize("seed", range(20))
def test_a_configuration_read_and_written_again_decides_the_same(seed: int) -> None:
    rng = random.Random(1000 + seed)
    text = random_text(rng)
    model, _ = parse(text)
    out, report = emit(model)
    judge, again = MoxaCli.read(text, script=False), MoxaCli.read(out)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            judge.policies[int(rule.source_ids["moxa.index"])].enabled = False
    for _ in range(300):
        pkt = random_packet(rng)
        if pkt.in_if != pkt.out_if:
            assert judge.allows(pkt) == again.allows(pkt), (seed, pkt, text, out)


def small_model() -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    for zone in ("inside", "outside", "dmz", "ot"):
        p.zones[zone] = Zone(zone)
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    rules = [
        Rule("web-out", ["inside"], ["outside"], ["10.1.0.0/16"], services=["web"]),
        Rule("not-guests", ["inside"], ["dmz"], ["10.1.9.0/24"], negate_source=True),
        Rule("ping", ["inside"], ["outside"], services=["ping"]),
        Rule("gre", ["inside"], ["outside"], services=["gre"]),
        Rule("to-ot", ["inside"], ["ot"], action=Action.DROP),
        Rule("six", ["inside"], ["outside"], ["2001:db8::/32"]),
        Rule("block-all-v6", ["outside"], ["inside"], action=Action.DROP),
    ]  # fmt: skip
    for rule in rules:
        rule.origin = rule.name
    p.rules = rules
    return p


def test_emitter_pieces_zones_and_what_is_written_disabled() -> None:
    model = small_model()
    text, report = emit(model, Options(zone_map={"inside": "lan", "outside": "wan1", "dmz": "wan2"}))
    judge = MoxaCli.read(text)
    items = {name: item for (kind, name), item in report.items.items() if kind == "rule"}
    assert items["web-out"].emitted_as == ["firewall 1-2"] and not items["web-out"].disabled
    # Every source but 10.1.9.0/24: the ranges it leaves.
    assert [p.src for i, p in sorted(judge.policies.items()) if i in (3, 4)] == [
        (0, _ip("10.1.8.255")), (_ip("10.1.10.0"), 2**32 - 1)]  # fmt: skip
    for name, code in (("ping", "SERVICE_NOT_WRITTEN"), ("gre", "SERVICE_NOT_WRITTEN"), ("to-ot", "MOXA_ZONE"), ("six", "NOT_WRITTEN")):
        assert items[name].disabled and code in {f.code for f in items[name].findings}, name
    assert "MOXA_IPV4_ONLY" in {f.code for f in items["block-all-v6"].findings}
    for index, policy in judge.policies.items():
        if not policy.enabled:
            assert policy.src == (0, 0), index  # (a policy written disabled matches nothing as well)
    # After the rules: the source's default between every pair of interfaces written.
    tail = [p for i, p in sorted(judge.policies.items())][-6:]
    assert {p.ifaces for p in tail} == {(a, b) for a in WORDS for b in WORDS if a != b} and all(p.action == "drop" for p in tail)
    assert {"MOXA_LOAD", "MOXA_ZONES", "MOXA_DEFAULT_RULES"} <= codes(report)
    assert not verdict(model, "10.1.2.3", "192.0.2.1", dport=22, ingress="inside", egress="outside")


def test_emitter_numbers_from_the_policy_id_start_and_never_enters_a_policy_twice() -> None:
    model = small_model()
    text, _ = emit(model, Options(zone_map={"inside": "lan", "outside": "wan1", "dmz": "wan2"}, policy_id_start=40))
    judge = MoxaCli.read(text)
    assert min(judge.policies) == 40
    assert "with policies give --policy-id-start" in text


def test_emitter_nat() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.ALLOW)
    p.zones = {name: Zone(name) for name in ("inside", "outside")}
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["range"] = Service("range", [ServiceEntry(Protocol.TCP, "8000-8010")])
    nats = [
        NatRule("fwd", ["outside"], destinations=["203.0.113.10"], service="https", destination_translation=DestNat("10.0.0.5", "8443")),
        NatRule("fwd-dns", ["outside"], destinations=["203.0.113.10"], service="dns", destination_translation=DestNat("10.0.0.6")),
        NatRule("fwd-range", ["outside"], destinations=["203.0.113.10"], service="range", destination_translation=DestNat("10.0.0.7")),
        NatRule("one", dst_zones=["outside"], sources=["10.0.0.8"], source_translation=SourceNat(SnatKind.STATIC, ["203.0.113.8"], bidirectional=True)),
        NatRule("hide", ["inside"], ["outside"], ["10.0.0.0/24"], source_translation=SourceNat(SnatKind.INTERFACE, interface="ethernet1/1")),
        NatRule("hide-any", ["inside"], ["outside"], source_translation=SourceNat(SnatKind.INTERFACE)),
        NatRule("pool", ["inside"], ["outside"], ["10.0.1.0/24"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.20"])),
    ]  # fmt: skip
    for nat in nats:
        nat.origin = nat.name
    p.nat_rules = nats
    text, report = emit(p, Options(zone_map={"inside": "lan", "outside": "wan1"}))
    judge = MoxaCli.read(text)
    assert judge.nat == [
        "static tcp inside lan 10.0.0.5 8443 outside wan 1 443".split(),
        "static all inside lan 10.0.0.6 53 outside wan 1 53".split(),
        "static inside lan 10.0.0.8 outside wan 1 203.0.113.8".split(),
        "dynamic inside lan 10.0.0.0 10.0.0.255 outside wan 1".split(),
    ]  # fmt: skip
    nat_items = {name: item for (kind, name), item in report.items.items() if kind == "nat"}
    assert "MOXA_FORWARD_ADDRESS" in {f.code for f in nat_items["fwd"].findings}
    assert all(nat_items[name].skipped for name in ("fwd-range", "hide-any", "pool"))


def test_the_parser_reads_what_the_emitter_writes_and_compare(tmp_path: Any) -> None:
    model, _ = parse((DATA / "moxa_sample.ini").read_text(encoding="utf-8"))
    text, report = emit(model)
    back, _ = parse(text)
    assert [r.name for r in back.rules] == [f"firewall {n}" for n in range(1, 11)]
    assert "moxa" in cli.READ_BACK and cli.detect_format(text.encode()) == "moxa"
    # Same vendor: the port forward is for the address of WAN 1, as it was; nothing to review about it.
    assert "MOXA_FORWARD_ADDRESS" not in codes(report)
    out = tmp_path / "out.txt"
    assert cli.main(["convert", str(DATA / "moxa_sample.ini"), "--to", "moxa", "-o", str(out), "-q", "--compare"]) == 0


def test_sample_converts_to_every_target(tmp_path: Any) -> None:
    for target in cli.VENDORS:
        out = tmp_path / f"out.{target}"
        assert cli.main(["convert", str(DATA / "moxa_sample.ini"), "--to", target, "-o", str(out), "-q"]) == 0, target
    report = tmp_path / "report.json"
    args = ["convert", str(DATA / "moxa_sample.ini"), "--to", "moxa", "-o", str(tmp_path / "m.txt"), "--report-json", str(report), "-q"]
    assert cli.main(args) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["rule"]["total"] == 10 and data["summary"]["nat"]["total"] == 4
