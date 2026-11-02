# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Siemens SCALANCE (SC-600, S615): parser, emitter, and packet-level checks with a judge of its own.

``ScalanceCli`` reads the commands the emitter writes the way the device's CLI takes them, as Siemens's CLI manuals
describe them: ``configure terminal``, then FIREWALL mode (``firewall``) with IP services, ICMP services and protocols
defined before a rule names them, each name once, only the keywords and value ranges of the manuals; then FIREWALL NAT
mode. It decides packets as the device does (the WBM manual of the SC-600 and the assumptions of the parser): the rules
in ascending priority, first match, rules of equal priority in the order they were entered; what no rule matches
between two interfaces is dropped; traffic inside one VLAN does not pass the firewall. ``random_device`` writes a random
configuration together with the same decision, so the parser is checked against data it did not build. None of it
shares code with the parser or the emitter; it is written from the same reading of Siemens's documentation, so it
finds where the code disagrees with that reading, not where the reading is wrong.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, DestNat, NatRule, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import scalance as parse_scalance
from fwshift.report import Report, Severity

ZONE_MAP = {"eth0": "vlan1", "eth1": "vlan2", "eth2": "vlan3"}
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}


def parse_text(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_scalance.parse(text.encode(), report), report


def notes(report: Report) -> Dict[str, str]:
    return {note.code: note.message for note in report.notes}


# -- the judge: the CLI as the device takes it ----------------------------------------------------------------------------


def _in(address: str, value: str) -> bool:
    """Whether an address is in a value of a rule: ``0.0.0.0/0``, an address, a subnet, ``A-B``."""
    probe = ipaddress.ip_address(address)
    if "-" in value:
        first, last = (ipaddress.ip_address(v.strip()) for v in value.split("-", 1))
        return probe.version == first.version and first <= probe <= last  # type: ignore[operator]
    network = ipaddress.ip_network(value, strict=False)
    return probe.version == network.version and probe in network


@dataclass
class JService:
    kind: str  # service, icmp, proto
    proto: str = ""
    src: Optional[Tuple[int, int]] = None
    dst: Optional[Tuple[int, int]] = None
    icmp: Tuple[int, int, int] = (0, 0, 4)
    number: int = 0


@dataclass
class JRule:
    family: int
    from_if: str
    to_if: str
    src: str
    dst: str
    action: str
    service: str
    prior: int
    order: int


@dataclass
class ScalanceCli:
    services: Dict[str, JService] = field(default_factory=dict)
    rules: List[JRule] = field(default_factory=list)
    nat: List[List[str]] = field(default_factory=list)

    @staticmethod
    def _interface(words: List[str], index: int) -> Tuple[str, int]:
        word = words[index]
        if word in ("vlan", "ipsec", "ppp", "usb"):
            number = words[index + 1]
            assert number.isdigit() and 0 <= int(number) <= 4094, words
            return f"{word} {number}", index + 2
        assert word in ("device", "ipsecALL", "sinemarcall"), f"not an interface of the device: {word}"
        return word, index + 1

    @staticmethod
    def _ports(words: List[str], index: int) -> Tuple[Optional[Tuple[int, int]], int]:
        if words[index] == "all":
            return None, index + 1
        if words[index] == "port":
            port = int(words[index + 1])
            assert 0 <= port <= 65535
            return (port, port), index + 2
        assert words[index] == "range" and words[index + 2] == "-", words
        first, last = int(words[index + 1]), int(words[index + 3])
        assert 0 <= first <= last <= 65535
        return (first, last), index + 4

    def _name(self, name: str) -> None:
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", name), name
        assert name.lower() not in {n.lower() for n in self.services}, f"name given twice: {name}"

    @classmethod
    def read(cls, text: str) -> "ScalanceCli":
        device = cls()
        lines = text.splitlines()
        assert lines[0] == "configure terminal" and lines[-1] == "end", "the commands are for the configuration mode"
        mode = "config"
        for line in lines[1:-1]:
            words = line.split()
            if mode == "config":
                assert words in (["firewall"], ["firewallnat"]), line
                mode = "fw" if words == ["firewall"] else "nat"
                continue
            if words == ["exit"]:
                mode = "config"
                continue
            if mode == "nat":
                assert words[0] in ("masquerading", "napt", "src-nat", "netmap"), line
                device.nat.append(words)
                continue
            if words[:2] == ["service", "name"]:
                device._name(words[2])
                assert words[3] == "proto" and words[4] in ("tcp", "udp") and words[5] == "src", line
                src, index = cls._ports(words, 6)
                assert words[index] == "dst", line
                dst, index = cls._ports(words, index + 1)
                assert index == len(words), line
                device.services[words[2]] = JService("service", words[4], src, dst)
            elif words[:2] == ["icmp", "name"]:
                device._name(words[2])
                assert words[3] == "type" and words[5] == "code" and words[7] == "ver" and words[8] in ("ipv4", "ipv6") and len(words) == 9, line
                assert 0 <= int(words[4]) <= 255 and 0 <= int(words[6]) <= 255
                device.services[words[2]] = JService("icmp", icmp=(int(words[4]), int(words[6]), 4 if words[8] == "ipv4" else 6))
            elif words[:2] == ["proto", "name"]:
                device._name(words[2])
                assert words[3] == "num" and 1 <= int(words[4]) <= 254 and len(words) == 5, line
                device.services[words[2]] = JService("proto", number=int(words[4]))
            elif words[0] in ("ipv4rule", "ipv6rule"):
                assert words[1] == "from", line
                from_if, index = cls._interface(words, 2)
                assert words[index] == "to", line
                to_if, index = cls._interface(words, index + 1)
                assert from_if != to_if, f"traffic inside one interface does not pass the firewall; FWShift writes no rule for it: {line}"
                fields: Dict[str, str] = {}
                while index < len(words):
                    key, value = words[index], words[index + 1]
                    assert key in ("srcip", "dstip", "action", "service", "log", "prior") and key not in fields, line
                    fields[key] = value
                    index += 2
                family = 4 if words[0] == "ipv4rule" else 6
                for side in ("srcip", "dstip"):
                    value = fields[side]
                    first = value.split("-")[0].split("/")[0]
                    assert ipaddress.ip_address(first).version == family, line
                assert fields["action"] in ("acc", "drop", "rej") and fields.get("log", "no") in ("no", "info", "war", "cri"), line
                prior = int(fields["prior"])
                assert 0 <= prior <= 999, line
                service = fields.get("service", "")
                assert not service or service in device.services, f"service used before it is defined: {line}"
                device.rules.append(JRule(family, from_if, to_if, fields["srcip"], fields["dstip"], fields["action"], service, prior,
                                          len(device.rules)))  # fmt: skip
            else:
                raise AssertionError(f"not a command of FIREWALL mode: {line}")
        assert mode == "config"
        return device

    def _service(self, name: str, pkt: Packet, family: int) -> bool:
        if not name:
            return True
        service = self.services[name]
        number = NUMBERS.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        if service.kind == "proto":
            return service.number == number
        if service.kind == "icmp":
            kind, code, version = service.icmp
            return version == family and number == (1 if family == 4 else 58) and pkt.icmp_type == kind and code == 0
        if number != NUMBERS[service.proto]:
            return False
        ok_dst = service.dst is None or service.dst[0] <= pkt.dport <= service.dst[1]
        ok_src = service.src is None or service.src[0] <= pkt.sport <= service.src[1]
        return ok_dst and ok_src

    def allows(self, pkt: Packet) -> bool:
        if pkt.in_if == pkt.out_if:
            return True  # (switched inside the VLAN)
        family = ipaddress.ip_address(pkt.src).version
        for rule in sorted(self.rules, key=lambda r: (r.prior, r.order)):
            if rule.family != family or rule.from_if != pkt.in_if or rule.to_if != pkt.out_if:
                continue
            if not _in(pkt.src, rule.src) or not _in(pkt.dst, rule.dst) or not self._service(rule.service, pkt, family):
                continue
            return rule.action == "acc"
        return False


# -- the sample -------------------------------------------------------------------------------------------------------------


def test_sample_rules_in_order_of_priority() -> None:
    p, report = load("scalance_sample.cfg")
    assert p.vendor == "scalance" and p.default_interzone == Action.DROP and p.default_intrazone == Action.ALLOW
    assert list(p.zones) == ["vlan1", "vlan2", "vlan3", "ipsecALL"]
    assert p.zone_networks["vlan1"] == ["192.168.10.0/24", "10.20.0.0/16"]
    names = [r.name for r in p.rules]
    # No priority is 0: rule 4 first; then 5 (rule 2), 10 (rule 1), 20 (rule 3) ...; the two of 40 in the order entered.
    assert names[:7] == ["ipv4rule 4", "ipv4rule 2", "ipv4rule 1", "ipv4rule 3", "ipv4rule 5", "ipv4rule 6", "ipv4rule 7"]
    assert names[-2:] == ["ipv6rule 1", "ipv6rule 2"]
    assert "ipv4rule 10" not in names  # (to the device)
    assert report.item("rule", "ipv4rule 10").skipped
    by = {r.name: r for r in p.rules}
    assert by["ipv4rule 2"].action == Action.DROP and by["ipv4rule 2"].log_end
    assert by["ipv4rule 3"].sources == ["198.51.100.40-198.51.100.49"] and not by["ipv4rule 3"].log_end
    assert by["ipv4rule 7"].destinations[0] == "192.168.30.64/30"  # ("A - B" as the manuals print it)
    assert by["ipv4rule 8"].action == Action.RESET_CLIENT and by["ipv4rule 8"].services == [ANY]
    assert by["ipv4rule 5"].destinations == ["0.0.0.0/0"]  # (any of the IPv4 list)
    assert by["ipv6rule 2"].destinations == ["::/0"]
    assert by["ipv4rule 13"].src_zones == ["ipsecALL"]
    assert any("DYNAMIC" in u for u in by["ipv4rule 11"].unsupported)
    assert any("ENIP" in u for u in by["ipv4rule 12"].unsupported)
    assert any("rule set maintenance" in u for u in by["ipv4rule 14"].unsupported)
    assert p.services["HTTPS"].entries == [ServiceEntry(Protocol.TCP, "443")]  # (set prot tcp after udp)
    assert p.services["HIGHPORTS"].entries == [ServiceEntry(Protocol.TCP, "8000-8100", "1024-65535")]
    assert p.services["UNREACH"].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]
    assert p.services["PING6"].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=128, icmp_code=0)]
    assert p.services["GRE"].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    found = notes(report)
    assert "SCALANCE_PRERULE" in found and "SCALANCE_RULESET" in found and "SCALANCE_NAT_ORDER" in found


def test_sample_nat_before_the_firewall() -> None:
    p, _ = load("scalance_sample.cfg")
    nat = {n.name: n for n in p.nat_rules}
    assert [n.name for n in p.nat_rules] == ["napt 1", "napt 2", "netmap destination 1", "src-nat 1", "masquerading 1"]
    assert all(n.combines and not n.unsupported for n in p.nat_rules)
    napt = nat["napt 1"]
    assert napt.src_zones == ["vlan2"] and napt.destinations == ["198.51.100.2"]  # (auto: the address of vlan 2)
    assert napt.destination_translation is not None and napt.destination_translation.address == "192.168.30.10"
    assert napt.destination_translation.port == "443" and p.services[napt.service].entries == [ServiceEntry(Protocol.TCP, "8443")]
    assert nat["netmap destination 1"].destination_translation.address == "192.168.30.64/30"  # type: ignore[union-attr]
    src = nat["src-nat 1"].source_translation
    assert src is not None and src.kind == SnatKind.DYNAMIC_PORT and src.addresses == ["198.51.100.3"]
    masq = nat["masquerading 1"].source_translation
    assert masq is not None and masq.kind == SnatKind.INTERFACE and masq.interface_address == "198.51.100.2"
    # The rules named the translated address; the model names the address as it arrives.
    by = {r.name: r for r in p.rules}
    assert p.lookup_after_dnat and "198.51.100.2" in by["ipv4rule 6"].destinations
    assert "198.51.100.64/30" in by["ipv4rule 7"].destinations


def test_detection() -> None:
    data = (DATA / "scalance_sample.cfg").read_bytes()
    assert cli.detect_format(data) == "scalance"
    for name in sorted(p.name for p in DATA.glob("*sample*")):
        if name != "scalance_sample.cfg":
            assert not parse_scalance.looks_like_scalance((DATA / name).read_bytes()), name
    assert not parse_scalance.looks_like_scalance(b"firewall\nservice timestamps\ninterface vlan 1\n ip address 10.0.0.1 255.255.255.0\n")


# -- the traps, one by one -------------------------------------------------------------------------------------------------

BASE = "firewall\nservice name WEB proto tcp src all dst port 80\n"


def test_priority_then_creation_and_changes_by_index() -> None:
    p, _ = parse_text(BASE + "ipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 10.0.0.1 action acc service WEB prior 3\n"
                      "ipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 10.0.0.1 action drop prior 3\n"
                      "ipv4rule from vlan1 to vlan2 srcip 0.0.0.0/0 dstip 0.0.0.0/0 action drop\n"
                      "ipv4rule idx 3 set prior 9\nipv4rule idx 1 set action drop\nipv4rule idx 2 set dstip 10.0.0.0/24\nexit\n")  # fmt: skip
    assert [r.name for r in p.rules] == ["ipv4rule 1", "ipv4rule 2", "ipv4rule 3"]
    assert p.rules[0].action == Action.DROP and p.rules[1].destinations == ["10.0.0.0/24"]
    assert p.rules[2].src_zones == ["vlan1"] and p.rules[2].dst_zones == ["vlan2"]


def test_firewall_switched_off() -> None:
    p, report = parse_text(BASE + "shutdown\nipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 0.0.0.0/0 action drop\nexit\n")
    assert not p.rules[0].enabled and p.default_interzone == Action.ALLOW
    assert "SCALANCE_FIREWALL_OFF" in notes(report)


def test_what_is_not_read_is_never_any() -> None:
    p, report = parse_text(BASE + "ipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 10.0.0.1 action acc schedule night\n"
                           "ipv4rule from vlan 1 to vlan 2 srcip 2001:db8::1 dstip 10.0.0.1 action acc\n"
                           "ipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 10.0.0.1 action allow\n"
                           "icmp name P6 type 128 code 0 ver ipv6\n"
                           "ipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 10.0.0.1 action acc service P6\n"
                           "icmp name ANY type 256 code 256 ver ipv4\n"
                           "ipv4rule from vlan 1 to vlan 2 srcip 0.0.0.0/0 dstip 10.0.0.1 action acc service ANY\n"
                           "user-firewall something\nexit\n")  # fmt: skip
    assert all(rule.unsupported for rule in p.rules)
    assert p.services["ANY"].unsupported
    assert "SCALANCE_UNREAD" in notes(report)


def test_nat_that_cannot_be_read() -> None:
    p, _ = parse_text("firewallnat\nnapt srcint vlan 2 proto tcp type ipv4 dstip auto transip 10.0.0.5 dstport 80 transport 8080\n"
                      "napt srcint vlan 2 proto tcp type ipv4 dstip 192.0.2.1 transip 10.0.0.5 dstport 8000 - 8010 transport 9000 - 9010\n"
                      "napt srcint vlan 2 proto tcp type ipv4 dstip 192.0.2.1 transip 10.0.0.5 dstport 8000 - 8010 transport 80\n"
                      "netmap destination srcint vlan 2 dstint vlan 1 type ipv4 srcip 0.0.0.0/0 dstip 192.0.2.0/29 transip 10.0.0.0/28\n"
                      "exit\n")  # fmt: skip
    first, shifted, many_to_one, netmap = p.nat_rules
    assert any("auto" in u for u in first.unsupported)  # (no address of vlan 2 in the configuration)
    assert shifted.unsupported and not many_to_one.unsupported and netmap.unsupported
    assert many_to_one.destination_translation is not None and many_to_one.destination_translation.port == "80"


def test_not_a_scalance_configuration() -> None:
    with pytest.raises(ParseError):
        parse_text("interface vlan 1\nip address 10.0.0.1 255.255.255.0\nexit\n")


# -- the emitter -------------------------------------------------------------------------------------------------------------


def test_sample_to_itself_reads_back_and_decides_alike() -> None:
    p, report = load("scalance_sample.cfg")
    text = cli.convert(p, "scalance", report)
    device = ScalanceCli.read(text)
    assert [r.prior for r in device.rules] == sorted(r.prior for r in device.rules)
    assert any(words[0] == "napt" and "443" in words for words in device.nat)
    assert ["masquerading", "vlan", "2"] in device.nat
    back, _ = parse_text(text)
    rng = random.Random(5)
    zones = {"vlan1": "vlan 1", "vlan2": "vlan 2", "vlan3": "vlan 3", "ipsecALL": "ipsecALL"}
    pool4 = ["192.168.10.20", "192.168.10.30", "192.168.10.77", "198.51.100.10", "198.51.100.45", "198.51.100.200", "192.168.30.10",
             "192.168.30.65", "10.30.1.1", "10.20.3.4"]  # fmt: skip
    pool6 = ["2001:db8:1::10", "2001:db8:1::99", "2001:db8:2::5", "2001:db8:9::1"]
    for _ in range(3000):
        family = rng.choice([4, 4, 6])
        pool = pool4 if family == 4 else pool6
        a, b = rng.sample(list(zones), 2)
        pkt = Packet(a, b, rng.choice(pool), rng.choice(pool), rng.choice(["tcp", "udp", "icmp" if family == 4 else "icmp6", "47"]),
                     rng.choice([1024, 40000]), rng.choice([102, 443, 502, 514, 4840, 8050]), rng.choice([0, 3, 8, 128]))  # fmt: skip
        if family == 4 and pkt.proto == "icmp" and pkt.icmp_type == 3:
            continue  # (the judge's packets have code 0; the sample allows code 4)
        expected = model_allows(p, pkt)
        assert model_allows(back, pkt) == expected, pkt
        written = Packet(zones[a], zones[b], pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        # The rules of the output name the translated address, as the device sees it; the model the address as it arrives.
        if not any(pkt.dst in (n.destinations[0],) or (n.destination_translation and pkt.dst == n.destination_translation.address)
                   for n in p.nat_rules):  # fmt: skip
            assert device.allows(written) == expected, pkt


def equal_seeds() -> List[int]:
    return list(range(30))


@pytest.mark.parametrize("seed", equal_seeds())
def test_emitted_rules_decide_like_the_model(seed: int) -> None:
    """Random models written for the device: the judge decides every packet between two interfaces as the model does,
    unless a rule was left out (then the report says so, and the model is set aside)."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.negate_service = False  # (a rule of the device names one service: left out, tested below)
    for zone in ZONE_MAP:
        model.zones[zone] = Zone(zone)  # ("any" is written for the zones the policy names)
    report = Report()
    text = cli.convert(model, "scalance", report, Options(zone_map=dict(ZONE_MAP)))
    device = ScalanceCli.read(text)
    left_out = [i for i in report.items.values() if i.kind == "rule" and i.skipped
                and not any(f.code in ("SCALANCE_INTRAZONE", "DISABLED_NOT_WRITTEN") for f in i.findings)]  # fmt: skip
    if left_out:
        assert all(any(f.severity == Severity.REVIEW for f in i.findings) for i in left_out)
        pytest.skip("a rule was left out, and said so")
    names = {"eth0": "vlan 1", "eth1": "vlan 2", "eth2": "vlan 3"}
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if pkt.in_if == pkt.out_if:
            continue
        written = Packet(names[pkt.in_if], names[pkt.out_if], pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        assert device.allows(written) == model_allows(model, pkt), (seed, pkt)


def test_most_random_models_are_written_whole() -> None:
    whole = 0
    for seed in equal_seeds():
        model = random_model(random.Random(seed))
        for rule in model.rules:
            rule.negate_service = False
        for zone in ZONE_MAP:
            model.zones[zone] = Zone(zone)
        report = Report()
        cli.convert(model, "scalance", report, Options(zone_map=dict(ZONE_MAP)))
        whole += not any(i.kind == "rule" and i.skipped and not any(f.code in ("SCALANCE_INTRAZONE", "DISABLED_NOT_WRITTEN") for f in i.findings)
                         for i in report.items.values())  # fmt: skip
    assert whole >= len(equal_seeds()) // 2


def small(rules: List[Rule], **kwargs: object) -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    for zone in ("vlan1", "vlan2", "vlan3"):
        p.zones[zone] = Zone(zone)
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["unreach"] = Service("unreach", [ServiceEntry(Protocol.ICMP, icmp_type=3)])
    p.services["all-icmp"] = Service("all-icmp", [ServiceEntry(Protocol.ICMP)])
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    for key, value in kwargs.items():
        setattr(p, key, value)
    return p


def test_priorities_per_run_of_one_action_and_the_default_at_the_end() -> None:
    p = small([Rule("a", ["vlan1"], ["vlan2"], ["10.0.0.0/24"], ["10.1.0.1"], ["web"]),
               Rule("b", ["vlan1"], ["vlan2"], ["10.0.0.0/24"], [ANY], action=Action.DROP),
               Rule("c", ["vlan2"], ["vlan1"], [ANY], ["10.0.0.5"], ["all-icmp"])])  # fmt: skip
    report = Report()
    device = ScalanceCli.read(cli.convert(p, "scalance", report, Options(policy_id_start=10)))
    priors = {(r.from_if, r.to_if, r.action, r.src, r.dst): r.prior for r in device.rules}
    assert priors[("vlan 1", "vlan 2", "acc", "10.0.0.0/24", "10.1.0.1")] == 10
    assert priors[("vlan 1", "vlan 2", "drop", "10.0.0.0/24", "0.0.0.0/0")] == 11
    assert priors[("vlan 2", "vlan 1", "acc", "0.0.0.0/0", "10.0.0.5")] == 12
    assert priors[("vlan 1", "vlan 3", "drop", "0.0.0.0/0", "0.0.0.0/0")] == 13  # (the default, for every pair)
    assert sum(1 for r in device.rules if r.service and device.services[r.service].kind == "service") == 2  # (80 and 443)
    assert any(device.services[r.service].kind == "proto" and device.services[r.service].number == 1 for r in device.rules if r.service)
    assert "SCALANCE_DEFAULT_RULES" in notes(report)


def test_default_accept_and_the_zone_that_blocks_inside() -> None:
    p = small([Rule("a", ["vlan1"], ["vlan2"], action=Action.DROP)], default_interzone=Action.ALLOW, default_intrazone=Action.DENY)
    report = Report()
    device = ScalanceCli.read(cli.convert(p, "scalance", report))
    assert device.rules[-1].action == "acc"
    assert not device.allows(Packet("vlan 1", "vlan 2", "10.0.0.1", "10.0.0.2", "tcp", 1, 80))
    assert device.allows(Packet("vlan 2", "vlan 1", "10.0.0.1", "10.0.0.2", "tcp", 1, 80))
    assert {"SCALANCE_DEFAULT_ACCEPT", "SCALANCE_INTRAZONE_DEFAULT", "SCALANCE_IPV4_ONLY"} <= set(notes(report))


def test_icmp_type_without_code_becomes_every_code_of_it() -> None:
    p = small([Rule("a", ["vlan1"], ["vlan2"], services=["unreach"])])
    device = ScalanceCli.read(cli.convert(p, "scalance", Report()))
    codes = sorted(s.icmp[1] for s in device.services.values() if s.kind == "icmp")
    assert codes == list(range(16))


def test_what_the_device_cannot_say_is_left_out_and_said() -> None:
    p = small([Rule("neg", ["vlan1"], ["vlan2"], services=["web"], negate_service=True, action=Action.DROP),
               Rule("off", ["vlan1"], ["vlan2"], enabled=False),
               Rule("inside", ["vlan1"], ["vlan1"], scope=RuleScope.INTRAZONE, action=Action.DROP),
               Rule("reset", ["vlan1"], ["vlan3"], action=Action.RESET_BOTH),
               Rule("trust", ["trust"], ["vlan2"])])  # fmt: skip
    report = Report()
    text = cli.convert(p, "scalance", report)
    neg, off, inside = report.item("rule", "neg"), report.item("rule", "off"), report.item("rule", "inside")
    assert neg.skipped and any("NOT enforced" in f.message for f in neg.findings)
    assert off.skipped and inside.skipped and inside.findings[0].severity == Severity.REVIEW
    assert any(f.code == "SCALANCE_REJECT" for f in report.item("rule", "reset").findings)
    assert "action rej" in text and "from trust to vlan 2" in text
    assert "SCALANCE_ZONE_NAMES" in notes(report)
    with pytest.raises(AssertionError):
        ScalanceCli.read(text)  # (the device refuses an interface named trust)


def test_nat_written_for_the_device() -> None:
    p = small([Rule("in", ["vlan2"], ["vlan1"], [ANY], ["198.51.100.10"], ["web"])])
    p.services["tcp-8080"] = Service("tcp-8080", [ServiceEntry(Protocol.TCP, "8080")])
    p.nat_rules = [NatRule("fwd", ["vlan2"], ["vlan2"], destinations=["198.51.100.10"], service="tcp-8080",
                           destination_translation=DestNat("10.0.0.10", "80")),
                   NatRule("out", dst_zones=["vlan2"], source_translation=SourceNat(SnatKind.INTERFACE, interface="vlan2")),
                   NatRule("pool", ["vlan1"], ["vlan2"], sources=["10.0.0.0/24"], service="web",
                           source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.3"]))]  # fmt: skip
    for nat in p.nat_rules:
        nat.origin = nat.name
    report = Report()
    device = ScalanceCli.read(cli.convert(p, "scalance", report))
    assert device.nat[0] == "napt srcint vlan 2 proto tcp type ipv4 dstip 198.51.100.10 transip 10.0.0.10 dstport 8080 transport 80".split()
    assert device.nat[1] == ["masquerading", "vlan", "2"]
    assert report.item("nat", "pool").skipped  # (source NAT names no service on the device)


def test_prefix_and_priority_start_are_checked() -> None:
    p = small([Rule("a", ["vlan1"], ["vlan2"])])
    with pytest.raises(FwshiftError):
        cli.convert(p, "scalance", Report(), Options(object_prefix="9bad prefix"))
    with pytest.raises(FwshiftError):
        cli.convert(p, "scalance", Report(), Options(policy_id_start=1000))


# -- random configurations, read by the parser ---------------------------------------------------------------------------

LITERALS = ["0.0.0.0/0", "10.1.0.0/24", "10.1.0.5", "10.2.0.0/16", "10.1.0.1-10.1.0.9", "10.2.3.0 - 10.2.3.40", "192.0.2.0/25"]
SERVICES = {"WEB": ("tcp", None, (80, 80)), "HI": ("tcp", (1024, 65535), (8000, 8010)), "DNS": ("udp", None, (53, 53))}


@dataclass
class _GenRule:
    from_if: int
    to_if: int
    src: str
    dst: str
    action: str
    service: str
    prior: Optional[int]


def random_device(rng: random.Random) -> Tuple[str, List[_GenRule]]:
    lines = ["configure terminal"]
    for vlan in (1, 2, 3):
        lines += [f"vlan {vlan}", f"name v{vlan}", "exit", f"interface vlan {vlan}", f"ip address 10.{vlan}.0.1 255.255.0.0", "exit"]
    lines.append("firewall")
    for name, (proto, src, dst) in SERVICES.items():
        def ports(r: Optional[Tuple[int, int]]) -> str:
            return "all" if r is None else (f"port {r[0]}" if r[0] == r[1] else f"range {r[0]} - {r[1]}")
        lines.append(f"service name {name} proto {proto} src {ports(src)} dst {ports(dst)}")
    lines += ["icmp name PING type 8 code 0 ver ipv4", "proto name GRE num 47"]
    rules: List[_GenRule] = []
    for _ in range(rng.randint(4, 14)):
        a, b = rng.choice([(1, 2), (1, 2), (2, 1), (1, 3)])  # (few pairs, so that rules overlap and their order decides)
        rule = _GenRule(a, b, rng.choice(LITERALS), rng.choice(LITERALS), rng.choice(["acc", "acc", "drop", "rej"]),
                        rng.choice(["", "", "", "WEB", "HI", "DNS", "PING", "GRE"]), rng.choice([None, 0, 1, 2, 5]))  # fmt: skip
        rules.append(rule)
        line = f"ipv4rule from vlan {a} to vlan {b} srcip {rule.src} dstip {rule.dst} action {rule.action}"
        line += f" service {rule.service}" if rule.service else ""
        line += f" log {rng.choice(['no', 'info'])}" if rng.random() < 0.5 else ""
        line += f" prior {rule.prior}" if rule.prior is not None else ""
        lines.append(line)
    for _ in range(rng.randint(0, 2)):
        index = rng.randrange(len(rules))
        rules[index].prior = rng.choice([0, 3, 4])
        lines.append(f"ipv4rule idx {index + 1} set prior {rules[index].prior}")
    lines += ["exit", "end"]
    return "\n".join(lines) + "\n", rules


def device_decides(rules: List[_GenRule], pkt: Packet) -> bool:
    if pkt.in_if == pkt.out_if:
        return True
    order = sorted(range(len(rules)), key=lambda i: (rules[i].prior or 0, i))
    for index in order:
        rule = rules[index]
        if f"vlan{rule.from_if}" != pkt.in_if or f"vlan{rule.to_if}" != pkt.out_if:
            continue
        if not _in(pkt.src, rule.src.replace(" ", "")) or not _in(pkt.dst, rule.dst.replace(" ", "")):
            continue
        if rule.service:
            if rule.service == "PING":
                if not (pkt.proto == "icmp" and pkt.icmp_type == 8):
                    continue
            elif rule.service == "GRE":
                if pkt.proto != "47":
                    continue
            else:
                proto, src, dst = SERVICES[rule.service]
                if pkt.proto != proto or not (dst[0] <= pkt.dport <= dst[1]) or (src and not src[0] <= pkt.sport <= src[1]):
                    continue
        return rule.action == "acc"
    return False


@pytest.mark.parametrize("seed", range(40))
def test_parsed_configuration_decides_like_the_device(seed: int) -> None:
    rng = random.Random(1000 + seed)
    text, rules = random_device(rng)
    p, _ = parse_text(text)
    assert not any(r.unsupported for r in p.rules)
    hosts = ["10.1.0.5", "10.1.0.77", "10.2.3.20", "10.2.9.9", "10.3.0.4", "192.0.2.10", "198.51.100.1"]
    for _ in range(300):
        a, b = rng.choice([("vlan1", "vlan2"), ("vlan2", "vlan1"), ("vlan1", "vlan3"), ("vlan3", "vlan2")])
        pkt = Packet(a, b, rng.choice(hosts), rng.choice(hosts), rng.choice(["tcp", "udp", "icmp", "47"]), rng.choice([1000, 2000]),
                     rng.choice([53, 80, 8005, 9000]), rng.choice([0, 8]))  # fmt: skip
        assert model_allows(p, pkt) == device_decides(rules, pkt), (seed, pkt, text)
    # And written back for the device, the judge agrees as well.
    device = ScalanceCli.read(cli.convert(copy.deepcopy(p), "scalance", Report()))
    for _ in range(200):
        a, b = rng.sample(["vlan1", "vlan2", "vlan3"], 2)
        pkt = Packet(a, b, rng.choice(hosts), rng.choice(hosts), rng.choice(["tcp", "udp", "icmp", "47"]), rng.choice([1000, 2000]),
                     rng.choice([53, 80, 8005, 9000]), rng.choice([0, 8]))  # fmt: skip
        written = Packet(a.replace("vlan", "vlan "), b.replace("vlan", "vlan "), pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        assert device.allows(written) == device_decides(rules, pkt), (seed, pkt)
