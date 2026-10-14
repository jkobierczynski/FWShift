# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Forcepoint NGFW: the parser against policies made up at random, the emitter against the model through a made-up SMC,
the loader and the dump program against that SMC, and both by hand.

The judge of what an engine does with a policy is ``helpers.ForcepointSmc``, which reads the answers of the SMC API on
its own; the made-up SMC is ``fake_smc.FakeSmc``. Every policy here is made up; the addresses are documentation and
private ones.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fake_smc import FakeSmc
from helpers import DATA, ForcepointSmc
from test_iptables import Packet, model_allows, random_model

from fwshift import cli, transform
from fwshift.emitters import smc_loader
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, NatRule, Policy, Rule, SnatKind, Zone
from fwshift.options import Options
from fwshift.parsers import forcepoint as parse_forcepoint
from fwshift.parsers import smc_dump
from fwshift.report import Report

BASE = "https://smc.example.net:8082/7.4"
E = f"{BASE}/elements"
LISTS = ("fw_ipv4_access_rule", "fw_ipv6_access_rule", "fw_ipv4_nat_rule", "fw_ipv6_nat_rule")
ZONES = ["Internal", "External", "DMZ"]
KEY = "secret-key"


def parse(text: str, policy: str = "") -> Tuple[Policy, Report]:
    report = Report()
    return parse_forcepoint.parse(text.encode("utf-8"), report, policy=policy), report


def codes(report: Report) -> List[str]:
    return [f.code for f in report.notes] + [f.code for item in report.items.values() for f in item.findings]


# -- answers of an SMC, made up -------------------------------------------------------------------------------------


class Answers:
    """The answers of the SMC API for one policy, as the dump program writes them, built up piece by piece."""

    def __init__(self) -> None:
        self.out: List[Dict[str, Any]] = []
        self.key = 1000

    def _next(self) -> int:
        self.key += 1
        return self.key

    def element(self, kind: str, name: str, **fields: Any) -> str:
        href = f"{E}/{kind}/{self._next()}"
        self.out.append({"name": name, **fields, "link": [{"rel": "self", "href": href}]})
        return href

    def policy(self, kind: str, name: str, template: Optional[str] = None, system: bool = False, lists: Tuple[str, ...] = LISTS) -> str:
        href = f"{E}/{kind}/{self._next()}"
        body: Dict[str, Any] = {"name": name, "system": system, "link": [{"rel": "self", "href": href}]}
        if kind != "sub_ipv4_fw_policy":
            body["template"] = template
        body["link"] += [{"rel": rel + "s", "href": f"{href}/{rel}"} for rel in lists]
        self.out.append(body)
        return href

    def rules(self, parent: str, rel: str, entries: List[Dict[str, Any]]) -> List[str]:
        where = f"{parent}/{rel}"
        hrefs = []
        listing: Dict[str, Any] = {"fwshift_list": where, "result": []}
        self.out.append(listing)
        for entry in entries:
            href = f"{where}/{self._next()}"
            hrefs.append(href)
            listing["result"].append({"href": href, "name": entry.get("name", ""), "type": rel})
            self.out.append({**entry, "tag": f"{href.rsplit('/', 1)[-1]}.0", "link": [{"rel": "self", "href": href}]})
        return hrefs

    def text(self) -> str:
        return "\n".join(json.dumps(answer) for answer in self.out) + "\n"


def rule(src: Any, dst: Any, svc: Any, action: Any, name: str = "", log: str = "undefined", **extra: Any) -> Dict[str, Any]:
    def cell(value: Any, key: str) -> Dict[str, Any]:
        if value in ("any", None):
            return {"any": True}
        if value == "none":
            return {"none": True}
        return {key: list(value)}

    body = {"sources": cell(src, "src"), "destinations": cell(dst, "dst"), "services": cell(svc, "service"),
            "action": action if isinstance(action, dict) else {"action": [action]}, "options": {"log_level": log}, "is_disabled": False}  # fmt: skip
    if name:
        body["name"] = name
    body.update(extra)
    return body


def insert_point(name: str = "Insert Point", kind: str = "normal", **extra: Any) -> Dict[str, Any]:
    return {"name": name, "type": kind, **extra}


def base_template(a: Answers, extra_v4: Optional[List[Dict[str, Any]]] = None) -> Tuple[str, Dict[str, str]]:
    """The predefined template: (its href, the insert point of each list)."""
    top = a.policy("fw_template_policy", "Firewall Template", None, system=True)
    ident = a.element("tcp_service", "Ident", min_dst_port=113, system=True)
    points: Dict[str, str] = {}
    for rel in LISTS:
        entries = list(extra_v4 or []) if rel == "fw_ipv4_access_rule" else []
        entries.append(insert_point())
        if rel.endswith("access_rule"):
            entries += [rule("any", "any", [ident], "refuse", log="stored"), rule("any", "any", "any", "discard", log="stored")]
        hrefs = a.rules(top, rel, entries)
        points[rel] = hrefs[len(entries) - (3 if rel.endswith("access_rule") else 1)]
    return top, points


# -- a policy made up at random ---------------------------------------------------------------------------------------

V4 = {"Internal": "10.0.1.", "DMZ": "192.168.10.", "External": "203.0.113."}
V6 = {"Internal": "2001:db8:1::", "DMZ": "2001:db8:10::", "External": "2001:db8:99::"}
PORTS = [22, 25, 53, 80, 443, 8000, 8005, 8443, 9000]


def random_smc(rng: random.Random) -> str:
    a = Answers()
    zones = {zone: a.element("interface_zone", zone) for zone in ZONES}
    hosts = [a.element("host", f"h{n}", address=V4[z] + str(10 + n), secondary=[V4[z] + str(60 + n)] if n % 3 == 0 else [])
             for n, z in enumerate(ZONES * 2)]  # fmt: skip
    dual = a.element("host", "dual", address="192.168.10.25", ipv6_address="2001:db8:10::25")
    lan = a.element("network", "lan", ipv4_network="10.0.1.0/24", broadcast=rng.random() < 0.5)
    dmz = a.element("network", "dmz", ipv4_network="192.168.10.0/28", broadcast=False)
    lan6 = a.element("network", "lan6", ipv6_network="2001:db8:1::/64")
    span = a.element("address_range", "span", ip_range="10.0.1.40-10.0.1.70")
    span6 = a.element("address_range", "span6", ip_range="2001:db8:10::20-2001:db8:10::30")
    grp = a.element("group", "grp", element=[hosts[0], dmz, span6])
    nested = a.element("group", "nested", element=[grp, hosts[2], lan])
    lone = a.element("expression", "not lan", operator="exclusion", ne_ref=[lan], sub_expression=[])
    inter = a.element("expression", "lan but span", operator="intersection", ne_ref=[lan],
                      sub_expression=[{"operator": "exclusion", "ne_ref": [span], "sub_expression": []}])  # fmt: skip
    union = a.element("expression", "two", operator="union", ne_ref=[hosts[1], hosts[4]], sub_expression=[])
    rows = [a.element("match_expression", f"row{n}", ref=[zones[z], addr]) for n, (z, addr) in
            enumerate([("Internal", lan), ("DMZ", dmz), ("External", hosts[2]), ("Internal", span)])]  # fmt: skip
    addresses = hosts + [dual, lan, dmz, span, grp, nested, inter, union] + list(zones.values()) + rows
    six = [lan6, span6, dual, grp] + list(zones.values())
    tcp = [a.element("tcp_service", f"tcp{p}", min_dst_port=p) for p in (22, 80, 443)]
    tcp += [a.element("tcp_service", "tcp8000-8010", min_dst_port=8000, max_dst_port=8010)]
    tcp += [a.element("tcp_service", "smtp from high", min_dst_port=25, min_src_port=1024, max_src_port=65535)]
    udp = [a.element("udp_service", "dns", min_dst_port=53)]
    icmp = [a.element("icmp_service", "ping", icmp_type=8), a.element("icmp_ipv6_service", "ping6", icmp_type=128)]
    gre = a.element("ip_service", "gre", protocol_number=47)
    web = a.element("service_group", "web", element=[tcp[1], tcp[2], tcp[3]])
    services = tcp + udp + icmp + [gre, web]

    def pick(pool: List[str], none: bool = True) -> Any:
        roll = rng.random()
        if roll < 0.25:
            return "any"
        if none and roll < 0.28:
            return "none"
        return rng.sample(pool, rng.randint(1, 3))

    def action() -> Any:
        return rng.choice(["allow", "allow", "discard", "refuse", "continue"])

    def random_rule(pool: List[str], index: int, prefix: str = "r") -> Dict[str, Any]:
        verb = action()
        src = [lone] if rng.random() < 0.1 else pick(pool)
        dst = [lone] if rng.random() < 0.1 else pick(pool)
        body = rule(src, dst, pick(services), verb, name=f"{prefix}{index}", log=rng.choice(["undefined", "stored", "none"]))
        body["is_disabled"] = rng.random() < 0.1
        return body

    top, points = base_template(a)
    template = top
    if rng.random() < 0.5:
        # A template of its own between: rules around its insert point.
        template = a.policy("fw_template_policy", "Branch Template", top)
        mine: Dict[str, str] = {}
        for rel in LISTS:
            entries = [insert_point("Policy rules", parent_insert_point=points[rel])]
            if rel == "fw_ipv4_access_rule":
                entries = [random_rule(addresses, 0, "t") | {"parent_insert_point": points[rel]}] + entries
                entries.append(random_rule(addresses, 1, "t") | {"parent_insert_point": points[rel]})
            hrefs = a.rules(template, rel, entries)
            mine[rel] = hrefs[1 if rel == "fw_ipv4_access_rule" else 0]
        points = mine
    policy = a.policy("fw_policy", "Random", template)
    v4: List[Dict[str, Any]] = []
    for index in range(rng.randint(4, 12)):
        if rng.random() < 0.1:
            v4.append({"comment": f"section {index}"})
        body = random_rule(addresses, index)
        if rng.random() < 0.12:
            sub = a.policy("sub_ipv4_fw_policy", f"sub{index}", lists=("fw_ipv4_access_rule",))
            inner = []
            for n in range(rng.randint(1, 3)):
                child = random_rule(addresses, n, f"s{index}-")
                child["services"] = {"any": True} if rng.random() < 0.6 else body["services"]
                if child["action"]["action"] == ["continue"]:
                    child["action"] = {"action": ["allow"]}
                inner.append(child)
            a.rules(sub, "fw_ipv4_access_rule", inner)
            body["action"] = {"action": ["jump"], "sub_policy": sub}
        v4.append(body)
    v6 = [random_rule(six, n, "six") for n in range(rng.randint(1, 4))]
    nat: List[Dict[str, Any]] = []
    public = a.element("host", "public", address="203.0.113.200")
    for n in range(rng.randint(0, 4)):
        kind = rng.choice(["dst", "dynamic", "static", "none", "alias"])
        body = rule("any", "any", "any", "allow", name=f"nat{n}")
        del body["action"]
        body["used_on"] = {"any": True}
        if kind == "dst":
            body["destinations"] = {"dst": [public]}
            body["services"] = {"service": [tcp[2]]}
            port = rng.choice([None, 8443])
            translated: Dict[str, Any] = {"element": hosts[1], "ip_descriptor": V4["DMZ"] + "11"}
            original: Dict[str, Any] = {"element": public, "ip_descriptor": "203.0.113.200"}
            if port:
                original.update({"min_port": "443", "max_port": "443"})
                translated.update({"min_port": str(port), "max_port": str(port)})
            body["options"]["static_dst_nat"] = {"automatic_proxy": True, "original_value": original, "translated_value": translated}
        elif kind == "dynamic":
            body["sources"] = {"src": [lan]}
            body["options"]["dynamic_src_nat"] = {"translation_values": [{"ip_descriptor": "203.0.113.1", "min_port": 1024, "max_port": 65535}]}
        elif kind == "static":
            body["sources"] = {"src": [hosts[1]]}
            body["options"]["static_src_nat"] = {"original_value": {"element": hosts[1]}, "translated_value": {"ip_descriptor": "203.0.113.111"}}
        elif kind == "none":
            body["sources"] = {"src": [lan]}
            body["destinations"] = {"dst": [dmz]}
        nat.append(body)
    a.rules(policy, "fw_ipv4_access_rule", [dict(e, parent_insert_point=points["fw_ipv4_access_rule"]) for e in v4])
    a.rules(policy, "fw_ipv6_access_rule", [dict(e, parent_insert_point=points["fw_ipv6_access_rule"]) for e in v6])
    a.rules(policy, "fw_ipv4_nat_rule", [dict(e, parent_insert_point=points["fw_ipv4_nat_rule"]) for e in nat])
    a.rules(policy, "fw_ipv6_nat_rule", [])
    return a.text()


def random_packet(rng: random.Random, zones: List[str] = ZONES) -> Packet:
    family = 6 if rng.random() < 0.25 else 4
    table = V4 if family == 4 else V6
    in_if, out_if = rng.choice(zones), rng.choice(zones)

    def address(zone: str) -> str:
        roll = rng.random()
        if family == 4:
            if roll < 0.15:
                return rng.choice(["10.0.1.0", "10.0.1.255", "192.168.10.0", "192.168.10.15", "203.0.113.200"])
            return table.get(zone, "198.51.100.") + str(rng.choice([1, 10, 11, 12, 13, 14, 15, 25, 40, 55, 60, 63, 70, 71, 200]))
        return table.get(zone, "2001:db8:77::") + format(rng.choice([1, 0x10, 0x11, 0x20, 0x25, 0x31]), "x")

    proto = rng.choice(["tcp", "tcp", "udp", "icmp" if family == 4 else "icmp6", "47"])
    pkt = Packet(in_if, out_if, address(in_if), address(out_if), proto)
    if proto in ("tcp", "udp"):
        pkt.dport = rng.choice(PORTS)
        pkt.sport = rng.choice([514, 1023, 40000])
    elif proto.startswith("icmp"):
        pkt.icmp_type = rng.choice([8, 128, 0])
    return pkt


def model_nat(p: Policy, pkt: Packet) -> Tuple[str, str, str]:
    """(source, destination, port) of a packet as the first NAT rule of the model that matches it leaves it."""
    from test_iptables import _entry_matches, _member_matches

    for nat in p.nat_rules:
        if not nat.enabled or nat.unsupported:
            continue
        if not any(_member_matches(p, m, pkt.src) for m in nat.sources) or not any(_member_matches(p, m, pkt.dst) for m in nat.destinations):
            continue
        if nat.service != ANY and not any(_entry_matches(e, pkt) for e in transform.flatten_services(p, nat.service) or []):
            continue
        src, dst, port = pkt.src, pkt.dst, pkt.dport
        if nat.destination_translation is not None:
            dst = start(p, nat.destination_translation.address)
            port = int(nat.destination_translation.port or port)
        how = nat.source_translation
        if how is not None:
            src = "MASQ" if how.kind == SnatKind.INTERFACE else start(p, how.addresses[0])
        return ("Original" if src == pkt.src else src, "Original" if dst == pkt.dst else dst, "Original" if port == pkt.dport else str(port))
    return ("Original", "Original", "Original")


def start(p: Policy, member: str) -> str:
    intervals = transform.address_intervals(p, member) or []
    assert intervals, member
    return str(ipaddress.ip_address(intervals[0][1]) if intervals[0][0] == 4 else ipaddress.IPv6Address(intervals[0][1]))


# -- the parser against the judge -------------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(60))
def test_parsed_policy_decides_like_the_engine(seed: int) -> None:
    """Templates and insert points, sections, Continue, jumps, zones and match expressions, expressions, networks without
    broadcast, NONE cells: the model decides every packet as the engine would."""
    rng = random.Random(seed)
    text = random_smc(rng)
    judge = ForcepointSmc(text)
    p, report = parse(text)
    for rule_ in p.rules:
        assert not rule_.unsupported or rule_.action != Action.DROP or not rule_.enabled, (seed, rule_.name, rule_.unsupported)
    unsupported = [r.name for r in p.rules if r.unsupported]
    assert not unsupported, (seed, unsupported, report.to_text())
    for _ in range(400):
        pkt = random_packet(rng)
        assert model_allows(p, pkt) == judge.allows(pkt), (seed, pkt, judge.deciding(pkt))


@pytest.mark.parametrize("seed", range(40))
def test_parsed_nat_translates_like_the_engine(seed: int) -> None:
    rng = random.Random(500 + seed)
    text = random_smc(rng)
    judge = ForcepointSmc(text)
    p, report = parse(text)
    assert not [n.name for n in p.nat_rules if n.unsupported], (seed, report.to_text())
    for _ in range(300):
        pkt = random_packet(rng)
        if ":" in pkt.src:
            continue
        assert model_nat(p, pkt) == judge.translation(pkt), (seed, pkt)


# -- the emitter, through the made-up SMC -----------------------------------------------------------------------------


def plan_of(text: str) -> Dict[str, Any]:
    assert text.startswith("#!/usr/bin/env python3\n")
    head, marker, tail = text.partition("\n# The policy, as data.")
    assert marker and "def main(" in head
    return dict(json.loads("\n".join(line[3:] for line in tail.splitlines() if line.startswith("#: "))))


def load_into(text: str, smc: Optional[FakeSmc] = None, name: str = "FWShift", journal: str = "", extra: Optional[List[str]] = None,
              monkeypatch: Any = None) -> Tuple[FakeSmc, int, List[str]]:  # fmt: skip
    smc = smc or FakeSmc(KEY)
    said: List[str] = []
    import os

    old = os.environ.get("SMC_API_KEY")
    os.environ["SMC_API_KEY"] = KEY
    try:
        if not journal:
            import tempfile

            journal = os.path.join(tempfile.mkdtemp(), "journal.json")
        argv = ["--host", "smc.example.net", "--journal", journal] + (extra or [])
        status = smc_loader.main(argv, transport=smc, say=said.append, plan=plan_of(text))
    finally:
        if old is None:
            os.environ.pop("SMC_API_KEY", None)
        else:
            os.environ["SMC_API_KEY"] = old
    return smc, status, said


def emitted(model: Policy, options: Optional[Options] = None, tmp: Optional[Path] = None) -> Tuple[ForcepointSmc, Report, str, FakeSmc]:
    report = Report()
    text = cli.convert(copy.deepcopy(model), "forcepoint", report, options or Options())
    journal = str(tmp / "journal.json") if tmp else ""
    smc, status, said = load_into(text, journal=journal)
    assert status == 0, said
    dump = smc.dump_policy((options or Options()).target_policy)
    return ForcepointSmc(dump), report, text, smc


def as_written(model: Policy, report: Report) -> Policy:
    """The model with the rules the emitter wrote disabled switched off: what the output is to decide like."""
    out = copy.deepcopy(model)
    for rule_ in out.rules:
        item = report.items.get(("rule", rule_.origin))
        if item is not None and item.disabled:
            rule_.enabled = False
    return out


@pytest.mark.parametrize("seed", range(40))
def test_emitted_policy_decides_like_the_model(seed: int, tmp_path: Path) -> None:
    """Whatever the lists, negations, zones and rule types: the policy loaded into an SMC decides as the model, but for
    the rules written disabled, and only those with a negated service are."""
    from test_iptables import ZONES as IFACES

    rng = random.Random(seed)
    model = random_model(rng)
    for zone in IFACES:
        model.zones[zone] = Zone(zone, [zone])
    model.default_interzone, model.default_intrazone = rng.choice([(Action.DENY, Action.DENY), (Action.ALLOW, Action.DENY),
                                                                   (Action.DENY, Action.ALLOW), (Action.ALLOW, Action.ALLOW)])  # fmt: skip
    model.zones[IFACES[0]].intrazone_allow = rng.choice([None, True, False])
    judge, report, _, _ = emitted(model, tmp=tmp_path)
    for rule_ in model.rules:
        item = report.items.get(("rule", rule_.origin))
        assert not (item and item.disabled) or rule_.negate_service, (seed, rule_.name, report.to_text())
    written = as_written(model, report)
    for _ in range(400):
        pkt = random_packet(rng, IFACES)
        pkt.src, pkt.dst = rng.choice(["10.0.0.17", "10.0.1.200", "10.0.2.150", "10.0.3.9", "10.0.4.4", "10.0.9.9", "10.0.0.34"]), \
            rng.choice(["10.0.0.17", "10.0.1.130", "10.0.2.99", "10.0.3.50", "10.0.4.1", "10.0.0.34", "192.0.2.1"])
        if rng.random() < 0.2:
            pkt.src, pkt.dst = rng.choice(["2001:db8:1::5", "2001:db8:2::9", "2001:db8:3::1"]), rng.choice(["2001:db8:1:1::5", "2001:db8:2::1"])
        if pkt.proto.startswith("icmp"):
            pkt.proto = "icmp6" if ":" in pkt.src else "icmp"
        pkt.icmp_type = rng.choice([8, 128])
        verdict = model_verdict_with_defaults(written, pkt)
        assert judge.allows(pkt) == verdict, (seed, pkt, judge.deciding(pkt))


def model_verdict_with_defaults(p: Policy, pkt: Packet) -> bool:
    from test_iptables import model_verdict

    verdict = model_verdict(p, pkt)
    if verdict is not None:
        return verdict
    inside = pkt.in_if == pkt.out_if
    default = (p.default_intrazone if inside else p.default_interzone) == Action.ALLOW
    zone = p.zones.get(pkt.in_if)
    if inside and zone is not None and zone.intrazone_allow is not None:
        return zone.intrazone_allow
    return default


def test_sample_round_trip_through_an_smc(tmp_path: Path) -> None:
    """The sample, written for an SMC, loaded, read out again: every packet is decided and translated as before, but
    by the rules written disabled (users, VPN, schedule, block list), and the rules come back in order."""
    text = (DATA / "forcepoint_sample.json").read_text()
    before = ForcepointSmc(text)
    p, _ = parse(text)
    judge, report, out, smc = emitted(p, tmp=tmp_path)
    disabled = {key[1] for key, item in report.items.items() if key[0] == "rule" and item.disabled}
    assert disabled == {"Rule @900.0", "vpn only", "helpdesk to dmz", "office web", "block list"}, disabled
    written = as_written(p, report)
    rng = random.Random(7)
    zones = ZONES + ["Guest"]
    for _ in range(2000):
        pkt = random_packet(rng, zones)
        assert judge.allows(pkt) == model_allows(written, pkt), pkt
        if ":" not in pkt.src:
            assert judge.translation(pkt) == model_nat(p, pkt), pkt
    # The second reading reads what the first did.
    again, _ = parse(smc.dump_policy("FWShift"))
    for _ in range(1000):
        pkt = random_packet(rng, zones)
        assert model_allows(again, pkt) == model_allows(written, pkt), pkt
    names = [r.get("name") for r in judge.rules[4] if "sources" in r]
    assert names.index("allow web") < names.index("to admin sub-policy / admins in") < names.index("drop netbios")
    assert before.allows(Packet("Internal", "DMZ", "10.1.5.15", "192.168.10.10", "tcp", 40000, 22))


# -- the sample, by hand ---------------------------------------------------------------------------------------------


def test_sample_reads_as_documented() -> None:
    p, report = parse((DATA / "forcepoint_sample.json").read_text())
    assert p.vendor == "forcepoint" and p.scope == "Branch Policy" and p.default_interzone == Action.DROP
    names = [r.name for r in p.rules]
    assert names[:4] == ["Rule @900.0", "dns to resolver", "allow web", "to admin sub-policy / admins in"]
    assert names[-6:] == ["v6 web", "v6 ping", "v6 mail", "v6 guests", "Rule @952.0", "Rule @953.0"]
    by = {r.name: r for r in p.rules}
    assert by["internal zone out"].src_zones == ["Internal"] and by["internal zone out"].sources == ["net-lan (in rules)"]
    assert p.addresses["net-lan (in rules)"].value == "10.1.0.1-10.1.255.254"
    assert by["internal zone out"].log_start, "logging from the Continue rule above"
    assert by["to admin sub-policy / admins in"].log_start, "the Continue rule holds in the sub-policy"
    assert by["not to dmz"].negate_destination and by["not to dmz"].destinations == ["net-dmz"]
    assert by["refuse admins 8443"].action == Action.RESET_CLIENT
    assert not by["old block"].enabled and not by["unfinished"].enabled
    assert by["office web"].schedule == "Office hours"
    assert by["helpdesk to dmz"].users == ["helpdesk"]
    assert by["no social"].applications == ["Facebook"]
    assert by["vpn only"].unsupported and by["block list"].unsupported
    assert [r.name for r in p.rules if r.name.startswith("zone or web host out")] == ["zone or web host out", "zone or web host out (2)"]
    assert p.address_groups["lan without admins"].members == ["10.1.0.0-10.1.5.9", "10.1.5.21-10.1.255.255"]
    nat = {n.name: n for n in p.nat_rules}
    assert nat["publish web"].destination_translation is not None and nat["publish web"].destination_translation.address == "192.168.10.10"
    assert nat["publish web"].destination_translation.port == "8443"
    assert nat["mail static"].sources == ["mail-01 IPv4"] and nat["mail static"].source_translation is not None
    assert nat["guests hide"].source_translation is not None and nat["guests hide"].source_translation.kind == SnatKind.INTERFACE
    assert nat["no nat inside"].source_translation is None and nat["no nat inside"].destination_translation is None
    found = codes(report)
    for code in ("CONTINUE_RULE", "NONE_CELL", "AUTOMATIC_RULES", "SOURCE_VPN_NONE", "NETWORK_BROADCAST", "FORCEPOINT_ZONES",
                 "FORCEPOINT_ELEMENT_NAT", "REFUSE_ACTION", "RULE_SPLIT", "JUMP_FLATTENED", "CONNECTION_LIMIT", "NAT_ENGINE",
                 "NAT_INTERFACE_ALIAS"):  # fmt: skip
        assert code in found, code
    assert "MISSING_ELEMENTS" not in found and "TEMPLATE_RULES_NOT_READ" not in found


def test_detection_and_the_xml_export() -> None:
    data = (DATA / "forcepoint_sample.json").read_bytes()
    assert cli.detect_format(data) == "forcepoint"
    xml = b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE generic_import_export SYSTEM "generic_import_export_v7.4.dtd">\n<generic_import_export build="1"/>'
    assert cli.detect_format(xml) == "forcepoint"
    with pytest.raises(ParseError, match="forcepoint-dump"):
        parse_forcepoint.parse(xml, Report())
    with pytest.raises(ParseError, match="no firewall policy"):
        parse('{"name": "x", "link": [{"rel": "self", "href": "' + E + '/host/1"}]}\n{"fwshift_list": "x", "result": []}')


def test_several_policies_need_policy() -> None:
    a = Answers()
    top, points = base_template(a)
    for name in ("One", "Two"):
        href = a.policy("fw_policy", name, top)
        for rel in LISTS:
            a.rules(href, rel, [dict(rule("any", "any", "any", "allow", name=f"{name} rule"), parent_insert_point=points[rel])]
                    if rel == "fw_ipv4_access_rule" else [])
    with pytest.raises(ParseError, match="--policy"):
        parse(a.text())
    p, _ = parse(a.text(), policy="Two")
    assert p.scope == "Two" and p.rules[0].name == "Two rule"
    with pytest.raises(ParseError, match="no firewall policy 'Three'"):
        parse(a.text(), policy="Three")


def test_missing_template_gets_the_documented_tail() -> None:
    a = Answers()
    policy = a.policy("fw_policy", "Lonely", f"{E}/fw_template_policy/11")
    host = a.element("host", "web", address="192.168.10.10")
    a.rules(policy, "fw_ipv4_access_rule", [rule("any", [host], "any", "allow", name="to web")])
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, report = parse(a.text())
    assert [r.name for r in p.rules] == ["to web", "Firewall Template: Refuse Ident", "Firewall Template: Discard all",
                                         "Firewall Template: Refuse Ident (IPv6)", "Firewall Template: Discard all (IPv6)"]  # fmt: skip
    assert "TEMPLATE_RULES_NOT_READ" in codes(report) and "TEMPLATE_RULE_ASSUMED" in codes(report)


def test_missing_elements_never_match() -> None:
    a = Answers()
    top, points = base_template(a)
    policy = a.policy("fw_policy", "P", top)
    a.rules(policy, "fw_ipv4_access_rule", [dict(rule([f"{E}/host/999"], "any", "any", "discard", name="gone"), parent_insert_point=points["fw_ipv4_access_rule"])])
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, report = parse(a.text())
    gone = next(r for r in p.rules if r.name == "gone")
    assert gone.unsupported and "MISSING_ELEMENTS" in codes(report)


def test_list_answers_without_their_name_are_said() -> None:
    text = (DATA / "forcepoint_sample.json").read_text() + '{"result": [{"href": "' + E + '/host/1"}]}\n'
    _, report = parse(text)
    assert "LIST_NOT_PLACED" in codes(report)


def test_continue_logging_and_overlap() -> None:
    """Continue sets logging for the rules below that may match the same traffic, and for no others."""
    a = Answers()
    top, points = base_template(a)
    lan = a.element("network", "lan", ipv4_network="10.0.1.0/24")
    dmz = a.element("network", "dmz", ipv4_network="192.168.10.0/24")
    inside = a.element("host", "inside", address="10.0.1.5")
    policy = a.policy("fw_policy", "P", top)
    parent = points["fw_ipv4_access_rule"]
    a.rules(policy, "fw_ipv4_access_rule", [dict(e, parent_insert_point=parent) for e in [
        rule([lan], "any", "any", "continue", name="defaults", log="stored", options={"log_level": "stored", "log_closing_mode": True}),
        rule([inside], "any", "any", "allow", name="inner"),
        rule([dmz], "any", "any", "allow", name="other"),
        rule([inside], "any", "any", "allow", name="quiet", log="none"),
    ]])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, _ = parse(a.text())
    by = {r.name: r for r in p.rules}
    assert by["inner"].log_start and by["inner"].log_end
    assert not by["other"].log_start and not by["quiet"].log_start


def test_jump_to_a_missing_sub_policy_and_circles() -> None:
    a = Answers()
    top, points = base_template(a)
    policy = a.policy("fw_policy", "P", top)
    parent = points["fw_ipv4_access_rule"]
    a.rules(policy, "fw_ipv4_access_rule", [dict(rule("any", "any", "any", {"action": ["jump"], "sub_policy": f"{E}/sub_ipv4_fw_policy/77"},
                                                       name="jump"), parent_insert_point=parent)])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, _ = parse(a.text())
    assert p.rules[0].unsupported and p.rules[0].action == Action.DROP
    b = Answers()
    top, points = base_template(b)
    sub = b.policy("sub_ipv4_fw_policy", "loop", lists=("fw_ipv4_access_rule",))
    b.rules(sub, "fw_ipv4_access_rule", [rule("any", "any", "any", {"action": ["jump"], "sub_policy": sub}, name="again")])
    policy = b.policy("fw_policy", "P", top)
    b.rules(policy, "fw_ipv4_access_rule", [dict(rule("any", "any", "any", {"action": ["jump"], "sub_policy": sub}, name="in"),
                                                 parent_insert_point=points["fw_ipv4_access_rule"])])  # fmt: skip
    for rel in LISTS[1:]:
        b.rules(policy, rel, [])
    with pytest.raises(ParseError, match="circle"):
        parse(b.text())


def test_expressions_that_are_not_read() -> None:
    a = Answers()
    top, points = base_template(a)
    lan = a.element("network", "lan", ipv4_network="10.0.1.0/24")
    dmz = a.element("network", "dmz", ipv4_network="192.168.10.0/24")
    name = a.element("domain_name", "www.example.com")
    two = a.element("expression", "not two", operator="exclusion", ne_ref=[lan, dmz], sub_expression=[])
    named = a.element("expression", "with a name", operator="union", ne_ref=[lan, name], sub_expression=[])
    policy = a.policy("fw_policy", "P", top)
    parent = points["fw_ipv4_access_rule"]
    a.rules(policy, "fw_ipv4_access_rule", [dict(rule([two], "any", "any", "allow", name="a"), parent_insert_point=parent),
                                            dict(rule([named], "any", "any", "allow", name="b"), parent_insert_point=parent)])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, _ = parse(a.text())
    assert all(r.unsupported for r in p.rules if r.name in ("a", "b"))


def test_insert_points_of_a_template_of_its_own() -> None:
    """A template between: its rules above its insert point come before the rules of the policy, those below after."""
    a = Answers()
    top, points = base_template(a)
    mid = a.policy("fw_template_policy", "Mid", top)
    hrefs = a.rules(mid, "fw_ipv4_access_rule", [dict(rule("any", "any", "any", "allow", name="above"), parent_insert_point=points["fw_ipv4_access_rule"]),
                                                 insert_point("Here", parent_insert_point=points["fw_ipv4_access_rule"]),
                                                 dict(rule("any", "any", "any", "discard", name="below"), parent_insert_point=points["fw_ipv4_access_rule"])])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(mid, rel, [])
    policy = a.policy("fw_policy", "P", mid)
    a.rules(policy, "fw_ipv4_access_rule", [dict(rule("any", "any", "any", "allow", name="mine"), parent_insert_point=hrefs[1]),
                                            rule("any", "any", "any", "allow", name="stray")])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, report = parse(a.text())
    assert [r.name for r in p.rules][:4] == ["above", "mine", "stray", "below"]
    assert "RULE_ORDER" not in codes(report)


# -- the emitter, by hand -------------------------------------------------------------------------------------------


def small_model() -> Policy:
    from fwshift.model import Address, AddressGroup, AddressKind, Service, ServiceEntry, Protocol

    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "192.168.10.10/32")
    p.addresses["web6"] = Address("web6", AddressKind.NETWORK, "2001:db8:10::10/128")
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.0.1.0/24")
    p.addresses["www"] = Address("www", AddressKind.FQDN, "www.example.com")
    p.address_groups["both"] = AddressGroup("both", ["web", "web6"])
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["several"] = Service("several", [ServiceEntry(Protocol.TCP, "80,8080"), ServiceEntry(Protocol.UDP, "53")])
    p.rules.append(Rule("in", src_zones=["untrust"], dst_zones=["dmz"], destinations=["both"], services=["https"], origin="in"))
    p.rules.append(Rule("out", src_zones=["trust"], sources=["lan"], destinations=["www"], services=["several"], origin="out"))
    p.zones["trust"] = Zone("trust", ["eth1"])
    p.zones["untrust"] = Zone("untrust", ["eth0"])
    p.zones["dmz"] = Zone("dmz", ["eth2"])
    p.nat_rules.append(NatRule("pub", destinations=["203.0.113.10"], service="https", origin="pub"))
    from fwshift.model import DestNat, SourceNat

    p.nat_rules[0].destination_translation = DestNat("web")
    p.nat_rules.append(NatRule("hide", src_zones=["trust"], sources=["lan"], origin="hide", source_translation=SourceNat(SnatKind.INTERFACE)))
    return p


def test_emitter_writes_each_ip_version_its_part() -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    plan = plan_of(text)
    rules = plan["rules"]
    assert [r["name"] for r in rules["fw_ipv4_access_rule"]] == ["in", "out"]
    assert [r["name"] for r in rules["fw_ipv6_access_rule"]] == ["in"]  # (lan is IPv4 only)
    elements = {(e["type"], e["body"]["name"]): e["body"] for e in plan["elements"]}
    assert ("group", "both IPv4") in elements and ("group", "both IPv6") in elements
    assert ("domain_name", "www.example.com") in elements
    v4_in = rules["fw_ipv4_access_rule"][0]
    assert v4_in["sources"] == {"src": [{"@ref": "interface_zone", "name": "untrust"}]}
    assert v4_in["destinations"]["dst"][0]["@ref"] == "match_expression"
    assert plan["zones"] == ["untrust", "dmz", "trust"]
    assert [n["name"] for n in plan["nat"]["fw_ipv4_nat_rule"]] == ["pub", "hide"]
    assert plan["existing"] == [{"type": "default_nat_address_alias", "name": "$$ Default NAT Address"}]
    assert ("service_group", "several") in elements and ("tcp_service", "several tcp-80") in elements


def test_emitter_options_and_names() -> None:
    with pytest.raises(FwshiftError, match="--target-policy"):
        cli.convert(small_model(), "forcepoint", Report(), Options(target_policy="bad\x01name"))
    with pytest.raises(FwshiftError, match="--target-prefix"):
        cli.convert(small_model(), "forcepoint", Report(), Options(object_prefix="a/b"))
    plan = plan_of(cli.convert(small_model(), "forcepoint", Report(), Options(object_prefix="fws-", target_template="My Template",
                                                                                target_policy="Mine")))  # fmt: skip
    assert plan["template"] == "My Template" and plan["policy"] == "Mine"
    assert all(e["body"]["name"].startswith("fws-") or e["type"] == "domain_name" for e in plan["elements"])


def test_what_the_emitter_cannot_write_is_disabled() -> None:
    p = small_model()
    p.rules[0].negate_service = True
    p.rules[1].users = ["alice"]
    p.rules.append(Rule("timed", schedule="night", origin="timed"))
    report = Report()
    plan = plan_of(cli.convert(p, "forcepoint", report, Options()))
    written = {r["name"]: r for r in plan["rules"]["fw_ipv4_access_rule"]}
    assert all(written[name]["is_disabled"] for name in ("in", "out", "timed"))
    assert {"NEGATED_SERVICE", "USER_MATCH", "SCHEDULE"} <= set(codes(report))


def test_defaults_become_rules_at_the_end() -> None:
    p = small_model()
    p.default_interzone, p.default_intrazone = Action.ALLOW, Action.DENY
    report = Report()
    plan = plan_of(cli.convert(p, "forcepoint", report, Options()))
    names = [r["name"] for r in plan["rules"]["fw_ipv4_access_rule"]]
    assert names[-1] == "FWShift: default" and "FWShift: inside zone trust" in names
    assert "DEFAULT_ALLOW_ADDED" in codes(report)


# -- the loader -----------------------------------------------------------------------------------------------------


def test_loader_show_and_plan(capsys: Any) -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    said: List[str] = []
    assert smc_loader.main(["--show"], say=said.append, plan=plan_of(text)) == 0
    assert said[0].startswith("Firewall policy 'FWShift' on template 'Firewall Template'")
    assert smc_loader.main([], say=said.append, plan=plan_of(text)) == 1 and "--host is needed" in capsys.readouterr().err


def test_loader_creates_reuses_and_undoes(tmp_path: Path) -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    journal = tmp_path / "j.json"
    smc, status, said = load_into(text, journal=str(journal))
    assert status == 0, said
    policies = [h for h in smc.elements if "/fw_policy/" in h and h.count("/") == f"{E}/fw_policy/1".count("/")]
    assert len(policies) == 1
    names = [smc.elements[h].get("name") for h in smc.rules[policies[0] + "/fw_ipv4_access_rule"]]
    assert names == ["in", "out"]
    assert not smc.logged_in, "logged out at the end"
    created = json.loads(journal.read_text())["created"]
    assert created[-1]["type"] == "fw_policy" and any(e["type"] == "interface_zone" for e in created)
    # Run again: the policy exists, nothing is created.
    _, status, said = load_into(text, smc=smc, journal=str(tmp_path / "j2.json"))
    assert status == 1
    before = len(smc.elements)
    _, status, said = load_into(text, smc=smc, journal=str(journal), extra=["--undo"])
    assert status == 0, said
    assert len(smc.elements) < before and not [h for h in smc.elements if "/fw_policy/" in h]
    assert (tmp_path / "j.json.undone").exists()


def test_loader_stops_on_a_name_that_says_something_else(tmp_path: Path, capsys: Any) -> None:
    smc = FakeSmc(KEY)
    smc._add("host", {"name": "web", "address": "192.168.10.99"})
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    _, status, _ = load_into(text, smc=smc, journal=str(tmp_path / "j.json"))
    assert status == 1 and "host 'web'" in capsys.readouterr().err
    assert not (tmp_path / "j.json").exists()
    # The same host, saying the same, is used.
    smc = FakeSmc(KEY)
    smc._add("host", {"name": "web", "address": "192.168.10.10"})
    _, status, said = load_into(text, smc=smc, journal=str(tmp_path / "j.json"))
    assert status == 0 and any("used as they are: host 'web'" in line for line in said)


def test_loader_needs_the_template_and_the_aliases(tmp_path: Path, capsys: Any) -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options(target_template="Nowhere"))
    _, status, _ = load_into(text, journal=str(tmp_path / "j.json"))
    assert status == 1 and "template 'Nowhere'" in capsys.readouterr().err
    smc = FakeSmc(KEY)
    alias = next(h for h, e in smc.elements.items() if e.get("name") == "$$ Default NAT Address")
    del smc.elements[alias]
    _, status, _ = load_into(cli.convert(small_model(), "forcepoint", Report(), Options()), smc=smc, journal=str(tmp_path / "j.json"))
    assert status == 1 and "$$ Default NAT Address" in capsys.readouterr().err


def test_loader_stopped_half_way_keeps_a_journal(tmp_path: Path, capsys: Any) -> None:
    smc = FakeSmc(KEY)
    smc.refuse["match_expression"] = 400
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    journal = tmp_path / "j.json"
    _, status, _ = load_into(text, smc=smc, journal=str(journal))
    err = capsys.readouterr().err
    assert status == 1 and "--undo" in err
    assert json.loads(journal.read_text())["created"]
    del smc.refuse["match_expression"]
    _, status, said = load_into(text, smc=smc, journal=str(journal), extra=["--undo"])
    assert status == 0, said
    assert not [h for h, e in smc.elements.items() if e.get("name") in ("lan", "web")]


def test_loader_refuses_links_elsewhere_and_edited_plans(tmp_path: Path, capsys: Any) -> None:
    smc = FakeSmc(KEY)
    smc.broken_location = True
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    _, status, _ = load_into(text, smc=smc, journal=str(tmp_path / "j.json"))
    assert status == 1 and "somewhere else" in capsys.readouterr().err
    plan = plan_of(text)
    plan["elements"][0]["type"] = "fw_policy"
    assert smc_loader.main(["--show"], say=lambda line: None, plan=plan) == 1
    plan = plan_of(text)
    plan["rules"]["fw_ipv4_access_rule"][0]["sources"] = {"src": [{"@ref": "host", "name": "nobody"}]}
    assert smc_loader.main(["--show"], say=lambda line: None, plan=plan) == 1
    assert "a reference to host 'nobody'" in capsys.readouterr().err


def test_loader_host_and_key(capsys: Any, monkeypatch: Any) -> None:
    assert smc_loader.base_url("smc.example.net") == "https://smc.example.net:8082"
    assert smc_loader.base_url("smc.example.net:8443") == "https://smc.example.net:8443"
    for bad in ("http://smc.example.net", "smc.example.net/path", "user@smc.example.net", "a b"):
        with pytest.raises(smc_loader.Stop):
            smc_loader.base_url(bad)
    monkeypatch.delenv("SMC_API_KEY", raising=False)
    monkeypatch.setattr(smc_loader, "someone_to_ask", lambda: False)
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    assert smc_loader.main(["--host", "smc.example.net"], transport=FakeSmc(KEY), say=lambda line: None, plan=plan_of(text)) == 1
    assert "SMC_API_KEY" in capsys.readouterr().err
    monkeypatch.setenv("SMC_API_KEY", "wrong")
    assert smc_loader.main(["--host", "smc.example.net"], transport=FakeSmc(KEY), say=lambda line: None, plan=plan_of(text)) == 1
    assert "refused the login" in capsys.readouterr().err


# -- the dump program -----------------------------------------------------------------------------------------------


def test_dump_program_reads_what_the_loader_wrote(tmp_path: Path) -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    smc, status, _ = load_into(text, journal=str(tmp_path / "j.json"))
    assert status == 0
    out = tmp_path / "dump.json"
    said: List[str] = []
    assert smc_dump.main(["--host", "smc.example.net", "--policy", "FWShift", "-o", str(out)], transport=smc, say=said.append, key=KEY) == 0
    assert cli.detect_format(out.read_bytes()) == "forcepoint"
    p, report = parse(out.read_text())
    assert [r.name for r in p.rules if not r.name.startswith("Rule @")][:2] == ["in", "out"]
    assert smc_dump.main(["--host", "smc.example.net", "--policy", "Nothing", "-o", str(out)], transport=smc, say=said.append, key=KEY) == 1


def test_dump_program_follows_no_links_elsewhere() -> None:
    smc = FakeSmc(KEY)
    session = smc_dump.Session(smc, KEY, "", "")
    session.login()
    assert session.own(f"{E}/host/1") and not session.own("https://elsewhere.example.org/7.4/elements/host/1")
    assert smc_dump.links({"sources": {"src": ["a"]}, "link": [{"rel": "self", "href": "b"}], "inspection_policy": "c"}) == ["a"]


def test_cli_writes_the_dump_program(tmp_path: Path) -> None:
    out = tmp_path / "smc_dump.py"
    assert cli.main(["script", "forcepoint-dump", "-o", str(out)]) == 0
    text = out.read_text()
    assert text.startswith("#!/usr/bin/env python3") and "def dump(" in text


# -- found in review (round 33) -------------------------------------------------------------------------------------


def one_rule_policy(*rules_: Dict[str, Any], elements: Optional[List[Tuple[str, str, Dict[str, Any]]]] = None,
                    nat: Optional[List[Dict[str, Any]]] = None) -> Tuple[Answers, Dict[str, str]]:  # fmt: skip
    a = Answers()
    top, points = base_template(a)
    hrefs = {name: a.element(kind, name, **fields) for kind, name, fields in elements or []}
    policy = a.policy("fw_policy", "P", top)
    built = [r(hrefs) if callable(r) else r for r in rules_]
    a.rules(policy, "fw_ipv4_access_rule", [dict(r, parent_insert_point=points["fw_ipv4_access_rule"]) for r in built])
    a.rules(policy, "fw_ipv6_access_rule", [])
    a.rules(policy, "fw_ipv4_nat_rule", [dict(n(hrefs) if callable(n) else n, parent_insert_point=points["fw_ipv4_nat_rule"]) for n in nat or []])
    a.rules(policy, "fw_ipv6_nat_rule", [])
    return a, hrefs


def test_r33_cells_that_cannot_be_read_are_never_any() -> None:
    lan = [("network", "lan", {"ipv4_network": "10.0.1.0/24"}), ("match_expression", "empty", {"ref": []})]
    a, _ = one_rule_policy(lambda h: rule([{"href": h["lan"]}], "any", "any", "discard", name="odd"),
                           lambda h: rule([h["lan"], 7], "any", "any", "discard", name="mixed"),
                           lambda h: rule([h["empty"]], "any", "any", "discard", name="empty row"), elements=lan,
                           nat=[lambda h: dict(rule([{"x": 1}], "any", "any", "allow", name="odd nat"), used_on={"any": True})])  # fmt: skip
    p, _ = parse(a.text())
    by = {r.name: r for r in p.rules}
    assert all(by[name].unsupported for name in ("odd", "mixed", "empty row"))
    assert p.nat_rules[0].unsupported


def test_r33_names_made_up_do_not_take_an_element_of_the_same_name() -> None:
    elements = [("host", "dual", {"address": "192.168.10.25", "ipv6_address": "2001:db8:10::25"}),
                ("network", "dual IPv4", {"ipv4_network": "0.0.0.0/0"})]  # fmt: skip
    a, _ = one_rule_policy(lambda h: rule([h["dual"]], "any", "any", "allow", name="from dual"),
                           lambda h: rule([h["dual IPv4"]], "any", "any", "discard", name="all"), elements=elements)  # fmt: skip
    p, _ = parse(a.text())
    judge = ForcepointSmc(a.text())
    pkt = Packet("Internal", "External", "203.0.113.9", "192.0.2.10", "tcp", 40000, 443)
    assert model_allows(p, pkt) == judge.allows(pkt) is False


def test_r33_a_missing_zone_is_unsupported() -> None:
    a, _ = one_rule_policy(rule([f"{E}/interface_zone/9999"], "any", "any", "discard", name="from gone"))
    p, report = parse(a.text())
    assert p.rules[0].unsupported and "MISSING_ELEMENTS" in codes(report)


def test_r33_nat_port_without_an_original_port_and_odd_ports() -> None:
    elements = [("host", "pub", {"address": "203.0.113.200"}), ("host", "srv", {"address": "192.168.10.11"}),
                ("tcp_service", "upper only", {"max_dst_port": 90}), ("tcp_service", "zero", {"min_dst_port": 0, "max_dst_port": 0})]  # fmt: skip
    a, _ = one_rule_policy(lambda h: rule("any", "any", [h["upper only"]], "allow", name="upper"),
                           lambda h: rule("any", "any", [h["zero"]], "allow", name="zero"), elements=elements,
                           nat=[lambda h: dict(rule("any", [h["pub"]], "any", "allow", name="fwd"), used_on={"any": True},
                                               options={"static_dst_nat": {"original_value": {"element": h["pub"]},
                                                                           "translated_value": {"element": h["srv"], "min_port": 8443, "max_port": 8443}}}),
                                lambda h: dict(rule("any", "any", "any", "allow", name="pool"), used_on={"any": True},
                                               options={"dynamic_src_nat": {"translation_values": []}})])  # fmt: skip
    p, _ = parse(a.text())
    by = {r.name: r for r in p.rules}
    assert by["upper"].unsupported and by["zero"].unsupported
    nat = {n.name: n for n in p.nat_rules}
    assert nat["fwd"].destination_translation is not None and nat["fwd"].destination_translation.port == "8443"
    assert nat["pool"].unsupported


def test_r33_links_of_another_shape_are_a_parse_error() -> None:
    with pytest.raises(ParseError):
        parse('{"name": "x", "link": 5}\n')


def test_r33_interzone_rule_of_one_zone_is_not_written() -> None:
    p = small_model()
    from fwshift.model import RuleScope

    p.rules = [Rule("same", src_zones=["dmz"], dst_zones=["dmz"], scope=RuleScope.INTERZONE, origin="same")]
    report = Report()
    plan = plan_of(cli.convert(p, "forcepoint", report, Options()))
    assert not plan["rules"]["fw_ipv4_access_rule"] and report.items[("rule", "same")].skipped


def test_r33_applications_are_written_per_ip_version(tmp_path: Path) -> None:
    p = small_model()
    p.rules = [Rule("no ping", applications=["ping", "ping6"], action=Action.DROP, origin="no ping"),
               Rule("rest", origin="rest")]  # fmt: skip
    judge, report, _, _ = emitted(p, tmp=tmp_path)
    for src, dst, proto, icmp in (("10.0.1.5", "192.168.10.10", "icmp", 8), ("2001:db8:1::5", "2001:db8:10::10", "icmp6", 128)):
        pkt = Packet("trust", "dmz", src, dst, proto, icmp_type=icmp)
        assert not judge.allows(pkt), pkt


def test_r33_a_negated_group_with_a_host_name_is_disabled() -> None:
    from fwshift.model import AddressGroup

    p = small_model()
    p.address_groups["mixed"] = AddressGroup("mixed", ["www", "lan"])
    p.rules = [Rule("not mixed", sources=["mixed"], negate_source=True, origin="not mixed")]
    report = Report()
    plan = plan_of(cli.convert(p, "forcepoint", report, Options()))
    assert plan["rules"]["fw_ipv4_access_rule"][0]["is_disabled"] and "NEGATED_FQDN" in codes(report)


def test_r33_translations_of_both_ip_versions_are_not_written() -> None:
    from fwshift.model import SourceNat

    p = small_model()
    p.nat_rules = [NatRule("pool", sources=["both"], origin="pool", source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["both"]))]
    report = Report()
    plan = plan_of(cli.convert(p, "forcepoint", report, Options()))
    assert not plan["nat"]["fw_ipv6_nat_rule"] and report.items[("nat", "pool")].skipped


def test_r33_the_loader_uses_an_element_only_when_it_matches_no_more(tmp_path: Path, capsys: Any) -> None:
    smc = FakeSmc(KEY)
    smc._add("host", {"name": "web", "address": "192.168.10.10", "secondary": ["10.9.9.9"]})
    _, status, _ = load_into(cli.convert(small_model(), "forcepoint", Report(), Options()), smc=smc, journal=str(tmp_path / "j.json"))
    assert status == 1 and "host 'web'" in capsys.readouterr().err
    assert smc_loader.same("tcp_service", {"min_dst_port": 443, "max_dst_port": None}, {"min_dst_port": 443, "max_dst_port": 443})
    assert not smc_loader.same("tcp_service", {"min_dst_port": 443, "protocol_agent_ref": f"{E}/protocol/1"}, {"min_dst_port": 443})
    assert not smc_loader.same("icmp_service", {"icmp_type": 8, "icmp_code": 0}, {"icmp_type": 8})
    assert not smc_loader.same("alias", {}, {})


def test_r33_the_loader_says_what_the_smc_may_have_created(tmp_path: Path, capsys: Any) -> None:
    smc = FakeSmc(KEY)
    smc.broken_location = True
    journal = tmp_path / "j.json"
    _, status, _ = load_into(cli.convert(small_model(), "forcepoint", Report(), Options()), smc=smc, journal=str(journal))
    err = capsys.readouterr().err
    assert status == 1 and "said it created it" in err and "Nothing was created" not in err
    assert journal.exists()


def test_r33_the_loader_checks_each_rule_it_wrote(tmp_path: Path, capsys: Any) -> None:
    p = small_model()
    p.rules[0].enabled = False
    smc = FakeSmc(KEY)
    smc.drop_disabled = True
    _, status, _ = load_into(cli.convert(p, "forcepoint", Report(), Options()), smc=smc, journal=str(tmp_path / "j.json"))
    assert status == 1 and "otherwise than it was sent" in capsys.readouterr().err


def test_r33_cookies_and_headers() -> None:
    assert smc_loader.cookies("JSESSIONID=a1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT\nLB=x; Secure") == "JSESSIONID=a1; LB=x"


def test_r33_the_dump_program_leaves_out_unreadable_lists_and_foreign_links(tmp_path: Path) -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    smc, status, _ = load_into(text, journal=str(tmp_path / "j.json"))
    assert status == 0
    policy = next(h for h, e in smc.elements.items() if e.get("name") == "FWShift" and "/fw_policy/" in h)
    smc.missing_lists.append(policy + "/fw_ipv4_access_rule")
    _, report = parse(smc.dump_policy("FWShift"))
    assert "MISSING_ELEMENTS" in codes(report)
    smc.foreign_entries = True
    out = tmp_path / "dump.json"
    assert smc_dump.main(["--host", "smc.example.net", "--policy", "FWShift", "-o", str(out)], transport=smc, say=lambda line: None, key=KEY) == 1
    assert not any("elsewhere" in url for method, url in smc.calls)
    assert not out.exists() and not (tmp_path / "dump.json.tmp").exists()


# -- found by the mutation check -------------------------------------------------------------------------------------


def test_m25_continue_disabled_odd_verbs_and_vpn() -> None:
    elements = [("network", "lan", {"ipv4_network": "10.0.1.0/24"})]
    a, _ = one_rule_policy(lambda h: dict(rule([h["lan"]], "any", "any", "continue", name="off", log="stored"), is_disabled=True),
                           lambda h: rule([h["lan"]], "any", "any", "allow", name="after"),
                           lambda h: rule([h["lan"]], "any", "any", {"action": []}, name="no verb"),
                           lambda h: rule([h["lan"]], "any", "any", "allow", name="clients", match_vpn_options={"match_type": "mobile_vpn"}),
                           lambda h: dict(rule([h["lan"]], "any", "any", "allow", name="closing", log="none"),
                                          options={"log_level": "none", "log_closing_mode": True}), elements=elements)  # fmt: skip
    p, _ = parse(a.text())
    by = {r.name: r for r in p.rules}
    assert not by["after"].log_start, "a disabled Continue rule sets nothing"
    assert by["no verb"].unsupported and by["no verb"].action == Action.DROP
    assert by["clients"].unsupported
    assert not by["closing"].log_end


JUMP_ELEMENTS = [("network", "lan", {"ipv4_network": "10.0.1.0/24"}), ("network", "dmz", {"ipv4_network": "192.168.10.0/24"}),
                 ("tcp_service", "ssh", {"min_dst_port": 22}), ("tcp_service", "http", {"min_dst_port": 80})]  # fmt: skip


def jump_policy(parent: Any, children: List[Any]) -> str:
    """A policy whose first rule jumps into a sub-policy of ``children``, then allows the rest; with negations of lan
    and dmz among the elements."""
    a = Answers()
    top, points = base_template(a)
    h = {name: a.element(kind, name, **fields) for kind, name, fields in JUMP_ELEMENTS}
    h["not lan"] = a.element("expression", "not lan", operator="exclusion", ne_ref=[h["lan"]], sub_expression=[])
    h["not dmz"] = a.element("expression", "not dmz", operator="exclusion", ne_ref=[h["dmz"]], sub_expression=[])
    sub = a.policy("sub_ipv4_fw_policy", "sub", lists=("fw_ipv4_access_rule",))
    a.rules(sub, "fw_ipv4_access_rule", [child(h) for child in children])
    policy = a.policy("fw_policy", "P", top)
    jump = parent(h)
    jump["action"] = {"action": ["jump"], "sub_policy": sub}
    a.rules(policy, "fw_ipv4_access_rule", [dict(jump, parent_insert_point=points["fw_ipv4_access_rule"]),
                                            dict(rule("any", "any", "any", "allow", name="rest"), parent_insert_point=points["fw_ipv4_access_rule"])])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    return a.text()


def test_m25_jumps_both_negated_apart_and_services_not_within() -> None:
    cases = [
        # Both negated: neither lan nor dmz is discarded; the rest is allowed below.
        (lambda h: rule([h["not lan"]], "any", "any", "allow", name="jump"), [lambda h: rule([h["not dmz"]], "any", "any", "discard", name="neither")],
         [("10.0.1.5", 22, True), ("192.168.10.5", 22, True), ("203.0.113.5", 22, False)]),
        # Apart: a jump from lan into a rule for dmz matches nothing.
        (lambda h: rule([h["lan"]], "any", "any", "allow", name="jump"), [lambda h: rule([h["dmz"]], "any", "any", "discard", name="apart")],
         [("10.0.1.5", 22, True), ("192.168.10.5", 22, True)]),
        # Services: a jump for SSH into a rule for HTTP matches nothing.
        (lambda h: rule("any", "any", [h["ssh"]], "allow", name="jump"), [lambda h: rule("any", "any", [h["http"]], "discard", name="web")],
         [("10.0.1.5", 80, True), ("10.0.1.5", 22, True)]),
    ]  # fmt: skip
    for parent, children, packets in cases:
        text = jump_policy(parent, children)
        judge = ForcepointSmc(text)
        p, report = parse(text)
        for src, port, allowed in packets:
            pkt = Packet("Internal", "External", src, "198.51.100.7", "tcp", 40000, port)
            assert model_allows(p, pkt) == judge.allows(pkt) == allowed, (src, port, [(r.name, r.sources, r.services, r.unsupported) for r in p.rules])
        assert all(r.sources for r in p.rules)
    _, report = parse(jump_policy(cases[1][0], cases[1][1]))
    assert "JUMP_EMPTY" in codes(report)


def test_m25_rules_at_the_second_insert_point_of_a_template() -> None:
    a = Answers()
    top, points = base_template(a)
    mid = a.policy("fw_template_policy", "Mid", top)
    parent = points["fw_ipv4_access_rule"]
    hrefs = a.rules(mid, "fw_ipv4_access_rule", [insert_point("First", parent_insert_point=parent),
                                                 dict(rule("any", "any", "any", "discard", name="between"), parent_insert_point=parent),
                                                 insert_point("Second", parent_insert_point=parent)])  # fmt: skip
    for rel in LISTS[1:]:
        a.rules(mid, rel, [])
    policy = a.policy("fw_policy", "P", mid)
    a.rules(policy, "fw_ipv4_access_rule", [dict(rule("any", "any", "any", "allow", name="late"), parent_insert_point=hrefs[2])])
    for rel in LISTS[1:]:
        a.rules(policy, rel, [])
    p, _ = parse(a.text())
    assert [r.name for r in p.rules][:2] == ["between", "late"]


def test_m25_nat_rules_say_their_ip_version() -> None:
    a, _ = one_rule_policy(nat=[dict(rule("any", "any", "any", "allow", name="no nat"), used_on={"any": True})])
    p, _ = parse(a.text())
    assert p.nat_rules[0].sources == ["0.0.0.0/0"]


def test_m25_emitter_negated_any_of_a_version_icmp_lists_and_merged_zones() -> None:
    from fwshift.model import DestNat

    p = small_model()
    p.rules = [Rule("not v4", sources=["0.0.0.0/0"], negate_source=True, origin="not v4"),
               Rule("ping", services=["ping"], origin="ping")]  # fmt: skip
    from fwshift.model import Service, ServiceEntry, Protocol

    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    plan = plan_of(cli.convert(p, "forcepoint", Report(), Options()))
    v4 = [r["name"] for r in plan["rules"]["fw_ipv4_access_rule"]]
    v6 = [r["name"] for r in plan["rules"]["fw_ipv6_access_rule"]]
    assert "not v4" not in v4 and "not v4" in v6
    assert "ping" in v4 and "ping" not in v6
    # Two zones merged into one by --zone-map: no rule that allows inside it.
    q = small_model()
    q.default_intrazone = Action.ALLOW
    report = Report()
    plan = plan_of(cli.convert(q, "forcepoint", report, Options(zone_map={"trust": "inside", "dmz": "inside"})))
    names = [r["name"] for r in plan["rules"]["fw_ipv4_access_rule"]]
    assert "FWShift: inside zone inside" not in names and "INTRAZONE_ALLOW_MERGED" in codes(report)
    # A port range translated to a range of another size.
    r = small_model()
    r.services["range"] = Service("range", [ServiceEntry(Protocol.TCP, "8000-8010")])
    r.nat_rules[0].service = "range"
    r.nat_rules[0].destination_translation = DestNat("web", "9000")
    report = Report()
    cli.convert(r, "forcepoint", report, Options())
    assert report.items[("nat", "pub")].skipped, "an SMC translates a range of ports to a range of the same size"


def test_m25_loader_stops_on_an_existing_policy_a_missing_alias_and_a_wrong_order(tmp_path: Path, capsys: Any) -> None:
    text = cli.convert(small_model(), "forcepoint", Report(), Options())
    smc, status, _ = load_into(text, journal=str(tmp_path / "a.json"))
    assert status == 0
    before = len(smc.elements)
    capsys.readouterr()
    _, status, _ = load_into(text, smc=smc, journal=str(tmp_path / "b.json"))
    assert status == 1 and "exists already" in capsys.readouterr().err and len(smc.elements) == before
    smc = FakeSmc(KEY)
    del smc.elements[next(h for h, e in smc.elements.items() if e.get("name") == "$$ Default NAT Address")]
    _, status, _ = load_into(text, smc=smc, journal=str(tmp_path / "c.json"))
    assert status == 1 and "does not have" in capsys.readouterr().err
    p = small_model()
    p.rules.append(Rule("third", origin="third"))
    smc = FakeSmc(KEY)
    smc.add_after_before = True
    _, status, _ = load_into(cli.convert(p, "forcepoint", Report(), Options()), smc=smc, journal=str(tmp_path / "d.json"))
    assert status == 1 and "in another order" in capsys.readouterr().err
