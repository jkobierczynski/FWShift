# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Barracuda CloudGen Firewall: answers of its REST API read, a script for that API written, and packets through both.

What the firewall decides is worked out by ``helpers.BarracudaRest``, which shares no code with fwshift's parser and
emitter. It is written from the same reading of what is known of the API (DEVELOPMENT.md).
"""

from __future__ import annotations

import copy
import json
import random
import subprocess
from typing import Any, Dict, List, Tuple

import pytest
from helpers import DATA, BarracudaRest
from test_iptables import ZONES, Packet, model_allows, random_model, random_packet
from tools.make_barracuda_sample import entry, net, port, proto, ref, rule, svc

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope, Service
from fwshift.model import ServiceEntry, Zone
from fwshift.options import Options
from fwshift.parsers import barracuda as parse_barracuda
from fwshift.report import Report, Severity

Json = Dict[str, Any]


def text_of(answers: List[Json]) -> str:
    return "\n".join(json.dumps(answer) for answer in answers) + "\n"


def parse(answers: Any) -> Tuple[Policy, Report]:
    report = Report()
    text = answers if isinstance(answers, str) else text_of(answers)
    return parse_barracuda.parse(text.encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


# -- a firewall made up at random ---------------------------------------------------------------------

NETWORKS = [
    net("n0", ["10.0.0.0/24"]), net("n1", ["10.0.1.0/24", "2001:db8:1::/48"]), net("half", ["10.0.1.128/25"]),
    net("span", ["10.0.2.100-10.0.3.50"]), net("host", ["10.0.0.17"]),
    net("holes", ["10.0.0.0/22"], excluded=["10.0.1.0/24", "10.0.2.128/25"]),
    net("nested", [ref("n0"), ref("host"), "10.0.4.0/24"]), net("six", ["2001:db8:2::/48", "2001:db8:3::1"]),
    net("at0", [entry("10.0.0.0/23", "eth0"), entry("10.0.3.0/24", "eth1")]),
    net("at1", [entry("10.0.2.0/24", "eth1"), entry("2001:db8::/32", "eth2"), "10.0.4.0/24"]),
]  # fmt: skip
PLAIN = ["n0", "n1", "half", "span", "host", "holes", "nested", "six"]
SERVICES = [
    svc("web", [port("tcp", "80", "443")]), svc("dns", [port("tcp", "53"), port("udp", "53")]),
    svc("alt", [port("tcp", "8000-8010", "9000")]), svc("hi", [port("tcp", "22", "8000", client={"from": 1024, "to": 2000})]),
    svc("icmp", [proto("icmp")]), svc("icmp6", [proto("icmpv6")]), svc("gre", [proto("47")]),
    svc("mix", [ref("web"), ref("gre"), port("udp", "*")]),
]  # fmt: skip


def random_answers(rng: random.Random) -> List[Json]:
    rules = []
    for index in range(rng.randint(4, 12)):
        bidirectional = rng.random() < 0.15
        source = "Any" if rng.random() < 0.3 else rng.choice(PLAIN if bidirectional else PLAIN + ["at0", "at1"])
        destination = "Any" if rng.random() < 0.3 else rng.choice(PLAIN if bidirectional else PLAIN + ["at1"])
        service = "Any" if rng.random() < 0.3 else rng.choice(["web", "dns", "alt", "hi", "icmp", "icmp6", "gre", "mix"])
        action = rng.choice(["pass", "pass", "pass", "block", "deny"])
        rules.append(rule(f"r{index}", source, destination, service, action, version=rng.choice(["IPv4", "IPv4", "IPv6"]),
                          deactivated=rng.random() < 0.1, bidirectional=bidirectional))  # fmt: skip
    return [{"rules": rules}, *NETWORKS, *SERVICES]


def packets(rng: random.Random, count: int) -> List[Packet]:
    out = []
    for index in range(count):
        pkt = random_packet(rng, 6 if index % 4 == 0 else 4)
        pkt.in_if = rng.choice(ZONES)
        out.append(pkt)
    return out


def test_parsed_answers_decide_like_the_firewall() -> None:
    """References, exclusions, entries at interfaces, services of several kinds, both IP versions, bi-directional
    rules: the model decides as the firewall would."""
    allowed = compared = 0
    for seed in range(100):
        rng = random.Random(seed)
        answers = random_answers(rng)
        judge = BarracudaRest(text_of(answers))
        p, report = parse(answers)
        assert not [r.name for r in p.rules if r.unsupported], seed
        for pkt in packets(rng, 300):
            expected = judge.allows(pkt)
            compared += 1
            allowed += expected
            assert model_allows(p, pkt) == expected, (seed, pkt, judge.deciding(pkt))
    assert compared // 20 < allowed < compared * 9 // 10, (allowed, compared)


# Networks behind the zones of the random models: the smaller network decides, eth2 has the default route.
ZONE_NETWORKS = {"eth0": ["10.0.0.0/23", "2001:db8::/47"], "eth1": ["10.0.2.0/23", "2001:db8:2::/48"], "eth2": ["0.0.0.0/0", "::/0"]}


def zone_of(address: str) -> str:
    import ipaddress

    ip = ipaddress.ip_address(address)
    for zone in ("eth0", "eth1"):
        if any(ip.version == ipaddress.ip_network(n).version and ip in ipaddress.ip_network(n) for n in ZONE_NETWORKS[zone]):
            return zone
    return "eth2"


@pytest.mark.parametrize("seed", range(60))
@pytest.mark.parametrize("by_interface", [True, False])
def test_emitted_rules_decide_like_the_model(seed: int, by_interface: bool) -> None:
    """Zones as interfaces of the source entries or as networks, negation, both IP versions: the script gives the
    verdicts of the model, for traffic that arrives and leaves where the networks say."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {name: Zone(name) for name in ZONES}
    report = Report()
    options = Options(zone_networks=ZONE_NETWORKS, interface_map={z: z for z in ZONES} if by_interface else {})
    text = cli.convert(model, "barracuda", report, options)
    judge = BarracudaRest(text)
    lost = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    for name in lost:
        reasons = {f.code for f in report.item("rule", name).findings if f.severity == Severity.REVIEW}
        assert reasons <= {"SERVICE_NEGATE", "UNCONVERTIBLE_OBJECT", "RULE_TYPE"}, (seed, name, reasons)
    rules = []
    for r in model.rules:
        if r.name in lost:
            continue
        if "RULE_TYPE" in codes(report, "rule", r.origin):
            r = copy.copy(r)
            r.scope = RuleScope.UNIVERSAL  # a blocking rule of a type the firewall has not: written for its zones, blocks more
        rules.append(r)
    expected = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                      services=model.services, service_groups=model.service_groups, rules=rules)  # fmt: skip
    for index in range(500):
        pkt = random_packet(rng, 6 if index % 4 == 0 else 4)
        pkt.out_if = zone_of(pkt.dst)
        pkt.in_if = rng.choice(ZONES) if by_interface else zone_of(pkt.src)
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, pkt, judge.deciding(pkt), text)


@pytest.mark.parametrize("seed", range(30))
def test_round_trip_keeps_every_decision(seed: int) -> None:
    rng = random.Random(7000 + seed)
    answers = random_answers(rng)
    before = BarracudaRest(text_of(answers))
    report = Report()
    written = cli.convert(parse(answers)[0], "barracuda", report)
    after = BarracudaRest(written)
    for pkt in packets(rng, 300):
        assert after.allows(pkt) == before.allows(pkt), (seed, pkt, after.deciding(pkt), before.deciding(pkt))


# -- reading, by hand ---------------------------------------------------------------------------------


def test_the_sample_is_read_as_saved() -> None:
    report = Report()
    p = parse_barracuda.parse((DATA / "barracuda_sample.json").read_bytes(), report)
    rules = {r.name: r for r in p.rules}
    assert cli.detect_format((DATA / "barracuda_sample.json").read_bytes()) == "barracuda"
    assert set(p.zones) == {"port1", "port2"} and p.default_interzone == Action.DENY
    assert rules["BLOCK-BAD"].action == Action.DROP and rules["BLOCK-BAD"].sources == ["Blocked-Nets (IPv4)"]
    assert p.address_groups["Blocked-Nets (IPv4)"].members == ["198.51.100.0/24"]
    assert rules["BLOCK-BAD-V6"].sources == ["Blocked-Nets (IPv6)"]
    assert rules["ADMIN-SSH (port2)"].src_zones == ["port2"] and rules["ADMIN-SSH (port2)"].sources == ["Admin-Hosts (port2)"]
    assert p.address_groups["Admin-Hosts (port2)"].members == ["10.10.5.10", "10.10.5.11"]
    assert rules["ADMIN-SSH (port1)"].sources == ["Admin-Hosts (port1)"] and rules["ADMIN-SSH (port1)"].destinations == ["DMZ-Servers"]
    assert rules["SERVER-SYNC (back)"].sources == ["Office-LAN"] and rules["SERVER-SYNC (back)"].destinations == ["DMZ-Servers"]
    assert rules["DNS-OUT"].enabled is False and not rules["DNS-OUT"].unsupported
    assert rules["DENY-LAN-DMZ"].action == Action.RESET_CLIENT
    assert rules["WEB-IN"].unsupported and rules["WEB-IN"].action == Action.ALLOW
    assert rules["TO-LAB"].unsupported and rules["TO-LAB"].action == Action.DROP
    assert rules["GRE-LAB"].profiles == {"application": "urlFilter", "ips": "Default"}
    assert rules["ODD"].schedule and rules["UPDATES"].destinations == ["Updates (IPv4)"]
    assert p.address_groups["Updates (IPv4)"].members == ["updates.example.com (IPv4)"]
    assert "ICMP_LIMITS" in codes(report, "rule", "PING-ALL")
    assert p.addresses["DMZ-Servers"].value == "10.20.0.16-10.20.0.255"  # the exclusion subtracted
    assert p.services["Odd-Ports"].entries == [ServiceEntry(Protocol.TCP, "1000-2000", "1024-65535")]
    assert p.service_groups["Web-Group"].members == ["HTTP+S", "Web-Group entries"]
    assert p.services["GRE"].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    assert {"BARRACUDA_FORMAT", "CONNECTION_NOT_READ", "ICMP_LIMITS"} <= set(codes(report))
    assert "INTERFACE_SPLIT" in codes(report, "rule", "ADMIN-SSH (port1)")


def test_what_is_not_there_or_not_known_is_not_any() -> None:
    base = [NETWORKS[0], SERVICES[0]]
    p, report = parse([{"rules": [rule("a", "n0", "gone", "web"), rule("b", "n0", "Any", "nothere")]}, *base])
    assert all(r.unsupported for r in p.rules) and "OBJECTS_MISSING" in codes(report)
    odd = rule("c", "n0", "Any", "web")
    odd["sourceInterface"] = "port3"
    del_state = rule("d", "n0", "Any", "web")
    del del_state["deactivated"]
    no_version = rule("e", "n0", "Any", "web")
    no_version["ipVersion"] = ""
    explicit = rule("f", "n0", "Any", "web")
    explicit["destination"] = {"explicit": [{"ip": "10.0.0.1"}]}
    unknown_policy = rule("g", "n0", "Any", "web", policies={"users": {"references": "staff"}, "mysteryFilter": "on"})
    p, report = parse([{"rules": [odd, del_state, no_version, explicit, unknown_policy]}, *base])
    rules = {r.name: r for r in p.rules}
    assert all(rules[n].unsupported for n in "cdefg"), {n: rules[n].unsupported for n in rules}
    assert rules["g"].users == ["staff"]
    assert "the input does not say whether the rule is active" in rules["d"].unsupported
    # An action this parser does not know blocks, and is reported as a blocking rule that could not be converted.
    p, _ = parse([{"rules": [rule("h", "n0", "Any", "web", "teleport")]}, *base])
    assert p.rules[0].action == Action.DROP and p.rules[0].unsupported


def test_network_objects_that_cannot_be_read() -> None:
    cases = [
        net("geo", ["10.0.0.1"], kind="geoLocation"), net("loop", [ref("loop2")]), net("loop2", [ref("loop")]),
        net("badip", ["10.0.0.300"]), net("hostex", ["www.example.com"], excluded=["10.0.0.1"]),
        net("mac", [{"entry": {"ip": "10.0.0.1", "mac": "00:11:22:33:44:55"}}]), net("empty", []),
        net("allgone", ["10.0.0.0/24"], excluded=["10.0.0.0/23"]), net("refex", ["10.0.0.0/24"]),
    ]  # fmt: skip
    cases[-1]["excluded"] = [ref("n0")]
    p, _ = parse([{"rules": [rule(f"r-{c['name']}", c["name"], "Any", "Any") for c in cases]}, *cases, NETWORKS[0]])
    for r in p.rules:
        assert r.unsupported, r.name
    assert all(p.addresses[c["name"]].kind == AddressKind.UNSUPPORTED for c in cases)


def test_services_that_cannot_be_read() -> None:
    cases = [svc("noports", [proto("tcp")]), svc("badport", [port("tcp", "0")]), svc("proto0", [proto("0")]),
             svc("rpc", [{"entry": {"protocol": "udp", "ports": ["111"], "dynService": "nfs"}}]),
             svc("client", [port("tcp", "80", client={"from": "a", "to": 3})]), svc("none", []),
             svc("huge", [port("udp", "70000")]), svc("word", [proto("teleport")])]  # fmt: skip
    p, _ = parse([{"rules": [rule(f"r-{c['name']}", "Any", "Any", c["name"]) for c in cases]}, *cases])
    assert all(p.services[c["name"]].unsupported for c in cases), {c["name"]: p.services[c["name"]].unsupported for c in cases}
    report = Report()
    lost = cli.convert(p, "panos", report)
    assert lost and all(report.item("rule", r.origin).disabled for r in p.rules)


@pytest.mark.parametrize("text, message", [
    ("", "the input is empty"),
    ("{\"rules\": [1]}", "not a rule"),
    ("{\"x\": 1}", "no rules and no objects"),
    ("{\"rules\": [{\"name\": \"a\", \"action\": {\"type\": \"pass\"}, \"source\": {}}, {\"name\": \"a\", \"action\": {}, \"source\": {}}]}", "twice"),
    ("{\"rules\": [{\"action\": {\"type\": \"pass\"}, \"source\": {}}]}", "a rule without a name"),
    ("{\"name\": \"n\", \"included\": []}\n{\"name\": \"n\", \"included\": []}", "twice"),
    ("{\"rules\": [] ", "not valid JSON"),
])  # fmt: skip
def test_malformed_input_ends_in_an_error_that_says_why(text: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse(text)


def test_huge_and_deep_inputs_end_in_an_error_or_a_reason() -> None:
    chain = [net(f"c{i}", [ref(f"c{i + 1}")]) for i in range(80)] + [net("c80", ["10.0.0.1"])]
    p, _ = parse([{"rules": [rule("deep", "c0", "Any", "Any")]}, *chain])
    assert p.rules[0].unsupported
    many = [net(f"m{i}", [f"10.{i // 256}.{i % 256}.{j}" for j in range(250)]) for i in range(900)]
    with pytest.raises(ParseError, match="more than 200000 addresses"):
        parse([{"rules": [rule("big", "m0", "Any", "Any")]}, *many])


def test_the_command_line_finds_and_reads_answers() -> None:
    data = (DATA / "barracuda_sample.json").read_bytes()
    assert cli.detect_format(data) == "barracuda"
    assert cli.detect_format(json.dumps(NETWORKS[0]).encode()) == "barracuda"
    with pytest.raises(FwshiftError, match="pfSense or SonicWall"):
        cli.load(data, "barracuda", Report(), interface_addresses=["x=10.0.0.1/24"])


# -- writing, by hand ---------------------------------------------------------------------------------


def small(**changes: Any) -> Policy:
    p = Policy(vendor="test")
    p.zones = {"inside": Zone("inside"), "outside": Zone("outside")}
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.1.0.0/16")
    p.addresses["www"] = Address("www", AddressKind.FQDN, "www.example.com")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["echo"] = Service("echo", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["srcport"] = Service("srcport", [ServiceEntry(Protocol.TCP, "80", "1024-2000")])
    for key, value in changes.items():
        setattr(p, key, value)
    return p


def emit(p: Policy, **options: Any) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(p, "barracuda", report, Options(**options)), report


def calls(text: str) -> List[Tuple[str, Json]]:
    import re

    return [(endpoint, json.loads(body)) for _, endpoint, body in re.findall(r"^call (POST|PATCH) (\S+) <<'FWSHIFT_JSON'\n(.*?)\nFWSHIFT_JSON$", text, re.S | re.M)]


def test_rules_go_to_the_top_last_first_and_a_block_rule_follows_them_deactivated() -> None:
    p = small(rules=[Rule(name="first", origin="first", sources=["lan"], services=["web"]),
                     Rule(name="second", origin="second", action=Action.DROP)])  # fmt: skip
    text, report = emit(p)
    rules = [body for endpoint, body in calls(text) if endpoint == "rules"]
    assert [r["name"] for r in rules] == ["FWSHIFT-BLOCK-v6", "FWSHIFT-BLOCK", "second-v6", "second", "first"]
    assert all(r["position"] == {"placement": "top"} for r in rules)
    assert all(r["deactivated"] is True for r in rules)
    patches = [endpoint for endpoint, body in calls(text) if endpoint.startswith("rules/")]
    assert patches == ["rules/first", "rules/second", "rules/second-v6"]  # activated first rule first, the block rules not
    assert {"BARRACUDA_LOAD", "BLOCK_RULE_INACTIVE"} <= set(codes(report))
    assert [e for e, _ in calls(text)].index("rules") > max(i for i, (e, _) in enumerate(calls(text)) if e.startswith("objects"))


def test_the_script_runs_in_a_shell_without_a_firewall() -> None:
    p = small(rules=[Rule(name="it's \"quoted\"", origin="q", sources=["lan"], services=["web"], description="a $HOME `x` 'y'")])
    text, _ = emit(p)
    result = subprocess.run(["sh", "-c", text, "fwshift"], env={"DRY_RUN": "1", "PATH": "/usr/bin:/bin"}, capture_output=True,
                            text=True, timeout=30)  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert "POST rules" in result.stdout and '"a $HOME `x` \'y\'"' in result.stdout
    missing = subprocess.run(["sh", "-c", text, "fwshift"], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=30)
    assert missing.returncode != 0 and "BARRACUDA" in missing.stderr


def test_zones_without_networks_or_interfaces() -> None:
    p = small(rules=[Rule(name="allow", origin="allow", src_zones=["inside"], dst_zones=["outside"], services=["web"]),
                     Rule(name="block", origin="block", src_zones=["inside"], dst_zones=["outside"], action=Action.DROP)])  # fmt: skip
    text, report = emit(p)
    assert "ZONE_NETWORK_MISSING" in codes(report, "rule", "allow") and report.item("rule", "allow").disabled
    assert "ZONE_WIDENED" in codes(report, "rule", "block") and not report.item("rule", "block").disabled
    text, report = emit(p, interface_map={"inside": "port2"}, zone_networks={"inside": ["10.1.0.0/16"], "outside": ["0.0.0.0/0", "::/0"]})
    objects = {b["name"]: b for e, b in calls(text) if e == "objects/networks"}
    assert objects["allow.src"]["included"][0]["entry"] == {"ip": "0.0.0.0/0", "interface": "port2"}
    assert objects["allow.dst"]["included"] == [{"entry": {"ip": "0.0.0.0/1"}}, {"entry": {"ip": "128.0.0.0/1"}}] or all(
        "10.1." not in item["entry"]["ip"] for item in objects["allow.dst"]["included"])
    assert "INTERFACES_REQUIRED" in codes(report)
    with pytest.raises(FwshiftError, match="interface-map"):
        emit(p, interface_map={"inside": "port 2; rm"})


def test_what_the_api_cannot_take_is_deactivated_or_left_out() -> None:
    nat = NatRule(name="publish", destinations=["lan"], destination_translation=DestNat("10.1.0.5"))
    nat.origin = "publish"
    p = small(rules=[Rule(name="host", origin="host", destinations=["www"]), Rule(name="ping", origin="ping", services=["echo"]),
                     Rule(name="src", origin="src", services=["srcport"]),
                     Rule(name="x" * 60, origin="long", services=["web"])], nat_rules=[nat])  # fmt: skip
    text, report = emit(p)
    for name in ("host", "ping"):
        assert report.item("rule", name).disabled, name
    services = {b["name"]: b for e, b in calls(text) if e == "objects/services"}
    assert services["srcport"]["entries"] == [{"entry": {"protocol": "tcp", "ports": ["80"], "clientPortUsed": {"from": 1024, "to": 2000}}}]
    assert report.item("nat", "publish").skipped and "NAT_NOT_CONVERTED" in codes(report, "nat", "publish")
    names = [b["name"] for e, b in calls(text) if "name" in b]
    assert all(len(n) <= 32 for n in names) and "x" * 32 in names
    objects = {b["name"]: b for e, b in calls(text) if e == "objects/networks"}
    assert objects["www"]["included"] == [{"entry": {"ip": "192.0.0.8"}}] and "FWSHIFT PLACEHOLDER" in objects["www"]["comment"]
    rules = {b["name"]: b for e, b in calls(text) if e == "rules"}
    assert rules["host"]["comment"].startswith("FWSHIFT inactive")


def test_negation_and_ranges_are_written_as_networks() -> None:
    p = small(rules=[Rule(name="not-lan", origin="not-lan", sources=["lan"], negate_source=True, services=["web"])])
    p.addresses["r"] = Address("r", AddressKind.RANGE, "10.2.0.1-10.2.0.6")
    p.rules.append(Rule(name="range", origin="range", destinations=["r"]))
    text, report = emit(p)
    objects = {b["name"]: b for e, b in calls(text) if e == "objects/networks"}
    assert [i["entry"]["ip"] for i in objects["r"]["included"]] == ["10.2.0.1", "10.2.0.2/31", "10.2.0.4/31", "10.2.0.6"]
    assert "10.1.0.0/16" not in json.dumps(objects["not-lan.src"]) and "NEGATION_EXPANDED" in codes(report, "rule", "not-lan")
    rules = {b["name"]: b for e, b in calls(text) if e == "rules"}
    assert rules["range"]["destination"] == {"references": "r"}


# -- what the review of version 0.11.0 found ----------------------------------------------------------


def test_a_refused_call_leaves_only_a_prefix_of_the_rules_active(tmp_path: Any) -> None:
    """The rules are created deactivated and activated first rule first: a call the firewall refuses stops the script,
    and what is active then is the start of the policy, never a later allow without the blocks above it."""
    p = small(rules=[Rule(name="block-guests", origin="b", sources=["lan"], action=Action.DROP),
                     Rule(name="allow-web", origin="a", services=["web"]),
                     Rule(name="allow-more", origin="m")])  # fmt: skip
    text, _ = emit(p)
    fake = tmp_path / "curl"
    fake.write_text('#!/bin/sh\nfor a in "$@"; do last="$a"; done\nprev=""; method=""\nfor a in "$@"; do [ "$prev" = "-X" ] && '
                    'method="$a"; prev="$a"; done\necho "$method $last" >> "$LOG"\ncat > /dev/null\ncase "$last" in *"$FAIL"*) '
                    'exit 22;; esac\necho "{}"\n')  # fmt: skip
    fake.chmod(0o755)
    log = tmp_path / "log"
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "BARRACUDA": "https://fw.example.net:8443", "TOKEN": "t", "LOG": str(log),
           "FAIL": "rules/allow-web", "TMPDIR": str(tmp_path)}  # fmt: skip
    result = subprocess.run(["sh", "-c", text, "fwshift"], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    made = log.read_text().split("\n")
    patches = [line.split("/rules/")[1] for line in made if line.startswith("PATCH")]
    assert patches == ["block-guests", "allow-web"]  # the refused one is the last; allow-more was never activated
    assert all(line.startswith("POST") for line in made[: made.index(next(line for line in made if line.startswith("PATCH")))])
    assert not list(tmp_path.glob("tmp.*")), "the file with the token is left behind"


def test_upper_and_lower_case_are_one_name() -> None:
    p = small(rules=[Rule(name="r", origin="r", sources=["ANY"], services=["any"]), Rule(name="R", origin="R2", sources=["LAN"])])
    p.addresses["ANY"] = Address("ANY", AddressKind.NETWORK, "10.0.0.1/32")
    p.addresses["LAN"] = Address("LAN", AddressKind.NETWORK, "10.9.0.0/16")
    p.services["any"] = Service("any", [ServiceEntry(Protocol.TCP, "22")])
    text, report = emit(p)
    for kind in ("objects/networks", "objects/services", "rules"):
        names = [b["name"].lower() for e, b in calls(text) if e == kind]
        assert len(names) == len(set(names)), names
    rules = {b["name"]: b for e, b in calls(text) if e == "rules"}
    assert rules["r"]["source"]["references"].lower() != "any" and rules["r"]["service"]["references"].lower() != "any"
    assert {"r", "R_2"} <= set(rules)
    # Read: only the name Any is the object Any, and an object of the input of that name is that object.
    p, report = parse([{"rules": [rule("a", "ANY", "Any", "Any"), rule("b", "Any", "Any", "Any")]}, net("Any", ["10.0.0.5"])])
    rules_read = {r.name: r for r in p.rules}
    assert rules_read["a"].unsupported and "OBJECTS_MISSING" in codes(report)
    assert rules_read["b"].sources == ["Any"] and p.addresses["Any"].value == "10.0.0.5"


def test_one_object_used_by_many_rules_is_derived_once() -> None:
    big = net("big", [f"10.{i // 250}.{i % 250}.1" for i in range(40000)] + ["2001:db8::1", entry("10.200.0.0/16", "port1")])
    rules = [rule(f"r{i}", "big", "big", "Any", version="IPv4") for i in range(300)]
    p, _ = parse([{"rules": rules}, big])
    derived = [g for g in p.address_groups if g.startswith("big (")]
    assert sorted(derived) == ["big (IPv4)", "big (no interface, IPv4)", "big (port1)"]  # port1 holds IPv4 only
    assert sum(len(r.sources) + len(r.destinations) for r in p.rules) <= 3 * len(p.rules)


@pytest.mark.parametrize("source", ["barracuda", "fmc", "checkpoint"])
def test_a_lone_surrogate_ends_in_an_error(source: str) -> None:
    with pytest.raises(ParseError, match="half of a UTF-16 pair"):
        cli.load(b'[{"rules": [], "rulebase": [], "name": "\\ud800"}]', source, Report())


def test_rule_attributes_read_strictly() -> None:
    base = [NETWORKS[0], SERVICES[0]]
    odd_user = rule("u1", "n0", "Any", "web", policies={"user": {"name": "staff"}})
    list_user = rule("u2", "n0", "Any", "web", policies={"users": [{"references": "staff"}]})
    good_user = rule("u3", "n0", "Any", "web", policies={"users": {"references": ["staff", "Any"]}})
    one = rule("b1", "n0", "Any", "web", "block")
    one["bidirectional"] = 1
    at_iface = rule("b2", "n0", "at1", "web", bidirectional=True)
    expiring = rule("e1", "n0", "Any", "web", expiresIn=3600)
    expiring_block = rule("e2", "n0", "Any", "web", "block", expiresIn=3600)
    dynamic = rule("d1", "n0", "Any", "web", dynamic=True)
    p, report = parse([{"rules": [odd_user, list_user, good_user, one, at_iface, expiring, expiring_block, dynamic]}, *base,
                       NETWORKS[9]])  # fmt: skip
    rules = {r.name: r for r in p.rules}
    assert rules["u1"].unsupported and rules["u2"].unsupported and not rules["u3"].unsupported and rules["u3"].users == ["staff"]
    assert rules["b1"].unsupported and rules["b2"].unsupported and rules["b2 (back)"].unsupported
    assert rules["e1"].unsupported and not rules["e2"].unsupported and "RULE_EXPIRES" in codes(report, "rule", "e2")
    assert [f.severity for f in report.item("rule", "d1").findings if f.code == "DYNAMIC_RULE"] == [Severity.APPROX]


def test_service_entries_read_strictly() -> None:
    cases = [svc("hidden", [{"entry": {"protocol": "tcp", "ports": ["22"], "clientPortUsed": None,
                                       "tcp": {"clientPortUsed": {"from": 1024, "to": 2000}}}}]),
             svc("icmptype", [{"entry": {"protocol": "icmp", "icmp": {"type": 8}}}]),
             svc("twice", [{"entry": {"protocol": "tcp", "ports": ["*"], "tcp": {"ports": ["80"]}}}]),
             svc("wrongsub", [{"entry": {"protocol": "tcp", "ports": ["80"], "udp": {"ports": ["53"]}}}]),
             svc("group", [ref("gone")])]  # fmt: skip
    p, report = parse([{"rules": [rule(f"r-{c['name']}", "Any", "Any", c["name"]) for c in cases]}, *cases])
    assert p.services["hidden"].entries == [ServiceEntry(Protocol.TCP, "22", "1024-2000")]
    for name in ("icmptype", "twice", "wrongsub"):
        assert p.services[name].unsupported, name
    rules = {r.name: r for r in p.rules}
    assert rules["r-group"].unsupported and "OBJECTS_MISSING" in codes(report)


def test_entries_read_strictly() -> None:
    cases = [net("zero", [{"entry": {"ip": "10.0.0.1", "interface": 0}}]), net("listy", [{"entry": {"ip": "10.0.0.1", "interface": []}}]),
             net("short", ["192.168.50-100"])]  # fmt: skip
    p, _ = parse([{"rules": [rule("r", "zero", "Any", "Any")]}, *cases])
    assert all(p.addresses[c["name"]].kind == AddressKind.UNSUPPORTED for c in cases)


def test_names_fwshift_makes_do_not_collide_with_names_of_the_input() -> None:
    p, _ = parse([{"rules": [rule("x (back)", "n0", "Any", "Any"), rule("x", "n0", "n1", "Any", bidirectional=True),
                             rule("y (eth0)", "Any", "Any", "Any"), rule("y", "at0", "Any", "Any")]}, *NETWORKS])  # fmt: skip
    names = [r.name for r in p.rules]
    assert len(names) == len(set(names)) and "x (back) 2" in names and "y (eth0) 2" in names
    cli.convert(p, "panos", Report())


def test_services_by_ip_version_and_protocols_by_number() -> None:
    p = small(rules=[Rule(name="ping", origin="ping"), Rule(name="tcp", origin="tcp")])
    p.services["icmp4"] = Service("icmp4", [ServiceEntry(Protocol.ICMP)])
    p.services["both"] = Service("both", [ServiceEntry(Protocol.ICMP), ServiceEntry(Protocol.TCP, "22")])
    p.services["six"] = Service("six", [ServiceEntry(Protocol.IP, ip_protocol=6)])
    p.rules[0].services = ["icmp4"]
    p.rules[1].services = ["six"]
    p.rules.append(Rule(name="mixed", origin="mixed", services=["both"]))
    text, report = emit(p)
    rules = {b["name"]: b for e, b in calls(text) if e == "rules"}
    assert "ping" in rules and rules["ping"]["ipVersion"] == "IPv4" and not any(n.startswith("ping-v6") for n in rules)
    services = {b["name"]: b for e, b in calls(text) if e == "objects/services"}
    assert services["six"]["entries"] == [{"entry": {"protocol": "tcp", "ports": ["*"]}}]
    v6 = rules["mixed-v6"]["service"]["references"]
    assert services[v6]["entries"] == [{"entry": {"protocol": "tcp", "ports": ["22"]}}] and rules["mixed"]["service"]["references"] == "both"


def test_destinations_an_asa_worked_out_need_no_networks() -> None:
    rule_ = Rule(name="out", origin="out", src_zones=["inside"], dst_zones=["outside"], services=["web"], egress_implied=True)
    text, report = emit(small(rules=[rule_]), interface_map={"inside": "port2"})
    assert not report.item("rule", "out").disabled, [f.message for f in report.item("rule", "out").findings]
