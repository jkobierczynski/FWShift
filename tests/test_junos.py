# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Juniper SRX: configurations read in both forms, set commands written, and packets through both.

What an SRX decides is worked out by ``helpers.JunosConfig``, which shares no code with fwshift's parser and emitter.
It is written from the same reading of Juniper's documentation (DEVELOPMENT.md).
"""

from __future__ import annotations

import random
from typing import Any, List, Tuple

import pytest
from helpers import DATA, JunosConfig
from test_iptables import ZONES, Packet, model_allows, random_model, random_packet

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope, Service
from fwshift.model import ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import junos as parse_junos
from fwshift.report import Report, Severity


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_junos.parse(text.encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


def emit(p: Policy, **options: Any) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(p, "junos", report, Options(**options)), report


# -- an SRX made up at random ------------------------------------------------------------------------

BASE = [f"set security zones security-zone {z} interfaces ge-0/0/{i}.0" for i, z in enumerate(ZONES)] + [
    "set security address-book global address n0 10.0.0.0/24",
    "set security address-book global address n1 10.0.1.0/24",
    "set security address-book global address half 10.0.1.128/25",
    "set security address-book global address span range-address 10.0.2.100 to 10.0.3.50",
    "set security address-book global address host 10.0.0.17/32",
    "set security address-book global address six 2001:db8:1::/48",
    "set security address-book global address-set grp address n0",
    "set security address-book global address-set grp address span",
    "set security address-book global address-set nested address-set grp",
    "set security address-book global address-set nested address host",
    "set security address-book global address-set mixed address six",
    "set security address-book global address-set mixed address n1",
    # A book of zone eth1 in which n0 is something else.
    "set security address-book book1 address n0 10.0.3.0/24",
    "set security address-book book1 address only1 10.0.4.0/24",
    "set security address-book book1 attach zone eth1",
    "set applications application web protocol tcp",
    "set applications application web destination-port 80",
    "set applications application alt term t1 protocol tcp destination-port 8000-8010",
    "set applications application alt term t2 protocol udp destination-port 9000",
    "set applications application hi protocol tcp",
    "set applications application hi destination-port 8080",
    "set applications application hi source-port 1024-2000",
    "set applications application gre protocol gre",
    "set applications application ping protocol icmp",
    "set applications application ping icmp-type echo-request",
    "set applications application-set webs application web",
    "set applications application-set webs application junos-https",
    "set applications application-set webs application alt",
]  # fmt: skip
GLOBAL_NAMES = ["n0", "n1", "half", "span", "host", "six", "grp", "nested", "mixed"]
IPV4_NAMES = ["n0", "n1", "half", "span", "host", "grp", "nested"]
APPS = ["web", "alt", "hi", "gre", "ping", "webs", "junos-http", "junos-dns-udp", "junos-icmp-all"]


def random_config(rng: random.Random) -> str:
    lines = list(BASE)
    if rng.random() < 0.2:
        lines.append("set security policies default-policy permit-all")
    for index in range(rng.randint(4, 14)):
        glob = rng.random() < 0.25
        a, b = rng.choice(ZONES), rng.choice(ZONES)
        context = "global" if glob else f"from-zone {a} to-zone {b}"
        where = f"set security policies {context} policy p{index}"
        names = GLOBAL_NAMES + ([] if glob or b != "eth1" else ["only1"])
        src_names = GLOBAL_NAMES + ([] if glob or a != "eth1" else ["only1"])
        exclude_src = rng.random() < 0.15
        exclude_dst = rng.random() < 0.15
        sources = rng.sample(IPV4_NAMES, rng.randint(1, 2)) if exclude_src else (["any"] if rng.random() < 0.3 else rng.sample(src_names, rng.randint(1, 3)))
        destinations = rng.sample(IPV4_NAMES, rng.randint(1, 2)) if exclude_dst else (["any"] if rng.random() < 0.3 else rng.sample(names, rng.randint(1, 3)))
        applications = ["any"] if rng.random() < 0.3 else rng.sample(APPS, rng.randint(1, 2))
        lines += [f"{where} match source-address {s}" for s in sources]
        lines += [f"{where} match destination-address {d}" for d in destinations]
        lines += [f"{where} match application {x}" for x in applications]
        if exclude_src:
            lines.append(f"{where} match source-address-excluded")
        if exclude_dst:
            lines.append(f"{where} match destination-address-excluded")
        if glob and rng.random() < 0.5:
            lines += [f"{where} match from-zone {z}" for z in rng.sample(ZONES, rng.randint(1, 2))]
        if glob and rng.random() < 0.5:
            lines += [f"{where} match to-zone {z}" for z in rng.sample(ZONES, rng.randint(1, 2))]
        lines.append(f"{where} then {rng.choice(['permit', 'permit', 'deny', 'reject'])}")
        if rng.random() < 0.1:
            lines.append("deactivate " + where[4:])
        elif len(sources) > 1 and rng.random() < 0.3:
            lines.append(f"deactivate {where[4:]} match source-address {sources[0]}")
    return "\n".join(lines) + "\n"


def packets(rng: random.Random, count: int) -> List[Packet]:
    out = []
    for index in range(count):
        pkt = random_packet(rng, 6 if index % 4 == 0 else 4)
        pkt.in_if, pkt.out_if = rng.choice(ZONES), rng.choice(ZONES)
        out.append(pkt)
    return out


def test_parsed_configuration_decides_like_the_srx() -> None:
    """Pairs of zones and global policies, address books of zones, sets, negation, applications with terms, deactivated
    policies and members, the default policy: the model decides as the SRX would."""
    allowed = compared = 0
    for seed in range(100):
        rng = random.Random(seed)
        text = random_config(rng)
        judge = JunosConfig(text)
        p, report = parse(text)
        assert not [r.name for r in p.rules if r.unsupported], (seed, [(r.name, r.unsupported) for r in p.rules if r.unsupported])
        for pkt in packets(rng, 300):
            expected = judge.allows(pkt)
            compared += 1
            allowed += expected
            assert model_allows(p, pkt) == expected, (seed, pkt, judge.deciding(pkt))
    assert compared // 20 < allowed < compared * 9 // 10, (allowed, compared)


@pytest.mark.parametrize("seed", range(60))
def test_emitted_policies_decide_like_the_model(seed: int) -> None:
    """Pairs of zones for rules of given zones, global policies at the end, negation natively or as what is left, rule
    types: the set commands give the verdicts of the model."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {name: Zone(name) for name in ZONES}
    text, report = emit(model)
    judge = JunosConfig(text)
    lost = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    for name in lost:
        reasons = {f.code for f in report.item("rule", name).findings if f.severity == Severity.REVIEW}
        assert reasons <= {"SERVICE_NEGATE", "UNCONVERTIBLE_OBJECT"}, (seed, name, reasons)
    expected = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                      services=model.services, service_groups=model.service_groups,
                      rules=[r for r in model.rules if r.name not in lost])  # fmt: skip
    for pkt in packets(rng, 500):
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, pkt, judge.deciding(pkt), text)


@pytest.mark.parametrize("seed", range(30))
def test_round_trip_keeps_every_decision(seed: int) -> None:
    rng = random.Random(9000 + seed)
    text = random_config(rng)
    before = JunosConfig(text)
    written, _ = emit(parse(text)[0])
    after = JunosConfig(written)
    for pkt in packets(rng, 300):
        assert after.allows(pkt) == before.allows(pkt), (seed, pkt, after.deciding(pkt), before.deciding(pkt))


# -- reading, by hand ---------------------------------------------------------------------------------


def test_the_sample_is_read_as_saved() -> None:
    data = (DATA / "junos_sample.conf").read_bytes()
    assert cli.detect_format(data) == "junos"
    p, report = parse(data.decode())
    rules = {r.name: r for r in p.rules}
    assert set(p.zones) == {"untrust", "trust", "dmz", "guest"} and p.zones["dmz"].interfaces == ["ge-0/0/2.0", "ge-0/0/3.0"]
    assert list(rules)[:4] == ["block-bad", "web-out", "updates", "ping-out"] and list(rules)[-2:] == ["global-block", "global-ntp"]
    assert rules["block-bad"].action == Action.DROP and rules["block-bad"].log_start and not rules["block-bad"].log_end
    assert rules["web-out"].description == "web for the office" and rules["web-out"].log_end
    assert rules["global-block"].action == Action.RESET_CLIENT and rules["global-block"].src_zones == [ANY]
    assert rules["global-ntp"].src_zones == ["trust"] and rules["global-ntp"].dst_zones == ["untrust"]
    assert rules["admin"].destinations == ["dmz-net (dmz-book)"] and rules["not-servers"].destinations == ["lan-net (dmz-book)"]
    assert p.addresses["lan-net (dmz-book)"].value == "10.20.0.64/26" and p.addresses["lan-net"].value == "10.10.0.0/16"
    assert rules["not-servers"].negate_source and rules["dmz-out"].enabled is False and not rules["dmz-out"].unsupported
    assert rules["guest-web"].schedule == "work-hours" and rules["guest-web"].destinations == ["0.0.0.0/0"]
    assert rules["guest-ping"].unsupported == [] and p.services["junos-ping"].unsupported
    assert "to-box" not in rules and "HOST_POLICIES" in codes(report)
    assert p.services["app-mail-sub"].entries == [ServiceEntry(Protocol.TCP, "587"), ServiceEntry(Protocol.TCP, "465")]
    assert p.services["app-high"].entries == [ServiceEntry(Protocol.TCP, "1000-2000", "1024-65535")]
    assert p.services["app-ntp"].entries == [ServiceEntry(Protocol.UDP, "123")]
    assert p.services["app-ping"].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    assert p.addresses["updates"].kind == AddressKind.FQDN and p.addresses["updates"].fqdn_family == 4
    # Policies name the translated destination: the model has the original one as well, and says so.
    assert "203.0.113.10" in rules["web-in"].destinations and "NAT_PORT_TRANSLATION" in codes(report, "rule", "web-in")
    assert "203.0.113.25" in rules["mail-in"].destinations
    nats = {n.name: n for n in p.nat_rules}
    assert list(nats) == ["inbound static-mail", "from-internet dnat-web", "inbound static-mail (outbound)", "trust-out snat-lan",
                          "dmz-out snat-dmz", "vr-out snat-vr"]  # fmt: skip
    assert nats["from-internet dnat-web"].destination_translation == DestNat("10.20.0.80", "8080")
    assert nats["inbound static-mail (outbound)"].source_translation == SourceNat(SnatKind.STATIC, ["203.0.113.25"])
    assert nats["trust-out snat-lan"].source_translation == SourceNat(SnatKind.INTERFACE) and nats["trust-out snat-lan"].dst_zones == ["untrust"]
    assert nats["dmz-out snat-dmz"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.50-203.0.113.59"])
    assert nats["vr-out snat-vr"].unsupported and all(n.combines for n in nats.values())


BRACES = """## Last commit: 2026-10-01 10:00:00 UTC by admin
version 21.4R3.15;
security {
    address-book {
        global {
            address web 10.20.0.80/32;
            address lan 10.10.0.0/16;
            /* the web servers */
            address-set servers {
                address web;
            }
        }
    }
    policies {
        from-zone trust to-zone dmz {
            policy to-web {
                match {
                    source-address lan;
                    destination-address servers;
                    application [ junos-http junos-https ];
                }
                then {
                    permit;
                    log {
                        session-close;
                    }
                }
            }
            inactive: policy old {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
    }
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
        }
        security-zone dmz {
            interfaces {
                ge-0/0/2.0 {
                    host-inbound-traffic {
                        system-services {
                            ping;
                        }
                    }
                }
            }
        }
    }
}
"""

SET_FORM = """set version 21.4R3.15
set security address-book global address web 10.20.0.80/32
set security address-book global address lan 10.10.0.0/16
set security address-book global address-set servers address web
set security policies from-zone trust to-zone dmz policy to-web match source-address lan
set security policies from-zone trust to-zone dmz policy to-web match destination-address servers
set security policies from-zone trust to-zone dmz policy to-web match application junos-http
set security policies from-zone trust to-zone dmz policy to-web match application junos-https
set security policies from-zone trust to-zone dmz policy to-web then permit
set security policies from-zone trust to-zone dmz policy to-web then log session-close
set security policies from-zone trust to-zone dmz policy old match source-address any
set security policies from-zone trust to-zone dmz policy old match destination-address any
set security policies from-zone trust to-zone dmz policy old match application any
set security policies from-zone trust to-zone dmz policy old then deny
deactivate security policies from-zone trust to-zone dmz policy old
set security zones security-zone trust interfaces ge-0/0/1.0
set security zones security-zone dmz interfaces ge-0/0/2.0 host-inbound-traffic system-services ping
"""


def test_the_configuration_in_braces_reads_as_its_set_lines() -> None:
    assert cli.detect_format(BRACES.encode()) == "junos"
    braces, _ = parse(BRACES)
    lines, _ = parse(SET_FORM)
    assert braces.to_dict() == lines.to_dict()
    assert [r.enabled for r in braces.rules] == [True, False]


@pytest.mark.parametrize("text, message", [
    ("", "empty"),
    ("set system host-name x\n", "no 'security' part"),
    ('set security policies from-zone a to-zone b policy "p then permit\n', "quoted string that is not closed"),
    ("delete security policies\n", "file of commands"),
    ("set security zones security-zone a\nfrobnicate\n", "not a line of"),
    ("security {\n    zones {\n", "ends inside a statement"),
    ("security { zones } }\n", "statement is not finished"),
    ("set security policies default-policy maybe-all\n", "default-policy"),
    ("set groups g security policies from-zone a to-zone b policy p then permit\nset apply-groups g\n", "display inheritance"),
    ("set security address-book b1 attach zone a\nset security zones security-zone a address-book address x 10.0.0.1/32\n", "two address books"),
    ("set security zones security-zone a\x00\n", "NUL"),
])  # fmt: skip
def test_malformed_input_ends_in_an_error_that_says_why(text: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse(text)


def test_what_is_not_there_or_not_known_is_not_any() -> None:
    head = "set security zones security-zone a interfaces ge-0/0/0.0\nset security zones security-zone b interfaces ge-0/0/1.0\n"
    where = "set security policies from-zone a to-zone b policy"
    text = head + "\n".join([
        f"{where} p1 match source-address gone", f"{where} p1 match destination-address any", f"{where} p1 match application any",
        f"{where} p1 then permit",
        f"{where} p2 match source-address any", f"{where} p2 match destination-address any", f"{where} p2 match application nothere",
        f"{where} p2 then permit",
        f"{where} p3 match source-address any", f"{where} p3 match destination-address any", f"{where} p3 match application any",
        f"{where} p4 match source-address any", f"{where} p4 match destination-address any", f"{where} p4 match application any",
        f"{where} p4 match dynamic-application junos:FACEBOOK", f"{where} p4 then permit",
        f"{where} p5 match source-address any", f"{where} p5 match destination-address any", f"{where} p5 match application junos-weird",
        f"{where} p5 then permit",
        f"{where} p6 match source-address any", f"{where} p6 match application any", f"{where} p6 then permit",
        f"{where} p7 match source-address any", f"{where} p7 match destination-address any", f"{where} p7 match application any",
        f"{where} p7 then permit tunnel ipsec-vpn vpn1",
        f"{where} p8 match source-address any", f"{where} p8 match destination-address any", f"{where} p8 match application any",
        f"{where} p8 match source-address-excluded", f"{where} p8 then deny",
        "set security policies from-zone a to-zone c policy p9 match source-address any",
        "set security policies from-zone a to-zone c policy p9 match destination-address any",
        "set security policies from-zone a to-zone c policy p9 match application any",
        "set security policies from-zone a to-zone c policy p9 then permit",
    ]) + "\n"  # fmt: skip
    p, report = parse(text)
    rules = {r.name: r for r in p.rules}
    for name in ("p1", "p2", "p3", "p4", "p6", "p7", "p8", "p9"):
        assert rules[name].unsupported, name
    assert p.services["junos-weird"].unsupported and "OBJECTS_MISSING" in codes(report)
    assert rules["p3"].action == Action.DROP  # no action is not "permit"


def test_applications_and_addresses_read_strictly() -> None:
    head = "set security zones security-zone a interfaces ge-0/0/0.0\n"
    text = head + "\n".join([
        "set applications application noport protocol tcp",
        "set applications application badport protocol tcp destination-port 0",
        "set applications application rpc protocol udp destination-port 111",
        "set applications application rpc rpc-program-number 100003",
        "set applications application mixed protocol tcp destination-port 80",
        "set applications application mixed term t1 protocol udp destination-port 53",
        "set applications application named protocol tcp destination-port https",
        "set applications application unknown protocol tcp destination-port nosuchport",
        "set security address-book global address hostbits 10.0.0.1/24",
        "set security address-book global address wild wildcard-address 10.0.0.1/255.0.255.255",
        "set security address-book global address two 10.0.0.1/32",
        "set security address-book global address two 10.0.0.2/32",
    ]) + "\n"  # fmt: skip
    reader = parse_junos._Reader(parse_junos._lines(text.encode()), Report())
    reader.zones()
    reader.address_books()
    reader.applications()
    for name in ("noport", "badport", "rpc", "mixed", "unknown"):
        reader.application(name)
        assert reader.p.services[name].unsupported, name
    reader.application("named")
    assert reader.p.services["named"].entries == [ServiceEntry(Protocol.TCP, "443")]
    for name in ("hostbits", "wild", "two"):
        model = reader.address(name, "a")
        assert model is not None and reader.p.addresses[model].kind == AddressKind.UNSUPPORTED, name


def test_parts_that_are_not_read_are_named() -> None:
    text = "\n".join([
        "set security zones security-zone a interfaces ge-0/0/0.0",
        "set logical-systems ls1 security zones security-zone x interfaces ge-0/0/5.0",
        "set security nat source rule-set r1 from zone a",
        "set security nat source rule-set r1 to zone a",
        "set security nat source rule-set r1 rule x match source-address 10.0.0.0/8",
        "set security nat source rule-set r1 rule x match application junos-http",
        "set security nat source rule-set r1 rule x then source-nat interface",
    ]) + "\n"  # fmt: skip
    p, report = parse(text)
    assert "PARTS_NOT_READ" in codes(report) and p.nat_rules[0].unsupported


# -- writing, by hand ---------------------------------------------------------------------------------


def small(**changes: Any) -> Policy:
    p = Policy(vendor="test")
    p.zones = {"inside": Zone("inside"), "outside": Zone("outside")}
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.1.0.0/16")
    p.addresses["www"] = Address("www", AddressKind.FQDN, "www.example.com")
    p.addresses["junos-bad"] = Address("junos-bad", AddressKind.NETWORK, "10.9.0.0/16")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8::/32")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    for key, value in changes.items():
        setattr(p, key, value)
    return p


def test_rules_for_every_zone_at_the_end_become_global_policies() -> None:
    p = small(rules=[Rule(name="out", origin="out", src_zones=["inside"], dst_zones=["outside"], sources=["lan"], services=["web"]),
                     Rule(name="block-all", origin="block-all", action=Action.DROP)])  # fmt: skip
    text, report = emit(p)
    assert "set security policies from-zone inside to-zone outside policy out then permit" in text
    assert "set security policies global policy block-all then deny" in text
    p.rules.append(Rule(name="late", origin="late", src_zones=["inside"], dst_zones=["inside"]))
    text, report = emit(p)
    assert "set security policies global policy block-all then deny" in text
    assert "set security policies global policy late match from-zone inside" in text


def test_negation_natively_where_junos_can_and_as_what_is_left_where_not() -> None:
    p = small(rules=[Rule(name="not-lan", origin="n1", sources=["lan"], negate_source=True),
                     Rule(name="not-six", origin="n2", destinations=["six"], negate_destination=True)])  # fmt: skip
    text, report = emit(p)
    assert "policy not-lan match source-address-excluded" in text and "policy not-lan match source-address lan" in text
    assert "not-six match destination-address-excluded" not in text and "NEGATION_EXPANDED" in codes(report, "rule", "n2")


def test_names_junos_keeps_for_itself_and_zones_it_cannot_take() -> None:
    p = small(rules=[Rule(name="r", origin="r", sources=["junos-bad"])])
    text, report = emit(p)
    assert "address xjunos-bad 10.9.0.0/16" in text and "RENAMED" in codes(report, "address", "junos-bad")
    bad = small(rules=[Rule(name="r", origin="r", src_zones=["in side"])])
    with pytest.raises(FwshiftError, match="zone-map"):
        emit(bad)
    text, _ = emit(bad, zone_map={"in side": "inside"})
    assert "from-zone inside" in text


def test_deactivated_and_described_policies() -> None:
    p = small(rules=[Rule(name="host", origin="host", destinations=["www"], description='say "hi" \\ there'),
                     Rule(name="off", origin="off", enabled=False)])  # fmt: skip
    p.addresses["www"].kind = AddressKind.UNSUPPORTED
    text, report = emit(p)
    assert "deactivate security policies global policy host" in text and "deactivate security policies global policy off" in text
    assert 'description "FWSHIFT inactive, see the report. say \\"hi\\" \\\\ there"' in text
    assert JunosConfig(text).sets  # the judge reads the quoting back


def test_nat_as_junos_has_it() -> None:
    p = small()
    p.addresses["public"] = Address("public", AddressKind.NETWORK, "203.0.113.10")
    p.addresses["server"] = Address("server", AddressKind.NETWORK, "10.1.0.10")
    p.services["http"] = Service("http", [ServiceEntry(Protocol.TCP, "80")])
    dnat = NatRule(name="publish", origin="publish", src_zones=["outside"], destinations=["public"], service="http",
                   destination_translation=DestNat("server", "8080"))  # fmt: skip
    snat = NatRule(name="hide", origin="hide", src_zones=["inside"], dst_zones=["outside"], sources=["lan"],
                   source_translation=SourceNat(SnatKind.INTERFACE))  # fmt: skip
    both = NatRule(name="both", origin="both", src_zones=["inside"], dst_zones=["outside"], sources=["lan"], destinations=["six"],
                   source_translation=SourceNat(SnatKind.STATIC, ["203.0.113.0/24"], bidirectional=True))  # fmt: skip
    p.nat_rules = [dnat, snat, both]
    p.rules = [Rule(name="to-server", origin="to-server", src_zones=["outside"], dst_zones=["inside"], destinations=["public"], services=["http"])]
    text, report = emit(p)
    assert "set security nat destination pool publish-pool address 10.1.0.10/32 port 8080" in text
    assert "rule publish match destination-address 203.0.113.10/32" in text and "rule publish match destination-port 80" in text
    assert "rule hide then source-nat interface" in text and "rule-set fwshift-source-inside-outside to zone outside" in text
    assert report.item("nat", "both").skipped
    # The policy names what the SRX sees after destination NAT: the server and its port.
    assert "policy to-server match destination-address server" in text


# -- what the review of version 0.12.0 found ----------------------------------------------------------


def nat_policy() -> Policy:
    p = small()
    p.addresses["public"] = Address("public", AddressKind.NETWORK, "203.0.113.10")
    p.addresses["server"] = Address("server", AddressKind.NETWORK, "10.1.0.10")
    p.services["http"] = Service("http", [ServiceEntry(Protocol.TCP, "80")])
    p.services["ssh"] = Service("ssh", [ServiceEntry(Protocol.TCP, "22")])
    return p


def test_a_bidirectional_static_nat_rewrites_the_policies_too() -> None:
    p = nat_policy()
    p.nat_rules = [NatRule(name="pair", origin="pair", src_zones=["inside"], dst_zones=["outside"], sources=["server"],
                           source_translation=SourceNat(SnatKind.STATIC, ["public"], bidirectional=True))]  # fmt: skip
    p.rules = [Rule(name="no-ssh", origin="no-ssh", src_zones=["outside"], dst_zones=["inside"], destinations=["public"],
                    services=["ssh"], action=Action.DROP)]  # fmt: skip
    text, report = emit(p)
    assert "rule pair then static-nat prefix 10.1.0.10/32" in text
    assert "policy no-ssh match destination-address server" in text  # what the SRX looks up after static NAT


def test_icmpv6_types_by_name() -> None:
    reader = parse_junos._Reader(parse_junos._lines(b"set applications application p6 protocol icmp6\n"
                                                    b"set applications application p6 icmp6-type echo-request\n"), Report())  # fmt: skip
    reader.applications()
    reader.application("p6")
    assert reader.p.services["p6"].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=128)]
    text, _ = emit(Policy(vendor="test", services=reader.p.services, rules=[Rule(name="r", origin="r", services=["p6"])]))
    assert "set applications application p6 icmp6-type 128" in text


def test_a_static_nat_that_an_earlier_destination_nat_would_lose_to_stays_destination_nat() -> None:
    p = nat_policy()
    forward = NatRule(name="fwd80", origin="fwd80", src_zones=["outside"], destinations=["public"], service="http",
                      destination_translation=DestNat("10.1.0.80"))  # fmt: skip
    inbound = NatRule(name="all", origin="all", src_zones=["outside"], destinations=["public"], destination_translation=DestNat("server"))
    outbound = NatRule(name="all (outbound)", origin="all (outbound)", sources=["server"],
                       source_translation=SourceNat(SnatKind.STATIC, ["public"]))  # fmt: skip
    p.nat_rules = [forward, inbound, outbound]
    text, report = emit(p)
    assert "static-nat" not in text and "rule all then destination-nat pool" in text


def test_hostile_braces_end_in_an_error() -> None:
    with pytest.raises(ParseError, match="two lists"):
        parse("security { policies { from-zone a to-zone b { policy p { match { source-address [ a b ] destination-address [ c d ]; } } } } }\n")
    with pytest.raises(ParseError, match="nested more than 64"):
        parse("security " + "{ x " * 70 + "{ y; }" + " }" * 71 + "\n")
    import time

    long_line = "set security policies from-zone a to-zone b policy p match source-address " + " ".join(f"n{i}" for i in range(20000))
    started = time.monotonic()
    with pytest.raises(ParseError):
        parse("deactivate security policies from-zone a to-zone b policy q\n" + long_line + "\nset system x\n" + "x\n")
    assert time.monotonic() - started < 5


def test_names_that_look_like_addresses_and_books_of_one_name() -> None:
    text = "\n".join([
        "set security zones security-zone dmz interfaces ge-0/0/2.0",
        "set security zones security-zone dmz address-book address web 10.30.0.80/32",
        "set security address-book global address 203.0.113.10 10.99.0.0/16",
        "set security address-book dmz address web 10.20.0.0/24",
        "set security policies from-zone dmz to-zone dmz policy p match source-address 203.0.113.10",
        "set security policies from-zone dmz to-zone dmz policy p match destination-address web",
        "set security policies from-zone dmz to-zone dmz policy p match application any",
        "set security policies from-zone dmz to-zone dmz policy p then permit",
    ]) + "\n"  # fmt: skip
    p, _ = parse(text)
    assert p.rules[0].sources == ["203.0.113.10 (object)"] and p.addresses["203.0.113.10 (object)"].value == "10.99.0.0/16"
    assert p.rules[0].destinations == ["web (zone dmz)"] and p.addresses["web (zone dmz)"].value == "10.30.0.80"


def test_a_rule_for_more_services_than_its_destination_nat_is_for_its_review() -> None:
    p = nat_policy()
    p.nat_rules = [NatRule(name="fwd80", origin="fwd80", src_zones=["outside"], destinations=["public"], service="http",
                           destination_translation=DestNat("server"))]  # fmt: skip
    p.rules = [Rule(name="pub", origin="pub", src_zones=["outside"], dst_zones=["inside"], destinations=["public"])]
    for target in ("junos", "fortios"):
        report = Report()
        cli.convert(copy_policy(p), target, report, Options())
        assert [f.severity for f in report.item("rule", "pub").findings if f.code == "NAT_DESTINATION_WIDENED"] == [Severity.REVIEW], target


def copy_policy(p: Policy) -> Policy:
    import copy

    return copy.deepcopy(p)


def test_details_of_reading() -> None:
    text = "\n".join([
        "{master:0}",
        "set security zones security-zone a interfaces ge-0/0/0.0",
        "set security zones security-zone any interfaces ge-0/0/1.0",
        "set security address-book global address v6 2001:DB8::/32",
        "set security nat source pool p1",
        "set security nat static rule-set s from zone a",
        "set security nat static rule-set s rule r match destination-address 203.0.113.1/32",
        "set security nat static rule-set s rule r then static-nat prefix 10.1.1.2/32",
        "set security nat static rule-set s rule r then static-nat prefix mapped-port 300 to 400",
        "set security policies from-zone a to-zone any policy p match source-address v6",
        "set security policies from-zone a to-zone any policy p match destination-address any",
        "set security policies from-zone a to-zone any policy p match application any",
        "set security policies from-zone a to-zone any policy p then permit",
    ]) + "\n"  # fmt: skip
    p, report = parse(text)
    assert p.addresses["v6"].kind == AddressKind.NETWORK and "PARTS_NOT_READ" not in codes(report)
    assert p.nat_rules[0].destination_translation == DestNat("10.1.1.2", "300-400") and not p.nat_rules[0].unsupported
    assert p.rules[0].unsupported  # the zone named any
    # An export with display inheritance shows what groups give where it applies: read as it is.
    inherited = "\n".join([
        "set groups g security zones security-zone a interfaces ge-0/0/0.0",
        "set apply-groups g",
        "set security zones security-zone a interfaces ge-0/0/0.0",
    ]) + "\n"  # fmt: skip
    assert parse(inherited)[0].zones["a"].interfaces == ["ge-0/0/0.0"]


def test_details_of_writing() -> None:
    p = small(rules=[Rule(name="never", origin="never", src_zones=["inside"], dst_zones=["inside"], scope=RuleScope.INTERZONE),
                     Rule(name="all", origin="all")])  # fmt: skip
    p.addresses["junos+lab"] = Address("junos+lab", AddressKind.NETWORK, "10.8.0.0/16")
    p.rules[1].sources = ["junos+lab"]
    text, report = emit(p)
    assert report.item("rule", "never").skipped and "junos_lab" not in text.replace("xjunos_lab", "")
