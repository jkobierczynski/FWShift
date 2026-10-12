# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""WatchGuard: the configuration file of Policy Manager read and written, and packets through both.

What a Firebox decides by a file is worked out by ``helpers.WatchGuardXml``, which shares no code with fwshift's
parser and emitter. It is written from the same reading of what is known of the format (DEVELOPMENT.md).
"""

from __future__ import annotations

import random
from typing import List, Optional, Tuple

import pytest
from helpers import DATA, WatchGuardXml
from test_iptables import ZONES, Packet, model_allows, model_verdict, random_model, random_packet
from tools.make_watchguard_sample import address_group, alias, interface, policy, profile, service, snat

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, Service, ServiceEntry
from fwshift.model import SnatKind, SourceNat, Zone  # noqa: F401
from fwshift.options import Options
from fwshift.parsers import watchguard as parse_watchguard
from fwshift.report import Report, Severity

KINDS = {"External": "2", "Trusted": "1", "DMZ": "3", "Guests": "1", "Lab": "8"}
NETS = {"External": "10.0.4", "Trusted": "10.0.0", "DMZ": "10.0.2", "Guests": "10.0.1", "Lab": "10.0.3"}


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_watchguard.parse(text.encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


# -- a Firebox made up at random ----------------------------------------------------------------------

GROUPS = [address_group("h17", ("host", "10.0.0.17")), address_group("n1", ("net", "10.0.1.0", "255.255.255.0")),
          address_group("half", ("net", "10.0.1.128", "255.255.255.128")), address_group("span", ("range", "10.0.2.100", "10.0.3.50")),
          address_group("two", ("host", "10.0.3.9"), ("net", "10.0.4.0", "255.255.255.192"))]  # fmt: skip
SERVICES = [service("Any", (0, 0)), service("web", (6, 80)), service("alt", (6, 8000, 8010)), service("dns", (6, 53), (17, 53)),
            service("gre", (47, 0)), service("ping", (1, "icmp", 8, 255))]  # fmt: skip
NAMED = ["Any-Trusted", "Any-External", "Any-Optional", "Any", "A-h17", "A-mix", "A-nested", "A-dmz"]


def base_aliases() -> List[str]:
    return [alias("A-h17", [("tuple", "h17", "Any")]), alias("A-mix", [("tuple", "n1", "Trusted"), ("tuple", "span", "Any")]),
            alias("A-nested", [("ref", "A-h17"), ("tuple", "two", "Guests")]), alias("A-dmz", [("tuple", "Any", "DMZ")])]  # fmt: skip


def random_profile(rng: random.Random) -> str:
    interfaces = [interface(name, kind, f"{NETS[name]}.1", "255.255.255.0") for name, kind in KINDS.items()]
    aliases = base_aliases()
    policies = []
    for index in range(rng.randint(4, 12)):
        name = f"p{index}"
        froms = rng.sample(NAMED, rng.randint(1, 2)) if rng.random() < 0.7 else []
        tos = rng.sample(NAMED, rng.randint(1, 2)) if rng.random() < 0.7 else []
        members_from = [("ref", a) for a in froms] or [("tuple", rng.choice(["Any", "h17", "n1"]), rng.choice(list(KINDS) + ["Any"]))]
        members_to = [("ref", a) for a in tos] or [("tuple", rng.choice(["Any", "span", "two"]), rng.choice(list(KINDS) + ["Any-External"]))]
        aliases += [alias(f"{name}.1.from", members_from, "16"), alias(f"{name}.1.to", members_to, "16")]
        action = rng.choice(["Allow", "Allow", "Proxy", "Deny"])
        policies.append(policy(name, rng.choice(["Any", "web", "alt", "dns", "gre", "ping"]), [f"{name}.1.from"], [f"{name}.1.to"],
                               action, enabled=rng.random() > 0.1))  # fmt: skip
    return profile(interfaces, GROUPS, aliases, SERVICES, [], policies)


def packets(rng: random.Random, count: int) -> List[Packet]:
    out = []
    for _ in range(count):
        pkt = random_packet(rng, 4)
        pkt.in_if, pkt.out_if = rng.sample(list(KINDS), 2)
        pkt.dport = rng.choice([53, 80, 443, 8000, 8005])
        out.append(pkt)
    return out


def test_parsed_configuration_decides_like_the_firebox() -> None:
    """Aliases of aliases, interfaces and their kinds, services of several kinds, the four actions: the model decides as
    the Firebox would, in manual order."""
    allowed = compared = 0
    for seed in range(80):
        rng = random.Random(seed)
        text = random_profile(rng)
        judge = WatchGuardXml(text)
        p, report = parse(text)
        assert "POLICY_ORDER_AUTOMATIC" not in codes(report)
        for pkt in packets(rng, 300):
            expected = judge.allows(pkt)
            compared += 1
            allowed += expected
            assert model_allows(p, pkt) == expected, (seed, pkt, model_verdict(p, pkt), judge.deciding(pkt))
    assert compared // 10 < allowed < compared * 9 // 10, (allowed, compared)


@pytest.mark.parametrize("seed", range(60))
def test_emitted_policies_decide_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {name: Zone(name) for name in ZONES}
    report = Report()
    text = cli.convert(model, "watchguard", report)
    judge = WatchGuardXml(text, {zone: "custom" for zone in ZONES})
    lost = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    for name in lost:
        reasons = {f.code for f in report.item("rule", name).findings if f.severity == Severity.REVIEW}
        assert reasons <= {"SERVICE_NEGATE", "UNCONVERTIBLE_OBJECT", "RULE_TYPE"}, (seed, name, reasons)
    expected = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                      services=model.services, service_groups=model.service_groups,
                      rules=[r for r in model.rules if r.name not in lost])  # fmt: skip
    for index in range(500):
        pkt = random_packet(rng, 6 if index % 4 == 0 else 4)
        pkt.in_if, pkt.out_if = rng.choice(ZONES), rng.choice(ZONES)
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(30))
def test_round_trip_keeps_every_decision(seed: int) -> None:
    rng = random.Random(4000 + seed)
    text = random_profile(rng)
    before = WatchGuardXml(text)
    report = Report()
    written = cli.convert(parse(text)[0], "watchguard", report)
    after = WatchGuardXml(written, {name: before.kinds[name] for name in KINDS})
    for pkt in packets(rng, 300):
        assert after.allows(pkt) == before.allows(pkt), (seed, pkt, written)


# -- reading, by hand ---------------------------------------------------------------------------------

def test_the_sample_is_read_as_saved() -> None:
    report = Report()
    p = parse_watchguard.parse((DATA / "watchguard_sample.xml").read_bytes(), report)
    rules = {r.name: r for r in p.rules}
    assert p.scope == "Fireware 12.10.4" and set(p.zones) == {"External", "Trusted", "DMZ", "Guests", "Lab"}
    assert rules["Block Bad"].action == Action.DENY and rules["Block Bad"].src_zones == ["Trusted", "Guests"]
    assert rules["Block Bad"].destinations == ["Bad-Nets.1.alm", "Bad-Nets.2.alm"]
    assert rules["Admin SSH"].src_zones == ["Trusted"] and rules["Admin SSH"].sources == ["Admins.1.alm"]
    assert rules["Web Out"].src_zones == ["Trusted", "Guests", "DMZ"] and rules["Web Out"].profiles == {"proxy": "HTTP-proxy"}
    assert rules["Web In"].destinations == ["Web-Public.1.snat"] and rules["Web In"].dst_zones == [ANY]
    assert rules["DMZ Updates"].schedule == "Business Hours" and not rules["Guests Out"].enabled
    assert rules["Staff Only"].users == ["Staff"] and rules["Lab Tunnel"].src_zones == ["Lab"]
    assert p.addresses["Update-Site.1.alm updates.example.com"].kind == AddressKind.FQDN
    assert p.address_groups["Firebox"].members == ["198.51.100.2", "10.10.0.1", "10.20.0.1", "10.30.0.1", "10.40.0.1"]
    nats = {n.name: n for n in p.nat_rules}
    web, mail = nats["Web-Public (Web In)"], nats["Mail-Public (Mail In)"]
    assert web.destination_translation == DestNat("Web-Public.2.snat") and web.src_zones == ["External"] and web.sources == [ANY]
    assert mail.destination_translation == DestNat("Mail-Public.2.snat", "2525") and mail.service == "SMTP" and mail.dst_zones == ["External"]
    assert "NAT_NOT_READ" in codes(report) and "WATCHGUARD_FORMAT" in codes(report)


def test_automatic_order_is_said() -> None:
    text = random_profile(random.Random(1)).replace("<auto-order-enabled>0</auto-order-enabled>", "<auto-order-enabled>1</auto-order-enabled>")
    _, report = parse(text)
    assert "orders its policies automatically" in next(n.message for n in report.notes if n.code == "POLICY_ORDER_AUTOMATIC")
    _, report = parse(text.replace("<auto-order-enabled>1</auto-order-enabled>", ""))
    assert "does not say whether" in next(n.message for n in report.notes if n.code == "POLICY_ORDER_AUTOMATIC")


def test_what_cannot_be_read_is_not_any() -> None:
    interfaces = [interface("Trusted", "1"), interface("External", "2")]
    aliases = base_aliases()[:1] + [
        alias("gone.1.from", [("ref", "Nowhere")], "16"), alias("odd.1.from", [("tuple", "Any", "Wlan9")], "16"),
        alias("missing.1.from", [("tuple", "no-group", "Any")], "16"), alias("loop", [("ref", "loop")], "16"),
        alias("to", [("ref", "Any-External")], "16"),
    ]  # fmt: skip
    policies = [policy("gone", "Any", ["gone.1.from"], ["to"]), policy("odd", "Any", ["odd.1.from"], ["to"]),
                policy("missing", "Any", ["missing.1.from"], ["to"]), policy("loop", "Any", ["loop"], ["to"]),
                policy("weird action", "Any", ["A-h17"], ["to"], "Teleport"), policy("no service", "nothing", ["A-h17"], ["to"])]  # fmt: skip
    text = profile(interfaces, GROUPS, aliases, SERVICES, [], policies)
    text = text.replace("<enabled>true</enabled>", "<enabled>maybe</enabled>", 1)
    p, _ = parse(text)
    rules = {r.name: r for r in p.rules}
    assert "alias 'Nowhere' is not in the configuration" in rules["gone"].unsupported
    assert "the configuration does not say whether the policy is enabled" in rules["gone"].unsupported
    assert rules["odd"].unsupported == ["interface 'Wlan9', which is no interface of the configuration"]
    assert rules["missing"].unsupported == ["address 'no-group' is not in the configuration"]
    assert rules["loop"].unsupported == ["aliases nested more than 64 deep, or in a circle"]
    assert rules["weird action"].unsupported == ["action 'teleport', which this parser does not know"]
    assert rules["no service"].unsupported == ["service 'nothing' is not in the configuration"]


def test_what_is_no_configuration_is_refused_with_a_reason() -> None:
    for data, message in ((b"<config/>", "not a configuration of a Firebox"), (b"<profile/>", "holds no <abs-policy-list>"),
                          (b"<profile><abs", "not well-formed")):  # fmt: skip
        with pytest.raises((ParseError, FwshiftError), match=message):
            parse_watchguard.parse(data, Report())
    assert cli.detect_format((DATA / "watchguard_sample.xml").read_bytes()) == "watchguard"
    assert cli.detect_format(b"<?xml version='1.0'?><config/>") == "panos"


def test_broken_files_never_end_in_a_traceback() -> None:
    rng = random.Random(3)
    sample = (DATA / "watchguard_sample.xml").read_text(encoding="utf-8")
    for _ in range(200):
        text = list(sample)
        for _ in range(rng.randint(1, 6)):
            position = rng.randrange(len(text))
            text[position:position + rng.randint(0, 30)] = rng.choice(["", "<", "</alias>", "x", "<type>9</type>", "&amp;"])
        try:
            p = parse_watchguard.parse("".join(text).encode(), Report())
            cli.convert(p, "watchguard", Report())
        except (ParseError, FwshiftError):
            pass


# -- writing, by hand ---------------------------------------------------------------------------------

def model_policy(*rules: Rule) -> Policy:
    p = Policy(vendor="panos")
    for name in ("trust", "untrust", "dmz"):
        p.zones[name] = Zone(name)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32")
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "198.51.100.10/32")
    p.addresses["net"] = Address("net", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["Any"] = Address("Any", AddressKind.NETWORK, "10.99.0.0/16")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["src"] = Service("src", [ServiceEntry(Protocol.TCP, "80", "1024-2000")])
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def emitted(p: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(p, "watchguard", report, options), report


def test_policies_as_policy_manager_has_them() -> None:
    p = model_policy(
        Rule("out", src_zones=["trust"], dst_zones=["untrust"], sources=["net"]),
        Rule("not net", src_zones=["trust", "dmz"], dst_zones=["untrust"], sources=["net"], negate_source=True, action=Action.DROP),
        Rule("ports", src_zones=["trust"], dst_zones=["untrust"], services=["src"]),
        Rule("named any", src_zones=["trust"], dst_zones=["untrust"], destinations=["Any"]),
    )
    text, report = emitted(p)
    judge = WatchGuardXml(text, {"trust": "custom", "untrust": "custom", "dmz": "custom"})
    assert judge.allows(Packet("trust", "untrust", "10.10.0.5", "203.0.113.5", "tcp", 1024, 80))
    assert not judge.allows(Packet("dmz", "untrust", "10.20.0.5", "203.0.113.5", "tcp", 1024, 80))
    assert not judge.allows(Packet("trust", "untrust", "10.11.0.5", "10.99.0.1", "tcp", 1024, 80))
    assert report.item("rule", "ports").disabled and "<auto-order-enabled>0</auto-order-enabled>" in text
    assert "renamed to 'Any_2'" in report.item("address", "Any").findings[0].message or "RENAMED" in codes(report, "address", "Any")
    assert "WATCHGUARD_LOAD" in codes(report) and "INTERFACES_REQUIRED" in codes(report)
    assert "<firewall>Deny</firewall>" in text and "<firewall>2</firewall>" in text


def test_static_nat_is_an_action_of_the_policy() -> None:
    p = model_policy(Rule("web in", src_zones=["untrust"], dst_zones=["dmz"], destinations=["pub"], services=["https"]),
                     Rule("web all", src_zones=["dmz"], dst_zones=["dmz"], destinations=["pub"]))  # fmt: skip
    p.nat_rules = [
        NatRule("publish", origin="publish", src_zones=["untrust"], dst_zones=["untrust"], destinations=["pub"], service="https",
                destination_translation=DestNat("web", "8443")),
        NatRule("unused", origin="unused", src_zones=["untrust"], destinations=["net"], destination_translation=DestNat("web")),
        NatRule("hide", origin="hide", dst_zones=["untrust"], sources=["net"], source_translation=SourceNat(SnatKind.INTERFACE)),
    ]  # fmt: skip
    text, report = emitted(p)
    judge = WatchGuardXml(text, {"trust": "custom", "untrust": "custom", "dmz": "custom"})
    pkt = Packet("untrust", "dmz", "203.0.113.5", "198.51.100.10", "tcp", 1024, 443)
    assert judge.allows(pkt) and judge.translation(pkt) == ("10.20.0.10", "8443")
    assert report.item("nat", "publish").emitted_as and "NAT_NOT_IN_POLICY" in codes(report, "rule", "web all")
    assert report.item("nat", "unused").skipped and report.item("nat", "hide").skipped
    assert "dynamic NAT" in report.item("nat", "hide").findings[0].message


def test_every_sample_converts() -> None:
    for name in ("panos_sample.xml", "fortios_sample.conf", "checkpoint_sample.json", "asa_sample.cfg", "sophos_sample.xml",
                 "fmc_sample.json", "fdm_sample.txt", "iptables_sample.rules", "pfsense_sample.xml", "sonicwall_sample.exp",
                 "watchguard_sample.xml"):  # fmt: skip
        data = (DATA / name).read_bytes()
        report = Report()
        text = cli.convert(cli.load(data, cli.detect_format(data), report), "watchguard", report)
        WatchGuardXml(text)


# -- what the review of version 0.10.0 found ---------------------------------------------------------------


def nat_model(nat: NatRule, rule: Rule) -> Policy:
    p = model_policy(rule)
    p.nat_rules = [nat]
    return p


def test_a_static_nat_action_goes_only_where_the_nat_rule_applies() -> None:
    rule = Rule("in", src_zones=["untrust"], dst_zones=[ANY], destinations=["pub"], services=["https"])
    cases = (
        NatRule("partners", origin="partners", src_zones=["untrust"], sources=["net"], destinations=["pub"], destination_translation=DestNat("web")),
        NatRule("off", origin="off", src_zones=["untrust"], destinations=["pub"], destination_translation=DestNat("web"), enabled=False),
    )  # fmt: skip
    for nat in cases:
        text, report = emitted(nat_model(nat, copy_rule(rule)))
        assert "NAT_NOT_IN_POLICY" in codes(report, "rule", "in") and report.item("nat", nat.origin).skipped, nat.name
        judge = WatchGuardXml(text, {"trust": "custom", "untrust": "custom", "dmz": "custom"})
        assert judge.translation(Packet("untrust", "dmz", "192.0.2.7", "198.51.100.10", "tcp", 1024, 443)) == ("Original", "Original")
    nat = NatRule("ok", origin="ok", src_zones=["untrust"], destinations=["pub"], destination_translation=DestNat("web"))
    _, report = emitted(nat_model(nat, Rule("in", origin="in", src_zones=["untrust"], dst_zones=["dmz"], destinations=["pub"])))
    assert "NAT_ZONE_DROPPED" in codes(report, "rule", "in")


def copy_rule(rule: Rule) -> Rule:
    import copy

    return copy.deepcopy(rule)


def test_the_translation_of_a_policy_is_for_what_that_policy_matches() -> None:
    interfaces = [interface("External", "2"), interface("Trusted", "1"), interface("DMZ", "3")]
    groups = [address_group("partner", ("net", "203.0.113.0", "255.255.255.0")), address_group("P.1.snat", ("host", "198.51.100.10")),
              address_group("P.2.snat", ("host", "10.20.0.10"))]  # fmt: skip
    aliases = [alias("P.snat", [("tuple", "P.1.snat", "Any-External")], "32"), alias("from", [("tuple", "partner", "External")], "16"),
               alias("to", [("ref", "P.snat")], "16"), alias("ext", [("ref", "Any-External")], "16"), alias("opt", [("ref", "Any-Optional")], "16"),
               alias("bob", [("tuple", "Any", "Any", "bob")], "16")]  # fmt: skip
    policies = [policy("A", "HTTPS", ["from"], ["to"]), policy("B", "HTTPS", ["ext"], ["opt"]), policy("C", "HTTPS", ["opt"], ["bob"]),
                policy("D", "HTTPS", ["ext"], ["P.snat"])]  # fmt: skip
    p, _ = parse(profile(interfaces, groups, aliases, [service("HTTPS", (6, 443))], [snat("P", "P.1.snat", "P.2.snat")], policies))
    nats = {n.name: n for n in p.nat_rules}
    assert nats["P (A)"].sources == ["partner"] and nats["P (A)"].src_zones == ["External"]
    assert nats["P (D)"].sources == [ANY] and {r.name: r for r in p.rules}["D"].destinations == ["P.1.snat"]
    assert {r.name: r for r in p.rules}["C"].unsupported == ["user 'bob' in the To list"]


def test_aliases_that_multiply_and_interfaces_of_no_known_type() -> None:
    aliases = [alias("L0", [("tuple", "h17", "Any")])]
    for level in range(1, 12):
        aliases.append(alias(f"L{level}", [("ref", f"L{level - 1}")] * 10))
    aliases += [alias("x.from", [("ref", "L11")], "16"), alias("x.to", [("ref", "Any")], "16")]
    text = profile([interface("Trusted", "1")], GROUPS, aliases, SERVICES, [], [policy("x", "Any", ["x.from"], ["x.to"])])
    p, _ = parse(text)
    assert p.rules[0].sources == ["h17"]
    untyped = interface("Trusted", "1").replace("<if-property>1</if-property>", "")
    text = profile([untyped, interface("External", "2")], GROUPS, [alias("t.from", [("ref", "Any-Trusted")], "16"),
                   alias("t.to", [("ref", "Any-External")], "16")], SERVICES, [], [policy("t", "Any", ["t.from"], ["t.to"], "Deny")])  # fmt: skip
    p, _ = parse(text)
    assert "the configuration does not say of what type Trusted is" in p.rules[0].unsupported[0]


def test_the_order_and_what_disagrees() -> None:
    text = random_profile(random.Random(2)).replace(
        "<system-parameters>", "<policy-view><ui-pm><auto-order-enabled>0</auto-order-enabled></ui-pm></policy-view><system-parameters>"
    ).replace("<auto-order-enabled>0</auto-order-enabled></misc-global-setting>", "<auto-order-enabled>1</auto-order-enabled></misc-global-setting>")
    _, report = parse(text)
    assert "POLICY_ORDER_AUTOMATIC" in codes(report)
    text = random_profile(random.Random(2)).replace("<firewall>1</firewall><enable>1</enable>", "<firewall>2</firewall><enable>1</enable>", 1)
    p, _ = parse(text)
    assert any("say different things" in u for r in p.rules for u in r.unsupported)
    with pytest.raises(ParseError, match="defined twice"):
        parse(random_profile(random.Random(2)).replace("</alias-list>", alias("A-h17", [("tuple", "h17", "Any")]) + "</alias-list>"))


def test_the_firebox_itself_and_services_fireware_cannot_name() -> None:
    interfaces = [interface("Trusted", "1")]
    text = profile(interfaces, GROUPS, [alias("f.from", [("ref", "Any-Trusted")], "16"), alias("f.to", [("ref", "Firebox")], "16")],
                   SERVICES, [], [policy("to the firebox", "Any", ["f.from"], ["f.to"], "Deny")])  # fmt: skip
    p, _ = parse(text)
    assert p.rules[0].destinations == ["Firebox"] and not p.rules[0].unsupported
    out = cli.convert(p, "watchguard", Report())
    assert "<alias-name>Firebox</alias-name>" in out
    model = model_policy(Rule("zero", src_zones=["trust"], dst_zones=["untrust"], services=["zero"]))
    model.services["zero"] = Service("zero", [ServiceEntry(Protocol.TCP, "0")])
    _, report = emitted(model)
    assert report.item("rule", "zero").disabled and "port 0 and no other" in report.item("service", "zero").findings[0].message


def test_what_the_converter_disabled_carries_its_name_in_the_file() -> None:
    """Section 10 of the manual: search the result for FWSHIFT to find placeholders and disabled policies."""
    p = Policy(vendor="test")
    p.zones = {"Trusted": Zone("Trusted", ["Trusted"]), "External": Zone("External", ["External"])}
    p.addresses["odd"] = Address("odd", AddressKind.UNSUPPORTED, "", raw="a wildcard mask")
    p.rules = [Rule(name="uses odd", origin="uses odd", action=Action.ALLOW, src_zones=["Trusted"], dst_zones=["External"],
                    sources=["odd"], destinations=[ANY], services=[ANY], description="keep this"),
               Rule(name="fine", origin="fine", action=Action.ALLOW, src_zones=["Trusted"], dst_zones=["External"],
                    sources=[ANY], destinations=[ANY], services=[ANY], description="as it was")]  # fmt: skip
    from fwshift.emitters import watchguard as emit_watchguard

    out = emit_watchguard.emit(p, Report(), Options())
    assert "<description>FWSHIFT PLACEHOLDER, matches nothing: a wildcard mask</description>" in out
    assert "<description>FWSHIFT inactive, see the report. keep this</description>" in out
    assert "<description>as it was</description>" in out and out.count("FWSHIFT inactive") == 1
