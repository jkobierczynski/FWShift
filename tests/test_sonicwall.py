# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""SonicWall: the settings export read, the commands of the command line written, and packets through both.

What a firewall decides by an export is worked out by ``helpers.SonicWallExp``, and by emitted commands by
``helpers.SonicWallCli``: both share no code with fwshift's parser and emitter. They are written from the same
reading of what SonicWall publishes, which DEVELOPMENT.md lists.
"""

from __future__ import annotations

import base64
import ipaddress
import random
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA, SonicWallCli, SonicWallExp
from test_iptables import ZONES, Packet, model_allows, model_verdict, random_model, random_packet
from tools.make_sonicwall_sample import address, encode, iface, nat, rule, service, table, zone

from fwshift import cli, transform
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, ANY_V4, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol, Rule
from fwshift.model import RuleScope, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import sonicwall as parse_sonicwall
from fwshift.report import Report, Severity

Pairs = List[Tuple[str, str]]


def parse(pairs: Pairs, **options: object) -> Tuple[Policy, Report]:
    report = Report()
    return parse_sonicwall.parse(encode(pairs), report, **options), report  # type: ignore[arg-type]


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


# -- a SonicWall made up at random ------------------------------------------------------------------

ZONE_TYPES = {"LAN": "1", "WAN": "0", "DMZ": "2", "Lab": "1", "Guests": "4"}
NETWORKS = {"LAN": "10.0.0", "WAN": "10.0.4", "DMZ": "10.0.2", "Lab": "10.0.3", "Guests": "10.0.1"}


def base(rng: Optional[random.Random] = None) -> Pairs:
    pairs: Pairs = [("buildNum", "7.1.2-7019")]
    pairs += table([zone(name, kind) for name, kind in ZONE_TYPES.items()])
    pairs += table([iface(str(n), f"X{n}", name, f"{prefix}.1", "255.255.255.0") for n, (name, prefix) in enumerate(NETWORKS.items())])
    pairs += table([
        address("h17", "1", "LAN", "10.0.0.17", "255.255.255.255"),
        address("n1", "4", "Guests", "10.0.1.0", "255.255.255.0"),
        address("half", "4", "Guests", "10.0.1.128", "255.255.255.128"),
        address("span", "2", "DMZ", "10.0.2.100", "10.0.3.50"),
        address("n3", "4", "Lab", "10.0.3.0", "255.255.255.0"),
        address("g", "8", "LAN", "0.0.0.0", "0.0.0.0"),
        address("nested", "8", "LAN", "0.0.0.0", "0.0.0.0"),
    ])  # fmt: skip
    for index, (member, group) in enumerate([("h17", "g"), ("span", "g"), ("g", "nested"), ("n3", "nested")]):
        pairs += [(f"addro_atomToGrp_{index}", member), (f"addro_grpToGrp_{index}", group)]
    pairs += table([service("web", "6", "80", "80"), service("alt", "6", "8000", "8010"), service("dns", "17", "53", "53"),
                    service("gre", "47", "0", "0"),
                    {"svcObjId": "mix", "svcObjType": "2", "svcObjIpType": "0", "svcObjPort1": "0", "svcObjPort2": "0"}])  # fmt: skip
    for index, (member, group) in enumerate([("web", "mix"), ("dns", "mix"), ("gre", "mix")]):
        pairs += [(f"so_atomToGrp_{index}", member), (f"so_grpToGrp_{index}", group)]
    return pairs


def random_export(rng: random.Random, priorities: bool = False) -> bytes:
    pairs = base(rng)
    zones = list(ZONE_TYPES)
    objects = ["", "", "h17", "n1", "half", "span", "n3", "g", "nested"]
    services = ["", "", "web", "alt", "dns", "gre", "mix"]
    rows = []
    for _ in range(rng.randint(5, 18)):
        src, dst = rng.sample(zones, 2) if rng.random() < 0.85 else (rng.choice(zones),) * 2
        rows.append(rule(rng.choice(["2", "2", "1", "0"]), src, dst, rng.choice(objects), rng.choice(objects), rng.choice(services),
                         enabled="0" if rng.random() < 0.1 else "1"))  # fmt: skip
    if rng.random() < 0.5:
        rows.append(rule(rng.choice(["2", "0"]), "WAN", "LAN", default="1"))
    if priorities:
        counters: Dict[Tuple[str, str], int] = {}
        order = list(range(len(rows)))
        rng.shuffle(order)
        for index in order:
            key = (rows[index]["policySrcZone"], rows[index]["policyDstZone"])
            counters[key] = counters.get(key, 0) + 1
            rows[index]["policyPriority"] = str(counters[key])
    pairs += table(rows)
    return encode(pairs)


def packets(rng: random.Random, count: int, zones: List[str]) -> List[Packet]:
    out = []
    for _ in range(count):
        pkt = random_packet(rng, 4)
        pkt.in_if, pkt.out_if = rng.sample(zones, 2)
        pkt.dport = rng.choice([53, 80, 443, 8000, 8005, 9000])
        out.append(pkt)
    return out


@pytest.mark.parametrize("priorities", [False, True])
def test_parsed_export_decides_like_the_firewall(priorities: bool) -> None:
    """Rules per pair of zones, first match, objects, nested groups, services of several kinds, default rows and
    the defaults of SonicOS where an export has none: the model decides as the firewall would."""
    allowed = compared = 0
    for seed in range(60):
        rng = random.Random(seed + (1000 if priorities else 0))
        data = random_export(rng, priorities)
        judge = SonicWallExp(data)
        report = Report()
        p = parse_sonicwall.parse(data, report)
        for pkt in packets(rng, 300, list(ZONE_TYPES)):
            expected = judge.allows(pkt)
            compared += 1
            allowed += expected
            assert model_allows(p, pkt) == expected, (seed, pkt, model_verdict(p, pkt), judge.deciding(pkt))
    assert compared // 5 < allowed < compared * 4 // 5, (allowed, compared)


# -- the model written for SonicOS ---------------------------------------------------------------------

TARGET_TYPES = {"eth0": "trusted", "eth1": "untrusted", "eth2": "public"}


@pytest.mark.parametrize("seed", range(60))
def test_emitted_rules_decide_like_the_model(seed: int) -> None:
    """Lists, negations, rule types and both IP versions on a firewall whose own defaults allow some pairs: the
    commands decide as the model. What SonicOS cannot say is written disabled, for a reason the report gives."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {name: Zone(name) for name in ZONES}
    report = Report()
    text = cli.convert(model, "sonicwall", report)
    judge = SonicWallCli(text, TARGET_TYPES)
    lost = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    for name in lost:
        reasons = {f.code for f in report.item("rule", name).findings if f.severity == Severity.REVIEW}
        assert reasons <= {"SERVICE_NEGATE", "UNCONVERTIBLE_OBJECT"}, (seed, name, reasons)
    expected = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                      services=model.services, service_groups=model.service_groups,
                      rules=[r for r in model.rules if r.name not in lost])  # fmt: skip
    for index in range(500):
        pkt = random_packet(rng, 6 if index % 4 == 0 else 4)
        pkt.in_if, pkt.out_if = rng.choice(ZONES), rng.choice(ZONES)
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, pkt, judge.deciding(pkt, pkt.in_if, pkt.out_if), text)


@pytest.mark.parametrize("seed", range(30))
def test_round_trip_keeps_every_decision(seed: int) -> None:
    rng = random.Random(5000 + seed)
    data = random_export(rng, seed % 2 == 1)
    before = SonicWallExp(data)
    report = Report()
    text = cli.convert(parse_sonicwall.parse(data, report), "sonicwall", report)
    after = SonicWallCli(text, {name: before.zone_type(name) for name in ZONE_TYPES})
    lost = [item.name for item in report.items.values() if item.kind == "rule" and item.disabled]
    for pkt in packets(rng, 300, list(ZONE_TYPES)):
        decided = before.deciding(pkt)
        if decided is not None and before.column("policyDstSvc").get(decided, "") in ("gre", "mix"):
            continue  # GRE is nothing FWShift writes for SonicOS: such a rule is disabled, as the report says
        assert after.allows(pkt) == before.allows(pkt), (seed, pkt, decided, lost, text)


# -- NAT ------------------------------------------------------------------------------------------------

def nat_model(rng: random.Random) -> Policy:
    p = random_model(rng)
    p.rules = []
    p.zones = {name: Zone(name, [name]) for name in ZONES}
    p.services["one"] = Service("one", [ServiceEntry(Protocol.TCP, "8080")])
    four = ["net0", "net1", "net2", "net3", "net4", "half", "span", "host", "10.0.3.0/24", "10.0.0.34"]
    for index in range(rng.randint(4, 9)):
        rule_ = NatRule(f"n{index}", origin=f"n{index}")
        rule_.src_zones = [ANY] if rng.random() < 0.4 else [rng.choice(ZONES)]
        rule_.sources = [ANY] if rng.random() < 0.4 else [rng.choice(four)]
        rule_.destinations = [ANY] if rng.random() < 0.4 else [rng.choice(four)]
        rule_.service = rng.choice([ANY, ANY, "web", "one"])
        shape = rng.choice(["masq", "host", "dnat", "dnat-port", "none"])
        if shape in ("masq", "host", "none"):
            rule_.dst_zones = [rng.choice(ZONES)]
        if shape == "masq":
            rule_.source_translation = SourceNat(SnatKind.INTERFACE)
        elif shape == "host":
            rule_.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [rng.choice(["host", "192.0.2.77"])])
        elif shape.startswith("dnat"):
            rule_.dst_zones = [ANY]
            rule_.destination_translation = DestNat(rng.choice(["host", "10.0.4.9"]), "8443" if shape == "dnat-port" else "")
        rule_.enabled = rng.random() > 0.1
        p.nat_rules.append(rule_)
    return p


def model_translation(p: Policy, pkt: Packet, skipped: List[str]) -> Tuple[str, str, str]:
    from test_iptables import _entry_matches, _member_matches

    for rule_ in p.nat_rules:
        if not rule_.enabled or rule_.origin in skipped:
            continue
        if ANY not in rule_.src_zones and pkt.in_if not in rule_.src_zones:
            continue
        if rule_.destination_translation is None and ANY not in rule_.dst_zones and pkt.out_if not in rule_.dst_zones:
            continue
        if not any(_member_matches(p, m, pkt.src) for m in rule_.sources) or not any(_member_matches(p, m, pkt.dst) for m in rule_.destinations):
            continue
        if rule_.service != ANY and not any(_entry_matches(e, pkt) for e in transform.flatten_services(p, rule_.service) or []):
            continue
        source = destination = port = "Original"
        if rule_.source_translation is not None:
            if rule_.source_translation.kind == SnatKind.INTERFACE:
                source = IFACE_IP[pkt.out_if]
            else:
                source = str(ipaddress.ip_address((transform.address_intervals(p, rule_.source_translation.addresses[0]) or [])[0][1]))
        if rule_.destination_translation is not None:
            destination = str(ipaddress.ip_address((transform.address_intervals(p, rule_.destination_translation.address) or [])[0][1]))
            port = rule_.destination_translation.port or "Original"
            if port == str(pkt.dport):
                port = "Original"
        return source, destination, port
    return "Original", "Original", "Original"


IFACE_IP = {"eth0": "192.0.2.1", "eth1": "198.51.100.1", "eth2": "203.0.113.1"}
IFACE_MAP = {"eth0": "X0", "eth1": "X1", "eth2": "X2"}


@pytest.mark.parametrize("seed", range(40))
def test_emitted_nat_translates_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = nat_model(rng)
    report = Report()
    text = cli.convert(model, "sonicwall", report, Options(interface_map=IFACE_MAP))
    builtin = {f"{IFACE_MAP[zone]} IP": [(4, int(ipaddress.ip_address(ip)), int(ipaddress.ip_address(ip)))] for zone, ip in IFACE_IP.items()}
    judge = SonicWallCli(text, TARGET_TYPES, {x: z for z, x in IFACE_MAP.items()}, builtin)
    skipped = [item.name for item in report.items.values() if item.kind == "nat" and item.skipped]
    for name in skipped:
        message = report.item("nat", name).findings[0].message
        assert "translation to port" in message, (seed, name, message)
    for _ in range(400):
        pkt = random_packet(rng, 4)
        pkt.in_if, pkt.out_if = rng.choice(ZONES), rng.choice(ZONES)
        pkt.dport = rng.choice([53, 80, 443, 8080])
        assert judge.translation(pkt) == model_translation(model, pkt, skipped), (seed, pkt, text)


# -- reading, by hand -----------------------------------------------------------------------------------

def test_the_sample_is_read_as_exported() -> None:
    report = Report()
    p = parse_sonicwall.parse((DATA / "sonicwall_sample.exp").read_bytes(), report)
    rules = {r.name: r for r in p.rules}
    assert p.scope == "SonicOS 7.1.2-7019" and p.zones["LAN"].interfaces == ["X0"] and p.zones["WAN"].interfaces == ["X1", "X4"]
    assert rules["LAN to WAN #1"].action == Action.DENY and rules["LAN to WAN #1"].destinations == ["Bad Networks"]
    assert rules["Admins out by SSH"].sources == ["Admin PCs"] and p.services["SSH"].builtin == "sonicwall"
    assert not rules["LAN to WAN #4"].enabled and rules["Administrators to the DMZ"].users == ["Admins"]
    assert rules["Updates in working hours"].schedule == "Work Hours" and rules["IPv6 out"].sources == ["::/0"]
    assert p.address_groups["Partners"].members == ["Partner Net", "Bad Networks"]
    assert p.addresses["X0 Subnet"].value == "10.10.0.0/16" and p.addresses["X0 Subnet"].builtin == "sonicwall"
    assert p.services["Echo Object"].unsupported.startswith("ICMP type and code")
    # Pairs of zones the export holds no default rule for: what SonicOS does for their security types.
    assert [r.name for r in p.rules if r.name.startswith("default ")] == [
        "default LAN to DMZ", "default DMZ to WAN", "default Servers to WAN", "default Servers to DMZ"]  # fmt: skip
    assert codes(report, "rule", "default LAN to DMZ") == ["DEFAULT_RULE_ASSUMED"] and "ZONE_TYPE_ASSUMED" in codes(report)
    nats = {n.name: n for n in p.nat_rules}
    default = nats["Default NAT"].source_translation
    assert default is not None and default.kind == SnatKind.INTERFACE and default.interface == "X1" and default.interface_address == "198.51.100.2"
    assert nats["Web server"].destination_translation == DestNat("Web Server") and nats["Web server"].src_zones == ["WAN"]
    assert nats["Web server"].dst_zones == ["WAN"]  # where the original address is: in the network of X1
    assert nats["Mail on another port"].destination_translation == DestNat("Mail Server", "25")
    one = nats["Servers one to one"].source_translation
    assert one is not None and one.kind == SnatKind.STATIC and one.addresses == ["Server Public"]
    mirror = nats["Servers one to one (reflexive)"]
    assert mirror.destinations == ["Server Public"] and mirror.destination_translation == DestNat("Server Range")
    assert mirror.src_zones == ["WAN"] and codes(report, "nat", mirror.name)[-1] == "NAT_REFLEXIVE"
    assert not nats["Old admin NAT"].enabled and "NAT_INTERFACE" in codes(report, "nat", "Web server")


def test_what_a_rule_says_beyond_the_model() -> None:
    pairs = base() + table([
        rule("2", "LAN", "WAN", svc="web", name="source port") | {"policySrcSvc": "dns"},
        rule("7", "LAN", "WAN", name="odd action"),
        rule("2", "LAN", "WAN", name="geo") | {"policyGeoIpBlock": "1"},
    ])  # fmt: skip
    p, report = parse(pairs)
    rules = {r.name: r for r in p.rules}
    assert rules["source port"].unsupported == ["source port service 'dns'"]
    assert rules["odd action"].unsupported == ["action code '7', which this parser does not know"]
    assert rules["geo"].profiles == {"GeoIpBlock": "1"}


def test_objects_that_cannot_be_read() -> None:
    pairs = base() + table([address("odd", "16", "LAN", "1.2.3.4", "0"), address("bad", "1", "LAN", "nonsense", "255.255.255.255"),
                            address("empty", "8", "LAN", "0.0.0.0", "0.0.0.0")], start=50)  # fmt: skip
    pairs += table([service("broken", "6", "90", "80"), service("weird", "x", "0", "0"), service("echo", "1", "0", "0")], start=50)
    p, _ = parse(pairs)
    assert p.addresses["odd"].kind == AddressKind.UNSUPPORTED and "type 16" in p.addresses["odd"].raw
    assert p.addresses["bad"].kind == AddressKind.UNSUPPORTED and p.address_groups["empty"].unsupported == "a group without members"
    assert p.services["broken"].unsupported == "a port range 90-80 that is not one" and "IP type 'x'" in p.services["weird"].unsupported
    assert "'every type'" in p.services["echo"].unsupported


def test_objects_sonicos_has_by_itself() -> None:
    pairs = base() + table([iface("9", "X9", "WAN")], start=9) + table([
        rule("2", "LAN", "WAN", src="LAN Subnets", dst="X9 IP"),
        rule("2", "DMZ", "WAN", src="Firewalled Subnets", dst="All X1 Management IP"),
        rule("2", "Lab", "WAN", src="X3 Default Gateway", dst="Unknown Object", svc="HTTPS"),
    ])  # fmt: skip
    p, report = parse(pairs)
    assert p.address_groups["LAN Subnets"].members == ["10.0.0.0/24"]
    assert p.addresses["X9 IP"].kind == AddressKind.UNSUPPORTED and "--interface-address" in p.addresses["X9 IP"].raw
    assert p.address_groups["Firewalled Subnets"].members == ["10.0.0.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.1.0/24"]
    assert p.addresses["All X1 Management IP"].value == "10.0.4.1"
    assert p.addresses["X3 Default Gateway"].kind == AddressKind.UNSUPPORTED and "Unknown Object" not in p.addresses
    assert codes(report, "address", "X9 IP") == ["DEFAULT_OBJECT"] and p.services["HTTPS"].builtin == "sonicwall"
    p, _ = parse(pairs, interface_addresses=["x9=198.51.100.9/24"])
    assert p.addresses["X9 IP"].value == "198.51.100.9"
    for bad, message in (("X9", "is not INTERFACE=ADDRESS/BITS"), ("X7=10.0.0.1/24", "no interface 'X7' in the export"),
                         ("X9=2001:db8::1/64", "takes IPv4 addresses")):  # fmt: skip
        with pytest.raises(FwshiftError, match=message):
            parse(pairs, interface_addresses=[bad])
    with pytest.raises(FwshiftError, match="two IPv4 addresses"):
        parse(pairs, interface_addresses=["X9=198.51.100.9/24", "x9=198.51.100.8/24"])


def test_default_rules_of_unknown_security_types_are_said() -> None:
    pairs = [("buildNum", "6.5.4.15")] + table([zone("LAN", "1"), zone("Branch", "5")]) + table([
        iface("0", "X0", "LAN", "10.0.0.1", "255.255.255.0"), iface("1", "X1", "Branch", "10.9.0.1", "255.255.255.0")])  # fmt: skip
    pairs += table([rule("2", "LAN", "Branch", src="")], start=0)
    p, report = parse(pairs)
    assert [r.name for r in p.rules] == ["LAN to Branch #1"]
    assert "DEFAULT_RULES_UNKNOWN" in codes(report) and "Branch" in next(n.message for n in report.notes if n.code == "DEFAULT_RULES_UNKNOWN")


def test_nat_policies_as_they_are_read() -> None:
    pairs = base() + table([
        nat(orig_src="n1", trans_src="X1 IP", outbound="1", comment="hide"),
        nat(orig_src="n1", trans_src="h17", outbound="99", comment="unknown interface"),
        nat(orig_dst="h17", trans_dst="span", comment="to many"),
        nat(orig_svc="web", trans_svc="alt", comment="port only"),
        nat(orig_dst="h17", trans_dst="n3", orig_svc="web", trans_svc="mix", comment="odd port"),
        nat(orig_src="half", trans_src="n1", outbound="1", comment="to a bigger network"),
    ])  # fmt: skip
    p, report = parse(pairs)
    nats = {n.name: n for n in p.nat_rules}
    hide = nats["hide"].source_translation
    assert hide is not None and hide.kind == SnatKind.INTERFACE and hide.interface_address == "10.0.4.1"
    assert codes(report, "nat", "unknown interface") == ["NAT_INTERFACE"] and nats["unknown interface"].dst_zones == [ANY]
    to_many = nats["to many"].destination_translation
    assert to_many is not None and to_many.spread
    assert nats["port only"].unsupported == ["translated service 'alt' without a translated destination"]
    assert nats["odd port"].unsupported == ["translated service 'mix' that is not one TCP or UDP port"]
    bigger = nats["to a bigger network"].source_translation
    assert bigger is not None and bigger.kind == SnatKind.DYNAMIC_PORT


def test_what_is_no_export_is_refused_with_a_reason() -> None:
    for data, message in (
        (b"", "the file is empty"),
        (b"%%%% not base64", "neither Base64 nor key=value pairs"),
        (base64.b64encode(b"hello world"), "does not start with the keys of one"),
        (b"policyAction_0=2&policyAction_0=1", "twice, with two values"),
        (b"policyAction_0=2&garbage", "is no key=value pair"),
    ):  # fmt: skip
        with pytest.raises(ParseError, match=message):
            parse_sonicwall.parse(data, Report())
    p = parse_sonicwall.parse(b"buildNum=7.0.1&policyAction_0=2&policySrcZone_0=LAN&policyDstZone_0=WAN\n", Report())
    assert p.rules[0].sources == [ANY_V4] and p.zones["LAN"].name == "LAN"


def test_the_format_is_detected() -> None:
    assert cli.detect_format((DATA / "sonicwall_sample.exp").read_bytes()) == "sonicwall"
    assert cli.detect_format(b"buildNum=7.0.1&shortProdName=TZ&policyAction_0=2") == "sonicwall"
    assert cli.detect_format(b"#config-version=FGT\nconfig system global\nend\n") == "fortios"
    assert cli.detect_format(b"QUJDREVGR0g=") != "sonicwall"


def test_broken_exports_never_end_in_a_traceback() -> None:
    rng = random.Random(7)
    sample = base64.b64decode((DATA / "sonicwall_sample.exp").read_bytes().strip())
    for _ in range(300):
        data = bytearray(sample)
        for _ in range(rng.randint(1, 8)):
            position = rng.randrange(len(data))
            data[position:position + rng.randint(0, 20)] = bytes(rng.randrange(32, 127) for _ in range(rng.randint(0, 20)))
        try:
            p = parse_sonicwall.parse(base64.b64encode(bytes(data)), Report())
            cli.convert(p, "sonicwall", Report())
        except (ParseError, FwshiftError):
            pass


# -- writing, by hand -----------------------------------------------------------------------------------

def policy(*rules: Rule) -> Policy:
    p = Policy(vendor="panos")
    for name in ("trust", "untrust", "dmz"):
        p.zones[name] = Zone(name)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32")
    p.addresses["net"] = Address("net", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8:1::/64")
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.addresses["X1 IP"] = Address("X1 IP", AddressKind.NETWORK, "198.51.100.2/32")
    p.address_groups["both"] = AddressGroup("both", ["net", "six"])
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["HTTP"] = Service("HTTP", [ServiceEntry(Protocol.TCP, "80,8080")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    for item in rules:
        item.origin = item.origin or item.name
        p.rules.append(item)
    return p


def emitted(p: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(p, "sonicwall", report, options), report


def test_rules_as_sonicos_has_them() -> None:
    text, report = emitted(policy(
        Rule("web in", src_zones=["untrust"], dst_zones=["dmz"], destinations=["web"], services=["https", "HTTP"]),
        Rule("out", src_zones=["trust"], dst_zones=["untrust", "dmz"], sources=["both"]),
        Rule("not net", src_zones=["trust"], dst_zones=["untrust"], sources=["net"], negate_source=True, action=Action.DROP),
        Rule("ping", src_zones=["dmz"], dst_zones=["trust"], services=["ping"]),
        Rule("gre", src_zones=["dmz"], dst_zones=["trust"], services=["gre"]),
    ))  # fmt: skip
    lines = text.splitlines()
    assert lines[0] == "configure terminal" and lines[-2:] == ["commit", "exit"]
    assert 'address-object ipv4 "web" host 10.20.0.10 zone dmz' in lines and 'address-object ipv6 "six" network 2001:db8:1:: /64 zone trust' in lines
    assert 'address-object ipv4 "X1 IP 2" host 198.51.100.2 zone trust' not in lines  # not created: the name of an object of SonicOS
    assert "renamed to 'X1 IP 2'" in report.item("address", "X1 IP").findings[0].message
    assert 'service-object "HTTP 2 tcp 80" TCP 80 80' in lines and 'service-group "HTTP 2"' in lines
    assert ('access-rule ipv4 from untrust to dmz action allow source address any service group "svc web in" destination address name "web"'
            in lines)  # fmt: skip
    assert codes(report, "rule", "out") == ["RULE_SPLIT"] and report.item("rule", "out").emitted_as == ["out", "out 2", "out 3", "out 4"]
    assert 'access-rule ipv6 from trust to untrust action allow source address group "both v6" service any destination address any' in lines
    assert any(line.startswith("access-rule ipv4 from trust to untrust action discard source address group \"src not net\"") for line in lines)
    assert 'access-rule ipv4 from dmz to trust action allow source address any service name "Ping" destination address any' in lines
    gre = report.item("rule", "gre")
    assert gre.disabled and "no enable" in text.split('name "gre"')[1].splitlines()[2]
    assert "IP protocol 47, for which FWShift does not know the command of SonicOS" in report.item("service", "gre").findings[0].message
    # Every pair ends in a rule that denies: SonicOS allows some pairs by itself.
    assert 'name "FWSHIFT trust to untrust"' in text and 'name "FWSHIFT untrust to untrust v6"' in text
    assert "DEFAULT_DENY_ADDED" in codes(report) and "SONICWALL_LOAD" in codes(report)
    judge = SonicWallCli(text, {"trust": "trusted", "untrust": "untrusted", "dmz": "public"})
    assert judge.allows(Packet("trust", "untrust", "10.10.1.1", "203.0.113.5", "tcp", 1024, 80))
    assert judge.allows(Packet("trust", "untrust", "10.99.1.1", "203.0.113.5", "tcp", 1024, 80)) is False
    assert judge.allows(Packet("untrust", "dmz", "203.0.113.5", "10.20.0.10", "tcp", 1024, 8080))


def test_names_and_zones_sonicos_would_refuse() -> None:
    p = policy(Rule("r", src_zones=["trust"], dst_zones=["untrust"], sources=['a "quoted" name']))
    p.addresses['a "quoted" name'] = Address('a "quoted" name', AddressKind.NETWORK, "10.1.0.0/24")
    p.addresses["x" * 40] = Address("x" * 40, AddressKind.NETWORK, "10.2.0.0/24")
    p.rules[0].destinations = ["x" * 40]
    text, report = emitted(p)
    assert 'address-object ipv4 "a _quoted_ name" network 10.1.0.0 255.255.255.0 zone trust' in text and f'"{"x" * 32}"' in text
    with pytest.raises(FwshiftError, match="cannot be the name of a SonicOS zone"):
        emitted(policy(Rule("r", src_zones=["any-thing"], dst_zones=["Any"])))
    text, _ = emitted(policy(Rule("r", src_zones=["trust"], dst_zones=["untrust"])), Options(zone_map={"trust": "LAN", "untrust": "WAN"}))
    assert "access-rule ipv4 from LAN to WAN action allow" in text


def test_nat_as_sonicos_has_it() -> None:
    p = policy()
    p.zones["untrust"].interfaces = ["ethernet1/1"]
    p.zones["dmz"].interfaces = ["ethernet1/3"]
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "198.51.100.10/32")
    p.nat_rules = [
        NatRule("publish", origin="publish", src_zones=["untrust"], destinations=["pub"], service="https",
                destination_translation=DestNat("web", "8443")),
        NatRule("hide", origin="hide", src_zones=["dmz"], dst_zones=["untrust"], sources=["web"], source_translation=SourceNat(SnatKind.INTERFACE)),
        NatRule("static", origin="static", dst_zones=["untrust"], sources=["web"], source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True)),
        NatRule("pool", origin="pool", dst_zones=["untrust"], sources=["net"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["site"])),
    ]  # fmt: skip
    text, report = emitted(p, Options(interface_map={"ethernet1/1": "X1", "ethernet1/3": "X2"}))
    assert ('nat-policy inbound X1 outbound any source any translated-source original destination name "pub" translated-destination '
            'name "web" service name "https 2" translated-service name "tcp 8443"') in text  # fmt: skip
    assert 'nat-policy inbound X2 outbound X1 source name "web" translated-source name "X1 IP" destination any' in text
    assert report.item("nat", "static").emitted_as == ["static", "static in"] and "NAT_BIDIRECTIONAL" in codes(report, "nat", "static")
    assert report.item("nat", "pool").skipped and "translated source site" in report.item("nat", "pool").findings[0].message
    _, report = emitted(p)
    assert report.item("nat", "hide").skipped and "--interface-map" in report.item("nat", "hide").findings[0].message
    assert "NAT_ZONES" in codes(report, "nat", "publish")


def test_rule_types_and_defaults() -> None:
    p = policy(Rule("inside", src_zones=["trust", "dmz"], scope=RuleScope.INTRAZONE),
               Rule("between", src_zones=["trust", "dmz"], dst_zones=["trust", "dmz"], scope=RuleScope.INTERZONE))  # fmt: skip
    p.zones["dmz"].intrazone_allow = True
    p.default_interzone = Action.ALLOW
    text, report = emitted(p)
    assert "from trust to trust action allow" in text and "from trust to dmz action allow" in text and "from dmz to dmz action allow" in text
    assert 'name "FWSHIFT untrust to untrust"' in text and "FWSHIFT trust to trust" not in text and "FWSHIFT dmz to dmz" not in text
    assert "FWSHIFT trust to dmz" not in text
    assert "INTERZONE_DEFAULT" in codes(report)


def test_every_sample_converts() -> None:
    for name in ("panos_sample.xml", "fortios_sample.conf", "checkpoint_sample.json", "asa_sample.cfg", "sophos_sample.xml",
                 "fmc_sample.json", "fdm_sample.txt", "iptables_sample.rules", "pfsense_sample.xml", "sonicwall_sample.exp"):  # fmt: skip
        data = (DATA / name).read_bytes()
        report = Report()
        text = cli.convert(cli.load(data, cli.detect_format(data), report), "sonicwall", report)
        SonicWallCli(text)  # the strict reader takes it


# -- what the review of version 0.9.0 found ---------------------------------------------------------------


def test_what_a_row_does_not_say_is_not_any() -> None:
    pairs = base() + [("policyAction_0", "2"), ("policyAction_1", "2"), ("policySrcZone_1", "LAN"), ("policyDstZone_1", "WAN"),
                      ("policySrcNet_1", ""), ("policyDstNet_1", ""), ("policyDstSvc_1", ""), ("policyEnabled_1", "1"),
                      ("policyAction_2", "2"), ("policySrcZone_2", ""), ("policyDstZone_2", "WAN"), ("policySrcNet_2", ""),
                      ("policyDstNet_2", ""), ("policyDstSvc_2", ""), ("policyEnabled_2", "1")]  # fmt: skip
    pairs += [("natPolicyOrigSrc_0", ""), ("natPolicyTransSrc_0", "h17")]
    pairs += [("svcObjId_9", "no ports"), ("svcObjType_9", "1"), ("svcObjIpType_9", "6")]
    pairs += [("svcObjId_10", "one port"), ("svcObjType_10", "1"), ("svcObjIpType_10", "6"), ("svcObjPort1_10", "0"), ("svcObjPort2_10", "80")]
    p, _ = parse(pairs)
    rules = {r.name: r for r in p.rules}
    assert rules["any to any #1"].unsupported == ["the export does not say SrcZone, DstZone, SrcNet, DstNet, DstSvc, Enabled"]
    assert not rules["LAN to WAN #1"].unsupported and rules["any to WAN #1"].unsupported == ["an empty source zone"]
    assert p.nat_rules[0].unsupported[0].startswith("the export does not say OrigDst, OrigSvc")
    assert p.services["no ports"].unsupported == "a TCP or UDP service whose ports the export does not hold"
    assert p.services["one port"].entries == [ServiceEntry(Protocol.TCP, "80")]


def test_the_default_rule_of_a_pair_is_its_last() -> None:
    pairs = base() + table([rule("2", "WAN", "LAN", default="1") | {"policyPriority": "1"},
                            rule("0", "WAN", "LAN", src="n1") | {"policyPriority": "2"}])  # fmt: skip
    p, _ = parse(pairs + [("policyPriority_0", "1")])
    assert [r.action for r in p.rules if r.src_zones == ["WAN"] and r.dst_zones == ["LAN"]] == [Action.DENY, Action.ALLOW]
    p, _ = parse(base() + table([rule("2", "LAN", "WAN") | {"policyPriority": "9" * 5000}]))
    assert len(p.rules) >= 1  # a priority nobody can mean is no priority: the order of the file


def test_an_ipv6_rule_naming_what_sonicos_has_by_itself_is_not_guessed() -> None:
    p, _ = parse(base() + table([rule("1", "LAN", "WAN", src="LAN Subnets", six=True, name="v6 deny")]))
    assert p.rules[0].unsupported == ["it names 'LAN Subnets', an object SonicOS has by itself, whose IPv6 addresses are not in the export"]


def test_service_groups_are_written_after_the_groups_in_them() -> None:
    p = policy(Rule("deny", src_zones=["trust"], dst_zones=["untrust"], services=["outer"], action=Action.DENY))
    p.services["t22"] = Service("t22", [ServiceEntry(Protocol.TCP, "22")])
    p.services["t23"] = Service("t23", [ServiceEntry(Protocol.TCP, "23")])
    from fwshift.model import ServiceGroup

    p.service_groups["outer"] = ServiceGroup("outer", ["inner", "t23"])
    p.service_groups["inner"] = ServiceGroup("inner", ["t22"])
    text, _ = emitted(p)
    assert text.index('service-group "inner"') < text.index('service-group "outer"')
    assert 'service-group "outer"\n    service-group "inner"\n    service-object "t23"' in text
    judge = SonicWallCli(text, {"trust": "trusted", "untrust": "untrusted", "dmz": "public"})
    assert not judge.allows(Packet("trust", "untrust", "10.10.0.5", "203.0.113.5", "tcp", 1024, 22))


def test_groups_sonicos_has_itself_are_named_not_spelled_out() -> None:
    pairs = base() + table([zone("VPN", "5")], start=9) + table([address("H", "1", "LAN", "10.0.0.99", "255.255.255.255"),
                                                                address("Grp", "8", "LAN", "0.0.0.0", "0.0.0.0")], start=20)  # fmt: skip
    pairs += [("addro_atomToGrp_20", "VPN Subnets"), ("addro_grpToGrp_20", "Grp"), ("addro_atomToGrp_21", "H"), ("addro_grpToGrp_21", "Grp"),
              ("addro_atomToGrp_22", "LAN Subnets"), ("addro_grpToGrp_22", "Grp")]  # fmt: skip
    pairs += table([rule("1", "DMZ", "LAN", src="Grp")])
    report = Report()
    text = cli.convert(parse_sonicwall.parse(encode(pairs), report), "sonicwall", report)
    assert 'address-group ipv4 "Grp"\n    address-group ipv4 "VPN Subnets"\n    address-object ipv4 "H"\n    address-group ipv4 "LAN Subnets"' in text
    assert not report.item("rule", "DMZ to LAN #1").disabled


def test_cycles_zones_with_spaces_and_too_many_zones() -> None:
    p = policy(Rule("r", src_zones=["Guest Net"], dst_zones=["untrust"], sources=["loop"]))
    p.address_groups["loop"] = AddressGroup("loop", ["loop2", "net"])
    p.address_groups["loop2"] = AddressGroup("loop2", ["loop"])
    text, report = emitted(p)
    assert 'access-rule ipv4 from "Guest Net" to untrust' in text and report.item("rule", "r").disabled
    SonicWallCli(text)
    many = policy(*[Rule(f"r{n}", src_zones=[f"z{n}"], dst_zones=["untrust"]) for n in range(120)])
    with pytest.raises(FwshiftError, match="writes SonicOS rules for 100 at most"):
        emitted(many)


def test_text_that_cannot_stand_in_a_command() -> None:
    p = policy()
    p.zones["untrust"].interfaces = ["e1"]
    p.nat_rules = [NatRule("n", origin="n", src_zones=["untrust"], destinations=["web"], destination_translation=DestNat("net"),
                           description='a "quoted" \\ comment')]  # fmt: skip
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.rules.append(Rule("r", src_zones=["trust"], dst_zones=["untrust"], destinations=["site"]))
    text, _ = emitted(p, Options(interface_map={"e1": "X1"}))
    assert 'address-object fqdn "site" domain "www.example.com" zone untrust' in text
    assert '\\' not in text.split('comment "')[1].split("\n")[0]
