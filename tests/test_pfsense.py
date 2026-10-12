# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""pfSense: the parser against a firewall made up at random, the emitter against the model, and both by hand.

The judge of what a pfSense does is ``helpers.PfSense``, which reads ``config.xml`` on its own.
"""

from __future__ import annotations

import copy
import random
import re
from typing import List, Optional, Sequence, Tuple

import pytest
from helpers import DATA, PfSense
from test_iptables import Packet, model_allows, model_verdict, random_model

from fwshift import cli
from fwshift.model import ANY, DestNat, NatRule, Policy, ServiceEntry, SnatKind, SourceNat
from fwshift.options import Options
from fwshift.parsers import pfsense as parse_pfsense
from fwshift.report import Report, Severity

# -- a pfSense made up at random --------------------------------------------------------------------


def x(tag: str, *content: str) -> str:
    """An element; a flag when it has no content."""
    return f"<{tag}>{''.join(content)}</{tag}>"


BASE_INTERFACES = {
    "wan": ("WAN", "198.51.100.2", 24, "", 0),
    "lan": ("LAN", "10.0.1.1", 24, "2001:db8:1::1", 64),
    "opt1": ("DMZ", "10.0.2.1", 24, "2001:db8:2::1", 64),
    "opt2": ("GUEST", "10.0.3.1", 24, "", 0),
}
ZONES = [descr for descr, *_ in BASE_INTERFACES.values()]
INSIDE = {"LAN": "10.0.1.", "DMZ": "10.0.2.", "GUEST": "10.0.3."}
OUTSIDE = ["203.0.113.5", "203.0.113.77", "198.51.100.99", "192.0.2.14", "10.9.9.9", "172.16.5.5"]
PUBLIC = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]  # addresses the firewall answers for on WAN
PORTS = [22, 25, 53, 80, 443, 8000, 8005, 8080, 9000]


def interfaces_xml(blockpriv: bool = False, extra: str = "") -> str:
    out = []
    for key, (descr, address, bits, address6, bits6) in BASE_INTERFACES.items():
        parts = [x("enable"), x("if", f"igb{len(out)}"), x("descr", descr), x("ipaddr", address), x("subnet", str(bits))]
        if address6:
            parts += [x("ipaddrv6", address6), x("subnetv6", str(bits6))]
        if key == "wan":
            parts += [x("gateway", "WANGW")] + ([x("blockpriv")] if blockpriv else [])
        out.append(x(key, *parts))
    return x("interfaces", *out) + extra


def config(*sections: str, version: str = "23.3", ipv6: bool = True, system: str = "", blockpriv: bool = False,
           interfaces: Optional[str] = None) -> str:  # fmt: skip
    head = x("version", version) + x("system", (x("ipv6allow") if ipv6 else "") + x("disablenatreflection", "yes") + system)
    return '<?xml version="1.0"?>\n' + x("pfsense", head, interfaces if interfaces is not None else interfaces_xml(blockpriv), *sections)


def side(spec: str, port: str = "") -> str:
    """``any``, ``net:lan``, an address or an alias, with ``!`` in front for "not"."""
    negated = spec.startswith("!")
    spec = spec.lstrip("!")
    inner = x("any") if spec == "any" else x("network", spec[4:]) if spec.startswith("net:") else x("address", spec)
    return inner + (x("not") if negated else "") + (x("port", port) if port else "")


def rule(interface: str, action: str = "pass", src: str = "any", dst: str = "any", proto: str = "", dport: str = "",
         sport: str = "", family: str = "inet", descr: str = "", extra: str = "", floating: str = "") -> str:  # fmt: skip
    """A rule; ``floating`` is "", or "in", "out" or "any" with "!" behind it for a rule that is not quick."""
    parts = [x("type", action), x("interface", interface), x("ipprotocol", family) if family else ""]
    if floating:
        parts += [x("floating", "yes"), x("direction", floating.rstrip("!"))] + ([] if floating.endswith("!") else [x("quick", "yes")])
    if proto:
        parts.append(x("protocol", proto))
    parts += [x("source", side(src, sport)), x("destination", side(dst, dport)), x("descr", f"<![CDATA[{descr}]]>") if descr else "", extra]
    return x("rule", *parts)


def alias(name: str, kind: str, *entries: str) -> str:
    return x("alias", x("name", name), x("type", kind), x("address", " ".join(entries)), x("descr"), x("detail"))


ALIASES = x(
    "aliases",
    alias("Servers", "host", "10.0.2.10", "10.0.2.11", "2001:db8:2::10"),
    alias("Admins", "host", "10.0.1.34", "10.0.1.51"),
    alias("Inside", "network", "10.0.1.0/24", "10.0.3.0/24", "Servers"),
    alias("Partners", "network", "203.0.113.0/25", "192.0.2.14"),
    alias("Private", "network", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
    alias("Web", "port", "80", "443", "8000:8010"),
    alias("Mail", "port", "25", "Web"),
)
ADDRESSES = ["any", "any", "Servers", "Admins", "Inside", "Partners", "Private", "10.0.2.0/24", "10.0.1.34", "203.0.113.77",
             "net:lan", "net:opt1", "net:wan", "net:lanip", "net:wanip", "net:(self)", "net:INSIDE"]  # fmt: skip
GROUPS = x("ifgroups", x("ifgroupentry", x("ifname", "INSIDE"), x("members", "lan opt2")),
           x("ifgroupentry", x("ifname", "SERVED"), x("members", "opt1 opt2")))  # fmt: skip


NO_NAT = x("nat", x("outbound", x("mode", "disabled")))


def random_rule(rng: random.Random, interface: str, number: int, floating: str = "") -> str:
    family = rng.choice(["inet", "inet", "inet", "inet46", "inet6", ""])
    proto = rng.choice(["", "", "tcp", "tcp", "udp", "tcp/udp", "icmp", "esp"])
    action = rng.choice(["pass", "pass", "pass", "block", "reject"])

    def pick() -> str:
        spec = rng.choice(ADDRESSES)
        if family in ("inet46", "inet6") and not spec.startswith(("net:", "any")) and spec[0].isdigit():
            spec = "Servers"  # the web interface takes no IPv4 address in such a rule
        if spec == "net:wan" and family in ("inet6", "inet46"):
            spec = "net:lan"
        return ("!" if spec != "any" and rng.random() < 0.2 else "") + spec

    dport = sport = extra = ""
    if proto in ("tcp", "udp", "tcp/udp"):
        dport = rng.choice(["", "22", "53", "80-443", "Web", "Mail", "8000-8010", "https", "ssh"])
        sport = rng.choice(["", "", "", "1024-65535"])
    if proto == "icmp" and rng.random() < 0.6:
        extra = x("icmptype", rng.choice(["echoreq", "echoreq,unreach", "timex"]))
    if rng.random() < 0.1:
        extra += x("disabled")
    if rng.random() < 0.2:
        extra += x("log")
    return rule(interface, action, pick(), pick(), proto, dport, sport, family, f"{interface.replace(',', '+')} {number}", extra, floating)


def random_firewall(rng: random.Random, floating: bool = True, version: str = "23.3") -> str:
    rules: List[str] = []
    if floating:
        for number in range(rng.randint(0, 5)):
            where = rng.choice(["wan", "lan", "opt1", "lan,opt1", "wan,opt2", "any", "INSIDE", "lan,INSIDE"])
            way = rng.choice(["in", "in", "in!", "any", "any!", "out"])
            text = random_rule(rng, where, number, way)
            if not way.startswith("in"):
                # What leaves is only blocked here: a rule that passes it in front of one that blocks is nothing
                # the model can say, and gets a test of its own.
                text = text.replace(x("type", "pass"), x("type", "block")).replace(x("type", "reject"), x("type", "block"))
                text = text.replace(x("direction", "any"), x("direction", "out")) if rng.random() < 0.5 else text
            rules.append(text)
    for interface in ("INSIDE", "wan", "lan", "SERVED", "opt1", "opt2", "INSIDE"):
        rules += [random_rule(rng, interface, len(rules) + number) for number in range(rng.randint(0, 4))]
    rng.shuffle(rules)
    return config(ALIASES, GROUPS, NO_NAT, x("filter", *rules), version=version, ipv6=rng.random() < 0.7, blockpriv=rng.random() < 0.4)


def route(address: str) -> str:
    """The zone an address is reached by: the networks of the interfaces, and the rest by WAN."""
    if ":" in address:
        return {"2001:db8:1:": "LAN", "2001:db8:2:": "DMZ"}.get(address[:11], "WAN")
    return next((zone for zone, prefix in INSIDE.items() if address.startswith(prefix)), "WAN")


def random_packet(rng: random.Random, judge: Optional[PfSense] = None) -> Packet:
    zone = rng.choice(ZONES)
    if rng.random() < 0.8:
        hosts = [10, 11, 34, 51, 77, 200]
        src = INSIDE[zone] + str(rng.choice(hosts)) if zone in INSIDE and rng.random() < 0.9 else rng.choice(OUTSIDE)
        dst = rng.choice(
            [prefix + str(host) for prefix in INSIDE.values() for host in hosts] + OUTSIDE + PUBLIC + ["198.51.100.2", "10.0.1.1", "10.0.2.1"]
        )
    else:
        pool = ["2001:db8:1::5", "2001:db8:1::1", "2001:db8:2::10", "2001:db8:2::99", "2001:db8:ffff::9", "fd00::7"]
        src, dst = rng.choice(pool), rng.choice(pool)
    proto = rng.choice(["tcp", "tcp", "tcp", "udp", "icmp" if "." in src else "icmp6", "50", "47"])
    pkt = Packet(zone, "", src, dst, proto, rng.choice([1024, 40000, 600]), rng.choice(PORTS), rng.choice([0, 3, 8, 11, 128, 1]))
    target = judge._arriving(judge.key(zone), pkt)[0] if judge is not None else dst
    pkt.out_if = route(target)
    return pkt


def parse(text: str, **options: Sequence[str]) -> Tuple[Policy, Report]:
    report = Report()
    return parse_pfsense.parse(text.encode(), report, **options), report  # type: ignore[arg-type]


@pytest.mark.parametrize("version,floating", [("23.3", False), ("23.3", True), ("24.0", True), ("22.2", True)])
def test_parsed_configuration_decides_like_pfsense(version: str, floating: bool) -> None:
    """Tabs, groups, floating rules that are quick or not, for what arrives and what leaves, aliases in aliases,
    the words pfSense has for networks, IPv4 and IPv6 in one rule, "Block private networks", IPv6 switched off."""
    allowed = compared = 0
    seen: set = set()  # why pfSense did not load a rule: an address the firewall does not have
    for seed in range(70):
        rng = random.Random(seed)
        text = random_firewall(rng, floating, version)
        judge = PfSense(text)
        p, report = parse(text)
        assert not any(r.unsupported for r in p.rules), (seed, [(r.name, r.unsupported) for r in p.rules if r.unsupported])
        seen |= {note.message.split("(")[-1].split(":")[0] for note in report.notes if note.code == "RULE_NOT_LOADED"}
        for _ in range(300):
            pkt = random_packet(rng, judge)
            expected = judge.allows(pkt)
            allowed += expected
            compared += 1
            assert model_allows(p, pkt) == expected, (seed, pkt, model_verdict(p, pkt), text)
    assert allowed > compared // 12, (allowed, compared)  # the firewalls let a good part of the packets through
    assert seen, "no rule that pfSense does not load was among them"


# -- the emitter against the model ------------------------------------------------------------------

from test_asa import ZONE_NETWORKS, effective, emitter_packet  # noqa: E402

ZONE_MAP = {"eth0": "wan", "eth1": "lan", "eth2": "opt1"}
TARGET_NETWORKS = {ZONE_MAP[zone]: networks for zone, networks in ZONE_NETWORKS.items()}


def target(*sections: str, ipv6: bool = True, gateway: bool = False) -> PfSense:
    """A pfSense whose interfaces carry the zone names of the random models as their descriptions; with ``gateway``
    the WAN has one, and outbound NAT, automatic, translates what leaves by it from the networks of the others."""
    inside = {"lan": ("10.0.2.1", "23"), "opt1": ("10.0.4.1", "24")} if gateway else {}
    interfaces = x("interfaces", *(
        x(key, x("enable"), x("if", f"igb{n}"), x("descr", zone), x("ipaddr", inside.get(key, (f"192.0.2.{n * 64 + 1}",))[0]),
          x("subnet", inside.get(key, ("", "26"))[1]), x("gateway", "WANGW") if gateway and key == "wan" else "")
        for n, (zone, key) in enumerate(ZONE_MAP.items())
    ))  # fmt: skip
    return PfSense(config(*sections, interfaces=interfaces, ipv6=ipv6))


def restored(text: str, *sections: str, gateway: bool = False) -> PfSense:
    judge = target(*sections, gateway=gateway)
    judge.restore(text)
    return judge


@pytest.mark.parametrize("seed", range(60))
def test_emitted_rules_decide_like_the_model(seed: int) -> None:
    """Lists, negations, rule types, zone pairs, services of several kinds: with the networks of every zone
    given, the rules pfSense gets decide as the model does. Only a negated service is nothing it can say."""
    rng = random.Random(seed)
    model = random_model(rng)
    report = Report()
    text = cli.convert(model, "pfsense", report, Options(zone_map=ZONE_MAP, zone_networks=TARGET_NETWORKS))
    for item in report.items.values():
        assert not item.disabled or {f.code for f in item.findings if f.severity == Severity.REVIEW} - {"EGRESS_NO_ADDRESS"} == {"SERVICE_NEGATE"}, (seed, item.name, [f.code for f in item.findings])
    expected = effective(model, report)
    judge = restored(text)
    for _ in range(400):
        pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, pkt, judge.deciding(pkt), model_verdict(expected, pkt), text)


@pytest.mark.parametrize("seed", range(30))
def test_a_firewall_that_keeps_its_own_outbound_nat_decides_like_the_model(seed: int) -> None:
    """Without NAT rules in the policy the file holds no NAT area, and the firewall it is restored on keeps its own
    outbound NAT: automatic, it translates the source of what leaves by the WAN. A rule that pf looks at after
    that translation (a floating rule for what leaves) must not name a source then."""
    rng = random.Random(7000 + seed)
    model = random_model(rng)
    model.nat_rules = []
    # A rule ahead of all others that blocks some sources from leaving by the WAN, whatever zone they come from.
    blocked = rng.choice(["10.0.2.0/25", "10.0.4.0/26", "10.0.0.0/24"])
    model.rules.insert(0, Rule(name="keep in", origin="keep in", src_zones=[ANY], dst_zones=["eth0"], sources=[blocked], action=Action.DENY))
    report = Report()
    text = cli.convert(model, "pfsense", report, Options(zone_map=ZONE_MAP, zone_networks=TARGET_NETWORKS))
    assert "<nat>" not in text
    expected = effective(model, report)
    judge = restored(text, gateway=True)
    translated = 0
    for _ in range(300):
        pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
        translated += judge.translation(pkt)[0] != "Original"
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, pkt, judge.deciding(pkt), model_verdict(expected, pkt), text)
    assert translated, "automatic outbound NAT translated nothing"


@pytest.mark.parametrize("seed", range(40))
def test_without_zone_networks_nothing_gets_wider_in_silence(seed: int) -> None:
    """Without the networks a rule cannot be kept to its zone: such a rule is disabled, or says that it applies by
    whatever interface its destination is reached."""
    rng = random.Random(1000 + seed)
    model = random_model(rng)
    report = Report()
    text = cli.convert(model, "pfsense", report, Options(zone_map=ZONE_MAP))
    expected = effective(model, report)
    approximated = {item.name for item in report.items.values() if "EGRESS_INTERFACE" in [f.code for f in item.findings]}
    judge = restored(text)
    for _ in range(400):
        pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
        if judge.allows(pkt) != model_allows(expected, pkt):
            assert judge.deciding(pkt).split(":")[0] in approximated, (seed, pkt, judge.deciding(pkt), approximated)


# -- NAT ----------------------------------------------------------------------------------------------

VIPS = x("virtualip", *(
    x("vip", x("mode", "ipalias"), x("interface", "wan"), x("subnet", address), x("subnet_bits", "32")) for address in PUBLIC
))  # fmt: skip


def forward(dst: str, port: str, target: str, local: str = "", proto: str = "tcp", src: str = "any", interface: str = "wan",
            link: str = "", descr: str = "", extra: str = "") -> str:  # fmt: skip
    return x(
        "rule", x("source", side(src)), x("destination", side(dst, port)), x("ipprotocol", "inet"), x("protocol", proto),
        x("target", target), x("local-port", local or port.split("-")[0]) if port else "", x("interface", interface),
        x("descr", descr), x("associated-rule-id", link), extra,
    )  # fmt: skip


def one_to_one(external: str, inside: str, interface: str = "wan", descr: str = "", extra: str = "") -> str:
    return x("onetoone", x("external", external), x("descr", descr), x("interface", interface), x("source", x("address", inside)),
             x("destination", x("any")), x("ipprotocol", "inet"), extra)  # fmt: skip


def outbound(source: str, target: str = "wanip", destination: str = "", interface: str = "wan", descr: str = "", extra: str = "",
             bits: str = "") -> str:  # fmt: skip
    where = x("network", destination) if destination else x("any")
    return x("rule", x("source", x("network", source)), x("sourceport"), x("descr", descr), x("target", target),
             x("target_subnet", bits), x("interface", interface), x("poolopts"), x("destination", where), extra)  # fmt: skip


def random_nat_firewall(rng: random.Random) -> str:
    """Port forwards with the rules that go with them, a 1:1 rule, outbound NAT in every mode."""
    forwards: List[str] = []
    wan_rules: List[str] = []
    taken: List[Tuple[str, str]] = []
    for number in range(rng.randint(1, 3)):
        dst = rng.choice(PUBLIC[:2] + ["net:wanip"])
        proto = rng.choice(["tcp", "tcp", "udp", "tcp/udp"])
        port = rng.choice(["22", "25", "53", "80", "443", "8000-8010", "Web"])
        if any(d == dst for d, _ in taken):
            continue  # one forward per address: which of two that overlap wins is a test of its own
        taken.append((dst, port))
        # One host per forward: a rule for a host that two addresses lead to is a rule for both of them in the
        # model, which is reported and looked at in a test of its own.
        host = ["10.0.2.10", "10.0.2.11", "10.0.2.77"][len(taken) - 1]
        link = rng.choice(["nat_1", "nat_1", "pass", ""])
        source = rng.choice(["any", "any", "Partners"])
        forwards.append(forward(dst, port, host, proto=proto, src=source, link=link, descr=f"forward {number}"))
        local = port if port != "8000-8010" else "8000-8010"
        if link == "nat_1":
            wan_rules.append(rule("wan", "pass", source, host, proto, local, descr=f"NAT forward {number}"))
    ones: List[str] = []
    if rng.random() < 0.6:
        ones.append(one_to_one(PUBLIC[2], "10.0.2.200", descr="one"))
        wan_rules.append(rule("wan", "pass", "any", "10.0.2.200", "tcp", "25", descr="mail to the 1:1 host"))
    mode = rng.choice(["automatic", "hybrid", "advanced", "disabled", ""])
    manual = [
        outbound("10.0.2.0/24", PUBLIC[1], descr="servers leave by their own address"),
        outbound("10.0.1.0/24", "", "203.0.113.0/25", descr="no NAT to the partners", extra=x("nonat")),
        outbound("Admins", descr="administrators"),
        outbound("any", PUBLIC[0], "192.0.2.0/24", descr="everything to the test network", bits="32"),
    ]
    rng.shuffle(manual)
    nat = x("nat", x("outbound", x("mode", mode) if mode else "", *manual[: rng.randint(0, 4)]), *forwards, *ones)
    rules = list(wan_rules)
    for interface in ("lan", "opt1", "opt2", "INSIDE"):
        rules += [random_rule(rng, interface, len(rules) + number) for number in range(rng.randint(1, 4))]
    rules.append(rule("wan", "pass", "Partners", "any", "tcp", "22", descr="partners to anything by ssh"))
    rng.shuffle(rules)
    return config(ALIASES, GROUPS, VIPS, nat, x("filter", *rules), ipv6=rng.random() < 0.7, blockpriv=rng.random() < 0.3)


def model_translation(p: Policy, pkt: Packet) -> Tuple[str, str, str]:
    """(source, destination, port) of a packet when it leaves, as a platform does it that translates the destination
    on arrival and the source on departure, each by its first rule: "Original" for what stays."""
    from test_iptables import _entry_matches, _member_matches

    def matches(nat: NatRule, dst: str, dport: int, zone_in: Optional[str], zone_out: Optional[str]) -> bool:
        if not nat.enabled or nat.unsupported:
            return False
        if zone_in is not None and ANY not in nat.src_zones and zone_in not in nat.src_zones:
            return False
        if zone_out is not None and ANY not in nat.dst_zones and zone_out not in nat.dst_zones:
            return False
        probe = copy.copy(pkt)
        probe.dst, probe.dport = dst, dport
        if not any(_member_matches(p, m, pkt.src) for m in nat.sources) or not any(_member_matches(p, m, dst) for m in nat.destinations):
            return False
        return nat.service == ANY or any(_entry_matches(e, probe) for e in transform_entries(p, nat.service))

    dst, dport = pkt.dst, pkt.dport
    for nat in p.nat_rules:
        if nat.destination_translation is not None and matches(nat, pkt.dst, pkt.dport, pkt.in_if, None):
            dst = interval_start(p, nat.destination_translation.address)
            dport = int(nat.destination_translation.port or dport)
            break
    src = pkt.src
    for nat in p.nat_rules:
        if nat.destination_translation is None and matches(nat, dst, dport, None, pkt.out_if):
            how = nat.source_translation
            if how is not None:
                src = how.interface_address or "MASQ" if how.kind == SnatKind.INTERFACE else interval_start(p, how.addresses[0])
            break
    return ("Original" if src == pkt.src else src, "Original" if dst == pkt.dst else dst, "Original" if dport == pkt.dport else str(dport))


def deciding(p: Policy, pkt: Packet) -> str:
    """The name of the rule of the model that decides about a packet; "" when none does."""
    for rule in p.rules:
        alone = copy.copy(p)
        alone.rules = [rule]
        if model_verdict(alone, pkt) is not None:
            return rule.name
    return ""


def transform_entries(p: Policy, service: str) -> List[ServiceEntry]:
    from fwshift import transform

    return transform.flatten_services(p, service) or []


def interval_start(p: Policy, member: str) -> str:
    import ipaddress

    from fwshift import transform

    intervals = transform.address_intervals(p, member) or []
    assert intervals, member
    return str(ipaddress.ip_address(intervals[0][1]))


def test_parsed_nat_translates_and_decides_like_pfsense() -> None:
    """Port forwards before the rules, with the rule pfSense links to them or passing by themselves; 1:1 NAT in
    both directions; outbound NAT by hand, by itself, both or not at all, with the rule that says "no NAT"."""
    translated = allowed = direct = 0
    for seed in range(80):
        rng = random.Random(3000 + seed)
        text = random_nat_firewall(rng)
        judge = PfSense(text)
        p, report = parse(text)
        assert not any(r.unsupported for r in p.rules) and not any(n.unsupported for n in p.nat_rules), (seed, report.to_text())
        for _ in range(300):
            pkt = random_packet(rng, judge)
            if ":" in pkt.src:
                continue
            got, want = model_translation(p, pkt), judge.translation(pkt)
            translated += want != ("Original", "Original", "Original")
            assert got == want, (seed, pkt, got, want, text)
            expected = judge.allows(pkt)
            allowed += expected
            if model_allows(p, pkt) != expected:
                # The one thing the model has wider, and says so: the rule that stands for a port forward that passes
                # its own traffic also passes what is sent to the translated address directly.
                name = deciding(p, pkt)
                assert name.endswith(" - pass") and not expected and judge.translation(pkt)[1] == "Original", (seed, pkt, name, text)
                assert any(f.code == "AUTOMATIC_RULE" and f.severity == Severity.APPROX for f in report.item("rule", name).findings)
                direct += 1
    assert translated > 2000 and allowed > 1200 and direct, (translated, allowed, direct)


# -- pfSense to pfSense -------------------------------------------------------------------------------


def round_trip(text: str) -> Tuple[PfSense, Report, str]:
    """A firewall with the three areas restored from what FWShift made of its own configuration."""
    p, report = parse(text)
    cli_report = report
    written = cli.convert(p, "pfsense", cli_report)
    # What "Block private networks" does is a rule in what was written. The target is taken without the setting:
    # with it, pfSense drops such packets before any rule, also those a port forward of the source passed by itself.
    judge = PfSense(text.replace(x("blockpriv"), ""))
    judge.restore(written)
    return judge, cli_report, written


@pytest.mark.parametrize("kind", ["rules", "floating", "nat"])
def test_converted_pfsense_decides_like_the_pfsense_it_came_from(kind: str) -> None:
    """Read, written and restored, a firewall does what it did: the same verdict and the same translation for
    every packet. Nothing may need a person to look at it but the restore itself."""
    compared = allowed = 0
    for seed in range(40):
        rng = random.Random(7000 + seed)
        text = random_nat_firewall(rng) if kind == "nat" else random_firewall(rng, floating=kind == "floating")
        before = PfSense(text)
        after, report, written = round_trip(text)
        review = {f.code for item in report.items.values() for f in item.findings if f.severity == Severity.REVIEW}
        review |= {note.code for note in report.notes if note.severity == Severity.REVIEW}
        assert review <= {"PFSENSE_RESTORE", "RULE_NOT_LOADED", "RULE_ORDER_VERSION", "FLOATING_AFTER_NAT"}, (seed, report.to_text())
        for _ in range(300):
            pkt = random_packet(rng, before)
            expected = before.allows(pkt)
            compared += 1
            allowed += expected
            if after.allows(pkt) != expected:
                # A port forward that passed its own traffic has a rule now, which also passes what is sent to the
                # translated address directly: the report says so.
                name = after.deciding(pkt)
                assert name.endswith(" - pass") and not expected and before.translation(pkt)[1] == "Original", (seed, pkt, name, written)
                assert any(f.code == "AUTOMATIC_RULE" and f.severity == Severity.APPROX for f in report.item("rule", name).findings)
            if ":" not in pkt.src:
                assert after.translation(pkt) == before.translation(pkt), (seed, pkt, written)
    assert allowed > compared // 25, (allowed, compared)


# -- the parser by hand -------------------------------------------------------------------------------

from fwshift import transform  # noqa: E402
from fwshift.errors import FwshiftError, ParseError  # noqa: E402
from fwshift.model import ANY_V4, ANY_V6, Action, AddressKind, Protocol  # noqa: E402


def read(*sections: str, **options: object) -> Tuple[Policy, Report]:
    given = options.pop("interface_addresses", ())
    return parse(config(*sections, **options), interface_addresses=given)  # type: ignore[arg-type]


def codes(report: Report, name: str = "", kind: str = "rule") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


def by_name(p: Policy) -> dict:
    return {r.name: r for r in p.rules}


def test_the_order_of_the_model_is_the_order_in_which_pfsense_decides() -> None:
    p, report = read(GROUPS, NO_NAT, x(
        "filter",
        rule("lan", descr="tab"),
        rule("INSIDE", "block", descr="group"),
        rule("any", "block", proto="tcp", dport="23", descr="late one", floating="in!"),
        rule("any", "pass", proto="tcp", dport="23", descr="late two", floating="in!"),
        rule("lan,opt1", "pass", proto="icmp", descr="quick", floating="in"),
        rule("wan", "block", dst="203.0.113.0/24", descr="leaving", floating="out"),
        rule("opt1", "block", descr="both ways", floating="any"),
    ), blockpriv=True)  # fmt: skip
    assert [r.name for r in p.rules] == [
        "leaving", "both ways - leaving", "Block private networks from WAN", "quick", "both ways", "group", "tab",
        "late two", "late one",
    ]  # fmt: skip
    rules = by_name(p)
    assert rules["leaving"].src_zones == [ANY] and rules["leaving"].dst_zones == ["WAN"]
    assert rules["both ways - leaving"].dst_zones == ["DMZ"] and rules["both ways"].src_zones == ["DMZ"]
    assert rules["quick"].src_zones == ["LAN", "DMZ"] and rules["group"].src_zones == ["LAN", "GUEST"]
    assert rules["late one"].src_zones == [ANY] and rules["tab"].dst_zones == [ANY]
    private = rules["Block private networks from WAN"]
    assert private.sources == parse_pfsense.PRIVATE_NETWORKS and private.action == Action.DROP and private.src_zones == ["WAN"]
    assert codes(report, private.name) == ["AUTOMATIC_RULE"]
    note = next(n for n in report.notes if n.code == "FLOATING_LAST_MATCH")
    assert "'late two', 'late one'" in note.message and "2 floating rules are not 'quick'" in note.message
    assert p.default_interzone == p.default_intrazone == Action.DENY and p.lookup_after_dnat
    assert {name: zone.interfaces for name, zone in p.zones.items()} == {"WAN": ["wan"], "LAN": ["lan"], "DMZ": ["opt1"], "GUEST": ["opt2"]}


def test_a_rule_that_passes_what_leaves_before_one_that_blocks_it_cannot_be_said() -> None:
    p, report = read(NO_NAT, x(
        "filter",
        rule("wan", "pass", dst="203.0.113.5", descr="exception", floating="out"),
        rule("wan", "block", dst="203.0.113.0/24", descr="rest", floating="out"),
        rule("lan", "block", dst="203.0.113.0/24", descr="other interface", floating="out"),
        rule("wan", "pass", descr="only passes", floating="out!"),
        # Not quick: the last one that matches decides, so a pass behind a block comes first.
        rule("opt1", "block", dst="203.0.113.0/24", descr="late block", floating="out!"),
        rule("opt1", "pass", dst="203.0.113.5", descr="later pass", floating="out!"),
        rule("opt2", "pass", dst="203.0.113.5", descr="early pass", floating="out!"),
        rule("opt2", "block", dst="203.0.113.0/24", descr="early block", floating="out!"),
    ))  # fmt: skip
    rules = by_name(p)
    assert list(rules) == ["rest", "other interface", "early block", "late block"]
    assert rules["rest"].unsupported == ["it blocks traffic that leaves, except what a floating rule before it passes ('exception')"]
    assert not rules["other interface"].unsupported and not rules["early block"].unsupported
    assert rules["late block"].unsupported == ["it blocks traffic that leaves, except what a floating rule before it passes ('later pass')"]
    note = next(n for n in report.notes if n.code == "FLOATING_OUT_PASS")
    assert "'exception'" in note.message and "'only passes'" in note.message and note.severity == Severity.INFO


@pytest.mark.parametrize("nat,named,expected", [
    (NO_NAT, "10.0.1.0/24", False), ("", "10.0.1.0/24", True), ("", "any", False),
    (x("nat", x("outbound", x("mode", "advanced"))), "10.0.1.0/24", False),
    (x("nat", x("outbound", x("mode", "advanced"), outbound("10.0.1.0/24"))), "10.0.1.0/24", True),
    (x("nat", x("outbound", x("mode", "disabled")), one_to_one(PUBLIC[0], "10.0.1.5")), "10.0.1.0/24", True),
])  # fmt: skip
def test_what_leaves_is_matched_after_outbound_nat(nat: str, named: str, expected: bool) -> None:
    """A floating rule for what leaves by an interface sees the source outbound NAT made of it."""
    p, _ = read(nat, x("filter", rule("wan", "block", src=named, descr="leaving", floating="out")))
    assert bool(by_name(p)["leaving"].unsupported) == expected
    if expected:
        assert "after outbound NAT" in by_name(p)["leaving"].unsupported[0]


def test_rules_pfsense_does_not_load_are_not_converted_and_named() -> None:
    interfaces = interfaces_xml(extra="").replace("</interfaces>", x("opt3", x("if", "igb9"), x("descr", "SPARE"), x("ipaddr", "10.0.9.1"), x("subnet", "24")) + "</interfaces>")
    p, report = read(ALIASES, NO_NAT, x(
        "filter",
        rule("lan", src="Gone", descr="alias that is gone"),
        rule("lan", dst="Web", descr="ports as an address"),
        rule("lan", proto="tcp", dport="Nothing", descr="ports that are gone"),
        rule("lan", proto="tcp", dport="Servers", descr="addresses as ports"),
        rule("opt3", descr="interface not enabled"),
        rule("opt7", descr="interface not there"),
        rule("lan", src="net:opt3", descr="network of an interface not enabled"),
        rule("lan", dst="net:opt2", family="inet6", descr="no IPv6 there"),
        rule("lan", dst="net:wanip", family="inet6", descr="no IPv6 address"),
        rule("lan", dst="www.example.com", descr="host name in a rule"),
        rule("lan", dst="2001:db8::1", descr="other IP version"),
        rule("lan", descr="no source").replace(x("source", x("any")), ""),
        rule("opt3", descr="disabled and not there", extra=x("disabled")),
        rule("wan,opt3", descr="floating without an interface that is there", floating="in").replace("wan,opt3", "opt3,opt9"),
        rule("lan", descr="fine"),
    ), interfaces=interfaces)  # fmt: skip
    assert [r.name for r in p.rules] == ["fine"]
    note = next(n for n in report.notes if n.code == "RULE_NOT_LOADED")
    assert note.severity == Severity.REVIEW and "pfSense does not load 13 rules" in note.message
    for text in (
        "'alias that is gone' (source: alias 'Gone' cannot be resolved)", "'ports as an address' (destination: alias 'Web' cannot be resolved)",
        "'ports that are gone' (destination port: 'Nothing' is neither a port nor an alias of ports)",
        "'addresses as ports' (destination port: 'Servers' is neither a port nor an alias of ports)",
        "'interface not enabled' (its interface 'opt3' is not there or not enabled)", "'interface not there' (its interface 'opt7'",
        "(source: interface 'opt3' is not there or not enabled)", "(destination: interface GUEST has no IPv6 network)",
        "(destination: interface WAN has no IPv6 address)", "(destination: alias 'www.example.com' cannot be resolved)",
        "(destination: '2001:db8::1' is not an IPv4 address)", "'no source' (source: it has no address)",
        "'floating without an interface that is there' (its interface 'opt3,opt9'",
    ):  # fmt: skip
        assert text in note.message, text
    assert "disabled and not there" not in note.message
    assert "SPARE" not in p.zones


def test_an_address_the_configuration_does_not_hold_is_asked_for() -> None:
    interfaces = interfaces_xml().replace(x("ipaddr", "198.51.100.2") + x("subnet", "24"), x("ipaddr", "dhcp")).replace(
        x("ipaddrv6", "2001:db8:1::1") + x("subnetv6", "64"), x("ipaddrv6", "track6"))  # fmt: skip
    sections = (NO_NAT, x(
        "filter",
        rule("wan", dst="net:wanip", proto="tcp", dport="443", descr="to the firewall"),
        rule("lan", src="net:lan", family="inet46", descr="lan out"),
        rule("lan", dst="net:(self)", proto="udp", dport="53", descr="dns"),
        rule("opt1", src="net:wan", descr="from the wan network"),
    ))  # fmt: skip
    p, report = read(*sections, interfaces=interfaces)
    rules = by_name(p)
    address = p.addresses["WAN address"]
    assert address.kind == AddressKind.UNSUPPORTED and address.builtin == "pfsense" and address.fqdn_family == 4
    assert address.raw == "the IPv4 address of interface WAN is not in the configuration (dhcp); give it with --interface-address"
    assert p.addresses["WAN net"].kind == AddressKind.UNSUPPORTED and "track6" in p.addresses["LAN net IPv6"].raw
    assert p.address_groups["This Firewall"].unsupported == "the IPv4 address of WAN (dhcp) is not in the configuration; give it with --interface-address"
    # Both IP versions of one rule: the half that is known is a rule, the other one is another, and that one is unusable.
    assert rules["lan out"].sources == ["LAN net"] and rules["lan out IPv6"].sources == ["LAN net IPv6"]
    assert rules["lan out"].destinations == [ANY_V4] and rules["lan out IPv6"].destinations == [ANY_V6]
    taint = transform.tainted_addresses(p)
    assert set(taint) == {"WAN address", "WAN net", "LAN net IPv6", "This Firewall"}
    p, report = read(*sections, interfaces=interfaces, interface_addresses=["WAN=198.51.100.7/27", "lan=2001:db8:99::1/64"])
    assert not transform.tainted_addresses(p)
    assert p.addresses["WAN address"].value == "198.51.100.7/32" and p.addresses["WAN net"].value == "198.51.100.0/27"
    assert p.addresses["LAN net IPv6"].value == "2001:db8:99::/64" and "198.51.100.7" in p.address_groups["This Firewall"].members
    assert by_name(p)["lan out"].sources == ["LAN net", "LAN net IPv6"] and by_name(p)["lan out"].destinations == [ANY]
    for bad, text in (("wan", "is not INTERFACE=ADDRESS/BITS"), ("wan=198.51.100.7", "is not INTERFACE=ADDRESS/BITS"),
                      ("wan=nonsense/24", "is not INTERFACE=ADDRESS/BITS"), ("opt9=10.0.0.1/24", "no interface 'opt9' in the configuration; it has wan (WAN), lan (LAN)")):  # fmt: skip
        with pytest.raises(FwshiftError, match=re.escape(text)):
            read(*sections, interfaces=interfaces, interface_addresses=[bad])


def test_ipv4_and_ipv6_of_one_rule() -> None:
    p, report = read(ALIASES, NO_NAT, x(
        "filter",
        rule("lan", family="", descr="no word is IPv4"),
        rule("lan", family="inet46", descr="both"),
        rule("lan", family="inet6", descr="six"),
        rule("lan", family="inet46", proto="icmp", extra=x("icmptype", "echoreq"), descr="ping both"),
        rule("lan", family="inet46", src="net:lan", dst="net:(self)", descr="words"),
        rule("lan", family="inet", src="Servers", dst="Inside", descr="aliases of both versions"),
        rule("lan", family="inet6", src="Servers", dst="!Private", descr="one side negated"),
        rule("lan", family="inet", src="!Servers", dst="!Private", descr="both sides negated"),
        rule("lan", family="inet46", dst="net:opt2", descr="one half is not there"),
        rule("lan", family="inet6", src="Admins", descr="nothing of that version"),
    ))  # fmt: skip
    rules = by_name(p)
    assert rules["no word is IPv4"].sources == [ANY_V4] and rules["both"].sources == [ANY] and rules["six"].destinations == [ANY_V6]
    assert rules["ping both"].services == ["icmp-echoreq", "icmp6-echoreq"]
    assert p.services["icmp-echoreq"].entries[0].icmp_type == 8 and p.services["icmp6-echoreq"].entries[0].icmp_type == 128
    assert rules["words"].sources == ["LAN net", "LAN net IPv6"] and rules["words"].destinations == ["This Firewall", "This Firewall IPv6"]
    # A rule for IPv4 whose aliases hold addresses of both versions stays a rule for IPv4.
    assert rules["aliases of both versions"].sources == ["Servers IPv4"] and rules["aliases of both versions"].destinations == ["Inside"]
    assert p.address_groups["Servers IPv4"].members == ["10.0.2.10", "10.0.2.11"]
    assert rules["one side negated"].sources == ["Servers IPv6"] and rules["one side negated"].destinations == ["Private"]
    assert rules["both sides negated"].sources == ["Servers", "::/0"] and rules["both sides negated"].negate_source
    assert rules["one half is not there"].destinations == ["GUEST net"]
    assert codes(report, "one half is not there") == ["RULE_HALF_NOT_LOADED"]
    # Loaded by pfSense, and good for nothing there either: no IPv4 source has an IPv6 destination.
    assert rules["nothing of that version"].sources == ["Admins"] and rules["nothing of that version"].destinations == [ANY_V6]
    assert not any(n.code == "RULE_NOT_LOADED" for n in report.notes)


def test_without_allow_ipv6_nothing_of_ipv6_is_converted() -> None:
    p, report = read(NO_NAT, x(
        "filter", rule("lan", family="inet46", descr="both"), rule("lan", family="inet6", descr="six"), rule("lan", descr="four"),
    ), ipv6=False, blockpriv=True)  # fmt: skip
    assert [(r.name, r.sources) for r in p.rules][1:] == [("both", [ANY_V4]), ("four", [ANY_V4])]
    assert "fc00::/7" not in p.rules[0].sources and len(p.rules[0].sources) == 4
    note = next(n for n in report.notes if n.code == "IPV6_NOT_ALLOWED")
    assert "2 rules for IPv6 or for both IP versions were read for IPv4 only" in note.message
    assert not any(n.code == "RULE_NOT_LOADED" for n in report.notes)


def test_aliases_become_groups_and_services() -> None:
    aliases = x(
        "aliases",
        alias("Hosts", "host", "10.0.2.10", "www.example.com", "Printer", "2001:DB8::1"),
        alias("Nets", "network", "10.0.2.77/24", "Hosts", "single"),
        alias("List", "urltable", "https://lists.example.org/a.txt"),
        alias("Fetched", "url", "192.0.2.1", "192.0.2.9"),
        alias("ByHand", "host", "10.0.0.1-10.0.0.9"),
        alias("Odd", "host", "10.0.0.300"),
        alias("Mixed", "network", "Web"),
        alias("Strange", "geoip", "BE"),
        alias("Loop", "network", "Loop", "10.0.0.1"),
        alias("Empty", "host"),
        alias("Web", "port", "80", "443", "8000:8010"),
        alias("More", "port", "Web", "25", "8005"),
        alias("NoPorts", "port"),
        alias("Round", "port", "Round"),
        alias("Named", "port", "http"),
        alias("Table", "urltable_ports", "https://lists.example.org/p.txt"),
    )
    p, report = read(aliases, NO_NAT, x(
        "filter",
        rule("lan", dst="Nets", proto="tcp", dport="Web", descr="web"),
        rule("lan", proto="udp", dport="Web", descr="web over udp"),
        rule("lan", proto="tcp/udp", dport="More", sport="Web", descr="with source ports"),
        rule("lan", proto="tcp", dport="80:90", descr="colon"),
        rule("lan", proto="tcp", dport="1-65535", descr="every port"),
        rule("lan", proto="", dport="22", descr="no protocol"),
        *(rule("lan", proto="tcp", dport=name, descr=f"ports {name}") for name in ("NoPorts", "Round", "Named", "Table")),
    ))  # fmt: skip
    groups = p.address_groups
    assert groups["Hosts"].members == ["10.0.2.10", "www.example.com", "Printer", "2001:db8::1"]
    assert p.addresses["www.example.com"].kind == AddressKind.FQDN and p.addresses["Printer"].value == "printer"
    assert groups["Nets"].members == ["10.0.2.0/24", "Hosts", "single"] and groups["Fetched"].members == ["192.0.2.1", "192.0.2.9"]
    assert groups["List"].unsupported.startswith("a URL table") and groups["Strange"].unsupported == "an alias of type 'geoip', which FWShift does not know"
    assert groups["ByHand"].unsupported == "its entry '10.0.0.1-10.0.0.9' is neither an address nor a host name pfSense could resolve"
    assert "10.0.0.300" in groups["Odd"].unsupported and groups["Mixed"].unsupported == "its entry 'Web' is an alias of ports"
    assert groups["Loop"].members == ["Loop", "10.0.0.1"] and groups["Empty"].members == []
    rules = by_name(p)
    assert rules["web"].services == ["Web"] and p.services["Web"].entries == [ServiceEntry(Protocol.TCP, "80,443,8000-8010")]
    assert rules["web over udp"].services == ["Web-udp"] and p.services["Web-udp"].entries[0].protocol == Protocol.UDP
    service = p.services[rules["with source ports"].services[0]]
    assert [(e.protocol.value, e.dst_ports, e.src_ports) for e in service.entries] == [
        ("tcp", "80,443,8000-8010,25,8005", "80,443,8000-8010"), ("udp", "80,443,8000-8010,25,8005", "80,443,8000-8010")]  # fmt: skip
    assert p.services[rules["colon"].services[0]].entries[0].dst_ports == "80-90"
    assert p.services[rules["every port"].services[0]].entries == [ServiceEntry(Protocol.TCP)] and rules["every port"].services == ["tcp"]
    assert rules["no protocol"].services == ["tcp"]  # filter.inc: TCP, and no port where no protocol was given
    assert all(service.builtin == "pfsense" for service in p.services.values())
    message = next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")
    for text in ("alias 'NoPorts' is empty", "alias 'Round' holds itself"):
        assert text in message
    # A service name is a port to pf; a URL table of ports is something pfSense has and the configuration does not hold.
    assert p.services[rules["ports Named"].services[0]].entries[0].dst_ports == "80"
    assert rules["ports Table"].unsupported == ["alias 'Table' is a URL table of ports, which is not in the configuration"]
    cli.convert(p, "json", Report())  # a group that holds itself is made unusable, like everywhere


def test_what_a_rule_matches_besides_addresses_and_ports() -> None:
    p, report = read(NO_NAT, x(
        "filter",
        rule("lan", "reject", proto="esp", descr="esp", extra=x("log")),
        rule("lan", proto="igmp", descr="igmp"), rule("lan", proto="any", descr="word any"), rule("lan", proto="rdp", descr="unknown protocol"),
        rule("lan", proto="icmp", extra=x("icmptype", "toobig"), descr="type of the other version"),
        rule("lan", proto="icmp", extra=x("icmptype", "any"), descr="every type"),
        rule("lan", proto="icmp", family="inet6", extra=x("icmptype", "neighbrsol,neighbradv"), descr="neighbours"),
        rule("lan", proto="tcp", extra=x("os", "Windows"), descr="os"), rule("lan", extra=x("tagged", "VOICE"), descr="tagged"),
        rule("lan", extra=x("dscp", "af11") + x("vlanprio", "be"), descr="marks"), rule("lan", extra=x("vlanprio", "none"), descr="no priority"),
        rule("lan", proto="tcp", extra=x("tcpflags1", "syn") + x("tcpflags2", "syn,ack"), descr="flags"),
        rule("lan", extra=x("gateway", "WAN2GW") + x("tag", "OUT") + x("statetype", "<![CDATA[keep state]]>"), descr="routed"),
        rule("lan", extra=x("statetype", "none"), descr="stateless"), rule("lan", extra=x("sched", "Night"), descr="scheduled"),
        rule("lan", extra=x("nat", x("enable")), family="inet6", descr="nat64"),
        rule("lan", "match", extra=x("tag", "X"), descr="marks only", floating="in!"),
        rule("lan", descr=""), rule("lan", descr="twice"), rule("lan", descr="twice"),
        rule("lan", descr="R&amp;amp;D &lt;lab&gt;").replace("<![CDATA[", "").replace("]]>", ""),
        rule("lan", descr="R&amp;D in CDATA"),
    ))  # fmt: skip
    rules = by_name(p)
    assert rules["esp"].action == Action.RESET_CLIENT and rules["esp"].log_start and not rules["esp"].log_end
    assert p.services["esp"].entries == [ServiceEntry(Protocol.IP, ip_protocol=50)] and p.services["igmp"].entries[0].ip_protocol == 2
    assert rules["word any"].services == [ANY] and rules["unknown protocol"].unsupported == ["protocol 'rdp'"]
    assert rules["type of the other version"].unsupported == ["ICMP type 'toobig', which pf does not have for IPv4"]
    assert p.services["icmp"].entries == [ServiceEntry(Protocol.ICMP)] and rules["every type"].services == ["icmp"]
    assert [e.icmp_type for e in p.services[rules["neighbours"].services[0]].entries] == [135, 136]
    assert rules["os"].unsupported == ["it matches operating system of the sender (os) 'Windows'"]
    assert rules["tagged"].unsupported == ["it matches a mark set by another rule (tagged) 'VOICE'"]
    assert len(rules["marks"].unsupported) == 2 and not rules["no priority"].unsupported
    assert rules["flags"].unsupported == ["it matches TCP flags of its own (tcpflags) 'syn'", "it matches TCP flags of its own (tcpflags) 'syn,ack'"]
    assert rules["routed"].handling == {"gateway": "WAN2GW", "tag": "OUT"} and codes(report, "routed") == ["POLICY_ROUTING"]
    assert rules["stateless"].handling == {"statetype": "none"} and codes(report, "stateless") == ["STATELESS_RULE"]
    assert rules["scheduled"].schedule == "Night" and rules["nat64"].unsupported == ["it translates IPv6 to IPv4 (NAT64)"]
    assert "marks only" not in rules and "'marks only' is a rule of type 'match'" in next(n.message for n in report.notes if n.code == "MATCH_RULE_SKIPPED")
    assert rules["LAN rule 17"].description == "a pfSense rule without a description" and "twice 2" in rules
    assert "R&D <lab>" in rules and "R&D in CDATA" in rules


@pytest.mark.parametrize("version,expected", [("23.3", ["second group", "tunnel", "first group", "tab"]), ("24.0", ["first group", "second group", "tunnel", "tab"]),
                                               ("", ["first group", "second group", "tunnel", "tab"])])  # fmt: skip
def test_rules_of_groups_are_ordered_as_the_version_of_pfsense_orders_them(version: str, expected: List[str]) -> None:
    filter_section = x("filter", rule("lan", descr="tab"), rule("SERVED", "block", descr="second group"), rule("openvpn", descr="tunnel"),
                       rule("INSIDE", descr="first group"))  # fmt: skip
    p, report = read(GROUPS, NO_NAT, filter_section, x("openvpn", x("openvpn-server", x("vpnid", "1"))), version=version)
    assert [r.name for r in p.rules] == expected
    note = next(n for n in report.notes if n.code == "RULE_ORDER_VERSION")
    assert note.severity == Severity.REVIEW and ("in the order of the file" if version == "23.3" else "group by group") in note.message
    assert by_name(p)["tunnel"].src_zones == ["OpenVPN"] and p.zones["OpenVPN"].interfaces == []
    # Groups that share no interface: their order decides nothing, and nothing is said.
    apart = GROUPS.replace("opt1 opt2", "opt1")
    _, report = read(apart, NO_NAT, filter_section, x("openvpn", x("openvpn-server", x("vpnid", "1"))), version=version)
    assert not any(n.code == "RULE_ORDER_VERSION" for n in report.notes)
    # Without a tunnel pfSense has no interface for the rule.
    p, report = read(GROUPS, NO_NAT, filter_section, version=version)
    assert "tunnel" not in by_name(p) and "its interface 'openvpn' is not there" in next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")


def nats(p: Policy) -> dict:
    return {n.name: n for n in p.nat_rules}


def test_port_forwards_as_they_are_read() -> None:
    aliases = x("aliases", alias("Web", "port", "80", "443"), alias("Pool", "host", "10.0.2.10", "10.0.2.11"), alias("One", "host", "10.0.2.10"))
    p, report = read(aliases, VIPS, x(
        "nat", x("outbound", x("mode", "disabled")),
        forward(PUBLIC[0], "443", "10.0.2.10", descr="same port"),
        forward(PUBLIC[0], "8080", "10.0.2.10", "80", descr="other port"),
        forward(PUBLIC[0], "8000-8010", "10.0.2.10", descr="range to itself"),
        forward(PUBLIC[0], "9000-9010", "10.0.2.10", "7000", descr="range to another range"),
        forward(PUBLIC[1], "Web", "Pool", "Web", proto="tcp/udp", descr="alias of ports"),
        forward(PUBLIC[1], "Web", "One", "8443", descr="alias to one port"),
        forward("net:wanip", "25", "lanip", proto="tcp", src="!203.0.113.0/24", descr="words", link="pass"),
        forward(PUBLIC[2], "", "10.0.2.12", proto="gre", descr="a protocol"),
        forward(PUBLIC[2], "", "10.0.2.13", proto="any", descr="everything"),
        forward(PUBLIC[2], "53", "10.0.2.14", proto="udp", descr="not this one", extra=x("nordr")),
        forward(PUBLIC[2], "22", "10.0.2.15", descr="switched off", extra=x("disabled")),
        forward(PUBLIC[2], "23", "Gone", descr="target that is gone"),
        forward(PUBLIC[2], "24", "10.0.2.16", interface="opt9", descr="interface that is gone"),
        forward("2001:db8::1", "443", "2001:db8:2::10", descr="six").replace(x("ipprotocol", "inet"), x("ipprotocol", "inet6")),
    ))  # fmt: skip
    found = nats(p)
    same = found["same port"]
    assert (same.src_zones, same.dst_zones, same.sources, same.destinations, same.service) == (["WAN"], ["WAN"], [ANY_V4], [PUBLIC[0]], "tcp-443")
    assert same.destination_translation == DestNat("10.0.2.10") and same.combines and same.enabled and not same.unsupported
    assert found["other port"].destination_translation == DestNat("10.0.2.10", "80") and found["other port"].service == "tcp-8080"
    assert found["range to itself"].destination_translation == DestNat("10.0.2.10") and found["range to itself"].service == "tcp-8000-8010"
    assert found["range to another range"].unsupported == ["a range of ports translated to another range (9000-9010 to 7000-7010), which the model cannot say"]
    alias_rule = found["alias of ports"]
    assert alias_rule.service == "Web" and alias_rule.destination_translation == DestNat("Pool", spread=True)
    assert [e.protocol.value for e in p.services["Web"].entries] == ["tcp", "udp"]
    assert found["alias to one port"].unsupported == ["several ports (80,443) translated to the one port 8443"] and found["alias to one port"].service == "Web-tcp"
    words = found["words"]
    assert words.destinations == ["WAN address"] and words.destination_translation == DestNat("LAN address")
    assert words.unsupported == ["negated source in a NAT rule"]
    assert found["a protocol"].unsupported == ["NAT limited to protocol gre"] and found["everything"].service == ANY
    assert "exception from port forwarding only ('no rdr')" in found["not this one"].unsupported[0] and found["not this one"].destination_translation is None
    assert not found["switched off"].enabled and found["six"].unsupported == ["IPv6 NAT"]
    message = next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")
    assert "port forward 'target that is gone' (its target 'Gone' cannot be resolved)" in message
    assert "port forward 'interface that is gone' (its interface 'opt9' is not there or not enabled)" in message
    # The rule that stands for a forward that passes its own traffic: unusable where the forward is.
    passing = by_name(p)["words - pass"]
    assert passing.unsupported == ["negated source in a NAT rule"] and passing.src_zones == ["WAN"] and passing.services == ["tcp-25"]
    assert [f.severity for f in report.item("rule", "words - pass").findings if f.code == "AUTOMATIC_RULE"] == [Severity.APPROX]


@pytest.mark.parametrize("system,own,zones,code", [
    (x("disablenatreflection", "yes"), "", ["WAN"], ""),
    ("", "", ["WAN"], "NAT_REFLECTION_PROXY"),
    (x("enablenatreflectionpurenat", "yes"), "", ["WAN", "LAN", "DMZ", "GUEST"], "NAT_REFLECTION"),
    (x("disablenatreflection", "yes"), "purenat", ["WAN", "LAN", "DMZ", "GUEST"], "NAT_REFLECTION"),
    (x("enablenatreflectionpurenat", "yes"), "disable", ["WAN"], ""),
    (x("disablenatreflection", "yes"), "enable", ["WAN"], "NAT_REFLECTION_PROXY"),
])  # fmt: skip
def test_nat_reflection_puts_a_port_forward_on_the_inside_interfaces(system: str, own: str, zones: List[str], code: str) -> None:
    extra = x("natreflection", own) if own else ""
    text = '<?xml version="1.0"?>\n' + x("pfsense", x("version", "23.3"), x("system", system), interfaces_xml(),
                                         x("nat", forward(PUBLIC[0], "443", "10.0.2.10", descr="web", extra=extra)))  # fmt: skip
    p, report = parse(text)
    assert nats(p)["web"].src_zones == zones and nats(p)["web"].dst_zones == ["WAN"]
    assert [f.code for f in report.item("nat", "web").findings] == ([code] if code else [])


def test_one_to_one_nat_is_two_translations() -> None:
    p, report = read(x(
        "nat", x("outbound", x("mode", "disabled")),
        one_to_one(PUBLIC[0], "10.0.2.10", descr="host"),
        one_to_one("198.51.100.77", "10.0.2.64/26", descr="network"),
        one_to_one("wanip", "10.0.2.11", descr="address of the interface"),
        one_to_one(PUBLIC[1], "10.0.2.12", descr="not this one", extra=x("nobinat")),
        one_to_one(PUBLIC[1], "10.0.2.13", descr="reflected", extra=x("natreflection", "enable")),
        one_to_one(PUBLIC[2], "10.0.2.14", interface="opt9", descr="interface that is gone"),
        one_to_one("2001:db8::5", "2001:db8:2::15", descr="six"),
        x("npt", x("descr", "prefix")),
    ))  # fmt: skip
    found = nats(p)
    arriving, leaving = found["host - inbound"], found["host - outbound"]
    assert (arriving.src_zones, arriving.dst_zones, arriving.destinations, arriving.destination_translation) == (["WAN"], ["WAN"], [PUBLIC[0]], DestNat("10.0.2.10"))
    assert (leaving.src_zones, leaving.dst_zones, leaving.sources) == ([ANY], ["WAN"], ["10.0.2.10"])
    assert leaving.source_translation == SourceNat(SnatKind.STATIC, [PUBLIC[0]]) and arriving.combines and leaving.combines
    assert list(found)[:2] == ["host - inbound", "host - outbound"]
    assert found["network - inbound"].destinations == ["198.51.100.64/26"] and found["network - outbound"].source_translation.addresses == ["198.51.100.64/26"]
    assert found["address of the interface - inbound"].destinations == ["WAN address"]
    assert "exception from 1:1 NAT only ('no binat')" in found["not this one"].unsupported[0]
    assert found["reflected - inbound"].src_zones == ["WAN", "LAN", "DMZ", "GUEST"] and codes(report, "reflected - inbound", "nat") == ["NAT_REFLECTION"]
    assert "IPv6 NAT" in found["six"].unsupported
    assert "1:1 NAT rule 'interface that is gone'" in next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")
    assert "1 IPv6 prefix translation (NPt)" in next(n.message for n in report.notes if n.code == "NPT_NOT_CONVERTED")


def test_outbound_nat_of_every_version_and_mode() -> None:
    aliases = alias("Pool", "host", "198.51.100.20", "198.51.100.21") + alias("Ports", "port", "500", "4500")
    old = x("rule", x("source", x("network", "10.0.3.0/24")), x("sourceport"), x("descr", "as 2.6 wrote it"), x("target"),
            x("interface", "wan"), x("destination", x("address", "203.0.113.0/24"), x("not")), x("dstport", "8000:8010"), x("protocol", "tcp"))  # fmt: skip
    other = x("rule", x("source", x("network", "10.0.3.0/24")), x("descr", "other subnet"), x("target", "other-subnet"),
              x("targetip", "198.51.100.32"), x("targetip_subnet", "28"), x("interface", "wan"), x("destination", x("any")))  # fmt: skip
    rules = [
        outbound("10.0.1.0/24", descr="to the interface"), outbound("10.0.2.0/24", PUBLIC[0], descr="to a virtual address"),
        outbound("Admins2", "198.51.100.40", bits="32", descr="alias that is gone"),
        outbound("any", "198.51.100.48", "Partners", bits="29", descr="pool", extra=x("staticnatport")),
        outbound("(self)", "Pool", descr="alias as pool", extra=x("natport", "2000:3000")).replace(x("poolopts"), x("poolopts", "round-robin")),
        outbound("lan", PUBLIC[1], descr="network of an interface", extra=x("staticnatport")),
        outbound("10.0.1.0/24", "", "203.0.113.0/24", descr="exception", extra=x("nonat")),
        outbound("10.0.9.0/24", "198.51.100.64", bits="24", descr="bitmask").replace(x("poolopts"), x("poolopts", "bitmask")),
        outbound("10.0.1.0/24", descr="other interface", interface="opt9"), outbound("10.0.1.0/24", descr="off", extra=x("disabled")),
        outbound("10.0.1.0/24", descr="isakmp", extra=x("dstport", "Ports") + x("protocol", "udp") + x("staticnatport")),
        outbound("2001:db8:1::/64", descr="six"), old, other,
    ]
    p, report = read(ALIASES.replace("</aliases>", aliases + "</aliases>"), VIPS, x("nat", x("outbound", x("mode", "advanced"), *rules)))
    found = nats(p)
    first = found["to the interface"]
    assert (first.src_zones, first.dst_zones, first.sources, first.destinations, first.service) == ([ANY], ["WAN"], ["10.0.1.0/24"], [ANY_V4], ANY)
    assert first.source_translation == SourceNat(SnatKind.INTERFACE, interface="wan", interface_address="198.51.100.2") and first.combines
    assert found["to a virtual address"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, [PUBLIC[0]])
    pool = found["pool"]
    assert pool.sources == [ANY_V4] and pool.destinations == ["Partners"] and pool.source_translation == SourceNat(SnatKind.DYNAMIC, ["198.51.100.48/29"])
    assert found["alias as pool"].sources == ["This Firewall"] and found["alias as pool"].source_translation.addresses == ["Pool"]
    assert codes(report, "alias as pool", "nat") == ["NAT_SOURCE_PORT"]
    assert found["network of an interface"].sources == ["LAN net"] and codes(report, "network of an interface", "nat") == []
    assert found["network of an interface"].source_translation == SourceNat(SnatKind.DYNAMIC, [PUBLIC[1]])
    exception = found["exception"]
    assert exception.source_translation is None and exception.destination_translation is None and exception.destinations == ["203.0.113.0/24"]
    assert found["bitmask"].source_translation == SourceNat(SnatKind.STATIC, ["198.51.100.0/24"])
    assert not found["off"].enabled and found["six"].unsupported == ["IPv6 NAT"]
    assert found["isakmp"].service == "udp-500_4500" and codes(report, "isakmp", "nat") == ["NAT_STATIC_PORT"]
    old_rule = found["as 2.6 wrote it"]
    assert old_rule.source_translation.kind == SnatKind.INTERFACE and old_rule.destinations == ["203.0.113.0/24"]
    assert old_rule.unsupported == ["negated destination in a NAT rule"] and old_rule.service == "tcp-8000-8010"
    assert found["other subnet"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.32/28"])
    message = next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")
    assert "outbound NAT rule 'alias that is gone' (source: alias 'Admins2' cannot be resolved)" in message
    assert "outbound NAT rule 'other interface' (its interface 'opt9' is not there or not enabled)" in message
    # The modes: by hand, by itself, both, not at all; no word is "by itself".
    routes = x("gateways", x("gateway_item", x("interface", "lan"), x("name", "CORE")), x("gateway_item", x("interface", "wan"), x("name", "WANGW"))) + x(
        "staticroutes", x("route", x("network", "10.50.0.0/16"), x("gateway", "CORE")), x("route", x("network", "192.0.2.0/24"), x("gateway", "CORE")),
        x("route", x("network", "10.60.0.0/16"), x("gateway", "WANGW")), x("route", x("network", "10.70.0.0/16"), x("gateway", "CORE"), x("disabled")))  # fmt: skip
    for mode, expected in (("advanced", ["m"]), ("hybrid", ["m", "Automatic outbound NAT on WAN"]), ("automatic", ["Automatic outbound NAT on WAN"]),
                           ("", ["Automatic outbound NAT on WAN"]), ("disabled", [])):  # fmt: skip
        p, report = read(routes, x("nat", x("outbound", x("mode", mode) if mode else "", outbound("10.0.1.0/24", PUBLIC[0], descr="m"))), x("pppoes", x("pppoe", x("mode", "server"))))
        assert [n.name for n in p.nat_rules] == expected, mode
        if "Automatic outbound NAT on WAN" in expected:
            automatic = nats(p)["Automatic outbound NAT on WAN"]
            assert automatic.sources == ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.50.0.0/16"] and automatic.dst_zones == ["WAN"]
            assert automatic.source_translation == SourceNat(SnatKind.INTERFACE, interface="wan", interface_address="198.51.100.2")
            assert codes(report, automatic.name, "nat") == ["AUTOMATIC_RULE", "NAT_AUTOMATIC_SOURCES"]
    p, _ = read()  # no NAT in the file at all: automatic
    assert [n.name for n in p.nat_rules] == ["Automatic outbound NAT on WAN"]


def test_what_pfsense_does_by_itself_is_named() -> None:
    interfaces = interfaces_xml().replace(x("gateway", "WANGW"), x("gateway", "WANGW") + x("blockbogons"))
    p, report = read(x("bridges", x("bridged", x("members", "lan opt2"))), x("captiveportal", x("guests", x("enable"), x("interface", "opt2"))),
                     x("filter", rule("lan", descr="one")), interfaces=interfaces, system=x("disablefilter"))  # fmt: skip
    found = {n.code: n for n in report.notes}
    assert {"BOGONS_NOT_CONVERTED", "BRIDGE_NOT_CONVERTED", "CAPTIVE_PORTAL", "FILTER_DISABLED"} <= set(found)
    assert all(found[code].severity == Severity.REVIEW for code in ("BOGONS_NOT_CONVERTED", "BRIDGE_NOT_CONVERTED", "CAPTIVE_PORTAL", "FILTER_DISABLED"))
    assert "is set on WAN" in found["BOGONS_NOT_CONVERTED"].message and found["PFSENSE_AUTOMATIC_RULES"].severity == Severity.INFO
    assert "antispoof" in found["PFSENSE_AUTOMATIC_RULES"].message and "port 0" in found["PFSENSE_AUTOMATIC_RULES"].message
    _, report = read(x("filter", rule("lan", descr="one")))
    assert [n.code for n in report.notes] == ["PFSENSE_AUTOMATIC_RULES"]


@pytest.mark.parametrize("data,message", [
    (b"", "not well-formed XML"), (b"<pfsense>", "not well-formed XML"), (b"hello", "not well-formed XML"),
    (b'<!DOCTYPE pfsense [<!ENTITY a "b">]><pfsense/>', "DOCTYPE or entity declaration; the configuration files of pfSense never do"),
    (b"<opnsense><version>1</version></opnsense>", "configuration of an OPNsense firewall"),
    (b"<config><devices/></config>", "not a pfSense configuration: the first element is <config>"),
    (b"<pfsense><filter><rule><source><any/></source><source><any/></source><interface>lan</interface></rule></filter>"
     b"<interfaces><lan><enable/></lan></interfaces></pfsense>", "<source> occurs 2 times in one <rule>"),
    (b"<pfsense><interfaces/><interfaces/></pfsense>", "<interfaces> occurs 2 times"),
    (b"\xff\xfe<\x00p\x00", "not well-formed XML"),
])  # fmt: skip
def test_what_is_no_pfsense_configuration_is_refused_with_a_reason(data: bytes, message: str) -> None:
    with pytest.raises(ParseError, match=re.escape(message)):
        parse_pfsense.parse(data, Report())


def test_upper_case_elements_and_an_empty_configuration_are_read() -> None:
    p, report = parse("<PFSENSE><Version>23.3</Version></PFSENSE>")
    assert p.vendor == "pfsense" and not p.rules and not p.nat_rules and not p.zones
    text = config(x("FILTER", x("RULE", x("TYPE", "block"), x("Interface", "lan"), x("Source", x("ANY")), x("destination", x("any")), x("descr", "upper"))))
    p, _ = parse(text)
    assert [(r.name, r.action) for r in p.rules] == [("upper", Action.DROP)]


def test_a_broken_configuration_never_ends_in_a_traceback() -> None:
    """Bytes cut out, doubled and replaced at random, and elements taken out, doubled, moved and given other
    text: an answer or an error with a reason, nothing else."""
    import xml.etree.ElementTree as ET

    sample = (DATA / "pfsense_sample.xml").read_bytes()
    words = [b"<any></any>", b"<not></not>", b"opt9", b"lan,wan", b"::1", b"10.0.0.0/33", b"99999", b"1-0", b"&amp;", b"]]>", b"<x>", b"</rule>",
             b"<floating>yes</floating>", b"<direction>out</direction>", b"inet46", b"tcp/udp", b"\x00", b"<rule>", b"<source>", b"(self)", b"wanip",
             b"WebPorts", b"Private", b"any", b"", b"-1", b"0", b"65536", b"80:70", b"dhcp", b"track6", b"hybrid", b"pass", b"match", b"out"]  # fmt: skip
    rng = random.Random(8)
    read_fine = 0

    def attempt(data: bytes) -> int:
        try:
            policy = parse_pfsense.parse(data, Report())
            for target in ("pfsense", "panos", "asa", "json"):
                cli.convert(copy.deepcopy(policy), target, Report())
            return 1
        except FwshiftError:
            return 0

    for _ in range(300):
        data = bytearray(sample)
        for _ in range(rng.randint(1, 4)):
            start = rng.randrange(len(data))
            end = min(len(data), start + rng.choice([1, 3, 10, 40, 200]))
            action = rng.random()
            if action < 0.35:
                del data[start:end]
            elif action < 0.6:
                data[start:start] = data[start:end]
            else:
                data[start:end] = rng.choice(words)
        read_fine += attempt(bytes(data))
    assert read_fine > 10, read_fine
    read_fine = 0
    for _ in range(500):
        root = ET.fromstring(sample)
        for _ in range(rng.randint(1, 5)):
            parents = [node for node in root.iter() if len(node)]
            parent = rng.choice(parents)
            child = rng.choice(list(parent))
            action = rng.random()
            if action < 0.25:
                parent.remove(child)
            elif action < 0.45:
                parent.append(copy.deepcopy(child))
            elif action < 0.6:
                parent.remove(child)
                rng.choice(parents).append(child)
            else:
                leaf = rng.choice([node for node in root.iter() if not len(node)])
                leaf.text = rng.choice(words).decode("latin-1")
        read_fine += attempt(ET.tostring(root))
    assert read_fine > 250, read_fine


def test_the_format_is_detected() -> None:
    sample = (DATA / "pfsense_sample.xml").read_bytes()
    assert cli.detect_format(sample) == "pfsense"
    assert cli.detect_format(b'\xef\xbb\xbf<?xml version="1.0"?>\n<!-- a backup -->\n<pfsense>\n<version>23.3</version></pfsense>') == "pfsense"
    assert cli.detect_format(b"<PFSENSE><version>1</version></PFSENSE>") == "pfsense"
    assert cli.detect_format(b"<opnsense><version>1</version></opnsense>") == "pfsense"  # for the answer the parser has for it
    assert cli.detect_format((DATA / "panos_sample.xml").read_bytes()) == "panos" and cli.detect_format((DATA / "sophos_sample.xml").read_bytes()) == "sophos"
    assert cli.detect_format(b"<config><pfsense/></config>") == "panos"
    written = cli.convert(parse_pfsense.parse(sample, Report()), "pfsense", Report())
    assert cli.detect_format(written.encode()) == "pfsense"


# -- the emitter by hand ------------------------------------------------------------------------------

import xml.etree.ElementTree as ET  # noqa: E402

from fwshift.model import Address, AddressGroup, Rule, RuleScope, Service, ServiceGroup, Zone  # noqa: E402


def policy(*rules: Rule, zones: Sequence[str] = ("wan", "lan", "opt1"), vendor: str = "panos") -> Policy:
    p = Policy(vendor=vendor)
    for zone in zones:
        p.zones[zone] = Zone(zone)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32", "the web server")
    p.addresses["net"] = Address("net", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["span"] = Address("span", AddressKind.RANGE, "10.30.0.5-10.30.0.9")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8:1::/64")
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.address_groups["servers"] = AddressGroup("servers", ["web", "span", "10.20.0.64/26", "site"])
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["www"] = Service("www", [ServiceEntry(Protocol.TCP, "80,443,8000-8010")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8), ServiceEntry(Protocol.ICMP6, icmp_type=128)])
    p.service_groups["basics"] = ServiceGroup("basics", ["dns", "ping", "https"])
    for item in rules:
        item.origin = item.origin or item.name
        p.rules.append(item)
    return p


def allow(name: str, src: str = "lan", dst: str = ANY, **fields: object) -> Rule:
    item = Rule(name=name, src_zones=[src], dst_zones=[dst])
    for key, value in fields.items():
        setattr(item, key, value)
    return item


def emitted(p: Policy, options: Optional[Options] = None) -> Tuple[ET.Element, Report, str]:
    report = Report()
    text = cli.convert(p, "pfsense", report, options)
    return ET.fromstring(text), report, text


def shape(node: ET.Element) -> str:
    """A rule in one line: interface, action, IP version, protocol, source, destination."""
    def one(tag: str) -> str:
        part = node.find(tag)
        assert part is not None
        word = "any" if part.find("any") is not None else "net:" + (part.findtext("network") or "") if part.find("network") is not None else (part.findtext("address") or "")
        return ("!" if part.find("not") is not None else "") + word + (":" + (part.findtext("port") or "") if part.find("port") is not None else "")

    words = [node.findtext("interface"), node.findtext("type"), node.findtext("ipprotocol"), node.findtext("protocol") or "-", one("source"), one("destination")]
    if node.findtext("icmptype"):
        words.append(node.findtext("icmptype"))
    return " ".join(str(word) for word in words) + (" disabled" if node.find("disabled") is not None else "") + (" log" if node.find("log") is not None else "")


def shapes(root: ET.Element) -> List[str]:
    return [shape(node) for node in root.findall("filter/rule")]


def aliases_of(root: ET.Element) -> dict:
    return {node.findtext("name"): (node.findtext("type"), node.findtext("address")) for node in root.findall("aliases/alias")}


def test_a_rule_names_one_protocol_and_the_rest_is_aliases() -> None:
    root, report, text = emitted(policy(
        allow("one port", services=["https"]),
        allow("ports of a service", sources=["net"], destinations=["servers"], services=["www"]),
        allow("tcp and udp alike", services=["dns"]),
        allow("a group of services", destinations=["web", "10.20.0.11"], services=["basics"], action=Action.DROP, log_end=True),
        allow("ping", services=["ping"]),
        allow("everything", action=Action.RESET_BOTH, log_end=False),
    ))  # fmt: skip
    assert text.startswith('<?xml version="1.0"?>\n<!-- Generated by FWShift') and root.tag == "pfsense"
    assert shapes(root) == [
        "lan pass inet46 tcp any !net:(self):443 log",
        "lan pass inet tcp net servers:www_ports log",
        "lan pass inet46 tcp/udp any !net:(self):53 log",
        "lan block inet tcp any dst_a_group_of_services:ports_53_443 log", "lan block inet udp any dst_a_group_of_services:53 log",
        "lan block inet icmp any dst_a_group_of_services echoreq log",
        "lan pass inet46 icmp any !net:(self) echoreq log",
        "lan reject inet46 - any any",
    ]  # fmt: skip
    found = aliases_of(root)
    assert found["web"] == ("host", "10.20.0.10") and found["net"] == ("network", "10.10.0.0/16") and found["site"] == ("host", "www.example.com")
    assert found["span"] == ("network", "10.30.0.5 10.30.0.6/31 10.30.0.8/31") and found["six"] == ("network", "2001:db8:1::/64")
    assert found["servers"] == ("network", "web span 10.20.0.64/26 site")
    assert found["www_ports"] == ("port", "80 443 8000:8010") and found["dst_a_group_of_services"] == ("host", "web 10.20.0.11")
    assert codes(report, "a group of services") == ["RULE_SPLIT"] and codes(report, "everything") == ["RESET_ACTION"]
    assert report.item("rule", "a group of services").emitted_as == ["lan (3 rules)"] and report.item("rule", "one port").emitted_as == ["lan"]
    trackers = [node.findtext("tracker") for node in root.findall("filter/rule")]
    assert len(set(trackers)) == len(trackers) == 8 and all(2000000000 < int(t) < 4294967295 for t in trackers)  # type: ignore[arg-type]
    assert "<descr><![CDATA[ports of a service]]></descr>" in text and "<statetype><![CDATA[keep state]]></statetype>" in text
    note = next(n for n in report.notes if n.code == "PFSENSE_RESTORE")
    assert note.severity == Severity.REVIEW and "There is no NAT area in the file" in note.message and "replaces that area" in note.message
    assert root.find("nat") is None


def test_what_a_rule_of_pfsense_cannot_say_is_written_disabled() -> None:
    p = policy(
        allow("negated service", services=["https"], negate_service=True),
        allow("code", services=["unreach"]), allow("type without a name", services=["odd"]), allow("protocol without a name", services=["eigrp"]),
        allow("user", users=["alice"]), allow("category", url_categories=["news"]), allow("schedule", schedule="night"),
        allow("unknown application", applications=["no-such-app"], services=["application-default"]),
        allow("gone", sources=["missing"]), allow("placeholder", destinations=["holder"], action=Action.DENY),
        allow("fine", services=["tcp-and-gre"]),
    )
    p.services["unreach"] = Service("unreach", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=1)])
    p.services["odd"] = Service("odd", [ServiceEntry(Protocol.ICMP, icmp_type=99)])
    p.services["eigrp"] = Service("eigrp", [ServiceEntry(Protocol.IP, ip_protocol=88)])
    p.services["tcp-and-gre"] = Service("tcp-and-gre", [ServiceEntry(Protocol.IP, ip_protocol=6), ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.addresses["holder"] = Address("holder", AddressKind.UNSUPPORTED, "", raw="a region")
    root, report, text = emitted(p)
    by_descr = {node.findtext("descr"): shape(node) for node in root.findall("filter/rule")}
    # A negation that could not be written must not read as its opposite: such a rule gets a service that stands in.
    assert by_descr["FWSHIFT inactive, see the report: negated service"] == "lan pass inet46 tcp any !net:(self):1 disabled log"
    assert by_descr["FWSHIFT inactive, see the report: unknown application"] == "lan pass inet46 tcp any !net:(self):1 disabled log"
    for name, code in (("negated service", "SERVICE_NEGATE"), ("code", "ICMP_CODE"), ("type without a name", "ICMP_TYPE"),
                       ("protocol without a name", "PROTOCOL_NOT_AVAILABLE"), ("user", "USER_MATCH"), ("category", "URL_CATEGORY"),
                       ("schedule", "SCHEDULE"), ("unknown application", "APP_UNKNOWN"), ("gone", "UNCONVERTIBLE_OBJECT"),
                       ("placeholder", "UNCONVERTIBLE_OBJECT")):  # fmt: skip
        item = report.item("rule", name)
        assert item.disabled and code in [f.code for f in item.findings], (name, [f.code for f in item.findings])
        assert "disabled" in by_descr[f"FWSHIFT inactive, see the report: {name}"], name
    assert "NOT enforced until fixed" in report.item("rule", "placeholder").findings[-1].message
    found = aliases_of(root)
    assert found["holder"] == ("host", "192.0.0.8") and found["missing"] == ("host", "192.0.0.8")
    assert "FWSHIFT PLACEHOLDER, matches nothing: a region" in text
    assert shapes(root)[-2:] == ["lan pass inet46 gre any !net:(self) log", "lan pass inet46 tcp any !net:(self) log"]  # protocols 47 and 6 by their names


def test_ip_versions_of_a_rule() -> None:
    root, report, _ = emitted(policy(
        allow("four", sources=["net"]), allow("six", sources=["six"]), allow("both", sources=["net", "six"]),
        allow("neither", sources=["net"], destinations=["six"]),
        allow("not an address", sources=["10.0.0.1"], negate_source=True),
        allow("not a network", destinations=["net"], negate_destination=True),
        allow("not anything", sources=[ANY], negate_source=True),
        allow("host name", destinations=["site"]),
        allow("ping for IPv4", sources=["net"], services=["ping"]),
        allow("any of IPv4", sources=[ANY_V4]), allow("any of both", sources=[ANY_V4, ANY_V6]),
    ))  # fmt: skip
    assert shapes(root) == [
        "lan pass inet - net !net:(self) log", "lan pass inet6 - six !net:(self) log", "lan pass inet46 - src_both !net:(self) log",
        "lan pass inet46 - !src_not_an_address !net:(self) log", "lan pass inet46 - any !net log",
        "lan pass inet46 - any site log", "lan pass inet icmp net !net:(self) echoreq log",
        "lan pass inet - any !net:(self) log", "lan pass inet46 - any !net:(self) log",
    ]  # fmt: skip
    assert aliases_of(root)["src_not_an_address"] == ("host", "10.0.0.1")
    for name in ("neither", "not anything"):
        assert report.item("rule", name).skipped and codes(report, name) == ["NO_COMMON_FAMILY"]


def test_names_pfsense_would_refuse_or_take_for_something_else() -> None:
    services = ["ssh", "http", "MyPorts", "x" * 40, "lower_case"]
    p = policy(allow("r", sources=["all", "LAN", "123", "tcp", "ssh", "_x", "a-b c", "pkg_one", "lan__network", "x" * 40, "ALL"]),
               *(allow(f"r{number}", services=[name]) for number, name in enumerate(services)))  # fmt: skip
    for name in ("all", "LAN", "123", "tcp", "ssh", "_x", "a-b c", "pkg_one", "lan__network", "x" * 40, "ALL"):
        p.addresses[name] = Address(name, AddressKind.NETWORK, f"10.1.{len(p.addresses)}.0/24")
    for name in ("ssh", "http", "MyPorts", "x" * 40, "lower_case"):
        p.services[name] = Service(name, [ServiceEntry(Protocol.TCP, f"{2000 + len(p.services)},{3000 + len(p.services)}")])
    root, report, _ = emitted(p)
    names = set(aliases_of(root))
    assert {"all_2", "LAN_2", "123_2", "tcp_2", "ssh_2", "x_x", "a_b_c", "pkg_one_2", "lan__network_2", "x" * 31, "ALL_2"} <= names, sorted(names)
    assert not names & {"all", "LAN", "123", "tcp", "ssh", "_x", "pkg_one", "lan__network", "ALL", "http"}
    # An alias of ports must not be a word pfSense could take for a service: an upper-case letter or an underscore tells.
    ports = {name for name, (kind, _) in aliases_of(root).items() if kind == "port"}
    assert ports == {"ssh_ports", "http_ports", "MyPorts", "x" * 20 + "_ports", "lower_case"}, ports
    assert all(len(name) <= 31 and re.fullmatch(r"[A-Za-z0-9_]+", name) for name in names)
    assert "renamed to 'all_2'" in report.item("address", "all").findings[0].message
    # Names that come from a pfSense are names it takes.
    native = Policy(vendor="pfsense")
    native.zones["LAN"] = Zone("LAN", ["lan"])
    native.address_groups["Web"] = AddressGroup("Web", ["10.0.0.1"])
    native.rules.append(Rule(name="r", origin="r", src_zones=["LAN"], sources=["Web"]))
    root, _, _ = emitted(native)
    assert set(aliases_of(root)) == {"Web"}


def test_text_is_written_the_way_pfsense_reads_it() -> None:
    p = policy(allow('R&D <lab> "one" ]]> two', description="  more\ttext\x07\n here  "))
    p.addresses["web"].description = "a & b"
    root, _, text = emitted(p)
    assert "<descr><![CDATA[R&amp;D &lt;lab&gt; &quot;one&quot; ]]&gt; two: more text here]]></descr>" in text
    assert "<descr><![CDATA[a &amp; b]]></descr>" in text
    judge = restored(text)
    back, _ = parse(ET.tostring(judge.root, encoding="unicode"))
    assert back.rules[0].name == 'R&D <lab> "one" ]]> two: more text here' and back.address_groups["web"].description == "a & b"


def test_zones_become_interfaces() -> None:
    p = policy(
        allow("mapped by name", src="inside"), allow("mapped by interface", src="dmz"), allow("two interfaces", src="branch"),
        allow("a name of its own", src="Partner_Net"), allow("no name pfSense takes", src="guest-net"), allow("every zone", src=ANY),
        allow("several zones", src_zones=["inside", "dmz"]), allow("tunnel", src="vpn"),
        zones=("inside", "dmz", "branch", "Partner_Net", "guest-net", "vpn"),
    )
    p.zones["dmz"].interfaces = ["ethernet1/3"]
    p.zones["branch"].interfaces = ["ethernet1/4", "ethernet1/5"]
    options = Options(zone_map={"inside": "lan", "vpn": "enc0"}, interface_map={"ethernet1/3": "opt1", "ethernet1/4": "opt2", "ethernet1/5": "opt3"})
    root, report, _ = emitted(p, options)
    found: dict = {}
    for node in root.findall("filter/rule"):
        found.setdefault(node.findtext("descr"), []).append(node.findtext("interface"))
    assert found["mapped by name"] == ["lan"] and found["mapped by interface"] == ["opt1"] and found["two interfaces"] == ["opt2", "opt3"]
    assert found["a name of its own"] == ["Partner_Net"] and found["several zones"] == ["lan", "opt1"] and found["tunnel"] == ["enc0"]
    assert found["every zone"] == ["lan", "opt1", "opt2", "opt3", "Partner_Net", "enc0"]
    assert "FWSHIFT inactive, see the report: no name pfSense takes" not in found  # nowhere to write it
    item = report.item("rule", "no name pfSense takes")
    assert item.disabled and "'guest-net' is no interface a rule of pfSense can name" in item.findings[0].message
    assert "and not for guest-net" in next(n.message for n in report.notes if n.code == "INTERFACE_NAME")
    note = next(n for n in report.notes if n.code == "INTERFACES_REQUIRED")
    assert note.message.endswith("create an interface group of that name on the firewall: Partner_Net") and note.severity == Severity.REVIEW
    with pytest.raises(FwshiftError, match="--target-nat-zone: 'out-side' is no interface a pfSense rule can name"):
        emitted(p, Options(nat_zone="out-side"))


def test_destination_zones_are_kept_by_the_networks_behind_them() -> None:
    networks = {"wan": ["0.0.0.0/0", "::/0"], "lan": ["10.10.0.0/16", "2001:db8:1::/64"], "opt1": ["10.20.0.0/16"]}
    p = policy(
        allow("to the internet", dst="wan"), allow("to a server", dst="opt1", destinations=["web"]),
        allow("server in another zone", dst="wan", destinations=["web"]),
        allow("deny to the dmz", dst="opt1", action=Action.DENY), allow("inside the zone", scope=RuleScope.INTRAZONE),
        allow("anywhere else", scope=RuleScope.INTERZONE),
    )
    root, report, _ = emitted(p, Options(zone_networks=networks))
    by_descr = {node.findtext("descr"): shape(node) for node in root.findall("filter/rule")}
    found = aliases_of(root)
    assert by_descr["to the internet"] == "lan pass inet46 - any dst_to_the_internet log"
    kept = found["dst_to_the_internet"][1].split()
    assert "10.0.0.0/13" in kept and "10.10.0.0/16" not in kept and "10.20.0.0/16" not in kept and "2001:db8:1::/64" not in kept
    assert by_descr["to a server"] == "lan pass inet - any web log" and codes(report, "to a server") == []
    assert report.item("rule", "server in another zone").skipped and codes(report, "server in another zone") == ["EGRESS_BY_NETWORKS", "EGRESS_NO_ADDRESS"]
    assert by_descr["deny to the dmz"] == "lan block inet - any dst_deny_to_the_dmz log" and found["dst_deny_to_the_dmz"] == ("network", "10.20.0.0/16")
    assert by_descr["inside the zone"] == "lan pass inet46 - any dst_inside_the_zone log"
    assert found["dst_inside_the_zone"] == ("network", "10.10.0.0/16 2001:db8:1::/64")
    assert by_descr["anywhere else"].startswith("lan pass inet46 - any dst_anywhere_else") and "10.10.0.0/16" not in found["dst_anywhere_else"][1]
    # Without the networks: a rule to any address of a zone cannot be written, a rule to named addresses says what it is.
    root, report, _ = emitted(p)
    by_descr = {node.findtext("descr"): shape(node) for node in root.findall("filter/rule")}
    assert by_descr["FWSHIFT inactive, see the report: to the internet"] == "lan pass inet46 tcp any !net:(self):1 disabled log"
    assert "name the networks behind lan, opt1, wan with --zone-network" in report.item("rule", "to the internet").findings[0].message
    assert by_descr["to a server"] == "lan pass inet - any web log"
    assert [(f.code, f.severity) for f in report.item("rule", "to a server").findings] == [("EGRESS_INTERFACE", Severity.APPROX)]
    _, report, _ = emitted(p, Options(zone_networks={"wan": ["0.0.0.0/0"], "lan": ["10.10.0.0/16"], "opt1": ["10.20.0.0/16"], "opt7": ["10.70.0.0/16"]}))
    assert "names zones the policy does not know: opt7" in next(n.message for n in report.notes if n.code == "ZONE_NETWORK_UNKNOWN")


def test_what_blocks_traffic_that_leaves_is_a_floating_rule() -> None:
    p = policy(
        allow("nothing to the sinkhole", src=ANY, dst="wan", destinations=["203.0.113.0/24"], action=Action.DROP),
        allow("nothing of them out", src=ANY, src_zones=[ANY], dst_zones=["wan", "opt1"], sources=["net"], action=Action.DENY),
        allow("first rule that passes"),
        allow("too late for a floating rule", src=ANY, dst="wan", destinations=["198.51.100.0/24"], action=Action.DROP),
    )
    # The file sets outbound NAT (here: off, as only a destination is translated), so what leaves keeps its source.
    p.nat_rules.append(NatRule(name="in", origin="in", src_zones=["wan"], destinations=["192.0.2.10"], service="https", destination_translation=DestNat("web")))
    root, report, _ = emitted(p)
    assert root.findtext("nat/outbound/mode") == "disabled"
    nodes = root.findall("filter/rule")
    assert [(n.findtext("descr"), n.findtext("floating"), n.findtext("direction"), n.findtext("quick")) for n in nodes[:2]] == [
        ("nothing to the sinkhole", "yes", "out", "yes"), ("nothing of them out", "yes", "out", "yes")]  # fmt: skip
    assert shape(nodes[0]) == "wan block inet - any 203.0.113.0/24 log" and shape(nodes[1]) == "wan,opt1 block inet - net any log"
    assert report.item("rule", "nothing to the sinkhole").emitted_as == ["floating rule for what leaves by wan"]
    assert all(node.find("floating") is None for node in nodes[2:])
    late = [shape(node) for node in nodes if node.findtext("descr") == "too late for a floating rule"]
    assert late == [f"{key} block inet - any 198.51.100.0/24 log" for key in ("wan", "lan", "opt1")]
    assert [f.code for f in report.item("rule", "too late for a floating rule").findings] == ["EGRESS_INTERFACE"]
    # A rule for what leaves sees the source after outbound NAT: where the source is translated it is no floating rule.
    p.nat_rules.append(NatRule(name="out", origin="out", dst_zones=["wan"], sources=["net"], source_translation=SourceNat(SnatKind.INTERFACE, interface="wan")))
    root, report, _ = emitted(p)
    floating = [node.findtext("descr") for node in root.findall("filter/rule") if node.find("floating") is not None]
    assert floating == ["nothing to the sinkhole"]
    # Without a NAT area the firewall keeps its own outbound NAT, automatic on an interface with a gateway: a floating
    # rule that names a source is said to be one, and with the networks of every zone it is none.
    p.nat_rules.clear()
    root, report, _ = emitted(p)
    floating = [node.findtext("descr") for node in root.findall("filter/rule") if node.find("floating") is not None]
    assert floating == ["nothing to the sinkhole", "nothing of them out"] and root.find("nat") is None
    assert codes(report, "nothing of them out") == ["FLOATING_AFTER_NAT"]
    networks = {"wan": ["0.0.0.0/0", "::/0"], "lan": ["10.10.0.0/16"], "opt1": ["10.20.0.0/16"]}
    root, report, _ = emitted(p, Options(zone_networks=networks))
    floating = [node.findtext("descr") for node in root.findall("filter/rule") if node.find("floating") is not None]
    assert floating == ["nothing to the sinkhole"] and "FLOATING_AFTER_NAT" not in codes(report, "nothing of them out")


def test_defaults_of_the_source_are_said() -> None:
    p = policy(allow("one"))
    p.default_interzone = Action.ALLOW
    root, report, _ = emitted(p)
    added = [shape(node) for node in root.findall("filter/rule") if (node.findtext("descr") or "").startswith("FWSHIFT: the source accepts")]
    assert added == ["wan pass inet46 - any any", "lan pass inet46 - any any", "opt1 pass inet46 - any any"]
    assert shapes(root)[-1] == added[-1] and shapes(root)[1:3] == ["lan pass inet46 - any !net:(self) log", added[1]]  # at the end of every tab
    assert [n.code for n in report.notes if n.severity == Severity.REVIEW] == ["PFSENSE_RESTORE", "INTERZONE_DEFAULT"]
    p = policy(allow("one"))
    p.default_intrazone = Action.ALLOW
    _, report, _ = emitted(p)
    assert "INTRAZONE_DEFAULT" in [n.code for n in report.notes]
    p = policy(allow("one"))
    p.zones["lan"].intrazone_allow = True
    _, report, _ = emitted(p)
    assert "these zones allow traffic between their own interfaces" in next(n.message for n in report.notes if n.code == "INTRAZONE_ALLOW")
    root, report, text = emitted(Policy(vendor="panos"))
    assert root.findall("filter") and not root.findall("filter/rule") and root.find("aliases") is None


def nat_policy(*rules: NatRule) -> Policy:
    p = policy(zones=("wan", "lan", "opt1"))
    p.addresses["vip"] = Address("vip", AddressKind.NETWORK, "198.51.100.10/32")
    p.addresses["pool"] = Address("pool", AddressKind.RANGE, "198.51.100.21-198.51.100.23")
    for nat in rules:
        nat.origin = nat.name
        p.nat_rules.append(nat)
    return p


def nat_shapes(root: ET.Element) -> List[str]:
    out: List[str] = []
    for node in root.findall("nat/rule"):
        out.append(f"forward {node.findtext('interface')} {node.findtext('protocol')} {shape_side(node, 'source')} > {shape_side(node, 'destination')} "
                   f"-> {node.findtext('target')}:{node.findtext('local-port') or ''}" + (" disabled" if node.find("disabled") is not None else ""))  # fmt: skip
    for node in root.findall("nat/onetoone"):
        out.append(f"1:1 {node.findtext('interface')} {shape_side(node, 'source')} <> {node.findtext('external')} for {shape_side(node, 'destination')}")
    for node in root.findall("nat/outbound/rule"):
        extra = "".join(f" {tag}" for tag in ("nonat", "staticnatport", "disabled") if node.find(tag) is not None)
        target = (node.findtext("target") or "") + ("/" + (node.findtext("target_subnet") or "") if node.findtext("target_subnet") else "")
        ports = "".join(f" {tag}={node.findtext(tag)}" for tag in ("protocol", "sourceport", "dstport", "poolopts") if node.findtext(tag))
        where = node.find("destination")
        assert where is not None
        out.append(f"outbound {node.findtext('interface')} {node.findtext('source/network')} > "
                   f"{'any' if where.find('any') is not None else where.findtext('network')} -> {target}{ports}{extra}")  # fmt: skip
    return out


def shape_side(node: ET.Element, tag: str) -> str:
    part = node.find(tag)
    assert part is not None
    word = "any" if part.find("any") is not None else part.findtext("network") or part.findtext("address") or ""
    return word + (":" + (part.findtext("port") or "") if part.find("port") is not None else "")


def test_nat_rules_as_pfsense_has_them() -> None:
    p = nat_policy(
        NatRule(name="web", src_zones=["wan"], destinations=["vip"], service="www", destination_translation=DestNat("web")),
        NatRule(name="other port", src_zones=["wan", "lan"], destinations=["vip"], service="https", destination_translation=DestNat("10.20.0.11", "8443")),
        NatRule(name="everything", dst_zones=["wan"], destinations=["198.51.100.12"], destination_translation=DestNat("10.20.0.12")),
        NatRule(name="static", dst_zones=["wan"], sources=["web"], source_translation=SourceNat(SnatKind.STATIC, ["198.51.100.11"], bidirectional=True)),
        NatRule(name="static network", src_zones=["opt1"], dst_zones=["wan"], sources=["10.20.4.0/24"],
                source_translation=SourceNat(SnatKind.STATIC, ["198.51.104.0/24"], bidirectional=True)),
        NatRule(name="exception", dst_zones=["wan"], sources=["net"], destinations=["203.0.113.0/24"]),
        NatRule(name="hide", src_zones=["lan"], dst_zones=["wan"], sources=["net"], source_translation=SourceNat(SnatKind.INTERFACE, interface="ethernet1/1")),
        NatRule(name="hide behind one", dst_zones=["wan"], sources=["net", "10.30.0.0/24"], service="dns",
                source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["vip"])),
        NatRule(name="pool", dst_zones=["wan"], sources=[ANY], source_translation=SourceNat(SnatKind.DYNAMIC, ["198.51.100.32/28"]), enabled=False),
        NatRule(name="short list", dst_zones=["wan"], sources=["net"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool"])),
        NatRule(name="one way static", dst_zones=["wan"], sources=["10.20.5.0/24"], source_translation=SourceNat(SnatKind.STATIC, ["198.51.105.0/24"])),
    )  # fmt: skip
    root, report, _ = emitted(p)
    assert root.findtext("nat/outbound/mode") == "advanced"
    assert nat_shapes(root) == [
        "forward wan tcp any > vip:80 -> 10.20.0.10:80", "forward wan tcp any > vip:443 -> 10.20.0.10:443", "forward wan tcp any > vip:8000-8010 -> 10.20.0.10:8000",
        "forward wan tcp any > vip:443 -> 10.20.0.11:8443", "forward lan tcp any > vip:443 -> 10.20.0.11:8443",
        "forward wan any any > 198.51.100.12 -> 10.20.0.12:",
        "1:1 wan 10.20.0.10 <> 198.51.100.11 for any", "1:1 wan 10.20.4.0/24 <> 198.51.104.0 for any",
        "outbound wan net > 203.0.113.0/24 ->  nonat",
        "outbound wan net > any -> wanip",
        "outbound wan nat_src_hide_behind_one > any -> 198.51.100.10/32 protocol=tcp/udp dstport=53",
        "outbound wan any > any -> 198.51.100.32/28 staticnatport disabled",
        "outbound wan net > any -> nat_pool_short_list poolopts=round-robin",
        "outbound wan 10.20.5.0/24 > any -> 198.51.105.0/24 poolopts=bitmask staticnatport",
    ]  # fmt: skip
    assert all(node.findtext("natreflection") == "disable" and node.findtext("associated-rule-id") == "" for node in root.findall("nat/rule"))
    assert aliases_of(root)["nat_pool_short_list"] == ("host", "198.51.100.21 198.51.100.22 198.51.100.23")
    assert report.item("nat", "web").emitted_as == ["3 port forwards"] and report.item("nat", "static").emitted_as == ["1:1 NAT"]
    assert [(f.code, f.severity) for f in report.item("nat", "hide").findings][0] == ("NAT_INPUT_INTERFACE", Severity.APPROX)
    assert codes(report, "everything", "nat")[0] == "NAT_INPUT_INTERFACE" and codes(report, "pool", "nat")[:2] == ["NAT_STATIC_PORT", "NAT_DISABLED"]
    assert codes(report, "static network", "nat")[0] == "NAT_INPUT_INTERFACE"
    # The source had one rule per connection, pfSense one of each direction: what that changes is said rule by rule.
    assert "NAT_ORDER" in codes(report, "everything", "nat")
    note = next(n for n in report.notes if n.code == "PFSENSE_RESTORE")
    assert "The NAT area holds 6 port forwards and 2 1:1 rules, and sets outbound NAT to manual mode with the 6 rules of the source" in note.message
    # Only destinations are translated: outbound NAT is switched off, as on the source.
    root, report, _ = emitted(nat_policy(NatRule(name="web", src_zones=["wan"], destinations=["vip"], service="https", destination_translation=DestNat("web"))))
    assert root.findtext("nat/outbound/mode") == "disabled" and "switches outbound NAT off" in next(n.message for n in report.notes if n.code == "PFSENSE_RESTORE")


@pytest.mark.parametrize("nat,code,text", [
    (NatRule(name="n", src_zones=["wan"], destinations=["vip"], service="https", destination_translation=DestNat("net")), "NAT_DESTINATION", "one IPv4 address"),
    (NatRule(name="n", src_zones=["wan"], destinations=["vip"], destination_translation=DestNat("web", "80")), "NAT_PORT", "a port translation needs"),
    (NatRule(name="n", src_zones=["wan"], destinations=["vip"], service="www", destination_translation=DestNat("web", "80")), "NAT_PORT", "ports 8000-8010 translated to the one port 80"),
    (NatRule(name="n", src_zones=["wan"], destinations=["vip"], service="ping", destination_translation=DestNat("web")), "NAT_SERVICE", "not a TCP, UDP or SCTP service"),
    (NatRule(name="n", src_zones=["wan"], destinations=["site"], service="https", destination_translation=DestNat("web")), "NAT_ADDRESSES", "static IPv4 addresses"),
    (NatRule(name="n", destinations=["vip"], service="https", destination_translation=DestNat("web")), "", ""),
    (NatRule(name="n", sources=["net"], source_translation=SourceNat(SnatKind.INTERFACE)), "NAT_INTERFACE", "names no zone its traffic leaves by"),
    (NatRule(name="n", dst_zones=["wan"], sources=["six"], source_translation=SourceNat(SnatKind.INTERFACE)), "NAT_IPV6", "IPv4 only"),
    (NatRule(name="n", dst_zones=["wan"], sources=["net"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["site"])), "NAT_POOL", "translated source"),
    (NatRule(name="n", dst_zones=["wan"], sources=["net"], source_translation=SourceNat(SnatKind.STATIC, ["198.51.100.0/24"], bidirectional=True)), "NAT_BIDIRECTIONAL", "same size"),
    (NatRule(name="n", dst_zones=["wan"], sources=["web"], service="https", source_translation=SourceNat(SnatKind.STATIC, ["vip"], bidirectional=True)), "NAT_BIDIRECTIONAL", "for every service"),
    (NatRule(name="n", dst_zones=["wan"], sources=["net"], unsupported=["something"]), "NAT_NOT_CONVERTED", "not converted: something"),
    (NatRule(name="n", dst_zones=["guest-net"], sources=["net"], source_translation=SourceNat(SnatKind.INTERFACE)), "NAT_INTERFACE", "'guest-net' is no interface"),
])  # fmt: skip
def test_nat_rules_pfsense_cannot_have_are_left_out(nat: NatRule, code: str, text: str) -> None:
    root, report, _ = emitted(nat_policy(nat))
    item = report.item("nat", "n")
    if not code:
        # A port forward for traffic from every zone: on every interface there is.
        assert not item.skipped and [node.findtext("interface") for node in root.findall("nat/rule")] == ["wan", "lan", "opt1"]
        return
    assert item.skipped and [f.code for f in item.findings] == [code] and text in item.findings[0].message, [f.message for f in item.findings]
    assert root.find("nat") is None and "There is no NAT area in the file" in next(n.message for n in report.notes if n.code == "PFSENSE_RESTORE")


def test_a_rule_that_translates_source_and_destination_is_two_rules() -> None:
    twice = NatRule(name="twice", src_zones=["wan"], dst_zones=["wan"], sources=["203.0.113.0/24"], destinations=["vip"], service="https",
                    source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]), destination_translation=DestNat("web", "8443"))  # fmt: skip
    root, report, _ = emitted(nat_policy(twice))
    assert nat_shapes(root) == [
        "forward wan tcp 203.0.113.0/24 > vip:443 -> 10.20.0.10:8443",
        "outbound lan 203.0.113.0/24 > 10.20.0.10/32 -> 10.20.0.1/32 protocol=tcp dstport=8443",
        "outbound opt1 203.0.113.0/24 > 10.20.0.10/32 -> 10.20.0.1/32 protocol=tcp dstport=8443",
    ]  # fmt: skip
    assert codes(report, "twice", "nat") == ["NAT_OUTPUT_INTERFACE", "NAT_INPUT_INTERFACE", "NAT_AFTER_DNAT"]
    root, report, _ = emitted(nat_policy(twice), Options(nat_zone="opt1"))
    assert [shape for shape in nat_shapes(root) if shape.startswith("outbound")] == ["outbound opt1 203.0.113.0/24 > 10.20.0.10/32 -> 10.20.0.1/32 protocol=tcp dstport=8443"]


def test_rules_are_written_for_the_translated_destination() -> None:
    """pfSense looks its rules up after a port forward: what a rule of the model says of the original address,
    the written rule says of the translated one, and the firewall decides as the model does."""
    p = nat_policy(
        NatRule(name="web", src_zones=["wan"], dst_zones=["wan"], destinations=["vip"], service="https", destination_translation=DestNat("web")),
        NatRule(name="mail", src_zones=["wan"], dst_zones=["wan"], destinations=["198.51.100.11"], service="smtp", destination_translation=DestNat("10.20.0.25")),
        NatRule(name="out", dst_zones=["wan"], sources=["net"],
                source_translation=SourceNat(SnatKind.INTERFACE, interface="wan", interface_address="198.51.100.2")),
    )
    p.services["smtp"] = Service("smtp", [ServiceEntry(Protocol.TCP, "25")])
    for item in (allow("to the web server", src="wan", destinations=["vip"], services=["https"]),
                 allow("to the mail server", src="wan", destinations=["198.51.100.11", "10.20.0.25"], services=["smtp"]),
                 allow("out", sources=["net"])):  # fmt: skip
        item.origin = item.name
        p.rules.append(item)
    root, report, text = emitted(p)
    assert shapes(root) == ["wan pass inet tcp any web:443 log", "wan pass inet tcp any 10.20.0.25:25 log", "lan pass inet - net !net:(self) log"]
    assert codes(report, "to the web server") == ["NAT_DESTINATION_REWRITTEN"]
    interfaces = x("interfaces", *(x(key, x("enable"), x("descr", key), x("ipaddr", address), x("subnet", "24")) for key, address in
                                   (("wan", "198.51.100.2"), ("lan", "10.10.0.1"), ("opt1", "10.20.0.1"))))  # fmt: skip
    judge = PfSense(config(interfaces=interfaces))
    judge.restore(text)
    for pkt, verdict, moved in (
        (Packet("wan", "opt1", "203.0.113.9", "198.51.100.10", "tcp", 1024, 443), True, ("Original", "10.20.0.10", "Original")),
        (Packet("wan", "opt1", "203.0.113.9", "198.51.100.10", "tcp", 1024, 80), False, ("Original", "Original", "Original")),
        (Packet("wan", "opt1", "203.0.113.9", "198.51.100.11", "tcp", 1024, 25), True, ("Original", "10.20.0.25", "Original")),
        (Packet("lan", "wan", "10.10.3.3", "203.0.113.9", "udp", 1024, 53), True, ("198.51.100.2", "Original", "Original")),
        (Packet("opt1", "wan", "10.20.0.10", "203.0.113.9", "udp", 1024, 53), False, ("Original", "Original", "Original")),
    ):  # fmt: skip
        assert judge.allows(pkt) == verdict == model_allows(p, pkt), pkt
        assert judge.translation(pkt) == moved == model_translation(p, pkt), pkt


def test_what_the_firewall_itself_is_stays_a_word_of_pfsense() -> None:
    interfaces = interfaces_xml().replace(x("ipaddr", "198.51.100.2") + x("subnet", "24"), x("ipaddr", "dhcp"))
    text = config(GROUPS, ALIASES, NO_NAT, x(
        "filter",
        rule("lan", src="net:lan", dst="net:wanip", family="inet46", descr="to the outside address"),
        rule("lan", dst="net:(self)", proto="udp", dport="53", family="inet46", descr="to the firewall"),
        rule("lan", src="net:INSIDE", dst="net:opt1", descr="group to a network"),
        rule("opt1", src="net:wan", descr="from the wan network"),
    ), interfaces=interfaces)  # fmt: skip
    p, report = parse(text)
    root = ET.fromstring(cli.convert(p, "pfsense", report))
    # (The rule for the firewall itself comes back as one rule per IP version: only the IPv6 addresses are all known.)
    assert shapes(root) == [
        "lan pass inet - net:lan net:wanip", "lan pass inet udp any net:(self):53", "lan pass inet6 udp any net:(self):53",
        "lan pass inet - INSIDE_net net:opt1", "opt1 pass inet - net:wan any",
    ]  # fmt: skip
    assert not report.item("rule", "to the outside address").disabled and not any(i.disabled for i in report.items.values())
    assert aliases_of(root)["INSIDE_net"] == ("network", "10.0.1.0/24 10.0.3.0/24") and "WAN_address" not in aliases_of(root)
    assert codes(report, "to the outside address") == ["RULE_HALF_NOT_LOADED"]
    # For another platform the address is needed: the rule is unusable, and says which option gives it.
    report = Report()
    cli.convert(parse(text)[0], "panos", report)
    item = report.item("rule", "to the outside address")
    assert item.disabled and "give it with --interface-address" in item.findings[-1].message
    # A zone that is renamed takes its words along.
    root = ET.fromstring(cli.convert(parse(text)[0], "pfsense", Report(), Options(zone_map={"LAN": "opt5", "WAN": "opt6"})))
    assert shapes(root)[0] == "opt5 pass inet - net:opt5 net:opt6ip"


# -- what the review of version 0.8.0 found -----------------------------------------------------------


def test_ports_named_by_service_are_read_as_their_numbers() -> None:
    p, report = read(NO_NAT, x(
        "filter",
        rule("lan", "block", proto="tcp", dport="ssh", descr="no ssh"),
        rule("lan", "block", proto="tcp/udp", dport="domain", descr="dns"),
        rule("lan", "block", proto="tcp", dport="nosuch", descr="unknown name"),
        rule("lan", "block", dport="23", descr="no protocol"),
        rule("lan", "block", proto="tcp", dport="9000-8000", descr="backwards"),
    ))  # fmt: skip
    rules = by_name(p)
    # pf looks a name up as a service (getservbyname): a port alias needs a name that is no service.
    assert rules["no ssh"].services == ["tcp-22"] and rules["dns"].services == ["tcp-udp-53"]
    assert rules["unknown name"].unsupported == ["port 'nosuch' is a service name FWShift has no number for"]
    # A port and no protocol: pfSense writes "proto tcp", and the port is not looked at.
    assert rules["no protocol"].services == ["tcp"] and p.services["tcp"].entries[0].dst_ports in ("", "1-65535")
    assert "'backwards' (destination port: port range '9000-8000' runs backwards and matches no port)" in next(
        n.message for n in report.notes if n.code == "RULE_NOT_LOADED")  # fmt: skip


def test_a_floating_rule_without_a_direction_is_for_both() -> None:
    p, report = read(NO_NAT, x(
        "filter",
        rule("opt1", "block", descr="no direction", floating="in").replace(x("direction", "in"), ""),
        rule("opt1", "block", descr="odd direction", floating="sideways"),
        rule("lan", descr="tab"),
    ))  # fmt: skip
    assert [(r.name, r.src_zones, r.dst_zones) for r in p.rules] == [
        ("no direction - leaving", [ANY], ["DMZ"]), ("no direction", ["DMZ"], [ANY]), ("tab", ["LAN"], [ANY])]  # fmt: skip
    assert "'odd direction' (direction 'sideways', which pf does not have)" in next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")
    _, report = read(NO_NAT, x("filter", rule("any", descr="every interface", floating="in")), version="22.2")
    assert "(pfSense 2.6 loads no floating rule for interface 'any')" in next(n.message for n in report.notes if n.code == "RULE_NOT_LOADED")
    # What pfSense does not know as a type is a pass rule, and a family it does not know is IPv4.
    p, _ = read(NO_NAT, x("filter", rule("lan", "Block", descr="type"), rule("lan", family="INET6", descr="family")))
    assert [(r.action, r.sources) for r in p.rules] == [(Action.ALLOW, [ANY_V4]), (Action.ALLOW, [ANY_V4])]


def test_nat_on_groups_and_on_the_interfaces_of_the_system() -> None:
    openvpn = x("openvpn", x("openvpn-server", x("vpnid", "1"), x("tunnel_network", "10.8.0.0/24")))
    p, report = read(GROUPS, openvpn, x(
        "nat", x("outbound", x("mode", "disabled")),
        forward("198.51.100.10", "80", "10.0.2.10", interface="INSIDE", descr="on a group", extra=x("natreflection", "disable")),
        forward("198.51.100.11", "80", "10.0.2.11", interface="openvpn", descr="on openvpn", extra=x("natreflection", "disable")),
    ), x("filter"))  # fmt: skip
    nats = {nat.name: nat for nat in p.nat_rules}
    assert nats["on a group"].src_zones == ["LAN", "GUEST"] and nats["on openvpn"].src_zones == ["OpenVPN"]
    assert not any(n.code == "RULE_NOT_LOADED" for n in report.notes)


def test_several_ports_to_one_is_said_like_pfsense_writes_it() -> None:
    p, _ = read(ALIASES, x(
        "nat", x("outbound", x("mode", "disabled")),
        forward("198.51.100.10", "Web", "10.0.2.10", local="80", descr="alias to one", extra=x("natreflection", "disable")),
        forward("198.51.100.11", "8000-8010", "10.0.2.11", local="8000-8010", descr="range to range", extra=x("natreflection", "disable")),
    ), x("filter"))  # fmt: skip
    nats = {nat.name: nat for nat in p.nat_rules}
    assert nats["alias to one"].unsupported == ["several ports (80,443,8000-8010) translated to the one port 80"]
    assert not nats["range to range"].unsupported and nats["range to range"].destination_translation == DestNat("10.0.2.11")


def test_networks_of_virtual_addresses_and_their_negation() -> None:
    vips = x("virtualip", x("vip", x("mode", "carp"), x("interface", "lan"), x("subnet", "10.0.1.254"), x("subnet_bits", "24"), x("uniqid", "abc"),
                            x("vhid", "1")),
             x("vip", x("mode", "ipalias"), x("interface", "_vipabc"), x("subnet", "172.16.5.1"), x("subnet_bits", "24")))  # fmt: skip
    # An IP alias on a CARP address belongs to the interface of that address.
    p, report = read(NO_NAT, vips, x("filter", rule("lan", "block", dst="!net:lan", descr="not lan")), version="24.0")
    assert p.address_groups["LAN net"].members == ["10.0.1.0/24", "172.16.5.0/24"] and p.rules[0].negate_destination
    # pfSense 2.6 writes "not" of such a list as {!a !b}: pf reads that as every address.
    p, report = read(NO_NAT, vips, x("filter", rule("lan", "block", src="!net:lan", descr="antispoof by hand")), version="22.2")
    assert p.rules[0].sources == [ANY_V4] and not p.rules[0].negate_source
    assert [(f.code, f.severity) for f in report.item("rule", "antispoof by hand").findings] == [("NEGATED_LIST", Severity.REVIEW)]


def test_an_interface_without_addresses_of_one_version_in_a_rule_for_both() -> None:
    sections = (NO_NAT, x("filter", rule("lan", "block", family="inet46", dst="!net:opt2", descr="not guest"),
                          rule("lan", "block", family="inet46", dst="net:opt2", descr="to guest")))  # fmt: skip
    # After 2.7.2 the table of an interface network holds both versions: "not" of what has no IPv6 is every IPv6 address.
    p, report = read(*sections, version="24.0")
    assert [(r.name, r.destinations, r.negate_destination) for r in p.rules] == [
        ("not guest", ["GUEST net"], True), ("not guest IPv6", [ANY_V6], False), ("to guest", ["GUEST net"], False)]  # fmt: skip
    assert "the rule matches nothing of IPv6 there" in report.item("rule", "to guest").findings[0].message
    p, report = read(*sections, version="23.3")
    assert [r.name for r in p.rules] == ["not guest", "to guest"] and codes(report, "not guest") == ["RULE_HALF_NOT_LOADED"]


def test_automatic_outbound_nat_knows_the_networks_of_tunnels() -> None:
    interfaces = interfaces_xml().replace("</interfaces>", x("opt3", x("enable"), x("if", "ovpns1"), x("descr", "VPN"), x("ipaddr", "10.8.0.1"),
                                                             x("subnet", "24")) + "</interfaces>")  # fmt: skip
    p, _ = read(x("openvpn", x("openvpn-server", x("vpnid", "1"), x("tunnel_network", "10.8.0.0/24"))), x("filter"), interfaces=interfaces)
    automatic = next(nat for nat in p.nat_rules if nat.name == "Automatic outbound NAT on WAN")
    # An OpenVPN interface has no gateway of its own for this: its network is translated, not translated into.
    assert automatic.sources == ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.8.0.0/24"] and automatic.dst_zones == ["WAN"]


def test_what_is_nested_too_deep_is_unusable_and_no_crash() -> None:
    chain = x("aliases", *(alias(f"A{i}", "host", f"A{i + 1}") for i in range(1000)), alias("A1000", "host", "10.0.0.1"))
    ports = x("aliases", *(alias(f"P{i}", "port", f"P{i + 1}") for i in range(1000)), alias("P1000", "port", "80"))
    p, _ = read(chain, NO_NAT, x("filter", rule("lan", src="A0", descr="deep")))
    assert p.address_groups["A0"].unsupported == "aliases nested more than 64 deep, or in a circle"
    assert transform.tainted_addresses(p)
    p, report = read(ports, NO_NAT, x("filter", rule("lan", proto="tcp", dport="P0", descr="deep ports")))
    assert not [r for r in p.rules if r.name == "deep ports" and not r.unsupported]


def test_bridges_and_interfaces_of_one_name() -> None:
    _, report = read(NO_NAT, x("bridges", x("bridged", x("members", "lan,opt1"), x("bridgeif", "bridge0"))), x("filter"))
    assert "BRIDGE_NOT_CONVERTED" in codes(report)
    p, _ = read(NO_NAT, x("filter", rule("opt1", descr="r")), interfaces=interfaces_xml().replace(x("descr", "LAN"), x("descr", "DMZ")))
    assert {name: zone.interfaces for name, zone in p.zones.items()} == {"WAN": ["wan"], "DMZ": ["lan"], "OPT1": ["opt1"], "GUEST": ["opt2"]}
    assert p.rules[0].src_zones == ["OPT1"]


def test_outbound_nat_without_a_version_is_also_for_ipv6() -> None:
    p, report = read(x("nat", x("outbound", x("mode", "advanced"), outbound("any", descr="everything"), outbound("10.0.1.0/24", descr="lan"))), x("filter"))
    assert [(f.code, f.severity) for f in report.item("nat", "everything").findings] == [("NAT_IPV6_ALSO", Severity.INFO)]
    assert report.item("nat", "lan").findings == []


def test_an_interface_address_given_twice_is_refused() -> None:
    interfaces = interfaces_xml().replace(x("ipaddr", "198.51.100.2") + x("subnet", "24"), x("ipaddr", "dhcp"))
    with pytest.raises(FwshiftError, match="--interface-address: two IPv4 addresses for 'WAN'"):
        read(NO_NAT, x("filter"), interfaces=interfaces, interface_addresses=["wan=198.51.100.7/24", "WAN=198.51.100.8/24"])
    with pytest.raises(FwshiftError, match="--interface-address is for a pfSense or SonicWall source"):
        cli.load((DATA / "asa_sample.cfg").read_bytes(), "asa", Report(), interface_addresses=["wan=198.51.100.7/24"])


def test_a_rule_that_passes_to_any_destination_does_not_open_the_firewall() -> None:
    root, report, _ = emitted(policy(allow("out"), allow("to the firewall", destinations=["10.20.0.1"])))
    assert shapes(root) == ["lan pass inet46 - any !net:(self) log", "lan pass inet - any 10.20.0.1 log"]
    note = next(n for n in report.notes if n.code == "SELF_EXCLUDED")
    assert note.severity == Severity.INFO and "not This Firewall" in note.message
    # A rule of a pfSense says what it says: "any" is any, the firewall too.
    native = Policy(vendor="pfsense")
    native.zones["LAN"] = Zone("LAN", ["lan"])
    native.rules.append(Rule(name="r", origin="r", src_zones=["LAN"]))
    root, report, _ = emitted(native)
    assert shapes(root) == ["lan pass inet46 - any any log"] and "SELF_EXCLUDED" not in codes(report)


def test_names_pfsense_would_change_in_outbound_nat_are_wrapped() -> None:
    p = policy(zones=("trust", "untrust"))
    p.nat_rules.append(NatRule(name="LAN via opt2", origin="LAN via opt2", src_zones=["trust"], dst_zones=["untrust"], sources=["10.1.0.0/24", "10.2.0.0/24"],
                               source_translation=SourceNat(SnatKind.INTERFACE, interface="ethernet1/1")))  # fmt: skip
    root, _, _ = emitted(p, Options(zone_map={"trust": "lan", "untrust": "wan"}))
    # pfSense reads "opt" in a source of outbound NAT as the name of an interface; an alias that holds the alias reads right.
    found = aliases_of(root)
    assert found["nat_src_LAN_via_opt2"] == ("network", "10.1.0.0/24 10.2.0.0/24") and found["nat_set"] == ("network", "nat_src_LAN_via_opt2")
    assert root.findtext("nat/outbound/rule/source/network") == "nat_set"


def test_characters_xml_cannot_hold_are_dropped() -> None:
    root, _, text = emitted(policy(allow("r", description="bad ￾ char ￿ end \ud800")))
    import xml.parsers.expat

    xml.parsers.expat.ParserCreate().Parse(text.encode("utf-8", "surrogatepass"), True)
    assert "bad char end" in " ".join((root.findtext("filter/rule/descr") or "").split())
