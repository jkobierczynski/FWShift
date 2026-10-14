# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""OPNsense: the parser against a firewall made up at random, the emitter against the model, and both by hand.

The judge of what an OPNsense does is ``helpers.OPNsense``, which reads ``config.xml`` on its own. Every configuration
here is made up; the addresses are documentation and private ones.
"""

from __future__ import annotations

import random
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Sequence, Tuple

import pytest
from helpers import DATA, OPNsense, PfSense
from test_iptables import Packet, model_allows, model_verdict, random_model
from test_pfsense import deciding, model_translation

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Policy, Rule
from fwshift.options import Options
from fwshift.parsers import opnsense as parse_opnsense
from fwshift.report import Report, Severity

MODELS = ("1.0.4", "1.0.5", "1.0.6")


def x(tag: str, *content: str, **attributes: str) -> str:
    extra = "".join(f' {key}="{value}"' for key, value in attributes.items())
    return f"<{tag}{extra}>{''.join(content)}</{tag}>"


BASE_INTERFACES = {
    "wan": ("WAN", "198.51.100.2", 24, "", 0),
    "lan": ("LAN", "10.0.1.1", 24, "2001:db8:1::1", 64),
    "opt1": ("DMZ", "10.0.2.1", 24, "2001:db8:2::1", 64),
    "opt2": ("GUEST", "10.0.3.1", 24, "", 0),
}
ZONES = [descr for descr, *_ in BASE_INTERFACES.values()]
INSIDE = {"LAN": "10.0.1.", "DMZ": "10.0.2.", "GUEST": "10.0.3."}
OUTSIDE = ["203.0.113.5", "203.0.113.77", "198.51.100.99", "192.0.2.14", "10.9.9.9", "172.16.5.5"]
PUBLIC = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
PORTS = [22, 25, 53, 80, 443, 8000, 8005, 8080, 9000]


GROUP_INTERFACES = "".join(
    x(name, x("internal_dynamic", "1"), x("enable", "1"), x("if", name), x("descr", name), x("virtual", "1"), x("type", "group"))
    for name in ("INSIDE", "SERVED")
)  # as OPNsense lists its interface groups among the interfaces


def interfaces_xml(blockpriv: bool = False, extra: str = GROUP_INTERFACES) -> str:
    out = []
    for key, (descr, address, bits, address6, bits6) in BASE_INTERFACES.items():
        parts = [x("enable", "1"), x("if", f"vtnet{len(out)}"), x("descr", descr), x("ipaddr", address), x("subnet", str(bits))]
        if address6:
            parts += [x("ipaddrv6", address6), x("subnetv6", str(bits6))]
        if key == "wan":
            parts += [x("gateway", "WAN_GW")] + ([x("blockpriv", "1")] if blockpriv else [])
        out.append(x(key, *parts))
    return x("interfaces", *out, extra)


def config(*sections: str, model: str = "1.0.6", ipv6: bool = True, system: str = "", blockpriv: bool = False, rules: str = "",
           snat: str = "", onetoone: str = "", aliases: str = "", interfaces: Optional[str] = None) -> str:  # fmt: skip
    head = x("system", (x("ipv6allow", "1") if ipv6 and model == "1.0.4" else "") + x("disablenatreflection", "yes") + system)
    settings = x("Interfaces", x("settings", x("disableipv6", "0" if ipv6 else "1"))) if model != "1.0.4" else ""
    firewall = x("Firewall", x("Alias", x("geoip", x("url")), x("aliases", aliases), version="1.0.1"),
                 x("Filter", x("rules", rules), x("snatrules", snat), x("npt"), x("onetoone", onetoone), version=model))  # fmt: skip
    body = [head, interfaces if interfaces is not None else interfaces_xml(blockpriv), *sections, x("OPNsense", settings, firewall)]
    return '<?xml version="1.0"?>\n' + x("opnsense", *body)


def alias(name: str, kind: str, *entries: str, enabled: str = "1") -> str:
    return x("alias", x("enabled", enabled), x("name", name), x("type", kind), x("content", "\n".join(entries)), x("description"),
             uuid=f"2b000000-0000-4000-8000-{abs(hash(name)) % 10**12:012d}")  # fmt: skip


ALIASES = "".join([
    alias("Servers", "host", "10.0.2.10", "10.0.2.11", "2001:db8:2::10"),
    alias("Admins", "host", "10.0.1.34", "10.0.1.51"),
    alias("Inside", "network", "10.0.1.0/24", "10.0.3.0/24", "Servers"),
    alias("Partners", "network", "203.0.113.0/25", "192.0.2.14", "!203.0.113.77"),
    alias("Private", "network", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "!10.0.2.0/24", "10.0.2.11"),
    alias("Span", "host", "10.0.1.40-10.0.1.60"),
    alias("Nets", "networkgroup", "__lan_network", "__opt1_network"),
    alias("Off", "network", "10.0.3.0/24", enabled="0"),
    alias("Web", "port", "80", "443", "8000:8010"),
    alias("Mail", "port", "25", "Web"),
    alias("Gone", "port", "8080", enabled="0"),
    alias("Webs", "port", "80", "Gone"),
])  # fmt: skip
ADDRESSES = ["any", "any", "Servers", "Admins", "Inside", "Partners", "Private", "Span", "Nets", "Off", "10.0.2.0/24", "10.0.1.34",
             "203.0.113.77", "lan", "opt1", "wan", "lanip", "wanip", "(self)", "INSIDE", "__opt1_network"]  # fmt: skip
GROUPS_SAME = x("ifgroups", x("ifgroupentry", x("ifname", "INSIDE"), x("members", "lan,opt2"), x("sequence", "0"), uuid="0b000000-0000-4000-8000-000000000001"),
                x("ifgroupentry", x("ifname", "SERVED"), x("members", "opt1,opt2"), x("sequence", "0"), uuid="0b000000-0000-4000-8000-000000000002"),
                version="1.0.0")  # fmt: skip
GROUPS = x("ifgroups", x("ifgroupentry", x("ifname", "INSIDE"), x("members", "lan,opt2"), x("sequence", "10"), uuid="0b000000-0000-4000-8000-000000000001"),
           x("ifgroupentry", x("ifname", "SERVED"), x("members", "opt1,opt2"), x("sequence", "5"), uuid="0b000000-0000-4000-8000-000000000002"),
           version="1.0.0")  # fmt: skip
NO_NAT = x("nat", x("outbound", x("mode", "disabled")))


def mvc_rule(interface: str, action: str = "pass", src: str = "any", dst: str = "any", proto: str = "any", dport: str = "",
             sport: str = "", family: str = "inet", descr: str = "", extra: str = "", direction: str = "in", quick: str = "1",
             sequence: int = 1, enabled: str = "1") -> str:  # fmt: skip
    """A rule of the "Rules [new]" pages; ``src`` and ``dst`` with "!" in front for "not"."""
    parts = [x("enabled", enabled), x("sequence", str(sequence)), x("action", action), x("quick", quick), x("interface", interface),
             x("direction", direction), x("ipprotocol", family), x("protocol", proto)]  # fmt: skip
    for tag, spec, port in (("source", src, sport), ("destination", dst, dport)):
        parts += [x(f"{tag}_net", spec.lstrip("!")), x(f"{tag}_not", "1" if spec.startswith("!") else "0"), x(f"{tag}_port", port)]
    parts += [x("description", descr), extra]
    return x("rule", *parts, uuid=f"5e000000-0000-4000-8000-{abs(hash((interface, descr, sequence))) % 10**12:012d}")


def side(spec: str, port: str = "", not_flag: str = "1") -> str:
    """``any``, ``net:lan``, an address or an alias, with ``!`` in front for "not"."""
    negated = spec.startswith("!")
    spec = spec.lstrip("!")
    inner = x("any", "1") if spec == "any" else x("network", spec[4:]) if spec.startswith("net:") else x("address", spec)
    return inner + (x("not", not_flag) if negated else "") + (x("port", port) if port else "")


def legacy_rule(interface: str, action: str = "pass", src: str = "any", dst: str = "any", proto: str = "", dport: str = "",
                sport: str = "", family: str = "inet", descr: str = "", extra: str = "", floating: str = "", quick: str = "1",
                not_flag: str = "1") -> str:  # fmt: skip
    """A rule of <filter>; ``floating`` is "", or "in", "out" or "any" (or "-" for a floating rule without a direction)."""
    parts = [x("type", action), x("interface", interface), x("ipprotocol", family) if family else ""]
    if floating:
        parts += [x("floating", "yes")] + ([x("direction", floating)] if floating != "-" else [])
    if quick != "-":
        parts.append(x("quick", quick))
    if proto:
        parts.append(x("protocol", proto))
    parts += [x("source", side(src, sport, not_flag)), x("destination", side(dst, dport, not_flag)), x("descr", descr), extra]
    return x("rule", *parts)


def _pick(rng: random.Random, family: str, words: bool = True) -> str:
    spec = rng.choice(ADDRESSES)
    if family in ("inet46", "inet6") and spec[0].isdigit():
        spec = "Servers"
    if spec == "wan" and family != "inet":
        spec = "lan"
    if spec == "any":
        return spec
    return ("!" if rng.random() < 0.2 else "") + spec


def random_mvc(rng: random.Random, interface: str, number: int, direction: str = "in", model: str = "1.0.6") -> str:
    if direction == "in" and model != "1.0.4" and "," not in interface and interface and rng.random() < 0.1:
        direction = "any"  # a tab for both directions (26.1): what leaves is only blocked here, as for floating rules
    family = rng.choice(["inet", "inet", "inet46", "inet6"])
    proto = rng.choice(["any", "any", "TCP", "TCP", "UDP", "TCP/UDP", "ICMP", "IPV6-ICMP", "ESP"])
    action = rng.choice(["pass", "pass", "pass", "block", "reject"]) if direction == "in" else "block"
    dport = sport = extra = ""
    if proto in ("TCP", "UDP", "TCP/UDP"):
        dport = rng.choice(["", "22", "53", "80-443", "Web", "Mail", "8000-8010", "https", "Webs"])
        sport = rng.choice(["", "", "", "1024-65535"])
    if proto == "ICMP" and rng.random() < 0.6:
        extra = x("icmptype", rng.choice(["echoreq", "echoreq,unreach", "timex"]))
    if proto == "IPV6-ICMP" and rng.random() < 0.6:
        extra = x("icmp6type", rng.choice(["128", "128,1", "3"]))
    src, dst = _pick(rng, family), _pick(rng, family)
    if rng.random() < 0.2 and not src.startswith("!") and src != "any":
        other = _pick(rng, family).lstrip("!")
        src = src if other == "any" else f"{src},{other}"  # a list: one rule per item
    if direction == "out" and model == "1.0.6" and rng.random() < 0.4:
        extra += x("received-on", rng.choice(["lan", "opt1", "lan,opt2", "INSIDE"])) + x("received-on-not", "0")
    quick = "0" if rng.random() < 0.15 else "1"
    enabled = "0" if rng.random() < 0.1 else "1"
    return mvc_rule(interface, action, src, dst, proto, dport, sport, family, f"new {interface.replace(',', '+') or 'all'} {number}",
                    extra, direction, quick, rng.randint(1, 50) * 10, enabled)  # fmt: skip


def random_legacy(rng: random.Random, interface: str, number: int, floating: str = "", model: str = "1.0.6", both: bool = True) -> str:
    family = rng.choice(["inet", "inet", "inet46", "inet6", ""])
    proto = rng.choice(["", "", "tcp", "tcp", "udp", "tcp/udp", "icmp", "ipv6-icmp", "esp"])
    action = rng.choice(["pass", "pass", "pass", "block", "reject"])
    if floating and floating not in ("in", "-"):
        action = "block"
    dport = sport = extra = ""
    if proto in ("tcp", "udp", "tcp/udp", "") and rng.random() < 0.7:
        dport = rng.choice(["", "22", "53", "80-443", "Web", "Mail", "8000-8010", "https", "Webs"])
        sport = rng.choice(["", "", "", "1024-65535"])
    if proto == "icmp" and rng.random() < 0.6:
        extra = x("icmptype", rng.choice(["echoreq", "echoreq,unreach", "timex"]))
    if proto == "ipv6-icmp" and rng.random() < 0.6:
        extra = x("icmp6-type", rng.choice(["echoreq", "unreach"]))
    elif proto == "ipv6-icmp" and rng.random() < 0.3:
        extra = x("icmptype", "echoreq")  # the type of ICMP for IPv4, which OPNsense does not use here
    if rng.random() < 0.15:
        extra += x("disabled", rng.choice(["1", "1", "0", ""]))
    if rng.random() < 0.2:
        extra += x("log", "1")
    quick = rng.choice(["1", "1", "1", "0", "-"]) if not floating else rng.choice(["1", "1", "0", "-"])
    not_flag = rng.choice(["1", "1", "1", ""])
    text = legacy_rule(interface, action, _pick(rng, family), _pick(rng, family), proto, dport, sport, family,
                       f"old {interface.replace(',', '+') or 'all'} {number}", extra, floating, quick, not_flag)  # fmt: skip
    if not floating and both and rng.random() < 0.08:
        text = text.replace(x("type", action), x("type", "block") + x("direction", "any"))  # both directions, on a tab
    if rng.random() < 0.05 and not dport and not sport:
        text = re.sub(r"<destination>.*?</destination>", "", text)  # no destination: any
    return text


def random_firewall(rng: random.Random, model: str = "1.0.6", floating: bool = True, nat: str = NO_NAT, rules: Sequence[str] = ()) -> str:
    legacy: List[str] = list(rules)
    mvc: List[str] = []
    if floating:
        for number in range(rng.randint(0, 4)):
            where = rng.choice(["wan", "lan", "opt1", "lan,opt1", "wan,opt2", "", "INSIDE", "lan,INSIDE"])
            way = rng.choice(["in", "in", "in", "-", "any", "out"])
            legacy.append(random_legacy(rng, where, number, way, model))
        for number in range(rng.randint(0, 4)):
            where = rng.choice(["lan,opt1", "wan,opt2", "", "wan", "opt1"])
            way = rng.choice(["in", "in", "out", "out"])
            mvc.append(random_mvc(rng, where, number, way, model))
    for interface in ("INSIDE", "wan", "lan", "SERVED", "opt1", "opt2"):
        legacy += [random_legacy(rng, interface, len(legacy) + n, model=model) for n in range(rng.randint(0, 3))]
        mvc += [random_mvc(rng, interface, len(mvc) + n, model=model) for n in range(rng.randint(0, 3))]
    rng.shuffle(legacy)
    rng.shuffle(mvc)
    groups = GROUPS if rng.random() < 0.6 else GROUPS_SAME
    return config(groups, nat, x("filter", *legacy), model=model, ipv6=rng.random() < 0.7, blockpriv=rng.random() < 0.4,
                  rules="".join(mvc), aliases=ALIASES)  # fmt: skip


def route(address: str) -> str:
    if ":" in address:
        return {"2001:db8:1:": "LAN", "2001:db8:2:": "DMZ"}.get(address[:11], "WAN")
    return next((zone for zone, prefix in INSIDE.items() if address.startswith(prefix)), "WAN")


def random_packet(rng: random.Random, judge: Optional[OPNsense] = None) -> Packet:
    zone = rng.choice(ZONES)
    if rng.random() < 0.8:
        hosts = [10, 11, 34, 45, 51, 77, 200]
        src = INSIDE[zone] + str(rng.choice(hosts)) if zone in INSIDE and rng.random() < 0.9 else rng.choice(OUTSIDE)
        dst = rng.choice([prefix + str(host) for prefix in INSIDE.values() for host in hosts] + OUTSIDE + PUBLIC + ["198.51.100.2", "10.0.1.1"])
    else:
        pool = ["2001:db8:1::5", "2001:db8:1::1", "2001:db8:2::10", "2001:db8:2::99", "2001:db8:ffff::9", "fd00::7", "fe80::9"]
        src, dst = rng.choice(pool), rng.choice(pool)
    proto = rng.choice(["tcp", "tcp", "tcp", "udp", "icmp" if "." in src else "icmp6", "50", "47"])
    pkt = Packet(zone, "", src, dst, proto, rng.choice([1024, 40000, 600]), rng.choice(PORTS), rng.choice([0, 3, 8, 11, 128, 1]))
    target = judge._arriving(judge.key(zone), pkt)[0] if judge is not None else dst
    pkt.out_if = route(target)
    return pkt


def parse(text: str, **options: Sequence[str]) -> Tuple[Policy, Report]:
    report = Report()
    return parse_opnsense.parse(text.encode(), report, **options), report  # type: ignore[arg-type]


@pytest.mark.parametrize("model,floating", [("1.0.4", True), ("1.0.5", True), ("1.0.6", False), ("1.0.6", True)])
def test_parsed_configuration_decides_like_opnsense(model: str, floating: bool) -> None:
    """Both kinds of rule in the order of their priorities, quick or not, for what arrives and what leaves (and where it
    arrived), lists of addresses, aliases that leave addresses out and that are disabled, the words OPNsense has for
    networks, IPv4 and IPv6 in one rule, flags as each series reads them, "Block private networks", IPv6 switched off."""
    allowed = compared = 0
    for seed in range(70):
        rng = random.Random(seed)
        text = random_firewall(rng, model, floating)
        judge = OPNsense(text)
        p, report = parse(text)
        assert not any(r.unsupported for r in p.rules), (seed, [(r.name, r.unsupported) for r in p.rules if r.unsupported])
        for _ in range(300):
            pkt = random_packet(rng, judge)
            expected = judge.allows(pkt)
            allowed += expected
            compared += 1
            assert model_allows(p, pkt) == expected, (seed, pkt, judge.deciding(pkt), model_verdict(p, pkt), text)
    assert allowed > compared // 15, (allowed, compared)


# -- NAT ----------------------------------------------------------------------------------------------

VIPS = x("virtualip", *(
    x("vip", x("mode", "ipalias"), x("interface", "wan"), x("subnet", address), x("subnet_bits", "32")) for address in PUBLIC
))  # fmt: skip


def forward(model: str, dst: str, port: str, target: str, local: str = "", proto: str = "tcp", src: str = "any",
            interface: str = "wan", mode: str = "", descr: str = "", sequence: int = 100, extra: str = "") -> str:  # fmt: skip
    """A port forward in the form of the series: ``mode`` is "pass", "rule" (26.1 and later) or "" (by hand)."""
    local = local or port.split("-")[0] if port else ""
    if model == "1.0.4":
        return x("rule", x("source", side(src)), x("destination", side(dst, port)), x("ipprotocol", "inet"), x("protocol", proto),
                 x("target", target), x("local-port", local) if local else "", x("interface", interface), x("descr", descr),
                 x("associated-rule-id", mode), x("natreflection", "disable"), extra)  # fmt: skip
    return x("rule", x("sequence", str(sequence)), x("disabled", "0"), x("nordr", "0"), x("interface", interface), x("ipprotocol", "inet"),
             x("protocol", proto), x("source", x("network", src), x("port"), x("not", "0")),
             x("destination", x("network", dst.replace("net:", "")), x("port", port), x("not", "0")), x("target", target),
             x("local-port", local), x("log", "0"), x("descr", descr), x("natreflection", "disable"), x("pass", mode), extra,
             uuid=f"4d000000-0000-4000-8000-{sequence:012d}")  # fmt: skip


def binat(external: str, inside: str, kind: str = "binat", descr: str = "", sequence: int = 100) -> str:
    return x("rule", x("enabled", "1"), x("sequence", str(sequence)), x("interface", "wan"), x("type", kind), x("source_net", inside),
             x("source_not", "0"), x("destination_net", "any"), x("destination_not", "0"), x("external", external),
             x("natreflection"), x("description", descr), uuid=f"71000000-0000-4000-8000-{sequence:012d}")  # fmt: skip


def snat(source: str, target: str = "", destination: str = "any", descr: str = "", sequence: int = 100, nonat: str = "0",
         interface: str = "wan") -> str:  # fmt: skip
    return x("rule", x("enabled", "1"), x("nonat", nonat), x("sequence", str(sequence)), x("interface", interface), x("ipprotocol", "inet"),
             x("protocol", "any"), x("source_net", source), x("source_not", "0"), x("destination_net", destination),
             x("destination_not", "0"), x("target", target), x("staticnatport", "0"), x("description", descr),
             uuid=f"6f000000-0000-4000-8000-{sequence:012d}")  # fmt: skip


def outbound(source: str, target: str = "wanip", destination: str = "", descr: str = "", extra: str = "") -> str:
    where = x("network", destination) if destination else x("any", "1")
    return x("rule", x("source", x("network", source)), x("descr", descr), x("target", target), x("interface", "wan"),
             x("ipprotocol", "inet"), x("destination", where), extra)  # fmt: skip


def random_nat_firewall(rng: random.Random, model: str) -> str:
    """Port forwards in the form of the series, with the rules that go with them; 1:1 NAT; outbound NAT of both kinds in
    every mode."""
    forwards: List[str] = []
    wan_rules: List[str] = []
    taken: List[str] = []
    for number in range(rng.randint(1, 3)):
        dst = rng.choice(PUBLIC[:2] + ["net:wanip"])
        if dst in taken:
            continue
        taken.append(dst)
        proto = rng.choice(["tcp", "tcp", "udp", "tcp/udp"])
        port = rng.choice(["22", "25", "53", "80", "443", "8000-8010"])
        host = ["10.0.2.10", "10.0.2.11", "10.0.2.77"][len(taken) - 1]
        source = rng.choice(["any", "any", "Partners"])
        modes = ["pass", "", "link"] + (["rule", "rule"] if model != "1.0.4" else [])
        mode = rng.choice(modes)
        forwards.append(forward(model, dst, port, host, proto=proto, src=source, mode="" if mode == "link" else mode,
                                descr=f"forward {number}", sequence=(len(taken)) * 100))  # fmt: skip
        if mode == "link":
            wan_rules.append(legacy_rule("wan", "pass", source, host, proto, port, descr=f"NAT forward {number}"))
    ones: List[str] = []
    if rng.random() < 0.6:
        ones.append(binat(PUBLIC[2], "10.0.2.200", rng.choice(["binat", "binat", "nat"]), "one"))
        wan_rules.append(legacy_rule("wan", "pass", "any", "10.0.2.200", "tcp", "25", descr="mail to the 1:1 host"))
    mode = rng.choice(["automatic", "hybrid", "advanced", "disabled", ""])
    manual = [
        outbound("10.0.2.0/24", PUBLIC[1], descr="servers leave by their own address"),
        outbound("10.0.1.0/24", "", "203.0.113.0/25", descr="no NAT to the partners", extra=x("nonat", "1")),
        outbound("Admins", descr="administrators"),
        outbound("any", PUBLIC[0], "192.0.2.0/24", descr="everything to the test network"),
    ]
    rng.shuffle(manual)
    newer = [snat("10.0.3.0/24", PUBLIC[0], descr="guests", sequence=200), snat("Servers", "", "203.0.113.0/25", "servers to partners", 100),
             snat("10.0.1.0/24", "", "192.0.2.0/24", "no nat", 300, "1"), snat("10.0.1.0/24", "wanip", descr="lan by guest", interface="opt2")]  # fmt: skip
    rng.shuffle(newer)
    nat = x("nat", x("outbound", x("mode", mode) if mode else "", *manual[: rng.randint(0, 4)]), *forwards)
    rules = list(wan_rules)
    for interface in ("lan", "opt1", "opt2", "INSIDE"):
        rules += [random_legacy(rng, interface, len(rules) + n, model=model, both=False) for n in range(rng.randint(1, 4))]
    rules.append(legacy_rule("wan", "pass", "Partners", "any", "tcp", "22", descr="partners to anything by ssh"))
    rng.shuffle(rules)
    return config(GROUPS, VIPS, nat, x("filter", *rules), model=model, ipv6=rng.random() < 0.7, blockpriv=rng.random() < 0.3,
                  snat="".join(newer[: rng.randint(0, 4)]), onetoone="".join(ones), aliases=ALIASES)  # fmt: skip


@pytest.mark.parametrize("model", MODELS)
def test_parsed_nat_translates_and_decides_like_opnsense(model: str) -> None:
    """Port forwards that pass their own traffic, that register a rule of their own (26.1 and later) or have one by hand;
    1:1 NAT both ways and one way; Source NAT rules (in every mode up to 26.1) before those of the outbound page, and the
    automatic ones."""
    translated = allowed = direct = 0
    for seed in range(60):
        rng = random.Random(3000 + seed)
        text = random_nat_firewall(rng, model)
        judge = OPNsense(text)
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
                # The rule that stands for a port forward that passes its own traffic also passes what is sent to the
                # translated address directly, and says so.
                name = deciding(p, pkt)
                assert name.endswith(" - pass") and not expected and judge.translation(pkt)[1] == "Original", (seed, pkt, name, judge.deciding(pkt), text)
                assert any(f.code == "AUTOMATIC_RULE" and f.severity == Severity.APPROX for f in report.item("rule", name).findings)
                direct += 1
    assert translated > 1500 and allowed > 700, (translated, allowed, direct)


# -- the emitter against the model ------------------------------------------------------------------

from test_asa import ZONE_NETWORKS, effective, emitter_packet  # noqa: E402

ZONE_MAP = {"eth0": "wan", "eth1": "lan", "eth2": "opt1"}
TARGET_NETWORKS = {ZONE_MAP[zone]: networks for zone, networks in ZONE_NETWORKS.items()}
SERIES = {"24.7": "1.0.4", "25.1": "1.0.4", "25.7": "1.0.4", "26.1": "1.0.5", "26.7": "1.0.6"}


def target(series: str = "26.7", ipv6: bool = True, gateway: bool = False, nat: str = "") -> OPNsense:
    """An OPNsense of a series whose interfaces carry the zone names of the random models as their descriptions; with
    ``gateway`` the WAN has one, and outbound NAT, automatic, translates what leaves by it from the networks of the others."""
    inside = {"lan": ("10.0.2.1", "23"), "opt1": ("10.0.4.1", "24")} if gateway else {}
    interfaces = x("interfaces", *(
        x(key, x("enable", "1"), x("if", f"vtnet{n}"), x("descr", zone), x("ipaddr", inside.get(key, (f"192.0.2.{n * 64 + 1}",))[0]),
          x("subnet", inside.get(key, ("", "26"))[1]), x("gateway", "WAN_GW") if gateway and key == "wan" else "")
        for n, (zone, key) in enumerate(ZONE_MAP.items())
    ))  # fmt: skip
    return OPNsense(config(nat, interfaces=interfaces, ipv6=ipv6, model=SERIES[series]))


def restored(text: str, series: str = "26.7", gateway: bool = False) -> OPNsense:
    judge = target(series, gateway=gateway)
    judge.restore(text)
    return judge


@pytest.mark.parametrize("seed", range(50))
def test_emitted_rules_decide_like_the_model(seed: int) -> None:
    """Lists, negations, rule types, zone pairs, services of several kinds, for each series: with the networks of every
    zone given, the rules OPNsense gets decide as the model does. Only a negated service is nothing it can say, and ICMP
    types before 25.1 (ICMPv6 types before 25.7)."""
    rng = random.Random(seed)
    series = list(SERIES)[seed % len(SERIES)]
    model = random_model(rng)
    report = Report()
    text = cli.convert(model, "opnsense", report, Options(zone_map=ZONE_MAP, zone_networks=TARGET_NETWORKS, target_version=series))
    allowed = {"SERVICE_NEGATE", "OPNSENSE_ICMP_TYPES"}
    for item in report.items.values():
        codes = {f.code for f in item.findings if f.severity == Severity.REVIEW} - {"EGRESS_NO_ADDRESS"}
        assert not item.disabled or (codes and codes <= allowed), (seed, item.name, [f.code for f in item.findings])
    expected = effective(model, report)
    judge = restored(text, series)
    for _ in range(400):
        pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
        assert judge.allows(pkt) == model_allows(expected, pkt), (seed, series, pkt, judge.deciding(pkt), model_verdict(expected, pkt), text)


# -- OPNsense to OPNsense -----------------------------------------------------------------------------


def round_trip(text: str, series: str) -> Tuple[OPNsense, Report, str]:
    """A firewall with the three areas restored from what FWShift made of its own configuration, for its own series."""
    p, report = parse(text)
    written = cli.convert(p, "opnsense", report, Options(target_version=series))
    # What "Block private networks" does is a rule in what was written: the target is taken without the setting.
    judge = OPNsense(re.sub(r"<blockpriv>1</blockpriv>", "", text))
    judge.restore(written)
    return judge, report, written


@pytest.mark.parametrize("kind,model", [("rules", "1.0.6"), ("floating", "1.0.6"), ("floating", "1.0.5"), ("floating", "1.0.4"),
                                        ("nat", "1.0.6"), ("nat", "1.0.5"), ("nat", "1.0.4")])  # fmt: skip
def test_converted_opnsense_decides_like_the_opnsense_it_came_from(kind: str, model: str) -> None:
    """Read, written and restored, a firewall does what it did: the same verdict and the same translation for every
    packet. Nothing may need a person to look at it but the restore itself."""
    series = {"1.0.4": "25.7", "1.0.5": "26.1", "1.0.6": "26.7"}[model]
    compared = allowed = 0
    for seed in range(40):
        rng = random.Random(7000 + seed)
        text = random_nat_firewall(rng, model) if kind == "nat" else random_firewall(rng, model, floating=kind == "floating")
        before = OPNsense(text)
        after, report, written = round_trip(text, series)
        review = {f.code for item in report.items.values() for f in item.findings if f.severity == Severity.REVIEW}
        review |= {note.code for note in report.notes if note.severity == Severity.REVIEW}
        assert review <= {"OPNSENSE_RESTORE", "RULE_NOT_LOADED", "FLOATING_AFTER_NAT", "OPNSENSE_FLAG_UNCLEAR",
                          "OPNSENSE_SNAT_MODE"}, (seed, report.to_text())
        for _ in range(300):
            pkt = random_packet(rng, before)
            expected = before.allows(pkt)
            compared += 1
            allowed += expected
            if after.allows(pkt) != expected:
                name = after.deciding(pkt)
                assert name.endswith(" - pass") and not expected and before.translation(pkt)[1] == "Original", (seed, pkt, name, before.deciding(pkt), written)
                assert any(f.code == "AUTOMATIC_RULE" and f.severity == Severity.APPROX for f in report.item("rule", name).findings)
            if ":" not in pkt.src:
                assert after.translation(pkt) == before.translation(pkt), (seed, pkt, written)
    assert allowed > compared // 30, (allowed, compared)


# -- pfSense to OPNsense ------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["rules", "floating", "nat"])
def test_converted_pfsense_decides_alike_on_opnsense(kind: str) -> None:
    """A pfSense read and written for OPNsense: restored on an OPNsense with the same interfaces, it decides and translates
    as the pfSense did (where pfSense and OPNsense read a file differently, the file for OPNsense says it as OPNsense reads it)."""
    import test_pfsense as pf

    compared = allowed = 0
    for seed in range(30):
        rng = random.Random(9000 + seed)
        text = pf.random_nat_firewall(rng) if kind == "nat" else pf.random_firewall(rng, floating=kind == "floating")
        before = PfSense(text)
        p, report = pf.parse(text)
        written = cli.convert(p, "opnsense", report)
        review = {f.code for item in report.items.values() for f in item.findings if f.severity == Severity.REVIEW}
        review |= {note.code for note in report.notes if note.severity == Severity.REVIEW}
        assert review <= {"OPNSENSE_RESTORE", "RULE_NOT_LOADED", "RULE_ORDER_VERSION", "FLOATING_AFTER_NAT"}, (seed, report.to_text())
        assert "pfSense" not in " ".join(f.message for f in report.notes if f.code == "OPNSENSE_RESTORE")
        interfaces = "".join(
            x(key, x("enable", "1"), x("if", f"vtnet{n}"), x("descr", descr), x("ipaddr", address), x("subnet", str(bits)),
              *([x("ipaddrv6", address6), x("subnetv6", str(bits6))] if address6 else []), x("gateway", "WAN_GW") if key == "wan" else "")
            for n, (key, (descr, address, bits, address6, bits6)) in enumerate(pf.BASE_INTERFACES.items())
        )  # fmt: skip
        ipv6 = "<ipv6allow" in text
        vips = pf.VIPS if "<virtualip>" in text else ""
        after = OPNsense(config(GROUPS, vips, NO_NAT, interfaces=x("interfaces", interfaces, GROUP_INTERFACES), ipv6=ipv6))
        after.restore(written)
        for _ in range(300):
            pkt = pf.random_packet(rng, before)
            expected = before.allows(pkt)
            compared += 1
            allowed += expected
            if after.allows(pkt) != expected:
                name = after.deciding(pkt)
                assert name.endswith(" - pass") and not expected and before.translation(pkt)[1] == "Original", (seed, pkt, name, before.deciding(pkt), written)
            if ":" not in pkt.src:
                assert after.translation(pkt) == before.translation(pkt), (seed, pkt, written)
    assert allowed > compared // 30, (allowed, compared)


# -- the parser by hand -------------------------------------------------------------------------------

import copy  # noqa: E402

from fwshift.model import ANY_V4, ANY_V6  # noqa: E402


def read(*sections: str, interface_addresses: Sequence[str] = (), **options: object) -> Tuple[Policy, Report]:
    return parse(config(*sections, **options), interface_addresses=interface_addresses)  # type: ignore[arg-type]


def by_name(p: Policy) -> dict:
    return {rule.name: rule for rule in p.rules}


def codes(report: Report, name: str = "", kind: str = "rule") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


@pytest.mark.parametrize("data,message", [
    (b"", "not well-formed XML"), (b"hello", "not well-formed XML"),
    (b'<!DOCTYPE opnsense [<!ENTITY a "b">]><opnsense/>', "DOCTYPE or entity declaration"),
    (b"<pfsense><version>23.3</version></pfsense>", "not an OPNsense configuration: the first element is <pfsense>"),
    (b"<opnsense><filter/></opnsense>", "no version of the firewall model"),
    (b'<opnsense><OPNsense><Firewall><Filter version="1.0.3"/></Firewall></OPNsense></opnsense>', "before 24.7 (firewall model 1.0.3)"),
    (b'<opnsense><OPNsense><Firewall><Filter version="x"/></Firewall></OPNsense></opnsense>', "no version of the firewall model"),
])  # fmt: skip
def test_what_is_no_opnsense_configuration_is_refused_with_a_reason(data: bytes, message: str) -> None:
    with pytest.raises(ParseError, match=re.escape(message)):
        parse_opnsense.parse(data, Report())


def test_a_rule_type_opnsense_writes_as_it_is_refuses_the_file() -> None:
    """pf refuses the whole ruleset for such a rule, and the firewall keeps the one it had: the file says nothing."""
    with pytest.raises(ParseError, match="type 'allow'.*keeps the one it had"):
        read(x("filter", legacy_rule("lan", "allow", descr="odd")))
    with pytest.raises(ParseError, match="action 'drop'"):
        read(rules=mvc_rule("lan", "drop", descr="odd"))


def test_the_series_is_said_and_a_newer_one_is_read_with_care() -> None:
    _, report = read(model="1.0.6")
    found = {n.code: n for n in report.notes}
    assert "OPNsense 26.7 (firewall model 1.0.6)" in found["OPNSENSE_VERSION"].message and "OPNSENSE_VERSION_NEWER" not in found
    _, report = parse(config().replace('version="1.0.6"', 'version="1.0.9"'))
    found = {n.code: n for n in report.notes}
    assert found["OPNSENSE_VERSION_NEWER"].severity == Severity.REVIEW and "after 26.7" in found["OPNSENSE_VERSION"].message
    _, report = read(model="1.0.4")
    assert "24.7 to 25.7" in next(n.message for n in report.notes if n.code == "OPNSENSE_VERSION")


@pytest.mark.parametrize("model", MODELS)
def test_flags_are_read_as_each_series_reads_them(model: str) -> None:
    """An empty element is "off" for most flags; "not" changed that in 26.1; "Block private networks" in 25.7."""
    rules = [
        legacy_rule("lan", descr="empty disabled", extra=x("disabled")),
        legacy_rule("lan", descr="zero disabled", extra=x("disabled", "0")),
        legacy_rule("lan", descr="disabled", extra=x("disabled", "1")),
        legacy_rule("lan", src="!net:opt1", descr="empty not", not_flag=""),
        legacy_rule("lan", src="!net:opt1", descr="zero not", not_flag="0"),
        legacy_rule("lan", src="!net:opt1", descr="one not", not_flag="1"),
    ]
    interfaces = interfaces_xml().replace(x("gateway", "WAN_GW"), x("gateway", "WAN_GW") + x("blockpriv"))
    p, report = read(x("filter", *rules), model=model, interfaces=interfaces)
    rules_read = by_name(p)
    assert rules_read["empty disabled"].enabled and rules_read["zero disabled"].enabled and not rules_read["disabled"].enabled
    old = model == "1.0.4"
    assert rules_read["empty not"].negate_source == old and rules_read["zero not"].negate_source == old
    assert rules_read["one not"].negate_source
    private = [r for r in p.rules if r.name.startswith("Block private networks")]
    assert bool(private) == old
    assert ("OPNSENSE_FLAG_UNCLEAR" in codes(report)) == old


def test_what_a_rule_of_the_old_kind_says_when_it_says_nothing() -> None:
    """No ipprotocol: both IP versions. A floating rule without a direction: what arrives. Ports without a protocol: no
    ports (any protocol). No quick on an interface: quick; quick 0: last match, after the quick rules."""
    rules = [
        legacy_rule("lan", dst="Servers", family="", descr="both"),
        legacy_rule("lan", dst="192.0.2.80", dport="80", descr="ports without a protocol"),
        legacy_rule("lan", "block", dst="192.0.2.0/24", descr="last match", quick="0"),
        legacy_rule("lan", dst="192.0.2.0/24", descr="first", quick="-"),
        legacy_rule("wan,lan", "block", dst="198.51.100.99", descr="floating", floating="-", quick="1"),
    ]
    p, report = read(x("filter", *rules), aliases=ALIASES)
    got = by_name(p)
    assert got["both"].destinations == ["Servers"] and got["ports without a protocol"].services == [ANY]
    assert [r.name for r in p.rules] == ["floating", "both", "ports without a protocol", "first", "last match"]
    assert got["floating"].src_zones == ["WAN", "LAN"] and got["floating"].dst_zones == [ANY]
    assert "FLOATING_LAST_MATCH" in codes(report)


def test_rules_are_in_the_order_of_their_priorities() -> None:
    """Floating, then groups by their sequence (the newer kind first in each), then interfaces (the newer kind by sequence,
    then the old kind in file order), then the rules port forwards register."""
    legacy = [
        legacy_rule("lan", descr="old lan"),
        legacy_rule("INSIDE", descr="old INSIDE"),
        legacy_rule("SERVED", descr="old SERVED"),
        legacy_rule("lan,opt1", descr="old floating", floating="in"),
    ]
    mvc = [
        mvc_rule("lan", descr="new lan 20", sequence=20),
        mvc_rule("lan", descr="new lan 10", sequence=10),
        mvc_rule("INSIDE", descr="new INSIDE", sequence=5),
        mvc_rule("SERVED", descr="new SERVED", sequence=500),
        mvc_rule("lan,opt1", descr="new floating", sequence=900),
    ]
    nat = x("nat", x("outbound", x("mode", "disabled")), forward("1.0.6", "net:wanip", "22", "10.0.2.10", mode="rule", descr="ssh"))
    p, report = read(GROUPS, nat, x("filter", *legacy), rules="".join(mvc))
    assert [r.name for r in p.rules] == [
        "new floating", "old floating", "new SERVED", "old SERVED", "new INSIDE", "old INSIDE", "new lan 10", "new lan 20", "old lan",
        "ssh (rule the port forward registers)",
    ]
    assert "OPNSENSE_REGISTERED_RULE" in codes(report)
    assert by_name(p)["old INSIDE"].src_zones == ["LAN", "GUEST"]


def test_rules_of_the_newer_kind() -> None:
    """Lists of addresses are one rule per pair; upper-case protocols; ICMP types by name and ICMPv6 types by number;
    what the model cannot say is unsupported or handling; categories become tags."""
    categories = x("Category", x("categories", x("category", x("name", "Web"), uuid="3c000000-0000-4000-8000-000000000001")), version="1.0.0")
    mvc = [
        mvc_rule("lan", src="Admins,10.0.1.99", dst="Servers,192.0.2.1", proto="TCP", dport="Web", descr="list",
                 extra=x("categories", "3c000000-0000-4000-8000-000000000001")),
        mvc_rule("opt1", proto="IPV6-ICMP", family="inet6", descr="icmp6", extra=x("icmp6type", "128,135")),
        mvc_rule("opt1", proto="ICMP", descr="icmp", extra=x("icmptype", "echoreq")),
        mvc_rule("opt1", proto="ICMP", family="inet6", descr="nothing"),
        mvc_rule("opt1", descr="tos", extra=x("tos", "0x10") + x("gateway", "WAN_GW") + x("statetype", "sloppy")),
    ]
    text = config(GROUPS, rules="".join(mvc), aliases=ALIASES).replace("</Firewall>", categories + "</Firewall>")
    p, report = parse(text)
    got = by_name(p)
    assert [r.name for r in p.rules if r.name.startswith("list")] == ["list", "list 2", "list 3", "list 4"]
    assert got["list"].tags == ["Web"] and got["list"].sources == ["Admins"] and got["list 4"].destinations == ["192.0.2.1"]
    assert p.services[got["icmp6"].services[0]].entries[0].icmp_type == 128
    assert "nothing" not in got and "OPNSENSE_RULE_EMPTY" in codes(report)
    assert got["tos"].unsupported == ["it matches the type of service (tos) '0x10'"]
    assert got["tos"].handling == {"gateway": "WAN_GW", "statetype": "sloppy state"}
    assert got["list"].source_ids["opnsense.uuid"].startswith("5e000000")


def test_aliases_as_pf_tables() -> None:
    """Entries one per line; "!" leaves addresses out, also of an alias inside another; a disabled alias is an empty
    table; ranges; host names; types whose addresses are not in the file are unsupported by name."""
    aliases = ALIASES + "".join([
        alias("Outer", "network", "Partners", "198.51.100.0/24"),
        alias("Mixed", "host", "Partners", "www.example.net"),
        alias("Geo", "geoip", "ZZ"),
        alias("Hosts", "host", "www.example.net", "Admins"),
    ])  # fmt: skip
    mvc = [mvc_rule("lan", dst=name, descr=name) for name in ("Partners", "Private", "Outer", "Off", "Geo", "Mixed", "Hosts", "Span", "!Off")]
    p, report = read(rules="".join(mvc), aliases=aliases)
    groups = p.address_groups
    assert groups["Partners"].members == ["192.0.2.14", "203.0.113.0-203.0.113.76", "203.0.113.78-203.0.113.127"]
    assert "10.0.2.11" in groups["Private"].members and "10.0.2.10" not in str(groups["Private"].members)
    assert "203.0.113.77" not in str(groups["Outer"].members) and "198.51.100.0/24" in groups["Outer"].members
    assert "geoip" in groups["Geo"].unsupported and "cannot be worked out" in groups["Mixed"].unsupported
    assert groups["Hosts"].members == ["www.example.net", "Admins"] and groups["Span"].members == ["10.0.1.40-10.0.1.60"]
    got = by_name(p)
    assert "Off" not in got and got["!Off"].destinations == [ANY_V4] and not got["!Off"].negate_destination
    assert any("Off" in n.message for n in report.notes if n.code == "OPNSENSE_RULE_EMPTY")
    assert "OPNSENSE_DISABLED_ALIAS" in codes(report)
    assert groups["__lan_network"].members == ["10.0.1.0/24", "2001:db8:1::/64"] and groups["__lan_network"].builtin == "opnsense"


def test_link_local_networks_in_rules_for_ipv6() -> None:
    """In a rule for IPv6 (inet46 is split in two first) the network of an interface comes with fe80::/10; "not" it leaves
    that out anyway; a rule of the old kind without a family is one rule, and gets nothing."""
    mvc = [mvc_rule("lan", src="lan", family="inet6", descr="six"), mvc_rule("lan", src="lan", family="inet46", descr="both"),
           mvc_rule("lan", src="!lan", family="inet6", descr="not six"), mvc_rule("lan", src="!wanip", family="inet6", descr="not wan"),
           mvc_rule("lan", src="!wanip", family="inet", descr="not wan4")]
    legacy = x("filter", legacy_rule("lan", src="net:lan", family="", descr="no family"))
    interfaces = interfaces_xml().replace(x("ipaddr", "198.51.100.2") + x("subnet", "24"), "")
    p, _ = read(legacy, rules="".join(mvc), interfaces=interfaces)
    got = by_name(p)
    assert got["six"].sources == ["LAN net IPv6", "fe80::/10"] and got["both"].sources == ["LAN net", "LAN net IPv6", "fe80::/10"]
    assert got["no family"].sources == ["LAN net", "LAN net IPv6"] and got["not wan4"].sources == [ANY_V4]
    assert got["not six"].sources == ["LAN net IPv6"] and got["not six"].negate_source
    assert got["not wan"].sources == [ANY_V6] and not got["not wan"].negate_source


def test_what_arrived_on_an_interface_and_leaves_by_another() -> None:
    mvc = [mvc_rule("wan", "block", proto="TCP", dport="25", direction="out", descr="mail out", extra=x("received-on", "opt1,INSIDE")),
           mvc_rule("wan", "block", direction="out", descr="negated", extra=x("received-on", "opt1") + x("received-on-not", "1"))]
    p, _ = read(GROUPS, rules="".join(mvc))
    got = by_name(p)
    assert got["mail out"].src_zones == ["DMZ", "LAN", "GUEST"] and got["mail out"].dst_zones == ["WAN"]
    assert got["negated"].src_zones == [ANY] and "negated" in got["negated"].unsupported[0]


def test_ipv6_is_switched_off_in_its_place_of_each_series() -> None:
    for model in MODELS:
        p, report = read(rules=mvc_rule("lan", family="inet46", descr="both"), model=model, ipv6=False)
        assert "IPV6_NOT_ALLOWED" in codes(report) and by_name(p)["both"].sources == [ANY_V4], model


def test_nat_of_both_forms_and_what_no_longer_counts() -> None:
    old = x("nat", x("outbound", x("mode", "advanced")), x("onetoone", x("external", "198.51.100.10")),
            forward("1.0.4", "net:wanip", "2222", "10.0.2.10", "22", descr="old form", mode="pass"))  # fmt: skip
    p, report = read(old, x("aliases", x("alias", x("name", "Gone"))), model="1.0.4",
                     onetoone=binat("198.51.100.11", "10.0.2.0/30", "nat", "one way") + binat("198.51.100.12", "10.0.2.200", descr="both ways"))
    names = [n.name for n in p.nat_rules]
    assert names == ["old form", "both ways - inbound", "both ways - outbound", "one way - outbound"]
    assert "old form - pass" in by_name(p)
    dead = next(n.message for n in report.notes if n.code == "OPNSENSE_OLD_SECTIONS")
    assert "<nat><onetoone>" in dead and "<aliases>" in dead
    newer = x("nat", x("outbound", x("mode", "automatic")),
              forward("1.0.5", "net:wanip", "80", "10.0.2.10", descr="later", sequence=200),
              forward("1.0.5", "net:wanip", "443", "10.0.2.11", descr="sooner", sequence=100))  # fmt: skip
    p, report = read(newer, model="1.0.5", snat=snat("10.0.3.0/24", PUBLIC[0], descr="guests"),
                     onetoone="", rules="")  # fmt: skip
    assert [n.name for n in p.nat_rules] == ["sooner", "later", "guests", "Automatic outbound NAT on WAN"]
    assert "OPNSENSE_SNAT_MODE" in codes(report)
    p, report = read(newer, model="1.0.6", snat=snat("10.0.3.0/24", PUBLIC[0], descr="guests"))
    assert "guests" not in [n.name for n in p.nat_rules] and "OPNSENSE_SNAT_MODE" not in codes(report)


def test_the_sample_is_read() -> None:
    p, report = parse((DATA / "opnsense_sample.xml").read_text())
    names = [r.name for r in p.rules]
    assert names[:4] == ["Never to the blocklist (floating)", "Never to the blocklist (floating) 2", "Guests never to the blocklist",
                         "DMZ may not send mail out (received-on)"]  # fmt: skip
    assert names.index("VPN users to the web servers") < names.index("No outside resolver (group)") < names.index("Inside may ping (old kind)")
    assert names.index("Default allow LAN to any rule") < names.index("Guests to the portal (no protocol, both IP versions)")
    assert names[-3:] == ["SSH to bastion (rule the port forward registers)", "LAN to test net (not quick)", "Time for everyone (floating, not quick)"]
    assert [n.name for n in p.nat_rules] == ["SSH to bastion", "Voice from the partner", "Mail relay 1:1 - inbound", "Mail relay 1:1 - outbound",
                                             "DMZ leaves as .10", "Guests leave as .30", "Automatic outbound NAT on WAN"]  # fmt: skip
    assert set(p.zones) == {"WAN", "LAN", "DMZ", "GUEST", "VPNSITE", "OpenVPN"}
    assert {"NPT_NOT_CONVERTED", "BOGONS_NOT_CONVERTED", "OPNSENSE_AUTOMATIC_RULES"} <= set(codes(report))
    assert not any("pfSense" in f.message for item in report.items.values() for f in item.findings)
    assert not any("pfSense" in n.message for n in report.notes)


def test_the_format_is_detected_and_pfsense_points_to_it() -> None:
    sample = (DATA / "opnsense_sample.xml").read_bytes()
    assert cli.detect_format(sample) == "opnsense"
    assert cli.detect_format(b'\xef\xbb\xbf<?xml version="1.0"?>\n<!-- a backup -->\n<opnsense><system/></opnsense>') == "opnsense"
    from fwshift.parsers import pfsense as parse_pfsense

    with pytest.raises(ParseError, match="--from opnsense"):
        parse_pfsense.parse(sample, Report())


def test_an_address_the_configuration_does_not_hold_is_asked_for() -> None:
    interfaces = interfaces_xml().replace(x("ipaddr", "198.51.100.2"), x("ipaddr", "dhcp"))
    p, report = read(rules=mvc_rule("wan", dst="wanip", descr="to me"), interfaces=interfaces)
    assert p.addresses["WAN address"].kind.name == "UNSUPPORTED"
    p, _ = read(rules=mvc_rule("wan", dst="wanip", descr="to me"), interfaces=interfaces, interface_addresses=["wan=198.51.100.7/24"])
    assert p.addresses["WAN address"].value == "198.51.100.7/32"
    data = config(rules=mvc_rule("wan", dst="wanip", descr="to me"), interfaces=interfaces).encode()
    policy = cli.load(data, "opnsense", Report(), interface_addresses=["wan=198.51.100.7/24"])
    assert policy.addresses["WAN address"].value == "198.51.100.7/32"


def test_a_broken_configuration_never_ends_in_a_traceback() -> None:
    """Bytes cut out, doubled and replaced at random, and elements taken out, doubled, moved and given other text: an
    answer or an error with a reason, nothing else."""
    sample = (DATA / "opnsense_sample.xml").read_bytes()
    words = [b"<any>1</any>", b"<not>1</not>", b"opt9", b"lan,wan", b"::1", b"10.0.0.0/33", b"99999", b"1-0", b"&amp;", b"<x>", b"</rule>",
             b"<floating>yes</floating>", b"<direction>out</direction>", b"inet46", b"TCP/UDP", b"\x00", b"<rule>", b"(self)", b"wanip",
             b"WebPorts", b"Blocklist", b"any", b"", b"-1", b"0", b"1", b"65536", b"80:70", b"dhcp", b"hybrid", b"pass", b"rule", b"out",
             b"!10.0.0.0/8", b"1.0.4", b"1.0.5", b"ipv6-icmp", b"128,x", b"geoip"]  # fmt: skip
    rng = random.Random(8)
    read_fine = 0

    def attempt(data: bytes) -> int:
        try:
            policy = parse_opnsense.parse(data, Report())
            for target in ("opnsense", "pfsense", "panos", "json"):
                cli.convert(copy.deepcopy(policy), target, Report())
            return 1
        except FwshiftError:
            return 0

    for _ in range(200):
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
    assert read_fine > 5, read_fine
    read_fine = 0
    for _ in range(400):
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
    assert read_fine > 150, read_fine


# -- the emitter by hand ------------------------------------------------------------------------------

from fwshift.model import Address, AddressKind, DestNat, NatRule, Service, ServiceEntry, SnatKind, SourceNat, Zone  # noqa: E402
from fwshift.model import Protocol as P  # noqa: E402


def policy(*rules: Rule, nat: Sequence[NatRule] = ()) -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    for zone in ("wan", "lan", "opt1"):
        p.zones[zone] = Zone(zone, [zone])
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.0.2.10/32")
    p.addresses["web6"] = Address("web6", AddressKind.NETWORK, "2001:db8:2::10/128")
    p.services["ping"] = Service("ping", [ServiceEntry(P.ICMP, icmp_type=8), ServiceEntry(P.ICMP6, icmp_type=128)])
    p.services["sctp-9"] = Service("sctp-9", [ServiceEntry(P.SCTP, "9")])
    p.services["https"] = Service("https", [ServiceEntry(P.TCP, "443")])
    p.rules = list(rules)
    p.nat_rules = list(nat)
    return p


def emitted(p: Policy, series: str = "26.7", **options: object) -> Tuple[ET.Element, Report, str]:
    report = Report()
    text = cli.convert(p, "opnsense", report, Options(target_version=series, **options))  # type: ignore[arg-type]
    return ET.fromstring(text), report, text


def mvc_rules(root: ET.Element) -> List[dict]:
    return [{child.tag: child.text or "" for child in rule} for rule in root.findall("OPNsense/Firewall/Filter/rules/rule")]


def test_the_areas_for_each_series() -> None:
    """The model version of the firewall rules of the series; port forwards of the old form up to 25.7, of the newer one
    from 26.1; the target of Source NAT empty for the address of the interface from 26.1, the word of it before."""
    rule = Rule(name="web", origin="web", src_zones=["wan"], dst_zones=["lan"], destinations=["web"], services=["https"])
    forward = NatRule(name="fwd", origin="fwd", src_zones=["wan"], destinations=["198.51.100.2"], service="https",
                      destination_translation=DestNat("web"))  # fmt: skip
    masq = NatRule(name="masq", origin="masq", dst_zones=["wan"], sources=["10.0.1.0/24"],
                   source_translation=SourceNat(SnatKind.INTERFACE, interface="wan"))  # fmt: skip
    for series, model in SERIES.items():
        root, report, text = emitted(policy(rule, nat=[forward, masq]), series)
        assert root.find("OPNsense/Firewall/Filter").get("version") == model and root.find("OPNsense/Firewall/Alias").get("version") == "1.0.1"
        node = root.find("nat/rule")
        newer = series in ("26.1", "26.7")
        assert (node.get("uuid") is not None) == newer and (node.find("sequence") is not None) == newer
        assert (node.findtext("destination/network") if newer else node.findtext("destination/address")) == "198.51.100.2"
        assert root.findtext("nat/outbound/mode") == "advanced"
        assert root.findtext("OPNsense/Firewall/Filter/snatrules/rule/target") == ("" if newer else "wanip")
        assert root.find("OPNsense/Firewall/Filter/npt") is not None and root.find("filter") is None
        note = next(n for n in report.notes if n.code == "OPNSENSE_RESTORE")
        assert series in note.message and "PFSENSE_RESTORE" not in codes(report)
        assert not any("pfSense" in f.message for item in report.items.values() for f in item.findings)
        assert ("statetype" in mvc_rules(root)[0]) == (series != "24.7")
    root, _, _ = emitted(policy(rule), "26.7")
    assert root.find("nat") is None and root.find("OPNsense/Firewall/Filter/snatrules") is None


def test_what_a_rule_of_a_series_cannot_say() -> None:
    """Before 25.1 a rule is for one IP version and names no ICMP types; before 25.7 no ICMPv6 types; ICMP for both IP
    versions is two rules in every series; SCTP has no ports in a rule of OPNsense."""
    both = Rule(name="both", origin="both", src_zones=["lan"], dst_zones=[ANY], destinations=["web", "web6"])
    ping = Rule(name="ping", origin="ping", src_zones=["lan"], dst_zones=[ANY], services=["ping"])
    sctp = Rule(name="sctp", origin="sctp", src_zones=["lan"], dst_zones=[ANY], services=["sctp-9"])
    expected = {"24.7": (2, {"ping", "sctp"}), "25.1": (1, {"ping", "sctp"}), "25.7": (1, {"sctp"}), "26.1": (1, {"sctp"}), "26.7": (1, {"sctp"})}
    for series, (count, disabled) in expected.items():
        root, report, _ = emitted(policy(both, ping, sctp), series)
        rules = mvc_rules(root)
        assert len([r for r in rules if r["description"] == "both"]) == count, series
        pings = [r for r in rules if r["description"].endswith("ping")]
        assert sorted((r["protocol"], r["ipprotocol"]) for r in pings) == [("ICMP", "inet"), ("IPV6-ICMP", "inet6")], series
        assert {item.name for item in report.items.values() if item.disabled} == disabled, series
        if series >= "25.7":
            assert {r.get("icmptype", "") + r.get("icmp6type", "") for r in pings} == {"echoreq", "128"}
    _, report, _ = emitted(policy(ping), "25.1")
    assert any("ICMPv6 types (25.7 and later do)" in f.message for f in report.item("rule", "ping").findings)


def test_what_leaves_for_named_zones_is_said_with_received_on() -> None:
    """26.7: a rule that blocks from named zones to others, above every rule that passes, is a rule for what leaves by the
    interfaces of its destination zones and arrived on those of its source zones."""
    block = Rule(name="no mail", origin="no mail", src_zones=["opt1"], dst_zones=["wan"], services=["https"], action=Action.DENY)
    allow = Rule(name="rest", origin="rest", src_zones=["opt1"], dst_zones=[ANY])
    root, report, _ = emitted(policy(block, allow), "26.7")
    first = mvc_rules(root)[0]
    assert (first["description"], first["direction"], first["interface"], first["received-on"]) == ("no mail", "out", "wan", "opt1")
    assert not report.item("rule", "no mail").disabled
    root, report, _ = emitted(policy(block, allow), "26.1")
    assert all("received-on" not in r for r in mvc_rules(root)) and report.item("rule", "no mail").disabled


def test_the_same_input_gives_the_same_file() -> None:
    p, _ = parse((DATA / "opnsense_sample.xml").read_text())
    first = cli.convert(copy.deepcopy(p), "opnsense", Report())
    assert first == cli.convert(copy.deepcopy(p), "opnsense", Report())
    uuids = re.findall(r'uuid="([^"]+)"', first)
    assert len(uuids) == len(set(uuids)) > 20
    # The aliases OPNsense keeps of the networks of an interface stay what they are.
    assert "<content>__lan_network\n__opt1_network</content>" in first and "<name>__lan_network</name>" not in first


def test_numbers_and_names_the_target_takes() -> None:
    rule = Rule(name="a & <b>", origin="a & <b>", src_zones=["lan"], dst_zones=[ANY], description="x")
    root, _, text = emitted(policy(rule))
    assert mvc_rules(root)[0]["description"] == "a & <b>: x" and "a &amp; &lt;b&gt;: x" in text
    back, _ = parse(config(rules="".join(ET.tostring(r, encoding="unicode") for r in root.findall("OPNsense/Firewall/Filter/rules/rule"))))
    assert [r.name for r in back.rules] == ["a & <b>: x"]
    with pytest.raises(FwshiftError, match="--target-version: '27.1'"):
        emitted(policy(rule), "27.1")
    many = [Rule(name=f"r{n}", origin=f"r{n}", src_zones=["lan"], dst_zones=[ANY], destinations=[f"10.1.{n // 250}.{n % 250}"]) for n in range(10500)]
    root, _, _ = emitted(policy(*many), "25.7")
    assert [r["sequence"] for r in mvc_rules(root)][-2:] == ["10499", "10500"]


def test_the_command_line_writes_for_a_series(tmp_path: object, capsys: pytest.CaptureFixture) -> None:
    import pathlib

    out = pathlib.Path(str(tmp_path)) / "out.xml"
    code = cli.main(["convert", str(DATA / "opnsense_sample.xml"), "--to", "opnsense", "--target-version", "25.7", "-o", str(out), "-q"])
    assert code == 0 and 'Filter version="1.0.4"' in out.read_text()
    assert cli.main(["convert", str(DATA / "opnsense_sample.xml"), "--to", "opnsense", "--target-version", "9", "-o", str(out), "-q"]) != 0
    assert "--target-version: '9'" in capsys.readouterr().err


# -- review round 32 ----------------------------------------------------------------------------------


def test_r32_outbound_nat_from_an_opt_network_keeps_the_word() -> None:
    """Outbound NAT from the network of an optN interface was written as an alias holding "opt1", a host name to OPNsense
    (and to pfSense): the rule matched nothing."""
    text = config(x("nat", x("outbound", x("mode", "advanced"))), snat=snat("opt1", PUBLIC[0], descr="dmz out"))
    p, _ = parse(text)
    for target in ("opnsense", "pfsense"):
        out = cli.convert(copy.deepcopy(p), target, Report())
        assert ">opt1<" in out and "nat_set" not in out, target
    judge = OPNsense(re.sub(r"<snatrules>.*?</snatrules>", "<snatrules/>", text))
    judge.restore(cli.convert(copy.deepcopy(p), "opnsense", Report()))
    pkt = Packet("DMZ", "WAN", "10.0.2.5", "192.0.2.9", "tcp", 1024, 443)
    assert judge.translation(pkt)[0] == PUBLIC[0]


def test_r32_a_tab_rule_for_both_directions_keeps_its_place() -> None:
    """A quick rule of a tab for both directions was moved before every rule of the groups and interfaces."""
    mvc = [mvc_rule("lan", src="lan", descr="pass", sequence=10),
           mvc_rule("lan", "block", dst="203.0.113.0/24", descr="block", sequence=20, direction="any")]
    legacy = x("filter", legacy_rule("lan", "block", dst="198.51.100.0/24", descr="old block", extra=x("direction", "any")))
    text = config(legacy, rules="".join(mvc))
    p, _ = parse(text)
    assert [r.name for r in p.rules] == ["block (leaving)", "old block (leaving)", "pass", "block", "old block"]
    judge = OPNsense(text)
    for pkt in (Packet("LAN", "WAN", "10.0.1.5", "203.0.113.9", "tcp", 1024, 80), Packet("DMZ", "WAN", "10.0.2.5", "203.0.113.9", "tcp", 1024, 80),
                Packet("DMZ", "LAN", "10.0.2.5", "10.0.1.9", "tcp", 1024, 80)):  # fmt: skip
        assert model_allows(p, pkt) == judge.allows(pkt), pkt


def test_r32_groups_of_one_sequence_are_ordered_as_one_tier() -> None:
    """Of groups with the same sequence, the newer kind of rule of every one of them comes first."""
    legacy = x("filter", legacy_rule("INSIDE", descr="old pass"))
    mvc = mvc_rule("SERVED", "block", dst="203.0.113.0/24", descr="new block")
    text = config(GROUPS_SAME, legacy, rules=mvc)
    p, _ = parse(text)
    assert [r.name for r in p.rules] == ["new block", "old pass"]
    pkt = Packet("GUEST", "WAN", "10.0.3.5", "203.0.113.9", "tcp", 1024, 80)
    assert model_allows(p, pkt) == OPNsense(text).allows(pkt) is False


def test_r32_what_leaves_after_source_nat_of_the_newer_kind_is_said() -> None:
    nat = x("nat", x("outbound", x("mode", "advanced")))
    rule = legacy_rule("opt2", "block", src="net:lan", descr="lan not out by guest", floating="out")
    p, _ = read(nat, x("filter", rule), snat=snat("lan", "", descr="lan", interface="opt2"))
    assert "after outbound NAT" in by_name(p)["lan not out by guest"].unsupported[0]
    p, _ = read(nat, x("filter", rule), onetoone=binat("198.51.100.12", "10.0.1.200"))
    assert "after outbound NAT" not in str(by_name(p)["lan not out by guest"].unsupported)  # (1:1 on WAN, not on GUEST)


def test_r32_a_disabled_alias_of_ports_inside_another_is_left_out() -> None:
    p, report = read(x("filter", legacy_rule("lan", "block", proto="tcp", dport="Webs", descr="web")), aliases=ALIASES)
    rule = by_name(p)["web"]
    assert p.services[rule.services[0]].entries[0].dst_ports == "80" and "RULE_NOT_LOADED" not in codes(report)
    _, report = read(x("filter", legacy_rule("lan", "block", proto="tcp", dport="Gone", descr="gone")), aliases=ALIASES)
    assert "RULE_NOT_LOADED" in codes(report)


@pytest.mark.parametrize("model", MODELS)
def test_r32_a_negated_source_of_outbound_nat_is_not_dropped(model: str) -> None:
    rule = x("rule", x("source", x("network", "10.0.1.0/24"), x("not", "1")), x("target", PUBLIC[0]), x("interface", "wan"),
             x("ipprotocol", "inet"), x("destination", x("any", "1")), x("descr", "all but lan"))  # fmt: skip
    p, _ = read(x("nat", x("outbound", x("mode", "advanced"), rule)), model=model)
    assert "a negated source in a NAT rule" in next(n for n in p.nat_rules if n.name == "all but lan").unsupported
    empty = rule.replace(x("not", "1"), x("not"))
    p, _ = read(x("nat", x("outbound", x("mode", "advanced"), empty)), model=model)
    assert bool(next(n for n in p.nat_rules if n.name == "all but lan").unsupported) == (model == "1.0.4")


def test_r32_outbound_nat_to_the_address_of_another_interface() -> None:
    p, _ = read(x("nat", x("outbound", x("mode", "advanced"))), snat=snat("10.0.1.0/24", "wanip", descr="by guest", interface="opt2"))
    nat = next(n for n in p.nat_rules if n.name == "by guest")
    assert nat.source_translation is not None and nat.source_translation.addresses == ["198.51.100.2"]
    pkt = Packet("LAN", "GUEST", "10.0.1.5", "10.0.3.9", "tcp", 1024, 80)
    assert model_translation(p, pkt)[0] == "198.51.100.2"


@pytest.mark.parametrize("model", MODELS)
def test_r32_a_port_forward_on_several_interfaces(model: str) -> None:
    nat = x("nat", x("outbound", x("mode", "disabled")),
            forward(model, "net:wanip", "22", "10.0.2.10", interface="wan,opt2", descr="ssh", mode="rule" if model != "1.0.4" else "pass"))
    text = config(nat, x("filter", legacy_rule("opt2", "pass", descr="guests")), model=model)
    p, report = parse(text)
    assert [n.name for n in p.nat_rules] == ["ssh", "ssh 2"] and "RULE_NOT_LOADED" not in codes(report)
    assert [n.src_zones for n in p.nat_rules] == [["WAN"], ["GUEST"]]
    if model != "1.0.4":
        assert "1 port forward registers" in next(n.message for n in report.notes if n.code == "OPNSENSE_REGISTERED_RULE")
    judge = OPNsense(text)
    for zone in ("WAN", "GUEST"):
        pkt = Packet(zone, "DMZ", "203.0.113.5" if zone == "WAN" else "10.0.3.5", "198.51.100.2", "tcp", 1024, 22)
        assert model_translation(p, pkt) == judge.translation(pkt) and model_allows(p, pkt) == judge.allows(pkt), zone


def test_r32_a_side_that_is_not_there_is_any() -> None:
    rule = "<rule><type>block</type><interface>lan</interface><ipprotocol>inet</ipprotocol><descr>bare</descr></rule>"
    p, report = read(x("filter", rule, legacy_rule("lan", descr="rest")))
    bare = by_name(p)["bare"]
    assert bare.sources == [ANY_V4] and bare.destinations == [ANY_V4] and "RULE_NOT_LOADED" not in codes(report)


def test_r32_one_way_one_to_one_comes_after_the_other_source_nat() -> None:
    nat = x("nat", x("outbound", x("mode", "hybrid")))
    text = config(nat, onetoone=binat("198.51.100.12", "10.0.1.50", "nat", "one way"), snat=snat("lan", "", descr="lan"))
    p, _ = parse(text)
    assert [n.name for n in p.nat_rules][-1] == "one way - outbound"
    pkt = Packet("LAN", "WAN", "10.0.1.50", "192.0.2.9", "tcp", 1024, 80)
    assert model_translation(p, pkt) == OPNsense(text).translation(pkt) == ("198.51.100.2", "Original", "Original")


def test_r32_icmpv6_rules_of_the_old_kind_take_no_type_of_icmp() -> None:
    rule = legacy_rule("lan", "block", proto="ipv6-icmp", family="inet6", descr="v6", extra=x("icmptype", "echoreq"))
    p, _ = read(x("filter", rule))
    assert p.services[by_name(p)["v6"].services[0]].entries[0].icmp_type is None


def test_r32_aliases_the_emitter_writes_are_names_opnsense_takes() -> None:
    """Host names stand in an alias of type host; names start with a letter; the type of an alias of the networks of
    interfaces is network."""
    p, _ = parse((DATA / "opnsense_sample.xml").read_text())
    p.address_groups["1stFloor"] = copy.deepcopy(p.address_groups["Updates"])
    p.address_groups["1stFloor"].name = "1stFloor"
    p.rules[5].destinations = ["1stFloor"]
    root = ET.fromstring(cli.convert(p, "opnsense", Report()))
    aliases = {a.findtext("name"): (a.findtext("type"), (a.findtext("content") or "").split("\n")) for a in root.iter("alias")}
    name = re.compile(r"[a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29})")
    assert all(name.fullmatch(n) for n in aliases), [n for n in aliases if not name.fullmatch(n)]
    assert aliases["Updates"] == ("network", ["192.0.2.10/31", "192.0.2.12/31", "Updates_hosts"])
    assert aliases["Updates_hosts"] == ("host", ["updates.example.net"]) and "x1stFloor" in aliases
    assert aliases["Inside_nets"][0] == "network"


def test_r32_the_network_of_an_interface_in_a_rule_for_ipv6_is_said_exactly() -> None:
    """OPNsense adds fe80::/10 to the network of an interface in a rule for IPv6: the word is written only where the
    members hold it too."""
    import test_pfsense as pf

    text = pf.config(pf.x("filter", pf.rule("lan", src="net:lan", family="inet6", descr="six"),
                          pf.rule("lan", src="net:lan", family="inet", descr="four")))  # fmt: skip
    p, _ = pf.parse(text)
    rules = {r["description"]: r for r in mvc_rules(ET.fromstring(cli.convert(p, "opnsense", Report())))}
    assert rules["four"]["source_net"] == "lan" and rules["six"]["source_net"] != "lan"
    p, _ = read(rules=mvc_rule("lan", src="lan", family="inet6", descr="six"))
    assert mvc_rules(ET.fromstring(cli.convert(p, "opnsense", Report())))[0]["source_net"] == "lan"


def test_r32_flags_of_the_newer_models() -> None:
    """An empty BooleanField is false: an empty <enabled/> is a disabled rule, alias, Source NAT or 1:1 rule."""
    mvc = mvc_rule("lan", descr="off").replace(x("enabled", "1"), x("enabled")) + mvc_rule("lan", descr="slow").replace(x("quick", "1"), x("quick"))
    off_alias = alias("Gone2", "network", "10.0.3.0/24").replace(x("enabled", "1"), x("enabled"))
    p, report = read(x("nat", x("outbound", x("mode", "advanced"))), rules=mvc, aliases=off_alias,
                     snat=snat("lan", "", descr="lan").replace(x("enabled", "1"), x("enabled")))  # fmt: skip
    assert not by_name(p)["off"].enabled and "FLOATING_LAST_MATCH" in codes(report)
    assert "disabled" in p.address_groups["Gone2"].unsupported and not next(n for n in p.nat_rules if n.name == "lan").enabled


def test_r32_a_disabled_rule_of_an_unknown_type_does_not_refuse_the_file() -> None:
    p, report = read(x("filter", legacy_rule("lan", "allow", descr="odd", extra=x("disabled", "1")), legacy_rule("lan", descr="rest")),
                     rules=mvc_rule("lan", "drop", descr="odd new", enabled="0"))  # fmt: skip
    assert [r.name for r in p.rules] == ["rest"]
    assert "'odd' (type 'allow')" in next(n.message for n in report.notes if n.code == "OPNSENSE_DISABLED_ODD")


# -- mutation check -----------------------------------------------------------------------------------


def test_m24_a_rule_of_the_newer_kind_without_an_ip_version_is_for_ipv4() -> None:
    rule = mvc_rule("lan", dst="Servers", descr="no family").replace(x("ipprotocol", "inet"), "")
    p, _ = read(rules=rule, aliases=ALIASES)
    assert by_name(p)["no family"].sources == [ANY_V4]


@pytest.mark.parametrize("model", MODELS)
def test_m24_a_port_forward_that_passes_by_itself(model: str) -> None:
    nat = x("nat", x("outbound", x("mode", "disabled")), forward(model, "net:wanip", "22", "10.0.2.10", mode="pass", descr="ssh"))
    text = config(nat, x("filter", legacy_rule("wan", "block", descr="nothing in")), model=model)
    p, _ = parse(text)
    assert "ssh - pass" in by_name(p)
    pkt = Packet("WAN", "DMZ", "203.0.113.5", "198.51.100.2", "tcp", 1024, 22)
    assert model_allows(p, pkt) == OPNsense(text).allows(pkt) is True


def test_m24_a_negated_destination_of_source_nat_is_said() -> None:
    rule = snat("lan", "", "192.0.2.0/24", "not to the test net").replace(x("destination_not", "0"), x("destination_not", "1"))
    p, _ = read(x("nat", x("outbound", x("mode", "advanced"))), snat=rule)
    assert "negated destination in a NAT rule" in next(n for n in p.nat_rules if n.name == "not to the test net").unsupported


def test_m24_what_an_alias_leaves_out_does_not_depend_on_the_order_of_its_entries() -> None:
    p, _ = read(rules=mvc_rule("lan", dst="Odd", descr="odd"), aliases=alias("Odd", "network", "!10.0.2.0/24", "10.0.2.11", "10.0.0.0/8"))
    members = p.address_groups["Odd"].members
    assert members == ["10.0.0.0/23", "10.0.2.11", "10.0.3.0-10.255.255.255"] and not any(m.startswith("10.0.2.0") for m in members)
