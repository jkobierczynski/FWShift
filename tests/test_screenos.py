# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Juniper ScreenOS (source only): ``get config`` read into the model, trap by trap, and packets through both.

The random configurations at the end are judged by ``screenos_allows``, which decides from the generator's own data
(zones and their blocking, address books per zone, services, policies per pair of zones, global policies, the
default policy) and shares no code with the parser. Both are written from the same reading of Juniper's
documentation (DEVELOPMENT.md): they find where the parser disagrees with that reading, not where the reading is wrong.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_verdict

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.model import ANY, ANY_V4, Action, AddressKind, Policy, Protocol, SnatKind
from fwshift.netutil import parse_literal
from fwshift.parsers import screenos as parse_screenos
from fwshift.report import Report, Severity


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_screenos.parse(text.encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


def rule(p: Policy, name: str):  # type: ignore[no-untyped-def]
    return next(r for r in p.rules if r.name == name)


BASE = """\
set zone id 100 "Lab"
set interface "ethernet0/0" zone "Untrust"
set interface "ethernet0/1" zone "DMZ"
set interface "ethernet0/2" zone "Trust"
set interface "ethernet0/3" zone "Lab"
set interface ethernet0/0 ip 203.0.113.2/24
set interface ethernet0/1 ip 10.20.0.1/24
set interface ethernet0/2 ip 10.10.0.1/16
set interface ethernet0/3 ip 10.40.0.1/24
set address "Trust" "lan" 10.10.0.0 255.255.0.0
set address "DMZ" "web" 10.20.0.10 255.255.255.255
set address "Untrust" "remote" 198.51.100.0 255.255.255.0
"""


# -- the sample ----------------------------------------------------------------------------------------------


def test_sample_zones_order_and_policies() -> None:
    p, report = parse((DATA / "screenos_sample.conf").read_text())
    assert p.vendor == "screenos" and p.default_interzone == Action.DENY
    assert set(p.zones) == {"Untrust", "DMZ", "Servers", "Lab", "Trust"}
    assert p.zones["Trust"].interfaces == ["bgroup0"] and p.zones["Trust"].intrazone_allow
    assert not p.zones["Untrust"].intrazone_allow and not p.zones["Servers"].intrazone_allow
    names = [r.name for r in p.rules]
    # Zones that do not block intra-zone traffic first; 'set policy move 20 before 4'; global policies last.
    assert names[:3] == ["intrazone-DMZ", "intrazone-Lab", "intrazone-Trust"]
    assert names.index("policy-20") == names.index("web-in") - 1
    assert names[-2:] == ["policy-17", "policy-18"]
    assert rule(p, "policy-18").src_zones == [ANY] and rule(p, "policy-18").dst_zones == [ANY]
    lan_out = rule(p, "lan-out")
    assert lan_out.services == ["web", "dns-split"] and lan_out.log_end and lan_out.source_ids == {"screenos.policy_id": "1"}
    assert rule(p, "policy-7").negate_source and rule(p, "policy-7").sources == ["blocked"]
    assert rule(p, "policy-8").destinations == ["db-net", "app1"]
    assert rule(p, "policy-9").enabled is False and "SCREENOS_INTRAZONE_IGNORED" in codes(report, "rule", "policy-9")
    assert rule(p, "policy-10").enabled  # Servers blocks intra-zone traffic: its policies count
    assert rule(p, "policy-12").enabled is False
    assert rule(p, "policy-20").action == Action.RESET_CLIENT
    for name, text in (("policy-14", "tunnel"), ("policy-15", "authentication")):
        assert any(text in u for u in rule(p, name).unsupported), name
    assert rule(p, "policy-16").dst_zones == [ANY] and "Global" not in p.zones and not rule(p, "policy-16").enabled
    assert "SCREENOS_GLOBAL_ZONE" in codes(report, "rule", "policy-16")
    assert p.services["FTP-Get"].unsupported and p.services["HTTP"].builtin == "screenos"
    assert rule(p, "policy-19").handling == {"application": "IGNORE"}
    assert "SCREENOS_VIP_PORT" in codes(report, "rule", "policy-5")


def test_sample_objects() -> None:
    p, report = parse((DATA / "screenos_sample.conf").read_text())
    assert p.addresses["lan"].value == "10.10.0.0/16" and p.addresses["lan"].description == "office LAN"
    assert p.addresses["updates"].kind == AddressKind.FQDN
    assert p.addresses["lan-v6"].value == "2001:db8:10::/64"
    # 'printer' is one address in Trust and another in DMZ; the policy of Trust gets Trust's.
    assert rule(p, "policy-9").destinations == ["printer (Trust)"] and p.addresses["printer (Trust)"].value == "10.10.9.9/32"
    assert "SCREENOS_ZONE_OBJECT" in codes(report)
    assert p.address_groups["blocked"].members == ["bad-host", "partner-net"]
    assert p.addresses["MIP(203.0.113.24)"].value == "203.0.113.24/29"
    assert p.services["hi-src"].entries[0].src_ports == "1024-2000" and p.services["hi-src"].entries[0].dst_ports == "9000"
    assert p.services["tcp-8080"].entries[0].dst_ports == "8080-8081"
    assert [e.protocol for e in p.services["dns-split"].entries] == [Protocol.UDP, Protocol.TCP]
    assert p.services["esp"].entries[0].ip_protocol == 50
    assert p.services["echo-only"].entries[0].icmp_type == 8
    assert p.service_groups["web"].members == ["HTTP", "HTTPS", "tcp-8080"]
    assert "SCREENOS_PREDEFINED" in codes(report) and "SCREENOS_POLICY_ORDER" in codes(report)
    assert p.zone_networks["Trust"] == ["10.10.0.0/16", "10.11.0.0/16", "2001:db8:10::/64"]


def test_sample_nat() -> None:
    p, report = parse((DATA / "screenos_sample.conf").read_text())
    nats = {n.name: n for n in p.nat_rules}
    order = [n.name for n in p.nat_rules]
    # Policy NAT in the order of the policies, one rule per service; then MIPs, VIPs, interfaces in NAT mode.
    assert order[:4] == ["nat-lan-out", "nat-lan-out-2", "nat-policy-3", "nat-policy-7"]
    assert order[4:] == ["mip-203.0.113.10", "mip-203.0.113.24", "vip-203.0.113.20-80", "vip-203.0.113.20-8443", "nat-mode-Trust"]
    assert nats["nat-lan-out"].service == "web" and nats["nat-lan-out-2"].service == "dns-split"
    assert nats["nat-lan-out"].source_translation is not None and nats["nat-lan-out"].source_translation.addresses == ["DIP(4)"]
    assert p.addresses["DIP(4)"].value == "203.0.113.100-203.0.113.120" and "DIP(5)" not in p.addresses
    snat = nats["nat-policy-3"].source_translation
    assert snat is not None and snat.kind == SnatKind.INTERFACE and snat.interface == "ethernet0/0"
    assert "NAT_OVERLAP" in codes(report, "nat", "nat-policy-3")
    assert nats["nat-policy-7"].unsupported  # (a negated source)
    mip = nats["mip-203.0.113.24"]
    assert mip.src_zones == ["Servers"] and mip.dst_zones == ["Untrust"] and mip.sources == ["10.30.0.24/29"]
    assert mip.source_translation is not None and mip.source_translation.bidirectional
    vip = nats["vip-203.0.113.20-8443"]
    assert vip.destinations == ["VIP(203.0.113.20)"] and vip.service == "tcp-8443" and vip.dst_zones == ["Untrust"]
    assert vip.destination_translation is not None and vip.destination_translation.address == "10.20.0.21"
    assert vip.destination_translation.port == "443"
    assert nats["nat-mode-Trust"].src_zones == ["Trust"] and nats["nat-mode-Trust"].dst_zones == ["Untrust"]


# -- traps, one by one ---------------------------------------------------------------------------------------


def test_global_policies_come_after_those_of_the_pair_wherever_they_are() -> None:
    p, _ = parse(BASE + """\
set policy id 1 from "Global" to "Global"  "Any" "Any" "ANY" permit
set policy id 2 from "Trust" to "Untrust"  "Any" "Any" "HTTP" deny
set policy id 3 from "Trust" to "Untrust"  "Any" "Any" "ANY" permit
""")
    assert [r.name for r in p.rules] == ["policy-2", "policy-3", "policy-1"]


def test_move_top_and_before() -> None:
    p, report = parse(BASE + """\
set policy id 1 from "Trust" to "Untrust"  "Any" "Any" "HTTP" permit
set policy id 2 from "Trust" to "Untrust"  "Any" "Any" "SSH" permit
set policy id 3 from "Trust" to "Untrust"  "Any" "Any" "ANY" deny
set policy id 4 top from "Trust" to "Untrust"  "Any" "remote" "ANY" deny
set policy id 5 before 2 from "Trust" to "Untrust"  "lan" "Any" "DNS" permit
set policy move 1 after 3
set policy move 9 before 1
""")
    assert [r.name for r in p.rules] == ["policy-4", "policy-5", "policy-2", "policy-3", "policy-1"]
    assert "SCREENOS_POLICY_ORDER" in codes(report) and "SCREENOS_NOT_READ" in codes(report)


def test_intrazone_blocking() -> None:
    p, report = parse(BASE + """\
set zone "DMZ" block
unset zone "Untrust" block
set policy id 1 from "Trust" to "Trust"  "Any" "Any" "ANY" deny
set policy id 2 from "DMZ" to "DMZ"  "Any" "Any" "ANY" deny
set policy id 3 from "Untrust" to "Untrust"  "Any" "Any" "ANY" deny
""")
    assert {p.rules[0].name, p.rules[1].name} == {"intrazone-Trust", "intrazone-Untrust"}
    assert len([r.name for r in p.rules if r.name.startswith("intrazone")]) == 2
    assert not rule(p, "policy-1").enabled and not rule(p, "policy-3").enabled and rule(p, "policy-2").enabled
    assert p.zones["DMZ"].intrazone_allow is False and p.zones["Lab"].intrazone_allow is True
    assert "SCREENOS_INTRAZONE_ALLOW" in codes(report, "rule", "intrazone-Trust")
    # Untrust blocks by default; without intra-zone policies or a global deny no rule is needed.
    q, _ = parse(BASE)
    assert q.zones["Untrust"].intrazone_allow is False and not q.rules


def test_default_permit_all() -> None:
    p, report = parse(BASE + "set policy default-permit-all\n")
    assert p.default_interzone == p.default_intrazone == Action.ALLOW and "SCREENOS_DEFAULT_PERMIT" in codes(report)
    q, _ = parse(BASE + "set policy default-permit-all\nunset policy default-permit-all\n")
    assert q.default_interzone == Action.DENY


def test_address_books_per_zone_and_the_global_book() -> None:
    p, _ = parse(BASE + """\
set address "Trust" "srv" 10.10.1.1 255.255.255.255
set address "DMZ" "srv" 10.20.0.5 255.255.255.255
set address "Global" "srv" 192.0.2.1 255.255.255.255
set address "Global" "shared" 192.0.2.2 255.255.255.255
set address "Trust" "same" 10.10.9.9 255.255.255.255
set address "DMZ" "same" 10.10.9.9 255.255.255.255
set policy id 1 from "Trust" to "DMZ"  "srv" "srv" "ANY" permit
set policy id 2 from "Untrust" to "DMZ"  "srv" "shared" "ANY" permit
set policy id 3 from "Global" to "Global"  "srv" "Any" "ANY" permit
set policy id 4 from "Trust" to "DMZ"  "same" "same" "ANY" permit
set policy id 5 from "Trust" to "DMZ"  "nowhere" "Any" "ANY" permit
""")
    values = {name: a.value for name, a in p.addresses.items()}
    assert [values[m] for m in rule(p, "policy-1").sources + rule(p, "policy-1").destinations] == ["10.10.1.1/32", "10.20.0.5/32"]
    # Untrust has no 'srv': the Global book's.
    assert [values[m] for m in rule(p, "policy-2").sources + rule(p, "policy-2").destinations] == ["192.0.2.1/32", "192.0.2.2/32"]
    assert values[rule(p, "policy-3").sources[0]] == "192.0.2.1/32"
    assert rule(p, "policy-4").sources == rule(p, "policy-4").destinations == ["same"]  # one address in both books
    assert rule(p, "policy-5").unsupported


def test_members_from_the_policy_context_and_negation() -> None:
    p, _ = parse(BASE + """\
set address "Trust" "admins" 10.10.5.0 255.255.255.0
set policy id 1 from "Trust" to "Untrust"  ! "lan" "remote" "HTTP" permit
set policy id 1
set src-address "admins"
set service "HTTPS"
set dst-address "Any"
exit
set policy id 2 from "Trust" to "Untrust"  "lan" "remote" "SSH" deny
set policy id 2
set dst-address negate
exit
set policy id 3 from "Trust" to "Untrust"  "lan" !"remote" "SSH" deny
""")
    first = rule(p, "policy-1")
    assert first.negate_source and first.sources == ["lan", "admins"] and first.services == ["HTTP", "HTTPS"]
    assert first.destinations == [ANY]
    assert rule(p, "policy-2").negate_destination and not rule(p, "policy-2").negate_source
    assert rule(p, "policy-3").negate_destination and rule(p, "policy-3").destinations == ["remote"]


def test_services() -> None:
    p, report = parse(BASE + """\
set service "range" protocol tcp src-port 0-65535 dst-port 1000-1010
set service "two" protocol udp src-port 0-65535 dst-port 514-514
set service "two" + tcp src-port 0-65535 dst-port 601-601
set service "two" timeout never
set service "bad" protocol tcp src-port 0-65535 dst-port 90-80
set service "rpc" protocol ms-rpc uuid 12345678-1234-abcd-ef00-0123456789ab
set service "proto" protocol 47 src-port 0-65535 dst-port 0-65535
set service "icmp-any-code" protocol icmp type 3
set group service "grp" add "range"
set group service "grp" add "two"
set group service "loop" add "loop"
set policy id 1 from "Trust" to "Untrust"  "Any" "Any" "grp" permit
set policy id 2 from "Trust" to "Untrust"  "Any" "Any" "bad" permit
set policy id 3 from "Trust" to "Untrust"  "Any" "Any" "rpc" permit
set policy id 4 from "Trust" to "Untrust"  "Any" "Any" "NO-SUCH" permit
set policy id 5 from "Trust" to "Untrust"  "Any" "Any" "MS-RPC-ANY" permit
set policy id 6 from "Trust" to "Untrust"  "Any" "Any" "loop" permit
set policy id 7 from "Trust" to "Untrust"  "Any" "Any" "proto" permit
set policy id 8 from "Trust" to "Untrust"  "Any" "Any" "icmp-any-code" permit
""")
    assert p.services["range"].entries[0].dst_ports == "1000-1010"
    assert [(e.protocol, e.dst_ports) for e in p.services["two"].entries] == [(Protocol.UDP, "514"), (Protocol.TCP, "601")]
    assert p.services["bad"].unsupported and p.services["rpc"].unsupported and p.services["MS-RPC-ANY"].unsupported
    assert rule(p, "policy-4").unsupported and "OBJECTS_MISSING" in codes(report)
    assert p.services["loop"].unsupported
    assert p.services["proto"].entries[0].ip_protocol == 47
    entry = p.services["icmp-any-code"].entries[0]
    assert entry.icmp_type == 3 and entry.icmp_code is None


def test_policy_nat_and_exemptions() -> None:
    p, report = parse(BASE + """\
set interface ethernet0/0 dip 4 203.0.113.100 203.0.113.120 fix-port
set interface ethernet0/0 dip 5 203.0.113.130 203.0.113.130
set policy id 1 from "Trust" to "Untrust"  "lan" "remote" "SSH" permit
set policy id 2 from "Trust" to "Untrust"  "lan" "Any" "ANY" nat src dip-id 4 permit
set policy id 3 from "DMZ" to "Untrust"  "web" "Any" "HTTP" nat src dip-id 5 permit
set policy id 4 from "Untrust" to "DMZ"  "Any" "web" "HTTP" nat dst ip 10.20.0.11 port 8080 permit
set policy id 5 from "Untrust" to "DMZ"  "Any" "web" "SSH" nat dst ip 10.20.0.11 to 10.20.0.19 permit
set policy id 6 from "DMZ" to "Untrust"  "web" "Any" "SSH" nat src dip-id 9 permit
set policy id 7 from "DMZ" to "Untrust"  "web" "Any" "SMTP" nat src deny
""")
    nats = {n.name: n for n in p.nat_rules}
    # No MIP, VIP or NAT mode: policy 1 passes SSH to remote untranslated ahead of policy 2.
    assert [n.name for n in p.nat_rules][:2] == ["nonat-policy-1", "nat-policy-2"]
    exempt = nats["nonat-policy-1"]
    assert exempt.source_translation is None and exempt.service == "SSH" and exempt.destinations == ["remote"]
    assert "NAT_EXEMPTION" in codes(report, "nat", "nonat-policy-1")
    pool = nats["nat-policy-2"].source_translation
    assert pool is not None and pool.kind == SnatKind.DYNAMIC and pool.addresses == ["DIP(4)"]  # fix-port: no PAT
    one = nats["nat-policy-3"].source_translation
    assert one is not None and one.kind == SnatKind.DYNAMIC_PORT and nats["nat-policy-3"].service == "HTTP"
    dnat = nats["nat-policy-4"].destination_translation
    assert dnat is not None and (dnat.address, dnat.port) == ("10.20.0.11", "8080")
    assert nats["nat-policy-5"].unsupported and nats["nat-policy-6"].unsupported
    assert "nat-policy-7" not in nats  # a deny translates nothing


def test_mip_vip_and_nat_mode() -> None:
    p, report = parse(BASE + """\
set interface ethernet0/2 nat
set interface ethernet0/0 mip 203.0.113.10 host 10.20.0.10 netmask 255.255.255.255 vr "trust-vr"
set interface ethernet0/0 mip 203.0.113.11 host 10.20.0.11 netmask 255.255.255.0
set interface ethernet0/0 vip interface-ip 2222 "SSH" 10.20.0.12
set interface ethernet0/0 vip 203.0.113.20 80 "DNS" 10.20.0.13
set policy id 1 from "Untrust" to "DMZ"  "Any" "MIP(203.0.113.10)" "HTTP" permit
set policy id 2 from "Untrust" to "DMZ"  "Any" "VIP(ethernet0/0)" "SSH" permit
set policy id 3 from "Trust" to "Untrust"  "lan" "Any" "ANY" nat src permit
""")
    nats = {n.name: n for n in p.nat_rules}
    assert p.addresses["MIP(203.0.113.10)"].value == "203.0.113.10/32"
    assert rule(p, "policy-1").destinations == ["MIP(203.0.113.10)"] and rule(p, "policy-1").dst_zones == ["DMZ"]
    assert nats["mip-203.0.113.11"].unsupported  # host bits under its netmask
    assert p.addresses["VIP(ethernet0/0)"].value == "203.0.113.2/32"
    ssh = nats["vip-ethernet0/0-2222"]
    assert ssh.destination_translation is not None and ssh.destination_translation.port == "22"
    assert "SCREENOS_VIP_PORT" in codes(report, "rule", "policy-2")
    assert nats["vip-203.0.113.20-80"].unsupported  # DNS is two protocols
    assert "SCREENOS_NAT_MODE" in codes(report, "nat", "nat-mode-Trust")
    # A MIP and a NAT mode interface exist: no no-NAT rules, the overlap is reported instead.
    assert not any(n.name.startswith("nonat") for n in p.nat_rules)


def test_not_converted_never_wider() -> None:
    p, report = parse(BASE + """\
set policy id 1 from "Trust" to "Untrust"  "Any" "Any" "HTTP" permit webauth
set policy id 2 from "Trust" to "Untrust"  "Any" "Any" "HTTP" permit frobnicate 3
set policy id 3 from "Trust" to "Untrust"  "Any" "Any" "HTTP"
set policy id 4 from "Trust" to "Global"  "Any" "Any" "HTTP" deny
set policy id 5 from "Trust" to "Untrust"  ! "Any" "Any" "HTTP" deny
set policy id 6 from "Trust" to "Untrust"  "Any" "Any" "HTTP" permit schedule "work" log count traffic gbw 0 priority 0 mbw 0
set policy id 6 application "HTTP"
set policy id 7 from "Trust" to "Untrust"  "Any" "Any" "HTTP" permit url-filter
""")
    for name in ("policy-1", "policy-2", "policy-3", "policy-5"):
        assert rule(p, name).unsupported, name
    assert not rule(p, "policy-4").enabled  # (a zone to the Global zone: decides nothing)
    six = rule(p, "policy-6")
    assert not six.unsupported and six.schedule == "work" and six.log_end and six.handling["traffic"].startswith("gbw")
    assert "SCREENOS_APPLICATION" in codes(report, "rule", "policy-6")
    assert rule(p, "policy-7").profiles == {"url-filter": "yes"}


def test_contexts_and_lines_not_read() -> None:
    p, report = parse(BASE + """\
set vrouter "trust-vr"
set route 10.50.0.0/16 interface ethernet0/2 gateway 10.10.0.254
set protocol bgp 65000
set service "x" protocol tcp src-port 0-65535 dst-port 1-1
exit
exit
set address "Trust" "broken"
set policy id 1 from "Trust" to "Untrust"  "lan" "Any" "ANY" permit
set policy id 1
set src-address "lan"
set something-new
exit
set policy id 77
exit
set vsys "tenant1"
set policy id 1 from "Trust" to "Untrust"  "Any" "Any" "ANY" deny
set policy id 1
exit
set address "Trust" "in-vsys" 10.10.7.0 255.255.255.0
exit
set address "Trust" "root" 10.10.8.0 255.255.255.0
set policy id 2 from "Trust" to "Untrust"  "root" "Any" "ANY" permit
set policy id 3 from "Trust" to "Untrust"  "in-vsys" "Any" "ANY" permit
""")
    assert "x" not in p.services  # (inside the BGP context, not a service)
    assert p.zone_networks["Trust"] == ["10.10.0.0/16", "10.50.0.0/16"]
    assert rule(p, "policy-1").unsupported and rule(p, "policy-1").action == Action.ALLOW
    assert "SCREENOS_NOT_READ" in codes(report) and "SCREENOS_VSYS" in codes(report)
    assert not rule(p, "policy-2").unsupported and rule(p, "policy-3").unsupported  # (the vsys's book is not read)
    assert rule(p, "policy-1").action == Action.ALLOW


def test_bad_input() -> None:
    with pytest.raises(ParseError, match="quoted string"):
        parse('set address "Trust "x" 10.0.0.1 255.255.255.255\n')
    with pytest.raises(ParseError, match="no ScreenOS configuration"):
        parse("set clock timezone 1\n")


def test_detection() -> None:
    data = (DATA / "screenos_sample.conf").read_bytes()
    assert parse_screenos.looks_like_screenos(data) and cli.detect_format(data) == "screenos"
    for other in sorted(DATA.iterdir()):
        if other.is_file() and "_sample." in other.name and not other.name.startswith("screenos"):
            assert not parse_screenos.looks_like_screenos(other.read_bytes()), other.name
    assert cli.detect_format(b'set policy id 3 from "Trust" to "Untrust" "Any" "Any" "ANY" permit\n') == "screenos"
    assert cli.detect_format(b"set address web ip-netmask 10.0.0.1/32\n") == "panos"
    assert cli.detect_format(b"set security policies from-zone a to-zone b policy p then permit\n") == "junos"


def test_converts_to_every_target(tmp_path) -> None:  # type: ignore[no-untyped-def]
    for target in ("junos", "fortios", "asa", "iptables"):
        out = tmp_path / f"out.{target}"
        assert cli.main(["convert", str(DATA / "screenos_sample.conf"), "--to", target, "-o", str(out), "-q"]) == 0
        assert out.read_text(encoding="utf-8")


# -- a ScreenOS made up at random, judged without the parser -------------------------------------------------

ZONES = ["Trust", "Untrust", "DMZ", "Lab"]
PORTS = [22, 53, 80, 443, 1000, 1005, 8080, 9000]


@dataclass
class _Policy:
    number: int
    src: str
    dst: str
    sources: List[str]
    destinations: List[str]
    services: List[str]
    negate_src: bool
    negate_dst: bool
    action: str
    enabled: bool


@dataclass
class Lab:
    text: str
    books: Dict[str, Dict[str, List[str]]]  # zone -> name -> literal networks (groups flattened)
    services: Dict[str, List[Tuple[str, str, str, Optional[int]]]]  # name -> (protocol, dst ports, src ports, icmp type)
    blocked: Dict[str, bool]
    policies: List[_Policy] = field(default_factory=list)  # in the order of evaluation
    default_permit: bool = False


def random_lab(rng: random.Random) -> Lab:
    books: Dict[str, Dict[str, List[str]]] = {
        "Trust": {"n0": ["10.0.0.0/24"], "half": ["10.0.1.128/25"], "host": ["10.0.0.17/32"]},
        "DMZ": {"n0": ["10.0.3.0/24"], "web": ["10.0.2.34/32"]},
        "Untrust": {"far": ["10.0.4.0/24"], "n1": ["10.0.1.0/24"]},
        "Lab": {"lab": ["10.0.2.0/24"]},
        "Global": {"host": ["10.0.0.34/32"], "g1": ["10.0.1.0/24"]},
    }
    lines = ['set zone id 100 "Lab"'] + [f'set interface "ethernet0/{i}" zone "{z}"' for i, z in enumerate(ZONES)]
    for zone, names in books.items():
        for name, (network,) in names.items():
            address, length = network.split("/")
            mask = ".".join(str((0xFFFFFFFF << (32 - int(length)) >> s) & 255) for s in (24, 16, 8, 0))
            lines.append(f'set address "{zone}" "{name}" {address} {mask}')
    groups = {("Trust", "tg"): ["n0", "host"], ("DMZ", "dg"): ["n0", "web"]}
    for (zone, name), members in groups.items():
        lines.append(f'set group address "{zone}" "{name}"')
        lines += [f'set group address "{zone}" "{name}" add "{m}"' for m in members]
        books[zone][name] = [n for m in members for n in books[zone][m]]
    services: Dict[str, List[Tuple[str, str, str, Optional[int]]]] = {
        "HTTP": [("tcp", "80", "", None)], "HTTPS": [("tcp", "443", "", None)], "PING": [("icmp", "", "", 8)],
        "DNS": [("tcp", "53", "", None), ("udp", "53", "", None)], "GRE": [("47", "", "", None)],
        "rng": [("tcp", "1000-1010", "", None)], "src": [("tcp", "9000", "1024-2000", None)],
        "two": [("udp", "1005", "", None), ("tcp", "8080", "", None)],
    }
    lines += ['set service "rng" protocol tcp src-port 0-65535 dst-port 1000-1010',
              'set service "src" protocol tcp src-port 1024-2000 dst-port 9000-9000',
              'set service "two" protocol udp src-port 0-65535 dst-port 1005-1005',
              'set service "two" + tcp src-port 0-65535 dst-port 8080-8080',
              'set group service "sg"', 'set group service "sg" add "HTTP"', 'set group service "sg" add "rng"']  # fmt: skip
    services["sg"] = services["HTTP"] + services["rng"]
    blocked = {"Trust": False, "Untrust": True, "DMZ": False, "Lab": False}
    for zone in ("Trust", "DMZ", "Untrust", "Lab"):
        choice = rng.random()
        if choice < 0.3:
            lines.append(f'set zone "{zone}" block')
            blocked[zone] = True
        elif choice < 0.45:
            lines.append(f'unset zone "{zone}" block')
            blocked[zone] = False
    lab = Lab("", books, services, blocked, default_permit=rng.random() < 0.2)
    if lab.default_permit:
        lines.append("set policy default-permit-all")

    def names(zone: str) -> List[str]:
        return sorted(set(books.get(zone, {})) | set(books["Global"]))

    order: List[_Policy] = []
    for number in range(1, rng.randint(4, 14)):
        if rng.random() < 0.2:
            src = dst = "Global"
        else:
            src, dst = rng.choice(ZONES), rng.choice(ZONES)
        pick_src = ["Any"] if rng.random() < 0.3 else rng.sample(names(src), rng.randint(1, 2))
        pick_dst = ["Any"] if rng.random() < 0.3 else rng.sample(names(dst), rng.randint(1, 2))
        pick_svc = ["ANY"] if rng.random() < 0.2 else rng.sample(sorted(services), rng.randint(1, 2))
        negate_src = pick_src != ["Any"] and rng.random() < 0.2
        negate_dst = pick_dst != ["Any"] and rng.random() < 0.2
        action = rng.choice(["permit", "permit", "deny", "reject"])
        policy = _Policy(number, src, dst, pick_src, pick_dst, pick_svc, negate_src, negate_dst, action, rng.random() > 0.1)
        bang_src, bang_dst = ("! " if negate_src else ""), ("! " if negate_dst else "")
        lines.append(f'set policy id {number} from "{src}" to "{dst}"  {bang_src}"{pick_src[0]}" {bang_dst}"{pick_dst[0]}" '
                     f'"{pick_svc[0]}" {action}{" log" if rng.random() < 0.3 else ""}')  # fmt: skip
        if not policy.enabled:
            lines.append(f"set policy id {number} disable")
        lines.append(f"set policy id {number}")
        lines += [f'set src-address "{n}"' for n in pick_src[1:]] + [f'set dst-address "{n}"' for n in pick_dst[1:]]
        lines += [f'set service "{n}"' for n in pick_svc[1:]]
        lines.append("exit")
        order.append(policy)
    for _ in range(rng.randint(0, 3)):
        moved, anchor = rng.sample(order, 2)
        where = rng.choice(["before", "after"])
        lines.append(f"set policy move {moved.number} {where} {anchor.number}")
        order.remove(moved)
        order.insert(order.index(anchor) + (where == "after"), moved)
    lab.policies, lab.text = order, "\n".join(lines) + "\n"
    return lab


def _within(address: str, network: str) -> bool:
    a, n = parse_literal(address), parse_literal(network)
    assert a is not None and n is not None
    return n[1] <= a[1] <= n[2]


def screenos_allows(lab: Lab, pkt: Packet) -> bool:
    """What the made-up device does with a packet that opens a connection, from the generator's own data."""
    if pkt.in_if == pkt.out_if and not lab.blocked[pkt.in_if]:
        return True  # inside a zone that does not block: no policy is looked at

    def address(name: str, zone: str, ip: str) -> bool:
        if name == "Any":
            return True
        book = lab.books[zone] if zone != "Global" and name in lab.books.get(zone, {}) else lab.books["Global"]
        return any(_within(ip, network) for network in book[name])

    def service(name: str) -> bool:
        if name == "ANY":
            return True
        for protocol, dports, sports, icmp in lab.services[name]:
            if protocol != pkt.proto:
                continue
            if protocol in ("tcp", "udp"):
                low, _, high = dports.partition("-")
                if int(low) <= pkt.dport <= int(high or low) and (not sports or int(sports.split("-")[0]) <= pkt.sport <= int(sports.split("-")[1])):
                    return True
            elif protocol == "icmp":
                if icmp is None or icmp == pkt.icmp_type:
                    return True
            else:
                return True
        return False

    pair = [x for x in lab.policies if x.src == pkt.in_if and x.dst == pkt.out_if]
    every = [x for x in lab.policies if x.src == x.dst == "Global"]
    for policy in pair + every:
        if not policy.enabled:
            continue
        zone_src = "Global" if policy.src == "Global" else pkt.in_if
        zone_dst = "Global" if policy.dst == "Global" else pkt.out_if
        if any(address(n, zone_src, pkt.src) for n in policy.sources) == policy.negate_src:
            continue
        if any(address(n, zone_dst, pkt.dst) for n in policy.destinations) == policy.negate_dst:
            continue
        if not any(service(n) for n in policy.services):
            continue
        return policy.action == "permit"
    return lab.default_permit


def model_allows(p: Policy, pkt: Packet) -> bool:
    verdict = model_verdict(p, pkt)
    if verdict is not None:
        return verdict
    if pkt.in_if == pkt.out_if:
        zone = p.zones.get(pkt.in_if)
        if zone is not None and zone.intrazone_allow is not None:
            return zone.intrazone_allow
        return p.default_intrazone == Action.ALLOW
    return p.default_interzone == Action.ALLOW


def random_packet(rng: random.Random) -> Packet:
    return Packet(rng.choice(ZONES), rng.choice(ZONES), f"10.0.{rng.randrange(5)}.{rng.choice([0, 17, 34, 129, 200])}",
                  f"10.0.{rng.randrange(5)}.{rng.choice([0, 17, 34, 129, 200])}", rng.choice(["tcp", "tcp", "udp", "icmp", "47"]),
                  rng.choice([1024, 1500, 40000]), rng.choice(PORTS), rng.choice([0, 8]))  # fmt: skip


@pytest.mark.parametrize("seed", range(30))
def test_random_configurations_decide_like_the_device(seed: int) -> None:
    rng = random.Random(seed)
    lab = random_lab(rng)
    p, report = parse(lab.text)
    assert not any(r.unsupported for r in p.rules), [r.unsupported for r in p.rules if r.unsupported]
    assert not any(f.severity == Severity.REVIEW for f in report.notes), report.notes
    for _ in range(300):
        pkt = random_packet(rng)
        assert model_allows(p, pkt) == screenos_allows(lab, pkt), (pkt, lab.text)


def test_any_ipv4_and_any_ipv6() -> None:
    p, _ = parse(BASE + 'set policy id 1 from "Trust" to "Untrust"  "Any-IPv4" "Any-IPv6" "ANY" permit\n')
    assert rule(p, "policy-1").sources == [ANY_V4] and rule(p, "policy-1").destinations == ["::/0"]
