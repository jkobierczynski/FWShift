# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco ASA: parser, emitter, and packet-level equivalence between a configuration and the model."""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

import pytest
from helpers import DATA, AsaConfig, load, run
from test_iptables import Packet, _in, model_verdict, random_model

from fwshift import cli, transform
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy
from fwshift.model import Protocol
from fwshift.model import Rule, RuleScope, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.netutil import normalize
from fwshift.options import Options
from fwshift.parsers import asa as parse_asa
from fwshift.report import Report, Severity


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_asa.parse(text.encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    if not kind:
        return [note.code for note in report.notes]
    return [finding.code for finding in report.item(kind, name).findings]


HEAD = """ASA Version 9.12(4)
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.10.0.1 255.255.0.0
interface GigabitEthernet0/2
 nameif dmz
 security-level 50
 ip address 10.20.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 203.0.113.1
"""


def rules_of(body: str, head: str = HEAD) -> Policy:
    return parse(head + body)[0]


def listed(p: Policy) -> List[Rule]:
    """The rules that come from access list entries, without those for interfaces that have no list."""
    return [rule for rule in p.rules if not rule.name.startswith("implicit-")]


# -- the sample ---------------------------------------------------------------------


def test_sample_objects() -> None:
    p, report = load("asa_sample.cfg")
    assert p.vendor == "asa" and p.lookup_after_dnat
    assert list(p.zones) == ["outside", "inside", "dmz", "guest"]  # the management-only interface forwards nothing
    assert p.zones["outside"].interfaces == ["GigabitEthernet0/0"]
    assert p.addresses["web-srv"].value == "10.20.0.10/32" and p.addresses["web-srv"].description == "Public web server"
    assert p.addresses["inside-v6"].value == "2001:db8:10::/64"
    assert p.addresses["admin-range"].kind == AddressKind.RANGE
    assert p.addresses["updates"].kind == AddressKind.FQDN and p.addresses["updates"].fqdn_family == 4
    assert p.address_groups["dmz-servers"].members == ["web-srv", "mail-srv", "10.20.0.50"]  # a name becomes its address
    assert p.address_groups["internal"].members == ["inside-net", "10.40.0.0/16", "dmz-servers"]
    assert [(e.protocol, e.dst_ports) for e in p.services["dns-ntp"].entries] == [
        (Protocol.TCP, "53"), (Protocol.UDP, "53"), (Protocol.UDP, "123")]  # fmt: skip
    assert p.service_groups["mail-services"].members == ["app-8443", "mail-services-inline"]
    assert p.services["web-ports"].entries[0].dst_ports == "80,443,8000-8010"
    assert [e.icmp_type for e in p.services["ping-types"].entries] == [8, 0]
    assert p.services["tcp-22"].builtin == "asa" and not p.services["web-ports"].builtin


def test_sample_rules() -> None:
    p, report = load("asa_sample.cfg")
    by_name = {rule.name: rule for rule in p.rules}
    web = by_name["outside_access_in-1"]
    # The entry names the real address; the model wants the one the client used as well.
    assert web.src_zones == ["outside"] and web.dst_zones == ["dmz"] and web.destinations == ["web-srv", "web-public"]
    assert web.description == "Published web server" and web.egress_implied
    assert "NAT_PORT_TRANSLATION" in codes(report, "rule", web.name)
    anywhere = by_name["inside_access_in-1"]
    assert anywhere.dst_zones == ["outside", "dmz", "guest"]  # every interface but the one it came in on
    deny = by_name["outside_access_in-4"]
    assert deny.action == Action.DROP and deny.dst_zones == [ANY] and deny.log_end
    assert by_name["inside_access_in-4"].schedule == "business-hours"
    assert by_name["inside_access_in-5"].destinations == [ANY_V6]
    assert by_name["inside_access_in-6"].destinations == ["10.20.0.50"] and by_name["inside_access_in-6"].dst_zones == ["dmz"]
    assert by_name["inside_access_in-7"].users == ["LOCAL\\alice"]
    assert not by_name["inside_access_in-8"].enabled
    high_ports = p.services[by_name["dmz_access_in-2"].services[0]].entries[0]
    assert (high_ports.src_ports, high_ports.dst_ports) == ("1024-65535", "25")
    implicit = by_name["implicit-guest"]
    assert implicit.src_zones == ["guest"] and implicit.dst_zones == ["outside"] and not implicit.egress_implied
    assert codes(report, "rule", "implicit-guest") == ["IMPLICIT_PERMIT"]
    assert {"UNBOUND_ACL", "VPN_BYPASS", "EGRESS_BY_ROUTE"} <= set(codes(report))
    assert not any(rule.unsupported for rule in p.rules)


def test_sample_nat() -> None:
    p, _ = load("asa_sample.cfg")
    exempt, forward, static, pat, guests = p.nat_rules  # twice NAT, object NAT (static first), after-auto
    assert exempt.source_translation is None and exempt.destination_translation is None
    assert (exempt.src_zones, exempt.dst_zones, exempt.sources, exempt.destinations) == (
        ["inside"], ["outside"], ["inside-net"], ["branch-net"])  # fmt: skip
    assert exempt.description == "VPN to the branch"
    # Written from the side of the server; read as what it is for a client.
    assert forward.src_zones == ["outside"] and forward.destinations == ["web-public"]
    assert forward.destination_translation == DestNat("web-srv", "8080")
    assert p.services[forward.service].entries[0].dst_ports == "80"
    assert static.name == "nat-mail-srv" and static.source_translation == SourceNat(
        SnatKind.STATIC, ["203.0.113.25"], bidirectional=True)  # fmt: skip
    assert pat.source_translation == SourceNat(
        SnatKind.INTERFACE, interface="GigabitEthernet0/0", interface_address="203.0.113.2")  # fmt: skip
    assert guests.name == "nat-after-auto-1" and guests.source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["guest-pool"])
    assert all(nat.combines for nat in p.nat_rules)


# -- what an entry says ----------------------------------------------------------------


@pytest.mark.parametrize(
    "ports,expected",
    [("eq www", "80"), ("lt 1024", "0-1023"), ("gt 1023", "1024-65535"), ("neq 25", "0-24,26-65535"),
     ("range 8000 8010", "8000-8010"), ("eq 65535", "65535"), ("neq 0", "1-65535")],
)  # fmt: skip
def test_port_operators(ports: str, expected: str) -> None:
    p = rules_of(f"access-list A extended permit tcp any any {ports}\naccess-group A in interface inside\n")
    assert p.services[p.rules[0].services[0]].entries[0].dst_ports == expected and not p.rules[0].unsupported


@pytest.mark.parametrize(
    "entry,why",
    [
        ("permit tcp any any eq nosuchport", "port"),
        ("permit tcp any any lt 0", "port"),
        ("permit tcp any any range 90 80", "port"),
        ("permit nosuchproto any any", "protocol"),
        ("permit ip any 10.0.0.0 0.0.0.255", "address"),  # a wildcard mask, as on a router
        ("permit ip any 10.0.0.0 255.0.255.0", "address"),
        ("permit ip any host 10.0.0.0/8", "host address"),
        ("permit ip any interface outside", "interface"),
        ("permit icmp any any nosuchtype", "ICMP"),
        ("permit ip any any eq 80", "port"),
        ("permit tcp any any eq 80 surprise", "surprise"),
        ("permit tcp any any eq 80 log 9", "'9'"),
        ("permit ip user any any any", "user any"),
        ("permit ip security-group name admins any any", "TrustSec"),
        ("permit ip object-group-security sg any any", "TrustSec"),
        ("permit tcp any object-group missing-ports any", "at the end"),
        ("permit object-group nothing any any", "not a protocol or service group"),
        ("permit ip any object-group users", "user group"),
        ("permit udp any any object-group tcp-only", "port group"),
    ],
)
def test_what_is_not_understood_makes_the_rule_unusable(entry: str, why: str) -> None:
    body = (
        "object-group user users\n user LOCAL\\x\n"
        "object-group service tcp-only tcp\n port-object eq 80\n"
        f"access-list A extended {entry}\naccess-group A in interface inside\n"
    )
    p = rules_of(body)
    assert [rule.name for rule in p.rules] == ["A-1", "implicit-dmz"] and p.rules[0].unsupported, entry
    assert why in " ".join(p.rules[0].unsupported), p.rules[0].unsupported
    # Whatever target: the rule is there, switched off, and reported.
    for target in ("panos", "fortios", "checkpoint", "iptables", "asa"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report)
        assert report.item("rule", "A-1").disabled, (target, entry)


def test_protocols_ports_and_groups() -> None:
    p = rules_of(
        "object-group protocol TCPUDP\n protocol-object tcp\n protocol-object udp\n"
        "object-group service WEB tcp-udp\n port-object eq www\n group-object MORE\n"
        "object-group service MORE tcp-udp\n port-object range 8080 8090\n"
        "object-group icmp-type PING\n icmp-object echo\n icmp-object 0\n"
        "object-group service MIX\n service-object gre\n service-object icmp6 echo\n service-object tcp source gt 1023\n"
        "access-list A extended permit object-group TCPUDP any any eq domain\n"
        "access-list A extended permit tcp any any object-group WEB\n"
        "access-list A extended permit udp any object-group WEB any\n"
        "access-list A extended permit icmp any any object-group PING\n"
        "access-list A extended permit icmp any any unreachable 4\n"
        "access-list A extended permit object-group MIX any any\n"
        "access-list A extended permit 47 any any\n"
        "access-list A extended permit esp any any\n"
        "access-list A extended permit icmp6 any any\n"
        "access-list A extended permit tcp any any\n"
        "access-list A extended permit 6 any any eq 22\n"
        "access-group A in interface inside\n"
    )
    entries = [p.services[rule.services[0]].entries for rule in listed(p)]
    assert [(e.protocol, e.dst_ports) for e in entries[0]] == [(Protocol.TCP, "53"), (Protocol.UDP, "53")]
    assert p.rules[1].services == ["WEB-tcp"] and entries[1][0].dst_ports == "80,8080-8090"
    assert entries[2][0].src_ports == "80,8080-8090" and entries[2][0].protocol == Protocol.UDP
    assert p.rules[3].services == ["PING"] and [e.icmp_type for e in entries[3]] == [8, 0]
    assert (entries[4][0].icmp_type, entries[4][0].icmp_code) == (3, 4)
    assert [(e.protocol, e.ip_protocol, e.icmp_type, e.src_ports) for e in entries[5]] == [
        (Protocol.IP, 47, None, ""), (Protocol.ICMP6, None, 128, ""), (Protocol.TCP, None, None, "1024-65535")]  # fmt: skip
    assert entries[6][0].ip_protocol == 47 and p.rules[6].services == ["gre"]
    assert entries[7][0].ip_protocol == 50
    assert entries[8][0].protocol == Protocol.ICMP6 and entries[8][0].icmp_type is None
    assert entries[9][0].protocol == Protocol.TCP and entries[9][0].dst_ports == ""
    assert entries[10][0].protocol == Protocol.TCP and entries[10][0].dst_ports == "22"
    assert not any(rule.unsupported for rule in p.rules)


def test_addresses_of_an_entry() -> None:
    p = rules_of(
        "names\nname 10.20.0.9 app-server\n"
        "object network NET\n subnet 10.20.0.0 255.255.255.0\n"
        "object-group network GRP\n network-object object NET\n network-object host app-server\n"
        " network-object 2001:db8::/32\n"
        "access-list A extended permit ip any4 any6\n"
        "access-list A extended permit ip host app-server 10.20.0.0 255.255.255.0\n"
        "access-list A extended permit ip host 2001:db8::1 2001:db8:1::/48\n"
        "access-list A extended permit ip object NET object-group GRP\n"
        "access-list A extended permit ip 0.0.0.0 0.0.0.0 ::/0\n"
        "access-list A extended permit ip object missing any\n"
        "access-group A in interface inside\n"
    )
    sides = [(rule.sources, rule.destinations) for rule in p.rules]
    assert sides[0] == ([ANY_V4], [ANY_V6])
    assert sides[1] == (["10.20.0.9"], ["10.20.0.0/24"])
    assert sides[2] == (["2001:db8::1"], ["2001:db8:1::/48"])
    assert sides[3] == (["NET"], ["GRP"]) and p.address_groups["GRP"].members == ["NET", "10.20.0.9", "2001:db8::/32"]
    assert sides[4] == ([ANY_V4], [ANY_V6])
    # An object that is not defined: the conversion gives it a placeholder and switches the rule off.
    report = Report()
    cli.convert(p, "panos", report)
    assert report.item("rule", "A-6").disabled and "UNDEFINED_REFERENCE" in codes(report, "address", "missing")


def test_logging_remarks_and_state_of_an_entry() -> None:
    p = rules_of(
        "access-list A remark first line\n"
        "access-list A remark second line\n"
        "access-list A extended permit ip any any log\n"
        "access-list A extended permit ip any any log 6 interval 300\n"
        "access-list A extended permit ip any any log disable\n"
        "access-list A extended deny ip any any\n"
        "access-list A extended deny ip any any log disable\n"
        "access-list A line 6 extended permit ip any any log default inactive\n"
        "access-list A extended permit ip any any time-range lunch inactive\n"
        "access-group A in interface inside\n"
    )
    assert p.rules[0].description == "first line / second line" and p.rules[1].description == ""
    assert [rule.log_end for rule in listed(p)] == [True, True, False, True, False, True, False]
    assert [rule.enabled for rule in listed(p)] == [True, True, True, True, True, False, False]
    assert p.rules[6].schedule == "lunch" and not any(rule.unsupported for rule in p.rules)


# -- which lists are policy, and for which interfaces ---------------------------------------


def test_only_bound_access_lists_are_policy() -> None:
    p, report = parse(HEAD + "access-list SPLIT extended permit ip any any\naccess-list CRYPTO extended permit ip any any\n")
    assert not [rule for rule in p.rules if not rule.name.startswith("implicit")]
    assert "NO_ACCESS_GROUP" in codes(report) and report.needs_review
    p, report = parse(HEAD + "access-list SPLIT standard permit 10.0.0.0 255.0.0.0\naccess-group GONE in interface inside\n")
    assert "ACL_MISSING" in codes(report)
    assert [rule.name for rule in p.rules] == ["implicit-dmz"]  # inside has a list, an empty one: nothing passes


def test_global_list_follows_the_interface_lists() -> None:
    p = rules_of(
        "access-list IN extended deny tcp any any eq 23\n"
        "access-list ALL extended permit tcp any any eq 22\n"
        "access-list ALL extended deny ip any any\n"
        "access-group IN in interface inside\n"
        "access-group ALL global\n"
    )
    assert [rule.name for rule in p.rules] == ["IN-1", "ALL-1", "ALL-2"]  # no implicit rules next to a global list
    everywhere = p.rules[1]
    # Between any two different interfaces: an ASA never sends traffic back where it came from.
    assert everywhere.scope == RuleScope.INTERZONE and everywhere.src_zones == everywhere.dst_zones == ["outside", "inside", "dmz"]
    assert everywhere.egress_implied and p.rules[2].src_zones == [ANY] and p.rules[2].dst_zones == [ANY]


def test_one_list_on_two_interfaces() -> None:
    p = rules_of(
        "access-list BOTH extended permit tcp any any eq 22\n"
        "access-list BOTH extended permit tcp any 10.20.0.0 255.255.255.0 eq 80\n"
        "access-group BOTH in interface inside\naccess-group BOTH in interface dmz\n"
    )
    first, second = p.rules
    assert first.scope == RuleScope.INTERZONE and first.src_zones == ["inside", "dmz"]
    assert first.dst_zones == ["outside", "inside", "dmz"]
    # The destination is in the network of dmz: reachable from inside, and from dmz not at all.
    assert (second.name, second.src_zones, second.dst_zones) == ("BOTH-2", ["inside"], ["dmz"])


def test_same_security_traffic() -> None:
    head = HEAD.replace("security-level 50", "security-level 100")  # inside and dmz on one level
    body = "access-list IN extended permit ip any any\naccess-group IN in interface inside\n"
    assert rules_of(body, head).rules[0].dst_zones == ["outside"]
    p = rules_of("same-security-traffic permit inter-interface\n" + body, head)
    assert p.rules[0].dst_zones == ["outside", "dmz"]
    p = rules_of("same-security-traffic permit inter-interface\nsame-security-traffic permit intra-interface\n" + body, head)
    assert p.rules[0].dst_zones == [ANY] and not p.rules[0].egress_implied  # nothing the ASA keeps apart
    # A permit that can never apply is left out and counted.
    p, report = parse(head + "access-list IN extended permit ip any 10.20.0.0 255.255.255.0\naccess-group IN in interface inside\n")
    assert [rule.name for rule in p.rules] == ["implicit-dmz"] and "RULE_WITHOUT_EFFECT" in codes(report)


def test_implicit_permit_follows_the_security_levels() -> None:
    p, report = parse(HEAD)
    assert [(rule.name, rule.src_zones, rule.dst_zones) for rule in p.rules] == [
        ("implicit-inside", ["inside"], ["outside", "dmz"]), ("implicit-dmz", ["dmz"], ["outside"])]  # fmt: skip
    head = HEAD.replace("security-level 50", "security-level 100")
    assert [rule.dst_zones for rule in rules_of("", head).rules] == [["outside"], ["outside"]]
    p = rules_of("same-security-traffic permit inter-interface\n", head)
    assert [rule.dst_zones for rule in p.rules] == [["outside", "dmz"], ["outside", "inside"]]
    # Without a security-level line the ASA gives "inside" 100 and every other name 0.
    bare = "interface e0\n nameif inside\ninterface e1\n nameif outside\ninterface e2\n nameif lab\n"
    assert [(r.src_zones, r.dst_zones) for r in rules_of("", bare).rules] == [(["inside"], ["outside", "lab"])]


def test_destination_zone_from_routes() -> None:
    body = (
        "route inside 10.40.0.0 255.255.0.0 10.10.0.254\n"
        "access-list OUT extended permit ip any 10.20.0.0 255.255.255.0\n"  # connected to dmz
        "access-list OUT extended permit ip any 10.40.1.0 255.255.255.0\n"  # a static route
        "access-list OUT extended permit ip any 10.0.0.0 255.0.0.0\n"  # spans several routes
        "access-list OUT extended permit ip any 198.51.100.0 255.255.255.0\n"  # the default route: back out
        "access-list OUT extended deny ip any 10.20.0.0 255.255.255.0\n"
        "access-group OUT in interface outside\n"
    )
    p, report = parse(HEAD + body)
    rules = [rule for rule in p.rules if rule.name.startswith("OUT")]
    assert [rule.dst_zones for rule in rules] == [["dmz"], ["inside"], ["dmz", "inside"], [ANY]]
    assert rules[3].action == Action.DROP  # the fourth entry can match nothing; a deny is kept as it is
    assert "RULE_WITHOUT_EFFECT" in codes(report) and "EGRESS_BY_ROUTE" in codes(report)
    # With a routing protocol the static routes are not the whole table: only connected networks count.
    p = rules_of("router ospf 1\n network 10.0.0.0 255.0.0.0 area 0\n" + body)
    rules = [rule for rule in p.rules if rule.name.startswith("OUT")]
    assert [rule.dst_zones for rule in rules][:4] == [["dmz"], ["inside", "dmz"], ["inside", "dmz"], ["inside", "dmz"]]


def test_outbound_access_lists() -> None:
    body = (
        "access-list IN extended permit ip any any\n"
        "access-list NO-TELNET extended deny tcp any any eq 23\n"
        "access-list NO-TELNET extended deny udp any any eq 69 inactive\n"
        "access-list NO-TELNET extended permit ip any any\n"
        "access-group IN in interface inside\n"
        "access-group NO-TELNET out interface dmz\n"
    )
    p, report = parse(HEAD + body)
    first, second = p.rules[:2]
    # A list that only denies and then permits everything: its denies come first, for that way out.
    assert (first.name, first.src_zones, first.dst_zones, first.action) == ("NO-TELNET-1", [ANY], ["dmz"], Action.DROP)
    assert second.name == "NO-TELNET-2" and not second.enabled and "OUTBOUND_ACL" not in codes(report)
    p, report = parse(HEAD + body.replace("permit ip any any\naccess-group IN", "permit tcp any any\naccess-group IN"))
    assert "OUTBOUND_ACL" in codes(report) and report.needs_review
    assert not [rule for rule in p.rules if rule.name.startswith("NO-TELNET")]


def test_management_and_control_plane() -> None:
    head = HEAD + "interface Management0/0\n management-only\n nameif mgmt\n security-level 100\n"
    p, report = parse(
        head
        + "access-list M extended permit ip any any\naccess-list C extended permit ip any any\n"
        "access-group M in interface mgmt\naccess-group C in interface outside control-plane\n"
        "access-list I extended permit tcp any any eq 22\naccess-group I in interface inside per-user-override\n"
    )
    assert "mgmt" not in p.zones and "MANAGEMENT_INTERFACE" in codes(report) and "PER_USER_OVERRIDE" in codes(report)
    assert [rule.name for rule in p.rules] == ["I-1", "implicit-dmz"]  # outside has no list for traffic through the ASA


def test_without_interface_sections_nothing_is_assumed() -> None:
    p, report = parse("access-list A extended permit ip any any\naccess-group A in interface inside\n")
    assert p.rules[0].src_zones == ["inside"] and p.rules[0].dst_zones == [ANY]
    assert "NO_INTERFACES" in codes(report) and "VERSION_ASSUMED" in codes(report)


# -- versions -----------------------------------------------------------------------------


def test_before_9_0_any_is_ipv4() -> None:
    old = HEAD.replace("9.12(4)", "8.4(7)")
    p, report = parse(
        old + "access-list A extended permit ip any any\naccess-group A in interface inside\n"
        "ipv6 access-list SIX permit ip any any\n"
    )
    assert p.rules[0].sources == [ANY_V4] and p.rules[0].destinations == [ANY_V4] and p.lookup_after_dnat
    assert "TABLE_NOT_CONVERTED" in codes(report)


def test_before_8_3_nat_is_not_converted_and_lists_name_translated_addresses() -> None:
    old = HEAD.replace("ASA Version 9.12(4)", "ASA Version 8.2(5)")
    p, report = parse(
        old + "access-list OUT extended permit tcp any host 203.0.113.10 eq www\naccess-group OUT in interface outside\n"
        "static (dmz,outside) 203.0.113.10 10.20.0.10 netmask 255.255.255.255\n"
        "global (outside) 1 interface\nnat (inside) 1 0.0.0.0 0.0.0.0\n"
    )
    assert not p.nat_rules and not p.lookup_after_dnat and "LEGACY_NAT" in codes(report)
    assert p.rules[0].destinations == ["203.0.113.10"]  # as the client sees it, which is what the model wants
    # The same commands without a version line are recognised for what they are.
    p, report = parse(HEAD.split("\n", 1)[1] + "access-list A extended permit ip any any\nnat (inside) 0 access-list X\n")
    assert not p.lookup_after_dnat and "VERSION_ASSUMED" not in codes(report)


# -- Firepower Threat Defense ------------------------------------------------------------

FTD = """NGFW Version 7.2.5
interface Ethernet1/1
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface Ethernet1/2
 nameif inside
 security-level 0
 ip address 10.10.0.1 255.255.0.0
interface Ethernet1/3
 nameif dmz
 security-level 0
 ip address 10.20.0.1 255.255.255.0
object network web
 host 10.20.0.10
object-group service |acSvcg-268435458
 service-object tcp destination eq www
 service-object tcp destination eq https
access-list CSM_FW_ACL_ remark rule-id 9998: PREFILTER POLICY: Default Tunnel and Priority Policy
access-list CSM_FW_ACL_ remark rule-id 9998: RULE: DEFAULT TUNNEL ACTION RULE
access-list CSM_FW_ACL_ advanced permit ipinip any any rule-id 9998
access-list CSM_FW_ACL_ advanced permit gre any any rule-id 9998
access-list CSM_FW_ACL_ remark rule-id 268435458: ACCESS POLICY: edge - Mandatory
access-list CSM_FW_ACL_ remark rule-id 268435458: L4 RULE: Web in
access-list CSM_FW_ACL_ advanced permit object-group |acSvcg-268435458 ifc outside any ifc dmz object web rule-id 268435458 event-log both
access-list CSM_FW_ACL_ advanced permit object-group |acSvcg-268435458 ifc inside any ifc dmz object web rule-id 268435458 event-log both
access-list CSM_FW_ACL_ remark rule-id 268435459: L7 RULE: Social media
access-list CSM_FW_ACL_ advanced permit ip ifc inside any ifc outside any rule-id 268435459
access-list CSM_FW_ACL_ remark rule-id 268435460: L4 RULE: Trusted backup
access-list CSM_FW_ACL_ advanced trust tcp ifc inside any ifc dmz any eq 873 rule-id 268435460 event-log flow-end
access-list CSM_FW_ACL_ advanced trust tcp ifc dmz any ifc inside any eq 873 rule-id 268435460 event-log flow-end
access-list CSM_FW_ACL_ remark rule-id 268435461: L4 RULE: DEFAULT ACTION RULE
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 268435461 event-log flow-start
access-group CSM_FW_ACL_ global
"""


def test_ftd_rules_carry_their_interfaces_and_names() -> None:
    p, report = parse(FTD)
    assert "FTD_CONFIGURATION" in codes(report) and "VERSION_ASSUMED" not in codes(report)
    names = [rule.name for rule in p.rules]
    assert names == ["DEFAULT TUNNEL ACTION RULE", "DEFAULT TUNNEL ACTION RULE-2", "Web in", "Social media",
                     "Trusted backup", "Trusted backup-2", "DEFAULT ACTION RULE"]  # fmt: skip
    by_name = {rule.name: rule for rule in p.rules}
    # Tunnels are handed on to the access rules, not allowed as such.
    assert by_name["DEFAULT TUNNEL ACTION RULE"].unsupported and by_name["DEFAULT TUNNEL ACTION RULE-2"].unsupported
    web = by_name["Web in"]  # two entries that differ in their interface: one rule
    assert web.src_zones == ["outside", "inside"] and web.dst_zones == ["dmz"] and web.log_start and web.log_end
    assert web.services == ["|acSvcg-268435458"] and not web.unsupported and not web.egress_implied
    # The conditions of an L7 rule are not in the configuration: never an allow as it stands.
    assert "L7" in by_name["Social media"].unsupported[0]
    # inside -> dmz and dmz -> inside is not "inside, dmz -> inside, dmz".
    assert (by_name["Trusted backup"].src_zones, by_name["Trusted backup"].dst_zones) == (["inside"], ["dmz"])
    assert (by_name["Trusted backup-2"].src_zones, by_name["Trusted backup-2"].dst_zones) == (["dmz"], ["inside"])
    assert by_name["Trusted backup"].action == Action.ALLOW and not by_name["Trusted backup"].log_start
    last = by_name["DEFAULT ACTION RULE"]
    assert last.action == Action.DROP and last.src_zones == [ANY] and last.log_start and not last.log_end
    report = Report()
    text = cli.convert(p, "panos", report)
    assert report.item("rule", "Social media").disabled and 'rules "Web in" from [ outside inside ]' in text


def test_entries_with_interfaces_are_never_read_without_them() -> None:
    """An FTD configuration without its version line: the interfaces of the entries still count."""
    p, _ = parse(FTD.split("\n", 1)[1])
    by_name = {rule.name: rule for rule in p.rules}
    assert by_name["Web in"].src_zones == ["outside", "inside"] and by_name["Web in"].dst_zones == ["dmz"]


# -- NAT ------------------------------------------------------------------------------------

NAT_OBJECTS = """object network SRV
 host 10.20.0.10
object network SRV-PUB
 host 203.0.113.10
object network LAN
 subnet 10.10.0.0 255.255.0.0
object network POOL
 range 203.0.113.100 203.0.113.110
object network ONE
 host 203.0.113.99
object network REMOTE
 subnet 10.99.0.0 255.255.0.0
object network VIP
 host 10.10.99.1
object network SIX
 subnet 2001:db8:10::/64
object-group network MIXED
 network-object object POOL
 network-object object ONE
object service HTTP
 service tcp destination eq www
object service ALT
 service tcp destination eq 8080
object service SRC-HTTP
 service tcp source eq www
object service SRC-ALT
 service tcp source eq 8080
object service BOTH
 service tcp source eq 1 destination eq 2
object service DNS
 service udp destination eq domain
"""


def nat_of(line: str, extra: str = "") -> Tuple[NatRule, Policy, Report]:
    p, report = parse(HEAD + NAT_OBJECTS + extra + line + "\n")
    assert len(p.nat_rules) == 1, line
    return p.nat_rules[0], p, report


def test_twice_nat_forms() -> None:
    nat, _, _ = nat_of("nat (inside,outside) source dynamic LAN interface")
    assert nat.source_translation is not None and nat.source_translation.kind == SnatKind.INTERFACE
    assert nat.source_translation.interface_address == "203.0.113.2" and not nat.unsupported
    nat, _, _ = nat_of("nat (inside,outside) source dynamic any ONE")
    assert nat.sources == [ANY] and nat.source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["ONE"])
    nat, _, _ = nat_of("nat (inside,outside) source dynamic LAN POOL")  # a range: one address per host
    assert nat.source_translation == SourceNat(SnatKind.DYNAMIC, ["POOL"])
    nat, _, report = nat_of("nat (inside,outside) source dynamic LAN POOL interface dns")
    assert nat.source_translation == SourceNat(SnatKind.DYNAMIC, ["POOL"])
    assert codes(report, "nat", "nat-1") == ["ATTRIBUTES_IGNORED"]
    nat, _, report = nat_of("nat (inside,outside) source dynamic LAN pat-pool MIXED round-robin extended flat interface")
    assert nat.source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["MIXED"]) and not nat.unsupported
    nat, _, _ = nat_of("nat (dmz,outside) source static SRV SRV-PUB")
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["SRV-PUB"], bidirectional=True)
    nat, _, _ = nat_of("nat (dmz,outside) source static SRV SRV-PUB unidirectional inactive description one way")
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["SRV-PUB"]) and not nat.enabled
    assert nat.description == "one way"
    nat, _, _ = nat_of("nat (inside,outside) source static any any destination static REMOTE REMOTE no-proxy-arp route-lookup")
    assert nat.source_translation is None and nat.destinations == ["REMOTE"] and nat.dst_zones == ["outside"]
    nat, _, _ = nat_of("nat (inside,any) 1 source static LAN LAN")
    assert nat.dst_zones == [ANY] and nat.source_translation is None and not nat.unsupported


def test_twice_nat_with_a_destination() -> None:
    # Inside clients reach the server by an address of their own network, and are hidden behind the ASA.
    nat, _, report = nat_of("nat (inside,dmz) source dynamic LAN interface destination static VIP SRV service HTTP ALT")
    assert nat.destinations == ["VIP"] and nat.destination_translation == DestNat("SRV", "8080") and nat.service == "HTTP"
    assert nat.source_translation is not None and nat.source_translation.interface == "GigabitEthernet0/2"
    # The model wants the zone the original destination is reached in, not the one behind it.
    assert nat.src_zones == ["inside"] and nat.dst_zones == ["inside"] and "NAT_ZONE_BY_ROUTE" in codes(report, "nat", "nat-1")
    nat, _, _ = nat_of("nat (inside,dmz) source static LAN LAN destination static VIP SRV service DNS DNS")
    assert nat.service == "DNS" and nat.destination_translation == DestNat("SRV") and nat.source_translation is None
    nat, p, report = nat_of("nat (outside,dmz) source static any any destination static interface SRV service HTTP ALT")
    assert nat.destinations == ["outside-interface"] and nat.destination_translation == DestNat("SRV", "8080")
    # The address of the interface, as it is today: an object that says what it stands for.
    own = p.addresses["outside-interface"]
    assert (own.value, own.builtin, own.raw) == ("203.0.113.2/32", "asa", "interface outside")
    assert "NAT_INTERFACE_ADDRESS" in codes(report, "nat", "nat-1")
    nat, _, report = nat_of("nat (dmz,outside) source static SRV SRV-PUB destination static REMOTE REMOTE")
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["SRV-PUB"]) and nat.destinations == ["REMOTE"]
    assert "NAT_REVERSE_DIRECTION" in codes(report, "nat", "nat-1")


def test_a_port_published_from_the_side_of_the_server() -> None:
    nat, p, _ = nat_of("nat (dmz,outside) source static SRV SRV-PUB service SRC-ALT SRC-HTTP")
    assert (nat.src_zones, nat.dst_zones, nat.sources, nat.destinations) == (["outside"], ["outside"], [ANY], ["SRV-PUB"])
    assert nat.destination_translation == DestNat("SRV", "8080") and p.services[nat.service].entries[0].dst_ports == "80"
    nat, p, _ = nat_of("nat (dmz,outside) source static SRV interface service SRC-HTTP SRC-HTTP")
    assert nat.destinations == ["outside-interface"] and nat.destination_translation == DestNat("SRV") and not nat.unsupported
    nat, _, _ = nat_of("nat (dmz,outside) source static SRV SRV-PUB destination static REMOTE REMOTE service SRC-ALT SRC-HTTP")
    assert nat.sources == ["REMOTE"] and not nat.unsupported


@pytest.mark.parametrize(
    "line,why",
    [
        ("nat (dmz,outside) source static SRV SRV-PUB service BOTH BOTH", "source and destination ports"),
        ("nat (dmz,outside) source static SRV SRV-PUB service HTTP DNS", "two protocols"),
        ("nat (dmz,outside) source static SRV SRV-PUB service HTTP ALT", "without a destination address"),
        ("nat (dmz,outside) source static SRV SRV-PUB service HTTP SRC-ALT", "one side only"),
        ("nat (dmz,outside) source static SRV SRV-PUB service SRC-ALT SRC-HTTP unidirectional", "source port"),
        ("nat (dmz,outside) source static SRV SRV-PUB service HTTP NOPE", "not a service object"),
        ("nat (dmz,outside) source static SRV NOPE", "not defined"),
        ("nat (dmz,outside) source static SRV interface", "without a service"),
        ("nat (dmz,any) source dynamic SRV interface", "without a mapped interface"),
        ("nat (dmz,outside) source dynamic SRV interface ipv6", "IPv6 address of the interface"),
        ("nat (dmz,outside) source static SRV SIX", "between IPv4 and IPv6"),
        ("nat (dmz,outside) source static SRV SRV-PUB destination static VIP SRV surprise", "surprise"),
        ("nat (dmz,outside) source wrong SRV SRV-PUB", "NAT line"),
        ("nat (dmz,outside) source dynamic SRV", "not defined"),
        ("nat (dmz,outside) source static SRV SRV-PUB destination static interface SRV", "interface 'dmz'"),
    ],
)
def test_nat_that_is_not_understood_is_not_converted(line: str, why: str) -> None:
    head = HEAD.replace(" ip address 10.20.0.1 255.255.255.0\n", "")  # dmz without an address
    p, _ = parse(head + NAT_OBJECTS + line + "\n")
    nat = p.nat_rules[0]
    assert nat.unsupported and why in " ".join(nat.unsupported), nat.unsupported
    for target in ("panos", "fortios", "checkpoint", "iptables", "asa"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report, Options(nat_zone="outside"))
        assert report.item("nat", nat.origin).skipped, target


def test_object_nat_forms() -> None:
    def one(lines: str) -> Tuple[NatRule, Policy, Report]:
        return nat_of("object network SRV\n" + lines)

    nat, _, _ = one(" nat (dmz,outside) static 203.0.113.10")
    assert nat.name == "nat-SRV" and nat.sources == ["SRV"] and nat.src_zones == ["dmz"] and nat.dst_zones == ["outside"]
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["203.0.113.10"], bidirectional=True)
    nat, _, _ = one(" nat (dmz,outside) static SRV-PUB no-proxy-arp")
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["SRV-PUB"], bidirectional=True)
    nat, p, _ = one(" nat (dmz,outside) static SRV-PUB service tcp 8080 www")
    assert nat.sources == [ANY] and nat.destinations == ["SRV-PUB"] and nat.destination_translation == DestNat("SRV", "8080")
    assert nat.src_zones == nat.dst_zones == ["outside"] and p.services[nat.service].entries[0].dst_ports == "80"
    nat, _, _ = one(" nat (dmz,outside) static interface service udp domain domain")
    assert nat.destinations == ["outside-interface"] and nat.destination_translation == DestNat("SRV")
    nat, _, _ = one(" nat (dmz,outside) dynamic interface")
    assert nat.source_translation is not None and nat.source_translation.kind == SnatKind.INTERFACE
    nat, _, _ = one(" nat (dmz,outside) dynamic 203.0.113.9")
    assert nat.source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.9"])
    nat, _, _ = one(" nat (dmz,outside) dynamic pat-pool POOL interface")
    assert nat.source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["POOL"])
    nat, _, _ = one(" nat (dmz,any) static 203.0.113.10 service tcp 8080 www")
    assert nat.src_zones == [ANY] and nat.dst_zones == ["outside"]  # where the published address is routed to
    # A subnet mapped to an address: as many addresses as the subnet has.
    nat, _, _ = nat_of("object network LAN\n nat (inside,outside) static 198.51.0.0")
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["198.51.0.0/16"], bidirectional=True)
    nat, _, _ = nat_of("object network POOL\n nat (inside,outside) static 198.51.100.50")
    assert nat.source_translation == SourceNat(SnatKind.STATIC, ["198.51.100.50-198.51.100.60"], bidirectional=True)
    nat, _, _ = one(" nat (dmz,outside) static interface")
    assert nat.unsupported
    nat, _, _ = one(" nat (dmz,outside) static 203.0.113.10 service tcp 8080 nosuchport")
    assert nat.unsupported


def test_nat_order_is_the_order_of_the_asa() -> None:
    p, _ = parse(
        HEAD
        + "object network BIG\n subnet 10.10.0.0 255.255.0.0\n nat (inside,outside) dynamic interface\n"
        "object network SMALL\n subnet 10.10.1.0 255.255.255.0\n nat (inside,outside) dynamic interface\n"
        "object network B-HOST\n host 10.20.0.11\n nat (dmz,outside) static 203.0.113.11\n"
        "object network A-HOST\n host 10.20.0.10\n nat (dmz,outside) static 203.0.113.10\n"
        "object network A-TWIN\n host 10.20.0.10\n nat (dmz,inside) static 10.10.99.10\n"
        "object network WIDE\n subnet 10.20.0.0 255.255.255.0\n nat (dmz,outside) static 203.0.113.0\n"
        "nat (inside,outside) after-auto source dynamic any interface\n"
        "nat (inside,outside) source static BIG BIG destination static BIG BIG\n"
    )
    # Twice NAT, then object NAT - static before dynamic, fewest addresses first, lowest address, name -
    # then twice NAT after-auto.
    assert [nat.name for nat in p.nat_rules] == [
        "nat-1", "nat-A-HOST", "nat-A-TWIN", "nat-B-HOST", "nat-WIDE", "nat-SMALL", "nat-BIG", "nat-after-auto-1"]  # fmt: skip


def test_rules_are_brought_to_the_original_address() -> None:
    body = (
        "object network SRV\n host 10.20.0.10\n nat (dmz,outside) static 203.0.113.10\n"
        "access-list OUT extended permit tcp any object SRV eq 443\n"
        "access-list OUT extended permit tcp any host 203.0.113.10 eq 22\n"
        "access-group OUT in interface outside\n"
    )
    p, report = parse(HEAD + body)
    assert p.rules[0].destinations == ["SRV", "203.0.113.10"] and p.rules[0].dst_zones == ["dmz"]
    assert "NAT_DESTINATION_REWRITTEN" in codes(report, "rule", "OUT-1")
    # The entry for the public address matches nothing on the ASA: that address is routed back out.
    assert [rule.name for rule in listed(p)] == ["OUT-1"] and "RULE_WITHOUT_EFFECT" in codes(report)
    # Where the configuration does not show the routes, the entry is kept and its meaning explained.
    p, report = parse("\n".join(line for line in HEAD.splitlines() if "ip address" not in line and "route" not in line) + "\n" + body)
    assert "NAT_ADDRESS_EXPOSED" in codes(report, "rule", "OUT-2")


# -- malformed input ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["", "hello world\n", "interface\n nameif\n", "object network\nobject-group\naccess-list\nnat\n",
     "context a\n config-url disk0:/a.cfg\n", "\x00\x01\x02", "config system global\nend\n"],
)  # fmt: skip
def test_what_is_not_an_asa_configuration(text: str) -> None:
    with pytest.raises(ParseError):
        parse(text)


def test_damaged_lines_do_not_stop_the_reading() -> None:
    rng = random.Random(7)
    lines = (DATA / "asa_sample.cfg").read_text().splitlines()
    for _ in range(300):
        mutated = list(lines)
        for _ in range(rng.randint(1, 6)):
            index = rng.randrange(len(mutated))
            words = mutated[index].split(" ")
            action = rng.random()
            if action < 0.3 and len(words) > 1:
                del words[rng.randrange(len(words))]
            elif action < 0.6:
                words.insert(rng.randrange(len(words) + 1), rng.choice(["any", "object", "object-group", "eq", "(", "99999",
                                                                        "host", "range", "\x07", "interface", "service", ""]))  # fmt: skip
            elif action < 0.8:
                rng.shuffle(words)
            else:
                mutated[index] = mutated[rng.randrange(len(mutated))]
                continue
            mutated[index] = " ".join(words)
        text = "\n".join(mutated)
        try:
            p, report = parse(text)
        except ParseError:
            continue
        for target in ("panos", "asa", "json"):
            try:
                cli.convert(copy.deepcopy(p), target, Report())
            except FwshiftError:
                pass


def test_deep_and_circular_groups() -> None:
    chain = "".join(f"object-group network G{n}\n group-object G{n + 1}\n" for n in range(3000))
    chain += "".join(f"object-group service S{n}\n group-object S{n + 1}\n service-object object X\n" for n in range(3000))
    p, report = parse(
        HEAD + chain + "object-group network G3000\n network-object host 10.1.1.1\n"
        "object service X\n service tcp destination eq 1\nobject-group service S3000\n service-object object X\n"
        "access-list A extended permit ip any object-group G0\n"
        "access-list A extended permit object-group S0 any any\n"
        "access-list A extended permit ip any object-group G2990\n"
        "access-group A in interface inside\n"
    )
    assert len(p.address_groups) == 3001 and "UNSUPPORTED_GROUP" in codes(report, "address-group", "G2936")
    for target in ("panos", "fortios", "checkpoint", "iptables", "asa"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report)
        # Nesting an ASA would not take is cut, and what was above the cut is not converted.
        assert report.item("rule", "A-1").disabled and report.item("rule", "A-2").disabled, target
        assert not report.item("rule", "A-3").disabled, target
    loop = (
        "object-group network A\n group-object B\nobject-group network B\n group-object A\n"
        "object-group service P tcp\n group-object Q\nobject-group service Q tcp\n group-object P\n port-object eq 80\n"
        "object-group protocol X\n group-object X\n"
        "access-list L extended permit tcp any object-group A object-group P\n"
        "access-list L extended permit object-group X any any\n"
        "access-group L in interface inside\n"
    )
    p, _ = parse(HEAD + loop)
    report = Report()
    cli.convert(p, "panos", report)
    assert report.item("rule", "L-1").disabled and report.item("rule", "L-2").disabled


def test_detect_format() -> None:
    assert cli.detect_format((DATA / "asa_sample.cfg").read_bytes()) == "asa"
    assert cli.detect_format(FTD.encode()) == "asa"
    assert cli.detect_format(b"hostname fw\naccess-list OUT extended permit ip any any\n") == "asa"
    assert cli.detect_format(b"object network A\n host 10.0.0.1\n") == "asa"
    assert cli.detect_format(b"config firewall policy\nedit 1\nnext\nend\n") == "fortios"


# -- a random ASA, with a judge of its own ----------------------------------------------------

NAMEIFS = ["outside", "inside", "dmz", "guest"]
NETWORKS = {"inside": ["10.0.1.0/24", "2001:db8:1::/48"], "dmz": ["10.0.2.0/24", "2001:db8:2::/48"],
            "guest": ["10.0.3.0/24", "10.0.4.0/24", "2001:db8:3::/48"]}  # fmt: skip
Match = Callable[[Packet], bool]


def route(address: str) -> str:
    for nameif, networks in NETWORKS.items():
        if any(_in(address, network) for network in networks):
            return nameif
    return "outside"


@dataclass
class Lab:
    """An ASA made up at random: its configuration as text, and what it does with a packet."""

    levels: Dict[str, int]
    intra: bool
    inter: bool
    routed: bool
    lines: List[str] = field(default_factory=list)
    acls: Dict[str, List[Tuple[bool, Match]]] = field(default_factory=dict)
    bound: Dict[str, str] = field(default_factory=dict)
    global_acl: str = ""

    def blocked(self, pkt: Packet) -> bool:
        if pkt.in_if == pkt.out_if:
            return not self.intra
        return self.levels[pkt.in_if] == self.levels[pkt.out_if] and not self.inter

    def allows(self, pkt: Packet) -> bool:
        if self.blocked(pkt):
            return False
        lists = [name for name in (self.bound.get(pkt.in_if, ""), self.global_acl) if name]
        for name in lists:
            for permit, match in self.acls[name]:
                if match(pkt):
                    return permit
        if lists:
            return False
        return self.levels[pkt.in_if] >= self.levels[pkt.out_if]  # blocked() dealt with the same level


def lab_packet(rng: random.Random, lab: Lab) -> Packet:
    if rng.random() < 0.75:
        src, dst = (f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}" for _ in range(2))
    else:
        src, dst = (f"2001:db8:{rng.randrange(4)}::{rng.randrange(1, 4)}" for _ in range(2))
    proto = rng.choice(["tcp", "tcp", "tcp", "udp", "icmp" if "." in src else "icmp6", "47", "50"])
    out_if = route(dst) if lab.routed else rng.choice(NAMEIFS)
    return Packet(rng.choice(NAMEIFS), out_if, src, dst, proto, rng.choice([53, 1024, 40000]),
                  rng.choice([22, 53, 80, 443, 8000, 8005, 8080, 9000]), rng.choice([0, 3, 8, 128, 129]))  # fmt: skip


def random_lab(rng: random.Random, routed: bool, nat: bool = False) -> Lab:
    levels = dict(zip(NAMEIFS, rng.choice([[0, 100, 50, 10], [0, 100, 50, 50], [0, 100, 100, 100], [50, 50, 50, 50]])))
    lab = Lab(levels, rng.random() < 0.3, rng.random() < 0.5, routed)
    lines = lab.lines
    lines.append("ASA Version 9.16(4)")
    for index, nameif in enumerate(NAMEIFS):
        lines += [f"interface GigabitEthernet0/{index}", f" nameif {nameif}", f" security-level {levels[nameif]}"]
        if routed and nameif in NETWORKS:
            network, mask = NETWORKS[nameif][0].split("/")[0], "255.255.255.0"
            lines.append(f" ip address {network[:-1]}1 {mask}")
            lines.append(f" ipv6 address {NETWORKS[nameif][-1].replace('::/48', '::1/48')}")
        elif routed:
            lines.append(" ip address 192.0.2.1 255.255.255.0")
    if routed:
        lines += ["route outside 0.0.0.0 0.0.0.0 192.0.2.254", "ipv6 route outside ::/0 2001:db8:ffff::1",
                  "route guest 10.0.4.0 255.255.255.0 10.0.3.254"]  # fmt: skip
    if lab.intra:
        lines.append("same-security-traffic permit intra-interface")
    if lab.inter:
        lines.append("same-security-traffic permit inter-interface")
    lines += [
        "names", "name 10.0.2.34 app",
        "object network NET1", " subnet 10.0.1.0 255.255.255.0",
        "object network NET2", " subnet 10.0.2.0 255.255.255.0",
        "object network HOST", " host 10.0.3.17",
        "object network SPAN", " range 10.0.3.100 10.0.4.50",
        "object network SIX", " subnet 2001:db8:2::/48",
        "object-group network GRP", " network-object object NET1", " network-object host app",
        " network-object 2001:db8:1::/48", " network-object 10.0.4.0 255.255.255.128",
        "object-group network NEST", " group-object GRP", " network-object object SPAN",
        "object service SVC-DNS", " service udp destination eq domain",
        "object service SVC-HIGH", " service tcp source gt 1023 destination range 8000 8010",
        "object-group service WEB tcp", " port-object eq www", " port-object eq https", " port-object range 8000 8005",
        "object-group service BOTH tcp-udp", " port-object eq domain", " group-object WEB2",
        "object-group service WEB2 tcp-udp", " port-object eq 8080",
        "object-group service MIX", " service-object object SVC-DNS", " service-object tcp destination eq ssh",
        " service-object icmp echo", " service-object icmp6 128", " service-object gre", " group-object MIX2",
        "object-group service MIX2", " service-object tcp-udp destination eq 9000",
        "object-group protocol TCPUDP", " protocol-object tcp", " protocol-object udp",
        "object-group icmp-type PING", " icmp-object echo", " icmp-object echo-reply",
    ]  # fmt: skip

    def members(*literals: str) -> Callable[[str], bool]:
        return lambda address: any(_in(address, literal) for literal in literals)

    grp = ("10.0.1.0/24", "10.0.2.34", "2001:db8:1::/48", "10.0.4.0/25")
    addresses: List[Tuple[str, Callable[[str], bool]]] = [
        ("any", lambda a: True), ("any", lambda a: True), ("any4", lambda a: "." in a), ("any6", lambda a: ":" in a),
        ("host 10.0.0.17", members("10.0.0.17")), ("host app", members("10.0.2.34")),
        ("10.0.1.0 255.255.255.0", members("10.0.1.0/24")), ("10.0.2.0 255.255.254.0", members("10.0.2.0/23")),
        ("2001:db8:3::/48", members("2001:db8:3::/48")), ("host 2001:db8:1::2", members("2001:db8:1::2")),
        ("object NET1", members("10.0.1.0/24")), ("object NET2", members("10.0.2.0/24")),
        ("object HOST", members("10.0.3.17")), ("object SPAN", members("10.0.3.100-10.0.4.50")),
        ("object SIX", members("2001:db8:2::/48")), ("object-group GRP", members(*grp)),
        ("object-group NEST", members(*grp, "10.0.3.100-10.0.4.50")),
    ]  # fmt: skip

    def port_in(port: int, ranges: List[Tuple[int, int]]) -> bool:
        return any(low <= port <= high for low, high in ranges)

    web = [(80, 80), (443, 443), (8000, 8005)]
    ports: List[Tuple[str, List[Tuple[int, int]]]] = [
        ("", [(0, 65535)]), ("eq 22", [(22, 22)]), ("eq www", [(80, 80)]), ("range 8000 8080", [(8000, 8080)]),
        ("gt 1023", [(1024, 65535)]), ("lt 1024", [(0, 1023)]), ("neq 443", [(0, 442), (444, 65535)]),
        ("object-group WEB", web), ("object-group BOTH", [(53, 53), (8080, 8080)]),
    ]  # fmt: skip

    def service(rng: random.Random) -> Tuple[str, str, str, Match]:
        kind = rng.random()
        if kind < 0.15:
            return "ip", "", "", lambda p: True
        if kind < 0.6:
            proto = rng.choice(["tcp", "tcp", "udp", "object-group TCPUDP"])
            protos = ["tcp", "udp"] if proto.startswith("object") else [proto]
            usable = [p for p in ports if p[0] != "object-group WEB" or protos == ["tcp"]]
            src_text, src = rng.choice(usable) if rng.random() < 0.2 else ("", [(0, 65535)])
            dst_text, dst = rng.choice(usable)
            return proto, src_text, dst_text, lambda p: p.proto in protos and port_in(p.sport, src) and port_in(p.dport, dst)
        if kind < 0.7:
            return rng.choice([("icmp", "", "", lambda p: p.proto == "icmp"),
                               ("icmp", "", "echo", lambda p: p.proto == "icmp" and p.icmp_type == 8),
                               ("icmp", "", "unreachable", lambda p: p.proto == "icmp" and p.icmp_type == 3),
                               ("icmp", "", "object-group PING", lambda p: p.proto == "icmp" and p.icmp_type in (8, 0)),
                               ("icmp6", "", "echo-reply", lambda p: p.proto == "icmp6" and p.icmp_type == 129),
                               ("icmp6", "", "", lambda p: p.proto == "icmp6")])  # fmt: skip
        if kind < 0.8:
            return rng.choice([("gre", "", "", lambda p: p.proto == "47"), ("50", "", "", lambda p: p.proto == "50"),
                               ("esp", "", "", lambda p: p.proto == "50")])  # fmt: skip
        return rng.choice([
            ("object SVC-DNS", "", "", lambda p: p.proto == "udp" and p.dport == 53),
            ("object SVC-HIGH", "", "", lambda p: p.proto == "tcp" and p.sport > 1023 and 8000 <= p.dport <= 8010),
            ("object-group MIX", "", "", lambda p: (p.proto == "udp" and p.dport == 53) or (p.proto == "tcp" and p.dport == 22)
             or (p.proto == "icmp" and p.icmp_type == 8) or (p.proto == "icmp6" and p.icmp_type == 128) or p.proto == "47"
             or (p.proto in ("tcp", "udp") and p.dport == 9000)),
        ])  # fmt: skip

    def acl(name: str) -> None:
        entries = lab.acls.setdefault(name, [])
        for _ in range(rng.randint(2, 9)):
            permit = rng.random() < 0.65
            proto, src_ports, dst_ports, service_match = service(rng)
            (src_text, src), (dst_text, dst) = rng.choice(addresses), rng.choice(addresses)
            inactive = rng.random() < 0.1
            words = ["access-list", name, "extended", "permit" if permit else "deny", proto, src_text, src_ports,
                     dst_text, dst_ports, rng.choice(["", "", "log", "log disable", "log 4 interval 60"]),
                     "inactive" if inactive else ""]  # fmt: skip
            if rng.random() < 0.2:
                lines.append(f"access-list {name} remark something about the next entry")
            lines.append(" ".join(word for word in words if word))
            if not inactive:
                entries.append((permit, lambda p, s=src, d=dst, m=service_match: s(p.src) and d(p.dst) and m(p)))

    if nat:
        # Access lists name real addresses: NAT changes nothing about what they let through.
        lines += [
            "object network NET2", " nat (dmz,outside) static 198.51.100.0",
            "object network HOST", " nat (guest,outside) static 198.51.101.17",
            "object network SPAN", " nat (guest,outside) static 198.51.102.100",
            "object network PUB", " host 198.51.110.1",
            "nat (inside,outside) source dynamic NET1 interface",
            "nat (outside,dmz) source static any any destination static PUB SIX-GW",
        ]  # fmt: skip
        lines[lines.index("names")] = "object network SIX-GW\n host 10.0.2.99\nnames"
    for nameif in NAMEIFS:
        if rng.random() < 0.7:
            acl(f"{nameif}_in")
            lab.bound[nameif] = f"{nameif}_in"
            lines.append(f"access-group {nameif}_in in interface {nameif}")
    if rng.random() < 0.4:
        acl("everywhere")
        lab.global_acl = "everywhere"
        lines.append("access-group everywhere global")
    return lab


def model_allows(p: Policy, pkt: Packet) -> bool:
    return bool(model_verdict(p, pkt))


@pytest.mark.parametrize("routed,nat", [(True, False), (False, False), (True, True)])
def test_parsed_configuration_decides_like_the_asa(routed: bool, nat: bool) -> None:
    """Interface and global lists, security levels, same-security-traffic, every form of an entry."""
    allowed = 0
    for seed in range(120):
        rng = random.Random(seed)
        lab = random_lab(rng, routed, nat)
        text = "\n".join(lab.lines) + "\n"
        p, report = parse(text)
        assert not any(rule.unsupported for rule in p.rules), (seed, [r.unsupported for r in p.rules if r.unsupported])
        assert p.default_interzone == Action.DENY and not report.needs_review, (seed, report.to_text())
        for _ in range(400):
            pkt = lab_packet(rng, lab)
            expected = lab.allows(pkt)
            allowed += expected
            assert model_allows(p, pkt) == expected, (seed, pkt, text)
    assert allowed > 4000  # the labs let a good part of the packets through


@pytest.mark.parametrize("nat", [False, True])
def test_converted_asa_decides_like_the_asa(nat: bool) -> None:
    """ASA to ASA: what the emitter writes for a parsed configuration does what the configuration did.

    With NAT the rules go to the original address and back to the real one: nothing may be left
    behind, and a rule for one host of a translated network stays a rule for one host.
    """
    compared = 0
    for seed in range(120):
        rng = random.Random(500 + seed)
        lab = random_lab(rng, routed=True, nat=nat)
        p, _ = parse("\n".join(lab.lines) + "\n")
        report = Report()
        emitted = AsaConfig(cli.convert(p, "asa", report), intra_interface=lab.intra)
        assert not [item.name for item in report.items.values() if item.kind == "rule" and item.status == "needs-review"
                    and not item.name.startswith("implicit-")], (seed, report.to_text())  # fmt: skip
        # An interface without a list lets traffic out by security level; that cannot be said in a list.
        inexact = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
        assert all(name.startswith("implicit-") for name in inexact), (seed, report.to_text())
        for _ in range(300):
            pkt = lab_packet(rng, lab)
            if lab.levels[pkt.in_if] == lab.levels[pkt.out_if] and pkt.in_if != pkt.out_if and not lab.inter:
                continue  # dropped by the security levels of the target, which the output does not set
            if f"implicit-{pkt.in_if}" in inexact:
                assert not emitted.allows(pkt), (seed, pkt)  # the implicit rule is written inactive
                continue
            compared += 1
            assert emitted.allows(pkt) == lab.allows(pkt), (seed, pkt, emitted.text)
    assert compared > 10000


# -- the emitter ----------------------------------------------------------------------------

ZONE_NETWORKS = {"eth0": ["10.0.0.0/24", "10.0.1.0/24", "2001:db8::/47"], "eth1": ["10.0.2.0/23", "2001:db8:2::/48"],
                 "eth2": ["10.0.4.0/24", "2001:db8:3::/48"]}  # fmt: skip


def zone_of(address: str) -> str:
    return next(zone for zone, networks in ZONE_NETWORKS.items() if any(_in(address, n) for n in networks))


def emitter_packet(rng: random.Random, zones: List[str]) -> Packet:
    if rng.random() < 0.7:
        src, dst = (f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}" for _ in range(2))
    else:
        src, dst = (f"2001:db8:{rng.randrange(4)}::{rng.randrange(1, 4)}" for _ in range(2))
    proto = rng.choice(["tcp", "tcp", "udp", "icmp" if "." in src else "icmp6", "47"])
    return Packet(rng.choice(zones), zone_of(dst), src, dst, proto, rng.choice([1024, 1500, 40000]),
                  rng.choice([22, 53, 80, 443, 8000, 8005, 8080, 9000]), rng.choice([0, 8, 13, 128]))  # fmt: skip


def effective(model: Policy, report: Report) -> Policy:
    """The model as the conversion left it: without the rules that were written inactive."""
    out = copy.deepcopy(model)
    for rule in out.rules:
        rule.enabled = rule.enabled and not report.item("rule", rule.origin).disabled
    return out


@pytest.mark.parametrize("seed", range(60))
def test_emitted_access_lists_decide_like_the_model(seed: int) -> None:
    """Lists, negations, rule types, zone pairs: with the networks of every zone given, nothing is lost.

    The world of the test is one where every address lies behind one zone, as --zone-network says.
    """
    rng = random.Random(seed)
    model = random_model(rng)
    report = Report()
    text = cli.convert(model, "asa", report, Options(zone_networks=ZONE_NETWORKS))
    # Only what an access list cannot say at all is written inactive: a negated service.
    for item in report.items.values():
        # (A deny rule that has no address left for one of its zones says so as loudly: see below.)
        assert not item.disabled or {f.code for f in item.findings if f.severity == Severity.REVIEW} - {"EGRESS_NO_ADDRESS"} == {"SERVICE_NEGATE"}
    expected = effective(model, report)
    for intra in (False, True):
        config = AsaConfig(text, intra_interface=intra)
        for _ in range(400):
            pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
            want = model_allows(expected, pkt)
            if pkt.in_if == pkt.out_if and not intra:
                want = False  # the ASA does not send it back, whatever the lists say
            assert config.allows(pkt) == want, (seed, intra, pkt, text)


@pytest.mark.parametrize("seed", range(40))
def test_without_zone_networks_nothing_gets_wider(seed: int) -> None:
    """Without the networks an entry cannot be kept to its zone: such rules are inactive or reported, never silent."""
    rng = random.Random(1000 + seed)
    model = random_model(rng)
    report = Report()
    config = AsaConfig(cli.convert(model, "asa", report))
    expected = effective(model, report)
    approximated = {item.name for item in report.items.values() if "EGRESS_INTERFACE" in [f.code for f in item.findings]}
    for _ in range(400):
        pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
        if pkt.in_if == pkt.out_if:
            assert not config.allows(pkt)
            continue
        entry = config.verdict(pkt)
        got = entry is not None and entry["permit"]
        if got != model_allows(expected, pkt):
            # The entry that decided belongs to a rule that was reported as written without its zone.
            assert entry is not None and any(f"remark {name}" in config.text for name in approximated), (seed, pkt)
            decided = [name for name in approximated if _entry_of(config, name, entry)]
            assert decided, (seed, pkt, entry["line"])


def _entry_of(config: AsaConfig, name: str, entry: Dict[str, object]) -> bool:
    """Whether an access list entry stands right below the remark that carries a rule name."""
    lines = config.text.splitlines()
    for index, line in enumerate(lines):
        if line == entry["line"] and index and lines[index - 1].endswith(f" remark {name}"):
            return True
    return False


def _policy(*rules: Rule, zones: Tuple[str, ...] = ("inside", "outside", "dmz")) -> Policy:
    p = Policy(vendor="panos")
    for zone in zones:
        p.zones[zone] = Zone(zone)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32")
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.addresses["site4"] = Address("site4", AddressKind.FQDN, "www.example.com", fqdn_family=4)
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["www"] = Service("www", [ServiceEntry(Protocol.TCP, "80,443")])
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def _convert(p: Policy, **options: object) -> Tuple[AsaConfig, Report, str]:
    report = Report()
    text = cli.convert(p, "asa", report, Options(**options))  # type: ignore[arg-type]
    return AsaConfig(text), report, text


def test_rule_to_every_other_zone_needs_no_destination() -> None:
    p = _policy(Rule("out", src_zones=["inside"], dst_zones=["outside", "dmz"], sources=["lan"], services=["https"]))
    config, report, text = _convert(p)
    assert "access-list inside_access_in extended permit object https object lan any log" in text
    assert report.item("rule", "out").status == "exact" and "access-group inside_access_in in interface inside" in text


def test_rule_to_one_zone_and_any_address_is_inactive_without_networks() -> None:
    p = _policy(Rule("out", src_zones=["inside"], dst_zones=["outside"], sources=["lan"], services=["https"]))
    config, report, text = _convert(p)
    assert "permit object https object lan any log inactive" in text and report.item("rule", "out").disabled
    assert "EGRESS_INTERFACE" in codes(report, "rule", "out") and "--zone-network" in report.to_text()
    # Networks for the zone it does not reach are not enough: nothing is known of the zone it is for.
    config, report, text = _convert(p, zone_networks={"dmz": ["10.20.0.0/16", "2001:db8:20::/48"]})
    assert report.item("rule", "out").disabled and "behind outside with --zone-network" in report.item("rule", "out").findings[0].message
    # With both, the entry leaves out the networks of the other zone; its own zone needs none.
    everything_else = ["0.0.0.0/0", "::/0"]
    config, report, text = _convert(p, zone_networks={"dmz": ["10.20.0.0/16", "2001:db8:20::/48"], "outside": everything_else})
    assert not report.item("rule", "out").disabled and codes(report, "rule", "out") == ["EGRESS_BY_NETWORKS"]
    assert report.item("rule", "out").status == "exact" and "ZONE_NETWORK_GAP" not in codes(report)
    entry = config.acls["inside_access_in"][0]
    assert not entry["inactive"] and entry["dst"][:2] == ["0.0.0.0-10.19.255.255", "10.21.0.0-255.255.255.255"]
    assert entry["dst"][2].startswith("::-2001:db8:1f:") and len(entry["dst"]) == 4
    # Networks of one IP version only say nothing about the other: a permit rule keeps out of it, and that is said.
    config, report, text = _convert(p, zone_networks={"dmz": ["10.20.0.0/16"], "outside": ["0.0.0.0/0"]})
    assert config.acls["inside_access_in"][0]["dst"] == ["0.0.0.0-10.19.255.255", "10.21.0.0-255.255.255.255"]
    assert report.item("rule", "out").status == "approximated"
    note = next(note for note in report.notes if note.code == "ZONE_NETWORK_GAP")
    assert "every IPv6 address" in note.message and note.severity == Severity.APPROX
    # With its own zone given too, the entry does not rely on the ASA refusing to send traffic back.
    config, _, _ = _convert(p, zone_networks={"dmz": ["10.20.0.0/16"], "inside": ["10.10.0.0/16"], "outside": everything_else})
    assert config.acls["inside_access_in"][0]["dst"][0] == "0.0.0.0-10.9.255.255"


def test_rule_to_one_zone_with_addresses_is_written_for_the_addresses() -> None:
    p = _policy(Rule("web", src_zones=["outside"], dst_zones=["dmz"], destinations=["web"], services=["https"]))
    _, report, text = _convert(p)
    assert "access-list outside_access_in extended permit object https any object web log\n" in text
    assert report.item("rule", "web").status == "approximated" and codes(report, "rule", "web") == ["EGRESS_INTERFACE"]
    # The address lies in the networks given for the zone, and every other zone is known: nothing is approximate.
    _, report, _ = _convert(p, zone_networks={"dmz": ["10.20.0.0/24"], "inside": ["10.10.0.0/16"]})
    assert report.item("rule", "web").status == "exact"
    # The zone the rule has to be told apart from has no networks: it may lie inside what was given for the dmz.
    _, report, _ = _convert(p, zone_networks={"dmz": ["10.20.0.0/24"]})
    assert codes(report, "rule", "web") == ["EGRESS_INTERFACE"]
    # A host name has no addresses to compare.
    p.rules[0].destinations = ["site"]
    _, report, _ = _convert(p, zone_networks={"dmz": ["10.20.0.0/24"], "inside": ["10.10.0.0/16"]})
    assert codes(report, "rule", "web") == ["EGRESS_INTERFACE"]


def test_rules_for_every_zone_keep_their_place() -> None:
    p = _policy(
        Rule("block", sources=["lan"], action=Action.DENY, log_end=False),
        Rule("first", src_zones=["inside"], services=["https"]),
        Rule("everyone", services=["www"]),
        Rule("second", src_zones=["inside"], services=["www"], action=Action.DROP),
        Rule("late", destinations=["web"]),
        Rule("dmz", src_zones=["dmz"], destinations=["lan"], enabled=False),
    )
    config, report, text = _convert(p)
    acls = {name: [entry["line"].split(" extended ")[1] for entry in entries] for name, entries in config.acls.items()}
    # The ASA reads the list of an interface before the global one: what stands above a rule of the
    # interface is in its list as well, in place.
    assert acls["inside_access_in"] == [
        "deny ip object lan any log disable", "permit object https any any log",
        "permit object-group www any any log", "deny object-group www any any"]  # fmt: skip
    assert acls["dmz_access_in"][-1] == "permit ip any object lan log inactive" and len(acls["dmz_access_in"]) == 4
    assert acls["global_access"] == [
        "deny ip object lan any log disable", "permit object-group www any any log",
        "permit ip any object web log", "deny ip any any"]  # fmt: skip
    assert config.bound == {"inside": "inside_access_in", "dmz": "dmz_access_in"} and config.global_acl == "global_access"
    assert report.item("rule", "everyone").emitted_as == ["global_access"]
    assert {"ASA_LOAD", "INTERFACES_REQUIRED", "EXISTING_OBJECTS"} <= set(codes(report))


def test_the_policy_is_closed_once() -> None:
    p = _policy(Rule("allow", services=["https"]), Rule("cleanup", action=Action.DROP))
    config, _, text = _convert(p)
    assert [entry["permit"] for entry in config.acls["global_access"]] == [True, False] and "nothing else" not in text
    p.default_interzone = Action.ALLOW
    p.rules.pop()
    config, report, text = _convert(p)
    assert config.acls["global_access"][-1]["line"].endswith("permit ip any any") and "INTERZONE_DEFAULT" in codes(report)


def test_negated_addresses_become_what_they_leave() -> None:
    p = _policy(Rule("r", sources=["lan", "10.20.0.0/24"], negate_source=True, destinations=["web"], negate_destination=True))
    config, report, text = _convert(p)
    entry = config.acls["global_access"][0]
    assert entry["src"] == ["0.0.0.0-10.9.255.255", "10.11.0.0-10.19.255.255", "10.20.1.0-255.255.255.255", "::/0"]
    assert entry["dst"] == ["0.0.0.0-10.20.0.9", "10.20.0.11-255.255.255.255", "::/0"]
    assert codes(report, "rule", "r") == ["NEGATION_EXPANDED"] * 2 and report.item("rule", "r").status == "exact"
    p = _policy(Rule("r", sources=["0.0.0.0/0", "::/0"], negate_source=True))
    _, report, text = _convert(p)
    assert report.item("rule", "r").skipped and "access-list global_access extended permit" not in text
    # What a host name leaves cannot be written out, and an inactive entry would say the opposite.
    p = _policy(Rule("r", destinations=["site"], negate_destination=True), Rule("s", services=["https"], negate_service=True))
    config, report, text = _convert(p)
    assert report.item("rule", "r").disabled and report.item("rule", "s").disabled
    assert [entry["line"] for entry in config.acls["global_access"]] == ["access-list global_access extended deny ip any any"]
    assert "remark FWSHIFT not converted, see the report: r" in text and "NEGATION_NOT_STATIC" in codes(report, "rule", "r")


def test_rule_types() -> None:
    p = _policy(
        Rule("inside-only", src_zones=["inside"], scope=RuleScope.INTRAZONE, destinations=["lan"]),
        Rule("inside-any", src_zones=["inside"], scope=RuleScope.INTRAZONE),
        Rule("between", src_zones=["inside", "dmz"], dst_zones=["inside", "dmz", "outside"], scope=RuleScope.INTERZONE),
        Rule("from-any", scope=RuleScope.INTERZONE, services=["https"]),
        Rule("nothing", src_zones=["dmz"], dst_zones=["dmz"], scope=RuleScope.INTERZONE),
        Rule("any-intra", scope=RuleScope.INTRAZONE),
    )
    config, report, text = _convert(p)
    assert codes(report, "rule", "inside-only") == ["EGRESS_INTERFACE"] and not report.item("rule", "inside-only").disabled
    assert "same-security-traffic permit intra-interface" in report.item("rule", "inside-only").findings[0].message
    assert report.item("rule", "inside-any").disabled
    # Between different zones is what every entry of an ASA is about.
    assert report.item("rule", "between").status == "exact" and report.item("rule", "from-any").status == "exact"
    assert report.item("rule", "nothing").skipped and "RULE_TYPE_EMPTY" in codes(report, "rule", "nothing")
    assert report.item("rule", "any-intra").disabled and "RULE_TYPE" in codes(report, "rule", "any-intra")


def test_objects_services_and_host_names() -> None:
    p = _policy(
        Rule("a", sources=["10.1.1.1", "10.2.0.0/16", "10.3.0.1-10.3.0.9", "2001:db8::/32"], destinations=["site", "site4"],
             services=["https", "www"]),
        Rule("b", sources=[ANY_V4], destinations=[ANY_V6], services=["ping", "gre", "high"], log_end=False),
        Rule("c", sources=["10.3.0.1-10.3.0.9"], destinations=["2001:db8::1"], services=["high"], action=Action.RESET_BOTH),
    )
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8, icmp_code=0)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.services["high"] = Service("high", [ServiceEntry(Protocol.UDP, "0-1023", "1024-65535")])
    config, report, text = _convert(p)
    assert config.networks["site"] == ["fqdn v4 www.example.com", "fqdn v6 www.example.com"]  # one object per IP version
    assert config.networks["site4"] == ["fqdn v4 www.example.com"] and "FQDN_DNS" in codes(report)
    first, second, third = config.acls["global_access"][:3]
    assert first["src"] == ["10.1.1.1", "10.2.0.0/255.255.0.0", "10.3.0.1-10.3.0.9", "2001:db8::/32"]
    assert [spec["dst"] for spec in first["services"]] == [(443, 443), (80, 80), (443, 443)]
    assert second["line"].startswith("access-list global_access extended permit object-group FWSHIFT_SERVICE_2 any4 any6")
    assert "object service ping\n service icmp 8 0\n" in text and "object service gre\n service gre\n" in text
    assert "object service high\n service udp source gt 1023 destination lt 1024\n" in text
    assert third["line"].endswith("deny object high object r-10.3.0.1-10.3.0.9 host 2001:db8::1")
    assert "RESET_ACTION" in codes(report, "rule", "c")


def test_what_cannot_be_converted_is_inactive_with_a_placeholder() -> None:
    p = _policy(
        Rule("odd", sources=["wild"], services=["strange"]),
        Rule("users", users=["bob"]),
        Rule("timed", schedule="night", action=Action.DROP),
        Rule("app", applications=["no-such-app"]),
    )
    p.addresses["wild"] = Address("wild", AddressKind.UNSUPPORTED, "", raw="wildcard mask")
    p.services["strange"] = Service("strange", [], unsupported="something odd")
    config, report, text = _convert(p)
    assert all(entry["inactive"] for entry in config.acls["global_access"][:4])
    assert config.networks["wild"] == ["192.0.0.8"] and config.services["strange"][0]["protocol"] == "255"
    assert "FWSHIFT PLACEHOLDER, matches nothing: wildcard mask" in text
    assert all(report.item("rule", name).disabled for name in ("odd", "users", "timed", "app"))


def test_names_and_the_prefix() -> None:
    p = _policy(Rule("r", sources=["any-thing"], destinations=["host"], services=["my service"]))
    p.addresses["any-thing"] = Address("any-thing", AddressKind.NETWORK, "10.1.1.1/32")
    p.addresses["host"] = Address("host", AddressKind.NETWORK, "10.1.1.2/32")  # a word of the command line
    p.addresses["my service"] = Address("my service", AddressKind.NETWORK, "10.1.1.3/32")
    p.services["my service"] = Service("my service", [ServiceEntry(Protocol.TCP, "1")])
    config, report, text = _convert(p)
    assert "host" not in config.kinds and "host_2" in config.kinds
    assert config.kinds["my_service"] == "object network" and config.kinds["my_service_2"] == "object service"
    config, _, text = _convert(p, object_prefix="NEW-", zone_map={"inside": "lan"})
    assert set(config.kinds) >= {"NEW-any-thing", "NEW-host", "NEW-my_service"} and "access-list NEW-global_access" in text


def test_interface_names_that_cannot_be() -> None:
    p = _policy(Rule("r", src_zones=["my zone"], services=["https"]), zones=("my zone", "outside"))
    config, report, text = _convert(p)
    assert report.item("rule", "r").disabled and "INTERFACE_NAME" in codes(report, "rule", "r")
    assert "my zone" not in text.replace("remark", "")
    config, report, text = _convert(p, zone_map={"my zone": "inside"})
    assert not report.item("rule", "r").disabled and config.bound == {"inside": "inside_access_in"}


# -- the emitter: NAT -----------------------------------------------------------------------


def _nat_policy(*rules: NatRule) -> Policy:
    p = _policy()
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.10/32")
    p.addresses["pool"] = Address("pool", AddressKind.NETWORK, "203.0.113.16/28")
    p.addresses["remote"] = Address("remote", AddressKind.NETWORK, "10.99.0.0/16")
    for nat in rules:
        nat.origin = nat.name
        p.nat_rules.append(nat)
    return p


def _nat_lines(p: Policy, **options: object) -> Tuple[List[str], Report, AsaConfig]:
    config, report, text = _convert(p, **options)
    return [line for line in text.splitlines() if line.startswith("nat ")], report, config


def test_nat_rules_as_twice_nat() -> None:
    p = _nat_policy(
        NatRule("exempt", ["inside"], ["outside"], ["lan"], ["remote"]),
        NatRule("forward", ["outside"], ["outside"], destinations=["pub"], service="https",
                destination_translation=DestNat("web", "8443")),
        NatRule("static", ["dmz"], ["outside"], ["web"], source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True)),
        NatRule("one-way", ["dmz"], ["outside"], ["web"], source_translation=SourceNat(SnatKind.STATIC, ["pub"])),
        NatRule("pool", ["dmz"], ["outside"], ["web"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool"])),
        NatRule("hide", ["inside"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.9"])),
        NatRule("dynamic", ["inside"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.DYNAMIC, ["pool"])),
        NatRule("pat", ["inside"], ["outside"], source_translation=SourceNat(SnatKind.INTERFACE), enabled=False),
        NatRule("both", ["inside"], ["inside"], ["lan"], ["pub"], "www", SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.9"]),
                DestNat("web"), description="hairpin"),
    )
    lines, report, config = _nat_lines(p)
    assert lines == [
        "nat (inside,outside) source static lan lan destination static remote remote no-proxy-arp route-lookup description exempt",
        "nat (outside,any) source static any any destination static pub web service https tcp-8443 unidirectional description forward",
        "nat (dmz,outside) source static web pub description static",
        "nat (dmz,outside) source static web pub unidirectional description one-way",
        "nat (dmz,outside) source dynamic web pat-pool r-203.0.113.16-203.0.113.31 description pool",
        "nat (inside,outside) source dynamic lan h-203.0.113.9 description hide",
        "nat (inside,outside) source dynamic lan r-203.0.113.16-203.0.113.31 description dynamic",
        "nat (inside,outside) source dynamic any interface inactive description pat",
        "nat (inside,any) source dynamic lan h-203.0.113.9 destination static pub web service tcp-80 tcp-80 description both hairpin",
        "nat (inside,any) source dynamic lan h-203.0.113.9 destination static pub web service https https description both hairpin",
    ]  # fmt: skip
    assert config.networks["r-203.0.113.16-203.0.113.31"] == ["203.0.113.16-203.0.113.31"]  # a pool holds no subnet
    assert all(report.item("nat", nat.origin).status == "exact" for nat in p.nat_rules)
    assert report.item("nat", "both").emitted_as == ["2 NAT lines"]


def test_a_published_port_of_a_source_that_combines_rules_is_written_from_the_server() -> None:
    forward = NatRule("forward", ["outside"], ["outside"], destinations=["pub"], service="https",
                      destination_translation=DestNat("web", "8443"), combines=True)  # fmt: skip
    hide = NatRule("hide", ["outside"], ["dmz"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]), combines=True)
    lines, report, config = _nat_lines(_nat_policy(forward, hide))
    # So that the rule that hides the clients still applies, as it did on the source.
    assert lines[0] == "nat (any,outside) source static web pub service tcp-src-8443 tcp-src-443 description forward"
    assert config.services["tcp-src-8443"] == [{"protocol": "tcp", "src": (8443, 8443), "dst": None, "icmp": None}]
    assert "NAT_ORDER" not in codes(report)
    # Without a port there is no such way to write it: the destination translation stands alone, and that is said.
    forward.service, forward.destination_translation = ANY, DestNat("web")
    lines, report, _ = _nat_lines(_nat_policy(forward, hide))
    # One way only: a static rule of an ASA would translate what the server opens as well.
    assert lines[0] == "nat (outside,any) source static any any destination static pub web unidirectional description forward"
    assert "NAT_ORDER" in codes(report)


def test_nat_to_the_outgoing_interface() -> None:
    def pat(**fields: str) -> NatRule:
        return NatRule("pat", ["inside"], [ANY], ["lan"], source_translation=SourceNat(SnatKind.INTERFACE, **fields))

    lines, report, _ = _nat_lines(_nat_policy(pat()))
    assert not lines and report.item("nat", "pat").skipped and "--target-nat-zone" in report.to_text()
    lines, report, _ = _nat_lines(_nat_policy(pat()), nat_zone="outside")
    assert lines == ["nat (inside,outside) source dynamic lan interface description pat"]
    # The address the interface has today is no substitute: an ASA refuses NAT to an address of its own.
    lines, report, _ = _nat_lines(_nat_policy(pat(interface_address="203.0.113.2")))
    assert not lines and report.item("nat", "pat").skipped
    p = _nat_policy(pat(interface="ethernet1/1", interface_address="203.0.113.2"))
    p.zones["outside"].interfaces = ["ethernet1/1"]
    lines, report, _ = _nat_lines(p, zone_map={"outside": "wan"})
    assert lines == ["nat (inside,wan) source dynamic lan interface description pat"]


@pytest.mark.parametrize(
    "nat,code",
    [
        (NatRule("n", sources=["site"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pub"])), "NAT_ADDRESSES"),
        (NatRule("n", destinations=["site"]), "NAT_ADDRESSES"),
        (NatRule("n", destinations=["pub", "pool"], destination_translation=DestNat("web")), "NAT_DESTINATION"),
        (NatRule("n", destination_translation=DestNat("web")), "NAT_DESTINATION"),
        (NatRule("n", destinations=["pub"], destination_translation=DestNat("web", "80")), "NAT_PORT"),
        (NatRule("n", destinations=["pub"], service="range", destination_translation=DestNat("web", "80")), "NAT_PORT"),
        (NatRule("n", destinations=["pub"], service="ping", destination_translation=DestNat("web")), "NAT_SERVICE"),
        (NatRule("n", destinations=["pub"], service="alltcp", destination_translation=DestNat("web")), "NAT_SERVICE"),
        (NatRule("n", destinations=["pub"], service="many", destination_translation=DestNat("web")), "NAT_SERVICE"),
        (NatRule("n", sources=["lan"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["site"])), "NAT_POOL"),
        (NatRule("n", ["my zone"], sources=["lan"], source_translation=SourceNat(SnatKind.STATIC, ["pool"])), "NAT_NOT_CONVERTED"),
        (NatRule("n", sources=["lan"], unsupported=["something"]), "NAT_NOT_CONVERTED"),
    ],
)  # fmt: skip
def test_nat_rules_an_asa_cannot_take(nat: NatRule, code: str) -> None:
    p = _nat_policy(nat)
    p.services["range"] = Service("range", [ServiceEntry(Protocol.TCP, "8000-8010")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["alltcp"] = Service("alltcp", [ServiceEntry(Protocol.TCP)])
    p.services["many"] = Service("many", [ServiceEntry(Protocol.TCP, ",".join(str(port) for port in range(100, 140, 2)))])
    lines, report, _ = _nat_lines(p)
    assert not lines and report.item("nat", "n").skipped and codes(report, "nat", "n") == [code]


def test_nat_details_that_are_reported() -> None:
    p = _nat_policy(
        NatRule("one", ["inside"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.DYNAMIC, ["pub"])),
        NatRule("sizes", ["dmz"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.STATIC, ["pool"], bidirectional=True)),
    )
    lines, report, _ = _nat_lines(p)
    assert codes(report, "nat", "one") == ["NAT_DYNAMIC_ONE_ADDRESS"] and codes(report, "nat", "sizes") == ["NAT_STATIC_SIZE"]
    assert lines[1] == "nat (dmz,outside) source static lan pool description sizes"


def test_rules_name_the_real_address_of_a_translated_destination() -> None:
    p = _nat_policy(NatRule("forward", ["outside"], ["outside"], destinations=["pub"], service="https",
                            destination_translation=DestNat("web", "8443")))  # fmt: skip
    p.rules.append(Rule("in", src_zones=["outside"], dst_zones=["dmz"], destinations=["pub"], services=["https"]))
    p.rules[0].origin = "in"
    config, report, text = _convert(p)
    assert "access-list outside_access_in extended permit object https any object web log" in text
    assert {"NAT_DESTINATION_REWRITTEN", "NAT_PORT_TRANSLATION"} <= set(codes(report, "rule", "in"))


def test_nat_order_when_a_rule_above_names_no_destination() -> None:
    """Model: the first rule that matches applies. ASA: the first rule that names the destination translates it."""
    hide = NatRule("hide", ["inside"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.9"]))
    uturn = NatRule("uturn", ["inside"], ["outside"], destinations=["pub"], destination_translation=DestNat("web"))
    _, report, _ = _nat_lines(_nat_policy(hide, uturn))
    assert codes(report, "nat", "uturn") == ["NAT_ORDER"] and report.item("nat", "uturn").status == "needs-review"
    # A rule above that names its destination claims its traffic on the ASA as it did on the source.
    hide.destinations = ["remote"]
    _, report, _ = _nat_lines(_nat_policy(hide, uturn))
    assert not codes(report, "nat", "uturn")
    hide.destinations = [ANY]
    hide.src_zones = ["dmz"]  # other traffic altogether
    _, report, _ = _nat_lines(_nat_policy(hide, uturn))
    assert not codes(report, "nat", "uturn")


# -- there and back ---------------------------------------------------------------------------


def test_sample_survives_the_way_there_and_back() -> None:
    original, _ = load("asa_sample.cfg")
    text, report = run("asa_sample.cfg", "asa")
    AsaConfig(text)
    again, second = parse(HEAD.split("interface")[0] + (DATA / "asa_sample.cfg").read_text().split("object network web-srv")[0]
                          .split("hostname edge-fw")[1] + text)  # fmt: skip
    # Same addresses, services and NAT; the rules differ in their generated names only.
    assert {n: (a.kind, a.value) for n, a in again.addresses.items() if not n.startswith("h-")} == {
        n: (a.kind, a.value) for n, a in original.addresses.items()}  # fmt: skip
    assert [(n.src_zones, n.sources, n.destinations, n.source_translation and n.source_translation.kind,
             n.destination_translation) for n in again.nat_rules] == [
        (n.src_zones, n.sources, n.destinations, n.source_translation and n.source_translation.kind,
         n.destination_translation) for n in original.nat_rules]  # fmt: skip
    def shape(p: Policy) -> List[Tuple[object, ...]]:
        def addresses(members: List[str]) -> object:
            return normalize([i for member in members for i in transform.known_intervals(p, member)[0]])

        return [(r.src_zones, r.dst_zones, addresses(r.sources), addresses(r.destinations), r.action)
                for r in p.rules if r.enabled and not r.name.startswith("implicit") and not r.schedule and r.users == [ANY]]  # fmt: skip

    assert shape(again)[: len(shape(original))] == shape(original)


@pytest.mark.parametrize("sample", ["panos_sample.xml", "fortios_sample.conf", "checkpoint_sample.json", "iptables_sample.rules"])
def test_every_sample_gives_commands_an_asa_would_take(sample: str) -> None:
    text, report = run(sample, "asa")
    config = AsaConfig(text)
    assert config.global_acl == "global_access" and config.acls["global_access"]
    again, second = parse("ASA Version 9.16(1)\n" + text)
    assert not any(rule.unsupported for rule in again.rules), [r.unsupported for r in again.rules if r.unsupported]
    assert not any(nat.unsupported for nat in again.nat_rules), [n.unsupported for n in again.nat_rules if n.unsupported]
    written = sum(1 for item in report.items.values() if item.kind == "nat" and not item.skipped)
    assert len(again.nat_rules) >= written


@pytest.mark.parametrize("target", ["panos", "fortios", "checkpoint", "iptables", "ip6tables", "asa"])
def test_asa_sample_converts_to_every_target(target: str) -> None:
    text, report = run("asa_sample.cfg", target, Options(nat_zone="outside", target_gateway="gw"))
    assert text and report.counts("rule")["total"] == 18
    assert report.item("rule", "inside_access_in-4").disabled  # a schedule is never dropped silently
    assert report.item("rule", "inside_access_in-8").status == "exact"  # inactive there, inactive here


def test_cli_options(capsys: pytest.CaptureFixture[str]) -> None:
    sample = str(DATA / "panos_sample.xml")
    args = ["convert", sample, "--to", "asa", "-q", "--zone-network", "dmz=10.20.0.0/16", "--zone-network", "dmz=10.21.0.0/16"]
    args += ["--zone-network", "untrust=0.0.0.0/0,::/0"]
    assert cli.main(args + ["--zone-network", "ot=10.30.0.0/16", "--zone-network", "trust=10.10.0.0/16,2001:db8:10::/48"]) == 0
    out = capsys.readouterr().out
    assert "range 10.22.0.0 10.29.255.255" in out  # both networks of dmz are left out
    assert cli.main(args + ["--zone-network", "ot=nonsense"]) == 1
    assert "--zone-network expects" in capsys.readouterr().err
    assert cli.main(["convert", str(DATA / "asa_sample.cfg"), "--to", "fortios", "-q"]) == 0
    assert 'set srcintf "outside"' in capsys.readouterr().out
    assert cli.main(["inspect", str(DATA / "asa_sample.cfg")]) == 0
    assert "format:          asa" in capsys.readouterr().out


# -- found in review ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "nat",
    ["object network DMZNET\n nat (dmz,outside) static 198.51.100.0\n",
     "object network PUBNET\n subnet 198.51.100.0 255.255.255.0\nnat (dmz,outside) source static DMZNET PUBNET\n"],
)  # fmt: skip
def test_rule_for_one_host_of_a_translated_network_stays_a_rule_for_one_host(nat: str) -> None:
    body = (
        "object network DMZNET\n subnet 10.20.0.0 255.255.255.0\n" + nat
        + "access-list O extended permit tcp any host 10.20.0.10 eq 80\n"
        "access-list O extended permit tcp any 10.20.0.32 255.255.255.240 eq 22\n"
        "access-list O extended deny ip any any\naccess-group O in interface outside\n"
    )
    p, report = parse(HEAD + body)
    # The same host and the same sixteen addresses of the other side, not all of it.
    assert p.rules[0].destinations == ["10.20.0.10", "198.51.100.10"]
    assert p.rules[1].destinations == ["10.20.0.32/28", "198.51.100.32/28"]
    out = Report()
    config = AsaConfig(cli.convert(copy.deepcopy(p), "asa", out))
    assert config.acls["outside_access_in"][0]["dst"] == ["10.20.0.10"] and out.item("rule", "O-1").status == "exact"
    assert config.acls["outside_access_in"][1]["dst"] == ["10.20.0.32/255.255.255.240"]
    assert "-d 10.20.0.0/24" not in cli.convert(copy.deepcopy(p), "iptables", Report()).split("*nat")[0]
    assert 'destination [ 10.20.0.10 198.51.100.10 ]' in cli.convert(copy.deepcopy(p), "panos", Report())
    assert 'set dstaddr "h-10.20.0.10"\n' in cli.convert(copy.deepcopy(p), "fortios", Report())


def test_part_of_a_translation_that_is_not_one_to_one_is_reported() -> None:
    """Four public addresses to one server: a rule for one of them cannot be told apart behind the translation."""
    p = _nat_policy(NatRule("many", ["outside"], ["outside"], destinations=["four"], destination_translation=DestNat("web")))
    p.addresses["four"] = Address("four", AddressKind.RANGE, "203.0.113.20-203.0.113.23")
    p.rules.append(Rule("one", src_zones=["outside"], dst_zones=["dmz"], destinations=["203.0.113.21"], services=["https"]))
    p.rules[0].origin = "one"
    for target in ("asa", "iptables"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report)
        assert "NAT_DESTINATION_WIDENED" in codes(report, "rule", "one") and report.item("rule", "one").status == "needs-review"


def test_port_translated_on_the_same_address() -> None:
    body = (
        "object network SRV\n host 10.20.0.10\nobject service HTTP\n service tcp destination eq www\n"
        "object service ALT\n service tcp destination eq 8080\n"
        "nat (outside,dmz) source static any any destination static SRV SRV service HTTP ALT\n"
        "access-list O extended permit tcp any object SRV eq www\n"
        "access-list O extended permit tcp any object SRV eq 8080\n"
        "access-list O extended permit tcp any object SRV range 80 8080\n"
        "access-list O extended permit ip any object SRV\n"
        "access-list O extended permit tcp any object SRV eq 22\n"
        "access-group O in interface outside\n"
    )
    p, report = parse(HEAD + body)
    # Port 80 is gone before the list is read: the entry matched nothing, the converted rule would.
    assert codes(report, "rule", "O-1") == ["NAT_PORT_EXPOSED"] and report.item("rule", "O-1").status == "needs-review"
    assert codes(report, "rule", "O-2") == ["NAT_PORT_TRANSLATION"]
    assert not codes(report, "rule", "O-3")  # a range that holds both ports matches the traffic on either side
    assert not codes(report, "rule", "O-4") and not codes(report, "rule", "O-5")
    # Back to an ASA nothing of that matters.
    out = Report()
    cli.convert(parse(HEAD + body)[0], "asa", out)
    assert not codes(out, "rule", "O-1") and not codes(out, "rule", "O-2")


def test_rule_for_the_translated_port_only_is_reported_towards_a_target_that_looks_up_after_nat() -> None:
    p = _nat_policy(NatRule("forward", ["outside"], ["outside"], destinations=["pub"], service="https",
                            destination_translation=DestNat("web", "8443")))  # fmt: skip
    p.services["alt"] = Service("alt", [ServiceEntry(Protocol.TCP, "8443")])
    p.rules.append(Rule("direct", src_zones=["outside"], dst_zones=["dmz"], destinations=["pub"], services=["alt"]))
    p.rules.append(Rule("server", src_zones=["outside"], dst_zones=["dmz"], destinations=["web"], services=["alt"]))
    p.rules[0].origin, p.rules[1].origin = "direct", "server"
    for target in ("asa", "iptables", "fortios"):
        report = Report()
        text = cli.convert(copy.deepcopy(p), target, report)
        # Port 8443 of the public address is not what the NAT rule forwards: the rule is not for that traffic
        # and keeps its address, on which nothing translated arrives.
        assert not [code for code in codes(report, "rule", "direct") if code.startswith("NAT_")], target
        if target == "asa":
            assert "permit object alt any object pub" in text
        # A rule for the server and its real port saw direct traffic only; after NAT it sees the forwarded traffic too.
        assert "NAT_ADDRESS_EXPOSED" in codes(report, "rule", "server"), target


def test_an_ftd_forwards_between_and_within_its_interfaces() -> None:
    hairpin = "access-list CSM_FW_ACL_ advanced permit tcp ifc inside any ifc inside any eq 445 rule-id 268435462\n"
    p, report = parse(FTD.replace("access-list CSM_FW_ACL_ remark rule-id 268435461", hairpin + "access-list CSM_FW_ACL_ remark rule-id 268435461"))
    assert "RULE_WITHOUT_EFFECT" not in codes(report) and len(p.rules) == 8
    inside = next(rule for rule in p.rules if rule.name == "rule-268435462")
    assert inside.src_zones == ["inside"] and inside.dst_zones == ["inside"]
    # An entry without interfaces is for every pair of them, the same one included.
    p, _ = parse(FTD.replace("ifc outside any ifc dmz object web", "any object web"))
    web = next(rule for rule in p.rules if rule.name == "Web in")
    assert web.src_zones == [ANY] and web.dst_zones == ["dmz"] and web.scope == RuleScope.UNIVERSAL


def _zone_rules(*rules: Rule, networks: Dict[str, List[str]]) -> Tuple[AsaConfig, Report]:
    config, report, _ = _convert(_policy(*rules), zone_networks=networks)
    return config, report


def test_zone_networks_follow_the_longest_prefix() -> None:
    deny = Rule("no-dmz", src_zones=["inside"], dst_zones=["dmz"], action=Action.DROP)
    allow = Rule("out", src_zones=["inside"])
    # "outside is everything else", said as a default route would say it.
    networks = {"outside": ["0.0.0.0/0", "::/0"], "inside": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"]}
    config, report = _zone_rules(deny, allow, networks=networks)
    assert config.acls["inside_access_in"][0]["dst"] == ["10.20.0.0/255.255.255.0"] and not report.item("rule", "no-dmz").skipped
    # One network inside another: the smaller one is the zone.
    nested = Rule("no-dmz", src_zones=["outside"], dst_zones=["dmz"], action=Action.DROP)
    config, _ = _zone_rules(nested, networks={"inside": ["10.0.0.0/8"], "dmz": ["10.20.0.0/24"]})
    # (A deny rule keeps what nobody placed: the addresses outside the two networks, and IPv6.)
    assert config.acls["outside_access_in"][0]["dst"] == ["0.0.0.0-9.255.255.255", "10.20.0.0/255.255.255.0", "11.0.0.0-255.255.255.255", "::/0"]
    to_inside = Rule("in", src_zones=["outside"], dst_zones=["inside"])
    config, _ = _zone_rules(to_inside, networks={"inside": ["10.0.0.0/8"], "dmz": ["10.20.0.0/24"]})
    assert config.acls["outside_access_in"][0]["dst"] == ["10.0.0.0-10.19.255.255", "10.20.1.0-10.255.255.255"]


def test_zone_networks_of_the_zones_a_rule_reaches_keep_it_there() -> None:
    """Networks that do not cover everything: what is given for the zone of the rule is where it goes, no further."""
    rule = Rule("to-dmz", src_zones=["inside"], dst_zones=["dmz"])
    networks = {"outside": ["203.0.113.0/24"], "inside": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"]}
    config, report = _zone_rules(rule, networks=networks)
    assert config.acls["inside_access_in"][0]["dst"] == ["10.20.0.0/255.255.255.0"]  # not "all but the other two"
    finding = report.item("rule", "to-dmz").findings[0]
    assert "and the addresses that lie in none of the networks given" in finding.message and finding.severity == Severity.APPROX
    assert "ZONE_NETWORK_GAP" in codes(report)
    # The zone of the rule has no networks, the others have: it is not given "the rest". Nobody said it has it.
    config, report = _zone_rules(Rule("out", src_zones=["inside"], dst_zones=["outside"]),
                                 networks={"inside": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"]})  # fmt: skip
    assert config.acls["inside_access_in"][0]["inactive"] and "behind outside" in report.item("rule", "out").findings[0].message
    # Said, it has.
    config, report = _zone_rules(Rule("out", src_zones=["inside"], dst_zones=["outside"]),
                                 networks={"inside": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"], "outside": ["0.0.0.0/0"]})  # fmt: skip
    assert config.acls["inside_access_in"][0]["dst"] == ["0.0.0.0-10.9.255.255", "10.11.0.0-10.19.255.255", "10.20.1.0-255.255.255.255"]
    assert "leaves out the networks given for the other zones" in report.item("rule", "out").findings[0].message


def test_zone_networks_that_cannot_be() -> None:
    p = _policy(Rule("r", src_zones=["inside"], dst_zones=["outside"]))
    for networks in ({"inside": ["10.0.0.0/8"], "dmz": ["10.0.0.0/8"]}, {"inside": ["10.0.0.1-10.0.0.9"], "dmz": ["10.0.0.5-10.0.0.20"]}):
        with pytest.raises(FwshiftError, match="--zone-network"):
            _convert(copy.deepcopy(p), zone_networks=networks)
    # A zone nobody knows: perhaps a further interface, perhaps a slip of the keyboard. Said either way.
    config, report, _ = _convert(copy.deepcopy(p), zone_networks={"dmzz": ["192.0.2.0/24"], "dmz": ["10.20.0.0/24"]})
    assert "ZONE_NETWORK_UNKNOWN" in codes(report) and report.needs_review


def test_other_interfaces_than_the_policy_names_are_an_assumption_that_is_stated() -> None:
    text, report = run("iptables_sample.rules", "asa")
    note = next(note for note in report.notes if note.code == "INTERFACES_REQUIRED")
    assert "and no others" in note.message and note.severity == Severity.REVIEW


def test_groups_that_hold_themselves_or_any() -> None:
    p, _ = parse(
        HEAD
        + "object-group network G\n network-object host 10.20.0.1\n group-object G\n"
        "object-group network ONLY\n group-object ONLY\n"
        "object-group service S\n group-object S\n"
        "access-list I extended permit ip any object-group G\n"
        "access-list I extended permit ip any object-group ONLY\n"
        "access-list I extended permit object-group S any any\n"
        "access-group I in interface inside\n"
    )
    for target in ("asa", "panos", "fortios", "checkpoint", "iptables"):
        report = Report()
        text = cli.convert(copy.deepcopy(p), target, report)
        # No platform takes such a group: a placeholder is written and the rules that use it are switched off.
        assert all(report.item("rule", name).disabled for name in ("I-1", "I-2", "I-3")), target
        assert "UNSUPPORTED_GROUP" in codes(report, "address-group", "G") and "group-object G" not in text
    config = AsaConfig(cli.convert(copy.deepcopy(p), "asa", Report()))
    assert config.networks["G"] == ["192.0.0.8"] and config.services["S"][0]["protocol"] == "255"
    # "any" as a member of a group: both IP versions.
    q = _policy(Rule("r", destinations=["everything"]))
    q.address_groups["everything"] = AddressGroup("everything", [ANY, "web"])
    config, report, _ = _convert(q)
    assert config.networks["everything"] == ["0.0.0.0/0.0.0.0", "::/0", "10.20.0.10"]


def test_access_group_for_an_interface_without_a_section() -> None:
    body = "access-list D extended permit tcp any any eq 80\naccess-group D in interface lab\naccess-group D out interface lab2\n"
    p, report = parse(HEAD + body)
    assert p.rules[0].src_zones == ["lab"] and "lab" in p.zones
    # The traffic of the other interfaces may leave by it as well.
    p, _ = parse(HEAD + body + "access-list I extended permit ip any any\naccess-group I in interface inside\n")
    assert next(rule for rule in p.rules if rule.name == "I-1").dst_zones == ["outside", "dmz", "lab", "lab2"]


def test_nesting_that_fans_out_costs_no_more_than_its_groups() -> None:
    """Forty levels of two groups that each hold both groups below: 2**40 paths, eighty groups."""
    depth = 40

    def diamond(kind: str, first: str, second: str, tag: str, suffix: str = "") -> List[str]:
        out = [f"object-group {kind} A0{tag}{suffix}", f" {first}", f"object-group {kind} B0{tag}{suffix}", f" {second}"]
        for level in range(1, depth):
            for name in "AB":
                out += [f"object-group {kind} {name}{level}{tag}{suffix}", f" group-object A{level - 1}{tag}", f" group-object B{level - 1}{tag}"]
        return out

    lines = diamond("network", "network-object host 10.20.0.5", "network-object host 10.20.0.6", "n")
    lines += diamond("service", "service-object tcp destination eq 80", "service-object udp destination eq 53", "s")
    lines += diamond("service", "port-object eq 80", "port-object eq 81", "p", " tcp")
    lines += diamond("protocol", "protocol-object tcp", "protocol-object udp", "q")
    lines += diamond("icmp-type", "icmp-object echo", "icmp-object echo-reply", "i")
    top = depth - 1
    body = "\n".join(lines) + (
        f"\naccess-list I extended permit ip any object-group A{top}n\n"
        f"access-list I extended permit object-group A{top}s any any\n"
        f"access-list I extended permit tcp any any object-group A{top}p\n"
        f"access-list I extended permit object-group A{top}q any any eq 53\n"
        f"access-list I extended permit icmp any any object-group A{top}i\n"
        "access-group I in interface inside\n"
    )
    p, _ = parse(HEAD + body)
    assert not any(rule.unsupported for rule in p.rules)
    assert p.services[p.rules[2].services[0]].entries[0].dst_ports == "80,81"
    for target in ("asa", "panos", "fortios", "checkpoint", "iptables", "ip6tables"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report)
        assert not [name for name in ("I-1", "I-2", "I-3", "I-4", "I-5") if report.item("rule", name).disabled], target


def test_the_address_of_an_interface_goes_back_as_the_word_interface() -> None:
    for line in (
        "nat (dmz,outside) source static SRV interface service SRC-ALT SRC-HTTP",
        "object network SRV\n nat (dmz,outside) static interface service tcp 8080 www",
    ):
        p, report = parse(HEAD + NAT_OBJECTS + line + "\n")
        text = cli.convert(p, "asa", report)
        # An ASA refuses an object with an address of its own in a NAT rule.
        assert "nat (any,outside) source static SRV interface service SRC-ALT SRC-HTTP" in text, text
        assert not codes(report, "nat", p.nat_rules[0].origin)
        assert "outside-interface" not in text  # the object that stood for the word is not left behind
        p, other = parse(HEAD + NAT_OBJECTS + line + "\n")
        cli.convert(p, "panos", other)
        assert codes(other, "nat", p.nat_rules[0].origin) == ["NAT_INTERFACE_ADDRESS"]
    p, _ = parse(HEAD + NAT_OBJECTS + "nat (outside,dmz) source static LAN LAN destination static interface SRV service HTTP ALT\n")
    text = cli.convert(p, "asa", Report())
    assert "nat (outside,any) source static LAN LAN destination static interface SRV service HTTP ALT" in text


def test_nat_lines_an_asa_would_refuse_are_not_written() -> None:
    mixed = NatRule("mixed", ["inside"], ["outside"], ["lan", "2001:db8:10::/64"], source_translation=SourceNat(SnatKind.INTERFACE))
    lines, report, _ = _nat_lines(_nat_policy(mixed))
    assert not lines and codes(report, "nat", "mixed") == ["NAT_ADDRESSES"]
    for bad in ("a,b", "x)", "any", "in side", "what?"):
        with pytest.raises(FwshiftError, match="--target-nat-zone"):
            _convert(_nat_policy(), nat_zone=bad)
    with pytest.raises(FwshiftError, match="--zone-map"):
        _convert(_policy(Rule("r", src_zones=["inside"])), zone_map={"inside": "any"})
    _, report, _ = _convert(_policy(Rule("r", src_zones=["inside"])), zone_map={"inside": "in?side"})
    assert "INTERFACE_NAME" in codes(report, "rule", "r")


def test_a_translation_of_the_destination_alone_is_written_one_way() -> None:
    forward = NatRule("forward", ["outside"], ["outside"], destinations=["pub"], destination_translation=DestNat("web"))
    exempt = NatRule("exempt", sources=["lan"], destinations=["remote"])
    nothing = NatRule("nothing", ["inside"], ["outside"])
    lines, _, _ = _nat_lines(_nat_policy(forward, exempt, nothing))
    assert lines == [
        "nat (outside,any) source static any any destination static pub web unidirectional description forward",
        "nat (any,any) source static lan lan destination static remote remote no-proxy-arp description exempt",
        "nat (inside,outside) source static any any no-proxy-arp route-lookup description nothing",
    ]


def test_lists_for_ipv6_and_ethertype_are_not_missing_lists() -> None:
    old = HEAD.replace("9.12(4)", "8.4(7)")
    p, report = parse(
        old + "ipv6 access-list SIX permit ip any any\naccess-list ETH ethertype permit bpdu\n"
        "access-group SIX in interface inside\naccess-group ETH in interface dmz\n"
    )
    assert "ACL_MISSING" not in codes(report) and "TABLE_NOT_CONVERTED" in codes(report)
    inside, dmz = p.rules
    # Its IPv6 traffic has a list (which is not converted); its IPv4 traffic still leaves by security level.
    assert (inside.name, inside.sources, inside.destinations) == ("implicit-inside", [ANY_V4], [ANY_V4])
    assert (dmz.name, dmz.sources) == ("implicit-dmz", [ANY])


def test_nat_without_interfaces_and_other_details() -> None:
    nat, _, _ = nat_of("nat source static SRV SRV-PUB")
    assert nat.src_zones == [ANY] and nat.dst_zones == [ANY] and not nat.unsupported
    nat, _, _ = nat_of("nat after-auto source dynamic any ONE")
    assert nat.name == "nat-after-auto-1" and nat.src_zones == [ANY]
    nat, _, _ = nat_of("nat (dmz,) source static SRV SRV-PUB")
    assert nat.unsupported
    # Port translation on an address that stays.
    nat, _, _ = nat_of("nat (outside,dmz) source static any any destination static SRV SRV service HTTP ALT")
    assert nat.destinations == ["SRV"] and nat.destination_translation == DestNat("SRV", "8080")


def test_icmp_inspection() -> None:
    body = "access-list I extended permit icmp any any echo\naccess-group I global\n"
    assert "ICMP_STATELESS" in codes(parse(HEAD + body)[1])
    inspected = "policy-map global_policy\n class inspection_default\n  inspect dns\n  inspect icmp\n"
    assert "ICMP_STATELESS" not in codes(parse(HEAD + inspected + body)[1])
    assert "ICMP_STATELESS" not in codes(parse(HEAD + body.replace("icmp any any echo", "tcp any any eq 80"))[1])


def test_interfaces_that_are_shut_down_or_bridged() -> None:
    body = "access-list O extended permit ip any 10.20.0.0 255.255.255.0\naccess-group O in interface outside\n"
    down = HEAD.replace(" nameif dmz\n", " shutdown\n nameif dmz\n")
    # Where its network leads while it is down is anybody's guess: no destination zone is worked out.
    assert parse(down + body)[0].rules[0].dst_zones == ["inside", "dmz"]
    assert parse(HEAD + body)[0].rules[0].dst_zones == ["dmz"]
    bridged = HEAD.replace(" nameif dmz\n", " nameif dmz\n bridge-group 1\n")
    p, report = parse(bridged + body)
    assert p.rules[0].dst_zones == ["inside", "dmz"] and "BRIDGE_GROUPS" in codes(report)


def test_policy_routing_and_the_guess_at_the_version() -> None:
    body = "access-list O extended permit ip any 198.51.100.0 255.255.255.0\naccess-group O in interface inside\n"
    assert parse(HEAD + body)[0].rules[0].dst_zones == ["outside"]  # the default route
    routed = HEAD.replace(" nameif inside\n", " nameif inside\n policy-route route-map PBR\n")
    assert parse(routed + body)[0].rules[0].dst_zones == ["outside", "dmz"]  # the routes shown are not all there is
    p, report = parse(HEAD.split("\n", 1)[1] + "ipv6 access-list SIX permit ip any any\naccess-list A extended permit ip any any\n")
    assert not p.lookup_after_dnat or "VERSION_ASSUMED" not in codes(report)


def test_zones_that_allow_traffic_inside_are_noted() -> None:
    p = _policy(Rule("r", src_zones=["inside"]))
    p.zones["inside"].intrazone_allow = True
    _, report, _ = _convert(p)
    assert "INTRAZONE_ALLOW" in codes(report)
    p.default_intrazone = Action.ALLOW
    _, report, _ = _convert(p)
    assert "INTRAZONE_DEFAULT" in codes(report)


# -- found in the second review of the ASA work -------------------------------------------------


def _reaches(config: AsaConfig, source: str, zone: str, dst: str, port: int = 443) -> bool:
    return config.allows(Packet(source, zone, "2001:db8:99::9" if ":" in dst else "192.0.2.9", dst, "tcp", 1024, port))


MIXED = (
    "object network DMZNET\n subnet 10.20.0.0 255.255.255.0\n nat (dmz,outside) static 198.51.100.0\n"
    "object-group network G\n network-object host 10.20.0.10\n network-object host 198.51.100.77\n"
    "access-list O extended permit tcp any object-group G eq 443\naccess-list O extended deny ip any any\n"
    "access-group O in interface outside\n"
)


def test_rule_that_names_both_sides_of_one_translation_is_reported() -> None:
    """The ASA read the list after NAT: the mapped address in the group was dead there. In the model it is not."""
    p, report = parse(HEAD + MIXED)
    finding = next(f for f in report.item("rule", "O-1").findings if f.code == "NAT_ADDRESS_EXPOSED")
    assert finding.severity == Severity.REVIEW and "198.51.100.77 of" in finding.message
    assert p.rules[0].nat_added == {"198.51.100.10": ["nat-DMZNET"]}
    for target in ("panos", "checkpoint"):
        out = copy.deepcopy(report)
        cli.convert(copy.deepcopy(p), target, out)
        assert out.item("rule", "O-1").status == "needs-review" and "NAT_ADDRESS_EXPOSED" in codes(out, "rule", "O-1"), target
    # A target that reads its rules as the ASA did gets the group as it was: dead there, dead here.
    for target in ("asa", "iptables", "fortios"):
        out = copy.deepcopy(report)
        text = cli.convert(copy.deepcopy(p), target, out)
        assert not [code for code in codes(out, "rule", "O-1") if code.startswith("NAT_")], target
        if target == "asa":
            config = AsaConfig(text)
            assert _reaches(config, "outside", "dmz", "10.20.0.10") and not _reaches(config, "outside", "dmz", "10.20.0.77")
            assert config.acls["outside_access_in"][0]["dst"] == ["10.20.0.10", "198.51.100.77"]
    # A rule for real addresses only goes to an ASA and back without a word.
    p, report = parse(HEAD + MIXED.replace(" network-object host 198.51.100.77\n", ""))
    text = cli.convert(p, "asa", report)
    assert not codes(report, "rule", "O-1") and not _reaches(AsaConfig(text), "outside", "dmz", "10.20.0.77")


def test_fortios_policy_that_names_a_host_and_the_external_network() -> None:
    conf = (
        'config system settings\n    set central-nat enable\nend\n'
        'config firewall address\n    edit "srv2"\n        set subnet 10.20.0.11 255.255.255.255\n    next\n'
        '    edit "pubnet"\n        set subnet 198.51.100.0 255.255.255.0\n    next\nend\n'
        'config firewall service custom\n    edit "HTTPS"\n        set tcp-portrange 443\n    next\nend\n'
        'config firewall vip\n    edit "vipnet"\n        set extip 198.51.100.1-198.51.100.254\n'
        '        set mappedip "10.20.0.1-10.20.0.254"\n        set extintf "wan"\n    next\nend\n'
        'config firewall policy\n    edit 1\n        set srcintf "wan"\n        set dstintf "dmz"\n        set action accept\n'
        '        set srcaddr "all"\n        set dstaddr "srv2" "pubnet"\n        set schedule "always"\n        set service "HTTPS"\n'
        "    next\nend\n"
    )
    report = Report()
    p = cli.load(conf.encode(), "fortios", report)
    # FortiOS matched the policy after the virtual IP: of the external network only .11 was ever let in.
    finding = next(f for f in report.item("rule", "policy-1").findings if f.code == "NAT_ADDRESS_EXPOSED")
    assert finding.severity == Severity.REVIEW and "198.51.100.1-198.51.100.10" in finding.message
    out = copy.deepcopy(report)
    cli.convert(copy.deepcopy(p), "panos", out)
    assert out.item("rule", "policy-1").status == "needs-review"
    # Back to FortiOS the policy is what it was.
    out = copy.deepcopy(report)
    text = cli.convert(copy.deepcopy(p), "fortios", out)
    assert 'set dstaddr "srv2" "pubnet"\n' in text and not [c for c in codes(out, "rule", "policy-1") if c.startswith("NAT_")]


def test_rule_of_a_pre_nat_source_that_names_more_of_the_real_side() -> None:
    p = _nat_policy(NatRule("static", ["dmz"], ["outside"], ["dmznet"],
                            source_translation=SourceNat(SnatKind.STATIC, ["pubnet"], bidirectional=True)))  # fmt: skip
    p.addresses["dmznet"] = Address("dmznet", AddressKind.NETWORK, "10.20.0.0/24")
    p.addresses["pubnet"] = Address("pubnet", AddressKind.NETWORK, "198.51.100.0/24")
    rule = Rule("mixed", src_zones=["outside"], dst_zones=["dmz"], destinations=["198.51.100.77", "10.20.0.64/26"], services=["https"])
    rule.origin = "mixed"
    p.rules.append(rule)
    # Before NAT the /26 was matched by traffic sent to it directly only; after NAT by all that is translated to it.
    for target in ("asa", "fortios", "iptables"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report)
        finding = next(f for f in report.item("rule", "mixed").findings if f.code == "NAT_ADDRESS_EXPOSED")
        assert finding.severity == Severity.REVIEW and "10.20.0.64-10.20.0.76, 10.20.0.78-10.20.0.127" in finding.message, target
    report = Report()
    cli.convert(copy.deepcopy(p), "panos", report)
    assert not [code for code in codes(report, "rule", "mixed") if code.startswith("NAT_")]
    # The services of the rule and of a port forwarding that do not meet expose nothing.
    q = _nat_policy(NatRule("forward", ["outside"], ["outside"], destinations=["pub"], service="https",
                            destination_translation=DestNat("web", "8443")))  # fmt: skip
    q.services["ssh"] = Service("ssh", [ServiceEntry(Protocol.TCP, "22")])
    q.rules.append(Rule("admin", src_zones=["outside"], dst_zones=["dmz"], destinations=["web"], services=["ssh"]))
    q.rules[0].origin = "admin"
    report = Report()
    cli.convert(q, "asa", report)
    assert not [code for code in codes(report, "rule", "admin") if code.startswith("NAT_")]


PUBLISHED = (
    "object network SRV\n host 10.20.0.10\n nat (dmz,outside) static 203.0.113.10 service tcp 8443 https\n"
    "access-list O extended permit tcp any any eq https\naccess-list O extended permit tcp any any eq 8443\n"
    "access-list O extended permit icmp any any echo\naccess-list O extended permit tcp any any eq 22\n"
    "access-list O extended permit ip any any\naccess-group O in interface outside\n"
)


def test_port_translation_is_looked_at_for_rules_to_any_destination() -> None:
    p, report = parse(HEAD + PUBLISHED)
    # Port 443 of the list is the real port: the published server listens on 8443 and was not let in by O-1.
    assert codes(report, "rule", "O-1") == ["NAT_PORT_EXPOSED"] and report.item("rule", "O-1").status == "needs-review"
    assert codes(report, "rule", "O-2") == ["NAT_PORT_TRANSLATION"]
    # ICMP has no ports, port 22 is not the one, and "ip" covers both ports.
    assert not codes(report, "rule", "O-3") and not codes(report, "rule", "O-4") and not codes(report, "rule", "O-5")
    out = copy.deepcopy(report)
    cli.convert(copy.deepcopy(p), "panos", out)
    assert "NAT_PORT_EXPOSED" in codes(out, "rule", "O-1") and "NAT_PORT_TRANSLATION" in codes(out, "rule", "O-2")
    # On a target that reads its rules as an ASA does, with the same NAT rule, nothing of it is true any more.
    for target in ("asa", "iptables"):
        out = copy.deepcopy(report)
        cli.convert(copy.deepcopy(p), target, out)
        assert not codes(out, "rule", "O-1") and not codes(out, "rule", "O-2"), target
    # Unless the target does not get that NAT rule.
    q = copy.deepcopy(p)
    q.nat_rules[0].unsupported.append("something the target cannot do")
    out = copy.deepcopy(report)
    cli.convert(q, "asa", out)
    assert out.item("nat", q.nat_rules[0].origin).skipped
    assert codes(out, "rule", "O-1") == ["NAT_PORT_EXPOSED"] and codes(out, "rule", "O-2") == ["NAT_PORT_TRANSLATION"]


def test_port_translation_towards_a_target_that_looks_up_after_nat_for_any_destination() -> None:
    p = _nat_policy(NatRule("forward", ["outside"], ["outside"], destinations=["pub"], service="https",
                            destination_translation=DestNat("web", "8443")))  # fmt: skip
    p.services["alt"] = Service("alt", [ServiceEntry(Protocol.TCP, "8443")])
    p.services["echo"] = Service("echo", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    for name, service in (("dead", "alt"), ("live", "https"), ("ping", "echo")):
        p.rules.append(Rule(name, src_zones=["outside"], dst_zones=["dmz"], services=[service]))
        p.rules[-1].origin = name
    for target in ("asa", "fortios", "iptables"):
        report = Report()
        cli.convert(copy.deepcopy(p), target, report)
        found = {name: [code for code in codes(report, "rule", name) if code.startswith("NAT_")] for name in ("dead", "live", "ping")}
        assert found == {"dead": ["NAT_PORT_EXPOSED"], "live": ["NAT_PORT_TRANSLATION"], "ping": []}, target


def test_static_nat_translated_to_any_is_skipped() -> None:
    p = _nat_policy(NatRule("s", ["inside"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.STATIC, [ANY], bidirectional=True)))
    lines, report, _ = _nat_lines(p)
    assert not lines and report.item("nat", "s").skipped


CONNECTED = {"outside": ["203.0.113.0/24"], "inside": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"]}
COMPLETE = {"outside": ["0.0.0.0/0", "::/0"], "inside": ["10.10.0.0/16", "2001:db8:10::/48"], "dmz": ["10.20.0.0/24", "2001:db8:20::/48"]}


def test_deny_rule_keeps_the_addresses_no_network_was_given_for() -> None:
    """Every zone has its connected network and nobody named the default route: what lies out there is not known."""
    deny = Rule("no-internet", src_zones=["inside"], dst_zones=["outside"], action=Action.DROP)
    config, report = _zone_rules(deny, Rule("rest", src_zones=["inside"]), networks=CONNECTED)
    assert not _reaches(config, "inside", "outside", "198.51.100.7") and not _reaches(config, "inside", "outside", "203.0.113.9")
    assert _reaches(config, "inside", "dmz", "10.20.0.5")
    finding = report.item("rule", "no-internet").findings[0]
    assert finding.code == "EGRESS_BY_NETWORKS" and finding.severity == Severity.APPROX and "are denied by it as well" in finding.message
    note = next(note for note in report.notes if note.code == "ZONE_NETWORK_GAP")
    assert "0.0.0.0-10.9.255.255" in note.message and "every IPv6 address" in note.message
    # A permit rule for the same zone stays out of them.
    allow = Rule("internet", src_zones=["inside"], dst_zones=["outside"])
    config, report = _zone_rules(allow, networks=CONNECTED)
    assert config.acls["inside_access_in"][0]["dst"] == ["203.0.113.0/255.255.255.0"]
    assert report.item("rule", "internet").status == "approximated"
    # A host out there that the rule names is denied as it was, and the report says what is not known about it.
    host = Rule("no-host", src_zones=["inside"], dst_zones=["outside"], destinations=["198.51.100.7"], action=Action.DROP)
    config, report = _zone_rules(host, Rule("rest", src_zones=["inside"]), networks=CONNECTED)
    assert not report.item("rule", "no-host").skipped and not _reaches(config, "inside", "outside", "198.51.100.7")
    assert codes(report, "rule", "no-host") == ["EGRESS_INTERFACE"]


def test_rule_to_every_other_zone_is_not_cut_down_to_the_networks() -> None:
    for deny in (Rule("lockdown", src_zones=["inside"], dst_zones=["outside", "dmz"], action=Action.DROP),
                 Rule("lockdown", src_zones=["inside"], scope=RuleScope.INTERZONE, action=Action.DROP)):  # fmt: skip
        config, report = _zone_rules(deny, Rule("rest", src_zones=["inside"]), networks=CONNECTED)
        assert not _reaches(config, "inside", "outside", "198.51.100.7") and not _reaches(config, "inside", "dmz", "10.20.0.5")
        # Only the zone's own network is left out, for an ASA that sends traffic back where it came from.
        assert config.acls["inside_access_in"][0]["dst"] == ["0.0.0.0-10.9.255.255", "10.11.0.0-255.255.255.255", "::/0"]
        assert not codes(report, "rule", "lockdown") and "ZONE_NETWORK_GAP" not in codes(report)


def test_network_for_everything_else_needs_the_networks_of_every_other_zone() -> None:
    allow = Rule("out", src_zones=["inside"], dst_zones=["outside"])
    for networks in ({"outside": ["0.0.0.0/0", "::/0"]}, {"outside": ["0.0.0.0/0", "::/0"], "inside": ["10.10.0.0/16"]}):
        config, report = _zone_rules(copy.deepcopy(allow), networks=networks)
        # Where the dmz lies nobody said: "everything else" would take it in.
        assert config.acls["inside_access_in"][0]["inactive"] and report.item("rule", "out").disabled
        note = next(note for note in report.notes if note.code == "ZONE_NETWORK_INCOMPLETE")
        assert note.severity == Severity.REVIEW and "dmz" in note.message
    config, report = _zone_rules(copy.deepcopy(allow), Rule("no", src_zones=["inside"], dst_zones=["dmz"], action=Action.DROP),
                                 networks=COMPLETE)  # fmt: skip
    assert report.item("rule", "out").status == "exact" and report.item("rule", "no").status == "exact"
    assert not {"ZONE_NETWORK_INCOMPLETE", "ZONE_NETWORK_GAP"} & set(codes(report))
    assert _reaches(config, "inside", "outside", "198.51.100.7") and _reaches(config, "inside", "outside", "2001:db8:99::7")
    assert not _reaches(config, "inside", "dmz", "10.20.0.5") and not _reaches(config, "inside", "dmz", "2001:db8:20::5")


def test_networks_of_one_ip_version_say_nothing_about_the_other() -> None:
    networks = {"inside": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"], "outside": ["0.0.0.0/0"]}
    config, report = _zone_rules(
        Rule("dmz-out", src_zones=["dmz"], dst_zones=["outside"]),
        Rule("no-out", src_zones=["inside"], dst_zones=["outside"], action=Action.DROP),
        Rule("rest", src_zones=["inside"]),
        networks=networks,
    )
    assert _reaches(config, "dmz", "outside", "198.51.100.7") and not _reaches(config, "dmz", "inside", "10.10.0.5")
    assert not _reaches(config, "dmz", "inside", "2001:db8:10::5") and not _reaches(config, "dmz", "outside", "2001:db8:99::7")
    assert not _reaches(config, "inside", "outside", "2001:db8:99::7") and not _reaches(config, "inside", "outside", "198.51.100.7")
    assert _reaches(config, "inside", "dmz", "10.20.0.5")
    note = next(note for note in report.notes if note.code == "ZONE_NETWORK_GAP")
    assert note.severity == Severity.APPROX and "every IPv6 address" in note.message


def test_rule_whose_destination_lies_behind_another_zone_by_the_networks() -> None:
    odd = Rule("odd", src_zones=["inside"], dst_zones=["outside"], destinations=["web"])
    config, report = _zone_rules(odd, networks=COMPLETE)
    item = report.item("rule", "odd")
    assert item.skipped and "inside_access_in" not in config.acls
    assert [(f.code, f.severity) for f in item.findings][-1] == ("EGRESS_NO_ADDRESS", Severity.APPROX)
    # Leaving out a deny rule is what a wrong network would do harm with.
    odd = Rule("odd", src_zones=["inside"], dst_zones=["outside"], destinations=["web"], action=Action.DROP)
    _, report = _zone_rules(odd, networks=COMPLETE)
    assert [(f.code, f.severity) for f in report.item("rule", "odd").findings][-1] == ("EGRESS_NO_ADDRESS", Severity.REVIEW)


def _without(networks: Dict[str, List[str]], rng: random.Random) -> Dict[str, List[str]]:
    """Networks as a person might give them: a zone forgotten, IPv6 forgotten, a default for the last zone."""
    out = {zone: list(nets) for zone, nets in networks.items()}
    how = rng.choice(["zone", "two zones", "ipv6", "ipv6 and zone", "default", "default and zone", "one network"])
    zones = sorted(out)
    rng.shuffle(zones)
    if "ipv6" in how:
        out = {zone: [n for n in nets if ":" not in n] for zone, nets in out.items()}
    if "default" in how:
        out[zones[2]] = ["0.0.0.0/0", "::/0"]
    if how == "one network":
        out[zones[1]] = out[zones[1]][1:]
    if "zone" in how:
        del out[zones[0]]
    if how == "two zones":
        del out[zones[1]]
    return out


@pytest.mark.parametrize("seed", range(80))
def test_incomplete_zone_networks_never_widen_without_a_word(seed: int) -> None:
    """Networks that are right as far as they go, but not all there is: a rule may lose traffic, never gain it."""
    rng = random.Random(3000 + seed)
    model = random_model(rng)
    networks = _without(ZONE_NETWORKS, rng)
    report = Report()
    config = AsaConfig(cli.convert(model, "asa", report, Options(zone_networks=networks)))
    expected = effective(model, report)
    flagged = {item.name for item in report.items.values() if "EGRESS_INTERFACE" in [f.code for f in item.findings]}
    for _ in range(400):
        pkt = emitter_packet(rng, ["eth0", "eth1", "eth2"])
        if pkt.in_if == pkt.out_if:
            continue
        entry = config.verdict(pkt)
        if entry is not None and entry["permit"] and not model_allows(expected, pkt):
            assert [name for name in flagged if _entry_of(config, name, entry)], (seed, networks, pkt, entry["line"])


def test_notes_about_loading_and_about_the_interfaces() -> None:
    p = _policy(Rule("r", src_zones=["inside"], dst_zones=["outside"]), zones=("inside", "outside"))
    _, report, _ = _convert(p, zone_networks={"dmz": ["10.20.0.0/24"]})
    load_note = next(note for note in report.notes if note.code == "ASA_LOAD")
    assert "end of section 1" in load_note.message and "in front of existing" not in load_note.message
    # A zone that only --zone-network names is taken to be an interface as well: the note lists it.
    interfaces = next(note for note in report.notes if note.code == "INTERFACES_REQUIRED")
    assert "inside, outside, dmz" in interfaces.message


def test_object_for_an_interface_address_stays_where_a_rule_needs_it() -> None:
    line = "object network SRV\n nat (dmz,outside) static interface service tcp 8080 www\n"
    body = "access-list O extended permit tcp any object SRV eq 8080\naccess-group O in interface outside\n"
    p, report = parse(HEAD + NAT_OBJECTS + line + body)
    assert "outside-interface" in p.rules[0].destinations
    assert "object network outside-interface" not in cli.convert(copy.deepcopy(p), "asa", copy.deepcopy(report))
    # Without the NAT rule on the target the rule keeps the address, and the object with it.
    p.nat_rules[0].unsupported.append("something the target cannot do")
    text = cli.convert(p, "asa", report)
    assert "object network outside-interface\n host 203.0.113.2\n" in text


def test_groups_nested_too_deep_are_named_as_that() -> None:
    lines = ["object-group protocol P0", " protocol-object tcp", "object-group icmp-type T0", " icmp-object echo"]
    for level in range(1, 70):
        lines += [f"object-group protocol P{level}", f" group-object P{level - 1}"]
        lines += [f"object-group icmp-type T{level}", f" group-object T{level - 1}"]
    body = "\n".join(lines) + (
        "\naccess-list I extended permit object-group P69 any any\n"
        "access-list I extended permit icmp any any object-group T69\naccess-group I in interface inside\n"
    )
    p, _ = parse(HEAD + body)
    assert "protocol groups nested more than 64 deep" in p.rules[0].unsupported[0]
    assert "ICMP type groups nested more than 64 deep" in p.rules[1].unsupported[0]


# -- found in the third review ------------------------------------------------------------------


def _two_addresses_for_one_server(first: str, second: str) -> Policy:
    nats = {
        "isp1": NatRule("isp1", ["outside"], ["outside"], destinations=["203.0.113.10"], destination_translation=DestNat("web")),
        "isp2": NatRule("isp2", ["outside"], ["outside"], destinations=["198.51.100.10"], destination_translation=DestNat("web")),
    }
    p = _nat_policy(nats[first], nats[second])
    p.rules.append(Rule("partners", src_zones=["outside"], dst_zones=["dmz"], destinations=["198.51.100.10"], services=["https"]))
    p.rules[0].origin = "partners"
    return p


@pytest.mark.parametrize("order", [("isp1", "isp2"), ("isp2", "isp1")])
def test_what_a_rule_exposes_does_not_depend_on_the_order_of_the_nat_rules(order: Tuple[str, str]) -> None:
    """One server behind two public addresses, a rule for one of them: after NAT it is a rule for the server."""
    for target in ("asa", "iptables", "fortios"):
        report = Report()
        cli.convert(_two_addresses_for_one_server(*order), target, report)
        finding = next(f for f in report.item("rule", "partners").findings if f.code == "NAT_ADDRESS_EXPOSED")
        assert finding.severity == Severity.REVIEW and "'isp1'" in finding.message and "203.0.113.10" in finding.message, target
    report = Report()
    cli.convert(_two_addresses_for_one_server(*order), "panos", report)
    assert report.item("rule", "partners").status == "exact"


TWO_PORTS = (
    "object network SRVA\n host 10.20.0.10\nobject network SRVB\n host 10.20.0.11\nobject network PUB\n host 203.0.113.10\n"
    "object service HTTP\n service tcp destination eq www\nobject service HTTPS\n service tcp destination eq https\n"
    "nat (outside,dmz) source static any any destination static PUB SRVA service HTTP HTTP\n"
    "nat (outside,dmz) source static any any destination static PUB SRVB service HTTPS HTTPS\n"
)


def test_one_public_address_for_two_servers_by_port() -> None:
    bound = "access-group O in interface outside\n"
    # A list for the second server: in the model it becomes a rule for the public address, which is the first server's too.
    p, report = parse(HEAD + TWO_PORTS + "access-list O extended permit tcp any object SRVB\n" + bound)
    assert p.rules[0].destinations == ["SRVB", "PUB"]
    finding = next(f for f in report.item("rule", "O-1").findings if f.code == "NAT_ADDRESS_EXPOSED")
    assert finding.severity == Severity.REVIEW and "'nat-1'" in finding.message
    # Kept to the port of its server, it exposes nothing.
    p, report = parse(HEAD + TWO_PORTS + "access-list O extended permit tcp any object SRVB eq https\n" + bound)
    assert codes(report, "rule", "O-1") == ["NAT_DESTINATION_REWRITTEN"]
    # A list for both servers is a rule for the public address, rightly.
    both = "object-group network BOTH\n network-object object SRVA\n network-object object SRVB\naccess-list O extended permit tcp any object-group BOTH\n"
    p, report = parse(HEAD + TWO_PORTS + both + bound)
    assert "NAT_ADDRESS_EXPOSED" not in codes(report, "rule", "O-1")
    # And back on an ASA each of the three is what it was, without a finding.
    for body in ("access-list O extended permit tcp any object SRVB\n", "access-list O extended permit tcp any object SRVB eq https\n", both):
        p, report = parse(HEAD + TWO_PORTS + body + bound)
        text = cli.convert(p, "asa", report)
        assert not codes(report, "rule", "O-1") and " PUB" not in text.split("access-list ", 1)[1].split("\nnat ")[0], body


def test_rule_of_a_pre_nat_source_goes_to_the_server_its_port_is_forwarded_to() -> None:
    p = _nat_policy(
        NatRule("web80", ["outside"], ["outside"], destinations=["pub"], service="http", destination_translation=DestNat("10.20.0.80")),
        NatRule("web443", ["outside"], ["outside"], destinations=["pub"], service="https", destination_translation=DestNat("web")),
    )
    p.services["http"] = Service("http", [ServiceEntry(Protocol.TCP, "80")])
    p.rules.append(Rule("secure", src_zones=["outside"], dst_zones=["dmz"], destinations=["pub"], services=["https"]))
    p.rules[0].origin = "secure"
    config, report, text = _convert(p)
    # Not to the server of port 80, which comes first.
    assert config.acls["outside_access_in"][0]["dst"] == ["10.20.0.10"]
    assert [f.message for f in report.item("rule", "secure").findings if f.code == "NAT_DESTINATION_REWRITTEN"][0].count("web443") == 1
    assert "NAT_ADDRESS_EXPOSED" not in codes(report, "rule", "secure")


def test_dead_rule_stays_dead_on_a_target_of_the_same_kind() -> None:
    """After DNAT nothing arrives for the public address: a rule for it, with the port of the server, matched nothing."""
    rules = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -i eth0 -d 198.51.100.10/32 -p tcp --dport 443 -j DNAT --to-destination 10.20.0.10:8443\nCOMMIT\n"
        "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -i eth0 -o eth2 -d 198.51.100.10/32 -p tcp --dport 8443 -j ACCEPT\nCOMMIT\n"
    )
    report = Report()
    p = cli.load(rules.encode(), "iptables", report)
    assert p.rules[0].destinations == ["198.51.100.10/32"] and not p.rules[0].nat_added
    text = cli.convert(copy.deepcopy(p), "iptables", copy.deepcopy(report))
    assert "-d 198.51.100.10/32 -p tcp -m tcp --dport 8443" in text and "-d 10.20.0.10" not in text.split("*filter")[1]
    config, out, _ = _convert(copy.deepcopy(p))
    assert config.acls["eth0_access_in"][0]["dst"] == ["198.51.100.10"]


def test_rule_for_one_address_of_a_dnat_range_comes_back_as_it_was() -> None:
    rules = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -d 203.0.113.10/32 -p tcp --dport 443 -j DNAT --to-destination 10.20.0.20-10.20.0.29\nCOMMIT\n"
        "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -d 10.20.0.21/32 -p tcp --dport 443 -j ACCEPT\nCOMMIT\n"
    )
    report = Report()
    p = cli.load(rules.encode(), "iptables", report)
    assert "NAT_DESTINATION_WIDENED" in codes(report, "rule", p.rules[0].origin)  # true of the model: PAN-OS gets the whole address
    text = cli.convert(p, "iptables", report)
    forward = [line for line in text.split("*filter")[1].splitlines() if line.startswith("-A FORWARD") and "ACCEPT" in line and "443" in line]
    assert len(forward) == 1 and "-d 10.20.0.21/32" in forward[0]
    assert not [code for code in codes(report, "rule", p.rules[0].origin) if code.startswith("NAT_")]


def test_negated_destination_that_names_part_of_a_translated_network() -> None:
    def policy(*negated: str, action: Action = Action.ALLOW) -> Policy:
        p = _nat_policy(NatRule("net", ["outside"], ["outside"], destinations=["198.51.100.0/24"],
                                destination_translation=DestNat("10.20.0.0/24")))  # fmt: skip
        p.rules.append(Rule("but", src_zones=["outside"], dst_zones=["dmz"], destinations=list(negated),
                            negate_destination=True, action=action))  # fmt: skip
        p.rules[0].origin = "but"
        return p

    def changes_meaning(report: Report) -> bool:
        return any("does not name the same on both sides" in finding.message for finding in report.item("rule", "but").findings)

    for target in ("iptables", "asa", "fortios"):
        # "Not the lower half of the public network": after NAT nothing has such an address, and the rule would match it all.
        for action in (Action.ALLOW, Action.DROP):
            for half in ("198.51.100.0/25", "10.20.0.0/25"):
                report = Report()
                cli.convert(policy(half, action=action), target, report)
                assert report.item("rule", "but").disabled and changes_meaning(report), (target, half)
        # The same half of both sides, or all of both, or none of either: the rule means the same after NAT.
        for same in (("198.51.100.0/25", "10.20.0.0/25"), ("198.51.100.0/24", "10.20.0.0/24"), ("192.0.2.0/24",)):
            report = Report()
            cli.convert(policy(*same), target, report)
            assert not changes_meaning(report), (target, same)
    report = Report()
    cli.convert(policy("198.51.100.0/25"), "panos", report)
    assert not report.item("rule", "but").disabled


def test_summary_network_for_the_own_zone_does_not_cut_a_rule_to_every_other_zone() -> None:
    """inside=10.0.0.0/8 and nothing for the dmz, which lies in it: nobody said the dmz is not behind inside."""
    for deny in (Rule("lockdown", src_zones=["inside"], dst_zones=["outside", "dmz"], action=Action.DROP),
                 Rule("lockdown", src_zones=["inside"], scope=RuleScope.INTERZONE, action=Action.DROP)):  # fmt: skip
        for networks in ({"inside": ["10.0.0.0/8"]}, {"inside": ["10.0.0.0/8"], "outside": ["0.0.0.0/0", "::/0"]}):
            config, report = _zone_rules(deny, Rule("rest", src_zones=["inside"]), networks=networks)
            assert config.acls["inside_access_in"][0]["dst"] == ["0.0.0.0/0", "::/0"]
            assert not _reaches(config, "inside", "dmz", "10.20.0.5")
    allow = Rule("out", src_zones=["inside"], dst_zones=["outside", "dmz"])
    config, _ = _zone_rules(allow, networks={"inside": ["10.0.0.0/8"]})
    assert _reaches(config, "inside", "dmz", "10.20.0.5")


def test_service_that_holds_both_ports_of_a_port_translation_needs_no_adjusting() -> None:
    wide = PUBLISHED.replace("permit tcp any any eq 22", "permit tcp any any range 1 65535")
    p, report = parse(HEAD + wide + "access-list O extended permit tcp any any\n")
    assert not codes(report, "rule", "O-4") and not codes(report, "rule", "O-6")
