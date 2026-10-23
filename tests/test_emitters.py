# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import List

import pytest
from helpers import FortiConfig, PanConfig, load, run

from fwshift import cli, transform
from fwshift.emitters import fortios as emit_fortios
from fwshift.emitters import panos as emit_panos
from fwshift.errors import FwshiftError
from fwshift.model import ANY, APP_DEFAULT, Action, Address, AddressKind, Policy, Protocol, Rule, RuleScope, Service
from fwshift.model import ServiceEntry
from fwshift.names import FORTIOS, FORTIOS_POLICY, PANOS, clean, unique
from fwshift.options import Options
from fwshift.parsers import fortios as parse_fortios
from fwshift.report import Report


def codes(report: Report, kind: str, name: str) -> List[str]:
    return [f.code for f in report.item(kind, name).findings]


# -- names and shared passes ------------------------------------------------


def test_name_rules() -> None:
    assert clean("10.0.0.0/24", PANOS) == "10.0.0.0_24"
    assert clean("_srv", PANOS) == "x_srv"
    assert clean('a"b(c)', FORTIOS) == "a_b_c_"
    assert len(clean("x" * 80, FORTIOS_POLICY)) == 35
    taken = {"web"}
    assert unique("web", taken, PANOS) == "web_2" and unique("web", taken, PANOS) == "web_3"


def test_rename_keeps_existing_names_and_updates_references() -> None:
    p = Policy(vendor="fortios")
    p.addresses["a/b"] = Address("a/b", AddressKind.NETWORK, "10.0.0.0/24")
    p.addresses["a_b"] = Address("a_b", AddressKind.NETWORK, "10.0.1.0/24")
    p.rules.append(Rule(name="r", sources=["a/b", "a_b"], origin="r"))
    report = Report()
    transform.sanitize_names(p, PANOS, PANOS, report)
    assert list(p.addresses) == ["a_b_2", "a_b"]  # the object that was already valid keeps its name
    assert p.rules[0].sources == ["a_b_2", "a_b"]
    assert p.addresses["a_b_2"].value == "10.0.0.0/24"


def test_zone_pairs() -> None:
    universal = Rule(name="u", src_zones=["a", "b"], dst_zones=["a", "b"])
    assert transform.zone_pairs(universal) == [(["a", "b"], ["a", "b"])]
    intra = Rule(name="i", src_zones=["a", "b"], dst_zones=["a", "b"], scope=RuleScope.INTRAZONE)
    assert transform.zone_pairs(intra) == [(["a"], ["a"]), (["b"], ["b"])]
    inter = Rule(name="x", src_zones=["a", "b"], dst_zones=["a", "b", "c"], scope=RuleScope.INTERZONE)
    assert transform.zone_pairs(inter) == [(["a"], ["b", "c"]), (["b"], ["a", "c"])]
    assert transform.zone_pairs(Rule(name="n", scope=RuleScope.INTRAZONE)) is None


def test_prune_unused() -> None:
    p, _ = load("fortios_sample.conf")
    assert "ALL_ICMP" in p.services and "internal-all" in p.address_groups
    assert transform.prune_unused(p) > 0
    assert "ALL_ICMP" not in p.services and "internal-all" not in p.address_groups
    assert "web-1" in p.addresses  # reached through the group dmz-servers
    assert "HTTP" in p.services  # reached through the group Web Access


# -- PAN-OS -> FortiOS ------------------------------------------------------


def test_panos_to_fortios_applications_become_ports() -> None:
    text, report = run("panos_sample.xml", "fortios")
    cfg = FortiConfig(text)
    policies = cfg.policies()
    assert list(policies)[:3] == ["Allow-Web-Out", "Allow-DNS", "Inbound-Web"]  # order preserved
    web = policies["Allow-Web-Out"]
    assert web.list("service") == ["app-web-browsing", "app-ssl"]
    assert web.get("action") == "accept" and web.get("status") == ""
    assert web.get("comments") == 'Outbound web for the "office" LAN'
    services = cfg.table("firewall service custom")
    assert services["app-ssl"].list("tcp-portrange") == ["443"]
    assert services["app-dns"].list("udp-portrange") == ["53"]
    assert services["app-ping"].get("protocol") == "ICMP" and services["app-ping"].get("icmptype") == "8"
    assert services["service-http"].list("tcp-portrange") == ["80", "8080"]  # PAN-OS predefined service
    assert report.item("rule", "Allow-Web-Out").status == "approximated"
    ot = policies["Engineering to PLCs"]
    assert ot.list("service") == ["app-modbus", "app-siemens-s7"]
    assert services["app-modbus"].list("tcp-portrange") == ["502"]


def test_panos_to_fortios_never_widens_silently() -> None:
    text, report = run("panos_sample.xml", "fortios")
    policies = FortiConfig(text).policies()
    # user match, unknown application, region, dynamic group: emitted, but switched off
    for name in ("Admin-SSH", "Block-Torrents", "Block-Region", "Tagged-Servers-Updates"):
        assert policies[name].get("status") == "disable", name
        assert report.item("rule", name).disabled
        assert report.item("rule", name).status == "needs-review"
    assert "USER_MATCH" in codes(report, "rule", "Admin-SSH")
    assert "APP_UNKNOWN" in codes(report, "rule", "Block-Torrents")
    assert "NOT enforced" in report.item("rule", "Block-Torrents").findings[-1].message
    # rules that convert are not touched by that
    assert policies["Allow-DNS"].get("status") == ""
    # every rule of the source is present
    assert len(policies) == 14


def test_panos_to_fortios_objects_and_families() -> None:
    text, _ = run("panos_sample.xml", "fortios")
    cfg = FortiConfig(text)
    v4, v6 = cfg.table("firewall address"), cfg.table("firewall address6")
    assert v4["lan-net"].list("subnet") == ["10.10.0.0", "255.255.0.0"]
    assert v4["admin-range"].get("start-ip") == "10.10.5.10" and v4["admin-range"].get("type") == "iprange"
    assert v4["updates.example.com"].get("fqdn") == "updates.example.com"
    assert v6["lan6-net"].get("ip6") == "2001:db8:10::/48"
    assert v4["odd-hosts"].list("subnet") == ["0.0.0.0", "255.255.255.255"]  # placeholder
    assert v4["n-10.10.200.0_24"].list("subnet") == ["10.10.200.0", "255.255.255.0"]  # literal in a rule
    groups = cfg.table("firewall addrgrp")
    assert list(groups) == ["dns-servers", "dmz-servers", "all-servers"]  # nested groups after their members
    policies = cfg.policies()
    deny_all = policies["Block-OT-Outbound"]
    assert deny_all.list("srcaddr") == ["all"] and deny_all.list("srcaddr6") == ["all"]
    mixed = policies["App-Server-Ports"]  # IPv4 and IPv6 sources, IPv4 destination
    assert mixed.list("srcaddr") == ["lan-net"] and mixed.list("srcaddr6") == []
    negated = policies["Not-From-Guests"]
    assert negated.get("srcaddr-negate") == "enable" and negated.list("srcaddr") == ["n-10.10.200.0_24"]
    assert policies["DMZ-Intrazone"].list("srcintf") == ["dmz"] == policies["DMZ-Intrazone"].list("dstintf")


def test_panos_to_fortios_nat() -> None:
    text, report = run("panos_sample.xml", "fortios")
    cfg = FortiConfig(text)
    vip = cfg.table("firewall vip")["Inbound-Web-DNAT"]
    assert (vip.get("extip"), vip.get("mappedip")) == ("203.0.113.10", "10.20.0.10")
    assert (vip.get("portforward"), vip.get("extport"), vip.get("mappedport")) == ("enable", "443", "8443")
    reverse = cfg.table("firewall vip")["Mail-Static-in"]
    assert (reverse.get("extip"), reverse.get("mappedip")) == ("203.0.113.25", "10.20.0.25")
    pools = cfg.table("firewall ippool")
    assert pools["snat-pool"].get("type") == "overload" and pools["snat-pool"].get("endip") == "198.51.100.23"
    assert pools["mail-public"].get("type") == "one-to-one"
    assert text.count("set nat disable") == 1  # the no-NAT rule
    # Central NAT matches post-NAT addresses: the rules now name the internal servers.
    policies = cfg.policies()
    assert policies["Inbound-Web"].list("dstaddr") == ["web-1"]
    assert policies["Inbound-Mail"].list("dstaddr") == ["mail-1"]
    assert "NAT_DESTINATION_REWRITTEN" in codes(report, "rule", "Inbound-Web")
    # (and the port it is translated to: the FortiGate of the lab blocked the published server on the pre-NAT port)
    assert "NAT_PORT_REWRITTEN" in codes(report, "rule", "Inbound-Web") and policies["Inbound-Web"].list("service") == ["tcp-8443"]
    assert any(n.code == "CENTRAL_NAT" for n in report.notes)
    assert any(n.code == "INTRAZONE_DEFAULT" for n in report.notes)


def test_app_map_option_resolves_unknown_application() -> None:
    options = Options(app_ports={"bittorrent": ["tcp/6881-6889", "udp/6881-6889"]})
    text, report = run("panos_sample.xml", "fortios", options)
    cfg = FortiConfig(text)
    assert cfg.policies()["Block-Torrents"].get("status") == ""
    assert cfg.table("firewall service custom")["app-bittorrent"].list("udp-portrange") == ["6881-6889"]
    assert not report.item("rule", "Block-Torrents").disabled


def test_zone_and_interface_map_fortios_target() -> None:
    options = Options(zone_map={"untrust": "wan1"}, interface_map={"ethernet1/2": "port2"})
    text, report = run("panos_sample.xml", "fortios", options)
    cfg = FortiConfig(text)
    zones = cfg.table("system zone")
    assert "wan1" not in zones and "untrust" not in zones  # mapped onto an existing interface
    assert zones["trust"].list("interface") == ["port2"]
    assert cfg.policies()["Allow-Web-Out"].list("dstintf") == ["wan1"]
    note = next(n for n in report.notes if n.code == "ZONES_WITHOUT_INTERFACES")
    assert "dmz" in note.message and "trust," not in note.message


def test_fortios_target_options() -> None:
    text, _ = run("fortios_sample.conf", "fortios", Options(target_vdom="edge", policy_id_start=100))
    assert 'config vdom\nedit "edge"\n' in text and text.rstrip().endswith("end\nend")
    assert "    edit 100\n" in text and "    edit 113\n" in text


def test_fortios_to_fortios_keeps_ipv4_only_any() -> None:
    text, _ = run("fortios_sample.conf", "fortios")
    policies = FortiConfig(text).policies()
    basics = policies["LAN basics"]
    assert basics.list("srcaddr") == ["all"] and basics.list("srcaddr6") == []
    v6 = policies["LAN v6 out"]
    assert v6.list("srcaddr6") == ["lan6-net"] and v6.list("dstaddr6") == ["all"] and v6.list("srcaddr") == []
    assert policies["Not web"].get("service-negate") == "enable"
    assert policies["Partner tunnel"].list("service") == ["GRE", "syslog-from-high"]


def test_fortios_roundtrip_is_stable_without_nat() -> None:
    source = b"""
config firewall address
    edit "a"
        set subnet 10.1.0.0 255.255.0.0
    next
    edit "b"
        set type iprange
        set start-ip 10.2.0.1
        set end-ip 10.2.0.9
    next
end
config firewall addrgrp
    edit "g"
        set member "a" "b"
    next
end
config firewall service custom
    edit "svc"
        set tcp-portrange 80 443:1024-65535
        set udp-portrange 53
    next
    edit "echo"
        set protocol ICMP
        set icmptype 8
    next
end
config firewall policy
    edit 1
        set name "one"
        set srcintf "p1"
        set dstintf "p2"
        set action accept
        set srcaddr "g"
        set dstaddr "all"
        set schedule "always"
        set service "svc" "echo"
        set logtraffic all
    next
    edit 2
        set name "two"
        set srcintf "any"
        set dstintf "p2"
        set srcaddr "a"
        set dstaddr "b"
        set dstaddr-negate enable
        set schedule "always"
        set service "ALL"
        set status disable
    next
end
"""
    first = parse_fortios.parse(source, Report())
    # explicit ids: with the default 'edit 0' every policy would read back as entry 0
    emitted = cli.convert(first, "fortios", Report(), Options(policy_id_start=1))
    second = parse_fortios.parse(emitted.encode(), Report())
    assert second.to_dict() == first.to_dict()


# -- FortiOS -> PAN-OS ------------------------------------------------------


def test_fortios_to_panos_rules() -> None:
    text, report = run("fortios_sample.conf", "panos")
    cfg = PanConfig(text)
    assert all(line.startswith("set ") for line in cfg.lines)  # nothing but set commands
    names = cfg.names("security")
    assert names[:2] == ["LAN to Internet", "LAN basics"] and names[-1] == "fwshift-intrazone-deny"
    first = "LAN to Internet"
    assert cfg.get("security", first, "from") == ["lan"] and cfg.get("security", first, "to") == ["wan1"]
    assert cfg.get("security", first, "service") == ["Web Access", "DNS"]
    assert cfg.get("security", first, "application") == [ANY]
    assert cfg.get("security", first, "action") == ["allow"]
    # 'all' to 'all' stays IPv4-only
    assert cfg.get("security", "LAN basics", "source") == ["0.0.0.0/0"]
    assert cfg.get("security", "OT no internet", "action") == ["drop"]
    assert cfg.get("security", "Inbound web", "destination") == ["vip-web"]  # pre-NAT address, post-NAT zone
    assert cfg.get("security", "Inbound web", "to") == ["dmz"]
    for name in ("Admins to DMZ", "Block geo", "policy-12", "Not web"):
        assert cfg.get("security", name, "disabled") == ["yes"], name
        assert report.item("rule", name).disabled
    assert cfg.get("security", "SCADA to PLCs", "disabled") is None
    assert "SERVICE_NEGATE" in codes(report, "rule", "Not web")
    assert "SCHEDULE" in codes(report, "rule", "policy-12")


def test_fortios_to_panos_icmp_and_ip_services_become_applications() -> None:
    text, report = run("fortios_sample.conf", "panos")
    cfg = PanConfig(text)
    assert "PING" not in cfg.names("service") and "GRE" not in cfg.names("service")
    assert cfg.get("service-group", "basic-net", "members") == ["DNS"]  # the ICMP member moved to the rule
    assert cfg.get("security", "LAN basics", "service") == ["basic-net"]
    assert cfg.get("security", "LAN basics-apps", "application") == ["ping"]
    assert cfg.get("security", "LAN basics-apps", "service") == [APP_DEFAULT]
    assert cfg.get("security", "Partner tunnel-apps", "application") == ["gre"]
    assert cfg.get("security", "Timestamp probes", "application") == ["icmp"]
    assert "ICMP_TYPE" in codes(report, "rule", "Timestamp probes")
    assert report.item("rule", "LAN basics").emitted_as == ["LAN basics", "LAN basics-apps"]


def test_fortios_to_panos_services_split_by_protocol() -> None:
    text, _ = run("fortios_sample.conf", "panos")
    cfg = PanConfig(text)
    assert cfg.get("service", "DNS-tcp", "protocol", "tcp", "port") == ["53"]
    assert cfg.get("service", "DNS-udp", "protocol", "udp", "port") == ["53"]
    assert cfg.get("service-group", "DNS", "members") == ["DNS-tcp", "DNS-udp"]
    assert cfg.get("service", "app-ports", "protocol", "tcp", "port") == ["8080,8443,9000-9010"]
    assert cfg.get("service", "syslog-from-high", "protocol", "udp", "source-port") == ["1024-65535"]
    assert cfg.get("address", "10.99.0.0_16", "ip-netmask") == ["10.99.0.0/16"]  # renamed: '/' is not allowed
    assert cfg.get("security", "Partner tunnel", "destination") == ["10.99.0.0_16"]
    assert cfg.get("address", "geo-blocked", "ip-netmask") == ["0.0.0.0/32"]  # placeholder


def test_fortios_to_panos_nat() -> None:
    text, report = run("fortios_sample.conf", "panos")
    cfg = PanConfig(text)
    assert cfg.names("nat") == ["vip-web", "vip-mail", "snat-1", "snat-2", "snat-7"]
    assert cfg.get("nat", "vip-web", "to") == ["wan1"] and cfg.get("nat", "vip-web", "destination") == ["vip-web"]
    assert cfg.get("nat", "vip-web", "service") == ["vip-web-port"]
    assert cfg.get("nat", "vip-web", "destination-translation", "translated-address") == ["10.20.0.10"]
    assert cfg.get("nat", "vip-web", "destination-translation", "translated-port") == ["8443"]
    assert cfg.get("nat", "vip-mail", "destination-translation", "translated-port") is None
    dipp = ("source-translation", "dynamic-ip-and-port")
    assert cfg.get("nat", "snat-1", *dipp, "translated-address") == ["198.51.100.1"]
    assert "NAT_INTERFACE_ADDRESS" in codes(report, "nat", "snat-1")
    assert cfg.get("nat", "snat-7", *dipp, "translated-address") == ["dmz-pool"]
    assert cfg.get("address", "dmz-pool", "ip-range") == ["198.51.100.20-198.51.100.23"]


def test_interface_map_and_scope_panos_target() -> None:
    options = Options(
        zone_map={"wan1": "untrust"}, interface_map={"wan1": "ethernet1/1"}, target_scope="device-group:Branch DG"
    )
    text, report = run("fortios_sample.conf", "panos", options)
    cfg = PanConfig(text)
    assert all(line.startswith('set device-group "Branch DG" ') for line in cfg.lines)
    assert any(" pre-rulebase security rules " in line for line in cfg.lines)
    dipp = ("source-translation", "dynamic-ip-and-port")
    assert cfg.get("nat", "snat-1", *dipp, "interface-address", "interface") == ["ethernet1/1"]
    assert cfg.get("nat", "snat-1", "to") == ["untrust"]
    assert "NAT_INTERFACE_ADDRESS" not in codes(report, "nat", "snat-1")
    with pytest.raises(FwshiftError):
        run("fortios_sample.conf", "panos", Options(target_scope="nonsense"))


def test_intrazone_tail_respects_zones_that_allow() -> None:
    p, _ = load("fortios_sample.conf")
    p.zones["lan"].intrazone_allow = True
    cfg = PanConfig(emit_panos.emit(p, Report(), Options(zone_map={"lan": "trust"})))
    assert cfg.names("security")[-2:] == ["fwshift-intrazone-allow", "fwshift-intrazone-deny"]
    assert cfg.get("security", "fwshift-intrazone-allow", "from") == ["trust"]  # the zone map applies
    assert cfg.get("security", "fwshift-intrazone-allow", "to") == ["trust"]
    assert cfg.get("security", "fwshift-intrazone-allow", "rule-type") == ["intrazone"]
    assert cfg.get("security", "fwshift-intrazone-deny", "from") == ["any"]
    assert cfg.get("security", "fwshift-intrazone-deny", "rule-type") == ["intrazone"]


def test_panos_to_panos_is_faithful() -> None:
    text, report = run("panos_sample.xml", "panos")
    cfg = PanConfig(text)
    assert "fwshift-intrazone-deny" not in cfg.names("security")  # same default on both sides
    assert cfg.get("security", "Allow-Web-Out", "application") == ["web-browsing", "ssl"]
    assert cfg.get("security", "Allow-Web-Out", "service") == [APP_DEFAULT]
    assert cfg.get("security", "Allow-Web-Out", "profile-setting", "group") == ["default-profiles"]
    assert cfg.get("security", "Admin-SSH", "source-user") == ["example\\netadmins"]
    assert cfg.get("security", "Admin-SSH", "disabled") is None
    assert cfg.get("security", "DMZ-Intrazone", "rule-type") == ["intrazone"]
    assert cfg.get("security", "Not-From-Guests", "negate-source") == ["yes"]
    assert cfg.get("address-group", "tagged-servers", "dynamic", "filter") == ["'servers'"]
    assert cfg.get("address", "web-1", "tag") == ["servers"] and "servers" in cfg.names("tag")
    assert "service-http" not in cfg.names("service")  # predefined on the target
    nat = ("source-translation", "dynamic-ip-and-port", "interface-address", "interface")
    assert cfg.get("nat", "Outbound-PAT", *nat) == ["ethernet1/1"]
    assert cfg.get("nat", "Mail-Static", "source-translation", "static-ip", "bi-directional") == ["yes"]
    assert report.counts("rule")["exact"] == 12 and report.counts("rule")["disabled"] == 2


# -- constructed cases ------------------------------------------------------


def _policy(rule: Rule) -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW)
    p.addresses["srv"] = Address("srv", AddressKind.NETWORK, "10.0.0.1/32")
    p.services["tcp-8443"] = Service("tcp-8443", [ServiceEntry(Protocol.TCP, "8443")])
    rule.origin = rule.name
    p.rules.append(rule)
    return p


def test_any_application_on_default_ports_is_not_guessed() -> None:
    report = Report()
    text = emit_fortios.emit(_policy(Rule(name="r", services=[APP_DEFAULT])), report, Options())
    assert FortiConfig(text).policies()["r"].get("status") == "disable"
    assert "APP_DEFAULT_ANY" in codes(report, "rule", "r")


def test_application_filter_on_explicit_service() -> None:
    allow = Rule(name="r", applications=["ssl"], services=["tcp-8443"])
    report = Report()
    text = emit_fortios.emit(_policy(allow), report, Options())
    policy = FortiConfig(text).policies()["r"]
    assert policy.list("service") == ["tcp-8443"] and policy.get("status") == ""
    assert report.item("rule", "r").status == "approximated"
    deny = Rule(name="r", applications=["ssl"], services=["tcp-8443"], action=Action.DENY)
    report = Report()
    emit_fortios.emit(_policy(deny), report, Options())
    assert report.item("rule", "r").status == "needs-review"  # blocks more than the source did


def test_interzone_rule_is_split_per_zone() -> None:
    rule = Rule(name="r", src_zones=["a", "b"], dst_zones=["a", "b"], scope=RuleScope.INTERZONE)
    report = Report()
    text = emit_fortios.emit(_policy(rule), report, Options())
    policies = FortiConfig(text).policies()
    assert [(p.list("srcintf"), p.list("dstintf")) for p in policies.values()] == [(["a"], ["b"]), (["b"], ["a"])]
    assert report.item("rule", "r").emitted_as == ["r", "r_2"]


def test_rule_without_common_ip_version_is_skipped() -> None:
    p = _policy(Rule(name="r", sources=["2001:db8::/64"], destinations=["srv"]))
    report = Report()
    text = emit_fortios.emit(p, report, Options())
    assert "config firewall policy" not in text
    assert report.item("rule", "r").status == "skipped"


def test_undefined_reference_gets_placeholder_and_disables_rule() -> None:
    p = _policy(Rule(name="r", destinations=["missing-object"], services=["missing-service"]))
    report = Report()
    cfg = PanConfig(emit_panos.emit(p, report, Options()))
    assert cfg.get("address", "missing-object", "ip-netmask") == ["0.0.0.0/32"]
    assert cfg.get("security", "r", "disabled") == ["yes"]
    assert report.item("address", "missing-object").status == "needs-review"
    assert report.item("service", "missing-service").status == "needs-review"


def test_long_and_duplicate_policy_names_fortios() -> None:
    p = _policy(Rule(name="a-very-long-rule-name-that-exceeds-the-fortios-limit"))
    second = Rule(name="a-very-long-rule-name-that-exceeds-the-fortios-limit!", origin="second")
    p.rules.append(second)
    text = emit_fortios.emit(p, Report(), Options())
    names = list(FortiConfig(text).policies())
    assert len(names) == 2 and all(len(n) <= 35 for n in names) and names[0] != names[1]


def test_json_target_dumps_the_model() -> None:
    text, _ = run("panos_sample.xml", "json")
    assert '"vendor": "panos"' in text and '"Allow-Web-Out"' in text
    assert ANY in text
