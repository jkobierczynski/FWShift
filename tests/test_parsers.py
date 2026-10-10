# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pytest
from helpers import load

from fwshift.errors import ParseError
from fwshift.model import ANY, ANY_V4, Action, AddressKind, Protocol, RuleScope, SnatKind
from fwshift.netutil import netmask_to_cidr, normalize, overlaps, parse_literal
from fwshift.parsers import fortios, panos
from fwshift.report import Report

# -- netutil --------------------------------------------------------------


def test_parse_literal() -> None:
    assert parse_literal("10.0.0.1") == (4, 167772161, 167772161)
    assert parse_literal("10.0.0.0/24") == (4, 167772160, 167772415)
    assert parse_literal("10.0.0.5/24") == (4, 167772160, 167772415)  # PAN-OS style host-with-mask
    assert parse_literal("10.0.0.1-10.0.0.9") == (4, 167772161, 167772169)
    assert parse_literal("2001:db8::/32") is not None and parse_literal("2001:db8::/32")[0] == 6  # type: ignore[index]
    assert parse_literal("10.0.0.9-10.0.0.1") is None
    assert parse_literal("web-1") is None
    assert parse_literal("") is None


def test_netmask_and_sets() -> None:
    assert netmask_to_cidr("10.10.0.0", "255.254.0.0") == "10.10.0.0/15"
    assert netmask_to_cidr("10.0.0.0", "255.0.255.0") is None  # wildcard mask
    assert normalize([(4, 5, 9), (4, 1, 4), (6, 1, 2)]) == [(4, 1, 9), (6, 1, 2)]
    assert overlaps([(4, 1, 5)], [(4, 5, 9)]) and not overlaps([(4, 1, 5)], [(6, 1, 5)])


# -- FortiOS syntax -------------------------------------------------------


def test_split_line_quotes_and_escapes() -> None:
    assert fortios.split_line('set comment "say \\"hi\\" now" x') == ["set", "comment", 'say "hi" now', "x"]
    assert fortios.split_line('set member "a b" "c"') == ["set", "member", "a b", "c"]
    assert fortios.split_line('set alias ""') == ["set", "alias", ""]


def test_tree_multiline_value_and_reopened_table() -> None:
    tree = fortios.parse_tree(
        'config firewall address\n    edit "a"\n        set comment "line one\nline two"\n    next\nend\n'
        'config firewall address\n    edit "b"\n        set subnet 10.0.0.0 255.0.0.0\n    next\nend\n'
    )
    table = tree.children["firewall address"]
    assert list(table.entries) == ["a", "b"]
    assert table.entries["a"].get("comment") == "line one\nline two"
    assert table.entries["b"].list("subnet") == ["10.0.0.0", "255.0.0.0"]


VDOM_CONFIG = b"""
config vdom
edit root
next
edit branch
next
end
config global
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
end
config vdom
edit root
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "HTTPS"
    next
end
end
config vdom
edit branch
config firewall policy
    edit 7
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
end
"""


def test_vdom_selection() -> None:
    with pytest.raises(ParseError, match="branch, root"):
        fortios.parse(VDOM_CONFIG, Report())
    with pytest.raises(ParseError, match="not found"):
        fortios.parse(VDOM_CONFIG, Report(), vdom="nope")
    root = fortios.parse(VDOM_CONFIG, Report(), vdom="root")
    assert [r.name for r in root.rules] == ["policy-1"] and root.rules[0].action == Action.ALLOW
    branch = fortios.parse(VDOM_CONFIG, Report(), vdom="branch")
    assert branch.rules[0].action == Action.DROP  # no 'set action' means deny
    assert branch.rules[0].services == [ANY]


def test_fortios_rejects_non_config() -> None:
    with pytest.raises(ParseError):
        fortios.parse(b"hello world\n", Report())


# -- FortiOS sample -------------------------------------------------------


def test_fortios_objects() -> None:
    p, report = load("fortios_sample.conf")
    assert "all" not in p.addresses
    assert p.addresses["lan-net"].value == "10.10.0.0/15"
    assert p.addresses["lan-net"].description == 'Office "LAN" networks'
    assert p.addresses["admin-range"].kind == AddressKind.RANGE
    assert p.addresses["geo-blocked"].kind == AddressKind.UNSUPPORTED
    assert p.addresses["lan6-net"].value == "2001:db8:10::/48"
    assert p.addresses["vip-web"].value == "203.0.113.10/32"  # a VIP is known by its external address
    assert p.address_groups["internal-all"].members == ["lan-net", "dmz-servers"]
    dns = p.services["DNS"].entries
    assert [(e.protocol, e.dst_ports) for e in dns] == [(Protocol.TCP, "53"), (Protocol.UDP, "53")]
    assert p.services["app-ports"].entries[0].dst_ports == "8080,8443,9000-9010"
    high = p.services["syslog-from-high"].entries[0]
    assert (high.dst_ports, high.src_ports) == ("514", "1024-65535")
    assert p.services["PING"].entries[0].icmp_type == 8
    assert p.services["ALL_ICMP"].entries[0].icmp_type is None
    assert p.services["GRE"].entries[0].ip_protocol == 47
    assert p.zones["lan"].interfaces == ["internal1", "internal2"]
    assert p.zones["lan"].intrazone_allow is False
    assert report.item("address", "geo-blocked").status == "needs-review"


def test_fortios_rules() -> None:
    p, report = load("fortios_sample.conf")
    rules = {r.name: r for r in p.rules}
    assert list(rules)[:2] == ["LAN to Internet", "LAN basics"]
    first = rules["LAN to Internet"]
    assert (first.src_zones, first.dst_zones) == (["lan"], ["wan1"])
    assert first.destinations == [ANY]  # IPv4 'all' behind an IPv4-only source
    assert first.profiles == {"av-profile": "default", "ssl-ssh-profile": "certificate-inspection"}
    assert first.log_end is True
    # 'all' to 'all' is IPv4-only on FortiOS: one side keeps the IPv4 literal.
    assert rules["LAN basics"].sources == [ANY_V4] and rules["LAN basics"].destinations == [ANY]
    assert rules["LAN v6 out"].sources == ["lan6-net"] and rules["LAN v6 out"].destinations == [ANY]
    assert rules["Block geo"].action == Action.DROP and rules["Block geo"].services == [ANY]
    assert rules["Block geo"].src_zones == [ANY]
    assert rules["Admins to DMZ"].unsupported == ["groups netadmins"]
    assert rules["policy-12"].schedule == "office-hours"
    assert rules["Not web"].negate_service and not rules["Not web"].enabled
    assert rules["Inbound web"].destinations == ["vip-web"]
    assert report.item("rule", "Inbound web").status == "needs-review"  # port-forwarding VIP
    assert "fixedport" in report.item("rule", "Timestamp probes").findings[0].message


def test_fortios_nat_rules() -> None:
    p, _ = load("fortios_sample.conf")
    nat = {n.name: n for n in p.nat_rules}
    # destination NAT first, as a first-match rulebase needs it
    assert list(nat) == ["vip-web", "vip-mail", "snat-1", "snat-2", "snat-7"]
    web = nat["vip-web"]
    assert web.dst_zones == ["wan1"] and web.destinations == ["vip-web"]
    assert web.destination_translation is not None
    assert (web.destination_translation.address, web.destination_translation.port) == ("10.20.0.10", "8443")
    assert p.services[web.service].entries[0].dst_ports == "443"
    assert nat["vip-mail"].service == ANY and nat["vip-mail"].destination_translation.port == ""  # type: ignore[union-attr]
    out = nat["snat-1"].source_translation
    assert out is not None and out.kind == SnatKind.INTERFACE
    assert (out.interface, out.interface_address, out.addresses) == ("wan1", "198.51.100.1", [])
    assert nat["snat-2"].sources == [ANY]
    pool = nat["snat-7"].source_translation
    assert pool is not None and pool.kind == SnatKind.DYNAMIC_PORT and pool.addresses == ["dmz-pool"]
    assert p.addresses["dmz-pool"].value == "198.51.100.20-198.51.100.23"


CENTRAL_NAT = b"""
config system settings
    set central-nat enable
end
config firewall address
    edit "srv"
        set subnet 10.20.0.10 255.255.255.255
    next
    edit "lan"
        set subnet 10.10.0.0 255.255.0.0
    next
end
config firewall vip
    edit "vip-srv"
        set extip 203.0.113.10
        set mappedip "10.20.0.10"
        set extintf "any"
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set orig-addr "lan"
        set dst-addr "all"
    next
    edit 2
        set srcintf "lan"
        set dstintf "dmz"
        set orig-addr "lan"
        set dst-addr "all"
        set nat disable
    next
end
config firewall policy
    edit 1
        set name "in"
        set srcintf "wan"
        set dstintf "dmz"
        set action accept
        set srcaddr "all"
        set dstaddr "srv"
        set schedule "always"
        set service "HTTPS"
    next
end
"""


def test_fortios_central_nat_source() -> None:
    report = Report()
    p = fortios.parse(CENTRAL_NAT, report)
    # The policy names the mapped address; the pre-NAT address is added for pre-NAT platforms.
    assert p.rules[0].destinations == ["srv", "vip-srv"]
    assert report.item("rule", "in").status == "approximated"
    names = [n.name for n in p.nat_rules]
    assert names == ["vip-srv", "central-snat-1", "central-snat-2"]
    assert p.nat_rules[1].source_translation is not None
    assert p.nat_rules[2].source_translation is None  # 'set nat disable' is an exemption
    assert "HTTPS" in p.services and p.services["HTTPS"].builtin == "fortios"  # factory default assumed


# -- PAN-OS ---------------------------------------------------------------


def test_panos_objects() -> None:
    p, report = load("panos_sample.xml")
    assert p.scope == "vsys1" and p.default_intrazone == Action.ALLOW
    assert p.addresses["dns-1"].value == "192.0.2.53"  # from shared
    assert p.addresses["odd-hosts"].kind == AddressKind.UNSUPPORTED
    assert p.address_groups["tagged-servers"].dynamic_filter == "'servers'"
    assert p.address_groups["all-servers"].members == ["dmz-servers", "dns-servers"]
    assert p.services["udp-syslog-src"].entries[0].src_ports == "1024-65535"
    assert p.services["service-http"].builtin == "panos"  # predefined, referenced by a group
    assert p.services["service-http"].entries[0].dst_ports == "80,8080"
    assert p.zones["dmz"].interfaces == ["ethernet1/3"]
    assert report.item("address", "odd-hosts").status == "needs-review"


def test_panos_rules() -> None:
    p, _ = load("panos_sample.xml")
    rules = {r.name: r for r in p.rules}
    assert len(rules) == 14
    assert rules["Allow-Web-Out"].applications == ["web-browsing", "ssl"]  # application group expanded
    assert rules["Allow-Web-Out"].profiles == {"group": "default-profiles"}
    assert rules["Allow-DNS"].src_zones == ["trust", "dmz"]
    assert rules["Admin-SSH"].users == ["example\\netadmins"]
    assert rules["Block-Region"].action == Action.DROP
    assert rules["Block-Region"].destinations == ["KP", "198.51.100.200"]
    assert rules["Not-From-Guests"].negate_source
    assert rules["DMZ-Intrazone"].scope == RuleScope.INTRAZONE
    assert not rules["Old-Rule"].enabled
    assert rules["Inbound-Web"].log_start and rules["Inbound-Web"].log_end


def test_panos_nat_rules() -> None:
    p, _ = load("panos_sample.xml")
    nat = {n.name: n for n in p.nat_rules}
    assert nat["No-NAT-Partner"].source_translation is None and nat["No-NAT-Partner"].destination_translation is None
    dnat = nat["Inbound-Web-DNAT"].destination_translation
    assert dnat is not None and (dnat.address, dnat.port) == ("web-1", "8443")
    static = nat["Mail-Static"].source_translation
    assert static is not None and static.kind == SnatKind.STATIC and static.bidirectional
    assert nat["Outbound-PAT"].source_translation.interface == "ethernet1/1"  # type: ignore[union-attr]


def test_panos_refuses_doctype_and_garbage() -> None:
    with pytest.raises(ParseError, match="DOCTYPE"):
        panos.parse(b'<!DOCTYPE x [<!ENTITY a "b">]><config/>', Report())
    with pytest.raises(ParseError, match="well-formed"):
        panos.parse(b"<config><oops></config>", Report())
    with pytest.raises(ParseError, match="no <config>"):
        panos.parse(b"<response/>", Report())


PANORAMA = b"""<config>
  <shared>
    <address><entry name="shared-host"><ip-netmask>192.0.2.1</ip-netmask></entry></address>
    <pre-rulebase><security><rules>
      <entry name="shared-pre"><from><member>any</member></from><to><member>any</member></to>
        <source><member>shared-host</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service><action>deny</action></entry>
    </rules></security></pre-rulebase>
    <post-rulebase><security><rules>
      <entry name="shared-post"><from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service><action>deny</action></entry>
    </rules></security></post-rulebase>
  </shared>
  <devices><entry name="localhost.localdomain"><device-group>
    <entry name="Europe">
      <pre-rulebase><security><rules>
        <entry name="europe-pre"><from><member>any</member></from><to><member>any</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <application><member>dns</member></application><service><member>application-default</member></service><action>allow</action></entry>
      </rules></security></pre-rulebase>
    </entry>
    <entry name="Belgium">
      <address><entry name="shared-host"><ip-netmask>192.0.2.99</ip-netmask></entry></address>
      <pre-rulebase><security><rules>
        <entry name="belgium-pre"><from><member>any</member></from><to><member>any</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <application><member>ssl</member></application><service><member>application-default</member></service><action>allow</action>
          <target><devices><entry name="0123456789"/></devices></target></entry>
      </rules></security></pre-rulebase>
      <post-rulebase><security><rules>
        <entry name="belgium-post"><from><member>any</member></from><to><member>any</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <application><member>any</member></application><service><member>any</member></service><action>deny</action></entry>
      </rules></security></post-rulebase>
    </entry>
  </device-group></entry></devices>
  <readonly><devices><entry name="localhost.localdomain"><device-group>
    <entry name="Belgium"><parent-dg>Europe</parent-dg></entry>
  </device-group></entry></devices></readonly>
</config>"""


def test_panorama_hierarchy_and_rule_order() -> None:
    with pytest.raises(ParseError, match="Belgium, Europe"):
        panos.parse(PANORAMA, Report())
    report = Report()
    p = panos.parse(PANORAMA, report, device_group="Belgium")
    assert [r.name for r in p.rules] == ["shared-pre", "europe-pre", "belgium-pre", "belgium-post", "shared-post"]
    assert p.addresses["shared-host"].value == "192.0.2.99"  # the device group overrides shared
    assert report.item("rule", "belgium-pre").status == "needs-review"  # targeted to one device
    europe = panos.parse(PANORAMA, Report(), device_group="Europe")
    assert [r.name for r in europe.rules] == ["shared-pre", "europe-pre", "shared-post"]
