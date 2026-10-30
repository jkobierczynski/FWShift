# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cases where a careless conversion would change what the firewall allows.

Each test is a small synthetic configuration built around one semantic trap.
"""

from __future__ import annotations

import io
import json
import sys
from typing import List, Tuple

import pytest
from helpers import DATA, FortiConfig, PanConfig

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import AddressKind
from fwshift.options import Options
from fwshift.parsers import fortios as parse_fortios
from fwshift.report import Report

# -- builders ---------------------------------------------------------------

FORTI_OBJECTS = """
config system interface
    edit "wan"
        set ip 198.51.100.1 255.255.255.0
    next
    edit "dmz"
        set ip 10.20.0.1 255.255.255.0
    next
end
config firewall address
    edit "all"
    next
    edit "lan-net"
        set subnet 10.10.0.0 255.255.0.0
    next
    edit "bad-hosts"
        set subnet 10.10.9.0 255.255.255.0
    next
    edit "srv"
        set subnet 10.20.0.10 255.255.255.255
    next
    edit "partner"
        set subnet 10.99.0.0 255.255.0.0
    next
    edit "wan-net"
        set subnet 203.0.113.0 255.255.255.0
    next
    edit "fq"
        set type fqdn
        set fqdn "updates.example.com"
    next
end
config firewall address6
    edit "all"
    next
    edit "lan6"
        set ip6 2001:db8:10::/48
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
    edit "GRE"
        set protocol IP
        set protocol-number 47
    next
    edit "ALL"
        set protocol IP
    next
end
"""


def forti(policies: str, extra: str = "") -> bytes:
    return (FORTI_OBJECTS + extra + "config firewall policy\n" + policies + "end\n").encode()


def policy(number: int, *lines: str, base: bool = True) -> str:
    default = ['set srcintf "lan"', 'set dstintf "wan"', 'set schedule "always"', 'set service "HTTPS"']
    body = (default if base else []) + list(lines)
    return f"    edit {number}\n" + "".join(f"        {line}\n" for line in body) + "    next\n"


def convert(data: bytes, target: str, options: Options | None = None) -> Tuple[str, Report]:
    report = Report()
    p = cli.load(data, cli.detect_format(data), report)
    return cli.convert(p, target, report, options), report


def codes(report: Report, kind: str, name: str) -> List[str]:
    return [f.code for f in report.item(kind, name).findings]


def pan_xml(rules: str = "", nat: str = "", addresses: str = "", services: str = "", extra: str = "") -> bytes:
    return f"""<config><devices><entry name="fw"><vsys><entry name="vsys1">
      <address>
        <entry name="mgmt"><ip-netmask>10.1.0.0/24</ip-netmask></entry>
        <entry name="srv"><ip-netmask>10.20.0.10/32</ip-netmask></entry>
        <entry name="srv-public"><ip-netmask>203.0.113.10/32</ip-netmask></entry>
        <entry name="dmz-net"><ip-netmask>10.20.0.0/24</ip-netmask></entry>
        <entry name="fq"><fqdn>updates.example.com</fqdn></entry>
        {addresses}
      </address>
      <service>{services}</service>
      {extra}
      <rulebase><security><rules>{rules}</rules></security><nat><rules>{nat}</rules></nat></rulebase>
    </entry></vsys></entry></devices></config>""".encode()


def pan_rule(name: str, source: str = "any", destination: str = "any", action: str = "allow", extra: str = "",
             src_zone: str = "trust", dst_zone: str = "untrust", app: str = "any", service: str = "any") -> str:
    def members(text: str) -> str:
        return "".join(f"<member>{m}</member>" for m in text.split(","))

    return f"""<entry name="{name}"><from>{members(src_zone)}</from><to>{members(dst_zone)}</to>
      <source>{members(source)}</source><destination>{members(destination)}</destination>
      <application>{members(app)}</application><service>{members(service)}</service>
      <action>{action}</action>{extra}</entry>"""


# -- negation and IP versions -------------------------------------------------


def test_fortios_negation_of_one_ip_version_only_disables_the_rule() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "bad-hosts"', "set srcaddr-negate enable",
                        'set dstaddr "all"', 'set srcaddr6 "lan6"', 'set dstaddr6 "all"'))
    for target in ("panos", "fortios"):
        text, report = convert(data, target)
        assert report.item("rule", "policy-1").disabled, target
        assert "negated for one IP version only" in report.item("rule", "policy-1").findings[0].message
    assert "srcaddr6-negate" not in convert(data, "fortios")[0]


def test_fortios_negated_ipv4_policy_stays_ipv4_only_on_panos() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "bad-hosts"', "set srcaddr-negate enable",
                        'set dstaddr "all"'))
    text, report = convert(data, "panos")
    cfg = PanConfig(text)
    assert cfg.get("security", "policy-1", "negate-source") == ["yes"]
    # PAN-OS negation covers IPv6 too: the other side has to keep the rule to IPv4.
    assert cfg.get("security", "policy-1", "destination") == ["0.0.0.0/0"]
    assert report.item("rule", "policy-1").status == "exact"


def test_fortios_both_sides_negated_cannot_be_kept_to_one_ip_version() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "bad-hosts"', "set srcaddr-negate enable",
                        'set dstaddr "srv"', "set dstaddr-negate enable"))
    text, report = convert(data, "panos")
    assert PanConfig(text).get("security", "policy-1", "disabled") == ["yes"]
    assert report.item("rule", "policy-1").status == "needs-review"


def test_fortios_consistent_negation_of_both_ip_versions_is_exact() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "bad-hosts"', "set srcaddr-negate enable",
                        'set dstaddr "all"', 'set srcaddr6 "lan6"', "set srcaddr6-negate enable", 'set dstaddr6 "all"'))
    text, report = convert(data, "panos")
    cfg = PanConfig(text)
    assert cfg.get("security", "policy-1", "source") == ["bad-hosts", "lan6"]
    assert cfg.get("security", "policy-1", "negate-source") == ["yes"]
    assert cfg.get("security", "policy-1", "destination") == ["any"]
    assert report.item("rule", "policy-1").status == "exact"


def test_panos_negated_ipv4_list_keeps_matching_all_ipv6_on_fortios() -> None:
    data = pan_xml(pan_rule("r1", source="mgmt", action="deny", extra="<negate-source>yes</negate-source>")
                   + pan_rule("r2"))
    text, report = convert(data, "fortios")
    r1 = FortiConfig(text).policies()["r1"]
    assert r1.list("srcaddr") == ["mgmt"] and r1.get("srcaddr-negate") == "enable"
    # "not mgmt" includes every IPv6 source: the IPv6 half must be there, and not negated.
    assert r1.list("srcaddr6") == ["all"] and r1.list("dstaddr6") == ["all"]
    assert r1.get("srcaddr6-negate") == ""
    assert report.item("rule", "r1").status == "exact"


def test_panos_negated_destination_and_ipv6_only_list_on_fortios() -> None:
    data = pan_xml(
        pan_rule("d", destination="srv", extra="<negate-destination>yes</negate-destination>")
        + pan_rule("v6", source="lan6", extra="<negate-source>yes</negate-source>"),
        addresses='<entry name="lan6"><ip-netmask>2001:db8:10::/48</ip-netmask></entry>',
    )
    policies = FortiConfig(convert(data, "fortios")[0]).policies()
    d = policies["d"]
    assert d.list("dstaddr") == ["srv"] and d.get("dstaddr-negate") == "enable"
    assert d.list("dstaddr6") == ["all"] and d.get("dstaddr6-negate") == ""
    v6 = policies["v6"]
    assert v6.list("srcaddr") == ["all"] and v6.get("srcaddr-negate") == ""
    assert v6.list("srcaddr6") == ["lan6"] and v6.get("srcaddr6-negate") == "enable"


def test_fortios_all_with_fqdn_stays_ipv4_on_panos() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "fq"'))
    cfg = PanConfig(convert(data, "panos")[0])
    # A PAN-OS FQDN object also resolves AAAA records; 'any' as source would let IPv6 in.
    assert cfg.get("security", "policy-1", "source") == ["0.0.0.0/0"]
    assert cfg.get("security", "policy-1", "destination") == ["fq"]


def test_fqdn_is_written_for_both_ip_versions_only_when_the_source_meant_both() -> None:
    from_pan = FortiConfig(convert(pan_xml(pan_rule("r", destination="fq")), "fortios")[0])
    assert from_pan.table("firewall address")["fq"].get("type") == "fqdn"
    assert from_pan.table("firewall address6")["fq"].get("fqdn") == "updates.example.com"
    assert from_pan.policies()["r"].list("dstaddr6") == ["fq"]
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "fq"'))
    from_forti = FortiConfig(convert(data, "fortios")[0])
    assert "fq" not in from_forti.table("firewall address6")
    assert from_forti.policies()["policy-1"].list("dstaddr6") == []


# -- reserved and predefined names --------------------------------------------


def test_fortios_objects_named_any_are_not_the_wildcard() -> None:
    extra = """
config firewall address
    edit "any"
        set subnet 10.99.0.0 255.255.0.0
    next
end
config firewall service custom
    edit "any"
        set tcp-portrange 443
    next
end
"""
    data = forti(policy(1, "set action accept", 'set srcaddr "any"', 'set dstaddr "all"', 'set service "any"')
                 + policy(2, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"'), extra)
    text, _ = convert(data, "panos")
    cfg = PanConfig(text)
    assert cfg.get("address", "any-object", "ip-netmask") == ["10.99.0.0/16"]
    assert cfg.get("security", "policy-1", "source") == ["any-object"]
    assert cfg.get("security", "policy-1", "service") == ["any-object"]
    forti_cfg = FortiConfig(convert(data, "fortios")[0])
    assert forti_cfg.policies()["policy-1"].list("srcaddr") == ["any-object"]
    assert forti_cfg.policies()["policy-1"].list("service") == ["any-object"]


def test_panos_objects_named_like_fortios_builtins_are_renamed() -> None:
    data = pan_xml(
        pan_rule("r1", source="all", service="ALL") + pan_rule("r2", source="all,mgmt", service="HTTP") + pan_rule("r3"),
        addresses='<entry name="all"><ip-netmask>10.99.0.0/16</ip-netmask></entry>',
        services='<entry name="ALL"><protocol><tcp><port>443</port></tcp></protocol></entry>'
        '<entry name="HTTP"><protocol><tcp><port>8080</port></tcp></protocol></entry>',
    )
    text, report = convert(data, "fortios")
    cfg = FortiConfig(text)
    assert "all" not in cfg.table("firewall address") and "ALL" not in cfg.table("firewall service custom")
    assert cfg.table("firewall address")["all_2"].list("subnet") == ["10.99.0.0", "255.255.0.0"]
    assert cfg.table("firewall service custom")["HTTP_2"].list("tcp-portrange") == ["8080"]
    policies = cfg.policies()
    assert policies["r1"].list("srcaddr") == ["all_2"] and policies["r1"].list("service") == ["ALL_2"]
    assert policies["r2"].list("srcaddr") == ["all_2", "mgmt"]
    assert policies["r3"].list("srcaddr") == ["all"] and policies["r3"].list("service") == ["ALL"]
    assert report.item("address", "all").emitted_as == ["all_2"]


# -- FortiOS policy attributes ------------------------------------------------


@pytest.mark.parametrize("line", [
    "set tos 0x10", "set reputation-minimum 3", "set sgt-check enable", "set policy-expiry enable",
    'set devices "windows-pc"', 'set vlan-filter "100-200"', "set ntlm enable", "set fsso enable",
    'set ztna-ems-tag-secondary "t"', 'set internet-service-src-custom "x"', 'set network-service-dynamic "ns"',
    'set groups "staff"', 'set application 15832',
])
def test_fortios_attribute_that_narrows_the_match_disables_the_rule(line: str) -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', line))
    text, report = convert(data, "panos")
    assert PanConfig(text).get("security", "policy-1", "disabled") == ["yes"], line
    assert report.item("rule", "policy-1").status == "needs-review"


def test_fortios_unknown_attribute_is_flagged_and_switched_off_ones_are_not() -> None:
    data = forti(
        policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', "set some-future-match enable")
        + policy(2, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', "set some-future-match disable",
                 "set fsso disable", "set tos 0x00", "set auto-asic-offload disable")
    )
    text, report = convert(data, "panos")
    assert codes(report, "rule", "policy-1") == ["UNKNOWN_ATTRIBUTES"]
    assert report.item("rule", "policy-1").status == "needs-review"
    assert PanConfig(text).get("security", "policy-1", "disabled") is None  # reported, still enabled
    assert report.item("rule", "policy-2").status == "exact"


def test_fortios_policy_missing_mandatory_fields_is_not_read_as_any() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', base=False))
    text, report = convert(data, "panos")
    assert PanConfig(text).get("security", "policy-1", "disabled") == ["yes"]
    messages = " ".join(f.message for f in report.item("rule", "policy-1").findings)
    assert "without srcintf" in messages and "without dstintf" in messages and "without a service" in messages


def test_fortios_service_limited_to_an_address_disables_the_rules_using_it() -> None:
    extra = 'config firewall service custom\n    edit "to-srv"\n        set iprange 10.20.0.10\n' \
            '        set tcp-portrange 443\n    next\nend\n'
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set service "to-srv"'), extra)
    text, report = convert(data, "panos")
    assert PanConfig(text).get("security", "policy-1", "disabled") == ["yes"]
    assert "UNCONVERTIBLE_OBJECT" in codes(report, "rule", "policy-1")


def test_fortios_unconverted_policy_tables_are_reported() -> None:
    extra = 'config firewall policy6\n    edit 1\n        set action accept\n    next\nend\n' \
            'config firewall local-in-policy\n    edit 1\n        set action deny\n    next\nend\n'
    _, report = convert(forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"'), extra), "panos")
    tables = [n.message for n in report.notes if n.code == "TABLE_NOT_CONVERTED"]
    assert len(tables) == 2 and "firewall policy6" in tables[0]
    assert report.needs_review


# -- quoting, malformed values, encodings -------------------------------------


def test_unbalanced_quote_is_noticed() -> None:
    bad = forti(
        policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set comments "5" rack"')
        + policy(2, 'set srcaddr "all"', 'set dstaddr "all"')
        + policy(3, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set comments "the 19" one"')
    )
    _, report = convert(bad, "panos")
    assert any(n.code == "SUSPICIOUS_QUOTING" for n in report.notes) and report.needs_review
    with pytest.raises(ParseError, match="unterminated quoted string starting on line"):
        parse_fortios.parse(forti(policy(1, 'set comments "never closed')), Report())


def test_legitimate_multiline_value_gives_no_warning() -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"',
                        'set comments "first line\nsecond line"'))
    _, report = convert(data, "panos")
    assert not any(n.code == "SUSPICIOUS_QUOTING" for n in report.notes)


@pytest.mark.parametrize("target", ["panos", "fortios"])
def test_address_values_of_the_wrong_shape_do_not_crash(target: str) -> None:
    extra = """
config firewall address
    edit "odd-subnet"
        set subnet 10.0.0.1-10.0.0.9
    next
    edit "odd-range"
        set type iprange
        set start-ip 10.0.0.9
        set end-ip banana
    next
end
config firewall vip
    edit "odd-vip"
        set extip 203.0.113.1/32
        set mappedip "10.20.0.10"
        set extintf "wan"
    next
    edit "bad-vip"
        set extip nonsense
        set mappedip "10.20.0.11"
    next
end
"""
    data = forti(policy(1, "set action accept", 'set srcaddr "odd-subnet" "odd-range"', 'set dstaddr "odd-vip"')
                 + policy(2, "set action accept", 'set srcaddr "all"', 'set dstaddr "bad-vip"'), extra)
    report = Report()
    p = cli.load(data, "fortios", report)
    assert p.addresses["odd-subnet"].kind == AddressKind.UNSUPPORTED
    assert p.addresses["odd-range"].kind == AddressKind.UNSUPPORTED
    assert p.addresses["odd-vip"].value == "203.0.113.1/32"  # a /32 written with its mask is still one address
    assert p.addresses["bad-vip"].kind == AddressKind.UNSUPPORTED
    cli.convert(p, target, report)
    assert report.item("rule", "policy-1").disabled and report.item("rule", "policy-2").disabled


def test_panos_address_with_a_range_in_ip_netmask() -> None:
    data = pan_xml(pan_rule("r", source="weird"),
                   addresses='<entry name="weird"><ip-netmask>10.0.0.1-10.0.0.5</ip-netmask></entry>')
    for target in ("panos", "fortios"):
        _, report = convert(data, target)
        assert report.item("rule", "r").disabled
        assert report.item("address", "weird").status == "needs-review"


def test_unknown_xml_encoding_is_a_clean_error(capsys: pytest.CaptureFixture[str], tmp_path: object) -> None:
    with pytest.raises(ParseError, match="not well-formed"):
        cli.load(b'<?xml version="1.0" encoding="foo"?><config/>', "panos", Report())


def test_output_is_utf8_whatever_the_console_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    source = (DATA / "fortios_sample.conf").read_text(encoding="utf-8").replace("Engineering access", "Engineering → access")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(source.encode("utf-8")), encoding="utf-8"))
    assert cli.main(["convert", "-", "--to", "panos", "-q"]) == 0
    assert "Engineering → access" in raw.getvalue().decode("utf-8")


def test_app_map_values_are_validated() -> None:
    from fwshift.appmap import parse_spec

    for spec in ("tcp/abc,-5", "ip/any", "tcp/70000", "tcp/90-80", "icmp/x", "gre/1"):
        with pytest.raises(FwshiftError):
            parse_spec(spec)


# -- intrazone default --------------------------------------------------------


def test_intrazone_tail_covers_zones_no_rule_names() -> None:
    extra = """
config system zone
    edit "servers"
        set interface "port5" "port6"
        set intrazone allow
    next
    edit "guests"
        set interface "port7" "port8"
    next
end
"""
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set srcintf "any"'), extra)
    text, report = convert(data, "panos")
    cfg = PanConfig(text)
    assert cfg.names("security")[-2:] == ["fwshift-intrazone-allow", "fwshift-intrazone-deny"]
    assert cfg.get("security", "fwshift-intrazone-allow", "from") == ["servers"]
    assert cfg.get("security", "fwshift-intrazone-allow", "action") == ["allow"]
    # The deny applies to every zone, 'guests' included although no rule names it.
    assert cfg.get("security", "fwshift-intrazone-deny", "from") == ["any"]
    assert "servers" in next(n.message for n in report.notes if n.code == "ZONES_REQUIRED")


# -- NAT ----------------------------------------------------------------------

DNAT = """<entry name="web-dnat"><from><member>untrust</member></from><to><member>untrust</member></to>
  <source><member>any</member></source><destination><member>srv-public</member></destination><service>any</service>
  <destination-translation><translated-address>srv</translated-address></destination-translation></entry>"""


def test_rule_on_the_internal_address_is_reported_under_central_nat() -> None:
    data = pan_xml(
        pan_rule("public", src_zone="untrust", dst_zone="dmz", destination="srv-public", service="service-https")
        + pan_rule("internal", src_zone="any", dst_zone="dmz", destination="dmz-net")
        + pan_rule("from-lan", src_zone="trust", dst_zone="dmz", destination="dmz-net"),
        nat=DNAT,
    )
    text, report = convert(data, "fortios")
    policies = FortiConfig(text).policies()
    assert policies["public"].list("dstaddr") == ["srv"]  # rewritten to the post-NAT address
    # 'internal' did not match traffic sent to the public address on PAN-OS; it does after translation.
    assert "NAT_ADDRESS_EXPOSED" in codes(report, "rule", "internal")
    assert report.item("rule", "internal").status == "needs-review"
    assert report.item("rule", "from-lan").status == "exact"  # the translation only applies from untrust


def test_negated_destination_next_to_destination_nat() -> None:
    data = pan_xml(
        pan_rule("neg", src_zone="untrust", dst_zone="dmz", destination="srv-public",
                 extra="<negate-destination>yes</negate-destination>"),
        nat=DNAT,
    )
    text, report = convert(data, "fortios")
    assert FortiConfig(text).policies()["neg"].get("status") == "disable"
    assert "negated destination" in report.item("rule", "neg").findings[0].message


def test_bidirectional_static_nat_alone_rewrites_the_inbound_rule() -> None:
    nat = """<entry name="mail-static"><from><member>dmz</member></from><to><member>untrust</member></to>
      <source><member>srv</member></source><destination><member>any</member></destination><service>any</service>
      <source-translation><static-ip><translated-address>srv-public</translated-address>
      <bi-directional>yes</bi-directional></static-ip></source-translation></entry>"""
    data = pan_xml(pan_rule("in", src_zone="untrust", dst_zone="dmz", destination="srv-public"), nat=nat)
    text, report = convert(data, "fortios")
    cfg = FortiConfig(text)
    assert cfg.table("firewall vip")["mail-static-in"].get("mappedip") == "10.20.0.10"
    assert cfg.policies()["in"].list("dstaddr") == ["srv"]
    assert "NAT_DESTINATION_REWRITTEN" in codes(report, "rule", "in")


def test_nat_rule_that_cannot_be_written_leaves_no_trace() -> None:
    nat = """<entry name="both"><from><member>untrust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>srv-public</member></destination><service>any</service>
      <source-translation><dynamic-ip-and-port><translated-address><member>fq</member></translated-address>
      </dynamic-ip-and-port></source-translation>
      <destination-translation><translated-address>srv</translated-address></destination-translation></entry>"""
    data = pan_xml(pan_rule("in", src_zone="untrust", dst_zone="dmz", destination="srv-public"), nat=nat)
    text, report = convert(data, "fortios")
    assert report.item("nat", "both").status == "skipped"
    assert "config firewall vip" not in text and "central-snat-map" not in text
    assert FortiConfig(text).policies()["in"].list("dstaddr") == ["srv-public"]  # not rewritten either


def test_static_nat_of_a_subnet_is_reported() -> None:
    nat = """<entry name="net-static"><from><member>dmz</member></from><to><member>untrust</member></to>
      <source><member>dmz-net</member></source><destination><member>any</member></destination><service>any</service>
      <source-translation><static-ip><translated-address>203.0.113.0/24</translated-address></static-ip>
      </source-translation></entry>"""
    _, report = convert(pan_xml(pan_rule("r"), nat=nat), "fortios")
    assert "NAT_STATIC_RANGE" in codes(report, "nat", "net-static")


VIP = """
config firewall vip
    edit "vip-srv"
        set extip 203.0.113.10
        set mappedip "10.20.0.10"
        set extintf "wan"
    next
end
"""


def test_fortios_policy_covering_a_vip_address_without_naming_the_vip() -> None:
    def inbound(number: int, *lines: str) -> str:
        return policy(number, 'set srcintf "wan"', 'set dstintf "dmz"', 'set schedule "always"', 'set service "HTTPS"',
                      'set srcaddr "all"', *lines, base=False)

    data = forti(
        inbound(1, "set action accept", 'set dstaddr "vip-srv"')
        + inbound(2, "set action accept", 'set dstaddr "wan-net"')
        + inbound(3, "set action accept", 'set dstaddr "srv"')
        + inbound(4, 'set dstaddr "all"')
        + inbound(5, 'set dstaddr "all"', "set match-vip enable"),
        VIP,
    )
    text, report = convert(data, "panos")
    cfg = PanConfig(text)
    assert report.item("rule", "policy-1").status == "exact"  # names the VIP
    # 2 covers the external address only: FortiOS did not apply it to the VIP traffic, PAN-OS would.
    assert codes(report, "rule", "policy-2") == ["NAT_ADDRESS_EXPOSED"]
    # 3 names the mapped address, which FortiOS matches after translation: the external address is added.
    assert cfg.get("security", "policy-3", "destination") == ["srv", "vip-srv"]
    assert codes(report, "rule", "policy-3") == ["NAT_DESTINATION_REWRITTEN"]
    # A deny on 'all' passes VIP traffic on FortiOS unless match-vip is on.
    assert codes(report, "rule", "policy-4") == ["DENY_AND_VIP"]
    assert report.item("rule", "policy-5").status == "exact"
    assert cfg.get("nat", "vip-srv", "from") == ["wan"] and cfg.get("nat", "vip-srv", "to") == ["wan"]


def test_fortios_policy_without_nat_in_front_of_one_with_nat() -> None:
    data = forti(
        policy(1, "set action accept", 'set srcaddr "lan-net"', 'set dstaddr "partner"', 'set service "GRE"')
        + policy(2, "set action accept", 'set srcaddr "lan-net"', 'set dstaddr "all"', "set nat enable")
    )
    text, report = convert(data, "panos")
    cfg = PanConfig(text)
    # NAT rules do not match on service: without a no-NAT rule, partner traffic would be translated.
    assert cfg.names("nat") == ["nonat-1", "snat-2"]
    assert cfg.get("nat", "nonat-1", "destination") == ["partner"]
    assert cfg.get("nat", "nonat-1", "source-translation", "dynamic-ip-and-port", "translated-address") is None
    assert codes(report, "nat", "nonat-1") == ["NAT_EXEMPTION"]
    assert "set nat disable" in convert(data, "fortios")[0]


def test_fortios_policy_without_nat_that_addresses_cannot_tell_apart() -> None:
    data = forti(
        policy(1, "set action accept", 'set srcaddr "lan-net"', 'set dstaddr "all"', "set nat enable")
        + policy(2, "set action accept", 'set srcaddr "lan-net"', 'set dstaddr "partner"', 'set service "GRE"')
    )
    text, report = convert(data, "panos")
    assert PanConfig(text).names("nat") == ["snat-1"]
    assert "NAT_OVERLAP" in codes(report, "nat", "snat-1")
    assert report.item("nat", "snat-1").status == "needs-review"
    # With service ALL on the NAT policy, everything hits it first on FortiOS too: nothing to report.
    data = forti(
        policy(1, "set action accept", 'set srcaddr "lan-net"', 'set dstaddr "all"', "set nat enable", 'set service "ALL"')
        + policy(2, "set action accept", 'set srcaddr "lan-net"', 'set dstaddr "partner"', 'set service "GRE"')
    )
    assert "NAT_OVERLAP" not in codes(convert(data, "panos")[1], "nat", "snat-1")


# -- applications, rule types, groups ------------------------------------------


def test_deny_rule_with_applications_always_needs_review() -> None:
    data = pan_xml(pan_rule("any-port", app="ssl", action="deny") +
                   pan_rule("default-port", app="ssl", service="application-default", action="deny"))
    text, report = convert(data, "fortios")
    policies = FortiConfig(text).policies()
    assert policies["any-port"].list("service") == ["app-ssl"] and policies["any-port"].get("status") == ""
    assert report.item("rule", "any-port").status == "needs-review"
    assert "other ports are no longer stopped" in report.item("rule", "any-port").findings[0].message
    assert report.item("rule", "default-port").status == "needs-review"


def test_interzone_rule_with_a_single_zone_matches_nothing() -> None:
    data = pan_xml(pan_rule("x", src_zone="dmz", dst_zone="dmz", extra="<rule-type>interzone</rule-type>"))
    text, report = convert(data, "fortios")
    assert "config firewall policy" not in text
    assert report.item("rule", "x").status == "skipped"


def test_icmp_type_approximation_is_reported_through_a_group() -> None:
    extra = """
config firewall service custom
    edit "TIMESTAMP"
        set protocol ICMP
        set icmptype 13
    next
end
config firewall service group
    edit "probes"
        set member "TIMESTAMP" "HTTPS"
    next
end
"""
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set service "probes"'), extra)
    _, report = convert(data, "panos")
    assert "ICMP_TYPE" in codes(report, "rule", "policy-1")


def test_panorama_export_without_hierarchy_information_says_so() -> None:
    xml = b"""<config><devices><entry name="p"><device-group>
      <entry name="parent"><pre-rulebase><security><rules/></security></pre-rulebase></entry>
      <entry name="child"><pre-rulebase><security><rules/></security></pre-rulebase></entry>
    </device-group></entry></devices></config>"""
    report = Report()
    cli.load(xml, "panos", report, device_group="child")
    assert any(n.code == "NO_HIERARCHY" for n in report.notes) and report.needs_review


# -- second review round ------------------------------------------------------

GROUPS_WITH_FQDN = """<address-group>
  <entry name="dmz-servers"><static><member>srv</member><member>fq</member></static></entry>
  <entry name="public-servers"><static><member>srv-public</member><member>fq</member></static></entry>
</address-group>"""


def test_group_holding_an_fqdn_is_still_read_for_destination_nat() -> None:
    data = pan_xml(
        pan_rule("mgmt", src_zone="any", dst_zone="dmz", destination="dmz-servers")
        + pan_rule("neg", src_zone="untrust", dst_zone="dmz", destination="public-servers",
                   extra="<negate-destination>yes</negate-destination>")
        + pan_rule("in", src_zone="untrust", dst_zone="dmz", destination="public-servers", service="service-https"),
        nat=DNAT, extra=GROUPS_WITH_FQDN,
    )
    text, report = convert(data, "fortios")
    policies = FortiConfig(text).policies()
    assert "NAT_ADDRESS_EXPOSED" in codes(report, "rule", "mgmt")  # the group names the internal server
    assert policies["neg"].get("status") == "disable"  # the negated group names the public address only
    assert policies["in"].list("dstaddr") == ["public-servers", "srv"]  # internal address added next to the group
    assert "NAT_DESTINATION_REWRITTEN" in codes(report, "rule", "in")


def test_fortios_group_holding_an_fqdn_next_to_a_vip() -> None:
    extra = VIP + 'config firewall addrgrp\n    edit "protected"\n        set member "srv" "fq"\n    next\nend\n'

    def inbound(number: int, *lines: str) -> str:
        return policy(number, 'set srcintf "wan"', 'set dstintf "dmz"', 'set schedule "always"', 'set service "HTTPS"',
                      'set srcaddr "all"', "set action accept", 'set dstaddr "protected"', *lines, base=False)

    text, report = convert(forti(inbound(1, "set dstaddr-negate enable") + inbound(2), extra), "panos")
    cfg = PanConfig(text)
    assert cfg.get("security", "policy-1", "disabled") == ["yes"]
    assert cfg.get("security", "policy-2", "destination") == ["protected", "vip-srv"]


def test_fortios_addresses_of_one_ip_version_on_one_side_only() -> None:
    data = forti(
        policy(1, "set action accept", 'set srcaddr "lan-net"', 'set srcaddr6 "lan6"', 'set dstaddr "srv"',
               "set dstaddr-negate enable")
        + policy(2, "set action accept", 'set srcaddr "bad-hosts"', "set srcaddr-negate enable", 'set dstaddr "all"',
                 'set dstaddr6 "all"')
    )
    text, report = convert(data, "panos")
    cfg = PanConfig(text)
    # Neither policy has a complete IPv6 pair, so neither may match IPv6 after conversion.
    assert cfg.get("security", "policy-1", "source") == ["lan-net"]
    assert cfg.get("security", "policy-2", "destination") == ["0.0.0.0/0"]
    assert codes(report, "rule", "policy-1") == ["INCOMPLETE_ADDRESS_PAIR"]
    forti_cfg = FortiConfig(convert(data, "fortios")[0])
    assert all(p.list("srcaddr6") == [] and p.list("dstaddr6") == [] for p in forti_cfg.policies().values())


def test_fortios_fqdn_on_both_sides_is_reported_for_panos() -> None:
    extra = 'config firewall address\n    edit "fq2"\n        set type fqdn\n        set fqdn "b.example.com"\n    next\nend\n'
    data = forti(policy(1, "set action accept", 'set srcaddr "fq"', 'set dstaddr "fq2"'), extra)
    _, report = convert(data, "panos")
    assert "FQDN_FAMILY" in codes(report, "rule", "policy-1")
    assert report.item("rule", "policy-1").status == "approximated"


def test_zone_map_merge_does_not_create_an_intrazone_allow() -> None:
    extra = 'config system zone\n    edit "servers"\n        set interface "port3" "port4"\n' \
            '        set intrazone allow\n    next\nend\n'
    data = forti(
        policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set srcintf "servers"')
        + policy(2, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', 'set srcintf "dmz"'),
        extra,
    )
    merged = Options(zone_map={"servers": "inside", "dmz": "inside"})
    text, report = convert(data, "panos", merged)
    assert "fwshift-intrazone-allow" not in PanConfig(text).names("security")
    assert any(n.code == "INTRAZONE_ALLOW_MERGED" for n in report.notes)
    # Merged with an unmapped interface of that name counts as well.
    text, report = convert(data, "panos", Options(zone_map={"servers": "dmz"}))
    assert "fwshift-intrazone-allow" not in PanConfig(text).names("security")
    # A plain rename keeps the rule.
    text, _ = convert(data, "panos", Options(zone_map={"servers": "srv-zone"}))
    assert PanConfig(text).get("security", "fwshift-intrazone-allow", "from") == ["srv-zone"]


@pytest.mark.parametrize("line", ['set groups "disable"', 'set groups "0"', 'set users "0"'])
def test_fortios_group_named_like_an_off_value_still_restricts(line: str) -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', line))
    assert convert(data, "panos")[1].item("rule", "policy-1").disabled


def test_deny_on_the_internal_address_is_reported_under_central_nat() -> None:
    data = pan_xml(
        pan_rule("block", src_zone="untrust", dst_zone="dmz", destination="srv", action="deny")
        + pan_rule("in", src_zone="untrust", dst_zone="dmz", destination="srv-public", service="service-https"),
        nat=DNAT,
    )
    _, report = convert(data, "fortios")
    finding = report.item("rule", "block").findings[0]
    assert finding.code == "NAT_ADDRESS_EXPOSED" and "blocks that traffic" in finding.message
    assert report.item("rule", "block").status == "needs-review"


def test_panos_service_with_unreadable_ports() -> None:
    data = pan_xml(pan_rule("r", service="odd"), services='<entry name="odd"><protocol><tcp><port>80,abc</port>'
                   "<source-port>x</source-port></tcp></protocol></entry>")
    text, report = convert(data, "fortios")
    cfg = FortiConfig(text)
    assert cfg.table("firewall service custom")["odd"].list("tcp-portrange") == ["1"]  # placeholder, not "80:x abc:x"
    assert cfg.policies()["r"].get("status") == "disable"
    assert report.item("service", "odd").status == "needs-review"


def test_factory_service_names_and_vip_names_are_not_reused() -> None:
    nat = DNAT.replace('name="web-dnat"', 'name="all"')
    data = pan_xml(pan_rule("r", service="VNC"), nat=nat,
                   services='<entry name="VNC"><protocol><tcp><port>5901</port></tcp></protocol></entry>')
    cfg = FortiConfig(convert(data, "fortios")[0])
    assert "VNC" not in cfg.table("firewall service custom")
    assert cfg.table("firewall service custom")["VNC_2"].list("tcp-portrange") == ["5901"]
    assert list(cfg.table("firewall vip")) == ["all_2"]


def test_panos_elements_that_are_missing_are_not_read_as_any() -> None:
    bare = '<entry name="bare"><from><member>trust</member></from><to><member>untrust</member></to></entry>'
    data = pan_xml(bare + pan_rule("svc", service="noport"),
                   services='<entry name="noport"><protocol><tcp></tcp></protocol></entry>')
    text, report = convert(data, "fortios")
    policies = FortiConfig(text).policies()
    assert policies["bare"].get("status") == "disable" and policies["svc"].get("status") == "disable"
    assert "rule without <source>" in " ".join(f.message for f in report.item("rule", "bare").findings)
    assert "1-65535" not in text


@pytest.mark.parametrize("line", ['set network-service-dynamic "disable"', 'set internet-service-name "disable"'])
def test_fortios_name_attributes_under_restricting_prefixes(line: str) -> None:
    data = forti(policy(1, "set action accept", 'set srcaddr "all"', 'set dstaddr "all"', line))
    assert convert(data, "panos")[1].item("rule", "policy-1").disabled


def test_factory_service_group_names_are_reserved() -> None:
    extra = '<service-group><entry name="Web Access"><members><member>service-https</member></members></entry>' \
            "</service-group>"
    cfg = FortiConfig(convert(pan_xml(pan_rule("r", service="Web Access"), extra=extra), "fortios")[0])
    assert list(cfg.table("firewall service group")) == ["Web Access_2"]
    assert cfg.policies()["r"].list("service") == ["Web Access_2"]


def test_azure_firewall_dnat_allows_before_the_network_rules() -> None:
    """Azure Firewall allows what a DNAT rule translates, and no network rule sees it: a network deny for the same
    traffic does not block it. The model says so with an allow rule ahead of the network rules; a PAN-OS target then
    allows the translated traffic, and an Azure Firewall target writes the DNAT rule only where the model allows it."""
    group = {"type": "Microsoft.Network/FirewallPolicies/RuleCollectionGroups", "name": "p/g", "priority": 100, "ruleCollections": [
        {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "deny-all", "priority": 100, "action": {"type": "Deny"},
         "rules": [{"ruleType": "NetworkRule", "name": "all", "ipProtocols": ["Any"], "sourceAddresses": ["*"], "destinationAddresses": ["*"],
                    "destinationPorts": ["*"]}]},
        {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": "pub", "priority": 200, "action": {"type": "DNAT"},
         "rules": [{"ruleType": "NatRule", "name": "web", "ipProtocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["203.0.113.5"],
                    "destinationPorts": ["443"], "translatedAddress": "10.0.0.5", "translatedPort": "443"}]}]}  # fmt: skip
    report = Report()
    policy = cli.load(json.dumps([group]).encode(), "azure-firewall", report)
    assert [(r.name, r.action.value) for r in policy.rules] == [("pub/web (DNAT)", "allow"), ("deny-all/all", "deny")]
    text = cli.convert(policy, "azure-firewall", Report())
    assert '"translatedAddress": "10.0.0.5"' in text
    # Without the DNAT's allow rule the model blocks it, and the DNAT rule, which would allow it, is not written.
    policy.rules = policy.rules[1:]
    out = Report()
    assert "translatedAddress" not in cli.convert(policy, "azure-firewall", out)
    assert out.item("nat", "pub/web").findings[0].code == "AZFW_DNAT_NOT_ALLOWED"


def test_f5_afm_accept_in_the_global_context_is_not_an_allow() -> None:
    """On a BIG-IP in Firewall mode an accept in the global context only hands the packet on: the virtual server's
    default still drops it. Read as an allow it would open what the BIG-IP blocks; an accept-decisively does allow."""
    tmsh = """sys db tm.fw.defaultaction {
    value "drop"
}
security firewall policy /Common/g {
    rules {
        web {
            action accept
            ip-protocol tcp
        }
        dns {
            action accept-decisively
            ip-protocol udp
        }
    }
}
security firewall global-rules {
    enforced-policy /Common/g
}
ltm virtual /Common/fwd {
    destination /Common/0.0.0.0:any
    ip-forward
    mask any
    source 0.0.0.0/0
}
"""
    report = Report()
    policy = cli.load(tmsh.encode(), cli.detect_format(tmsh.encode()), report)
    verdicts = {r.name: (r.action.value, r.services) for r in policy.rules}
    assert verdicts["global/web>fwd/(default)"] == ("drop", ["tcp-any"])
    assert verdicts["global/dns@fwd"] == ("allow", ["udp-any"])
    # A PAN-OS target gets the drop, not an allow.
    text = cli.convert(policy, "panos", Report())
    assert "global_web_fwd__default_ action drop" in text and "global_dns_fwd action allow" in text


def test_oci_stateless_rule_decides_over_a_stateful_one_and_needs_its_reply() -> None:
    """OCI: when a stateless and a stateful rule of a VNIC match the same traffic, the stateless one decides and the
    connection is not tracked, so the reply needs a rule in the other direction. Read as two allow rules, the stateful
    one would let it through; the model blocks it first, and a PAN-OS target does not allow it."""
    rules = [{"protocol": "6", "source": "198.51.100.0/24", "source-type": "CIDR_BLOCK", "is-stateless": stateless,
              "tcp-options": {"destination-port-range": {"min": 443, "max": 443}}} for stateless in (True, False)]  # fmt: skip
    answers = [{"data": [{"id": "ocid1.subnet.oc1.x.a", "display-name": "a", "vcn-id": "ocid1.vcn.oc1.x.v", "cidr-block": "10.0.1.0/24",
                          "security-list-ids": ["ocid1.securitylist.oc1.x.l"]}]},
               {"data": [{"id": "ocid1.securitylist.oc1.x.l", "display-name": "l", "vcn-id": "ocid1.vcn.oc1.x.v",
                          "ingress-security-rules": rules, "egress-security-rules": []}]}]  # fmt: skip
    policy = cli.load("\n".join(json.dumps(a) for a in answers).encode(), "oci", Report())
    names = [r.name for r in policy.rules]
    assert policy.rules[0].name == "a-stateless-in" and policy.rules[0].action.value == "drop" and names.index("l-in-2") > 0
    text = cli.convert(policy, "panos", Report())
    assert "rules a-stateless-in action drop" in text and text.index("rules a-stateless-in ") < text.index("rules l-in-2 ")
