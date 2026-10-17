# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAN-OS's set format as a source (0.34.0): what ``show config running`` prints with ``set cli config-output-format
set``, and what the PAN-OS target writes, is read as the XML it stands for.

The differential test: the XML samples printed as set commands (by ``flatten`` below, which prints every element of
the XML the way PAN-OS does: an entry as the word of its list and its name, a list of members in [ ], a value after
its path) are read to the same policy as the XML; and what the PAN-OS target writes reads back to the policy it was
written from (``--compare`` now reads PAN-OS output back).
"""

from __future__ import annotations

import dataclasses
import json
import random
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Iterator, List

import pytest
from test_iptables import random_model

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.model import Rule
from fwshift.parsers import panos as parse_panos
from fwshift.parsers import panos_set
from fwshift.report import Report

DATA = Path(__file__).parent / "data"


def quoted(word: str) -> str:
    if word and all(c.isalnum() or c in "-_./:,@*" for c in word):
        return word
    return '"' + word + '"'  # (as PAN-OS prints it: a backslash or a quote inside as it is)


def flatten(element: ET.Element, path: List[str], brackets: bool = True) -> Iterator[str]:
    """The set commands of the children of an element, as PAN-OS prints them."""
    for child in element:
        if child.tag == "entry":
            continue  # (the entries of a list are printed by their list)
        entries = child.findall("entry")
        members = child.findall("member")
        if entries:
            for entry in entries:
                here = path + [child.tag, quoted(entry.get("name", ""))]
                if len(entry) or (entry.text or "").strip():
                    yield from flatten(entry, here, brackets)
                else:
                    yield "set " + " ".join(here)
        elif members:
            values = [quoted(m.text or "") for m in members]
            if len(values) == 1 and not brackets:
                yield "set " + " ".join(path + [child.tag, values[0]])
            else:
                yield "set " + " ".join(path + [child.tag, "["] + values + ["]"])
        elif len(child):
            yield from flatten(child, path + [child.tag], brackets)
        elif (child.text or "").strip():
            yield "set " + " ".join(path + [child.tag, quoted(child.text.strip())])
        else:
            yield "set " + " ".join(path + [child.tag])  # (an element without a value: qos marking follow-c2s-flow)


def printed(xml: bytes, brackets: bool = True, vsys_prefix: bool = False) -> str:
    """A configuration of one firewall as PAN-OS prints it in set format (vsys1 without its prefix, as one with a
    single virtual system prints it; with ``vsys_prefix``, as one with several does)."""
    root = ET.fromstring(xml)
    config = root if root.tag == "config" else root.find(".//config")
    assert config is not None
    lines: List[str] = []
    for part in config:
        if part.tag not in ("shared", "devices"):
            lines += flatten(_wrap(part), [], brackets)  # (readonly, mgt-config)
    shared = config.find("shared")
    if shared is not None:
        lines += flatten(shared, ["shared"], brackets)
    for device in config.findall("devices/entry"):
        for part in device:
            if part.tag == "vsys":
                for vsys in part.findall("entry"):
                    prefix = ["vsys", quoted(vsys.get("name", ""))] if vsys_prefix or vsys.get("name") != "vsys1" else []
                    lines += flatten(vsys, prefix, brackets)
            elif part.tag == "device-group":
                for group in part.findall("entry"):
                    lines += flatten(group, ["device-group", quoted(group.get("name", ""))], brackets)
            else:
                lines += flatten(_wrap(part), [], brackets)  # (deviceconfig, network: no prefix)
    return "\n".join(lines) + "\n"


def _wrap(element: ET.Element) -> ET.Element:
    holder = ET.Element("holder")
    holder.append(element)
    return holder


def model_json(policy: object) -> object:
    return json.loads(json.dumps(dataclasses.asdict(policy), default=str))  # type: ignore[call-overload]


@pytest.mark.parametrize("sample", ["panos_sample.xml", "panos_logged.xml"])
@pytest.mark.parametrize("brackets", [True, False])
def test_the_samples_printed_as_set_commands_read_as_the_xml(sample: str, brackets: bool) -> None:
    xml = (DATA / sample).read_bytes()
    text = printed(xml, brackets)
    assert text.count("\nset ") > 50
    from_xml, from_set = Report(), Report()
    a = parse_panos.parse(xml, from_xml)
    b = parse_panos.parse(text.encode(), from_set)
    assert model_json(a) == model_json(b)
    assert [n.code for n in from_xml.notes] == [n.code for n in from_set.notes if n.code != "PANOS_SET_FORMAT"]


def test_a_firewall_with_several_virtual_systems() -> None:
    xml = (DATA / "panos_sample.xml").read_bytes()
    text = printed(xml, vsys_prefix=True).replace("set vsys vsys1 ", "set vsys vsys2 ")
    text += "set vsys vsys1 address only-here ip-netmask 10.99.0.0/16\n"
    policy = parse_panos.parse(text.encode(), Report(), vsys="vsys2")
    assert model_json(policy)["rules"] == model_json(parse_panos.parse(xml, Report()))["rules"]  # type: ignore[index]
    assert "only-here" not in policy.addresses
    assert "only-here" in parse_panos.parse(text.encode(), Report(), vsys="vsys1").addresses


def test_panorama_device_groups_and_shared_objects() -> None:
    text = """\
set shared address shared-net ip-netmask 10.50.0.0/16
set shared service tcp-8080 protocol tcp port 8080
set device-group branch address branch-web ip-netmask 10.60.0.10/32
set device-group branch pre-rulebase security rules to-web from any
set device-group branch pre-rulebase security rules to-web to any
set device-group branch pre-rulebase security rules to-web source shared-net
set device-group branch pre-rulebase security rules to-web destination branch-web
set device-group branch pre-rulebase security rules to-web application any
set device-group branch pre-rulebase security rules to-web service tcp-8080
set device-group branch pre-rulebase security rules to-web action allow
set device-group branch post-rulebase security rules last from any
set device-group branch post-rulebase security rules last to any
set device-group branch post-rulebase security rules last source any
set device-group branch post-rulebase security rules last destination any
set device-group branch post-rulebase security rules last application any
set device-group branch post-rulebase security rules last service any
set device-group branch post-rulebase security rules last action deny
"""
    assert cli.detect_format(text.encode()) == "panos"
    policy = parse_panos.parse(text.encode(), Report(), device_group="branch")
    assert [r.name for r in policy.rules] == ["to-web", "last"]
    assert policy.rules[0].sources == ["shared-net"] and policy.rules[0].services == ["tcp-8080"]
    assert policy.addresses["shared-net"].value == "10.50.0.0/16" and policy.services["tcp-8080"].entries[0].dst_ports == "8080"


SMALL = """\
admin@PA-VM# set deviceconfig system hostname "lab fw"
set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24
set network interface ethernet ethernet1/2 layer3 units ethernet1/2.10 tag 10
set network virtual-router default interface [ ethernet1/1 ethernet1/2.10 ]
set network virtual-router default routing-table ip static-route def destination 0.0.0.0/0
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 [ ethernet1/2.10 ]
set tag prod color color1
set address "web 1" ip-netmask 10.10.0.10/32
set address "web 1" tag prod
set address "web 1" description "say "hi" [not a list]"
set address-group grp static [ "web 1" ]
set service svc protocol tcp port 8080
set rulebase security rules r1 from trust
set rulebase security rules r1 to untrust
set rulebase security rules r1 source grp
set rulebase security rules r1 destination any
set rulebase security rules r1 application any
set rulebase security rules r1 service svc
set rulebase security rules r1 action allow
set rulebase security rules r1 tag prod
set rulebase nat rules n1 from trust
set rulebase nat rules n1 to untrust
set rulebase nat rules n1 source any
set rulebase nat rules n1 destination any
set rulebase nat rules n1 service any
set rulebase nat rules n1 source-translation dynamic-ip-and-port interface-address interface ethernet1/1
"""


def test_what_a_session_prints_is_read_with_its_quotes_lists_and_prompt() -> None:
    xml = ET.fromstring(panos_set.to_xml(SMALL.encode(), Report()))
    vsys = xml.find("devices/entry/vsys/entry[@name='vsys1']")
    assert vsys is not None
    assert vsys.findtext("address/entry[@name='web 1']/description") == 'say "hi" [not a list]'
    assert [m.text for m in vsys.findall("address/entry/tag/member")] == ["prod"]
    assert vsys.findtext("tag/entry[@name='prod']/color") == "color1"
    assert [m.text for m in vsys.findall("zone/entry[@name='untrust']/network/layer3/member")] == ["ethernet1/1"]
    assert vsys.findtext("rulebase/nat/rules/entry/service") == "any"  # (one, not a list)
    assert [m.text for m in vsys.findall("rulebase/security/rules/entry/service/member")] == ["svc"]
    device = xml.find("devices/entry")
    assert device is not None and device.findtext("deviceconfig/system/hostname") == "lab fw"
    assert device.find("network/interface/ethernet/entry[@name='ethernet1/1']/layer3/ip/entry[@name='192.0.2.1/24']") is not None
    assert device.findtext("network/interface/ethernet/entry/layer3/units/entry/tag") == "10"  # (a VLAN, not a list)
    assert [m.text for m in device.findall("network/virtual-router/entry/interface/member")] == ["ethernet1/1", "ethernet1/2.10"]
    assert device.findtext("network/virtual-router/entry/routing-table/ip/static-route/entry[@name='def']/destination") == "0.0.0.0/0"
    policy = cli.load(SMALL.encode(), cli.detect_format(SMALL.encode()), Report())
    assert policy.vendor == "panos" and policy.zones["trust"].interfaces == ["ethernet1/2.10"]
    assert policy.rules[0].sources == ["grp"] and policy.address_groups["grp"].members == ["web 1"]
    assert policy.nat_rules[0].source_translation is not None and policy.nat_rules[0].source_translation.interface == "ethernet1/1"


def test_commands_other_than_set_are_said_and_broken_lines_refused() -> None:
    report = Report()
    parse_panos.parse((SMALL + "delete address old\ndelete address older\nedit rulebase\n").encode(), report)
    note = next(n for n in report.notes if n.code == "SET_COMMANDS_NOT_READ")
    assert note.message.endswith("delete (2), edit (1)")
    with pytest.raises(ParseError, match="line 2: a quote is not closed"):
        panos_set.to_xml(b'set address a ip-netmask 10.0.0.1\nset address "b ip-netmask 10.0.0.2\n', Report())
    with pytest.raises(ParseError, match="not closed"):
        panos_set.to_xml(b"set rulebase security rules r from [ a b\n", Report())
    with pytest.raises(ParseError, match="no set commands"):
        panos_set.to_xml(b"# nothing\n", Report())


def test_detection_tells_set_commands_of_pan_os_from_junos_and_fortios() -> None:
    assert cli.detect_format(SMALL.encode()) == "panos"
    assert cli.detect_format((DATA / "junos_sample.conf").read_bytes()) == "junos"
    flat = b"config firewall policy\nedit 1\nset srcaddr all\nset service ALL\nset address a b c\nnext\nend\n"
    assert cli.detect_format(flat) == "fortios"
    assert cli.detect_format(b"set security zones security-zone trust interfaces ge-0/0/0.0\n") == "junos"


@pytest.mark.parametrize("seed", range(40))
def test_what_the_panos_target_writes_reads_back_to_what_it_was_written_from(seed: int) -> None:
    """A random policy -> PAN-OS set commands -> read back -> PAN-OS again: the same commands (a fixed point; the
    objects perhaps in another order, as the target writes groups after what they hold), and the rules read back are
    the rules written."""
    p = random_model(random.Random(seed))
    first = cli.convert(p, "panos", Report())
    back = parse_panos.parse(first.encode(), Report())
    second = cli.convert(back, "panos", Report())
    def rulebase(text: str) -> List[str]:
        return [line for line in text.splitlines() if line.startswith("set rulebase ")]

    assert rulebase(second) == rulebase(first)  # (in order: the order of first match)
    assert sorted(second.splitlines()) == sorted(first.splitlines())  # (the objects: the same, perhaps in another order)
    written = [line.split()[4] for line in first.splitlines() if line.startswith("set rulebase security rules ")]
    assert [r.name for r in back.rules] == list(dict.fromkeys(written))


def test_compare_reads_panos_output_back(tmp_path: Path) -> None:
    out = tmp_path / "out.set"
    report = tmp_path / "report.json"
    code = cli.main(["convert", str(DATA / "panos_sample.xml"), "--to", "panos", "-o", str(out), "--compare",
                     "--report-json", str(report), "-q"])  # fmt: skip
    assert code in (0, 3)
    notes = json.loads(report.read_text())["notes"]
    assert not [n for n in notes if n["code"] == "COMPARE_NOT_READ_BACK"]
    disabled = {item["name"] for item in json.loads(report.read_text())["items"] if item["disabled"]}
    assert disabled == {"Block-Region", "Old-Rule"}  # (what --compare finds open comes from these, which are said)
    assert out.read_text().startswith("set ")
    # A policy the target writes without loss: read back, nothing differs.
    source = tmp_path / "source.set"
    for seed in (7, 11, 23):
        source.write_text(cli.convert(random_model(random.Random(seed)), "panos", Report()))
        cli.main(["convert", str(source), "--to", "panos", "-o", str(out), "--compare", "--report-json", str(report), "-q"])
        codes = [n["code"] for n in json.loads(report.read_text())["notes"]]
        assert [c for c in codes if c.startswith("COMPARE_")] == ["COMPARE_EQUIVALENT"], codes


# What the samples do not have: a firewall with the rest of what the parser reads, and a Panorama with device groups
# in a hierarchy, a template and targets. Synthetic, as everything in tests/data.
FIREWALL = """\
<config version="11.1.0"><mgt-config><users><entry name="admin"><phash>*</phash></entry></users></mgt-config>
<shared><certificate><entry name="lab-ca"><common-name>lab-ca</common-name><public-key>-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQ0FMQUJDQUxBQkNBTEFCQ0FMQUJDQUww
-----END CERTIFICATE-----
</public-key></entry></certificate></shared>
<devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>lab-fw</hostname><login-banner>Authorised use only.
All activity is logged.</login-banner></system></deviceconfig>
<network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry>
<entry name="ethernet1/5"><virtual-wire/></entry></ethernet></interface></network>
<vsys><entry name="vsys1">
<zone><entry name="inside"><network><layer3><member>ethernet1/2</member><member>ethernet1/3</member></layer3></network></entry>
<entry name="l2"><network><layer2><member>ethernet1/4</member></layer2></network></entry>
<entry name="wire"><network><virtual-wire><member>ethernet1/5</member></virtual-wire></network></entry>
<entry name="span"><network><tap><member>ethernet1/6</member></tap></network></entry>
<entry name="outside"><network><layer3><member>ethernet1/1</member></layer3></network><enable-user-identification>yes</enable-user-identification></entry></zone>
<tag><entry name="prod"><color>color1</color></entry></tag>
<schedule><entry name="biz"><schedule-type><recurring><weekly><monday><member>08:00-18:00</member></monday></weekly></recurring></schedule-type></entry></schedule>
<address><entry name="hosts-odd"><ip-wildcard>10.20.1.1/0.0.254.0</ip-wildcard></entry>
<entry name="span-a"><ip-range>10.20.3.1-10.20.3.9</ip-range><tag><member>prod</member></tag></entry>
<entry name="www"><fqdn>www.example.com</fqdn><description>the "public" site, C:\\temp\\</description></entry>
<entry name="pool-1"><ip-netmask>198.51.100.10/32</ip-netmask></entry><entry name="pool-2"><ip-netmask>198.51.100.11/32</ip-netmask></entry>
<entry name="web"><ip-netmask>10.20.2.10/32</ip-netmask></entry><entry name="web-pub"><ip-netmask>203.0.113.10/32</ip-netmask></entry></address>
<address-group><entry name="tagged"><dynamic><filter>'prod' and 'web'</filter></dynamic></entry>
<entry name="both"><static><member>span-a</member><member>www</member></static></entry></address-group>
<service><entry name="sctp-9"><protocol><sctp><port>9</port></sctp></protocol></entry>
<entry name="syslog-hi"><protocol><udp><port>514</port><source-port>1024-65535</source-port><override><no/></override></udp></protocol></entry>
<entry name="tcp-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry></service>
<service-group><entry name="svcs"><members><member>sctp-9</member><member>tcp-8443</member></members></entry></service-group>
<application-filter><entry name="risky"><category><member>networking</member></category><risk><member>5</member></risk></entry></application-filter>
<application-group><entry name="webapps"><members><member>web-browsing</member><member>ssl</member></members></entry></application-group>
<rulebase><security><rules>
<entry name="Office hours"><from><member>inside</member></from><to><member>outside</member></to>
<source><member>both</member></source><destination><member>any</member></destination>
<source-user><member>EXAMPLE\\domain users</member><member>EXAMPLE\\jdoe</member></source-user>
<category><member>any</member></category><application><member>webapps</member></application>
<service><member>application-default</member></service><hip-profiles><member>any</member></hip-profiles>
<action>allow</action><schedule>biz</schedule><log-start>yes</log-start><log-setting>default</log-setting>
<profile-setting><profiles><virus><member>default</member></virus><spyware><member>strict</member></spyware></profiles></profile-setting>
<qos><marking><follow-c2s-flow/></marking></qos><tag><member>prod</member></tag>
<description>in office hours only
and logged</description></entry>
<entry name="no-risky"><from><member>any</member></from><to><member>outside</member></to><source><member>tagged</member></source>
<destination><member>any</member></destination><negate-source>yes</negate-source><application><member>risky</member></application>
<service><member>any</member></service><action>deny</action><disabled>yes</disabled><rule-type>interzone</rule-type>
<qos><marking><ip-dscp>af11</ip-dscp></marking></qos></entry>
<entry name="sctp"><from><member>inside</member></from><to><member>inside</member></to><source><member>any</member></source>
<destination><member>hosts-odd</member></destination><application><member>any</member></application>
<service><member>svcs</member><member>syslog-hi</member></service><action>allow</action><rule-type>intrazone</rule-type></entry>
</rules></security>
<nat><rules>
<entry name="pool"><from><member>inside</member></from><to><member>outside</member></to><source><member>any</member></source>
<destination><member>any</member></destination><service>any</service><to-interface>ethernet1/1</to-interface>
<source-translation><dynamic-ip><translated-address><member>pool-1</member><member>pool-2</member></translated-address>
<fallback><interface-address><interface>ethernet1/1</interface></interface-address></fallback></dynamic-ip></source-translation></entry>
<entry name="publish"><from><member>outside</member></from><to><member>outside</member></to><source><member>any</member></source>
<destination><member>web-pub</member></destination><service>tcp-8443</service>
<destination-translation><translated-address>web</translated-address><translated-port>443</translated-port></destination-translation></entry>
<entry name="one-to-one"><from><member>inside</member></from><to><member>outside</member></to><source><member>web</member></source>
<destination><member>any</member></destination><service>any</service><nat-type>ipv4</nat-type>
<source-translation><static-ip><translated-address>web-pub</translated-address><bi-directional>yes</bi-directional></static-ip></source-translation></entry>
<entry name="dyn"><from><member>outside</member></from><to><member>outside</member></to><source><member>any</member></source>
<destination><member>web-pub</member></destination><service>any</service><disabled>yes</disabled>
<dynamic-destination-translation><translated-address>www</translated-address><distribution>round-robin</distribution></dynamic-destination-translation></entry>
</rules></nat></rulebase>
</entry></vsys></entry></devices></config>
"""

PANORAMA = """\
<config version="11.1.0">
<shared><address><entry name="shared-net"><ip-netmask>10.50.0.0/16</ip-netmask></entry></address>
<pre-rulebase><security><rules><entry name="shared-first"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>shared-net</member></destination><application><member>ping</member></application>
<service><member>application-default</member></service><action>allow</action></entry></rules></security></pre-rulebase></shared>
<devices><entry name="localhost.localdomain">
<template><entry name="branch-net"><config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<zone><entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone>
</entry></vsys></entry></devices></config></entry></template>
<device-group>
<entry name="region"><address><entry name="region-dns"><ip-netmask>10.60.0.53/32</ip-netmask></entry></address>
<pre-rulebase><security><rules><entry name="to-dns"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>region-dns</member></destination><application><member>dns</member></application>
<service><member>application-default</member></service><action>allow</action></entry></rules></security></pre-rulebase></entry>
<entry name="branch"><address><entry name="branch-web"><ip-netmask>10.61.0.10/32</ip-netmask></entry></address>
<pre-rulebase><security><rules><entry name="to-web"><from><member>any</member></from><to><member>any</member></to>
<source><member>shared-net</member></source><destination><member>branch-web</member></destination><application><member>any</member></application>
<service><member>service-https</member></service><action>allow</action>
<target><devices><entry name="001801000001"><vsys><entry name="vsys1"/><entry name="vsys2"/></vsys></entry></devices></target></entry>
</rules></security></pre-rulebase>
<post-rulebase><security><rules><entry name="last"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application>
<service><member>any</member></service><action>deny</action></entry></rules></security></post-rulebase></entry>
</device-group></entry></devices>
<readonly><devices><entry name="localhost.localdomain"><device-group>
<entry name="region"><id>11</id></entry><entry name="branch"><id>12</id><parent-dg>region</parent-dg></entry>
</device-group></entry></devices></readonly>
</config>
"""


@pytest.mark.parametrize("brackets", [True, False])
@pytest.mark.parametrize("which", ["firewall", "region", "branch"])
def test_the_rest_of_what_the_parser_reads_printed_as_set_commands(which: str, brackets: bool) -> None:
    xml = (FIREWALL if which == "firewall" else PANORAMA).encode()
    text = printed(xml, brackets)
    group = "" if which == "firewall" else which
    from_xml, from_set = Report(), Report()
    a = parse_panos.parse(xml, from_xml, device_group=group)
    b = parse_panos.parse(text.encode(), from_set, device_group=group)
    assert model_json(a) == model_json(b)
    assert [n.code for n in from_xml.notes] == [n.code for n in from_set.notes if n.code != "PANOS_SET_FORMAT"]
    if which == "firewall":
        rule = b.rules[0]
        assert rule.schedule == "biz" and rule.users == ["EXAMPLE\\domain users", "EXAMPLE\\jdoe"]
        assert "qos" in rule.handling and b.rules[1].negate_source and not b.rules[1].enabled
        assert b.addresses["www"].description == 'the "public" site, C:\\temp\\'
        assert '"EXAMPLE\\domain users"' in text and "-----END CERTIFICATE-----" in text
    if which == "branch":
        assert [r.name for r in b.rules] == ["shared-first", "to-dns", "to-web", "last"]  # (the parent's rules too)
        assert b.rules[2].targets == ["001801000001"]


def test_one_command_may_set_several_values_of_an_entry() -> None:
    """As the CLI takes them, and as migration scripts and Palo Alto's own examples write them."""
    text = b"""\
set address web ip-netmask 10.20.2.10/32 description "the web server" tag [ prod ]
set rulebase security rules r1 from trust to untrust source any destination web application any service any action allow
set rulebase security rules r1 disabled yes description old negate-source yes log-end no schedule biz
"""
    policy = parse_panos.parse(text, Report())
    rule = policy.rules[0]
    assert rule.src_zones == ["trust"] and rule.dst_zones == ["untrust"] and rule.destinations == ["web"]
    assert not rule.enabled and rule.negate_source and not rule.log_end and rule.schedule == "biz" and rule.description == "old"
    assert policy.addresses["web"].description == "the web server" and policy.addresses["web"].tags == ["prod"]


def test_what_panorama_prints_around_the_device_groups_hides_none_of_them() -> None:
    """A template, a log collector, set cli of the session, a device group without anything in it: the device group
    is still found by itself, and no virtual system is made up."""
    rule = ("set device-group branch pre-rulebase security rules r from any to any source any destination any "
            "application any service any action allow\n")  # fmt: skip
    text = ("admin@pano> set cli config-output-format set\n"
            "admin@pano> configure\nEntering configuration mode\n[edit]\n"
            "admin@pano# set template T1 config devices localhost.localdomain vsys vsys1 zone trust network layer3 ethernet1/1\n"
            "set log-collector 0071 deviceconfig system hostname lc1\nset device-group empty\n" + rule
            + "set device-group branch pre-rulebase security rules r target devices 001801000001 vsys [ vsys1 vsys2 ]\n")  # fmt: skip
    report = Report()
    policy = parse_panos.parse(text.encode(), report, device_group="branch")
    assert policy.scope == "device-group branch" and [r.name for r in policy.rules] == ["r"]
    assert policy.rules[0].targets == ["001801000001"]
    assert "SET_COMMANDS_NOT_READ" not in [n.code for n in report.notes]  # (configure, Entering, [edit]: of the session)
    with pytest.raises(ParseError, match="several device groups"):
        parse_panos.parse(text.encode(), Report())  # (empty is a device group too)


def test_quoted_brackets_are_values_and_odd_input_is_refused_as_such() -> None:
    xml = ET.fromstring(panos_set.to_xml(b'set address a description "]"\nset address b description "["\n', Report()))
    assert [e.findtext("description") for e in xml.iter("entry") if e.get("name") in ("a", "b")] == ["]", "["]
    with pytest.raises(ParseError, match="deeper than"):
        panos_set.to_xml(("set deviceconfig " + "x " * 200 + "y\n").encode(), Report())
    with pytest.raises(ParseError, match="service takes one value"):
        panos_set.to_xml(b"set rulebase nat rules n service [ a b ]\n", Report())
    one = ET.fromstring(panos_set.to_xml(b"set rulebase nat rules n service [ a ]\n", Report()))
    assert one.findtext(".//nat/rules/entry/service") == "a"
    with pytest.raises(ParseError, match="without its"):
        panos_set.to_xml(b"set address a description ]\n", Report())


def test_a_utf16_export_is_read_as_before_and_a_utf16_set_file_too() -> None:
    xml = (DATA / "panos_sample.xml").read_text(encoding="utf-8")
    assert len(parse_panos.parse(xml.encode("utf-16"), Report()).rules) == 14
    assert len(parse_panos.parse(SMALL.encode("utf-16"), Report()).rules) == 1
    assert cli.detect_format(SMALL.encode("utf-16")) == "panos"


def test_flat_fortios_of_any_section_is_not_taken_for_pan_os() -> None:
    flat = b'config wireless-controller vap\nedit "corp"\nset schedule "always"\nnext\nend\n'
    assert cli.detect_format(flat) == "fortios"


def test_the_target_writes_backslashes_as_pan_os_prints_them_and_no_quote_inside_a_value() -> None:
    xml = FIREWALL.encode()
    text = cli.convert(parse_panos.parse(xml, Report()), "panos", Report())
    assert 'source-user [ "EXAMPLE\\domain users" "EXAMPLE\\jdoe" ]' in text
    assert "description \"the 'public' site, C:\\temp\\\"" in text
    assert "\\\\" not in text
    back = parse_panos.parse(text.encode(), Report())
    assert back.rules[0].users == ["EXAMPLE\\domain users", "EXAMPLE\\jdoe"]


RULE_1 = "set rulebase security rules r1 from trust to untrust source any destination any application any service any action allow"


def test_a_quoted_word_inside_a_value_that_runs_over_lines_ends_nothing() -> None:
    """A banner that quotes a word: the commands after it are read, none is swallowed."""
    text = ('set deviceconfig system login-banner "NOTICE\nUse is subject to the "AUP" of the company.\n"AUP"\n'
            'All sessions are logged."\n' + RULE_1 + "\nset address web ip-netmask 10.20.2.10/32\n"
            'set rulebase security rules r2 from any to any source any destination web application any service any '
            'action deny description "block web"\n')  # fmt: skip
    report = Report()
    xml = ET.fromstring(panos_set.to_xml(text.encode(), report))
    assert xml.findtext("devices/entry/deviceconfig/system/login-banner") == (
        'NOTICE\nUse is subject to the "AUP" of the company.\n"AUP"\nAll sessions are logged.')
    policy = parse_panos.parse(text.encode(), Report())
    assert [r.name for r in policy.rules] == ["r1", "r2"] and "web" in policy.addresses
    assert policy.rules[1].description == "block web" and "SET_COMMANDS_NOT_READ" not in [n.code for n in report.notes]
    with pytest.raises(ParseError, match="runs into the commands"):
        panos_set.to_xml(b'set address a description "never closed\nset address b ip-netmask 10.0.0.1\nset x "y"\n', Report())


@pytest.mark.parametrize("line, check", [
    ('description "Server "web 1" and "web 2""', lambda r: r.description == 'Server "web 1" and "web 2"'),
    ('description "6" pipe" ', lambda r: r.description == '6" pipe'),
    ("description [legacy]", lambda r: r.description == "[legacy]"),
    ("profile-setting group default log-setting fwd", lambda r: r.profiles == {"group": "default"} and r.handling.get("log-setting") == "fwd"),
    ("option disable-server-response-inspection yes disabled yes", lambda r: not r.enabled),
    ("qos marking ip-dscp af11 description x", lambda r: r.handling["qos"] == "ip-dscp af11" and r.description == "x"),
    ("target devices 001801000001 negate yes", lambda r: r.targets == []),  # (negated: every device but this one)
])  # fmt: skip
def test_one_command_after_a_part_of_the_rule_is_of_the_rule_again(line: str, check: Callable[[Rule], bool]) -> None:
    policy = parse_panos.parse(f"{RULE_1}\nset rulebase security rules r1 {line}\n".encode(), Report())
    assert check(policy.rules[0]), policy.rules[0]


@pytest.mark.parametrize("tail, kind, addresses, extra", [
    ("source-translation static-ip translated-address 203.0.113.9 bi-directional yes", "static", ["203.0.113.9"], True),
    ("source-translation dynamic-ip-and-port interface-address ip 203.0.113.1/24 interface ethernet1/1", "interface", ["203.0.113.1/24"], "ethernet1/1"),
    ("source-translation dynamic-ip-and-port translated-address [ 203.0.113.5 203.0.113.6 ]", "dynamic-ip-and-port", ["203.0.113.5", "203.0.113.6"], None),
    ("destination-translation translated-address 10.20.2.10 translated-port 8080", "", [], "10.20.2.10:8080"),
])  # fmt: skip
def test_nat_rules_in_one_command(tail: str, kind: str, addresses: List[str], extra: object) -> None:
    text = f"set rulebase nat rules n1 from trust to untrust source any destination any service any {tail}\n"
    nat = parse_panos.parse(text.encode(), Report()).nat_rules[0]
    assert nat.service == "any" and not nat.unsupported
    if kind:
        assert nat.source_translation is not None and nat.source_translation.kind.value == kind
        assert nat.source_translation.addresses == addresses
        if kind == "static":
            assert nat.source_translation.bidirectional is extra
        if kind == "interface":
            assert nat.source_translation.interface == extra
    else:
        assert nat.destination_translation is not None
        assert f"{nat.destination_translation.address}:{nat.destination_translation.port}" == extra


def test_pre_and_post_rulebases_without_a_vsys_and_a_relative_edit_level() -> None:
    text = RULE_1 + "\nset pre-rulebase security rules pr from any to any source any destination any application any service any action deny\n"
    assert [r.name for r in parse_panos.parse(text.encode(), Report()).rules] == ["pr", "r1"]
    report = Report()
    parse_panos.parse(("[edit vsys vsys2]\nadmin@fw# show\n" + RULE_1 + "\n").encode(), report)
    note = next(n for n in report.notes if n.code == "SET_COMMANDS_NOT_READ")
    assert note.message.endswith("[edit vsys vsys2] (1)")


def test_a_dynamic_filter_with_a_backslash_comes_back_as_it_was() -> None:
    text = "set address-group dg dynamic filter \"'dom\\srv' and 'lab'\"\n" + RULE_1 + "\n"
    policy = parse_panos.parse(text.encode(), Report())
    assert policy.address_groups["dg"].dynamic_filter == "'dom\\srv' and 'lab'"
    written = cli.convert(policy, "panos", Report())
    assert "'dom\\srv' and 'lab'" in written and "\\\\" not in written
