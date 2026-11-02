# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""LANCOM R&S Unified Firewall: answers of its REST API read, a script for that API written, and packets through both.

What the firewall decides is worked out by ``Desktop`` below, from the answers of the API or from the calls of a script,
and shares no code with fwshift's parser and emitter. It is written from the same reading of LANCOM's documentation
(DEVELOPMENT.md): a connection between two desktop objects lets through its services in their directions, an object
takes its addresses at its interface only (``any``: at every interface), and what no connection allows is blocked.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import shutil
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import ZONES, Packet, _entry_matches, _member_matches, model_allows, random_model, random_packet
from tools.make_lancomuf_sample import answers, connection, entry, group, host, internet, iprange, member, network
from tools.make_lancomuf_sample import rule, sample, service, vpngroup

from fwshift import cli, transform
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.model import DestNat, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import lancomuf as parse_lancomuf
from fwshift.report import Report

Json = Dict[str, Any]
_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "gre": 47, "esp": 50, "ah": 51, "igmp": 2, "ospf": 89, "vrrp": 112}


# -- the judge -----------------------------------------------------------------------------------------


class Desktop:
    """What a Unified Firewall lets through, from the objects, services and connections it holds (IPv4 only)."""

    def __init__(self, objects: Dict[str, Json], services: Dict[str, Json], connections: List[Json],
                 netconns: Optional[Dict[str, str]] = None) -> None:  # fmt: skip
        self.objects, self.services, self.connections = objects, services, connections
        self.netconns = netconns or {}

    @classmethod
    def of_answers(cls, data: Json) -> "Desktop":
        objects: Dict[str, Json] = {}
        services: Dict[str, Json] = {}
        for key, items in data.items():
            if key in ("fwshift", "desktop-connections", "network-connections", "protocols"):
                continue
            for item in items:
                (services if "services" in item else objects)[item["id"]] = item
        netconns = {n["id"]: n["name"] for n in data.get("network-connections", [])}
        return cls(objects, services, list(data.get("desktop-connections", [])), netconns)

    @classmethod
    def of_script(cls, text: str) -> "Desktop":
        """Replay the calls of a script: every id it uses was given by a call before, every name it creates is new."""
        ids: Dict[str, str] = {}
        objects: Dict[str, Json] = {}
        services: Dict[str, Json] = {}
        connections: List[Json] = []
        names = set()
        checked = {m.group(1): set(m.group(2).split("\n")) for m in
                   re.finditer(r"^names_free (\S+) <<'FWSHIFT_NAMES'\n(.*?)\nFWSHIFT_NAMES$", text, re.S | re.M)}  # fmt: skip
        for entity, var, body in re.findall(r"^create (\S+) (\S+) <<FWSHIFT_JSON\n(.*?)\nFWSHIFT_JSON$", text, re.S | re.M):
            def known(match: "re.Match[str]") -> str:
                assert match.group(1) in ids, f"{match.group(1)} is used before a call gave it"
                return ids[match.group(1)]

            assert "$" not in re.sub(r"\$\{(ID_\d+)\}", "", body), body
            item = json.loads(re.sub(r"\$\{(ID_\d+)\}", known, body))
            new = str(uuid.uuid4())
            ids[var] = new
            if entity == "networks":
                assert item["name"].lower() not in names and item["name"] in checked["networks"]
                names.add(item["name"].lower())
                assert set(item) <= {"name", "type", "icon", "interface", "ipv4", "description", "tags", "color", "top", "left",
                                     "layer", "nologin", "exemptFromIdps", "exemptFromAv"}  # fmt: skip
                ipaddress.ip_network(item["ipv4"])  # a prefix, strict
                objects[new] = dict(item, id=new)
            elif entity == "userdefined-services":
                assert item["name"].lower() not in names and item["name"] in checked["userdefined-services"]
                names.add(item["name"].lower())
                for found in item["services"]:
                    assert found["protocol"] in _NUMBERS, found
                    if found["protocol"] in ("tcp", "udp"):
                        assert 1 <= found["portfrom"] <= found["portto"] <= 65535
                    else:
                        assert "portfrom" not in found
                services[new] = dict(item, id=new)
            elif entity == "desktop-connections":
                assert item["obja"] in objects and item["objb"] in objects and item["obja"] != item["objb"]
                pair = {item["obja"], item["objb"]}
                assert all({c["obja"], c["objb"]} != pair for c in connections), "two connections between the same objects"
                for found in item["rules"]:
                    assert found["uniqueId"] in services
                    assert found["action"] in ("leftToRight", "rightToLeft", "both")
                    assert found["natactive"] in ("none", "left", "right", "both")
                connections.append(item)
            else:
                raise AssertionError(f"a call to {entity}")
        return cls(objects, services, connections)

    # -- objects

    def _where(self, ident: str, depth: int = 0) -> List[Tuple[str, Tuple[int, int]]]:
        """(interface, (first, last)) of every address of an object; interface "any" for every interface."""
        assert depth < 10
        item = self.objects[ident]
        kind = item.get("type")
        if kind in ("host", "network"):
            net = ipaddress.ip_network(item["ipv4"], strict=False)
            return [(item["interface"], (int(net.network_address), int(net.broadcast_address)))]
        if kind == "iprange":
            return [(item["interface"], (int(ipaddress.ip_address(item["start"])), int(ipaddress.ip_address(item["end"]))))]
        if kind == "hostgroup":
            out: List[Tuple[str, Tuple[int, int]]] = []
            for found in item["hostgroupobjectitems"]:
                if isinstance(found, str):
                    out += self._where(found, depth + 1)
                else:
                    net = ipaddress.ip_network(found["ipv4"], strict=False)
                    out.append((found["interface"], (int(net.network_address), int(net.broadcast_address))))
            return out
        if kind == "internet":
            return [(self.netconns.get(c, c), (0, 2**32 - 1)) for c in item["connections"]]
        return []  # a VPN, user or the firewall itself: nothing forwarded is decided here

    def _holds(self, ident: str, interface: str, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        if ip.version != 4:
            return False
        return any((where in (interface, "any")) and low <= int(ip) <= high for where, (low, high) in self._where(ident))

    # -- services

    def _service_matches(self, ident: str, pkt: Packet, depth: int = 0) -> bool:
        assert depth < 10
        for found in self.services[ident]["services"]:
            if isinstance(found, str):
                if self._service_matches(found, pkt, depth + 1):
                    return True
                continue
            number = _NUMBERS[found["protocol"]] if not str(found["protocol"]).isdigit() else int(found["protocol"])
            proto = {"tcp": 6, "udp": 17, "icmp": 1}.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
            if number != proto:
                continue
            if number in (6, 17):
                low, high = found["portfrom"], found.get("portto") or found["portfrom"]
                if not low <= pkt.dport <= high:
                    continue
            return True
        return False

    def allows(self, pkt: Packet) -> bool:
        for conn in self.connections:
            a, b = conn["obja"], conn["objb"]
            if a not in self.objects or b not in self.objects:
                continue
            for found in conn["rules"]:
                if not found.get("timeranges"):
                    continue  # Always Off
                if found["uniqueId"] not in self.services or not self._service_matches(found["uniqueId"], pkt):
                    continue
                ways = {"leftToRight": [(a, b)], "rightToLeft": [(b, a)], "both": [(a, b), (b, a)]}[found["action"]]
                for src, dst in ways:
                    if self._holds(src, pkt.in_if, pkt.src) and self._holds(dst, pkt.out_if, pkt.dst):
                        return True
        return False


# -- a firewall made up at random ------------------------------------------------------------------------


def _i(number: int) -> str:
    return f"0e5f1a2b-0000-4000-8000-{number:012d}"


OBJECTS = {
    "hosts": [host(1, "h-a", "eth0", "10.0.0.17"), host(2, "h-b", "eth1", "10.0.2.34"), host(3, "h-c", "eth2", "10.0.4.51")],
    "networks": [network(10, "n0", "eth0", "10.0.0.0/24"), network(11, "n1", "eth1", "10.0.1.0/24"),
                 network(12, "n2", "eth2", "10.0.3.0/24"), network(13, "half", "eth1", "10.0.1.128/25")],
    "ipranges": [iprange(20, "span", "eth1", "10.0.2.100", "10.0.3.50"), iprange(21, "roam", "any", "10.0.0.0", "10.0.4.255")],
    "hostgroups": [group(30, "both", [_i(10), _i(12)]), group(31, "inline", [member("x", "eth0", "10.0.0.34"),
                                                                              member("y", "eth2", "10.0.4.0/25")])],
    "internet": [internet(40, "inet", ["eth2"])],
}  # fmt: skip
OBJECT_IDS = [o["id"] for items in OBJECTS.values() for o in items]
SERVICES = {
    "predefined-services": [service("p.web", "p.web", [entry("tcp", 80), entry("tcp", 443)], False),
                            service("p.dns", "p.dns", [entry("tcp", 53), entry("udp", 53)], False),
                            service("p.ping", "p.ping", [entry("icmp")], False)],
    "userdefined-services": [service(_i(70), "alt", [entry("tcp", 8000, 8010), entry("tcp", 9000)]),
                             service(_i(71), "gre", [entry("gre")])],
    "servicegroups": [service(_i(80), "mix", ["p.web", _i(71)])],
}  # fmt: skip
SERVICE_IDS = ["p.web", "p.dns", "p.ping", _i(70), _i(71), _i(80)]


def random_answers(rng: random.Random) -> Json:
    connections: List[Json] = []
    pairs = set()
    for index in range(rng.randint(3, 10)):
        a, b = rng.sample(OBJECT_IDS, 2)
        if frozenset((a, b)) in pairs:
            continue
        pairs.add(frozenset((a, b)))
        rules = [rule(rng.choice(SERVICE_IDS), action=rng.choice(["leftToRight", "leftToRight", "rightToLeft", "both"]),
                      times=[] if rng.random() < 0.1 else None) for _ in range(rng.randint(1, 3))]  # fmt: skip
        connections.append(connection(index, a, b, rules))
    return answers(OBJECTS, SERVICES, connections)


def packets(rng: random.Random, count: int) -> List[Packet]:
    out = []
    for index in range(count):
        pkt = random_packet(rng, 6 if index % 10 == 0 else 4)
        if pkt.proto == "icmp6":
            pkt.proto = "icmp"
        out.append(pkt)
    return out


def parse(data: Json) -> Tuple[Policy, Report]:
    report = Report()
    return parse_lancomuf.parse(json.dumps(data).encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


# -- reading ----------------------------------------------------------------------------------------------


def test_parsed_answers_decide_like_the_firewall() -> None:
    """Hosts, networks, ranges at an interface or at any, groups by reference and inline at several interfaces, the
    Internet, services of several kinds, groups of services, every direction, rules switched off: the model decides as
    the desktop would."""
    allowed = compared = 0
    for seed in range(80):
        rng = random.Random(seed)
        data = random_answers(rng)
        judge = Desktop.of_answers(data)
        p, _ = parse(data)
        assert not [r.name for r in p.rules if r.unsupported], seed
        for pkt in packets(rng, 300):
            expected = judge.allows(pkt)
            compared += 1
            allowed += expected
            assert model_allows(p, pkt) == expected, (seed, pkt)
    assert compared // 50 < allowed < compared // 2, (allowed, compared)


def test_the_sample_is_read_as_saved() -> None:
    p, report = parse(json.loads((DATA / "lancomuf_sample.json").read_text(encoding="utf-8")))
    assert json.loads((DATA / "lancomuf_sample.json").read_text(encoding="utf-8")) == sample()  # the generator wrote it
    by_name = {r.name: r for r in p.rules}
    web = by_name["LAN to Internet - internet.http"]
    assert (web.src_zones, web.sources, web.dst_zones, web.destinations) == (["eth1"], ["LAN"], ["WAN"], ["Internet"])
    assert web.action == Action.ALLOW and web.log_end and web.enabled
    assert p.addresses["Internet"].value == "0.0.0.0/0"  # every address behind the connection WAN (resolved by its id)
    assert sorted(p.zones) == ["WAN", "eth1", "eth2", "eth3", "eth4"]
    # A direction of its own, and both directions.
    assert "Internet to Webserver - internet.https" in by_name
    assert "Admin-PCs to Servers - remote.rdp" in by_name and "Servers to Admin-PCs - remote.rdp" in by_name
    assert "Servers to Admin-PCs - standard.ssh" not in by_name
    # A group at two interfaces: a rule per interface.
    split = [r for r in p.rules if r.name.startswith("Jump-Hosts to OT-Cell")]
    assert [(r.src_zones, r.sources) for r in split] == [(["eth1"], ["Jump-Hosts (eth1)"]), (["eth3"], ["Jump-Hosts (eth3)"])]
    assert all("INTERFACE_SPLIT" in codes(report, "rule", r.origin) for r in split)
    # An IP range at any interface.
    assert by_name["Monitoring to OT-Cell - standard.ping"].src_zones == [ANY]
    assert not by_name["Monitoring to OT-Cell - standard.ping"].enabled  # no time range: Always Off
    assert "Mon 06:00:00 - Mon 22:00:00" in by_name["HMI to OT-Cell - OPC-UA"].schedule
    # Services.
    assert p.service_groups["Web"].members == ["internet.http", "internet.https"]
    assert p.services["vpn.ipsec"].entries[2] == ServiceEntry(Protocol.IP, ip_protocol=50)
    assert p.services["OPC-UA"].entries == [ServiceEntry(Protocol.TCP, "4840-4843")]
    assert p.services["Legacy-App"].unsupported
    assert by_name["LAN to Mailserver - internet.smtp"].handling["proxy"]
    # What is not read is not any.
    assert by_name["DMZ to Internet - Legacy-App"].unsupported
    assert "not a direction" in by_name["DMZ to Internet - standard.ssh"].unsupported[0]
    assert by_name["Branch Sites to LAN - remote.rdp"].unsupported
    assert by_name["LAN to Lab-v6 - internet.http"].unsupported and p.addresses["Lab-v6"].kind == AddressKind.UNSUPPORTED
    assert by_name["Printer to DMZ - internet.http"].unsupported
    assert report.item("rule", "LAN to Firewall - traffic to the firewall").skipped
    # NAT: masquerading of a service, in the direction it is allowed.
    nat = {n.name: n for n in p.nat_rules}
    assert set(nat) == {f"LAN to Internet - {s} (NAT)" for s in ("internet.http", "internet.https", "standard.dns", "standard.ping")} | \
        {"DMZ to Internet - GRE-Tunnel (NAT)"}  # fmt: skip
    assert nat["DMZ to Internet - GRE-Tunnel (NAT)"].source_translation == SourceNat(SnatKind.INTERFACE, interface="WAN")
    assert "DMZ_NOT_READ" in codes(report, "rule", "Internet to Webserver - internet.https")
    assert "CONNECTION_NAT_NOT_READ" in codes(report, "rule", "LAN to Mailserver - internet.smtp")
    assert {"LANCOM_UF_FORMAT", "OBJECTS_MISSING", "CONNECTION_KEYS_NOT_READ", "VPN_USER_OBJECTS", "MASQUERADING_READ"} <= set(codes(report))


def _one(objects: Dict[str, List[Json]], rules: List[Json], a: str = _i(10), b: str = _i(11), **extra: Any) -> Tuple[Policy, Report]:
    return parse(answers(objects, SERVICES, [connection(1, a, b, rules, **extra)]))


def test_what_is_not_there_or_not_known_is_not_any() -> None:
    plain = {"networks": OBJECTS["networks"]}
    for bad in (network(10, "n0", "eth0", "10.0.0.0/24", ipv6="2001:db8::/64"), network(10, "n0", "", "10.0.0.0/24"),
                network(10, "n0", "eth0", "2001:db8::/64"), network(10, "n0", "eth0", "ten")):  # fmt: skip
        p, _ = _one({"networks": [bad] + OBJECTS["networks"][1:]}, [rule("p.web")])
        assert p.rules[0].unsupported, bad
    for raw in (rule("p.web", action="drop"), rule("p.web", action="block"), rule("p.web", times=None, extra=1),
                rule("p.web", log="yes"), rule("nothing"), {**rule("p.web"), "timeranges": None},
                rule("p.web", times=[{"repeattype": "once", "starttime": "00:00", "endtime": "01:00", "startweekday": 0, "endweekday": 0}])):  # fmt: skip
        p, report = _one(plain, [raw])
        assert all(r.unsupported for r in p.rules), raw
    p, report = _one(plain, [rule("p.web")], b=_i(999))
    assert p.rules[0].unsupported and "OBJECTS_MISSING" in codes(report)
    p, report = _one(plain, [rule(_i(998))])
    assert p.rules[0].unsupported and "OBJECTS_MISSING" in codes(report)


def test_services_that_cannot_be_read() -> None:
    for entries in ([entry("tcp")], [entry("tcp", 0)], [entry("tcp", 90, 80)], [entry("gre", 1)], [entry("ipx")],
                    [entry("tcp", 80, sourceportfrom=1024)], [], [_i(997)]):  # fmt: skip
        services = {"userdefined-services": [service(_i(70), "x", entries)]}
        p, _ = parse(answers({"networks": OBJECTS["networks"]}, services, [connection(1, _i(10), _i(11), [rule(_i(70))])]))
        assert p.rules[0].unsupported, entries
    services = {"userdefined-services": [service(_i(70), "x", [entry("47"), entry("Mine"), entry("UDP", "5000", "")])],
                "protocols": [{"id": "p-mine", "name": "Mine", "number": 253}]}
    p, _ = parse(answers({"networks": OBJECTS["networks"]}, services, [connection(1, _i(10), _i(11), [rule(_i(70))])]))
    assert p.services["x"].entries == [ServiceEntry(Protocol.IP, ip_protocol=47), ServiceEntry(Protocol.IP, ip_protocol=253),
                                       ServiceEntry(Protocol.UDP, "5000")]  # fmt: skip


def test_nat_settings() -> None:
    plain = {"networks": OBJECTS["networks"]}
    p, _ = _one(plain, [rule("p.web", action="both", nat="right")])
    assert [(n.sources, n.destinations) for n in p.nat_rules] == [(["n1"], ["n0"])]
    p, _ = _one(plain, [rule("p.web", action="leftToRight", nat="right")])
    assert not p.nat_rules  # masquerading for a direction no rule allows translates nothing
    p, report = _one(plain, [rule("p.web", nat="sideways")])
    assert not p.nat_rules and "NAT_NOT_READ" in codes(report, "rule", p.rules[0].origin)
    p, report = _one(plain, [rule("p.web", nat="left", use_connection=True)])
    assert not p.nat_rules and "CONNECTION_NAT_NOT_READ" in codes(report, "rule", p.rules[0].origin)


def test_vpn_user_and_firewall_objects() -> None:
    objects = {"networks": OBJECTS["networks"], "vpngroups": [vpngroup(50, "vpn")],
               "firewall": [{"id": _i(60), "name": "Firewall", "type": "firewall"}]}  # fmt: skip
    p, report = parse(answers(objects, SERVICES, [connection(1, _i(50), _i(10), [rule("p.web")]),
                                                  connection(2, _i(10), _i(60), [rule("p.web")])]))  # fmt: skip
    assert len(p.rules) == 1 and p.rules[0].unsupported
    assert "FIREWALL_TRAFFIC" in codes(report, "rule", "n0 to Firewall - traffic to the firewall")


@pytest.mark.parametrize("text,message", [
    ("", "the input is empty"),
    ("{", "not valid JSON"),
    ('{"fwshift": "lancom-uf"}', "no desktop objects and no desktop connections"),
    ('{"networks": [{"id": "1", "type": "network"}]}', "a desktop object without a name"),
    ('{"networks": [{"id": "1", "name": "a"}, {"id": "1", "name": "b"}]}', "is in the input twice"),
    ('{"desktop-connections": [{"obja": "1", "objb": "2", "rules": 5}]}', "are not a list"),
    ('{"desktop-connections": [{"obja": "1", "objb": "2", "rules": [5]}]}', "is not a JSON object"),
])  # fmt: skip
def test_malformed_input_ends_in_an_error_that_says_why(text: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        parse_lancomuf.parse(text.encode(), Report())


def test_detection_names_the_sample_and_no_other() -> None:
    assert cli.detect_format((DATA / "lancomuf_sample.json").read_bytes()) == "lancom-uf"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != "lancomuf_sample.json":
            assert not parse_lancomuf.looks_like_lancomuf(path.read_bytes()), path.name
    assert cli.detect_format(json.dumps({"desktop-connections": []}).encode()) == "lancom-uf"


# -- writing ----------------------------------------------------------------------------------------------


def emit(p: Policy, **options: Any) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(p, "lancom-uf", report, Options(**options)), report


_LOSS = {"LANCOM_PART_NOT_WRITTEN", "DENY_ZONE_WIDENED", "PROFILES_NOT_CONVERTED"}


def _first_match(p: Policy, pkt: Packet) -> Optional[Rule]:
    """The rule of the model that decides a packet (as test_iptables.model_verdict does)."""
    for r in p.rules:
        if not r.enabled or r.unsupported or r.users != [ANY]:
            continue
        zone_ok = (ANY in r.src_zones or pkt.in_if in r.src_zones) and (ANY in r.dst_zones or pkt.out_if in r.dst_zones)
        if r.scope == RuleScope.INTRAZONE:
            zone_ok = pkt.in_if == pkt.out_if and (ANY in r.src_zones or pkt.in_if in r.src_zones)
        elif r.scope == RuleScope.INTERZONE:
            zone_ok = zone_ok and pkt.in_if != pkt.out_if
        if not zone_ok:
            continue
        if any(_member_matches(p, m, pkt.src) for m in r.sources) == r.negate_source:
            continue
        if any(_member_matches(p, m, pkt.dst) for m in r.destinations) == r.negate_destination:
            continue
        entries = [e for s in r.services for e in (transform.flatten_services(p, s) or [])] if r.services != [ANY] else []
        if (r.services == [ANY] or any(_entry_matches(e, pkt) for e in entries)) == r.negate_service:
            continue
        return r
    return None


@pytest.mark.parametrize("seed", range(60))
def test_emitted_script_never_allows_more_and_loses_only_what_it_says(seed: int) -> None:
    """Random models (negation, groups, ranges, rule types, blocking rules above allowing ones, ICMP types, source ports,
    IPv6): what the script allows the model allows, and what the model allows by a rule without a finding of loss, the
    script allows too."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {name: Zone(name) for name in ZONES}
    text, report = emit(model)
    judge = Desktop.of_script(text)
    # Blocking rules the script cannot take out of the others are reported (REVIEW) and are not enforced.
    unenforced = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    effective = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                       services=model.services, service_groups=model.service_groups,
                       rules=[r for r in model.rules if r.origin not in unenforced])  # fmt: skip
    for r in model.rules:
        if r.action != Action.ALLOW and "RULE_TYPE" in codes(report, "rule", r.origin):
            r.scope = RuleScope.UNIVERSAL  # taken out for every pair of zones: blocks more, said so (APPROX)
    for _ in range(400):
        pkt = random_packet(rng, 4)
        allowed = judge.allows(pkt)
        if allowed:
            assert model_allows(effective, pkt), (seed, pkt)
        deciding = _first_match(effective, pkt)
        if deciding is not None and deciding.action == Action.ALLOW:
            item = report.item("rule", deciding.origin)
            lossy = item.skipped or {f.code for f in item.findings} & _LOSS
            if not lossy:
                assert allowed, (seed, pkt, deciding.name, [f.code for f in item.findings])


@pytest.mark.parametrize("seed", range(25))
def test_round_trip_keeps_every_decision(seed: int) -> None:
    rng = random.Random(7000 + seed)
    data = random_answers(rng)
    before = Desktop.of_answers(data)
    report = Report()
    after = Desktop.of_script(cli.convert(parse(data)[0], "lancom-uf", report))
    for pkt in packets(rng, 300):
        assert after.allows(pkt) == before.allows(pkt), (seed, pkt)


def small(**changes: Any) -> Policy:
    p = Policy(vendor="test")
    p.zones = {"inside": Zone("inside"), "outside": Zone("outside")}
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.1.0.0/16")
    p.addresses["srv"] = Address("srv", AddressKind.NETWORK, "192.0.2.10/32")
    p.addresses["www"] = Address("www", AddressKind.FQDN, "www.example.com")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["echo"] = Service("echo", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    for key, value in changes.items():
        setattr(p, key, value)
    return p


def bodies(text: str, entity: str) -> List[Json]:
    return [json.loads(body) for found, _, body in re.findall(r"^create (\S+) (\S+) <<FWSHIFT_JSON\n(.*?)\nFWSHIFT_JSON$", text, re.S | re.M)
            if found == entity]


def test_objects_are_named_after_the_model_and_bound_to_interfaces() -> None:
    p = small(rules=[Rule(name="web", origin="web", src_zones=["inside"], dst_zones=["outside"], sources=["lan"],
                          destinations=["srv"], services=["web"])])  # fmt: skip
    text, report = emit(p, interface_map={"outside": "eth2"})
    nets = {n["name"]: (n["interface"], n["ipv4"]) for n in bodies(text, "networks")}
    assert nets == {"fws-lan": ("inside", "10.1.0.0/16"), "fws-srv": ("eth2", "192.0.2.10/32")}
    assert bodies(text, "userdefined-services")[0]["services"] == [{"protocol": "tcp", "noproxy": True, "portfrom": 80, "portto": 80},
                                                                   {"protocol": "tcp", "noproxy": True, "portfrom": 443, "portto": 443}]  # fmt: skip
    conn = bodies(text, "desktop-connections")[0]
    assert [r["action"] for r in conn["rules"]] == ["leftToRight"]
    assert "INTERFACES_REQUIRED" in codes(report) and "inside" in report.notes[-1].message
    assert "LANCOM_UF_LOAD" in codes(report)
    text, _ = emit(p, object_prefix="mig_")
    assert {n["name"] for n in bodies(text, "networks")} == {"mig_lan", "mig_srv"}


def test_blocking_rules_are_taken_out_of_the_rules_below() -> None:
    p = small(rules=[Rule(name="no-host", origin="no-host", destinations=["10.1.2.3"], action=Action.DROP),
                     Rule(name="any-to-lan", origin="any-to-lan", src_zones=["outside"], dst_zones=["inside"], destinations=["lan"],
                          services=["web"])])  # fmt: skip
    text, report = emit(p)
    cidrs = sorted(n["ipv4"] for n in bodies(text, "networks") if n["interface"] == "inside")
    assert "10.1.2.3/32" not in cidrs and "10.1.2.2/32" in cidrs and "10.1.2.4/30" in cidrs
    assert "DENY_SUBTRACTED" in codes(report, "rule", "any-to-lan")
    # A blocking rule of one zone above an allowing one for every zone: taken out everywhere, the rule allows less.
    p = small(rules=[Rule(name="b", origin="b", src_zones=["outside"], action=Action.DROP, services=["web"]),
                     Rule(name="a", origin="a", services=["web"])])  # fmt: skip
    text, report = emit(p)
    assert "DENY_ZONE_WIDENED" in codes(report, "rule", "a") and not bodies(text, "desktop-connections")
    # A blocking rule that cannot be read is not enforced, and said so.
    p = small(rules=[Rule(name="b", origin="b", destinations=["www"], action=Action.DROP), Rule(name="a", origin="a", services=["web"])])
    text, report = emit(p)
    assert report.item("rule", "b").disabled and bodies(text, "desktop-connections")


def test_what_the_desktop_cannot_say_is_left_out_and_reported() -> None:
    p = small(rules=[Rule(name="ping", origin="ping", services=["echo"]),
                     Rule(name="six", origin="six", destinations=["2001:db8::/64"]),
                     Rule(name="dns", origin="dns", destinations=["www"]),
                     Rule(name="later", origin="later", schedule="workdays"),
                     Rule(name="off", origin="off", enabled=False),
                     Rule(name="every", origin="every", sources=["lan"], destinations=["srv"])])  # fmt: skip
    text, report = emit(p)
    assert report.item("rule", "ping").skipped and "LANCOM_PART_NOT_WRITTEN" in codes(report, "rule", "ping")
    assert report.item("rule", "six").skipped and "IPV6_NOT_WRITTEN" in codes(report, "rule", "six")
    assert report.item("rule", "dns").skipped and report.item("rule", "later").skipped
    assert "rule off: disabled in the source, not written" in text
    every = bodies(text, "userdefined-services")[0]["services"]
    assert {e["protocol"] for e in every} == set(_NUMBERS) and {"APPROX"} <= {
        f.severity.name for f in report.item("rule", "every").findings}  # every protocol: those with a name


def test_masquerading_is_written_where_a_nat_rule_translates_a_connection_whole() -> None:
    nat = NatRule(name="hide", origin="hide", src_zones=["inside"], dst_zones=["outside"], sources=["lan"],
                  source_translation=SourceNat(SnatKind.INTERFACE, interface="outside"))  # fmt: skip
    dnat = NatRule(name="pub", origin="pub", destinations=["192.0.2.80"], destination_translation=DestNat("10.1.0.80"))
    p = small(rules=[Rule(name="out", origin="out", src_zones=["inside"], dst_zones=["outside"], sources=["lan"], services=["web"]),
                     Rule(name="in", origin="in", src_zones=["outside"], dst_zones=["inside"], destinations=["lan"], services=["web"])],
              nat_rules=[nat, dnat])  # fmt: skip
    text, report = emit(p)
    # Both rules join the same two objects with the same service: one rule of the connection, both ways, masqueraded
    # from left (the LAN) to right only.
    (conn,) = bodies(text, "desktop-connections")
    assert [(r["action"], r["natactive"]) for r in conn["rules"]] == [("both", "left")]
    assert report.item("nat", "hide").emitted_as and report.item("nat", "pub").skipped


def test_schedules_of_a_lancom_source_are_kept() -> None:
    weekdays = [{"repeattype": "weekly", "starttime": "07:00:00", "endtime": "19:00:00", "startweekday": d, "endweekday": d}
                for d in range(5)]  # fmt: skip
    p, _ = _one({"networks": OBJECTS["networks"]}, [rule("p.web", times=weekdays)])
    text, report = emit(p)
    assert bodies(text, "desktop-connections")[0]["rules"][0]["timeranges"] == weekdays
    assert "SCHEDULE_KEPT" in codes(report, "rule", p.rules[0].origin)


def test_interface_map_is_checked() -> None:
    with pytest.raises(FwshiftError, match="--interface-map"):
        emit(small(), interface_map={"inside": "eth 1; rm"})


POSIX_SHELL = pytest.mark.skipif(os.name == "nt" or shutil.which("sh") is None or shutil.which("curl") is None
                                 or shutil.which("python3") is None, reason="needs a POSIX shell, curl and python3")  # fmt: skip


class _Api(BaseHTTPRequestHandler):
    """A made-up REST API of a Unified Firewall: lists what it holds, and creates what is posted with an id of its own."""

    store: Dict[str, List[Json]] = {}
    calls: List[Tuple[str, str]] = []
    token = ""

    def log_message(self, *args: Any) -> None:
        pass

    def _answer(self, code: int, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.headers.get("Authorization") != f"Bearer {self.token}":
            return self._answer(401, {"error": "no token"})
        entity = self.path.split("/model/", 1)[1]
        self.calls.append(("GET", entity))
        self._answer(200, {"data": self.store.get(entity, [])})

    def do_POST(self) -> None:
        if self.headers.get("Authorization") != f"Bearer {self.token}":
            return self._answer(401, {"error": "no token"})
        entity = self.path.split("/model/", 1)[1]
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.calls.append(("POST", entity))
        if entity == "desktop-connections" and body["objb"] == "refuse-me":
            return self._answer(400, {"error": "refused"})
        item = dict(body, id=str(uuid.uuid4()))
        self.store.setdefault(entity, []).append(item)
        self._answer(201, item)


def _serve() -> Tuple[ThreadingHTTPServer, str]:
    _Api.store, _Api.calls, _Api.token = {}, [], "t0ken"
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/api"


@POSIX_SHELL
def test_the_script_creates_through_the_api_what_the_model_allows() -> None:
    """The sample, converted and run against a made-up API: what the API then holds decides as the script says, every
    reference is an id the API gave, and nothing is deleted."""
    p, _ = parse(sample())
    text, _ = emit(p)
    server, url = _serve()
    try:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "UF_API": url, "UF_TOKEN": "t0ken", "NO_PROXY": "127.0.0.1",
               "no_proxy": "127.0.0.1"}  # fmt: skip
        result = subprocess.run(["sh", "-c", text, "fwshift"], env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        assert {method for method, _ in _Api.calls} == {"GET", "POST"}
        held = Desktop(
            {o["id"]: o for o in _Api.store["networks"]}, {s["id"]: s for s in _Api.store["userdefined-services"]},
            _Api.store["desktop-connections"],
        )  # fmt: skip
        expected = Desktop.of_script(text)
        rng = random.Random(5)
        for _ in range(500):
            pkt = random_packet(rng, 4)
            pkt.src = f"{rng.choice(['192.168.10', '172.16.20', '10.30.0', '198.51.100'])}.{rng.choice([5, 10, 25, 50, 210])}"
            pkt.dst = f"{rng.choice(['192.168.10', '172.16.20', '10.30.0', '203.0.113'])}.{rng.choice([5, 10, 25, 50])}"
            pkt.in_if, pkt.out_if = rng.choice(["eth1", "eth2", "eth3", "WAN"]), rng.choice(["eth1", "eth2", "eth3", "WAN"])
            pkt.dport = rng.choice([22, 25, 53, 80, 443, 502, 3389, 4841])
            assert held.allows(pkt) == expected.allows(pkt), pkt
        # Run again: every name is taken now, and nothing more is created.
        before = len(_Api.calls)
        again = subprocess.run(["sh", "-c", text, "fwshift"], env=env, capture_output=True, text=True, timeout=120)
        assert again.returncode != 0 and "these names are taken" in again.stderr
        assert all(method == "GET" for method, _ in _Api.calls[before:])
    finally:
        server.shutdown()


@POSIX_SHELL
def test_the_script_runs_dry_and_refuses_to_run_without_an_address() -> None:
    p = small(rules=[Rule(name="it's \"quoted\" $HOME `x`", origin="q", sources=["lan"], services=["web"], description="a $HOME `x`")])
    text, _ = emit(p)
    result = subprocess.run(["sh", "-c", text, "fwshift"], env={"DRY_RUN": "1", "PATH": "/usr/bin:/bin"}, capture_output=True,
                            text=True, timeout=30)  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert "POST model/desktop-connections" in result.stdout and "dry-run-id-" in result.stdout
    missing = subprocess.run(["sh", "-c", text, "fwshift"], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=30)
    assert missing.returncode != 0 and "UF_API" in missing.stderr


def test_every_sample_converts_to_the_desktop() -> None:
    for path in sorted(DATA.glob("*_sample.*")):
        if path.suffix == ".log":
            continue  # (logs, not configurations)
        data = path.read_bytes()
        report = Report()
        policy = cli.load(data, cli.detect_format(data), report)
        text = cli.convert(policy, "lancom-uf", report)
        Desktop.of_script(text)  # every call is one the API takes, as far as the judge knows
        assert text.startswith("#!/bin/sh"), path.name
