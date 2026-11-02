# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Zscaler Internet Access (ZIA) Cloud Firewall: parser, emitter, and a judge of its own.

``Tenant`` is a made-up ZIA tenant, written from Zscaler's API reference and SDK: locations and predefined network
services it has, IP groups, network services and firewall filtering rules created by POST (a name once per kind, every
reference an id that exists, only the keys a rule of the API has, an order from 1 to one past the last rule, the
rule placed at its order and the others moved down). ``run_script`` replays the script the emitter writes against it,
call by call, the way sh would (an id is the answer of an earlier call); ``Tenant.decides`` judges a connection from a
location to the internet as ZIA does: rules in ascending order, first match, disabled rules skipped, the default rule
last. ``test_script_runs_against_a_fake_api`` runs the script itself with sh, jq and a fake curl. None of this shares
code with the parser or the emitter; it is written from the same reading of the documentation as the code it checks.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry, ServiceGroup
from fwshift.options import Options
from fwshift.parsers import zscaler as parse_zscaler
from fwshift.report import Report, Severity

RULE_KEYS = {"name", "order", "rank", "action", "state", "description", "locations", "locationGroups", "srcIps", "srcIpGroups",
             "destAddresses", "destIpGroups", "nwServices", "nwServiceGroups", "enableFullLogging"}  # fmt: skip
PREDEFINED = {"ICMP_ANY": {"proto": "icmp"}, "GRE_PROTOCOL": {"proto": "47"}, "ESP_PROTOCOL": {"proto": "50"},
              "TCP_ANY": {"destTcpPorts": []}, "UDP_ANY": {"destUdpPorts": []}, "DNS": {"destTcpPorts": [{"start": 53}], "destUdpPorts": [{"start": 53}]},
              "HTTP": {"destTcpPorts": [{"start": 80}]}, "HTTPS": {"destTcpPorts": [{"start": 443}]}, "SSH": {"destTcpPorts": [{"start": 22}]}}  # fmt: skip


def parse(document: Any, report: Optional[Report] = None) -> Policy:
    text = document if isinstance(document, str) else json.dumps(document)
    return parse_zscaler.parse(text.encode(), report or Report())


def codes(report: Report, origin: str) -> List[str]:
    return [f.code for f in report.item("rule", origin).findings]


def all_codes(report: Report) -> List[str]:
    return [n.code for n in report.notes] + [f.code for item in report.items.values() for f in item.findings]


# -- the made-up tenant ---------------------------------------------------------------------------------


class Tenant:
    def __init__(self, locations: List[str], default: str = "BLOCK_DROP") -> None:
        self.next_id = 1000
        self.objects: Dict[str, Dict[int, Dict[str, Any]]] = {"/locations": {}, "/networkServices": {}, "/ipSourceGroups": {},
                                                              "/ipDestinationGroups": {}, "/firewallFilteringRules": {}}  # fmt: skip
        for name in locations:
            self._add("/locations", {"name": name})
        for name, fields in PREDEFINED.items():
            self._add("/networkServices", dict(fields, name=name, type="PREDEFINED"))
        self.rules: List[int] = []  # ids, in order
        self.default = default

    def _add(self, path: str, body: Dict[str, Any]) -> int:
        self.next_id += 1
        self.objects[path][self.next_id] = dict(body, id=self.next_id)
        return self.next_id

    def find(self, path: str, name: str) -> Optional[int]:
        found = [i for i, o in self.objects[path].items() if o["name"] == name]
        return found[0] if found else None

    def create(self, path: str, body: Dict[str, Any]) -> int:
        assert path in ("/ipSourceGroups", "/ipDestinationGroups", "/networkServices", "/firewallFilteringRules"), path
        name = body.get("name")
        assert isinstance(name, str) and name and self.find(path, name) is None, (path, name)
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]*", name), name
        if path == "/ipSourceGroups":
            assert set(body) <= {"name", "ipAddresses", "description"} and body["ipAddresses"], body
            for value in body["ipAddresses"]:
                _interval(value)
        elif path == "/ipDestinationGroups":
            assert set(body) <= {"name", "type", "addresses", "description"} and body["addresses"], body
            assert body["type"] in ("DSTN_IP", "DSTN_FQDN")
            for value in body["addresses"]:
                assert body["type"] == "DSTN_FQDN" or _interval(value)
        elif path == "/networkServices":
            assert body.get("type") == "CUSTOM" and set(body) <= {"name", "type", "description", "srcTcpPorts", "destTcpPorts",
                                                                   "srcUdpPorts", "destUdpPorts"}, body  # fmt: skip
            assert body.get("destTcpPorts") or body.get("destUdpPorts"), body
            for key in ("srcTcpPorts", "destTcpPorts", "srcUdpPorts", "destUdpPorts"):
                for item in body.get(key, []):
                    assert set(item) <= {"start", "end"} and 1 <= item["start"] <= item.get("end", item["start"]) <= 65535
        else:
            assert set(body) <= RULE_KEYS, set(body) - RULE_KEYS
            assert len(name) <= 31, name
            assert body["action"] in ("ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP") and body["state"] in ("ENABLED", "DISABLED")
            assert isinstance(body["order"], int) and 1 <= body["order"] <= len(self.rules) + 1, body["order"]
            assert len(body.get("locations", [])) <= 8
            for key, path_of in (("locations", "/locations"), ("srcIpGroups", "/ipSourceGroups"), ("destIpGroups", "/ipDestinationGroups"),
                                 ("nwServices", "/networkServices")):  # fmt: skip
                for ref in body.get(key, []):
                    assert set(ref) == {"id"} and ref["id"] in self.objects[path_of], (key, ref)
            for value in body.get("srcIps", []):
                assert _interval(value)[0] == 4
            for value in body.get("destAddresses", []):
                assert re.fullmatch(r"[a-z0-9.-]+", value) or _interval(value)[0] == 4, value
        ident = self._add(path, body)
        if path == "/firewallFilteringRules":
            self.rules.insert(body["order"] - 1, ident)
        return ident

    # -- deciding -----------------------------------------------------------------------------------

    def _service(self, service: Dict[str, Any], pkt: Packet) -> bool:
        if "proto" in service:
            return pkt.proto == service["proto"]
        for word in ("Tcp", "Udp"):
            if pkt.proto != word.lower() or (f"dest{word}Ports" not in service and f"src{word}Ports" not in service):
                continue
            dst, src = service.get(f"dest{word}Ports", []), service.get(f"src{word}Ports", [])
            if (not dst or any(r["start"] <= pkt.dport <= r.get("end", r["start"]) for r in dst)) and \
                    (not src or any(r["start"] <= pkt.sport <= r.get("end", r["start"]) for r in src)):
                return True
        return False

    def matches(self, rule: Dict[str, Any], location: str, pkt: Packet) -> bool:
        if rule["state"] != "ENABLED":
            return False
        if rule.get("locations") and location not in [self.objects["/locations"][r["id"]]["name"] for r in rule["locations"]]:
            return False
        sources = list(rule.get("srcIps", [])) + [a for r in rule.get("srcIpGroups", []) for a in self.objects["/ipSourceGroups"][r["id"]]["ipAddresses"]]
        if sources and not any(_holds(a, pkt.src) for a in sources):
            return False
        destinations = list(rule.get("destAddresses", [])) + [a for r in rule.get("destIpGroups", [])
                                                             for a in self.objects["/ipDestinationGroups"][r["id"]]["addresses"]]  # fmt: skip
        if destinations and not any(_holds(a, pkt.dst) for a in destinations if _interval(a, strict=False)[0]):
            return False
        services = [self.objects["/networkServices"][r["id"]] for r in rule.get("nwServices", [])]
        return not services or any(self._service(s, pkt) for s in services)

    def decides(self, location: str, pkt: Packet) -> bool:
        for ident in self.rules:
            rule = self.objects["/firewallFilteringRules"][ident]
            if self.matches(rule, location, pkt):
                return rule["action"] == "ALLOW"
        return self.default == "ALLOW"


def _interval(text: str, strict: bool = True) -> Tuple[int, int, int]:
    try:
        if "-" in text:
            low, high = (ipaddress.ip_address(t) for t in text.split("-"))
            assert low.version == high.version and int(low) <= int(high)
            return (low.version, int(low), int(high))
        net = ipaddress.ip_network(text)  # (strict: no host bits)
        return (net.version, int(net.network_address), int(net.broadcast_address))
    except ValueError:
        if strict:
            raise
        return (0, 0, 0)


def _holds(text: str, address: str) -> bool:
    found = _interval(text, strict=False)
    probe = ipaddress.ip_address(address)
    return found[0] == probe.version and found[1] <= int(probe) <= found[2]


def run_script(text: str, tenant: Tenant) -> None:
    """Replay the emitted script: every id it uses is the answer of an earlier call."""
    ids: Dict[str, int] = {}
    lines = text.splitlines()
    index = 0
    body: Optional[str] = None
    while index < len(lines):
        line = lines[index]
        heredoc = re.fullmatch(r'cat > "\$OUT/(\d+)\.json" <<FWSHIFT_JSON', line)
        if heredoc:
            body = lines[index + 1]
            assert lines[index + 2] == "FWSHIFT_JSON"
            index += 3
            continue
        need = re.fullmatch(r"(ID_\d+)=\$\(need (/\w+) '([^']*)' \d+\)", line)
        create = re.fullmatch(r"(ID_\d+)=\$\(create (/\w+) '([^']*)' \"\$OUT/\d+\.json\" \d+\)", line)
        if need:
            found = tenant.find(need.group(2), need.group(3))
            assert found is not None, f"not on the tenant: {need.group(3)}"
            assert need.group(1) not in ids
            ids[need.group(1)] = found
        elif create:
            assert body is not None
            undefined = [v for v in re.findall(r"\$\{(ID_\d+)\}", body) if v not in ids]
            assert not undefined, undefined
            assert "$" not in re.sub(r"\$\{ID_\d+\}|\\\$", "", body) and "`" not in body.replace("\\`", "")
            resolved = re.sub(r"\$\{(ID_\d+)\}", lambda m: str(ids[m.group(1)]), body)
            resolved = re.sub(r"\\([\\$`])", r"\1", resolved)  # (what an unquoted here-document does)
            data = json.loads(resolved)
            assert data["name"] == create.group(3)
            ids[create.group(1)] = tenant.create(create.group(2), data)
            body = None
        index += 1


# -- the parser -----------------------------------------------------------------------------------------


def test_sample_is_read() -> None:
    p, report = load("zscaler_sample.json")
    assert p.vendor == "zscaler"
    assert list(p.zones) == ["HQ-Brussels", "Branch-Ghent", "HQ-Servers", "Guest-WiFi", "road-warrior", "internet"]
    names = [r.name for r in p.rules]
    # Ascending order; the two predefined rules of order 3 keep the order of the answer; the default rule is last.
    assert names[:6] == ["Allow DNS to resolvers", "Block SSH out", "Block malicious IPs and domains", "Office 365 One Click Rule",
                         "Partner app", "Branch web"]  # fmt: skip
    assert names[-1] == "Default Firewall Filtering Rule"
    assert all(r.dst_zones == ["internet"] for r in p.rules)
    rules = {r.name: r for r in p.rules}
    dns = rules["Allow DNS to resolvers"]
    assert dns.src_zones == ["HQ-Brussels"] and dns.sources == ["Engineering-Nets"] and dns.destinations == ["198.51.100.53"]
    assert dns.services == ["DNS"] and dns.tags == ["dns"] and not dns.unsupported
    assert p.address_groups["Engineering-Nets"].members == ["10.10.0.0/16", "10.20.1.1-10.20.1.50"]
    assert rules["Block SSH out"].action == Action.RESET_CLIENT
    assert rules["Block SSH out"].src_zones == ["HQ-Brussels", "Branch-Ghent", "HQ-Servers", "Guest-WiFi", "road-warrior"]
    assert rules["Block GRE and ESP"].action == Action.DENY
    assert rules["Default Firewall Filtering Rule"].action == Action.DROP
    assert rules["Default Firewall Filtering Rule"].source_ids["zscaler.default"] == "true"
    assert not rules["Office 365 One Click Rule"].enabled and not rules["Infra out"].enabled
    assert rules["Branch web"].src_zones == ["Branch-Ghent"] and rules["Branch web"].schedule == "Work hours"
    partner = rules["Partner app"]
    assert partner.sources == ["10.10.20.0/24", "Eng-v6"] and partner.destinations == ["Partner-Servers", "Partner-v6"]
    assert p.zone_networks == {"HQ-Servers": ["10.10.20.0/24"]}
    services = p.services
    assert services["App-8443"].entries == [ServiceEntry(Protocol.TCP, "8443,8000-8010")]
    assert services["Syslog-From-Highport"].entries == [ServiceEntry(Protocol.UDP, "514", "1024-65535")]
    assert services["DNS"].entries == [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")] and services["DNS"].builtin == "zscaler"
    assert services["TCP_ANY"].entries == [ServiceEntry(Protocol.TCP)]
    assert services["ICMP_ANY"].entries == [ServiceEntry(Protocol.ICMP)]
    assert services["GRE_PROTOCOL"].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    assert p.service_groups["Infra"].members == ["DNS", "NTP", "ICMP_ANY"]
    notes = {n.code: n for n in report.notes}
    assert notes["ZSCALER_OUTBOUND_ONLY"].severity == Severity.REVIEW
    assert "Guest-WiFi" in notes["ZSCALER_FIREWALL_OFF"].message
    assert "Ranked web" in notes["ZSCALER_RANK"].message


@pytest.mark.parametrize("rule,code", [
    ("Block malicious IPs and domains", "ZSCALER_CATEGORY"), ("Office 365 One Click Rule", "ZSCALER_APPLICATION"),
    ("Engineers to SaaS", "ZSCALER_IDENTITY"), ("Engineers to SaaS", "ZSCALER_FQDN"), ("No embargoed countries", "ZSCALER_COUNTRY"),
    ("Evaluate apps", "ZSCALER_EVAL_NWAPP"), ("Ranked web", "ZSCALER_FQDN"), ("Ghent and corporate", "ZSCALER_LOCATION_GROUP"),
    ("Allow DNS to resolvers", "ZSCALER_SUBLOCATION"),
])  # fmt: skip
def test_what_narrows_a_match_is_not_modelled(rule: str, code: str) -> None:
    p, report = load("zscaler_sample.json")
    found = next(r for r in p.rules if r.name == rule)
    assert code in codes(report, rule)
    assert found.unsupported or code == "ZSCALER_SUBLOCATION"


def rule_doc(**fields: Any) -> Dict[str, Any]:
    return dict({"id": 1, "name": "r", "order": 1, "rank": 7, "action": "ALLOW", "state": "ENABLED"}, **fields)


def test_answers_concatenated_or_in_an_array_are_told_apart() -> None:
    rules = [rule_doc(srcIpGroups=[{"id": 5, "name": "g"}], nwServices=[{"id": 7, "name": "s"}]),
             {"id": 2, "name": "Default Firewall Filtering Rule", "order": -1, "rank": 7, "action": "ALLOW", "state": "ENABLED", "defaultRule": True}]  # fmt: skip
    groups = [{"id": 5, "name": "g", "ipAddresses": ["192.0.2.0/24"]}]
    services = [{"id": 7, "name": "s", "destTcpPorts": [{"start": 8080}], "type": "CUSTOM"}]
    locations = [{"id": 9, "name": "site", "parentId": 0, "tz": "GMT"}]
    text = "\n".join(json.dumps(x) for x in (rules, groups, services, locations))
    for document in (text, json.dumps([rules, groups, services, locations])):
        p = parse(document)
        assert p.rules[0].sources == ["g"] and p.rules[0].services == ["s"] and p.rules[0].src_zones == ["site", "road-warrior"]
        assert p.rules[-1].action == Action.ALLOW


def test_rules_alone_and_missing_references() -> None:
    report = Report()
    p = parse([rule_doc(srcIpGroups=[{"id": 5, "name": "g"}], locations=[{"id": 3, "name": "Paris"}])], report)
    assert p.rules[0].unsupported == ["source group g is not in the input"]
    assert p.rules[0].src_zones == ["Paris"]  # (the name the reference carries)
    found = {n.code for n in report.notes}
    assert {"ZSCALER_RULES_ALONE", "ZSCALER_NO_DEFAULT_RULE", "ZSCALER_NO_LOCATIONS", "ZSCALER_REFERENCE"} <= found


def test_without_locations_a_rule_applies_to_every_zone() -> None:
    p = parse({"firewallFilteringRules": [rule_doc()]})
    assert p.rules[0].src_zones == [ANY]


def test_a_rule_naming_nothing_unknown_is_exact_and_an_unknown_field_is_not() -> None:
    report = Report()
    p = parse({"firewallFilteringRules": [rule_doc(srcIps=["10.0.0.0/8"], someNewCriterion=["x"], deviceTrustLevels=["LOW_TRUST"])]}, report)
    assert "'someNewCriterion' is not read" in p.rules[0].unsupported
    assert any("device trust levels" in u for u in p.rules[0].unsupported)
    assert "ZSCALER_UNKNOWN_FIELD" in codes(report, "r")


def test_destination_groups_of_fqdns_or_countries() -> None:
    document = {"firewallFilteringRules": [rule_doc(destIpGroups=[{"id": 4, "name": "f"}]), rule_doc(id=2, name="q", order=2, destIpGroups=[{"id": 6, "name": "o"}])],
                "ipDestinationGroups": [{"id": 4, "name": "f", "type": "DSTN_DOMAIN", "addresses": [".example.com"]},
                                        {"id": 6, "name": "o", "type": "DSTN_OTHER", "addresses": [], "countries": ["COUNTRY_KP"]}]}  # fmt: skip
    report = Report()
    p = parse(document, report)
    assert p.rules[0].unsupported and p.rules[1].unsupported
    assert "ZSCALER_FQDN" in codes(report, "r") and "ZSCALER_CATEGORY" in codes(report, "q")
    assert p.address_groups["f"].unsupported


def test_a_service_without_ports_that_is_not_known() -> None:
    p = parse({"firewallFilteringRules": [rule_doc(nwServices=[{"id": 1, "name": "WEIRD"}])],
               "networkServices": [{"id": 1, "name": "WEIRD", "type": "STANDARD"}]})  # fmt: skip
    assert p.services["WEIRD"].unsupported


def test_errors() -> None:
    with pytest.raises(ParseError):
        parse({"code": "UNAUTHORIZED", "message": "Authentication required"})
    with pytest.raises(ParseError):
        parse({"locations": []})
    with pytest.raises(ParseError):
        parse("{not json")
    with pytest.raises(ParseError):
        parse([{"id": 1, "name": "r", "rank": 7, "action": "ALLOW", "state": "ENABLED"}])  # (no order)


def test_detection_claims_its_own_sample_only() -> None:
    assert cli.detect_format((DATA / "zscaler_sample.json").read_bytes()) == "zscaler"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and "_sample." in path.name and path.name != "zscaler_sample.json":
            assert not parse_zscaler.looks_like_zscaler(path.read_bytes()), path.name
    assert parse_zscaler.looks_like_zscaler(json.dumps([rule_doc(action="BLOCK_DROP")]).encode())


# -- the emitter -----------------------------------------------------------------------------------------


def test_sample_to_zscaler_runs_against_the_tenant() -> None:
    p, report = load("zscaler_sample.json")
    text = cli.convert(p, "zscaler", report, Options())
    tenant = Tenant(["HQ-Brussels", "Branch-Ghent", "HQ-Servers", "Guest-WiFi"])
    run_script(text, tenant)
    rules = [tenant.objects["/firewallFilteringRules"][i] for i in tenant.rules]
    assert [r["order"] for r in rules] == list(range(1, len(rules) + 1))
    names = [r["name"] for r in rules]
    assert "fws-Block malicious IPs and do" not in " ".join(names)  # (a predefined rule is not created)
    assert not any("Default" in n for n in names)
    assert "ZSCALER_DEFAULT_RULE" in codes(report, "Default Firewall Filtering Rule")
    by_name = {r["name"]: r for r in rules}
    assert by_name["fws-Block GRE and ESP"]["action"] == "BLOCK_ICMP"
    assert by_name["fws-Branch web"]["state"] == "DISABLED"  # (its time window)
    pkt = Packet("", "", "10.10.1.5", "198.51.100.53", "udp", 40000, 53)
    assert tenant.decides("HQ-Brussels", pkt) and not tenant.decides("Branch-Ghent", pkt)
    assert not tenant.decides("HQ-Brussels", Packet("", "", "10.10.1.5", "198.51.100.9", "tcp", 40000, 22))
    assert tenant.decides("HQ-Servers", Packet("", "", "10.10.20.7", "203.0.113.50", "tcp", 40000, 8005))
    assert tenant.decides("Guest-WiFi", Packet("", "", "10.99.0.1", "192.0.2.1", "icmp", 0, 0, 8))


def test_on_premises_policy_loses_inbound_and_internal_rules() -> None:
    p = Policy(vendor="panos")
    p.zones = {z: Zone_(z) for z in ("trust", "dmz", "untrust")}
    p.rules = [
        Rule("out", src_zones=["trust"], dst_zones=["untrust"], origin="out"),
        Rule("in", src_zones=["untrust"], dst_zones=["dmz"], origin="in"),
        Rule("in-deny", src_zones=["untrust"], dst_zones=["dmz"], action=Action.DROP, origin="in-deny"),
        Rule("east-west", src_zones=["trust"], dst_zones=["dmz"], action=Action.DROP, origin="east-west"),
        Rule("everywhere", src_zones=["trust"], dst_zones=[ANY], action=Action.DROP, origin="everywhere"),
    ]
    report = Report()
    text = cli.convert(p, "zscaler", report, Options(inside_zones=["trust", "dmz"]))
    assert "ZSCALER_INBOUND" in codes(report, "in") and report.item("rule", "in").skipped
    assert next(f for f in report.item("rule", "in").findings if f.code == "ZSCALER_INBOUND").severity == Severity.REVIEW
    assert next(f for f in report.item("rule", "in-deny").findings if f.code == "ZSCALER_INBOUND").severity == Severity.INFO
    assert "ZSCALER_INTERNAL" in codes(report, "east-west") and report.item("rule", "east-west").skipped
    assert next(f for f in report.item("rule", "everywhere").findings if f.code == "ZSCALER_INTERNAL").severity == Severity.REVIEW
    assert "ZSCALER_LOST" in {n.code for n in report.notes} and "ZSCALER_BLOCK_RULE" in {n.code for n in report.notes}
    tenant = Tenant(["trust", "dmz"])
    run_script(text, tenant)
    rules = [tenant.objects["/firewallFilteringRules"][i] for i in tenant.rules]
    assert [r["name"] for r in rules] == ["fws-out", "fws-everywhere", "fws-block the rest"]
    assert rules[-1]["state"] == "DISABLED" and rules[0]["locations"]


def Zone_(name: str) -> Any:
    from fwshift.model import Zone

    return Zone(name)


def test_order_start_prefix_and_ipv6() -> None:
    p = Policy(vendor="panos", zones={})
    p.addresses["v6"] = Address("v6", AddressKind.NETWORK, "2001:db8::/32")
    p.addresses["web"] = Address("web", AddressKind.FQDN, "www.example.com")
    p.rules = [Rule("a", sources=["10.0.0.0/8", "v6"], origin="a"), Rule("b", sources=["v6"], action=Action.DROP, origin="b"),
               Rule("c", destinations=["web"], origin="c"), Rule("d", sources=["web"], origin="d")]  # fmt: skip
    report = Report()
    text = cli.convert(p, "zscaler", report, Options(policy_id_start=3, object_prefix="mig-"))
    assert '"order": 3' in text and "'mig-a'" in text
    assert next(f for f in report.item("rule", "a").findings if f.code == "ZSCALER_IPV6").severity == Severity.APPROX
    assert "ZSCALER_IPV6_ONLY" in codes(report, "b")
    assert '"destAddresses": ["www.example.com"]' in text or "DSTN_FQDN" in text
    assert "FQDN_NOT_SUPPORTED" in codes(report, "d")
    with pytest.raises(FwshiftError):
        cli.convert(p, "zscaler", Report(), Options(inside_zones=["nowhere"]))


def test_services_that_cannot_be_written_disable_the_rule() -> None:
    p = Policy(vendor="panos")
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")])
    p.services["mixed"] = Service("mixed", [ServiceEntry(Protocol.TCP, "80", "1024-2000"), ServiceEntry(Protocol.TCP, "443"),
                                            ServiceEntry(Protocol.UDP, ""), ServiceEntry(Protocol.ICMP)])  # fmt: skip
    p.rules = [Rule("p", services=["ping"], origin="p"), Rule("s", services=["sctp"], origin="s"), Rule("m", services=["mixed"], origin="m"),
               Rule("n", services=["mixed"], negate_service=True, origin="n")]  # fmt: skip
    report = Report()
    text = cli.convert(p, "zscaler", report, Options())
    assert "SERVICE_NOT_WRITTEN" in codes(report, "p") and "SERVICE_NOT_WRITTEN" in codes(report, "s")
    assert "SERVICE_NEGATE" in codes(report, "n")
    tenant = Tenant([])
    run_script(text, tenant)
    m = next(tenant.objects["/firewallFilteringRules"][i] for i in tenant.rules if tenant.objects["/firewallFilteringRules"][i]["name"] == "fws-m")
    assert m["state"] == "ENABLED" and len(m["nwServices"]) == 3  # two custom services (by source ports) and ICMP_ANY
    for pkt, verdict in ((Packet("", "", "10.0.0.1", "192.0.2.1", "tcp", 1500, 80), True), (Packet("", "", "10.0.0.1", "192.0.2.1", "tcp", 3000, 80), False),
                         (Packet("", "", "10.0.0.1", "192.0.2.1", "tcp", 3000, 443), True), (Packet("", "", "10.0.0.1", "192.0.2.1", "udp", 3000, 9), True),
                         (Packet("", "", "10.0.0.1", "192.0.2.1", "icmp", 0, 0, 3), True)):  # fmt: skip
        assert tenant.matches(m, "x", pkt) == verdict, pkt


def test_a_name_that_needs_quoting_or_a_dollar_stays_literal() -> None:
    p = Policy(vendor="panos")
    p.rules = [Rule("it's $HOME `x`", description='say "$(rm -rf /)" \\ `id`', origin="q")]
    text = cli.convert(p, "zscaler", Report(), Options())
    tenant = Tenant([])
    run_script(text, tenant)
    rule = tenant.objects["/firewallFilteringRules"][tenant.rules[0]]
    assert rule["description"] == 'say "$(rm -rf /)" \\ `id`'


# -- packet level: random models, emitted, replayed and judged ------------------------------------------------

INSIDE = ["lan", "dmz"]
NETS = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "192.0.2.0/25", "198.51.100.10-198.51.100.40", "2001:db8:1::/48"]


def random_model(rng: random.Random) -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.zones = {z: Zone_(z) for z in INSIDE + ["wan"]}
    for index, net in enumerate(NETS):
        kind = AddressKind.RANGE if "-" in net else AddressKind.NETWORK
        p.addresses[f"n{index}"] = Address(f"n{index}", kind, net)
    p.address_groups["g"] = AddressGroup("g", ["n0", "n4", "n5"])
    p.address_groups["h"] = AddressGroup("h", ["g", "n3"])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["hi"] = Service("hi", [ServiceEntry(Protocol.TCP, "8000-8010", "1024-2000")])
    p.services["icmp"] = Service("icmp", [ServiceEntry(Protocol.ICMP)])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.service_groups["mix"] = ServiceGroup("mix", ["web", "gre", "icmp"])
    addresses = list(p.addresses) + list(p.address_groups) + ["10.0.0.17", "192.0.2.64/26"]
    services = list(p.services) + list(p.service_groups)
    zones = INSIDE + ["wan"]
    for index in range(rng.randint(3, 10)):
        rule = Rule(f"r{index}", origin=f"r{index}")
        rule.src_zones = [ANY] if rng.random() < 0.3 else rng.sample(zones, rng.randint(1, 2))
        rule.dst_zones = [ANY] if rng.random() < 0.4 else rng.sample(zones, rng.randint(1, 2))
        rule.sources = [ANY] if rng.random() < 0.4 else rng.sample(addresses, rng.randint(1, 3))
        rule.destinations = [ANY] if rng.random() < 0.4 else rng.sample(addresses, rng.randint(1, 3))
        rule.services = [ANY] if rng.random() < 0.3 else rng.sample(services, rng.randint(1, 2))
        rule.action = rng.choice([Action.ALLOW, Action.ALLOW, Action.DROP, Action.RESET_CLIENT])
        rule.negate_source = rule.sources != [ANY] and rng.random() < 0.2
        rule.negate_destination = rule.destinations != [ANY] and rng.random() < 0.2
        rule.enabled = rng.random() > 0.1
        p.rules.append(rule)
    return p


def random_packet(rng: random.Random) -> Packet:
    hosts = ["10.0.0.17", "10.0.0.200", "10.0.1.5", "10.0.1.200", "192.0.2.10", "192.0.2.100", "198.51.100.20", "203.0.113.9"]
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47"])
    return Packet(rng.choice(INSIDE), "wan", rng.choice(hosts), rng.choice(hosts), proto, rng.choice([1500, 40000]),
                  rng.choice([53, 80, 443, 8005, 9000]), rng.choice([0, 8]))  # fmt: skip


@pytest.mark.parametrize("seed", range(30))
def test_emitted_rules_decide_like_the_model(seed: int) -> None:
    """From a location to the internet the tenant gives the model's verdict, rules created disabled left out of the model."""
    rng = random.Random(seed)
    model = random_model(rng)
    report = Report()
    text = cli.convert(model, "zscaler", report, Options(inside_zones=list(INSIDE)))
    tenant = Tenant(list(INSIDE))
    run_script(text, tenant)
    judged = Policy(vendor=model.vendor, addresses=model.addresses, address_groups=model.address_groups, services=model.services,
                    service_groups=model.service_groups, default_interzone=Action.DENY)  # fmt: skip
    for rule in model.rules:
        copy_of = Rule(**{k: getattr(rule, k) for k in ("name", "src_zones", "dst_zones", "sources", "destinations", "services", "action",
                                                         "enabled", "negate_source", "negate_destination", "negate_service", "origin")})  # fmt: skip
        item = report.item("rule", rule.origin)
        if item.disabled or item.skipped:
            copy_of.enabled = False
        judged.rules.append(copy_of)
    for _ in range(300):
        pkt = random_packet(rng)
        assert tenant.decides(pkt.in_if, pkt) == model_allows(judged, pkt), (seed, pkt, text)


def test_most_random_rules_are_written_enabled() -> None:
    written = disabled = 0
    for seed in range(30):
        model = random_model(random.Random(seed))
        report = Report()
        cli.convert(model, "zscaler", report, Options(inside_zones=list(INSIDE)))
        for rule in model.rules:
            item = report.item("rule", rule.origin)
            written += not item.skipped
            disabled += item.disabled
    assert disabled < written / 3, (disabled, written)


# -- the script itself, with sh, jq and a fake curl -------------------------------------------------------

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
state_file = os.environ["FAKE_ZIA_STATE"]
state = json.load(open(state_file))
method, out, headers, data, url = "GET", None, None, None, None
i = 0
while i < len(args):
    a = args[i]
    if a == "-X": method = args[i + 1]; i += 2; continue
    if a == "-o": out = args[i + 1]; i += 2; continue
    if a == "-D": headers = args[i + 1]; i += 2; continue
    if a in ("-w", "-H"): i += 2; continue
    if a == "--data-binary": data = open(args[i + 1][1:]).read(); i += 2; continue
    if a.startswith("http"): url = a
    i += 1
path = url.split("/api/v1", 1)[1]
query = ""
if "?" in path:
    path, query = path.split("?", 1)
state["calls"].append([method, path])
objects = state["objects"].setdefault(path, [])
if method == "GET":
    answer, code = objects, 200
else:
    body = json.loads(data)
    state["next"] += 1
    body["id"] = state["next"]
    objects.append(body)
    answer, code = body, 200
json.dump(state, open(state_file, "w"))
open(out, "w").write(json.dumps(answer))
open(headers, "w").write("HTTP/1.1 %d OK\r\n" % code)
sys.stdout.write(str(code))
'''


@pytest.mark.skipif(shutil.which("jq") is None or shutil.which("sh") is None, reason="needs sh and jq")
def test_script_runs_against_a_fake_api(tmp_path: Path) -> None:
    p, report = load("zscaler_sample.json")
    script = tmp_path / "load.sh"
    script.write_text(cli.convert(p, "zscaler", report, Options()))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
    state = {"next": 500, "calls": [], "objects": {"/locations": [{"id": 11, "name": n} for n in ("HQ-Brussels", "Branch-Ghent", "HQ-Servers", "Guest-WiFi")],
                                                   "/networkServices": [{"id": 20 + i, "name": n} for i, n in enumerate(PREDEFINED)]}}  # fmt: skip
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(state))
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", FAKE_ZIA_STATE=str(state_file), ZIA_BASE="https://api.example.net/zia/api/v1",
               ZIA_TOKEN="t", JOURNAL=str(tmp_path / "journal.txt"))  # fmt: skip
    env.pop("DRY_RUN", None)
    # sleep is part of the pacing; make it instant here.
    sleep = bin_dir / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(sleep.stat().st_mode | stat.S_IEXEC)
    done = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    final = json.loads(state_file.read_text())
    rules = final["objects"]["/firewallFilteringRules"]
    assert [r["order"] for r in rules] == list(range(1, len(rules) + 1))
    assert all(isinstance(ref["id"], int) for r in rules for key in ("locations", "nwServices", "srcIpGroups") for ref in r.get(key, []))
    assert not any(c[1] in ("/status/activate", "/authenticatedSession") for c in final["calls"])
    assert all(c[0] in ("GET", "POST") for c in final["calls"])
    journal = (tmp_path / "journal.txt").read_text().splitlines()
    assert len(journal) == len([c for c in final["calls"] if c[0] == "POST"])
    # A second run refuses the names it would take, and changes nothing.
    again = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=120)
    assert again.returncode != 0 and "the name is taken" in again.stderr
    assert len(json.loads(state_file.read_text())["objects"]["/firewallFilteringRules"]) == len(rules)
    dry = subprocess.run(["sh", str(script)], env=dict(env, DRY_RUN="1"), capture_output=True, text=True, timeout=60)
    assert dry.returncode == 0 and "POST /firewallFilteringRules" in dry.stderr


def test_report_codes_of_a_zscaler_target_are_in_the_manual() -> None:
    manual = (Path(__file__).resolve().parents[1] / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    for code in ("ZSCALER_LOAD", "ZSCALER_INBOUND", "ZSCALER_INTERNAL", "ZSCALER_OUTBOUND_ONLY", "ZSCALER_IPV6"):
        assert f"`{code}`" in manual


def test_sample_converts_to_every_target() -> None:
    for target in sorted(cli.EMITTERS):
        p, report = load("zscaler_sample.json")
        cli.convert(p, target, report, Options())
