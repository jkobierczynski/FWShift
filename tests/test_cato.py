# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cato Networks: the WAN Firewall and the Internet Firewall, read from the GraphQL API and written as addRule calls.

``CatoWorld`` is the judge, written from Cato's documentation and its API schema, not from the parser: a list of rules
per policy, first match, the WAN Firewall ending in block and the Internet Firewall in allow; the objects of a column
are alternatives and the columns must all hold; direction BOTH also matches the other way; an exception skips the rule
when all of its columns hold; traffic inside one network range never reaches Cato. It reads both the rules of the
API's answers (references by id, resolved through the lookups) and the rules the emitter writes (references by name).
``CatoScript`` reads the script strictly: the rule bodies, only the fields and values the API schema has, names given
once, every body added once and in order.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from test_iptables import Packet, model_allows, model_verdict, random_model

from fwshift.cli import detect_format, main
from fwshift.emitters import cato as emit_cato
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, Address, AddressKind, Policy, Rule, Service, ServiceEntry, Protocol, Zone
from fwshift.options import Options
from fwshift.parsers import cato as parse_cato
from fwshift.report import Report, Severity

DATA = Path(__file__).parent / "data"
SAMPLE = DATA / "cato_sample.json"
INTERNET, REMOTE = "internet", "remote-users"

# -- the strict reader -------------------------------------------------------------------------------------------------

_SIDE = {"host", "site", "subnet", "ip", "ipRange", "globalIpRange", "networkInterface", "siteNetworkSubnet", "floatingSubnet", "user",
         "usersGroup", "group", "systemGroup"}  # fmt: skip
_IF_DEST = {"application", "customApp", "appCategory", "customCategory", "sanctionedAppsCategory", "country", "domain", "fqdn", "ip", "subnet",
            "ipRange", "globalIpRange", "remoteAsn", "containers", "group"}  # fmt: skip
_TRACKING = {"event", "alert"}
_WAN_RULE = {"name", "description", "enabled", "action", "direction", "source", "destination", "service", "connectionsOriginList", "tracking",
             "exceptions", "application", "country", "device", "deviceOS", "deviceAttributes", "schedule", "activePeriod", "actionConfig"}  # fmt: skip
_IF_RULE = (_WAN_RULE - {"direction", "application"}) | {"actionConfig"}
_WAN_EXC = {"name", "source", "destination", "service", "application", "country", "device", "deviceOS", "deviceAttributes", "direction",
            "connectionsOriginList"}  # fmt: skip
_IF_EXC = _WAN_EXC - {"application", "direction"}
_ORIGINS = {"SITE", "REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER"}


def _ipv4(text: Any) -> ipaddress.IPv4Address:
    assert isinstance(text, str), text
    return ipaddress.IPv4Address(text)  # (the API's IPAddress is IPv4)


def _check_side(cell: Any, allowed: Set[str], where: str) -> None:
    assert isinstance(cell, dict), where
    assert set(cell) <= allowed, (where, set(cell) - allowed)
    for key, value in cell.items():
        assert isinstance(value, list), (where, key)
        for item in value:
            if key == "ip":
                _ipv4(item)
            elif key == "subnet":
                assert isinstance(item, str) and "/" in item
                ipaddress.IPv4Network(item, strict=True)
            elif key == "ipRange":
                assert set(item) == {"from", "to"} and _ipv4(item["from"]) <= _ipv4(item["to"]), item
            elif key == "fqdn":
                assert isinstance(item, str) and re.fullmatch(r"([a-z0-9_-]+\.)+[a-z]{2,63}", item), item
            else:
                assert set(item) == {"by", "input"} and item["by"] in ("ID", "NAME") and isinstance(item["input"], str) and item["input"], item


def _check_service(cell: Any, where: str) -> None:
    assert isinstance(cell, dict) and set(cell) <= {"standard", "custom"}, where
    for item in cell.get("custom", []):
        assert set(item) <= {"protocol", "port", "portRange"} and item["protocol"] in ("ANY", "TCP", "UDP", "TCP_UDP", "ICMP"), item
        assert not ("port" in item and "portRange" in item), item
        if item["protocol"] in ("ICMP", "ANY"):
            assert set(item) == {"protocol"}, item
        else:
            assert "port" in item or "portRange" in item, item
        for port in item.get("port", []):
            assert isinstance(port, int) and 1 <= port <= 65535, item
        if "portRange" in item:
            span = item["portRange"]
            assert set(span) == {"from", "to"} and 1 <= span["from"] <= span["to"] <= 65535, item


class CatoScript:
    """The rules the script adds, per policy and in the order they are added, read as strictly as the API reads them."""

    def __init__(self, text: str) -> None:
        self.files: Dict[str, Dict[str, Any]] = {}
        self.rules: Dict[str, List[Dict[str, Any]]] = {"wanFirewall": [], "internetFirewall": []}
        lines = text.split("\n")
        assert lines[0] == "#!/bin/sh" and "set -eu" in lines
        used: Set[str] = set()
        names: Dict[str, Set[str]] = {"wanFirewall": set(), "internetFirewall": set()}
        index = 0
        while index < len(lines):
            line = lines[index]
            heredoc = re.fullmatch(r"cat > \"(\$OUT/(?:wan|internet)-\d{3}\.json)\" <<'FWSHIFT_EOF'", line)
            add = re.fullmatch(r"add (wanFirewall|internetFirewall) \"(\$OUT/[a-z]+-\d{3}\.json)\"", line)
            if heredoc:
                end = lines.index("FWSHIFT_EOF", index)
                assert heredoc.group(1) not in self.files
                self.files[heredoc.group(1)] = json.loads("\n".join(lines[index + 1:end]))
                index = end + 1
                continue
            if add:
                policy, path = add.groups()
                assert path in self.files and path not in used, path  # written before, added once
                assert ("wan-" in path) == (policy == "wanFirewall")
                used.add(path)
                body = self.files[path]
                self._check(body, policy)
                assert body["name"].lower() not in names[policy], body["name"]
                names[policy].add(body["name"].lower())
                self.rules[policy].append(body)
            index += 1
        assert used == set(self.files), "every rule written is added"

    @staticmethod
    def _check(body: Dict[str, Any], policy: str) -> None:
        wan = policy == "wanFirewall"
        assert set(body) <= (_WAN_RULE if wan else _IF_RULE), set(body) - (_WAN_RULE if wan else _IF_RULE)
        assert isinstance(body["name"], str) and body["name"].strip() and isinstance(body["enabled"], bool)
        assert body["action"] in (("ALLOW", "BLOCK", "PROMPT") if wan else ("ALLOW", "BLOCK", "PROMPT", "RBI", "CAPTIVE_PORTAL"))
        if wan:
            assert body.get("direction", "TO") in ("TO", "BOTH")
        _check_side(body.get("source", {}), _SIDE, "source")
        _check_side(body.get("destination", {}), _SIDE if wan else _IF_DEST, "destination")
        _check_service(body.get("service", {}), "service")
        assert set(body.get("connectionsOriginList", [])) <= _ORIGINS
        assert set(body.get("tracking", {})) <= _TRACKING
        seen: Set[str] = set()
        for exception in body.get("exceptions", []):
            assert set(exception) <= (_WAN_EXC if wan else _IF_EXC) and exception["name"] not in seen, exception
            assert any(isinstance(v, dict) and any(v.values()) or isinstance(v, list) and v for k, v in exception.items() if k != "name"), \
                f"an exception without criteria matches everything: {exception}"
            seen.add(exception["name"])
            _check_side(exception.get("source", {}), _SIDE, "exception source")
            _check_side(exception.get("destination", {}), _SIDE if wan else _IF_DEST, "exception destination")
            _check_service(exception.get("service", {}), "exception service")


# -- the judge ----------------------------------------------------------------------------------------------------------


class Flow:
    """A connection: where it comes from (a site's name, remote-users) and goes to (a site, remote-users, internet)."""

    def __init__(self, src_site: str, src: str, dst_site: str, dst: str, proto: str, dport: int = 0) -> None:
        self.src_site, self.src, self.dst_site, self.dst, self.proto, self.dport = src_site, src, dst_site, dst, proto, dport

    def swapped(self) -> "Flow":
        return Flow(self.dst_site, self.dst, self.src_site, self.src, self.proto, self.dport)

    def __repr__(self) -> str:
        return f"Flow({self.src_site} {self.src} -> {self.dst_site} {self.dst} {self.proto}/{self.dport})"


class CatoWorld:
    """What Cato does with a connection, for the rules of the two policies (from the API's answer or from the script)."""

    def __init__(self, wan: List[Dict[str, Any]], internet: List[Dict[str, Any]], sites: Optional[Dict[str, Tuple[str, List[str]]]] = None,
                 hosts: Optional[Dict[str, str]] = None, ranges: Optional[Dict[str, List[str]]] = None,
                 groups: Optional[Dict[str, List[Tuple[str, str]]]] = None) -> None:  # fmt: skip
        self.wan, self.internet = wan, internet
        self.sites = sites or {}  # site id -> (name, network ranges)
        self.hosts = hosts or {}  # host id -> address
        self.ranges = ranges or {}  # global range id -> networks
        self.groups = groups or {}  # group id -> [(type, member id)]

    def _site_name(self, ref: Dict[str, Any]) -> str:
        if ref.get("by") == "NAME":
            return str(ref["input"])
        ident = ref.get("id", ref.get("input"))
        return self.sites[ident][0] if ident in self.sites else str(ref.get("name"))

    @staticmethod
    def _in(address: str, net: str) -> bool:
        if "-" in net:
            low, high = net.split("-")
            return ipaddress.ip_address(low) <= ipaddress.ip_address(address) <= ipaddress.ip_address(high)
        return ipaddress.ip_address(address) in ipaddress.ip_network(net, strict=False)

    def _member(self, kind: str, ident: str, site: str, address: str) -> bool:
        if kind == "SITE":
            return self.sites.get(ident, ("", []))[0] == site
        if kind == "HOST":
            return self.hosts.get(ident) == address
        if kind == "GLOBAL_IP_RANGE":
            return any(self._in(address, n) for n in self.ranges[ident])
        raise AssertionError(kind)

    def _side(self, cell: Dict[str, Any], site: str, address: str) -> bool:
        if not any(cell.get(k) for k in cell):
            return True
        for key, values in cell.items():
            for value in values or []:
                if key == "site" and self._site_name(value) == site:
                    return True
                if key == "ip" and value == address:
                    return True
                if key == "subnet" and self._in(address, value):
                    return True
                if key == "ipRange" and self._in(address, f"{value['from']}-{value['to']}"):
                    return True
                if key == "host" and self.hosts.get(value.get("id", value.get("input"))) == address:
                    return True
                if key == "globalIpRange" and any(self._in(address, n) for n in self.ranges[value.get("id", value.get("input"))]):
                    return True
                if key == "group" and any(self._member(kind, ident, site, address) for kind, ident in self.groups[value.get("id", value.get("input"))]):
                    return True
        return False

    @staticmethod
    def _service(cell: Dict[str, Any], flow: Flow) -> bool:
        customs = cell.get("custom") or []
        if not customs and not cell.get("standard"):
            return True
        for item in customs:
            protocol = item["protocol"]
            if protocol == "ANY":
                return True
            if protocol == "ICMP":
                if flow.proto == "icmp":
                    return True
                continue
            if flow.proto not in {"TCP": ["tcp"], "UDP": ["udp"], "TCP_UDP": ["tcp", "udp"]}[protocol]:
                continue
            if "port" not in item and "portRange" not in item:
                return True
            if flow.dport in (item.get("port") or []):
                return True
            span = item.get("portRange")
            if span and span["from"] <= flow.dport <= span["to"]:
                return True
        return False

    def _columns(self, rule: Dict[str, Any], flow: Flow, internet: bool) -> bool:
        origin = "SITE" if flow.src_site != REMOTE else "REMOTE_CLIENT"
        if rule.get("connectionsOriginList") and origin not in rule["connectionsOriginList"]:
            return False
        if not self._side(rule.get("source") or {}, flow.src_site, flow.src):
            return False
        if not self._side(rule.get("destination") or {}, "" if internet else flow.dst_site, flow.dst):
            return False
        return self._service(rule.get("service") or {}, flow)

    def _matches(self, rule: Dict[str, Any], flow: Flow, internet: bool) -> bool:
        directions = [flow] + ([flow.swapped()] if rule.get("direction") == "BOTH" else [])
        if not any(self._columns(rule, f, internet) for f in directions):
            return False
        for exception in rule.get("exceptions") or []:
            if self._columns(exception, flow, internet):
                return False  # (the rule is skipped; the ones below decide)
        return True

    def allows(self, flow: Flow) -> bool:
        if flow.src_site == INTERNET:
            return False  # (nothing from the internet without Remote Port Forwarding)
        if flow.dst_site == INTERNET:
            for rule in self.internet:
                if rule.get("enabled") and self._matches(rule, flow, True):
                    return rule["action"] == "ALLOW"
            return True
        if flow.src_site == flow.dst_site and flow.src_site != REMOTE:
            for _, networks in self.sites.values():
                if any(self._in(flow.src, n) and self._in(flow.dst, n) for n in networks):
                    return True  # (inside one network range: it never reaches Cato)
        for rule in self.wan:
            if rule.get("enabled") and self._matches(rule, flow, False):
                return rule["action"] == "ALLOW"
        return False


# -- helpers ---------------------------------------------------------------------------------------------------------------


def parse(document: Any) -> Tuple[Policy, Report]:
    report = Report()
    return parse_cato.parse(json.dumps(document).encode(), report), report


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    report = Report()
    return emit_cato.emit(model, report, options or Options()), report


def codes(report: Report) -> Set[str]:
    return {f.code for f in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def rule_codes(report: Report, name: str) -> Set[str]:
    return {f.code for f in report.item("rule", name).findings}


def by_name(p: Policy, name: str) -> Rule:
    return next(r for r in p.rules if r.name == name)


def ref(ident: str, name: str = "") -> Dict[str, str]:
    return {"id": ident, "name": name or ident}


def wan_rule(name: str, action: str = "ALLOW", **fields: Any) -> Dict[str, Any]:
    rule: Dict[str, Any] = {"id": f"id-{name}", "name": name, "enabled": True, "action": action, "direction": "TO", "source": {},
                            "destination": {}, "service": {"standard": [], "custom": []}, "exceptions": []}  # fmt: skip
    rule.update(fields)
    return {"rule": rule, "properties": []}


SITES = {"1": ("Site-A", ["10.1.0.0/24", "10.1.1.0/24"]), "2": ("Site-B", ["10.2.0.0/24"]), "3": ("Site-C", ["10.3.0.0/24"])}
HOSTS = {"h1": ("10.1.0.10", "1"), "h2": ("10.2.0.20", "2")}
RANGES = {"g1": ["10.1.1.0/25"], "g2": ["198.51.100.0/28"]}
GROUPS = {"G1": [("SITE", "3"), ("HOST", "h1")], "G2": [("GLOBAL_IP_RANGE", "g1"), ("HOST", "h2")]}


def bundle(wan: List[Dict[str, Any]], internet: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "wanFirewall": {"rules": wan},
        "sites": [{"entity": {"id": i, "name": n, "type": "site"}} for i, (n, _) in SITES.items()],
        "networkRanges": {i: [{"subnet": s, "name": f"r{k}"} for k, s in enumerate(nets)] for i, (_, nets) in SITES.items()},
        "hosts": {site: [{"hostId": h, "name": f"host-{h}", "ip": ip} for h, (ip, s) in HOSTS.items() if s == site] for site in SITES},
        "networkInterfaces": [], "siteRanges": [],
        "globalIpRanges": [{"id": g, "name": f"range-{g}", "ipRange": nets[0]} for g, nets in RANGES.items()],
        "groups": [{"id": g, "name": f"group-{g}", "members": {"items": [{"id": m, "name": m, "type": t} for t, m in members]}}
                   for g, members in GROUPS.items()],
    }  # fmt: skip
    if internet is not None:
        out["internetFirewall"] = {"rules": internet}
    return out


def world(document: Dict[str, Any]) -> CatoWorld:
    wan = [e["rule"] for e in document["wanFirewall"]["rules"]]
    internet = [e["rule"] for e in document.get("internetFirewall", {}).get("rules", [])]
    if "internetFirewall" in document:
        internet = internet + []
    return CatoWorld(wan, internet, SITES, {h: ip for h, (ip, _) in HOSTS.items()}, RANGES, GROUPS)


# -- the sample ------------------------------------------------------------------------------------------------------------


def test_sample_is_detected_and_no_other_sample_is() -> None:
    assert detect_format(SAMPLE.read_bytes()) == "cato"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != SAMPLE.name and "_sample." in path.name:
            assert not parse_cato.looks_like_cato(path.read_bytes()), path.name
    assert parse_cato.looks_like_cato(b'{"data": {"policy": {"wanFirewall": {"policy": {"rules": []}}}}}')
    assert not parse_cato.looks_like_cato(b'{"rules": []}')


def test_sample_zones_networks_and_order() -> None:
    p, report = parse(json.loads(SAMPLE.read_text()))
    assert list(p.zones) == ["Brussels-HQ", "Antwerp-DC", "Ghent-Plant", "Leuven-Lab", REMOTE, INTERNET]
    assert p.zones["Brussels-HQ"].interfaces == ["Brussels HQ"]  # (the site's own name, for a Cato target)
    assert p.zone_networks["Antwerp-DC"] == ["10.20.0.0/24", "10.20.30.0/24"]
    assert p.default_interzone == Action.DENY and p.default_intrazone == Action.DENY
    local = [r for r in p.rules if r.source_ids.get("cato.local")]
    assert len(local) == 6 and p.rules[:6] == local and all(r.sources == r.destinations and r.src_zones == r.dst_zones for r in local)
    last = p.rules[-1]
    assert last.name == "Internet Firewall implicit allow" and last.dst_zones == [INTERNET] and last.action == Action.ALLOW
    assert REMOTE in last.src_zones and INTERNET not in last.src_zones
    wan = [r for r in p.rules if r.source_ids.get("cato.policy") == "wanFirewall"]
    internet = [r for r in p.rules if r.source_ids.get("cato.policy") == "internetFirewall"]
    assert p.rules.index(wan[-1]) < p.rules.index(internet[0])
    assert all(INTERNET not in r.dst_zones for r in wan) and all(r.dst_zones == [INTERNET] for r in internet)
    assert "Retired rule" not in [r.name for r in p.rules] and "CATO_REMOVED" in codes(report)
    assert {"CATO_SOURCE", "CATO_INTERNET_TOP", "CATO_INBOUND"} <= codes(report)


def test_sample_sites_or_addresses_become_parts() -> None:
    p, report = parse(json.loads(SAMPLE.read_text()))
    first, second = by_name(p, "Allow HQ to DC servers"), by_name(p, "Allow HQ to DC servers (2)")
    assert (first.dst_zones, first.destinations) == (["Antwerp-DC"], ["fileserver", "erp-db"])
    assert second.destinations == ["Monitoring"] and REMOTE in second.dst_zones
    assert p.addresses["Monitoring"].value == "198.51.100.10-198.51.100.20"
    modbus = [r for r in p.rules if r.name.startswith("Modbus to the plant")]
    assert [(r.src_zones, r.sources) for r in modbus][0] == (["Brussels-HQ"], [ANY])
    assert modbus[2].src_zones == ["Ghent-Plant"] and modbus[2].sources == ["historian"]
    assert "CATO_RULE_SPLIT" in rule_codes(report, "Modbus to the plant")
    assert by_name(p, "Block OT to HQ").src_zones == ["Ghent-Plant", "Leuven-Lab"]  # (a group of sites)


def test_sample_both_directions_exceptions_and_what_is_not_converted() -> None:
    p, report = parse(json.loads(SAMPLE.read_text()))
    forward, reverse = by_name(p, "Historian both ways"), by_name(p, "Historian both ways (2)")
    assert (forward.sources, forward.destinations) == (reverse.destinations, reverse.sources) and forward.services == reverse.services
    assert reverse.source_ids["cato.direction"] == "reverse" and "CATO_BOTH" in rule_codes(report, "Historian both ways")
    remote = by_name(p, "Remote users to DC")
    assert remote.src_zones == [REMOTE] and remote.destinations == ["erp-db"] and remote.negate_destination
    assert "CATO_EXCEPTION_CUT" in rule_codes(report, "Remote users to DC")
    plant = by_name(p, "Plant has no internet")
    assert plant.destinations == ["fqdn updates.example.com"] and plant.negate_destination and plant.action == Action.DENY
    assert by_name(p, "Finance to ERP").unsupported and "CATO_USERS" in rule_codes(report, "Finance to ERP")
    prompt = by_name(p, "Prompt for SSH")
    assert prompt.unsupported and prompt.action == Action.ALLOW and "CATO_ACTION" in rule_codes(report, "Prompt for SSH")
    assert "CATO_STANDARD_SERVICE" in rule_codes(report, "Prompt for SSH") and p.services["SSH"].entries[0].dst_ports == "22"
    assert by_name(p, "Old block").enabled is False
    assert p.addresses["host lab-printer"].kind == AddressKind.UNSUPPORTED and "CATO_UNRESOLVED" in rule_codes(report, "Unknown host")
    assert by_name(p, "Block guest except DNS").unsupported and "CATO_EXCEPTION" in rule_codes(report, "Block guest except DNS")
    assert by_name(p, "Maintenance window").schedule.startswith("SATURDAY,SUNDAY")
    assert by_name(p, "Teams between sites").unsupported and by_name(p, "Floating range").unsupported
    assert "CATO_ORIGIN" in rule_codes(report, "Block remote users to SMB")
    assert "CATO_SYSTEM_RULE" in rule_codes(report, "Block anonymizers")
    assert by_name(p, "Allow HQ to DC servers").log_end is True and by_name(p, "Block OT to HQ").log_end is False


# -- traps of the format, one by one ------------------------------------------------------------------------------------


def test_a_bare_answer_of_the_api_is_read_and_says_what_is_missing() -> None:
    answer = {"data": {"policy": {"wanFirewall": {"policy": {"rules": [wan_rule("r1", source={"site": [ref("7", "Office")]})]}},
                                  "internetFirewall": {"policy": {"rules": []}}}}}  # fmt: skip
    p, report = parse(answer)
    assert by_name(p, "r1").src_zones == ["Office"] and "CATO_NO_LOOKUPS" in codes(report)
    assert p.rules[-1].name == "Internet Firewall implicit allow"


def test_errors_and_shapes_that_are_refused() -> None:
    with pytest.raises(ParseError, match="error answer"):
        parse({"errors": [{"message": "permission denied"}], "data": None})
    with pytest.raises(ParseError, match="no WAN or Internet Firewall"):
        parse({"sites": []})
    with pytest.raises(ParseError, match="JSON object"):
        parse_cato.parse(b"[1, 2]", Report())
    with pytest.raises(ParseError, match="'rule' object"):
        parse({"wanFirewall": {"rules": [{"properties": []}]}})


def test_rules_are_read_in_the_order_of_their_index() -> None:
    rules = [wan_rule("second", index=2), wan_rule("first", index=1)]
    for entry, index in zip(rules, (2, 1)):
        entry["rule"]["index"] = index
    p, _ = parse(bundle(rules))
    assert [r.name for r in p.rules if r.source_ids.get("cato.policy")] == ["first", "second"]


def test_an_empty_destination_of_a_wan_rule_is_every_site_and_remote_users_not_the_internet() -> None:
    p, _ = parse(bundle([wan_rule("r")]))
    rule = by_name(p, "r")
    assert set(rule.dst_zones) == {"Site-A", "Site-B", "Site-C", REMOTE} and INTERNET not in rule.src_zones + rule.dst_zones


def test_connection_origins() -> None:
    rules = [wan_rule("sites", connectionsOriginList=["SITE"]), wan_rule("remote", connectionsOriginList=["REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER"]),
             wan_rule("legacy", connectionOrigin="REMOTE"), wan_rule("client", connectionsOriginList=["REMOTE_CLIENT"])]  # fmt: skip
    p, report = parse(bundle(rules))
    assert by_name(p, "sites").src_zones == ["Site-A", "Site-B", "Site-C"]
    assert by_name(p, "remote").src_zones == [REMOTE] == by_name(p, "legacy").src_zones
    assert by_name(p, "client").unsupported and "CATO_ORIGIN" in rule_codes(report, "client")


def test_exceptions_of_one_column_are_cut_out_and_others_are_not() -> None:
    def exception(**columns: Any) -> Dict[str, Any]:
        return dict({"name": "e", "source": {}, "destination": {}, "service": {"standard": [], "custom": []}}, **columns)

    rules = [
        wan_rule("site out", exceptions=[exception(source={"site": [ref("2", "Site-B")]})]),
        wan_rule("cut", source={"subnet": ["10.1.0.0/24"]}, exceptions=[exception(source={"ip": ["10.1.0.10"]})]),
        wan_rule("service", exceptions=[exception(service={"standard": [], "custom": [{"protocol": "TCP", "port": [22]}]})]),
        wan_rule("both columns", exceptions=[exception(source={"ip": ["10.1.0.10"]}, service={"custom": [{"protocol": "TCP", "port": [22]}]})]),
        wan_rule("user", exceptions=[exception(source={"user": [ref("u1", "someone")]})]),
        wan_rule("both ways", direction="BOTH", exceptions=[exception(source={"ip": ["10.1.0.10"]})]),
        wan_rule("everything", source={"site": [ref("1", "Site-A")]}, exceptions=[exception(source={"site": [ref("1", "Site-A")]})]),
    ]
    p, report = parse(bundle(rules))
    assert "Site-B" not in by_name(p, "site out").src_zones and "Site-A" in by_name(p, "site out").src_zones
    cut = by_name(p, "cut")
    assert cut.sources == ["10.1.0.0-10.1.0.9", "10.1.0.11-10.1.0.255"] and not cut.negate_source
    service = by_name(p, "service")
    assert service.negate_service and service.services == ["tcp/22"]
    for name in ("both columns", "user", "both ways"):
        assert by_name(p, name).unsupported and "CATO_EXCEPTION" in rule_codes(report, name), name
    everything = by_name(p, "everything")
    assert not everything.enabled and "CATO_EMPTY" in rule_codes(report, "everything")


def test_services() -> None:
    custom = [{"protocol": "TCP_UDP", "port": [53]}, {"protocol": "UDP", "portRange": {"from": 5000, "to": 5010}}, {"protocol": "ICMP"},
              {"protocol": "TCP", "port": [80, 443]}]  # fmt: skip
    rules = [wan_rule("custom", service={"custom": custom}), wan_rule("any", service={"custom": [{"protocol": "ANY"}]}),
             wan_rule("any with port", service={"custom": [{"protocol": "ANY", "port": [80]}]}),
             wan_rule("unknown standard", service={"standard": [ref("x", "Quake")], "custom": []}),
             wan_rule("port zero", service={"custom": [{"protocol": "TCP", "port": [0]}]})]  # fmt: skip
    p, report = parse(bundle(rules))
    services = by_name(p, "custom").services
    assert services == ["tcp-udp/53", "udp/5000-5010", "icmp", "tcp/80,443"]
    assert [e.protocol for e in p.services["tcp-udp/53"].entries] == [Protocol.TCP, Protocol.UDP]
    assert by_name(p, "any").services == [ANY]
    assert by_name(p, "any with port").unsupported and by_name(p, "port zero").unsupported
    assert p.services["Quake"].unsupported and not by_name(p, "unknown standard").unsupported


def test_columns_that_narrow_and_cannot_be_modelled() -> None:
    rules = [wan_rule("country", country=[ref("BE", "Belgium")]), wan_rule("os", deviceOS=["WINDOWS"]),
             wan_rule("app", application={"application": [ref("teams", "Teams")]}), wan_rule("prompt", action="PROMPT"),
             wan_rule("system group", source={"systemGroup": [ref("all", "All Floating Ranges")]}),
             wan_rule("sub", ruleType="SUB_POLICY_SCOPE")]  # fmt: skip
    rules[-1]["ruleType"] = "SUB_POLICY_SCOPE"
    p, report = parse(bundle(rules))
    for name, code in (("country", "CATO_DEVICE"), ("os", "CATO_DEVICE"), ("app", "CATO_APPLICATION"), ("prompt", "CATO_ACTION"),
                       ("system group", "CATO_OBJECT"), ("sub", "CATO_SUB_POLICY")):  # fmt: skip
        assert by_name(p, name).unsupported and code in rule_codes(report, name), name
    assert report.item("rule", "app").findings[0].severity == Severity.REVIEW


def test_internet_destinations() -> None:
    internet = [wan_rule("addresses", "BLOCK", destination={"ip": ["203.0.113.5"], "ipRange": [{"from": "198.51.100.1", "to": "198.51.100.9"}]}),
                wan_rule("name", destination={"fqdn": ["www.example.com"]}), wan_rule("domain", destination={"domain": ["example.org"]}),
                wan_rule("asn", destination={"remoteAsn": ["64500"]})]  # fmt: skip
    for entry in internet:
        del entry["rule"]["direction"]
    p, report = parse(bundle([], internet))
    assert by_name(p, "addresses").destinations == ["203.0.113.5", "198.51.100.1-198.51.100.9"]
    assert p.addresses["fqdn www.example.com"].kind == AddressKind.FQDN
    assert by_name(p, "domain").unsupported and by_name(p, "asn").unsupported


def test_a_group_with_members_beyond_the_page_is_not_guessed() -> None:
    document = bundle([wan_rule("r", source={"group": [ref("G1")]})])
    document["groups"][0]["members"]["paging"] = {"total": 40}
    p, report = parse(document)
    assert by_name(p, "r").unsupported and "CATO_UNRESOLVED" in rule_codes(report, "r")


# -- the parser against the judge -------------------------------------------------------------------------------------------


def _random_side(rng: random.Random, internet: bool = False) -> Dict[str, Any]:
    if rng.random() < 0.3:
        return {}
    cell: Dict[str, Any] = {}
    kinds = ["ip", "subnet", "ipRange", "globalIpRange"] + ([] if internet else ["site", "host", "group"])
    for kind in rng.sample(kinds, rng.randint(1, 2)):
        if kind == "site":
            cell["site"] = [ref(i, SITES[i][0]) for i in rng.sample(list(SITES), rng.randint(1, 2))]
        elif kind == "host":
            cell["host"] = [ref(h) for h in rng.sample(list(HOSTS), 1)]
        elif kind == "group":
            cell["group"] = [ref(g) for g in rng.sample(list(GROUPS), 1)]
        elif kind == "globalIpRange":
            cell["globalIpRange"] = [ref("g2" if internet else "g1")]
        elif kind == "ip":
            cell["ip"] = [rng.choice(["203.0.113.9", "198.51.100.5"] if internet else ["10.1.0.10", "10.2.0.7", "10.99.0.4"])]
        elif kind == "subnet":
            cell["subnet"] = [rng.choice(["203.0.113.0/24"] if internet else ["10.1.0.0/24", "10.3.0.0/25", "10.99.0.0/24"])]
        else:
            cell["ipRange"] = [rng.choice([{"from": "198.51.100.1", "to": "198.51.100.7"}] if internet else
                                          [{"from": "10.1.0.5", "to": "10.1.1.20"}, {"from": "10.2.0.1", "to": "10.2.0.30"}])]  # fmt: skip
    return cell


def _random_service(rng: random.Random) -> Dict[str, Any]:
    pool = [{"protocol": "TCP", "port": [80, 443]}, {"protocol": "UDP", "portRange": {"from": 5000, "to": 5010}},
            {"protocol": "TCP_UDP", "port": [53]}, {"protocol": "ICMP"}, {"protocol": "TCP", "portRange": {"from": 20, "to": 25}}]  # fmt: skip
    return {"standard": [], "custom": [] if rng.random() < 0.35 else rng.sample(pool, rng.randint(1, 2))}


def random_bundle(rng: random.Random) -> Dict[str, Any]:
    wan: List[Dict[str, Any]] = []
    for index in range(rng.randint(3, 9)):
        fields: Dict[str, Any] = {"source": _random_side(rng), "destination": _random_side(rng), "service": _random_service(rng),
                                  "direction": "BOTH" if rng.random() < 0.2 else "TO", "enabled": rng.random() > 0.1}  # fmt: skip
        if rng.random() < 0.15:
            fields["connectionsOriginList"] = rng.choice([["SITE"], ["REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER"]])
        if rng.random() < 0.25 and (fields["direction"] == "TO" or rng.random() < 0.1):
            column = rng.choice(["source", "destination", "source", "destination", "service", "two"])
            exception: Dict[str, Any] = {"name": "x"}
            if column == "service":
                exception["service"] = {"standard": [], "custom": [{"protocol": "TCP", "port": [80, 22]}]}
                fields["service"] = fields["service"] if rng.random() < 0.2 else {"standard": [], "custom": []}
            elif column == "two" and rng.random() < 0.5:
                exception.update(source=_random_side(rng), service=_random_service(rng))
            else:
                exception["destination" if column == "destination" else "source"] = _random_side(rng) or {"site": [ref("2", "Site-B")]}
            fields["exceptions"] = [exception]
        wan.append(wan_rule(f"w{index}", rng.choice(["ALLOW", "ALLOW", "BLOCK"]), **fields))
    internet: List[Dict[str, Any]] = []
    for index in range(rng.randint(0, 4)):
        entry = wan_rule(f"i{index}", rng.choice(["ALLOW", "BLOCK", "BLOCK"]), source=_random_side(rng), destination=_random_side(rng, True),
                         service=_random_service(rng))  # fmt: skip
        del entry["rule"]["direction"]
        internet.append(entry)
    return bundle(wan, internet)


ADDRESSES = {"Site-A": ["10.1.0.10", "10.1.0.77", "10.1.1.9", "10.1.1.200"], "Site-B": ["10.2.0.20", "10.2.0.7", "10.2.0.99"],
             "Site-C": ["10.3.0.5", "10.3.0.200"], REMOTE: ["10.99.0.4", "10.99.0.33"], INTERNET: ["203.0.113.9", "198.51.100.5", "192.0.2.77"]}  # fmt: skip


def random_flow(rng: random.Random) -> Flow:
    src_site = rng.choice(["Site-A", "Site-B", "Site-C", REMOTE])
    dst_site = rng.choice(["Site-A", "Site-B", "Site-C", REMOTE, INTERNET, INTERNET])
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47"])
    return Flow(src_site, rng.choice(ADDRESSES[src_site]), dst_site, rng.choice(ADDRESSES[dst_site]), proto, rng.choice([22, 53, 80, 443, 5005, 21]))


def packet(flow: Flow) -> Packet:
    return Packet(flow.src_site, flow.dst_site, flow.src, flow.dst, flow.proto, 40000, flow.dport if flow.proto in ("tcp", "udp") else 0)


def test_random_policies_read_decide_like_the_judge() -> None:
    clean = 0
    for seed in range(100):
        rng = random.Random(seed)
        document = random_bundle(rng)
        model, _ = parse(document)
        if any(r.unsupported for r in model.rules):
            continue  # (set aside: the parser flagged a rule)
        clean += 1
        judge = world(document)
        for _ in range(250):
            flow = random_flow(rng)
            assert model_allows(model, packet(flow)) == judge.allows(flow), (seed, flow)
    assert clean >= 40


# -- the emitter ---------------------------------------------------------------------------------------------------------


def test_sample_written_for_cato_keeps_site_names_and_order() -> None:
    p, _ = parse(json.loads(SAMPLE.read_text()))
    text, report = emit(p, Options(zone_networks=dict(p.zone_networks)))
    script = CatoScript(text)
    wan = [r["name"] for r in script.rules["wanFirewall"]]
    assert wan[:3] == ["fws-Allow HQ to DC servers", "fws-Allow HQ to DC servers (2)", "fws-Block OT to HQ"]
    block = script.rules["wanFirewall"][2]
    assert [s["input"] for s in block["source"]["site"]] == ["Ghent Plant", "Leuven Lab"]
    assert all("inside" not in name for name in wan)  # (traffic inside one range never reaches Cato)
    assert script.rules["wanFirewall"][0]["destination"] == {"ip": ["10.20.0.10", "10.20.0.20"]}  # (within the site's networks)
    internet = [r["name"] for r in script.rules["internetFirewall"]]
    assert "fws-Internet Firewall implicit allow" not in internet and "CATO_DEFAULT_ALLOW" in codes(report)
    assert "CATO_INTERNET_DEFAULT" not in codes(report)
    finance = next(r for r in script.rules["wanFirewall"] if r["name"] == "fws-Finance to ERP")
    assert finance["enabled"] is False and report.item("rule", "Finance to ERP").disabled
    assert "CATO_LOAD" in codes(report) and report.item("rule", "Unknown host").skipped


def _model(*rules: Rule, zones: Tuple[str, ...] = ("lan", "dmz", "wan")) -> Policy:
    p = Policy(vendor="panos")
    for zone in zones:
        p.zones[zone] = Zone(zone)
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443,8000-8010")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["src"] = Service("src", [ServiceEntry(Protocol.TCP, "80", "1024")])
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8::/64")
    p.addresses["www"] = Address("www", AddressKind.FQDN, "www.example.com")
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def test_zones_inside_and_the_internet() -> None:
    p = _model(Rule("out", src_zones=["lan"], dst_zones=["wan"], services=["web"]), Rule("in", src_zones=["wan"], dst_zones=["dmz"]),
               Rule("both", src_zones=["lan"], destinations=["10.20.0.5"]), Rule("deny in", src_zones=["wan"], action=Action.DENY))  # fmt: skip
    text, report = emit(p, Options(inside_zones=["lan", "dmz"]))
    script = CatoScript(text)
    assert [r["name"] for r in script.rules["internetFirewall"]][:2] == ["fws-out", "fws-both"]
    assert script.rules["internetFirewall"][0]["service"]["custom"] == [{"protocol": "TCP", "port": [80, 443]}, {"protocol": "TCP", "portRange": {"from": 8000, "to": 8010}}]
    assert [r["name"] for r in script.rules["wanFirewall"]] == ["fws-both"]
    assert report.item("rule", "in").skipped and "CATO_FROM_INTERNET" in rule_codes(report, "in")
    assert next(f for f in report.item("rule", "deny in").findings if f.code == "CATO_FROM_INTERNET").severity == Severity.INFO
    last = script.rules["internetFirewall"][-1]
    assert last["action"] == "BLOCK" and last["enabled"] is False and "CATO_INTERNET_DEFAULT" in codes(report)
    assert "CATO_SITE_NAMES" in codes(report)


def test_the_zone_behind_the_default_route_is_the_internet() -> None:
    p = _model(Rule("out", src_zones=["lan"], dst_zones=["wan"]))
    text, report = emit(p, Options(zone_networks={"lan": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"], "wan": ["0.0.0.0/0"]}))
    script = CatoScript(text)
    assert script.rules["internetFirewall"][0]["source"] == {"subnet": ["10.10.0.0/16"]} and "CATO_INTERNET_BY_ROUTE" in codes(report)


def test_a_zone_and_addresses_are_written_as_sites_and_an_exception() -> None:
    p = _model(Rule("r", src_zones=["lan"], dst_zones=["dmz"], sources=["10.1.0.0/24"], destinations=["10.2.0.5"], negate_destination=True))
    script = CatoScript(emit(p)[0])
    rule = script.rules["wanFirewall"][0]
    assert rule["source"] == {"site": [{"by": "NAME", "input": "lan"}]} and rule["destination"] == {"site": [{"by": "NAME", "input": "dmz"}]}
    sources = [e["source"] for e in rule["exceptions"] if "source" in e]
    assert sources == [{"ipRange": [{"from": "0.0.0.0", "to": "10.0.255.255"}, {"from": "10.1.1.0", "to": "255.255.255.255"}]}]
    assert [e["destination"] for e in rule["exceptions"] if "destination" in e] == [{"ip": ["10.2.0.5"]}]
    judge = CatoWorld(script.rules["wanFirewall"], [])
    assert judge.allows(Flow("lan", "10.1.0.9", "dmz", "10.2.0.6", "tcp", 80))
    assert not judge.allows(Flow("lan", "10.1.0.9", "dmz", "10.2.0.5", "tcp", 80))
    assert not judge.allows(Flow("lan", "10.1.7.9", "dmz", "10.2.0.6", "tcp", 80))
    assert not judge.allows(Flow("dmz", "10.1.0.9", "lan", "10.2.0.6", "tcp", 80))


def test_what_cannot_be_written() -> None:
    p = _model(Rule("ping", services=["ping"]), Rule("src ports", services=["src"]), Rule("six only", sources=["six"]),
               Rule("six and four", sources=["six", "10.0.0.0/8"]), Rule("name", destinations=["www"], src_zones=["lan"], dst_zones=["dmz"]),
               Rule("deny ping", services=["ping"], action=Action.DENY), Rule("not dns", services=["dns"], negate_service=True),
               Rule("user", users=["corp\\someone"]))  # fmt: skip
    text, report = emit(p, Options(inside_zones=["lan", "dmz"]))
    script = CatoScript(text)
    for name in ("ping", "src ports", "six only", "name", "deny ping"):
        assert report.item("rule", name).skipped, name
    assert "NOT enforced" in report.item("rule", "deny ping").findings[-1].message
    assert next(f for f in report.item("rule", "six and four").findings if f.code == "CATO_IPV6").severity == Severity.APPROX
    negated = next(r for r in script.rules["wanFirewall"] if r["name"] == "fws-not dns")
    assert negated["service"] == {"custom": []} and negated["exceptions"][0]["service"] == {"custom": [{"protocol": "TCP_UDP", "port": [53]}]}
    user = next(r for r in script.rules["wanFirewall"] if r["name"] == "fws-user")
    assert user["enabled"] is False and report.item("rule", "user").disabled


def test_remote_users_as_source_and_destination() -> None:
    p = _model(Rule("from users", src_zones=[REMOTE, "lan"], dst_zones=["dmz"]), Rule("to users", src_zones=["lan"], dst_zones=[REMOTE, "dmz"]),
               zones=("lan", "dmz", REMOTE, INTERNET))  # fmt: skip
    p.vendor = "cato"
    p.zones["lan"].interfaces, p.zones["dmz"].interfaces = ["Main Office"], ["Data Center"]
    text, report = emit(p)
    rules = CatoScript(text).rules["wanFirewall"]
    assert rules[0]["source"] == {"site": [{"by": "NAME", "input": "Main Office"}]} and "connectionsOriginList" not in rules[0]
    assert rules[1]["connectionsOriginList"] == ["REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER"] and rules[1]["source"] == {}
    assert rules[2]["destination"] == {} and rules[2]["exceptions"] == [{"destination": {"site": [{"by": "NAME", "input": "Main Office"}]},
                                                                         "name": "fwshift 1"}]
    assert "CATO_REMOTE_DESTINATION" in rule_codes(report, "to users")
    judge = CatoWorld(rules, [])
    assert judge.allows(Flow("Main Office", "10.0.0.1", REMOTE, "10.99.0.1", "tcp", 80))
    assert not judge.allows(Flow("Main Office", "10.0.0.1", "Main Office", "10.0.1.1", "tcp", 80))


def test_too_many_objects_in_one_rule_is_not_written() -> None:
    p = _model(Rule("many", sources=[f"10.0.{i}.{i * 2 + 1}" for i in range(70)]))
    _, report = emit(p)
    assert report.item("rule", "many").skipped and "more than 64" in report.item("rule", "many").findings[-1].message


def test_defaults_that_differ_from_cato() -> None:
    p = _model(Rule("r", src_zones=["lan"], dst_zones=["dmz"]))
    p.default_interzone = Action.ALLOW
    p.default_intrazone = Action.ALLOW
    text, report = emit(p, Options(inside_zones=["lan", "dmz"]))
    rules = CatoScript(text).rules["wanFirewall"]
    assert rules[-1]["name"] == "fws-allow the rest between sites" and rules[-1]["enabled"] is False
    inside = [r for r in rules if r["name"].startswith("fws-inside")]
    assert [r["source"] for r in inside] == [{"site": [{"by": "NAME", "input": "lan"}]}, {"site": [{"by": "NAME", "input": "dmz"}]}]
    assert {"CATO_WAN_DEFAULT", "CATO_INTRAZONE"} <= codes(report)


def test_nat_is_not_written() -> None:
    from fwshift.model import DestNat, NatRule, SnatKind, SourceNat

    p = _model(Rule("r"))
    p.nat_rules = [NatRule("hide", source_translation=SourceNat(SnatKind.INTERFACE), origin="hide"),
                   NatRule("forward", destinations=["198.51.100.10"], destination_translation=DestNat("10.20.0.5"), origin="forward")]  # fmt: skip
    _, report = emit(p)
    assert report.item("nat", "hide").skipped and report.item("nat", "hide").status == "skipped"
    assert next(f for f in report.item("nat", "forward").findings if f.code == "CATO_NAT").severity == Severity.REVIEW


@pytest.mark.parametrize("seed", range(30))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    from test_iptables import random_packet

    rng = random.Random(seed)
    model = random_model(rng)
    for zone in ("eth0", "eth1", "eth2"):
        model.zones[zone] = Zone(zone)
    internet = rng.random() < 0.4
    options = Options(inside_zones=["eth0", "eth1"]) if internet else Options()
    text, report = emit(model, options)
    for rule in model.rules:
        item = report.item("rule", rule.origin)
        if item.disabled or item.skipped:
            rule.enabled = False
    script = CatoScript(text)
    for body in script.rules["internetFirewall"]:
        if body["name"] == "fws-block the rest to the internet":
            body["enabled"] = True  # (written off, for a person to switch on: the model's default)
    judge = CatoWorld(script.rules["wanFirewall"], script.rules["internetFirewall"])
    compared = 0
    for _ in range(500):
        pkt = random_packet(rng, 4)
        if pkt.dport == 0 and pkt.proto in ("tcp", "udp"):
            continue
        dst_site = INTERNET if internet and pkt.out_if == "eth2" else pkt.out_if
        if internet and pkt.in_if == "eth2":
            continue  # (from the internet: these policies do not decide it)
        flow = Flow(pkt.in_if, pkt.src, dst_site, pkt.dst, pkt.proto, pkt.dport)
        expected = model_verdict(model, pkt)
        allowed = model.default_interzone == Action.ALLOW if expected is None else expected
        if pkt.in_if == pkt.out_if and expected is None:
            allowed = model.default_intrazone == Action.ALLOW
        compared += 1
        assert judge.allows(flow) == allowed, (seed, pkt, [r["name"] for r in script.rules["wanFirewall"]])
    assert compared > 300


def test_a_policy_read_written_and_judged_again_decides_the_same() -> None:
    """Cato -> model -> Cato: the rules written decide, for the judge, what the rules read decide."""
    agreed = 0
    for seed in range(40):
        rng = random.Random(500 + seed)
        document = random_bundle(rng)
        model, _ = parse(document)
        if any(r.unsupported for r in model.rules):
            continue
        text, report = emit(model, Options(zone_networks=dict(model.zone_networks)))
        if any(item.skipped and item.findings and item.findings[-1].severity == Severity.REVIEW for item in report.items.values()):
            continue  # (a rule was not written: the report says so)
        script = CatoScript(text)
        source, written = world(document), CatoWorld(script.rules["wanFirewall"], script.rules["internetFirewall"], SITES)
        for _ in range(200):
            flow = random_flow(rng)
            assert source.allows(flow) == written.allows(flow), (seed, flow)
        agreed += 1
    assert agreed >= 25


# -- the script itself -----------------------------------------------------------------------------------------------------

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
body = args[args.index("--data-binary") + 1][1:]
request = json.load(open(body))
log = os.environ["FAKE_LOG"]
count = sum(1 for _ in open(log)) if os.path.exists(log) else 0
with open(log, "a") as handle:
    handle.write(json.dumps({"headers": [a for a in args if a.startswith("x-api-key")], "request": request}) + "\n")
json.dump({"data": {"policy": {"x": {"addRule": {"rule": {"rule": {"id": "id%d" % (count + 1)}}, "status": "SUCCESS", "errors": []}}}}}, open(out, "w"))
sys.stdout.write("200")
'''


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_script_runs_against_a_fake_api(tmp_path: Path) -> None:
    p, _ = parse(json.loads(SAMPLE.read_text()))
    text, _ = emit(p, Options(zone_networks=dict(p.zone_networks)))
    script = tmp_path / "load.sh"
    script.write_text(text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", FAKE_LOG=str(tmp_path / "log"), OUT=str(tmp_path / "out"),
               CATO_API_KEY="secret", CATO_ACCOUNT_ID="12345", CATO_WAN_POSITION="FIRST_IN_SECTION", CATO_WAN_REF="s-1")  # fmt: skip
    dry = subprocess.run(["sh", str(script)], env=dict(env, DRY_RUN="1"), capture_output=True, text=True, timeout=60)
    assert dry.returncode == 0 and not (tmp_path / "log").exists(), dry.stderr
    run = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    calls = [json.loads(line) for line in (tmp_path / "log").read_text().splitlines()]
    reader = CatoScript(text)
    assert len(calls) == len(reader.rules["wanFirewall"]) + len(reader.rules["internetFirewall"])
    first = calls[0]["request"]
    assert first["variables"]["accountId"] == "12345" and first["variables"]["policy"] is None
    assert first["variables"]["input"]["at"] == {"position": "FIRST_IN_SECTION", "ref": "s-1"}
    assert calls[1]["request"]["variables"]["input"]["at"] == {"position": "AFTER_RULE", "ref": "id1"}
    wan_count = len(reader.rules["wanFirewall"])
    assert calls[wan_count]["request"]["variables"]["input"]["at"] == {"position": "LAST_IN_POLICY"}  # (the Internet Firewall starts anew)
    assert "internetFirewall(input: $policy)" in calls[wan_count]["request"]["query"]
    assert [c["request"]["variables"]["input"]["rule"] for c in calls] == reader.rules["wanFirewall"] + reader.rules["internetFirewall"]
    assert calls[0]["headers"] == ["x-api-key: secret"]
    assert len((tmp_path / "out" / "created.txt").read_text().splitlines()) == len(calls)
    bad = subprocess.run(["sh", str(script)], env=dict(env, CATO_WAN_POSITION="SOMEWHERE"), capture_output=True, text=True, timeout=60)
    assert bad.returncode != 0 and "not a valid value" in bad.stderr


def test_cli_converts_the_sample_both_ways(tmp_path: Path) -> None:
    out = tmp_path / "out.sh"
    assert main(["convert", str(SAMPLE), "--to", "cato", "-o", str(out), "-q"]) == 0
    assert CatoScript(out.read_text()).rules["wanFirewall"]
    assert main(["convert", str(SAMPLE), "--to", "panos", "-o", str(tmp_path / "out.set"), "-q"]) == 0
