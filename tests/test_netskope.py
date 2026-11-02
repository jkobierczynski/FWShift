# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Netskope Cloud Firewall: the parser (FWShift reads it only), and packet-level equivalence with a judge of its own.

``CfwJudge`` decides connections from the JSON as the Cloud Firewall does by Netskope's documentation: the rules of
the Real-time Protection policies top to bottom, first match, policies of other types and disabled ones skipped; a
rule matches the access method the traffic came by (none named: all), its Source IP (Matches / Does Not Match) and its
destination (Any Traffic; a custom firewall app's destinations with its ports, empty destinations being any; a
destination profile's addresses together with a service object's ports); what no rule matches gets the Default Action.
Random policies are written as that JSON and decided by the judge and by the model the parser reads, packet by packet.
The judge shares no code with the parser; both are written from the same reading of the documentation, and the shape
of the JSON is FWShift's reading (Netskope does not publish it): they find where the code disagrees with that reading,
not where the reading is wrong.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
from typing import Any, Dict, List, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.options import Options
from fwshift.model import ANY, Action, Policy
from fwshift.parsers import netskope as parse_netskope
from fwshift.report import Report

METHODS = {"client": "Client", "ipsec": "IPSec", "gre": "GRE"}


def parse(document: Any) -> Tuple[Policy, Report]:
    report = Report()
    return parse_netskope.parse(json.dumps(document).encode(), report), report


def codes(report: Report) -> set:
    found = {note.code for note in report.notes}
    for item in report.items.values():
        found |= {f.code for f in item.findings}
    return found


def rule_codes(report: Report, name: str) -> set:
    return {f.code for item in report.items.values() if item.name == name for f in item.findings}


def fw(name: str, action: str = "allow", enabled: str = "1", **data: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {"policy_type": "firewall", "json_version": 3, "match_criteria_action": {"action_name": action}}
    body.update(data)
    return {"rule_name": name, "enabled": enabled, "rule_data": body}


def bundle(rules: List[Dict[str, Any]], **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"default_action": "block", "rules": rules}
    out.update(extra)
    return out


def by_name(model: Policy) -> Dict[str, Any]:
    return {rule.name: rule for rule in model.rules}


def verdict(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 443, zone: str = "client") -> bool:
    return model_allows(model, Packet(zone, "internet", src, dst, proto, 40000, dport, 8))


# -- the sample -------------------------------------------------------------------------------------


def test_sample_is_read_in_order() -> None:
    data = (DATA / "netskope_sample.json").read_bytes()
    assert cli.detect_format(data) == "netskope"
    report = Report()
    model = cli.load(data, "netskope", report)
    assert model.vendor == "netskope"
    assert set(model.zones) == {"client", "ipsec", "gre", "internet"}
    names = [rule.name for rule in model.rules]
    # The web and DLP policies are skipped; the rule of two custom apps is two rules in its place; the Default Action ends.
    assert names == ["Block known bad ranges", "Branch mail to partner", "Voice from sites", "Admins to jump hosts [app-ssh-jump]",
                     "Admins to jump hosts [app-rdp-gw]", "Engineering to git", "Block BitTorrent", "Not from the server networks: no NTP",
                     "Time servers", "Old FTP exception", "SaaS files from the office", "Ping out", "DNS out", "Contractors: nothing else",
                     "Lab network out", "Default Action"]  # fmt: skip
    rules = by_name(model)
    assert len({rule.origin for rule in model.rules}) == len(model.rules)
    assert rules["Branch mail to partner"].src_zones == ["ipsec", "gre"] and rules["Branch mail to partner"].dst_zones == ["internet"]
    assert rules["Block known bad ranges"].src_zones == ["client", "ipsec", "gre"]
    assert rules["Not from the server networks: no NTP"].negate_source
    assert rules["Not from the server networks: no NTP"].sources == ["10.20.10.0/24", "10.20.11.0/25"]
    assert not rules["Old FTP exception"].enabled
    assert rules["Default Action"].action == Action.DENY
    assert rules["Admins to jump hosts [app-rdp-gw]"].source_ids == {"netskope.rule_id": "105", "netskope.rule_name": "Admins to jump hosts"}
    assert model.address_groups["dp-blocked-ranges"].members == ["192.0.2.128/26", "203.0.113.200"]
    assert model.address_groups["dp-saas-domains"].unsupported
    assert [(e.protocol.value, e.dst_ports) for e in model.services["svc-voice"].entries] == [("tcp", "5061"), ("udp", "5060,10000-20000")]
    assert [(e.protocol.value, e.dst_ports) for e in model.services["DNS"].entries] == [("tcp", "53"), ("udp", "53")]
    unsupported = {rule.name for rule in model.rules if rule.unsupported}
    assert unsupported == {"Engineering to git", "Block BitTorrent", "SaaS files from the office", "Contractors: nothing else"}
    assert rule_codes(report, "Engineering to git") == {"NETSKOPE_USERS", "NETSKOPE_FQDN"}
    assert rule_codes(report, "Block BitTorrent") == {"NETSKOPE_APPLICATION"}
    assert rule_codes(report, "SaaS files from the office") == {"NETSKOPE_NOT_CONVERTED", "NETSKOPE_FQDN"}
    assert {"NETSKOPE_SOURCE", "NETSKOPE_WEB_TRAFFIC", "NETSKOPE_OTHER_POLICIES", "NETSKOPE_ICMP"} <= codes(report)
    assert "NETSKOPE_DEFAULT_ASSUMED" not in codes(report)
    # Packets: first match, the access method, the negated source, the product of profile and service object.
    assert verdict(model, "10.20.1.1", "198.51.100.25", dport=587, zone="ipsec")
    assert not verdict(model, "10.20.1.1", "198.51.100.25", dport=587, zone="client")  # (not by the Client)
    assert not verdict(model, "10.20.1.1", "198.51.100.25", dport=443, zone="gre")
    assert not verdict(model, "10.40.0.9", "192.0.2.130", zone="ipsec")  # (the bad ranges come first)
    assert verdict(model, "10.40.0.9", "192.0.2.10", zone="ipsec")
    assert not verdict(model, "10.20.9.1", "198.51.100.123", "udp", 123, "ipsec")  # (not from the server networks: blocked)
    assert verdict(model, "10.20.10.9", "198.51.100.123", "udp", 123, "ipsec")
    assert verdict(model, "10.30.1.1", "2001:db8:5::1", "udp", 15000, "gre")
    assert verdict(model, "10.99.0.5", "203.0.113.40", "udp", 3389, "client")
    assert not verdict(model, "10.99.0.5", "203.0.113.40", "tcp", 22, "client")
    assert verdict(model, "10.1.1.1", "192.0.2.10", "icmp", 0, "client")
    assert not verdict(model, "10.1.1.1", "192.0.2.10", "tcp", 8080, "client")  # (the Default Action)


def test_detection_claims_no_other_sample() -> None:
    for path in sorted(DATA.iterdir()):
        if path.is_file() and "_sample." in path.name and path.name != "netskope_sample.json":
            assert not parse_netskope.looks_like_netskope(path.read_bytes()), path.name
    assert parse_netskope.looks_like_netskope(json.dumps([fw("a")]).encode())
    assert not parse_netskope.looks_like_netskope(b'{"rule_data": {}}')


# -- the traps one by one ---------------------------------------------------------------------------


def test_input_forms() -> None:
    rules = [fw("all out", any_traffic=True)]
    for document in (rules, {"data": rules}, bundle(rules), {"rules": {"data": rules}}):
        model, report = parse(document)
        assert [r.name for r in model.rules] == ["all out", "Default Action"]
        assert not model.rules[0].unsupported
    # Without the Default Action, Netskope's default (Block) is taken and said.
    model, report = parse(rules)
    assert "NETSKOPE_DEFAULT_ASSUMED" in codes(report) and model.rules[-1].action == Action.DENY
    model, report = parse(bundle([], default_action="Allow"))
    assert model.rules[-1].action == Action.ALLOW and verdict(model, "10.0.0.1", "192.0.2.1", "udp", 9)
    with pytest.raises(ParseError, match="default_action"):
        parse(bundle([], default_action="alert"))
    with pytest.raises(ParseError, match="list of rules"):
        parse({"something": 1})
    with pytest.raises(ParseError, match="JSON"):
        parse_netskope.parse(b"{not json", Report())
    with pytest.raises(ParseError, match="not an object"):
        parse(bundle(["x"]))
    _, report = parse(bundle([], other=1))
    assert "NETSKOPE_UNKNOWN_KEYS" in codes(report)


def test_private_access_rules_are_refused() -> None:
    npa = {"rule_name": "npa", "enabled": "1", "rule_data": {"policy_type": "private-app", "private_apps": ["wiki"], "users": ["a@example.com"],
           "match_criteria_action": {"action_name": "allow"}}}  # fmt: skip
    with pytest.raises(ParseError, match="Private Access"):
        parse([npa])


def test_other_policy_types_are_skipped() -> None:
    web = {"rule_name": "web", "enabled": "1", "rule_data": {"policy_type": "web", "match_criteria_action": {"action_name": "allow"}}}
    model, report = parse(bundle([web, fw("block all", "block", any_traffic=True)]))
    assert [r.name for r in model.rules] == ["block all", "Default Action"]
    model, report = parse(bundle([web]))
    assert [r.name for r in model.rules] == ["Default Action"]
    assert {"NETSKOPE_NO_FIREWALL_RULES", "NETSKOPE_OTHER_POLICIES"} <= codes(report)
    # A rule that does not say its type is kept, not converted.
    untyped = fw("untyped", any_traffic=True)
    del untyped["rule_data"]["policy_type"]
    model, _ = parse(bundle([untyped]))
    assert model.rules[0].unsupported


def test_enabled_values() -> None:
    model, report = parse(bundle([fw("a", enabled="0", any_traffic=True), fw("b", any_traffic=True), fw("c", enabled="yes", any_traffic=True)]))
    rules = by_name(model)
    assert not rules["a"].enabled and not rules["a"].unsupported
    assert rules["b"].enabled
    assert not rules["c"].enabled and rules["c"].unsupported


def test_what_narrows_is_not_converted() -> None:
    cases = {
        "users": ({"users": ["u@example.com"]}, "NETSKOPE_USERS"),
        "groups": ({"user_groups": ["Sales"]}, "NETSKOPE_USERS"),
        "ous": ({"organization_units": ["/example/eng"]}, "NETSKOPE_USERS"),
        "cloud": ({"cloud_apps": ["Box"]}, "NETSKOPE_APPLICATION"),
        "location": ({"net_location_obj": ["HQ"]}, "NETSKOPE_NOT_CONVERTED"),
        "countries": ({"src_countries": ["BE"]}, "NETSKOPE_NOT_CONVERTED"),
        "schedule": ({"schedule": {"time_interval_obj": ["work hours"], "time_range": []}}, "NETSKOPE_NOT_CONVERTED"),
        "unknown": ({"dst_countries": ["BE"]}, "NETSKOPE_NOT_CONVERTED"),
        "method": ({"access_method": ["Clientless"]}, "NETSKOPE_NOT_CONVERTED"),
        "src fqdn": ({"src_ips": ["host.example.com"]}, "NETSKOPE_FQDN"),
        "host bits": ({"src_ips": ["10.0.0.5/24"]}, "NETSKOPE_NOT_CONVERTED"),
        "negate nothing": ({"b_negate_src_ips": True}, "NETSKOPE_NOT_CONVERTED"),
        "action": ({"match_criteria_action": {"action_name": "alert"}}, "NETSKOPE_NOT_CONVERTED"),
        "action key": ({"match_criteria_action": {"action_name": "allow", "isolate": True}}, "NETSKOPE_NOT_CONVERTED"),
    }
    for name, (data, code) in cases.items():
        model, report = parse(bundle([fw(name, any_traffic=True, **data)]))
        assert model.rules[0].unsupported, name
        assert code in rule_codes(report, name), name
    # Empty criteria are Any, as Netskope reads a criterion that is not used.
    model, report = parse(bundle([fw("empty", any_traffic=True, users=[], user_groups=[], net_location_obj=[], b_negate_net_location=False,
                                     schedule={"time_interval_obj": [], "time_range": []}, access_method=[])]))  # fmt: skip
    assert not model.rules[0].unsupported
    # A key of the rule outside rule_data that is not known.
    odd = fw("odd", any_traffic=True)
    odd["priority"] = 3
    model, _ = parse(bundle([odd]))
    assert model.rules[0].unsupported


def test_destinations() -> None:
    objects = {
        "service_objects": [{"name": "web", "protocols": {"tcp": ["80", "443"]}}, {"name": "bad", "protocols": {"tcp": ["0"]}},
                            {"name": "none", "protocols": {}}],
        "destination_profiles": [{"name": "p1", "type": "insensitive", "values": ["192.0.2.0/24"]}, {"name": "rx", "type": "regex", "values": [".*"]},
                                 {"name": "empty", "type": "insensitive", "values": []}],
        "firewall_apps": [{"name": "a1", "destinations": ["192.0.2.5"], "protocols": {"tcp": ["22"]}},
                          {"name": "a2", "destinations": [], "protocols": {"udp": ["500"]}}],
    }  # fmt: skip
    rules = [fw("profile only", destination_profiles=["p1"]), fw("service only", service_objects=["web"]),
             fw("both", destination_profiles=["p1"], service_objects=["web"]), fw("apps", firewall_apps=["a1", "a2"]),
             fw("one app", firewall_apps=["a1"]), fw("apps and profile", firewall_apps=["a1"], destination_profiles=["p1"]),
             fw("any and more", any_traffic=True, service_objects=["web"]), fw("nothing"), fw("missing profile", destination_profiles=["nope"]),
             fw("missing service", service_objects=["SSH"]), fw("bad service", service_objects=["bad"]), fw("no protocols", service_objects=["none"]),
             fw("regex", destination_profiles=["rx"]), fw("empty profile", destination_profiles=["empty"]), fw("predefined", firewall_apps=["SSH"])]  # fmt: skip
    model, report = parse(bundle(rules, **objects))
    got = by_name(model)
    assert got["profile only"].destinations == ["p1"] and got["profile only"].services == [ANY]
    assert got["service only"].destinations == [ANY] and got["service only"].services == ["web"]
    assert got["both"].destinations == ["p1"] and got["both"].services == ["web"]
    assert got["apps [a1]"].destinations == ["a1"] and got["apps [a2]"].destinations == [ANY] and got["apps [a2]"].services == ["a2"]
    assert "apps" not in got and "NETSKOPE_APPS_SPLIT" in rule_codes(report, "apps [a1]")
    assert got["one app"].destinations == ["a1"] and got["one app"].services == ["a1"]
    for name in ("apps and profile", "any and more", "nothing", "missing profile", "missing service", "bad service", "no protocols", "regex",
                 "empty profile", "predefined"):  # fmt: skip
        assert got[name].unsupported, name
    assert not any(got[name].unsupported for name in ("profile only", "service only", "both", "apps [a1]", "apps [a2]", "one app"))


def test_port_forms() -> None:
    objects = {"service_objects": [{"name": "s", "protocols": {"tcp": ["22, 80", "8000 - 8010"], "tcp_udp": ["53"], "udp": "123,124"}}]}
    model, _ = parse(bundle([fw("r", service_objects=["s"])], **objects))
    assert [(e.protocol.value, e.dst_ports) for e in model.services["s"].entries] == [("tcp", "22,80,8000-8010,53"), ("udp", "123,124,53")]
    for bad in (["70000"], ["1-"], ["any"], [{"port": 1}]):
        model, _ = parse(bundle([fw("r", service_objects=["s"])], service_objects=[{"name": "s", "protocols": {"tcp": bad}}]))
        assert model.services["s"].unsupported and model.rules[0].unsupported, bad


def test_names_are_unique() -> None:
    model, _ = parse(bundle([fw("same", any_traffic=True), fw("same", any_traffic=True), fw("", any_traffic=True), fw("Default Action", any_traffic=True)]))
    assert [r.name for r in model.rules] == ["same", "same (2)", "rule 3", "Default Action", "Default Action (2)"]


# -- the judge ---------------------------------------------------------------------------------------

V4 = ["10.1.0.5", "10.1.2.7", "10.2.0.9", "10.3.3.3", "192.0.2.10", "192.0.2.70", "198.51.100.5", "198.51.100.200", "203.0.113.9", "203.0.113.130"]
V6 = ["2001:db8:1::5", "2001:db8:2::9", "fd00:1::3"]
NETS = ["10.1.0.0/16", "10.2.0.0/24", "10.1.2.0-10.1.2.200", "10.3.3.3", "192.0.2.0/26", "198.51.100.0/25", "203.0.113.128/25", "2001:db8:1::/48",
        "fd00:1::/32"]  # fmt: skip
PORTS = [22, 53, 80, 123, 443, 500, 3389, 8080, 8443]
PORT_TEXTS = ["22", "53", "80", "443", "8000-8500", "3389", "500", "123", "1-1024"]


def in_net(address: str, net: str) -> bool:
    probe = ipaddress.ip_address(address)
    if "-" in net:
        first, last = (ipaddress.ip_address(x.strip()) for x in net.split("-"))
        return probe.version == first.version and first <= probe <= last  # type: ignore[operator]
    network = ipaddress.ip_network(net, strict=False)
    return probe.version == network.version and probe in network


def port_in(port: int, texts: List[str]) -> bool:
    for text in texts:
        low, _, high = text.partition("-")
        if int(low) <= port <= int(high or low):
            return True
    return False


class CfwJudge:
    """The Cloud Firewall as Netskope documents it, for the JSON the tests write."""

    def __init__(self, document: Dict[str, Any]) -> None:
        self.doc = document
        self.services = {s["name"]: s["protocols"] for s in document.get("service_objects", [])}
        self.profiles = {p["name"]: p["values"] for p in document.get("destination_profiles", [])}
        self.apps = {a["name"]: a for a in document.get("firewall_apps", [])}

    def _proto_ok(self, protocols: Dict[str, Any], proto: str, port: int) -> bool:
        if proto == "icmp":
            return protocols.get("icmp") is True  # (ICMP for IPv4: FWShift's reading, as the parser's)
        if proto not in ("tcp", "udp"):
            return False
        return port_in(port, list(protocols.get(proto, [])) + list(protocols.get("tcp_udp", [])))

    def _rule_matches(self, data: Dict[str, Any], method: str, src: str, dst: str, proto: str, port: int) -> bool:
        methods = data.get("access_method") or list(METHODS.values())
        if METHODS[method] not in methods:
            return False
        sources = data.get("src_ips") or []
        if sources:
            inside = any(in_net(src, net) for net in sources)
            if inside == bool(data.get("b_negate_src_ips")):
                return False
        if data.get("any_traffic"):
            return True
        if data.get("firewall_apps"):
            for name in data["firewall_apps"]:
                app = self.apps[name]
                if (not app["destinations"] or any(in_net(dst, net) for net in app["destinations"])) and self._proto_ok(app["protocols"], proto, port):
                    return True
            return False
        profiles, services = data.get("destination_profiles") or [], data.get("service_objects") or []
        if profiles and not any(in_net(dst, net) for p in profiles for net in self.profiles[p]):
            return False
        return not services or any(self._proto_ok(self.services[s], proto, port) for s in services)

    def allows(self, method: str, src: str, dst: str, proto: str, port: int) -> bool:
        for rule in self.doc["rules"]:
            data = rule["rule_data"]
            if data["policy_type"] != "firewall" or rule["enabled"] != "1":
                continue
            if self._rule_matches(data, method, src, dst, proto, port):
                return bool(data["match_criteria_action"]["action_name"] == "allow")
        return bool(self.doc["default_action"] == "allow")


def random_document(rng: random.Random) -> Dict[str, Any]:
    def protocols() -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key in rng.sample(["tcp", "udp", "tcp_udp", "icmp"], rng.randint(1, 2)):
            out[key] = True if key == "icmp" else rng.sample(PORT_TEXTS, rng.randint(1, 3))
        return out

    services = [{"name": f"svc{i}", "type": "custom", "protocols": protocols()} for i in range(4)]
    profiles = [{"name": f"dp{i}", "type": "insensitive", "values": rng.sample(NETS, rng.randint(1, 3))} for i in range(3)]
    apps = [{"name": f"app{i}", "destinations": rng.sample(NETS, rng.randint(0, 2)), "protocols": protocols()} for i in range(3)]
    rules: List[Dict[str, Any]] = []
    for index in range(rng.randint(1, 8)):
        if rng.random() < 0.1:
            rules.append({"rule_name": f"web {index}", "enabled": "1", "rule_data": {"policy_type": "web", "match_criteria_action": {"action_name": "block"}}})
            continue
        data: Dict[str, Any] = {"access_method": rng.sample(list(METHODS.values()), rng.randint(0, 3))}
        if rng.random() < 0.5:
            data["src_ips"] = rng.sample(NETS, rng.randint(1, 2))
            data["b_negate_src_ips"] = rng.random() < 0.3
        kind = rng.choice(["any", "apps", "profiles", "services", "both"])
        if kind == "any":
            data["any_traffic"] = True
        elif kind == "apps":
            data["firewall_apps"] = rng.sample([a["name"] for a in apps], rng.randint(1, 3))
        if kind in ("profiles", "both"):
            data["destination_profiles"] = rng.sample([p["name"] for p in profiles], rng.randint(1, 2))
        if kind in ("services", "both"):
            data["service_objects"] = rng.sample([s["name"] for s in services], rng.randint(1, 2))
        rules.append(fw(f"rule {index}", rng.choice(["allow", "block"]), rng.choice(["1", "1", "1", "0"]), **data))
    return {"default_action": rng.choice(["block", "allow"]), "service_objects": services, "destination_profiles": profiles,
            "firewall_apps": apps, "rules": rules}  # fmt: skip


@pytest.mark.parametrize("seed", range(60))
def test_random_policies_agree_with_the_judge(seed: int) -> None:
    rng = random.Random(seed)
    document = random_document(rng)
    judge = CfwJudge(document)
    model, report = parse(copy.deepcopy(document))
    assert not [rule.name for rule in model.rules if rule.unsupported]
    for _ in range(150):
        method = rng.choice(list(METHODS))
        family = rng.choice([4, 4, 4, 6])
        src, dst = (rng.choice(V4), rng.choice(V4)) if family == 4 else (rng.choice(V6), rng.choice(V6))
        proto = rng.choice(["tcp", "tcp", "udp", "icmp" if family == 4 else "icmp6", "47"])
        port = rng.choice(PORTS)
        expected = judge.allows(method, src, dst, proto, port)
        got = model_allows(model, Packet(method, "internet", src, dst, proto, 40000, port, 8))
        assert got == expected, (seed, method, src, dst, proto, port)


def test_the_judge_sees_the_traps() -> None:
    """The cases where a careless reading goes wrong, decided by the judge and the model alike."""
    document = bundle([fw("not from", "block", src_ips=["10.1.0.0/16"], b_negate_src_ips=True, any_traffic=True),
                       fw("sites only", access_method=["IPSec", "GRE"], any_traffic=True)],  # fmt: skip
                      default_action="block")
    judge, (model, _) = CfwJudge(document), parse(document)
    for method, src, expected in (("client", "10.2.0.9", False), ("client", "10.1.0.5", False), ("ipsec", "10.1.0.5", True), ("gre", "10.2.0.9", False)):
        assert judge.allows(method, src, "192.0.2.10", "tcp", 443) == expected
        assert verdict(model, src, "192.0.2.10", zone=method) == expected


def test_converts_to_every_target() -> None:
    """The sample goes to every target FWShift writes without an error (the goldens hold the output)."""
    data = (DATA / "netskope_sample.json").read_bytes()
    for target in cli.VENDORS:
        report = Report()
        model = cli.load(data, "netskope", report)
        assert cli.convert(model, target, report, Options())
    assert "netskope" in cli.SOURCES and "netskope" not in cli.VENDORS and "netskope" not in cli.EMITTERS


def test_no_emitter_is_offered() -> None:
    with pytest.raises(SystemExit):
        cli.main(["convert", str(DATA / "netskope_sample.json"), "--to", "netskope", "-q"])
