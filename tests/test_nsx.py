# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VMware NSX distributed firewall: parser, emitter, and packet-level equivalence with a judge of its own.

The judge below reads NSX Policy API JSON as NSX evaluates it (categories in order, policies and rules by their
sequence numbers, the default layer-3 rule, groups of addresses, nested groups and services, segments), and
shares no code with the parser.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet

from fwshift import cli
from fwshift.emitters import nsx as emit_nsx
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, RuleScope
from fwshift.model import Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import nsx as parse_nsx
from fwshift.report import Report, Severity

# -- the judge --------------------------------------------------------------------------------

ORDER = ["Emergency", "Infrastructure", "Environment", "Application", ""]
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}


class Judge:
    def __init__(self, document: Any) -> None:
        self.policies: List[Dict[str, Any]] = []
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.services: Dict[str, Dict[str, Any]] = {}
        self.segments: Dict[str, Dict[str, Any]] = {}
        self.visit(document, "/infra/domains/default")

    def visit(self, node: Any, domain: str) -> None:
        if isinstance(node, list):
            for item in node:
                self.visit(item, domain)
            return
        if not isinstance(node, dict):
            return
        kind = node.get("resource_type", "")
        if kind.startswith("Child") and kind != "ChildResourceReference":
            self.visit(node[kind[5:]], domain)
        elif kind == "ChildResourceReference":
            self.visit(node["children"], f"/infra/domains/{node['id']}")
        elif kind == "Domain":
            self.visit(node.get("children", []), f"/infra/domains/{node['id']}")
        elif kind == "Infra":
            self.visit(node.get("children", []), domain)
        elif kind == "Group":
            self.groups[node.get("path") or f"{domain}/groups/{node['id']}"] = node
        elif kind == "Service":
            self.services[node.get("path") or f"/infra/services/{node['id']}"] = node
        elif kind == "Segment":
            self.segments[node.get("path") or f"/infra/segments/{node['id']}"] = node
        elif kind == "SecurityPolicy":
            rules = list(node.get("rules") or []) + [c["Rule"] for c in node.get("children") or [] if c.get("resource_type") == "ChildRule"]
            self.policies.append(dict(node, rules=rules))

    def in_group(self, path: str, address: Any, depth: int = 0) -> bool:
        assert depth < 10
        node = self.groups[path]
        result = False
        for expression in node.get("expression") or []:
            kind = expression["resource_type"]
            if kind == "IPAddressExpression":
                result = result or any(self.holds(text, address) for text in expression["ip_addresses"])
            elif kind == "PathExpression":
                for member in expression["paths"]:
                    if "/groups/" in member:
                        result = result or self.in_group(member, address, depth + 1)
                    else:
                        segment = self.segments[member]
                        result = result or any(self.holds(s["network"], address) for s in segment["subnets"])
            elif kind == "ConjunctionOperator":
                assert expression["conjunction_operator"] == "OR"
            else:
                raise AssertionError(f"the judge does not know {kind}")
        return result

    @staticmethod
    def holds(text: str, address: Any) -> bool:
        if "-" in text:
            first, last = (ipaddress.ip_address(t.strip()) for t in text.split("-"))
            return first.version == address.version and first <= address <= last  # type: ignore[operator]
        network = ipaddress.ip_network(text, strict=False)
        return network.version == address.version and address in network

    def side(self, items: List[str], excluded: bool, address: Any) -> bool:
        if [i.upper() for i in items] in ([], ["ANY"]):
            found = True
        else:
            found = any(self.in_group(i, address) if i.startswith("/") else self.holds(i, address) for i in items)
        return found != excluded

    def entry(self, entry: Dict[str, Any], pkt: Packet, depth: int = 0) -> bool:
        kind = entry["resource_type"]
        proto = PROTO.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        if kind == "L4PortSetServiceEntry":
            if proto != {"TCP": 6, "UDP": 17}[entry["l4_protocol"]]:
                return False

            def within(ports: List[str], port: int) -> bool:
                if not ports:
                    return True
                for item in ports:
                    for part in item.replace(" ", "").split(","):
                        first, _, last = part.partition("-")
                        if int(first) <= port <= int(last or first):
                            return True
                return False

            return within(entry.get("destination_ports") or [], pkt.dport) and within(entry.get("source_ports") or [], pkt.sport)
        if kind == "ICMPTypeServiceEntry":
            if proto != (1 if entry["protocol"] == "ICMPv4" else 58):
                return False
            return entry.get("icmp_type") is None or entry["icmp_type"] == pkt.icmp_type
        if kind == "IPProtocolServiceEntry":
            return proto == entry["protocol_number"]
        if kind == "NestedServiceServiceEntry":
            assert depth < 10
            return any(self.entry(e, pkt, depth + 1) for e in self.services[entry["nested_service_path"]]["service_entries"])
        raise AssertionError(f"the judge does not know {kind}")

    def matches(self, rule: Dict[str, Any], pkt: Packet) -> bool:
        source, destination = ipaddress.ip_address(pkt.src), ipaddress.ip_address(pkt.dst)
        family = rule.get("ip_protocol", "IPV4_IPV6")
        if family != "IPV4_IPV6" and family != f"IPV{source.version}":
            return False
        if not self.side(rule.get("source_groups") or [], bool(rule.get("sources_excluded")), source):
            return False
        if not self.side(rule.get("destination_groups") or [], bool(rule.get("destinations_excluded")), destination):
            return False
        assert [p.upper() for p in rule.get("profiles") or ["ANY"]] == ["ANY"]
        assert rule.get("direction", "IN_OUT") == "IN_OUT"
        services = [s for s in rule.get("services") or []]
        if [s.upper() for s in services] == ["ANY"] or (not services and not rule.get("service_entries")):
            return True
        entries = [e for path in services for e in self.services[path]["service_entries"]] + list(rule.get("service_entries") or [])
        return any(self.entry(e, pkt) for e in entries)

    def allows(self, pkt: Packet) -> bool:
        layer3 = [p for p in self.policies if p.get("category", "") != "Ethernet"]
        layer3.sort(key=lambda p: (ORDER.index(p.get("category", "")), bool(p.get("is_default")), p.get("sequence_number", 0)))
        default = True
        skip_environment = False
        for policy in layer3:
            if skip_environment and policy.get("category") == "Environment":
                continue
            for rule in sorted(policy["rules"], key=lambda r: r.get("sequence_number", 0)):
                if rule.get("disabled"):
                    continue
                if rule.get("is_default"):
                    default = rule["action"] == "ALLOW"
                    continue
                if not self.matches(rule, pkt):
                    continue
                if rule["action"] == "JUMP_TO_APPLICATION":
                    skip_environment = True
                    break
                return rule["action"] == "ALLOW"
        return default


# -- random policies --------------------------------------------------------------------------

V4 = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "10.0.2.0/23", "10.0.0.17", "10.0.2.100-10.0.3.50", "10.0.4.0/24"]
V6 = ["2001:db8:1::/48", "2001:db8:2::/64", "2001:db8::1"]


def random_nsx(rng: random.Random) -> Dict[str, Any]:
    domain = "/infra/domains/default"
    groups: List[Dict[str, Any]] = []
    for index in range(5):
        expression: List[Dict[str, Any]] = [{"resource_type": "IPAddressExpression", "ip_addresses": rng.sample(V4, rng.randint(1, 3))}]
        if rng.random() < 0.4:
            expression += [{"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                           {"resource_type": "IPAddressExpression", "ip_addresses": rng.sample(V6, rng.randint(1, 2))}]  # fmt: skip
        if index and rng.random() < 0.3:
            expression += [{"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                           {"resource_type": "PathExpression", "paths": [f"{domain}/groups/g{rng.randrange(index)}"]}]  # fmt: skip
        groups.append({"resource_type": "ChildGroup", "Group": {"resource_type": "Group", "id": f"g{index}", "expression": expression}})
    groups.append({"resource_type": "ChildGroup", "Group": {"resource_type": "Group", "id": "seg", "expression": [
        {"resource_type": "PathExpression", "paths": ["/infra/segments/s1"]}]}})  # fmt: skip
    services: List[Dict[str, Any]] = []

    def l4(proto: str) -> Dict[str, Any]:
        ports = rng.choice([["80"], ["443", "8000-8010"], ["53"], ["22", "9000"], []])
        return {"resource_type": "L4PortSetServiceEntry", "l4_protocol": proto, "destination_ports": ports,
                "source_ports": rng.choice([[], [], ["1024-2000"]])}  # fmt: skip

    for index in range(5):
        kind = rng.random()
        if kind < 0.5:
            entries = [l4(rng.choice(["TCP", "UDP"])) for _ in range(rng.randint(1, 2))]
        elif kind < 0.65:
            entries = [{"resource_type": "ICMPTypeServiceEntry", "protocol": rng.choice(["ICMPv4", "ICMPv6"]),
                        "icmp_type": rng.choice([8, 128, 0])}]  # fmt: skip
        elif kind < 0.75:
            entries = [{"resource_type": "IPProtocolServiceEntry", "protocol_number": 47}]
        elif index:
            entries = [{"resource_type": "NestedServiceServiceEntry", "nested_service_path": f"/infra/services/s{rng.randrange(index)}"},
                       l4("TCP")]  # fmt: skip
        else:
            entries = [l4("TCP")]
        services.append({"resource_type": "ChildService", "Service": {"resource_type": "Service", "id": f"s{index}",
                                                                      "service_entries": entries}})  # fmt: skip

    def members() -> List[str]:
        if rng.random() < 0.3:
            return ["ANY"]
        out = []
        for _ in range(rng.randint(1, 2)):
            out.append(rng.choice([f"{domain}/groups/g{rng.randrange(5)}", f"{domain}/groups/seg", rng.choice(V4), rng.choice(V6)]))
        return out

    policies = []
    for index in range(rng.randint(2, 5)):
        category = rng.choice(["Emergency", "Infrastructure", "Environment", "Application", "Application"])
        rules = []
        for number in range(rng.randint(1, 5)):
            sources, destinations = members(), members()
            rule: Dict[str, Any] = {
                "resource_type": "Rule", "id": f"p{index}r{number}", "sequence_number": 10 * number + rng.choice([0, 0, 5]),
                "source_groups": sources, "destination_groups": destinations,
                "sources_excluded": sources != ["ANY"] and rng.random() < 0.2,
                "destinations_excluded": destinations != ["ANY"] and rng.random() < 0.2,
                "services": rng.choice([["ANY"], [f"/infra/services/s{rng.randrange(5)}"],
                                        [f"/infra/services/s{rng.randrange(5)}", f"/infra/services/s{rng.randrange(5)}"]]),
                "action": rng.choice(["ALLOW", "ALLOW", "DROP", "REJECT"]),
                "ip_protocol": rng.choice(["IPV4_IPV6", "IPV4_IPV6", "IPV4", "IPV6"]), "disabled": rng.random() < 0.1,
            }  # fmt: skip
            if rule["services"] != ["ANY"] and rng.random() < 0.2:
                rule["service_entries"] = [l4("UDP")]
            if category == "Environment" and rng.random() < 0.2:
                rule["action"] = "JUMP_TO_APPLICATION"
            rules.append(rule)
        policies.append({"resource_type": "ChildSecurityPolicy", "SecurityPolicy": {
            "resource_type": "SecurityPolicy", "id": f"p{index}", "category": category, "sequence_number": index * 10,
            "rules": rules}})  # fmt: skip
    policies.append({"resource_type": "ChildSecurityPolicy", "SecurityPolicy": {
        "resource_type": "SecurityPolicy", "id": "default-layer3-section", "category": "Application", "is_default": True,
        "rules": [{"resource_type": "Rule", "id": "default-layer3-rule", "is_default": True, "sequence_number": 1,
                   "source_groups": ["ANY"], "destination_groups": ["ANY"], "services": ["ANY"],
                   "action": rng.choice(["ALLOW", "DROP"])}]}})  # fmt: skip
    segment = {"resource_type": "ChildSegment", "Segment": {"resource_type": "Segment", "id": "s1",
                                                            "subnets": [{"gateway_address": "10.0.3.1/24", "network": "10.0.3.0/24"}]}}  # fmt: skip
    return {"resource_type": "Infra", "children": [
        {"resource_type": "ChildDomain", "Domain": {"resource_type": "Domain", "id": "default", "children": groups + policies}},
        segment] + services}  # fmt: skip


def nsx_packet(rng: random.Random) -> Packet:
    pkt = random_packet(rng, rng.choice([4, 4, 6]))
    if pkt.proto == "icmp6" or pkt.proto == "icmp":
        pkt.icmp_type = rng.choice([0, 8, 128])
    if rng.random() < 0.2 and ":" not in pkt.src:
        pkt.src = rng.choice(["10.0.0.17", "10.0.3.9", "10.0.2.120"])
    return pkt


def test_parsed_policy_decides_like_the_judge() -> None:
    compared = 0
    for seed in range(150):
        rng = random.Random(seed)
        document = random_nsx(rng)
        model = parse_nsx.parse(json.dumps(document).encode(), Report())
        if any(rule.unsupported for rule in model.rules):
            continue
        compared += 1
        judge = Judge(document)
        for _ in range(250):
            pkt = nsx_packet(rng)
            assert model_allows(model, pkt) == judge.allows(pkt), (seed, pkt, json.dumps(document, indent=1))
    assert compared >= 80


# -- the emitter ------------------------------------------------------------------------------

ZONES_AT = {"eth0": ["10.0.0.0/23", "2001:db8::/47"], "eth1": ["10.0.2.0/23", "2001:db8:2::/48"], "eth2": ["10.0.4.0/22", "2001:db8:3::/48"]}


def zone_of(address: str) -> str:
    probe = ipaddress.ip_address(address)
    return next(zone for zone, networks in ZONES_AT.items() if any(probe in ipaddress.ip_network(n) for n in networks))


@pytest.mark.parametrize("seed", range(40))
def test_emitted_policy_decides_like_the_model(seed: int) -> None:
    """Zones become the networks behind them; the judge reads the emitted body. Rules the emitter writes disabled are
    left out of the model's side of the comparison (the report says so)."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL  # (a rule type is written approximately: blocks more)
    report = Report()
    text = emit_nsx.emit(model, report, Options(zone_networks=ZONES_AT))
    judge = Judge(json.loads(text))
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        assert judge.allows(pkt) == model_allows(compared, pkt), (seed, pkt, text)


def test_roundtrip_through_nsx_keeps_every_decision() -> None:
    source, _ = load("nsx_sample.json")
    text = cli.convert(source, "nsx", Report())
    # The services of NSX itself are referred to, not written: an export of the target manager holds them.
    sample = json.loads((DATA / "nsx_sample.json").read_text(encoding="utf-8"))
    builtin = [c for c in sample["children"] if c.get("resource_type") == "ChildService" and c["Service"].get("_system_owned")]
    again = parse_nsx.parse(json.dumps([json.loads(text), {"results": [c["Service"] for c in builtin]}]).encode(), Report())
    rng = random.Random(5)
    for _ in range(2000):
        pkt = nsx_packet(rng)
        pkt.src = rng.choice(["10.10.5.15", "10.10.200.9", "10.10.7.15", "10.20.0.10", "10.20.1.5", "198.51.100.66", pkt.src])
        pkt.dst = rng.choice(["10.20.0.10", "10.20.1.9", "10.20.2.7", "10.30.1.7", "192.0.2.53", "198.51.100.40", pkt.dst])
        if (":" in pkt.src) != (":" in pkt.dst):
            continue
        assert model_allows(again, pkt) == model_allows(source, pkt), pkt


# -- the sample -------------------------------------------------------------------------------


def test_nsx_sample_rules() -> None:
    p, report = load("nsx_sample.json")
    assert p.vendor == "nsx" and p.default_interzone == Action.DROP and not p.nat_rules
    names = [r.name for r in p.rules]
    # categories in their order, then policies by number, the default policy last
    assert names[:4] == ["Block quarantined", "DNS to resolvers", "NTP", "Guests stay out"]
    assert "LAN to the application rules" not in names and names[-1] == "Old rule"
    rules = {r.name: r for r in p.rules}
    assert rules["Block quarantined"].sources == ["Quarantine"] and p.address_groups["Quarantine"].dynamic_filter.startswith("nsx:")
    assert rules["Block quarantined"].log_start and rules["Block quarantined"].source_ids["nsx.rule_id"] == "1002"
    assert rules["DNS to resolvers"].services == ["DNS", "DNS-UDP"] and p.services["DNS"].builtin == "nsx"
    assert rules["NTP"].destinations == ["192.0.2.123"] and p.services[rules["NTP"].services[0]].entries[0].dst_ports == "123"
    assert "conditional jump" in rules["LAN block the rest"].unsupported[0]
    assert rules["Inbound web"].services == ["Web all"] and p.service_groups["Web all"].members == ["HTTPS", "app-8443"]
    assert not rules["Inbound web"].unsupported  # applied to DMZ, which holds its destinations
    assert "direction IN" in rules["App to DB"].unsupported[0]
    assert rules["Others no SSH"].negate_source and rules["Others no SSH"].action == Action.DENY
    assert p.address_groups["OT cell"].members == ["10.30.1.0/24"]
    assert "context profile SSL" in rules["TLS out"].unsupported[0]
    assert rules["Ping over IPv6"].sources == [ANY_V6]
    assert not rules["Old rule"].enabled
    assert p.address_groups["DMZ"].members == ["Web servers", "App servers"]
    assert p.address_groups["DB servers"].members == ["10.20.2.0/24", "2001:db8:20:2::/64"]
    codes = {n.code for n in report.notes}
    assert {"LAYER2_NOT_CONVERTED", "DYNAMIC_MEMBERSHIP"} <= codes and "DEFAULT_RULE_MISSING" not in codes
    assert [f.code for f in report.item("address-group", "OT cell").findings] == ["SEGMENT_AS_SUBNET"]
    assert [f.code for f in report.item("service", "FTP").findings] == ["ALG_SERVICE"]


def test_flat_list_answers_in_one_array() -> None:
    """The list answers of the API (policies, the rules of each, groups, services), put in one JSON array."""
    policies = {"results": [{"resource_type": "SecurityPolicy", "id": "p1", "path": "/infra/domains/default/security-policies/p1",
                             "category": "Application", "sequence_number": 5}], "result_count": 1}
    rules = {"results": [
        {"resource_type": "Rule", "id": "r2", "display_name": "second", "parent_path": "/infra/domains/default/security-policies/p1",
         "sequence_number": 20, "source_groups": ["ANY"], "destination_groups": ["/infra/domains/default/groups/web"],
         "services": ["/infra/services/web"], "action": "DROP"},
        {"resource_type": "Rule", "id": "r1", "display_name": "first", "parent_path": "/infra/domains/default/security-policies/p1",
         "sequence_number": 10, "source_groups": ["10.0.0.0/8"], "destination_groups": ["ANY"], "services": ["ANY"], "action": "ALLOW"},
    ], "result_count": 2}  # fmt: skip
    groups = {"results": [{"resource_type": "Group", "id": "web", "display_name": "web", "path": "/infra/domains/default/groups/web",
                           "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["192.0.2.10"]}]}]}
    services = {"results": [{"resource_type": "Service", "id": "web", "path": "/infra/services/web", "service_entries": [
        {"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["80", "443"]}]}]}  # fmt: skip
    p, report = parse(json.dumps([policies, rules, groups, services]))
    assert [(r.name, r.action) for r in p.rules] == [("first", Action.ALLOW), ("second", Action.DROP)]
    assert p.services["web"].entries[0].dst_ports == "80,443" and p.address_groups["web"].members == ["192.0.2.10"]
    assert "DEFAULT_RULE_MISSING" in {n.code for n in report.notes} and p.default_interzone == Action.DENY


# -- parser details ---------------------------------------------------------------------------


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_nsx.parse(text.encode(), report), report


def one_policy(rules: List[Dict[str, Any]], groups: Optional[List[Dict[str, Any]]] = None, **extra: Any) -> str:
    policy = {"resource_type": "SecurityPolicy", "id": "p", "category": "Application", "rules": rules}
    policy.update(extra)
    return json.dumps({"resource_type": "Infra", "children": [{"resource_type": "ChildDomain", "Domain": {
        "resource_type": "Domain", "id": "default",
        "children": [{"resource_type": "ChildGroup", "Group": g} for g in groups or []]
                    + [{"resource_type": "ChildSecurityPolicy", "SecurityPolicy": policy}]}}]})  # fmt: skip


def nsx_rule(ident: str, **fields: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"resource_type": "Rule", "id": ident, "source_groups": ["ANY"], "destination_groups": ["ANY"],
                           "services": ["ANY"], "action": "ALLOW"}  # fmt: skip
    out.update(fields)
    return out


G = "/infra/domains/default/groups/"


def test_what_is_never_read_as_any() -> None:
    groups = [{"resource_type": "Group", "id": "both", "expression": [
                  {"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.0/8"]},
                  {"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"},
                  {"resource_type": "IPAddressExpression", "ip_addresses": ["10.1.0.0/16"]}]},
              {"resource_type": "Group", "id": "idfw", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.2.0.0/16"]}],
               "extended_expression": [{"resource_type": "IdentityGroupExpression"}]},
              {"resource_type": "Group", "id": "macs", "expression": [{"resource_type": "MACAddressExpression", "mac_addresses": ["00:00:5e:00:53:01"]}]},
              {"resource_type": "Group", "id": "bad", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.0/33"]}]}]  # fmt: skip
    p, _ = parse(one_policy([
        nsx_rule("and", source_groups=[G + "both"]),
        nsx_rule("identity", source_groups=[G + "idfw"]),
        nsx_rule("mac", source_groups=[G + "macs"]),
        nsx_rule("badaddress", source_groups=[G + "bad"]),
        nsx_rule("missing", source_groups=[G + "nowhere"]),
        nsx_rule("profile", profiles=["/infra/context-profiles/SSL"]),
        nsx_rule("out", direction="OUT"),
        nsx_rule("strange", action="REDIRECT"),
        nsx_rule("badservice", services=["/infra/services/nowhere"]),
        nsx_rule("ether", service_entries=[{"resource_type": "EtherTypeServiceEntry", "ether_type": 2048}], services=[]),
        nsx_rule("fine", source_groups=["10.9.0.0/16"]),
    ], groups))
    assert [r.name for r in p.rules] == ["and", "identity", "mac", "badaddress", "missing", "profile", "out", "strange",
                                         "badservice", "ether", "fine"]  # fmt: skip
    groups_of = p.address_groups
    assert groups_of["both"].unsupported and groups_of["idfw"].unsupported and groups_of["macs"].dynamic_filter
    assert groups_of["bad"].unsupported and groups_of["nowhere"].unsupported
    assert p.rules[5].unsupported and p.rules[6].unsupported and p.rules[7].unsupported and p.rules[7].action == Action.DROP
    assert p.services["nowhere"].unsupported and p.services[p.rules[9].services[0]].unsupported
    assert not p.rules[-1].unsupported
    out = cli.convert(p, "iptables", Report())
    assert out.count("# FWSHIFT disabled") == 10  # every rule but the last


def test_applied_to_direction_and_versions() -> None:
    groups = [{"resource_type": "Group", "id": "web", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.1.0/24"]}]},
              {"resource_type": "Group", "id": "mixed", "expression": [
                  {"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.2.0/24"]},
                  {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                  {"resource_type": "IPAddressExpression", "ip_addresses": ["2001:db8::/32"]}]}]  # fmt: skip
    p, report = parse(one_policy([
        nsx_rule("covered", destination_groups=[G + "web"], scope=[G + "web"]),
        nsx_rule("wider", destination_groups=[G + "mixed"], scope=[G + "web"]),
        nsx_rule("block-wider", destination_groups=[G + "mixed"], scope=[G + "web"], action="DROP"),
        nsx_rule("block-in", destination_groups=[G + "web"], direction="IN", action="DROP"),
        nsx_rule("v4", source_groups=[G + "mixed"], destination_groups=[G + "web"], ip_protocol="IPV4"),
        nsx_rule("v6", source_groups=[G + "mixed"], destination_groups=[G + "mixed"], ip_protocol="IPV6"),
        nsx_rule("v6-none", source_groups=[G + "web"], destination_groups=[G + "mixed"], ip_protocol="IPV6"),
    ], groups))
    rules = {r.name: r for r in p.rules}
    assert not rules["covered"].unsupported and rules["wider"].unsupported and not rules["block-wider"].unsupported
    assert [f.code for f in report.item("rule", "block-wider").findings] == ["APPLIED_TO"]
    assert [f.code for f in report.item("rule", "block-in").findings] == ["DIRECTION"]
    assert rules["v4"].sources == ["10.0.2.0/24"] and rules["v4"].destinations == ["web"]  # the IPv4 part of the group
    assert rules["v6"].sources == rules["v6"].destinations == ["2001:db8::/32"]
    assert "v6-none" not in rules and "RULE_WITHOUT_EFFECT" in {n.code for n in report.notes}


def test_connectivity_preference_and_stateless_policies() -> None:
    groups = [{"resource_type": "Group", "id": "app", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.5.0/24"]}]}]
    p, report = parse(one_policy([nsx_rule("in", destination_groups=[G + "app"])], groups, scope=[G + "app"],
                                 connectivity_preference="ALLOWLIST", stateful=False))
    assert [(r.name, r.action, r.sources, r.destinations) for r in p.rules] == [
        ("in", Action.ALLOW, [ANY], ["app"]), ("p-default-source", Action.DROP, ["app"], [ANY]),
        ("p-default-destination", Action.DROP, [ANY], ["app"])]  # fmt: skip
    assert "STATELESS_POLICY" in {n.code for n in report.notes}
    p, _ = parse(one_policy([], groups, scope=[G + "app"], connectivity_preference="DENYLIST"))
    assert all(r.unsupported and r.action == Action.ALLOW for r in p.rules)


def test_equal_sequence_layer2_drops_and_gateway_policies() -> None:
    document = {"resource_type": "Infra", "children": [{"resource_type": "ChildDomain", "Domain": {"resource_type": "Domain", "id": "default", "children": [
        {"resource_type": "ChildSecurityPolicy", "SecurityPolicy": {"resource_type": "SecurityPolicy", "id": "a", "category": "Application",
                                                                    "sequence_number": 3, "rules": [nsx_rule("ra")]}},
        {"resource_type": "ChildSecurityPolicy", "SecurityPolicy": {"resource_type": "SecurityPolicy", "id": "b", "category": "Application",
                                                                    "sequence_number": 3, "rules": [nsx_rule("rb")]}},
        {"resource_type": "ChildSecurityPolicy", "SecurityPolicy": {"resource_type": "SecurityPolicy", "id": "l2", "category": "Ethernet",
                                                                    "rules": [nsx_rule("drop-mac", action="DROP")]}},
        {"resource_type": "ChildGatewayPolicy", "GatewayPolicy": {"resource_type": "GatewayPolicy", "id": "gw"}}]}}]}  # fmt: skip
    p, report = parse(json.dumps(document))
    notes = {n.code: n for n in report.notes}
    assert {"EQUAL_SEQUENCE", "LAYER2_NOT_CONVERTED", "GATEWAY_POLICY_NOT_CONVERTED"} <= set(notes)
    assert notes["LAYER2_NOT_CONVERTED"].severity == Severity.REVIEW and [r.name for r in p.rules] == ["ra", "rb"]


def test_services_of_every_kind() -> None:
    entries = [{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["22, 33-70", "443"], "source_ports": ["1024-65535"]},
               {"resource_type": "ICMPTypeServiceEntry", "protocol": "ICMPv6", "icmp_type": 128, "icmp_code": 0},
               {"resource_type": "IPProtocolServiceEntry", "protocol_number": 50},
               {"resource_type": "IPProtocolServiceEntry", "protocol_number": 17},
               {"resource_type": "IGMPTypeServiceEntry"},
               {"resource_type": "ALGTypeServiceEntry", "alg": "TFTP", "destination_ports": ["69"]}]  # fmt: skip
    p, _ = parse(one_policy([nsx_rule("r", services=[], service_entries=entries)]))
    service = p.services[p.rules[0].services[0]]
    assert [(e.protocol.value, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code, e.ip_protocol) for e in service.entries] == [
        ("tcp", "22,33-70,443", "1024-65535", None, None, None), ("icmp6", "", "", 128, 0, None), ("ip", "", "", None, None, 50),
        ("udp", "", "", None, None, None), ("ip", "", "", None, None, 2), ("udp", "69", "", None, None, None)]  # fmt: skip


def test_parse_errors_and_detection() -> None:
    for text in (b"{not json", b'{"results": []}', b'{"resource_type": "Infra", "children": []}'):
        with pytest.raises(ParseError):
            parse_nsx.parse(text, Report())
    assert cli.detect_format(b'{"results": [{"resource_type": "SecurityPolicy", "id": "p"}]}') == "nsx"
    assert cli.detect_format(b'[{"uid": "x", "rulebase": []}]') == "checkpoint"


# -- emitter details --------------------------------------------------------------------------


def test_panos_to_nsx_output() -> None:
    policy, report = load("panos_sample.xml")
    networks = {"trust": ["10.10.0.0/16"], "dmz": ["10.20.0.0/24"], "ot": ["10.30.0.0/16"], "untrust": ["0.0.0.0/0", "::/0"]}
    body = json.loads(cli.convert(policy, "nsx", report, Options(zone_networks=networks)))
    assert body["resource_type"] == "Infra"
    domain = body["children"][-1]
    assert (domain["resource_type"], domain["id"], domain["target_type"]) == ("ChildResourceReference", "default", "Domain")
    policy_body = domain["children"][-1]["SecurityPolicy"]
    assert (policy_body["id"], policy_body["category"]) == ("FWShift", "Application")
    rules = {r["display_name"]: r for r in policy_body["rules"]}
    assert [r["sequence_number"] for r in policy_body["rules"]] == list(range(10, 10 * len(policy_body["rules"]) + 1, 10))
    inbound = rules["Inbound-Web"]  # the distributed firewall sees the address of the server, after the gateway's NAT
    assert inbound["destination_groups"] == ["10.20.0.10"] and not inbound["disabled"]
    assert rules["Admin-SSH"]["disabled"] and rules["Admin-SSH"]["notes"].startswith("FWSHIFT disabled")
    assert rules["Not-From-Guests"]["source_groups"] == ["10.10.0.0-10.10.199.255", "10.10.201.0-10.10.255.255"]
    assert policy_body["rules"][-1]["display_name"] == "fwshift-default-deny" and policy_body["rules"][-1]["action"] == "DROP"
    assert all(item.skipped for item in [report.item("nat", n.origin) for n in policy.nat_rules])
    assert {"NSX_LOAD", "NSX_DEFAULT_DENY"} <= {n.code for n in report.notes}


def test_objects_negation_and_port_lists() -> None:
    p = Policy(vendor="panos", default_interzone=Action.ALLOW, default_intrazone=Action.ALLOW)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.0.1.0/24")
    p.addresses["web6"] = Address("web6", AddressKind.NETWORK, "2001:db8:1::/64")
    p.addresses["name"] = Address("name", AddressKind.FQDN, "www.example.com")
    p.address_groups["all-web"] = AddressGroup("all-web", ["web", "web6"])
    p.address_groups["outer"] = AddressGroup("outer", ["all-web", "10.9.9.9"])
    p.services["many"] = Service("many", [ServiceEntry(Protocol.TCP, ",".join(str(n) for n in range(8000, 8014)) + ",9000-9010")])
    p.rules += [Rule("lists", sources=["outer"], destinations=[ANY_V4], services=["many"], origin="lists"),
                Rule("not-web", sources=["web"], negate_source=True, action=Action.DROP, origin="not-web"),
                Rule("fqdn", destinations=["name"], origin="fqdn"),
                Rule("neg-service", services=["many"], negate_service=True, origin="neg-service")]  # fmt: skip
    report = Report()
    body = json.loads(emit_nsx.emit(p, report, Options()))
    groups = {c["Group"]["id"]: c["Group"] for c in body["children"][-1]["children"] if c["resource_type"] == "ChildGroup"}
    assert groups["outer"]["expression"] == [
        {"resource_type": "IPAddressExpression", "ip_addresses": ["10.9.9.9"]},
        {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
        {"resource_type": "PathExpression", "paths": ["/infra/domains/default/groups/all-web"]}]  # fmt: skip
    assert [e["resource_type"] for e in groups["all-web"]["expression"]] == ["IPAddressExpression", "ConjunctionOperator",
                                                                             "IPAddressExpression"]  # one IP version each
    services = {c["Service"]["id"]: c["Service"] for c in body["children"] if c["resource_type"] == "ChildService"}
    lists = [e["destination_ports"] for e in services["many"]["service_entries"]]
    assert all(sum(2 if "-" in v else 1 for v in ports) <= 15 for ports in lists) and sum(len(x) for x in lists) == 15
    rules = {r["display_name"]: r for r in body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"]}
    assert rules["lists"]["destination_groups"] == ["0.0.0.0/0"] and not rules["lists"]["disabled"]
    assert rules["not-web"]["sources_excluded"] and rules["not-web"]["source_groups"] == ["/infra/domains/default/groups/web"]
    assert rules["fqdn"]["disabled"] and rules["neg-service"]["disabled"]
    assert "fwshift-default-deny" not in rules  # the source allows by default, as NSX does
    assert report.item("rule", "fqdn").disabled


def test_nsx_to_nsx_keeps_dynamic_groups_and_refers_to_its_services() -> None:
    source, _ = load("nsx_sample.json")
    body = json.loads(cli.convert(source, "nsx", Report()))
    groups = {c["Group"]["display_name"]: c["Group"] for c in body["children"][-1]["children"] if c["resource_type"] == "ChildGroup"}
    assert groups["Quarantine"]["expression"][0]["resource_type"] == "Condition"
    services = [c["Service"]["id"] for c in body["children"] if c["resource_type"] == "ChildService"]
    assert "HTTPS" not in services and "app-8443" in services
    rules = {r["display_name"]: r for r in body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"]}
    assert rules["DNS to resolvers"]["services"] == ["/infra/services/DNS", "/infra/services/DNS-UDP"]
    assert not rules["Block quarantined"]["disabled"]


def test_names_from_the_input_cannot_break_the_body() -> None:
    p = Policy(vendor="panos")
    p.rules.append(Rule('evil"/../x\n', origin="evil", action=Action.DROP))
    body = json.loads(emit_nsx.emit(p, Report(), Options()))
    rule = body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"][0]
    assert rule["id"] == "evil_.._x" and "/" not in rule["id"] and rule["display_name"] == 'evil"/../x\n'


def test_zones_without_networks() -> None:
    p = Policy(vendor="panos")
    p.rules += [Rule("allow", src_zones=["trust"], origin="allow"), Rule("block", src_zones=["guest"], action=Action.DROP, origin="block")]
    report = Report()
    body = json.loads(emit_nsx.emit(p, report, Options()))
    rules = {r["display_name"]: r for r in body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"]}
    assert rules["allow"]["disabled"] and not rules["block"]["disabled"]
    assert [f.code for f in report.item("rule", "allow").findings] == ["ZONE_NETWORK_MISSING"]
    assert "ZONE_WIDENED" in [f.code for f in report.item("rule", "block").findings]
    with pytest.raises(FwshiftError):
        emit_nsx.emit(p, Report(), Options(zone_networks={"a": ["10.0.0.0/16"], "b": ["10.0.255.0-10.1.0.255"]}))


# -- review round 27 ------------------------------------------------------------------------


def policies(*items: Dict[str, Any], groups: Optional[List[Dict[str, Any]]] = None, default: str = "DROP",
             services: Optional[List[Dict[str, Any]]] = None) -> str:
    out: List[Dict[str, Any]] = [dict(item, resource_type="SecurityPolicy") for item in items]
    out.append({"resource_type": "SecurityPolicy", "id": "default-layer3-section", "path": "/infra/domains/default/security-policies/default-layer3-section",
                "category": "Application", "is_default": True, "rules": [nsx_rule("default-layer3-rule", is_default=True, action=default)]})
    return json.dumps({"results": out + [dict(g, resource_type="Group", path=G + g["id"]) for g in groups or []]
                       + [dict(sv, resource_type="Service", path="/infra/services/" + sv["id"]) for sv in services or []]})  # fmt: skip


def test_r27_names_that_are_words_or_addresses() -> None:
    groups = [{"id": "g1", "display_name": "any", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.5"]}]},
              {"id": "g2", "display_name": "10.0.0.5", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.0/8"]}]}]  # fmt: skip
    services = [{"id": "s1", "display_name": "any", "service_entries": [{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP",
                                                                         "destination_ports": ["22"]}]}]  # fmt: skip
    p, report = parse(policies({"id": "p", "category": "Application", "rules": [
        nsx_rule("a", source_groups=[G + "g1"]), nsx_rule("b", source_groups=[G + "g2"], action="DROP"),
        nsx_rule("c", source_groups=["10.0.0.5"]), nsx_rule("d", services=["/infra/services/s1"])]}, groups=groups, services=services))
    rules = {r.name: r for r in p.rules}
    assert rules["a"].sources == ["any-object"] and rules["b"].sources == ["10.0.0.5 (object)"] and rules["c"].sources == ["10.0.0.5"]
    assert rules["d"].services == ["any-object"] and p.services["any-object"].entries[0].dst_ports == "22"
    assert [f.code for f in report.item("address-group", "any-object").findings] == ["RENAMED"]


def test_r27_a_jump_to_the_application_rules_leaves_every_environment_policy() -> None:
    drop = {"id": "a1", "category": "Application", "sequence_number": 1, "rules": [nsx_rule("app-drop", destination_groups=["10.0.0.5"], action="DROP")]}
    p, _ = parse(policies({"id": "e1", "category": "Environment", "sequence_number": 1, "rules": [nsx_rule("jump", action="JUMP_TO_APPLICATION")]},
                          {"id": "e2", "category": "Environment", "sequence_number": 2, "rules": [nsx_rule("e2-allow")]}, drop))
    assert [r.name for r in p.rules] == ["app-drop"]
    p, _ = parse(policies({"id": "e1", "category": "Environment", "sequence_number": 1, "rules": [
        nsx_rule("jump", action="JUMP_TO_APPLICATION", source_groups=["10.0.1.0/24"])]},
        {"id": "e2", "category": "Environment", "sequence_number": 2, "rules": [nsx_rule("e2-allow")]}, drop))  # fmt: skip
    assert "conditional jump" in p.rules[0].unsupported[0]
    p, _ = parse(policies({"id": "e1", "category": "Environment", "rules": [
        nsx_rule("jump", action="JUMP_TO_APPLICATION", scope=[G + "web"]), nsx_rule("e-drop", destination_groups=["10.0.0.5"], action="DROP")]},
        groups=[{"id": "web", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.2.0/24"]}]}], default="ALLOW"))  # fmt: skip
    assert [r.name for r in p.rules] == ["e-drop"] and p.rules[0].unsupported  # a jump with an applied-to is conditional


def test_r27_fqdn_inside_a_group_disables_the_rule() -> None:
    p = Policy(vendor="panos")
    p.addresses["bad"] = Address("bad", AddressKind.FQDN, "bad.example.com")
    p.addresses["h1"] = Address("h1", AddressKind.NETWORK, "192.0.2.10/32")
    p.address_groups["blk"] = AddressGroup("blk", ["bad", "h1"])
    p.rules += [Rule("deny-blk", destinations=["blk"], action=Action.DROP, origin="deny-blk"),
                Rule("allow-not-blk", sources=["blk"], negate_source=True, destinations=["192.0.2.200"], origin="allow-not-blk")]
    report = Report()
    body = json.loads(emit_nsx.emit(p, report, Options()))
    rules = {r["display_name"]: r for r in body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"]}
    assert rules["deny-blk"]["disabled"] and rules["allow-not-blk"]["disabled"]
    assert "FQDN_NOT_SUPPORTED" in [f.code for f in report.item("rule", "allow-not-blk").findings]


def test_r27_one_ip_version_between_dynamic_groups_is_written_back() -> None:
    tags = [{"id": i, "expression": [{"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag", "operator": "EQUALS",
                                      "value": i}]} for i in ("web", "db")]  # fmt: skip
    text = policies({"id": "p", "category": "Application", "rules": [
        nsx_rule("v4", source_groups=[G + "web"], destination_groups=[G + "db"], ip_protocol="IPV4")]}, groups=tags)  # fmt: skip
    p, _ = parse(text)
    assert not p.rules[0].unsupported and p.rules[0].handling["nsx.ip_protocol"] == "IPV4"
    body = json.loads(cli.convert(p, "nsx", Report()))
    assert body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"][0]["ip_protocol"] == "IPV4"
    assert "# FWSHIFT disabled" in cli.convert(parse(text)[0], "iptables", Report())  # (other targets cannot write the groups)


def test_r27_applied_to_one_end_and_written_back() -> None:
    groups = [{"id": "web", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.1.0/24"]}]},
              {"id": "db", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.2.0/24"]}]},
              {"id": "both", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.1.0/24", "10.0.2.0/24"]}]}]  # fmt: skip
    p, report = parse(policies({"id": "p", "category": "Application", "rules": [
        nsx_rule("one-end", source_groups=[G + "web"], destination_groups=[G + "db"], scope=[G + "web"]),
        nsx_rule("both-ends", source_groups=[G + "web"], destination_groups=[G + "db"], scope=[G + "both"])]}, groups=groups))  # fmt: skip
    assert [f.code for f in report.item("rule", "one-end").findings] == ["APPLIED_TO_ONE_END"]
    assert not report.item("rule", "both-ends").findings and not any(r.unsupported for r in p.rules)
    body = json.loads(cli.convert(p, "nsx", Report()))
    rules = body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"]
    assert rules[0]["scope"] == ["/infra/domains/default/groups/web"] and rules[1]["scope"] == ["/infra/domains/default/groups/both"]


def test_r27_missing_fields_defaults_and_odd_shapes() -> None:
    p, report = parse(policies({"id": "p", "category": "Application", "rules": [
        {"resource_type": "Rule", "id": "bare"},
        {"id": "no-type", "source_groups": ["ANY"], "destination_groups": ["10.0.0.5"], "services": ["ANY"], "action": "DROP"},
        {"source_groups": ["ANY"], "destination_groups": ["10.0.0.6"], "services": ["ANY"], "action": "DROP"},
        {"source_groups": ["ANY"], "destination_groups": ["10.0.0.7"], "services": ["ANY"], "action": "DROP"}]}))  # fmt: skip
    assert [(r.name, r.action, bool(r.unsupported)) for r in p.rules] == [
        ("bare", Action.DROP, True), ("no-type", Action.DROP, False), ("rule", Action.DROP, False), ("rule-2", Action.DROP, False)]  # fmt: skip
    vpc = {"id": "vpc-default-layer3-section", "category": "Application", "is_default": True, "sequence_number": 9,
           "rules": [nsx_rule("vpc-default", is_default=True, action="ALLOW")]}  # fmt: skip
    p, report = parse(policies(vpc))
    assert p.default_interzone == Action.DROP and "DEFAULT_RULES" in {n.code for n in report.notes}
    for document in ([{"resource_type": "Group", "id": f"g{i}", "path": G + f"g{i}",
                       "expression": [{"resource_type": "PathExpression", "paths": [G + f"g{i + 1}"]}]} for i in range(3000)]
                     + [{"resource_type": "SecurityPolicy", "id": "p", "rules": [nsx_rule("r", source_groups=[G + "g0"])]}],):  # fmt: skip
        with pytest.raises(ParseError):
            parse_nsx.parse(json.dumps(document).encode(), Report())
    with pytest.raises(ParseError):
        parse_nsx.parse(b"[" * 100000 + b"]" * 100000, Report())


def test_r27_dynamic_groups_nest_by_their_new_ids_and_services_keep_clear_of_nsx() -> None:
    groups = [{"id": "grp-0001", "display_name": "Admins", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.5.0/24"]}]},
              {"id": "grp-0002", "display_name": "Web", "expression": [
                  {"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag", "operator": "EQUALS", "value": "web"},
                  {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                  {"resource_type": "PathExpression", "paths": [G + "grp-0001"]}]}]  # fmt: skip
    services = [{"id": "custom-http", "display_name": "HTTP", "service_entries": [{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP",
                                                                                   "destination_ports": ["8080"]}]},
                {"id": "HTTP", "display_name": "HTTP", "_system_owned": True, "service_entries": [
                    {"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["80"]}]}]  # fmt: skip
    p, _ = parse(policies({"id": "p", "category": "Application", "rules": [
        nsx_rule("r1", source_groups=[G + "grp-0002"], services=["/infra/services/custom-http"]),
        nsx_rule("r2", services=["/infra/services/HTTP"])]}, groups=groups, services=services))  # fmt: skip
    body = json.loads(cli.convert(p, "nsx", Report(), Options(object_prefix="mig-")))
    written = {c["Group"]["id"]: c["Group"] for c in body["children"][-1]["children"] if c["resource_type"] == "ChildGroup"}
    assert written["mig-Web"]["expression"][2]["paths"] == ["/infra/domains/default/groups/mig-Admins"] and "mig-Admins" in written
    created = [c["Service"]["id"] for c in body["children"] if c["resource_type"] == "ChildService"]
    rules = body["children"][-1]["children"][-1]["SecurityPolicy"]["rules"]
    assert created == ["mig-HTTP-2"] and rules[0]["services"] == ["/infra/services/mig-HTTP-2"] and rules[1]["services"] == ["/infra/services/HTTP"]
    p = Policy(vendor="panos")
    p.services["HTTPS"] = Service("HTTPS", [ServiceEntry(Protocol.TCP, "8443")])
    p.rules.append(Rule("r", services=["HTTPS"], origin="r"))
    body = json.loads(emit_nsx.emit(p, Report(), Options()))
    assert [c["Service"]["id"] for c in body["children"] if c["resource_type"] == "ChildService"] == ["HTTPS-2"]


def test_r27_legacy_precedence_and_equal_rule_numbers() -> None:
    maps = {"results": [
        {"resource_type": "CommunicationMap", "id": "allow-map", "category": "Application", "precedence": 20,
         "communication_entries": [nsx_rule("allow", destination_groups=["10.0.0.5"], resource_type="CommunicationEntry")]},
        {"resource_type": "CommunicationMap", "id": "deny-map", "category": "Application", "precedence": 10,
         "communication_entries": [nsx_rule("deny", destination_groups=["10.0.0.5"], action="DROP", resource_type="CommunicationEntry")]}]}  # fmt: skip
    p, _ = parse(json.dumps(maps))
    assert [r.name for r in p.rules] == ["deny", "allow"]
    p, report = parse(policies({"id": "p", "category": "Application", "rules": [
        nsx_rule("a", sequence_number=5), nsx_rule("b", sequence_number=5, action="DROP")]}))  # fmt: skip
    assert "EQUAL_SEQUENCE" in {n.code for n in report.notes}


def test_r27_the_default_policy_comes_last_in_its_category_whatever_its_number() -> None:
    document = {"results": [
        {"resource_type": "SecurityPolicy", "id": "default-layer3-section", "category": "Application", "is_default": True,
         "sequence_number": 0, "rules": [nsx_rule("added-to-default", destination_groups=["10.0.0.5"], sequence_number=1),
                                         nsx_rule("default-layer3-rule", is_default=True, action="DROP", sequence_number=2)]},
        {"resource_type": "SecurityPolicy", "id": "app", "category": "Application", "sequence_number": 50,
         "rules": [nsx_rule("block", destination_groups=["10.0.0.5"], action="DROP")]}]}  # fmt: skip
    p, _ = parse(json.dumps(document))
    assert [r.name for r in p.rules] == ["block", "added-to-default"] and p.default_interzone == Action.DROP
