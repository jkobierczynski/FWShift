# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Azure Firewall: parser, emitter, and packet-level equivalence with a judge of its own.

``Judge`` reads a firewall policy as the Azure CLI gives it, or the ARM template the emitter writes, as Microsoft
documents that Azure Firewall decides: the rule collection groups of the base policy before those of the child, DNAT
rules, then network rules, then application rules, each pass by group priority and then collection priority; the rules
of a collection with the collection's action; what no rule allows denied. It is strict about what it reads (names,
priorities, fields, values a rule takes, the order of deployment of the groups) and shares no code with the parser or
the emitter. Like them, it is written from the documentation, not from a firewall.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
import re
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.emitters import azurefw as emit_azurefw
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, ANY_V4, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope
from fwshift.model import Service, ServiceEntry, SnatKind, SourceNat
from fwshift.options import Options
from fwshift.parsers import azurefw as parse_azurefw
from fwshift.report import Report, Severity

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,78}[A-Za-z0-9_]|[A-Za-z0-9]")
NETWORK_FIELDS = {"ruleType", "name", "description", "ipProtocols", "sourceAddresses", "sourceIpGroups", "destinationAddresses",
                  "destinationIpGroups", "destinationFqdns", "destinationPorts"}  # fmt: skip
NAT_FIELDS = {"ruleType", "name", "description", "ipProtocols", "sourceAddresses", "sourceIpGroups", "destinationAddresses",
              "destinationPorts", "translatedAddress", "translatedFqdn", "translatedPort"}  # fmt: skip
PROTO = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}


def _ports(values: List[str], port: int) -> bool:
    for value in values:
        if value == "*":
            return True
        first, _, last = value.partition("-")
        if int(first) <= port <= int(last or first):
            return True
    return False


class Judge:
    """A firewall policy (with its base policies) or the classic rules of a firewall, as Azure Firewall decides."""

    def __init__(self, document: Any, strict: bool = False, fqdns: Optional[Dict[str, List[str]]] = None,
                 tags: Optional[Dict[str, List[str]]] = None) -> None:  # fmt: skip
        self.strict, self.fqdns, self.tags = strict, fqdns or {}, tags or {}
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, List[Dict[str, Any]]] = {}
        self.ip_groups: Dict[str, List[str]] = {}
        self.order: List[str] = []
        self._walk(document)
        leaves = [n for n in self.policies if not any(self._base(p) == n for p in self.policies.values())]
        assert len(leaves) == 1, leaves
        chain = [leaves[0]]
        while self._base(self.policies[chain[0]]):
            chain.insert(0, self._base(self.policies[chain[0]]))
        self.passes: Dict[str, List[Tuple[str, List[Dict[str, Any]]]]] = {"nat": [], "network": [], "application": []}
        for policy in chain:
            groups = sorted(self.groups.get(policy, []), key=lambda g: int(g["priority"]))
            if strict:
                numbers = [int(g["priority"]) for g in groups]
                assert len(set(numbers)) == len(numbers) and all(100 <= n <= 65000 for n in numbers), numbers
            for group in groups:
                collections = sorted(group["ruleCollections"], key=lambda c: int(c["priority"]))
                if strict:
                    numbers = [int(c["priority"]) for c in collections]
                    assert len(set(numbers)) == len(numbers) and all(100 <= n <= 65000 for n in numbers), numbers
                for collection in collections:
                    self._check_collection(collection)
                    kinds = {r["ruleType"] for r in collection["rules"]}
                    assert len(kinds) <= 1, kinds
                    kind = {"NatRule": "nat", "NetworkRule": "network", "ApplicationRule": "application"}.get(next(iter(kinds), "NetworkRule"))
                    assert kind is not None
                    self.passes[kind].append((collection["action"]["type"].lower(), collection["rules"]))

    @staticmethod
    def _base(policy: Dict[str, Any]) -> str:
        base = policy.get("basePolicy")
        return str(base["id"]).rsplit("/", 1)[-1] if isinstance(base, dict) else ""

    def _walk(self, node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                self._walk(item)
            return
        if not isinstance(node, dict):
            return
        if "resources" in node and "$schema" in node:
            policies = [r for r in node["resources"] if r["type"] == "Microsoft.Network/firewallPolicies"]
            assert len(policies) == 1
            previous = f"[resourceId('Microsoft.Network/firewallPolicies', '{policies[0]['name']}')]"
            for resource in node["resources"]:
                kind = resource["type"]
                assert kind in ("Microsoft.Network/firewallPolicies", "Microsoft.Network/firewallPolicies/ruleCollectionGroups"), kind
                if kind == "Microsoft.Network/firewallPolicies":
                    assert set(resource["properties"]) <= {"sku", "threatIntelMode", "dnsSettings"}
                    self.policies[resource["name"]] = dict(resource["properties"], name=resource["name"])
                    continue
                policy, group = resource["name"].split("/")
                assert NAME.fullmatch(group), group
                # Azure refuses changes to one policy in parallel: each group waits for the one before.
                assert resource["dependsOn"] == [previous], (resource["dependsOn"], previous)
                previous = f"[resourceId('Microsoft.Network/firewallPolicies/ruleCollectionGroups', '{policy}', '{group}')]"
                assert len(json.dumps(resource)) < 2_000_000
                self.groups.setdefault(policy, []).append(dict(resource["properties"], name=group))
            return
        kind = str(node.get("type", "")).lower()
        if kind == "microsoft.network/firewallpolicies":
            self.policies[node["name"]] = node
        elif kind == "microsoft.network/firewallpolicies/rulecollectiongroups":
            policy = re.search(r"/firewallPolicies/([^/]+)/", node["id"], re.IGNORECASE).group(1)  # type: ignore[union-attr]
            self.groups.setdefault(policy, []).append(node)
        elif kind == "microsoft.network/ipgroups":
            self.ip_groups[node["id"].lower()] = node["ipAddresses"]

    def _check_collection(self, collection: Dict[str, Any]) -> None:
        if not self.strict:
            return
        assert NAME.fullmatch(collection["name"]), collection["name"]
        nat = collection["ruleCollectionType"] == "FirewallPolicyNatRuleCollection"
        assert collection["ruleCollectionType"] in ("FirewallPolicyNatRuleCollection", "FirewallPolicyFilterRuleCollection")
        assert collection["action"]["type"] in (("DNAT",) if nat else ("Allow", "Deny"))
        assert collection["rules"], collection["name"]
        for rule in collection["rules"]:
            assert NAME.fullmatch(rule["name"]), rule["name"]
            assert set(rule) <= (NAT_FIELDS if nat else NETWORK_FIELDS), set(rule)
            assert rule["ruleType"] == ("NatRule" if nat else "NetworkRule")
            protocols = rule["ipProtocols"]
            assert protocols and set(protocols) <= ({"TCP", "UDP"} if nat else {"TCP", "UDP", "ICMP", "Any"}), protocols
            assert rule["destinationPorts"], rule
            for port in rule["destinationPorts"]:
                assert port == "*" or re.fullmatch(r"\d+(-\d+)?", port), port
                if port != "*":
                    first, _, last = port.partition("-")
                    assert 1 <= int(first) <= int(last or first) <= (63999 if nat else 65535), port
            if "ICMP" in protocols or "Any" in protocols and rule["destinationPorts"] != ["*"]:
                assert rule["destinationPorts"] == ["*"] or "Any" in protocols, rule
            sources = [k for k in ("sourceAddresses", "sourceIpGroups") if k in rule]
            assert len(sources) == 1 and rule[sources[0]], rule
            for value in rule.get("sourceAddresses", []) + rule.get("destinationAddresses", []):
                if value != "*" and not re.fullmatch(r"[A-Za-z][A-Za-z0-9.]*", value):
                    assert ipaddress.ip_network(value, strict=True).version == 4, value  # (a CIDR or an address, IPv4 only)
            if nat:
                assert len(rule["destinationAddresses"]) == 1 and ipaddress.ip_address(rule["destinationAddresses"][0]).version == 4
                assert len(rule["destinationPorts"]) == 1 and "-" not in rule["destinationPorts"][0]
                assert ("translatedAddress" in rule) != ("translatedFqdn" in rule) and rule["translatedPort"].isdigit()
            else:
                destinations = [k for k in ("destinationAddresses", "destinationIpGroups", "destinationFqdns") if k in rule]
                assert len(destinations) == 1 and rule[destinations[0]], rule
                if "destinationFqdns" in rule:
                    assert set(protocols) <= {"TCP", "UDP"}, rule  # (FQDNs in network rules: TCP and UDP)
                    assert all("*" not in f for f in rule["destinationFqdns"])

    # -- deciding ---------------------------------------------------------------------------

    def _in(self, address: str, values: List[str], tags: bool) -> bool:
        probe = ipaddress.ip_address(address)
        for value in values:
            if value in ("*", "Any"):
                return True
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9.]*", value):
                assert tags, value
                if any(probe in ipaddress.ip_network(n) for n in self.tags[value]):
                    return True
                continue
            if "-" in value:
                first, last = (ipaddress.ip_address(v) for v in value.split("-"))
                if first <= probe <= last:
                    return True
                continue
            if probe in ipaddress.ip_network(value, strict=False):
                return True
        return False

    def _source(self, rule: Dict[str, Any], address: str) -> bool:
        if self._in(address, rule.get("sourceAddresses", []), tags=False):
            return True
        return any(self._in(address, self.ip_groups[g.lower()], tags=False) for g in rule.get("sourceIpGroups", []))

    def _destination(self, rule: Dict[str, Any], address: str) -> bool:
        if self._in(address, rule.get("destinationAddresses", []), tags=True):
            return True
        if any(self._in(address, self.ip_groups[g.lower()], tags=False) for g in rule.get("destinationIpGroups", [])):
            return True
        return any(self._in(address, self.fqdns[f], tags=False) for f in rule.get("destinationFqdns", []))

    @staticmethod
    def _service(rule: Dict[str, Any], pkt: Packet) -> bool:
        protocols, ports = rule.get("ipProtocols") or rule.get("protocols"), rule["destinationPorts"]
        if "Any" in protocols:
            if ports == ["*"]:
                return True  # every IP protocol (so documented since November 2020)
            protocols = sorted(set(protocols) | {"TCP", "UDP"})
        name = PROTO.get(pkt.proto, "")
        if name not in protocols:
            return False
        return name == "ICMP" or _ports(ports, pkt.dport)

    def decide(self, pkt: Packet) -> Optional[bool]:
        """True or False; None where an application rule could decide (by a name the packet does not carry)."""
        if ipaddress.ip_address(pkt.src).version == 6:
            return False  # (Azure Firewall forwards no IPv6)
        for _, rules in self.passes["nat"]:
            for rule in rules:
                if self._source(rule, pkt.src) and self._in(pkt.dst, rule["destinationAddresses"], tags=False) and self._service(rule, pkt):
                    return True
        for action, rules in self.passes["network"]:
            if any(self._source(r, pkt.src) and self._destination(r, pkt.dst) and self._service(r, pkt) for r in rules):
                return action == "allow"
        for _, rules in self.passes["application"]:
            for rule in rules:
                ports = [int(p.get("port") or {"http": 80, "https": 443}[p["protocolType"].lower()]) for p in rule["protocols"]]
                if pkt.proto == "tcp" and pkt.dport in ports and self._source(rule, pkt.src):
                    return None
        return False


def judge_packets(rng: random.Random, count: int = 300) -> List[Packet]:
    out = []
    for _ in range(count):
        pkt = random_packet(rng, 4)
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        out.append(pkt)
    return out


def emitted_model(seed: int, default: Action = Action.DENY) -> Policy:
    """A random model whose services a network rule can say exactly: no source ports, no ICMP types, every protocol
    rather than GRE alone, no negated services and no rule types (each of those is said as allowing less or blocking more,
    which another test checks)."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.default_interzone = model.default_intrazone = default  # (the judge of the model has one default)
    model.services["ranges"].entries = [ServiceEntry(Protocol.TCP, "8000-8010,9000")]
    model.services["ping"].entries = [ServiceEntry(Protocol.ICMP)]
    model.services["gre"].entries = [ServiceEntry(Protocol.IP)]
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
        rule.negate_service = False
    return model


# -- the emitter, packet by packet ---------------------------------------------------------------


@pytest.mark.parametrize("seed", range(30))
def test_emitted_policy_decides_like_the_model(seed: int) -> None:
    """Zones become the networks behind them; the judge reads the template strictly. Rules the emitter does not write are
    left out of the model's side of the comparison (the report says so)."""
    model = emitted_model(seed, Action.ALLOW if seed % 5 == 0 else Action.DENY)
    report = Report()
    text = emit_azurefw.emit(model, report, Options(zone_networks=ZONES_AT))
    judge = Judge(json.loads(text), strict=True)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for pkt in judge_packets(random.Random(seed + 1000)):
        assert judge.decide(pkt) == model_allows(compared, pkt), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(20))
def test_what_cannot_be_said_allows_less_and_blocks_more(seed: int) -> None:
    """With source ports, ICMP types, GRE alone and negated services: a packet the output allows and the model does not is
    decided by a blocking rule that blocks more, never otherwise; one the model allows and the output does not by a rule
    that allows less, or one that blocks more."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_azurefw.emit(model, report, Options(zone_networks=ZONES_AT))
    judge = Judge(json.loads(text), strict=True)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    flagged = {item.name: {f.code for f in item.findings} for item in report.items.values() if item.kind == "rule"}
    lossy = {name for name, codes in flagged.items() if codes & {"AZFW_PART_NOT_WRITTEN", "AZFW_BLOCKS_MORE"}}
    for pkt in judge_packets(random.Random(seed + 2000)):
        verdict, expected = judge.decide(pkt), model_allows(compared, pkt)
        if verdict != expected:
            assert lossy, (seed, pkt)
            if verdict:  # (opened: only where nothing was written that blocks more, which cannot open anything)
                pytest.fail(f"the output allows what the model blocks: {pkt}")


def test_emitted_policy_shape_names_and_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    model = emitted_model(3)
    monkeypatch.setattr(emit_azurefw, "_MAX_GROUP_BYTES", 400)
    report = Report()
    text = emit_azurefw.emit(model, report, Options(zone_networks=ZONES_AT, target_policy="Policy One!"))
    template = json.loads(text)
    groups = [r for r in template["resources"] if r["type"].endswith("ruleCollectionGroups")]
    assert len(groups) > 1 and template["resources"][0]["name"] == "Policy_One_"
    assert [g["properties"]["priority"] for g in groups] == sorted(g["properties"]["priority"] for g in groups)
    Judge(template, strict=True)  # (every group waits for the one before)
    assert any(n.code == "AZFW_LOAD" and n.severity == Severity.REVIEW for n in report.notes)


# -- the parser, packet by packet ----------------------------------------------------------------

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network"
LITERALS = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "10.0.2.0/23", "10.0.0.17", "10.0.2.100-10.0.3.50", "*"]


def random_export(rng: random.Random) -> List[Any]:
    """The CLI's answers for a random child policy with a base policy, IP groups, network rules of every protocol and DNAT."""
    ip_groups = [{"id": f"{SUB}/ipGroups/ipg{i}", "name": f"ipg{i}", "type": "Microsoft.Network/IpGroups",
                  "ipAddresses": rng.sample(LITERALS[:-1], 2)} for i in range(2)]  # fmt: skip

    def addresses(key: str) -> Dict[str, Any]:
        if rng.random() < 0.2:
            return {key.replace("Addresses", "IpGroups"): [rng.choice(ip_groups)["id"]]}
        return {key: rng.sample(LITERALS, rng.randint(1, 2))}

    def network_rule(index: int) -> Dict[str, Any]:
        protocols = rng.choice([["TCP"], ["UDP"], ["TCP", "UDP"], ["ICMP"], ["Any"], ["Any"], ["TCP", "ICMP"]])
        ports = ["*"] if rng.random() < 0.3 else rng.sample(["22", "53", "80", "443", "8000-8010", "9000"], rng.randint(1, 2))
        rule = {"ruleType": "NetworkRule", "name": f"r{index}", "ipProtocols": protocols, "destinationPorts": ports}
        rule.update(addresses("sourceAddresses"))
        rule.update(addresses("destinationAddresses"))
        return rule

    counter = [0]

    def collection(priority: int) -> Dict[str, Any]:
        counter[0] += 1
        if rng.random() < 0.15:
            rules = [{"ruleType": "NatRule", "name": f"n{counter[0]}", "ipProtocols": [rng.choice(["TCP", "UDP"])],
                      "sourceAddresses": rng.sample(LITERALS, 1), "destinationAddresses": [f"10.0.4.{rng.randrange(1, 5)}"],
                      "destinationPorts": [rng.choice(["80", "443", "22"])], "translatedAddress": "10.0.0.5", "translatedPort": "8080"}]  # fmt: skip
            return {"name": f"c{counter[0]}", "priority": priority, "ruleCollectionType": "FirewallPolicyNatRuleCollection",
                    "action": {"type": "DNAT"}, "rules": rules}  # fmt: skip
        return {"name": f"c{counter[0]}", "priority": priority, "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                "action": {"type": rng.choice(["Allow", "Deny"])}, "rules": [network_rule(i) for i in range(rng.randint(1, 3))]}  # fmt: skip

    def groups(policy: str) -> List[Dict[str, Any]]:
        out = []
        for number in rng.sample(range(100, 1000, 50), rng.randint(1, 3)):
            out.append({"id": f"{SUB}/firewallPolicies/{policy}/ruleCollectionGroups/g{number}", "name": f"g{number}",
                        "priority": number, "type": "Microsoft.Network/FirewallPolicies/RuleCollectionGroups",
                        "ruleCollections": [collection(p) for p in rng.sample(range(100, 2000, 100), rng.randint(1, 3))]})  # fmt: skip
        return out

    base = {"id": f"{SUB}/firewallPolicies/base", "name": "base", "type": "Microsoft.Network/FirewallPolicies"}
    child = {"id": f"{SUB}/firewallPolicies/child", "name": "child", "type": "Microsoft.Network/FirewallPolicies",
             "basePolicy": {"id": base["id"]}}  # fmt: skip
    return [child, groups("child"), base, groups("base"), ip_groups]


@pytest.mark.parametrize("seed", range(40))
def test_parsed_policy_decides_like_the_judge(seed: int) -> None:
    rng = random.Random(seed)
    export = random_export(rng)
    judge = Judge(export)
    report = Report()
    model = parse_azurefw.parse(json.dumps(export).encode(), report)
    assert not any(r.unsupported for r in model.rules)
    for _ in range(300):
        pkt = random_packet(rng, 4)
        if rng.random() < 0.2:
            pkt.dst = f"10.0.4.{rng.randrange(1, 5)}"
            pkt.dport = rng.choice([80, 443, 22])
        assert judge.decide(pkt) == model_allows(model, pkt), (seed, pkt, json.dumps(export))


@pytest.mark.parametrize("seed", range(15))
def test_roundtrip_through_azure_firewall_keeps_every_decision(seed: int) -> None:
    rng = random.Random(seed)
    export = random_export(rng)
    model = parse_azurefw.parse(json.dumps(export).encode(), Report())
    report = Report()
    text = emit_azurefw.emit(model, report, Options())
    assert not any(item.disabled or item.skipped for item in report.items.values() if item.kind in ("rule", "nat")), report.to_text()
    before, after = Judge(export), Judge(json.loads(text), strict=True)
    after.ip_groups = before.ip_groups
    for _ in range(300):
        pkt = random_packet(rng, 4)
        if rng.random() < 0.2:
            pkt.dst, pkt.dport = f"10.0.4.{rng.randrange(1, 5)}", rng.choice([80, 443, 22])
        assert before.decide(pkt) == after.decide(pkt), (seed, pkt)


# -- the sample ----------------------------------------------------------------------------------


def test_sample_order_inheritance_and_passes() -> None:
    p, report = load("azurefw_sample.json")
    assert p.vendor == "azure-firewall" and p.scope == "fwpol-shop" and not p.zones
    names = [r.name for r in p.rules]
    # DNAT first (as allow rules for what they translate), then the network rules of the base policy, then those of the
    # child by group priority (rcg-late 200 before rcg-shop 300), then the application rules, whatever their collection's
    # priority.
    assert names[:4] == ["dnat-web/web-https (DNAT)", "dnat-web/ssh-admin (DNAT)", "base-deny/deny-telnet", "base-allow-dns/dns-out"]
    assert [r.source_ids["azurefw.policy"] for r in p.rules[2:5]] == ["fwpol-base", "fwpol-base", "fwpol-shop"]
    assert p.rules[4].source_ids["azurefw.group"] == "rcg-late" and names.index("net-allow-web/web-to-db") > 6
    kinds = [r.source_ids["azurefw.type"] for r in p.rules]
    assert kinds == sorted(kinds, key=["nat", "network", "application"].index)
    assert p.default_interzone == Action.DENY and p.default_intrazone == Action.DENY
    codes = {n.code: n.severity for n in report.notes}
    assert codes["AZFW_THREAT_INTEL"] == Severity.REVIEW and codes["AZFW_IDPS"] == Severity.INFO
    assert codes["AZFW_DYNAMIC"] == Severity.REVIEW and "AZFW_FQDN_DNS_PROXY" not in codes
    assert "198.51.100.0/24" in next(n.message for n in report.notes if n.code == "AZFW_SNAT")


def test_sample_members_services_and_nat() -> None:
    p, _ = load("azurefw_sample.json")
    by = {r.source_ids["azurefw.rule"]: r for r in p.rules if not r.name.endswith("(DNAT)")}
    assert by["deny-telnet"].sources == [ANY_V4] and by["deny-telnet"].action == Action.DENY
    assert p.address_groups["ipg-dns"].members == ["10.10.8.8", "10.10.8.9"]
    assert p.address_groups["ipg-partners"].dynamic_filter.startswith("azure-ipgroup:/subscriptions/")
    assert p.address_groups["Storage.WestEurope"].dynamic_filter == "azure-tag:Storage.WestEurope"
    assert by["every-protocol-to-partner"].services == [ANY]  # Any with every port: every IP protocol
    dns = p.services[by["dns-any-protocol"].services[0]].entries
    assert {(e.protocol, e.dst_ports) for e in dns} == {(Protocol.TCP, "53"), (Protocol.UDP, "53")}
    assert p.services[by["icmp-mgmt"].services[0]].entries == [ServiceEntry(Protocol.ICMP)]
    ntp = by["ntp-out"]
    assert p.addresses[ntp.destinations[0]].kind == AddressKind.FQDN and p.addresses[ntp.destinations[0]].fqdn_family == 4
    assert by["v6-ssh"].unsupported and "IPv6" in by["v6-ssh"].unsupported[0]
    assert by["allow-updates"].unsupported and "target FQDNs" in by["allow-updates"].unsupported[0]
    assert "web categories Gambling" in by["no-gambling"].unsupported[0]
    nat = {n.name.rsplit("/", 1)[-1]: n for n in p.nat_rules}
    assert nat["ssh-admin"].destination_translation == DestNat("10.10.1.5", "22")
    assert nat["web-https"].destination_translation == DestNat("10.10.1.4", "")
    allow = p.rules[1]
    assert allow.destinations == ["203.0.113.10"] and allow.sources == ["198.51.100.0/24"] and allow.action == Action.ALLOW


def test_sample_decides_like_the_judge() -> None:
    data = (DATA / "azurefw_sample.json").read_bytes()
    judge = Judge(json.loads(data), fqdns={"time.example.org": ["192.0.2.123/32"]}, tags={"Storage.WestEurope": ["198.51.100.0/25"]})
    p, _ = load("azurefw_sample.json")
    p.address_groups["Storage.WestEurope"].dynamic_filter = ""
    p.address_groups["Storage.WestEurope"].members = ["198.51.100.0/25"]
    p.address_groups["ipg-partners"].dynamic_filter = ""
    p.address_groups["ipg-partners"].members = ["203.0.113.64/26"]
    judge.ip_groups[f"{SUB.replace('/rg/', '/rg-hub/')}/ipGroups/ipg-partners".lower()] = ["203.0.113.64/26"]
    p.addresses["time.example.org"] = Address("time.example.org", AddressKind.NETWORK, "192.0.2.123/32")
    rng = random.Random(7)
    addresses = ["10.10.1.4", "10.10.1.15", "10.10.2.15", "10.10.3.9", "10.10.4.2", "10.10.8.8", "10.10.8.53", "10.10.9.1", "192.0.2.123",
                 "198.51.100.7", "203.0.113.10", "203.0.113.70", "10.10.5.5", "10.10.1.6"]  # fmt: skip
    decided = 0
    for _ in range(3000):
        pkt = Packet("any", "any", rng.choice(addresses), rng.choice(addresses), rng.choice(["tcp", "udp", "icmp", "47"]),
                     40000, rng.choice([22, 23, 53, 80, 123, 443, 1433, 2222, 8000, 9000]))  # fmt: skip
        verdict = judge.decide(pkt)
        if verdict is None:
            continue  # (an application rule may decide it, by a name)
        decided += 1
        model = [r for r in p.rules if not r.unsupported or "IPv6" in r.unsupported[0]]
        trimmed = copy.copy(p)
        trimmed.rules = model
        assert verdict == model_allows(trimmed, pkt), pkt
    assert decided > 2000


def test_sample_to_azure_firewall() -> None:
    p, _ = load("azurefw_sample.json")
    report = Report()
    text = cli.convert(p, "azure-firewall", report)
    template = json.loads(text)
    judge = Judge(template, strict=True, fqdns={"time.example.org": ["192.0.2.123/32"]}, tags={"Storage.WestEurope": ["198.51.100.0/25"]})
    judge.ip_groups[f"{SUB.replace('/rg/', '/rg-hub/')}/ipGroups/ipg-partners".lower()] = ["203.0.113.64/26"]
    assert len(judge.passes["nat"]) == 2 and not judge.passes["application"]
    # The allow rules for what the DNAT rules translate are the DNAT rules themselves on Azure Firewall.
    assert not any("DNAT" in r["name"] for _, rules in judge.passes["network"] for r in rules)
    assert template["resources"][0]["properties"]["dnsSettings"] == {"enableProxy": True}
    written = json.dumps(template)
    assert "Storage.WestEurope" in written and "ipGroups/ipg-partners" in written
    assert any("allow-updates" in line for line in template["metadata"]["notWritten"])
    items = {i.name: i for i in report.items.values()}
    assert items["app-deny/no-gambling"].disabled
    assert items["dnat-web/ssh-admin"].emitted_as


# -- formats the parser reads ------------------------------------------------------------------


def classic(**extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "id": f"{SUB}/azureFirewalls/fw1", "name": "fw1", "type": "Microsoft.Network/azureFirewalls",
        "properties": {
            "threatIntelMode": "Alert", "additionalProperties": {"Network.DNS.EnableProxy": "false"},
            "natRuleCollections": [{"name": "nat1", "properties": {"priority": 100, "action": {"type": "Dnat"}, "rules": [
                {"name": "web", "protocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["203.0.113.5"],
                 "destinationPorts": ["80"], "translatedAddress": "10.1.0.4", "translatedPort": "8080"}]}}],
            "networkRuleCollections": [
                {"name": "allow-all", "properties": {"priority": 300, "action": {"type": "Allow"}, "rules": [
                    {"name": "any", "protocols": ["Any"], "sourceAddresses": ["10.1.0.0/16"], "destinationAddresses": ["*"], "destinationPorts": ["*"]}]}},
                {"name": "deny-ssh", "properties": {"priority": 200, "action": {"type": "Deny"}, "rules": [
                    {"name": "ssh", "protocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["*"], "destinationPorts": ["22"]},
                    {"name": "dns-name", "protocols": ["UDP"], "sourceAddresses": ["*"], "destinationFqdns": ["ns.example.com"],
                     "destinationPorts": ["53"]}]}},
            ],
            "applicationRuleCollections": [{"name": "web", "properties": {"priority": 100, "action": {"type": "Allow"}, "rules": [
                {"name": "updates", "sourceAddresses": ["10.1.0.0/16"], "protocols": [{"protocolType": "Https", "port": 443}],
                 "targetFqdns": ["*"]}]}}],
        },
    }  # fmt: skip
    out["properties"].update(extra)
    return out


def test_classic_rules() -> None:
    report = Report()
    p = parse_azurefw.parse(json.dumps(classic()).encode(), report)
    assert [r.name for r in p.rules] == ["nat1/web (DNAT)", "deny-ssh/ssh", "deny-ssh/dns-name", "allow-all/any", "web/updates"]
    assert p.rules[-1].destinations == [ANY] and not p.rules[-1].unsupported  # target '*': every name, read as the port
    item = report.item("rule", "web/updates")
    assert [f.code for f in item.findings] == ["AZFW_APP_ANY_NAME"] and item.findings[0].severity == Severity.REVIEW
    codes = {n.code for n in report.notes}
    assert {"AZFW_CLASSIC", "AZFW_FQDN_DNS_PROXY", "AZFW_INFRASTRUCTURE"} <= codes
    assert p.nat_rules[0].destination_translation == DestNat("10.1.0.4", "8080")
    # The firewall uses a policy: the policy is read, not its (empty) classic rules.
    firewall = classic(networkRuleCollections=[], natRuleCollections=[], applicationRuleCollections=[],
                       firewallPolicy={"id": f"{SUB}/firewallPolicies/pol"})  # fmt: skip
    with pytest.raises(ParseError, match="not in the input"):
        parse_azurefw.parse(json.dumps(firewall).encode(), Report())


def template_export() -> Dict[str, Any]:
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"firewallPolicies_pol_tpl_name": {"type": "String", "defaultValue": "pol-tpl"},
                       "ipGroups_ipg_web_name": {"type": "String", "defaultValue": "ipg-web"},
                       "deployLate": {"type": "bool"}},
        "variables": {"web": "10.20.1.0/24"},
        "resources": [
            {"type": "Microsoft.Network/ipGroups", "apiVersion": "2024-05-01", "name": "[parameters('ipGroups_ipg_web_name')]",
             "properties": {"ipAddresses": ["10.20.1.4", "10.20.1.5"]}},
            {"type": "Microsoft.Network/firewallPolicies", "apiVersion": "2024-05-01", "name": "[parameters('firewallPolicies_pol_tpl_name')]",
             "properties": {"threatIntelMode": "Off"},
             "resources": [{"type": "ruleCollectionGroups", "apiVersion": "2024-05-01", "name": "nested", "properties": {
                 "priority": 400, "ruleCollections": [{"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "deny-rest",
                                                       "priority": 100, "action": {"type": "Deny"}, "rules": [
                     {"ruleType": "NetworkRule", "name": "rest", "ipProtocols": ["Any"], "sourceAddresses": ["*"],
                      "destinationAddresses": ["*"], "destinationPorts": ["*"]}]}]}}]},
            {"type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups", "apiVersion": "2024-05-01",
             "name": "[concat(parameters('firewallPolicies_pol_tpl_name'), '/rcg-web')]", "properties": {
                 "priority": 300, "ruleCollections": [{"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "web",
                                                       "priority": 100, "action": {"type": "Allow"}, "rules": [
                     {"ruleType": "NetworkRule", "name": "to-web", "ipProtocols": ["TCP"], "sourceAddresses": ["[variables('web')]"],
                      "destinationIpGroups": ["[resourceId('Microsoft.Network/ipGroups', parameters('ipGroups_ipg_web_name'))]"],
                      "destinationPorts": ["443"]}]}]}},
            {"type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups", "apiVersion": "2024-05-01",
             "condition": "[parameters('deployLate')]",
             "name": "[concat(parameters('firewallPolicies_pol_tpl_name'), '/rcg-late')]", "properties": {
                 "priority": 500, "ruleCollections": [{"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "late",
                                                       "priority": 100, "action": {"type": "Allow"}, "rules": [
                     {"ruleType": "NetworkRule", "name": "late", "ipProtocols": ["UDP"], "sourceAddresses": ["*"],
                      "destinationAddresses": ["*"], "destinationPorts": ["53"]}]}]}},
        ],
    }  # fmt: skip


def test_exported_template() -> None:
    report = Report()
    p = parse_azurefw.parse(json.dumps(template_export()).encode(), report)
    assert p.scope == "pol-tpl"
    assert [r.name for r in p.rules] == ["web/to-web", "deny-rest/rest", "late/late"]
    assert p.rules[0].sources == ["10.20.1.0/24"] and p.address_groups[p.rules[0].destinations[0]].members == ["10.20.1.4", "10.20.1.5"]
    assert p.rules[2].unsupported and "condition" in p.rules[2].unsupported[0]
    assert any(n.code == "AZFW_TEMPLATE_CONDITION" for n in report.notes)


def test_selection_inheritance_and_errors() -> None:
    export = json.loads((DATA / "azurefw_sample.json").read_bytes())
    without_base = [export[1], export[3], export[4]]
    report = Report()
    p = parse_azurefw.parse(json.dumps(without_base).encode(), report)
    assert any(n.code == "AZFW_BASE_POLICY_MISSING" and n.severity == Severity.REVIEW for n in report.notes)
    assert not any(r.source_ids["azurefw.policy"] == "fwpol-base" for r in p.rules)
    # The base policy alone, by --policy.
    base = parse_azurefw.parse(json.dumps(export).encode(), Report(), policy="fwpol-base")
    assert [r.source_ids["azurefw.rule"] for r in base.rules] == ["deny-telnet", "dns-out"]
    other = dict(export[0], name="other", id=export[0]["id"].replace("fwpol-base", "other"))
    with pytest.raises(ParseError, match="give --policy"):
        parse_azurefw.parse(json.dumps(export + [other]).encode(), Report())
    with pytest.raises(ParseError, match="no firewall policy or firewall 'nope'"):
        parse_azurefw.parse(json.dumps(export).encode(), Report(), policy="nope")
    with pytest.raises(ParseError, match="no firewall policy"):
        parse_azurefw.parse(b'[{"type": "Microsoft.Network/networkSecurityGroups", "name": "x"}]', Report())
    # The policy names a group that is not in the input.
    report = Report()
    parse_azurefw.parse(json.dumps([export[0], export[1], export[2], export[4]]).encode(), report)
    assert any(n.code in ("AZFW_INCOMPLETE_EXPORT", "AZFW_NO_GROUPS") for n in report.notes)


def test_what_is_never_read_as_any() -> None:
    group = {"type": "Microsoft.Network/FirewallPolicies/RuleCollectionGroups", "id": f"{SUB}/firewallPolicies/p/ruleCollectionGroups/g",
             "name": "g", "priority": 100, "ruleCollections": [
                 {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "c", "priority": 100, "action": {"type": "Permit"},
                  "rules": [{"ruleType": "NetworkRule", "name": "a", "ipProtocols": ["TCP"], "sourceAddresses": ["10.0.0.1"],
                             "destinationAddresses": ["10.0.0.2"], "destinationPorts": ["99999"]},
                            {"ruleType": "NetworkRule", "name": "b", "ipProtocols": ["GRE"], "sourceAddresses": ["10.0.0.1"],
                             "destinationAddresses": ["10.0.0.2"], "destinationPorts": ["*"]},
                            {"ruleType": "NetworkRule", "name": "c", "ipProtocols": ["TCP"], "destinationAddresses": ["10.0.0.2"],
                             "destinationPorts": ["22"]},
                            {"ruleType": "NetworkRule", "name": "d", "ipProtocols": ["TCP"], "sourceAddresses": ["10.0.0.1"],
                             "destinationFqdns": ["*.example.com"], "destinationPorts": ["22"]}]},
                 {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "mixed", "priority": 100, "action": {"type": "Allow"},
                  "rules": [{"ruleType": "ApplicationRule", "name": "app", "sourceAddresses": ["*"], "protocols": [{"protocolType": "Ftp"}],
                             "targetUrls": ["www.example.com/x"]},
                            {"ruleType": "NetworkRule", "name": "net", "ipProtocols": ["TCP"], "sourceAddresses": ["*"],
                             "destinationAddresses": ["10.0.0.3"], "destinationPorts": ["80"]}]}]}  # fmt: skip
    report = Report()
    p = parse_azurefw.parse(json.dumps([group]).encode(), report)
    by = {r.source_ids["azurefw.rule"]: r for r in p.rules}
    assert all(by[n].unsupported for n in "abcd") and by["a"].action == Action.DENY
    assert by["app"].unsupported and by["app"].source_ids["azurefw.type"] == "application"
    assert [r.source_ids["azurefw.rule"] for r in p.rules][-1] == "app" and not by["net"].unsupported
    codes = {n.code for n in report.notes}
    assert {"AZFW_EQUAL_PRIORITY", "AZFW_MIXED_COLLECTION"} <= codes


def test_dnat_forms() -> None:
    rules = [{"ruleType": "NatRule", "name": "many", "ipProtocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["203.0.113.5"],
              "destinationPorts": ["8000-8002"], "translatedAddress": "10.0.0.5", "translatedPort": "80"},
             {"ruleType": "NatRule", "name": "byname", "ipProtocols": ["UDP"], "sourceAddresses": ["*"], "destinationAddresses": ["203.0.113.5"],
              "destinationPorts": ["53"], "translatedFqdn": "dns.example.net", "translatedPort": "53"},
             {"ruleType": "NatRule", "name": "icmp", "ipProtocols": ["ICMP"], "sourceAddresses": ["*"], "destinationAddresses": ["*"],
              "destinationPorts": ["1"], "translatedAddress": "10.0.0.0/24", "translatedPort": "1"}]  # fmt: skip
    group = {"type": "Microsoft.Network/FirewallPolicies/RuleCollectionGroups", "name": "p/g", "priority": 100, "ruleCollections": [
        {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": "c", "priority": 100, "action": {"type": "DNAT"}, "rules": rules}]}
    report = Report()
    p = parse_azurefw.parse(json.dumps([group]).encode(), report)
    nat = {n.name: n for n in p.nat_rules}
    assert [f.code for f in report.item("nat", "c/many").findings] == ["AZFW_DNAT_PORTS"]
    assert p.addresses[nat["c/byname"].destination_translation.address].kind == AddressKind.FQDN  # type: ignore[union-attr]
    assert len(nat["c/icmp"].unsupported) >= 3 and p.rules[2].unsupported == nat["c/icmp"].unsupported


def test_detection() -> None:
    data = (DATA / "azurefw_sample.json").read_bytes()
    assert cli.detect_format(data) == "azure-firewall" and parse_azurefw.looks_like_azurefw(data)
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != "azurefw_sample.json":
            assert not parse_azurefw.looks_like_azurefw(path.read_bytes()), path.name
    assert cli.detect_format(json.dumps(template_export()).encode()) == "azure-firewall"
    assert cli.detect_format(json.dumps(classic()).encode()) == "azure-firewall"
    both = json.dumps([classic(), {"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg", "securityRules": []}]).encode()
    with pytest.raises(FwshiftError, match="--from azure or --from azure-firewall"):
        cli.detect_format(both)


# -- the emitter, case by case ---------------------------------------------------------------


def small(*rules: Rule, nat: Optional[List[NatRule]] = None, vendor: str = "panos") -> Policy:
    p = Policy(vendor=vendor)
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443")])
    p.services["ssh-from"] = Service("ssh-from", [ServiceEntry(Protocol.TCP, "22", "1024-65535")])
    p.addresses["www"] = Address("www", AddressKind.FQDN, "www.example.com")
    p.addresses["v6"] = Address("v6", AddressKind.NETWORK, "2001:db8::/64")
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    for item in nat or []:
        item.origin = item.name
        p.nat_rules.append(item)
    return p


def test_dnat_written_only_where_the_policy_allows_it() -> None:
    nat = NatRule("pub", sources=[ANY], destinations=["203.0.113.5"], service="web", destination_translation=DestNat("10.0.0.5", "8443"))
    allow = Rule("allow-web", sources=[ANY], destinations=["203.0.113.5"], services=["web"])
    deny = Rule("deny-bad", sources=["198.51.100.0/24"], destinations=[ANY], action=Action.DENY)
    report = Report()
    text = emit_azurefw.emit(small(allow, nat=[copy.deepcopy(nat)]), report, Options())
    rule = Judge(json.loads(text), strict=True).passes["nat"][0][1][0]
    assert rule["translatedAddress"] == "10.0.0.5" and rule["translatedPort"] == "8443" and rule["destinationPorts"] == ["443"]
    report = Report()
    text = emit_azurefw.emit(small(deny, allow, nat=[copy.deepcopy(nat)]), report, Options())
    assert not Judge(json.loads(text)).passes["nat"]
    item = report.item("nat", "pub")
    assert item.skipped and item.findings[0].code == "AZFW_DNAT_NOT_ALLOWED" and "deny-bad" in item.findings[0].message
    # The same with the deny rule of a zone the NAT rule's sources are not in.
    deny_zone = Rule("deny-dmz", src_zones=["dmz"], action=Action.DENY)
    nat_zone = copy.deepcopy(nat)
    nat_zone.src_zones = ["untrust"]
    report = Report()
    networks = {"dmz": ["10.9.0.0/16"], "untrust": ["0.0.0.0/0"]}
    text = emit_azurefw.emit(small(deny_zone, allow, nat=[nat_zone]), report, Options(zone_networks=networks))
    assert Judge(json.loads(text), strict=True).passes["nat"], report.to_text()
    # Source NAT is Azure's own; a NAT rule of every service, or of high ports, cannot be written.
    snat = NatRule("hide", source_translation=SourceNat(SnatKind.INTERFACE, interface="wan"))
    every = NatRule("every", destinations=["203.0.113.6"], destination_translation=DestNat("10.0.0.6"))
    high = NatRule("high", destinations=["203.0.113.7"], service="high", destination_translation=DestNat("10.0.0.7"))
    p = small(Rule("all", sources=[ANY]), nat=[snat, every, high])
    p.services["high"] = Service("high", [ServiceEntry(Protocol.TCP, "64500")])
    report = Report()
    emit_azurefw.emit(p, report, Options())
    assert report.item("nat", "hide").findings[0].code == "AZFW_SNAT_NOT_WRITTEN"
    assert "every service" in report.item("nat", "every").findings[0].message
    assert "63999" in report.item("nat", "high").findings[0].message


def test_what_a_network_rule_cannot_say() -> None:
    rules = [Rule("from-name", sources=["www"], destinations=[ANY], services=["web"]),
             Rule("to-name-icmp-deny", destinations=["www"], action=Action.DENY),
             Rule("src-ports", services=["ssh-from"], destinations=["10.0.0.1"]),
             Rule("src-ports-deny", services=["ssh-from"], destinations=["10.0.0.2"], action=Action.DENY),
             Rule("six", sources=["v6"], destinations=[ANY]),
             Rule("users", users=["alice"], destinations=["10.0.0.3"]),
             Rule("zone", src_zones=["lan"], destinations=["10.0.0.4"])]  # fmt: skip
    report = Report()
    text = emit_azurefw.emit(small(*rules), report, Options())
    Judge(json.loads(text), strict=True)
    codes = {name: [f.code for f in report.item("rule", name).findings] for name in [r.name for r in rules]}
    assert codes["from-name"] == ["FQDN_NOT_SUPPORTED"] and report.item("rule", "from-name").disabled
    assert codes["to-name-icmp-deny"] == ["AZFW_FQDN_PROTOCOL"]
    assert codes["src-ports"] == ["AZFW_PART_NOT_WRITTEN", "AZFW_NOT_WRITTEN"] and report.item("rule", "src-ports").skipped
    assert codes["src-ports-deny"] == ["AZFW_BLOCKS_MORE"]
    assert "AZFW_IPV6_NOT_WRITTEN" in codes["six"] and report.item("rule", "six").skipped
    assert codes["users"] == ["USER_MATCH"] and codes["zone"] == ["ZONE_NETWORK_MISSING"]
    assert {"AZFW_TARGET_IPV6", "AZFW_LOAD", "AZFW_TARGET_SNAT"} <= {n.code for n in report.notes}


def test_native_service_tags_and_ip_groups() -> None:
    p, _ = load("azurefw_sample.json")
    p.vendor = "panos"  # (from another platform the dynamic groups are not Azure's)
    report = Report()
    emit_azurefw.emit(p, report, Options())
    assert report.item("rule", "net-allow-web/storage").disabled
    tag = Rule("tag-source", sources=["Storage.WestEurope"])
    q, _ = load("azurefw_sample.json")
    tag.origin = tag.name
    q.rules.insert(0, tag)
    report = Report()
    emit_azurefw.emit(q, report, Options())
    assert [f.code for f in report.item("rule", "tag-source").findings] == ["AZFW_SOURCE_TAG"]


def test_default_allow_and_intrazone() -> None:
    p = small(Rule("block", sources=["10.0.0.0/8"], action=Action.DENY))
    p.default_interzone = Action.ALLOW
    report = Report()
    judge = Judge(json.loads(emit_azurefw.emit(p, report, Options())), strict=True)
    assert judge.decide(Packet("a", "b", "192.0.2.1", "192.0.2.2", "47")) is True
    assert judge.decide(Packet("a", "b", "10.0.0.1", "192.0.2.2", "tcp", 1, 80)) is False
    assert any(n.code == "AZFW_DEFAULT_ALLOW" for n in report.notes)
    p = small(Rule("lan-out", src_zones=["lan"], dst_zones=["wan"]))
    p.zones = {}
    p.default_intrazone = Action.ALLOW
    report = Report()
    judge = Judge(json.loads(emit_azurefw.emit(p, report, Options(zone_networks={"lan": ["10.1.0.0/16"], "wan": ["0.0.0.0/0"]}))), strict=True)
    assert judge.decide(Packet("lan", "lan", "10.1.0.1", "10.1.0.2", "udp", 1, 53)) is True
    assert judge.decide(Packet("lan", "wan", "10.1.0.1", "192.0.2.2", "udp", 1, 53)) is True
    assert judge.decide(Packet("wan", "lan", "192.0.2.2", "10.1.0.1", "udp", 1, 53)) is False
    assert any(n.code == "INTRAZONE_WRITTEN" for n in report.notes)


def test_read_back_through_the_command_line(tmp_path: Any) -> None:
    out, compared = tmp_path / "out.json", tmp_path / "compare.txt"
    args = ["convert", str(DATA / "azurefw_sample.json"), "--to", "azure-firewall", "-o", str(out), f"--compare={compared}", "-q"]
    assert cli.main(args) == 0
    assert "certain" in compared.read_text(encoding="utf-8")
    assert cli.detect_format(out.read_bytes()) == "azure-firewall"
