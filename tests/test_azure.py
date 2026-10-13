# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Azure network security groups: parser, emitter, and packet-level equivalence with judges of their own.

``AzureJudge`` reads network security groups as the Azure CLI prints them and decides a connection as Azure does: the
outbound rules of the group behind the source, the inbound rules of the group behind the destination, each list in the
order of its priorities, first match. ``TemplateJudge`` reads the template the emitter writes, the same way. Neither
shares code with the parser or the emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, model_verdict, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.emitters import azure as emit_azure
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry, Zone
from fwshift.options import Options
from fwshift.parsers import azure as parse_azure
from fwshift.report import Report

NUMBER = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
LOAD_BALANCER = ipaddress.ip_address("168.63.129.16")
DEFAULTS = [
    ("AllowVnetInBound", "Inbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
    ("AllowAzureLoadBalancerInBound", "Inbound", 65001, "AzureLoadBalancer", "*", "Allow"),
    ("DenyAllInBound", "Inbound", 65500, "*", "*", "Deny"),
    ("AllowVnetOutBound", "Outbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
    ("AllowInternetOutBound", "Outbound", 65001, "*", "Internet", "Allow"),
    ("DenyAllOutBound", "Outbound", 65500, "*", "*", "Deny"),
]


def ip(text: str) -> Any:
    return ipaddress.ip_address(text)


def proto_number(pkt: Packet) -> int:
    return NUMBER.get(pkt.proto) or int(pkt.proto)


def in_ports(value: str, port: int) -> bool:
    if value in ("*", "Any"):
        return True
    first, _, last = value.partition("-")
    return int(first) <= port <= int(last or first)


def protocol_matches(protocol: str, pkt: Packet) -> bool:
    number = proto_number(pkt)
    return {"tcp": number == 6, "udp": number == 17, "icmp": number == 1, "esp": number == 50, "ah": number == 51,
            "*": number in (6, 17, 1)}[protocol.lower()]  # fmt: skip


def ports_match(rule: Dict[str, Any], side: str, port: int, pkt: Packet) -> bool:
    if proto_number(pkt) not in (6, 17):
        return True
    values = [rule[f"{side}PortRange"]] if rule.get(f"{side}PortRange") else rule.get(f"{side}PortRanges") or ["*"]
    return any(in_ports(str(v), port) for v in values)


class _Lists:
    """What a security rule's address fields hold, as a judge reads them."""

    def __init__(self, vnet: List[str], asgs: Dict[str, List[str]], tags: Optional[Dict[str, List[str]]] = None) -> None:
        self.vnet, self.asgs, self.tags = vnet, asgs, tags or {}

    def holds(self, rule: Dict[str, Any], side: str, address: Any) -> bool:
        values = [rule[f"{side}AddressPrefix"]] if rule.get(f"{side}AddressPrefix") else rule.get(f"{side}AddressPrefixes") or []
        for value in values:
            text = str(value)
            if text in ("*", "Any"):
                return True
            if text == "VirtualNetwork":
                if any(address in ipaddress.ip_network(n) for n in self.vnet if ipaddress.ip_network(n).version == address.version):
                    return True
                continue
            if text == "AzureLoadBalancer":
                if address == LOAD_BALANCER:
                    return True
                continue
            if text[0].isalpha():
                if any(ipaddress.ip_network(n).version == address.version and address in ipaddress.ip_network(n) for n in self.tags.get(text, [])):
                    return True
                continue  # (another service tag: no address of these tests is in it)
            network = ipaddress.ip_network(text, strict=False)
            if network.version == address.version and address in network:
                return True
        for asg in rule.get(f"{side}ApplicationSecurityGroups") or []:
            if any(ip(m) == address for m in self.asgs.get(asg["id"].lower(), [])):
                return True
        return False

    def decide(self, rules: List[Dict[str, Any]], direction: str, pkt: Packet) -> bool:
        mine = sorted((r for r in rules if r["direction"] == direction), key=lambda r: r["priority"])
        src, dst = ip(pkt.src), ip(pkt.dst)
        for rule in mine:
            if not protocol_matches(rule["protocol"], pkt):
                continue
            if not ports_match(rule, "source", pkt.sport, pkt) or not ports_match(rule, "destination", pkt.dport, pkt):
                continue
            if self.holds(rule, "source", src) and self.holds(rule, "destination", dst):
                return rule["access"] == "Allow"
        return False


class AzureJudge:
    """Groups as the CLI prints them, each behind the networks the test gives it."""

    def __init__(self, groups: List[Dict[str, Any]], networks: Dict[str, List[str]], asgs: Dict[str, List[str]]) -> None:
        self.groups = {g["name"]: g for g in groups}
        self.networks = networks
        self.lists = _Lists([n for nets in networks.values() for n in nets], asgs)

    def group_of(self, address: Any) -> Optional[str]:
        for name, networks in self.networks.items():
            if any(ipaddress.ip_network(n).version == address.version and address in ipaddress.ip_network(n) for n in networks):
                return name
        return None

    def rules(self, name: str) -> List[Dict[str, Any]]:
        group = self.groups[name]
        defaults = group.get("defaultSecurityRules") or [
            {"name": n, "direction": d, "priority": p, "sourceAddressPrefix": s, "destinationAddressPrefix": t, "access": a, "protocol": "*",
             "sourcePortRange": "*", "destinationPortRange": "*"} for n, d, p, s, t, a in DEFAULTS]  # fmt: skip
        return list(group["securityRules"]) + list(defaults)

    def allows(self, pkt: Packet) -> Optional[bool]:
        sender, receiver = self.group_of(ip(pkt.src)), self.group_of(ip(pkt.dst))
        if sender is None and receiver is None:
            return None
        if sender is not None and not self.lists.decide(self.rules(sender), "Outbound", pkt):
            return False
        return receiver is None or self.lists.decide(self.rules(receiver), "Inbound", pkt)


# -- random groups ------------------------------------------------------------------------------

NETWORKS = {"nsg-a": ["10.0.1.0/24", "2001:db8:0:1::/64"], "nsg-b": ["10.0.2.0/24"], "nsg-c": ["10.0.3.16/28", "2001:db8:0:3::/64"]}
PREFIXES = ["10.0.1.0/24", "10.0.2.0/25", "10.0.0.0/16", "198.51.100.0/24", "192.0.2.0/25", "10.0.3.20", "2001:db8::/48",
            "2001:db8:0:1::/64", "203.0.113.0/24"]  # fmt: skip
ASG_IDS = {"asg-x": "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/asg-x"}
ASG_MEMBERS = {"asg-x": ["10.0.1.5", "10.0.2.7", "2001:db8:0:1::5"]}
OUTSIDE = ["198.51.100.7", "192.0.2.9", "203.0.113.5", "10.9.0.5", "168.63.129.16", "2001:db8:ff::1", "2001:db8:0:9::1"]


def random_side(rng: random.Random, prefix: str, loose: bool) -> Dict[str, Any]:
    roll = rng.random()
    if roll < 0.25:
        return {f"{prefix}AddressPrefix": "*", f"{prefix}AddressPrefixes": []}
    if roll < 0.35:
        return {f"{prefix}AddressPrefix": "VirtualNetwork", f"{prefix}AddressPrefixes": []}
    if roll < 0.4:
        return {f"{prefix}AddressPrefix": "AzureLoadBalancer", f"{prefix}AddressPrefixes": []}
    if roll < 0.5:
        return {f"{prefix}ApplicationSecurityGroups": [{"id": ASG_IDS["asg-x"]}], f"{prefix}AddressPrefixes": []}
    if loose and roll < 0.58:
        return {f"{prefix}AddressPrefix": rng.choice(["Internet", "Storage"]), f"{prefix}AddressPrefixes": []}
    chosen = rng.sample(PREFIXES, rng.randint(1, 3))
    if len(chosen) == 1:
        return {f"{prefix}AddressPrefix": chosen[0], f"{prefix}AddressPrefixes": []}
    return {f"{prefix}AddressPrefixes": chosen}


def random_rule(rng: random.Random, name: str, direction: str, priority: int, loose: bool) -> Dict[str, Any]:
    protocol = rng.choice(["Tcp", "Tcp", "Udp", "Icmp", "*", "*", "Esp", "Ah"])
    rule: Dict[str, Any] = {"name": name, "direction": direction, "priority": priority, "access": rng.choice(["Allow", "Allow", "Deny"]),
                            "protocol": protocol, "sourcePortRange": "*", "destinationPortRange": "*"}  # fmt: skip
    if protocol in ("Tcp", "Udp") or (protocol == "*" and rng.random() < 0.3 and (loose or rule["access"] == "Deny")):
        choice = rng.choice([["22"], ["80", "443"], ["8000-8080"], ["53"]])
        if len(choice) == 1:
            rule["destinationPortRange"] = choice[0]
        else:
            del rule["destinationPortRange"]
            rule["destinationPortRanges"] = choice
        if rng.random() < 0.15:
            rule["sourcePortRange"] = "1024-65535"
    rule.update(random_side(rng, "source", loose))
    rule.update(random_side(rng, "destination", loose))
    return rule


def random_azure(rng: random.Random, loose: bool = False) -> List[Dict[str, Any]]:
    groups = []
    for name in NETWORKS:
        rules = []
        for direction in ("Inbound", "Outbound"):
            for index in range(rng.randint(0, 5)):
                rules.append(random_rule(rng, f"{direction[:2]}{index}", direction, 100 + 10 * index, loose))
        group: Dict[str, Any] = {"name": name, "id": f"/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}",
                                 "type": "Microsoft.Network/networkSecurityGroups", "securityRules": rules}  # fmt: skip
        if rng.random() < 0.5:
            group["defaultSecurityRules"] = [{"name": n, "direction": d, "priority": p, "sourceAddressPrefix": s, "destinationAddressPrefix": t,
                                              "access": a, "protocol": "*", "sourcePortRange": "*", "destinationPortRange": "*"}
                                             for n, d, p, s, t, a in DEFAULTS]  # fmt: skip
        groups.append(group)
    return groups


def interfaces() -> List[Dict[str, Any]]:
    return [{"name": f"nic-{index}", "id": f"/subscriptions/0/nic-{index}", "type": "Microsoft.Network/networkInterfaces",
             "ipConfigurations": [{"privateIPAddress": address, "applicationSecurityGroups": [{"id": ASG_IDS["asg-x"]}]}]}
            for index, address in enumerate(ASG_MEMBERS["asg-x"])]  # fmt: skip


def zone_by_networks(address: str, networks: Dict[str, List[str]]) -> str:
    probe = ip(address)
    for name, nets in networks.items():
        if any(ipaddress.ip_network(n).version == probe.version and probe in ipaddress.ip_network(n) for n in nets):
            return name
    return "outside"


def azure_packet(rng: random.Random) -> Optional[Packet]:
    pool = OUTSIDE + ["10.0.1.5", "10.0.1.200", "10.0.2.7", "10.0.2.130", "10.0.3.20", "10.0.3.17", "2001:db8:0:1::5", "2001:db8:0:1::99",
                      "2001:db8:0:3::4"]  # fmt: skip
    src, dst = rng.choice(pool), rng.choice(pool)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    pkt = random_packet(rng, 6 if ":" in src else 4)
    pkt.src, pkt.dst = src, dst
    pkt.proto = rng.choice(["tcp", "tcp", "udp", "icmp" if ":" not in src else "icmp6", "50", "51", "47"])
    pkt.sport = rng.choice([53, 1024, 40000])
    pkt.dport = rng.choice([22, 53, 80, 443, 8000, 8080, 3389])
    pkt.in_if, pkt.out_if = zone_by_networks(src, NETWORKS), zone_by_networks(dst, NETWORKS)
    return pkt


@pytest.mark.parametrize("loose", [False, True])
def test_parsed_policy_decides_like_the_judge(loose: bool) -> None:
    """Exactly, when every address is one the export says (loose: service tags too, and the model never allows more)."""
    compared = 0
    for seed in range(100):
        rng = random.Random(seed + (1000 if loose else 0))
        groups = random_azure(rng, loose)
        model = parse_azure.parse(json.dumps([groups, interfaces()]).encode(), Report())
        judge = AzureJudge(groups, NETWORKS, {ASG_IDS["asg-x"].lower(): ASG_MEMBERS["asg-x"]})
        for _ in range(300):
            pkt = azure_packet(rng)
            if pkt is None:
                continue
            verdict = judge.allows(pkt)
            if verdict is None:
                continue
            compared += 1
            got = model_allows(model, pkt)
            if loose:
                assert got <= verdict, (seed, pkt, json.dumps(groups, indent=1))
            else:
                assert got == verdict, (seed, pkt, json.dumps(groups, indent=1))
    assert compared > 10000


# -- the judge of a template ----------------------------------------------------------------------


class TemplateJudge:
    def __init__(self, text: str) -> None:
        template = json.loads(text)
        assert template["$schema"].endswith("deploymentTemplate.json#")
        self.networks: Dict[str, List[str]] = template["metadata"]["networks"]
        self.rules: Dict[str, List[Dict[str, Any]]] = {}
        for resource in template["resources"]:
            assert resource["type"] == "Microsoft.Network/networkSecurityGroups"
            rules = [dict(r["properties"], name=r["name"]) for r in resource["properties"]["securityRules"]]
            for direction in ("Inbound", "Outbound"):
                numbers = [r["priority"] for r in rules if r["direction"] == direction]
                assert len(numbers) == len(set(numbers)) and all(100 <= n <= 4096 for n in numbers), numbers
                assert numbers == sorted(numbers)
            names = [r["name"].lower() for r in rules]
            assert len(names) == len(set(names))
            for rule in rules:
                assert len(rule.get("description", "")) <= 140 and 1 <= len(rule["name"]) <= 80
                for side in ("source", "destination"):
                    given = [k for k in (f"{side}AddressPrefix", f"{side}AddressPrefixes", f"{side}ApplicationSecurityGroups") if k in rule]
                    assert len(given) == 1, rule
                    prefixes = rule.get(f"{side}AddressPrefixes") or []
                    assert len({ipaddress.ip_network(p).version for p in prefixes}) <= 1, rule
            self.rules[resource["name"]] = rules
        self.lists = _Lists([], {})
        self.one = None if self.networks else (next(iter(self.rules)) if self.rules else None)

    def group_of(self, address: Any) -> Optional[str]:
        if self.one is not None:
            return self.one
        best: Optional[Tuple[int, str]] = None
        for name, networks in self.networks.items():
            for text in networks:
                network = ipaddress.ip_network(text)
                if network.version == address.version and address in network and (best is None or network.prefixlen > best[0]):
                    best = (network.prefixlen, name)
        return best[1] if best else None

    def allows(self, pkt: Packet) -> Optional[bool]:
        sender, receiver = self.group_of(ip(pkt.src)), self.group_of(ip(pkt.dst))
        if sender is None and receiver is None:
            return None
        if sender is not None and not self.lists.decide(self.rules[sender], "Outbound", pkt):
            return False
        return receiver is None or self.lists.decide(self.rules[receiver], "Inbound", pkt)


NARROWER = {"ZONE_WIDENED", "RULE_TYPE"}


def compare(model: Policy, report: Report, text: str, rng: random.Random, inside: bool, seed: int) -> int:
    judge = TemplateJudge(text)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    codes = {f.code for item in report.items.values() for f in item.findings}
    exact = not codes & NARROWER
    count = 0
    for _ in range(500):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        if rng.random() < 0.2:
            pkt.proto = rng.choice(["50", "51"])
        verdict = judge.allows(pkt)
        if verdict is None:
            assert inside
            continue
        count += 1
        wanted = model_allows(compared, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        # (Left out: ICMP types, ICMPv6 and other protocols; Azure carries TCP, UDP, ICMP, ESP and AH.)
        plain = pkt.proto in ("tcp", "udp", "50", "51") or (pkt.proto == "icmp" and not codes & {"AZURE_PART_NOT_WRITTEN", "ICMP_TYPE_WIDENED"})
        if exact and plain:
            assert verdict == wanted, (seed, pkt, text)
    return count


@pytest.mark.parametrize("seed", range(40))
def test_emitted_template_decides_like_the_model(seed: int) -> None:
    """A group per zone; outbound for traffic from it, inbound for traffic into it: each end gives the model's verdict."""
    rng = random.Random(seed)
    model = random_model(rng)
    report = Report()
    text = emit_azure.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare(model, report, text, rng, False, seed) == 500


@pytest.mark.parametrize("seed", range(20))
def test_emitted_template_with_an_inside_decides_like_the_model(seed: int) -> None:
    rng = random.Random(3000 + seed)
    model = random_model(rng)
    report = Report()
    inside = rng.sample(sorted(ZONES_AT), rng.randint(1, 2))
    text = emit_azure.emit(model, report, Options(zone_networks=ZONES_AT, inside_zones=inside))
    assert compare(model, report, text, rng, True, seed) > 100


@pytest.mark.parametrize("seed", range(20))
def test_emitted_template_never_allows_more(seed: int) -> None:
    """Zones without networks: one group, or blocking rules that block everywhere."""
    rng = random.Random(4000 + seed)
    model = random_model(rng)
    report = Report()
    networks = {zone: nets for zone, nets in ZONES_AT.items() if rng.random() < 0.6}
    text = emit_azure.emit(model, report, Options(zone_networks=networks))
    judge = TemplateJudge(text)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for _ in range(300):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        if pkt.in_if not in networks and pkt.out_if not in networks and networks:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        assert verdict <= model_allows(compared, pkt), (seed, pkt, text)


SAMPLE_NETWORKS = {"nsg-web": ["10.30.1.0/24", "2001:db8:30:1::/64"], "nsg-app": ["10.30.2.0/24"], "nsg-db": ["10.30.3.20"],
                   "outside": ["0.0.0.0/0", "::/0"]}  # fmt: skip
SAMPLE_ADDRESSES = ["10.30.1.10", "10.30.1.11", "10.30.1.99", "10.30.2.10", "10.30.2.50", "10.30.3.20", "10.30.9.5", "198.51.100.40",
                    "198.51.100.7", "192.0.2.200", "203.0.113.9", "203.0.113.70", "203.0.113.130", "168.63.129.16", "2001:db8:30:1::10",
                    "2001:db8:ff::5", "2001:db8:ee::1"]  # fmt: skip


def sample_packet(rng: random.Random) -> Optional[Packet]:
    src, dst = rng.choice(SAMPLE_ADDRESSES), rng.choice(SAMPLE_ADDRESSES)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    pkt = random_packet(rng, 6 if ":" in src else 4)
    pkt.src, pkt.dst = src, dst
    pkt.proto = rng.choice(["tcp", "tcp", "udp", "icmp" if ":" not in src else "tcp", "50", "51"])
    pkt.sport = rng.choice([53, 1024, 40000])
    pkt.dport = rng.choice([22, 53, 80, 443, 1433, 8443, 3389])
    networks = {k: v for k, v in SAMPLE_NETWORKS.items() if k != "outside"}
    pkt.in_if, pkt.out_if = zone_by_networks(src, networks), zone_by_networks(dst, networks)
    return pkt


def sample_judge() -> AzureJudge:
    document = json.loads((DATA / "azure_sample.json").read_text(encoding="utf-8"))
    asgs: Dict[str, List[str]] = {}
    for nic in document[1]:
        for config in nic["ipConfigurations"]:
            for asg in config["applicationSecurityGroups"]:
                asgs.setdefault(asg["id"].lower(), []).append(config["privateIPAddress"])
    networks = {k: v for k, v in SAMPLE_NETWORKS.items() if k != "outside"}
    judge = AzureJudge(document[0], networks, asgs)
    judge.lists.vnet = ["10.30.0.0/16", "2001:db8:30::/56"]
    judge.lists.tags = {v["name"]: v["properties"]["addressPrefixes"] for v in document[3]["values"]}
    return judge


def test_azure_sample_decides_like_the_judge() -> None:
    """The sample's service tags are in it: only Internet (outside) and VirtualNetwork from outside are not known."""
    p, _ = load("azure_sample.json")
    judge = sample_judge()
    rng = random.Random(11)
    count = 0
    for _ in range(5000):
        pkt = sample_packet(rng)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        got = model_allows(p, pkt)
        assert got <= verdict, pkt
        if pkt.in_if != "outside" and pkt.out_if != "outside":
            assert got == verdict, pkt  # (between groups everything is known)
    assert count > 2000


def test_roundtrip_through_azure_keeps_every_decision() -> None:
    source, _ = load("azure_sample.json")
    text = cli.convert(source, "azure", Report(), Options(zone_networks=SAMPLE_NETWORKS, inside_zones=["nsg-web", "nsg-app", "nsg-db"]))
    judge = TemplateJudge(text)
    rng = random.Random(12)
    count = 0
    for _ in range(4000):
        pkt = sample_packet(rng)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert verdict == model_allows(source, pkt), pkt
    assert count > 1500


# -- the sample -------------------------------------------------------------------------------


def test_azure_sample_rules() -> None:
    p, report = load("azure_sample.json")
    assert p.vendor == "azure" and list(p.zones) == ["nsg-web", "nsg-app", "nsg-db", "outside"] and not p.nat_rules
    by = {r.name: r for r in p.rules}
    https = by["nsg-web:Allow-HTTPS"]
    assert (https.src_zones, https.dst_zones, https.sources, https.destinations) == (["outside"], ["nsg-web"], [ANY], ["asg-web"])
    assert p.address_groups["asg-web"].members == ["10.30.1.10/31", "2001:db8:30:1::10/127"]
    assert https.source_ids["azure.priority"] == "100" and https.source_ids["azure.direction"] == "Inbound"
    assert p.services[https.services[0]].entries == [ServiceEntry(Protocol.TCP, dst_ports="443,80")]
    assert p.address_groups["Storage.WestEurope"].members == ["203.0.113.64/26", "2001:db8:ee::/48"]
    assert p.address_groups["AzureLoadBalancer"].members == ["168.63.129.16"]
    assert p.address_groups["Internet"].dynamic_filter == "azure-tag:Internet"
    # Between groups: the outbound rule of one and the inbound rules of the other, in their order.
    names = [r.name for r in p.rules if r.src_zones == ["nsg-web"] and r.dst_zones == ["nsg-app"]]
    assert names[0] == "nsg-web:Allow-App-Out+nsg-app:Allow-From-Web"
    assert by["nsg-web:Allow-App-Out+nsg-app:Allow-From-Web"].source_ids["azure.outbound"] == "nsg-web:Allow-App-Out"
    assert by["nsg-app:Allow-Dns"].services == ["udp-53-from-1024-65535"]
    # Internet on the side of a group's own resources: nothing (no rule for it between groups).
    assert not any(r.name.startswith("nsg-web:Deny-Internet+") for r in p.rules)
    codes = {f.code for f in report.notes}
    assert {"AZURE_ZONES", "AZURE_COMPOSED", "AZURE_DYNAMIC", "AZURE_ANY_PROTOCOL"} <= codes
    assert "--zone-network nsg-db=10.30.3.20" in next(f.message for f in report.notes if f.code == "AZURE_ZONES")


# -- reading: details -------------------------------------------------------------------------


def cli_rule(name: str, direction: str, priority: int, access: str = "Allow", protocol: str = "Tcp", source: str = "*",
             destination: str = "*", port: str = "443", **more: Any) -> Dict[str, Any]:  # fmt: skip
    return dict({"name": name, "direction": direction, "priority": priority, "access": access, "protocol": protocol,
                 "sourceAddressPrefix": source, "destinationAddressPrefix": destination, "sourcePortRange": "*",
                 "destinationPortRange": port}, **more)  # fmt: skip


def one_group(*rules: Dict[str, Any], name: str = "nsg-a") -> Dict[str, Any]:
    return {"name": name, "id": f"/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}",
            "type": "Microsoft.Network/networkSecurityGroups", "securityRules": list(rules)}


def test_every_form_azure_gives() -> None:
    rule = cli_rule("Allow-Web", "Inbound", 100, source="198.51.100.0/24")
    rest = {"name": "nsg-a", "id": "/x/networkSecurityGroups/nsg-a", "type": "Microsoft.Network/networkSecurityGroups",
            "properties": {"securityRules": [{"name": "Allow-Web", "properties": {k: v for k, v in rule.items() if k != "name"}}]}}  # fmt: skip
    graph = {"count": 1, "total_records": 1, "data": [dict(rest, type="microsoft.network/networksecuritygroups")]}
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "parameters": {"networkSecurityGroups_nsg_a_name": {"type": "String"}},
                "resources": [
                    {"type": "Microsoft.Network/networkSecurityGroups", "name": "[parameters('networkSecurityGroups_nsg_a_name')]",
                     "properties": {"securityRules": [{"name": "Allow-Web", "properties": {k: v for k, v in rule.items() if k != "name"}}]}},
                    {"type": "Microsoft.Network/networkSecurityGroups/securityRules",
                     "name": "[concat(parameters('networkSecurityGroups_nsg_a_name'), '/Allow-Web')]",
                     "properties": {k: v for k, v in rule.items() if k != "name"}},
                    {"type": "Microsoft.Network/networkSecurityGroups/securityRules",
                     "name": "[concat(parameters('networkSecurityGroups_nsg_a_name'), '/Allow-Ssh')]",
                     "properties": {k: v for k, v in cli_rule("x", "Inbound", 110, port="22").items() if k != "name"}}]}  # fmt: skip
    for document in (one_group(rule), [one_group(rule)], rest, {"value": [rest]}, graph, template):
        report = Report()
        p = parse_azure.parse(json.dumps(document).encode(), report)
        inbound = [r for r in p.rules if r.src_zones == ["outside"]]
        assert inbound[0].sources == ["198.51.100.0/24"] and inbound[0].services == ["tcp-443"], document
        assert any(f.code == "AZURE_DEFAULT_RULES_ADDED" for f in report.notes)
    p = parse_azure.parse(json.dumps(template).encode(), Report())
    assert list(p.zones)[0] == "nsg_a" and [r.name for r in p.rules if r.src_zones == ["outside"]][:2] == ["nsg_a:Allow-Web", "nsg_a:Allow-Ssh"]
    report = Report()
    parse_azure.parse(json.dumps(dict(graph, skip_token="abc")).encode(), report)
    assert any(f.code == "AZURE_INCOMPLETE_EXPORT" for f in report.notes)


def test_what_is_never_read_as_any() -> None:
    rules = [cli_rule("No-Source", "Inbound", 100), cli_rule("Both", "Inbound", 110, sourceAddressPrefixes=["10.0.0.0/8"]),
             cli_rule("Odd", "Inbound", 120, source="789"), cli_rule("Proto", "Inbound", 130, protocol="Gre"),
             cli_rule("Port", "Inbound", 140, port="80-x"), cli_rule("IcmpPort", "Inbound", 150, protocol="Icmp", port="8"),
             cli_rule("Access", "Inbound", 160, access="Maybe"), cli_rule("Way", "Sideways", 170)]  # fmt: skip
    del rules[0]["sourceAddressPrefix"]
    p = parse_azure.parse(json.dumps(one_group(*rules)).encode(), Report())
    by = {r.name: r for r in p.rules}
    for name, words in (("No-Source", "no source address"), ("Both", "together"), ("Odd", "cannot be read"), ("Proto", "protocol"),
                        ("Port", "port"), ("IcmpPort", "ports with protocol"), ("Access", "access"), ("Way", "direction")):  # fmt: skip
        assert any(words in u for u in by[f"nsg-a:{name}"].unsupported), (name, by[f"nsg-a:{name}"].unsupported)


def test_priorities_order_and_equal_priorities() -> None:
    rules = [cli_rule("Later", "Inbound", 300, access="Deny"), cli_rule("First", "Inbound", 100, port="22"),
             cli_rule("Same", "Inbound", 300, port="80")]  # fmt: skip
    report = Report()
    p = parse_azure.parse(json.dumps(one_group(*rules)).encode(), report)
    assert [r.name for r in p.rules if r.src_zones == ["outside"]][:3] == ["nsg-a:First", "nsg-a:Later", "nsg-a:Same"]
    assert any(f.code == "AZURE_EQUAL_PRIORITY" for f in report.notes)


def test_application_security_groups_service_tags_and_chains() -> None:
    asg = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/asg-web"
    rule = cli_rule("To-Web", "Inbound", 100, destinationApplicationSecurityGroups=[{"id": asg}])
    del rule["destinationAddressPrefix"]
    tags = {"changeNumber": "9", "values": [{"name": "Sql.WestEurope", "properties": {"addressPrefixes": ["203.0.113.128/27"]}}]}
    sql = cli_rule("Sql", "Outbound", 100, destination="Sql.WestEurope", port="1433")
    nic = {"name": "nic-1", "id": "/x/nic-1", "type": "Microsoft.Network/networkInterfaces",
           "networkSecurityGroup": {"id": "/x/networkSecurityGroups/nsg-nic"},
           "ipConfigurations": [{"privateIPAddress": "10.0.1.5", "applicationSecurityGroups": [{"id": asg}],
                                 "subnet": {"id": "/x/virtualNetworks/v/subnets/s1"}}]}  # fmt: skip
    group = dict(one_group(rule, sql), subnets=[{"id": "/x/virtualNetworks/v/subnets/s1"}])
    report = Report()
    p = parse_azure.parse(json.dumps([group, nic, tags]).encode(), report)
    assert p.address_groups["asg-web"].members == ["10.0.1.5"]
    assert p.address_groups["Sql.WestEurope"].members == ["203.0.113.128/27"] and "change 9" in p.address_groups["Sql.WestEurope"].description
    assert any(f.code == "AZURE_NSG_CHAIN" and "nic-1" in f.message for f in report.notes)
    # Without the interfaces, an application security group is a dynamic group; with interfaces of which none is a member,
    # it is not converted.
    p = parse_azure.parse(json.dumps([one_group(rule)]).encode(), Report())
    assert p.address_groups["asg-web"].dynamic_filter.startswith("azure-asg:")
    other = dict(nic, ipConfigurations=[{"privateIPAddress": "10.0.1.6"}])
    p = parse_azure.parse(json.dumps([one_group(rule), other]).encode(), Report())
    assert p.address_groups["asg-web"].unsupported


def test_errors_and_detection() -> None:
    with pytest.raises(ParseError, match="no network security groups"):
        parse_azure.parse(b'{"value": []}', Report())
    with pytest.raises(ParseError, match="JSON"):
        parse_azure.parse(b"{", Report())
    assert cli.detect_format((DATA / "azure_sample.json").read_bytes()) == "azure"
    assert cli.detect_format(json.dumps(one_group(cli_rule("x", "Inbound", 100))).encode()) == "azure"
    assert not parse_azure.looks_like_azure(b'{"SecurityGroups": []}')


# -- writing: details -------------------------------------------------------------------------


def small_policy() -> Policy:
    p = Policy(vendor="panos")
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.1.0.10/32")
    p.addresses["web6"] = Address("web6", AddressKind.NETWORK, "2001:db8:1::10/128")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443"), ServiceEntry(Protocol.UDP, "443")])
    rules = [Rule("block-guests", src_zones=["lan"], dst_zones=["dmz"], sources=["10.2.0.0/24"], action=Action.DROP),
             Rule("to-web", src_zones=["lan", "wan"], dst_zones=["dmz"], destinations=["web", "web6"], services=["https"])]  # fmt: skip
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    return p


NETS = {"lan": ["10.2.0.0/16"], "dmz": ["10.1.0.0/24", "2001:db8:1::/64"], "wan": ["0.0.0.0/0", "::/0"]}


def test_template_shape_and_splitting() -> None:
    report = Report()
    text = emit_azure.emit(small_policy(), report, Options(zone_networks=NETS, object_prefix="mig-"))
    template = json.loads(text)
    names = [r["name"] for r in template["resources"]]
    assert names == ["mig-lan", "mig-dmz", "mig-wan"] and template["resources"][0]["apiVersion"] == emit_azure.API_VERSION
    assert template["metadata"]["networks"]["mig-dmz"] == ["10.1.0.0/24", "2001:db8:1::/64"]
    dmz = [r["properties"] for r in template["resources"][1]["properties"]["securityRules"] if r["properties"]["direction"] == "Inbound"]
    # One security rule per protocol and IP version: TCP and UDP to the IPv4 and the IPv6 address.
    web = [r for r in dmz if r["description"].startswith("to-web")]
    assert {(r["protocol"], r.get("destinationAddressPrefix")) for r in web} >= {("Tcp", "10.1.0.10/32"), ("Udp", "2001:db8:1::10/128")}
    assert all("sourceAddressPrefixes" in r or r.get("sourceAddressPrefix") for r in web)
    assert [r["priority"] for r in dmz][:2] == [100, 110] and dmz[-1]["priority"] == 4096
    assert dmz[0]["access"] == "Deny" and dmz[0]["sourceAddressPrefix"] == "10.2.0.0/24"
    assert any(f.code == "AZURE_LOAD" for f in report.notes) and any(f.code == "AZURE_DEFAULTS_OVERRIDDEN" for f in report.notes)
    judge = TemplateJudge(text)
    assert judge.allows(Packet("wan", "dmz", "198.51.100.1", "10.1.0.10", "udp", 1, 443))
    assert not judge.allows(Packet("lan", "dmz", "10.2.0.9", "10.1.0.10", "tcp", 1, 443))
    assert judge.allows(Packet("lan", "dmz", "10.2.1.9", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("lan", "dmz", "10.2.1.9", "10.1.0.11", "tcp", 1, 443))


def test_what_a_security_rule_cannot_say() -> None:
    p = small_policy()
    p.addresses["host"] = Address("host", AddressKind.FQDN, "updates.example.com")
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    extra = [Rule("fqdn", destinations=["host"]), Rule("users", users=["alice"]), Rule("ping", services=["ping"]),
             Rule("no-ping", services=["ping"], action=Action.DROP), Rule("gre", services=["gre"]), Rule("zone", src_zones=["mars"])]  # fmt: skip
    for rule in extra:
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    text = emit_azure.emit(p, report, Options(zone_networks=NETS))
    assert report.item("rule", "fqdn").disabled and report.item("rule", "users").disabled and report.item("rule", "zone").disabled
    assert any(f.code == "AZURE_PART_NOT_WRITTEN" for f in report.item("rule", "ping").findings)
    assert any(f.code == "ICMP_TYPE_WIDENED" for f in report.item("rule", "no-ping").findings)
    assert report.item("rule", "gre").status == "skipped"
    metadata = json.loads(text)["metadata"]
    assert any(line.startswith("fqdn:") for line in metadata["notWritten"])
    with pytest.raises(FwshiftError, match="--inside-zone"):
        emit_azure.emit(small_policy(), Report(), Options(zone_networks=NETS, inside_zones=["moon"]))


def test_one_group_without_zones_defaults_and_azure_to_azure() -> None:
    p = Policy(vendor="nftables", default_interzone=Action.ALLOW, default_intrazone=Action.ALLOW)
    rule = Rule("no-telnet", services=["telnet"], action=Action.DROP)
    p.services["telnet"] = Service("telnet", [ServiceEntry(Protocol.TCP, "23")])
    rule.origin = rule.name
    p.rules.append(rule)
    report = Report()
    text = emit_azure.emit(p, report, Options())
    template = json.loads(text)
    assert [r["name"] for r in template["resources"]] == ["FWShift"] and template["metadata"]["networks"] == {}
    rules = [r["properties"] for r in template["resources"][0]["properties"]["securityRules"]]
    assert [(r["protocol"], r["access"]) for r in rules if r["direction"] == "Inbound"][-3:] == [("*", "Allow"), ("Esp", "Allow"), ("Ah", "Allow")]
    assert any(f.code == "AZURE_ONE_GROUP" for f in report.notes)
    judge = TemplateJudge(text)
    assert not judge.allows(Packet("x", "x", "10.0.0.1", "10.0.0.2", "tcp", 1, 23)) and judge.allows(Packet("x", "x", "10.0.0.1", "10.0.0.2", "tcp", 1, 22))
    # From Azure, service tags and application security groups are written again where no zone has to cut them.
    source = parse_azure.parse(json.dumps([one_group(cli_rule("Sql", "Outbound", 100, destination="Sql", port="1433"))]).encode(), Report())
    text = emit_azure.emit(source, Report(), Options(zone_networks={"nsg-a": ["10.0.1.0/24"], "outside": ["0.0.0.0/0", "::/0"]}))
    rules = [r["properties"] for r in json.loads(text)["resources"][0]["properties"]["securityRules"]]
    assert any(r.get("destinationAddressPrefix") == "Sql" for r in rules)


# -- review round 29 --------------------------------------------------------------------------

SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"


def properties(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in rule.items() if k != "name"}


def inbound_names(p: Policy, zone: str = "nsg-a") -> List[str]:
    return [r.name for r in p.rules if r.src_zones == ["outside"] and r.dst_zones == [zone]]


def longest_zone(address: str, networks: Dict[str, List[str]]) -> str:
    probe, best = ip(address), (-1, "nozone")
    for name, nets in networks.items():
        for text in nets:
            network = ipaddress.ip_network(text)
            if network.version == probe.version and probe in network and network.prefixlen > best[0]:
                best = (network.prefixlen, name)
    return best[1]


def reference(p: Policy, pkt: Packet) -> bool:
    """The model's verdict, with the default inside a zone where no rule decides."""
    verdict = model_verdict(p, pkt)
    if verdict is not None:
        return verdict
    if pkt.in_if == pkt.out_if:
        zone = p.zones.get(pkt.in_if)
        if zone is not None and zone.intrazone_allow is not None:
            return zone.intrazone_allow
        return p.default_intrazone == Action.ALLOW
    return p.default_interzone == Action.ALLOW


ONE_VERSION = [
    {"eth0": ZONES_AT["eth0"], "eth1": ZONES_AT["eth1"], "eth2": ["0.0.0.0/0", "2001:db8:3::/48"]},
    {"eth0": ZONES_AT["eth0"], "eth1": ZONES_AT["eth1"], "eth2": ["0.0.0.0/0"]},
    {"eth0": ["::/0", "10.0.0.0/23"], "eth1": ZONES_AT["eth1"], "eth2": ZONES_AT["eth2"]},
    {"eth0": ["0.0.0.0/0"], "eth1": ["::/0"], "eth2": ZONES_AT["eth2"]},
]


@pytest.mark.parametrize("seed", range(24))
def test_r29_zones_of_the_default_route_for_one_ip_version(seed: int) -> None:
    """A zone that holds the default route of one IP version only: the addresses of the other version that no zone holds
    are still decided by the rules (finding 1), and the end of a group whose own zone it is gives the default inside the
    zone (finding 5); an explicit 'no traffic inside the zone' is a deny."""
    rng = random.Random(9000 + seed)
    model = random_model(rng)
    model.default_interzone = Action.ALLOW if rng.random() < 0.5 else Action.DENY
    model.default_intrazone = Action.ALLOW if rng.random() < 0.5 else Action.DENY
    for zone in ("eth0", "eth1", "eth2"):
        model.zones[zone] = Zone(zone, intrazone_allow=rng.choice([None, True, False]))
    networks = ONE_VERSION[seed % len(ONE_VERSION)]
    report = Report()
    text = emit_azure.emit(model, report, Options(zone_networks=networks))
    judge = TemplateJudge(text)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    codes = {f.code for item in report.items.values() for f in item.findings}
    exact = not codes & (NARROWER | {"ZONE_DYNAMIC"})
    compared_count = 0
    for _ in range(600):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = longest_zone(pkt.src, networks), longest_zone(pkt.dst, networks)
        if rng.random() < 0.2:
            pkt.proto = rng.choice(["50", "51"])
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        compared_count += 1
        wanted = reference(compared, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        plain = pkt.proto in ("tcp", "udp", "50", "51") or (pkt.proto == "icmp" and not codes & {"AZURE_PART_NOT_WRITTEN", "ICMP_TYPE_WIDENED"})
        if exact and plain:
            assert verdict == wanted, (seed, pkt, text)
    assert compared_count > 300


def test_r29_the_block_of_no_zone_is_cut_to_the_other_ip_version() -> None:
    p = Policy(vendor="panos", default_interzone=Action.ALLOW, default_intrazone=Action.ALLOW)
    p.services["ssh"] = Service("ssh", [ServiceEntry(Protocol.TCP, "22")])
    rule = Rule("no-ssh", src_zones=[ANY], dst_zones=["lan"], services=["ssh"], action=Action.DENY)
    rule.origin = rule.name
    p.rules.append(rule)
    text = emit_azure.emit(p, Report(), Options(zone_networks={"lan": ["10.1.0.0/16", "2001:db8:1::/64"], "wan": ["0.0.0.0/0"]}))
    judge = TemplateJudge(text)
    assert not judge.allows(Packet("nozone", "lan", "2001:db8:ff::7", "2001:db8:1::5", "tcp", 40000, 22))
    assert not judge.allows(Packet("wan", "lan", "198.51.100.7", "10.1.0.5", "tcp", 40000, 22))
    assert judge.allows(Packet("wan", "lan", "198.51.100.7", "10.1.0.5", "tcp", 40000, 80))


def test_r29_the_default_inside_the_own_zone_of_the_default_route() -> None:
    for networks in ({"lan": ["0.0.0.0/0"], "dmz": ["10.1.0.0/24"]}, {"lan": ["0.0.0.0/0", "::/0"], "dmz": ["10.1.0.0/24"]}):
        p = Policy(vendor="panos", default_interzone=Action.ALLOW, default_intrazone=Action.DENY)
        judge = TemplateJudge(emit_azure.emit(p, Report(), Options(zone_networks=networks)))
        assert not judge.allows(Packet("lan", "lan", "198.51.100.7", "198.51.100.8", "tcp", 40000, 22)), networks
        assert judge.allows(Packet("lan", "dmz", "198.51.100.7", "10.1.0.8", "tcp", 40000, 22)), networks
    q = Policy(vendor="sonicwall", default_interzone=Action.DENY, default_intrazone=Action.ALLOW)
    q.zones["lan"] = Zone("lan", intrazone_allow=False)
    text = emit_azure.emit(q, Report(), Options(zone_networks={"lan": ["10.1.0.0/16"], "dmz": ["10.2.0.0/16"]}))
    assert not TemplateJudge(text).allows(Packet("lan", "lan", "10.1.0.5", "10.1.0.6", "tcp", 40000, 22))


def test_r29_a_priority_that_cannot_be_read_is_never_guessed() -> None:
    allow = cli_rule("Allow-All", "Inbound", 200, port="*")
    for value, words in (("abc", "cannot be read"), (float("nan"), "cannot be read"), (True, "cannot be read"), (100.9, "cannot be read"),
                         ("[parameters('p')]", "cannot be read"), (50, "not one Azure allows"), (5000, "not one Azure allows")):  # fmt: skip
        deny = cli_rule("Deny-Ssh", "Inbound", value, access="Deny", port="22")
        p = parse_azure.parse(json.dumps(one_group(deny, allow)).encode(), Report())
        rule = next(r for r in p.rules if r.name == "nsg-a:Deny-Ssh")
        assert any(words in u for u in rule.unsupported), (value, rule.unsupported)
    for value in (100, "100", 100.0):
        p = parse_azure.parse(json.dumps(one_group(allow, cli_rule("Deny-Ssh", "Inbound", value, access="Deny", port="22"))).encode(), Report())
        assert inbound_names(p)[:2] == ["nsg-a:Deny-Ssh", "nsg-a:Allow-All"] and not p.rules[0].unsupported, value
    # In a template, a priority given by a parameter with a default is worked out.
    deny = cli_rule("Deny-Ssh", "Inbound", "[parameters('denyPriority')]", access="Deny", port="22")
    template = {"$schema": SCHEMA, "parameters": {"denyPriority": {"type": "int", "defaultValue": 100}},
                "resources": [{"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg-a", "properties": {"securityRules": [
                    {"name": r["name"], "properties": properties(r)} for r in (allow, deny)]}}]}  # fmt: skip
    p = parse_azure.parse(json.dumps(template).encode(), Report())
    assert inbound_names(p)[:2] == ["nsg-a:Deny-Ssh", "nsg-a:Allow-All"] and not p.rules[0].unsupported


def test_r29_template_forms() -> None:
    deny = properties(cli_rule("x", "Inbound", 100, access="Deny", source="10.0.9.0/24", port="*"))
    nsg = {"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg-a", "properties": {"securityRules": []}}
    forms = {
        "nested child": [dict(nsg, resources=[{"type": "securityRules", "name": "Deny-Spoke", "properties": deny}])],
        "nested child, full name": [dict(nsg, resources=[{"type": "Microsoft.Network/networkSecurityGroups/securityRules",
                                                          "name": "nsg-a/Deny-Spoke", "properties": deny}])],
        "rules as a parameter": [dict(nsg, properties={"securityRules": "[parameters('rules')]"})],
        "Bicep format": [dict(nsg, name="[parameters('nsgName')]"),
                         {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "properties": deny,
                          "name": "[format('{0}/{1}', parameters('nsgName'), 'Deny-Spoke')]"}],
        "variables": [dict(nsg, name="[variables('names').nsg]"),
                      {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "properties": dict(deny, sourceAddressPrefix="[variables('spoke')]"),
                       "name": "[concat(variables('names').nsg, '/', 'Deny-Spoke')]"}],
    }  # fmt: skip
    parameters = {"rules": {"type": "array", "defaultValue": [{"name": "Deny-Spoke", "properties": deny}]},
                  "nsgName": {"type": "string", "defaultValue": "nsg-a"}}  # fmt: skip
    variables = {"names": {"nsg": "nsg-a"}, "spoke": "10.0.9.0/24"}
    for label, resources in forms.items():
        p = parse_azure.parse(json.dumps({"$schema": SCHEMA, "parameters": parameters, "variables": variables, "resources": resources}).encode(), Report())
        assert list(p.zones) == ["nsg-a", "outside"], label
        first = p.rules[0]
        assert first.name == "nsg-a:Deny-Spoke" and first.sources == ["10.0.9.0/24"] and first.action == Action.DENY and not first.unsupported, label
    # Copy loops: of a property, and of child resources.
    loop = dict(nsg, properties={"copy": [{"name": "securityRules", "count": "[length(parameters('denied'))]", "input": {
        "name": "[concat('Deny-', copyIndex('securityRules'))]",
        "properties": dict(deny, sourceAddressPrefix="[parameters('denied')[copyIndex('securityRules')]]",
                           priority="[add(100, copyIndex('securityRules'))]")}}]})  # fmt: skip
    children = [nsg, {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "copy": {"name": "r", "count": 2},
                      "name": "[concat('nsg-a/Deny-', copyIndex(1))]",
                      "properties": dict(deny, sourceAddressPrefix="[parameters('denied')[copyIndex()]]", priority="[add(100, copyIndex())]")}]  # fmt: skip
    for resources, names in (([loop], ["nsg-a:Deny-0", "nsg-a:Deny-1"]), (children, ["nsg-a:Deny-1", "nsg-a:Deny-2"])):
        document = {"$schema": SCHEMA, "parameters": {"denied": {"type": "array", "defaultValue": ["10.0.9.0/24", "10.0.8.0/24"]}},
                    "resources": resources}  # fmt: skip
        p = parse_azure.parse(json.dumps(document).encode(), Report())
        assert [(r.name, r.sources, r.unsupported) for r in p.rules[:2]] == [(names[0], ["10.0.9.0/24"], []), (names[1], ["10.0.8.0/24"], [])]
    # Conditions: false is not deployed; one left open makes a rule not converted and a group a finding.
    rdp = properties(cli_rule("x", "Inbound", 100, port="3389"))
    for condition, deployed in ((False, False), ("[parameters('openRdp')]", False), ("[not(parameters('openRdp'))]", True)):
        document = {"$schema": SCHEMA, "parameters": {"openRdp": {"type": "bool", "defaultValue": False}},
                    "resources": [nsg, {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "name": "nsg-a/Allow-Rdp",
                                        "condition": condition, "properties": rdp}]}  # fmt: skip
        p = parse_azure.parse(json.dumps(document).encode(), Report())
        assert ("nsg-a:Allow-Rdp" in inbound_names(p)) == deployed, condition
    document = {"$schema": SCHEMA, "resources": [dict(nsg, condition="[equals(resourceGroup().name, 'x')]"),
                                                 {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "name": "nsg-a/Allow-Rdp",
                                                  "condition": "[deployment().name]", "properties": rdp}]}  # fmt: skip
    report = Report()
    p = parse_azure.parse(json.dumps(document).encode(), report)
    assert any("condition" in u for u in next(r for r in p.rules if r.name == "nsg-a:Allow-Rdp").unsupported)
    assert any(f.code == "AZURE_TEMPLATE_CONDITION" and f.severity.name == "REVIEW" for f in report.notes)
    # What is not worked out makes the template unreadable, rather than a group or a rule missing.
    for resources, words in (
        ([dict(nsg, name="[uniqueString(resourceGroup().id)]")], "name of a network security group"),
        ([dict(nsg, properties={"securityRules": "[parameters('missing')]"})], "rules of group"),
        ([dict(nsg, copy={"name": "n", "count": "[parameters('missing')]"})], "count of a template copy loop"),
        ([nsg, {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "name": "[concat(resourceGroup().name, '/r')]", "properties": rdp}],
         "name of a rule"),
        ([{"type": "Microsoft.Resources/deployments", "name": "inner", "properties": {"template": {"resources": [nsg]}}}], "nested deployment"),
    ):  # fmt: skip
        with pytest.raises(ParseError, match=words):
            parse_azure.parse(json.dumps({"$schema": SCHEMA, "resources": resources}).encode(), Report())
    with pytest.raises(ParseError, match="symbolic"):
        parse_azure.parse(json.dumps({"$schema": SCHEMA, "languageVersion": "2.0", "resources": {"nsg": nsg}}).encode(), Report())
    # A field that is not worked out is left as written: the rule is not converted.
    document = {"$schema": SCHEMA, "resources": [nsg, {"type": "Microsoft.Network/networkSecurityGroups/securityRules", "name": "nsg-a/Odd",
                                                       "properties": dict(rdp, sourceAddressPrefix="[parameters('nowhere')]")}]}  # fmt: skip
    p = parse_azure.parse(json.dumps(document).encode(), Report())
    assert next(r for r in p.rules if r.name == "nsg-a:Odd").unsupported


def test_r29_rule_names_stay_short_and_never_loop() -> None:
    nsg = emit_azure._Nsg("g", "", [])
    emitter = emit_azure._Emitter(Policy(vendor="panos"), Report(), Options())
    names = [emitter._rule_name(nsg, "A" * 120, "Inbound") for _ in range(1500)]
    assert len(set(n.lower() for n in names)) == 1500 and all(len(n) <= 80 and n[-1].isalnum() for n in names)
    assert names[0] == "A" * 80 and names[1] == "A" * 78 + "-2" and names[-1].endswith("-1500")


def test_r29_any_protocol() -> None:
    p = Policy(vendor="panos")
    p.services["basic"] = Service("basic", [ServiceEntry(Protocol.TCP), ServiceEntry(Protocol.UDP), ServiceEntry(Protocol.ICMP)])
    for name, action in (("lan-out", Action.ALLOW), ("lan-no", Action.DENY)):
        rule = Rule(name, src_zones=["lan"], dst_zones=["wan"], services=["basic"], action=action)
        rule.origin = rule.name
        p.rules.append(rule)
    text = emit_azure.emit(p, Report(), Options(zone_networks={"lan": ["10.1.0.0/16"], "wan": ["0.0.0.0/0", "::/0"]}))
    rules = [r["properties"] for r in json.loads(text)["resources"][0]["properties"]["securityRules"] if r["name"].startswith("lan-")]
    assert {r["protocol"] for r in rules if r["access"] == "Allow"} == {"Tcp", "Udp", "Icmp"}
    assert {r["protocol"] for r in rules if r["access"] == "Deny"} == {"*"}
    for second, severity in ((cli_rule("Allow-Esp", "Inbound", 200, protocol="Esp", port="*"), "REVIEW"),
                             (cli_rule("Allow-Tcp", "Inbound", 200, port="*"), "INFO")):  # fmt: skip
        report = Report()
        parse_azure.parse(json.dumps(one_group(cli_rule("Deny-All", "Inbound", 100, access="Deny", protocol="*", port="*"), second)).encode(), report)
        assert [f.severity.name for f in report.notes if f.code == "AZURE_ANY_PROTOCOL"] == [severity]


VNETS = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks"


def vnet(name: str, prefix: str, peers: List[str] = (), state: str = "Connected") -> Dict[str, Any]:
    return {"name": name, "id": f"{VNETS}/{name}", "type": "Microsoft.Network/virtualNetworks", "addressSpace": {"addressPrefixes": [prefix]},
            "virtualNetworkPeerings": [{"name": f"to-{p}", "peeringState": state, "remoteVirtualNetwork": {"id": f"{VNETS}/{p}"}} for p in peers],
            "subnets": [{"id": f"{VNETS}/{name}/subnets/s", "addressPrefix": prefix.replace("/16", "/24")}]}  # fmt: skip


def test_r29_groups_in_virtual_networks_that_are_not_peered() -> None:
    a = dict(one_group(name="nsg-a"), subnets=[{"id": f"{VNETS}/vnet-1/subnets/s"}])
    b = dict(one_group(cli_rule("Deny-Internet-Ssh", "Inbound", 100, access="Deny", source="Internet", port="22"), name="nsg-b"),
             subnets=[{"id": f"{VNETS}/vnet-2/subnets/s"}])  # fmt: skip
    pkt = Packet("nsg-a", "nsg-b", "10.1.0.5", "10.2.0.5", "tcp", 40000, 22)
    cases = (([vnet("vnet-1", "10.1.0.0/16"), vnet("vnet-2", "10.2.0.0/16")], False, "AZURE_NOT_PEERED"),
             ([vnet("vnet-1", "10.1.0.0/16", ["vnet-2"]), vnet("vnet-2", "10.2.0.0/16")], True, ""),
             ([vnet("vnet-1", "10.1.0.0/16", ["vnet-2"], "Initiated"), vnet("vnet-2", "10.2.0.0/16")], False, "AZURE_NOT_PEERED"),
             ([vnet("vnet-1", "10.1.0.0/16")], True, "AZURE_PEERING_UNKNOWN"))  # fmt: skip
    for vnets, composed, code in cases:
        report = Report()
        p = parse_azure.parse(json.dumps([a, b] + vnets).encode(), report)
        assert any(r.src_zones == ["nsg-a"] and r.dst_zones == ["nsg-b"] for r in p.rules) == composed, vnets
        assert model_allows(p, pkt) == composed
        if code:
            assert any(f.code == code for f in report.notes), code


def test_r29_members_of_an_application_security_group_from_part_of_the_interfaces() -> None:
    asg = "/subscriptions/0/resourceGroups/rg-other/providers/Microsoft.Network/applicationSecurityGroups/asg-q"
    nic = {"name": "nic-1", "id": "/subscriptions/0/nic-1", "type": "Microsoft.Network/networkInterfaces",
           "ipConfigurations": [{"privateIPAddress": "10.0.5.4", "applicationSecurityGroups": [{"id": asg}]}]}
    for access, severity in (("Deny", "REVIEW"), ("Allow", "INFO")):
        rule = cli_rule("Quarantine", "Inbound", 100, access=access, port="*", sourceApplicationSecurityGroups=[{"id": asg}])
        del rule["sourceAddressPrefix"]
        report = Report()
        p = parse_azure.parse(json.dumps([one_group(rule), nic]).encode(), report)
        assert p.address_groups["asg-q"].members == ["10.0.5.4"]
        assert [f.severity.name for f in report.notes if f.code == "AZURE_ASG_MEMBERS"] == [severity]


def test_r29_resource_graph_as_the_rest_api_gives_it() -> None:
    row = dict(one_group(cli_rule("Allow-Web", "Inbound", 100)), type="microsoft.network/networksecuritygroups")
    for more in ({"totalRecords": 2500, "count": 1000}, {"count": 1, "$skipToken": "ew0K"}, {"count": 1, "resultTruncated": "true"},
                 {"count": 1, "resultTruncated": True}):  # fmt: skip
        report = Report()
        parse_azure.parse(json.dumps(dict(more, data=[row])).encode(), report)
        assert any(f.code == "AZURE_INCOMPLETE_EXPORT" for f in report.notes), more
    report = Report()
    parse_azure.parse(json.dumps({"totalRecords": 1, "count": 1, "data": [row], "resultTruncated": "false"}).encode(), report)
    assert not any(f.code == "AZURE_INCOMPLETE_EXPORT" for f in report.notes)
    table = {"totalRecords": 1, "count": 1, "data": {"columns": [{"name": "name"}], "rows": [["nsg-b"]]}}
    with pytest.raises(ParseError, match="table format"):
        parse_azure.parse(json.dumps([row, table]).encode(), Report())


def test_r29_groups_named_by_the_subnet_or_the_interface() -> None:
    S = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network"
    sub = one_group(cli_rule("Deny-Rdp", "Inbound", 100, access="Deny", port="3389"), name="nsg-subnet")
    own = one_group(cli_rule("Allow-Rdp", "Inbound", 100, port="3389"), name="nsg-nic")
    network = {"name": "vnet-1", "id": f"{S}/virtualNetworks/vnet-1", "type": "Microsoft.Network/virtualNetworks",
               "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]},
               "subnets": [{"id": f"{S}/virtualNetworks/vnet-1/subnets/s1", "addressPrefix": "10.1.1.0/24", "networkSecurityGroup": {"id": sub["id"]}}]}
    nic = {"name": "nic-1", "id": f"{S}/networkInterfaces/nic-1", "type": "Microsoft.Network/networkInterfaces", "networkSecurityGroup": {"id": own["id"]},
           "ipConfigurations": [{"privateIPAddress": "10.1.1.4", "subnet": {"id": f"{S}/virtualNetworks/vnet-1/subnets/s1"}}]}  # fmt: skip
    report = Report()
    parse_azure.parse(json.dumps([sub, own, network, nic]).encode(), report)
    assert any(f.code == "AZURE_NSG_CHAIN" and "nic-1" in f.message for f in report.notes)
    zones = next(f.message for f in report.notes if f.code == "AZURE_ZONES")
    assert "--zone-network nsg-subnet=10.1.1.0/24" in zones and "--zone-network nsg-nic=10.1.1.4" in zones


def test_r29_limits_of_a_group() -> None:
    p = Policy(vendor="panos")
    p.services["t"] = Service("t", [ServiceEntry(Protocol.TCP, "443")])
    for index in range(1100):
        rule = Rule(f"r{index}", sources=[f"10.{index // 250}.{index % 250}.0/24"], services=["t"])
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    template = json.loads(emit_azure.emit(p, report, Options()))
    assert template["resources"] == [] and any(f.code == "AZURE_TOO_MANY_RULES" for f in report.notes)
    rules = [cli_rule(f"To-{i}", "Inbound", 100 + i, destinationApplicationSecurityGroups=[{"id": f"/subscriptions/0/asg/asg-{i}"}]) for i in range(101)]
    for rule in rules:
        del rule["destinationAddressPrefix"]
    source = parse_azure.parse(json.dumps(one_group(*rules)).encode(), Report())
    report = Report()
    template = json.loads(emit_azure.emit(source, report, Options(zone_networks={"nsg-a": ["10.0.1.0/24"], "outside": ["0.0.0.0/0", "::/0"]})))
    assert [r["name"] for r in template["resources"]] == ["outside"]
    assert any("nsg-a" in f.message and "101 application security groups" in f.message for f in report.notes if f.code == "AZURE_TOO_MANY_RULES")


def test_r29_an_application_security_group_of_a_template_is_written_as_a_template_names_it() -> None:
    rule = cli_rule("Allow-Web", "Inbound", 100, destinationApplicationSecurityGroups=[
        {"id": "[resourceId('Microsoft.Network/applicationSecurityGroups', parameters('applicationSecurityGroups_asg_web_name'))]"}])
    del rule["destinationAddressPrefix"]
    document = {"$schema": SCHEMA, "parameters": {"networkSecurityGroups_nsg_web_name": {"type": "String"},
                                                  "applicationSecurityGroups_asg_web_name": {"type": "String"}},
                "resources": [{"type": "Microsoft.Network/networkSecurityGroups", "name": "[parameters('networkSecurityGroups_nsg_web_name')]",
                               "properties": {"securityRules": [{"name": "Allow-Web", "properties": properties(rule)}]}}]}  # fmt: skip
    p = parse_azure.parse(json.dumps(document).encode(), Report())
    text = emit_azure.emit(p, Report(), Options(zone_networks={"nsg_web": ["10.30.1.0/24"], "outside": ["0.0.0.0/0", "::/0"]}))
    ids = {a["id"] for res in json.loads(text)["resources"] for r in res["properties"]["securityRules"]
           for a in r["properties"].get("destinationApplicationSecurityGroups", [])}  # fmt: skip
    assert ids == {"[resourceId('Microsoft.Network/applicationSecurityGroups', 'asg_web')]"}


def test_r29_order_of_the_export_is_not_the_order_of_the_rules() -> None:
    """The rules of a list are read in the order of their priorities, also for what is said of them."""
    report = Report()
    rules = [cli_rule("Allow-Esp", "Inbound", 200, protocol="Esp", port="*"), cli_rule("Deny-All", "Inbound", 100, access="Deny", protocol="*", port="*")]
    parse_azure.parse(json.dumps(one_group(*rules)).encode(), report)
    assert [f.severity.name for f in report.notes if f.code == "AZURE_ANY_PROTOCOL"] == ["REVIEW"]


def test_r29_a_deny_rule_that_cannot_be_cut_blocks_all_it_blocked() -> None:
    def asg(name: str) -> List[Dict[str, Any]]:
        return [{"id": f"/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/{name}"}]

    out = cli_rule("To-A", "Outbound", 100, port="*", destinationApplicationSecurityGroups=asg("asg-a"))
    deny = cli_rule("No-B", "Inbound", 100, access="Deny", port="*", destinationApplicationSecurityGroups=asg("asg-b"))
    for rule in (out, deny):
        del rule["destinationAddressPrefix"]
    report = Report()
    p = parse_azure.parse(json.dumps([one_group(out, name="nsg-a"), one_group(deny, name="nsg-b")]).encode(), report)
    composed = next(r for r in p.rules if r.name == "nsg-a:To-A+nsg-b:No-B")
    assert composed.action == Action.DENY and composed.destinations == ["asg-b"]
    assert any(f.code == "AZURE_COMPOSED_WIDER" for f in report.item("rule", composed.origin).findings)


def test_r29_a_blocking_rule_of_a_zone_without_networks_blocks_everywhere() -> None:
    p = Policy(vendor="panos")
    p.services["ssh"] = Service("ssh", [ServiceEntry(Protocol.TCP, "22")])
    for rule in (Rule("guests-no-ssh", src_zones=["guest"], dst_zones=["lan"], services=["ssh"], action=Action.DENY),
                 Rule("to-lan", src_zones=[ANY], dst_zones=["lan"])):  # fmt: skip
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    judge = TemplateJudge(emit_azure.emit(p, report, Options(zone_networks={"lan": ["10.1.0.0/16"]})))
    assert any(f.code == "ZONE_WIDENED" for f in report.item("rule", "guests-no-ssh").findings)
    assert not judge.allows(Packet("x", "lan", "198.51.100.7", "10.1.0.5", "tcp", 40000, 22))
    assert judge.allows(Packet("x", "lan", "198.51.100.7", "10.1.0.5", "tcp", 40000, 80))
