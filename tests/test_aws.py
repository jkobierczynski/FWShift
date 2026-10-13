# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS security groups: parser, emitter, and packet-level equivalence with judges of their own.

``AwsJudge`` reads the answers of the AWS CLI as a VPC decides a connection: the outbound rules of the groups of the
source's interface, the inbound rules of the destination's, the network ACLs of both subnets where the connection
crosses from one to the other, public addresses translated to private ones. ``ScriptJudge`` reads the script the
emitter writes: its groups, the addresses each is for, and their rules. Neither shares code with the parser or the
emitter.
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
from fwshift.emitters import aws as emit_aws
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import Action, Address, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry, SnatKind
from fwshift.model import SourceNat
from fwshift.options import Options
from fwshift.parsers import aws as parse_aws
from fwshift.report import Report

NUMBER = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
NAMES = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "all": "-1"}


def proto_number(pkt: Packet) -> int:
    return NUMBER.get(pkt.proto) or int(pkt.proto)


def ip(text: str) -> Any:
    return ipaddress.ip_address(text)


def holds(cidr: str, address: Any) -> bool:
    network = ipaddress.ip_network(cidr, strict=False)
    return network.version == address.version and address in network


def matches_protocol(protocol: Any, low: Any, high: Any, pkt: Packet) -> bool:
    """A protocol and port range as a security group or the script has them."""
    text = NAMES.get(str(protocol).lower(), str(protocol).lower())
    if text == "-1":
        return True
    number = proto_number(pkt)
    if int(text) != number:
        return False
    if number in (6, 17):
        return int(low) <= pkt.dport <= int(high)
    if number in (1, 58):
        return low in (None, -1) or int(low) == pkt.icmp_type
    return True


# -- the judge of a VPC -----------------------------------------------------------------------


class AwsJudge:
    def __init__(self, document: Any) -> None:
        answers = document if isinstance(document, list) else [document]
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.interfaces: List[Dict[str, Any]] = []
        self.subnets: Dict[str, List[str]] = {}
        self.vpc: List[str] = []
        self.acls: List[Dict[str, Any]] = []
        self.entries: Dict[str, List[str]] = {}
        for answer in answers:
            for group in answer.get("SecurityGroups", []):
                self.groups[group["GroupId"]] = group
            self.interfaces += answer.get("NetworkInterfaces", [])
            for subnet in answer.get("Subnets", []):
                self.subnets[subnet["SubnetId"]] = [subnet["CidrBlock"]] + [b["Ipv6CidrBlock"] for b in subnet.get("Ipv6CidrBlockAssociationSet", [])]
            for vpc in answer.get("Vpcs", []):
                self.vpc += [b["CidrBlock"] for b in vpc["CidrBlockAssociationSet"]]
                self.vpc += [b["Ipv6CidrBlock"] for b in vpc.get("Ipv6CidrBlockAssociationSet", [])]
            self.acls += answer.get("NetworkAcls", [])
            if "PrefixListId" in answer:
                self.entries[answer["PrefixListId"]] = [e["Cidr"] for e in answer["Entries"]]
        self.by_address: Dict[Any, Dict[str, Any]] = {}
        self.public: Dict[Any, Any] = {}
        for interface in self.interfaces:
            for item in interface.get("PrivateIpAddresses", []):
                self.by_address[ip(item["PrivateIpAddress"])] = interface
                if "Association" in item:
                    self.public[ip(item["Association"]["PublicIp"])] = ip(item["PrivateIpAddress"])
            for item in interface.get("Ipv6Addresses", []):
                self.by_address[ip(item["Ipv6Address"])] = interface

    def member(self, group: str, address: Any) -> bool:
        interface = self.by_address.get(address)
        return interface is not None and any(g["GroupId"] == group for g in interface["Groups"])

    def element_holds(self, permission: Dict[str, Any], peer: Any) -> bool:
        if any(holds(r["CidrIp"], peer) for r in permission.get("IpRanges", [])):
            return True
        if any(holds(r["CidrIpv6"], peer) for r in permission.get("Ipv6Ranges", [])):
            return True
        if any(holds(c, peer) for r in permission.get("PrefixListIds", []) for c in self.entries.get(r["PrefixListId"], [])):
            return True
        return any(self.member(r["GroupId"], peer) for r in permission.get("UserIdGroupPairs", []) if r["GroupId"] in self.groups)

    def sg_allows(self, interface: Dict[str, Any], key: str, peer: Any, pkt: Packet) -> bool:
        for group in interface["Groups"]:
            for permission in self.groups[group["GroupId"]].get(key, []):
                if matches_protocol(permission["IpProtocol"], permission.get("FromPort", -1), permission.get("ToPort", -1), pkt) \
                        and self.element_holds(permission, peer):
                    return True
        return False

    def acl_allows(self, subnet: str, egress: bool, peer: Any, pkt: Packet) -> bool:
        acl = next((a for a in self.acls if any(x["SubnetId"] == subnet for x in a["Associations"])), None)
        acl = acl or next((a for a in self.acls if a["IsDefault"]), None)
        if acl is None:
            return True
        for entry in sorted((e for e in acl["Entries"] if e["Egress"] == egress), key=lambda e: e["RuleNumber"]):
            cidr = entry.get("CidrBlock") or entry["Ipv6CidrBlock"]
            if not holds(cidr, peer):
                continue
            protocol = entry["Protocol"]
            if protocol != "-1":
                if int(protocol) != proto_number(pkt):
                    continue
                if protocol in ("6", "17") and "PortRange" in entry and not entry["PortRange"]["From"] <= pkt.dport <= entry["PortRange"]["To"]:
                    continue
                if protocol in ("1", "58") and entry.get("IcmpTypeCode", {}).get("Type", -1) not in (-1, pkt.icmp_type):
                    continue
            return entry["RuleAction"] == "allow"
        return False

    def allows(self, pkt: Packet) -> Optional[bool]:
        """None when the VPC never sees the packet (or it could not be sent)."""
        src, dst = ip(pkt.src), ip(pkt.dst)
        source = self.by_address.get(src)
        if source is not None and dst in self.public:
            return None  # (back in through the internet gateway: not judged)
        real = self.public.get(dst, dst)
        target = self.by_address.get(real)
        if (source is None and any(holds(c, src) for c in self.vpc)) or (target is None and any(holds(c, real) for c in self.vpc)):
            return None  # an address of the VPC without an interface sends and receives nothing
        if source is None and target is None or src == real:
            return None
        if source is not None and not self.sg_allows(source, "IpPermissionsEgress", dst, pkt):
            return False
        if target is not None and not self.sg_allows(target, "IpPermissions", src, pkt):
            return False
        from_subnet = source["SubnetId"] if source else None
        to_subnet = target["SubnetId"] if target else None
        if from_subnet != to_subnet:
            if from_subnet and not self.acl_allows(from_subnet, True, dst, pkt):
                return False
            if to_subnet and not self.acl_allows(to_subnet, False, src, pkt):
                return False
        return True


# -- random VPCs ------------------------------------------------------------------------------

GROUP_IDS = ["sg-00000000000000a01", "sg-00000000000000a02", "sg-00000000000000a03", "sg-00000000000000a04"]
OUTSIDE = ["198.51.100.7", "192.0.2.5", "203.0.113.200", "2001:db8:ff::1", "2001:db8:0:9::5"]
CIDRS = ["0.0.0.0/0", "::/0", "10.0.1.0/24", "10.0.0.0/22", "198.51.100.0/24", "10.0.0.16/28", "2001:db8:0:1::/64",
         "2001:db8::/56", "192.0.2.0/25"]  # fmt: skip


def random_permission(rng: random.Random, egress: bool, remote: bool) -> Dict[str, Any]:
    kind = rng.choice(["-1", "tcp", "tcp", "udp", "icmp", "icmpv6", "47", "6"])
    permission: Dict[str, Any] = {"IpProtocol": kind, "IpRanges": [], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}
    if kind in ("tcp", "6"):
        permission["FromPort"], permission["ToPort"] = rng.choice([(22, 22), (80, 443), (0, 65535), (8000, 8080)])
    elif kind == "udp":
        permission["FromPort"], permission["ToPort"] = rng.choice([(53, 53), (0, 65535)])
    elif kind in ("icmp", "icmpv6"):
        permission["FromPort"], permission["ToPort"] = rng.choice([(-1, -1), (8, -1), (128, -1), (0, 0), (3, 4)])
    for _ in range(rng.randint(1, 3)):
        choice = rng.random()
        if choice < 0.55:
            cidr = rng.choice(CIDRS)
            permission["Ipv6Ranges" if ":" in cidr else "IpRanges"].append({"CidrIpv6" if ":" in cidr else "CidrIp": cidr})
        elif choice < 0.65:
            permission["PrefixListIds"].append({"PrefixListId": "pl-00000000000000001"})
        elif choice < 0.95 or not remote:
            permission["UserIdGroupPairs"].append({"GroupId": rng.choice(GROUP_IDS), "UserId": "111122223333"})
        else:
            permission["UserIdGroupPairs"].append({"GroupId": "sg-0ffffffffffffff01", "UserId": "444455556666", "VpcId": "vpc-0peer"})
    return permission


def random_aws(rng: random.Random, acls: bool = True, remote: bool = True) -> List[Dict[str, Any]]:
    groups = []
    for index, ident in enumerate(GROUP_IDS):
        inbound = [random_permission(rng, False, remote) for _ in range(rng.randint(0, 4))]
        if rng.random() < 0.6:
            outbound = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
        else:
            outbound = [random_permission(rng, True, remote) for _ in range(rng.randint(0, 3))]
        groups.append({"GroupId": ident, "GroupName": f"g{index}", "VpcId": "vpc-0a", "Description": "random",
                       "IpPermissions": inbound, "IpPermissionsEgress": outbound})  # fmt: skip
    interfaces = []
    for index in range(rng.randint(3, 6)):
        subnet = rng.randrange(3)
        host = 10 + index * 3
        private = [{"PrivateIpAddress": f"10.0.{subnet}.{host}", "Primary": True}]
        if rng.random() < 0.3:
            private[0]["Association"] = {"PublicIp": f"203.0.113.{10 + index}"}
        if rng.random() < 0.2:
            private.append({"PrivateIpAddress": f"10.0.{subnet}.{host + 1}", "Primary": False})
        six = [{"Ipv6Address": f"2001:db8:0:{subnet + 1}::{host:x}"}] if rng.random() < 0.5 else []
        interfaces.append({"NetworkInterfaceId": f"eni-{index:017x}", "VpcId": "vpc-0a", "SubnetId": f"subnet-{subnet}",
                           "Groups": [{"GroupId": g} for g in rng.sample(GROUP_IDS, rng.randint(1, 3))],
                           "PrivateIpAddress": private[0]["PrivateIpAddress"], "PrivateIpAddresses": private, "Ipv6Addresses": six})  # fmt: skip
    subnets = [{"SubnetId": f"subnet-{n}", "VpcId": "vpc-0a", "CidrBlock": f"10.0.{n}.0/24",
                "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": f"2001:db8:0:{n + 1}::/64"}]} for n in range(3)]  # fmt: skip
    answers: List[Dict[str, Any]] = [
        {"SecurityGroups": groups}, {"NetworkInterfaces": interfaces}, {"Subnets": subnets},
        {"Vpcs": [{"VpcId": "vpc-0a", "CidrBlock": "10.0.0.0/22", "CidrBlockAssociationSet": [{"CidrBlock": "10.0.0.0/22"}],
                   "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "2001:db8::/56"}]}]},
        {"PrefixListId": "pl-00000000000000001", "Entries": [{"Cidr": "198.51.100.0/25"}, {"Cidr": "10.0.2.0/24"}]},
    ]  # fmt: skip
    if acls:
        everything = [{"RuleNumber": n, "Protocol": "-1", "RuleAction": "allow", "Egress": e, k: c}
                      for e in (False, True) for n, k, c in ((100, "CidrBlock", "0.0.0.0/0"), (101, "Ipv6CidrBlock", "::/0"))]  # fmt: skip
        custom = []
        for egress in (False, True):
            for number in range(rng.randint(0, 4)):
                cidr = rng.choice(CIDRS + ["10.0.0.0/24", "203.0.113.0/24"])
                protocol = rng.choice(["-1", "6", "17", "1", "58", "47"])
                entry: Dict[str, Any] = {"RuleNumber": 10 * (number + 1), "Protocol": protocol, "Egress": egress,
                                         "RuleAction": rng.choice(["allow", "allow", "deny"]),
                                         ("Ipv6CidrBlock" if ":" in cidr else "CidrBlock"): cidr}  # fmt: skip
                if protocol in ("6", "17"):
                    low, high = rng.choice([(22, 22), (53, 443), (1024, 65535), (0, 65535)])
                    entry["PortRange"] = {"From": low, "To": high}
                if protocol in ("1", "58"):
                    entry["IcmpTypeCode"] = {"Type": rng.choice([-1, 8, 128]), "Code": -1}
                custom.append(entry)
            if rng.random() < 0.7:
                custom.append({"RuleNumber": 200, "Protocol": "-1", "RuleAction": "allow", "Egress": egress, "CidrBlock": "0.0.0.0/0"})
        answers.append({"NetworkAcls": [
            {"NetworkAclId": "acl-0default", "VpcId": "vpc-0a", "IsDefault": True, "Entries": everything,
             "Associations": [{"SubnetId": "subnet-0"}, {"SubnetId": "subnet-2"}]},
            {"NetworkAclId": "acl-0custom", "VpcId": "vpc-0a", "IsDefault": False, "Entries": custom,
             "Associations": [{"SubnetId": "subnet-1"}]},
        ]})  # fmt: skip
    return answers


def addresses_of(document: List[Dict[str, Any]]) -> List[str]:
    out = list(OUTSIDE) + ["10.0.3.9"]
    for answer in document:
        for interface in answer.get("NetworkInterfaces", []):
            out += [a["PrivateIpAddress"] for a in interface["PrivateIpAddresses"]] + [a["Ipv6Address"] for a in interface["Ipv6Addresses"]]
            out += [a["Association"]["PublicIp"] for a in interface["PrivateIpAddresses"] if "Association" in a]
    return out


def aws_packet(rng: random.Random, pool: List[str]) -> Optional[Packet]:
    src, dst = rng.choice(pool), rng.choice(pool)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    pkt = random_packet(rng, 6 if ":" in src else 4)
    pkt.src, pkt.dst = src, dst
    pkt.dport = rng.choice([22, 53, 80, 443, 8000, 8080, 3000, 40000])
    if pkt.proto in ("icmp", "icmp6"):
        pkt.icmp_type = rng.choice([0, 3, 8, 128])
    return pkt


def test_parsed_policy_decides_like_the_judge() -> None:
    compared = 0
    for seed in range(120):
        rng = random.Random(seed)
        document = random_aws(rng)
        report = Report()
        model = parse_aws.parse(json.dumps(document).encode(), report)
        judge = AwsJudge(document)
        pool = addresses_of(document)
        for _ in range(300):
            pkt = aws_packet(rng, pool)
            if pkt is None:
                continue
            verdict = judge.allows(pkt)
            if verdict is None:
                continue
            compared += 1
            assert model_allows(model, pkt) == verdict, (seed, pkt, json.dumps(document, indent=1))
    assert compared > 10000


# -- the judge of a script --------------------------------------------------------------------


class ScriptJudge:
    def __init__(self, text: str) -> None:
        self.attach: Dict[str, List[Any]] = {}
        names: Dict[str, str] = {}
        self.rules: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        lines = text.splitlines()
        for index, line in enumerate(lines):
            found = re.match(r"# attach (\S+): (.*)$", line)
            if found:
                self.attach[found.group(1)] = [self.span(token) for token in found.group(2).split()]
            found = re.match(r"(G\d+)=\$\(group '([^']+)' '[^']*'\) \|\| exit 1$", line)
            if found:
                names[found.group(1)] = found.group(2)
            found = re.match(r'(ingress|egress) "\$(G\d+)" <<\'FWSHIFT_JSON\'$', line)
            if found:
                assert lines[index + 2] == "FWSHIFT_JSON"
                self.rules.setdefault((names[found.group(2)], found.group(1)), []).extend(json.loads(lines[index + 1]))
        assert set(names.values()) == set(self.attach)

    @staticmethod
    def span(token: str) -> Tuple[Any, Any]:
        if "-" in token and "/" not in token:
            first, last = token.split("-")
            return ip(first), ip(last)
        network = ipaddress.ip_network(token)
        return network[0], network[-1]

    def groups_of(self, address: Any) -> List[str]:
        return [name for name, spans in self.attach.items() if any(a.version == address.version and a <= address <= b for a, b in spans)]

    def side(self, groups: List[str], word: str, peer: Any, pkt: Packet) -> bool:
        for group in groups:
            for permission in self.rules.get((group, word), []):
                if not matches_protocol(permission["IpProtocol"], permission.get("FromPort", -1), permission.get("ToPort", -1), pkt):
                    continue
                cidrs = [r["CidrIp"] for r in permission.get("IpRanges", [])] + [r["CidrIpv6"] for r in permission.get("Ipv6Ranges", [])]
                if any(holds(c, peer) for c in cidrs):
                    return True
        return False

    def allows(self, pkt: Packet) -> Optional[bool]:
        src, dst = ip(pkt.src), ip(pkt.dst)
        sources, targets = self.groups_of(src), self.groups_of(dst)
        if not sources and not targets:
            return None
        if len(sources) > 1 or len(targets) > 1:
            raise AssertionError(f"an address in two groups: {sources} {targets}")
        return (not sources or self.side(sources, "egress", dst, pkt)) and (not targets or self.side(targets, "ingress", src, pkt))


NARROWER = {"SOURCE_PORTS_WIDENED", "SERVICE_SCTP", "ZONE_WIDENED", "RULE_TYPE"}


def compare(model: Policy, report: Report, text: str, rng: random.Random, inside: bool, seed: int) -> int:
    """The script never allows more than the model; it allows as much, unless the report says what it left out."""
    judge = ScriptJudge(text)
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
        verdict = judge.allows(pkt)
        if verdict is None:
            assert inside
            continue
        count += 1
        wanted = model_allows(compared, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        # (What is left out of a negated service: the protocols other than TCP, UDP and ICMP.)
        if exact and ("AWS_PART_NOT_WRITTEN" not in codes or pkt.proto in ("tcp", "udp", "icmp", "icmp6")):
            assert verdict == wanted, (seed, pkt, text)
    return count


def without_source_ports(model: Policy) -> Policy:
    for service in model.services.values():
        for entry in service.entries:
            entry.src_ports = ""
    return model


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    """Every piece of every rule on both sides; every address in one group: the script gives the model's verdict."""
    rng = random.Random(seed)
    model = without_source_ports(random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_aws.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare(model, report, text, rng, False, seed) == 500


@pytest.mark.parametrize("seed", range(20))
def test_emitted_script_never_allows_more(seed: int) -> None:
    """With source ports, rule types and zones without networks: what is approximated blocks more, never less."""
    rng = random.Random(2000 + seed)
    model = random_model(rng)
    report = Report()
    networks = {zone: nets for zone, nets in ZONES_AT.items() if rng.random() < 0.8}
    text = emit_aws.emit(model, report, Options(zone_networks=networks))
    compare(model, report, text, rng, False, seed)


@pytest.mark.parametrize("seed", range(20))
def test_emitted_script_with_an_inside_decides_like_the_model(seed: int) -> None:
    """Groups only for the zones inside the VPC; outbound rules leave the inside to the inbound rules there."""
    rng = random.Random(1000 + seed)
    model = without_source_ports(random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    inside = rng.sample(sorted(ZONES_AT), rng.randint(1, 2))
    text = emit_aws.emit(model, report, Options(zone_networks=ZONES_AT, inside_zones=inside))
    assert compare(model, report, text, rng, True, seed) > 100


def test_roundtrip_through_aws_keeps_every_decision() -> None:
    """The sample, converted to a script; the script with every interface given the groups of its address."""
    document = json.loads((DATA / "aws_sample.json").read_text(encoding="utf-8"))
    source, _ = load("aws_sample.json")
    text = cli.convert(source, "aws", Report())
    script, judge = ScriptJudge(text), AwsJudge(document)
    rng = random.Random(7)
    pool = addresses_of(document)
    count = 0
    for _ in range(4000):
        pkt = aws_packet(rng, pool)
        if pkt is None or ip(pkt.dst) in judge.public or ip(pkt.src) in judge.public:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert script.allows(pkt) == verdict, pkt
    assert count > 1000


# -- the sample -------------------------------------------------------------------------------


def test_aws_sample_rules() -> None:
    p, report = load("aws_sample.json")
    assert p.vendor == "aws" and p.scope == "vpc-0a1b2c3d4e5f60789" and not p.zones
    assert p.default_interzone == Action.DENY and p.lookup_after_dnat
    names = [r.name for r in p.rules]
    # The network ACL of the database subnet first, then what the members with narrow outbound rules may reach inside,
    # then the inbound and the outbound rules.
    assert names[0] == "db-acl-in-db" and names.index("app-sg-to-db-sg") < names.index("app-sg-outbound-rest") < names.index("default-in-1")
    by = {r.name: r for r in p.rules}
    assert all(r.action == Action.ALLOW for r in p.rules if ("-in-" in r.name or "-out-" in r.name) and not r.name.startswith("db-acl"))
    assert by["app-sg-to-db-sg"].sources == ["10.20.2.30"] and by["app-sg-to-db-sg"].destinations == ["10.20.3.40"]
    assert by["app-sg-outbound-rest"].action == Action.DROP and by["app-sg-outbound-rest"].sources == ["app-sg members"]
    assert p.address_groups["app-sg members"].members == ["10.20.2.30"]  # (app-1 also carries monitoring-sg, which opens it)
    assert p.address_groups["web-sg"].members == ["10.20.1.10/31", "2001:db8:20:1::10/127"]
    assert p.address_groups["shop-prod"].members == ["10.20.0.0/16", "2001:db8:20::/56"] and p.address_groups["shop-prod"].builtin == "aws"
    assert by["web-sg-in-1"].destinations == ["web-sg", "203.0.113.10", "203.0.113.11"] and by["web-sg-in-1"].services == ["tcp-443"]
    assert by["web-sg-in-5"].sources == ["bastion-sg"] and by["web-sg-in-5"].description == "SSH from the bastion"
    assert by["web-sg-in-5"].source_ids == {"aws.group_id": "sg-0e0000000000000e1"}
    # Outbound rules are for the addresses outside the VPC (and its public addresses), and not for inside alone.
    assert "10.20.0.0/16" not in str(by["web-sg-out-2"].destinations) and "web-sg-out-1" not in by
    assert by["app-sg-out-2"].destinations == ["com.amazonaws.eu-west-1.s3"]
    assert p.address_groups["corp-offices"].members == ["192.0.2.128/25", "198.51.100.0/24"]
    assert p.address_groups["sg-0bbbbbbbbbbbbbbb0"].dynamic_filter.startswith("aws:")
    assert not any(r.name.startswith("legacy") for r in p.rules)
    assert [(n.sources, n.source_translation.addresses) for n in p.nat_rules if n.source_translation] == [
        (["10.20.1.10"], ["203.0.113.10"]), (["10.20.1.11"], ["203.0.113.11"]), (["10.20.9.5"], ["203.0.113.50"])]
    codes = {f.code for f in report.notes}
    assert {"AWS_EGRESS_PAIRS", "AWS_REMOTE_GROUP", "AWS_GROUP_UNUSED", "AWS_NACL_RETURN", "AWS_PUBLIC_ADDRESSES", "AWS_UNFILTERED"} <= codes
    assert not any(f.code == "NAT_DESTINATION_REWRITTEN" for item in report.items.values() for f in item.findings)


def test_aws_sample_decides_like_the_judge() -> None:
    document = json.loads((DATA / "aws_sample.json").read_text(encoding="utf-8"))
    p, _ = load("aws_sample.json")
    judge = AwsJudge(document)
    pool = addresses_of(document) + ["10.20.9.77", "198.51.100.9", "192.0.2.200", "203.0.113.130"]
    rng = random.Random(3)
    count = 0
    for _ in range(6000):
        pkt = aws_packet(rng, pool)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert model_allows(p, pkt) == verdict, pkt
    assert count > 2000
    # A few by hand.
    web = Packet("x", "x", "198.51.100.9", "203.0.113.10", "tcp", 40000, 443)
    assert model_allows(p, web) and judge.allows(web)
    assert not model_allows(p, Packet("x", "x", "10.20.1.10", "10.20.3.40", "tcp", 40000, 5432))  # the ACL of the database
    assert model_allows(p, Packet("x", "x", "10.20.2.30", "10.20.3.40", "tcp", 40000, 5432))  # the lambda, by the pair rule
    assert not model_allows(p, Packet("x", "x", "10.20.2.30", "10.20.1.10", "tcp", 40000, 443))  # its outbound rules say no


# -- reading: details -------------------------------------------------------------------------


def answers(groups: List[Dict[str, Any]], interfaces: Optional[List[Dict[str, Any]]] = None, **more: Any) -> bytes:
    document: List[Dict[str, Any]] = [{"SecurityGroups": groups}]
    if interfaces is not None:
        document.append({"NetworkInterfaces": interfaces})
    for key, value in more.items():
        document.append({key: value})
    return json.dumps(document).encode()


def sg(ident: str, inbound: List[Dict[str, Any]], outbound: Optional[List[Dict[str, Any]]] = None, vpc: str = "vpc-1") -> Dict[str, Any]:
    if outbound is None:
        outbound = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
    return {"GroupId": ident, "GroupName": ident[3:], "VpcId": vpc, "IpPermissions": inbound, "IpPermissionsEgress": outbound}


def eni(ident: str, address: str, groups: List[str], **more: Any) -> Dict[str, Any]:
    return dict({"NetworkInterfaceId": ident, "VpcId": "vpc-1", "SubnetId": "subnet-1", "Groups": [{"GroupId": g} for g in groups],
                 "PrivateIpAddress": address, "PrivateIpAddresses": [{"PrivateIpAddress": address}], "Ipv6Addresses": []}, **more)  # fmt: skip


def tcp(port: int, cidr: str = "0.0.0.0/0") -> Dict[str, Any]:
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}]}


def test_without_interfaces_groups_are_dynamic() -> None:
    report = Report()
    p = parse_aws.parse(answers([sg("sg-web", [tcp(443)], [tcp(5432, "10.0.0.0/8")])]), report)
    assert p.address_groups["web"].dynamic_filter.startswith("aws:") and not p.address_groups["web"].members
    codes = {f.code for f in report.notes}
    assert {"AWS_NO_INTERFACES", "AWS_EGRESS_UNKNOWN"} <= codes
    # No target can write a rule for members nobody knows.
    out = cli.convert(p, "iptables", Report())
    assert "--dport 443" not in out.replace("# ", "") or "FWSHIFT" in out


def test_several_vpcs_and_broken_input_are_refused() -> None:
    with pytest.raises(ParseError, match="several VPCs"):
        parse_aws.parse(answers([sg("sg-a", []), sg("sg-b", [], vpc="vpc-2")]), Report())
    with pytest.raises(ParseError, match="no security groups"):
        parse_aws.parse(b'{"NetworkInterfaces": []}', Report())
    with pytest.raises(ParseError, match="JSON"):
        parse_aws.parse(b'{"SecurityGroups": [', Report())
    with pytest.raises(ParseError, match="not an address"):
        parse_aws.parse(answers([sg("sg-a", [])], [eni("eni-1", "10.0.0.0/24", ["sg-a"])]), Report())
    odd = parse_aws.parse(answers([sg("sg-a", [{"IpProtocol": "tcp", "FromPort": 1, "ToPort": 2, "IpRanges": [5]}])],
                                  [eni("eni-1", "10.0.0.1", ["sg-a"])], Vpcs=[{"VpcId": "vpc-1", "CidrBlockAssociationSet": "x"}]), Report())  # fmt: skip
    assert "a rule without a source or destination" in next(r for r in odd.rules if r.name == "a-in-1").unsupported


def test_detection() -> None:
    assert cli.detect_format((DATA / "aws_sample.json").read_bytes()) == "aws"
    assert cli.detect_format(b'{"SecurityGroups": []}') == "aws"
    assert cli.detect_format(b'[{"GroupId": "sg-1", "IpPermissions": []}]') == "aws"
    assert parse_aws.looks_like_aws(b'{"SecurityGroupRules": []}') and not parse_aws.looks_like_aws(b"<config/>")


def test_what_is_never_read_as_any() -> None:
    groups = [sg("sg-a", [
        {"IpProtocol": "tcp", "FromPort": "x", "ToPort": 2, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        {"IpProtocol": "icmpv6", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.1"}]},
        {"IpProtocol": "gre", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "PrefixListIds": [{"PrefixListId": "pl-missing"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "UserIdGroupPairs": [{"GroupName": "old"}]},
        {"IpProtocol": "50", "FromPort": 1, "ToPort": 2, "IpRanges": [{"CidrIp": "192.0.2.1/32"}]},
    ])]  # fmt: skip
    report = Report()
    p = parse_aws.parse(answers(groups, [eni("eni-1", "10.0.0.5", ["sg-a"], Ipv6Addresses=[{"Ipv6Address": "2001:db8::5"}])]), report)
    by = {r.name: r for r in p.rules}
    assert by["a-in-1"].unsupported and by["a-in-2"].unsupported and by["a-in-3"].unsupported and by["a-in-4"].unsupported
    assert by["a-in-5"].unsupported
    assert p.address_groups["pl-missing"].unsupported and p.address_groups["old"].unsupported
    assert not by["a-in-8"].unsupported and by["a-in-8"].services == ["ip-50"]
    assert any(f.code == "AWS_PORTS_IGNORED" for f in report.item("rule", "a-in-8").findings)
    # A model rule that cannot be read allows nothing: whatever the packet.
    for name in ("a-in-1", "a-in-2", "a-in-3", "a-in-4", "a-in-5"):
        assert by[name].unsupported


def test_rules_of_describe_security_group_rules_and_names() -> None:
    groups = [{"GroupId": "sg-a", "GroupName": "any", "VpcId": "vpc-1", "IpPermissions": [], "IpPermissionsEgress": []},
              {"GroupId": "sg-b", "GroupName": "10.0.0.9", "VpcId": "vpc-1", "IpPermissions": [], "IpPermissionsEgress": []}]  # fmt: skip
    rules = [{"SecurityGroupRuleId": "sgr-1", "GroupId": "sg-a", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
              "CidrIpv4": "198.51.100.0/24", "Description": "web"},
             {"SecurityGroupRuleId": "sgr-2", "GroupId": "sg-a", "IsEgress": False, "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
              "ReferencedGroupInfo": {"GroupId": "sg-b", "UserId": "1"}},
             {"SecurityGroupRuleId": "sgr-3", "GroupId": "sg-a", "IsEgress": True, "IpProtocol": "-1", "FromPort": -1, "ToPort": -1,
              "CidrIpv4": "0.0.0.0/0"}]  # fmt: skip
    report = Report()
    p = parse_aws.parse(answers(groups, [eni("eni-1", "10.0.0.5", ["sg-a"]), eni("eni-2", "10.0.0.9", ["sg-b"])],
                                SecurityGroupRules=rules), report)  # fmt: skip
    assert "any-object" in p.address_groups and "10.0.0.9 (object)" in p.address_groups
    by = {r.name: r for r in p.rules}
    assert by["any-object-in-1"].source_ids == {"aws.group_id": "sg-a", "aws.rule_id": "sgr-1"}
    assert by["any-object-in-2"].sources == ["10.0.0.9 (object)"] and by["any-object-in-1"].description == "web"
    assert by["any-object-out-1"].destinations[0] == "0.0.0.0-10.0.0.4"  # (inside: from the interfaces)


def test_icmp_type_and_code() -> None:
    groups = [sg("sg-a", [{"IpProtocol": "icmp", "FromPort": 3, "ToPort": 4, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                          {"IpProtocol": "icmpv6", "FromPort": 128, "ToPort": -1, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])]  # fmt: skip
    p = parse_aws.parse(answers(groups, [eni("eni-1", "10.0.0.5", ["sg-a"], Ipv6Addresses=[{"Ipv6Address": "2001:db8::5"}])]), Report())
    assert p.services["icmp-3-4"].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]
    assert p.services["icmpv6-128"].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=128)]


def test_rules_of_an_ip_version_no_member_has_match_nothing() -> None:
    groups = [sg("sg-a", [tcp(22), {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])]
    p = parse_aws.parse(answers(groups, [eni("eni-1", "10.0.0.5", ["sg-a"])]), Report())
    assert [r.name for r in p.rules] == ["a-in-1", "a-out-1"]  # (no IPv6 member: the IPv6 rules are left out)


def test_interfaces_of_other_vpcs_prefixes_missing_groups_and_paging() -> None:
    report = Report()
    interfaces = [eni("eni-1", "10.0.0.5", ["sg-a", "sg-gone"]), eni("eni-2", "10.9.0.5", ["sg-b"], VpcId="vpc-9"),
                  eni("eni-3", "10.0.0.7", ["sg-c"], Ipv4Prefixes=[{"Ipv4Prefix": "10.0.0.64/28"}])]  # fmt: skip
    document = [{"SecurityGroups": [sg("sg-a", [tcp(22)]), sg("sg-b", [tcp(22)]), sg("sg-c", [tcp(22)])], "NextToken": "abc"},
                {"NetworkInterfaces": interfaces}]  # fmt: skip
    p = parse_aws.parse(json.dumps(document).encode(), report)
    codes = {f.code for f in report.notes}
    assert {"AWS_INCOMPLETE_EXPORT", "AWS_GROUP_MISSING", "AWS_OTHER_VPC_INTERFACES"} <= codes
    assert "another VPC" in p.address_groups["b"].unsupported and "delegated prefixes" in p.address_groups["c"].unsupported
    assert p.address_groups["a"].members == ["10.0.0.5"]


def test_network_acls_where_they_decide() -> None:
    groups = [sg("sg-a", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])]
    interfaces = [eni("eni-1", "10.0.1.5", ["sg-a"])]
    acl = {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": False, "Associations": [{"SubnetId": "subnet-1"}], "Entries": [
        {"RuleNumber": 10, "Protocol": "6", "RuleAction": "deny", "Egress": False, "CidrBlock": "198.51.100.0/24", "PortRange": {"From": 22, "To": 22}},
        {"RuleNumber": 20, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
        {"RuleNumber": 20, "Protocol": "-1", "RuleAction": "allow", "Egress": True, "CidrBlock": "0.0.0.0/0"},
        {"RuleNumber": 30, "Protocol": "-1", "RuleAction": "allow", "Egress": True, "Ipv6CidrBlock": "::/0"}]}  # fmt: skip
    subnets = [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}]
    report = Report()
    p = parse_aws.parse(answers(groups, interfaces, Subnets=subnets, NetworkAcls=[acl]), report)
    blocking = [r for r in p.rules if r.action != Action.ALLOW]
    assert [(r.sources, r.destinations) for r in blocking] == [(["198.51.100.0/24"], ["10.0.1.0/24"])]
    assert model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "tcp", 1024, 80))
    assert not model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "tcp", 1024, 22))
    assert model_allows(p, Packet("x", "x", "10.0.1.9", "10.0.1.5", "tcp", 1024, 22))  # (inside the subnet: no ACL)
    # Without the subnet the ACL cannot be placed; without ACLs, it is said that they are not in the export.
    report = Report()
    parse_aws.parse(answers(groups, interfaces, NetworkAcls=[acl]), report)
    assert any(f.code == "AWS_NACL_NO_SUBNET" for f in report.notes)
    report = Report()
    parse_aws.parse(answers(groups, interfaces), report)
    assert any(f.code == "AWS_NACL_NOT_EXPORTED" for f in report.notes)
    report = Report()
    parse_aws.parse(answers(groups, interfaces, Subnets=subnets, NetworkAcls=[dict(acl, Associations=[])]), report)
    assert any(f.code == "AWS_NACL_MISSING" for f in report.notes)
    broken = dict(acl, Entries=[{"RuleNumber": 1, "Protocol": "x", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}])
    report = Report()
    parse_aws.parse(answers(groups, interfaces, Subnets=subnets, NetworkAcls=[broken]), report)
    assert any(f.code == "AWS_NACL_NOT_CONVERTED" for f in report.notes)


# -- writing: details -------------------------------------------------------------------------


def small_policy() -> Policy:
    p = Policy(vendor="panos")
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.1.0.10/32")
    p.addresses["guests"] = Address("guests", AddressKind.NETWORK, "10.2.0.0/24")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    deny = Rule("no-guests", sources=["guests"], destinations=["web"], action=Action.DROP)
    allow = Rule("to-web", destinations=["web"], services=["https"])
    for rule in (deny, allow):
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def test_script_runs_in_every_mode(tmp_path: Any) -> None:
    import os
    import subprocess

    report = Report()
    text = emit_aws.emit(small_policy(), report, Options(inside_zones=[]))
    script = tmp_path / "groups.sh"
    script.write_text(text, encoding="utf-8")
    printed = subprocess.run(["sh", str(script)], env=dict(os.environ, DRY_RUN="1"), capture_output=True, text=True)
    assert printed.returncode == 0, printed.stderr
    assert "aws ec2 create-security-group --group-name fwshift-web" in printed.stderr
    assert "authorize-security-group-ingress --group-id sg-dryrun-fwshift-web" in printed.stderr
    missing = subprocess.run(["sh", str(script)], env={k: v for k, v in os.environ.items() if k != "VPC_ID"}, capture_output=True, text=True)
    assert missing.returncode != 0 and "VPC_ID" in missing.stderr
    # A stand-in for the AWS CLI that records the calls and answers like EC2.
    log = tmp_path / "calls.log"
    stub = tmp_path / "bin" / "aws"
    stub.parent.mkdir()
    stub.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$LOG"
case " $* " in *" --dry-run "*) echo "An error occurred (DryRunOperation) when calling the operation" >&2; exit 254 ;; esac
case "$2" in
  describe-security-groups) case "$*" in *group-name,Values=default*) echo sg-default ;; *) echo "${EXISTS:-None}" ;; esac ;;
  create-security-group) echo "sg-new$(wc -l < "$LOG" | tr -d ' ')" ;;
  describe-security-group-rules) echo "${LEFT:-0}" ;;
esac
exit 0
""", encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub.parent}:{os.environ['PATH']}", LOG=str(log), VPC_ID="vpc-1")
    checked = subprocess.run(["sh", str(script)], env=dict(env, CHECK="1"), capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    calls = log.read_text().splitlines()
    assert all("--dry-run" in c for c in calls if c.split()[1].startswith(("create", "authorize", "revoke")))
    assert any("authorize-security-group-ingress --group-id sg-default" in c for c in calls)
    log.write_text("")
    done = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    calls = log.read_text().splitlines()
    assert sum(c.startswith("ec2 revoke-security-group-egress --group-id sg-new") for c in calls) == 2 * text.count("=$(group ")
    assert any(c.startswith("ec2 authorize-security-group-ingress --group-id sg-new") for c in calls)
    assert not any("--dry-run" in c for c in calls)
    log.write_text("")
    stopped = subprocess.run(["sh", str(script)], env=dict(env, EXISTS="sg-old"), capture_output=True, text=True)
    assert stopped.returncode != 0 and "exists" in stopped.stderr
    assert not any("create-security-group" in c for c in log.read_text().splitlines())
    # A new group that still has outbound rules after the default ones were taken off stops the script.
    log.write_text("")
    kept = subprocess.run(["sh", str(script)], env=dict(env, LEFT="1"), capture_output=True, text=True)
    assert kept.returncode != 0 and "still has 1 outbound rules" in kept.stderr
    assert not any("authorize" in c for c in log.read_text().splitlines())


def test_deny_rules_are_taken_out_and_both_ends_written() -> None:
    report = Report()
    text = emit_aws.emit(small_policy(), report, Options())
    judge = ScriptJudge(text)
    assert judge.allows(Packet("x", "x", "198.51.100.1", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("x", "x", "10.2.0.7", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("x", "x", "198.51.100.1", "10.1.0.10", "tcp", 1, 80))
    assert any(f.code == "DENY_SUBTRACTED" for f in report.item("rule", "to-web").findings)
    assert report.item("rule", "no-guests").emitted_as == ["taken out of the rules below it"]
    assert "fwshift-no-rules" in text and "fwshift-web" in text
    # Every address in exactly one group per IP version.
    for address in ("0.0.0.0", "10.1.0.10", "10.2.0.255", "255.255.255.255", "::", "2001:db8::1"):
        assert len(judge.groups_of(ip(address))) == 1


def test_what_a_group_cannot_say() -> None:
    p = small_policy()
    p.addresses["host"] = Address("host", AddressKind.FQDN, "updates.example.com")
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")])
    p.services["high"] = Service("high", [ServiceEntry(Protocol.TCP, "443", "1024-65535")])
    extra = [Rule("fqdn", destinations=["host"]), Rule("sctp", services=["sctp"]), Rule("sport", services=["high"]),
             Rule("users", users=["alice"]), Rule("zone", src_zones=["lan"]), Rule("not-tcp", services=["https"], negate_service=True),
             Rule("intra", src_zones=["lan"], scope=RuleScope.INTRAZONE)]  # fmt: skip
    for rule in extra:
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    emit_aws.emit(p, report, Options())
    for name, code in (("fqdn", "FQDN_NOT_SUPPORTED"), ("sctp", "SERVICE_SCTP"), ("sport", "SOURCE_PORTS"), ("users", "USER_MATCH"),
                       ("zone", "ZONE_NETWORK_MISSING"), ("intra", "RULE_TYPE")):  # fmt: skip
        item = report.item("rule", name)
        assert item.disabled and any(f.code == code for f in item.findings), (name, item.findings)
    assert not any(f.code == "ADDRESS_UNKNOWN" for f in report.item("rule", "fqdn").findings)
    assert any(f.code == "AWS_PART_NOT_WRITTEN" for f in report.item("rule", "not-tcp").findings)


def test_defaults_inside_zones_names_and_quota() -> None:
    p = small_policy()
    p.default_interzone = p.default_intrazone = Action.ALLOW
    report = Report()
    text = emit_aws.emit(p, report, Options(object_prefix="mig-"))
    judge = ScriptJudge(text)
    assert judge.allows(Packet("x", "x", "10.9.9.9", "10.1.0.10", "udp", 1, 53))
    assert not judge.allows(Packet("x", "x", "10.2.0.9", "10.1.0.10", "udp", 1, 53))
    assert "mig-web" in judge.attach and any(f.code == "AWS_DEFAULT_ALLOW" for f in report.notes)
    with pytest.raises(FwshiftError, match="--inside-zone"):
        emit_aws.emit(small_policy(), Report(), Options(inside_zones=["dmz"]))
    p = small_policy()
    p.rules[1].src_zones = ["lan"]
    report = Report()
    text = emit_aws.emit(p, report, Options(zone_networks={"lan": ["10.3.0.0/16"], "dmz": ["10.1.0.0/24"], "wan": ["0.0.0.0/0"]},
                                            inside_zones=["dmz"]))  # fmt: skip
    judge = ScriptJudge(text)
    assert list(judge.attach) == ["fwshift-web", "fwshift-no-rules"]  # (only inside the VPC)
    assert judge.attach["fwshift-no-rules"] == [(ip("10.1.0.0"), ip("10.1.0.9")), (ip("10.1.0.11"), ip("10.1.0.255"))]
    assert judge.allows(Packet("x", "x", "10.3.4.5", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("x", "x", "10.4.4.5", "10.1.0.10", "tcp", 1, 443))
    # Many addresses: more rules than the quota.
    p = small_policy()
    p.rules[1].sources = [f"192.0.2.{n * 2}" for n in range(70)]
    report = Report()
    emit_aws.emit(p, report, Options())
    assert any(f.code == "AWS_RULE_QUOTA" for f in report.notes)


def test_aws_source_to_other_targets_and_nat() -> None:
    source, _ = load("aws_sample.json")
    report = Report()
    out = cli.convert(source, "fortios", report)
    assert "203.0.113.10" in out  # (the public address is a virtual IP there)
    report = Report()
    text = cli.convert(source, "aws", report)
    assert all(item.status == "skipped" for item in report.items.values() if item.kind == "nat")
    assert "# attach fwshift-web-sg: 10.20.1.10/31" in text
    assert not any(line.startswith("# attach") and "198.51.100" in line for line in text.splitlines())  # (inside the VPC only)


# -- review round 28 --------------------------------------------------------------------------


def vpc_answer(cidr: str = "10.0.0.0/16") -> Dict[str, Any]:
    return {"VpcId": "vpc-1", "CidrBlockAssociationSet": [{"CidrBlock": cidr}]}


def public_eni(ident: str, address: str, groups: List[str], public: str, **more: Any) -> Dict[str, Any]:
    out = eni(ident, address, groups, **more)
    out["PrivateIpAddresses"][0]["Association"] = {"PublicIp": public}
    return out


def test_r28_traffic_to_public_addresses_of_the_vpc_is_said_not_converted() -> None:
    """Inside -> a public address of the VPC leaves through the internet gateway: AWS sees public addresses at both ends.
    The parser reads outbound rules for the public addresses as AWS does, and says the rest is not converted."""
    groups = [sg("sg-s", [], [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}]),
              sg("sg-d", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "UserIdGroupPairs": [{"GroupId": "sg-s"}]}])]  # fmt: skip
    interfaces = [public_eni("eni-s", "10.0.0.5", ["sg-s"], "203.0.113.5"), public_eni("eni-d", "10.0.0.9", ["sg-d"], "203.0.113.9")]
    report = Report()
    p = parse_aws.parse(answers(groups, interfaces, Vpcs=[vpc_answer()]), report)
    assert any(f.code == "AWS_HAIRPIN" and f.severity.name == "REVIEW" for f in report.notes)
    # The outbound rules for outside keep the public addresses: AWS checks them against what is sent there.
    assert model_allows(p, Packet("x", "x", "10.0.0.9", "203.0.113.5", "tcp", 1, 443))
    assert not model_allows(p, Packet("x", "x", "10.0.0.5", "203.0.113.9", "tcp", 1, 443))
    # The emitter widens outbound rules to the inside of the VPC only, never to its public addresses.
    policy = Policy(vendor="panos")
    policy.rules.append(Rule("out", sources=["10.0.0.5"], destinations=["198.51.100.0/24"]))
    policy.rules.append(Rule("in", sources=["203.0.113.0/24"], destinations=["10.0.0.9"]))
    nat = NatRule("pub", sources=["10.0.0.9"])
    nat.source_translation = SourceNat(SnatKind.STATIC, ["203.0.113.9"], bidirectional=True)
    nat.origin = "pub"
    policy.nat_rules.append(nat)
    for rule in policy.rules:
        rule.origin = rule.name
    text = emit_aws.emit(policy, Report(), Options(zone_networks={"vpc": ["10.0.0.0/16"]}, inside_zones=["vpc"]))
    judge = ScriptJudge(text)
    assert not judge.side(judge.groups_of(ip("10.0.0.5")), "egress", ip("203.0.113.9"), Packet("x", "x", "10.0.0.5", "203.0.113.9", "tcp", 1, 22))


def test_r28_an_intrazone_blocking_rule_keeps_to_its_source_zones() -> None:
    p = Policy(vendor="panos")
    deny = Rule("no-lan", src_zones=["lan"], dst_zones=["dmz"], scope=RuleScope.INTRAZONE, action=Action.DROP)
    allow = Rule("any-any")
    for rule in (deny, allow):
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    text = emit_aws.emit(p, report, Options(zone_networks={"lan": ["10.1.0.0/16"], "dmz": ["10.2.0.0/16"]}))
    judge = ScriptJudge(text)
    assert not judge.allows(Packet("lan", "lan", "10.1.0.5", "10.1.0.6", "tcp", 1, 22))
    assert judge.allows(Packet("dmz", "dmz", "10.2.0.5", "10.2.0.6", "tcp", 1, 22))


def test_r28_values_json_allows_but_aws_never_has() -> None:
    for text in (b'{"SecurityGroups": [{"GroupId": "sg-a", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 1e400, "ToPort": 2, '
                 b'"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}',
                 b'{"SecurityGroups": [{"GroupId": "sg-a", "IpPermissions": [{"IpProtocol": "icmp", "FromPort": Infinity, '
                 b'"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}'):  # fmt: skip
        p = parse_aws.parse(text, Report())
        assert all(rule.unsupported for rule in p.rules if rule.name.startswith("a-in"))
    acl = {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": False, "Associations": [{"SubnetId": "subnet-1"}], "Entries": [
        {"RuleNumber": 1e999, "Protocol": "6", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 1, "To": 1e999}}]}  # fmt: skip
    text = answers([sg("sg-a", [tcp(22)])], [eni("eni-1", "10.0.1.5", ["sg-a"])], Subnets=[{"SubnetId": "subnet-1", "CidrBlock": "10.0.1.0/24"}],
                   NetworkAcls=[acl])  # fmt: skip
    report = Report()
    parse_aws.parse(text.replace(b"1e+999", b"1e999"), report)
    assert any(f.code == "AWS_NACL_NOT_CONVERTED" for f in report.notes)


def test_r28_acl_entries_without_their_ports_and_tcp_rules_without_ports() -> None:
    groups = [sg("sg-a", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])]
    interfaces = [eni("eni-1", "10.0.1.5", ["sg-a"])]
    subnets = [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}]
    for entry in ({"Protocol": "6"}, {"Protocol": "6", "PortRange": {"From": "x", "To": 2}}, {"Protocol": "1"},
                  {"Protocol": "1", "IcmpTypeCode": {"Type": "echo"}}):  # fmt: skip
        acl = {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": False, "Associations": [{"SubnetId": "subnet-1"}], "Entries": [
            dict({"RuleNumber": 10, "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}, **entry)]}  # fmt: skip
        report = Report()
        p = parse_aws.parse(answers(groups, interfaces, Subnets=subnets, NetworkAcls=[acl]), report)
        assert any(f.code == "AWS_NACL_NOT_CONVERTED" and "inbound" in f.message for f in report.notes), entry
    assert {r.name: r for r in p.rules}["a-in-2"].unsupported  # (a TCP rule without its port range)


def test_r28_replies_icmp_and_other_protocols_through_a_stateless_acl() -> None:
    groups = [sg("sg-a", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])]
    entries = [{"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
               {"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow", "Egress": True, "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 0, "To": 65535}},
               {"RuleNumber": 110, "Protocol": "17", "RuleAction": "allow", "Egress": True, "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 0, "To": 65535}},
               {"RuleNumber": 120, "Protocol": "-1", "RuleAction": "allow", "Egress": True, "Ipv6CidrBlock": "::/0"},
               {"RuleNumber": 121, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "Ipv6CidrBlock": "::/0"}]  # fmt: skip
    acl = {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": False, "Associations": [{"SubnetId": "subnet-1"}], "Entries": entries}
    report = Report()
    parse_aws.parse(answers(groups, [eni("eni-1", "10.0.1.5", ["sg-a"])], Subnets=[{"SubnetId": "subnet-1", "CidrBlock": "10.0.1.0/24"}],
                            NetworkAcls=[acl]), report)  # fmt: skip
    assert [f.message for f in report.notes if f.code == "AWS_NACL_RETURN"] and \
        all("outbound" in f.message for f in report.notes if f.code == "AWS_NACL_RETURN")


def test_r28_routed_interfaces_ipv6_members_without_a_block_and_nat_gateways() -> None:
    groups = [sg("sg-app", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])]
    interfaces = [eni("eni-app", "10.0.2.10", ["sg-app"], Ipv6Addresses=[{"Ipv6Address": "2001:db8:0:2::10"}], SubnetId="subnet-2"),
                  dict(public_eni("eni-nat", "10.0.1.5", [], "203.0.113.50", SubnetId="subnet-1"), InterfaceType="nat_gateway")]  # fmt: skip
    subnets = [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24"}, {"SubnetId": "subnet-2", "VpcId": "vpc-1", "CidrBlock": "10.0.2.0/24"}]
    acl = {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": True, "Associations": [{"SubnetId": "subnet-1"}, {"SubnetId": "subnet-2"}],
           "Entries": [{"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": e, "CidrBlock": "0.0.0.0/0"} for e in (False, True)]}  # fmt: skip
    report = Report()
    p = parse_aws.parse(answers(groups, interfaces, Subnets=subnets, NetworkAcls=[acl], Vpcs=[vpc_answer()]), report)
    assert any(f.code == "AWS_ROUTED_THROUGH" and "eni-nat" in f.message for f in report.notes)
    assert not p.nat_rules  # (a NAT gateway's public address lets nothing in)
    assert not any(" members" == name or name.startswith("-") for name in p.address_groups)
    # The ACL lists no IPv6 rule: IPv6 is denied, also for a subnet whose answer has no IPv6 block.
    assert not model_allows(p, Packet("x", "x", "2001:db8:ff::1", "2001:db8:0:2::10", "tcp", 1, 22))
    assert model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.2.10", "tcp", 1, 22))
