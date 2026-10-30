# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""OCI security lists and network security groups: parser, emitter, and packet-level equivalence with judges of their own.

``OciJudge`` reads the answers of the OCI CLI as a VCN decides a connection, from Oracle's documentation: at each VNIC
the rules of its subnet's security lists and of its NSGs together, the sender's egress rules and the receiver's ingress
rules, a stateless match (which decides over a stateful one) needing its reply let through in the other direction by
the same VNIC, public addresses translated to private ones. ``ScriptJudge`` reads the script the emitter writes,
strictly (the shape of AddSecurityRuleDetails, 25 rules a call, 120 an NSG): its NSGs, the addresses each is for, and
their rules. Neither shares code with the parser or the emitter.
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
from fwshift.emitters import oci as emit_oci
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import Action, Address, AddressKind, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import oci as parse_oci
from fwshift.report import Report

NUMBER = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
REPLY = {1: {8: 0, 13: 14, 15: 16, 17: 18}, 58: {128: 129}}


def proto_number(pkt: Packet) -> int:
    return NUMBER.get(pkt.proto) or int(pkt.proto)


def ip(text: str) -> Any:
    return ipaddress.ip_address(text)


def holds(cidr: str, address: Any) -> bool:
    network = ipaddress.ip_network(cidr, strict=False)
    return network.version == address.version and address in network


def get(node: Dict[str, Any], key: str) -> Any:
    """A key as the CLI spells it (kebab-case) or as the API does (camelCase)."""
    if key in node:
        return node[key]
    camel = re.sub(r"-([a-z0-9])", lambda m: m.group(1).upper(), key)
    return node.get(camel)


def documents(text: str) -> List[Any]:
    decoder, out, position = json.JSONDecoder(), [], 0
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        value, position = decoder.raw_decode(text, position)
        out.append(value)
    return out


def in_range(node: Any, value: int) -> bool:
    return node is None or node["min"] <= value <= node["max"]


def matches_service(rule: Dict[str, Any], pkt: Packet) -> bool:
    protocol = str(rule["protocol"])
    if protocol == "all":
        return True
    number = proto_number(pkt)
    if int(protocol) != number:
        return False
    if number in (6, 17):
        options = get(rule, "tcp-options" if number == 6 else "udp-options") or {}
        return in_range(get(options, "destination-port-range"), pkt.dport) and in_range(get(options, "source-port-range"), pkt.sport)
    if number in (1, 58):
        options = get(rule, "icmp-options")
        return options is None or options["type"] == pkt.icmp_type  # (a packet here carries no code)
    return True


def reply_of(pkt: Packet) -> Optional[Packet]:
    """The reply of a packet; None when it has none (an ICMP message that is no request)."""
    number = proto_number(pkt)
    if number in (1, 58):
        if pkt.icmp_type not in REPLY[number]:
            return None
        return Packet(pkt.out_if, pkt.in_if, pkt.dst, pkt.src, pkt.proto, 0, 0, REPLY[number][pkt.icmp_type])
    return Packet(pkt.out_if, pkt.in_if, pkt.dst, pkt.src, pkt.proto, pkt.dport, pkt.sport, pkt.icmp_type)


# -- the judge of a VCN -----------------------------------------------------------------------


class OciJudge:
    def __init__(self, answers: List[Any]) -> None:
        self.vcn: List[str] = []
        self.subnets: Dict[str, Dict[str, Any]] = {}
        self.lists: Dict[str, Dict[str, Any]] = {}
        self.nsg_rules: Dict[str, List[Dict[str, Any]]] = {}
        self.vnics: List[Dict[str, Any]] = []
        self.extra: Dict[str, List[str]] = {}
        self.regions: Dict[str, str] = {}
        self.ranges: Dict[str, List[Dict[str, Any]]] = {}
        for answer in answers:
            if "regions" in answer:
                self.ranges = {r["region"]: r["cidrs"] for r in answer["regions"]}
                continue
            if "nsgId" in answer:
                self.nsg_rules[answer["nsgId"]] = answer["data"]
                continue
            items = answer["data"] if isinstance(answer["data"], list) else [answer["data"]]
            for item in items:
                ident = item.get("id", "")
                if "key" in item:
                    self.regions[item["key"].lower()] = item["name"]
                elif ident.startswith("ocid1.vcn."):
                    self.vcn += get(item, "cidr-blocks") + (get(item, "ipv6-cidr-blocks") or [])
                elif ident.startswith("ocid1.subnet."):
                    self.subnets[ident] = item
                elif ident.startswith("ocid1.securitylist."):
                    self.lists[ident] = item
                elif ident.startswith("ocid1.vnic."):
                    self.vnics.append(item)
                elif ident.startswith("ocid1.privateip."):
                    self.extra.setdefault(get(item, "vnic-id"), []).append(get(item, "ip-address"))
        self.by_address: Dict[Any, Dict[str, Any]] = {}
        self.public: Dict[Any, Any] = {}
        for vnic in self.vnics:
            for text in [get(vnic, "private-ip")] + self.extra.get(vnic["id"], []) + (get(vnic, "ipv6-addresses") or []):
                self.by_address[ip(text)] = vnic
            if get(vnic, "public-ip"):
                self.public[ip(get(vnic, "public-ip"))] = ip(get(vnic, "private-ip"))

    def label(self, name: str) -> List[str]:
        found = re.fullmatch(r"all-([a-z]+)-services-in-oracle-services-network", name)
        tag = "OSN"
        if not found:
            found, tag = re.fullmatch(r"oci-([a-z]+)-objectstorage", name), "OBJECT_STORAGE"
        region = self.regions.get(found.group(1), "") if found else ""
        return [c["cidr"] for c in self.ranges.get(region, []) if tag in c["tags"]]

    def peer_holds(self, rule: Dict[str, Any], egress: bool, peer: Any) -> bool:
        side = "destination" if egress else "source"
        value, kind = rule[side], get(rule, f"{side}-type")
        if kind == "NETWORK_SECURITY_GROUP":
            vnic = self.by_address.get(peer)
            return vnic is not None and value in (get(vnic, "nsg-ids") or [])
        if kind == "SERVICE_CIDR_BLOCK":
            return any(holds(c, peer) for c in self.label(value))
        return holds(value, peer)

    def rules(self, vnic: Dict[str, Any], egress: bool) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for ident in get(self.subnets[get(vnic, "subnet-id")], "security-list-ids"):
            out += get(self.lists[ident], "egress-security-rules" if egress else "ingress-security-rules")
        for nsg in get(vnic, "nsg-ids") or []:
            out += [r for r in self.nsg_rules.get(nsg, []) if r["direction"] == ("EGRESS" if egress else "INGRESS")
                    and get(r, "is-valid") is not False]  # fmt: skip
        return out

    def passes(self, vnic: Dict[str, Any], egress: bool, peer: Any, pkt: Packet) -> bool:
        return any(matches_service(r, pkt) and self.peer_holds(r, egress, peer) for r in self.rules(vnic, egress))

    def side(self, vnic: Dict[str, Any], egress: bool, peer: Any, pkt: Packet) -> bool:
        matched = [r for r in self.rules(vnic, egress) if matches_service(r, pkt) and self.peer_holds(r, egress, peer)]
        if not matched:
            return False
        if not any(get(r, "is-stateless") for r in matched):
            return True  # tracked: the reply is let back in whatever the other rules say
        reply = reply_of(pkt)
        return reply is None or self.passes(vnic, not egress, peer, reply)

    def allows(self, pkt: Packet) -> Optional[bool]:
        """None when the VCN never sees the packet (or it could not be sent)."""
        src, dst = ip(pkt.src), ip(pkt.dst)
        source = self.by_address.get(src)
        if source is not None and dst in self.public:
            return None  # (back in through the internet gateway: not judged)
        real = self.public.get(dst, dst)
        target = self.by_address.get(real)
        if (source is None and any(holds(c, src) for c in self.vcn)) or (target is None and any(holds(c, real) for c in self.vcn)):
            return None  # an address of the VCN without a VNIC sends and receives nothing
        if (source is None and target is None) or src == real:
            return None
        if source is not None and not self.side(source, True, real, pkt):
            return False
        if target is not None and not self.side(target, False, src, Packet(pkt.in_if, pkt.out_if, pkt.src, str(real), pkt.proto, pkt.sport,
                                                                            pkt.dport, pkt.icmp_type)):  # fmt: skip
            return False
        return True


# -- random VCNs ------------------------------------------------------------------------------

VCN = "ocid1.vcn.oc1.eu-frankfurt-1.examplerandom"
LISTS = [f"ocid1.securitylist.oc1.eu-frankfurt-1.examplesl{n}" for n in range(4)]
NSGS = [f"ocid1.networksecuritygroup.oc1.eu-frankfurt-1.examplensg{n}" for n in range(4)]
OUTSIDE = ["198.51.100.7", "192.0.2.5", "203.0.113.200", "203.0.113.140", "2001:db8:ff::1", "2001:db8:1:9::5"]
CIDRS = ["0.0.0.0/0", "::/0", "10.0.1.0/24", "10.0.0.0/22", "198.51.100.0/24", "10.0.0.16/28", "2001:db8:0:1::/64", "2001:db8::/56",
         "192.0.2.0/25", "10.0.2.0/23"]  # fmt: skip
LABEL = "all-fra-services-in-oracle-services-network"


def random_rule(rng: random.Random, egress: bool, nsg: bool) -> Dict[str, Any]:
    side = "destination" if egress else "source"
    protocol = rng.choice(["all", "6", "6", "6", "17", "1", "58", "47"])
    rule: Dict[str, Any] = {"protocol": protocol, "is-stateless": rng.random() < 0.3, "tcp-options": None, "udp-options": None,
                            "icmp-options": None, "description": None}  # fmt: skip
    if protocol in ("6", "17") and rng.random() < 0.85:
        options: Dict[str, Any] = {}
        if rng.random() < 0.8:
            low, high = rng.choice([(22, 22), (80, 443), (1, 65535), (8000, 8080), (53, 53), (1024, 65535), (5432, 5432)])
            options["destination-port-range"] = {"min": low, "max": high}
        if rng.random() < 0.35:
            low, high = rng.choice([(22, 22), (80, 443), (1024, 65535), (5432, 5432), (53, 53)])
            options["source-port-range"] = {"min": low, "max": high}
        rule["tcp-options" if protocol == "6" else "udp-options"] = options
    elif protocol in ("1", "58") and rng.random() < 0.7:
        kind = rng.choice([0, 3, 8, 128, 129] if protocol == "1" else [128, 129, 2, 1])
        rule["icmp-options"] = {"type": kind, "code": 4 if kind == 3 and rng.random() < 0.5 else None}
    choice = rng.random()
    if nsg and choice < 0.3:
        rule[side], rule[f"{side}-type"] = rng.choice(NSGS + ["ocid1.networksecuritygroup.oc1.eu-frankfurt-1.exampleelsewhere"]), \
            "NETWORK_SECURITY_GROUP"
    elif choice < 0.36:
        rule[side], rule[f"{side}-type"] = LABEL, "SERVICE_CIDR_BLOCK"
    else:
        rule[side], rule[f"{side}-type"] = rng.choice(CIDRS), "CIDR_BLOCK"
    return rule


def random_oci(rng: random.Random) -> List[Any]:
    answers: List[Any] = [{"data": {"id": VCN, "display-name": "rand", "cidr-blocks": ["10.0.0.0/22"], "ipv6-cidr-blocks": ["2001:db8::/56"],
                                    "default-security-list-id": LISTS[0], "lifecycle-state": "AVAILABLE"}}]  # fmt: skip
    subnets = []
    for n in range(3):
        node = {"id": f"ocid1.subnet.oc1.eu-frankfurt-1.examplesubnet{n}", "display-name": f"s{n}", "vcn-id": VCN,
                "cidr-block": f"10.0.{n}.0/24", "security-list-ids": rng.sample(LISTS, rng.randint(1, 2)), "lifecycle-state": "AVAILABLE"}  # fmt: skip
        if n != 2:
            node["ipv6-cidr-blocks"] = [f"2001:db8:0:{n + 1}::/64"]
        subnets.append(node)
    answers.append({"data": subnets})
    lists = []
    for index, ident in enumerate(LISTS):
        ingress = [random_rule(rng, False, False) for _ in range(rng.randint(0, 4))]
        if rng.random() < 0.5:
            egress = [{"protocol": "all", "destination": c, "destination-type": "CIDR_BLOCK", "is-stateless": rng.random() < 0.3}
                      for c in ("0.0.0.0/0", "::/0")]  # fmt: skip
        else:
            egress = [random_rule(rng, True, False) for _ in range(rng.randint(0, 3))]
        lists.append({"id": ident, "display-name": f"sl{index}", "vcn-id": VCN, "lifecycle-state": "AVAILABLE",
                      "ingress-security-rules": ingress, "egress-security-rules": egress})  # fmt: skip
    answers.append({"data": lists})
    answers.append({"data": [{"id": ident, "display-name": f"nsg{n}", "vcn-id": VCN, "lifecycle-state": "AVAILABLE"}
                             for n, ident in enumerate(NSGS)]})  # fmt: skip
    for n, ident in enumerate(NSGS):
        rules = []
        for count in range(rng.randint(0, 4)):
            egress = rng.random() < 0.4
            rule = random_rule(rng, egress, True)
            rule.update({"direction": "EGRESS" if egress else "INGRESS", "id": f"{n}{count:05X}", "is-valid": rng.random() > 0.05})
            rules.append(rule)
        answers.append({"nsgId": ident, "data": rules})
    vnics = []
    for index in range(rng.randint(3, 6)):
        subnet = rng.randrange(3)
        host = 10 + index * 3
        node = {"id": f"ocid1.vnic.oc1.eu-frankfurt-1.examplevnic{index}", "display-name": f"v{index}",
                "subnet-id": f"ocid1.subnet.oc1.eu-frankfurt-1.examplesubnet{subnet}", "private-ip": f"10.0.{subnet}.{host}",
                "nsg-ids": rng.sample(NSGS, rng.randint(0, 3)), "lifecycle-state": "AVAILABLE",
                "ipv6-addresses": [f"2001:db8:0:{subnet + 1}::{host:x}"] if subnet != 2 and rng.random() < 0.5 else [],
                "public-ip": f"203.0.113.{10 + index}" if rng.random() < 0.3 else None}  # fmt: skip
        vnics.append(node)
        private = [{"id": f"ocid1.privateip.oc1.eu-frankfurt-1.example{index}a", "ip-address": node["private-ip"], "vnic-id": node["id"],
                    "subnet-id": node["subnet-id"], "is-primary": True}]  # fmt: skip
        if rng.random() < 0.2:
            private.append({"id": f"ocid1.privateip.oc1.eu-frankfurt-1.example{index}b", "ip-address": f"10.0.{subnet}.{host + 1}",
                            "vnic-id": node["id"], "subnet-id": node["subnet-id"], "is-primary": False})  # fmt: skip
        answers.append({"data": private})
    for node in vnics:
        answers.append({"data": node})
    answers.append({"data": [{"key": "FRA", "name": "eu-frankfurt-1"}]})
    answers.append({"last_updated_timestamp": "2026-10-01T00:00:00", "regions": [{"region": "eu-frankfurt-1", "cidrs": [
        {"cidr": "203.0.113.128/26", "tags": ["OSN", "OBJECT_STORAGE"]}, {"cidr": "203.0.113.0/26", "tags": ["OCI"]}]}]})  # fmt: skip
    return answers


def addresses_of(answers: List[Any]) -> List[str]:
    out = list(OUTSIDE) + ["10.0.3.9"]
    for answer in answers:
        items = answer.get("data") if isinstance(answer.get("data"), list) else [answer.get("data")]
        for item in items:
            if isinstance(item, dict) and str(item.get("id", "")).startswith("ocid1.vnic."):
                out += [item["private-ip"]] + (item["ipv6-addresses"] or []) + ([item["public-ip"]] if item["public-ip"] else [])
            if isinstance(item, dict) and str(item.get("id", "")).startswith("ocid1.privateip."):
                out.append(item["ip-address"])
    return out


def oci_packet(rng: random.Random, pool: List[str]) -> Optional[Packet]:
    src, dst = rng.choice(pool), rng.choice(pool)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    pkt = random_packet(rng, 6 if ":" in src else 4)
    pkt.src, pkt.dst = src, dst
    pkt.dport = rng.choice([22, 53, 80, 443, 5432, 8000, 8080, 3000, 40000])
    pkt.sport = rng.choice([22, 53, 80, 1000, 5432, 40000])
    if pkt.proto in ("icmp", "icmp6"):
        pkt.icmp_type = rng.choice([0, 3, 8, 128, 129])
    return pkt


def concatenated(answers: List[Any]) -> bytes:
    return "".join(json.dumps(a, indent=1) + "\n" for a in answers).encode()


def test_parsed_policy_decides_like_the_judge() -> None:
    compared = 0
    for seed in range(80):
        rng = random.Random(seed)
        answers = random_oci(rng)
        report = Report()
        model = parse_oci.parse(concatenated(answers), report)
        judge = OciJudge(answers)
        pool = addresses_of(answers)
        for _ in range(250):
            pkt = oci_packet(rng, pool)
            if pkt is None:
                continue
            verdict = judge.allows(pkt)
            if verdict is None:
                continue
            compared += 1
            assert model_allows(model, pkt) == verdict, (seed, pkt)
    assert compared > 8000


# -- the judge of a script --------------------------------------------------------------------

KEYS = {"description", "direction", "isStateless", "protocol", "source", "sourceType", "destination", "destinationType", "tcpOptions",
        "udpOptions", "icmpOptions"}  # fmt: skip


class ScriptJudge:
    def __init__(self, text: str) -> None:
        self.attach: Dict[str, List[Any]] = {}
        names: Dict[str, str] = {}
        self.rules: Dict[str, List[Dict[str, Any]]] = {}
        lines = text.splitlines()
        for index, line in enumerate(lines):
            found = re.match(r"# attach (\S+): (.*)$", line)
            if found:
                assert found.group(1) not in self.attach
                self.attach[found.group(1)] = [self.span(token) for token in found.group(2).split()]
            found = re.match(r"(G\d+)=\$\(nsg '([^']+)'\) \|\| exit 1$", line)
            if found:
                assert re.fullmatch(r"[A-Za-z0-9._-]{1,100}", found.group(2))
                names[found.group(1)] = found.group(2)
            found = re.match(r'rules "\$(G\d+)" <<\'FWSHIFT_JSON\'$', line)
            if found:
                assert lines[index + 2] == "FWSHIFT_JSON"
                call = json.loads(lines[index + 1])
                assert 1 <= len(call) <= 25
                for rule in call:
                    self.check(rule)
                self.rules.setdefault(names[found.group(1)], []).extend(call)
        assert set(names.values()) == set(self.attach)
        assert all(len(rules) <= 120 for rules in self.rules.values())

    @staticmethod
    def check(rule: Dict[str, Any]) -> None:
        """What AddSecurityRuleDetails takes, as the API reference describes it."""
        assert set(rule) <= KEYS, rule
        assert rule["isStateless"] is False and rule["direction"] in ("INGRESS", "EGRESS")
        side = "source" if rule["direction"] == "INGRESS" else "destination"
        assert rule[side + "Type"] == "CIDR_BLOCK" and ipaddress.ip_network(rule[side])  # (strict: a network address)
        other = "destination" if side == "source" else "source"
        assert other not in rule and other + "Type" not in rule
        protocol = rule["protocol"]
        assert protocol == "all" or (protocol.isdigit() and 0 <= int(protocol) <= 255)
        options = {k for k in ("tcpOptions", "udpOptions", "icmpOptions") if k in rule}
        assert options <= {"6": {"tcpOptions"}, "17": {"udpOptions"}, "1": {"icmpOptions"}, "58": {"icmpOptions"}}.get(protocol, set())
        for key in ("tcpOptions", "udpOptions"):
            for part in rule.get(key, {}).values():
                assert set(part) == {"min", "max"} and 0 <= part["min"] <= part["max"] <= 65535
        if "icmpOptions" in rule:
            assert set(rule["icmpOptions"]) <= {"type", "code"} and "type" in rule["icmpOptions"]
        version = ipaddress.ip_network(rule[side]).version
        assert not (protocol == "1" and version == 6) and not (protocol == "58" and version == 4)
        assert len(rule["description"]) <= 255

    @staticmethod
    def span(token: str) -> Tuple[Any, Any]:
        if "-" in token and "/" not in token:
            first, last = token.split("-")
            return ip(first), ip(last)
        network = ipaddress.ip_network(token)
        return network[0], network[-1]

    def groups_of(self, address: Any) -> List[str]:
        return [name for name, spans in self.attach.items() if any(a.version == address.version and a <= address <= b for a, b in spans)]

    def side(self, groups: List[str], direction: str, peer: Any, pkt: Packet) -> bool:
        key = "source" if direction == "INGRESS" else "destination"
        for group in groups:
            for rule in self.rules.get(group, []):
                if rule["direction"] == direction and holds(rule[key], peer) and matches_service(rule, pkt):
                    return True
        return False

    def allows(self, pkt: Packet) -> Optional[bool]:
        src, dst = ip(pkt.src), ip(pkt.dst)
        sources, targets = self.groups_of(src), self.groups_of(dst)
        if not sources and not targets:
            return None
        return (not sources or self.side(sources, "EGRESS", dst, pkt)) and (not targets or self.side(targets, "INGRESS", src, pkt))


NARROWER = {"SERVICE_SCTP", "ZONE_WIDENED", "RULE_TYPE"}


def compare(model: Policy, report: Report, text: str, rng: random.Random, inside: bool, seed: int, decide: Any = model_allows) -> int:
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
        wanted = decide(compared, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        if exact and ("OCI_PART_NOT_WRITTEN" not in codes or pkt.proto in ("tcp", "udp", "icmp", "icmp6")):
            assert verdict == wanted, (seed, pkt, text)
    return count


@pytest.mark.parametrize("seed", range(30))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    """Every piece of every rule on both sides, source ports too; every address in its NSGs: the model's verdict."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_oci.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare(model, report, text, rng, False, seed) == 500


@pytest.mark.parametrize("seed", range(15))
def test_emitted_script_never_allows_more(seed: int) -> None:
    """With rule types and zones without networks: what is approximated blocks more, never less."""
    rng = random.Random(2000 + seed)
    model = random_model(rng)
    report = Report()
    networks = {zone: nets for zone, nets in ZONES_AT.items() if rng.random() < 0.8}
    text = emit_oci.emit(model, report, Options(zone_networks=networks))
    compare(model, report, text, rng, False, seed)


@pytest.mark.parametrize("seed", range(15))
def test_the_defaults_inside_and_between_zones_as_the_source_decides(seed: int) -> None:
    from test_gcp import model_decides, with_random_defaults

    rng = random.Random(5000 + seed)
    model = with_random_defaults(rng, random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_oci.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare(model, report, text, rng, False, seed, decide=model_decides) == 500


@pytest.mark.parametrize("seed", range(15))
def test_emitted_script_with_an_inside_decides_like_the_model(seed: int) -> None:
    """NSGs only for the zones inside the VCN; egress rules leave the inside to the ingress rules there."""
    rng = random.Random(1000 + seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    inside = rng.sample(sorted(ZONES_AT), rng.randint(1, 2))
    text = emit_oci.emit(model, report, Options(zone_networks=ZONES_AT, inside_zones=inside))
    assert compare(model, report, text, rng, True, seed) > 100


def test_random_vcns_through_the_script_keep_every_decision() -> None:
    """Random VCNs read and written again: the NSGs decide as the security lists and NSGs did, where nothing was flagged."""
    compared = 0
    for seed in range(25):
        rng = random.Random(9000 + seed)
        answers = random_oci(rng)
        report = Report()
        model = parse_oci.parse(concatenated(answers), report)
        text = cli.convert(model, "oci", report)
        # (A rule the parser could not read matches nothing in the model either: ICMP with an address of the other version.)
        lossy = [item.name for item in report.items.values() if item.kind == "rule" and item.disabled
                 and {f.code for f in item.findings} != {"UNSUPPORTED_MATCH"}]  # fmt: skip
        part = any(f.code == "OCI_PART_NOT_WRITTEN" for item in report.items.values() for f in item.findings)
        script, judge = ScriptJudge(text), OciJudge(answers)
        pool = addresses_of(answers)
        for _ in range(250):
            pkt = oci_packet(rng, pool)
            if pkt is None or ip(pkt.dst) in judge.public or ip(pkt.src) in judge.public:
                continue
            verdict = judge.allows(pkt)
            if verdict is None:
                continue
            written = script.allows(pkt)
            assert written is not None and written <= verdict, (seed, pkt)
            if not lossy and (not part or pkt.proto in ("tcp", "udp", "icmp", "icmp6")):
                compared += 1
                assert written == verdict, (seed, pkt)
    assert compared > 2000


def test_roundtrip_through_oci_keeps_every_decision() -> None:
    """The sample, converted to a script; every VNIC put in the NSGs of its addresses, and the subnets' lists emptied."""
    answers = documents((DATA / "oci_sample.json").read_text(encoding="utf-8"))
    source, _ = load("oci_sample.json")
    text = cli.convert(source, "oci", Report())
    script, judge = ScriptJudge(text), OciJudge(answers)
    rng = random.Random(7)
    pool = addresses_of(answers) + ["203.0.113.130", "203.0.113.200", "198.51.100.9"]
    count = 0
    for _ in range(4000):
        pkt = oci_packet(rng, pool)
        if pkt is None or ip(pkt.dst) in judge.public or ip(pkt.src) in judge.public:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert script.allows(pkt) == verdict, pkt
    assert count > 1000


# -- the sample -------------------------------------------------------------------------------


def test_oci_sample_rules() -> None:
    p, report = load("oci_sample.json")
    assert p.vendor == "oci" and p.scope.startswith("ocid1.vcn.") and not p.zones
    assert p.default_interzone == Action.DENY and p.lookup_after_dnat
    names = [r.name for r in p.rules]
    by = {r.name: r for r in p.rules}
    # The stateless rules without their replies first, then what addresses with narrow egress rules may reach inside the
    # VCN, then the ingress and the egress rules.
    assert names[0] == "db-subnet-stateless-in"
    assert names.index("app-subnet-to-db-sl") < names.index("app-subnet-egress-rest") < names.index("web-sl-in-1")
    first = by["db-subnet-stateless-in"]
    assert first.action == Action.DROP and first.sources == ["10.30.2.0/24"] and first.destinations == ["10.30.3.0/24"]
    assert p.services[first.services[0]].entries == [ServiceEntry(Protocol.TCP, "5432", "0-1023")]  # (replies to 1024-65535 only)
    backup = by["db-subnet-stateless-in-2"]
    assert backup.sources == ["10.30.9.10"]  # (the stateless rule decides over the stateful one for management)
    ping = by["db-subnet-stateless-in-3"]
    assert p.services[ping.services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    assert not any("icmp-3-4" in r.services for r in p.rules if r.action == Action.DROP)  # (no reply needed)
    assert p.address_groups["web-nsg"].members == ["10.30.1.10/31", "2001:db8:30:1::10/127"]
    assert p.address_groups["app-nsg"].members == ["10.30.2.30-10.30.2.32"]  # (a secondary address too)
    assert p.address_groups["Default Security List for shop-vcn"].members == ["web-subnet", "mgmt-subnet"]
    assert p.address_groups["shop-vcn"].members == ["10.30.0.0/16", "2001:db8:30::/56"] and p.address_groups["shop-vcn"].builtin == "oci"
    assert p.address_groups["all-fra-services-in-oracle-services-network"].members == ["203.0.113.128-203.0.113.223"]
    assert p.address_groups["oci-ams-objectstorage"].unsupported
    assert by["web-sl-in-1"].destinations == ["web-sl", "203.0.113.10", "203.0.113.11"] and by["web-sl-in-1"].description == "HTTPS from anywhere"
    assert by["web-nsg-in-1"].sources == ["bastion-nsg"] and by["web-nsg-in-1"].source_ids == {
        "oci.nsg_id": "ocid1.networksecuritygroup.oc1.eu-frankfurt-1.examplewebnsg", "oci.rule_id": "0A1B01"}
    assert by["db-sl-in-1"].source_ids["oci.rule"] == "ingress 1"
    assert by["app-sl-out-3"].services == ["udp-123-from-123"] and "10.30.0.0" not in str(by["app-sl-out-3"].destinations)
    assert "app-sl-out-1" not in by  # (inside the VCN only: the pairs decide)
    assert by["db-sl-in-6"].unsupported  # (ICMPv6 with an IPv4 block)
    assert not any(r.name.startswith(("spare-sl", "legacy-nsg")) for r in p.rules)
    assert not any("0A1B03" in r.source_ids.values() for r in p.rules)  # (is-valid false)
    assert [(n.sources, n.source_translation.addresses) for n in p.nat_rules if n.source_translation] == [
        (["10.30.1.10"], ["203.0.113.10"]), (["10.30.1.11"], ["203.0.113.11"]), (["10.30.9.5"], ["203.0.113.50"])]
    codes = {f.code for f in report.notes}
    assert {"OCI_EGRESS_PAIRS", "OCI_STATELESS_REPLY", "OCI_REMOTE_NSG", "OCI_SERVICE_LABEL", "OCI_UNUSED", "OCI_RULE_INVALID",
            "OCI_PUBLIC_ADDRESSES", "OCI_HAIRPIN", "OCI_UNFILTERED", "OCI_DEFAULT_SECURITY_LIST", "OCI_TERMINATED"} <= codes
    assert "OCI_EGRESS_PAIRS_LEFT_OUT" not in codes
    assert any(f.code == "OCI_SERVICE_RANGES" for f in report.item("rule", "app-sl-out-2").findings)
    assert any(f.code == "OCI_STATELESS_REPLY" for f in report.item("rule", "db-sl-in-2").findings)


def test_oci_sample_decides_like_the_judge() -> None:
    answers = documents((DATA / "oci_sample.json").read_text(encoding="utf-8"))
    p, _ = load("oci_sample.json")
    judge = OciJudge(answers)
    pool = addresses_of(answers) + ["203.0.113.130", "203.0.113.200", "198.51.100.9", "192.0.2.200"]
    rng = random.Random(3)
    count = 0
    for _ in range(6000):
        pkt = oci_packet(rng, pool)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert model_allows(p, pkt) == verdict, pkt
    assert count > 2000
    # A few by hand.
    assert model_allows(p, Packet("x", "x", "198.51.100.9", "203.0.113.10", "tcp", 40000, 443))  # HTTPS to a public address
    assert model_allows(p, Packet("x", "x", "10.30.2.30", "10.30.3.40", "tcp", 40000, 5432))  # the app tier, by the pair rule
    assert not model_allows(p, Packet("x", "x", "10.30.2.30", "10.30.3.40", "tcp", 1000, 5432))  # no stateless reply to port 1000
    assert model_allows(p, Packet("x", "x", "10.30.9.5", "10.30.3.40", "tcp", 40000, 5432))  # management, stateful
    assert not model_allows(p, Packet("x", "x", "10.30.9.10", "10.30.3.40", "tcp", 40000, 5432))  # the backup host: stateless wins
    assert not model_allows(p, Packet("x", "x", "10.30.2.30", "10.30.1.10", "tcp", 40000, 443))  # app's egress rules say no
    assert model_allows(p, Packet("x", "x", "10.30.1.10", "10.30.2.30", "tcp", 40000, 8080))  # web-nsg to app-nsg, both ends


# -- reading: details -------------------------------------------------------------------------


def subnet(name: str, cidr: str, lists: List[str], **more: Any) -> Dict[str, Any]:
    return dict({"id": f"ocid1.subnet.oc1.x.{name}", "display-name": name, "vcn-id": "ocid1.vcn.oc1.x.v", "cidr-block": cidr,
                 "security-list-ids": lists}, **more)  # fmt: skip


def security_list(name: str, ingress: List[Dict[str, Any]], egress: Optional[List[Dict[str, Any]]] = None, vcn: str = "ocid1.vcn.oc1.x.v") -> Dict[str, Any]:
    if egress is None:
        egress = [{"protocol": "all", "destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK", "is-stateless": False}]
    return {"id": f"ocid1.securitylist.oc1.x.{name}", "display-name": name, "vcn-id": vcn, "ingress-security-rules": ingress,
            "egress-security-rules": egress}  # fmt: skip


def tcp_in(port: int, cidr: str = "0.0.0.0/0", stateless: bool = False, **more: Any) -> Dict[str, Any]:
    return dict({"protocol": "6", "source": cidr, "source-type": "CIDR_BLOCK", "is-stateless": stateless,
                 "tcp-options": {"destination-port-range": {"min": port, "max": port}}}, **more)  # fmt: skip


def small(lists: List[Dict[str, Any]], subnets: Optional[List[Dict[str, Any]]] = None, *more: Any) -> bytes:
    answers: List[Any] = [{"data": subnets if subnets is not None else [subnet("a", "10.0.1.0/24", [lists[0]["id"]])]}, {"data": lists}]
    return concatenated(answers + list(more))


def test_detection() -> None:
    for path in sorted(DATA.glob("*sample*")):
        assert parse_oci.looks_like_oci(path.read_bytes()) == path.name.startswith("oci_"), path.name
    assert cli.detect_format((DATA / "oci_sample.json").read_bytes()) == "oci"
    assert cli.detect_format(small([security_list("l", [tcp_in(22)])])) == "oci"


def test_camel_case_and_an_array_read_the_same() -> None:
    kebab = small([security_list("l", [tcp_in(22, stateless=True)])])
    rules = [{"protocol": "6", "source": "0.0.0.0/0", "sourceType": "CIDR_BLOCK", "isStateless": True,
              "tcpOptions": {"destinationPortRange": {"min": 22, "max": 22}}}]  # fmt: skip
    camel = json.dumps([{"data": [{"id": "ocid1.subnet.oc1.x.a", "displayName": "a", "vcnId": "ocid1.vcn.oc1.x.v", "cidrBlock": "10.0.1.0/24",
                                   "securityListIds": ["ocid1.securitylist.oc1.x.l"]}]},
                        {"data": [{"id": "ocid1.securitylist.oc1.x.l", "displayName": "l", "vcnId": "ocid1.vcn.oc1.x.v",
                                   "ingressSecurityRules": rules,
                                   "egressSecurityRules": [{"protocol": "all", "destination": "0.0.0.0/0", "isStateless": False}]}]}]).encode()  # fmt: skip
    one, two = parse_oci.parse(kebab, Report()), parse_oci.parse(camel, Report())
    assert one.to_dict() == two.to_dict()


def test_several_vcns_and_broken_input_are_refused() -> None:
    other = security_list("o", [tcp_in(80)], vcn="ocid1.vcn.oc1.x.w")
    data = small([security_list("l", [tcp_in(22)]), other])
    with pytest.raises(ParseError, match="several VCNs"):
        parse_oci.parse(data, Report())
    report = Report()
    p = parse_oci.parse(data, report, vcn="ocid1.vcn.oc1.x.v")
    assert not any(r.name.startswith("o-") for r in p.rules) and any(f.code == "OCI_OTHER_VCN" for f in report.notes)
    with pytest.raises(ParseError, match="--policy"):
        parse_oci.parse(data, Report(), vcn="nope")
    # A VNIC in a subnet of the other VCN is left out with it.
    lists = [security_list("l", [tcp_in(22)]), other]
    subnets = [subnet("a", "10.0.1.0/24", [lists[0]["id"]]), subnet("b", "10.9.1.0/24", [other["id"]], **{"vcn-id": "ocid1.vcn.oc1.x.w"})]
    vnic = {"id": "ocid1.vnic.oc1.x.9", "subnet-id": "ocid1.subnet.oc1.x.b", "private-ip": "10.9.1.5", "nsg-ids": []}
    report = Report()
    p = parse_oci.parse(small(lists, subnets, {"data": vnic}), report, vcn="ocid1.vcn.oc1.x.v")
    assert "b" not in p.address_groups and not any(f.code == "OCI_SUBNET_MISSING" for f in report.notes)
    with pytest.raises(ParseError, match="no security lists"):
        parse_oci.parse(b'{"data": []}', Report())
    with pytest.raises(ParseError, match="cannot be read"):
        parse_oci.parse(b'{"data": [', Report())
    with pytest.raises(ParseError, match="not a CIDR"):
        parse_oci.parse(small([security_list("l", [])], [subnet("a", "10.0.1.0", ["ocid1.securitylist.oc1.x.l"])]), Report())


def test_what_is_never_read_as_any() -> None:
    odd = [
        {"protocol": "6", "source": "10.0.0.0/8", "source-type": "CIDR_BLOCK", "udp-options": {}},
        {"protocol": "1", "source": "10.0.0.0/8", "source-type": "CIDR_BLOCK", "icmp-options": {"code": 3}},
        {"protocol": "tcp", "source": "10.0.0.0/8"},
        {"protocol": "6", "source": "10.0.0.5"},
        {"protocol": "6", "source": "10.0.0.0/8", "tcp-options": {"destination-port-range": {"min": 90, "max": 80}}},
        {"protocol": "all", "source": "10.0.0.0/8", "tcp-options": {}},
        {"protocol": "47", "source": "10.0.0.0/8", "udp-options": {}},
        {"protocol": "6", "source": "10.0.0.0/8", "source-type": "SOMETHING_NEW"},
        {"protocol": "6", "source": "10.0.0.0/8", "is-stateless": "yes"},
    ]
    p = parse_oci.parse(small([security_list("l", odd)]), Report())
    rules = [r for r in p.rules if r.name.startswith("l-in-")]
    assert len(rules) == len(odd) and all(r.unsupported for r in rules), [(r.name, r.unsupported) for r in rules]


def test_stateless_rules_need_their_replies() -> None:
    reply = {"protocol": "6", "destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK", "is-stateless": True,
             "tcp-options": {"source-port-range": {"min": 80, "max": 80}}}  # fmt: skip
    # With the reply rule the stateless ingress rule is a plain allow; without it, nothing passes.
    p = parse_oci.parse(small([security_list("l", [tcp_in(80, stateless=True)], [reply])]), Report())
    assert model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "tcp", 40000, 80)) and p.rules[0].action == Action.ALLOW
    report = Report()
    p = parse_oci.parse(small([security_list("l", [tcp_in(80, stateless=True)], [])]), report)
    assert not model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "tcp", 40000, 80))
    assert p.rules[0].action == Action.DROP and any(f.code == "OCI_STATELESS_REPLY" for f in report.notes)
    # A stateful rule for the same traffic does not help: the stateless one decides.
    p = parse_oci.parse(small([security_list("l", [tcp_in(80, stateless=True), tcp_in(80)], [])]), Report())
    assert not model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "tcp", 40000, 80))
    # An ICMP message that is no request needs no reply; a request needs its reply type.
    icmp = [{"protocol": "1", "source": "0.0.0.0/0", "is-stateless": True, "icmp-options": {"type": t}} for t in (3, 8)]
    p = parse_oci.parse(small([security_list("l", icmp, [])]), Report())
    assert model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "icmp", 0, 0, 3))
    assert not model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "icmp", 0, 0, 8))
    echo = [{"protocol": "1", "destination": "198.51.100.0/24", "is-stateless": False, "icmp-options": {"type": 0, "code": 0}}]
    p = parse_oci.parse(small([security_list("l", icmp, echo)]), Report())
    assert model_allows(p, Packet("x", "x", "198.51.100.1", "10.0.1.5", "icmp", 0, 0, 8))
    assert not model_allows(p, Packet("x", "x", "192.0.2.1", "10.0.1.5", "icmp", 0, 0, 8))


def test_nsgs_need_their_vnics_and_their_rules() -> None:
    nsg = {"id": "ocid1.networksecuritygroup.oc1.x.n", "display-name": "n", "vcn-id": "ocid1.vcn.oc1.x.v"}
    rule = {"direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "source-type": "CIDR_BLOCK", "is-stateless": False, "id": "01"}
    report = Report()
    p = parse_oci.parse(small([security_list("l", [])], None, {"data": [nsg]}, {"nsgId": nsg["id"], "data": [rule]}), report)
    assert p.address_groups["n"].dynamic_filter.startswith("oci:") and any(f.code == "OCI_NO_VNICS" for f in report.notes)
    report = Report()
    parse_oci.parse(small([security_list("l", [])], None, {"data": [nsg]}, {"data": [rule]}), report)
    codes = {f.code for f in report.notes}
    assert {"OCI_NSG_RULES_UNWRAPPED", "OCI_NSG_RULES_MISSING"} <= codes
    vnic = {"id": "ocid1.vnic.oc1.x.1", "subnet-id": "ocid1.subnet.oc1.x.a", "private-ip": "10.0.1.5", "nsg-ids": [nsg["id"], "ocid1.networksecuritygroup.oc1.x.gone"],
            "skip-source-dest-check": True, "security-attributes": {"Oracle-ZPR": {"app": {"value": "x", "mode": "enforce"}}}}  # fmt: skip
    report = Report()
    p = parse_oci.parse(small([security_list("l", [])], None, {"data": [nsg]}, {"nsgId": nsg["id"], "data": [rule]}, {"data": vnic},
                              {"data": [{"id": "ocid1.privateip.oc1.x.9", "ip-address": "10.0.1.9", "vnic-id": "ocid1.vnic.oc1.x.2"}]}), report)  # fmt: skip
    assert p.address_groups["n"].members == ["10.0.1.5"]
    codes = {f.code for f in report.notes}
    assert {"OCI_NSG_MISSING", "OCI_ROUTED_THROUGH", "OCI_ZPR", "OCI_VNIC_MISSING"} <= codes


def test_paging_and_service_labels_without_ranges() -> None:
    rules = [{"protocol": "6", "source": "oci-fra-objectstorage", "source-type": "SERVICE_CIDR_BLOCK"}]
    report = Report()
    answers: List[Any] = [{"data": [subnet("a", "10.0.1.0/24", ["ocid1.securitylist.oc1.x.l"])], "opc-next-page": "AAAA"},
                          {"data": [security_list("l", rules)]}]  # fmt: skip
    p = parse_oci.parse(concatenated(answers), report)
    assert p.address_groups["oci-fra-objectstorage"].unsupported
    assert {"OCI_INCOMPLETE_EXPORT", "OCI_SERVICE_LABEL"} <= {f.code for f in report.notes}
    report = Report()
    parse_oci.parse(concatenated([{"data": [security_list("l", [tcp_in(22)])]}]), report)
    assert any(f.code == "OCI_SUBNETS_MISSING" for f in report.notes)


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

    text = emit_oci.emit(small_policy(), Report(), Options())
    script = tmp_path / "nsgs.sh"
    script.write_text(text, encoding="utf-8")
    printed = subprocess.run(["sh", str(script)], env=dict(os.environ, DRY_RUN="1"), capture_output=True, text=True)
    assert printed.returncode == 0, printed.stderr
    assert "oci network nsg create --compartment-id ocid1.compartment.oc1..dryrun --vcn-id ocid1.vcn.oc1..dryrun --display-name fwshift-web" in printed.stderr
    assert "oci network nsg rules add --nsg-id ocid1.networksecuritygroup.dryrun.fwshift-web --security-rules [" in printed.stderr
    missing = subprocess.run(["sh", str(script)], env={k: v for k, v in os.environ.items() if k not in ("VCN_ID", "COMPARTMENT_ID")},
                             capture_output=True, text=True)  # fmt: skip
    assert missing.returncode != 0 and "COMPARTMENT_ID" in missing.stderr
    # A stand-in for the OCI CLI that records the calls and answers like OCI.
    log = tmp_path / "calls.log"
    stub = tmp_path / "bin" / "oci"
    stub.parent.mkdir()
    stub.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$LOG"
case "$2 $3" in
  "nsg list") printf '%s\\n' "${EXISTS:-}" ;;
  "nsg create") echo "ocid1.networksecuritygroup.oc1.x.new$(wc -l < "$LOG" | tr -d ' ')" ;;
  "nsg rules") [ -n "${REFUSE:-}" ] && { echo 'ServiceError: InvalidParameter' >&2; exit 1; } ;;
esac
exit 0
""", encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub.parent}:{os.environ['PATH']}", LOG=str(log), VCN_ID="ocid1.vcn.oc1.x.v",
               COMPARTMENT_ID="ocid1.compartment.oc1..c")  # fmt: skip
    done = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    calls = log.read_text().splitlines()
    assert sum(c.startswith("network nsg create") for c in calls) == text.count("=$(nsg ")
    assert any(c.startswith("network nsg rules add --nsg-id ocid1.networksecuritygroup.oc1.x.new") for c in calls)
    assert all("--wait-for-state AVAILABLE" in c for c in calls if "nsg create" in c)
    log.write_text("")
    stopped = subprocess.run(["sh", str(script)], env=dict(env, EXISTS="1"), capture_output=True, text=True)
    assert stopped.returncode != 0 and "exists" in stopped.stderr
    assert not any("nsg create" in c for c in log.read_text().splitlines())
    refused = subprocess.run(["sh", str(script)], env=dict(env, REFUSE="1"), capture_output=True, text=True)
    assert refused.returncode != 0 and "FAILED: nsg rules add" in refused.stderr


def test_deny_rules_are_taken_out_and_both_ends_written() -> None:
    report = Report()
    text = emit_oci.emit(small_policy(), report, Options())
    judge = ScriptJudge(text)
    assert judge.allows(Packet("x", "x", "198.51.100.1", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("x", "x", "10.2.0.7", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("x", "x", "198.51.100.1", "10.1.0.10", "tcp", 1, 80))
    assert any(f.code == "DENY_SUBTRACTED" for f in report.item("rule", "to-web").findings)
    assert report.item("rule", "no-guests").emitted_as == ["taken out of the rules below it"]
    assert "fwshift-no-rules" in text and "fwshift-web" in text
    for address in ("0.0.0.0", "10.1.0.10", "10.2.0.255", "255.255.255.255", "::", "2001:db8::1"):
        assert len(judge.groups_of(ip(address))) == 1
    assert {"OCI_LOAD", "OCI_ATTACH", "OCI_SECURITY_LISTS"} <= {f.code for f in report.notes}


def test_source_ports_icmp_and_what_an_nsg_cannot_say() -> None:
    p = small_policy()
    p.addresses["host"] = Address("host", AddressKind.FQDN, "updates.example.com")
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")])
    p.services["high"] = Service("high", [ServiceEntry(Protocol.UDP, "53", "1024-65535")])
    p.services["unreach"] = Service("unreach", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)])
    extra = [Rule("fqdn", destinations=["host"]), Rule("sctp", services=["sctp"]), Rule("sport", destinations=["web"], services=["high"]),
             Rule("icmp", destinations=["web"], services=["unreach"]), Rule("users", users=["alice"]), Rule("zone", src_zones=["lan"]),
             Rule("not-tcp", services=["https"], negate_service=True), Rule("intra", src_zones=["lan"], scope=RuleScope.INTRAZONE)]  # fmt: skip
    for rule in extra:
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    text = emit_oci.emit(p, report, Options())
    for name, code in (("fqdn", "FQDN_NOT_SUPPORTED"), ("sctp", "SERVICE_SCTP"), ("users", "USER_MATCH"), ("zone", "ZONE_NETWORK_MISSING"),
                       ("intra", "RULE_TYPE")):  # fmt: skip
        item = report.item("rule", name)
        assert item.disabled and any(f.code == code for f in item.findings), (name, item.findings)
    assert not report.item("rule", "sport").disabled
    assert any(f.code == "OCI_PART_NOT_WRITTEN" for f in report.item("rule", "not-tcp").findings)
    rules = [r for rs in ScriptJudge(text).rules.values() for r in rs]
    assert {"description": "FWShift: sport", "direction": "INGRESS", "isStateless": False, "protocol": "17", "source": "128.0.0.0/1",
            "sourceType": "CIDR_BLOCK", "udpOptions": {"destinationPortRange": {"max": 53, "min": 53},
                                                      "sourcePortRange": {"max": 65535, "min": 1024}}} in rules  # fmt: skip
    assert any(r.get("icmpOptions") == {"type": 3, "code": 4} for r in rules)
    assert ScriptJudge(text).allows(Packet("x", "x", "198.51.100.1", "10.1.0.10", "udp", 2000, 53))


def test_defaults_inside_zones_names_and_limits() -> None:
    p = small_policy()
    p.default_interzone = p.default_intrazone = Action.ALLOW
    report = Report()
    text = emit_oci.emit(p, report, Options(object_prefix="mig-"))
    judge = ScriptJudge(text)
    assert judge.allows(Packet("x", "x", "10.9.9.9", "10.1.0.10", "udp", 1, 53))
    assert not judge.allows(Packet("x", "x", "10.2.0.9", "10.1.0.10", "udp", 1, 53))
    assert "mig-web" in judge.attach and any(f.code == "OCI_DEFAULT_ALLOW" for f in report.notes)
    with pytest.raises(FwshiftError, match="--inside-zone"):
        emit_oci.emit(small_policy(), Report(), Options(inside_zones=["dmz"]))
    p = small_policy()
    p.rules[1].src_zones = ["lan"]
    text = emit_oci.emit(p, Report(), Options(zone_networks={"lan": ["10.3.0.0/16"], "dmz": ["10.1.0.0/24"], "wan": ["0.0.0.0/0"]},
                                              inside_zones=["dmz"]))  # fmt: skip
    judge = ScriptJudge(text)
    assert list(judge.attach) == ["fwshift-web", "fwshift-no-rules"]  # (only inside the VCN)
    assert judge.allows(Packet("x", "x", "10.3.4.5", "10.1.0.10", "tcp", 1, 443))
    assert not judge.allows(Packet("x", "x", "10.4.4.5", "10.1.0.10", "tcp", 1, 443))
    # Many addresses: more rules than an NSG takes, split into parts that a VNIC is put in together.
    p = small_policy()
    p.rules[1].sources = [f"192.0.2.{n * 2}" for n in range(100)] + [f"198.51.100.{n * 2}" for n in range(60)]
    report = Report()
    text = emit_oci.emit(p, report, Options(inside_zones=["dmz"], zone_networks={"dmz": ["10.1.0.0/24"]}))
    judge = ScriptJudge(text)
    assert judge.groups_of(ip("10.1.0.10")) == ["fwshift-web", "fwshift-web-part2"]
    assert judge.allows(Packet("x", "x", "198.51.100.118", "10.1.0.10", "tcp", 1, 443))
    assert judge.allows(Packet("x", "x", "192.0.2.0", "10.1.0.10", "tcp", 1, 443))
    assert any(f.code == "OCI_RULE_LIMIT" for f in report.notes)


def test_oci_source_to_other_targets() -> None:
    source, _ = load("oci_sample.json")
    out = cli.convert(source, "fortios", Report())
    assert "203.0.113.10" in out  # (the public address is a virtual IP there)
    report = Report()
    text = cli.convert(source, "oci", report)
    assert all(item.status == "skipped" for item in report.items.values() if item.kind == "nat")
    assert not any(line.startswith("# attach") and "198.51.100" in line for line in text.splitlines())  # (inside the VCN only)
    text = cli.convert(source, "aws", Report())
    assert "authorize-security-group-ingress" in text
