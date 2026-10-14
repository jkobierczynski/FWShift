# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Google Cloud firewall: parser, emitters, and packet-level equivalence with judges of their own.

``GcpJudge`` reads the answers of gcloud as Google Cloud decides a connection: the egress steps of the sender, the
ingress steps of the receiver (VPC firewall rules, the global and the regional network firewall policy, in the order
of the network, then the implied action), external addresses translated to internal ones. ``ScriptJudge`` reads the
script the gcp emitter writes as a network firewall policy decides. Neither shares code with the parser or the
emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
import shlex
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.parsers import gcp as parse_gcp
from fwshift.report import Report

NUMBER = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "esp": 50, "ah": 51, "sctp": 132, "ipip": 4, "gre": 47, "icmpv6": 58}


def ip(text: str) -> Any:
    return ipaddress.ip_address(text)


def holds(cidr: str, address: Any) -> bool:
    network = ipaddress.ip_network(cidr, strict=False)
    return network.version == address.version and address in network


def proto_number(pkt: Packet) -> int:
    return NUMBER.get(pkt.proto) or int(pkt.proto)


def in_ports(ports: List[str], port: int) -> bool:
    if not ports:
        return True
    for text in ports:
        first, _, last = text.partition("-")
        if int(first) <= port <= int(last or first):
            return True
    return False


def l4_matches(entries: List[Dict[str, Any]], key: str, pkt: Packet) -> bool:
    for entry in entries:
        protocol = str(entry[key]).lower()
        if protocol == "all":
            return True
        number = PROTOCOLS.get(protocol) or int(protocol)
        if number != proto_number(pkt):
            continue
        if number in (6, 17, 132) and not in_ports(entry.get("ports", []), pkt.dport):
            continue
        return True
    return False


def last(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1]


# -- the judge of a network -----------------------------------------------------------------------


class GcpJudge:
    def __init__(self, bundle: Dict[str, Any], network: str = "") -> None:
        rules = bundle.get("firewall-rules", [])
        policies = bundle.get("network-firewall-policies", [])
        self.network = network or last(rules[0]["network"] if rules else policies[0]["associations"][0]["attachmentTarget"])
        found = [n for n in bundle.get("networks", []) if n["name"] == self.network]
        self.order = found[0].get("networkFirewallPolicyEnforcementOrder", "AFTER_CLASSIC_FIREWALL") if found else "AFTER_CLASSIC_FIREWALL"
        self.vpc = [r for r in rules if last(r["network"]) == self.network and not r.get("disabled")]
        self.vpc.sort(key=lambda r: (r.get("priority", 1000), 0 if "denied" in r else 1))
        mine = [p for p in policies if any(last(a["attachmentTarget"]) == self.network for a in p.get("associations", []))]
        self.global_policies = [p for p in mine if not p.get("region")]
        self.regional = [p for p in mine if p.get("region")]
        self.vms: List[Dict[str, Any]] = []
        self.public: Dict[Any, Any] = {}
        for instance in bundle.get("instances", []):
            for nic in instance["networkInterfaces"]:
                if last(nic["network"]) != self.network:
                    continue
                vm = {"name": instance["name"], "region": last(instance["zone"]).rsplit("-", 1)[0],
                      "tags": set(instance.get("tags", {}).get("items", [])),
                      "accounts": {a["email"] for a in instance.get("serviceAccounts", [])},
                      "primary": [ip(nic["networkIP"])] + ([ip(nic["ipv6Address"])] if nic.get("ipv6Address") else []),
                      "aliases": [a["ipCidrRange"] for a in nic.get("aliasIpRanges", [])]}  # fmt: skip
                self.vms.append(vm)
                for config in nic.get("accessConfigs", []):
                    self.public[ip(config["natIP"])] = ip(nic["networkIP"])

    def vm_of(self, address: Any) -> Optional[Dict[str, Any]]:
        for vm in self.vms:
            if address in vm["primary"] or any(holds(a, address) for a in vm["aliases"]):
                return vm
        return None

    def tagged(self, address: Any, tags: List[str], accounts: List[str]) -> bool:
        return any(address in vm["primary"] and (vm["tags"] & set(tags) or vm["accounts"] & set(accounts)) for vm in self.vms)

    def vpc_step(self, vm: Dict[str, Any], direction: str, own: Any, peer: Any, pkt: Packet) -> Optional[str]:
        for rule in self.vpc:
            if rule.get("direction", "INGRESS") != direction:
                continue
            tags, accounts = rule.get("targetTags", []), rule.get("targetServiceAccounts", [])
            if (tags or accounts) and not (vm["tags"] & set(tags) or vm["accounts"] & set(accounts)):
                continue
            if direction == "INGRESS":
                ranges, stags, saccounts = rule.get("sourceRanges", []), rule.get("sourceTags", []), rule.get("sourceServiceAccounts", [])
                if not ranges and not stags and not saccounts:  # (no source: every address of the version of the rule)
                    dests = rule.get("destinationRanges", [])
                    ranges = ["::/0"] if dests and all(":" in r for r in dests) else ["0.0.0.0/0"]
                if not (any(holds(r, peer) for r in ranges) or self.tagged(peer, stags, saccounts)):
                    continue
                if rule.get("destinationRanges") and not any(holds(r, own) for r in rule["destinationRanges"]):
                    continue
            else:
                sources = rule.get("sourceRanges", [])
                every = ["::/0"] if sources and all(":" in r for r in sources) else ["0.0.0.0/0"]
                if not any(holds(r, peer) for r in rule.get("destinationRanges", every)):
                    continue
                if rule.get("sourceRanges") and not any(holds(r, own) for r in rule["sourceRanges"]):
                    continue
            if not l4_matches(rule.get("allowed") or rule.get("denied"), "IPProtocol", pkt):
                continue
            return "allow" if "allowed" in rule else "deny"
        return None

    def policy_step(self, policy: Dict[str, Any], vm: Dict[str, Any], direction: str, own: Any, peer: Any, pkt: Packet) -> Optional[str]:
        for rule in sorted(policy["rules"], key=lambda r: r["priority"]):
            if rule.get("disabled") or rule["direction"] != direction:
                continue
            accounts = rule.get("targetServiceAccounts", [])
            if accounts and not vm["accounts"] & set(accounts):
                continue
            match = rule["match"]
            srcs, dsts = match.get("srcIpRanges", []), match.get("destIpRanges", [])
            remote, near = (srcs, dsts) if direction == "INGRESS" else (dsts, srcs)
            if not any(holds(r, peer) for r in remote):
                continue
            if near and not any(holds(r, own) for r in near):
                continue
            if not l4_matches(match["layer4Configs"], "ipProtocol", pkt):
                continue
            return None if rule["action"] == "goto_next" else rule["action"]
        return None

    def decide(self, vm: Dict[str, Any], direction: str, own: Any, peer: Any, pkt: Packet) -> str:
        policies = self.global_policies + [p for p in self.regional if last(p["region"]) == vm["region"]]
        steps = [("vpc", None)] + [("policy", p) for p in policies]
        if self.order == "BEFORE_CLASSIC_FIREWALL":
            steps = steps[1:] + steps[:1]
        for kind, policy in steps:
            verdict = self.vpc_step(vm, direction, own, peer, pkt) if kind == "vpc" else self.policy_step(policy, vm, direction, own, peer, pkt)
            if verdict is not None:
                return verdict
        return "deny" if direction == "INGRESS" else "allow"

    def allows(self, pkt: Packet) -> Optional[bool]:
        src, dst = ip(pkt.src), ip(pkt.dst)
        source = self.vm_of(src)
        if source is not None and dst in self.public:
            return None  # (to an external address from inside: not judged)
        real = self.public.get(dst, dst)
        target = self.vm_of(real)
        if (source is None and target is None) or src == real or source is target:
            return None
        if source is not None and self.decide(source, "EGRESS", src, real, pkt) != "allow":
            return False
        return target is None or self.decide(target, "INGRESS", real, src, pkt) == "allow"


# -- random networks ------------------------------------------------------------------------------

API = "https://www.googleapis.com/compute/v1/projects/p"
NET = f"{API}/global/networks/net"
TAGS = ["web", "app", "db"]
ACCOUNTS = ["a@p.iam.gserviceaccount.com", "b@p.iam.gserviceaccount.com"]
RANGES4 = ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "198.51.100.0/24", "192.0.2.0/25", "10.1.2.16/28"]
RANGES6 = ["::/0", "2001:db8::/32", "2001:db8:1::/48", "2001:db8:ff::/48"]
OUTSIDE = ["198.51.100.7", "192.0.2.5", "203.0.113.9", "10.9.9.9", "2001:db8:ff::1", "2001:db8:abcd::1"]


def random_l4(rng: random.Random, key: str) -> List[Dict[str, Any]]:
    out = []
    for _ in range(rng.randint(1, 2)):
        protocol = rng.choice(["tcp", "tcp", "udp", "icmp", "58", "all", "esp", "6", "sctp"])
        entry: Dict[str, Any] = {key: protocol}
        if protocol in ("tcp", "udp", "6", "sctp") and rng.random() < 0.7:
            entry["ports"] = rng.choice([["22"], ["80", "443"], ["8000-8080"], ["53"], ["1-65535"]])
        out.append(entry)
    return out


def random_vpc_rule(rng: random.Random, index: int) -> Dict[str, Any]:
    direction = rng.choice(["INGRESS", "INGRESS", "EGRESS"])
    six = rng.random() < 0.25
    pool = RANGES6 if six else RANGES4
    rule: Dict[str, Any] = {"kind": "compute#firewall", "name": f"r{index}", "network": NET, "priority": rng.choice([100, 500, 1000, 1000]),
                            "direction": direction, "disabled": rng.random() < 0.1}  # fmt: skip
    rule["denied" if rng.random() < 0.35 else "allowed"] = random_l4(rng, "IPProtocol")
    target = rng.random()
    if target < 0.4:
        rule["targetTags"] = rng.sample(TAGS, rng.randint(1, 2))
    elif target < 0.55:
        rule["targetServiceAccounts"] = [rng.choice(ACCOUNTS)]
    if direction == "INGRESS":
        source = rng.random()
        if source < 0.6:
            rule["sourceRanges"] = rng.sample(pool, rng.randint(1, 2))
        if 0.45 < source < 0.8 and "targetServiceAccounts" not in rule:
            rule["sourceTags"] = [rng.choice(TAGS)]
        elif 0.8 <= source < 0.9 and "targetTags" not in rule:
            rule["sourceServiceAccounts"] = [rng.choice(ACCOUNTS)]
        if rng.random() < 0.1:
            rule["destinationRanges"] = [rng.choice(["10.1.1.0/24", "10.1.0.0/16"] if not six else ["2001:db8:1::/48"])]
    else:
        if rng.random() < 0.8:
            rule["destinationRanges"] = rng.sample(pool, rng.randint(1, 2))
        elif six and rng.random() < 0.5:
            rule["destinationRanges"] = ["::/0"]
        if rng.random() < 0.15:
            rule["sourceRanges"] = [rng.choice(["10.1.1.0/24", "10.1.0.0/16"] if not six else ["2001:db8:1::/48"])]
    return rule


def random_policy_rule(rng: random.Random, priority: int) -> Dict[str, Any]:
    direction = rng.choice(["INGRESS", "INGRESS", "EGRESS"])
    pool = RANGES6 if rng.random() < 0.25 else RANGES4
    match: Dict[str, Any] = {("srcIpRanges" if direction == "INGRESS" else "destIpRanges"): rng.sample(pool, rng.randint(1, 2)),
                             "layer4Configs": random_l4(rng, "ipProtocol")}  # fmt: skip
    rule = {"kind": "compute#firewallPolicyRule", "priority": priority, "direction": direction,
            "action": rng.choice(["allow", "deny", "goto_next", "allow"]), "match": match, "disabled": rng.random() < 0.08}  # fmt: skip
    if rng.random() < 0.2:
        rule["targetServiceAccounts"] = [rng.choice(ACCOUNTS)]
    return rule


def predefined() -> List[Dict[str, Any]]:
    return [{"priority": p, "direction": d, "action": "goto_next",
             "match": {("destIpRanges" if d == "EGRESS" else "srcIpRanges"): [r], "layer4Configs": [{"ipProtocol": "all"}]}}
            for p, d, r in ((2147483644, "EGRESS", "::/0"), (2147483645, "INGRESS", "::/0"), (2147483646, "EGRESS", "0.0.0.0/0"),
                            (2147483647, "INGRESS", "0.0.0.0/0"))]  # fmt: skip


def random_gcp(rng: random.Random, policies: bool = True) -> Dict[str, Any]:
    rules = [random_vpc_rule(rng, i) for i in range(rng.randint(2, 9))]
    found: List[Dict[str, Any]] = []
    if policies:
        for region in ([""] if rng.random() < 0.7 else []) + (["r1"] if rng.random() < 0.5 else []):
            numbers = sorted(rng.sample(range(10, 2000, 10), rng.randint(1, 6)))
            policy: Dict[str, Any] = {"kind": "compute#firewallPolicy", "name": f"pol{region}",
                                      "associations": [{"name": "a", "attachmentTarget": NET}],
                                      "rules": [random_policy_rule(rng, n) for n in numbers] + predefined()}  # fmt: skip
            if region:
                policy["region"] = f"{API}/regions/{region}"
            found.append(policy)
    instances = []
    for index in range(rng.randint(2, 5)):
        nic: Dict[str, Any] = {"network": NET, "networkIP": f"10.1.{rng.randrange(3)}.{10 + index * 4}"}
        if rng.random() < 0.4:
            nic["ipv6Address"] = f"2001:db8:1::{10 + index:x}"
        if rng.random() < 0.3:
            nic["accessConfigs"] = [{"natIP": f"203.0.113.{100 + index}", "type": "ONE_TO_ONE_NAT"}]
        if rng.random() < 0.15:
            nic["aliasIpRanges"] = [{"ipCidrRange": f"10.2.{index}.0/28"}]
        instances.append({"kind": "compute#instance", "name": f"vm{index}", "zone": f"{API}/zones/{rng.choice(['r1', 'r2'])}-a",
                          "tags": {"items": rng.sample(TAGS, rng.randint(0, 2))},
                          "serviceAccounts": [{"email": rng.choice(ACCOUNTS)}], "networkInterfaces": [nic]})  # fmt: skip
    network = {"kind": "compute#network", "name": "net", "selfLink": NET,
               "networkFirewallPolicyEnforcementOrder": rng.choice(["AFTER_CLASSIC_FIREWALL", "BEFORE_CLASSIC_FIREWALL"])}  # fmt: skip
    return {"networks": [network], "firewall-rules": rules, "network-firewall-policies": found, "instances": instances}


def addresses_of(bundle: Dict[str, Any]) -> List[str]:
    out = list(OUTSIDE)
    for instance in bundle["instances"]:
        for nic in instance["networkInterfaces"]:
            out.append(nic["networkIP"])
            if nic.get("ipv6Address"):
                out.append(nic["ipv6Address"])
            for config in nic.get("accessConfigs", []):
                out.append(config["natIP"])
            for alias in nic.get("aliasIpRanges", []):
                out.append(str(ipaddress.ip_network(alias["ipCidrRange"])[3]))
    return out


def gcp_packet(rng: random.Random, pool: List[str]) -> Optional[Packet]:
    src, dst = rng.choice(pool), rng.choice(pool)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    pkt = random_packet(rng, 6 if ":" in src else 4)
    pkt.src, pkt.dst = src, dst
    pkt.proto = rng.choice(["tcp", "tcp", "udp", "icmp" if ":" not in src else "icmp6", "50", "sctp"])
    pkt.dport = rng.choice([22, 53, 80, 443, 8000, 8080, 3000])
    return pkt


def judged(bundle: Dict[str, Any], model: Any, rng: random.Random, seed: int, packets: int = 300) -> int:
    judge = GcpJudge(bundle)
    pool = addresses_of(bundle)
    count = 0
    for _ in range(packets):
        pkt = gcp_packet(rng, pool)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert model_allows(model, pkt) == verdict, (seed, pkt, json.dumps(bundle, indent=1))
    return count


def test_parsed_policy_decides_like_the_judge() -> None:
    compared = 0
    for seed in range(250):
        rng = random.Random(seed)
        bundle = random_gcp(rng)
        model = parse_gcp.parse(json.dumps(bundle).encode(), Report())
        compared += judged(bundle, model, rng, seed)
    assert compared > 25000


def test_the_sample_decides_like_the_judge() -> None:
    bundle = json.loads((DATA / "gcp_sample.json").read_text(encoding="utf-8"))
    model, report = load("gcp_sample.json")
    rng = random.Random(4)
    assert judged(bundle, model, rng, 0, packets=5000) > 2000


# -- the judge of the script ----------------------------------------------------------------------


class ScriptJudge:
    """The rules a script creates, as a network firewall policy decides: by priority, ingress and egress apart."""

    def __init__(self, text: str) -> None:
        self.rules: List[Dict[str, Any]] = []
        assert "network-firewall-policies create \"$POLICY\" --global" in text
        assert "associations create" not in text.replace("#   gcloud compute network-firewall-policies associations create", "")
        for line in text.splitlines():
            if not line.startswith("run compute network-firewall-policies rules create "):
                continue
            words = shlex.split(line.replace('"$POLICY"', "POLICY"))
            rule: Dict[str, Any] = {"priority": int(words[5]), "disabled": False}
            for word in words[6:]:
                key, _, value = word.partition("=")
                rule[key] = value
                if key == "--disabled":
                    rule["disabled"] = True
            assert rule["--firewall-policy"] == "POLICY" and "--global-firewall-policy" in rule
            for side in ("--src-ip-ranges", "--dest-ip-ranges"):
                ranges = rule[side].split(",")
                assert len({ipaddress.ip_network(r).version for r in ranges}) == 1, rule  # (one IP version per rule)
            self.rules.append(rule)
        numbers = [r["priority"] for r in self.rules]
        assert numbers == sorted(numbers) and len(numbers) == len(set(numbers)) and max(numbers) <= 2147483547

    @staticmethod
    def l4(text: str, pkt: Packet) -> bool:
        entries = []
        for part in text.split(","):
            protocol, _, port = part.partition(":")
            entries.append({"ipProtocol": protocol, "ports": [port] if port else []})
        return l4_matches(entries, "ipProtocol", pkt)

    def decide(self, direction: str, pkt: Packet) -> Optional[bool]:
        src, dst = ip(pkt.src), ip(pkt.dst)
        for rule in self.rules:
            if rule["disabled"] or rule["--direction"] != direction:
                continue
            if not any(holds(r, src) for r in rule["--src-ip-ranges"].split(",")):
                continue
            if not any(holds(r, dst) for r in rule["--dest-ip-ranges"].split(",")):
                continue
            if not self.l4(rule["--layer4-configs"], pkt):
                continue
            return rule["--action"] == "allow"
        return None

    def allows(self, pkt: Packet) -> bool:
        ingress, egress = self.decide("INGRESS", pkt), self.decide("EGRESS", pkt)
        assert ingress is not None and ingress == egress, (pkt, ingress, egress)
        return ingress


NARROWER = {"ZONE_WIDENED", "RULE_TYPE", "GCP_PART_NOT_WRITTEN", "GCP_BLOCKS_MORE"}


def compare(model: Any, report: Report, text: str, rng: random.Random, seed: int, packets: int = 500) -> int:
    judge = ScriptJudge(text)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    codes = {f.code for item in report.items.values() for f in item.findings}
    exact = not codes & NARROWER
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        if rng.random() < 0.15:
            pkt.proto = rng.choice(["50", "sctp"])
        verdict = judge.allows(pkt)
        wanted = model_allows(compared, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        if exact:
            assert verdict == wanted, (seed, pkt, text)
        count += 1
    return count


def without_source_ports_and_icmp_types(model: Any) -> Any:
    for service in model.services.values():
        for entry in service.entries:
            entry.src_ports = ""
            entry.icmp_type = entry.icmp_code = None
    return model


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    from fwshift.emitters import gcp as emit_gcp
    from fwshift.model import RuleScope
    from fwshift.options import Options

    rng = random.Random(seed)
    model = without_source_ports_and_icmp_types(random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_gcp.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare(model, report, text, rng, seed) == 500


@pytest.mark.parametrize("seed", range(25))
def test_emitted_script_never_allows_more(seed: int) -> None:
    from fwshift.emitters import gcp as emit_gcp
    from fwshift.options import Options

    rng = random.Random(3000 + seed)
    model = random_model(rng)
    report = Report()
    networks = {zone: nets for zone, nets in ZONES_AT.items() if rng.random() < 0.8}
    text = emit_gcp.emit(model, report, Options(zone_networks=networks))
    compare(model, report, text, rng, seed)


# -- what is read, and what is not ------------------------------------------------------------------


def bundle(rules: List[Dict[str, Any]] = (), policies: List[Dict[str, Any]] = (), instances: Optional[List[Dict[str, Any]]] = None,
           order: str = "AFTER_CLASSIC_FIREWALL") -> bytes:  # fmt: skip
    out: Dict[str, Any] = {"networks": [{"kind": "compute#network", "name": "net", "selfLink": NET, "networkFirewallPolicyEnforcementOrder": order}],
                           "firewall-rules": list(rules), "network-firewall-policies": list(policies)}  # fmt: skip
    if instances is not None:
        out["instances"] = instances
    return json.dumps(out).encode()


def vm(name: str, address: str, tags: List[str] = (), account: str = "a@p.iam.gserviceaccount.com", region: str = "r1") -> Dict[str, Any]:
    return {"kind": "compute#instance", "name": name, "zone": f"{API}/zones/{region}-a", "tags": {"items": list(tags)},
            "serviceAccounts": [{"email": account}], "networkInterfaces": [{"network": NET, "networkIP": address}]}  # fmt: skip


def fw(name: str, priority: int = 1000, direction: str = "INGRESS", action: str = "allow", **more: Any) -> Dict[str, Any]:
    out = {"kind": "compute#firewall", "name": name, "network": NET, "priority": priority, "direction": direction,
           ("allowed" if action == "allow" else "denied"): [{"IPProtocol": "tcp", "ports": ["22"]}]}  # fmt: skip
    out.update(more)
    return out


def pol(name: str, rules: List[Dict[str, Any]], region: str = "", target: str = NET) -> Dict[str, Any]:
    out: Dict[str, Any] = {"kind": "compute#firewallPolicy", "name": name, "associations": [{"name": "a", "attachmentTarget": target}],
                           "rules": rules + predefined()}  # fmt: skip
    if region:
        out["region"] = f"{API}/regions/{region}"
    return out


def prule(priority: int, action: str = "allow", direction: str = "INGRESS", **match: Any) -> Dict[str, Any]:
    body = {"layer4Configs": [{"ipProtocol": "tcp", "ports": ["443"]}]}
    body.update(match)
    if direction == "INGRESS":
        body.setdefault("srcIpRanges", ["0.0.0.0/0"])
    else:
        body.setdefault("destIpRanges", ["0.0.0.0/0"])
    return {"priority": priority, "direction": direction, "action": action, "match": body}


def parse(data: bytes, network: str = "") -> Tuple[Any, Report]:
    report = Report()
    return parse_gcp.parse(data, report, network=network), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def test_detection_networks_and_errors() -> None:
    assert cli.detect_format(bundle([fw("a", sourceRanges=["10.0.0.0/8"])])) == "gcp"
    assert cli.detect_format(json.dumps([fw("a")]).encode()) == "gcp"
    assert cli.detect_format(json.dumps([{k: v for k, v in fw("a").items() if k != "kind"}]).encode()) == "gcp"
    assert cli.detect_format(json.dumps(pol("p", [])).encode()) == "gcp"
    other = dict(fw("b"), network=f"{API}/global/networks/other")
    with pytest.raises(ParseError, match="several networks"):
        parse(bundle([fw("a"), other]))
    model, _ = parse(bundle([fw("a"), other], instances=[vm("v", "10.0.0.5")]), network="net")
    assert [r.name for r in model.rules if r.name == "b"] == []
    assert model.scope == "net"
    with pytest.raises(ParseError, match="no firewall rule or policy of network 'nowhere'"):
        parse(bundle([fw("a")]), network="nowhere")
    with pytest.raises(ParseError, match="two rules with one priority"):
        parse(bundle(policies=[pol("p", [prule(10), prule(10, "deny")])]))
    with pytest.raises(ParseError, match="several global network firewall policies"):
        parse(bundle(policies=[pol("p", [prule(10)]), pol("q", [prule(20)])]))
    with pytest.raises(ParseError, match="enforcement order 'SIDEWAYS'"):
        parse(bundle([fw("a")], order="SIDEWAYS"))
    with pytest.raises(ParseError, match="no firewall rules or network firewall policies"):
        parse(json.dumps({"networks": []}).encode())
    with pytest.raises(ParseError, match="is not an address"):
        parse(bundle([fw("a")], instances=[vm("v", "10.0.0.0/24")]))
    with pytest.raises(ParseError, match="cannot be read"):
        parse(b"{")


def test_what_cannot_be_resolved_is_not_converted() -> None:
    instances = [vm("web", "10.0.0.5", ["web"]), vm("db", "10.0.0.6", ["db"], account="b@p.iam.gserviceaccount.com")]
    rules = [prule(10, "deny", srcFqdns=["blocked.example.com"]), prule(20, "deny", srcRegionCodes=["XX"], srcIpRanges=["198.51.100.0/24"]),
             dict(prule(30, "deny"), targetSecureTags=[{"name": "tagValues/1", "state": "EFFECTIVE"}]),
             dict(prule(40, "deny"), targetSecureTags=[{"name": "tagValues/2", "state": "INEFFECTIVE"}]),
             dict(prule(50, "deny"), targetType="INTERNAL_MANAGED_LB"), prule(60, "deny", srcNetworkType="INTERNET"),
             prule(70, "apply_security_profile_group")]  # fmt: skip
    model, report = parse(bundle(policies=[pol("p", rules)], instances=instances))
    unsupported = {r.source_ids.get("gcp.priority") for r in model.rules if r.unsupported}
    assert {"10", "20", "30", "50", "60", "70"} <= unsupported and "40" not in {r.source_ids.get("gcp.priority") for r in model.rules}
    # Without the instances: what a rule applies to is not known.
    model, report = parse(bundle([fw("a", sourceRanges=["10.0.0.0/8"], targetTags=["web"])]))
    assert "GCP_NO_INSTANCES" in codes(report) and all(r.unsupported for r in model.rules if r.enabled)


def test_notes_of_the_export() -> None:
    instances = [vm("web", "10.0.0.5", ["web"])]
    other = pol("elsewhere", [prule(10)], target=f"{API}/global/networks/other")
    regional = [pol("r-a", [prule(10)], region="r1"), pol("r-b", [prule(10, "deny")], region="r1")]
    data = json.loads(bundle([fw("a", sourceRanges=["0.0.0.0/0"])], [other] + regional, instances))
    data["firewall-rules"].append({"nextPageToken": "x"})
    del data["networks"]
    model, report = parse(json.dumps(data).encode(), network="net")
    found = codes(report)
    assert {"GCP_POLICY_NOT_ASSOCIATED", "GCP_REGIONAL_SEVERAL", "GCP_INCOMPLETE_EXPORT", "GCP_ORDER_ASSUMED", "GCP_NOT_IN_EXPORT",
            "GCP_UNFILTERED", "GCP_SOURCE"} <= found  # fmt: skip


def test_ties_targets_and_sources() -> None:
    """A deny before an allow of one priority; tags and service accounts as targets and sources; no source is 0.0.0.0/0."""
    instances = [vm("web", "10.0.0.5", ["web"]), vm("app", "10.0.0.6", ["app"], account="b@p.iam.gserviceaccount.com")]
    rules = [fw("allow-all-ssh", sourceRanges=["0.0.0.0/0"]), fw("deny-ssh", action="deny", sourceRanges=["198.51.100.0/24"]),
             fw("from-web", 900, sourceTags=["web"], targetServiceAccounts=["b@p.iam.gserviceaccount.com"], allowed=[{"IPProtocol": "tcp", "ports": ["8080"]}]),
             fw("no-source", 1100, allowed=[{"IPProtocol": "udp"}])]  # fmt: skip
    data = bundle(rules, instances=instances)
    model, _ = parse(data)
    judge = GcpJudge(json.loads(data))
    for src, dst, proto, port, wanted in (("198.51.100.7", "10.0.0.5", "tcp", 22, False), ("192.0.2.7", "10.0.0.5", "tcp", 22, True),
                                          ("10.0.0.5", "10.0.0.6", "tcp", 8080, True), ("10.0.0.6", "10.0.0.5", "tcp", 8080, False),
                                          ("192.0.2.7", "10.0.0.6", "udp", 53, True), ("2001:db8::7", "2001:db8::9", "udp", 53, None)):  # fmt: skip
        pkt = Packet("", "", src, dst, proto, 40000, port)
        assert judge.allows(pkt) == wanted, pkt
        if wanted is not None:
            assert model_allows(model, pkt) == wanted, pkt


def test_script_runs_dry_and_quotes_what_it_writes(tmp_path: Any) -> None:
    import subprocess

    from fwshift.model import Policy, Protocol, Rule, Service, ServiceEntry
    from fwshift.options import Options

    p = Policy(vendor="test")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443")])
    rule = Rule("it's `$(touch pwned)` \"x\"\nnext", sources=["10.0.0.0/8"], destinations=["192.0.2.0/24"], services=["web"])
    rule.origin = rule.name
    p.rules.append(rule)
    report = Report()
    text = cli.convert(p, "gcp", report, Options(target_policy="Shop Policy!", object_prefix="X_"))
    assert "POLICY=x-shop-policy" in text and "pwned" in text
    script = tmp_path / "s.sh"
    script.write_text(text, encoding="utf-8")
    done = subprocess.run(["sh", str(script)], env={"DRY_RUN": "1", "PATH": "/usr/bin:/bin"}, cwd=tmp_path, capture_output=True, text=True)
    assert done.returncode == 0 and not (tmp_path / "pwned").exists(), done.stderr
    assert "rules create 1000" in done.stderr and "--description=it's `$(touch pwned)` \"x\"_next" in done.stderr
    assert {"GCP_LOAD", "GCP_ORDER"} <= codes(report)
    judge = ScriptJudge(text)
    assert judge.allows(Packet("", "", "10.1.2.3", "192.0.2.9", "tcp", 40000, 443)) is True
    assert judge.allows(Packet("", "", "10.1.2.3", "192.0.2.9", "tcp", 40000, 80)) is False


def test_what_a_rule_of_google_cloud_cannot_say() -> None:
    from fwshift.model import Action, Policy, Protocol, Rule, Service, ServiceEntry
    from fwshift.options import Options

    p = Policy(vendor="test", default_interzone=Action.ALLOW)
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["from-high"] = Service("from-high", [ServiceEntry(Protocol.TCP, "22", "1024-65535")])
    for name, action, service in (("allow-ping", Action.ALLOW, "ping"), ("deny-ping", Action.DROP, "ping"), ("allow-ssh", Action.ALLOW, "from-high"),
                                  ("deny-ssh", Action.DENY, "from-high")):  # fmt: skip
        rule = Rule(name, sources=["10.0.0.0/8"], destinations=["any"], services=[service], action=action)
        rule.origin = name
        p.rules.append(rule)
    report = Report()
    text = cli.convert(p, "gcp", report, Options())
    assert {f.code for f in report.item("rule", "allow-ping").findings} >= {"GCP_PART_NOT_WRITTEN"}
    assert {f.code for f in report.item("rule", "deny-ping").findings} >= {"GCP_BLOCKS_MORE"}
    assert "--layer4-configs=icmp --enable-logging --description=deny-ping" in text and "--description=allow-ping" not in text
    assert "--layer4-configs=tcp:22 --enable-logging --description=deny-ssh" in text
    assert report.item("rule", "allow-ssh").skipped and "#   allow-ssh: what it allows cannot be said" in text
    assert text.count("--action=allow --src-ip-ranges=0.0.0.0/0 --dest-ip-ranges=0.0.0.0/0 --layer4-configs=all") == 2  # (the default allows)


# -- review round 35 ---------------------------------------------------------------------------------


def allows(model: Any, src: str, dst: str, port: int = 22, proto: str = "tcp") -> bool:
    return model_allows(model, Packet("", "", src, dst, proto, 40000, port))


def test_r35_effective_firewalls_read_hierarchical_and_system_policies_first() -> None:
    instances = [vm("web", "10.0.0.5", ["web"])]
    effective = {"firewalls": [fw("ssh", sourceRanges=["0.0.0.0/0"])],
                 "firewallPolicys": [{"name": "111", "shortName": "org-block", "type": "HIERARCHY",
                                      "rules": [prule(10, "deny", srcIpRanges=["198.51.100.0/24"], layer4Configs=[{"ipProtocol": "all"}])]},
                                     {"name": "pol", "type": "NETWORK", "rules": [prule(10, "deny", srcIpRanges=["192.0.2.0/24"], layer4Configs=[{"ipProtocol": "all"}])]},
                                     {"name": "odd", "type": "SOMETHING_NEW", "rules": [prule(20, "allow")]}]}  # fmt: skip
    data = json.dumps([effective, {"kind": "compute#instanceList", "items": instances}]).encode()
    model, report = parse(data)
    assert not allows(model, "198.51.100.7", "10.0.0.5")  # (the organization's deny comes before the VPC rule)
    assert allows(model, "192.0.2.7", "10.0.0.5")  # (the VPC rule before the network policy: AFTER_CLASSIC_FIREWALL)
    assert not allows(model, "192.0.2.7", "10.0.0.5", 80)  # (what the VPC rule does not decide, the network policy denies)
    assert "GCP_EFFECTIVE" in codes(report) and "GCP_NOT_IN_EXPORT" not in codes(report)
    assert [r.unsupported for r in model.rules if r.name.startswith("odd")][0]


def test_r35_hierarchical_policies_are_a_first_step() -> None:
    instances = [vm("web", "10.0.0.5", ["web"])]
    org = {"kind": "compute#firewallPolicy", "name": "222", "shortName": "org", "parent": "organizations/1",
           "associations": [{"name": "org", "attachmentTarget": "organizations/1"}],
           "rules": [prule(10, "deny", srcIpRanges=["198.51.100.0/24"], layer4Configs=[{"ipProtocol": "all"}]),
                     dict(prule(20, "deny", srcIpRanges=["192.0.2.0/24"], layer4Configs=[{"ipProtocol": "all"}]), targetResources=[f"{API}/global/networks/other"])] + predefined()}  # fmt: skip
    model, report = parse(bundle([fw("ssh", sourceRanges=["0.0.0.0/0"])], [org], instances))
    assert not allows(model, "198.51.100.7", "10.0.0.5") and allows(model, "192.0.2.7", "10.0.0.5")
    assert "GCP_HIERARCHICAL_READ" in codes(report) and "GCP_POLICY_NOT_ASSOCIATED" not in codes(report)
    assert model.scope == "net"


def test_r35_a_policy_without_its_rules_is_said() -> None:
    policy = pol("p", [])
    del policy["rules"]
    _, report = parse(bundle([fw("ssh", sourceRanges=["0.0.0.0/0"])], [policy], [vm("web", "10.0.0.5")]))
    assert "GCP_POLICY_WITHOUT_RULES" in codes(report)


def test_r35_entries_that_cannot_be_read_are_never_any() -> None:
    instances = [vm("web", "10.0.0.5", ["web"])]
    for rule in (fw("d", action="deny", sourceRanges=["0.0.0.0/0"], targetTags=[None]), fw("d", action="deny", sourceRanges=[None]),
                 fw("d", action="deny", sourceRanges=["0.0.0.0/0"], denied=[{"IPProtocol": "tcp", "ports": [None]}]),
                 fw("d", action="deny", sourceRanges=["0.0.0.0/0"], disabled="maybe"),
                 fw("d", action="deny", sourceRanges=["0.0.0.0/0"], fwshiftUnknown=["target_tags"])):  # fmt: skip
        model, _ = parse(bundle([rule, fw("ssh", 2000, sourceRanges=["0.0.0.0/0"])], instances=instances))
        assert [r.unsupported for r in model.rules if r.name == "d"][0], rule
    model, _ = parse(bundle(policies=[pol("p", [prule(10, "deny", srcIpRanges=[None, "10.0.0.0/8"])])], instances=instances))
    assert [r.unsupported for r in model.rules if r.name.startswith("p:10")][0]


def test_r35_no_source_is_every_address_of_the_rules_version() -> None:
    instances = [dict(vm("web", "10.0.0.5"), networkInterfaces=[{"network": NET, "networkIP": "10.0.0.5", "ipv6Address": "2001:db8:1::5"}])]
    rules = [fw("v6-in", destinationRanges=["2001:db8:1::/64"]),
             fw("v6-out", direction="EGRESS", action="deny", sourceRanges=["2001:db8:1::/64"], denied=[{"IPProtocol": "all"}])]  # fmt: skip
    data = bundle(rules, instances=instances)
    model, _ = parse(data)
    judge = GcpJudge(json.loads(data))
    for src, dst, wanted in (("2001:db8:ff::7", "2001:db8:1::5", True), ("198.51.100.7", "10.0.0.5", False),
                             ("2001:db8:1::5", "2001:db8:ff::7", False), ("10.0.0.5", "198.51.100.7", True)):  # fmt: skip
        pkt = Packet("", "", src, dst, "tcp", 40000, 22)
        assert judge.allows(pkt) == wanted and model_allows(model, pkt) == wanted, pkt


def test_r35_an_instance_whose_tags_are_not_known() -> None:
    instances = [vm("web", "10.0.0.5", ["web"]), dict(vm("new", "10.0.0.6"), fwshiftUnknown=["tags"])]
    model, _ = parse(bundle([fw("d", 900, action="deny", sourceRanges=["0.0.0.0/0"], targetTags=["web"]),
                             fw("every", sourceRanges=["0.0.0.0/0"])], instances=instances))  # fmt: skip
    assert [r.unsupported for r in model.rules if r.name == "d"][0]
    assert not [r.unsupported for r in model.rules if r.name == "every"][0]


def test_r35_a_rule_for_no_instance_is_left_out_and_said() -> None:
    model, report = parse(bundle([fw("nobody", sourceRanges=["0.0.0.0/0"], targetTags=["none"])], instances=[vm("web", "10.0.0.5", ["web"])]))
    assert report.item("rule", "nobody").skipped and "GCP_NO_INSTANCE" in codes(report)
    assert not [r for r in model.rules if r.name == "nobody"]


def test_r35_a_rule_too_long_for_google_cloud_is_not_written_in_part() -> None:
    from fwshift.emitters import gcp as emit_gcp
    from fwshift.model import Policy, Rule
    from fwshift.options import Options

    p = Policy(vendor="test")
    sources = ["10.0.0.0/8"] + [f"2001:db8:{i:x}::1" for i in range(0, 10002, 2)]
    rule = Rule("long", sources=sources, destinations=["any"], services=["any"])
    rule.origin = "long"
    p.rules.append(rule)
    report = Report()
    planned = emit_gcp.plan(p, report, Options())
    assert not [r for r in planned.rules if r.origin == "long"] and report.item("rule", "long").disabled
    assert "LIST_TOO_LONG" in {f.code for f in report.item("rule", "long").findings}


def test_r35_mutation_survivors() -> None:
    """Ports on ICMP, source tags while an instance's tags are not known, a policy rule without a source: never read
    as more than the rule says."""
    instances = [vm("web", "10.0.0.5", ["web"]), dict(vm("new", "10.0.0.6"), fwshiftUnknown=["tags"])]
    for rule in (fw("d", sourceRanges=["0.0.0.0/0"], allowed=[{"IPProtocol": "icmp", "ports": ["8"]}]),
                 fw("d", action="deny", sourceTags=["web"])):  # fmt: skip
        model, _ = parse(bundle([rule, fw("ssh", 2000, sourceRanges=["0.0.0.0/0"])], instances=instances))
        assert [r.unsupported for r in model.rules if r.name == "d"][0], rule
    model, _ = parse(bundle(policies=[pol("p", [prule(10, "deny", srcIpRanges=[])])], instances=instances[:1]))
    assert [r.unsupported for r in model.rules if r.name.startswith("p:10")][0]


def test_r35_goto_next_and_regional_policies_without_a_region() -> None:
    instances = [vm("web", "10.0.0.5", ["web"])]
    every_tcp = [{"ipProtocol": "tcp"}]
    rules = [prule(10, "goto_next", srcIpRanges=["10.0.0.0/8"], layer4Configs=every_tcp), prule(20, "allow", layer4Configs=every_tcp)]
    model, _ = parse(bundle(policies=[pol("p", rules)], instances=instances))
    assert not allows(model, "10.1.1.1", "10.0.0.5") and allows(model, "198.51.100.7", "10.0.0.5")
    # A goto_next whose match cannot be worked out: the rules after it in its policy are not converted.
    rules = [prule(10, "goto_next", srcFqdns=["x.example.com"], layer4Configs=every_tcp), prule(20, "allow", layer4Configs=every_tcp)]
    model, _ = parse(bundle(policies=[pol("p", rules)], instances=instances))
    assert [r.unsupported for r in model.rules if r.name.startswith("p:20")][0]
    # A regional policy in the answer of get-effective-firewalls says no region.
    effective = {"firewalls": [fw("ssh", sourceRanges=["0.0.0.0/0"])],
                 "firewallPolicys": [{"name": "reg", "type": "NETWORK_REGIONAL", "rules": [prule(10, "deny", layer4Configs=every_tcp)]}]}
    model, _ = parse(json.dumps([effective, {"kind": "compute#instanceList", "items": instances}]).encode())
    assert [r.unsupported for r in model.rules if r.name.startswith("reg:10")][0]
