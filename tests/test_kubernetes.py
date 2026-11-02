# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Kubernetes NetworkPolicy and Calico: the parser, the two emitters, the samples.

The judges here are written from the Kubernetes and Calico documentation, not from the parser: ``K8sJudge`` decides a
connection the way a cluster enforces NetworkPolicies (isolation per direction, a union of allows, both ends, the
node exception, named ports), ``CalicoJudge`` the way Felix walks tiers, policies and rules (Allow, Deny, Pass, Log,
the end of a tier, the profile). The random clusters carry for every selector the predicate it stands for, so that
the Calico judge needs no parser of selectors. ``K8sJudge`` also reads what the NetworkPolicy emitter writes (with a
pod for each address, labelled with the group whose addresses hold it), and ``GnpJudge`` what the Calico emitter
writes.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.emitters import calico as emit_calico
from fwshift.emitters import kubernetes as emit_kubernetes
from fwshift.errors import ParseError
from fwshift.model import Action, Address, AddressKind, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import kubernetes as parse_kubernetes
from fwshift.report import Report, Severity

NUMBERS = {"tcp": 6, "udp": 17, "sctp": 132, "icmp": 1, "icmp6": 58}


def ip(text: str) -> Any:
    return ipaddress.ip_address(text)


def inside(address: str, cidr: str) -> bool:
    probe, network = ip(address), ipaddress.ip_network(cidr, strict=False)
    return probe.version == network.version and probe in network


def proto_number(pkt: Packet) -> int:
    return NUMBERS.get(pkt.proto) or int(pkt.proto)


# -- the judge of Kubernetes ------------------------------------------------------------------------


def selector_matches(selector: Optional[Dict[str, Any]], labels: Dict[str, str]) -> bool:
    """A label selector as the Kubernetes API documents it; an absent selector is handled by the caller."""
    selector = selector or {}
    if any(labels.get(k) != v for k, v in (selector.get("matchLabels") or {}).items()):
        return False
    for item in selector.get("matchExpressions") or []:
        key, op, values = item["key"], item["operator"], item.get("values") or []
        if op == "In" and not (key in labels and labels[key] in values):
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


class K8sJudge:
    def __init__(self, objects: List[Dict[str, Any]]) -> None:
        self.namespaces: Dict[str, Dict[str, str]] = {}
        self.pods: List[Dict[str, Any]] = []
        self.policies: List[Dict[str, Any]] = []
        for obj in objects:
            meta = obj.get("metadata", {})
            if obj["kind"] == "Namespace":
                labels = dict(meta.get("labels") or {})
                labels["kubernetes.io/metadata.name"] = meta["name"]
                self.namespaces[meta["name"]] = labels
            elif obj["kind"] == "Pod":
                spec, status = obj.get("spec", {}), obj.get("status", {})
                if spec.get("hostNetwork") or status.get("phase") in ("Succeeded", "Failed") or not status.get("podIPs"):
                    continue
                self.pods.append({"ns": meta.get("namespace", "default"), "labels": meta.get("labels") or {},
                                  "ips": [ip(i["ip"]) for i in status["podIPs"]],
                                  "nodes": [ip(i["ip"]) for i in status.get("hostIPs") or []],
                                  "ports": [p for c in spec.get("containers") or [] for p in c.get("ports") or []]})  # fmt: skip
            elif obj["kind"] == "NetworkPolicy" and obj.get("apiVersion") == "networking.k8s.io/v1":
                self.policies.append(obj)

    def pod_at(self, address: str) -> Optional[Dict[str, Any]]:
        probe = ip(address)
        return next((pod for pod in self.pods if probe in pod["ips"]), None)

    @staticmethod
    def types(spec: Dict[str, Any]) -> List[str]:
        if spec.get("policyTypes"):
            return spec["policyTypes"]
        return ["Ingress"] + (["Egress"] if spec.get("egress") else [])

    def selects(self, policy: Dict[str, Any], pod: Dict[str, Any]) -> bool:
        return pod["ns"] == policy["metadata"].get("namespace", "default") and selector_matches(policy["spec"].get("podSelector"), pod["labels"])

    def peer(self, policy: Dict[str, Any], peer: Dict[str, Any], address: str) -> bool:
        if "ipBlock" in peer:
            block = peer["ipBlock"]
            return inside(address, block["cidr"]) and not any(inside(address, e) for e in block.get("except") or [])
        pod = self.pod_at(address)
        if pod is None:
            return False
        if "namespaceSelector" in peer:
            labels = self.namespaces.get(pod["ns"], {"kubernetes.io/metadata.name": pod["ns"]})
            if not selector_matches(peer["namespaceSelector"], labels):
                return False
        elif pod["ns"] != policy["metadata"].get("namespace", "default"):
            return False
        return "podSelector" not in peer or selector_matches(peer["podSelector"], pod["labels"])

    @staticmethod
    def port(item: Dict[str, Any], pkt: Packet, target: Optional[Dict[str, Any]]) -> bool:
        protocol = item.get("protocol", "TCP")
        if pkt.proto != protocol.lower():
            return False
        if "port" not in item:
            return True
        value = item["port"]
        if isinstance(value, str):
            if target is None:
                return False
            return any(p.get("name") == value and p.get("protocol", "TCP") == protocol and p["containerPort"] == pkt.dport
                       for p in target["ports"])  # fmt: skip
        return value <= pkt.dport <= item.get("endPort", value)

    def side(self, pod: Dict[str, Any], direction: str, peer: str, pkt: Packet, target: Optional[Dict[str, Any]]) -> bool:
        mine = [p for p in self.policies if direction in self.types(p["spec"]) and self.selects(p, pod)]
        if not mine:
            return True
        key, peers_key = direction.lower(), "from" if direction == "Ingress" else "to"
        for policy in mine:
            for rule in policy["spec"].get(key) or []:
                peers, ports = rule.get(peers_key) or [], rule.get("ports") or []
                if peers and not any(self.peer(policy, p, peer) for p in peers):
                    continue
                if ports and not any(self.port(p, pkt, target) for p in ports):
                    continue
                return True
        return False

    def allows(self, pkt: Packet) -> Optional[bool]:
        src, dst = self.pod_at(pkt.src), self.pod_at(pkt.dst)
        if src is None and dst is None:
            return None
        if (src is not None and ip(pkt.dst) in src["nodes"]) or (dst is not None and ip(pkt.src) in dst["nodes"]):
            return True
        out = src is None or self.side(src, "Egress", pkt.dst, pkt, dst)
        return out and (dst is None or self.side(dst, "Ingress", pkt.src, pkt, dst))


# -- random clusters ------------------------------------------------------------------------------

POD_V4 = [f"10.244.{a}.{b}" for a in range(3) for b in (5, 6, 9, 130)]
POD_V6 = [f"2001:db8:244::{n:x}" for n in range(1, 9)]
OUTSIDE = ["192.0.2.10", "198.51.100.7", "203.0.113.200", "10.1.0.5", "2001:db8:ffff::5", "2001:db8:aaaa::9"]
NODES = ["10.0.0.1", "10.0.0.2"]
CIDRS = ["10.244.0.0/16", "10.244.1.0/24", "10.244.0.0/25", "0.0.0.0/0", "192.0.2.0/24", "198.51.100.0/25", "::/0",
         "2001:db8:244::/120", "2001:db8:ffff::/48", "10.0.0.0/8"]
EXCEPTS = {"10.244.0.0/16": ["10.244.2.0/24"], "0.0.0.0/0": ["10.0.0.0/8", "192.0.2.0/25"], "::/0": ["2001:db8:244::/64"],
           "10.0.0.0/8": ["10.244.1.0/26"], "10.244.1.0/24": ["10.244.1.128/25"]}
APPS = ["web", "db", "api"]


def random_cluster(rng: random.Random) -> List[Dict[str, Any]]:
    objects: List[Dict[str, Any]] = []
    for name in ("a", "b", "c"):
        labels = {k: rng.choice(v) for k, v in (("env", ["prod", "dev"]), ("team", ["x", "y"])) if rng.random() < 0.7}
        objects.append({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}})
    v4, v6 = rng.sample(POD_V4, 9), rng.sample(POD_V6, 4)
    for index, address in enumerate(v4):
        labels = {"app": rng.choice(APPS)} if rng.random() < 0.85 else {}
        if rng.random() < 0.4:
            labels["tier"] = rng.choice(["fe", "be"])
        ips = [address] + ([v6.pop()] if v6 and rng.random() < 0.5 else [])
        ports = [{"name": "http", "containerPort": rng.choice([80, 8080, 8081]), "protocol": "TCP"}] if rng.random() < 0.7 else []
        if rng.random() < 0.3:
            ports.append({"name": "dns", "containerPort": 53, "protocol": "UDP"})
        objects.append({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": f"p{index}", "namespace": rng.choice("abc"), "labels": labels},
                        "spec": {"containers": [{"name": "c", "ports": ports}]},
                        "status": {"phase": "Running", "podIPs": [{"ip": i} for i in ips], "hostIPs": [{"ip": rng.choice(NODES)}]}})  # fmt: skip
    for index in range(rng.randint(2, 7)):
        objects.append(random_netpol(rng, f"np{index}"))
    return objects


def random_selector(rng: random.Random, keys: Tuple[str, ...] = ("app", "tier")) -> Dict[str, Any]:
    roll = rng.random()
    if roll < 0.25:
        return {}
    if roll < 0.7:
        key = rng.choice(keys)
        return {"matchLabels": {key: rng.choice(APPS if key == "app" else ["fe", "be", "prod", "dev", "x", "y"])}}
    key = rng.choice(keys)
    op = rng.choice(["In", "NotIn", "Exists", "DoesNotExist"])
    item: Dict[str, Any] = {"key": key, "operator": op}
    if op in ("In", "NotIn"):
        item["values"] = rng.sample(APPS if key == "app" else ["fe", "be", "prod", "dev", "x", "y"], 2)
    return {"matchExpressions": [item]}


def random_peer(rng: random.Random) -> Dict[str, Any]:
    roll = rng.random()
    if roll < 0.3:
        cidr = rng.choice(CIDRS)
        block: Dict[str, Any] = {"cidr": cidr}
        if cidr in EXCEPTS and rng.random() < 0.6:
            block["except"] = EXCEPTS[cidr]
        return {"ipBlock": block}
    if roll < 0.55:
        return {"podSelector": random_selector(rng)}
    if roll < 0.8:
        return {"namespaceSelector": random_selector(rng, ("env", "team", "kubernetes.io/metadata.name"))}
    return {"namespaceSelector": random_selector(rng, ("env", "team")), "podSelector": random_selector(rng)}


def random_port(rng: random.Random) -> Dict[str, Any]:
    port: Dict[str, Any] = {}
    if rng.random() < 0.7:
        port["protocol"] = rng.choice(["TCP", "TCP", "UDP"])
    roll = rng.random()
    if roll < 0.4:
        port["port"] = rng.choice([53, 80, 443, 8080])
    elif roll < 0.6:
        port["port"] = rng.choice(["http", "dns"])
    elif roll < 0.8:
        port["port"], port["endPort"] = 8000, 8090
    return port


def random_netpol(rng: random.Random, name: str) -> Dict[str, Any]:
    spec: Dict[str, Any] = {"podSelector": random_selector(rng)}
    roll = rng.random()
    if roll < 0.7:
        spec["policyTypes"] = rng.choice([["Ingress"], ["Egress"], ["Ingress", "Egress"]])
    for key, peers in (("ingress", "from"), ("egress", "to")):
        if rng.random() < 0.7:
            rules = []
            for _ in range(rng.randint(0, 3)):
                rule: Dict[str, Any] = {}
                if rng.random() < 0.8:
                    rule[peers] = [random_peer(rng) for _ in range(rng.randint(1, 2))]
                if rng.random() < 0.7:
                    rule["ports"] = [random_port(rng) for _ in range(rng.randint(1, 2))]
                rules.append(rule)
            spec[key] = rules
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": rng.choice("abc")},
            "spec": spec}


def pool_of(objects: List[Dict[str, Any]]) -> List[str]:
    pods = [i["ip"] for o in objects if o["kind"] == "Pod" for i in o.get("status", {}).get("podIPs") or []]
    return pods + OUTSIDE + NODES


def cluster_packet(rng: random.Random, pool: List[str]) -> Optional[Packet]:
    src, dst = rng.choice(pool), rng.choice(pool)
    if ip(src).version != ip(dst).version or src == dst:
        return None
    proto = rng.choice(["tcp", "tcp", "udp", "icmp" if ":" not in src else "icmp6", "sctp", "47"])
    return Packet("eth0", "eth0", src, dst, proto, rng.choice([1024, 40000]), rng.choice([53, 80, 443, 8080, 8081, 8050, 9000]),
                  rng.choice([0, 8, 128]))  # fmt: skip


def parse(objects: Any, dialect: str = "kubernetes", report: Optional[Report] = None) -> Policy:
    document = {"apiVersion": "v1", "kind": "List", "items": objects} if isinstance(objects, list) else objects
    return parse_kubernetes.parse(json.dumps(document).encode(), report or Report(), dialect)


def test_parsed_kubernetes_decides_like_the_judge() -> None:
    compared = allowed = 0
    for seed in range(150):
        rng = random.Random(seed)
        objects = random_cluster(rng)
        model = parse(objects)
        judge = K8sJudge(objects)
        pool = pool_of(objects)
        for _ in range(250):
            pkt = cluster_packet(rng, pool)
            if pkt is None:
                continue
            verdict = judge.allows(pkt)
            wanted = False if verdict is None else verdict
            compared += 1
            allowed += wanted
            assert model_allows(model, pkt) == wanted, (seed, pkt, json.dumps(objects, indent=1))
    assert compared > 20000 and compared / 4 < allowed < compared * 3 / 4


# -- the judge of Calico --------------------------------------------------------------------------

Pred = Callable[[Dict[str, str]], bool]
SELECTORS: List[Tuple[str, Pred]] = [
    ("all()", lambda L: True),
    ("app == 'web'", lambda L: L.get("app") == "web"),
    ("app != 'web'", lambda L: L.get("app") != "web"),
    ("has(tier)", lambda L: "tier" in L),
    ("!has(tier)", lambda L: "tier" not in L),
    ("app in {'web', 'db'}", lambda L: L.get("app") in ("web", "db")),
    ("app not in {'db'}", lambda L: L.get("app") != "db"),
    ("app == 'api' || tier == 'fe'", lambda L: L.get("app") == "api" or L.get("tier") == "fe"),
    ("app == 'web' && !(tier == 'be')", lambda L: L.get("app") == "web" and L.get("tier") != "be"),
    ("feed == 'bad'", lambda L: L.get("feed") == "bad"),
    ("app starts with 'w'", lambda L: L.get("app", "\0").startswith("w")),
    ("projectcalico.org/namespace == 'a'", lambda L: L.get("projectcalico.org/namespace") == "a"),
]
# The selectors of the Calico sample.
SAMPLE_SELECTORS: List[Tuple[str, Pred]] = [
    ("projectcalico.org/namespace != 'kube-system'", lambda L: L.get("projectcalico.org/namespace") != "kube-system"),
    ("k8s-app == 'kube-dns'", lambda L: L.get("k8s-app") == "kube-dns"),
    ("role == 'node'", lambda L: L.get("role") == "node"),
    ("role == 'partner'", lambda L: L.get("role") == "partner"),
    ("feed == 'threats'", lambda L: L.get("feed") == "threats"),
    ("feed == 'partners'", lambda L: L.get("feed") == "partners"),
    ("app == 'payments-api'", lambda L: L.get("app") == "payments-api"),
    ("app == 'debug'", lambda L: L.get("app") == "debug"),
    ("app == 'cart'", lambda L: L.get("app") == "cart"),
    ("app == 'db'", lambda L: L.get("app") == "db"),
    ("projectcalico.org/namespace in {'shop', 'payments'}", lambda L: L.get("projectcalico.org/namespace") in ("shop", "payments")),
]
NS_SELECTORS: List[Tuple[str, Callable[[Dict[str, str], bool], bool]]] = [
    ("team == 'ops'", lambda L, g: L.get("team") == "ops"),
    ("all()", lambda L, g: not g),
    ("env == 'prod'", lambda L, g: L.get("env") == "prod"),
    ("global()", lambda L, g: g),
    ("projectcalico.org/name == 'b'", lambda L, g: L.get("projectcalico.org/name") == "b"),
    ("global() || team == 'x'", lambda L, g: g or L.get("team") == "x"),
]


def random_calico(rng: random.Random) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """A cluster with Calico policies, and the predicates of every selector, by the text the cluster holds."""
    objects = random_cluster(rng)
    if rng.random() < 0.5:
        objects = [o for o in objects if o["kind"] != "NetworkPolicy"]
    v3 = "projectcalico.org/v3"
    tiers = []
    for name, order in (("first", 10), ("second", 20)):
        if rng.random() < 0.7:
            spec: Dict[str, Any] = {"order": order}
            if rng.random() < 0.4:
                spec["defaultAction"] = "Pass"
            tiers.append(name)
            objects.append({"apiVersion": v3, "kind": "Tier", "metadata": {"name": name}, "spec": spec})
    objects.append({"apiVersion": v3, "kind": "GlobalNetworkSet", "metadata": {"name": "bad", "labels": {"feed": "bad"}},
                    "spec": {"nets": ["198.51.100.0/25", "2001:db8:ffff::/48"]}})  # fmt: skip
    objects.append({"apiVersion": v3, "kind": "NetworkSet", "metadata": {"name": "near", "namespace": "a", "labels": {"app": "web"}},
                    "spec": {"nets": ["192.0.2.0/24"]}})  # fmt: skip

    def entity(source: bool) -> Optional[Dict[str, Any]]:
        if rng.random() < 0.35:
            return None
        out: Dict[str, Any] = {}
        if rng.random() < 0.3:
            out["nets"] = rng.sample(CIDRS, rng.randint(1, 2))
        if rng.random() < 0.15:
            out["notNets"] = [rng.choice(["10.244.1.0/24", "192.0.2.0/25", "2001:db8:244::/124"])]
        if rng.random() < 0.4:
            out["selector"] = rng.choice(SELECTORS)[0]
        if rng.random() < 0.15:
            out["notSelector"] = rng.choice(SELECTORS[1:])[0]
        if rng.random() < 0.2:
            out["namespaceSelector"] = rng.choice(NS_SELECTORS)[0]
        return out

    def rule() -> Dict[str, Any]:
        out: Dict[str, Any] = {"action": rng.choice(["Allow", "Allow", "Deny", "Pass", "Log"])}
        roll = rng.random()
        if roll < 0.35:
            out["protocol"] = rng.choice(["TCP", "UDP"])
        elif roll < 0.45:
            out["protocol"], out["icmp"] = "ICMP", {"type": 8}
        elif roll < 0.5:
            out["protocol"] = 47
        elif roll < 0.6:
            out["notProtocol"] = rng.choice(["TCP", "UDP", "ICMP"])
        for key, source in (("source", True), ("destination", False)):
            found = entity(source)
            if found is not None:
                out[key] = found
        if out.get("protocol") in ("TCP", "UDP") and rng.random() < 0.6:
            dest = out.setdefault("destination", {})
            choice = rng.random()
            if choice < 0.4:
                dest["ports"] = rng.sample([53, 80, 443, "8000:8090"], rng.randint(1, 2))
            elif choice < 0.6:
                dest["ports"] = ["http"]
            elif choice < 0.8:
                dest["notPorts"] = [rng.choice([80, 443, "8040:8060"])]
            else:
                out.setdefault("source", {})["ports"] = ["1000:2000"]
        if rng.random() < 0.1:
            out["ipVersion"] = rng.choice([4, 6])
        return out

    for index in range(rng.randint(2, 6)):
        global_ = rng.random() < 0.5
        spec = {"selector": rng.choice(SELECTORS)[0]}
        if tiers and rng.random() < 0.6:
            spec["tier"] = rng.choice(tiers)
        if rng.random() < 0.8:
            spec["order"] = rng.choice([1, 5, 5, 10, 1000, 2000])
        for key in ("ingress", "egress"):
            if rng.random() < 0.7:
                spec[key] = [rule() for _ in range(rng.randint(0, 3))]
        if rng.random() < 0.5:
            spec["types"] = [t for t in ("Ingress", "Egress") if t.lower() in spec] or ["Ingress"]
        meta: Dict[str, Any] = {"name": f"cp{index}"}
        if not global_:
            meta["namespace"] = rng.choice("abc")
        objects.append({"apiVersion": v3, "kind": "GlobalNetworkPolicy" if global_ else "NetworkPolicy", "metadata": meta, "spec": spec})
    return objects, {}


class CalicoJudge:
    def __init__(self, objects: List[Dict[str, Any]]) -> None:
        self.k8s = K8sJudge(objects)
        self.tiers: Dict[str, Tuple[float, str]] = {"default": (1_000_000, "Deny")}
        self.sets: List[Tuple[str, Dict[str, str], List[str]]] = []
        self.policies: List[Dict[str, Any]] = []
        selectors = dict(SELECTORS + SAMPLE_SELECTORS)
        self.selector = lambda text, labels: selectors[text](labels)  # noqa: E731
        spaces = dict(NS_SELECTORS)
        self.space = lambda text, labels, glob: spaces[text](labels, glob)  # noqa: E731
        for obj in objects:
            meta, spec = obj.get("metadata", {}), obj.get("spec", {})
            if obj["kind"] == "Tier":
                self.tiers[meta["name"]] = (spec.get("order", 1_000_000), spec.get("defaultAction", "Deny"))
            elif obj["kind"] in ("GlobalNetworkSet", "NetworkSet"):
                self.sets.append((meta.get("namespace", ""), meta.get("labels", {}), spec["nets"]))
            elif obj["kind"] == "HostEndpoint":
                self.sets.append(("", meta.get("labels", {}), [a + ("/32" if "." in a else "/128") for a in spec.get("expectedIPs", [])]))
            elif spec.get("doNotTrack") or spec.get("preDNAT"):
                continue  # (for host endpoints only)
            elif obj["kind"] == "GlobalNetworkPolicy" or (obj["kind"] == "NetworkPolicy" and obj["apiVersion"].startswith("projectcalico")):
                self.policies.append(obj)
            elif obj["kind"] == "NetworkPolicy":
                # How Calico holds a Kubernetes policy: in the default tier, order 1000, its rules allow.
                self.policies.append({"k8s": obj, "metadata": meta, "spec": {"order": 1000}})

    def labels(self, pod: Dict[str, Any]) -> Dict[str, str]:
        out = dict(pod["labels"])
        out["projectcalico.org/namespace"] = pod["ns"]
        return out

    def ns_labels(self, name: str) -> Dict[str, str]:
        out = dict(self.k8s.namespaces.get(name, {}))
        out["projectcalico.org/name"] = name
        return out

    def types(self, policy: Dict[str, Any]) -> List[str]:
        if "k8s" in policy:
            return self.k8s.types(policy["k8s"]["spec"])
        spec = policy["spec"]
        if spec.get("types"):
            return spec["types"]
        out = (["Ingress"] if "ingress" in spec or "egress" not in spec else []) + (["Egress"] if "egress" in spec else [])
        return out

    def applies(self, policy: Dict[str, Any], pod: Dict[str, Any]) -> bool:
        if "k8s" in policy:
            return self.k8s.selects(policy["k8s"], pod)
        ns = policy["metadata"].get("namespace")
        if ns and pod["ns"] != ns:
            return False
        return self.selector(policy["spec"].get("selector", "all()"), self.labels(pod))

    def in_scope(self, policy: Dict[str, Any], entity: Dict[str, Any], selector: str, address: str) -> bool:
        """Whether the address is that of a pod or network set the selector picks, in the scope of the rule."""
        ns = policy["metadata"].get("namespace")
        space = entity.get("namespaceSelector")
        pod = self.k8s.pod_at(address)
        if pod is not None and self.selector(selector, self.labels(pod)):
            if space is not None:
                if self.space(space, self.ns_labels(pod["ns"]), False):
                    return True
            elif not ns or pod["ns"] == ns:
                return True
        for set_ns, labels, nets in self.sets:
            if not any(inside(address, n) for n in nets) or not self.selector(selector, labels):
                continue
            if space is not None:
                if self.space(space, self.ns_labels(set_ns) if set_ns else {}, not set_ns):
                    return True
            elif (not ns) or set_ns == ns:
                return True
        return False

    def entity(self, policy: Dict[str, Any], entity: Optional[Dict[str, Any]], address: str, port: Optional[int],
               target: Optional[Dict[str, Any]], pkt: Packet) -> bool:  # fmt: skip
        if not entity:
            return True
        if entity.get("nets") and not any(inside(address, n) for n in entity["nets"]):
            return False
        if any(inside(address, n) for n in entity.get("notNets") or []):
            return False
        if ("selector" in entity or "namespaceSelector" in entity) and not self.in_scope(policy, entity, entity.get("selector", "all()"), address):
            return False
        if "notSelector" in entity and self.in_scope(policy, entity, entity["notSelector"], address):
            return False

        def port_in(items: List[Any]) -> bool:
            for item in items:
                if isinstance(item, int) and item == port:
                    return True
                if isinstance(item, str) and ":" in item:
                    low, high = map(int, item.split(":"))
                    if port is not None and low <= port <= high:
                        return True
                elif isinstance(item, str) and target is not None:
                    if any(p.get("name") == item and p.get("protocol", "TCP").lower() == pkt.proto and p["containerPort"] == port
                           for p in target["ports"]):  # fmt: skip
                        return True
            return False

        if entity.get("ports") and not port_in(entity["ports"]):
            return False
        if entity.get("notPorts") and port_in(entity["notPorts"]):
            return False
        return True

    def matches(self, policy: Dict[str, Any], rule: Dict[str, Any], pkt: Packet) -> bool:
        number = proto_number(pkt)
        names = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPv6": 58}
        if "protocol" in rule and names.get(rule["protocol"], rule["protocol"]) != number:
            return False
        if "notProtocol" in rule and names.get(rule["notProtocol"], rule["notProtocol"]) == number:
            return False
        if "icmp" in rule and pkt.icmp_type != rule["icmp"]["type"]:
            return False
        if "ipVersion" in rule and ip(pkt.src).version != rule["ipVersion"]:
            return False
        target = self.k8s.pod_at(pkt.dst)
        return self.entity(policy, rule.get("source"), pkt.src, pkt.sport, self.k8s.pod_at(pkt.src), pkt) and \
            self.entity(policy, rule.get("destination"), pkt.dst, pkt.dport, target, pkt)  # fmt: skip

    def endpoint(self, pod: Dict[str, Any], direction: str, pkt: Packet) -> bool:
        mine = [p for p in self.policies if direction in self.types(p) and self.applies(p, pod)]

        def tier_of(policy: Dict[str, Any]) -> str:
            return "default" if "k8s" in policy else policy["spec"].get("tier", "default")

        tiers = sorted({tier_of(p) for p in mine}, key=lambda t: (self.tiers[t][0], t))
        for tier in tiers:
            ordered = sorted((p for p in mine if tier_of(p) == tier),
                             key=lambda p: (p["spec"].get("order") is None, p["spec"].get("order") or 0, p["metadata"].get("namespace", ""),
                                            ("knp.default." if "k8s" in p else "") + p["metadata"]["name"]))  # fmt: skip
            passed = False
            for policy in ordered:
                if "k8s" in policy:
                    dst = self.k8s.pod_at(pkt.dst)
                    peer = pkt.src if direction == "Ingress" else pkt.dst
                    if self.k8s.side_of(policy["k8s"], direction, peer, pkt, dst):
                        return True
                    continue
                for rule in policy["spec"].get(direction.lower()) or []:
                    if "http" in rule:
                        continue  # (an HTTP match: what the conversion leaves out, as it says)
                    if not self.matches(policy, rule, pkt):
                        continue
                    if rule["action"] == "Log":
                        continue
                    if rule["action"] == "Pass":
                        passed = True
                        break
                    return rule["action"] == "Allow"
                if passed:
                    break
            if not passed and self.tiers[tier][1] == "Deny":
                return False
        return True

    def allows(self, pkt: Packet) -> Optional[bool]:
        src, dst = self.k8s.pod_at(pkt.src), self.k8s.pod_at(pkt.dst)
        if src is None and dst is None:
            return None
        return (src is None or self.endpoint(src, "Egress", pkt)) and (dst is None or self.endpoint(dst, "Ingress", pkt))


def _side_of(self: K8sJudge, policy: Dict[str, Any], direction: str, peer: str, pkt: Packet, target: Optional[Dict[str, Any]]) -> bool:
    """Whether one Kubernetes policy's rules of a direction allow the connection."""
    key, peers_key = direction.lower(), "from" if direction == "Ingress" else "to"
    for rule in policy["spec"].get(key) or []:
        peers, ports = rule.get(peers_key) or [], rule.get("ports") or []
        if peers and not any(self.peer(policy, p, peer) for p in peers):
            continue
        if ports and not any(self.port(p, pkt, target) for p in ports):
            continue
        return True
    return False


K8sJudge.side_of = _side_of  # type: ignore[attr-defined]


def test_parsed_calico_decides_like_the_judge() -> None:
    compared = flagged = 0
    for seed in range(200):
        rng = random.Random(seed)
        objects, _ = random_calico(rng)
        report = Report()
        model = parse(objects, "calico", report)
        if any(rule.unsupported for rule in model.rules):
            flagged += 1
            continue
        judge = CalicoJudge(objects)
        pool = pool_of(objects) + ["198.51.100.20", "192.0.2.200"]
        for _ in range(200):
            pkt = cluster_packet(rng, pool)
            if pkt is None:
                continue
            if pkt.proto in ("icmp", "icmp6"):
                pkt.icmp_type = rng.choice([0, 8])
            verdict = judge.allows(pkt)
            compared += 1
            assert model_allows(model, pkt) == (False if verdict is None else verdict), (seed, pkt, json.dumps(objects, indent=1))
    assert flagged < 20 and compared > 20000


# -- the emitters -----------------------------------------------------------------------------------


class GnpJudge:
    """What the Calico emitter writes, read strictly: one GlobalNetworkPolicy, nets of one IP version per rule, the fields
    of the API reference only. Every address is an endpoint the policy applies to."""

    RULE = {"action", "ipVersion", "protocol", "notProtocol", "icmp", "source", "destination", "metadata"}
    ENTITY = {"nets", "notNets", "ports"}

    def __init__(self, text: str) -> None:
        body = json.loads(text)
        assert body["apiVersion"] == "projectcalico.org/v3" and body["kind"] == "GlobalNetworkPolicy"
        spec = body["spec"]
        assert set(spec) == {"tier", "order", "selector", "types", "ingress", "egress"} and spec["types"] == ["Ingress", "Egress"]
        assert spec["ingress"] == spec["egress"]
        for rule in spec["ingress"]:
            assert set(rule) <= self.RULE and rule["action"] in ("Allow", "Deny"), rule
            for key in ("source", "destination"):
                entity = rule.get(key, {})
                assert set(entity) <= self.ENTITY, rule
                nets = entity.get("nets", []) + entity.get("notNets", [])
                assert len({ipaddress.ip_network(n).version for n in nets}) <= 1, rule
                if nets:
                    assert rule.get("ipVersion") == ipaddress.ip_network(nets[0]).version, rule
                if "ports" in entity:
                    assert rule.get("protocol") in ("TCP", "UDP", "SCTP"), rule
        self.rules = spec["ingress"]

    def verdict(self, pkt: Packet) -> bool:
        number = proto_number(pkt)
        names = {"TCP": 6, "UDP": 17, "SCTP": 132, "ICMP": 1, "ICMPv6": 58}
        for rule in self.rules:
            if "ipVersion" in rule and ip(pkt.src).version != rule["ipVersion"]:
                continue
            if "protocol" in rule and names.get(rule["protocol"], rule["protocol"]) != number:
                continue
            if "notProtocol" in rule and names.get(rule["notProtocol"], rule["notProtocol"]) == number:
                continue
            if "icmp" in rule and (pkt.icmp_type != rule["icmp"]["type"] or "code" in rule["icmp"] and rule["icmp"]["code"] != 0):
                continue
            ok = True
            for key, address, port in (("source", pkt.src, pkt.sport), ("destination", pkt.dst, pkt.dport)):
                entity = rule.get(key, {})
                if entity.get("nets") and not any(inside(address, n) for n in entity["nets"]):
                    ok = False
                if any(inside(address, n) for n in entity.get("notNets", [])):
                    ok = False
                if entity.get("ports") and not any(p == port if isinstance(p, int) else int(p.split(":")[0]) <= port <= int(p.split(":")[1])
                                                   for p in entity["ports"]):  # fmt: skip
                    ok = False
            if ok:
                return rule["action"] == "Allow"
        raise AssertionError("the policy ends with a rule that matches everything")


def disabled_left_out(model: Policy, report: Report) -> Policy:
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    return compared


@pytest.mark.parametrize("seed", range(40))
def test_emitted_calico_decides_like_the_model(seed: int) -> None:
    """First match in Calico as in the model: every packet gets the model's verdict, rules written disabled aside."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_calico.emit(model, report, Options(zone_networks=ZONES_AT))
    judge = GnpJudge(text)
    compared = disabled_left_out(model, report)
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        assert judge.verdict(pkt) == model_allows(compared, pkt), (seed, pkt, text)


def network_policies(text: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[Tuple[Any, Any]]]]:
    """The policies of the NetworkPolicy emitter, read strictly, and the addresses each group's pods have."""
    document = json.loads(text)
    assert document["apiVersion"] == "v1" and document["kind"] == "List"
    groups: Dict[str, List[Tuple[Any, Any]]] = {}
    names = set()
    for item in document["items"]:
        assert item["apiVersion"] == "networking.k8s.io/v1" and item["kind"] == "NetworkPolicy"
        meta, spec = item["metadata"], item["spec"]
        assert "namespace" not in meta and meta["name"] not in names and len(meta["name"]) <= 253
        assert meta["name"] == meta["name"].lower() and meta["name"][0].isalnum() and meta["name"][-1].isalnum()
        names.add(meta["name"])
        assert set(spec) <= {"podSelector", "policyTypes", "ingress", "egress"} and spec["policyTypes"] == ["Ingress", "Egress"]
        group = spec["podSelector"]["matchLabels"][emit_kubernetes.LABEL]
        assert len(group) <= 63 and group[0].isalnum() and group[-1].isalnum()
        for key, peers in (("ingress", "from"), ("egress", "to")):
            for rule in spec.get(key, []):
                assert set(rule) <= {peers, "ports"}
                for peer in rule.get(peers, []):
                    assert set(peer) == {"ipBlock"}
                    block = ipaddress.ip_network(peer["ipBlock"]["cidr"])
                    for cut in peer["ipBlock"].get("except", []):
                        assert ipaddress.ip_network(cut).subnet_of(block) and ipaddress.ip_network(cut) != block  # type: ignore[arg-type]
                for port in rule.get("ports", []):
                    assert port["protocol"] in ("TCP", "UDP", "SCTP")
                    if "port" in port:
                        assert 1 <= port["port"] <= port.get("endPort", port["port"]) <= 65535
        spans = []
        for token in meta["annotations"]["fwshift/addresses"].split():
            if "-" in token and "/" not in token:
                first, last = token.split("-")
                spans.append((ip(first), ip(last)))
            else:
                network = ipaddress.ip_network(token)
                spans.append((network[0], network[-1]))
        groups[group] = spans
    return document["items"], groups


class NetpolJudge:
    """The policies the emitter wrote, on a cluster whose pods carry the group whose addresses hold theirs."""

    def __init__(self, text: str) -> None:
        self.policies, self.groups = network_policies(text)

    def group_of(self, address: str) -> Optional[str]:
        probe = ip(address)
        found = [g for g, spans in self.groups.items() if any(a.version == probe.version and a <= probe <= b for a, b in spans)]
        assert len(found) <= 1, (address, found)
        return found[0] if found else None

    def allows(self, pkt: Packet) -> Optional[bool]:
        objects: List[Dict[str, Any]] = list(self.policies)
        for index, address in enumerate((pkt.src, pkt.dst)):
            group = self.group_of(address)
            if group is not None:
                objects.append({"kind": "Pod", "metadata": {"name": f"pod{index}", "namespace": "default", "labels": {emit_kubernetes.LABEL: group}},
                                "spec": {}, "status": {"phase": "Running", "podIPs": [{"ip": address}]}})  # fmt: skip
        return K8sJudge(objects).allows(pkt)


NARROWER = {"SOURCE_PORTS_WIDENED", "ZONE_WIDENED", "RULE_TYPE"}


def without_source_ports(model: Policy) -> Policy:
    for service in model.services.values():
        for entry in service.entries:
            entry.src_ports = ""
    return model


@pytest.mark.parametrize("seed", range(30))
def test_emitted_network_policies_decide_like_the_model(seed: int) -> None:
    """Deny rules taken out, both ends written, every address in one group: the model's verdict for TCP, UDP and SCTP;
    never more than the model for the protocols a NetworkPolicy cannot name on their own."""
    rng = random.Random(seed)
    model = without_source_ports(random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_kubernetes.emit(model, report, Options(zone_networks=ZONES_AT))
    judge = NetpolJudge(text)
    compared = disabled_left_out(model, report)
    codes = {f.code for item in report.items.values() for f in item.findings}
    for _ in range(300):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        verdict = judge.allows(pkt)
        assert verdict is not None
        wanted = model_allows(compared, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        if "K8S_PART_NOT_WRITTEN" not in codes or pkt.proto in ("tcp", "udp"):
            assert verdict == wanted, (seed, pkt, text)


@pytest.mark.parametrize("seed", range(10))
def test_emitted_network_policies_never_allow_more(seed: int) -> None:
    rng = random.Random(3000 + seed)
    model = random_model(rng)
    report = Report()
    networks = {zone: nets for zone, nets in ZONES_AT.items() if rng.random() < 0.8}
    judge = NetpolJudge(emit_kubernetes.emit(model, report, Options(zone_networks=networks)))
    compared = disabled_left_out(model, report)
    for _ in range(300):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        assert judge.allows(pkt) <= model_allows(compared, pkt), (seed, pkt)


@pytest.mark.parametrize("dialect", ["kubernetes", "calico"])
def test_samples_through_both_targets_keep_every_decision(dialect: str) -> None:
    """The sample, converted to Calico and to NetworkPolicies with every pod labelled: the source's verdict for every
    connection of a pod (TCP and UDP; Calico also ICMP)."""
    objects = sample_objects(dialect)
    source, _ = load(f"{dialect}_sample.json")
    judge: Any = K8sJudge(objects) if dialect == "kubernetes" else CalicoJudge(objects)
    gnp = GnpJudge(cli.convert(source, "calico", Report()))
    netpol = NetpolJudge(cli.convert(source, "kubernetes", Report()))
    pods = [str(a) for pod in (judge.k8s if dialect == "calico" else judge).pods for a in pod["ips"]]
    pool = pods + ["10.0.0.11", "10.0.0.12", "192.0.2.10", "198.51.100.9", "203.0.113.70", "10.20.0.1", "2001:db8:ffff::1", "2001:db8:aaaa::2"]
    rng = random.Random(11)
    count = 0
    for _ in range(6000):
        pkt = cluster_packet(rng, pool)
        if pkt is None or pkt.proto in ("sctp",):
            continue
        if pkt.proto in ("icmp", "icmp6"):
            pkt.icmp_type = rng.choice([8, 128, 0])
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        # (The policy applies to every pod, at both ends: each end gives the verdict of its one list.)
        assert gnp.verdict(pkt) == verdict, pkt
        if pkt.proto in ("tcp", "udp"):
            assert netpol.allows(pkt) == verdict, pkt
    assert count > 2000


def sample_objects(dialect: str) -> List[Dict[str, Any]]:
    text = (DATA / f"{dialect}_sample.json").read_text(encoding="utf-8")
    documents = parse_kubernetes._documents(text)
    return [obj for document in documents for obj in parse_kubernetes._objects(document)]


# -- the samples ----------------------------------------------------------------------------------


def rule_named(p: Policy, name: str) -> Rule:
    return next(r for r in p.rules if r.name == name)


def test_kubernetes_sample() -> None:
    p, report = load("kubernetes_sample.json")
    assert p.vendor == "kubernetes" and not p.zones and p.default_interzone == Action.DENY
    codes = {n.code for n in report.notes}
    assert {"K8S_SNAPSHOT", "K8S_IPBLOCK_PODS", "K8S_SERVICES", "K8S_IGNORED"} <= codes
    # Node rules first, the rules of pods that are not isolated last.
    assert p.rules[0].name == "node 10.0.0.11 to its pods" and p.rules[-1].name == "not isolated: to pods"
    # A named port is the port of each pod: web-1 has http on 8080, web-2 on 8081.
    first, second = rule_named(p, "shop/allow-web/ingress-1"), rule_named(p, "shop/allow-web/ingress-1-2")
    assert {first.services[0], second.services[0]} == {"tcp-8080", "tcp-8081"}
    # The default of policyTypes: a policy with an egress section isolates for both (the worker gets no ingress).
    worker = rule_named(p, "isolated/ingress-5")
    assert worker.action == Action.DROP and p.address_groups[worker.destinations[0]].members == ["payments/worker-1"]
    # protocol ICMP is refused by the API: the rule is kept, and not converted.
    assert rule_named(p, "payments/api-ingress/ingress-3").unsupported
    # SCTP and endPort.
    assert p.services["tcp-8443+tcp-9000-9010"].entries[1].dst_ports == "9000-9010"
    assert p.services["sctp-3868"].entries[0].protocol == Protocol.SCTP
    # The pods of the host network and pods that ended are not in it.
    assert "10.0.0.11" not in p.address_groups["all-pods"].members
    assert p.address_groups["all-pods"].builtin == "kubernetes"


def test_calico_sample() -> None:
    p, report = load("calico_sample.json")
    assert p.vendor == "calico"
    codes = {n.code for n in report.notes}
    assert {"CALICO_LOG_RULE", "CALICO_HOST_ONLY", "CALICO_HOST_ENDPOINTS", "CALICO_NODE_TRAFFIC"} <= codes
    names = [r.name for r in p.rules]
    # Tier security (order 100) before platform (200) before default.
    assert names.index("security.block-threats/egress-1") < names.index("platform.dns/egress-1") < names.index("shop/web-calico/egress-3")
    # The HTTP match stays, not converted.
    assert any(r.unsupported == ["an HTTP match (application layer policy)"] for r in p.rules)
    # notPorts: 8000-8100 without 8050.
    assert "tcp-8000-8049+tcp-8051-8100" in p.services
    # notProtocol: every protocol but TCP, as a negated service.
    assert any(r.negate_service and p.services[r.services[0]].entries[0].protocol == Protocol.TCP for r in p.rules)
    # A global() namespace selector reaches the global network set.
    rule = rule_named(p, "payments/api-calico/ingress-1")
    assert p.address_groups[rule.sources[0]].members == ["203.0.113.0/26", "2001:db8:aaaa::/48"]


def test_detection_of_every_sample() -> None:
    for path in sorted(DATA.glob("*")):
        if path.is_dir():
            continue
        data = path.read_bytes()
        found_k8s, found_calico = parse_kubernetes.looks_like_kubernetes(data), parse_kubernetes.looks_like_calico(data)
        if path.name == "kubernetes_sample.json":
            assert found_k8s and not found_calico and cli.detect_format(data) == "kubernetes"
        elif path.name == "calico_sample.json":
            assert found_calico and not found_k8s and cli.detect_format(data) == "calico"
        else:
            assert not found_k8s and not found_calico, path.name


# -- the traps, one by one ------------------------------------------------------------------------


def pod(name: str, address: str, labels: Dict[str, str], ns: str = "default", **more: Any) -> Dict[str, Any]:
    status = {"phase": "Running", "podIPs": [{"ip": a} for a in address.split(",")], "hostIP": "10.0.0.1"}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": dict(more), "status": status}


def netpol(name: str, spec: Dict[str, Any], ns: str = "default") -> Dict[str, Any]:
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns}, "spec": spec}


def verdict(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 80) -> bool:
    return model_allows(model, Packet("eth0", "eth0", src, dst, proto, 40000, dport))


PODS = [pod("a", "10.244.0.1", {"app": "a"}), pod("b", "10.244.0.2", {"app": "b"}), pod("c", "10.244.0.3", {"app": "c"}, "other")]


def test_isolation_comes_only_from_a_policy_of_that_type() -> None:
    model = parse(PODS + [netpol("in", {"podSelector": {"matchLabels": {"app": "a"}}, "policyTypes": ["Ingress"]})])
    assert not verdict(model, "10.244.0.2", "10.244.0.1")  # a is isolated for ingress, nothing allows
    assert verdict(model, "10.244.0.1", "10.244.0.2")  # a is not isolated for egress, b not for ingress
    assert verdict(model, "192.0.2.1", "10.244.0.2") and verdict(model, "10.244.0.2", "192.0.2.1")
    assert not verdict(model, "192.0.2.1", "192.0.2.2")  # no pod at either end: not the cluster's


def test_policies_are_a_union_and_both_ends_count() -> None:
    allow_b = netpol("b", {"podSelector": {"matchLabels": {"app": "a"}}, "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "b"}}}]}]})
    allow_c = netpol("c", {"podSelector": {"matchLabels": {"app": "a"}}, "ingress": [{"from": [{"namespaceSelector": {}}], "ports": [{"port": 443}]}]})
    deny_b_out = netpol("out", {"podSelector": {"matchLabels": {"app": "b"}}, "policyTypes": ["Egress"]})
    model = parse(PODS + [allow_b, allow_c])
    assert verdict(model, "10.244.0.2", "10.244.0.1", dport=22)
    assert verdict(model, "10.244.0.3", "10.244.0.1", dport=443) and not verdict(model, "10.244.0.3", "10.244.0.1", dport=22)
    model = parse(PODS + [allow_b, deny_b_out])
    assert not verdict(model, "10.244.0.2", "10.244.0.1")  # the ingress side allows, the egress side of b does not


def test_peer_with_both_selectors_is_an_and_two_peers_an_or() -> None:
    ns = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other", "labels": {"team": "x"}}},
          {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "default", "labels": {}}}]
    one = netpol("one", {"podSelector": {"matchLabels": {"app": "a"}}, "ingress": [{"from": [
        {"namespaceSelector": {"matchLabels": {"team": "x"}}, "podSelector": {"matchLabels": {"app": "b"}}}]}]})
    two = netpol("two", {"podSelector": {"matchLabels": {"app": "a"}}, "ingress": [{"from": [
        {"namespaceSelector": {"matchLabels": {"team": "x"}}}, {"podSelector": {"matchLabels": {"app": "b"}}}]}]})
    model = parse(PODS + ns + [one])
    assert not verdict(model, "10.244.0.2", "10.244.0.1") and not verdict(model, "10.244.0.3", "10.244.0.1")
    model = parse(PODS + ns + [two])
    assert verdict(model, "10.244.0.2", "10.244.0.1") and verdict(model, "10.244.0.3", "10.244.0.1")


def test_ipblock_except_end_port_and_named_ports() -> None:
    spec = {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [
        {"from": [{"ipBlock": {"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}}],
         "ports": [{"port": 8000, "endPort": 8010}, {"protocol": "UDP", "port": "dns"}]}]}
    pods = [pod("a", "10.244.0.1", {}, containers=[{"name": "x", "ports": [{"name": "dns", "containerPort": 5353, "protocol": "UDP"}]}])]
    model = parse(pods + [netpol("p", spec)])
    assert verdict(model, "192.0.2.1", "10.244.0.1", dport=8005) and not verdict(model, "192.0.2.200", "10.244.0.1", dport=8005)
    assert not verdict(model, "192.0.2.1", "10.244.0.1", dport=8011)
    assert verdict(model, "192.0.2.1", "10.244.0.1", "udp", 5353) and not verdict(model, "192.0.2.1", "10.244.0.1", "udp", 53)


def test_node_traffic_is_always_allowed() -> None:
    model = parse(PODS + [netpol("deny", {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})])
    assert verdict(model, "10.0.0.1", "10.244.0.1") and verdict(model, "10.244.0.1", "10.0.0.1")
    assert not verdict(model, "10.0.0.2", "10.244.0.1")


def test_what_is_never_read_as_any() -> None:
    report = Report()
    model = parse(PODS + [netpol("odd", {"podSelector": {"matchLabels": {"app": "a"}}, "ingress": [
        {"from": [{"podSelector": {"matchLabels": {"app": "b"}}, "ipBlock": {"cidr": "10.0.0.0/8"}}]},
        {"from": [{"ipBlock": {"cidr": "10.0.0.0/8", "except": ["192.0.2.0/24"]}}]},
        {"ports": [{"port": "x", "endPort": 90}]},
        {"future": True},
    ]}), netpol("bad", {"podSelector": {"matchExpressions": [{"key": "a", "operator": "Gt"}]}})], report=report)
    assert sum(1 for r in model.rules if r.unsupported) >= 4
    assert any(n.code == "K8S_POLICY_NOT_CONVERTED" for n in report.notes)
    with pytest.raises(ParseError):
        parse([netpol("only", {"podSelector": {}})])
    with pytest.raises(ParseError):
        parse_kubernetes.parse(b"apiVersion: v1\nkind: List\n", Report())


def test_namespaces_missing_from_the_export() -> None:
    report = Report()
    spec = {"podSelector": {}, "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"team": "x"}}}]},
                                           {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "other"}}}]}]}
    model = parse(PODS + [netpol("p", spec)], report=report)
    assert any(n.code == "K8S_NAMESPACE_MISSING" for n in report.notes)
    assert rule_named(model, "default/p/ingress-1").unsupported and not rule_named(model, "default/p/ingress-2").unsupported


def test_calico_order_pass_log_and_tier_default() -> None:
    v3 = "projectcalico.org/v3"
    objects = PODS + [
        {"apiVersion": v3, "kind": "Tier", "metadata": {"name": "t"}, "spec": {"order": 10, "defaultAction": "Pass"}},
        {"apiVersion": v3, "kind": "GlobalNetworkPolicy", "metadata": {"name": "late"}, "spec": {
            "order": 20, "selector": "app == 'a'", "ingress": [{"action": "Allow"}]}},
        {"apiVersion": v3, "kind": "GlobalNetworkPolicy", "metadata": {"name": "early"}, "spec": {
            "order": 10, "selector": "app == 'a'", "ingress": [
                {"action": "Log"}, {"action": "Deny", "protocol": "TCP", "destination": {"ports": [22]}},
                {"action": "Pass", "source": {"nets": ["192.0.2.0/24"]}}]}},
        {"apiVersion": v3, "kind": "GlobalNetworkPolicy", "metadata": {"name": "t.gate"}, "spec": {
            "tier": "t", "order": 1, "selector": "all()", "ingress": [{"action": "Deny", "source": {"nets": ["198.51.100.0/24"]}}]}},
    ]
    model = parse(objects, "calico")
    assert not verdict(model, "10.244.0.2", "10.244.0.1", dport=22)  # early comes first, whatever the file order
    assert verdict(model, "10.244.0.2", "10.244.0.1", dport=80)  # then late allows
    assert verdict(model, "192.0.2.5", "10.244.0.1", dport=80)  # Pass skips late, and the last tier: the profile allows
    assert not verdict(model, "192.0.2.5", "10.244.0.1", dport=22)  # (the Deny above the Pass)
    assert not verdict(model, "198.51.100.5", "10.244.0.2")  # the tier t denies first
    assert verdict(model, "203.0.113.5", "10.244.0.2")  # tier t passes, nothing in default applies to b: the profile


def test_calico_without_tier_object_or_with_unreadable_selector() -> None:
    report = Report()
    objects = PODS + [
        {"apiVersion": "projectcalico.org/v3", "kind": "GlobalNetworkPolicy", "metadata": {"name": "x.p"}, "spec": {"tier": "x", "ingress": []}},
        {"apiVersion": "projectcalico.org/v3", "kind": "GlobalNetworkPolicy", "metadata": {"name": "q"}, "spec": {"selector": "app ==", "ingress": []}},
        {"apiVersion": "projectcalico.org/v3", "kind": "GlobalNetworkPolicy", "metadata": {"name": "ok"}, "spec": {"selector": "app == 'a'",
                                                                                                                  "types": ["Ingress"]}},
    ]
    model = parse(objects, "calico", report)
    assert sum(1 for n in report.notes if n.code == "K8S_POLICY_NOT_CONVERTED") == 2
    assert not verdict(model, "10.244.0.2", "10.244.0.1")
    with pytest.raises(ParseError):
        parse(PODS + objects[1:], "kubernetes")  # (--from kubernetes reads no Calico policy: there is none left)


def test_calico_selector_language() -> None:
    selector = parse_kubernetes._CalicoSelector
    labels = {"app": "web", "tier": "fe"}
    for text, wanted in (("app == 'web' && tier != 'be'", True), ("!has(app)", False), ("app in {'db', \"web\"}", True),
                         ("app not in {'web'}", False), ("(app == 'x' || tier == 'fe') && has(tier)", True),
                         ("app contains 'e'", True), ("app ends with 'b'", True), ("all()", True), ("", True),
                         ("missing != 'x'", True), ("global()", False)):  # fmt: skip
        assert selector(text)(labels) is wanted, text
    for text in ("app = 'web'", "app == web", "has(app", "app in {'a' 'b'}", "&& app == 'x'"):
        with pytest.raises(parse_kubernetes._Bad):
            selector(text)


def test_calico_emitter_details() -> None:
    p = Policy(vendor="panos")
    p.addresses["net"] = Address("net", AddressKind.NETWORK, "10.0.0.0/8")
    p.addresses["web"] = Address("web", AddressKind.FQDN, "www.example.com")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,8000-8080", "1024-65535")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.rules = [Rule("r1", sources=["net"], services=["web"]), Rule("r2", destinations=["net"], services=["ping"], action=Action.DROP),
               Rule("r3", services=["gre"], negate_service=True), Rule("r4", destinations=["web"]),
               Rule("r5", sources=["net"], negate_source=True, services=["web", "ping"], negate_service=True)]
    for rule in p.rules:
        rule.origin = rule.name
    report = Report()
    body = json.loads(emit_calico.emit(p, report, Options(target_policy="Edge_Policy")))
    assert body["metadata"]["name"] == "edge-policy"
    rules = body["spec"]["ingress"]
    assert rules[0] == {"action": "Allow", "ipVersion": 4, "protocol": "TCP", "source": {"ports": ["1024:65535"], "nets": ["10.0.0.0/8"]},
                        "destination": {"ports": [80, "8000:8080"]}, "metadata": {"annotations": {"fwshift/rule": "r1"}}}
    assert rules[1]["protocol"] == "ICMP" and rules[1]["icmp"] == {"type": 8} and rules[1]["action"] == "Deny"
    assert rules[2]["notProtocol"] == 47 and "ipVersion" not in rules[2]
    assert rules[-1]["action"] == "Deny" and len(rules) == 4
    assert report.item("rule", "r4").disabled and report.item("rule", "r5").disabled
    assert "r4" in body["metadata"]["annotations"]["fwshift/not-written"]
    assert body["spec"]["selector"] == f"fwshift/policy == '{body['metadata']['name']}'"


def test_network_policy_emitter_details() -> None:
    assert emit_kubernetes.ip_blocks([(4, 0, 2**32 - 1)]) == [{"ipBlock": {"cidr": "0.0.0.0/0"}}]
    blocks = emit_kubernetes.ip_blocks([(4, 0, int(ipaddress.ip_address("10.0.0.0")) - 1),
                                        (4, int(ipaddress.ip_address("11.0.0.0")), 2**32 - 1)])
    assert blocks == [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}]
    p = Policy(vendor="panos")
    p.addresses["inside"] = Address("inside", AddressKind.NETWORK, "10.0.0.0/24")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443"), ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.rules = [Rule("block", sources=["10.0.0.9"], action=Action.DROP), Rule("open", destinations=["inside"], services=["web"])]
    for rule in p.rules:
        rule.origin = rule.name
    report = Report()
    text = emit_kubernetes.emit(p, report, Options())
    items, groups = network_policies(text)
    codes = {f.code for item in report.items.values() for f in item.findings} | {n.code for n in report.notes}
    assert {"DENY_SUBTRACTED", "K8S_PART_NOT_WRITTEN", "K8S_LOAD", "K8S_LABEL_PODS"} <= codes
    target = next(i for i in items if any(r.get("ports") for r in i["spec"].get("ingress", [])))
    rule = target["spec"]["ingress"][0]
    assert rule["ports"] == [{"protocol": "TCP", "port": 443}]
    assert {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.9/32"]}} in rule["from"]


def test_severities_of_the_new_findings() -> None:
    _, report = load("kubernetes_sample.json")
    by_code = {n.code: n.severity for n in report.notes}
    assert by_code["K8S_SNAPSHOT"] == Severity.REVIEW and by_code["K8S_SELF_TRAFFIC"] == Severity.INFO
