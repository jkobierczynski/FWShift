# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build the two synthetic Kubernetes samples.

``tests/data/kubernetes_sample.json`` is what ``kubectl get networkpolicy,pod,namespace,service -A -o json`` answers
for a small made-up cluster (one ``List``); ``tests/data/calico_sample.json`` is the same cluster with the answers of
``calicoctl get tier,globalnetworkpolicy,networkpolicy,globalnetworkset,networkset,hostendpoint -A -o json``
appended, one document after the other. The shapes follow the API references of Kubernetes and Calico; nothing in
them came from a cluster. All names and addresses are invented (RFC 1918, RFC 5737, RFC 3849).

Usage: python3 tests/tools/make_kubernetes_samples.py
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
NODES = {"node-a": "10.0.0.11", "node-b": "10.0.0.12"}


def namespace(name: str, **labels: str) -> Dict[str, Any]:
    labels = dict(labels, **{"kubernetes.io/metadata.name": name})
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}, "spec": {"finalizers": ["kubernetes"]},
            "status": {"phase": "Active"}}


def pod(ns: str, name: str, ips: List[str], node: str, labels: Dict[str, str], ports: List[Tuple[str, int, str]] = (),  # type: ignore[assignment]
        phase: str = "Running", host_network: bool = False, account: str = "default") -> Dict[str, Any]:
    container: Dict[str, Any] = {"name": name.split("-")[0], "image": "registry.example.com/" + name.split("-")[0] + ":1.0"}
    if ports:
        container["ports"] = [{"name": n, "containerPort": p, "protocol": proto} for n, p, proto in ports]
    spec: Dict[str, Any] = {"containers": [container], "nodeName": node, "serviceAccountName": account}
    if host_network:
        spec["hostNetwork"] = True
    status: Dict[str, Any] = {"phase": phase, "hostIP": NODES[node], "hostIPs": [{"ip": NODES[node]}]}
    if ips:
        status["podIP"] = ips[0]
        status["podIPs"] = [{"ip": ip} for ip in ips]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns, "labels": labels}, "spec": spec, "status": status}


def service(ns: str, name: str, kind: str, selector: Dict[str, str], cluster_ip: str, port: int, target: Any) -> Dict[str, Any]:
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns},
            "spec": {"type": kind, "selector": selector, "clusterIP": cluster_ip, "clusterIPs": [cluster_ip],
                     "ports": [{"port": port, "targetPort": target, "protocol": "TCP"}]}}


def netpol(ns: str, name: str, selector: Dict[str, Any], types: Optional[List[str]], ingress: Optional[List[Any]] = None,
           egress: Optional[List[Any]] = None) -> Dict[str, Any]:
    spec: Dict[str, Any] = {"podSelector": selector}
    if types is not None:
        spec["policyTypes"] = types
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns}, "spec": spec}


def labels(**values: str) -> Dict[str, Any]:
    return {"matchLabels": dict(values)}


def cluster() -> List[Dict[str, Any]]:
    items = [
        namespace("shop", team="shop", env="prod"),
        namespace("payments", team="payments", env="prod"),
        namespace("monitoring", team="ops"),
        namespace("dev", env="dev"),
        namespace("kube-system"),
        pod("shop", "web-1", ["10.244.1.10", "2001:db8:244:1::10"], "node-a", {"app": "web", "tier": "frontend"},
            [("http", 8080, "TCP"), ("metrics", 9100, "TCP")], account="web"),
        pod("shop", "web-2", ["10.244.2.10", "2001:db8:244:2::10"], "node-b", {"app": "web", "tier": "frontend"},
            [("http", 8081, "TCP"), ("metrics", 9100, "TCP")], account="web"),
        pod("shop", "cart-1", ["10.244.1.20"], "node-a", {"app": "cart"}, [("grpc", 50051, "TCP")]),
        pod("shop", "db-1", ["10.244.2.30"], "node-b", {"app": "db"}, [("pg", 5432, "TCP")]),
        pod("shop", "migrate-29", [], "node-a", {"job": "migrate"}, phase="Succeeded"),
        pod("payments", "api-1", ["10.244.1.40", "2001:db8:244:1::40"], "node-a", {"app": "payments-api"},
            [("https", 8443, "TCP"), ("sig", 3868, "SCTP")]),
        pod("payments", "worker-1", ["10.244.2.41"], "node-b", {"app": "worker"}),
        pod("monitoring", "prometheus-0", ["10.244.3.5"], "node-b", {"app": "prometheus"}, [("web", 9090, "TCP")]),
        pod("dev", "debug", ["10.244.3.9"], "node-a", {"app": "debug"}),
        pod("kube-system", "coredns-5d7f", ["10.244.0.2"], "node-a", {"k8s-app": "kube-dns"},
            [("dns", 53, "UDP"), ("dns-tcp", 53, "TCP")]),
        pod("kube-system", "kube-proxy-x7", ["10.0.0.11"], "node-a", {"k8s-app": "kube-proxy"}, host_network=True),
        service("shop", "web", "ClusterIP", {"app": "web"}, "10.96.0.80", 80, "http"),
        service("shop", "web-public", "LoadBalancer", {"app": "web"}, "10.96.0.81", 443, "http"),
        netpol("shop", "default-deny", {}, ["Ingress", "Egress"]),
        netpol("shop", "allow-web", labels(app="web"), ["Ingress"], ingress=[
            {"from": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "192.168.0.0/16"]}},
                      {"ipBlock": {"cidr": "2001:db8:ffff::/48"}}],
             "ports": [{"protocol": "TCP", "port": "http"}]},
            {"from": [{"namespaceSelector": labels(team="ops")}], "ports": [{"port": 9100}]},
        ]),
        netpol("shop", "web-to-cart", labels(app="cart"), ["Ingress"], ingress=[
            {"from": [{"podSelector": labels(app="web")}], "ports": [{"protocol": "TCP", "port": 50051}]}]),
        netpol("shop", "cart-to-db", labels(app="db"), ["Ingress"], ingress=[
            {"from": [{"podSelector": labels(app="cart")}], "ports": [{"protocol": "TCP", "port": "pg"}]}]),
        netpol("shop", "web-egress", labels(app="web"), ["Egress"], egress=[
            {"to": [{"podSelector": labels(app="cart")}], "ports": [{"port": "grpc"}]},
            {"to": [{"namespaceSelector": labels(**{"kubernetes.io/metadata.name": "kube-system"}),
                     "podSelector": labels(**{"k8s-app": "kube-dns"})}],
             "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
            {"to": [{"ipBlock": {"cidr": "2001:db8:ffff::/48"}}], "ports": [{"port": 443}]},
        ]),
        netpol("shop", "cart-egress", labels(app="cart"), ["Egress"], egress=[
            {"to": [{"podSelector": labels(app="db")}], "ports": [{"port": 5432}]},
            {"to": [{"namespaceSelector": {}, "podSelector": labels(**{"k8s-app": "kube-dns"})}], "ports": [{"protocol": "UDP", "port": 53}]},
        ]),
        netpol("payments", "api-ingress", labels(app="payments-api"), ["Ingress"], ingress=[
            {"from": [{"namespaceSelector": labels(team="shop")}, {"podSelector": labels(app="worker")}],
             "ports": [{"port": 8443}, {"port": 9000, "endPort": 9010}, {"protocol": "SCTP", "port": "sig"}]},
            {"from": [{"namespaceSelector": labels(env="prod"), "podSelector": labels(app="web")}], "ports": [{"port": 8443}]},
            {"from": [{"podSelector": labels(app="worker")}], "ports": [{"protocol": "ICMP"}]},
        ]),
        netpol("payments", "worker-egress", labels(app="worker"), None, egress=[
            {"to": [{"ipBlock": {"cidr": "192.0.2.0/24"}}], "ports": [{"port": 443}]}]),
        netpol("monitoring", "allow-all-egress", {}, ["Egress"], egress=[{}]),
        netpol("monitoring", "scrape-only", labels(app="prometheus"), ["Ingress"], ingress=[
            {"from": [{"namespaceSelector": labels(team="ops")}], "ports": [{"port": "web"}]}]),
        netpol("dev", "not-from-prod", {}, ["Ingress"], ingress=[
            {"from": [{"namespaceSelector": {"matchExpressions": [{"key": "env", "operator": "NotIn", "values": ["prod"]}]}}]}]),
    ]
    return items


def calico() -> List[Dict[str, Any]]:
    v3 = "projectcalico.org/v3"

    def tier(name: str, order: float, default: str = "") -> Dict[str, Any]:
        spec: Dict[str, Any] = {"order": order}
        if default:
            spec["defaultAction"] = default
        return {"apiVersion": v3, "kind": "Tier", "metadata": {"name": name}, "spec": spec}

    def gnp(name: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        return {"apiVersion": v3, "kind": "GlobalNetworkPolicy", "metadata": {"name": name}, "spec": spec}

    def np(ns: str, name: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        return {"apiVersion": v3, "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ns}, "spec": spec}

    tiers = {"kind": "TierList", "apiVersion": v3, "items": [tier("security", 100), tier("platform", 200, "Pass"),
                                                            {"apiVersion": v3, "kind": "Tier", "metadata": {"name": "default"},
                                                             "spec": {"order": 1000000}}]}  # fmt: skip
    policies = {"kind": "GlobalNetworkPolicyList", "apiVersion": v3, "items": [
        gnp("security.ping", {"tier": "security", "order": 5, "selector": "app == 'web'", "types": ["Ingress"], "ingress": [
            {"action": "Allow", "protocol": "ICMP", "icmp": {"type": 8}, "source": {"nets": ["10.0.0.0/8"]}},
            {"action": "Allow", "protocol": "ICMPv6", "icmp": {"type": 128}},
            {"action": "Log", "protocol": "ICMP"},
        ]}),
        gnp("security.block-threats", {"tier": "security", "order": 10, "selector": "projectcalico.org/namespace in {'shop', 'payments'}", "types": ["Ingress", "Egress"],
                                       "ingress": [{"action": "Deny", "source": {"selector": "feed == 'threats'"}},
                                                   {"action": "Deny", "protocol": "TCP", "destination": {"ports": [23, "135:139"]}},
                                                   {"action": "Pass"}],
                                       "egress": [{"action": "Deny", "destination": {"selector": "feed == 'threats'"}},
                                                  {"action": "Pass"}]}),
        gnp("security.raw-untracked", {"tier": "security", "order": 1, "selector": "role == 'node'", "doNotTrack": True,
                                       "applyOnForward": True, "types": ["Ingress"], "ingress": [{"action": "Allow"}]}),
        gnp("platform.dns", {"tier": "platform", "order": 100, "selector": "projectcalico.org/namespace != 'kube-system'",
                             "types": ["Egress"], "egress": [
                                 {"action": "Allow", "protocol": "UDP", "destination": {"selector": "k8s-app == 'kube-dns'", "ports": [53]}},
                                 {"action": "Deny", "protocol": "UDP", "destination": {"ports": [53]}}]}),
        gnp("platform.nodes", {"tier": "platform", "order": 200, "selector": "app == 'db'", "types": ["Ingress"], "ingress": [
            {"action": "Allow", "protocol": "TCP", "source": {"selector": "role == 'node'"}, "destination": {"ports": [10250]}}]}),
    ]}
    ns_policies = {"kind": "NetworkPolicyList", "apiVersion": v3, "items": [
        np("shop", "web-calico", {"order": 100, "selector": "app == 'web'", "types": ["Ingress", "Egress"], "ingress": [
            {"action": "Allow", "protocol": "TCP", "source": {"selector": "role == 'partner'"}, "destination": {"ports": ["http"]}},
            {"action": "Deny", "source": {"nets": ["10.0.0.0/8"], "notNets": ["10.244.0.0/16"]}},
            {"action": "Allow", "protocol": "TCP", "source": {"nets": ["10.0.0.0/8"]}, "destination": {"ports": ["8000:8100"], "notPorts": [8050]}},
            {"action": "Allow", "notProtocol": "TCP", "source": {"namespaceSelector": "team == 'ops'"}},
            {"action": "Allow", "protocol": "TCP", "source": {"serviceAccounts": {"names": ["web"]}}, "destination": {"ports": [8080]},
             "http": {"methods": ["GET"]}},
        ], "egress": [
            {"action": "Allow", "protocol": "TCP", "destination": {"selector": "app == 'cart'", "ports": [50051]}},
            {"action": "Allow", "ipVersion": 6, "destination": {"nets": ["2001:db8:ffff::/48"]}},
            {"action": "Deny"},
        ]}),
        np("payments", "api-calico", {"selector": "app == 'payments-api'", "ingress": [
            {"action": "Allow", "protocol": "TCP", "source": {"namespaceSelector": "global()", "selector": "feed == 'partners'"},
             "destination": {"ports": [8443]}},
            {"action": "Allow", "protocol": "TCP", "source": {"notSelector": "app == 'debug'"}, "destination": {"ports": [8443]}},
        ]}),
    ]}
    sets = {"kind": "GlobalNetworkSetList", "apiVersion": v3, "items": [
        {"apiVersion": v3, "kind": "GlobalNetworkSet", "metadata": {"name": "threat-feed", "labels": {"feed": "threats"}},
         "spec": {"nets": ["198.51.100.0/24", "203.0.113.64/26"]}},
        {"apiVersion": v3, "kind": "GlobalNetworkSet", "metadata": {"name": "partner-feed", "labels": {"feed": "partners"}},
         "spec": {"nets": ["203.0.113.0/26", "2001:db8:aaaa::/48"]}},
    ]}
    local_sets = {"kind": "NetworkSetList", "apiVersion": v3, "items": [
        {"apiVersion": v3, "kind": "NetworkSet", "metadata": {"name": "partners", "namespace": "shop", "labels": {"role": "partner"}},
         "spec": {"nets": ["192.0.2.0/25"]}},
    ]}
    hosts = {"kind": "HostEndpointList", "apiVersion": v3, "items": [
        {"apiVersion": v3, "kind": "HostEndpoint", "metadata": {"name": "node-a-eth0", "labels": {"role": "node"}},
         "spec": {"node": "node-a", "interfaceName": "eth0", "expectedIPs": ["10.0.0.11"]}},
        {"apiVersion": v3, "kind": "HostEndpoint", "metadata": {"name": "node-b-eth0", "labels": {"role": "node"}},
         "spec": {"node": "node-b", "interfaceName": "eth0", "expectedIPs": ["10.0.0.12"]}},
    ]}
    return [tiers, policies, ns_policies, sets, local_sets, hosts]


def main() -> None:
    k8s = {"apiVersion": "v1", "kind": "List", "metadata": {"resourceVersion": ""}, "items": cluster()}
    (ROOT / "tests" / "data" / "kubernetes_sample.json").write_text(json.dumps(k8s, indent=2) + "\n", encoding="utf-8")
    text = json.dumps(k8s, indent=2) + "\n" + "".join(json.dumps(doc, indent=2) + "\n" for doc in calico())
    (ROOT / "tests" / "data" / "calico_sample.json").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
