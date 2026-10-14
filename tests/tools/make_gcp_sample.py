# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/gcp_sample.json: a made-up VPC network of Google Cloud, as gcloud prints it, under one key per answer:

    gcloud compute networks describe vpc-shop --format=json                         ("networks")
    gcloud compute firewall-rules list --format=json                                ("firewall-rules")
    gcloud compute network-firewall-policies describe pol-shop --global --format=json
    gcloud compute network-firewall-policies describe pol-ew1 --region europe-west1 --format=json
                                                                                    ("network-firewall-policies")
    gcloud compute instances list --format=json                                     ("instances")

Every address is a documentation or private address, every id and project name is made up. Not taken from any real
project.

    python3 tests/tools/make_gcp_sample.py
"""

from __future__ import annotations

import json
import zlib
from pathlib import Path
from typing import Any, Dict, List

API = "https://www.googleapis.com/compute/v1/projects/example-shop"
NETWORK = f"{API}/global/networks/vpc-shop"


def firewall(name: str, priority: int, direction: str, action: str, protocols: List[Dict[str, Any]], **more: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"kind": "compute#firewall", "id": str(10 ** 18 + zlib.crc32(name.encode())), "creationTimestamp": "2026-09-01T00:00:00.000-07:00",
                           "name": name, "network": NETWORK, "priority": priority, "direction": direction,
                           "allowed" if action == "allow" else "denied": protocols, "disabled": False, "logConfig": {"enable": False},
                           "selfLink": f"{API}/global/firewalls/{name}"}  # fmt: skip
    out.update(more)
    return out


def tcp(*ports: str) -> Dict[str, Any]:
    return {"IPProtocol": "tcp", "ports": list(ports)} if ports else {"IPProtocol": "tcp"}


def predefined() -> List[Dict[str, Any]]:
    return [{"kind": "compute#firewallPolicyRule", "priority": p, "direction": d, "action": "goto_next", "enableLogging": False,
             "match": {("destIpRanges" if d == "EGRESS" else "srcIpRanges"): [r], "layer4Configs": [{"ipProtocol": "all"}]}}
            for p, d, r in ((2147483644, "EGRESS", "::/0"), (2147483645, "INGRESS", "::/0"), (2147483646, "EGRESS", "0.0.0.0/0"),
                            (2147483647, "INGRESS", "0.0.0.0/0"))]  # fmt: skip


def rule(priority: int, name: str, direction: str, action: str, match: Dict[str, Any], **more: Any) -> Dict[str, Any]:
    out = {"kind": "compute#firewallPolicyRule", "ruleName": name, "priority": priority, "direction": direction, "action": action,
           "match": match, "enableLogging": False}  # fmt: skip
    out.update(more)
    return out


def instance(name: str, zone: str, address: str, tags: List[str], account: str, six: str = "", external: str = "",
             alias: str = "") -> Dict[str, Any]:  # fmt: skip
    nic: Dict[str, Any] = {"kind": "compute#networkInterface", "name": "nic0", "network": NETWORK, "networkIP": address,
                           "subnetwork": f"{API}/regions/{zone.rsplit('-', 1)[0]}/subnetworks/shop"}  # fmt: skip
    if six:
        nic["ipv6Address"] = six
        nic["stackType"] = "IPV4_IPV6"
    if external:
        nic["accessConfigs"] = [{"kind": "compute#accessConfig", "name": "External NAT", "natIP": external, "type": "ONE_TO_ONE_NAT"}]
    if alias:
        nic["aliasIpRanges"] = [{"ipCidrRange": alias, "subnetworkRangeName": "pods"}]
    return {"kind": "compute#instance", "id": str(10 ** 18 + zlib.crc32(name.encode())), "name": name, "zone": f"{API}/zones/{zone}",
            "status": "RUNNING", "tags": {"items": tags} if tags else {}, "networkInterfaces": [nic],
            "serviceAccounts": [{"email": account, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]}  # fmt: skip


def sample() -> Dict[str, Any]:
    web_sa, app_sa, db_sa = (f"{n}@example-shop.iam.gserviceaccount.com" for n in ("web", "app", "db"))
    rules = [
        firewall("allow-https-web", 1000, "INGRESS", "allow", [tcp("443", "8443-8444")], sourceRanges=["0.0.0.0/0"], targetTags=["web"],
                 description="https to the web servers", logConfig={"enable": True, "metadata": "EXCLUDE_ALL_METADATA"}),
        firewall("allow-https-web-v6", 1000, "INGRESS", "allow", [tcp("443")], sourceRanges=["::/0"], targetTags=["web"]),
        firewall("deny-ssh-blocked", 1000, "INGRESS", "deny", [tcp("22")], sourceRanges=["203.0.113.0/24"]),
        firewall("allow-ssh-admins", 1010, "INGRESS", "allow", [tcp("22")], sourceRanges=["198.51.100.0/24"]),
        firewall("allow-app-from-web", 900, "INGRESS", "allow", [tcp("8080"), {"IPProtocol": "icmp"}], sourceTags=["web"], targetTags=["app"]),
        firewall("allow-db-from-app", 900, "INGRESS", "allow", [tcp("5432")], sourceServiceAccounts=[app_sa], targetServiceAccounts=[db_sa]),
        firewall("allow-mgmt-v6", 1100, "INGRESS", "allow", [tcp("22"), {"IPProtocol": "58"}], sourceRanges=["2001:db8:900::/48"],
                 targetServiceAccounts=[web_sa]),
        firewall("deny-egress-doc", 500, "EGRESS", "deny", [{"IPProtocol": "all"}], destinationRanges=["192.0.2.0/24"]),
        firewall("db-no-internet", 600, "EGRESS", "deny", [{"IPProtocol": "all"}], destinationRanges=["0.0.0.0/0"], targetTags=["db"]),
        firewall("db-to-vpc", 590, "EGRESS", "allow", [{"IPProtocol": "all"}], destinationRanges=["10.50.0.0/16"], targetTags=["db"]),
        firewall("old-dns", 1000, "INGRESS", "allow", [{"IPProtocol": "udp", "ports": ["53"]}], sourceRanges=["10.0.0.0/8"], disabled=True),
    ]
    global_policy = {
        "kind": "compute#firewallPolicy", "id": "3333333333333333301", "name": "pol-shop", "description": "the global policy of vpc-shop",
        "fingerprint": "AAAAAAAAAAA=", "selfLink": f"{API}/global/firewallPolicies/pol-shop", "ruleTupleCount": 30,
        "associations": [{"name": "pol-shop-vpc-shop", "attachmentTarget": NETWORK, "firewallPolicyId": "3333333333333333301"}],
        "rules": [
            rule(100, "deny-tor", "INGRESS", "deny", {"srcIpRanges": ["203.0.113.128/25"], "layer4Configs": [{"ipProtocol": "all"}]},
                 enableLogging=True, description="a blocked range"),
            rule(200, "rfc1918-next", "INGRESS", "goto_next", {"srcIpRanges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                                                                "layer4Configs": [{"ipProtocol": "all"}]}),
            rule(300, "allow-monitoring", "INGRESS", "allow", {"srcIpRanges": ["10.0.0.0/8", "198.51.100.200/32"],
                                                                "layer4Configs": [{"ipProtocol": "tcp", "ports": ["9100"]}]}),
            rule(400, "allow-dns-out", "EGRESS", "allow", {"destIpRanges": ["198.51.100.53/32"],
                                                           "layer4Configs": [{"ipProtocol": "udp", "ports": ["53"]}, {"ipProtocol": "tcp", "ports": ["53"]}]},
                 targetServiceAccounts=[app_sa]),
            rule(500, "geo-and-fqdn", "INGRESS", "deny", {"srcRegionCodes": ["XX"], "srcFqdns": ["blocked.example.com"],
                                                          "layer4Configs": [{"ipProtocol": "tcp"}]}, disabled=True),
            rule(600, "deny-smtp-out", "EGRESS", "deny", {"destIpRanges": ["0.0.0.0/0"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["25"]}]}),
        ] + predefined(),
    }  # fmt: skip
    regional_policy = {
        "kind": "compute#firewallPolicy", "id": "3333333333333333302", "name": "pol-ew1", "region": f"{API}/regions/europe-west1",
        "selfLink": f"{API}/regions/europe-west1/firewallPolicies/pol-ew1", "ruleTupleCount": 10,
        "associations": [{"name": "pol-ew1-vpc-shop", "attachmentTarget": NETWORK, "firewallPolicyId": "3333333333333333302"}],
        "rules": [
            rule(100, "allow-lb-health", "INGRESS", "allow", {"srcIpRanges": ["192.0.2.64/26"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["80"]}]}),
        ] + predefined(),
    }  # fmt: skip
    instances = [
        instance("web-1", "europe-west1-b", "10.50.1.10", ["web"], web_sa, six="2001:db8:50:1::10", external="192.0.2.10"),
        instance("web-2", "europe-west4-a", "10.50.1.11", ["web"], web_sa),
        instance("app-1", "europe-west1-c", "10.50.2.20", ["app"], app_sa, alias="10.60.0.0/24"),
        instance("db-1", "europe-west1-b", "10.50.3.30", ["db"], db_sa),
        instance("bastion", "europe-west1-d", "10.50.9.5", [], "bastion@example-shop.iam.gserviceaccount.com", external="192.0.2.5"),
    ]
    network = {"kind": "compute#network", "id": "1111111111111111111", "name": "vpc-shop", "selfLink": NETWORK, "autoCreateSubnetworks": False,
               "networkFirewallPolicyEnforcementOrder": "AFTER_CLASSIC_FIREWALL"}  # fmt: skip
    return {"networks": [network], "firewall-rules": rules, "network-firewall-policies": [global_policy, regional_policy], "instances": instances}


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "data" / "gcp_sample.json"
    path.write_text(json.dumps(sample(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
