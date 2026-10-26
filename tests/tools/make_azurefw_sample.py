# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writes tests/data/azurefw_sample.json: what the Azure CLI answers for a child firewall policy, its base policy, their
rule collection groups and the IP groups, in one JSON array (as `jq -s .` puts the answers together).

Synthetic: the subscription is all zeros, the addresses are of RFC 1918, RFC 5737 and RFC 3849, the names of
example.com/.net/.org. The shape follows the REST API specification as the CLI prints it (properties flattened); it has
not been compared with the answer of a real subscription.

    python3 tests/tools/make_azurefw_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-hub/providers/Microsoft.Network"


def policy(name: str, **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"id": f"{SUB}/firewallPolicies/{name}", "name": name, "location": "westeurope", "resourceGroup": "rg-hub",
                           "type": "Microsoft.Network/FirewallPolicies", "provisioningState": "Succeeded", "sku": {"tier": "Standard"},
                           "threatIntelMode": "Alert", "childPolicies": [], "firewalls": []}  # fmt: skip
    out.update(extra)
    return out


def group(policy_name: str, name: str, priority: int, collections: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"id": f"{SUB}/firewallPolicies/{policy_name}/ruleCollectionGroups/{name}", "name": name, "priority": priority,
            "provisioningState": "Succeeded", "resourceGroup": "rg-hub", "ruleCollections": collections,
            "type": "Microsoft.Network/FirewallPolicies/RuleCollectionGroups"}  # fmt: skip


def network(name: str, priority: int, action: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"name": name, "priority": priority, "action": {"type": action}, "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
            "rules": [dict({"ruleType": "NetworkRule", "sourceAddresses": [], "sourceIpGroups": [], "destinationAddresses": [],
                            "destinationIpGroups": [], "destinationFqdns": []}, **r) for r in rules]}  # fmt: skip


def application(name: str, priority: int, action: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"name": name, "priority": priority, "action": {"type": action}, "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
            "rules": [dict({"ruleType": "ApplicationRule", "sourceAddresses": [], "sourceIpGroups": [], "targetFqdns": [],
                            "targetUrls": [], "fqdnTags": [], "webCategories": [], "terminateTLS": False}, **r) for r in rules]}  # fmt: skip


def dnat(name: str, priority: int, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"name": name, "priority": priority, "action": {"type": "DNAT"}, "ruleCollectionType": "FirewallPolicyNatRuleCollection",
            "rules": [dict({"ruleType": "NatRule", "sourceAddresses": [], "sourceIpGroups": []}, **r) for r in rules]}


def ip_group(name: str, addresses: List[str]) -> Dict[str, Any]:
    return {"id": f"{SUB}/ipGroups/{name}", "name": name, "location": "westeurope", "resourceGroup": "rg-hub",
            "type": "Microsoft.Network/IpGroups", "provisioningState": "Succeeded", "ipAddresses": addresses}  # fmt: skip


def sample() -> List[Any]:
    base = policy("fwpol-base", ruleCollectionGroups=[{"id": f"{SUB}/firewallPolicies/fwpol-base/ruleCollectionGroups/base-rcg"}],
                  childPolicies=[{"id": f"{SUB}/firewallPolicies/fwpol-shop"}])  # fmt: skip
    child = policy(
        "fwpol-shop", basePolicy={"id": f"{SUB}/firewallPolicies/fwpol-base"}, threatIntelMode="Deny",
        dnsSettings={"enableProxy": True, "servers": ["10.10.8.8"]}, snat={"privateRanges": ["IANAPrivateRanges", "198.51.100.0/24"]},
        intrusionDetection={"mode": "Alert"},
        ruleCollectionGroups=[{"id": f"{SUB}/firewallPolicies/fwpol-shop/ruleCollectionGroups/{n}"}
                              for n in ("DefaultDnatRuleCollectionGroup", "rcg-late", "rcg-shop")],
    )  # fmt: skip
    base_groups = [group("fwpol-base", "base-rcg", 500, [
        network("base-allow-dns", 200, "Allow", [
            {"name": "dns-out", "ipProtocols": ["UDP", "TCP"], "sourceAddresses": ["10.10.0.0/16"],
             "destinationIpGroups": [f"{SUB}/ipGroups/ipg-dns"], "destinationPorts": ["53"]},
        ]),
        network("base-deny", 100, "Deny", [
            {"name": "deny-telnet", "description": "Telnet nowhere", "ipProtocols": ["TCP"], "sourceAddresses": ["*"],
             "destinationAddresses": ["*"], "destinationPorts": ["23"]},
        ]),
    ])]  # fmt: skip
    child_groups = [
        group("fwpol-shop", "DefaultDnatRuleCollectionGroup", 100, [
            dnat("dnat-web", 100, [
                {"name": "web-https", "ipProtocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["203.0.113.10"],
                 "destinationPorts": ["443"], "translatedAddress": "10.10.1.4", "translatedPort": "443"},
                {"name": "ssh-admin", "description": "Admin SSH on a high port", "ipProtocols": ["TCP"],
                 "sourceAddresses": ["198.51.100.0/24"], "destinationAddresses": ["203.0.113.10"], "destinationPorts": ["2222"],
                 "translatedAddress": "10.10.1.5", "translatedPort": "22"},
            ]),
        ]),
        group("fwpol-shop", "rcg-shop", 300, [
            application("app-out", 100, "Allow", [
                {"name": "allow-updates", "sourceAddresses": ["10.10.1.0/24"], "protocols": [{"protocolType": "Https", "port": 443}],
                 "targetFqdns": ["*.example.com", "updates.example.net"]},
                {"name": "allow-wsus", "sourceIpGroups": [f"{SUB}/ipGroups/ipg-servers"],
                 "protocols": [{"protocolType": "Http", "port": 80}, {"protocolType": "Https", "port": 443}], "fqdnTags": ["WindowsUpdate"]},
            ]),
            network("net-allow-web", 200, "Allow", [
                {"name": "web-to-db", "ipProtocols": ["TCP"], "sourceAddresses": ["10.10.1.0/24"], "destinationAddresses": ["10.10.2.0/24"],
                 "destinationPorts": ["1433"]},
                {"name": "icmp-mgmt", "ipProtocols": ["ICMP"], "sourceAddresses": ["10.10.9.0/24"], "destinationAddresses": ["10.10.0.0/16"],
                 "destinationPorts": ["*"]},
                {"name": "ntp-out", "ipProtocols": ["UDP"], "sourceIpGroups": [f"{SUB}/ipGroups/ipg-servers"],
                 "destinationFqdns": ["time.example.org"], "destinationPorts": ["123"]},
                {"name": "storage", "ipProtocols": ["TCP"], "sourceAddresses": ["10.10.0.0/16"], "destinationAddresses": ["Storage.WestEurope"],
                 "destinationPorts": ["443"]},
                {"name": "app-ports", "ipProtocols": ["TCP"], "sourceAddresses": ["10.10.1.10-10.10.1.20"],
                 "destinationAddresses": ["10.10.3.0/24"], "destinationPorts": ["8000-8080", "9000"]},
                {"name": "partner-sftp", "ipProtocols": ["TCP"], "sourceIpGroups": [f"{SUB}/ipGroups/ipg-partners"],
                 "destinationAddresses": ["10.10.1.6"], "destinationPorts": ["22"]},
            ]),
            network("net-deny-lateral", 300, "Deny", [
                {"name": "block-lateral", "ipProtocols": ["Any"], "sourceAddresses": ["10.10.0.0/16"], "destinationAddresses": ["10.10.0.0/16"],
                 "destinationPorts": ["*"]},
            ]),
            application("app-deny", 400, "Deny", [
                {"name": "no-gambling", "sourceAddresses": ["*"], "protocols": [{"protocolType": "Http", "port": 80},
                                                                              {"protocolType": "Https", "port": 443}],
                 "webCategories": ["Gambling"]},
            ]),
        ]),
        group("fwpol-shop", "rcg-late", 200, [
            network("net-partner", 100, "Allow", [
                {"name": "every-protocol-to-partner", "ipProtocols": ["Any"], "sourceAddresses": ["10.10.4.0/24"],
                 "destinationAddresses": ["192.0.2.0/24"], "destinationPorts": ["*"]},
                {"name": "dns-any-protocol", "ipProtocols": ["Any"], "sourceAddresses": ["10.10.0.0/16"], "destinationAddresses": ["10.10.8.53"],
                 "destinationPorts": ["53"]},
                {"name": "v6-ssh", "ipProtocols": ["TCP"], "sourceAddresses": ["2001:db8:10::/64"], "destinationAddresses": ["10.10.5.0/24"],
                 "destinationPorts": ["22"]},
            ]),
        ]),
    ]  # fmt: skip
    groups = [ip_group("ipg-dns", ["10.10.8.8", "10.10.8.9"]), ip_group("ipg-servers", ["10.10.1.0/24", "10.10.2.10-10.10.2.20"])]
    return [base, child, base_groups, child_groups, groups]


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "data" / "azurefw_sample.json"
    target.write_text(json.dumps(sample(), indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {target}")
