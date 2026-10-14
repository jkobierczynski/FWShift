# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/meraki_sample.json: the answers of the Meraki Dashboard API (v1) for a made-up MX network at a
small plant, bundled as the commands of the manual bundle them (each answer under the name of its endpoint).

VLANs (one with an IPv6 prefix), a static route, outbound layer 3 rules with VLAN objects, policy objects and their
groups, a host name and a port range, the fixed default rule, layer 7 rules, port forwarding, 1:1 NAT and 1:many NAT,
uplinks, a group policy, cellular and site-to-site VPN rules. Every address is a documentation or private address; the
identifiers are invented; nothing is taken from a real network.

    python3 tests/tools/make_meraki_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path

NETWORK = "N_100000000000000001"
DEFAULT = {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcPort": "Any", "srcCidr": "Any", "destPort": "Any",
           "destCidr": "Any", "syslogEnabled": False}  # fmt: skip


def rule(comment: str, policy: str, protocol: str, src: str, dst: str, dport: str = "Any", sport: str = "Any", log: bool = False) -> dict:
    return {"comment": comment, "policy": policy, "protocol": protocol, "srcPort": sport, "srcCidr": src, "destPort": dport,
            "destCidr": dst, "syslogEnabled": log}  # fmt: skip


BUNDLE = {
    "fwshift": "meraki-mx",
    "network": {"id": NETWORK, "organizationId": "100001", "name": "plant-a", "productTypes": ["appliance", "switch"],
                "isBoundToConfigTemplate": False},
    "applianceSettings": {"deploymentMode": "routed", "clientTrackingMethod": "MAC address"},
    "vlansSettings": {"vlansEnabled": True},
    "vlans": [
        {"id": 10, "name": "office", "subnet": "10.10.10.0/24", "applianceIp": "10.10.10.1",
         "ipv6": {"enabled": True, "prefixAssignments": [{"autonomous": False, "staticPrefix": "2001:db8:10::/64",
                                                          "staticApplianceIp6": "2001:db8:10::1"}]}},
        {"id": 20, "name": "servers", "subnet": "10.10.20.0/24", "applianceIp": "10.10.20.1", "groupPolicyId": "101"},
        {"id": "30", "name": "ot-cell", "subnet": "10.10.30.0/24", "applianceIp": "10.10.30.1"},
    ],
    "staticRoutes": [
        {"id": "d0000000-0000-4000-8000-000000000001", "ipVersion": 4, "enabled": True, "name": "plc-ring", "subnet": "172.16.40.0/24",
         "gatewayIp": "10.10.30.254", "gatewayVlanId": 30},
    ],
    "l3FirewallRules": {"rules": [
        rule("office to servers web", "allow", "tcp", "VLAN(10).*", "10.10.20.0/24", "80,443"),
        rule("historian", "allow", "tcp", "10.10.20.15/32", "VLAN(30).*,172.16.40.0/24", "4840", log=True),
        rule("eng ws to plc", "allow", "tcp", "OBJ(4003)", "GRP(5002)", "102", log=True),
        rule("ot cell isolated", "deny", "any", "Any", "VLAN(30).*,172.16.40.0/24", log=True),
        rule("ot no internet", "deny", "any", "10.10.30.0/24,172.16.40.0/24", "Any", log=True),
        rule("block update site", "deny", "tcp", "10.10.10.0/24", "updates.example.com", "443"),
        rule("dns to servers", "allow", "udp", "Any", "VLAN(20).53", "53"),
        rule("ping servers", "allow", "icmp", "VLAN(10).*", "VLAN(20).*"),
        rule("office ipv6 out", "allow", "any", "2001:db8:10::/64", "Any"),
        rule("passive ftp", "allow", "tcp", "10.10.10.0/24", "VLAN(20).21", "50000-50100"),
        rule("bad ports", "allow", "tcp", "10.10.10.0/24", "Any", "1024-5000,5004"),
        DEFAULT,
    ]},
    "l7FirewallRules": {"rules": [
        {"policy": "deny", "type": "applicationCategory", "value": {"id": "meraki:layer7/category/24", "name": "Advertising"}},
        {"policy": "deny", "type": "port", "value": "23"},
        {"policy": "deny", "type": "ipRange", "value": "198.51.100.0/24"},
    ]},
    "firewalledServices": [{"service": "ICMP", "access": "unrestricted"}, {"service": "web", "access": "blocked"},
                           {"service": "SNMP", "access": "blocked"}],
    "portForwardingRules": {"rules": [
        {"name": "vpn-portal", "lanIp": "10.10.20.30", "uplink": "internet1", "protocol": "tcp", "publicPort": "8443", "localPort": "443",
         "allowedIps": ["198.51.100.0/24"]},
    ]},
    "oneToOneNatRules": {"rules": [
        {"name": "mail", "publicIp": "203.0.113.25", "lanIp": "10.10.20.25", "uplink": "internet1",
         "allowedInbound": [{"protocol": "tcp", "destinationPorts": ["25"], "allowedIps": ["any"]},
                            {"protocol": "icmp-ping", "destinationPorts": ["any"], "allowedIps": ["192.0.2.0/24"]}]},
    ]},
    "oneToManyNatRules": {"rules": [
        {"publicIp": "203.0.113.30", "uplink": "internet1",
         "portRules": [{"name": "scada-view", "protocol": "tcp", "publicPort": "9443", "localIp": "10.10.20.40", "localPort": "443",
                        "allowedIps": ["192.0.2.10/32"]}]},
    ]},
    "inboundFirewallRules": {"rules": [DEFAULT | {"policy": "deny"}], "syslogDefaultRule": False},
    "cellularFirewallRules": {"rules": [rule("cell: no ot", "deny", "any", "10.10.30.0/24", "Any"), DEFAULT]},
    "policyObjects": [
        {"id": "4003", "name": "eng-ws", "category": "network", "type": "cidr", "cidr": "10.10.10.50/32", "groupIds": []},
        {"id": "4004", "name": "plc-1", "category": "network", "type": "cidr", "cidr": "172.16.40.11/32", "groupIds": ["5002"]},
        {"id": "4005", "name": "plc-2", "category": "network", "type": "cidr", "cidr": "172.16.40.12/32", "groupIds": ["5002"]},
    ],
    "policyObjectsGroups": [{"id": "5002", "name": "plcs", "category": "NetworkObjectGroup", "objectIds": [4004, 4005]}],
    "groupPolicies": [
        {"groupPolicyId": "101", "name": "servers-restricted",
         "firewallAndTrafficShaping": {"settings": "custom", "l3FirewallRules": [
             {"comment": "only https out", "policy": "allow", "protocol": "tcp", "destPort": "443", "destCidr": "Any"}],
             "l7FirewallRules": [], "trafficShapingRules": []}},
    ],
    "uplinkStatuses": [{"networkId": NETWORK, "serial": "Q000-0000-0001", "model": "MX68",
                        "uplinks": [{"interface": "wan1", "status": "active", "ip": "203.0.113.2", "gateway": "203.0.113.1",
                                     "publicIp": "203.0.113.2"}]}],
    "uplinksNat": [{"networkId": NETWORK, "uplinks": [{"interface": "wan1", "nat": {"enabled": True}}]}],
    "vpnFirewallRules": {"rules": [rule("vpn: no ot", "deny", "any", "10.10.30.0/24", "Any"), DEFAULT]},
}


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "data" / "meraki_sample.json"
    path.write_text(json.dumps(BUNDLE, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
