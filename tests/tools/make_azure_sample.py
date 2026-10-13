# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/azure_sample.json: made-up network security groups, as the Azure CLI prints them, in one JSON array:

    az network nsg list -g rg-shop -o json
    az network nic list -g rg-shop -o json
    az network vnet list -g rg-shop -o json
    az network list-service-tags --location westeurope -o json   (cut down to the tags the rules name)

Every address is a documentation or private address, every id is made up (subscription 00000000-...). Not taken from
any real subscription.

    python3 tests/tools/make_azure_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-shop/providers/Microsoft.Network"
DEFAULTS = [
    ("AllowVnetInBound", "Inbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow", "Allow inbound traffic from all VMs in VNET"),
    ("AllowAzureLoadBalancerInBound", "Inbound", 65001, "AzureLoadBalancer", "*", "Allow", "Allow inbound traffic from azure load balancer"),
    ("DenyAllInBound", "Inbound", 65500, "*", "*", "Deny", "Deny all inbound traffic"),
    ("AllowVnetOutBound", "Outbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow", "Allow outbound traffic from all VMs to all VMs in VNET"),
    ("AllowInternetOutBound", "Outbound", 65001, "*", "Internet", "Allow", "Allow outbound traffic from all VMs to Internet"),
    ("DenyAllOutBound", "Outbound", 65500, "*", "*", "Deny", "Deny all outbound traffic"),
]


def side(prefix: str, value: Any) -> Dict[str, Any]:
    """One side of a rule as the CLI prints it: the singular field, or the plural list, or application security groups."""
    if isinstance(value, dict):
        return {f"{prefix}ApplicationSecurityGroups": [{"id": f"{SUB}/applicationSecurityGroups/{value['asg']}", "resourceGroup": "rg-shop"}],
                f"{prefix}AddressPrefixes": []}
    if isinstance(value, list):
        return {f"{prefix}AddressPrefixes": value}
    return {f"{prefix}AddressPrefix": value, f"{prefix}AddressPrefixes": []}


def ports(prefix: str, value: Any) -> Dict[str, Any]:
    if isinstance(value, list):
        return {f"{prefix}PortRanges": value}
    return {f"{prefix}PortRange": value, f"{prefix}PortRanges": []}


def rule(nsg: str, name: str, direction: str, priority: int, access: str, protocol: str, source: Any, destination: Any,
         destination_ports: Any = "*", source_ports: Any = "*", description: str = "", default: bool = False) -> Dict[str, Any]:  # fmt: skip
    kind = "defaultSecurityRules" if default else "securityRules"
    out: Dict[str, Any] = {"access": access, "direction": direction, "priority": priority, "protocol": protocol, "name": name,
                           "id": f"{SUB}/networkSecurityGroups/{nsg}/{kind}/{name}", "provisioningState": "Succeeded",
                           "resourceGroup": "rg-shop", "type": f"Microsoft.Network/networkSecurityGroups/{kind}"}  # fmt: skip
    if description:
        out["description"] = description
    out.update(side("source", source))
    out.update(side("destination", destination))
    out.update(ports("source", source_ports))
    out.update(ports("destination", destination_ports))
    return out


def nsg(name: str, rules: List[Dict[str, Any]], subnets: List[str] = (), interfaces: List[str] = ()) -> Dict[str, Any]:
    defaults = [rule(name, n, d, p, a, "*", s, t, description=text, default=True) for n, d, p, s, t, a, text in DEFAULTS]
    return {
        "id": f"{SUB}/networkSecurityGroups/{name}", "name": name, "location": "westeurope", "resourceGroup": "rg-shop",
        "type": "Microsoft.Network/networkSecurityGroups", "provisioningState": "Succeeded", "flushConnection": False,
        "resourceGuid": "22222222-2222-2222-2222-222222222222", "tags": {"env": "shop"},
        "securityRules": rules, "defaultSecurityRules": defaults,
        "subnets": [{"id": f"{SUB}/virtualNetworks/vnet-shop/subnets/{s}", "resourceGroup": "rg-shop"} for s in subnets],
        "networkInterfaces": [{"id": f"{SUB}/networkInterfaces/{i}", "resourceGroup": "rg-shop"} for i in interfaces],
    }  # fmt: skip


def groups() -> List[Dict[str, Any]]:
    web = nsg("nsg-web", [
        rule("nsg-web", "Allow-HTTPS", "Inbound", 100, "Allow", "Tcp", "*", {"asg": "asg-web"}, ["443", "80"], description="Web from anywhere"),
        rule("nsg-web", "Allow-SSH-Admins", "Inbound", 110, "Allow", "Tcp", ["198.51.100.0/24", "192.0.2.128/25"], "10.30.1.0/24", "22"),
        rule("nsg-web", "Allow-HTTPS-v6", "Inbound", 120, "Allow", "Tcp", "2001:db8:ff::/48", "*", "443"),
        rule("nsg-web", "Deny-Partner", "Inbound", 130, "Deny", "*", "203.0.113.0/24", "*", description="Old partner range"),
        rule("nsg-web", "Allow-Ping-VNet", "Inbound", 140, "Allow", "Icmp", "VirtualNetwork", "*"),
        rule("nsg-web", "Allow-App-Out", "Outbound", 100, "Allow", "Tcp", "*", "10.30.2.0/24", "8443"),
        rule("nsg-web", "Allow-Storage", "Outbound", 110, "Allow", "Tcp", "VirtualNetwork", "Storage.WestEurope", "443"),
        rule("nsg-web", "Deny-Internet", "Outbound", 4000, "Deny", "*", "*", "Internet"),
    ], subnets=["snet-web"])
    app = nsg("nsg-app", [
        rule("nsg-app", "Allow-From-Web", "Inbound", 100, "Allow", "Tcp", "10.30.1.0/24", "*", "8443"),
        rule("nsg-app", "Allow-Esp-Partner", "Inbound", 110, "Allow", "Esp", "198.51.100.40", "10.30.2.10"),
        rule("nsg-app", "Allow-Probe", "Inbound", 120, "Allow", "Tcp", "AzureLoadBalancer", "*", "8443"),
        rule("nsg-app", "Deny-VNet", "Inbound", 200, "Deny", "*", "VirtualNetwork", "*"),
        rule("nsg-app", "Allow-Db", "Outbound", 100, "Allow", "Tcp", "*", {"asg": "asg-db"}, "1433"),
        rule("nsg-app", "Allow-Sql", "Outbound", 110, "Allow", "Tcp", "*", "Sql.WestEurope", "1433"),
        rule("nsg-app", "Allow-Dns", "Outbound", 120, "Allow", "Udp", "*", "10.30.0.4", "53", source_ports="1024-65535"),
        rule("nsg-app", "Deny-Out", "Outbound", 4000, "Deny", "*", "*", "*"),
    ], subnets=["snet-app"])
    db = nsg("nsg-db", [
        rule("nsg-db", "Allow-Sql-From-App", "Inbound", 100, "Allow", "Tcp", "10.30.2.0/24", {"asg": "asg-db"}, "1433"),
        rule("nsg-db", "Allow-Old-Gre", "Inbound", 110, "Allow", "Ah", "10.30.9.0/24", "*", description="AH from the management subnet"),
    ], interfaces=["nic-db1"])
    return [web, app, db]


def interfaces() -> List[Dict[str, Any]]:
    def nic(name: str, subnet: str, address: str, asgs: List[str], six: str = "", own: str = "") -> Dict[str, Any]:
        configs = [{"name": "ipconfig1", "privateIPAddress": address, "privateIPAddressVersion": "IPv4",
                    "privateIPAllocationMethod": "Static", "primary": True,
                    "subnet": {"id": f"{SUB}/virtualNetworks/vnet-shop/subnets/{subnet}", "resourceGroup": "rg-shop"},
                    "applicationSecurityGroups": [{"id": f"{SUB}/applicationSecurityGroups/{a}", "resourceGroup": "rg-shop"} for a in asgs]}]  # fmt: skip
        if six:
            configs.append({"name": "ipconfig6", "privateIPAddress": six, "privateIPAddressVersion": "IPv6", "primary": False,
                            "subnet": {"id": f"{SUB}/virtualNetworks/vnet-shop/subnets/{subnet}", "resourceGroup": "rg-shop"},
                            "applicationSecurityGroups": [{"id": f"{SUB}/applicationSecurityGroups/{a}", "resourceGroup": "rg-shop"} for a in asgs]})  # fmt: skip
        out: Dict[str, Any] = {"id": f"{SUB}/networkInterfaces/{name}", "name": name, "location": "westeurope", "resourceGroup": "rg-shop",
                               "type": "Microsoft.Network/networkInterfaces", "ipConfigurations": configs}  # fmt: skip
        if own:
            out["networkSecurityGroup"] = {"id": f"{SUB}/networkSecurityGroups/{own}", "resourceGroup": "rg-shop"}
        return out

    return [
        nic("nic-web1", "snet-web", "10.30.1.10", ["asg-web"], "2001:db8:30:1::10"),
        nic("nic-web2", "snet-web", "10.30.1.11", ["asg-web"], "2001:db8:30:1::11"),
        nic("nic-app1", "snet-app", "10.30.2.10", []),
        nic("nic-db1", "snet-db", "10.30.3.20", ["asg-db"], own="nsg-db"),
    ]


def vnet() -> Dict[str, Any]:
    subnets = []
    for name, cidr, six, group in (("snet-web", "10.30.1.0/24", "2001:db8:30:1::/64", "nsg-web"), ("snet-app", "10.30.2.0/24", "", "nsg-app"),
                                   ("snet-db", "10.30.3.0/24", "", ""), ("snet-mgmt", "10.30.9.0/24", "", "")):  # fmt: skip
        item: Dict[str, Any] = {"id": f"{SUB}/virtualNetworks/vnet-shop/subnets/{name}", "name": name, "resourceGroup": "rg-shop",
                                "type": "Microsoft.Network/virtualNetworks/subnets"}  # fmt: skip
        if six:
            item["addressPrefixes"] = [cidr, six]
        else:
            item["addressPrefix"] = cidr
        if group:
            item["networkSecurityGroup"] = {"id": f"{SUB}/networkSecurityGroups/{group}", "resourceGroup": "rg-shop"}
        subnets.append(item)
    return {"id": f"{SUB}/virtualNetworks/vnet-shop", "name": "vnet-shop", "location": "westeurope", "resourceGroup": "rg-shop",
            "type": "Microsoft.Network/virtualNetworks", "addressSpace": {"addressPrefixes": ["10.30.0.0/16", "2001:db8:30::/56"]},
            "subnets": subnets}  # fmt: skip


def tags() -> Dict[str, Any]:
    def tag(name: str, prefixes: List[str]) -> Dict[str, Any]:
        return {"name": name, "id": name, "properties": {"changeNumber": "7", "region": "westeurope", "systemService": name.split(".")[0],
                                                         "addressPrefixes": prefixes}}  # fmt: skip

    return {"name": "public", "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Network/serviceTags/public",
            "type": "Microsoft.Network/serviceTags", "changeNumber": "63", "cloud": "Public",
            "values": [tag("Storage.WestEurope", ["203.0.113.64/26", "2001:db8:ee::/48"]), tag("Sql.WestEurope", ["203.0.113.128/27"])]}  # fmt: skip


def sample() -> List[Any]:
    return [groups(), interfaces(), [vnet()], tags()]


def main() -> None:
    data = Path(__file__).resolve().parent.parent / "data"
    (data / "azure_sample.json").write_text(json.dumps(sample(), indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
