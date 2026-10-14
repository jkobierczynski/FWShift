# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/terraform_aws_sample.json and terraform_azure_sample.json: made-up states, as

    terraform show -json        (of a state with the hashicorp/aws, and one with the hashicorp/azurerm resources)

prints them. What a refresh puts in a state is there too: the inline rules of a group repeat the rules of its separate
rule resources, and a network ACL's subnet_ids its associations. Every address is a documentation or private address,
every id is made up. Not taken from any real account or subscription.

    python3 tests/tools/make_terraform_samples.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

AWS = "registry.terraform.io/hashicorp/aws"
AZURERM = "registry.terraform.io/hashicorp/azurerm"
VPC = "vpc-0a1b2c3d4e5f63001"
SG = {"web": "sg-0a1b2c3d4e5f63021", "app": "sg-0a1b2c3d4e5f63022", "db": "sg-0a1b2c3d4e5f63023", "bastion": "sg-0a1b2c3d4e5f63024"}
SUBNET = {"web": ("subnet-0a1b2c3d4e5f63011", "10.30.1.0/24", "2001:db8:30:1::/64"), "app": ("subnet-0a1b2c3d4e5f63012", "10.30.2.0/24", ""),
          "db": ("subnet-0a1b2c3d4e5f63013", "10.30.3.0/24", ""), "mgmt": ("subnet-0a1b2c3d4e5f63014", "10.30.9.0/24", "")}  # fmt: skip
CORP = "pl-0a1b2c3d4e5f63061"


def resource(address: str, kind: str, name: str, provider: str, values: Dict[str, Any], index: Any = None,
             deposed: str = "") -> Dict[str, Any]:  # fmt: skip
    out: Dict[str, Any] = {"address": address, "mode": "managed", "type": kind, "name": name, "provider_name": provider,
                           "schema_version": 0, "values": values, "sensitive_values": {}}  # fmt: skip
    if index is not None:
        out["index"] = index
    if deposed:
        out["deposed_key"] = deposed
    return out


def aws(kind: str, name: str, values: Dict[str, Any], module: str = "", index: Any = None, deposed: str = "") -> Dict[str, Any]:
    address = (module + "." if module else "") + f"{kind}.{name}" + ("" if index is None else f"[{json.dumps(index)}]")
    return resource(address, kind, name, AWS, values, index, deposed)


def inline(protocol: str, low: int, high: int, cidrs: List[str] = (), six: List[str] = (), lists: List[str] = (),
           groups: List[str] = (), self_: bool = False, description: str = "") -> Dict[str, Any]:  # fmt: skip
    return {"description": description, "from_port": low, "to_port": high, "protocol": protocol, "cidr_blocks": list(cidrs),
            "ipv6_cidr_blocks": list(six), "prefix_list_ids": list(lists), "security_groups": list(groups), "self": self_}  # fmt: skip


def single(group: str, ident: str, protocol: str, low: Optional[int], high: Optional[int], cidr4: Optional[str] = None,
           cidr6: Optional[str] = None, plist: Optional[str] = None, ref: Optional[str] = None, description: Optional[str] = None) -> Dict[str, Any]:  # fmt: skip
    return {"id": ident, "security_group_rule_id": ident, "security_group_id": group, "ip_protocol": protocol, "from_port": low,
            "to_port": high, "cidr_ipv4": cidr4, "cidr_ipv6": cidr6, "prefix_list_id": plist, "referenced_security_group_id": ref,
            "description": description, "tags": None, "tags_all": {}}  # fmt: skip


def acl_entry(number: int, action: str, protocol: str, cidr: str = "", six: str = "", low: int = 0, high: int = 0,
              icmp_type: int = 0, icmp_code: int = 0) -> Dict[str, Any]:  # fmt: skip
    return {"rule_no": number, "action": action, "protocol": protocol, "cidr_block": cidr, "ipv6_cidr_block": six, "from_port": low,
            "to_port": high, "icmp_type": icmp_type, "icmp_code": icmp_code}  # fmt: skip


def aws_state() -> Dict[str, Any]:
    resources: List[Dict[str, Any]] = [
        aws("aws_vpc", "main", {"id": VPC, "cidr_block": "10.30.0.0/16", "ipv6_cidr_block": "2001:db8:30::/56", "tags": {"Name": "shop"}}),
    ]
    for name, (ident, cidr, six) in SUBNET.items():
        resources.append(aws("aws_subnet", name, {"id": ident, "vpc_id": VPC, "cidr_block": cidr, "ipv6_cidr_block": six,
                                                  "tags": {"Name": f"shop-{name}"}}))  # fmt: skip
    resources.append(aws("aws_ec2_managed_prefix_list", "corp", {
        "id": CORP, "name": "corp-offices", "address_family": "IPv4", "max_entries": 5,
        "entry": [{"cidr": "198.51.100.0/25", "description": "office a"}, {"cidr": "203.0.113.64/26", "description": "office b"}]}))
    # web: inline rules only, a prefix list and IPv6.
    resources.append(aws("aws_security_group", "web", {
        "id": SG["web"], "name": "shop-web", "description": "web tier", "vpc_id": VPC, "tags": {"Name": "shop-web"},
        "ingress": [inline("tcp", 443, 443, ["0.0.0.0/0"], ["::/0"], description="https"),
                    inline("tcp", 80, 80, ["0.0.0.0/0"], description="http"),
                    inline("tcp", 22, 22, groups=[SG["bastion"]], description="ssh from bastion"),
                    inline("icmp", 3, 4, ["10.0.0.0/8"], description="fragmentation needed")],
        "egress": [inline("tcp", 8080, 8080, groups=[SG["app"]], description="to app"),
                   inline("tcp", 443, 443, lists=[CORP], description="to the offices")]}))
    # app: separate rules (the new resources and a legacy one), echoed inline.
    resources.append(aws("aws_security_group", "app", {
        "id": SG["app"], "name": "shop-app", "description": "app tier", "vpc_id": VPC, "tags": {"Name": "shop-app"},
        "ingress": [inline("tcp", 8080, 8080, groups=[SG["web"]], description="from web"),
                    inline("tcp", 22, 22, groups=[SG["bastion"]], description="ssh"),
                    inline("-1", 0, 0, self_=True, description="cluster")],
        "egress": [inline("tcp", 5432, 5432, ["10.30.3.0/24"], description="to db"),
                   inline("udp", 53, 53, ["10.30.0.2/32"], description="dns")]}))
    resources.append(aws("aws_vpc_security_group_ingress_rule", "app_from_web",
                         single(SG["app"], "sgr-0a1b2c3d4e5f63041", "tcp", 8080, 8080, ref=SG["web"], description="from web")))
    resources.append(aws("aws_vpc_security_group_ingress_rule", "app_ssh",
                         single(SG["app"], "sgr-0a1b2c3d4e5f63042", "tcp", 22, 22, ref=SG["bastion"], description="ssh")))
    resources.append(aws("aws_security_group_rule", "app_cluster", {
        "id": "sgrule-3001", "type": "ingress", "security_group_id": SG["app"], "protocol": "-1", "from_port": 0, "to_port": 0,
        "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [], "self": True, "source_security_group_id": None,
        "description": "cluster"}))
    resources.append(aws("aws_vpc_security_group_egress_rule", "app_db",
                         single(SG["app"], "sgr-0a1b2c3d4e5f63043", "6", 5432, 5432, cidr4="10.30.3.0/24", description="to db")))
    resources.append(aws("aws_vpc_security_group_egress_rule", "app_dns",
                         single(SG["app"], "sgr-0a1b2c3d4e5f63044", "udp", 53, 53, cidr4="10.30.0.2/32", description="dns")))
    # db: in a module, with rules made by count.
    resources.append(aws("aws_security_group", "db", {
        "id": SG["db"], "name": "shop-db", "description": "database", "vpc_id": VPC, "tags": {"Name": "shop-db"},
        "ingress": [inline("tcp", 5432, 5432, ["10.30.2.0/24"], description="postgres"),
                    inline("tcp", 5432, 5432, ["10.30.9.0/24"], description="postgres")], "egress": []}, module="module.database"))
    for index, cidr in enumerate(("10.30.2.0/24", "10.30.9.0/24")):
        resources.append(aws("aws_vpc_security_group_ingress_rule", "postgres", single(
            SG["db"], f"sgr-0a1b2c3d4e5f6305{index}", "tcp", 5432, 5432, cidr4=cidr, description="postgres"),
            module="module.database", index=index))  # fmt: skip
    # bastion: legacy rules with a cross-account group and all of ICMP.
    resources.append(aws("aws_security_group", "bastion", {
        "id": SG["bastion"], "name": "shop-bastion", "description": "jump host", "vpc_id": VPC, "tags": {},
        "ingress": [inline("tcp", 22, 22, ["198.51.100.0/24"], ["2001:db8:900::/48"], description="admins"),
                    inline("icmp", -1, -1, ["198.51.100.0/24"], description="")],
        "egress": [inline("-1", 0, 0, ["10.30.0.0/16"], description="inside")]}))
    resources.append(aws("aws_security_group_rule", "bastion_admins", {
        "id": "sgrule-3002", "type": "ingress", "security_group_id": SG["bastion"], "protocol": "tcp", "from_port": 22, "to_port": 22,
        "cidr_blocks": ["198.51.100.0/24"], "ipv6_cidr_blocks": ["2001:db8:900::/48"], "prefix_list_ids": [], "self": False,
        "source_security_group_id": None, "description": "admins"}))
    resources.append(aws("aws_security_group_rule", "bastion_audit", {
        "id": "sgrule-3003", "type": "ingress", "security_group_id": SG["bastion"], "protocol": "tcp", "from_port": 22, "to_port": 22,
        "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [], "self": False,
        "source_security_group_id": "444455556666/sg-0f9e8d7c6b5a43001", "description": "audit account"}))
    # The network ACL of the database subnet, with a separate entry and association.
    resources.append(aws("aws_network_acl", "db", {
        "id": "acl-0a1b2c3d4e5f63031", "vpc_id": VPC, "subnet_ids": [SUBNET["db"][0]], "tags": {"Name": "shop-db"},
        "ingress": [acl_entry(100, "deny", "6", "10.30.1.0/24", low=0, high=65535),
                    acl_entry(110, "allow", "6", "10.30.0.0/16", low=5432, high=5432),
                    acl_entry(120, "allow", "6", "0.0.0.0/0", low=1024, high=65535),
                    acl_entry(130, "allow", "1", "10.30.0.0/16", icmp_type=-1, icmp_code=-1)],
        "egress": [acl_entry(100, "allow", "-1", "0.0.0.0/0")]}))
    resources.append(aws("aws_network_acl_association", "db", {"id": "aclassoc-3001", "network_acl_id": "acl-0a1b2c3d4e5f63031",
                                                               "subnet_id": SUBNET["db"][0]}))  # fmt: skip
    # The members: instances and an interface.
    resources.append(aws("aws_instance", "web", {
        "id": "i-0a1b2c3d4e5f63051", "subnet_id": SUBNET["web"][0], "private_ip": "10.30.1.10", "secondary_private_ips": [],
        "ipv6_addresses": ["2001:db8:30:1::10"], "public_ip": "192.0.2.10", "vpc_security_group_ids": [SG["web"]],
        "primary_network_interface_id": "eni-0a1b2c3d4e5f63071", "source_dest_check": True}))  # fmt: skip
    resources.append(aws("aws_instance", "app", {
        "id": f"i-0a1b2c3d4e5f6305{2}", "subnet_id": SUBNET["app"][0], "private_ip": "10.30.2.20", "secondary_private_ips": ["10.30.2.21"],
        "ipv6_addresses": [], "public_ip": "", "vpc_security_group_ids": [SG["app"]], "primary_network_interface_id": "eni-0a1b2c3d4e5f63072"}))
    resources.append(aws("aws_network_interface", "db", {
        "id": "eni-0a1b2c3d4e5f63073", "subnet_id": SUBNET["db"][0], "private_ip": "10.30.3.30", "private_ips": ["10.30.3.30"],
        "security_groups": [SG["db"]], "ipv6_addresses": [], "interface_type": "interface", "source_dest_check": True}, module="module.database"))
    resources.append(aws("aws_instance", "bastion", {
        "id": "i-0a1b2c3d4e5f63054", "subnet_id": SUBNET["mgmt"][0], "private_ip": "10.30.9.5", "secondary_private_ips": [],
        "ipv6_addresses": [], "public_ip": "192.0.2.5", "vpc_security_group_ids": [SG["bastion"]],
        "primary_network_interface_id": "eni-0a1b2c3d4e5f63074"}))
    # Left out by FWShift: a deposed object, a data source, a firewall it does not read.
    resources.append(aws("aws_security_group", "web", {"id": "sg-0a1b2c3d4e5f63099", "name": "shop-web-old", "vpc_id": VPC,
                                                       "ingress": [inline("-1", 0, 0, ["0.0.0.0/0"])], "egress": []}, deposed="00000001"))  # fmt: skip
    resources.append({"address": "data.aws_caller_identity.current", "mode": "data", "type": "aws_caller_identity", "name": "current",
                      "provider_name": AWS, "schema_version": 0, "values": {"account_id": "111122223333"}, "sensitive_values": {}})  # fmt: skip
    resources.append(aws("aws_networkfirewall_firewall", "edge", {"id": "arn:aws:network-firewall:eu-west-1:111122223333:firewall/edge",
                                                                  "name": "edge", "vpc_id": VPC}))  # fmt: skip
    root = [r for r in resources if not r["address"].startswith("module.")]
    child = [r for r in resources if r["address"].startswith("module.")]
    return {"format_version": "1.0", "terraform_version": "1.13.4",
            "values": {"root_module": {"resources": root, "child_modules": [{"address": "module.database", "resources": child}]}}}  # fmt: skip


SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-shop/providers/Microsoft.Network"


def azurerm(kind: str, name: str, values: Dict[str, Any]) -> Dict[str, Any]:
    return resource(f"{kind}.{name}", kind, name, AZURERM, values)


def security_rule(name: str, priority: int, direction: str, access: str, protocol: str, source: Any = "*", destination: Any = "*",
                  ports: Any = "*", source_asgs: List[str] = (), destination_asgs: List[str] = (), description: str = "") -> Dict[str, Any]:  # fmt: skip
    out: Dict[str, Any] = {"name": name, "description": description, "priority": priority, "direction": direction, "access": access,
                           "protocol": protocol, "source_port_range": "*", "source_port_ranges": [],
                           "destination_port_range": ports if isinstance(ports, str) else "",
                           "destination_port_ranges": [] if isinstance(ports, str) else list(ports),
                           "source_address_prefix": source if isinstance(source, str) else "",
                           "source_address_prefixes": [] if isinstance(source, str) else list(source),
                           "destination_address_prefix": destination if isinstance(destination, str) else "",
                           "destination_address_prefixes": [] if isinstance(destination, str) else list(destination),
                           "source_application_security_group_ids": list(source_asgs),
                           "destination_application_security_group_ids": list(destination_asgs)}  # fmt: skip
    if source_asgs:
        out["source_address_prefix"] = ""
    if destination_asgs:
        out["destination_address_prefix"] = ""
    return out


def azure_state() -> Dict[str, Any]:
    vnet = f"{SUB}/virtualNetworks/vnet-shop"
    subnets = {"web": "10.40.1.0/24", "app": "10.40.2.0/24", "db": "10.40.3.0/24"}
    nsg = {name: f"{SUB}/networkSecurityGroups/nsg-{name}" for name in ("web", "app", "db")}
    asg = {name: f"{SUB}/applicationSecurityGroups/asg-{name}" for name in ("web", "app")}
    resources: List[Dict[str, Any]] = [
        azurerm("azurerm_virtual_network", "shop", {"id": vnet, "name": "vnet-shop", "resource_group_name": "rg-shop",
                                                    "address_space": ["10.40.0.0/16", "2001:db8:40::/48"], "subnet": []}),  # fmt: skip
    ]
    for name, prefix in subnets.items():
        resources.append(azurerm("azurerm_subnet", name, {"id": f"{vnet}/subnets/{name}", "name": name, "resource_group_name": "rg-shop",
                                                          "virtual_network_name": "vnet-shop", "address_prefixes": [prefix]}))  # fmt: skip
    for name, ident in asg.items():
        resources.append(azurerm("azurerm_application_security_group", name, {"id": ident, "name": f"asg-{name}", "resource_group_name": "rg-shop"}))
    resources.append(azurerm("azurerm_network_security_group", "web", {
        "id": nsg["web"], "name": "nsg-web", "resource_group_name": "rg-shop", "location": "westeurope", "tags": {},
        "security_rule": [
            security_rule("https-in", 100, "Inbound", "Allow", "Tcp", "Internet", ["10.40.1.0/24", "2001:db8:40:1::/64"], "443"),
            security_rule("block-doc", 110, "Inbound", "Deny", "*", ["198.51.100.0/24", "203.0.113.0/24"], "*", "*", description="blocked ranges"),
            security_rule("ssh-admin", 120, "Inbound", "Allow", "Tcp", "192.0.2.0/28", "*", "22"),
            security_rule("to-app", 100, "Outbound", "Allow", "Tcp", "*", "*", "8080", destination_asgs=[asg["app"]]),
            security_rule("no-internet", 4000, "Outbound", "Deny", "*", "*", "Internet", "*"),
        ]}))  # fmt: skip
    resources.append(azurerm("azurerm_network_security_group", "app", {
        "id": nsg["app"], "name": "nsg-app", "resource_group_name": "rg-shop", "location": "westeurope", "tags": {},
        "security_rule": [
            security_rule("from-web", 100, "Inbound", "Allow", "Tcp", "*", "*", ["8080", "8443"], source_asgs=[asg["web"]]),
            security_rule("icmp-vnet", 110, "Inbound", "Allow", "Icmp", "VirtualNetwork", "VirtualNetwork", "*"),
            security_rule("deny-rest", 4096, "Inbound", "Deny", "*", "*", "*", "*"),
        ]}))  # fmt: skip
    db_rules = [security_rule("postgres-from-app", 200, "Inbound", "Allow", "Tcp", "10.40.2.0/24", "10.40.3.0/24", "5432"),
                security_rule("deny-web", 210, "Inbound", "Deny", "*", "10.40.1.0/24", "*", "*")]
    resources.append(azurerm("azurerm_network_security_group", "db", {
        "id": nsg["db"], "name": "nsg-db", "resource_group_name": "rg-shop", "location": "westeurope", "tags": {}, "security_rule": db_rules}))
    for rule in db_rules:  # (the separate resources the inline rules above repeat)
        values = dict(rule, id=f"{nsg['db']}/securityRules/{rule['name']}", resource_group_name="rg-shop", network_security_group_name="nsg-db")
        resources.append(azurerm("azurerm_network_security_rule", rule["name"].replace("-", "_"), values))
    for name in subnets:
        resources.append(azurerm("azurerm_subnet_network_security_group_association", name, {
            "id": f"{vnet}/subnets/{name}", "subnet_id": f"{vnet}/subnets/{name}", "network_security_group_id": nsg[name]}))
    for name, address, group in (("web1", "10.40.1.4", "web"), ("app1", "10.40.2.4", "app"), ("app2", "10.40.2.5", "app")):
        nic = f"{SUB}/networkInterfaces/{name}-nic"
        subnet = "web" if group == "web" else "app"
        resources.append(azurerm("azurerm_network_interface", name, {
            "id": nic, "name": f"{name}-nic", "resource_group_name": "rg-shop", "private_ip_address": address,
            "ip_configuration": [{"name": "ipconfig1", "subnet_id": f"{vnet}/subnets/{subnet}", "private_ip_address": address,
                                  "private_ip_address_allocation": "Static", "primary": True}]}))  # fmt: skip
        resources.append(azurerm("azurerm_network_interface_application_security_group_association", name, {
            "id": f"{nic}|{asg[group]}", "network_interface_id": nic, "application_security_group_id": asg[group]}))
    resources.append(azurerm("azurerm_firewall", "hub", {"id": f"{SUB}/azureFirewalls/fw-hub", "name": "fw-hub"}))
    return {"format_version": "1.0", "terraform_version": "1.13.4", "values": {"root_module": {"resources": resources}}}


def main() -> None:
    folder = Path(__file__).resolve().parent.parent / "data"
    for name, document in (("terraform_aws_sample.json", aws_state()), ("terraform_azure_sample.json", azure_state())):
        (folder / name).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {folder / name}")


if __name__ == "__main__":
    main()
