# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/aws_sample.json: a made-up VPC, as the AWS CLI answers for it, in one JSON array:

    aws ec2 describe-security-groups --filters Name=vpc-id,Values=VPC --output json
    aws ec2 describe-network-interfaces --filters Name=vpc-id,Values=VPC --output json
    aws ec2 describe-vpcs --vpc-ids VPC --output json
    aws ec2 describe-subnets --filters Name=vpc-id,Values=VPC --output json
    aws ec2 describe-network-acls --filters Name=vpc-id,Values=VPC --output json
    aws ec2 describe-managed-prefix-lists --output json
    aws ec2 get-managed-prefix-list-entries --prefix-list-id PL   (wrapped as {"PrefixListId": PL, "Entries": [...]})

Every address is a documentation or private address, every id is made up. Not taken from any real account.

    python3 tests/tools/make_aws_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

VPC = "vpc-0a1b2c3d4e5f60789"
OWNER = "111122223333"
SG = {"default": "sg-0d0000000000000d1", "web": "sg-0e0000000000000e1", "app": "sg-0a0000000000000a1", "db": "sg-0db00000000000db1",
      "bastion": "sg-0b0000000000000b1", "monitoring": "sg-0c0000000000000c1", "legacy": "sg-0f0000000000000f1"}  # fmt: skip
CORP = "pl-0c0000000000000c1"
S3 = "pl-6da54004"
SUBNETS = {"public": ("subnet-0100000000000001a", "10.20.1.0/24", "2001:db8:20:1::/64"),
           "app": ("subnet-0200000000000002a", "10.20.2.0/24", "2001:db8:20:2::/64"),
           "db": ("subnet-0300000000000003a", "10.20.3.0/24", ""),
           "mgmt": ("subnet-0900000000000009a", "10.20.9.0/24", "")}  # fmt: skip


def perm(protocol: str, low: int = -1, high: int = -1, cidrs: List[str] = (), lists: List[str] = (),
         groups: List[str] = (), descriptions: str = "") -> Dict[str, Any]:  # fmt: skip
    out: Dict[str, Any] = {"IpProtocol": protocol}
    if protocol != "-1":
        out["FromPort"], out["ToPort"] = low, high
    note = {"Description": descriptions} if descriptions else {}
    out["IpRanges"] = [dict({"CidrIp": c}, **note) for c in cidrs if ":" not in c]
    out["Ipv6Ranges"] = [dict({"CidrIpv6": c}, **note) for c in cidrs if ":" in c]
    out["PrefixListIds"] = [dict({"PrefixListId": p}, **note) for p in lists]
    out["UserIdGroupPairs"] = [dict({"GroupId": g, "UserId": OWNER}, **note) for g in groups]
    return out


def everything() -> List[Dict[str, Any]]:
    return [perm("-1", cidrs=["0.0.0.0/0", "::/0"])]


def group(name: str, description: str, inbound: List[Dict[str, Any]], outbound: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"GroupId": SG[name], "GroupName": name if name == "default" else f"{name}-sg", "Description": description, "VpcId": VPC,
            "OwnerId": OWNER, "SecurityGroupArn": f"arn:aws:ec2:eu-west-1:{OWNER}:security-group/{SG[name]}",
            "IpPermissions": inbound, "IpPermissionsEgress": outbound, "Tags": [{"Key": "Name", "Value": name}]}  # fmt: skip


def groups() -> List[Dict[str, Any]]:
    peer = perm("tcp", 5432, 5432, descriptions="reporting VPC")
    peer["UserIdGroupPairs"] = [{"GroupId": "sg-0bbbbbbbbbbbbbbb0", "UserId": "444455556666", "VpcId": "vpc-0peer000000000000",
                                 "VpcPeeringConnectionId": "pcx-0123456789abcdef0", "PeeringStatus": "active",
                                 "Description": "reporting VPC"}]  # fmt: skip
    return [
        group("default", "default VPC security group", [perm("-1", groups=[SG["default"]])], everything()),
        group("web", "Web servers behind the internet", [
            perm("tcp", 443, 443, cidrs=["0.0.0.0/0", "::/0"], descriptions="HTTPS from anywhere"),
            perm("tcp", 80, 80, cidrs=["0.0.0.0/0", "::/0"], descriptions="HTTP, redirected"),
            perm("tcp", 22, 22, groups=[SG["bastion"]], descriptions="SSH from the bastion"),
            perm("icmp", 8, -1, groups=[SG["monitoring"]], descriptions="ping from monitoring"),
        ], [
            perm("tcp", 8443, 8443, groups=[SG["app"]], descriptions="to the application"),
            perm("tcp", 443, 443, cidrs=["0.0.0.0/0", "::/0"], descriptions="updates"),
            perm("udp", 53, 53, cidrs=["10.20.0.2/32"], descriptions="Amazon DNS"),
        ]),
        group("app", "Application servers", [
            perm("tcp", 8443, 8443, groups=[SG["web"]], descriptions="from the web servers"),
            perm("tcp", 22, 22, groups=[SG["bastion"]], descriptions="SSH from the bastion"),
            perm("icmpv6", -1, -1, cidrs=["2001:db8:20::/56"], descriptions="ICMPv6 inside the VPC"),
        ], [
            perm("tcp", 5432, 5432, groups=[SG["db"]], descriptions="to the database"),
            perm("tcp", 443, 443, lists=[S3], descriptions="to S3"),
        ]),
        group("db", "Database", [
            perm("tcp", 5432, 5432, groups=[SG["app"]], descriptions="from the application"),
            peer,
            perm("tcp", 22, 22, groups=[SG["bastion"]], descriptions="SSH from the bastion"),
        ], []),
        group("bastion", "Bastion host", [
            perm("tcp", 22, 22, lists=[CORP], descriptions="SSH from the offices"),
        ], [
            perm("tcp", 22, 22, cidrs=["10.20.0.0/16"], descriptions="SSH inside the VPC"),
            perm("tcp", 443, 443, cidrs=["0.0.0.0/0"], descriptions="updates"),
        ]),
        group("monitoring", "Monitoring", [
            perm("udp", 161, 162, cidrs=["10.20.9.0/24"], descriptions="SNMP from the management subnet"),
        ], everything()),
        group("legacy", "Old FTP server, decommissioned", [
            perm("tcp", 20, 21, cidrs=["0.0.0.0/0"], descriptions="FTP"),
            perm("50", cidrs=["192.0.2.10/32"], descriptions="ESP from the old VPN peer"),
        ], everything()),
    ]


def interface(ident: str, subnet: str, groups_of: List[str], private: List[str], six: List[str] = (), public: str = "",
              name: str = "", kind: str = "interface") -> Dict[str, Any]:  # fmt: skip
    addresses: List[Dict[str, Any]] = []
    for index, address in enumerate(private):
        item: Dict[str, Any] = {"PrivateIpAddress": address, "Primary": index == 0}
        if public and index == 0:
            item["Association"] = {"PublicIp": public, "IpOwnerId": OWNER}
        addresses.append(item)
    out: Dict[str, Any] = {
        "NetworkInterfaceId": ident, "VpcId": VPC, "SubnetId": SUBNETS[subnet][0], "OwnerId": OWNER, "InterfaceType": kind,
        "RequesterManaged": False, "Status": "in-use", "SourceDestCheck": True,
        "Groups": [{"GroupId": SG[g], "GroupName": g if g == "default" else f"{g}-sg"} for g in groups_of],
        "PrivateIpAddress": private[0], "PrivateIpAddresses": addresses,
        "Ipv6Addresses": [{"Ipv6Address": a, "IsPrimaryIpv6": False} for a in six],
        "TagSet": [{"Key": "Name", "Value": name}] if name else [],
    }  # fmt: skip
    if public:
        out["Association"] = {"PublicIp": public, "AllocationId": f"eipalloc-{ident[4:]}", "IpOwnerId": OWNER}
    return out


def interfaces() -> List[Dict[str, Any]]:
    return [
        interface("eni-0e10000000000000a", "public", ["web", "monitoring"], ["10.20.1.10"], ["2001:db8:20:1::10"], "203.0.113.10", "web-1"),
        interface("eni-0e20000000000000a", "public", ["web", "monitoring"], ["10.20.1.11"], ["2001:db8:20:1::11"], "203.0.113.11", "web-2"),
        interface("eni-0a10000000000000a", "app", ["app", "monitoring"], ["10.20.2.20", "10.20.2.21"], ["2001:db8:20:2::20"], name="app-1"),
        interface("eni-0a20000000000000a", "app", ["app"], ["10.20.2.30"], name="app-lambda", kind="lambda"),
        interface("eni-0db0000000000000a", "db", ["db"], ["10.20.3.40"], name="db-1"),
        interface("eni-0b10000000000000a", "mgmt", ["bastion", "default"], ["10.20.9.5"], public="203.0.113.50", name="bastion"),
        interface("eni-0c10000000000000a", "mgmt", ["monitoring", "default"], ["10.20.9.6"], name="monitor"),
    ]


def acl_entry(number: int, protocol: str, action: str, egress: bool, cidr: str, ports: tuple = (), icmp: tuple = ()) -> Dict[str, Any]:
    out: Dict[str, Any] = {"RuleNumber": number, "Protocol": protocol, "RuleAction": action, "Egress": egress,
                           ("Ipv6CidrBlock" if ":" in cidr else "CidrBlock"): cidr}  # fmt: skip
    if ports:
        out["PortRange"] = {"From": ports[0], "To": ports[1]}
    if icmp:
        out["IcmpTypeCode"] = {"Type": icmp[0], "Code": icmp[1]}
    return out


def acls() -> List[Dict[str, Any]]:
    default = [acl_entry(100, "-1", "allow", e, "0.0.0.0/0") for e in (False, True)]
    default += [acl_entry(101, "-1", "allow", e, "::/0") for e in (False, True)]
    default += [acl_entry(32767, "-1", "deny", e, "0.0.0.0/0") for e in (False, True)]
    default += [acl_entry(32768, "-1", "deny", e, "::/0") for e in (False, True)]
    database = [
        acl_entry(90, "6", "deny", False, "10.20.1.0/24", (0, 65535)),  # nothing from the public subnet
        acl_entry(100, "6", "allow", False, "10.20.2.0/24", (5432, 5432)),
        acl_entry(110, "6", "allow", False, "10.20.9.0/24", (22, 22)),
        acl_entry(120, "6", "allow", False, "10.20.0.0/16", (1024, 65535)),
        acl_entry(130, "1", "allow", False, "10.20.0.0/16", icmp=(3, 4)),
        acl_entry(32767, "-1", "deny", False, "0.0.0.0/0"),
        acl_entry(100, "6", "allow", True, "10.20.0.0/16", (1024, 65535)),
        acl_entry(32767, "-1", "deny", True, "0.0.0.0/0"),
    ]
    associations = [{"NetworkAclAssociationId": f"aclassoc-0{n}", "NetworkAclId": "acl-0d00000000000000a", "SubnetId": SUBNETS[s][0]}
                    for n, s in enumerate(("public", "app", "mgmt"))]  # fmt: skip
    return [
        {"NetworkAclId": "acl-0d00000000000000a", "VpcId": VPC, "IsDefault": True, "OwnerId": OWNER, "Tags": [],
         "Associations": associations, "Entries": default},
        {"NetworkAclId": "acl-0db0000000000000a", "VpcId": VPC, "IsDefault": False, "OwnerId": OWNER,
         "Tags": [{"Key": "Name", "Value": "db-acl"}],
         "Associations": [{"NetworkAclAssociationId": "aclassoc-0db", "NetworkAclId": "acl-0db0000000000000a",
                           "SubnetId": SUBNETS["db"][0]}],
         "Entries": database},
    ]  # fmt: skip


def sample() -> List[Dict[str, Any]]:
    subnets = []
    for name, (ident, cidr, six) in SUBNETS.items():
        subnets.append({"SubnetId": ident, "VpcId": VPC, "CidrBlock": cidr, "AvailabilityZone": "eu-west-1a", "OwnerId": OWNER,
                        "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": six, "Ipv6CidrBlockState": {"State": "associated"}}] if six else [],
                        "Tags": [{"Key": "Name", "Value": name}]})  # fmt: skip
    vpc = {"VpcId": VPC, "CidrBlock": "10.20.0.0/16", "State": "available", "OwnerId": OWNER, "IsDefault": False,
           "CidrBlockAssociationSet": [{"CidrBlock": "10.20.0.0/16", "CidrBlockState": {"State": "associated"}}],
           "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "2001:db8:20::/56", "Ipv6CidrBlockState": {"State": "associated"}}],
           "Tags": [{"Key": "Name", "Value": "shop-prod"}]}  # fmt: skip
    lists = [
        {"PrefixListId": CORP, "AddressFamily": "IPv4", "State": "create-complete", "PrefixListName": "corp-offices", "MaxEntries": 5,
         "Version": 3, "OwnerId": OWNER, "Tags": []},
        {"PrefixListId": S3, "AddressFamily": "IPv4", "State": "create-complete", "PrefixListName": "com.amazonaws.eu-west-1.s3",
         "MaxEntries": 3, "Version": 1, "OwnerId": "AWS", "Tags": []},
    ]  # fmt: skip
    return [
        {"SecurityGroups": groups()},
        {"NetworkInterfaces": interfaces()},
        {"Vpcs": [vpc]},
        {"Subnets": subnets},
        {"NetworkAcls": acls()},
        {"PrefixLists": lists},
        {"PrefixListId": CORP, "Entries": [{"Cidr": "198.51.100.0/24", "Description": "office Brussels"},
                                           {"Cidr": "192.0.2.128/25", "Description": "office Genk"}]},
        {"PrefixListId": S3, "Entries": [{"Cidr": "203.0.113.128/26"}, {"Cidr": "203.0.113.192/27"}]},
    ]  # fmt: skip


def main() -> None:
    data = Path(__file__).resolve().parent.parent / "data"
    (data / "aws_sample.json").write_text(json.dumps(sample(), indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
