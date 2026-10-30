# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/oci_sample.json: a made-up VCN, as the OCI CLI answers for it, one answer after the other (as the
shell loop of the manual concatenates them):

    oci network vcn get --vcn-id VCN
    oci network subnet list --compartment-id C --vcn-id VCN --all
    oci network security-list list --compartment-id C --vcn-id VCN --all
    oci network nsg list --compartment-id C --vcn-id VCN --all
    oci network nsg rules list --nsg-id NSG --all --query "{nsgId: 'NSG', data: data}"     (for each NSG)
    oci network private-ip list --subnet-id SUBNET --all                                   (for each subnet)
    oci network vnic get --vnic-id VNIC                                                     (for each VNIC)
    oci iam region list
    Oracle's public_ip_ranges.json

Keys in kebab-case, as the CLI prints them. Every address is a documentation or private address, every OCID is made
up; not taken from any real tenancy.

    python3 tests/tools/make_oci_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

COMPARTMENT = "ocid1.compartment.oc1..examplecompartmentshop"
REGION = "eu-frankfurt-1"


def ocid(kind: str, name: str) -> str:
    return f"ocid1.{kind}.oc1.{REGION}.example{name}"


VCN = ocid("vcn", "shopvcn")
DEFAULT_SL = ocid("securitylist", "default")
SL = {"web": ocid("securitylist", "websl"), "app": ocid("securitylist", "appsl"), "db": ocid("securitylist", "dbsl"),
      "spare": ocid("securitylist", "sparesl")}  # fmt: skip
NSG = {"web": ocid("networksecuritygroup", "webnsg"), "app": ocid("networksecuritygroup", "appnsg"),
       "bastion": ocid("networksecuritygroup", "bastionnsg"), "legacy": ocid("networksecuritygroup", "legacynsg"),
       "old": ocid("networksecuritygroup", "oldnsg")}  # fmt: skip
GONE_NSG = ocid("networksecuritygroup", "deletednsg")
OTHER_NSG = ocid("networksecuritygroup", "monitoringnsgotherteam")
SUBNETS = {"web": ("10.30.1.0/24", ["2001:db8:30:1::/64"], [DEFAULT_SL, SL["web"]]),
           "app": ("10.30.2.0/24", [], [SL["app"]]),
           "db": ("10.30.3.0/24", [], [SL["db"]]),
           "mgmt": ("10.30.9.0/24", [], [DEFAULT_SL])}  # fmt: skip


def common(kind: str, name: str, display: str) -> Dict[str, Any]:
    return {"compartment-id": COMPARTMENT, "defined-tags": {}, "display-name": display, "freeform-tags": {},
            "id": ocid(kind, name), "lifecycle-state": "AVAILABLE", "time-created": "2026-09-14T08:12:44.120000+00:00"}  # fmt: skip


def ports(low: int, high: int) -> Dict[str, int]:
    return {"max": high, "min": low}


def rule(direction: str, protocol: str, peer: str, kind: str = "CIDR_BLOCK", stateless: bool = False, tcp: Optional[Dict[str, Any]] = None,
         udp: Optional[Dict[str, Any]] = None, icmp: Optional[Dict[str, Any]] = None, description: Optional[str] = None,
         nsg_rule: str = "", valid: bool = True) -> Dict[str, Any]:  # fmt: skip
    """A rule of a security list (nsg_rule empty) or of an NSG (nsg_rule: its id)."""
    side = "source" if direction == "INGRESS" else "destination"
    out: Dict[str, Any] = {"description": description, side: peer, f"{side}-type": kind, "icmp-options": icmp,
                           "is-stateless": stateless, "protocol": protocol, "tcp-options": tcp, "udp-options": udp}  # fmt: skip
    if nsg_rule:
        other = "destination" if side == "source" else "source"
        out.update({"direction": direction, other: None, f"{other}-type": None, "id": nsg_rule, "is-valid": valid,
                    "time-created": "2026-09-14T08:20:01.000000+00:00"})  # fmt: skip
    return dict(sorted(out.items()))


def tcp(low: int, high: int, src: Optional[tuple] = None) -> Dict[str, Any]:
    return {"destination-port-range": ports(low, high), "source-port-range": ports(*src) if src else None}


def answers() -> List[Any]:
    out: List[Any] = []
    vcn = common("vcn", "shopvcn", "shop-vcn")
    vcn.update({"byoipv6-cidr-blocks": None, "cidr-block": "10.30.0.0/16", "cidr-blocks": ["10.30.0.0/16"],
                "default-dhcp-options-id": ocid("dhcpoptions", "default"), "default-route-table-id": ocid("routetable", "default"),
                "default-security-list-id": DEFAULT_SL, "dns-label": "shop", "ipv6-cidr-blocks": ["2001:db8:30::/56"],
                "ipv6-private-cidr-blocks": None, "vcn-domain-name": "shop.oraclevcn.com"})  # fmt: skip
    out.append({"data": dict(sorted(vcn.items())), "etag": "f00d0001"})

    subnets = []
    for name, (v4, v6, lists) in SUBNETS.items():
        node = common("subnet", f"{name}subnet", f"{name}-subnet")
        node.update({"availability-domain": None, "cidr-block": v4, "dhcp-options-id": ocid("dhcpoptions", "default"),
                     "dns-label": name, "ipv6-cidr-block": v6[0] if v6 else None, "ipv6-cidr-blocks": v6 or None,
                     "prohibit-internet-ingress": name != "web" and name != "mgmt", "prohibit-public-ip-on-vnic": name not in ("web", "mgmt"),
                     "route-table-id": ocid("routetable", "default"), "security-list-ids": lists, "vcn-id": VCN,
                     "virtual-router-ip": v4.replace(".0/24", ".1"), "virtual-router-mac": "00:00:17:00:00:01"})  # fmt: skip
        subnets.append(dict(sorted(node.items())))
    out.append({"data": subnets})

    lists = []
    default = common("securitylist", "default", "Default Security List for shop-vcn")
    default["egress-security-rules"] = [rule("EGRESS", "all", "0.0.0.0/0"), rule("EGRESS", "all", "::/0")]
    default["ingress-security-rules"] = [
        rule("INGRESS", "6", "0.0.0.0/0", tcp=tcp(22, 22)),
        rule("INGRESS", "1", "0.0.0.0/0", icmp={"code": 4, "type": 3}),
        rule("INGRESS", "1", "10.30.0.0/16", icmp={"code": None, "type": 3}),
        rule("INGRESS", "6", "::/0", tcp=tcp(22, 22)),
        rule("INGRESS", "58", "::/0", icmp={"code": 0, "type": 2}),
    ]
    lists.append(default)
    web = common("securitylist", "websl", "web-sl")
    web["egress-security-rules"] = []
    web["ingress-security-rules"] = [
        rule("INGRESS", "6", "0.0.0.0/0", tcp=tcp(443, 443), description="HTTPS from anywhere"),
        rule("INGRESS", "6", "::/0", tcp=tcp(80, 80)),
        rule("INGRESS", "6", "10.30.0.0/16", tcp=tcp(8080, 8080, (0, 65535))),
    ]
    lists.append(web)
    app = common("securitylist", "appsl", "app-sl")
    app["egress-security-rules"] = [
        rule("EGRESS", "6", "10.30.3.0/24", tcp=tcp(5432, 5432), description="PostgreSQL"),
        rule("EGRESS", "6", "all-fra-services-in-oracle-services-network", kind="SERVICE_CIDR_BLOCK", tcp=tcp(443, 443)),
        rule("EGRESS", "17", "0.0.0.0/0", udp=tcp(123, 123, (123, 123)), description="NTP"),
        rule("EGRESS", "6", "oci-fra-objectstorage", kind="SERVICE_CIDR_BLOCK", tcp=tcp(443, 443)),
        rule("EGRESS", "6", "oci-ams-objectstorage", kind="SERVICE_CIDR_BLOCK", tcp=tcp(443, 443)),
    ]
    app["ingress-security-rules"] = [
        rule("INGRESS", "6", "10.30.1.0/24", tcp=tcp(8080, 8080)),
        rule("INGRESS", "47", "10.30.9.0/24", description="GRE from management"),
        rule("INGRESS", "1", "10.30.9.0/24", icmp={"code": None, "type": 8}),
    ]
    lists.append(app)
    db = common("securitylist", "dbsl", "db-sl")
    db["egress-security-rules"] = [
        rule("EGRESS", "6", "10.30.2.0/24", stateless=True, tcp=tcp(1024, 65535, (5432, 5432)), description="replies to the app tier"),
        rule("EGRESS", "6", "10.30.9.0/24", tcp=tcp(22, 22)),
    ]
    db["ingress-security-rules"] = [
        rule("INGRESS", "6", "10.30.2.0/24", stateless=True, tcp=tcp(5432, 5432), description="app tier, stateless"),
        rule("INGRESS", "6", "10.30.9.0/24", tcp=tcp(5432, 5432), description="management, stateful"),
        rule("INGRESS", "6", "10.30.9.10/32", stateless=True, tcp=tcp(1, 65535), description="backup host, stateless"),
        rule("INGRESS", "1", "10.30.0.0/16", stateless=True, icmp={"code": None, "type": 8}, description="ping, stateless"),
        rule("INGRESS", "1", "10.30.0.0/16", stateless=True, icmp={"code": 4, "type": 3}),
        rule("INGRESS", "58", "10.30.0.0/16", icmp={"code": None, "type": 128}, description="ICMPv6 with an IPv4 block"),
    ]
    lists.append(db)
    spare = common("securitylist", "sparesl", "spare-sl")
    spare["egress-security-rules"] = []
    spare["ingress-security-rules"] = [rule("INGRESS", "all", "0.0.0.0/0")]
    lists.append(spare)
    for node in lists:
        node["vcn-id"] = VCN
    out.append({"data": [dict(sorted(n.items())) for n in lists]})

    nsgs = []
    for key, display in (("web", "web-nsg"), ("app", "app-nsg"), ("bastion", "bastion-nsg"), ("legacy", "legacy-nsg"), ("old", "old-nsg")):
        node = common("networksecuritygroup", f"{key}nsg", display)
        node["vcn-id"] = VCN
        if key == "old":
            node["lifecycle-state"] = "TERMINATED"
        nsgs.append(dict(sorted(node.items())))
    out.append({"data": nsgs})

    rules = {
        "web": [
            rule("INGRESS", "6", NSG["bastion"], kind="NETWORK_SECURITY_GROUP", tcp=tcp(22, 22), nsg_rule="0A1B01", description="SSH from the bastion"),
            rule("INGRESS", "6", OTHER_NSG, kind="NETWORK_SECURITY_GROUP", tcp=tcp(9100, 9100), nsg_rule="0A1B02",
                 description="node exporter, scraped from another team's NSG"),
            rule("INGRESS", "6", GONE_NSG, kind="NETWORK_SECURITY_GROUP", tcp=tcp(9200, 9200), nsg_rule="0A1B03", valid=False),
            rule("EGRESS", "6", NSG["app"], kind="NETWORK_SECURITY_GROUP", tcp=tcp(8080, 8080), nsg_rule="0A1B04"),
        ],
        "app": [
            rule("INGRESS", "6", NSG["web"], kind="NETWORK_SECURITY_GROUP", tcp=tcp(8080, 8443), nsg_rule="0B2C01"),
            rule("INGRESS", "6", NSG["app"], kind="NETWORK_SECURITY_GROUP", tcp=tcp(7000, 7001), nsg_rule="0B2C02", description="cluster"),
        ],
        "bastion": [
            rule("INGRESS", "6", "192.0.2.0/25", tcp=tcp(22, 22), nsg_rule="0C3D01", description="corporate office"),
            rule("INGRESS", "6", "198.51.100.0/25", tcp=tcp(22, 22), nsg_rule="0C3D02"),
            rule("EGRESS", "all", "10.30.0.0/16", nsg_rule="0C3D03"),
        ],
        "legacy": [rule("INGRESS", "6", "0.0.0.0/0", tcp=tcp(21, 21), nsg_rule="0D4E01")],
    }
    for key, items in rules.items():
        out.append({"nsgId": NSG[key], "data": items})

    vnics = [  # name, subnet, primary, secondary, ipv6, public, nsgs
        ("web-1", "web", "10.30.1.10", [], ["2001:db8:30:1::10"], "203.0.113.10", ["web"]),
        ("web-2", "web", "10.30.1.11", [], ["2001:db8:30:1::11"], "203.0.113.11", ["web"]),
        ("app-1", "app", "10.30.2.30", ["10.30.2.31"], [], None, ["app"]),
        ("app-2", "app", "10.30.2.32", [], [], None, ["app"]),
        ("db-1", "db", "10.30.3.40", [], [], None, []),
        ("bastion", "mgmt", "10.30.9.5", [], [], "203.0.113.50", ["bastion"]),
        ("backup", "mgmt", "10.30.9.10", [], [], None, []),
    ]
    for subnet in SUBNETS:
        items = []
        for name, where, primary, secondary, _, _, _ in vnics:
            if where != subnet:
                continue
            for number, address in enumerate([primary] + secondary):
                node = common("privateip", f"{name.replace('-', '')}{number}", f"{name}-ip{number}")
                node.update({"availability-domain": "Uocm:EU-FRANKFURT-1-AD-1", "hostname-label": name if not number else None,
                             "ip-address": address, "is-primary": not number, "subnet-id": ocid("subnet", f"{subnet}subnet"),
                             "vlan-id": None, "vnic-id": ocid("vnic", name.replace("-", ""))})  # fmt: skip
                items.append(dict(sorted(node.items())))
        if items:
            out.append({"data": items})
    for name, where, primary, _, six, public, groups in vnics:
        node = common("vnic", name.replace("-", ""), name)
        node.update({"availability-domain": "Uocm:EU-FRANKFURT-1-AD-1", "hostname-label": name, "ipv6-addresses": six or None,
                     "is-primary": True, "mac-address": "02:00:17:00:00:0" + str(len(name) % 10), "nsg-ids": [NSG[g] for g in groups],
                     "private-ip": primary, "public-ip": public, "skip-source-dest-check": False,
                     "subnet-id": ocid("subnet", f"{where}subnet"), "vlan-id": None})  # fmt: skip
        out.append({"data": dict(sorted(node.items())), "etag": "f00d0" + str(len(name))})
    out.append({"data": [{"key": "AMS", "name": "eu-amsterdam-1"}, {"key": "FRA", "name": REGION}]})
    out.append({
        "last_updated_timestamp": "2026-10-01T06:00:00.000000",
        "regions": [{"region": REGION, "cidrs": [
            {"cidr": "203.0.113.0/26", "tags": ["OCI"]},
            {"cidr": "203.0.113.128/26", "tags": ["OSN", "OBJECT_STORAGE"]},
            {"cidr": "203.0.113.192/27", "tags": ["OSN"]},
        ]}],
    })  # fmt: skip
    return out


def main() -> None:
    target = Path(__file__).resolve().parent.parent / "data" / "oci_sample.json"
    text = "".join(json.dumps(answer, indent=2) + "\n" for answer in answers())
    target.write_text(text, encoding="utf-8")
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
