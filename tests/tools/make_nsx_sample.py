# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/nsx_sample.json: a made-up distributed firewall policy, as the hierarchical NSX Policy API
returns it (GET /policy/api/v1/infra?type_filter=Domain;Group;SecurityPolicy;Rule;Service;ServiceEntry;Segment).

Every address is a documentation or private address. Not taken from any real NSX manager.

    python3 tests/tools/make_nsx_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

DOMAIN = "/infra/domains/default"


def ip_group(ident: str, name: str, *lists: List[str]) -> Dict[str, Any]:
    expression: List[Dict[str, Any]] = []
    for index, addresses in enumerate(lists):
        if index:
            expression.append({"resource_type": "ConjunctionOperator", "id": f"c{index}", "conjunction_operator": "OR"})
        expression.append({"resource_type": "IPAddressExpression", "id": f"e{index}", "ip_addresses": addresses})
    return group(ident, name, expression)


def group(ident: str, name: str, expression: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"resource_type": "ChildGroup", "marked_for_delete": False,
            "Group": {"resource_type": "Group", "id": ident, "display_name": name, "path": f"{DOMAIN}/groups/{ident}",
                      "parent_path": DOMAIN, "expression": expression, "_revision": 0}}


def service(ident: str, name: str, entries: List[Dict[str, Any]], system: bool = False) -> Dict[str, Any]:
    body: Dict[str, Any] = {"resource_type": "Service", "id": ident, "display_name": name, "path": f"/infra/services/{ident}",
                            "service_type": "NON_ETHER", "service_entries": entries, "_revision": 0}
    if system:
        body.update({"is_default": True, "_system_owned": True})
    return {"resource_type": "ChildService", "marked_for_delete": False, "Service": body}


def l4(ident: str, proto: str, *ports: str) -> Dict[str, Any]:
    return {"resource_type": "L4PortSetServiceEntry", "id": ident, "l4_protocol": proto, "source_ports": [],
            "destination_ports": list(ports)}


def rule(policy: str, ident: str, name: str, number: int, rule_id: int, sources: List[str], destinations: List[str],
         services: List[str], action: str = "ALLOW", **extra: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "resource_type": "Rule", "id": ident, "display_name": name, "path": f"{DOMAIN}/security-policies/{policy}/rules/{ident}",
        "parent_path": f"{DOMAIN}/security-policies/{policy}", "sequence_number": number, "rule_id": rule_id,
        "source_groups": sources, "destination_groups": destinations, "services": services, "profiles": ["ANY"],
        "scope": ["ANY"], "action": action, "direction": "IN_OUT", "ip_protocol": "IPV4_IPV6", "logged": False,
        "disabled": False, "sources_excluded": False, "destinations_excluded": False, "_revision": 0,
    }
    body.update(extra)
    return {"resource_type": "ChildRule", "marked_for_delete": False, "Rule": body}


def policy(ident: str, name: str, category: str, number: int, rules: List[Dict[str, Any]], scope: Optional[List[str]] = None,
           **extra: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "resource_type": "SecurityPolicy", "id": ident, "display_name": name, "path": f"{DOMAIN}/security-policies/{ident}",
        "parent_path": DOMAIN, "category": category, "sequence_number": number, "stateful": True, "tcp_strict": True,
        "scope": scope or ["ANY"], "children": rules, "_revision": 0,
    }
    body.update(extra)
    return {"resource_type": "ChildSecurityPolicy", "marked_for_delete": False, "SecurityPolicy": body}


def g(ident: str) -> str:
    return f"{DOMAIN}/groups/{ident}"


def s(ident: str) -> str:
    return f"/infra/services/{ident}"


def sample() -> Dict[str, Any]:
    groups = [
        ip_group("web-servers", "Web servers", ["10.20.0.10", "10.20.0.11"]),
        ip_group("app-servers", "App servers", ["10.20.1.0/24"]),
        ip_group("db-servers", "DB servers", ["10.20.2.0/24"], ["2001:db8:20:2::/64"]),
        ip_group("admins", "Admins", ["10.10.5.10-10.10.5.20"]),
        ip_group("lan", "LAN", ["10.10.0.0/16"]),
        ip_group("guests", "Guests", ["10.10.200.0/24"]),
        group("dmz", "DMZ", [{"resource_type": "PathExpression", "id": "p", "paths": [g("web-servers"), g("app-servers")]}]),
        group("ot-cell", "OT cell", [{"resource_type": "PathExpression", "id": "p", "paths": ["/infra/segments/seg-ot"]}]),
        group("quarantine", "Quarantine", [{"resource_type": "Condition", "id": "c", "member_type": "VirtualMachine",
                                            "key": "Tag", "operator": "EQUALS", "value": "security|quarantine"}]),
    ]
    services = [
        service("HTTP", "HTTP", [l4("HTTP", "TCP", "80")], system=True),
        service("HTTPS", "HTTPS", [l4("HTTPS", "TCP", "443")], system=True),
        service("SSH", "SSH", [l4("SSH", "TCP", "22")], system=True),
        service("DNS", "DNS", [l4("DNS", "TCP", "53")], system=True),
        service("DNS-UDP", "DNS-UDP", [l4("DNS-UDP", "UDP", "53")], system=True),
        service("ICMP-ALL", "ICMP ALL", [{"resource_type": "ICMPTypeServiceEntry", "id": "ICMP-ALL", "protocol": "ICMPv4"},
                                         {"resource_type": "ICMPTypeServiceEntry", "id": "ICMPv6-ALL", "protocol": "ICMPv6"}],
                system=True),
        service("app-8443", "app-8443", [l4("t8443", "TCP", "8443")]),
        service("modbus", "Modbus", [l4("modbus", "TCP", "502")]),
        service("mysql", "MySQL", [l4("mysql", "TCP", "3306")]),
        service("web-all", "Web all", [{"resource_type": "NestedServiceServiceEntry", "id": "n1", "nested_service_path": s("HTTPS")},
                                       {"resource_type": "NestedServiceServiceEntry", "id": "n2", "nested_service_path": s("app-8443")}]),
        service("ftp-alg", "FTP", [{"resource_type": "ALGTypeServiceEntry", "id": "ftp", "alg": "FTP", "destination_ports": ["21"],
                                    "source_ports": []}]),
    ]
    policies = [
        policy("layer2", "Layer 2", "Ethernet", 1, [
            rule("layer2", "l2-any", "L2 allow", 1, 1001, ["ANY"], ["ANY"], ["ANY"]),
        ]),
        policy("emergency", "Emergency", "Emergency", 10, [
            rule("emergency", "quarantine", "Block quarantined", 10, 1002, [g("quarantine")], ["ANY"], ["ANY"], "DROP", logged=True),
        ]),
        policy("infra", "Infrastructure services", "Infrastructure", 10, [
            rule("infra", "dns", "DNS to resolvers", 10, 1003, [g("lan")], ["192.0.2.53"], [s("DNS"), s("DNS-UDP")]),
            rule("infra", "ntp", "NTP", 20, 1004, ["ANY"], ["192.0.2.123"], [],
                 service_entries=[l4("ntp", "UDP", "123")]),
        ]),
        policy("zones", "Zones", "Environment", 10, [
            rule("zones", "guests", "Guests stay out", 10, 1005, [g("guests")], ["10.0.0.0/8"], ["ANY"], "DROP"),
            rule("zones", "to-app", "LAN to the application rules", 20, 1006, [g("lan")], [g("dmz")], ["ANY"], "JUMP_TO_APPLICATION"),
            rule("zones", "lan-block", "LAN block the rest", 30, 1007, [g("lan")], ["ANY"], [s("SSH")], "DROP"),
        ]),
        policy("web-tier", "Web tier", "Application", 10, [
            rule("web-tier", "inbound-web", "Inbound web", 10, 1010, ["ANY"], [g("web-servers")], [s("web-all")], logged=True),
            rule("web-tier", "web-to-app", "Web to app", 20, 1011, [g("web-servers")], [g("app-servers")], [s("app-8443")]),
            rule("web-tier", "app-to-db", "App to DB", 30, 1012, [g("app-servers")], [g("db-servers")], [s("mysql")], direction="IN"),
        ], scope=[g("dmz")]),
        policy("admin", "Admin", "Application", 20, [
            rule("admin", "admin-ssh", "Admins SSH", 10, 1020, [g("admins")], [g("dmz")], [s("SSH")]),
            rule("admin", "not-admin-ssh", "Others no SSH", 20, 1021, [g("admins")], [g("dmz")], [s("SSH")], "REJECT",
                 sources_excluded=True),
            rule("admin", "ot", "Engineering to PLCs", 30, 1022, ["10.10.7.15"], [g("ot-cell")], [s("modbus")]),
            rule("admin", "ftp", "FTP to partner", 40, 1023, [g("lan")], ["198.51.100.40"], [s("ftp-alg")]),
            rule("admin", "tls-only", "TLS out", 50, 1024, [g("lan")], ["ANY"], [s("HTTPS")],
                 profiles=["/infra/context-profiles/SSL"]),
            rule("admin", "ping6", "Ping over IPv6", 60, 1025, ["ANY"], ["ANY"], [s("ICMP-ALL")], ip_protocol="IPV6"),
            rule("admin", "old", "Old rule", 70, 1026, [g("lan")], [g("db-servers")], [s("mysql")], disabled=True),
        ]),
        policy("default-layer3-section", "Default Layer3 Section", "Application", 0, [
            rule("default-layer3-section", "default-layer3-rule", "Default Layer3 Rule", 2147483647, 2, ["ANY"], ["ANY"], ["ANY"],
                 "DROP", is_default=True),
        ], is_default=True),
    ]
    segments = [{"resource_type": "ChildSegment", "marked_for_delete": False,
                 "Segment": {"resource_type": "Segment", "id": "seg-ot", "display_name": "seg-ot", "path": "/infra/segments/seg-ot",
                             "subnets": [{"gateway_address": "10.30.1.1/24", "network": "10.30.1.0/24"}]}}]
    domain = {"resource_type": "ChildDomain", "marked_for_delete": False,
              "Domain": {"resource_type": "Domain", "id": "default", "display_name": "default", "path": DOMAIN,
                         "children": groups + policies}}
    return {"resource_type": "Infra", "id": "infra", "path": "/infra", "children": [domain] + services + segments}


def main() -> None:
    data = Path(__file__).resolve().parent.parent / "data"
    (data / "nsx_sample.json").write_text(json.dumps(sample(), indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
