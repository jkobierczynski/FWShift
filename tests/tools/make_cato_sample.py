# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build the synthetic Cato Networks sample, ``tests/data/cato_sample.json``.

It is the bundle of section 3 of the manual for a made-up account: the WAN Firewall (as the whole answer of the GraphQL
query), the Internet Firewall (as the policy object alone), and the lookups of sites, network ranges, hosts, network
interfaces, site ranges, global ranges and groups. The shapes follow the GraphQL schema as Cato's own CLI (catocli)
carries it; nothing in them came from an account. Names and addresses are invented (RFC 1918, RFC 5737).

    python3 tests/tools/make_cato_sample.py tests/data/cato_sample.json
"""

from __future__ import annotations

import json
import sys

def ref(i, n): return {"id": i, "name": n}
def side(**kw):
    base = {k: [] for k in ("host", "site", "subnet", "ip", "ipRange", "globalIpRange", "networkInterface", "siteNetworkSubnet",
                            "floatingSubnet", "user", "usersGroup", "group", "systemGroup")}
    base.update(kw); return base
def ifdest(**kw):
    base = {k: [] for k in ("application", "customApp", "appCategory", "customCategory", "sanctionedAppsCategory", "country", "domain",
                            "fqdn", "ip", "subnet", "ipRange", "globalIpRange", "remoteAsn", "group")}
    base["containers"] = {"fqdnContainer": [], "ipAddressRangeContainer": []}
    base.update(kw); return base
def svc(standard=(), custom=()):
    return {"standard": [ref(s, s) for s in standard], "custom": list(custom)}
def tcp(ports=None, rng=None, proto="TCP"):
    return {"port": ports, "portRange": {"from": rng[0], "to": rng[1]} if rng else None, "protocol": proto}
APP = {"application": [], "appCategory": [], "customApp": [], "customCategory": [], "sanctionedAppsCategory": [], "domain": [], "fqdn": [],
       "ip": [], "subnet": [], "ipRange": [], "globalIpRange": []}
index = [0]
def rule(name, action, source, destination, service=None, section=("s-1", "Site to site"), direction="TO", enabled=True, event=False,
         exceptions=(), schedule=None, application=None, origins=(), wan=True, props=(), rid=None, extra=None):
    index[0] += 1
    r = {"id": rid or f"r-{index[0]:04d}", "name": name, "description": "", "index": index[0], "section": ref(*section), "enabled": enabled,
         "source": source, "connectionOrigin": "ANY", "country": [], "device": [], "deviceOS": [],
         "destination": destination, "service": service or svc(), "action": action,
         "tracking": {"event": {"enabled": event}, "alert": {"enabled": False, "frequency": "HOURLY", "subscriptionGroup": [], "webhook": [], "mailingList": []}},
         "schedule": schedule or {"activeOn": "ALWAYS", "customTimeframe": None, "customRecurring": None},
         "activePeriod": {"useEffectiveFrom": False, "effectiveFrom": None, "useExpiresAt": False, "expiresAt": None},
         "exceptions": list(exceptions), "connectionsOriginList": list(origins)}
    if wan:
        r["direction"] = direction
        r["application"] = application or dict(APP)
    if extra:
        r.update(extra)
    return {"audit": {"updatedTime": "2026-10-01T08:00:00Z", "updatedBy": "admin@example.com"}, "rule": r, "properties": list(props),
            "ruleType": "POLICY_RULE", "subPolicy": None}

BXL, ANT, GNT = ref("1001", "Brussels HQ"), ref("1002", "Antwerp DC"), ref("1003", "Ghent Plant")
wan_rules = [
    rule("Allow HQ to DC servers", "ALLOW", side(site=[BXL]), side(group=[ref("g-1", "Servers")]),
         svc(["HTTPS"], [tcp([8443])]), event=True),
    rule("Block OT to HQ", "BLOCK", side(group=[ref("g-2", "OT sites")]), side(site=[BXL])),
    rule("Historian both ways", "ALLOW", side(host=[ref("h-3001", "historian")]), side(siteNetworkSubnet=[ref("sr-1002-30", "Antwerp DC \\ Routed lab")]),
         svc([], [tcp([1433]), tcp(None, (5000, 5010), "UDP")]), direction="BOTH"),
    rule("Remote users to DC", "ALLOW", side(), side(site=[ANT]), svc([], [tcp([53], None, "TCP_UDP"), tcp(None, None, "ICMP")]),
         section=("s-2", "Remote users"), origins=["REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER"],
         exceptions=[{"name": "not the database", "source": side(), "destination": side(host=[ref("h-2002", "erp-db")]), "service": svc(),
                      "application": dict(APP), "country": [], "device": [], "deviceOS": [], "direction": "TO", "connectionOrigin": "ANY",
                      "connectionsOriginList": []}]),
    rule("Modbus to the plant", "ALLOW", side(group=[ref("g-3", "Engineering")], ip=["10.20.0.99"], ipRange=[{"from": "10.10.20.100", "to": "10.10.20.120"}]),
         side(networkInterface=[ref("ni-1003-lan", "Ghent Plant \\ LAN")]), svc([], [tcp(None, (502, 502))]), event=True),
    rule("Finance to ERP", "ALLOW", side(usersGroup=[ref("ug-7", "Finance")]), side(host=[ref("h-2002", "erp-db")]), svc([], [tcp([5432])]),
         section=("s-2", "Remote users")),
    rule("Prompt for SSH", "PROMPT", side(), side(subnet=["10.20.0.0/24"]), svc(["SSH"])),
    rule("Old block", "BLOCK", side(subnet=["10.10.0.0/24"]), side(ip=["10.30.0.5"]), enabled=False),
    rule("Floating range", "ALLOW", side(floatingSubnet=[ref("fs-1", "Cloud floating")]), side(site=[ANT])),
    rule("Maintenance window", "ALLOW", side(site=[ANT]), side(site=[GNT]), svc(["RDP"]),
         schedule={"activeOn": "CUSTOM_RECURRING", "customTimeframe": None, "customRecurring": {"from": "22:00:00", "to": "23:59:00", "days": ["SATURDAY", "SUNDAY"]}}),
    rule("Teams between sites", "ALLOW", side(), side(), application=dict(APP, application=[ref("microsoft_teams", "Microsoft Teams")])),
    rule("Unknown host", "ALLOW", side(site=[BXL]), side(host=[ref("h-9999", "lab-printer")]), svc([], [tcp([9100])])),
    rule("Block guest except DNS", "BLOCK", side(subnet=["10.10.20.0/24"]), side(),
         exceptions=[{"name": "dns from one host", "source": side(ip=["10.10.20.5"]), "destination": side(),
                      "service": svc([], [tcp([53], None, "UDP")]), "application": dict(APP), "country": [], "device": [], "deviceOS": [],
                      "direction": "TO", "connectionOrigin": "ANY", "connectionsOriginList": []}]),
    rule("Block plant to remote users", "BLOCK", side(site=[GNT]), side(), extra={"connectionsOriginList": ["SITE"]}),
]
internet_rules = [
    rule("Block anonymizers", "BLOCK", side(), ifdest(appCategory=[ref("anonymizers", "Anonymizers")]), wan=False, props=["SYSTEM"],
         section=("s-10", "Default rules")),
    rule("Block bad networks", "BLOCK", side(), ifdest(subnet=["203.0.113.0/24"], ip=["198.51.100.66"]), wan=False, event=True,
         section=("s-11", "Internet")),
    rule("Plant has no internet", "BLOCK", side(site=[GNT]), ifdest(), wan=False, section=("s-11", "Internet"),
         exceptions=[{"name": "vendor updates", "source": side(), "destination": ifdest(fqdn=["updates.example.com"]), "service": svc(),
                      "country": [], "device": [], "deviceOS": [], "connectionOrigin": "ANY", "connectionsOriginList": []}]),
    rule("HQ web", "ALLOW", side(site=[BXL]), ifdest(domain=["example.org"]), svc(["HTTPS"]), wan=False, section=("s-11", "Internet")),
    rule("Isolate unknown sites", "RBI", side(), ifdest(customCategory=[ref("cc-1", "Uncategorized")]), wan=False, section=("s-11", "Internet")),
    rule("Partner FTP", "ALLOW", side(globalIpRange=[ref("gr-1", "Partner net")]), ifdest(fqdn=["ftp.example.net"]), svc(["FTP"]), wan=False,
         section=("s-11", "Internet")),
    rule("Retired rule", "BLOCK", side(), ifdest(ip=["192.0.2.200"]), wan=False, props=["REMOVED"], section=("s-11", "Internet")),
    rule("Block remote users to SMB", "BLOCK", side(), ifdest(), svc(["SMB"]), wan=False, origins=["REMOTE_CLIENT"], section=("s-11", "Internet")),
]

def policy(rules, sections):
    return {"enabled": True, "rules": rules,
            "sections": [{"section": ref(i, n), "properties": []} for i, n in sections],
            "revision": None, "audit": {"publishedTime": "2026-10-01T08:05:00Z", "publishedBy": "admin@example.com"}}

def entity(i, n, t, helper=None, desc=""):
    return {"entity": {"id": i, "name": n, "type": t}, "description": desc, "helperFields": helper or {}}

bundle = {
    "fwshift": "cato",
    "wanFirewall": {"data": {"policy": {"wanFirewall": {"policy": policy(wan_rules, [("s-1", "Site to site"), ("s-2", "Remote users")])}}}},
    "internetFirewall": policy(internet_rules, [("s-10", "Default rules"), ("s-11", "Internet")]),
    "sites": {"items": [entity("1001", "Brussels HQ", "site"), entity("1002", "Antwerp DC", "site"), entity("1003", "Ghent Plant", "site"),
                        entity("1004", "Leuven Lab", "site")], "total": 4},
    "networkRanges": {
        "1001": {"items": [{"networkRangeId": "nr-1", "name": "Native Range", "rangeType": "Native", "subnet": "10.10.0.0/24"},
                           {"networkRangeId": "nr-2", "name": "Guests", "rangeType": "VLAN", "subnet": "10.10.20.0/24", "vlan": 20}]},
        "1002": {"items": [{"networkRangeId": "nr-3", "name": "Native Range", "rangeType": "Native", "subnet": "10.20.0.0/24"},
                           {"networkRangeId": "nr-4", "name": "Routed lab", "rangeType": "Routed", "subnet": "10.20.30.0/24"}]},
        "1003": {"items": [{"networkRangeId": "nr-5", "name": "Native Range", "rangeType": "Native", "subnet": "10.30.0.0/24"}]},
        "1004": {"items": [{"networkRangeId": "nr-6", "name": "Native Range", "rangeType": "Native", "subnet": "10.40.0.0/24"}]},
    },
    "hosts": {
        "1002": {"items": [{"hostId": "h-2001", "name": "fileserver", "ip": "10.20.0.10", "macAddress": None},
                           {"hostId": "h-2002", "name": "erp-db", "ip": "10.20.0.20", "macAddress": None}]},
        "1003": {"items": [{"hostId": "h-3001", "name": "historian", "ip": "10.30.0.50", "macAddress": None}]},
    },
    "networkInterfaces": {"items": [entity("ni-1003-lan", "Ghent Plant \\ LAN", "networkInterface",
                                           {"siteId": "1003", "subnet": "10.30.0.0/24", "interfaceName": "LAN", "isDefault": True})], "total": 1},
    "siteRanges": {"items": [entity("sr-1002-30", "Antwerp DC \\ Routed lab", "siteRange", {"siteId": "1002", "subnet": "10.20.30.0/24",
                                                                                           "interfaceName": "LAN"})], "total": 1},
    "globalIpRanges": {"items": [{"id": "gr-1", "name": "Partner net", "description": "a partner network", "ipRange": "192.0.2.0/25"},
                                 {"id": "gr-2", "name": "Monitoring", "description": "", "ipRange": "198.51.100.10-198.51.100.20"}], "total": 2},
    "groups": {"items": [
        {"id": "g-1", "name": "Servers", "members": {"items": [{"id": "h-2001", "name": "fileserver", "type": "HOST"},
                                                              {"id": "h-2002", "name": "erp-db", "type": "HOST"},
                                                              {"id": "gr-2", "name": "Monitoring", "type": "GLOBAL_IP_RANGE"}], "paging": {"total": 3}}},
        {"id": "g-2", "name": "OT sites", "members": {"items": [{"id": "1003", "name": "Ghent Plant", "type": "SITE"},
                                                               {"id": "1004", "name": "Leuven Lab", "type": "SITE"}], "paging": {"total": 2}}},
        {"id": "g-3", "name": "Engineering", "members": {"items": [{"id": "1001", "name": "Brussels HQ", "type": "SITE"},
                                                                  {"id": "h-3001", "name": "historian", "type": "HOST"}], "paging": {"total": 2}}},
    ], "paging": {"total": 3}},
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(bundle, handle, indent=1)
    handle.write("\n")
