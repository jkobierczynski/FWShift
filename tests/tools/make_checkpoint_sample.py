# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build the synthetic Check Point sample: the shape of 'show access-rulebase' / 'show nat-rulebase'
with details-level full, use-object-dictionary true and dereference-group-members true. All names and addresses are invented.

Usage: python3 tests/tools/make_checkpoint_sample.py > tests/data/checkpoint_sample.json
"""
import json
import sys
import uuid

NS = uuid.UUID("6f1d2c3a-0000-4000-8000-000000000001")
USER = {"uid": "41e821a0-3720-11e3-aa6e-0800200c9fde", "name": "SMC User", "domain-type": "domain"}
DATA = {"uid": "a0bbbc99-adef-4ef8-bb6d-defdefdefdef", "name": "Check Point Data", "domain-type": "data domain"}
objects = {}


def uid(name):
    return str(uuid.uuid5(NS, name))


def obj(name, kind, predefined=False, **fields):
    entry = {"uid": uid(name), "name": name, "type": kind, "domain": DATA if predefined else USER}
    entry.update({key.replace("_", "-"): value for key, value in fields.items()})
    objects[name] = entry
    return entry["uid"]


def ref(name):
    return objects[name]["uid"]


# globals
obj("Any", "CpmiAnyObject", True)
obj("Policy Targets", "Global", True)
obj("Original", "Global", True)
for action in ("Accept", "Drop", "Reject"):
    obj(action, "RulebaseAction", True)
obj("Inner Layer", "Global", True)
obj("Log", "Track", True)
obj("None", "Track", True)
# network objects
obj("web-1", "host", ipv4_address="10.20.0.10", comments="Web server in the DMZ",
    nat_settings={"auto-rule": True, "ipv4-address": "203.0.113.10", "ipv6-address": "", "hide-behind": "ip-address",
                  "install-on": "All", "method": "static"})
obj("mail-1", "host", ipv4_address="10.20.0.25", nat_settings={"auto-rule": False})
obj("mail-public", "host", ipv4_address="203.0.113.25")
obj("dns-1", "host", ipv4_address="192.0.2.53")
obj("dns-2", "host", ipv4_address="192.0.2.54", ipv6_address="2001:db8:53::54")
obj("nat-out", "host", ipv4_address="198.51.100.20")
obj("lan-net", "network", subnet4="10.10.0.0", mask_length4=16, subnet_mask="255.255.0.0")
obj("guest-net", "network", subnet4="10.10.200.0", mask_length4=24, subnet_mask="255.255.255.0")
obj("dmz-net", "network", subnet4="10.20.0.0", mask_length4=24, subnet_mask="255.255.255.0")
obj("plc-net", "network", subnet4="10.30.1.0", mask_length4=24, subnet_mask="255.255.255.0",
    nat_settings={"auto-rule": True, "hide-behind": "gateway", "install-on": "All", "method": "hide"})
obj("lan6-net", "network", subnet6="2001:db8:10::", mask_length6=48)
obj("admin-range", "address-range", ipv4_address_first="10.10.5.10", ipv4_address_last="10.10.5.20")
obj("dns-servers", "group", members=[objects["dns-1"], objects["dns-2"]])
obj("dmz-servers", "group", members=[objects["web-1"], objects["mail-1"]], comments="Everything in the DMZ")
obj(".updates.example.com", "dns-domain", is_sub_domain=False)
obj("lan-without-guests", "group-with-exclusion", include=ref("lan-net"), **{"except": ref("guest-net")})
obj("netadmins", "access-role")
obj("gw-edge", "simple-gateway", ipv4_address="198.51.100.1")
for zone in ("InternalZone", "ExternalZone", "DMZZone"):
    obj(zone, "security-zone", True)
# services
obj("http", "service-tcp", True, port="80")
obj("https", "service-tcp", True, port="443")
obj("ssh", "service-tcp", True, port="22")
obj("smtp", "service-tcp", True, port="25")
obj("ident", "service-tcp", True, port="113")
obj("domain-udp", "service-udp", True, port="53")
obj("domain-tcp", "service-tcp", True, port="53")
obj("echo-request", "service-icmp", True, icmp_type=8)
obj("gre", "service-other", True, ip_protocol=47)
obj("tcp-2525", "service-tcp", port="2525")
obj("tcp-high", "service-tcp", port="9000-9010", comments="Application ports")
obj("syslog-from-high", "service-udp", port="514", source_port=">1023")
obj("app-ports", "service-group", members=[objects["https"], objects["tcp-high"]])
obj("Facebook", "application-site", True)
obj("Work-Hours", "time")
obj("Partner-VPN", "vpn-community-meshed")
obj("DMZ-Layer", "access-layer", implicit_cleanup_action="drop")
obj("Network", "access-layer", implicit_cleanup_action="drop")

used = set()
counter = {"n": 0}


def cell(names):
    used.update(names)
    return [ref(name) for name in names]


def rule(name, source, destination, service, action="Accept", track="Log", number=None, **extra):
    counter["n"] += 1
    used.update([action, track, "Policy Targets", "Any"])
    entry = {
        "uid": uid(f"rule-{counter['n']}"),
        "type": "access-rule",
        "domain": USER,
        "rule-number": number or counter["n"],
        "track": {"type": ref(track), "per-session": False, "per-connection": track != "None", "accounting": False,
                  "enable-firewall-session": False, "alert": "none"},
        "source": cell(source),
        "source-negate": False,
        "destination": cell(destination),
        "destination-negate": False,
        "service": cell(service),
        "service-negate": False,
        "vpn": cell(["Any"]),
        "action": ref(action),
        "action-settings": {"enable-identity-captive-portal": False},
        "content": cell(["Any"]),
        "content-negate": False,
        "content-direction": "any",
        "time": cell(["Any"]),
        "comments": "",
        "enabled": True,
        "install-on": cell(["Policy Targets"]),
    }
    if name:
        entry["name"] = name
    for key, value in extra.items():
        key = key.replace("_", "-")
        if key in ("vpn", "time", "install-on"):
            value = cell(value)
        elif key == "inline-layer":
            used.add(value)
            value = ref(value)
        entry[key] = value
    return entry


def section(name, rules):
    return {"uid": uid(f"section-{name}"), "name": name, "type": "access-section",
            "from": rules[0]["rule-number"], "to": rules[-1]["rule-number"], "rulebase": rules}


def dictionary(names):
    out, todo = [], sorted(names)
    seen = set()
    while todo:
        name = todo.pop(0)
        if name in seen:
            continue
        seen.add(name)
        out.append(objects[name])
    return out


infrastructure = [
    rule("DNS", ["lan-net", "dmz-net"], ["dns-servers"], ["domain-udp", "domain-tcp"], comments="Name resolution"),
    rule("", ["admin-range"], ["dmz-servers"], ["ssh"], install_on=["gw-edge"]),
]
outbound = [
    rule("Web out", ["InternalZone"], ["ExternalZone"], ["http", "https"]),
    rule("Guests stay out", ["guest-net"], ["dns-servers"], ["Any"], "Drop", destination_negate=True),
    rule("Social", ["lan-net"], ["Any"], ["Facebook"]),
    rule("Admins", ["netadmins"], ["plc-net"], ["Any"]),
    rule("Updates", ["dmz-servers"], [".updates.example.com"], ["https"], time=["Work-Hours"]),
    rule("Old rule", ["lan-without-guests"], ["Any"], ["syslog-from-high"], enabled=False),
    rule("Partners", ["lan-net"], ["plc-net"], ["Any"], vpn=["Partner-VPN"]),
    rule("IPv6 out", ["lan6-net"], ["Any"], ["https"], track="None"),
]
inbound = [
    rule("Public web", ["Any"], ["web-1"], ["https"], comments="web-1 has automatic static NAT"),
    rule("DMZ access", ["Any"], ["dmz-net"], ["Any"], "Inner Layer", "None", inline_layer="DMZ-Layer"),
    rule("Tunnels", ["Any"], ["gw-edge"], ["gre"]),
    rule("No ident", ["Any"], ["Any"], ["ident"], "Reject"),
    rule("Cleanup rule", ["Any"], ["Any"], ["Any"], "Drop"),
]
network_used = set(used) | {"Network"}
network = {
    "uid": ref("Network"),
    "name": "Network",
    "rulebase": [section("Infrastructure", infrastructure), section("Outbound", outbound), section("Inbound", inbound)],
    "objects-dictionary": dictionary(network_used),
    "from": 1,
    "to": counter["n"],
    "total": counter["n"],
}

used.clear()
counter["n"] = 0
dmz_rules = [
    rule("Web in", ["Any"], ["web-1"], ["app-ports"]),
    rule("Mail in", ["Any"], ["mail-1"], ["smtp"]),
    rule("Ping from LAN", ["lan-net"], ["Any"], ["echo-request"], track="None"),
]
dmz = {
    "uid": ref("DMZ-Layer"),
    "name": "DMZ-Layer",
    "rulebase": dmz_rules,
    "objects-dictionary": dictionary(set(used) | {"DMZ-Layer"}),
    "from": 1,
    "to": 3,
    "total": 3,
}

used.clear()
counter["n"] = 0


def nat(original_source="Any", original_destination="Any", original_service="Any", translated_source="Original",
        translated_destination="Original", translated_service="Original", method="static", **extra):
    counter["n"] += 1
    names = [original_source, original_destination, original_service, translated_source, translated_destination,
             translated_service, "Policy Targets"]
    used.update(names)
    entry = {
        "uid": uid(f"nat-{counter['n']}"),
        "type": "nat-rule",
        "domain": USER,
        "rule-number": counter["n"],
        "method": method,
        "auto-generated": False,
        "original-source": ref(original_source),
        "original-destination": ref(original_destination),
        "original-service": ref(original_service),
        "translated-source": ref(translated_source),
        "translated-destination": ref(translated_destination),
        "translated-service": ref(translated_service),
        "comments": "",
        "enabled": True,
        "install-on": [ref("Policy Targets")],
    }
    entry.update({key.replace("_", "-"): value for key, value in extra.items()})
    return entry


def nat_section(name, rules):
    entry = {"uid": uid(f"nat-section-{name}"), "name": name, "type": "nat-section", "rulebase": rules}
    if rules:
        entry.update({"from": rules[0]["rule-number"], "to": rules[-1]["rule-number"]})
    return entry


# An automatic rule names the object itself where SmartConsole shows "(Valid Address)" or "(Hiding Address)".
automatic = [
    nat(original_source="web-1", translated_source="web-1", auto_generated=True),
    nat(original_destination="web-1", translated_destination="web-1", auto_generated=True),
]
automatic_hide = [
    nat(original_source="plc-net", original_destination="plc-net", auto_generated=True),
    nat(original_source="plc-net", translated_source="plc-net", method="hide", auto_generated=True),
]
manual = [
    nat(original_source="lan-net", original_destination="dmz-net", comments="No NAT towards the DMZ"),
    nat(original_destination="mail-public", original_service="tcp-2525", translated_destination="mail-1",
        translated_service="smtp", comments="Mail on an alternative port"),
    nat(original_source="dmz-net", translated_source="nat-out", method="hide"),
    nat(original_source="lan-net", translated_source="gw-edge", method="hide", comments="Hide behind the gateway"),
    nat(original_source="guest-net", translated_source="nat-out", method="hide", enabled=False),
]
nat_rulebase = {
    "uid": uid("nat-rulebase"),
    "rulebase": [
        nat_section("Automatic Generated Rules : Machine Static NAT", automatic),
        nat_section("Automatic Generated Rules : Address Range Static NAT", []),
        nat_section("Automatic Generated Rules : Network Hide NAT", automatic_hide),
        nat_section("Manual Lower Rules", manual),
    ],
    "objects-dictionary": dictionary(used),
    "from": 1,
    "to": counter["n"],
    "total": counter["n"],
}

json.dump([network, dmz, nat_rulebase], sys.stdout, indent=1)
sys.stdout.write("\n")
