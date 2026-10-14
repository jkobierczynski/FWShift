# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco Meraki MX: parser, emitter, and packet-level equivalence with a judge of its own.

A random network is a plain description (VLANs, a static route, policy objects and groups, the outbound table, layer 7
rules, port forwarding, 1:1 and 1:many NAT, the uplinks, NAT exceptions, the inbound table, passthrough mode) that
``bundle`` writes as the answers of the Dashboard API and ``MxJudge`` decides packets from, as an MX does: inside one
VLAN everything passes; from a VLAN the outbound table (first match, then the fixed default rule that allows) and after
it the layer 7 rules that block; from the internet only what a NAT rule lets in, or with NAT exceptions and in
passthrough mode what the inbound table lets in. ``read_script`` reads the bodies the emitter writes back into such a
description, so the same judge decides the output. None of it shares code with the parser or the emitter.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows, random_model

from fwshift import cli
from fwshift.errors import ParseError
from fwshift.options import Options
from fwshift.parsers import meraki as parse_meraki
from fwshift.report import Report

UPLINK = "203.0.113.2"
UPLINK2 = "203.0.113.3"
DEFAULT = {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcPort": "Any", "srcCidr": "Any", "destPort": "Any",
           "destCidr": "Any", "syslogEnabled": False}  # fmt: skip
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}
POOL = ["10.10.10.5", "10.10.10.50", "10.10.20.15", "10.10.20.25", "10.10.20.30", "10.10.20.31", "10.10.30.9", "172.16.40.11", "172.16.40.99",
        "192.0.2.7", "198.51.100.4", "203.0.113.99", UPLINK, UPLINK2, "203.0.113.25", "203.0.113.30", "2001:db8:10::5", "2001:db8:99::1"]  # fmt: skip
PORTS = [22, 25, 53, 80, 102, 443, 4840, 8443, 9443, 1024, 5000, 5004, 0, 8000, 8005, 8010, 8011, 587]


def addr(text: str) -> Any:
    return ipaddress.ip_address(text)


def in_net(address: str, net: str) -> bool:
    probe, network = addr(address), ipaddress.ip_network(net, strict=False)
    return probe.version == network.version and probe in network


def ports_ok(field: str, port: int) -> bool:
    if field.lower() == "any":
        return True
    if "-" in field:
        low, high = (int(x) for x in field.split("-"))
        return low <= port <= high
    return port in [int(p) for p in field.split(",")]


# -- the judge ------------------------------------------------------------------------------------------------


class MxJudge:
    def __init__(self, mx: Dict[str, Any]) -> None:
        self.mx = mx
        self.uplinks: Dict[str, str] = mx.get("uplinks") or {"internet1": UPLINK}

    def zone(self, address: str) -> str:
        for ident, (subnet, v6) in self.mx["vlans"].items():
            if in_net(address, subnet) or (v6 and in_net(address, v6)) or any(in_net(address, r) for r in self.mx["routes"].get(ident, [])):
                return f"vlan{ident}"
        return "internet"

    def addresses(self, uplink: str) -> List[str]:
        if uplink in ("both", "all"):
            return list(self.uplinks.values())
        return [self.uplinks[uplink]] if uplink in self.uplinks else []

    def token(self, token: str, address: str) -> Optional[bool]:
        token = token.strip()
        if token.lower() == "any":
            return True
        vlan = re.fullmatch(r"VLAN\((\d+)\)\.(\*|\d+)", token)
        if vlan:
            subnet, v6 = self.mx["vlans"][vlan.group(1)]
            if vlan.group(2) == "*":
                return in_net(address, subnet) or bool(v6 and in_net(address, v6))
            base = ipaddress.ip_network(subnet).network_address
            return address == str(base + int(vlan.group(2)))
        ref = re.fullmatch(r"(OBJ|GRP)\((\d+)\)", token)
        if ref:
            if ref.group(1) == "OBJ":
                found = self.mx["objects"][ref.group(2)]
                return None if not found[0].isdigit() and ":" not in found else in_net(address, found)
            return any(self.token(f"OBJ({m})", address) for m in self.mx["groups"][ref.group(2)])
        if re.fullmatch(r"[0-9.:/a-f]+", token):
            return in_net(address, token)
        return None  # (a host name: the model matches no address with it)

    def side(self, field: str, address: str) -> Optional[bool]:
        results = [self.token(t, address) for t in field.split(",")]
        if True in results:
            return True
        return None if None in results else False

    def first_match(self, rules: List[Dict[str, Any]], pkt: Packet) -> Tuple[bool, Optional[bool]]:
        """(whether a rule matched, its verdict: None when it cannot be told)."""
        number = str(NUMBERS.get(pkt.proto, pkt.proto))
        for rule in rules:
            if rule.get("bad"):
                return True, None
            source, destination = self.side(rule["srcCidr"], pkt.src), self.side(rule["destCidr"], pkt.dst)
            if source is None or destination is None:
                if source is False or destination is False:
                    continue
                return True, None
            if not (source and destination):
                continue
            protocol = rule["protocol"].lower()
            if protocol in ("tcp", "udp"):
                if pkt.proto != protocol or not ports_ok(rule["srcPort"], pkt.sport) or not ports_ok(rule["destPort"], pkt.dport):
                    continue
            elif protocol in ("icmp", "icmp6"):
                if str(NUMBERS[protocol]) != number:
                    continue
            elif protocol != "any":
                raise AssertionError(rule)
            return True, rule["policy"] == "allow"
        return False, None

    def outbound(self, pkt: Packet) -> Optional[bool]:
        matched, verdict = self.first_match(self.mx["l3"], pkt)
        return verdict if matched else True

    def layer7(self, pkt: Packet) -> Optional[bool]:
        for rule in self.mx["l7"]:
            if rule["type"] == "port":
                if pkt.proto in ("tcp", "udp") and pkt.dport == int(rule["value"]):
                    return False
            elif rule["type"] == "ipRange":
                net, _, port = rule["value"].partition(":") if "::" not in rule["value"] else (rule["value"], "", "")
                if in_net(pkt.dst, net) and (not port or (pkt.proto in ("tcp", "udp") and pkt.dport == int(port))):
                    return False
            else:
                return None
        return True

    def public(self, address: str) -> bool:
        """Whether an address is one NAT rules or the uplinks answer on."""
        return address in self.uplinks.values() or any(address == o["publicIp"] for o in self.mx["one_to_one"]) or \
            any(address == m["publicIp"] for m in self.mx["one_to_many"])

    def inbound(self, pkt: Packet) -> Tuple[Optional[bool], str]:
        """(verdict, zone after NAT) for a packet from the internet."""
        for forward in self.mx["forwards"]:
            if pkt.dst in self.addresses(forward["uplink"]):
                if forward.get("bad"):
                    return None, "internet"
                if pkt.proto == forward["protocol"] and ports_ok(forward["publicPort"], pkt.dport):
                    return any(a == "any" or in_net(pkt.src, a) for a in forward["allowedIps"]), self.zone(forward["lanIp"])
        for one in self.mx["one_to_one"]:
            if pkt.dst == one["publicIp"]:
                if one.get("bad"):
                    return None, "internet"
                for entry in one["allowedInbound"]:
                    proto = entry["protocol"]
                    if (proto == "any" or (proto == "icmp-ping" and pkt.proto == "icmp" and pkt.icmp_type == 8) or
                            (proto == pkt.proto and any(p == "any" or ports_ok(p, pkt.dport) for p in entry["destinationPorts"]))) and \
                            any(a == "any" or in_net(pkt.src, a) for a in entry["allowedIps"]):
                        return True, self.zone(one["lanIp"])
                return False, self.zone(one["lanIp"])
        for many in self.mx["one_to_many"]:
            if pkt.dst == many["publicIp"]:
                for port_rule in many["portRules"]:
                    if port_rule.get("bad"):
                        return None, "internet"
                    if pkt.proto == port_rule["protocol"] and ports_ok(port_rule["publicPort"], pkt.dport):
                        return any(a == "any" or in_net(pkt.src, a) for a in port_rule["allowedIps"]), self.zone(port_rule["localIp"])
        return None, self.zone(pkt.dst)

    def allows(self, pkt: Packet) -> Tuple[Optional[bool], str, str]:
        ingress = self.zone(pkt.src)
        egress = self.zone(pkt.dst)
        if ingress == "internet":
            passthrough = self.mx.get("mode") == "passthrough"
            if passthrough or self.mx.get("nat_off"):
                if egress == "internet" or self.public(pkt.dst):
                    return None, ingress, egress  # (what NAT rules let in is the inbound table's, which the judge does not tell)
                table = self.mx.get("inbound")
                if table is None:
                    return (True if passthrough else None), ingress, egress
                matched, verdict = self.first_match(table["rules"], pkt)
                if matched:
                    return verdict, ingress, egress
                if table.get("default") is None:
                    return (True if passthrough else None), ingress, egress
                return table["default"] == "allow", ingress, egress
            verdict, after = self.inbound(pkt)
            if verdict is None:
                return (None if after == "internet" else False), ingress, after
            return verdict, ingress, after
        if ingress == egress:
            return True, ingress, egress
        verdict = self.outbound(pkt)
        if verdict:
            verdict = self.layer7(pkt)
        return verdict, ingress, egress


# -- random networks ------------------------------------------------------------------------------------------


def random_mx(rng: random.Random) -> Dict[str, Any]:
    mx: Dict[str, Any] = {"vlans": {"10": ("10.10.10.0/24", "2001:db8:10::/64" if rng.random() < 0.5 else ""), "20": ("10.10.20.0/24", ""),
                                    "30": ("10.10.30.0/24", "")},
                          "routes": {"30": ["172.16.40.0/24"]} if rng.random() < 0.7 else {},
                          "objects": {"4001": "10.10.10.50/32", "4002": "172.16.40.0/28", "4003": "updates.example.com", "4004": "10.10.10.50/32",
                                      "4005": "10.10.10.50/24"},
                          "names": {"4004": "any"}, "groups": {"5001": ["4001", "4002"], "5002": ["4001", "4005"]}, "l3": [], "l7": [],
                          "forwards": [], "one_to_one": [], "one_to_many": [], "default": rng.random() < 0.9,
                          "uplinks": {"internet1": UPLINK, "internet2": UPLINK2} if rng.random() < 0.3 else {"internet1": UPLINK},
                          "mode": "passthrough" if rng.random() < 0.08 else "routed", "nat_off": [], "inbound": None}  # fmt: skip
    if rng.random() < 0.15:
        mx["nat_off"] = [rng.choice(["wan" + name[8:] for name in mx["uplinks"]])]
    tokens = ["Any", "10.10.10.0/24", "10.10.20.15/32", "10.10.20.0/25", "172.16.40.0/24", "192.0.2.0/24", "198.51.100.4", "VLAN(10).*",
              "VLAN(20).*", "VLAN(30).*", "VLAN(20).15", "OBJ(4001)", "OBJ(4002)", "GRP(5001)", "2001:db8:10::/64", "2001:db8:99::/48",
              "OBJ(4004)"]  # fmt: skip
    for index in range(rng.randint(3, 12)):
        rule: Dict[str, Any] = {"comment": f"rule {index}" if rng.random() < 0.9 else "", "policy": rng.choice(["allow", "allow", "deny"]),
                                "protocol": rng.choice(["tcp", "tcp", "udp", "icmp", "icmp6", "any"]), "srcPort": "Any", "destPort": "Any",
                                "syslogEnabled": rng.random() < 0.3}  # fmt: skip
        for side in ("srcCidr", "destCidr"):
            picked = rng.sample(tokens, rng.randint(1, 2))
            rule[side] = "Any" if "Any" in picked else ",".join(picked)
        if rng.random() < 0.08:
            rule["destCidr"] = rng.choice(["updates.example.com", "OBJ(4003)"])
        if rule["protocol"] in ("tcp", "udp"):
            rule["destPort"] = rng.choice(["Any", "443", "80,443", "1024-5000", "53", "102"])
            if rng.random() < 0.15:
                rule["srcPort"] = rng.choice(["1024-65535", "5004"])
            if rng.random() < 0.04:
                rule["destPort"], rule["bad"] = "1024-5000,5004", True  # (a range and a port: not converted)
        if rng.random() < 0.03:
            rule["srcCidr"], rule["bad"] = "OBJ(9999)", True  # (an object not in the input)
        if rng.random() < 0.03:
            rule["srcCidr"], rule["bad"] = "10.10.10.5/24", True  # (host bits: not converted)
        if rng.random() < 0.03:
            rule["destCidr"], rule["bad"] = rng.choice(["OBJ(4005)", "GRP(5002)"]), True  # (an object with host bits, and a group of it)
        if rng.random() < 0.02:
            rule["srcCidr"], rule["bad"] = "OBJ(4003)", True  # (a host name as a source)
        mx["l3"].append(rule)
    if rng.random() < 0.3:
        mx["l7"].append({"policy": "deny", "type": "port", "value": rng.choice(["23", "443"])})
    if rng.random() < 0.3:
        mx["l7"].append({"policy": "deny", "type": "ipRange", "value": rng.choice(["198.51.100.0/24", "192.0.2.0/24:443", "2001:db8:99::/48"])})
    if rng.random() < 0.05:
        mx["l7"].append({"policy": "deny", "type": "applicationCategory", "value": {"id": "meraki:layer7/category/24", "name": "Advertising"}})
    if rng.random() < 0.6:
        ports = ("8443", "443") if rng.random() < 0.7 else ("8000-8010", "9000-9010")
        forward = {"name": "portal", "lanIp": "10.10.20.30", "uplink": rng.choice(list(mx["uplinks"]) + ["both"]), "protocol": "tcp",
                   "publicPort": ports[0], "localPort": ports[1],
                   "allowedIps": rng.choice([["any"], ["198.51.100.0/24"], ["192.0.2.7/32", "198.51.100.4"]])}  # fmt: skip
        if rng.random() < 0.06:
            forward["publicPort"], forward["bad"] = rng.choice(["any", ""]), True
        if rng.random() < 0.04:
            forward["allowedIps"], forward["bad"] = rng.choice([["198.51.100.5/24"], ["198.51.100.0/24, 192.0.2.0/24"], ["OBJ(77)"]]), True
        mx["forwards"].append(forward)
    if rng.random() < 0.6:
        one = {"name": "mail", "publicIp": "203.0.113.25", "lanIp": "10.10.20.25", "uplink": "internet1",
               "allowedInbound": [{"protocol": "tcp", "destinationPorts": rng.choice([["25"], ["25", "587"], ["any"], ["8000-8010"]]), "allowedIps": ["any"]},
                                  {"protocol": "icmp-ping", "destinationPorts": ["any"], "allowedIps": ["192.0.2.0/24"]}]}  # fmt: skip
        if rng.random() < 0.05:
            one["allowedInbound"][0]["destinationPorts"], one["bad"] = "25", True  # (not a list)
        mx["one_to_one"].append(one)
    if rng.random() < 0.5:
        ports = ("9443", "443") if rng.random() < 0.7 else ("5000-5004", "6000-6004")
        mx["one_to_many"].append({"publicIp": "203.0.113.30", "uplink": "internet1",
                                  "portRules": [{"name": "view", "protocol": "tcp", "publicPort": ports[0], "localIp": "10.10.10.5", "localPort": ports[1],
                                                 "allowedIps": ["192.0.2.7/32"]}]})  # fmt: skip
    if mx["mode"] == "passthrough" or mx["nat_off"] or rng.random() < 0.2:
        if rng.random() < 0.85:
            rules = []
            for index in range(rng.randint(0, 4)):
                rule = {"comment": f"in {index}", "policy": rng.choice(["allow", "deny"]), "protocol": rng.choice(["tcp", "udp", "any"]),
                        "srcPort": "Any", "srcCidr": rng.choice(["Any", "192.0.2.0/24", "198.51.100.4"]), "destPort": "Any",
                        "destCidr": rng.choice(["Any", "10.10.20.0/24", "10.10.20.15/32", "VLAN(10).*"]), "syslogEnabled": False}  # fmt: skip
                if rule["protocol"] != "any":
                    rule["destPort"] = rng.choice(["Any", "22", "443", "8000-8010"])
                rules.append(rule)
            mx["inbound"] = {"rules": rules, "default": rng.choice(["allow", "deny", "deny"])}
    return mx


def bundle(mx: Dict[str, Any], rng: random.Random) -> Dict[str, Any]:
    vlans = []
    for ident, (subnet, v6) in mx["vlans"].items():
        vlan: Dict[str, Any] = {"id": int(ident) if rng.random() < 0.5 else ident, "name": {"10": "office", "20": "servers", "30": "ot"}[ident],
                                "subnet": subnet, "applianceIp": str(ipaddress.ip_network(subnet).network_address + 1)}  # fmt: skip
        if v6:
            vlan["ipv6"] = {"enabled": True, "prefixAssignments": [{"staticPrefix": v6}]}
        vlans.append(vlan)
    routes = [{"enabled": True, "name": f"r{i}", "subnet": subnet, "gatewayIp": "10.10.30.254", "gatewayVlanId": int(ident)}
              for ident, subnets in mx["routes"].items() for i, subnet in enumerate(subnets)]  # fmt: skip
    names = mx.get("names", {})
    objects = [{"id": ident, "name": names.get(ident, f"obj-{ident}"), "category": "network", "type": "fqdn" if value[0].isalpha() else "cidr",
                ("fqdn" if value[0].isalpha() else "cidr"): value} for ident, value in mx["objects"].items()]  # fmt: skip
    groups = [{"id": ident, "name": f"grp-{ident}", "category": "NetworkObjectGroup", "objectIds": [int(m) for m in members]}
              for ident, members in mx["groups"].items()]  # fmt: skip
    l3 = [{k: v for k, v in rule.items() if k != "bad"} for rule in mx["l3"]]
    for rule in l3:
        for key in ("srcCidr", "destCidr"):
            if rng.random() < 0.1:
                rule[key] = rule[key].replace("OBJ(", "OBJ[").replace(")", "]") if "OBJ(" in rule[key] and "VLAN" not in rule[key] else rule[key]
            if rule[key] == "Any" and rng.random() < 0.3:
                rule[key] = "any"
    if mx["default"]:
        l3.append(dict(DEFAULT))
    strip = [{k: v for k, v in item.items() if k != "bad"} for item in mx["forwards"]]
    document = {"fwshift": "meraki-mx", "applianceSettings": {"deploymentMode": mx.get("mode", "routed")}, "vlansSettings": {"vlansEnabled": True},
                "vlans": vlans, "staticRoutes": routes, "l3FirewallRules": {"rules": l3}, "l7FirewallRules": {"rules": mx["l7"]},
                "portForwardingRules": {"rules": strip}, "oneToOneNatRules": {"rules": [{k: v for k, v in o.items() if k != "bad"} for o in mx["one_to_one"]]},
                "oneToManyNatRules": {"rules": mx["one_to_many"]}, "policyObjects": objects, "policyObjectsGroups": groups,
                "uplinkStatuses": [{"uplinks": [{"interface": "wan" + name[8:], "ip": address} for name, address in mx.get("uplinks", {"internet1": UPLINK}).items()]}]}  # fmt: skip
    if mx.get("nat_off"):
        document["uplinksNat"] = [{"uplinks": [{"interface": "wan" + name[8:], "nat": {"enabled": "wan" + name[8:] not in mx["nat_off"]}}
                                               for name in mx["uplinks"]]}]  # fmt: skip
    if mx.get("inbound") is not None:
        rules = [dict(r) for r in mx["inbound"]["rules"]]
        if mx["inbound"].get("default"):
            rules.append(dict(DEFAULT, policy=mx["inbound"]["default"]))
        document["inboundFirewallRules"] = {"rules": rules, "syslogDefaultRule": False}
    return document


def mx_packet(rng: random.Random) -> Optional[Packet]:
    src, dst = rng.choice(POOL), rng.choice(POOL)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if ":" in src else "icmp", "47"])
    return Packet("", "", src, dst, proto, rng.choice([1024, 40000, 5004, 80]), rng.choice(PORTS), rng.choice([8, 0, 3]))


def parse(document: Any) -> Tuple[Any, Report]:
    report = Report()
    return parse_meraki.parse(json.dumps(document).encode(), report), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def judged(mx: Dict[str, Any], model: Any, rng: random.Random, seed: int, packets: int = 300) -> int:
    judge = MxJudge(mx)
    by_index = {r.source_ids.get("meraki.rule"): r for r in model.rules if r.source_ids.get("meraki.table") == "outbound"}
    for index, rule in enumerate(mx["l3"], 1):
        if rule.get("bad"):
            assert by_index[str(index)].unsupported, (seed, rule)
    count = 0
    for _ in range(packets):
        pkt = mx_packet(rng)
        if pkt is None:
            continue
        verdict, ingress, egress = judge.allows(pkt)
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = _zone(model, ingress), _zone(model, egress)
        count += 1
        assert model_allows(model, pkt) == verdict, (seed, pkt, ingress, egress, json.dumps(mx, indent=1))
    return count


def _zone(model: Any, zone: str) -> str:
    """The zone of the model for vlanNN: vlanNN-name."""
    return next((z for z in model.zones if z == zone or z.startswith(zone + "-")), zone)


def test_parsed_network_decides_like_the_judge() -> None:
    compared = 0
    for seed in range(500):
        rng = random.Random(seed)
        mx = random_mx(rng)
        document = bundle(mx, rng)
        assert cli.detect_format(json.dumps(document).encode()) == "meraki"
        model, _ = parse(document)
        compared += judged(mx, model, rng, seed)
    assert compared > 30000


# -- the emitted script, read back -------------------------------------------------------------------------


def read_script(text: str) -> Dict[str, Any]:
    """The bodies of the script, as a random network (without VLANs: the judge is given them)."""
    found: Dict[str, Any] = {}
    lines = text.splitlines()
    assert lines[0] == "#!/bin/sh" and "set -eu" in lines
    index = 0
    while index < len(lines):
        start = re.fullmatch(r"cat > \"\$OUT/(\w+)\.json\" <<'FWSHIFT_EOF'", lines[index])
        if start:
            end = lines.index("FWSHIFT_EOF", index)
            found[start.group(1)] = json.loads("\n".join(lines[index + 1:end]))
            index = end
        index += 1
    for line in lines:
        assert line.isprintable() and len(line) < 4000, line
    mx: Dict[str, Any] = {"l3": [], "l7": [], "forwards": [], "one_to_one": [], "one_to_many": []}
    for rule in found["l3FirewallRules"]["rules"]:
        assert set(rule) == {"comment", "policy", "protocol", "srcPort", "srcCidr", "destPort", "destCidr", "syslogEnabled"}, rule
        assert rule["policy"] in ("allow", "deny") and rule["protocol"] in ("tcp", "udp", "icmp", "icmp6", "any"), rule
        assert len(rule["comment"]) <= 127
        for key in ("srcPort", "destPort"):
            value = rule[key]
            assert value == "Any" or re.fullmatch(r"\d+-\d+|\d+(,\d+)*", value), rule
            assert value == "Any" or all(1 <= int(p) <= 65535 for p in re.split("[-,]", value)), rule
            assert value == "Any" or rule["protocol"] in ("tcp", "udp"), rule
        for key in ("srcCidr", "destCidr"):
            if rule[key] != "Any":
                families = {ipaddress.ip_network(t).version for t in rule[key].split(",") if not t[0].isalpha()}
                assert len(families) <= 1, rule
                assert families != {6} or rule["protocol"] != "icmp", rule
                assert families != {4} or rule["protocol"] != "icmp6", rule
                assert key == "destCidr" or not any(t[0].isalpha() for t in rule[key].split(",")), rule
        mx["l3"].append(rule)
    assert found["l3FirewallRules"].get("syslogDefaultRule") is False
    mx["forwards"] = found.get("portForwardingRules", {}).get("rules", [])
    mx["one_to_one"] = found.get("oneToOneNatRules", {}).get("rules", [])
    mx["one_to_many"] = found.get("oneToManyNatRules", {}).get("rules", [])
    for item in mx["forwards"] + [r for m in mx["one_to_many"] for r in m["portRules"]]:
        for key in ("publicPort", "localPort"):
            low, _, high = item[key].partition("-")
            assert low.isdigit() and 1 <= int(low) <= int(high or low) <= 65535, item
        assert item["allowedIps"] and all(a == "any" or ipaddress.ip_network(a).version == 4 for a in item["allowedIps"]), item
    for one in mx["one_to_one"]:
        for entry in one["allowedInbound"]:
            assert entry["allowedIps"] and all(p == "any" or re.fullmatch(r"\d+(-\d+)?", p) for p in entry["destinationPorts"]), entry
    return mx


def emit(model: Any, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import meraki as emit_meraki

    report = Report()
    return emit_meraki.emit(model, report, options or Options()), report


NETWORKS = {"eth0": ["10.0.0.0/23", "2001:db8::/47"], "eth1": ["10.0.2.0/23", "2001:db8:2::/48"], "eth2": ["0.0.0.0/0", "::/0"]}


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    from test_iptables import random_packet

    from fwshift.model import Action, Zone

    rng = random.Random(seed)
    model = random_model(rng)
    for zone in NETWORKS:
        model.zones.setdefault(zone, Zone(zone))
    if rng.random() < 0.3:
        model.default_interzone = Action.ALLOW
    model.default_intrazone = Action.ALLOW
    options = Options(zone_networks=NETWORKS, inside_zones=["eth0", "eth1"])
    text, report = emit(model, options)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    mx = read_script(text)
    mx.update({"vlans": {"0": ("10.0.0.0/23", "2001:db8::/47"), "2": ("10.0.2.0/23", "2001:db8:2::/48")}, "routes": {}, "objects": {}, "groups": {}})
    judge = MxJudge(mx)
    compared = 0
    for _ in range(600):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        verdict, ingress, egress = judge.allows(pkt)
        if ingress == "internet" or ingress == egress:
            continue  # (from the internet only NAT lets in: the test below; inside one VLAN the MX does not filter)
        pkt.in_if = {"vlan0": "eth0", "vlan2": "eth1"}[ingress]
        pkt.out_if = {"vlan0": "eth0", "vlan2": "eth1", "internet": "eth2"}[egress]
        compared += 1
        assert verdict == model_allows(model, pkt), (seed, pkt, text)
    assert compared > 100


def random_nat_model(rng: random.Random) -> Any:
    """A model with destination NAT and 1:1 NAT to LAN and DMZ, and rules from the internet and a partner zone."""
    from fwshift.model import (ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, Service, ServiceEntry, SnatKind,
                               SourceNat, Zone)  # fmt: skip

    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    p.zones = {z: Zone(z) for z in ("lan", "dmz", "wan", "partner")}
    for name, value in (("pub-web", "203.0.113.10/32"), ("pub-mail", "203.0.113.20/32"), ("uplink", UPLINK + "/32"), ("web", "10.0.0.17/32"),
                        ("mail", "10.0.0.20/32"), ("db", "172.16.0.5/32"), ("partners", "192.0.2.0/24"), ("remote", "198.51.100.0/24"),
                        ("half", "198.51.100.0/25"), ("near", "192.0.2.0/25")):  # fmt: skip
        p.addresses[name] = Address(name, AddressKind.NETWORK, value)
    p.services = {"web443": Service("web443", [ServiceEntry(Protocol.TCP, "443")]), "alt": Service("alt", [ServiceEntry(Protocol.TCP, "8000-8010")]),
                  "alt5": Service("alt5", [ServiceEntry(Protocol.TCP, "8005")]),
                  "split": Service("split", [ServiceEntry(Protocol.TCP, "8000-8004"), ServiceEntry(Protocol.TCP, "8005-8010")]),
                  "dns": Service("dns", [ServiceEntry(Protocol.UDP, "53")]), "ping": Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)]),
                  "icmp": Service("icmp", [ServiceEntry(Protocol.ICMP)]), "smtp": Service("smtp", [ServiceEntry(Protocol.TCP, "25")]),
                  "from-high": Service("from-high", [ServiceEntry(Protocol.TCP, "443", "1024-65535")])}  # fmt: skip
    first = rng.choice(["web443", "alt"])
    p.nat_rules = [NatRule("dnat-web", destinations=["pub-web"], service=first, origin="dnat-web",
                           destination_translation=DestNat("web", rng.choice(["", "8443"]) if first == "web443" else rng.choice(["", "9000-9010"]))),
                   NatRule("dnat-uplink", destinations=["uplink"], service=rng.choice(["alt", "web443", "smtp"]), origin="dnat-uplink",
                           destination_translation=DestNat("db")),
                   NatRule("one-mail", sources=["mail"], source_translation=SourceNat(SnatKind.STATIC, ["pub-mail"], bidirectional=True), origin="one-mail"),
                   NatRule("masq", src_zones=["lan"], dst_zones=["wan"], source_translation=SourceNat(SnatKind.INTERFACE, interface_address="uplink"),
                           origin="masq")]  # fmt: skip
    rng.shuffle(p.nat_rules)
    sources = [[ANY], ["partners"], ["remote"], ["half"], ["near"], ["remote", "near"]]
    destinations = [[ANY], ["pub-web"], ["pub-mail"], ["uplink"], ["pub-web", "pub-mail"], ["uplink", "pub-web"]]
    for index in range(rng.randint(2, 9)):
        rule = Rule(f"in{index}", src_zones=rng.choice([["wan"], ["partner"], [ANY], ["wan", "partner"], ["lan"]]),
                    dst_zones=rng.choice([["lan"], ["dmz"], [ANY], ["lan", "dmz"]]), sources=rng.choice(sources), destinations=rng.choice(destinations),
                    services=[ANY] if rng.random() < 0.3 else [rng.choice(list(p.services))],
                    action=Action.ALLOW if rng.random() < 0.7 else Action.DENY, origin=f"in{index}")  # fmt: skip
        if rng.random() < 0.1:
            rule.unsupported = ["geo-ip"]
        if rng.random() < 0.07:
            rule.users = ["alice"]
        if rng.random() < 0.07:
            rule.applications = ["ssh"]
        if rng.random() < 0.05:
            rule.url_categories = ["news"]
        rule.negate_source = rule.sources != [ANY] and rng.random() < 0.1
        rule.negate_service = rule.services != [ANY] and rng.random() < 0.07
        rule.enabled = rng.random() > 0.05
        p.rules.append(rule)
    return p


NAT_ZONES = {"lan": ["10.0.0.0/16"], "dmz": ["172.16.0.0/16"], "partner": ["192.0.2.0/24"]}
NAT_TARGET = {"203.0.113.10": "10.0.0.17", "203.0.113.20": "10.0.0.20", UPLINK: "172.16.0.5"}


@pytest.mark.parametrize("seed", range(300))
def test_what_nat_lets_in_is_never_more_than_the_model_allows(seed: int) -> None:
    rng = random.Random(70000 + seed)
    model = random_nat_model(rng)
    networks = dict(NAT_ZONES) if rng.random() < 0.8 else {"lan": NAT_ZONES["lan"], "dmz": NAT_ZONES["dmz"]}
    text, report = emit(model, Options(zone_networks=networks, inside_zones=["lan", "dmz"]))
    mx = read_script(text)
    mx.update({"vlans": {"0": ("10.0.0.0/16", ""), "1": ("172.16.0.0/16", "")}, "routes": {}, "objects": {}, "groups": {}})
    judge = MxJudge(mx)
    zones = {"vlan0": "lan", "vlan1": "dmz"}
    for _ in range(400):
        src = rng.choice(["198.51.100.4", "198.51.100.200", "192.0.2.7", "192.0.2.200", "203.0.113.99"])
        dst = rng.choice(list(NAT_TARGET))
        proto = rng.choice(["tcp", "tcp", "udp", "icmp"])
        pkt = Packet("", "", src, dst, proto, rng.choice([1024, 40000, 80]), rng.choice([443, 8000, 8005, 8010, 8011, 53, 25, 80, 7999]), rng.choice([8, 0]))
        verdict, after = judge.inbound(pkt)
        if not verdict:
            continue
        pkt.in_if = "partner" if in_net(src, "192.0.2.0/24") else "wan"
        pkt.out_if = zones[after]
        assert judge.zone(NAT_TARGET[dst]) == after
        assert model_allows(model, pkt), (seed, pkt, text, [(r.name, r.src_zones, r.dst_zones, r.sources, r.destinations, r.services, r.action)
                                                          for r in model.rules])  # fmt: skip


def test_nat_differential_is_not_vacuous() -> None:
    """Over the seeds of the test above the MX lets traffic in often enough for it to mean something."""
    total = 0
    for seed in range(120):
        rng = random.Random(70000 + seed)
        model = random_nat_model(rng)
        text, _ = emit(model, Options(zone_networks=dict(NAT_ZONES), inside_zones=["lan", "dmz"]))
        mx = read_script(text)
        total += sum(len(r["allowedIps"]) for r in mx["forwards"]) + sum(len(r["portRules"]) for r in mx["one_to_many"]) + \
            sum(len(o["allowedInbound"]) for o in mx["one_to_one"])
    assert total > 60


@pytest.mark.parametrize("seed", range(80))
def test_a_network_read_and_written_again_decides_the_same(seed: int) -> None:
    rng = random.Random(9000 + seed)
    mx = random_mx(rng)
    mx["l7"] = [rule for rule in mx["l7"] if rule["type"] in ("port", "ipRange")]
    model, _ = parse(bundle(mx, rng))
    text, report = emit(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    written = read_script(text)
    written.update({"vlans": mx["vlans"], "routes": mx["routes"], "objects": mx["objects"], "groups": mx["groups"], "uplinks": mx["uplinks"]})
    judge = MxJudge(written)
    for _ in range(300):
        pkt = mx_packet(rng)
        if pkt is None:
            continue
        verdict, ingress, egress = judge.allows(pkt)
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = _zone(model, ingress), _zone(model, egress)
        if ingress == "internet":
            # (NAT rules that cannot be written, and the inbound table, are left out: the output lets in less)
            assert not verdict or model_allows(model, pkt), (seed, pkt, text)
        else:
            assert verdict == model_allows(model, pkt), (seed, pkt, text)


# -- what is read, and what is not ----------------------------------------------------------------------


def network(rules: List[Dict[str, Any]], **more: Any) -> Dict[str, Any]:
    document: Dict[str, Any] = {"vlans": [{"id": 10, "name": "office", "subnet": "10.10.10.0/24"}, {"id": 20, "name": "servers", "subnet": "10.10.20.0/24"}],
                                "l3FirewallRules": {"rules": rules + [dict(DEFAULT)]}, "uplinkStatuses": [{"uplinks": [{"interface": "wan1", "ip": UPLINK}]}]}  # fmt: skip
    document.update(more)
    return document


def rule(src: str = "Any", dst: str = "Any", protocol: str = "any", dport: str = "Any", policy: str = "allow", comment: str = "r",
         sport: str = "Any") -> Dict[str, Any]:  # fmt: skip
    return {"comment": comment, "policy": policy, "protocol": protocol, "srcPort": sport, "srcCidr": src, "destPort": dport, "destCidr": dst,
            "syslogEnabled": False}  # fmt: skip


def verdict(model: Any, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "vlan10-office", egress: str = "internet") -> bool:
    return model_allows(model, Packet(ingress, egress, src, dst, proto, 40000, dport, 8))


def test_detection_and_errors() -> None:
    data = (DATA / "meraki_sample.json").read_bytes()
    assert cli.detect_format(data) == "meraki"
    alone = json.dumps({"rules": [rule("10.10.10.0/24", "Any", policy="deny"), dict(DEFAULT)]}).encode()
    assert cli.detect_format(alone) == "meraki"
    model, report = parse(json.loads(alone))
    assert {"MERAKI_TABLE_ALONE", "MERAKI_NO_LAN"} <= codes(report)
    # (no VLANs: every address is in the zone internet, and the rules still apply)
    assert not verdict(model, "10.10.10.5", "192.0.2.1", ingress="internet", egress="internet")
    assert verdict(model, "10.10.20.5", "192.0.2.1", ingress="internet", egress="internet")
    with pytest.raises(ParseError, match="error answer"):
        parse({"errors": ["Invalid API key"], "l3FirewallRules": {"rules": []}})
    with pytest.raises(ParseError, match="template"):
        parse(network([], network={"isBoundToConfigTemplate": True}))
    with pytest.raises(ParseError, match="no l3FirewallRules"):
        parse({"vlans": []})
    with pytest.raises(ParseError, match="syslogDefaultRule"):
        parse({"rules": [rule("Any", "10.10.20.5", "tcp", "22", "deny"), dict(DEFAULT, policy="deny")], "syslogDefaultRule": False})


def test_addresses_ports_and_objects() -> None:
    objects = [{"id": "1", "name": "eng", "type": "cidr", "cidr": "10.10.10.50/32"}, {"id": "2", "name": "site", "type": "fqdn", "fqdn": "updates.example.com"},
               {"id": "3", "name": "odd", "type": "adaptivePolicyIpv4Cidr", "cidr": "10.10.10.0/24"}]  # fmt: skip
    groups = [{"id": "9", "name": "g", "category": "NetworkObjectGroup", "objectIds": [1]}, {"id": "8", "name": "h", "category": "NetworkObjectGroup",
               "objectIds": [1, 77]}]  # fmt: skip
    rules = [rule("OBJ[1]", "VLAN(20).15", "tcp", "80,443"), rule("GRP(9)", "updates.example.com", "tcp", "443", "deny", "fqdn"),
             rule("OBJ(3)", "Any", comment="odd"), rule("GRP(8)", "Any", comment="h"), rule("VLAN(99).*", "Any", comment="v99"),
             rule("10.10.10.5/24", "Any", comment="bits"), rule("Any", "Any", "tcp", "1024-5000,5004", comment="mix"),
             rule("Any", "Any", "icmp", "80", comment="icmp ports"), rule("Any", "Any", "gre", comment="gre"),
             rule("10.10.10.0/24, 2001:db8:10::/64", "Any", "tcp", "1024-5000", comment="range"),
             rule("10.10.10.0/24", "10.10.20.0/24", policy="deny", comment="block")]  # fmt: skip
    model, report = parse(network(rules, policyObjects=objects, policyObjectsGroups=groups))
    assert verdict(model, "10.10.10.50", "10.10.20.15", dport=443, egress="vlan20-servers")
    assert not verdict(model, "10.10.10.51", "10.10.20.15", dport=443, egress="vlan20-servers")
    by_comment = {r.description: r for r in model.rules}
    assert model.addresses["fqdn updates.example.com"].kind.name == "FQDN"
    for comment in ("odd", "h", "v99", "bits", "mix", "icmp ports", "gre"):
        assert by_comment[comment].unsupported, comment
    assert not by_comment["range"].unsupported and verdict(model, "2001:db8:10::5", "2001:db8:99::1", dport=2000)


def test_default_rule_layer7_and_inside_a_vlan() -> None:
    l7 = {"rules": [{"policy": "deny", "type": "port", "value": "23"}, {"policy": "deny", "type": "ipRange", "value": "198.51.100.0/24:8080"},
                    {"policy": "deny", "type": "host", "value": "games.example.com"}]}  # fmt: skip
    model, report = parse(network([rule("10.10.10.0/24", "198.51.100.0/24", policy="deny")], l7FirewallRules=l7))
    assert not verdict(model, "10.10.10.5", "198.51.100.9") and verdict(model, "10.10.20.5", "198.51.100.9", ingress="vlan20-servers")
    assert not verdict(model, "10.10.20.5", "192.0.2.9", dport=23, ingress="vlan20-servers")
    assert not verdict(model, "10.10.20.5", "198.51.100.9", dport=8080, ingress="vlan20-servers")
    assert verdict(model, "10.10.10.5", "10.10.10.9", ingress="vlan10-office", egress="vlan10-office")
    assert not verdict(model, "192.0.2.5", "10.10.10.9", ingress="internet", egress="vlan10-office")
    assert not verdict(model, "192.0.2.5", "198.51.100.9", ingress="internet", egress="internet")
    assert {"MERAKI_L7", "MERAKI_L7_PORTS"} <= codes(report)
    document = network([])
    document["l3FirewallRules"]["rules"] = []
    model, report = parse(document)
    assert "MERAKI_NO_DEFAULT_RULE" in codes(report) and verdict(model, "10.10.10.5", "192.0.2.9")


def test_nat_and_what_comes_in() -> None:
    more = {"portForwardingRules": {"rules": [{"name": "web", "lanIp": "10.10.20.30", "uplink": "internet1", "protocol": "tcp", "publicPort": "8443",
                                               "localPort": "443", "allowedIps": ["198.51.100.0/24"]},
                                              {"name": "odd", "lanIp": "10.10.20.31", "uplink": "internet2", "protocol": "tcp", "publicPort": "80-81",
                                               "localPort": "80", "allowedIps": ["any"]}]},
            "oneToOneNatRules": {"rules": [{"name": "mail", "publicIp": "203.0.113.25", "lanIp": "10.10.20.25", "uplink": "internet1",
                                            "allowedInbound": [{"protocol": "tcp", "destinationPorts": ["25"], "allowedIps": ["any"]}]}]}}  # fmt: skip
    model, report = parse(network([], **more))
    assert verdict(model, "198.51.100.4", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers")
    assert not verdict(model, "192.0.2.4", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers")
    assert verdict(model, "192.0.2.4", "203.0.113.25", dport=25, ingress="internet", egress="vlan20-servers")
    assert not verdict(model, "192.0.2.4", "203.0.113.25", dport=26, ingress="internet", egress="vlan20-servers")
    nats = {n.name: n for n in model.nat_rules}
    assert nats["NAT web"].destination_translation.port == "443" and nats["NAT odd"].unsupported
    assert nats["NAT mail"].source_translation.bidirectional and nats["NAT to the uplink"].source_translation.kind.name == "INTERFACE"
    exceptions = network([], uplinksNat=[{"uplinks": [{"interface": "wan1", "nat": {"enabled": False}}]}],
                         inboundFirewallRules={"rules": [rule("192.0.2.0/24", UPLINK, "tcp", "8443", comment="in")]}, **more)  # fmt: skip
    model, report = parse(exceptions)
    assert verdict(model, "192.0.2.4", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers")
    assert not verdict(model, "198.51.100.4", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers")
    assert "MERAKI_NAT_EXCEPTION" in codes(report) and not [n for n in model.nat_rules if n.name == "NAT to the uplink"]
    passthrough = network([], applianceSettings={"deploymentMode": "passthrough"})
    model, report = parse(passthrough)
    assert verdict(model, "192.0.2.4", "10.10.20.5", ingress="internet", egress="vlan20-servers") and "MERAKI_PASSTHROUGH" in codes(report)


def test_other_answers_are_said() -> None:
    document = (DATA / "meraki_sample.json").read_bytes()
    model, report = parse(json.loads(document))
    assert {"MERAKI_CELLULAR", "MERAKI_VPN", "MERAKI_GROUP_POLICY", "MERAKI_SERVICES", "MERAKI_SOURCE"} <= codes(report)
    assert "172.16.40.0/24" in model.address_groups["zone vlan30-ot-cell"].members


def test_emitter_rules_defaults_and_nat() -> None:
    from fwshift.model import Action, Address, AddressKind, DestNat, NatRule, Protocol, Rule, Service, ServiceEntry, SnatKind, SourceNat, Zone

    model = random_model(random.Random(2))
    model.zones = {"lan": Zone("lan"), "wan": Zone("wan")}
    model.addresses["site"] = Address("site", AddressKind.FQDN, "updates.example.com")
    model.services["mix"] = Service("mix", [ServiceEntry(Protocol.TCP, "80,443,8000-8010"), ServiceEntry(Protocol.UDP, "53"), ServiceEntry(Protocol.ICMP)])
    model.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    model.services["web443"] = Service("web443", [ServiceEntry(Protocol.TCP, "443")])
    model.rules = [Rule("mix", src_zones=["lan"], dst_zones=["wan"], sources=["net0", "six"], services=["mix"], origin="mix"),
                   Rule("ping", src_zones=["lan"], services=["ping"], origin="ping"),
                   Rule("fqdn-src", src_zones=["lan"], sources=["site"], origin="fqdn-src"),
                   Rule("fqdn-dst", src_zones=["lan"], destinations=["site"], action=Action.DENY, origin="fqdn-dst"),
                   Rule("in", src_zones=["wan"], dst_zones=["lan"], sources=["192.0.2.0/24"], destinations=["203.0.113.10"], services=["web443"],
                        origin="in"),
                   Rule("in-other", src_zones=["wan"], dst_zones=["lan"], destinations=["203.0.113.99"], origin="in-other")]  # fmt: skip
    model.nat_rules = [NatRule("dnat", destinations=["203.0.113.10"], service="web443", destination_translation=DestNat("10.0.0.17", "8443"), origin="dnat"),
                       NatRule("masq", src_zones=["lan"], dst_zones=["wan"], source_translation=SourceNat(SnatKind.INTERFACE), origin="masq")]  # fmt: skip
    model.default_interzone = Action.DENY
    options = Options(zone_networks={"lan": ["10.0.0.0/8", "2001:db8::/32"], "wan": ["0.0.0.0/0", "::/0"]}, inside_zones=["lan"])
    text, report = emit(model, options)
    mx = read_script(text)
    protocols = [(r["protocol"], r["destPort"]) for r in mx["l3"] if r["comment"] == "mix"]
    assert ("tcp", "80,443") in protocols and ("tcp", "8000-8010") in protocols and ("udp", "53") in protocols and ("icmp", "Any") in protocols
    assert len({r["srcCidr"] for r in mx["l3"] if r["comment"] == "mix"}) == 2  # (IPv4 and IPv6 apart)
    for name in ("ping", "fqdn-src"):
        assert report.item("rule", name).disabled, name
    assert any(r["destCidr"] == "updates.example.com" for r in mx["l3"])
    assert mx["l3"][-1]["policy"] == "deny" and mx["l3"][-1]["srcCidr"] == "Any"
    many = mx["one_to_many"][0]
    assert many["publicIp"] == "203.0.113.10" and many["portRules"][0]["localPort"] == "8443" and many["portRules"][0]["allowedIps"] == ["192.0.2.0/24"]
    assert "MERAKI_INBOUND" in {f.code for f in report.item("rule", "in-other").findings}
    assert "the allowed remote addresses of a NAT rule" in report.item("rule", "in").emitted_as
    assert {"MERAKI_LOAD", "MERAKI_NAT_UPLINK"} <= codes(report)
    no_networks, report = emit(model, Options(inside_zones=["lan"]))
    assert report.item("rule", "mix").disabled


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "meraki_sample.json").read_bytes()
    model = cli.load(data, "meraki", Report())
    assert len(model.rules) >= 12
    for target in sorted(cli.EMITTERS):
        cli.EMITTERS[target](model, Report(), Options())


# -- review round 39 --------------------------------------------------------------------------------------


def _nat_model(rules: List[Any], nats: List[Any]) -> Any:
    from fwshift.model import Action, Address, AddressKind, Policy, Protocol, Service, ServiceEntry, Zone

    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    p.zones = {z: Zone(z) for z in ("lan", "dmz", "wan")}  # (a rule from zone partner adds that zone)
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.10/32")
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.0.0.17/32")
    p.services["alt"] = Service("alt", [ServiceEntry(Protocol.TCP, "8000-8010")])
    p.services["alt5"] = Service("alt5", [ServiceEntry(Protocol.TCP, "8005")])
    p.services["web443"] = Service("web443", [ServiceEntry(Protocol.TCP, "443")])
    p.rules, p.nat_rules = rules, nats
    return p


def _dnat(service: str = "web443", port: str = "") -> Any:
    from fwshift.model import DestNat, NatRule

    return NatRule("dnat", destinations=["pub"], service=service, destination_translation=DestNat("web", port), origin="dnat")


def _inbound_rule(name: str = "in", **fields: Any) -> Any:
    from fwshift.model import Rule

    values: Dict[str, Any] = {"src_zones": ["wan"], "dst_zones": ["lan"], "destinations": ["pub"], "services": ["web443"]}
    values.update(fields)
    return Rule(name, origin=name, **values)


NAT_OPTIONS = Options(zone_networks={"lan": ["10.0.0.0/16"], "dmz": ["172.16.0.0/16"]}, inside_zones=["lan", "dmz"])


def test_r39_rules_that_are_not_converted_are_no_allowed_addresses() -> None:
    from fwshift.model import Action

    for field, value in (("unsupported", ["geo-ip"]), ("url_categories", ["news"]), ("applications", ["ssh"]), ("users", ["alice"]),
                         ("schedule", "nights"), ("negate_service", True)):  # fmt: skip
        text, report = emit(_nat_model([_inbound_rule(**{field: value})], [_dnat()]), NAT_OPTIONS)
        assert read_script(text)["one_to_many"] == [], field
        assert "MERAKI_INBOUND" in {f.code for f in report.item("rule", "in").findings}, field
        # (a rule that blocks and cannot be read ends the list: what comes after it is not let in)
        text, report = emit(_nat_model([_inbound_rule("block", action=Action.DENY, **{field: value}), _inbound_rule()], [_dnat()]), NAT_OPTIONS)
        assert read_script(text)["one_to_many"] == [], field
        assert "NAT_NOT_CONVERTED" in {f.code for f in report.item("nat", "dnat").findings}, field
    forward = {"name": "web", "lanIp": "10.10.20.30", "uplink": "internet1", "protocol": "tcp", "publicPort": "8443", "localPort": "443"}
    for given in (["198.51.100.5/24"], ["OBJ(77)"], ["not-an-ip"], ["198.51.100.0/24, 192.0.2.0/24"], "198.51.100.0/24"):
        model, _ = parse(network([], portForwardingRules={"rules": [dict(forward, allowedIps=given)]}))
        text, report = emit(model)
        assert read_script(text)["forwards"] == [], given
        assert not verdict(model, "192.0.2.9", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers"), given


def test_r39_a_rule_that_blocks_every_service_but_some_ends_the_list() -> None:
    from fwshift.model import Action, Protocol, Service, ServiceEntry

    p = _nat_model([_inbound_rule("block", action=Action.DENY, services=["dns"], negate_service=True), _inbound_rule()], [_dnat()])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.UDP, "53")])
    text, report = emit(p, NAT_OPTIONS)
    assert read_script(text)["one_to_many"] == []


def test_r39_the_rule_must_allow_all_of_the_ports_of_the_nat_rule() -> None:
    text, report = emit(_nat_model([_inbound_rule(services=["alt5"])], [_dnat("alt")]), NAT_OPTIONS)
    assert read_script(text)["one_to_many"] == []
    assert "some of the ports" in " ".join(f.message for f in report.item("rule", "in").findings)
    text, _ = emit(_nat_model([_inbound_rule(services=["alt"])], [_dnat("alt5")]), NAT_OPTIONS)
    assert read_script(text)["one_to_many"][0]["portRules"][0]["publicPort"] == "8005"
    text, _ = emit(_nat_model([_inbound_rule(services=["alt"])], [_dnat("alt", "9000-9010")]), NAT_OPTIONS)
    port_rule = read_script(text)["one_to_many"][0]["portRules"][0]
    assert (port_rule["publicPort"], port_rule["localPort"]) == ("8000-8010", "9000-9010")


def test_r39_zones_of_rules_from_the_internet() -> None:
    from fwshift.model import ANY

    # (a rule from a partner zone, with no networks for it: not the allowed addresses of everyone)
    text, report = emit(_nat_model([_inbound_rule(src_zones=["partner"])], [_dnat()]), NAT_OPTIONS)
    assert read_script(text)["one_to_many"] == []
    options = Options(zone_networks={"lan": ["10.0.0.0/16"], "dmz": ["172.16.0.0/16"], "partner": ["192.0.2.0/24"]}, inside_zones=["lan", "dmz"])
    text, _ = emit(_nat_model([_inbound_rule(src_zones=["partner"])], [_dnat()]), options)
    assert read_script(text)["one_to_many"][0]["portRules"][0]["allowedIps"] == ["192.0.2.0/24"]
    text, _ = emit(_nat_model([_inbound_rule(src_zones=["wan"])], [_dnat()]), options)
    allowed = read_script(text)["one_to_many"][0]["portRules"][0]["allowedIps"]
    assert not any(in_net("192.0.2.7", a) or in_net("10.0.0.9", a) for a in allowed) and any(in_net("198.51.100.4", a) for a in allowed)
    text, _ = emit(_nat_model([_inbound_rule(src_zones=[ANY])], [_dnat()]), options)
    assert read_script(text)["one_to_many"][0]["portRules"][0]["allowedIps"] == ["any"]
    # (a rule to the DMZ does not let in traffic NAT sends to the LAN)
    text, _ = emit(_nat_model([_inbound_rule(dst_zones=["dmz"])], [_dnat()]), NAT_OPTIONS)
    assert read_script(text)["one_to_many"] == []
    text, _ = emit(_nat_model([_inbound_rule(dst_zones=["dmz"]), _inbound_rule("lan", dst_zones=["lan"], sources=["198.51.100.0/24"])], [_dnat()]),
                   NAT_OPTIONS)  # fmt: skip
    assert read_script(text)["one_to_many"][0]["portRules"][0]["allowedIps"] == ["198.51.100.0/24"]


def test_r39_port_forwards_keep_their_uplink() -> None:
    uplinks = [{"uplinks": [{"interface": "wan1", "ip": UPLINK}, {"interface": "wan2", "ip": UPLINK2}]}]
    forward = {"name": "web", "lanIp": "10.10.20.30", "uplink": "internet2", "protocol": "tcp", "publicPort": "8443", "localPort": "443",
               "allowedIps": ["any"]}  # fmt: skip
    for nat in (None, [{"uplinks": [{"interface": "wan1", "nat": {"enabled": False}}, {"interface": "wan2", "nat": {"enabled": True}}]}],
                [{"uplinks": [{"interface": "wan1", "nat": {"enabled": False}}, {"interface": "wan2", "nat": {"enabled": False}}]}]):  # fmt: skip
        more: Dict[str, Any] = {"uplinkStatuses": uplinks, "portForwardingRules": {"rules": [forward]}}
        if nat:
            more.update(uplinksNat=nat, inboundFirewallRules={"rules": [dict(DEFAULT)]})
        model, _ = parse(network([], **more))
        if nat:
            continue  # (NAT exceptions: the inbound table decides, and NAT rules are not let in)
        mx = read_script(emit(model)[0])
        assert mx["forwards"] and mx["forwards"][0]["uplink"] == "internet2" and not mx["one_to_many"]
    from fwshift.model import DestNat, NatRule, SnatKind, SourceNat

    p = _nat_model([_inbound_rule(destinations=[UPLINK2])], [])
    p.nat_rules = [NatRule("masq", src_zones=["lan"], dst_zones=["wan"], source_translation=SourceNat(SnatKind.INTERFACE, interface_address=UPLINK),
                           origin="masq", tags=[f"meraki wan internet1 {UPLINK}", f"meraki wan internet2 {UPLINK2}"]),
                   NatRule("dnat", destinations=[UPLINK2], service="web443", destination_translation=DestNat("web"), origin="dnat")]  # fmt: skip
    mx = read_script(emit(p, NAT_OPTIONS)[0])
    assert mx["forwards"][0]["uplink"] == "internet2" and not mx["one_to_many"]


def test_r39_rules_inside_one_zone_are_said() -> None:
    from fwshift.model import Action, Rule

    p = _nat_model([Rule("lan", src_zones=["lan"], dst_zones=["lan"], sources=["10.0.0.5/32"], destinations=["10.0.0.6/32"], action=Action.DENY,
                         origin="lan")], [])  # fmt: skip
    text, report = emit(p, NAT_OPTIONS)
    assert any(f.code == "MERAKI_INTRAZONE" and f.severity.name == "REVIEW" for f in report.item("rule", "lan").findings)


def test_r39_a_rule_that_the_mx_cannot_write_is_disabled() -> None:
    from fwshift.model import Action, Address, AddressKind, Rule

    p = _nat_model([Rule("fqdn", src_zones=["lan"], sources=["2001:db8::/48"], destinations=["site"], action=Action.DENY, origin="fqdn")], [])
    p.addresses["site"] = Address("site", AddressKind.FQDN, "updates.example.com")
    text, report = emit(p, Options(zone_networks={"lan": ["10.0.0.0/16", "2001:db8::/32"]}, inside_zones=["lan"]))
    assert report.item("rule", "fqdn").disabled and "fqdn" in text


def test_r39_ports_of_nat_rules_are_checked() -> None:
    for port in ("8443,8444", "abc", "0", "70000", "²"):
        text, report = emit(_nat_model([_inbound_rule()], [_dnat(port=port)]), NAT_OPTIONS)
        assert read_script(text)["one_to_many"] == [], port
        assert "NAT_NOT_CONVERTED" in {f.code for f in report.item("nat", "dnat").findings}, port


def test_r39_dry_run_needs_no_key(tmp_path: Any) -> None:
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no sh")
    text, _ = emit(_nat_model([_inbound_rule()], [_dnat()]), NAT_OPTIONS)
    lines = text.splitlines()
    dry = next(i for i, line in enumerate(lines) if line.startswith('if [ "${DRY_RUN:-0}" = 1 ]'))
    assert all("MERAKI_API_KEY:?" not in line and not line.startswith("api ") for line in lines[:dry])
    script = tmp_path / "put.sh"
    script.write_text(text)
    env = {"PATH": os.environ.get("PATH", ""), "DRY_RUN": "1", "OUT": str(tmp_path / "out")}
    done = subprocess.run([sh, str(script)], env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert json.loads((tmp_path / "out" / "l3FirewallRules.json").read_text())["rules"]
    assert not list((tmp_path / "out").glob("before-*"))
    assert "Default rule" in text.split("set -eu")[0]


def test_r39_parser_findings() -> None:
    # H4: an object or group named any is not every address
    objects = [{"id": "1", "name": "any", "type": "cidr", "cidr": "10.10.10.50/32"}]
    groups = [{"id": "2", "name": "Any", "category": "NetworkObjectGroup", "objectIds": [1]}]
    for ref in ("OBJ(1)", "GRP(2)"):
        model, _ = parse(network([rule(ref, "198.51.100.0/24", "tcp", "22"), rule("Any", "198.51.100.0/24", policy="deny", comment="d")],
                                 policyObjects=objects, policyObjectsGroups=groups))  # fmt: skip
        assert verdict(model, "10.10.10.50", "198.51.100.1", dport=22) and not verdict(model, "10.10.10.9", "198.51.100.1", dport=22), ref
    # H5: passthrough reads the inbound table
    inbound = {"rules": [rule("Any", "10.10.20.5", "tcp", "22", "deny"), dict(DEFAULT)], "syslogDefaultRule": False}
    model, _ = parse(network([], applianceSettings={"deploymentMode": "passthrough"}, inboundFirewallRules=inbound))
    assert not verdict(model, "192.0.2.4", "10.10.20.5", dport=22, ingress="internet", egress="vlan20-servers")
    assert verdict(model, "192.0.2.4", "10.10.20.5", dport=80, ingress="internet", egress="vlan20-servers")
    model, _ = parse(network([], applianceSettings={"deploymentMode": "passthrough"}, inboundFirewallRules={"rules": [dict(DEFAULT, policy="deny")]}))
    assert not verdict(model, "192.0.2.4", "10.10.20.5", ingress="internet", egress="vlan20-servers")
    # H6: NAT exceptions with the inbound table at its default, or missing
    forward = {"name": "web", "lanIp": "10.10.20.30", "uplink": "internet1", "protocol": "tcp", "publicPort": "8443", "localPort": "443",
               "allowedIps": ["any"]}  # fmt: skip
    off = [{"uplinks": [{"interface": "wan1", "nat": {"enabled": False}}]}]
    for table in ({"rules": [dict(DEFAULT, policy="deny")]}, None):
        more: Dict[str, Any] = {"uplinksNat": off, "portForwardingRules": {"rules": [forward]}}
        if table is not None:
            more["inboundFirewallRules"] = table
        model, _ = parse(network([], **more))
        assert not verdict(model, "192.0.2.4", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers"), table
    # H7: a static route behind no VLAN, and the internet: the outbound rules still apply
    model, report = parse(network([rule("172.16.50.0/24", "Any", policy="deny")], staticRoutes=[{"subnet": "172.16.50.0/24", "gatewayIp": "192.168.9.1"}]))
    assert "MERAKI_ROUTE" in codes(report)
    assert not verdict(model, "192.0.2.4", "198.51.100.4", ingress="internet", egress="internet")
    # M1: NAT ports that are missing or any
    for port in ("any", "", None):
        item = dict(forward, publicPort=port) if port is not None else {k: v for k, v in forward.items() if k != "publicPort"}
        model, _ = parse(network([], portForwardingRules={"rules": [item]}))
        assert not verdict(model, "192.0.2.4", UPLINK, dport=22, ingress="internet", egress="vlan20-servers"), port
    for ports in ("25", [], None):
        entry: Dict[str, Any] = {"protocol": "tcp", "allowedIps": ["any"]}
        if ports is not None:
            entry["destinationPorts"] = ports
        one = {"name": "mail", "publicIp": "203.0.113.25", "lanIp": "10.10.20.25", "allowedInbound": [entry]}
        model, _ = parse(network([], oneToOneNatRules={"rules": [one]}))
        for dport in (2, 5, 25, 80):
            assert not verdict(model, "192.0.2.4", "203.0.113.25", dport=dport, ingress="internet", egress="vlan20-servers"), (ports, dport)
    # M2 and M3: host bits in an object, a group of an object that is not read, a VLAN without a subnet
    objects = [{"id": "1", "name": "bits", "type": "cidr", "cidr": "10.10.10.50/24"},
               {"id": "3", "name": "odd", "type": "adaptivePolicyIpv4Cidr", "cidr": "10.10.10.0/24"},
               {"id": "4", "name": "ok", "type": "cidr", "cidr": "10.10.10.60/32"}]  # fmt: skip
    groups = [{"id": "5", "name": "g", "category": "NetworkObjectGroup", "objectIds": [3, 4]}]
    vlans = [{"id": 10, "name": "office", "subnet": "10.10.10.0/24"}, {"id": 30, "name": "empty"}]
    rules = [rule("OBJ(1)", "Any", comment="bits"), rule("GRP(5)", "Any", policy="deny", comment="group"), rule("VLAN(30).*", "Any", policy="deny", comment="empty")]
    model, _ = parse(network(rules, vlans=vlans, policyObjects=objects, policyObjectsGroups=groups))
    by_comment = {r.description: r for r in model.rules}
    for comment in ("bits", "group", "empty"):
        assert by_comment[comment].unsupported, comment
    # L3: an inbound entry that is not a rule
    with pytest.raises(ParseError, match="inboundFirewallRules"):
        parse(network([], uplinksNat=off, inboundFirewallRules={"rules": [{"comment": "x"}]}))
    # L4: many rules with one comment are named fast, each once
    started = time.monotonic()
    model, _ = parse(network([rule("10.10.10.0/24", "198.51.100.0/24", comment="same") for _ in range(4000)]))
    assert time.monotonic() - started < 20
    names = [r.name for r in model.rules]
    assert len(names) == len(set(names)) and "same (4000)" in names
    # L6: a host name as a source
    objects = [{"id": "2", "name": "site", "type": "fqdn", "fqdn": "updates.example.com"}]
    model, _ = parse(network([rule("OBJ(2)", "Any", comment="src")], policyObjects=objects))
    assert {r.description: r for r in model.rules}["src"].unsupported


def test_r39_the_differential_of_the_reviewer() -> None:
    """The case behind most of the 5,748 differences: a DNAT range and a rule for one of its ports."""
    text, _ = emit(_nat_model([_inbound_rule(sources=["198.51.100.0/24"], services=["alt5"])], [_dnat("alt")]), NAT_OPTIONS)
    mx = read_script(text)
    mx.update({"vlans": {"0": ("10.0.0.0/16", "")}, "routes": {}})
    judge = MxJudge(mx)
    for port in range(7999, 8012):
        got, _ = judge.inbound(Packet("", "", "198.51.100.4", "203.0.113.10", "tcp", 40000, port, 0))
        assert not got, port


# -- what the mutation check of round 39 found ------------------------------------------------------------


def test_r39_a_default_rule_that_blocks_is_not_converted() -> None:
    document = network([])
    document["l3FirewallRules"]["rules"][-1]["policy"] = "deny"
    model, _ = parse(document)
    assert next(r for r in model.rules if r.name == "Default rule").unsupported


def test_r39_no_allowed_remote_addresses_let_in_nothing() -> None:
    forward = {"name": "web", "lanIp": "10.10.20.30", "uplink": "internet1", "protocol": "tcp", "publicPort": "8443", "localPort": "443",
               "allowedIps": []}  # fmt: skip
    model, _ = parse(network([], portForwardingRules={"rules": [forward]}))
    assert not verdict(model, "192.0.2.4", UPLINK, dport=8443, ingress="internet", egress="vlan20-servers")


def test_r39_the_uplink_of_nat_without_vlans_and_of_1_to_many_on_a_wan_address() -> None:
    uplinks = [{"uplinks": [{"interface": "wan1", "ip": UPLINK}, {"interface": "wan2", "ip": UPLINK2}]}]
    forward = {"name": "web", "lanIp": "10.10.20.30", "uplink": "internet2", "protocol": "tcp", "publicPort": "8443", "localPort": "443",
               "allowedIps": ["any"]}  # fmt: skip
    model, _ = parse({"l3FirewallRules": {"rules": [dict(DEFAULT)]}, "uplinkStatuses": uplinks, "portForwardingRules": {"rules": [forward]}})
    mx = read_script(emit(model)[0])
    assert mx["forwards"][0]["uplink"] == "internet2" and not mx["one_to_many"]
    many = {"publicIp": UPLINK2, "uplink": "internet2", "portRules": [{"name": "view", "protocol": "tcp", "publicPort": "9443", "localIp": "10.10.10.5",
                                                                     "localPort": "443", "allowedIps": ["192.0.2.7/32"]}]}  # fmt: skip
    model, _ = parse(network([], uplinkStatuses=uplinks, oneToManyNatRules={"rules": [many]}))
    mx = read_script(emit(model)[0])
    assert mx["forwards"][0]["uplink"] == "internet2" and mx["forwards"][0]["publicPort"] == "9443" and not mx["one_to_many"]


def test_r39_the_zone_of_the_translated_address_must_be_known() -> None:
    from fwshift.model import ANY, Address, AddressKind, DestNat, NatRule

    def model(dst_zones: List[str]) -> Any:
        p = _nat_model([_inbound_rule(dst_zones=dst_zones)], [NatRule("dnat", destinations=["pub"], service="web443", destination_translation=DestNat("far"),
                                                                     origin="dnat")])  # fmt: skip
        p.addresses["far"] = Address("far", AddressKind.NETWORK, "10.9.0.5/32")  # (in no network given)
        return p

    assert read_script(emit(model(["lan"]), NAT_OPTIONS)[0])["one_to_many"] == []
    assert read_script(emit(model([ANY]), NAT_OPTIONS)[0])["one_to_many"]


def test_r39_rules_that_block_and_cannot_be_read_end_the_list_and_others_do_not() -> None:
    from fwshift.model import Action, Address, AddressKind

    p = _nat_model([_inbound_rule("block", action=Action.DENY, destinations=["dyn"]), _inbound_rule()], [_dnat()])
    p.addresses["dyn"] = Address("dyn", AddressKind.UNSUPPORTED, "", raw="filled at run time")
    assert read_script(emit(p, NAT_OPTIONS)[0])["one_to_many"] == []
    p = _nat_model([_inbound_rule("block", action=Action.DENY, destinations=["site"]), _inbound_rule()], [_dnat()])
    p.addresses["site"] = Address("site", AddressKind.FQDN, "portal.example.com")
    assert read_script(emit(p, NAT_OPTIONS)[0])["one_to_many"] == []
    # (a rule that blocks other ports, or another address, does not end it)
    from fwshift.model import Protocol, Service, ServiceEntry

    p = _nat_model([_inbound_rule("ssh", action=Action.DENY, services=["ssh"]), _inbound_rule("other", action=Action.DENY, destinations=["web"]),
                    _inbound_rule()], [_dnat()])  # fmt: skip
    p.services["ssh"] = Service("ssh", [ServiceEntry(Protocol.TCP, "22")])
    assert read_script(emit(p, NAT_OPTIONS)[0])["one_to_many"][0]["portRules"][0]["allowedIps"] == ["any"]


def test_r39_one_to_one_lets_in_ping_only_for_echo_requests() -> None:
    from fwshift.model import Address, AddressKind, NatRule, Protocol, Service, ServiceEntry, SnatKind, SourceNat

    p = _nat_model([_inbound_rule(destinations=["pub"], services=["unreachable"])], [])
    p.services["unreachable"] = Service("unreachable", [ServiceEntry(Protocol.ICMP, icmp_type=3)])
    p.addresses["mail"] = Address("mail", AddressKind.NETWORK, "10.0.0.20/32")
    p.nat_rules = [NatRule("one", sources=["mail"], source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True), origin="one")]
    text, report = emit(p, NAT_OPTIONS)
    assert read_script(text)["one_to_one"][0]["allowedInbound"] == []
    assert "MERAKI_INBOUND_SERVICE" in {f.code for f in report.item("rule", "in").findings}


def test_r39_the_outbound_table_and_its_services() -> None:
    from fwshift.model import Action, Address, AddressKind, Protocol, Rule, Service, ServiceEntry

    # (the Default rule of a Meraki source is the fixed one of the MX, not a rule of its own)
    model, _ = parse(network([rule("10.10.10.0/24", "198.51.100.0/24", policy="deny")]))
    l3 = read_script(emit(model)[0])["l3"]
    assert [(r["policy"], r["srcCidr"], r["destCidr"]) for r in l3] == [("deny", "10.10.10.0/24", "198.51.100.0/24")]
    p = _nat_model([], [])
    p.addresses["site"] = Address("site", AddressKind.FQDN, "updates.example.com")
    p.services["low"] = Service("low", [ServiceEntry(Protocol.TCP, "0-100")])
    p.services["every"] = Service("every", [ServiceEntry(Protocol.TCP, "443"), ServiceEntry(Protocol.IP)])
    p.services["pings"] = Service("pings", [ServiceEntry(Protocol.ICMP), ServiceEntry(Protocol.ICMP6)])
    p.rules = [Rule("low", src_zones=["lan"], services=["low"], origin="low"),
               Rule("every", src_zones=["lan"], services=["every"], origin="every"),
               Rule("pings", src_zones=["lan"], sources=["10.0.0.0/24", "2001:db8::/48"], destinations=["198.51.100.0/24", "2001:db8:99::/48"],
                    services=["pings"], origin="pings"),
               Rule("names", src_zones=["lan"], sources=["site", "10.0.0.0/24"], action=Action.DENY, origin="names"),
               Rule("users", src_zones=["lan"], users=["alice"], origin="users")]  # fmt: skip
    text, report = emit(p, Options(zone_networks={"lan": ["10.0.0.0/16", "2001:db8::/32"]}, inside_zones=["lan"]))
    mx = read_script(text)
    for name in ("low", "names", "users"):
        assert report.item("rule", name).disabled, name
    assert [(r["protocol"], r["destPort"]) for r in mx["l3"] if r["comment"] == "every"] == [("any", "Any")]
    pings = {(r["protocol"], ":" in r["srcCidr"]) for r in mx["l3"] if r["comment"] == "pings"}
    assert pings == {("icmp", False), ("icmp6", True)}


def test_r39_too_many_allowed_remote_addresses() -> None:
    hosts = [f"198.51.100.{n}/32" for n in range(1, 140, 2)]
    text, report = emit(_nat_model([_inbound_rule(sources=hosts)], [_dnat()]), NAT_OPTIONS)
    assert read_script(text)["one_to_many"] == []
    text, report = emit(_nat_model([_inbound_rule(sources=hosts[:60])], [_dnat()]), NAT_OPTIONS)
    assert len(read_script(text)["one_to_many"][0]["portRules"][0]["allowedIps"]) == 60
