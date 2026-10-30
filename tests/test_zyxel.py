# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Zyxel ZLD: parser, emitter, and packet-level equivalence with a judge of its own.

A random ZLD firewall is a plain description (zones and their interfaces, address and service objects and groups, the
IPv4 and IPv6 security policy, the default rules, zones that block traffic between their members, virtual servers)
that ``render`` writes as a configuration file and ``ZldJudge`` decides packets from, as the CLI Reference Guide and
the User's Guide describe it: virtual servers first, then a zone that blocks inside itself, then the rules of the list
of the packet's IP version top to bottom (first match), then the default rule of that list. ``read_zld`` reads the
script the emitter writes into such a description, strictly (every name defined once and before it is used, names
ZLD takes, rules placed by their insert position), so the same judge decides the output. None of it shares code with
the parser or the emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
import re
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows, random_model

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import Action, Policy, Protocol, Rule, Zone
from fwshift.options import Options
from fwshift.parsers import zyxel as parse_zyxel
from fwshift.report import Report

ZONES = ["LAN1", "WAN", "DMZ", "LAB"]
INTERFACES = {"LAN1": ["ge3", "ge4"], "WAN": ["ge1"], "DMZ": ["ge5"], "LAB": ["ge6"]}
SUBNETS = {"ge1": "198.51.100.0/24", "ge3": "10.3.0.0/24", "ge4": "10.4.0.0/24", "ge5": "10.5.0.0/24", "ge6": "10.6.0.0/24"}
NETS4 = ["10.3.0.0/24", "10.4.0.0/25", "10.4.0.128/25", "10.5.0.16/28", "10.0.0.0/8", "192.0.2.0/24"]
HOSTS4 = ["10.3.0.5", "10.4.0.130", "10.5.0.20", "10.6.0.9", "192.0.2.7"]
RANGES4 = [("10.3.0.1", "10.3.0.20"), ("10.5.0.1", "10.5.0.40")]
NETS6 = ["2001:db8:3::/64", "2001:db8:5::/48"]
HOSTS6 = ["2001:db8:3::5", "2001:db8:5::20"]
RANGES6 = [("2001:db8:3::1", "2001:db8:3::f")]
GLOBALS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
INSIDES = ["10.5.0.20", "10.5.0.30", "10.3.0.5"]
POOL4 = ["10.3.0.5", "10.3.0.40", "10.4.0.130", "10.4.0.3", "10.5.0.20", "10.5.0.30", "10.6.0.9", "192.0.2.7", "198.51.100.77"] + GLOBALS
POOL6 = ["2001:db8:3::5", "2001:db8:3::99", "2001:db8:5::20", "2001:db8:9::1"]
PORTS = [22, 25, 53, 80, 443, 8080, 8443, 8085, 1024, 65535]
ICMP_NAMES = {"echo": 8, "echo-reply": 0, "unreachable": 3, "time-exceeded": 11}
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}


def addr(text: str) -> Any:
    return ipaddress.ip_address(text)


# -- the judge ------------------------------------------------------------------------------------------------


def spec_matches(spec: Any, address: str, zld: Dict[str, Any], depth: int = 0) -> bool:
    kind = spec[0]
    probe = addr(address)
    if kind == "any":
        return True
    if kind in ("net", "iface"):
        net = ipaddress.ip_network(spec[1] if kind == "net" else SUBNETS[spec[1]], strict=False)
        return probe.version == net.version and probe in net
    if kind == "host":
        return probe == addr(spec[1])
    if kind == "range":
        first, last = addr(spec[1]), addr(spec[2])
        return probe.version == first.version and int(first) <= int(probe) <= int(last)
    if kind == "object":
        return spec_matches(zld["objects"][spec[1]]["spec"], address, zld, depth + 1)
    if kind == "group":
        assert depth < 12
        return any(spec_matches(member, address, zld, depth + 1) for member in zld["groups"][spec[1]]["members"])
    raise AssertionError(spec)


def service_matches(spec: Any, pkt: Packet, zld: Dict[str, Any], depth: int = 0) -> bool:
    kind = spec[0]
    if kind == "any":
        return True
    if kind in ("tcp", "udp"):
        return pkt.proto == kind and spec[1] <= pkt.dport <= spec[2]
    if kind in ("icmp", "icmp6"):
        return pkt.proto == kind and (spec[1] is None or spec[1] == pkt.icmp_type)
    if kind == "proto":
        return str(NUMBERS.get(pkt.proto, pkt.proto)) == str(spec[1])
    if kind == "service":
        return service_matches(zld["services"][spec[1]]["spec"], pkt, zld, depth + 1)
    if kind == "sgroup":
        assert depth < 12
        return any(service_matches(member, pkt, zld, depth + 1) for member in zld["sgroups"][spec[1]]["members"])
    raise AssertionError(spec)


class ZldJudge:
    def __init__(self, zld: Dict[str, Any]) -> None:
        self.zld = zld

    def translate(self, pkt: Packet, ingress: str) -> Tuple[str, int, bool]:
        """(destination, port, translated by a server of every original address) after the virtual servers."""
        if ":" in pkt.src:
            return pkt.dst, pkt.dport, False
        for server in self.zld["servers"]:
            if not server["active"] or server["zone"] != ingress:
                continue
            if server["original"] != "any" and pkt.dst != server["original"]:
                continue
            if server["type"] == "any":
                return server["mapped"], pkt.dport, server["original"] == "any"
            if pkt.proto not in server["protocols"] or not server["first"] <= pkt.dport <= server["last"]:
                continue
            return server["mapped"], server["to"] + pkt.dport - server["first"], server["original"] == "any"
        return pkt.dst, pkt.dport, False

    def allows(self, pkt: Packet, ingress: str, egress: str) -> Optional[bool]:
        family = 6 if ":" in pkt.src else 4
        dst, dport, everything = self.translate(pkt, ingress)
        if everything:
            return None  # (a virtual server of every original address: no address to rewrite the rules for; NAT_REDIRECT)
        if dport != pkt.dport and any(rule["service"] != ("any",) for rule in self.zld["rules"][family]):
            return None  # (a port translation: rules that name the inside port are not rewritten; NAT_PORT_TRANSLATION)
        if dst == pkt.dst and any(server["original"] == pkt.dst for server in self.zld["servers"] if server["active"]):
            return None  # (traffic to an original address that is not translated: rules for the mapped address get it too)
        if ingress == egress and ingress in self.zld["blocked"]:
            return False  # (a zone feature: read as applying whether the security policy is active or not)
        if family in self.zld["inactive"]:
            return True
        seen = Packet(ingress, egress, pkt.src, dst, pkt.proto, pkt.sport, dport, pkt.icmp_type)
        for rule in self.zld["rules"][family]:
            if not rule["active"] or rule["to"] == "ZyWALL" or rule["from"] == "ZyWALL":
                continue
            if rule["from"] != "any" and rule["from"] != ingress:
                continue
            if rule["to"] != "any" and rule["to"] != egress:
                continue
            if rule["bad"] or rule["carried"]:
                return None  # (not converted, or carried as a user or schedule the judge does not decide)
            if not spec_matches(rule["source"], seen.src, self.zld) or not spec_matches(rule["destination"], seen.dst, self.zld):
                continue
            if not service_matches(rule["service"], seen, self.zld):
                continue
            if rule["sourceport"] is not None:
                proto, low, high = rule["sourceport"]
                if seen.proto != proto or not low <= seen.sport <= high:
                    continue
            return rule["action"] == "allow"
        return self.zld["defaults"][family] == "allow"


# -- random ZLD firewalls ----------------------------------------------------------------------------------------


def random_spec(rng: random.Random, family: int) -> Tuple[Any, bool]:
    """An address of an object, and whether it makes what uses it not converted."""
    roll = rng.random()
    if family == 6:
        if roll < 0.4:
            return ("net", rng.choice(NETS6)), False
        if roll < 0.7:
            return ("host", rng.choice(HOSTS6)), False
        return ("range",) + rng.choice(RANGES6), False
    if roll < 0.3:
        return ("net", rng.choice(NETS4)), False
    if roll < 0.55:
        return ("host", rng.choice(HOSTS4)), False
    if roll < 0.7:
        return ("range",) + rng.choice(RANGES4), False
    if roll < 0.85:
        return ("iface", rng.choice(["ge3", "ge4", "ge5"])), False
    if roll < 0.92:
        return ("iface", "ge6"), True  # (an interface that gets its address by DHCP)
    return ("geo", "XX"), True


def random_service(rng: random.Random) -> Tuple[Any, bool]:
    roll = rng.random()
    if roll < 0.55:
        proto = rng.choice(["tcp", "tcp", "udp"])
        low = rng.choice([22, 25, 53, 80, 443, 8080, 1024])
        high = low if rng.random() < 0.6 else low + rng.choice([5, 100])
        if rng.random() < 0.05:
            low, high = 1, 65535
        return (proto, low, high), False
    if roll < 0.75:
        return ("icmp", rng.choice([None, 8, 0, 11])), False
    if roll < 0.85:
        return ("icmp6", rng.choice([None, 128])), False
    if roll < 0.95:
        return ("proto", rng.choice([47, 50])), False
    return ("icmp", "bogus"), True


def random_zld(rng: random.Random, nat: Optional[bool] = None) -> Dict[str, Any]:
    zld: Dict[str, Any] = {"objects": {}, "groups": {}, "services": {}, "sgroups": {}, "rules": {4: [], 6: []}, "servers": [],
                           "defaults": {4: rng.choice(["deny", "deny", "allow", "reject"]), 6: rng.choice(["deny", "allow"])},
                           "blocked": [z for z in ZONES if rng.random() < 0.2], "inactive": set()}  # fmt: skip
    if rng.random() < 0.03:
        zld["inactive"].add(4)
    for index in range(rng.randint(2, 7)):
        family = 6 if rng.random() < 0.3 else 4
        spec, bad = random_spec(rng, family)
        zld["objects"][f"obj{index}"] = {"family": family, "spec": spec, "bad": bad}
    for index in range(rng.randint(0, 3)):
        members, bad, families = [], False, set()
        for _ in range(rng.randint(1, 3)):
            pool = [("object", n) for n in zld["objects"]] + [("group", g) for g in zld["groups"]]
            member = rng.choice(pool)
            members.append(member)
            found = zld["objects"][member[1]] if member[0] == "object" else zld["groups"][member[1]]
            bad = bad or found["bad"]
            families |= {found["family"]} if member[0] == "object" else found["families"]
        zld["groups"][f"grp{index}"] = {"members": members, "bad": bad, "families": families, "family": 0}
    for index in range(rng.randint(1, 5)):
        spec, bad = random_service(rng)
        zld["services"][f"svc{index}"] = {"spec": spec, "bad": bad}
    for index in range(rng.randint(0, 2)):
        members = []
        for _ in range(rng.randint(1, 3)):
            pool = [("service", n) for n in zld["services"]] + [("sgroup", g) for g in zld["sgroups"]]
            members.append(rng.choice(pool))
        bad = any((zld["services"] if m[0] == "service" else zld["sgroups"])[m[1]]["bad"] for m in members)
        zld["sgroups"][f"sg{index}"] = {"members": members, "bad": bad}

    def address(family: int) -> Tuple[Any, bool]:
        if rng.random() < 0.35:
            return ("any",), False
        pool = [("object", n) for n, o in zld["objects"].items() if o["family"] == family]
        pool += [("group", n) for n, g in zld["groups"].items() if g["families"] == {family}]
        if not pool:
            return ("any",), False
        choice = rng.choice(pool)
        found = zld["objects"][choice[1]] if choice[0] == "object" else zld["groups"][choice[1]]
        return choice, found["bad"]

    for family in (4, 6):
        for index in range(rng.randint(2 if family == 4 else 0, 9 if family == 4 else 4)):
            source, bad_source = address(family)
            destination, bad_destination = address(family)
            service: Any = ("any",)
            bad_service = False
            if rng.random() < 0.6:
                pool = [("service", n) for n in zld["services"]] + [("sgroup", n) for n in zld["sgroups"]]
                service = rng.choice(pool)
                bad_service = (zld["services"] if service[0] == "service" else zld["sgroups"])[service[1]]["bad"]
            rule: Dict[str, Any] = {
                "name": f"r{family}_{index}", "from": rng.choice(["any"] + ZONES), "to": rng.choice(["any", "any"] + ZONES),
                "source": source, "destination": destination, "service": service, "sourceport": None,
                "action": rng.choice(["allow", "allow", "deny", "reject"]), "active": rng.random() > 0.1,
                "bad": bad_source or bad_destination or bad_service, "carried": False, "extra": [], "activate_line": True,
            }  # fmt: skip
            if rng.random() < 0.05:
                rule["to"] = "ZyWALL"
            if family == 4 and rng.random() < 0.08:
                low = rng.choice([1024, 40000])
                rule["sourceport"] = (rng.choice(["tcp", "udp"]), low, low + rng.choice([0, 1000]))
            if rng.random() < 0.06:
                extra = rng.choice(["user alice", "schedule WORK", "ctmatch dnat", "device-tag foo"])
                rule["extra"].append(extra)
                if extra.startswith(("user", "schedule")):
                    rule["carried"] = True
                else:
                    rule["bad"] = True
            if rng.random() < 0.02:
                rule["action"], rule["bad"] = "", True
            zld["rules"][family].append(rule)
    with_nat = rng.random() < 0.5 if nat is None else nat
    if with_nat:
        for index, (original, mapped) in enumerate(zip(rng.sample(GLOBALS, rng.randint(1, 3)), rng.sample(INSIDES, 3))):
            server: Dict[str, Any] = {"name": f"vs{index}", "zone": "WAN", "original": original, "mapped": mapped, "type": "any",
                                      "protocols": [], "first": 0, "last": 0, "to": 0, "active": rng.random() > 0.1,
                                      "one_to_one": False}  # fmt: skip
            roll = rng.random()
            if roll < 0.5:
                server["type"] = "port"
                server["protocols"] = rng.choice([["tcp"], ["udp"], ["tcp", "udp"]])
                server["first"] = server["last"] = rng.choice([80, 443, 8080])
                server["to"] = rng.choice([server["first"], server["first"], 8443])
            elif roll < 0.65:
                server["type"] = "ports"
                server["protocols"] = ["tcp"]
                server["first"], server["last"] = 8080, 8089
                server["to"] = 8080
            elif roll < 0.8:
                server["one_to_one"] = True
            if rng.random() < 0.1:
                server["original"] = "any"
            zld["servers"].append(server)
    return zld


def spec_text(spec: Any, family: int, rng: random.Random) -> str:
    kind = spec[0]
    if kind == "net":
        net = ipaddress.ip_network(spec[1])
        if family == 4 and rng.random() < 0.4:
            return f"{net.network_address} {net.netmask}"
        return str(net)
    if kind == "host":
        return spec[1]
    if kind == "range":
        return f"{spec[1]}-{spec[2]}"
    if kind == "iface":
        return f"interface-subnet {spec[1]}"
    if kind == "geo":
        return f"geography {spec[1]}"
    raise AssertionError(spec)


def service_text(spec: Any, rng: random.Random) -> str:
    kind = spec[0]
    if kind in ("tcp", "udp"):
        return f"{kind} eq {spec[1]}" if spec[1] == spec[2] and rng.random() < 0.8 else f"{kind} range {spec[1]} {spec[2]}"
    if kind == "icmp":
        if spec[1] is None:
            return rng.choice(["protocol 1", "icmp"])
        names = {v: k for k, v in ICMP_NAMES.items()}
        return f"icmp {names[spec[1]] if spec[1] in names and rng.random() < 0.5 else spec[1]}"
    if kind == "icmp6":
        return "protocol 58" if spec[1] is None else rng.choice(["icmpv6 128", "icmpv6 echo-request"])
    if kind == "proto":
        return f"protocol {spec[1]}"
    raise AssertionError(spec)


def render(zld: Dict[str, Any], rng: random.Random) -> str:
    pad = rng.choice(["", " "])  # (sub-commands with an indent, or without)

    def block(head: str, lines: List[str]) -> List[str]:
        return [head] + [pad + line for line in lines] + [rng.choice(["!", "exit"])]

    out = ["! synthetic ZLD configuration", "!"]
    for interface, subnet in SUBNETS.items():
        net = ipaddress.ip_network(subnet)
        out += block(f"interface {interface}", [f"ip address {net.network_address + 1} {net.netmask}"])
    out += block("interface ge6", ["ip address dhcp"])
    for zone in ZONES:
        out += block(f"zone {zone}", [f"interface {i}" for i in INTERFACES[zone]] + (["block"] if zone in zld["blocked"] else []))
    for name, found in zld["objects"].items():
        keyword = "address-object" if found["family"] == 4 else "address6-object"
        out.append(f"{keyword} {name} {spec_text(found['spec'], found['family'], rng)}")
    for name, found in zld["groups"].items():
        lines = []
        for kind, member in found["members"]:
            if kind == "group":
                lines.append(f"object-group {member}")
            else:
                lines.append(("address-object " if zld["objects"][member]["family"] == 4 else "address6-object ") + member)
        families = found["families"]
        out += block(f"object-group {'address6' if families == {6} else 'address'} {name}", lines)
    for name, found in zld["services"].items():
        out.append(f"service-object {name} {service_text(found['spec'], rng) if found['spec'][1] != 'bogus' else 'icmp bogus'}")
    for name, found in zld["sgroups"].items():
        out += block(f"object-group service {name}", [("object-group " if k == "sgroup" else "service-object ") + m for k, m in found["members"]])
    out += ["username alice user-type user", "schedule-object WORK"]
    if 4 in zld["inactive"]:
        out.append("no secure-policy activate")
    for family, keyword in ((4, "secure-policy"), (6, "secure-policy6")):
        default = zld["defaults"][family]
        if default != "deny" or rng.random() < 0.5:
            out.append(f"{keyword} default-rule action {default} {rng.choice(['log', 'no log'])}")
    for family, keyword in ((4, "secure-policy"), (6, "secure-policy6")):
        for number, rule in enumerate(zld["rules"][family], 1):
            lines = [f"name {rule['name']}"]
            if rule["from"] != "any" or rng.random() < 0.3:
                lines.append(f"from {rule['from']}")
            if rule["to"] != "any" or rng.random() < 0.3:
                lines.append(f"to {rule['to']}")
            for key, words in (("source", ("sourceip", "sourceip6")), ("destination", ("destinationip", "destinationip6"))):
                spec = rule[key]
                if spec != ("any",) or rng.random() < 0.3:
                    lines.append(f"{words[family == 6]} {spec[1] if spec != ('any',) else 'any'}")
            if rule["service"] != ("any",) or rng.random() < 0.3:
                lines.append(f"service {rule['service'][1] if rule['service'] != ('any',) else 'any'}")
            if rule["sourceport"] is not None:
                proto, low, high = rule["sourceport"]
                lines.append(f"sourceport {proto} eq {low}" if low == high else f"sourceport {proto} range {low} {high}")
            lines += rule["extra"]
            if rule["action"]:
                lines.append(f"action {rule['action']}")
            if rng.random() < 0.3:
                lines.append(rng.choice(["log", "log alert", "no log"]))
            lines.append("activate" if rule["active"] else "no activate")
            out += block(f"{keyword} {number}", lines)
    for server in zld["servers"]:
        line = f"ip virtual-server {server['name']} interface ge1 original-ip {server['original']} map-to {server['mapped']} "
        if server["type"] == "any":
            line += "map-type any"
        elif server["type"] == "port":
            protocol = "any" if len(server["protocols"]) == 2 else server["protocols"][0]
            line += f"map-type port protocol {protocol} original-port {server['first']} mapped-port {server['to']}"
        else:
            line += f"map-type ports protocol tcp original-port-begin {server['first']} original-port-end {server['last']} mapped-port-begin {server['to']}"
        if server["one_to_one"]:
            line += " nat-1-1-map"
        if not server["active"]:
            line += " deactivate"
        out.append(line)
    return "\n".join(out) + "\n"


def zld_packet(rng: random.Random) -> Tuple[Packet, str, str]:
    six = rng.random() < 0.3
    pool = POOL6 if six else POOL4
    src, dst = rng.choice(pool), rng.choice(pool)
    proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if six else "icmp", "47", "50"])
    pkt = Packet("", "", src, dst, proto, rng.choice([1024, 40000, 53]), rng.choice(PORTS), rng.choice([0, 8, 11, 128]))
    return pkt, rng.choice(ZONES), rng.choice(ZONES)


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_zyxel.parse(text.encode(), report), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def judged(zld: Dict[str, Any], model: Policy, rng: random.Random, seed: int, packets: int = 300) -> int:
    from fwshift import transform

    judge = ZldJudge(zld)
    by_name = {r.name: r for r in model.rules}
    taint_a, taint_s = transform.tainted_addresses(model), transform.tainted_services(model)
    for family in (4, 6):
        for rule in zld["rules"][family]:
            if rule["bad"] and rule["name"] in by_name:  # (what the judge does not decide is not converted, never read as more)
                assert transform.blocking_reasons(by_name[rule["name"]], taint_a, taint_s), (seed, rule)
    count = 0
    for _ in range(packets):
        pkt, ingress, egress = zld_packet(rng)
        verdict = judge.allows(pkt, ingress, egress)
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = ingress, egress
        count += 1
        assert model_allows(model, pkt) == verdict, (seed, pkt, ingress, egress, render(zld, random.Random(0)))
    return count


@pytest.mark.parametrize("kind", ["policy", "nat"])
def test_parsed_zld_decides_like_the_judge(kind: str) -> None:
    compared = 0
    offset = {"policy": 0, "nat": 1000}[kind]
    for seed in range(offset, offset + 200):
        rng = random.Random(seed)
        zld = random_zld(rng, nat=kind == "nat")
        text = render(zld, rng)
        assert cli.detect_format(text.encode()) == "zyxel", text
        model, _ = parse(text)
        compared += judged(zld, model, rng, seed)
    assert compared > 20000


# -- the emitted script, read back ----------------------------------------------------------------------------

_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,30}")


def _ports(words: List[str]) -> Tuple[int, int]:
    if words[0] == "eq" and len(words) == 2:
        return int(words[1]), int(words[1])
    assert words[0] == "range" and len(words) == 3, words
    low, high = int(words[1]), int(words[2])
    assert 1 <= low <= high <= 65535, words
    return low, high


def read_zld(text: str, existing: int = 0) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """The script the emitter writes, read strictly as ZLD would take it, into a description for the judge; and the zone
    names it gives (from the comments that say which interfaces go in which zone). ``existing``: rules the firewall has
    already (inactive here), before which a rule can be inserted."""
    zld: Dict[str, Any] = {"objects": {}, "groups": {}, "services": {}, "sgroups": {}, "rules": {4: [], 6: []}, "servers": [],
                           "defaults": {4: "deny", 6: "deny"}, "blocked": [], "inactive": set()}  # fmt: skip
    zones: Dict[str, List[str]] = {z: [] for z in parse_zyxel.SYSTEM_ZONES}
    for family in (4, 6):
        zld["rules"][family] = [{"from": "any", "to": "any", "active": False, "existing": True} for _ in range(existing)]
    taken: set = set()
    lines = text.splitlines()
    assert lines[0].startswith("# Generated by FWShift") and "configure terminal" in lines

    def new_name(name: str) -> None:
        assert _NAME.fullmatch(name), name
        assert name.lower() not in taken, name
        taken.add(name.lower())

    def address(name: str, family: int) -> Any:
        if name in zld["objects"]:
            assert zld["objects"][name]["family"] == family, name
            return ("object", name)
        assert name in zld["groups"] and zld["groups"][name]["family"] == family, name
        return ("group", name)

    def service(name: str) -> Any:
        if name in zld["services"]:
            return ("service", name)
        assert name in zld["sgroups"], name
        return ("sgroup", name)

    index = 0
    for raw in lines:
        if raw.startswith("#   zone "):
            zone, _, interface = raw[len("#   zone "):].partition(" / interface ")
            if interface:
                zones.setdefault(zone, []).append(interface)
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line or line.startswith("#") or line in ("configure terminal", "exit"):
            continue
        assert not line.startswith(" "), line
        words = line.split()
        body: List[List[str]] = []
        if words[0] in ("object-group", "secure-policy", "secure-policy6", "policy", "zone"):
            while lines[index] != "exit":
                assert lines[index].startswith(" "), lines[index]
                body.append(lines[index].split())
                index += 1
            index += 1
        if words[0] in ("address-object", "address6-object"):
            family = 4 if words[0] == "address-object" else 6
            assert len(words) == 3, line
            new_name(words[1])
            value = words[2]
            if "-" in value:
                first, last = value.split("-")
                assert addr(first).version == family and int(addr(first)) <= int(addr(last))
                spec: Any = ("range", first, last)
            elif "/" in value:
                net = ipaddress.ip_network(value)  # (strict: a network address)
                assert net.version == family
                spec = ("net", value)
            else:
                assert addr(value).version == family
                spec = ("host", value)
            zld["objects"][words[1]] = {"family": family, "spec": spec}
        elif words[:2] in (["object-group", "address"], ["object-group", "address6"]):
            family = 4 if words[1] == "address" else 6
            new_name(words[2])
            members = []
            for entry in body:
                assert len(entry) == 2, entry
                assert entry[0] in ("object-group", "address-object" if family == 4 else "address6-object"), entry
                members.append(address(entry[1], family))
            assert members, line
            zld["groups"][words[2]] = {"family": family, "members": members}
        elif words[0] == "service-object":
            new_name(words[1])
            rest = words[2:]
            if rest[0] in ("tcp", "udp"):
                low, high = _ports(rest[1:])
                spec = (rest[0], low, high)
            elif rest[0] in ("icmp", "icmpv6"):
                assert len(rest) == 2 and 0 <= int(rest[1]) <= 255, line
                spec = ("icmp" if rest[0] == "icmp" else "icmp6", int(rest[1]))
            else:
                assert rest[0] == "protocol" and len(rest) == 2 and 1 <= int(rest[1]) <= 255, line
                number = int(rest[1])
                spec = ("icmp", None) if number == 1 else ("icmp6", None) if number == 58 else ("proto", number)
            zld["services"][words[1]] = {"spec": spec}
        elif words[:2] == ["object-group", "service"]:
            new_name(words[2])
            members = []
            for entry in body:
                assert len(entry) == 2 and entry[0] in ("service-object", "object-group"), entry
                members.append(service(entry[1]))
            assert members
            zld["sgroups"][words[2]] = {"members": members}
        elif words[0] == "zone":
            assert len(words) == 2 and not body, line
            new_name(words[1])
            zones[words[1]] = zones.get(words[1], [])
        elif words[0] in ("secure-policy", "secure-policy6"):
            family = 4 if words[0] == "secure-policy" else 6
            assert words[1] == "insert" and len(words) == 3, line
            position = int(words[2])
            assert 1 <= position <= len(zld["rules"][family]) + 1, line  # (insert before a rule that exists, or at the end)
            rule: Dict[str, Any] = {"from": "any", "to": "any", "source": ("any",), "destination": ("any",), "service": ("any",),
                                    "sourceport": None, "action": "", "active": True, "bad": False, "carried": False}  # fmt: skip
            assert body[0][0] == "name" and body[1] == ["no", "activate"], body  # (named, and inactive before it matches)
            new_name(body[0][1])
            assert len(body[0][1]) <= 30
            for entry in body[1:]:
                key = entry[0]
                if entry == ["no", "activate"]:
                    rule["active"] = False
                elif entry == ["activate"]:
                    rule["active"] = True
                elif key in ("from", "to"):
                    assert entry[1] in zones, entry
                    rule[key] = entry[1]
                elif key == ("sourceip" if family == 4 else "sourceip6"):
                    rule["source"] = address(entry[1], family)
                elif key == ("destinationip" if family == 4 else "destinationip6"):
                    rule["destination"] = address(entry[1], family)
                elif key == "service":
                    rule["service"] = service(entry[1])
                elif key == "action":
                    assert entry[1] in ("allow", "deny", "reject"), entry
                    rule["action"] = entry[1]
                elif key == "sourceport":
                    assert entry[1] in ("tcp", "udp"), entry
                    rule["sourceport"] = (entry[1],) + _ports(entry[2:])
                elif entry in (["log"], ["no", "log"]) or key == "description":
                    continue
                else:
                    raise AssertionError(entry)
            assert rule["action"], body
            zld["rules"][family].insert(position - 1, rule)
        elif words[:2] == ["ip", "virtual-server"]:
            new_name(words[2])
            values = dict(zip(words[3::2], words[4::2]))
            interface = values["interface"]
            zone = next(z for z, members in zones.items() if interface in members)
            server = {"name": words[2], "zone": zone, "original": values["original-ip"], "active": not line.endswith(" deactivate"),
                      "one_to_one": "nat-1-1-map" in words, "protocols": [], "first": 0, "last": 0, "to": 0}  # fmt: skip
            for key in ("original", "mapped"):
                value = values["original-ip" if key == "original" else "map-to"]
                if value in zld["objects"]:
                    found = zld["objects"][value]["spec"]
                    assert found[0] == "host", value  # (a range of a many 1:1 NAT: the judge decides one address)
                    value = found[1]
                server[key] = value
            server["type"] = values["map-type"]
            if values["map-type"] == "port":
                server["protocols"] = ["tcp", "udp"] if values["protocol"] == "any" else [values["protocol"]]
                server["first"] = server["last"] = int(values["original-port"])
                server["to"] = int(values["mapped-port"])
            elif values["map-type"] == "ports":
                server["protocols"] = ["tcp", "udp"] if values["protocol"] == "any" else [values["protocol"]]
                server["first"], server["last"] = int(values["original-port-begin"]), int(values["original-port-end"])
                server["to"] = int(values["mapped-port-begin"])
            zld["servers"].append(server)
        elif words[0] == "policy":
            assert words[1] == "insert", line  # (source NAT: not judged here)
        else:
            raise AssertionError(line)
    names = {z: z for z in zones}
    return zld, names


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import zyxel as emit_zyxel

    report = Report()
    return emit_zyxel.emit(model, report, options or Options()), report


def zoned(model: Policy) -> Policy:
    from test_iptables import ZONES as MODEL_ZONES

    for zone in MODEL_ZONES:
        model.zones.setdefault(zone, Zone(zone))
    return model


def compare(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    """The emitted script against the model (zones eth0, eth1, eth2, written FWS_eth0 ...)."""
    from test_iptables import ZONES as MODEL_ZONES
    from test_iptables import random_packet

    zld, _ = read_zld(text)
    judge = ZldJudge(zld)
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (written inactive, and said)
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.1:
            pkt.proto = "50"
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        verdict = judge.allows(pkt, "FWS_" + pkt.in_if, "FWS_" + pkt.out_if)
        assert verdict is not None
        assert verdict == model_allows(model, pkt), (seed, pkt, text)
        count += 1
    assert set(MODEL_ZONES) <= set(model.zones)
    return count


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = zoned(random_model(rng))
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW  # (the model's judge knows one default)
    text, report = emit(model)
    assert compare(model, report, text, rng, seed) == 400


@pytest.mark.parametrize("seed", range(60))
def test_a_zld_read_and_written_again_decides_the_same(seed: int) -> None:
    """ZLD -> model -> ZLD script: the script, judged, decides as the model of the first one (virtual servers included)."""
    rng = random.Random(5000 + seed)
    zld = random_zld(rng)
    model, _ = parse(render(zld, rng))
    text, report = emit(model)
    found, _ = read_zld(text)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    judge = ZldJudge(found)
    compared = 0
    for _ in range(300):
        pkt, ingress, egress = zld_packet(rng)
        verdict = judge.allows(pkt, ingress if ingress in parse_zyxel.SYSTEM_ZONES else "FWS_" + ingress,
                               egress if egress in parse_zyxel.SYSTEM_ZONES else "FWS_" + egress)  # fmt: skip
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = ingress, egress
        assert verdict == model_allows(model, pkt), (seed, pkt, text)
        compared += 1
    assert compared > 60, seed


# -- what is read, and what is not ------------------------------------------------------------------------------

BASE = """!
interface ge1
 ip address 198.51.100.2 255.255.255.0
!
interface ge3
 ip address 10.3.0.1 255.255.255.0
!
interface ge5
 ip address 10.5.0.1/24
!
zone WAN
 interface ge1
!
zone LAN1
 interface ge3
!
zone DMZ
 interface ge5
!
address-object WEB 10.5.0.10
service-object HTTP tcp eq 80
"""


def zld_text(policy: str = "", rest: str = "") -> str:
    return BASE + rest + policy


def verdict(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "LAN1", egress: str = "WAN") -> bool:
    return model_allows(model, Packet(ingress, egress, src, dst, proto, 40000, dport, 8))


def rule_named(model: Policy, name: str) -> Rule:
    return next(r for r in model.rules if r.name == name)


def test_detection_and_errors() -> None:
    text = zld_text("secure-policy 1\n name r\n action allow\n activate\n")
    assert cli.detect_format(text.encode()) == "zyxel" and parse_zyxel.looks_like_zyxel(text.encode())
    assert not parse_zyxel.looks_like_zyxel(b"address-object ipv4 X host 10.0.0.1\nservice-object X TCP 80 80\n")  # (SonicOS)
    assert not parse_zyxel.looks_like_zyxel(b"object-group network X\n network-object host 10.0.0.1\n")  # (ASA)
    with pytest.raises(ParseError):
        parse("hostname fw\nlogging on\n")


def test_rules_first_match_both_lists_and_the_defaults() -> None:
    text = zld_text("""secure-policy default-rule action allow log
secure-policy6 default-rule action deny no log
secure-policy 1
 name deny_web
 from LAN1
 to DMZ
 destinationip WEB
 service HTTP
 action deny
 activate
!
secure-policy 2
 name lan_any
 from LAN1
 action allow
 activate
!
secure-policy6 1
 name six
 from LAN1
 to WAN
 action allow
 activate
!
""")
    model, report = parse(text)
    assert verdict(model, "10.3.0.5", "10.5.0.10", egress="DMZ") is False
    assert verdict(model, "10.3.0.5", "10.5.0.10", dport=81, egress="DMZ") is True
    assert verdict(model, "2001:db8:3::5", "2001:db8:9::1", egress="WAN") is True
    assert verdict(model, "2001:db8:3::5", "2001:db8:9::1", egress="DMZ") is False  # (the IPv6 default denies)
    assert verdict(model, "198.51.100.9", "10.5.0.10", ingress="WAN", egress="DMZ") is True  # (the IPv4 default allows)
    assert rule_named(model, "lan_any").destinations == ["0.0.0.0/0"]  # (an IPv4 rule: never IPv6)
    assert model.rules[-1].name == "IPv6 default-rule" and "ZYXEL_DEFAULTS" in codes(report)


def test_zone_block_device_rules_and_inactive_policy() -> None:
    text = zld_text("""zone LAN1
 interface ge4
 block
!
secure-policy 1
 name to_device
 from LAN1
 to ZyWALL
 action allow
 activate
!
secure-policy 2
 name any_any
 action allow
 activate
!
""")
    model, report = parse(text)
    assert model.zones["LAN1"].interfaces == ["ge3", "ge4"]
    assert verdict(model, "10.3.0.5", "10.4.0.9", egress="LAN1") is False  # (block: inside the zone, whatever the rules say)
    assert verdict(model, "10.3.0.5", "10.4.0.9", egress="DMZ") is True
    assert report.items[("rule", "to_device")].skipped and "ZYXEL_BLOCK_INTRAZONE" in codes(report)
    model, report = parse(text.replace("secure-policy 1\n", "no secure-policy activate\nsecure-policy 1\n"))
    assert verdict(model, "10.3.0.5", "10.4.0.9", egress="WAN") is True and "ZYXEL_POLICY_OFF" in codes(report)
    assert not rule_named(model, "any_any").enabled


def test_objects_and_what_is_never_wider() -> None:
    text = zld_text("""interface ge6
 ip address dhcp
!
address-object MASKED 10.5.0.0 255.255.255.128
address-object RANGE 10.5.0.20-10.5.0.29
address-object IFNET interface-subnet ge3
address-object IFIP interface-ip ge1
address-object DYN interface-subnet ge6
address-object GW interface-gateway ge1
address6-object SIX 2001:db8:5::/48
object-group address INNER
 address-object MASKED
!
object-group address OUTER
 object-group INNER
 address-object RANGE
 address6-object SIX
!
object-group address BROKEN
 address-object MISSING
!
service-object ICMP_ECHO icmp echo
service-object ALL_TCP tcp range 1 65535
service-object GRE protocol 47
service-object ODD icmp bogus
secure-policy 1
 name broken
 sourceip BROKEN
 action deny
 activate
!
secure-policy 2
 name dyn
 destinationip DYN
 action deny
 activate
!
secure-policy 3
 name unknown_line
 from LAN1
 source-mac 00:11:22:33:44:55
 action deny
 activate
!
""")
    model, _ = parse(text)
    assert model.addresses["MASKED"].value == "10.5.0.0/25" and model.addresses["RANGE"].value == "10.5.0.20-10.5.0.29"
    assert model.addresses["IFNET"].value == "10.3.0.0/24" and model.addresses["IFIP"].value == "198.51.100.2"
    assert model.addresses["DYN"].kind.value == "unsupported" and model.addresses["GW"].kind.value == "unsupported"
    assert model.address_groups["OUTER"].members == ["INNER", "RANGE", "SIX"] and model.address_groups["BROKEN"].unsupported
    assert model.services["ICMP_ECHO"].entries[0].icmp_type == 8 and model.services["ALL_TCP"].entries[0].dst_ports == ""
    assert model.services["GRE"].entries[0].ip_protocol == 47 and model.services["ODD"].unsupported
    assert rule_named(model, "unknown_line").unsupported  # (a line FWShift does not know: not converted, never read as any)
    for name in ("broken", "dyn", "unknown_line"):
        report = Report()
        cli.convert(model, "panos", report)
        assert report.items[("rule", name)].disabled


def test_service_source_port_user_schedule_and_activate() -> None:
    text = zld_text("""object-group service WEBS
 service-object HTTP
!
secure-policy 1
 name sport
 sourceport tcp range 1024 65535
 service WEBS
 action allow
 activate
!
secure-policy 2
 name users
 user alice
 schedule WORK
 action allow
!
secure-policy 3
 name ctm
 ctmatch dnat
 action allow
 activate
!
""")
    model, report = parse(text)
    sport = rule_named(model, "sport")
    entries = model.services[sport.services[0]].entries
    assert [(e.protocol.value, e.dst_ports, e.src_ports) for e in entries] == [("tcp", "80", "1024-65535")]
    users = rule_named(model, "users")
    assert users.users == ["alice"] and users.schedule == "WORK" and users.enabled
    assert "ZYXEL_ACTIVATE_UNSAID" in codes(report)
    assert rule_named(model, "ctm").unsupported


def test_insert_append_and_zld3_firewall_rules() -> None:
    text = zld_text("""secure-policy insert 1
 name b
 action deny
exit
secure-policy insert 1
 name a
 action allow
exit
secure-policy append
 name c
 action allow
exit
""")
    model, _ = parse(text)
    assert [r.name for r in model.rules] == ["a", "b", "c"]
    model, report = parse(zld_text("firewall LAN1 WAN 1\n action deny\n activate\n!\nfirewall 2\n action allow\n activate\n!\n"))
    assert model.rules[0].src_zones == ["LAN1"] and model.rules[0].dst_zones == ["WAN"] and "ZYXEL_FIREWALL" in codes(report)


def test_virtual_servers_are_before_the_policy() -> None:
    text = zld_text("""address-object PUB 198.51.100.10
address-object PUBR 198.51.100.20-198.51.100.23
address-object INR 10.5.0.20-10.5.0.23
secure-policy 1
 name web
 from WAN
 to DMZ
 destinationip WEB
 service HTTP
 action allow
 activate
!
""", """ip virtual-server VS1 interface ge1 original-ip PUB map-to WEB map-type port protocol tcp original-port 80 mapped-port 80 nat-loopback
ip virtual-server VS2 interface ge1 original-ip 198.51.100.11 map-to 10.5.0.11 map-type any nat-1-1-map
ip virtual-server VS3 interface ge1 original-ip PUBR map-to INR map-type any nat-1-1-map
ip virtual-server VS4 interface ge1 original-ip 198.51.100.12 map-to 10.5.0.12 map-type ports protocol tcp original-port-begin 80 original-port-end 89 mapped-port-begin 1080
ip virtual-server VS5 interface ge1 original-ip 198.51.100.13 map-to 10.5.0.13 map-type port protocol udp original-port 53 mapped-port 53 deactivate
""")
    model, report = parse(text)
    assert model.lookup_after_dnat and "PUB" in rule_named(model, "web").destinations
    assert verdict(model, "203.0.113.5", "198.51.100.10", ingress="WAN", egress="DMZ") is True
    nats = {n.name: n for n in model.nat_rules}
    assert nats["virtual-server VS1"].src_zones == ["WAN"] and nats["virtual-server VS1"].destination_translation is not None
    two = nats["virtual-server VS2"].source_translation
    assert two is not None and two.bidirectional and nats["virtual-server VS2"].dst_zones == ["WAN"]
    assert nats["virtual-server VS3"].sources == ["INR"] and not nats["virtual-server VS3"].unsupported
    assert nats["virtual-server VS4"].unsupported  # (a shifted range of ports)
    assert not nats["virtual-server VS5"].enabled
    assert "ZYXEL_NAT_LOOPBACK" in codes(report)


def test_policy_routes_with_snat() -> None:
    text = zld_text("", """policy 1
 interface ge3
 source any
 next-hop auto
!
policy 2
 interface ge3
 next-hop interface ge1
 snat outgoing-interface
!
policy 3
 interface ge5
 snat pool WEB
!
policy 4
 interface ge5
!
""")
    model, report = parse(text)
    names = [n.name for n in model.nat_rules]
    assert names == ["policy-route 1", "policy-route 2", "policy-route 3"]  # (the route after the last SNAT is routing only)
    first, second, third = model.nat_rules
    assert first.source_translation is None and "ZYXEL_ROUTE_NO_SNAT" in codes(report)
    assert second.src_zones == ["LAN1"] and second.dst_zones == ["WAN"] and second.source_translation is not None
    assert third.source_translation is not None and third.source_translation.addresses == ["WEB"]


# -- the emitter ----------------------------------------------------------------------------------------------


def small_model() -> Policy:
    from fwshift.model import Address, AddressGroup, AddressKind, Service, ServiceEntry

    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    for zone in ("trust", "untrust", "LAN1"):
        p.zones[zone] = Zone(zone, interfaces=[{"trust": "eth1", "untrust": "eth2", "LAN1": "eth3"}[zone]])
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.1.0.10/32")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8:1::/64")
    p.address_groups["both"] = AddressGroup("both", ["web", "six"])
    p.services["web443"] = Service("web443", [ServiceEntry(Protocol.TCP, "443,8000-8010")])
    p.rules.append(Rule("allow web", src_zones=["untrust"], dst_zones=["trust", "LAN1"], destinations=["both"], services=["web443"]))
    p.rules.append(Rule("not these", src_zones=["trust"], dst_zones=["untrust"], sources=["10.1.0.0/24"], negate_source=True,
                        action=Action.DROP))  # fmt: skip
    p.rules.append(Rule("users", users=["bob"]))
    for rule in p.rules:
        rule.origin = rule.name
    return p


def test_emitter_objects_zones_rules_and_order() -> None:
    p = small_model()
    text, report = emit(p, Options(policy_id_start=5, zone_map={"untrust": "WAN"}))
    zld, _ = read_zld(text, existing=4)
    lines = text.splitlines()
    assert "zone FWS_trust" in lines and "zone WAN" not in lines and "zone LAN1" not in lines  # (WAN named by --zone-map, LAN1 a zone of ZLD)
    assert "#   zone WAN / interface eth2" in lines
    first = text.index("secure-policy insert 5")
    assert text.index("secure-policy insert 6") > first and "secure-policy6 insert 5" in text
    assert "object-group service FWS_web443" in text and "service-object FWS_tcp_8000_8010 tcp range 8000 8010" in text
    rules4 = zld["rules"][4][4:]
    assert all(r.get("existing") for r in zld["rules"][4][:4]) and not zld["rules"][4][-1].get("existing")  # (before the rules it has)
    assert [r["from"] for r in rules4[:2]] == ["WAN", "WAN"] and [r["to"] for r in rules4[:2]] == ["FWS_trust", "LAN1"]
    negated = rules4[2]
    assert negated["action"] == "deny" and negated["source"][0] == "group"  # (every IPv4 address but 10.1.0.0/24: ranges)
    assert report.items[("rule", "users")].disabled and "USER_MATCH" in codes(report)
    assert not re.search(r"^(no (?!activate|log|deactivate)|.*\b(delete|flush|rename)\b)", text, re.MULTILINE)  # (nothing deleted)
    assert "write" not in text.split()
    with pytest.raises(FwshiftError):
        emit(p, Options(object_prefix="9bad"))


def test_emitter_defaults_close_every_pair_of_zones() -> None:
    p = small_model()
    p.rules = []
    text, report = emit(p)
    zld, _ = read_zld(text)
    judge = ZldJudge(zld)
    assert judge.allows(Packet("", "", "10.1.0.5", "10.1.0.6", "tcp", 1024, 80), "FWS_trust", "FWS_trust") is True  # (inside: allowed)
    assert judge.allows(Packet("", "", "10.1.0.5", "10.2.0.6", "tcp", 1024, 80), "FWS_trust", "LAN1") is False
    assert "ZYXEL_DEFAULT_RULES" in codes(report)


def test_emitter_nat() -> None:
    from fwshift.model import DestNat, NatRule, Service, ServiceEntry, SnatKind, SourceNat

    p = small_model()
    p.services["tcp80"] = Service("tcp80", [ServiceEntry(Protocol.TCP, "80")])
    p.nat_rules.append(NatRule("pub", src_zones=["untrust"], destinations=["198.51.100.10"], service="tcp80",
                               destination_translation=DestNat("10.1.0.10", "8080")))  # fmt: skip
    p.nat_rules.append(NatRule("static", sources=["10.1.0.11"], dst_zones=["untrust"],
                               source_translation=SourceNat(SnatKind.STATIC, ["198.51.100.11"], bidirectional=True)))  # fmt: skip
    p.nat_rules.append(NatRule("hide", src_zones=["trust"], dst_zones=["untrust"], sources=["10.1.0.0/24"],
                               source_translation=SourceNat(SnatKind.INTERFACE)))  # fmt: skip
    p.nat_rules.append(NatRule("twice", src_zones=["trust"], destinations=["198.51.100.12"], destination_translation=DestNat("10.1.0.12"),
                               source_translation=SourceNat(SnatKind.INTERFACE)))  # fmt: skip
    for nat in p.nat_rules:
        nat.origin = nat.name
    text, report = emit(p)
    assert ("ip virtual-server FWS_pub interface eth2 original-ip 198.51.100.10 map-to 10.1.0.10 map-type port protocol tcp "
            "original-port 80 mapped-port 8080") in text  # fmt: skip
    assert "ip virtual-server FWS_static interface eth2 original-ip 198.51.100.11 map-to 10.1.0.11 map-type any nat-1-1-map" in text
    assert "policy insert 1\n deactivate" in text and " interface eth1\n" in text and " snat outgoing-interface\n no deactivate" in text
    assert report.items[("nat", "twice")].skipped and "ZYXEL_SNAT_EGRESS" in codes(report)


def test_the_parser_reads_what_the_emitter_writes_and_compare() -> None:
    model, _ = parse((DATA / "zyxel_sample.conf").read_text(encoding="utf-8"))
    text, report = emit(model)
    back, _ = parse(text)
    written = {r.name for r in back.rules}
    assert "FWS_LAN1_Outgoing" in written and "FWS_V6_Admin_Web" in written
    assert cli.detect_format(text.encode()) == "zyxel"
    assert "zyxel" in cli.READ_BACK


def test_sample_converts_to_every_target(tmp_path: Any) -> None:
    for target in cli.VENDORS:
        out = tmp_path / f"out.{target}"
        assert cli.main(["convert", str(DATA / "zyxel_sample.conf"), "--to", target, "-o", str(out), "-q"]) == 0, target
    report = tmp_path / "report.json"
    args = ["convert", str(DATA / "zyxel_sample.conf"), "--to", "zyxel", "-o", str(tmp_path / "z.txt"), "--report-json", str(report), "-q"]
    assert cli.main(args) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["rule"]["total"] == 19


def test_emitter_services_a_service_object_cannot_say() -> None:
    from fwshift.model import Service, ServiceEntry

    p = small_model()
    p.services["alltcp"] = Service("alltcp", [ServiceEntry(Protocol.TCP)])
    p.services["code"] = Service("code", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)])
    p.services["sport"] = Service("sport", [ServiceEntry(Protocol.UDP, "53", "1024-65535")])
    p.services["anyip"] = Service("anyip", [ServiceEntry(Protocol.IP)])
    p.rules = [Rule(name, services=[name]) for name in ("alltcp", "code", "sport", "anyip")]
    for rule in p.rules:
        rule.origin = rule.name
    text, report = emit(p)
    zld, _ = read_zld(text)
    assert "service-object FWS_alltcp tcp range 1 65535" in text.splitlines()
    assert report.items[("rule", "code")].disabled and not report.items[("rule", "sport")].disabled
    sport = next(r for r in zld["rules"][4] if r["sourceport"] is not None)
    assert sport["sourceport"] == ("udp", 1024, 65535) and zld["services"][sport["service"][1]]["spec"] == ("udp", 53, 53)
    anyip = next(r for r in zld["rules"][4] if r["service"] == ("any",) and r["active"] and r["action"] == "allow")
    assert anyip["from"] == "any"  # (every protocol: the rule names no service)


def test_compare_reads_the_output_with_its_zones_and_unzoned_nat_interfaces(tmp_path: Any) -> None:
    from fwshift.emitters import zyxel as emit_zyxel

    assert emit_zyxel.activate("#   zone WAN / interface ge1\n") == "zone WAN\n interface ge1\nexit\n"
    report = tmp_path / "report.json"
    args = ["convert", str(DATA / "zyxel_sample.conf"), "--to", "zyxel", "-o", str(tmp_path / "z.zysh"), "--report-json", str(report),
            "--compare", "-q"]  # fmt: skip
    assert cli.main(args) == 0
    notes = {n["code"]: n["message"] for n in json.loads(report.read_text(encoding="utf-8"))["notes"]}
    assert "(0 for certain" in notes["COMPARE_OPENED"]  # (only what the rules written inactive may have matched)
    model, report_ = parse(zld_text("", "interface ge7\n ip address 10.7.0.1 255.255.255.0\n!\n"
                                        "ip virtual-server VS interface ge7 original-ip 10.7.0.1 map-to 10.5.0.10 map-type any\n"))
    assert model.nat_rules[0].src_zones == ["ge7"] and model.zones["ge7"].interfaces == ["ge7"] and "ZYXEL_NAT_UNZONED" in codes(report_)
