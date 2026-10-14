# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Huawei USG: parser, emitter, and packet-level equivalence with a judge of its own.

A random USG is a plain description (zones, address sets, service sets, the rules of ``security-policy``, the
defaults, ``nat server``, ``nat-policy``) that ``render`` writes as ``display current-configuration`` and
``UsgJudge`` decides packets from, as a USG does: ``nat server`` first, then the rules top to bottom (first match),
then the default (permit inside a zone unless ``default packet-filter intrazone enable``, otherwise the default
action). ``read_usg`` reads the commands the emitter writes back into such a description, so the same judge decides
the output. None of it shares code with the parser or the emitter.
"""

from __future__ import annotations

import ipaddress
import json
import random
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows, random_model

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.options import Options
from fwshift.parsers import huawei as parse_huawei
from fwshift.report import Report

# The judge's own table of predefined services (the well-known ports).
KNOWN = {
    "http": [("tcp", None, [(80, 80)])], "https": [("tcp", None, [(443, 443)])], "ssh": [("tcp", None, [(22, 22)])],
    "dns": [("tcp", None, [(53, 53)]), ("udp", None, [(53, 53)])], "ntp": [("udp", None, [(123, 123)])],
    "icmp": [("icmp", None)], "gre": [("proto", 47)], "smtp": [("tcp", None, [(25, 25)])],
}  # fmt: skip
UNKNOWN_PREDEFINED = ["netbios-session", "ms-sql", "radius"]
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
ZONES = ["trust", "untrust", "dmz", "lab"]
NETS = ["10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/25", "10.0.2.16/28", "10.0.0.5/32", "10.0.1.130/32", "192.0.2.0/24", "10.0.0.0/16",
        "2001:db8:1::/48", "2001:db8:2::9/128"]  # fmt: skip (a rule that names a global address is reported, NAT_ADDRESS_EXPOSED)
RANGES = [("10.0.3.1", "10.0.3.20"), ("10.0.2.1", "10.0.2.40"), ("2001:db8:2::1", "2001:db8:2::f")]
GLOBALS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]
INSIDES = ["10.0.0.5", "10.0.1.130", "10.0.2.20", "10.0.3.9"]
POOL = ["10.0.0.5", "10.0.0.9", "10.0.1.16", "10.0.1.130", "10.0.2.20", "10.0.2.100", "10.0.3.9", "10.0.3.30", "10.0.200.1", "192.0.2.7",
        "198.51.100.4", "2001:db8:1::5", "2001:db8:2::9", "2001:db8:3::1", "2001:db8:2::20"] + GLOBALS  # fmt: skip
PORTS = [22, 25, 53, 80, 443, 8080, 8443, 123, 79, 81, 1023, 1024, 7999, 8000, 8100, 8101, 65535, 0]


def addr(text: str) -> Any:
    return ipaddress.ip_address(text)


# -- the judge ------------------------------------------------------------------------------------------------


def spec_matches(spec: Any, address: str, sets: Dict[str, Any], depth: int = 0) -> bool:
    kind = spec[0]
    probe = addr(address)
    if kind == "any":
        return True
    if kind == "net":
        net = ipaddress.ip_network(spec[1], strict=False)
        return probe.version == net.version and probe in net
    if kind == "range":
        first, last = addr(spec[1]), addr(spec[2])
        return probe.version == first.version and int(first) <= int(probe) <= int(last)
    if kind == "wild":
        base, wild = int(addr(spec[1])), int(addr(spec[2]))
        return probe.version == 4 and (int(probe) & ~wild & 0xFFFFFFFF) == (base & ~wild & 0xFFFFFFFF)
    if kind == "set":
        assert depth < 10
        return any(spec_matches(entry, address, sets, depth + 1) for entry in sets[spec[1]]["entries"])
    raise AssertionError(spec)


def ports_match(ports: Optional[List[Tuple[int, int]]], port: int) -> bool:
    return ports is None or any(lo <= port <= hi for lo, hi in ports)


def entry_matches(entry: Any, pkt: Packet, services: Dict[str, Any], depth: int = 0) -> bool:
    kind = entry[0]
    if kind in ("tcp", "udp", "sctp"):
        return pkt.proto == kind and ports_match(entry[1], pkt.sport) and ports_match(entry[2], pkt.dport)
    if kind in ("icmp", "icmp6"):
        return pkt.proto == kind and (entry[1] is None or entry[1] == pkt.icmp_type)
    if kind == "proto":
        return str(NUMBERS.get(pkt.proto, pkt.proto)) == str(entry[1])
    if kind == "set":
        assert depth < 10
        return any(entry_matches(e, pkt, services, depth + 1) for e in services[entry[1]]["entries"])
    if kind == "known":
        return any(entry_matches(e, pkt, services, depth + 1) for e in KNOWN[entry[1]])
    raise AssertionError(entry)


class UsgJudge:
    def __init__(self, usg: Dict[str, Any]) -> None:
        self.usg = usg

    def translate(self, pkt: Packet, ingress: str) -> Tuple[str, int]:
        for server in self.usg["servers"]:
            if server["zone"] and server["zone"] != ingress:
                continue
            if pkt.dst != server["global"]:
                continue
            if server["gport"] is not None:
                if pkt.proto == server["proto"] and pkt.dport == server["gport"]:
                    return server["inside"], server["iport"]
                continue
            if server["proto"] is not None and pkt.proto != server["proto"]:
                continue
            return server["inside"], pkt.dport
        return pkt.dst, pkt.dport

    def allows(self, pkt: Packet, ingress: str, egress: str) -> Optional[bool]:
        dst, dport = self.translate(pkt, ingress)
        if dport != pkt.dport and any(rule["services"] for rule in self.usg["rules"]):
            return None  # (a port translation: rules that name the inside port are not rewritten; NAT_PORT_TRANSLATION)
        if dst == pkt.dst and any(server["global"] == pkt.dst for server in self.usg["servers"]):
            return None  # (traffic to a global address that nat server does not translate: rules that name the inside
            #             address get the global one too, for every port, and say so; NAT_DESTINATION_REWRITTEN)
        seen = Packet(ingress, egress, pkt.src, dst, pkt.proto, pkt.sport, dport, pkt.icmp_type)
        sets, services = self.usg["sets"], self.usg["services"]
        for rule in self.usg["rules"]:
            if not rule["enabled"]:
                continue
            if rule["src_zones"] and ingress not in rule["src_zones"]:
                continue
            if rule["dst_zones"] and egress not in rule["dst_zones"]:
                continue
            if rule["bad"] or rule.get("carried") or (rule["dst_ex"] and not rule["dst"] and self.usg["servers"]):
                return None  # (not converted: the judge does not decide what comes after it; a negated destination is
                #             not rewritten through nat server)
            if rule["src"] and not any(spec_matches(s, seen.src, sets) for s in rule["src"]):
                continue
            if any(spec_matches(s, seen.src, sets) for s in rule["src_ex"]):
                continue
            if rule["dst"] and not any(spec_matches(s, seen.dst, sets) for s in rule["dst"]):
                continue
            if any(spec_matches(s, seen.dst, sets) for s in rule["dst_ex"]):
                continue
            if rule["services"] and not any(entry_matches(e, seen, services) for e in rule["services"]):
                continue
            return rule["action"] == "permit"
        if ingress == egress and not self.usg["policed"]:
            return True
        return bool(self.usg["default_permit"])


# -- random USGs ----------------------------------------------------------------------------------------------


def random_spec(rng: random.Random, in_set: bool, set_names: List[str]) -> Tuple[Any, bool]:
    """An address and whether it makes its rule or set not converted."""
    roll = rng.random()
    if set_names and roll < 0.25:
        return ("set", rng.choice(set_names)), False
    if roll < 0.35:
        first, last = rng.choice(RANGES)
        return ("range", first, last), False
    if roll < 0.42:
        if rng.random() < 0.7:
            return ("wild", rng.choice(["10.0.2.0", "10.0.2.77", "10.0.3.130"]), rng.choice(["0.0.0.255", "0.0.1.255"])), not in_set
        return ("wild", "10.0.2.0", "0.0.255.0"), True  # (not contiguous)
    return ("net", rng.choice(NETS)), False


def random_ports(rng: random.Random) -> Optional[List[Tuple[int, int]]]:
    if rng.random() < 0.3:
        return None
    out = []
    for _ in range(rng.randint(1, 3)):
        lo = rng.choice([22, 53, 80, 443, 8000, 8080, 1024])
        hi = lo if rng.random() < 0.6 else lo + rng.choice([0, 1, 100])
        out.append((lo, hi))
    return out


def random_entry(rng: random.Random) -> Any:
    roll = rng.random()
    if roll < 0.55:
        proto = rng.choice(["tcp", "tcp", "udp"])
        return (proto, random_ports(rng) if rng.random() < 0.2 else None, random_ports(rng))
    if roll < 0.75:
        return ("icmp", rng.choice([None, 8, 0]))
    if roll < 0.77:
        return ("proto", 0)  # (not converted: 0 may stand for every protocol)
    if roll < 0.85:
        return ("icmp6", rng.choice([None, 128]))
    return ("proto", rng.choice([47, 50]))


def random_usg(rng: random.Random, nat: Optional[bool] = None) -> Dict[str, Any]:
    usg: Dict[str, Any] = {"sets": {}, "services": {}, "rules": [], "servers": [], "snat": [], "policed": rng.random() < 0.3,
                           "default_permit": rng.random() < 0.25, "bad_sets": set(), "bad_services": set()}  # fmt: skip
    for index in range(rng.randint(0, 4)):
        name = f"as{index}"
        entries, bad = [], False
        for _ in range(rng.randint(1, 3)):
            spec, worse = random_spec(rng, True, list(usg["sets"]))
            entries.append(spec)
            bad = bad or worse or (spec[0] == "set" and spec[1] in usg["bad_sets"])
        if rng.random() < 0.05:
            entries.append(("mac", "00e0-fc12-3456"))
            bad = True
        usg["sets"][name] = {"entries": entries}
        if bad:
            usg["bad_sets"].add(name)
    for index in range(rng.randint(0, 3)):
        name = f"svc{index}"
        entries = [random_entry(rng) for _ in range(rng.randint(1, 3))]
        if usg["services"] and rng.random() < 0.3:
            entries.append(("set", rng.choice(list(usg["services"]))))
        usg["services"][name] = {"entries": entries}
        if any(e == ("proto", 0) or (e[0] == "set" and e[1] in usg["bad_services"]) for e in entries):
            usg["bad_services"].add(name)

    def zones() -> List[str]:
        return [] if rng.random() < 0.3 else rng.sample(ZONES, rng.randint(1, 2))

    for index in range(rng.randint(3, 12)):
        rule: Dict[str, Any] = {"name": f"rule{index}", "src_zones": zones(), "dst_zones": zones(), "src": [], "src_ex": [], "dst": [],
                                "dst_ex": [], "services": [], "inline": [], "action": rng.choice(["permit", "permit", "deny"]),
                                "enabled": rng.random() > 0.1, "bad": False, "extra": []}  # fmt: skip
        for side in ("src", "dst"):
            for _ in range(rng.choice([0, 0, 1, 1, 2])):
                spec, bad = random_spec(rng, False, list(usg["sets"]))
                rule[side].append(spec)
                rule["bad"] = rule["bad"] or bad or (spec[0] == "set" and spec[1] in usg["bad_sets"])
            if rng.random() < 0.15:
                spec, bad = random_spec(rng, False, list(usg["sets"]))
                rule[side + "_ex"].append(spec)
                rule["bad"] = rule["bad"] or bad or (spec[0] == "set" and spec[1] in usg["bad_sets"])
        for _ in range(rng.choice([0, 0, 1, 2])):
            roll = rng.random()
            if roll < 0.4 and usg["services"]:
                rule["services"].append(("set", rng.choice(list(usg["services"]))))
                rule["bad"] = rule["bad"] or rule["services"][-1][1] in usg["bad_services"]
            elif roll < 0.75:
                rule["services"].append(("known", rng.choice(list(KNOWN))))
            elif roll < 0.95:
                entry = random_entry(rng)
                rule["services"].append(entry)
                rule["inline"].append(entry)
                rule["bad"] = rule["bad"] or entry == ("proto", 0)
            else:
                rule["services"].append(("unknown", rng.choice(UNKNOWN_PREDEFINED)))
                rule["bad"] = True
        if rng.random() < 0.06:
            extra = rng.choice(["application app WeChat", "user user1", "time-range work", "destination-address domain-set web",
                                "source-mac-address 00e0-fc12-3456"])  # (the last: a line FWShift does not know)
            rule["extra"].append(extra)
            if extra.startswith(("application", "user", "time-range")):
                rule["carried"] = True  # (carried in the model as what it is; the judge does not decide it)
            else:
                rule["bad"] = True
        if rng.random() < 0.02:
            rule["action"], rule["bad"] = "", True  # (a rule without an action is not converted)
        if rng.random() < 0.02:
            rule["dst_zones"], rule["bad"] = ["guest"], True  # (a zone that is not in the configuration)
        if rng.random() < 0.08:
            rule["src_zones"] = ["local"] + rng.sample(ZONES, rng.randint(0, 1))  # (local alone: a rule for the firewall itself)
        if rng.random() < 0.04:
            rule["dst_ex"].append(("any",))
            rule["bad"] = rule["bad"] or bool(rule["dst"])  # (members minus every address: nothing; else a negation of any)
        usg["rules"].append(rule)
    with_nat = rng.random() < 0.5 if nat is None else nat
    if with_nat:
        for index, (global_, inside) in enumerate(zip(rng.sample(GLOBALS, rng.randint(1, 3)), rng.sample(INSIDES, 3))):
            server: Dict[str, Any] = {"name": f"srv{index}", "zone": rng.choice([None, None, "untrust"]), "global": global_, "inside": inside,
                                      "proto": None, "gport": None, "iport": None, "reverse": rng.random() < 0.5}  # fmt: skip
            roll = rng.random()
            if roll < 0.5:
                server["proto"] = rng.choice(["tcp", "udp"])
                server["gport"] = rng.choice([80, 443, 8080])
                server["iport"] = rng.choice([80, 8080, 8443])
                server["reverse"] = False if rng.random() < 0.7 else True
            elif roll < 0.65:
                server["proto"] = "icmp"
            usg["servers"].append(server)
        for index in range(rng.randint(0, 2)):
            usg["snat"].append({"name": f"snat{index}", "action": rng.choice(["easy-ip", "address-group pool1", "no-nat"])})
    return usg


def mask_of(length: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)


def address_text(spec: Any, rng: random.Random, in_set: bool) -> str:
    kind = spec[0]
    if kind == "net":
        net = ipaddress.ip_network(spec[1])
        if net.version == 6:
            return rng.choice([f"{net.network_address} {net.prefixlen}", f"{net.network_address}/{net.prefixlen}"])
        forms = [f"{net.network_address} mask {net.prefixlen}", f"{net.network_address} mask {mask_of(net.prefixlen)}"]
        if not in_set:
            forms.append(f"{net.network_address} {net.prefixlen}")
        return rng.choice(forms)
    if kind == "range":
        return f"range {spec[1]} {spec[2]}"
    if kind == "wild":
        return f"{spec[1]} {spec[2]}"
    if kind == "set":
        return f"address-set {spec[1]}"
    if kind == "any":
        return "any"
    if kind == "mac":
        return spec[1]
    raise AssertionError(spec)


def port_text(ports: List[Tuple[int, int]]) -> str:
    return " ".join(str(lo) if lo == hi else f"{lo} to {hi}" for lo, hi in ports)


def entry_text(entry: Any, rng: random.Random) -> str:
    kind = entry[0]
    if kind in ("tcp", "udp", "sctp"):
        line = f"protocol {kind}"
        if entry[1] is not None:
            line += " source-port " + port_text(entry[1])
        elif rng.random() < 0.2:
            line += " source-port 0 to 65535"
        if entry[2] is not None:
            line += " destination-port " + port_text(entry[2])
        return line
    if kind in ("icmp", "icmp6"):
        line = "protocol " + ("icmp" if kind == "icmp" else "icmpv6")
        return line + ("" if entry[1] is None else f" icmp-type {entry[1]}")
    if kind == "proto":
        return "protocol " + ({47: "gre", 50: "esp"}[entry[1]] if entry[1] and rng.random() < 0.5 else str(entry[1]))
    raise AssertionError(entry)


def render(usg: Dict[str, Any], rng: random.Random) -> str:
    out = ["#", rng.choice(["sysname USG-LAB", " sysname USG-LAB"])]  # (VRP prints commands of the system view with a space)
    if usg["policed"] and rng.random() < 0.3:
        out.append(" default packet-filter intrazone enable")  # (after another command of the system view, no # between)
        usg["policed_top"] = True
    out.append("#")
    interfaces = {"trust": "GigabitEthernet1/0/1", "untrust": "GigabitEthernet1/0/2", "dmz": "GigabitEthernet1/0/3", "lab": "GigabitEthernet1/0/4"}
    for index, (zone, interface) in enumerate(interfaces.items()):
        out += [f"interface {interface}", f" ip address 10.{index}.255.1 255.255.255.0", "#"]
    if usg["policed"] and not usg.get("policed_top") and rng.random() < 0.5:
        out += [rng.choice(["", " "]) + "default packet-filter intrazone enable", "#"]
        usg["policed_top"] = True
    for zone, interface in interfaces.items():
        if zone == "lab":
            out += ["firewall zone name lab id 4", " set priority 60"]
        else:
            out.append(f"firewall zone {zone}")
            out.append(f" set priority {dict(trust=85, untrust=5, dmz=50)[zone]}")
        out += [f" add interface {interface}", "#"]
    out += ["firewall zone local", " set priority 100", "#"]
    for name, found in usg["sets"].items():
        out.append(f"ip address-set {name} type object")
        if rng.random() < 0.3:
            out.append(f" description set {name}")
        for index, spec in enumerate(found["entries"]):
            number = f"{index} " if rng.random() < 0.9 else ""
            out.append(f" address {number}{address_text(spec, rng, True)}")
        out.append("#")
    for name, found in usg["services"].items():
        out.append(f"ip service-set {name} type object")
        for index, entry in enumerate(found["entries"]):
            text = f"service-set {entry[1]}" if entry[0] == "set" else entry_text(entry, rng)
            out.append(f" service {index} {text}")
        out.append("#")
    if any(s["action"].startswith("address-group") for s in usg["snat"]):
        out += ["nat address-group pool1 0", " mode pat", " section 0 203.0.113.20 203.0.113.22", "#"]
    out.append("security-policy")
    if usg["default_permit"]:
        out.append(" default action permit")
    if usg["policed"] and not usg.get("policed_top"):
        out.append(" default packet-filter intrazone enable")
    for rule in usg["rules"]:
        out.append(f" rule name {rule['name']}")
        if rng.random() < 0.2:
            out.append(f"  description \"allow {rule['name']}\"")
        out += [f"  source-zone {z}" for z in rule["src_zones"]]
        out += [f"  destination-zone {z}" for z in rule["dst_zones"]]
        for side, keyword in (("src", "source-address"), ("dst", "destination-address")):
            out += [f"  {keyword} {address_text(spec, rng, False)}" for spec in rule[side]]
            out += [f"  {keyword}-exclude {address_text(spec, rng, False)}" for spec in rule[side + "_ex"]]
        named = []
        for entry in rule["services"]:
            if entry[0] in ("set", "known", "unknown"):
                named.append(entry[1])
            else:
                out.append(f"  service {entry_text(entry, rng)}")
        if named:
            if rng.random() < 0.5:
                out.append("  service " + " ".join(named))
            else:
                out += [f"  service {name}" for name in named]
        out += [f"  {extra}" for extra in rule["extra"]]
        if rng.random() < 0.3:
            out.append("  policy logging")
        if rule["action"]:
            out.append(f"  action {rule['action']}")
        if not rule["enabled"]:
            out.append("  disable")
    out.append("#")
    if usg["snat"]:
        out.append("nat-policy")
        for snat in usg["snat"]:
            out += [f" rule name {snat['name']}", "  source-zone trust", "  egress-interface GigabitEthernet1/0/2",
                    "  source-address 10.0.0.0 mask 255.255.0.0", f"  action source-nat {snat['action']}"]  # fmt: skip
        out.append("#")
    names = {80: "www", 443: "https"}
    for server in usg["servers"]:
        line = f"nat server {server['name']} {rng.choice(['', '0 '])}"
        if server["zone"]:
            line += f"zone {server['zone']} "
        if server["proto"]:
            line += f"protocol {server['proto']} "
        line += f"global {server['global']}"
        if server["gport"] is not None:
            port = server["gport"]
            line += f" {names.get(port, port) if rng.random() < 0.5 else port}"
        line += f" inside {server['inside']}"
        if server["iport"] is not None:
            line += f" {server['iport']}"
        if not server["reverse"]:
            line += " no-reverse"
        line += rng.choice(["", " unr-route"])
        out.append(rng.choice(["", " "]) + line.replace("  ", " "))
    out += ["#", "return"]
    return "\n".join(out) + "\n"


def usg_packet(rng: random.Random) -> Optional[Tuple[Packet, str, str]]:
    src, dst = rng.choice(POOL), rng.choice(POOL)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    six = ":" in src
    proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if six else "icmp", "47", "50"])
    pkt = Packet("", "", src, dst, proto, rng.choice([1023, 1024, 40000, 53, 80]), rng.choice(PORTS), rng.choice([0, 8, 3, 128, 129]))
    return pkt, rng.choice(ZONES), rng.choice(ZONES)


def judged(usg: Dict[str, Any], model: Any, rng: random.Random, seed: int, packets: int = 300, zone_names: Optional[Dict[str, str]] = None) -> int:
    judge = UsgJudge(usg)
    by_name = {r.name: r for r in model.rules}
    for rule in usg["rules"]:
        if rule["bad"] and rule["name"] in by_name:  # (what the judge does not decide is not converted, never read as more)
            assert by_name[rule["name"]].unsupported, (seed, rule)
    count = 0
    for _ in range(packets):
        found = usg_packet(rng)
        if found is None:
            continue
        pkt, ingress, egress = found
        verdict = judge.allows(pkt, ingress, egress)
        if verdict is None:
            continue
        names = zone_names or {}
        pkt.in_if, pkt.out_if = names.get(ingress, ingress), names.get(egress, egress)
        count += 1
        assert model_allows(model, pkt) == verdict, (seed, pkt, json.dumps(usg, indent=1, default=str))
    return count


def parse(text: str) -> Tuple[Any, Report]:
    report = Report()
    return parse_huawei.parse(text.encode(), report), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


@pytest.mark.parametrize("kind", ["policy", "nat"])
def test_parsed_usg_decides_like_the_judge(kind: str) -> None:
    compared = 0
    offset = {"policy": 0, "nat": 1000}[kind]
    for seed in range(offset, offset + 200):
        rng = random.Random(seed)
        usg = random_usg(rng, nat=kind == "nat")
        text = render(usg, rng)
        assert cli.detect_format(text.encode()) == "huawei", text
        model, _ = parse(text)
        compared += judged(usg, model, rng, seed)
    assert compared > 15000


# -- the emitted configuration, read back --------------------------------------------------------------


def _read_address(words: List[str]) -> Any:
    if words[0] == "range":
        assert len(words) == 3, words
        addr(words[1]), addr(words[2])
        return ("range", words[1], words[2])
    if words[0] == "address-set":
        assert len(words) == 2, words
        return ("set", words[1])
    if len(words) == 1:
        assert "/" in words[0] and ":" in words[0], words
        return ("net", str(ipaddress.ip_network(words[0])))
    if words[1] == "mask":
        assert len(words) == 3 and words[2].isdigit(), words
        return ("net", str(ipaddress.ip_network(f"{words[0]}/{words[2]}")))
    assert len(words) == 2 and words[1].isdigit(), words
    return ("net", str(ipaddress.ip_network(f"{words[0]}/{words[1]}")))


def _read_ports(words: List[str], index: int) -> Tuple[List[Tuple[int, int]], int]:
    out = []
    while index < len(words) and words[index].isdigit():
        lo = int(words[index])
        if index + 2 < len(words) and words[index + 1] == "to":
            out.append((lo, int(words[index + 2])))
            index += 3
        else:
            out.append((lo, lo))
            index += 1
    assert out, words
    return out, index


def _read_entry(words: List[str]) -> Any:
    assert words[0] == "protocol", words
    proto = words[1]
    if proto in ("tcp", "udp", "sctp"):
        sports = dports = None
        index = 2
        while index < len(words):
            if words[index] == "source-port":
                sports, index = _read_ports(words, index + 1)
            else:
                assert words[index] == "destination-port", words
                dports, index = _read_ports(words, index + 1)
        return (proto, sports, dports)
    if proto in ("icmp", "icmpv6"):
        kind = "icmp" if proto == "icmp" else "icmp6"
        if len(words) == 2:
            return (kind, None)
        assert words[2] == "icmp-type" and len(words) == 4, words  # (an ICMP code the model does not judge)
        return (kind, int(words[3]))
    assert proto.isdigit() and len(words) == 2, words
    return ("proto", int(proto))


def read_usg(text: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """The commands the emitter writes, as a random USG; and the zone of the model -> the zone written."""
    usg: Dict[str, Any] = {"sets": {}, "services": {}, "rules": [], "servers": [], "snat": [], "policed": False, "default_permit": False}
    described: Dict[str, str] = {}  # zone written -> the zone of the model it stands for
    block = ""
    current: Any = None
    rule: Optional[Dict[str, Any]] = None
    lines = text.splitlines()
    assert lines[-1] != "" and "system-view" in lines and "return" in lines, text[-300:]
    for line in lines:
        assert len(line) < 4000 and line.isprintable(), line
        if line.startswith("#") or line in ("system-view", "return"):
            continue
        words = line.split()
        if not line.startswith(" "):
            block, current = words[0], None
            if words[:3] == ["firewall", "zone", "name"]:
                current = words[3]
                described[current] = current
            elif words[:2] == ["ip", "address-set"]:
                assert words[3:] == ["type", "object"] and words[2] not in usg["sets"], line
                current = usg["sets"].setdefault(words[2], {"entries": []})
            elif words[:2] == ["ip", "service-set"]:
                assert words[3:] == ["type", "object"] and words[2] not in usg["services"], line
                current = usg["services"].setdefault(words[2], {"entries": []})
            elif words[:2] == ["nat", "server"]:
                usg["servers"].append(read_server(words))
            elif words[:2] == ["nat", "address-group"] or words in (["security-policy"], ["nat-policy"]):
                pass
            else:
                raise AssertionError(f"not expected: {line}")
            continue
        if words == ["quit"]:
            if line == "  quit":
                rule = None
            continue
        if block == "firewall":
            assert words[0] in ("set", "description"), line
            if words[0] == "description":
                described[current] = line.strip().split(" ", 1)[1]
        elif block == "ip" and isinstance(current, dict) and line.startswith(" address "):
            assert words[1].isdigit() and int(words[1]) == len(current["entries"]), line
            current["entries"].append(_read_address(words[2:]))
        elif block == "ip" and isinstance(current, dict):
            assert words[0] == "service" and words[1].isdigit(), line
            current["entries"].append(_read_entry(words[2:]))
        elif block == "security-policy":
            if line.startswith(" rule name "):
                rule = {"name": words[2], "src_zones": [], "dst_zones": [], "src": [], "src_ex": [], "dst": [], "dst_ex": [], "services": [],
                        "action": "", "enabled": True, "bad": False}  # fmt: skip
                usg["rules"].append(rule)
            elif words == ["default", "action", "permit"]:
                usg["default_permit"] = True
            else:
                assert rule is not None and line.startswith("  "), line
                head = words[0]
                if head == "source-zone":
                    rule["src_zones"].append(words[1])
                elif head == "destination-zone":
                    rule["dst_zones"].append(words[1])
                elif head in ("source-address", "destination-address"):
                    rule["src" if head == "source-address" else "dst"].append(_read_address(words[1:]))
                elif head == "service":
                    assert len(words) == 2 and words[1] in usg["services"], line
                    rule["services"].append(("set", words[1]))
                elif head == "action":
                    assert words[1:] in (["permit"], ["deny"]), line
                    rule["action"] = words[1]
                elif head == "disable":
                    rule["enabled"] = False
                else:
                    assert head == "description" or words == ["policy", "logging"], line
        elif block in ("nat-policy", "nat"):
            pass  # (source NAT: after the policy, nothing the judge decides)
        else:
            raise AssertionError(f"not expected: {line}")
    for found in usg["rules"]:
        assert found["action"], found
        for spec in found["src"] + found["dst"]:
            assert spec[0] != "set" or spec[1] in usg["sets"], spec
    return usg, {model_zone: zone for zone, model_zone in described.items()}


def read_server(words: List[str]) -> Dict[str, Any]:
    server: Dict[str, Any] = {"name": words[2], "zone": None, "proto": None, "gport": None, "iport": None, "reverse": True}
    index = 3
    while index < len(words):
        word = words[index]
        if word == "zone":
            server["zone"] = words[index + 1]
            index += 2
        elif word == "protocol":
            server["proto"] = words[index + 1]
            index += 2
        elif word == "global":
            server["global"] = str(addr(words[index + 1]))
            index += 2
            if words[index].isdigit():
                server["gport"] = int(words[index])
                index += 1
        elif word == "inside":
            server["inside"] = str(addr(words[index + 1]))
            index += 2
            if index < len(words) and words[index].isdigit():
                server["iport"] = int(words[index])
                index += 1
        else:
            assert word == "no-reverse" and index == len(words) - 1, words
            server["reverse"] = False
            index += 1
    assert "global" in server and "inside" in server and (server["gport"] is None) == (server["iport"] is None), words
    return server


def compare(model: Any, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    """The emitted commands against the model (zones eth0, eth1, eth2), never allowing what the model does not."""
    import copy

    from test_iptables import ZONES as MODEL_ZONES
    from test_iptables import random_packet

    usg, written = read_usg(text)
    names = {zone: written.get(zone, zone) for zone in MODEL_ZONES}
    judge = UsgJudge(usg)
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (not written, and said)
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.1:
            pkt.proto = "50"
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 0, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        verdict = judge.allows(pkt, names[pkt.in_if], names[pkt.out_if])
        assert verdict is not None
        assert verdict == model_allows(model, pkt), (seed, pkt, text)
        count += 1
    return count


def zoned(model: Any) -> Any:
    from test_iptables import ZONES as MODEL_ZONES

    from fwshift.model import Zone

    for zone in MODEL_ZONES:
        model.zones.setdefault(zone, Zone(zone))
    return model


def emit(model: Any, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import huawei as emit_huawei

    report = Report()
    return emit_huawei.emit(model, report, options or Options()), report


@pytest.mark.parametrize("seed", range(40))
def test_emitted_configuration_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = zoned(random_model(rng))
    if rng.random() < 0.3:
        from fwshift.model import Action

        model.default_interzone = model.default_intrazone = Action.ALLOW  # (the model's judge knows one default)
    text, report = emit(model)
    assert compare(model, report, text, rng, seed) == 400


@pytest.mark.parametrize("seed", range(60))
def test_a_usg_read_and_written_again_decides_the_same(seed: int) -> None:
    """USG -> model -> USG commands: the commands, judged, decide as the model of the first one (NAT included)."""
    rng = random.Random(5000 + seed)
    usg = random_usg(rng)
    model, _ = parse(render(usg, rng))
    text, report = emit(model)
    found, written = read_usg(text)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    judge = UsgJudge(found)
    for _ in range(300):
        packet = usg_packet(rng)
        if packet is None:
            continue
        pkt, ingress, egress = packet
        verdict = judge.allows(pkt, written.get(ingress, ingress), written.get(egress, egress))
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = ingress, egress
        assert verdict == model_allows(model, pkt), (seed, pkt, text)


# -- what is read, and what is not ----------------------------------------------------------------------

BASE = """#
sysname USG
#
interface GigabitEthernet1/0/1
 ip address 10.0.0.1 255.255.255.0
#
interface GigabitEthernet1/0/2
 ip address 203.0.113.1 255.255.255.0
#
firewall zone trust
 set priority 85
 add interface GigabitEthernet1/0/1
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet1/0/2
#
"""


def usg_text(policy: str = "", rest: str = "") -> str:
    return BASE + rest + "security-policy\n" + policy + "#\nreturn\n"


def verdict(model: Any, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "trust", egress: str = "untrust") -> bool:
    return model_allows(model, Packet(ingress, egress, src, dst, proto, 40000, dport, 8))


def rule_named(model: Any, name: str) -> Any:
    return next(r for r in model.rules if r.name == name)


def test_detection_and_errors() -> None:
    assert cli.detect_format(usg_text().encode()) == "huawei"
    assert parse_huawei.looks_like_huawei(usg_text())
    assert not parse_huawei.looks_like_huawei("hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n")
    with pytest.raises(ParseError, match="older USG"):
        parse(BASE + "policy interzone trust untrust outbound\n policy 1\n  action permit\n")
    with pytest.raises(ParseError, match="not a configuration"):
        parse("sysname X\n#\nreturn\n")


def test_rules_first_match_and_the_defaults() -> None:
    policy = """ rule name web
  source-zone trust
  destination-zone untrust
  destination-address 192.0.2.0 mask 255.255.255.0
  service http https
  action permit
 rule name block
  source-zone trust
  action deny
"""
    model, report = parse(usg_text(policy))
    assert verdict(model, "10.0.0.5", "192.0.2.9") and verdict(model, "10.0.0.5", "192.0.2.9", dport=443)
    assert not verdict(model, "10.0.0.5", "192.0.2.9", dport=22)
    assert verdict(model, "10.0.0.5", "10.0.0.9", ingress="untrust", egress="untrust")  # (inside a zone: permitted)
    assert not verdict(model, "198.51.100.1", "10.0.0.9", ingress="untrust", egress="trust")
    assert {"HUAWEI_SOURCE", "HUAWEI_DEFAULTS", "HUAWEI_PREDEFINED"} <= codes(report)
    policed, _ = parse(usg_text(policy, "default packet-filter intrazone enable\n#\n"))
    assert not verdict(policed, "10.0.0.5", "10.0.0.9", ingress="untrust", egress="untrust")
    permit, _ = parse(usg_text(" default action permit\n" + policy))
    assert verdict(permit, "198.51.100.1", "10.0.0.9", ingress="untrust", egress="trust")
    assert not verdict(permit, "10.0.0.5", "8.8.8.8", dport=22)


def test_exclusions_sets_and_what_is_never_wider() -> None:
    rest = """ip address-set inner type object
 address 0 10.0.1.0 mask 24
 address 1 10.0.2.0 0.0.0.255
 address 2 range 10.0.3.1 10.0.3.9
#
ip address-set outer type object
 address 0 address-set inner
 address 1 2001:db8:1:: 48
#
ip address-set odd type object
 address 0 10.0.0.0 0.0.255.0
#
ip address-set macs type object
 address 0 00e0-fc12-3456
#
ip service-set svc type object
 service 0 protocol tcp source-port 1024 to 65535 destination-port 8000 to 8010 9000
 service 1 protocol icmp icmp-type 8
#
"""
    policy = """ rule name minus
  destination-address address-set outer
  destination-address-exclude 10.0.1.128 25
  service svc
  action permit
 rule name only-exclude
  source-address-exclude 10.0.0.0 mask 255.255.255.0
  action permit
 rule name nothing
  source-address 10.0.5.0 24
  source-address-exclude 10.0.0.0 16
  action permit
 rule name odd
  source-address address-set odd
  action permit
 rule name mac
  source-address address-set macs
  action permit
 rule name zero
  source-address 10.0.0.0 0
  action permit
 rule name wild
  source-address 10.0.0.0 0.0.0.255
  action permit
 rule name unknown
  service netbios-session
  action permit
"""
    model, _ = parse(usg_text(policy, rest))
    assert verdict(model, "10.0.0.5", "10.0.1.5", dport=8005) and verdict(model, "10.0.0.5", "10.0.2.200", dport=9000)
    assert not verdict(model, "10.0.0.5", "10.0.1.200", dport=8005)
    assert verdict(model, "10.0.0.5", "10.0.1.5", proto="icmp")
    assert rule_named(model, "only-exclude").negate_source
    for name in ("nothing", "odd", "mac", "zero", "wild", "unknown"):
        assert rule_named(model, name).unsupported, name
    assert not verdict(model, "10.0.0.5", "8.8.8.8", dport=22)
    app, _ = parse(usg_text(" rule name app\n  application app WeChat\n  action permit\n"))
    assert rule_named(app, "app").applications == ["WeChat"]


def test_local_zone_rules() -> None:
    policy = """ rule name to-firewall
  source-zone trust
  destination-zone local
  action permit
 rule name both
  source-zone trust local
  destination-zone untrust
  action permit
"""
    model, report = parse(usg_text(policy))
    assert [r.name for r in model.rules if not r.name.startswith("intrazone")] == ["both"]
    assert rule_named(model, "both").src_zones == ["trust"]
    assert {"HUAWEI_LOCAL_RULE", "HUAWEI_LOCAL_ZONE"} <= codes(report)
    assert "local" not in model.zones


def test_nat_server_is_before_the_policy() -> None:
    policy = """ rule name to-web
  source-zone untrust
  destination-zone trust
  destination-address 10.0.0.10 32
  service protocol tcp destination-port 8080
  action permit
 rule name to-host
  source-zone untrust
  destination-zone trust
  destination-address 10.0.0.20 32
  action permit
"""
    rest = """nat server web zone untrust protocol tcp global 203.0.113.10 www inside 10.0.0.10 8080 no-reverse
nat server host global 203.0.113.20 inside 10.0.0.20
nat server ping protocol icmp global 203.0.113.30 inside 10.0.0.30
nat server odd protocol tcp global 203.0.113.40 80 inside 10.0.0.40
nat server standby global 203.0.113.50 inside 10.0.0.50 vrrp 1
"""
    model, report = parse(usg_text(policy) + rest)
    assert model.lookup_after_dnat
    # (a rule that names the inside port of a port translation: narrower, and said, as for every source)
    assert not verdict(model, "198.51.100.1", "203.0.113.10", ingress="untrust", egress="trust")
    assert "NAT_PORT_TRANSLATION" in {f.code for f in report.item("rule", "to-web").findings}
    assert not verdict(model, "198.51.100.1", "203.0.113.10", dport=443, ingress="untrust", egress="trust")
    assert verdict(model, "198.51.100.1", "203.0.113.20", dport=22, ingress="untrust", egress="trust")
    unsupported = {n.name for n in model.nat_rules if n.unsupported}
    assert unsupported == {"nat-server-odd", "nat-server-standby"}
    host = next(n for n in model.nat_rules if n.name == "nat-server-host")
    assert host.source_translation is not None and host.source_translation.bidirectional
    assert "HUAWEI_NAT_ORDER" in codes(report)


def test_nat_policy() -> None:
    rest = """nat address-group pool1 0
 mode pat
 section 0 203.0.113.20 203.0.113.22
#
nat address-group fixed 1
 mode no-pat local
 section 0 203.0.113.30 203.0.113.31
#
nat-policy
 rule name out
  source-zone trust
  egress-interface GigabitEthernet1/0/2
  source-address 10.0.0.0 mask 255.255.255.0
  action source-nat easy-ip
 rule name pooled
  source-zone trust
  destination-zone untrust
  action source-nat address-group pool1
 rule name fixed
  action source-nat address-group fixed
 rule name none
  destination-address 192.0.2.0 24
  action no-nat
 rule name missing
  action source-nat address-group nowhere
#
"""
    model, _ = parse(usg_text("", rest))
    by_name = {n.name: n for n in model.nat_rules}
    assert by_name["out"].dst_zones == ["untrust"] and by_name["out"].source_translation is not None
    assert by_name["pooled"].source_translation.kind.name == "DYNAMIC_PORT"
    assert by_name["fixed"].source_translation.kind.name == "DYNAMIC"
    assert by_name["none"].source_translation is None and not by_name["none"].unsupported
    assert by_name["missing"].unsupported


def test_emitter_zones_names_and_nat() -> None:
    model, _ = parse(usg_text(""" rule name web
  source-zone untrust
  destination-zone trust
  destination-address 10.0.0.10 32
  service protocol tcp destination-port 8080
  action permit
""") + "nat server web protocol tcp global 203.0.113.10 80 inside 10.0.0.10 8080 no-reverse\n")
    from fwshift.model import Zone

    model.zones["lab"] = Zone("lab", interfaces=["GE1/0/4"])
    model.zones["Lab Two"] = Zone("Lab Two")
    text, report = emit(model)
    assert "firewall zone name FWS_lab" in text and "firewall zone name FWS_Lab_Two" in text and " description Lab Two" in text
    priorities = [int(line.split()[-1]) for line in text.splitlines() if line.startswith(" set priority")]
    assert len(set(priorities)) == len(priorities) and not set(priorities) & {100, 85, 50, 5}
    assert "nat server FWS_srv protocol tcp global 203.0.113.10 80 inside 10.0.0.10 8080 no-reverse" in text
    assert "#   firewall zone name FWS_lab / add interface GE1/0/4" in text
    assert {"HUAWEI_LOAD", "HUAWEI_INTRAZONE"} <= codes(report)
    prefixed, _ = emit(model, Options(object_prefix="NEW-"))
    assert "rule name NEW-web" in prefixed
    with pytest.raises(FwshiftError):
        emit(model, Options(object_prefix="1bad"))


def test_emitter_defaults_and_rules_it_cannot_write() -> None:
    from fwshift.model import Action, Address, AddressKind, Protocol, Rule, RuleScope, Service, ServiceEntry, Zone

    model = zoned(random_model(random.Random(1)))
    model.rules = []
    model.addresses["web"] = Address("web", AddressKind.FQDN, "www.example.com")
    model.services["any-code"] = Service("any-code", [ServiceEntry(Protocol.ICMP, icmp_code=3)])
    model.rules.append(Rule("fqdn", destinations=["web"], action=Action.ALLOW))
    model.rules.append(Rule("negated", services=["web"], negate_service=True, action=Action.ALLOW))
    model.rules.append(Rule("code", services=["any-code"], action=Action.ALLOW))
    model.rules.append(Rule("inside", src_zones=["eth0", "eth1"], services=["web"], scope=RuleScope.INTRAZONE, action=Action.ALLOW))
    for rule in model.rules:
        rule.origin = rule.name
    model.default_interzone, model.default_intrazone = Action.ALLOW, Action.DENY
    model.zones["eth2"] = Zone("eth2", intrazone_allow=True)
    text, report = emit(model)
    for name in ("fqdn", "negated", "code"):
        assert report.item("rule", name).disabled, name
    assert "# Written disabled:" in text and text.count("  disable") == 3
    assert " default action permit" in text and {"HUAWEI_DEFAULT_PERMIT", "INTRAZONE_RULES_ADDED"} <= codes(report)
    assert "rule name FWS_intrazone_eth0" in text and "rule name FWS_intrazone_eth2" not in text
    assert text.count("rule name FWS_inside_") == 2
    # (a rule that decides all traffic inside a zone leaves nothing for a rule at the end)
    model.rules.append(Rule("all-inside", src_zones=["eth0"], scope=RuleScope.INTRAZONE, action=Action.ALLOW, origin="all-inside"))
    text, _ = emit(model)
    assert "rule name FWS_intrazone_eth0" not in text and "rule name FWS_intrazone_eth1" in text


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "huawei_sample.cfg").read_bytes()
    assert cli.detect_format(data) == "huawei"
    report = Report()
    model = cli.load(data, "huawei", report)
    assert len(model.rules) >= 10 and model.nat_rules and "lab" in model.zones
    for target in sorted(cli.EMITTERS):
        out = Report()
        cli.EMITTERS[target](model, out, Options())


# -- review round 37 ------------------------------------------------------------------------------------


def test_r37_commands_of_the_system_view_at_any_indent() -> None:
    text = "#\n sysname FW\n default packet-filter intrazone enable\n vsys enable\n#\n" + BASE.split("#\n", 3)[3]
    model, report = parse(text + "security-policy\n rule name a\n  source-zone trust\n  destination-zone untrust\n  action permit\n#\n")
    assert not verdict(model, "10.0.0.5", "10.0.0.9", ingress="trust", egress="trust")
    assert "HUAWEI_VSYS" in codes(report)


def test_r37_virtual_systems_are_not_merged_into_the_root() -> None:
    root = usg_text(" rule name root1\n  source-zone trust\n  destination-zone untrust\n  destination-address 10.1.1.0 24\n  action permit\n")
    vsys = "switch vsys vsysa\n#\nsecurity-policy\n rule name vsysa-all\n  source-zone trust\n  destination-zone untrust\n  action permit\n#\n"
    model, report = parse(root + vsys)
    assert [r.name for r in model.rules if r.name.startswith(("root", "vsys"))] == ["root1"]
    assert not verdict(model, "10.0.0.5", "192.0.2.1") and "HUAWEI_VSYS" in codes(report)
    with pytest.raises(ParseError, match="vsys"):
        parse(BASE + "interface GigabitEthernet1/0/5\n switch vsys vsysa\n#\n" + "security-policy\n#\n")


def test_r37_nat_server_only_for_what_it_can_say() -> None:
    from fwshift.model import ANY, Action, DestNat, NatRule, Protocol, Rule, Service, ServiceEntry

    def model_with(nat: NatRule) -> Any:
        model = zoned(random_model(random.Random(3)))
        model.rules = [Rule("in", src_zones=["eth0"], dst_zones=["eth1"], destinations=["203.0.113.10"], action=Action.ALLOW, origin="in")]
        model.services["web80"] = Service("web80", [ServiceEntry(Protocol.TCP, "80")])
        model.services["empty"] = Service("empty", [])
        nat.origin = nat.name
        model.nat_rules = [nat]
        return model

    def written(nat: NatRule) -> bool:
        text, _ = emit(model_with(nat))
        return "nat server" in text

    def base() -> Dict[str, Any]:
        return dict(destinations=["203.0.113.10"], destination_translation=DestNat("10.0.0.5"))

    assert written(NatRule("plain", **base()))
    assert written(NatRule("zone", src_zones=["eth0"], **base()))
    assert not written(NatRule("sources", sources=["198.51.100.0/24"], **base()))
    assert not written(NatRule("dst-zone", dst_zones=["eth1"], **base()))
    assert not written(NatRule("zones", src_zones=["eth0", "eth2"], **base()))
    assert not written(NatRule("nosuch", service="nosuch", **base()))
    assert not written(NatRule("empty", service="empty", **base()))
    text, _ = emit(model_with(NatRule("sources", sources=["198.51.100.0/24"], **base())))
    assert "10.0.0.5" not in text  # (the rule is not rewritten for a translation that is not written)
    exempt = model_with(NatRule("plain", **base()))
    exempt.nat_rules.insert(0, NatRule("none", destinations=[ANY], origin="none"))
    text, _ = emit(exempt)
    assert "nat server" not in text


def test_r37_rules_of_any_zone_name_the_zones_and_disabled_rules_match_nothing() -> None:
    from fwshift.model import Action, Address, AddressKind, Rule

    model = zoned(random_model(random.Random(4)))
    model.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    model.rules = [Rule("any-any", services=["web"], action=Action.ALLOW, origin="any-any"),
                   Rule("fqdn", sources=["site"], action=Action.ALLOW, origin="fqdn")]  # fmt: skip
    text, report = emit(model)
    body = text.split("rule name FWS_any-any", 1)[1].split("quit", 1)[0]
    assert body.count("source-zone") == 3 and body.count("destination-zone") == 3
    fqdn = text.split("rule name FWS_fqdn", 1)[1].split("quit", 1)[0].splitlines()
    assert fqdn[1].strip() == "disable" and "  source-address 0.0.0.0 32" in fqdn
    zoneless = random_model(random.Random(4))
    zoneless.rules = [Rule("open", action=Action.ALLOW, origin="open")]
    text, report = emit(zoneless)
    assert "source-zone" not in text and "HUAWEI_NO_ZONES" in codes(report)


def test_r37_exclusions_of_any_protocol_zero_and_an_all_ones_wildcard() -> None:
    rest = "ip address-set all type object\n address 0 10.0.0.0 255.255.255.255\n#\nip service-set zero type object\n service 0 protocol 0\n#\n"
    policy = """ rule name minus-any
  destination-address 10.0.0.0 mask 8
  destination-address-exclude any
  action permit
 rule name all
  source-address address-set all
  action permit
 rule name zero
  service zero
  action permit
"""
    model, _ = parse(usg_text(policy, rest))
    for name in ("minus-any", "all", "zero"):
        assert rule_named(model, name).unsupported, name
    from fwshift.model import Action, Protocol, Rule, Service, ServiceEntry

    out = zoned(random_model(random.Random(5)))
    out.services["p0"] = Service("p0", [ServiceEntry(Protocol.IP, ip_protocol=0)])
    out.rules = [Rule("p0", services=["p0"], action=Action.ALLOW, origin="p0")]
    text, report = emit(out)
    assert report.item("rule", "p0").disabled and "protocol 0" not in text


def test_r37_nested_sets_resolve_once() -> None:
    import time

    rest = ""
    for level in range(12):
        last = level == 11
        rest += f"ip address-set A{level} type group\n" + "".join(
            f" address {k} 10.0.{k}.0 mask 24\n" if last else f" address {k} address-set A{level + 1}\n" for k in range(10)) + "#\n"
        rest += f"ip service-set S{level} type group\n" + "".join(
            f" service {k} protocol tcp destination-port {k + 1}\n" if last else f" service {k} service-set S{level + 1}\n" for k in range(10)) + "#\n"
    started = time.monotonic()
    model, _ = parse(usg_text(" rule name r\n  destination-address address-set A0\n  service S0\n  action permit\n", rest))
    assert time.monotonic() - started < 5
    assert not rule_named(model, "r").unsupported and verdict(model, "10.0.0.1", "10.0.9.9", dport=10)


def test_r37_lines_outside_their_place() -> None:
    model, _ = parse(BASE + "security-policy\nrule name a\nsource-zone trust\ndestination-zone trust\naction deny\n#\nreturn\n")
    assert not verdict(model, "10.0.0.5", "10.0.0.9", ingress="trust", egress="trust")
    model, _ = parse(usg_text(" rule name a\n  source-zone trust\n  action permit\n#\n  source-address 10.0.0.1 32\n  destination-zone untrust\n"))
    assert not verdict(model, "10.0.0.5", "192.0.2.1")
    with pytest.raises(ParseError, match="outside"):
        parse(usg_text() + "rule name lost\n action permit\n")
    with pytest.raises(ParseError, match="interzone"):
        parse(BASE + "firewall interzone trust untrust\n packet-filter 3000 outbound\n#\n")


def test_r37_version_100_meets_the_default_policy_inside_a_zone() -> None:
    model, report = parse("!Software Version V100R001C10SPC200\n" + usg_text())
    assert not verdict(model, "10.0.0.5", "10.0.0.9", ingress="trust", egress="trust")
    assert "HUAWEI_V100" in codes(report)


def test_r37_the_parser_reads_what_the_emitter_writes() -> None:
    model, _ = parse((DATA / "huawei_sample.cfg").read_text())
    text, report = emit(model)
    again, _ = parse(text)
    written = [r for r in model.rules if not report.item("rule", r.origin).disabled and r.enabled]
    assert len(written) > 8
    assert not [r.name for r in again.rules if r.unsupported and r.enabled]


def test_r37_descriptions_and_names() -> None:
    from fwshift.model import Action, Rule, Zone

    model = zoned(random_model(random.Random(6)))
    model.zones["what?"] = Zone("what?")
    model.rules = [Rule("r", description='why?\n"quoted"', action=Action.ALLOW, origin="r"),
                   Rule("blank", description="  ", action=Action.DENY, origin="blank")]  # fmt: skip
    text, _ = emit(model)
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    assert "?" not in body and "  description why   quoted" in body and "\n  description \n" not in body


def test_r37_mutation_survivors() -> None:
    from fwshift.model import Action, DestNat, NatRule, Rule, SnatKind, SourceNat

    # nat server: the zone and the protocol it is limited to
    model, _ = parse(usg_text("", "nat server ping protocol icmp global 203.0.113.30 inside 10.0.0.30\n"
                              "nat server web zone untrust protocol tcp global 203.0.113.10 80 inside 10.0.0.10 8080 no-reverse\n"))
    by_name = {n.name: n for n in model.nat_rules}
    assert by_name["nat-server-web"].src_zones == ["untrust"]
    assert model.services[by_name["nat-server-ping"].service].entries[0].protocol.name == "ICMP"
    # a command of the system view printed with a space after a # line is not part of the block before it
    model, _ = parse(usg_text(" rule name r\n  destination-address address-set lan\n  action permit\n",
                              " ip address-set lan type object\n  address 0 10.0.5.0 mask 24\n#\n"))
    assert not rule_named(model, "r").unsupported and verdict(model, "10.0.0.5", "10.0.5.9")
    # a rule without an action
    model, _ = parse(usg_text(" rule name r\n  source-zone trust\n"))
    assert rule_named(model, "r").unsupported
    # emitted rules name the inside address of a nat server written; not of one that is not
    base = zoned(random_model(random.Random(7)))
    base.rules = [Rule("in", src_zones=["eth0"], dst_zones=["eth1"], destinations=["203.0.113.10", "203.0.113.20/31"], action=Action.ALLOW,
                       origin="in")]  # fmt: skip
    base.nat_rules = [NatRule("x-1", destinations=["203.0.113.10"], destination_translation=DestNat("10.0.0.5"), origin="x"),
                      NatRule("x-2", destinations=["203.0.113.20/31"], destination_translation=DestNat("10.0.0.20/31"), origin="x")]  # fmt: skip
    text, _ = emit(base)
    assert "nat server" in text and "10.0.0.20" not in text  # (an origin rewritten for all its rules, or for none)
    base.nat_rules = base.nat_rules[:1]
    base.nat_rules[0].origin = "x-1"
    text, _ = emit(base)
    assert "destination-address 10.0.0.5 32" in text and "203.0.113.10 32" not in text.split("security-policy")[1]
    base.nat_rules = [NatRule("both", src_zones=["eth0"], sources=["10.0.0.5"], origin="both",
                              source_translation=SourceNat(SnatKind.STATIC, ["203.0.113.10"], bidirectional=True))]  # fmt: skip
    text, _ = emit(base)
    assert "nat server" not in text  # (a static translation both ways cannot be limited to a zone)
