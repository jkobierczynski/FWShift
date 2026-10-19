# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco IOS and IOS XE: parser, emitter, and packet-level equivalence with a judge of its own.

A random router is a plain description (interfaces, access lists, object groups, the zone-based firewall, NAT) that
``render`` writes as ``show running-config`` and ``IosJudge`` decides packets from, as IOS does: the inbound list of
the interface a packet arrives on, NAT, the outbound list of the interface it leaves by, then the zone-based firewall
of the two zones. ``read_router`` reads the configuration the emitter writes back into such a description, so the
same judge decides the output. None of it shares code with the parser or the emitter.
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
from fwshift.errors import ParseError
from fwshift.parsers import ios as parse_ios
from fwshift.report import Report

TCP_NAMES = {"www": 80, "domain": 53, "smtp": 25, "telnet": 23, "ftp": 21, "bgp": 179, "pop3": 110}
UDP_NAMES = {"domain": 53, "snmp": 161, "ntp": 123, "syslog": 514, "tftp": 69}
ICMP_NAMES = {"echo": (8, None), "echo-reply": (0, None), "unreachable": (3, None), "time-exceeded": (11, None), "port-unreachable": (3, 3)}
ICMP6_NAMES = {"echo-request": (128, None), "echo-reply": (129, None), "packet-too-big": (2, None)}
PROTO_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "gre": 47, "esp": 50, "sctp": 132}
PAM = {"http": [("tcp", 80, 80)], "https": [("tcp", 443, 443)], "dns": [("tcp", 53, 53), ("udp", 53, 53)], "ssh": [("tcp", 22, 22)],
       "tcp": [("tcp", 0, 65535)], "udp": [("udp", 0, 65535)], "icmp": [("icmp", 0, 255), ("icmp6", 0, 255)], "smtp": [("tcp", 25, 25)]}  # fmt: skip


def addr(text: str) -> Any:
    return ipaddress.ip_address(text)


# -- the judge -------------------------------------------------------------------------------------


def address_matches(spec: Any, address: Any, groups: Dict[str, Any]) -> bool:
    kind = spec[0]
    if kind == "any":
        return True
    if kind == "host":
        return address == addr(spec[1])
    if kind == "net":  # (IPv4 address, wildcard) or an IPv6 prefix
        if address.version == 4:
            base, wild = int(addr(spec[1])), int(addr(spec[2]))
            return address.version == 4 and int(address) & ~wild & 0xFFFFFFFF == base & ~wild & 0xFFFFFFFF
        return address in ipaddress.ip_network(spec[1])
    if kind == "group":
        return any(address in ipaddress.ip_network(member, strict=False) for member in groups[spec[1]])
    raise AssertionError(spec)


def port_matches(op: Any, port: int) -> bool:
    if op is None:
        return True
    kind, values = op
    if kind == "eq":
        return port in values
    if kind == "neq":
        return port not in values
    if kind == "lt":
        return port < values[0]
    if kind == "gt":
        return port > values[0]
    return values[0] <= port <= values[1]


def entry_matches(entry: Dict[str, Any], pkt: Packet, groups: Dict[str, Any], v6: bool) -> bool:
    if entry.get("evaluate"):
        return False  # (the replies of reflected connections only)
    src, dst = addr(pkt.src), addr(pkt.dst)
    if (src.version == 6) != v6:
        return False
    proto = entry["proto"]
    if proto not in ("ip", "ipv6"):
        wanted = proto if isinstance(proto, int) else {"icmp": 58 if v6 else 1}.get(proto, PROTO_NUMBERS.get(proto))
        if PROTO_NUMBERS.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1) != wanted:
            return False
    if not address_matches(entry["src"], src, groups) or not address_matches(entry.get("dst", ("any",)), dst, groups):
        return False
    if proto in ("tcp", "udp"):
        if not port_matches(entry.get("sport"), pkt.sport) or not port_matches(entry.get("dport"), pkt.dport):
            return False
        if entry.get("established"):
            return False  # (a packet that opens a connection has no ACK)
    if proto == "icmp" and entry.get("icmp") is not None and entry["icmp"][0] != pkt.icmp_type:
        return False
    return True


def acl_permits(acl: Optional[Dict[str, Any]], pkt: Packet, groups: Dict[str, Any]) -> bool:
    """First match; an undefined list, or one without entries, permits everything; then the implicit deny."""
    if acl is None or not acl["entries"]:
        return True
    for entry in acl["entries"]:
        if entry_matches(entry, pkt, groups, acl["kind"] == "ipv6"):
            return entry["action"] == "permit"
    return False


def acl_matches(acl: Optional[Dict[str, Any]], pkt: Packet, groups: Dict[str, Any]) -> bool:
    """For a class map: whether an entry permits the packet (deny and no match alike: not this class)."""
    if acl is None:
        return False
    for entry in acl["entries"]:
        if entry_matches(entry, pkt, groups, acl["kind"] == "ipv6"):
            return entry["action"] == "permit"
    return False


class IosJudge:
    def __init__(self, router: Dict[str, Any]) -> None:
        self.r = router
        self.by_name = {i["name"]: i for i in router["interfaces"]}

    def acl(self, interface: Dict[str, Any], direction: str, version: int) -> Optional[Dict[str, Any]]:
        name = interface.get(f"{direction}{version}")
        if not name:
            return None
        acl = self.r["acls"].get(name)
        if acl is None or (acl["kind"] == "ipv6") != (version == 6):
            return None
        return acl

    def class_matches(self, name: str, pkt: Packet) -> bool:
        match_all, criteria = self.r["classes"][name]
        results = []
        for kind, value in criteria:
            if kind == "acl":
                results.append(acl_matches(self.r["acls"].get(value), pkt, self.r["groups"]))
            elif kind == "protocol":
                ok = False
                for proto, low, high in PAM[value]:
                    if proto in ("icmp", "icmp6"):
                        ok = ok or pkt.proto == proto
                    else:
                        ok = ok or (pkt.proto == proto and low <= pkt.dport <= high)
                results.append(ok)
            else:
                results.append(self.class_matches(value, pkt))
        return all(results) if match_all else any(results)

    def zbfw(self, a: Dict[str, Any], b: Dict[str, Any], pkt: Packet) -> bool:
        if not any(i.get("zone") for i in self.r["interfaces"]):
            return True
        za, zb = a.get("zone"), b.get("zone")
        if not za and not zb:
            return True
        if not za or not zb:
            return False
        pair = self.r["pairs"].get(f"{za}>{zb}")
        if pair is None:
            return za == zb
        for target, action in self.r["policies"][pair]:
            if target == "class-default" or self.class_matches(target, pkt):
                return action in ("inspect", "pass")
        return False

    def nat_role(self, interface: Dict[str, Any]) -> str:
        return interface.get("nat") or ""

    def allows(self, pkt: Packet, ingress: str, egress: str) -> Optional[bool]:
        a, b = self.by_name[ingress], self.by_name[egress]
        version = addr(pkt.src).version
        groups = self.r["groups"]
        statics = self.r.get("statics", [])
        ports = self.r.get("port_statics", [])
        globals_ = {g for _, g in statics} | {p[3] for p in ports}
        if self.nat_role(a) != "outside" and pkt.dst in globals_:
            return None  # (to an outside address of NAT from inside: not judged)
        if not acl_permits(self.acl(a, "in", version), pkt, groups):
            return False
        after = Packet(pkt.in_if, pkt.out_if, pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        inside_view = Packet(pkt.in_if, pkt.out_if, pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)
        if version == 4 and self.nat_role(a) == "outside" and self.nat_role(b) == "inside":
            for local, global_ in statics:
                if pkt.dst == global_:
                    after.dst = inside_view.dst = local
            for proto, local, lport, global_, gport in ports:
                if pkt.dst == global_ and pkt.proto == proto and pkt.dport == gport:
                    after.dst, after.dport = local, lport
                    inside_view.dst, inside_view.dport = local, lport
        elif version == 4 and self.nat_role(a) == "inside" and self.nat_role(b) == "outside":
            translated = False
            for proto, local, lport, global_, gport in ports:
                if pkt.src == local and pkt.proto == proto and pkt.sport == lport:
                    return None  # (the source port of a port translation: not judged)
            for local, global_ in statics:
                if pkt.src == local:
                    after.src = global_
                    translated = True
            pat = self.r.get("pat")
            if not translated and pat:
                acl = self.r["acls"].get(pat["acl"])
                if acl is not None and acl_permits(acl, Packet("", "", pkt.src, "0.0.0.0", "ip"), groups) and acl["entries"]:
                    out_acl = self.acl(b, "out", 4)
                    if out_acl is not None and any(e.get("sport") for e in out_acl["entries"]):
                        return None  # (port translation changes the source port)
                    after.src = pat["address"]
        if not acl_permits(self.acl(b, "out", version), after, groups):
            return False
        return self.zbfw(a, b, inside_view)


# -- random routers ----------------------------------------------------------------------------------


NETS4 = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "192.0.2.0/24"]
NETS6 = ["2001:db8:0::/64", "2001:db8:1::/64", "2001:db8:2::/64", "2001:db8:9::/64"]
OUTSIDE4 = ["198.51.100.7", "203.0.113.9", "198.51.100.200"]
OUTSIDE6 = ["2001:db8:ff::7"]


def random_address(rng: random.Random, v6: bool, groups: Dict[str, Any]) -> Any:
    roll = rng.random()
    if roll < 0.3:
        return ("any",)
    if roll < 0.55:
        if v6:
            return ("host", f"2001:db8:{rng.randrange(3)}::{rng.choice([5, 9, 0x10])}")
        return ("host", rng.choice([f"10.0.{rng.randrange(3)}.{rng.choice([5, 9, 16, 130])}", rng.choice(OUTSIDE4),
                                    rng.choice(["203.0.113.2", "203.0.113.20"])]))
    if roll < 0.85 or not groups:
        if v6:
            return ("net", rng.choice(NETS6 + ["2001:db8::/32", "2001:db8:1::/80"]))
        base, wild = rng.choice([("10.0.0.0", "0.0.0.255"), ("10.0.1.0", "0.0.0.127"), ("10.0.0.0", "0.0.255.255"), ("0.0.0.0", "255.255.255.255"),
                                 ("10.0.1.77", "0.0.0.255"),
                                 ("198.51.100.0", "0.0.0.255"), ("10.0.0.0", "0.0.254.255"), ("10.0.0.128", "0.0.1.127"),
                                 ("192.0.2.0", "0.0.0.63")])  # fmt: skip
        return ("net", base, wild)
    names = [n for n, members in groups.items() if (":" in members[0]) == v6]
    return ("group", rng.choice(names)) if names else ("any",)


def random_ports(rng: random.Random, proto: str = "tcp") -> Any:
    roll = rng.random()
    if roll < 0.45:
        return ("eq", rng.sample([22, 25, 53, 80, 443, 8080, 3000] if proto == "tcp" else [53, 69, 123, 161, 514], rng.randint(1, 2)))
    if roll < 0.6:
        return ("range", sorted(rng.sample([20, 80, 1024, 8000, 8100, 65535], 2)))
    if roll < 0.75:
        return ("gt", [rng.choice([1023, 8000])])
    if roll < 0.9:
        return ("lt", [rng.choice([1024, 81])])
    return ("neq", [rng.choice([80, 22])])


def random_entry(rng: random.Random, v6: bool, standard: bool, groups: Dict[str, Any]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"action": "permit" if rng.random() < 0.6 else "deny"}
    if standard:
        entry.update(proto="ip", src=random_address(rng, False, {}))
        if entry["src"][0] == "group":
            entry["src"] = ("any",)
        return entry
    entry["proto"] = rng.choice(["ip", "tcp", "tcp", "udp", "icmp", "gre" if not v6 else "esp", 47 if not v6 else "tcp"])
    if v6 and entry["proto"] == "ip":
        entry["proto"] = "ipv6"
    entry["src"] = random_address(rng, v6, groups)
    entry["dst"] = random_address(rng, v6, groups)
    if entry["proto"] in ("tcp", "udp"):
        if rng.random() < 0.6:
            entry["dport"] = random_ports(rng, entry["proto"])
        if rng.random() < 0.15:
            entry["sport"] = ("gt", [1023])
        if entry["proto"] == "tcp" and entry["action"] == "permit" and rng.random() < 0.06:
            entry["established"] = True
    if entry["proto"] == "icmp" and rng.random() < 0.6:
        entry["icmp"] = rng.choice(list(ICMP6_NAMES.values()) if v6 else list(ICMP_NAMES.values()))
    entry["log"] = rng.random() < 0.2
    return entry


def random_router(rng: random.Random, zbfw: Optional[bool] = None, nat: Optional[bool] = None) -> Dict[str, Any]:
    groups: Dict[str, List[str]] = {}
    if rng.random() < 0.5:
        groups["G4"] = rng.sample(["10.0.0.5/32", "10.0.1.0/25", "198.51.100.0/24", "10.0.2.16/28"], 2)
        groups["G6"] = rng.sample(["2001:db8:1::/64", "2001:db8:2::9/128"], 1)
    acls: Dict[str, Dict[str, Any]] = {}
    names: List[str] = []
    for index in range(rng.randint(1, 4)):
        kind = rng.choice(["extended", "extended", "standard", "ipv6"])
        numbered = kind != "ipv6" and rng.random() < 0.3
        name = (str(10 + index) if kind == "standard" else str(110 + index)) if numbered else f"ACL-{kind[:3].upper()}-{index}"
        entries = [random_entry(rng, kind == "ipv6", kind == "standard", groups) for _ in range(rng.randint(0 if rng.random() < 0.1 else 1, 6))]
        if not numbered and kind != "standard" and rng.random() < 0.15:
            entries.insert(rng.randint(0, len(entries)), {"action": "permit", "evaluate": True})
        acls[name] = {"kind": kind, "entries": entries}
        names.append(name)
    interfaces = []
    count = rng.randint(2, 4)
    use_zbfw = zbfw if zbfw is not None else rng.random() < 0.35
    use_nat = nat if nat is not None else rng.random() < 0.35
    zones = ["inside", "outside", "dmz"][: rng.randint(1, 3)] if use_zbfw else []
    for index in range(count):
        interface: Dict[str, Any] = {"name": f"GigabitEthernet0/{index}", "v4": f"10.0.{index}.1/24",
                                     "v6": f"2001:db8:{index}::1/64" if rng.random() < 0.6 else None}  # fmt: skip
        if index == count - 1 and use_nat:
            interface["v4"] = "203.0.113.2/24"
        for direction in ("in", "out"):
            for version in (4, 6):
                if rng.random() < (0.45 if direction == "in" else 0.25):
                    pool = [n for n in names if (acls[n]["kind"] == "ipv6") == (version == 6)]
                    if pool:
                        interface[f"{direction}{version}"] = rng.choice(pool + (["MISSING"] if rng.random() < 0.05 else []))
        if use_zbfw and rng.random() < 0.85:
            interface["zone"] = rng.choice(zones)
        if use_nat:
            interface["nat"] = "outside" if index == count - 1 else "inside"
        interfaces.append(interface)
    router: Dict[str, Any] = {"interfaces": interfaces, "acls": acls, "groups": groups, "classes": {}, "policies": {}, "pairs": {},
                              "zones": zones, "statics": [], "port_statics": []}  # fmt: skip
    if use_zbfw:
        extended = [n for n in names if acls[n]["kind"] in ("extended", "ipv6")]
        for index in range(rng.randint(1, 4)):
            criteria: List[Tuple[str, str]] = []
            for _ in range(rng.randint(1, 2)):
                if extended and rng.random() < 0.6:
                    criteria.append(("acl", rng.choice(extended)))
                else:
                    criteria.append(("protocol", rng.choice(list(PAM))))
            if index and rng.random() < 0.3:
                criteria.append(("class", f"CM-{rng.randrange(index)}"))
            router["classes"][f"CM-{index}"] = (rng.random() < 0.5, criteria)
        for index in range(rng.randint(1, 3)):
            classes = [(c, rng.choice(["inspect", "inspect", "drop", "pass"])) for c in rng.sample(list(router["classes"]), rng.randint(1, len(router["classes"])))]
            classes.append(("class-default", rng.choice(["drop", "drop", "pass"])))
            router["policies"][f"PM-{index}"] = classes
        for source in zones:
            for destination in zones:
                if rng.random() < (0.7 if source != destination else 0.3):
                    router["pairs"][f"{source}>{destination}"] = rng.choice(list(router["policies"]))
    if use_nat:
        router["statics"] = [("10.0.0.9", "203.0.113.20")] if rng.random() < 0.7 else []
        if rng.random() < 0.5:
            router["port_statics"] = [("tcp", "10.0.1.16", 80, "203.0.113.2", 8080)]
        if rng.random() < 0.6:
            acls["NAT"] = {"kind": "standard", "entries": [{"action": "deny", "proto": "ip", "src": ("host", "10.0.0.5")},
                                                          {"action": "permit", "proto": "ip", "src": ("net", "10.0.0.0", "0.0.255.255")}]}  # fmt: skip
            router["pat"] = {"acl": "NAT", "interface": interfaces[-1]["name"], "address": "203.0.113.2"}
    return router


def address_text(spec: Any, v6: bool) -> str:
    kind = spec[0]
    if kind == "any":
        return "any"
    if kind == "host":
        return f"host {spec[1]}"
    if kind == "group":
        return f"object-group {spec[1]}"
    return spec[1] if v6 else f"{spec[1]} {spec[2]}"


def ports_text(op: Any, proto: str, rng: random.Random) -> str:
    if op is None:
        return ""
    names = {v: k for k, v in (TCP_NAMES if proto == "tcp" else UDP_NAMES).items()}
    values = [names[v] if v in names and rng.random() < 0.5 else str(v) for v in op[1]]
    return f" {op[0]} {' '.join(values)}"


def entry_text(entry: Dict[str, Any], kind: str, rng: random.Random) -> str:
    if entry.get("evaluate"):
        return "evaluate REFL"
    action = entry["action"] if rng.random() < 0.7 or entry["action"] == "permit" else "deny  "
    if kind == "standard":
        spec = entry["src"]
        text = "any" if spec[0] == "any" else spec[1] if spec[0] == "host" and rng.random() < 0.5 else address_text(spec, False)
        return f"{action} {text}" + (" log" if entry.get("log") else "")
    v6 = kind == "ipv6"
    proto = entry["proto"]
    text = f"{action} {proto} {address_text(entry['src'], v6)}{ports_text(entry.get('sport'), str(proto), rng)} "
    text += f"{address_text(entry['dst'], v6)}{ports_text(entry.get('dport'), str(proto), rng)}"
    if entry.get("icmp") is not None:
        table = ICMP6_NAMES if v6 else ICMP_NAMES
        names = [n for n, v in table.items() if v == tuple(entry["icmp"])]
        text += f" {names[0]}" if names and rng.random() < 0.5 else f" {entry['icmp'][0]}" + (f" {entry['icmp'][1]}" if entry["icmp"][1] is not None else "")
    if entry.get("established"):
        text += " established"
    if entry.get("log"):
        text += rng.choice([" log", " log-input"])
    return text


def render(router: Dict[str, Any], rng: random.Random) -> str:
    xe = rng.random() < 0.5
    out = ["Building configuration...", "", "Current configuration : 4242 bytes", "!", "version " + ("17.9" if xe else "15.4"), "hostname r1", "!"]
    for name, members in router["groups"].items():
        out.append(f"object-group {'v6-network' if ':' in members[0] else 'network'} {name}")
        for member in members:
            net = ipaddress.ip_network(member)
            if net.num_addresses == 1:
                out.append(f" host {net.network_address}")
            elif net.version == 4:
                out.append(f" {net.network_address} {net.netmask}")
            else:
                out.append(f" {net}")
        out.append("!")
    for zone in router["zones"]:
        out += [f"zone security {zone}", f" description zone {zone}"]
    for name, (match_all, criteria) in router["classes"].items():
        out.append(f"class-map type inspect {'match-all' if match_all else 'match-any'} {name}")
        for kind, value in criteria:
            out.append(f" match access-group name {value}" if kind == "acl" else f" match protocol {value}" if kind == "protocol" else f" match class-map {value}")
    for name, classes in router["policies"].items():
        out.append(f"policy-map type inspect {name}")
        for target, action in classes:
            out.append(" class class-default" if target == "class-default" else f" class type inspect {target}")
            out.append(f"  {action}")
    for index, (pair, policy) in enumerate(router["pairs"].items()):
        source, destination = pair.split(">")
        out += [f"zone-pair security ZP-{index} source {source} destination {destination}", f" service-policy type inspect {policy}"]
    for interface in router["interfaces"]:
        out.append(f"interface {interface['name']}")
        net = ipaddress.ip_interface(interface["v4"])
        out.append(f" ip address {net.ip} {net.netmask}")
        if interface.get("v6"):
            out.append(f" ipv6 address {interface['v6']}")
        for direction in ("in", "out"):
            if interface.get(f"{direction}4"):
                out.append(f" ip access-group {interface[f'{direction}4']} {direction}")
            if interface.get(f"{direction}6"):
                out.append(f" ipv6 traffic-filter {interface[f'{direction}6']} {direction}")
        if interface.get("nat"):
            out.append(f" ip nat {interface['nat']}")
        if interface.get("zone"):
            out.append(f" zone-member security {interface['zone']}")
        out.append("!")
    out += ["interface Loopback0", " ip address 10.255.255.1 255.255.255.255", "!"]
    for local, global_ in router.get("statics", []):
        out.append(f"ip nat inside source static {local} {global_}")
    for proto, local, lport, global_, gport in router.get("port_statics", []):
        out.append(f"ip nat inside source static {proto} {local} {lport} {global_} {gport} extendable")
    if router.get("pat"):
        out.append(f"ip nat inside source list {router['pat']['acl']} interface {router['pat']['interface']} overload")
    for name, acl in router["acls"].items():
        numbered = name.isdigit()
        if numbered and not xe:
            for entry in acl["entries"]:
                out.append(f"access-list {name} {entry_text(entry, acl['kind'], rng)}")
            continue
        out.append(f"ipv6 access-list {name}" if acl["kind"] == "ipv6" else f"ip access-list {acl['kind']} {name}")
        for index, entry in enumerate(acl["entries"], 1):
            if rng.random() < 0.15:
                out.append((f" {index * 10} " if xe and acl["kind"] != "ipv6" else " ") + "remark a remark")
            text = entry_text(entry, acl["kind"], rng)
            if acl["kind"] == "ipv6":
                out.append(f" sequence {index * 10} {text}" if xe else f" {text}" + (f" sequence {index * 10}" if rng.random() < 0.3 else ""))
            else:
                out.append(f" {index * 10} {text}" if xe else f" {text}")
        out.append("!")
    out.append("end")
    return "\n".join(out) + "\n"


def addresses_of(router: Dict[str, Any]) -> List[str]:
    out = list(OUTSIDE4) + list(OUTSIDE6) + ["10.0.0.5", "10.0.0.9", "10.0.1.16", "10.0.1.130", "10.0.2.16", "10.0.3.9", "192.0.2.7",
                                             "10.0.2.5", "10.0.4.5", "2001:db8:1::5", "2001:db8:2::9", "2001:db8::10", "2001:db8:1:0:1::5"]  # fmt: skip
    out += [g for _, g in router.get("statics", [])] + [p[3] for p in router.get("port_statics", [])]
    return out


def ios_packet(rng: random.Random, pool: List[str], router: Dict[str, Any]) -> Optional[Tuple[Packet, str, str]]:
    src, dst = rng.choice(pool), rng.choice(pool)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    six = ":" in src
    proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if six else "icmp", "47", "50" if six else "gre"])
    if proto == "gre":
        proto = "47"
    ports = [22, 25, 53, 80, 443, 8080, 3000, 8050, 69, 123, 161, 514, 79, 81, 1023, 1024, 7999, 8000, 8100, 8101, 65535, 0, 20]
    pkt = Packet("", "", src, dst, proto, rng.choice([1023, 1024, 40000, 53, 80]), rng.choice(ports), rng.choice([0, 8, 3, 11, 128, 129]))
    names = [i["name"] for i in router["interfaces"]]
    return pkt, rng.choice(names), rng.choice(names)


def unit_of(model: Any) -> Dict[str, str]:
    return {interface: zone.name for zone in model.zones.values() for interface in zone.interfaces}


def judged(router: Dict[str, Any], model: Any, rng: random.Random, seed: int, packets: int = 300) -> int:
    judge = IosJudge(router)
    units = unit_of(model)
    pool = addresses_of(router)
    count = 0
    for _ in range(packets):
        found = ios_packet(rng, pool, router)
        if found is None:
            continue
        pkt, ingress, egress = found
        verdict = judge.allows(pkt, ingress, egress)
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = units[ingress], units[egress]
        count += 1
        assert model_allows(model, pkt) == verdict, (seed, pkt, ingress, egress, json.dumps(router, indent=1, default=str))
    return count


def parse(text: str) -> Tuple[Any, Report]:
    report = Report()
    return parse_ios.parse(text.encode(), report), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


@pytest.mark.parametrize("kind", ["acl", "zbfw", "nat", "mixed"])
def test_parsed_router_decides_like_the_judge(kind: str) -> None:
    compared = 0
    offset = {"acl": 0, "zbfw": 1000, "nat": 2000, "mixed": 3000}[kind]
    for seed in range(offset, offset + 120):
        rng = random.Random(seed)
        router = random_router(rng, zbfw={"acl": False, "zbfw": True, "nat": False}.get(kind), nat={"acl": False, "zbfw": False, "nat": True}.get(kind))
        text = render(router, rng)
        assert cli.detect_format(text.encode()) == "ios", text
        model, _ = parse(text)
        compared += judged(router, model, rng, seed)
    assert compared > 15000


# -- the emitted configuration, read back --------------------------------------------------------------


def _address_spec(words: List[str], index: int, v6: bool) -> Tuple[Any, int]:
    word = words[index]
    if word == "any":
        return ("any",), index + 1
    if word == "host":
        return ("host", words[index + 1]), index + 2
    if word == "object-group":
        return ("group", words[index + 1]), index + 2
    if v6:
        assert "/" in word, words
        return ("net", word), index + 1
    ipaddress.ip_address(words[index + 1])
    return ("net", word, words[index + 1]), index + 2


def _port_op(words: List[str], index: int) -> Tuple[Any, int]:
    if index >= len(words) or words[index] not in ("eq", "lt", "gt", "range", "neq"):
        return None, index
    if words[index] == "range":
        return ("range", [int(words[index + 1]), int(words[index + 2])]), index + 3
    return (words[index], [int(words[index + 1])]), index + 2


def read_entry(text: str, v6: bool) -> Dict[str, Any]:
    """A strict reader of an entry the emitter writes."""
    words = text.split()
    entry: Dict[str, Any] = {"action": words[0]}
    assert words[0] in ("permit", "deny"), text
    proto = words[1]
    entry["proto"] = int(proto) if proto.isdigit() else proto
    assert proto in ("ip", "ipv6", "tcp", "udp", "icmp") or proto.isdigit(), text
    entry["src"], index = _address_spec(words, 2, v6)
    entry["sport"], index = _port_op(words, index)
    entry["dst"], index = _address_spec(words, index, v6)
    entry["dport"], index = _port_op(words, index)
    if proto == "icmp" and index < len(words) and words[index].isdigit():
        code = int(words[index + 1]) if index + 1 < len(words) and words[index + 1].isdigit() else None
        entry["icmp"] = (int(words[index]), code)
        index += 2 if code is not None else 1
    assert index == len(words), text
    return entry


def read_router(text: str, zones: List[str]) -> Dict[str, Any]:
    """The configuration the emitter writes, as a random router: each zone with one interface of its own name."""
    router: Dict[str, Any] = {"interfaces": [], "acls": {}, "groups": {}, "classes": {}, "policies": {}, "pairs": {}, "zones": []}
    current: Optional[Tuple[str, Any]] = None
    pair_name = ""
    pairs: Dict[str, Tuple[str, str]] = {}
    described: Dict[str, str] = {}  # zone written -> the zone of the model it stands for
    for line in text.splitlines():
        if not line or line.startswith("!") or line == "end":
            continue
        assert len(line) < 4000 and line.isprintable(), line
        if not line.startswith(" "):
            words = line.split()
            current = None
            if words[:2] == ["object-group", "network"]:
                router["groups"][words[2]] = []
                current = ("group", words[2])
            elif words[:3] == ["ip", "access-list", "extended"] or words[:2] == ["ipv6", "access-list"]:
                name = words[-1]
                assert name not in router["acls"], name
                router["acls"][name] = {"kind": "ipv6" if words[0] == "ipv6" else "extended", "entries": []}
                current = ("acl", name)
            elif words[:3] == ["class-map", "type", "inspect"]:
                assert words[3] in ("match-any", "match-all")
                router["classes"][words[4]] = (words[3] == "match-all", [])
                current = ("class", words[4])
            elif words[:3] == ["policy-map", "type", "inspect"]:
                router["policies"][words[3]] = []
                current = ("policy", words[3])
            elif words[:2] == ["zone", "security"]:
                router["zones"].append(words[2])
                current = ("zone", words[2])
                described[words[2]] = words[2]
            elif words[:2] == ["zone-pair", "security"]:
                assert words[3] == "source" and words[5] == "destination", line
                pair_name = words[2]
                pairs[pair_name] = (words[4], words[6])
                current = ("pair", pair_name)
            else:
                raise AssertionError(f"not expected: {line}")
            continue
        assert current is not None, line
        kind, name = current
        words = line.split()
        if kind == "group":
            if words[0] == "host":
                router["groups"][name].append(words[1] + "/32")
            elif words[0] == "range":
                first, last = addr(words[1]), addr(words[2])
                router["groups"][name] += [str(n) for n in ipaddress.summarize_address_range(first, last)]
            else:
                router["groups"][name].append(str(ipaddress.ip_network(f"{words[0]}/{words[1]}")))
        elif kind == "acl":
            router["acls"][name]["entries"].append(read_entry(line.strip(), router["acls"][name]["kind"] == "ipv6"))
        elif kind == "class":
            assert words[:3] == ["match", "access-group", "name"], line
            router["classes"][name][1].append(("acl", words[3]))
        elif kind == "policy":
            if line.startswith("  "):
                assert words[0] in ("inspect", "pass", "drop") and words[1:] in ([], ["log"]), line
                target = router["policies"][name][-1][0]
                router["policies"][name][-1] = (target, words[0])
            elif words[:3] == ["class", "type", "inspect"]:
                router["policies"][name].append((words[3], ""))
            else:
                assert words == ["class", "class-default"], line
                router["policies"][name].append(("class-default", ""))
        elif kind == "pair":
            assert words[:3] == ["service-policy", "type", "inspect"], line
            source, destination = pairs[name]
            router["pairs"][f"{source}>{destination}"] = words[3]
        elif kind == "zone":
            assert words[0] == "description", line
            described[name] = line.strip().split(" ", 1)[1]
    written = {model_zone: zone for zone, model_zone in described.items()}
    for zone in zones:
        router["interfaces"].append({"name": zone, "zone": written.get(zone)})
    for policy in router["policies"].values():
        assert policy and policy[-1][0] == "class-default" and all(action for _, action in policy), policy
        for target, _ in policy:
            assert target == "class-default" or target in router["classes"], target
    for _, criteria in router["classes"].values():
        assert all(value in router["acls"] for _, value in criteria)
    for acl in router["acls"].values():
        for entry in acl["entries"]:
            for side in ("src", "dst"):
                assert entry[side][0] != "group" or entry[side][1] in router["groups"]
    return router


NARROWER = {"RULE_TYPE"}  # (pass lets the first packet through, which is what the judge decides)


def compare(model: Any, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    from test_iptables import ZONES, random_packet

    import copy

    router = read_router(text, ZONES)
    judge = IosJudge(router)
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (not written, and said)
    found = {f.code for item in report.items.values() for f in item.findings}
    exact = not found & NARROWER
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.1:
            pkt.proto = "50"
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 0, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        verdict = judge.allows(pkt, pkt.in_if, pkt.out_if)
        assert verdict is not None
        wanted = model_allows(model, pkt)
        assert verdict <= wanted, (seed, pkt, text)
        if exact:
            assert verdict == wanted, (seed, pkt, text)
        count += 1
    return count


def zoned(model: Any) -> Any:
    from fwshift.model import Zone
    from test_iptables import ZONES

    for zone in ZONES:
        model.zones.setdefault(zone, Zone(zone))
    return model


@pytest.mark.parametrize("seed", range(40))
def test_emitted_configuration_decides_like_the_model(seed: int) -> None:
    from fwshift.emitters import ios as emit_ios
    from fwshift.options import Options

    rng = random.Random(seed)
    model = zoned(random_model(rng))
    report = Report()
    text = emit_ios.emit(model, report, Options())
    assert compare(model, report, text, rng, seed) == 400


# -- what is read, and what is not ----------------------------------------------------------------------

BASE = """version 15.4
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
{in0}
interface GigabitEthernet0/1
 ip address 192.0.2.1 255.255.255.0
{in1}
"""


def router_text(in0: str = "", in1: str = "", rest: str = "") -> str:
    return BASE.format(in0=in0, in1=in1) + rest


def rules_of(model: Any, prefix: str) -> List[Any]:
    return [r for r in model.rules if r.name.startswith(prefix)]


def verdict(model: Any, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "GigabitEthernet0/0",
            egress: str = "GigabitEthernet0/1", sport: int = 40000) -> bool:  # fmt: skip
    units = unit_of(model)
    return model_allows(model, Packet(units[ingress], units[egress], src, dst, proto, sport, dport, 8))


def test_detection_and_errors() -> None:
    text = router_text(" ip access-group A in", rest="ip access-list extended A\n permit ip any any\n")
    assert cli.detect_format(text.encode()) == "ios"
    assert cli.detect_format((DATA / "asa_sample.cfg").read_bytes()) == "asa"
    assert cli.detect_format(b"access-list 101 permit tcp any any eq 80\n") == "ios"
    assert cli.detect_format(b"version 17.9\nhostname r1\n") == "ios"
    with pytest.raises(ParseError, match="no interfaces and no access lists"):
        parse("hostname r1\n")
    with pytest.raises(ParseError, match="an IPv4 and an IPv6 list"):
        parse("ip access-list extended X\n permit ip any any\nipv6 access-list X\n permit ipv6 any any\n")


def test_entries_that_cannot_be_read_are_never_wider() -> None:
    entries = ["permit tcp any any eq 80 fragments", "permit ip any any dscp ef", "permit tcp any any time-range WORK",
               "permit tcp any any syn", "dynamic DYN permit ip any any", "permit foo any any", "permit ip any object-group NONE",
               "permit ip 10.0.0.0 0.255.254.255 any", "deny tcp any any established", "permit ip any any ttl eq 10",
               "permit icmp any any 300", "permit ip any any whatever"]  # fmt: skip
    text = router_text(" ip access-group A in", rest="ip access-list extended A\n" + "".join(f" {e}\n" for e in entries) +
                       " permit tcp any any established\n permit udp any lt 0 any\n")  # fmt: skip
    model, report = parse(text)
    found = rules_of(model, "A-")
    assert len(found) == len(entries) and all(r.unsupported for r in found), [(r.name, r.unsupported) for r in found]
    assert "IOS_SKIPPED_ENTRIES" in codes(report)
    # A host name in an object group, a group nested in itself: never any address.
    text = router_text(" ip access-group B in", rest="object-group network H\n host www.example.com\nobject-group network L\n group-object L\n"
                                                   "ip access-list extended B\n deny ip object-group H any\n deny ip any object-group L\n permit ip any any\n")  # fmt: skip
    model, _ = parse(text)
    assert all(r.unsupported for r in rules_of(model, "B-")[:2]) and not rules_of(model, "B-")[2].unsupported


def test_wildcards_named_numbered_and_sequence_numbers() -> None:
    assert parse_ios.wildcard_intervals("10.0.0.0", "0.0.254.255") is not None
    assert len(parse_ios.wildcard_intervals("10.0.0.0", "0.0.254.255") or []) == 128
    assert parse_ios.wildcard_intervals("10.0.0.0", "0.255.254.255") is None  # (too many pieces)
    text = router_text(" ip access-group 101 in", " ip access-group B in",
                       "access-list 101 remark first\naccess-list 101 deny tcp 10.0.0.0 0.0.254.255 any eq www\n"
                       "access-list 101 permit ip any any\nip access-list extended B\n 30 permit ip any any\n 10 deny udp any any eq domain\n"
                       " 20 remark second\n")  # fmt: skip
    model, _ = parse(text)
    assert not verdict(model, "10.0.2.5", "192.0.2.9") and verdict(model, "10.0.1.5", "192.0.2.9")
    assert [r.description for r in rules_of(model, "101-")][:1] == ["first"]
    assert [r.name for r in rules_of(model, "B-")] == ["B-10", "B-30"]  # (in the order of the sequence numbers)
    assert not verdict(model, "192.0.2.9", "10.0.0.5", "udp", 53, "GigabitEthernet0/1", "GigabitEthernet0/0")


def test_lists_that_pass_everything_and_the_notes_of_the_input() -> None:
    text = router_text(" ip access-group MISSING in\n ipv6 traffic-filter EMPTY in", " ip access-group V6 in\n ip vrf forwarding RED\n ip inspect FW in",
                       "ipv6 access-list EMPTY\nipv6 access-list V6\n permit ipv6 any any\nip access-list extended SPARE\n permit ip any any\n"
                       "ip access-list extended R\n permit tcp any any reflect T\n evaluate T\ninterface Loopback0\n ip address 10.9.9.9 255.255.255.255\n"
                       "interface Dialer1\n ip address negotiated\n ip nat enable\n")  # fmt: skip
    model, report = parse(text)
    found = codes(report)
    assert {"IOS_ACL_UNDEFINED", "IOS_ACL_EMPTY", "IOS_UNBOUND_ACL", "IOS_VRF", "IOS_CBAC", "IOS_INTERFACES_LEFT_OUT", "IOS_DHCP_ADDRESS",
            "IOS_NVI", "IOS_REFLEXIVE", "IOS_SOURCE"} <= found  # fmt: skip
    assert verdict(model, "10.0.0.5", "192.0.2.9")  # (an undefined list passes everything)
    assert verdict(model, "192.0.2.9", "10.0.0.5", ingress="GigabitEthernet0/1", egress="GigabitEthernet0/0")  # (an IPv6 list on IPv4)
    model, report = parse(router_text(" ip access-group A in", rest="ip access-list extended A\n permit ip any any\n"))
    assert "IOS_STATELESS" in codes(report)


def test_ipv6_lists_end_in_a_deny() -> None:
    text = router_text(" ipv6 traffic-filter V6 in\n ipv6 address 2001:db8::1/64",
                       rest="ipv6 access-list V6\n permit tcp any host 2001:db8:1::5 eq www sequence 10\n sequence 20 permit icmp any any echo-request\n")  # fmt: skip
    model, _ = parse(text)
    assert verdict(model, "2001:db8::9", "2001:db8:1::5")
    assert not verdict(model, "2001:db8::9", "2001:db8:1::5", "udp", 53)
    assert verdict(model, "2001:db8::9", "2001:db8:1::5", "icmp6", 0) is False
    assert verdict(model, "10.0.0.9", "192.0.2.9", "udp", 53)  # (IPv4 has no list here)


ZBFW = """class-map type inspect match-any WEB
 match protocol http
 match protocol https
class-map type inspect match-all ODD
 match protocol gopher
class-map type inspect match-any CUSTOM
 match protocol myapp
policy-map type inspect IN-OUT
 class type inspect WEB
  inspect
 class type inspect CUSTOM
  pass
 class class-default
  drop log
policy-map type inspect STRANGE
 class type inspect ODD
  inspect
 class class-default
  pass
zone security inside
zone security outside
zone-pair security ZP source inside destination outside
 service-policy type inspect IN-OUT
zone-pair security ZP2 source outside destination inside
 service-policy type inspect STRANGE
zone-pair security ZP3 source outside destination self
 service-policy type inspect IN-OUT
zone-pair security ZP4 source inside destination inside
 service-policy type inspect NOWHERE
ip port-map myapp port tcp 8443
"""


def test_zone_based_firewall() -> None:
    text = router_text(" zone-member security inside", " zone-member security outside", ZBFW +
                       "interface GigabitEthernet0/2\n ip address 10.0.2.1 255.255.255.0\n zone-member security inside\n"
                       "interface GigabitEthernet0/3\n ip address 10.0.3.1 255.255.255.0\n")  # fmt: skip
    model, report = parse(text)
    found = codes(report)
    assert {"IOS_SELF_ZONE", "IOS_POLICY_MISSING", "IOS_PORT_MAP", "IOS_PASS"} <= found
    assert verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 443) and not verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 22)
    assert verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 8443)  # (ip port-map, passed)
    assert unit_of(model)["GigabitEthernet0/0"] == unit_of(model)["GigabitEthernet0/2"] == "inside"
    assert not verdict(model, "10.0.0.5", "10.0.2.9", egress="GigabitEthernet0/2")  # (a zone pair without its policy drops)
    assert not verdict(model, "10.0.0.5", "10.0.3.9", egress="GigabitEthernet0/3")  # (zone to no zone)
    assert verdict(model, "10.0.3.5", "10.0.3.9", ingress="GigabitEthernet0/3", egress="GigabitEthernet0/3")
    assert [r.unsupported for r in model.rules if "ODD" in r.name][0]  # (an application whose ports are not known)
    assert verdict(model, "192.0.2.9", "10.0.0.5", "udp", 9, "GigabitEthernet0/1", "GigabitEthernet0/0")  # (class-default pass)
    # Interfaces of one zone with different lists: each interface a zone of its own.
    text = router_text(" zone-member security inside\n ip access-group A in", " zone-member security outside", ZBFW +
                       "interface GigabitEthernet0/2\n ip address 10.0.2.1 255.255.255.0\n zone-member security inside\n"
                       "ip access-list extended A\n deny tcp any any eq 443\n permit ip any any\n")  # fmt: skip
    model, report = parse(text)
    assert "IOS_ZONE_SPLIT" in codes(report) and not verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 443)
    assert verdict(model, "10.0.2.5", "192.0.2.9", "tcp", 443, ingress="GigabitEthernet0/2")


def test_nat_forms() -> None:
    text = router_text(" ip nat inside", " ip nat outside", "ip nat inside source static 10.0.0.9 192.0.2.20\n"
                       "ip nat inside source static network 10.0.5.0 192.0.2.64 /27\n"
                       "ip nat inside source static tcp 10.0.0.16 80 interface GigabitEthernet0/1 8080\n"
                       "ip nat inside source list NAT interface GigabitEthernet0/1 overload\n"
                       "ip nat inside source list NAT2 pool P overload\nip nat pool P 192.0.2.100 192.0.2.110 netmask 255.255.255.0\n"
                       "ip nat inside source route-map RM interface GigabitEthernet0/1 overload\n"
                       "ip nat outside source static 192.0.2.50 10.0.0.50\n"
                       "ip nat inside source list EXT interface GigabitEthernet0/1 overload\n"
                       "access-list 10 permit any\nip access-list standard NAT\n permit 10.0.0.0 0.0.0.255\n"
                       "ip access-list standard NAT2\n permit 10.0.1.0 0.0.0.255\n"
                       "ip access-list extended EXT\n permit tcp 10.0.0.0 0.0.0.255 any eq 80\n")  # fmt: skip
    model, report = parse(text)
    nats = {n.description.split(" source ", 1)[1][:30]: n for n in model.nat_rules}
    assert len(model.nat_rules) == 8
    assert sum(1 for n in model.nat_rules if n.unsupported) == 3  # (route-map, outside source, a list with ports)
    statics = [n for n in model.nat_rules if n.source_translation and n.source_translation.kind.value == "static"]
    assert {n.sources[0] for n in statics} == {"10.0.0.9", "10.0.5.0/27"}
    forward = [n for n in model.nat_rules if n.destination_translation]
    assert forward[0].destinations == ["192.0.2.1"] and forward[0].destination_translation.port == "80"
    assert any(n.source_translation and n.source_translation.kind.value == "interface" and n.sources == ["10.0.0.0/24"] for n in model.nat_rules)
    assert nats
    # Outbound lists see addresses after NAT: rewritten to the addresses as they arrive.
    text = router_text(" ip nat inside\n ip access-group OUT out", " ip nat outside\n ip access-group OUT2 out",
                       "ip nat inside source static 10.0.0.9 192.0.2.20\nip nat inside source list NAT interface GigabitEthernet0/1 overload\n"
                       "ip access-list standard NAT\n permit 10.0.0.0 0.0.0.255\n"
                       "ip access-list extended OUT\n permit tcp any host 10.0.0.9 eq www\n"
                       "ip access-list extended OUT2\n permit tcp host 192.0.2.1 any eq www\n permit tcp host 192.0.2.20 any eq 443\n"
                       " permit udp host 192.0.2.1 gt 1023 any eq domain\n")  # fmt: skip
    model, report = parse(text)
    assert verdict(model, "198.51.100.7", "192.0.2.20", ingress="GigabitEthernet0/1", egress="GigabitEthernet0/0")
    assert not verdict(model, "198.51.100.7", "10.0.0.9", "tcp", 22, ingress="GigabitEthernet0/1", egress="GigabitEthernet0/0")
    assert verdict(model, "10.0.0.5", "198.51.100.7")  # (leaves as 192.0.2.1)
    assert verdict(model, "10.0.0.9", "198.51.100.7", "tcp", 443) and not verdict(model, "10.0.0.9", "198.51.100.7", "tcp", 80)
    assert [r.unsupported for r in model.rules if "OUT2-30" in r.name][0]  # (source ports after port translation)


def test_composed_lists_that_grow_too_long_are_blocked_and_said() -> None:
    entries_in = "".join(f" permit tcp any host 10.0.1.{i} eq www\n" for i in range(1, 80))
    entries_out = "".join(f" permit tcp host 10.0.0.{i} any\n" for i in range(1, 80))
    text = router_text(" ip access-group I in", " ip access-group O out", f"ip access-list extended I\n{entries_in}ip access-list extended O\n{entries_out}")
    model, report = parse(text)
    assert "IOS_COMPOSED_LEFT_OUT" in codes(report)
    assert not verdict(model, "10.0.0.5", "10.0.1.5")


def test_emitter_names_nat_and_what_it_does_not_write() -> None:
    from fwshift.emitters import ios as emit_ios
    from fwshift.errors import FwshiftError
    from fwshift.model import Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, Service, ServiceEntry, SnatKind, SourceNat, Zone
    from fwshift.options import Options

    p = Policy(vendor="test", default_intrazone=Action.ALLOW)
    p.zones["trust zone"] = Zone("trust zone", ["port1"])
    p.zones["untrust"] = Zone("untrust", ["port2"])
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.0.0.10/32")
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    for name, action, services, destinations in (("allow-web", Action.ALLOW, ["https", "gre"], ["web"]), ("reset", Action.RESET_BOTH, ["https"], ["any"]),
                                                 ("to-site", Action.ALLOW, ["https"], ["site"]), ("off", Action.ALLOW, ["https"], ["web"])):  # fmt: skip
        rule = Rule(name, src_zones=["untrust"], dst_zones=["trust zone"], destinations=destinations, services=services, action=action)
        rule.origin = name
        rule.log_end = True
        rule.enabled = name != "off"
        p.rules.append(rule)
    static = NatRule("static", sources=["10.0.0.10"], src_zones=["trust zone"], dst_zones=["untrust"])
    static.source_translation = SourceNat(SnatKind.STATIC, ["192.0.2.10"], bidirectional=True)
    forward = NatRule("forward", destinations=["192.0.2.1"], service="https", src_zones=["untrust"])
    forward.destination_translation = DestNat("10.0.0.20", "8443")
    hide = NatRule("hide", sources=["10.0.0.0/24"], src_zones=["trust zone"], dst_zones=["untrust"])
    hide.source_translation = SourceNat(SnatKind.INTERFACE, interface="untrust")
    odd = NatRule("odd", sources=["10.0.0.0/24"], destinations=["198.51.100.0/24"], service="https")
    odd.source_translation = SourceNat(SnatKind.DYNAMIC, ["192.0.2.30"])
    for nat in (static, forward, hide, odd):
        nat.origin = nat.name
        p.nat_rules.append(nat)
    report = Report()
    text = emit_ios.emit(p, report, Options(interface_map={"port1": "GigabitEthernet0/1", "port2": "GigabitEthernet0/0"}, object_prefix="X"))
    assert "zone security X-trust-zone\n description trust zone" in text and "zone security X-untrust" in text
    assert "! interface GigabitEthernet0/1\n!  zone-member security X-trust-zone" in text
    assert "! ip nat inside source static 10.0.0.10 192.0.2.10" in text
    assert "! ip nat inside source static tcp 10.0.0.20 8443 192.0.2.1 443 extendable" in text
    assert "! ip nat inside source list X-NAT1 interface GigabitEthernet0/0 overload" in text
    assert report.item("nat", "odd").skipped and "NAT_NOT_CONVERTED" in codes(report)
    assert {"IOS_PASS", "IOS_LOG_ALLOW"} <= {f.code for f in report.item("rule", "allow-web").findings}
    assert "REJECT_AS_DENY" in {f.code for f in report.item("rule", "reset").findings}
    assert report.item("rule", "to-site").disabled and "!   to-site: host name object site" in text
    assert report.item("rule", "off").skipped
    assert {"IOS_LOAD", "IOS_ZONE_MEMBERS", "LOGGING_CONVERTED"} <= codes(report) and "IOS_INTRAZONE" not in codes(report)
    assert "permit tcp any host 10.0.0.10 eq 443" in text and "permit 47 any host 10.0.0.10" in text
    assert "  drop log" in text
    router = read_router(text, ["trust zone", "untrust"])
    judge = IosJudge(router)
    assert judge.allows(Packet("", "", "198.51.100.7", "10.0.0.10", "tcp", 40000, 443), "untrust", "trust zone")
    assert not judge.allows(Packet("", "", "198.51.100.7", "10.0.0.10", "tcp", 40000, 80), "untrust", "trust zone")
    assert judge.allows(Packet("", "", "10.0.0.7", "10.0.0.10", "tcp", 40000, 80), "trust zone", "trust zone")  # (inside a zone)
    with pytest.raises(FwshiftError, match="--target-prefix for IOS"):
        emit_ios.emit(p, Report(), Options(object_prefix="1bad prefix"))
    # Traffic inside a zone that the source denies: a zone pair from the zone to itself.
    p.default_intrazone = Action.DENY
    report = Report()
    text = emit_ios.emit(p, report, Options())
    assert "source FWS-trust-zone destination FWS-trust-zone" in text and "IOS_INTRAZONE" in codes(report)


# -- review round 36 ----------------------------------------------------------------------------------


def test_r36_a_list_of_evaluate_only_ends_in_its_implicit_deny() -> None:
    text = router_text(" ip access-group INBOUND in\n ipv6 traffic-filter V6IN in", rest="ip access-list extended INBOUND\n evaluate TCPTRAFFIC\n"
                       "ipv6 access-list V6IN\n evaluate REFL\n")  # fmt: skip
    model, report = parse(text)
    assert not verdict(model, "10.0.0.5", "192.0.2.9") and not verdict(model, "2001:db8::5", "2001:db8:1::9")
    assert "IOS_ACL_EMPTY" not in codes(report) and "IOS_REFLEXIVE" in codes(report)


def test_r36_nat_that_is_not_read_makes_what_comes_after_it_unconverted() -> None:
    for nat in ("ip nat inside destination list VIP pool REAL\n", "ip nat inside source static 10.0.0.9 192.0.2.20 route-map RM\n",
                "ip nat inside source static tcp 10.0.0.9 80 interface Dialer0 8080\n"):  # fmt: skip
        text = router_text(" ip nat inside\n ip access-group OUT out", " ip nat outside",
                           nat + "ip access-list extended OUT\n deny ip any host 10.0.0.9\n permit ip any any\n")  # fmt: skip
        model, report = parse(text)
        assert any(n.unsupported for n in model.nat_rules), nat
        denies = [r for r in model.rules if "OUT-10" in r.name and r.src_zones == ["GigabitEthernet0/1"]]
        assert denies and all(r.unsupported for r in denies), nat


def test_r36_port_maps_by_their_grammar() -> None:
    zbfw = ("class-map type inspect match-any HTTP\n match protocol http\nclass-map type inspect match-any TCP\n match protocol tcp\n"
            "policy-map type inspect PM\n class type inspect HTTP\n  drop\n class type inspect TCP\n  inspect\n class class-default\n  drop\n"
            "zone security a\nzone security b\nzone-pair security ZP source a destination b\n service-policy type inspect PM\n")  # fmt: skip
    model, _ = parse(router_text(" zone-member security a", " zone-member security b", zbfw + "ip port-map http port tcp from 8000 to 8100\n"))
    assert not verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 8050) and verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 8200)
    model, _ = parse(router_text(" zone-member security a", " zone-member security b", zbfw + "ip port-map http port tcp 8080 description web 3389\n"))
    assert not verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 8080) and verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 3389)
    for line in ("ip port-map http port tcp 99999\n", "ip port-map http port tcp 8080 list 10\n"):
        model, _ = parse(router_text(" zone-member security a", " zone-member security b", zbfw + line))
        assert [r.unsupported for r in model.rules if " HTTP" in r.name][0], line


def test_r36_no_traceback_for_ports_out_of_range() -> None:
    text = router_text(" ip nat inside\n ip access-group OUT out", " ip nat outside",
                       "ip nat inside source static tcp 10.0.0.9 80 192.0.2.5 99999\nip access-list extended OUT\n permit ip any any\n")  # fmt: skip
    model, _ = parse(text)
    assert all(n.unsupported for n in model.nat_rules)


def test_r36_access_group_lines_that_are_not_read() -> None:
    model, report = parse(router_text(" ip access-group common COMMON IFACL in", rest="ip access-list extended COMMON\n deny ip any any\n"))
    assert "IOS_ACL_NOT_READ" in codes(report)
    assert [r.unsupported for r in model.rules if "common" in r.name][0]


def test_r36_layer7_policies_and_class_maps_that_match_nothing() -> None:
    zbfw = ("class-map type inspect match-any HTTP\n match protocol http\nclass-map type inspect match-any NONE\n"
            "class-map type inspect match-any EMPTYACL\n match access-group name EMPTY\nip access-list extended EMPTY\n"
            "policy-map type inspect PM\n class type inspect NONE\n  drop\n class type inspect EMPTYACL\n  drop\n class type inspect HTTP\n"
            "  inspect\n  service-policy http L7\n class class-default\n  drop\nzone security a\nzone security b\n"
            "zone-pair security ZP source a destination b\n service-policy type inspect PM\n")  # fmt: skip
    model, report = parse(router_text(" zone-member security a", " zone-member security b", zbfw))
    assert "IOS_LAYER7" in codes(report)
    assert [r.unsupported for r in model.rules if " NONE" in r.name][0] and [r.unsupported for r in model.rules if " EMPTYACL" in r.name][0]


def test_r36_many_interfaces_one_outbound_list() -> None:
    interfaces = "".join(f"interface GigabitEthernet1/{i}\n ip address 10.{i}.0.1 255.255.255.0\n ip access-group IN{i} in\n" for i in range(30))
    lists = "".join(f"ip access-list extended IN{i}\n" + "".join(f" permit tcp any host 10.{i}.0.{j} eq www\n" for j in range(1, 11)) for i in range(30))
    text = "version 15.4\n" + interfaces + "interface GigabitEthernet2/0\n ip address 10.99.0.1 255.255.255.0\n ip access-group O out\n" + lists + \
        "ip access-list extended O\n deny tcp any any eq 22\n permit ip any any\n"
    model, _ = parse(text)
    assert len(model.rules) < 2500


def test_r36_default_zone_protocol_zero_and_banners() -> None:
    text = ("banner motd ^C\naccess-list 10 permit any\ninterface Fake\n ip address 10.9.9.1 255.255.255.0\n^C\n"
            + router_text(" ip access-group A in", rest="ip access-list extended A\n deny 0 any any\n permit ip any any\nzone security default\n"))  # fmt: skip
    model, report = parse(text)
    assert "Fake" not in unit_of(model) and "10" not in {r.source_ids.get("ios.acl") for r in model.rules}
    assert [r.unsupported for r in model.rules if r.name.startswith("A-10")][0]
    assert verdict(model, "10.0.0.5", "192.0.2.9")  # (both interfaces in the default zone: inside one zone)


def test_r36_emitter_zone_names_text_and_intrazone_zones() -> None:
    from fwshift.emitters import ios as emit_ios
    from fwshift.model import Action, Policy, Rule, Zone
    from fwshift.options import Options

    p = Policy(vendor="test", default_intrazone=Action.DENY)
    p.zones["default"] = Zone("default", ["Gi0/9\n shutdown"])
    p.zones["self"] = Zone("self", intrazone_allow=True)
    rule = Rule("r", src_zones=["default"], dst_zones=["self"])
    rule.origin = "r"
    p.rules.append(rule)
    text = emit_ios.emit(p, Report(), Options())
    assert "zone security FWS-default" in text and "zone security FWS-self" in text and "\n shutdown" not in text
    assert "source FWS-default destination FWS-default" in text and "source FWS-self destination FWS-self" not in text


def test_r36_mutation_survivors() -> None:
    """Denies of a class map's list, a class-default without an action, outside addresses of NAT in an outbound list,
    the denies of the list of a dynamic translation, and the default of the source in the emitted policy."""
    zbfw = ("ip access-list extended NOSSH\n deny tcp any any eq 22\n permit tcp any any\nclass-map type inspect match-any C1\n"
            " match access-group name NOSSH\nclass-map type inspect match-any ALL\n match protocol tcp\npolicy-map type inspect PM\n"
            " class type inspect C1\n  drop\n class type inspect ALL\n  inspect\n class class-default\nzone security a\nzone security b\n"
            "zone-pair security ZP source a destination b\n service-policy type inspect PM\n")  # fmt: skip
    model, _ = parse(router_text(" zone-member security a", " zone-member security b", zbfw))
    assert verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 22) and not verdict(model, "10.0.0.5", "192.0.2.9", "tcp", 80)
    assert not verdict(model, "10.0.0.5", "192.0.2.9", "udp", 53)  # (class-default without an action drops)
    nat = ("ip nat inside source static 10.0.0.9 192.0.2.20\nip nat inside source static tcp 10.0.0.16 80 192.0.2.1 8080\n"
           "ip access-list extended OUT\n deny ip any host 192.0.2.20\n deny tcp any host 192.0.2.1 eq 8080\n permit ip any any\n")  # fmt: skip
    model, _ = parse(router_text(" ip nat inside\n ip access-group OUT out", " ip nat outside", nat))
    outside = {"ingress": "GigabitEthernet0/1", "egress": "GigabitEthernet0/0"}
    assert verdict(model, "198.51.100.7", "192.0.2.20", **outside) and verdict(model, "198.51.100.7", "192.0.2.1", "tcp", 8080, **outside)
    pat = ("ip nat inside source list NAT interface GigabitEthernet0/1 overload\nip access-list standard NAT\n deny host 10.0.0.5\n"
           " permit 10.0.0.0 0.0.0.255\nip access-list extended OUT2\n permit tcp host 192.0.2.1 any\n")  # fmt: skip
    model, _ = parse(router_text(" ip nat inside", " ip nat outside\n ip access-group OUT2 out", pat))
    assert verdict(model, "10.0.0.6", "198.51.100.7") and not verdict(model, "10.0.0.5", "198.51.100.7")


def test_r36_emitted_default_allow() -> None:
    from fwshift.emitters import ios as emit_ios
    from fwshift.model import Action, Policy, Zone
    from fwshift.options import Options

    p = Policy(vendor="test", default_interzone=Action.ALLOW, default_intrazone=Action.ALLOW)
    p.zones["a"], p.zones["b"] = Zone("a"), Zone("b")
    text = emit_ios.emit(p, Report(), Options())
    judge = IosJudge(read_router(text, ["a", "b"]))
    assert judge.allows(Packet("", "", "10.0.0.5", "10.0.1.5", "47"), "a", "b") and judge.allows(Packet("", "", "10.0.0.5", "10.0.1.5", "tcp", 1, 22), "a", "b")


def test_r36_icmp_type_and_code_numbers() -> None:
    model, _ = parse(router_text(" ip access-group A in", rest="ip access-list extended A\n permit icmp any any 3 3\n permit icmp any any 8\n"))
    assert not any(r.unsupported for r in model.rules)
    units = unit_of(model)
    for icmp_type, wanted in ((3, True), (8, True), (0, False)):
        pkt = Packet(units["GigabitEthernet0/0"], units["GigabitEthernet0/1"], "10.0.0.5", "192.0.2.9", "icmp", 0, 0, icmp_type)
        assert model_allows(model, pkt) is wanted, icmp_type


def _run(argv: List[str]) -> int:
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            return cli.main(argv)
        except SystemExit as stop:
            return int(stop.code or 0)


def test_nat_sides_name_where_the_published_host_is(tmp_path: Any) -> None:
    """0.40.0: `ip nat inside source static` names the published host as its inside has it: the inside is the zone of
    the host's own address, the outside where the connections come from (it was the NAT rule's zones, both outside)."""
    import re
    from pathlib import Path

    lab = Path(__file__).resolve().parent.parent / "lab" / "policy" / "lab_panos.xml"
    nets = ["--zone-network", "inside=10.20.1.0/24", "--zone-network", "dmz=10.20.2.0/24", "--zone-network", "outside=10.20.3.0/24"]
    for extra, inside in ((nets, ["FWS-dmz", "FWS-inside"]), ([], ["FWS-inside"])):
        out = tmp_path / "o.ios"
        assert _run(["convert", str(lab), "--to", "ios", "-o", str(out), "-q", *extra]) in (0, 3)
        text = out.read_text(encoding="utf-8")
        found = re.findall(r"^! \(the interfaces of zone (\S+): ip nat (inside|outside)\)$", text, re.M)
        assert sorted(z for z, side in found if side == "inside") == inside and [z for z, side in found if side == "outside"] == ["FWS-outside"], found
        assert ("the interfaces toward 10.20.2.10" in text) == (not extra)


def test_ios_output_is_read_back(tmp_path: Any) -> None:
    """convert --compare reads IOS output back, with its interfaces in their zones (the commented lines at its end)."""
    from fwshift.emitters import ios as emit_ios

    report = tmp_path / "report.txt"
    code = _run(["convert", str(DATA / "asa_sample.cfg"), "--to", "ios", "-o", str(tmp_path / "o"), "--report", str(report), "-q", "--compare"])
    text = report.read_text(encoding="utf-8")
    assert code in (0, 3) and "COMPARE_NOT_READ_BACK" not in text and "COMPARE_" in text, text[-2000:]
    assert emit_ios.activate("! interface Gi2\n!  zone-member security FWS-a\n! ip nat inside source list X interface Gi4 overload\n") == \
        "interface Gi2\n zone-member security FWS-a\n! ip nat inside source list X interface Gi4 overload\n"


def test_huawei_output_is_read_back(tmp_path: Any) -> None:
    """0.40.0: convert --compare reads Huawei output back; its zones are matched without FWShift's own prefix."""
    report = tmp_path / "report.txt"
    code = _run(["convert", str(DATA / "huawei_sample.cfg"), "--to", "huawei", "-o", str(tmp_path / "o"), "--report", str(report), "-q",
                 "--compare", str(tmp_path / "compare.txt")])
    text = report.read_text(encoding="utf-8")
    assert code in (0, 3) and "COMPARE_NOT_READ_BACK" not in text and "COMPARE_" in text, text[-2000:]
    assert "opened" not in (tmp_path / "compare.txt").read_text(encoding="utf-8").split("Notes")[0].split("compared):", 1)[1].split("\n")[0]
