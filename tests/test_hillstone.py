# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hillstone StoneOS: parser, emitter, and packet-level equivalence with judges of their own.

``StoneOS`` reads the commands the emitter writes strictly, as a firewall of the reading of Hillstone's documentation
would take them (every name defined once and before it is used, one source and one destination zone per rule, an
address entry of one IP version, the ICMP types a service takes), and decides packets: the rules of ``policy-global``
first match in the order they were entered, a rule without a zone for every zone, ``Any`` every IPv4 address and
``IPv6-any`` every IPv6 address, then ``default-action`` (deny unless permit), inside a zone as between zones.

A random StoneOS configuration is a plain description that ``render`` writes as ``show configuration`` and ``Judge``
decides packets from with the same reading, placing rules (``top``, ``before``, ``move``) by itself. None of it shares
code with the parser or the emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import random
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import ZONES as MODEL_ZONES
from test_iptables import Packet, model_allows, random_model, random_packet

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import hillstone as parse_hillstone
from fwshift.report import Report

NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
# The judges' own table of predefined services (the well-known ports).
KNOWN: Dict[str, List[Any]] = {
    "Any": [("any",)], "ICMP": [("icmp", None, None)], "PING": [("icmp", 8, None)], "HTTP": [("tcp", (80, 80), None)],
    "HTTPS": [("tcp", (443, 443), None)], "SSH": [("tcp", (22, 22), None)], "DNS": [("tcp", (53, 53), None), ("udp", (53, 53), None)],
}  # fmt: skip
PREDEFINED_ZONES = {"trust", "untrust", "dmz", "l2-trust", "l2-untrust", "l2-dmz", "mgt", "vpnhub", "ha"}


def addr(text: str) -> Any:
    return ipaddress.ip_address(text)


def service_matches(entry: Any, pkt: Packet) -> bool:
    kind = entry[0]
    if kind == "any":
        return True
    if kind in ("tcp", "udp"):
        dst, src = entry[1], entry[2]
        return pkt.proto == kind and (dst is None or dst[0] <= pkt.dport <= dst[1]) and (src is None or src[0] <= pkt.sport <= src[1])
    if kind == "icmp":
        return pkt.proto == "icmp" and (entry[1] is None or entry[1] == pkt.icmp_type)
    if kind == "proto":
        return str(NUMBERS.get(pkt.proto, pkt.proto)) == str(entry[1])
    raise AssertionError(entry)


# -- the reader of the emitted commands ------------------------------------------------------------------------


class StoneOS:
    """The commands the emitter writes, read as a firewall would take them, and judged."""

    def __init__(self, text: str) -> None:
        lines = text.splitlines()
        assert lines[0] == "configure" and lines[-1] == "end", (lines[:1], lines[-1:])
        self.zones: Dict[str, bool] = {z: True for z in PREDEFINED_ZONES}
        self.entries: Dict[str, Tuple[int, List[Tuple[int, int, int]]]] = {}
        self.services: Dict[str, List[Any]] = dict(KNOWN)
        self.rules: List[Dict[str, Any]] = []
        self.dnat: List[str] = []
        self.snat: List[str] = []
        self.default_permit = False
        self.names: set = set()
        self.hosts: set = set()  # (entries with a host name: the judge cannot resolve them)
        index = 1
        while index < len(lines) - 1:
            words = shlex.split(lines[index])
            assert not lines[index].startswith(" "), lines[index]
            body: List[List[str]] = []
            raw: List[str] = []
            index += 1
            while lines[index] != "exit":
                raw.append(lines[index])
                body.append(shlex.split(lines[index]))
                index += 1
            index += 1
            if words[0] == "zone":
                self._define(words[1])
                self.zones[words[1]] = True
                assert all(line[0] == "description" for line in body), body
            elif words[0] == "address":
                self._address(words, body)
            elif words[0] == "service":
                self._service(words[1], body)
            elif words == ["policy-global"]:
                self._policy(raw)
            elif words == ["ip", "vrouter", "trust-vr"]:
                for line in raw:
                    head = line.split()[0]
                    assert head in ("snatrule", "dnatrule"), line
                    (self.snat if head == "snatrule" else self.dnat).append(line.strip())
            else:
                raise AssertionError(words)

    def _define(self, name: str) -> None:
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name), name
        assert name.lower() not in self.names, f"{name} defined twice"
        self.names.add(name.lower())

    def _address(self, words: List[str], body: List[List[str]]) -> None:
        name = words[1]
        self._define(name)
        family = 6 if words[2:] == ["ipv6"] else 4
        assert words[2:] in ([], ["ipv6"]), words
        found: List[Tuple[int, int, int]] = []
        assert body, f"empty address entry {name}"
        for line in body:
            if line[0] == "ip":
                assert len(line) == 2, line
                net = ipaddress.ip_network(line[1])  # (strict: a network address)
                found.append((net.version, int(net.network_address), int(net.broadcast_address)))
            elif line[0] == "range":
                assert len(line) == 3, line
                first, last = addr(line[1]), addr(line[2])
                assert first.version == last.version and int(first) <= int(last), line
                found.append((first.version, int(first), int(last)))
            elif line[0] == "host":
                assert len(line) == 2 and family == 4, line
                self.hosts.add(name)
            else:
                raise AssertionError(line)
        assert all(f[0] == family for f in found), (name, family, found)
        self.entries[name] = (family, found)

    def _ports(self, words: List[str], index: int) -> Tuple[Tuple[int, int], int]:
        first = int(words[index])
        last = int(words[index + 1]) if index + 1 < len(words) and words[index + 1].isdigit() else first
        assert 0 <= first <= last <= 65535, words
        return (first, last), index + (2 if index + 1 < len(words) and words[index + 1].isdigit() else 1)

    def _service(self, name: str, body: List[List[str]]) -> None:
        self._define(name)
        entries: List[Any] = []
        assert body
        for line in body:
            if line[0] in ("tcp", "udp"):
                assert line[1] == "dst-port", line
                dst, index = self._ports(line, 2)
                src = None
                if index < len(line):
                    assert line[index] == "src-port", line
                    src, index = self._ports(line, index + 1)
                assert index == len(line), line
                entries.append((line[0], dst, src))
            elif line[0] == "icmp":
                assert len(line) in (3, 6) and line[1] == "type" and int(line[2]) in (3, 4, 5, 8, 11, 12, 13, 15), line
                if len(line) == 6:
                    assert line[3] == "code" and 0 <= int(line[4]) == int(line[5]) <= 5, line
                    entries.append(("icmp-code", int(line[2]), int(line[4])))
                else:
                    entries.append(("icmp", int(line[2]), None))
            elif line[0] == "protocol":
                assert len(line) == 2 and 1 <= int(line[1]) <= 255 and int(line[1]) not in (6, 17, 1, 58), line
                entries.append(("proto", int(line[1])))
            else:
                raise AssertionError(line)
        self.services[name] = entries

    def _policy(self, raw: List[str]) -> None:
        ids: set = set()
        index = 0
        while index < len(raw):
            line = raw[index].strip()
            if line == "default-action permit":
                assert index == len(raw) - 1, "default-action comes after the rules"
                self.default_permit = True
                index += 1
                continue
            words = line.split()
            assert words[:2] == ["rule", "id"] and len(words) == 3, line
            assert words[2] not in ids
            ids.add(words[2])
            rule: Dict[str, Any] = {"id": words[2], "enabled": True, "src_zone": None, "dst_zone": None, "src": [], "dst": [],
                                    "services": [], "action": None, "name": None}  # fmt: skip
            index += 1
            while raw[index].strip() != "exit":
                part = shlex.split(raw[index])
                index += 1
                head = part[0]
                if head == "disable":
                    assert rule["action"] is None, "disable comes first"
                    rule["enabled"] = False
                elif head == "name":
                    assert rule["name"] is None and len(part) == 2
                    self._define(part[1])
                    rule["name"] = part[1]
                elif head == "action":
                    assert rule["action"] is None and part[1] in ("permit", "deny") and len(part) == 2, part
                    rule["action"] = part[1]
                elif head in ("src-zone", "dst-zone"):
                    key = head.replace("-", "_")
                    assert rule[key] is None, "one zone per side"
                    assert part[1] in self.zones, f"zone {part[1]} not defined before use"
                    rule[key] = part[1]
                elif head[:4] in ("src-", "dst-"):
                    side = rule["src" if head.startswith("src") else "dst"]
                    kind = head[4:]
                    if kind == "addr":
                        assert part[1] in ("Any", "IPv6-any") or part[1] in self.entries, f"address {part[1]} not defined before use"
                        side.append(("addr", part[1]))
                    elif kind == "ip":
                        net = ipaddress.ip_network(part[1])
                        side.append(("net", (net.version, int(net.network_address), int(net.broadcast_address))))
                    elif kind == "range":
                        side.append(("net", (addr(part[1]).version, int(addr(part[1])), int(addr(part[2])))))
                    else:
                        raise AssertionError(part)
                elif head == "service":
                    assert part[1] in self.services, f"service {part[1]} not defined before use"
                    rule["services"].append(part[1])
                elif head == "log":
                    assert part[1] in ("session-start", "session-end", "policy-deny"), part
                elif head == "description":
                    assert len(part) == 2 and len(part[1]) <= 255
                else:
                    raise AssertionError(part)
            index += 1
            assert rule["action"] and rule["name"] and rule["src"] and rule["dst"] and rule["services"], rule
            families = {self._family(ref) for ref in rule["src"] + rule["dst"]}
            assert len(families) == 1, f"a rule of one IP version: {rule}"
            self.rules.append(rule)

    def _family(self, ref: Any) -> int:
        if ref[0] == "net":
            return int(ref[1][0])
        if ref[1] == "Any":
            return 4
        if ref[1] == "IPv6-any":
            return 6
        return self.entries[ref[1]][0]

    def _side(self, refs: List[Any], address: str) -> bool:
        probe = addr(address)
        for kind, value in refs:
            if kind == "addr":
                if value == "Any" and probe.version == 4 or value == "IPv6-any" and probe.version == 6:
                    return True
                assert value not in self.hosts, f"{value} holds a host name: not for the judge"
                if value in self.entries and any(i[0] == probe.version and i[1] <= int(probe) <= i[2] for i in self.entries[value][1]):
                    return True
            elif value[0] == probe.version and value[1] <= int(probe) <= value[2]:
                return True
        return False

    def _service_ok(self, names: List[str], pkt: Packet) -> bool:
        for name in names:
            for entry in self.services[name]:
                if entry[0] == "icmp-code":
                    if pkt.proto == "icmp" and pkt.icmp_type == entry[1] and entry[2] == 0:
                        return True  # (the packets of the tests carry code 0)
                    continue
                if service_matches(entry, pkt):
                    return True
        return False

    def allows(self, pkt: Packet, ingress: str, egress: str) -> bool:
        for rule in self.rules:
            if not rule["enabled"]:
                continue
            if rule["src_zone"] is not None and rule["src_zone"] != ingress:
                continue
            if rule["dst_zone"] is not None and rule["dst_zone"] != egress:
                continue
            if self._side(rule["src"], pkt.src) and self._side(rule["dst"], pkt.dst) and self._service_ok(rule["services"], pkt):
                return bool(rule["action"] == "permit")
        return self.default_permit


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import hillstone as emit_hillstone

    report = Report()
    return emit_hillstone.emit(model, report, options or Options()), report


def zoned(model: Policy) -> Policy:
    for zone in MODEL_ZONES:
        model.zones.setdefault(zone, Zone(zone))
    return model


def compare(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    """The emitted commands against the model (zones eth0, eth1, eth2), never deciding otherwise."""
    config = StoneOS(text)
    names = {zone: f"FWS_{zone}" for zone in MODEL_ZONES}
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (written disabled, and said)
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 0, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        verdict = config.allows(pkt, names[pkt.in_if], names[pkt.out_if])
        assert verdict == model_allows(model, pkt), (seed, pkt, text)
        count += 1
    return count


@pytest.mark.parametrize("seed", range(40))
def test_emitted_commands_decide_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = zoned(random_model(rng))
    for rule in model.rules:
        if rule.action == Action.ALLOW and rng.random() < 0.3:
            rule.log_end = False
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW  # (the model's judge knows one default)
    text, report = emit(model)
    assert compare(model, report, text, rng, seed) == 400


# -- random StoneOS configurations ------------------------------------------------------------------------------

ZONES = ["trust", "untrust", "dmz", "lab"]
POOL = ["10.0.0.5", "10.0.0.9", "10.0.1.16", "10.0.1.130", "10.0.2.20", "10.0.2.100", "10.0.3.9", "10.0.3.30", "192.0.2.7",
        "198.51.100.4", "2001:db8:1::5", "2001:db8:2::9", "2001:db8:3::1"]  # fmt: skip
NETS = ["10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/25", "10.0.2.16/28", "10.0.0.5/32", "192.0.2.0/24", "10.0.0.0/16"]
NETS6 = ["2001:db8:1::/48", "2001:db8:2::9/128", "2001:db8::/32"]
RANGES = [("10.0.3.1", "10.0.3.20"), ("10.0.2.1", "10.0.2.40"), ("10.0.0.6", "10.0.1.20")]
PORTS = [22, 53, 80, 443, 8080, 123, 79, 81, 1023, 1024, 8000, 8005, 8010, 8011, 65535, 0]


def _in(address: str, spec: Any, entries: Dict[str, Any]) -> bool:
    probe = addr(address)
    kind = spec[0]
    if kind == "any":
        return probe.version == 4
    if kind == "any6":
        return probe.version == 6
    if kind == "net":
        net = ipaddress.ip_network(spec[1])
        return probe.version == net.version and probe in net
    if kind == "range":
        return probe.version == addr(spec[1]).version and int(addr(spec[1])) <= int(probe) <= int(addr(spec[2]))
    if kind == "entry":
        entry = entries[spec[1]]
        inside = any(_in(address, s, entries) for s in entry["specs"])
        return inside and not any(_in(address, s, entries) for s in entry["exclude"])
    raise AssertionError(spec)


def _service_in(pkt: Packet, name: str, services: Dict[str, Any], groups: Dict[str, List[str]]) -> bool:
    known = {key.lower(): value for key, value in KNOWN.items()}  # (predefined names are taken in any case)
    if name.lower() in known and name not in services and name not in groups:
        return any(service_matches(e, pkt) for e in known[name.lower()])
    if name in groups:
        return any(_service_in(pkt, member, services, groups) for member in groups[name])
    return any(service_matches(e, pkt) for e in services[name])


class Judge:
    """A StoneOS configuration described plainly, deciding packets as the firewall does (by the documentation)."""

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.conf = conf
        self.order = self._order()

    def _order(self) -> List[Dict[str, Any]]:
        order: List[Dict[str, Any]] = []
        by_id = {rule["id"]: rule for rule in self.conf["rules"]}
        for rule in self.conf["rules"]:
            where = rule.get("place")
            if where == "top":
                order.insert(0, rule)
            elif where and where[1] in [r["id"] for r in order]:
                position = [r["id"] for r in order].index(where[1])
                order.insert(position + (where[0] == "after"), rule)
            else:
                order.append(rule)
        for ident, where in self.conf["moves"]:
            rule = by_id[ident]
            order.remove(rule)
            if where == "top":
                order.insert(0, rule)
            elif where == "bottom":
                order.append(rule)
            else:
                position = [r["id"] for r in order].index(where[1])
                order.insert(position + (where[0] == "after"), rule)
        return order

    def allows(self, pkt: Packet, ingress: str, egress: str) -> Optional[bool]:
        entries, services, groups = self.conf["entries"], self.conf["services"], self.conf["groups"]
        for rule in self.order:
            if not rule["enabled"]:
                continue
            if rule["src_zones"] and ingress not in rule["src_zones"]:
                continue
            if rule["dst_zones"] and egress not in rule["dst_zones"]:
                continue
            if rule["bad"] or any(entries[s[1]]["bad"] for s in rule["src"] + rule["dst"] if s[0] == "entry"):
                return None  # (not converted: what comes after it is not decided)
            if not any(_in(pkt.src, s, entries) for s in rule["src"]):
                continue
            if not any(_in(pkt.dst, s, entries) for s in rule["dst"]):
                continue
            if rule["services"] != ["Any"] and not any(_service_in(pkt, s, services, groups) for s in rule["services"]):
                continue
            return rule["action"] == "permit"
        return bool(self.conf["permit"])


def random_conf(rng: random.Random) -> Dict[str, Any]:
    entries: Dict[str, Any] = {}
    for index in range(rng.randint(2, 7)):
        name = f"e{index}"
        specs: List[Any] = []
        exclude: List[Any] = []
        six = rng.random() < 0.2
        for _ in range(rng.randint(1, 3)):
            roll = rng.random()
            earlier = [n for n in entries if entries[n]["six"] == six]
            if earlier and roll < 0.25:
                specs.append(("entry", rng.choice(earlier)))
            elif six:
                specs.append(("net", rng.choice(NETS6)))
            elif roll < 0.6:
                specs.append(("net", rng.choice(NETS)))
            else:
                specs.append(("range",) + rng.choice(RANGES))
        if not six and rng.random() < 0.2:
            exclude.append(("range",) + rng.choice(RANGES))
        entries[name] = {"specs": specs, "exclude": exclude, "six": six, "bad": rng.random() < 0.06}
    # (a member that is bad, or holds one, makes what holds it bad too)
    for name, entry in entries.items():
        entry["bad"] = entry["bad"] or any(s[0] == "entry" and entries[s[1]]["bad"] for s in entry["specs"])
        if entry["exclude"] and any(s[0] == "entry" for s in entry["specs"]):
            entry["exclude"] = []  # (kept simple: exclusions on plain entries)
    services: Dict[str, List[Any]] = {}
    for index in range(rng.randint(1, 4)):
        found: List[Any] = []
        for _ in range(rng.randint(1, 3)):
            roll = rng.random()
            if roll < 0.5:
                low = rng.choice(PORTS)
                high = rng.choice([low, low, min(65535, low + rng.choice([1, 5, 10]))])
                src = (1024, 65535) if rng.random() < 0.2 else None
                found.append((rng.choice(["tcp", "udp"]), (low, high), src))
            elif roll < 0.75:
                found.append(("icmp", rng.choice([8, 3, 13]) if rng.random() < 0.7 else None, None))
            else:
                found.append(("proto", rng.choice([47, 50])))
        services[f"s{index}"] = found
    groups: Dict[str, List[str]] = {}
    for index in range(rng.randint(0, 2)):
        groups[f"g{index}"] = rng.sample(list(services) + list(groups) + ["HTTP", "DNS", "PING", "ssh"], rng.randint(1, 3))
    rules: List[Dict[str, Any]] = []
    ids = rng.sample(range(1, 60), rng.randint(3, 10))
    for ident in ids:
        def side() -> List[Any]:
            roll = rng.random()
            if roll < 0.2:
                return [("any",)]
            if roll < 0.27:
                return [("any6",)]
            out: List[Any] = []
            for _ in range(rng.randint(1, 2)):
                pick = rng.random()
                if pick < 0.6:
                    out.append(("entry", rng.choice(list(entries))))
                elif pick < 0.8:
                    out.append(("net", rng.choice(NETS)))
                else:
                    out.append(("range",) + rng.choice(RANGES))
            return out

        zone_roll = rng.random()
        rule = {
            "id": ident, "src_zones": [] if zone_roll < 0.2 else rng.sample(ZONES, 1), "dst_zones": [] if rng.random() < 0.2 else rng.sample(ZONES, 1),
            "src": side(), "dst": side(), "action": rng.choice(["permit", "permit", "deny", "reject"]), "enabled": rng.random() > 0.1,
            "services": ["Any"] if rng.random() < 0.25 else rng.sample(list(services) + list(groups) + ["HTTP", "https", "PING"], rng.randint(1, 2)),
            "bad": rng.random() < 0.06, "one_line": rng.random() < 0.15,
        }  # fmt: skip
        if rule["one_line"]:
            rule["src"], rule["dst"] = rule["src"][:1], rule["dst"][:1]
            rule["src"] = [s if s[0] in ("entry", "any", "any6") else ("any",) for s in rule["src"]]
            rule["dst"] = [s if s[0] in ("entry", "any", "any6") else ("any",) for s in rule["dst"]]
            rule["services"] = rule["services"][:1]
            rule["bad"], rule["enabled"] = False, True
        if rules and rng.random() < 0.2:
            rule["place"] = "top" if rng.random() < 0.4 else (rng.choice(["before", "after"]), rng.choice(rules)["id"])
        rules.append(rule)
    moves: List[Any] = []
    for _ in range(rng.randint(0, 2)):
        rule = rng.choice(rules)
        other = rng.choice(rules)
        if other is rule:
            moves.append((rule["id"], rng.choice(["top", "bottom"])))
        else:
            moves.append((rule["id"], (rng.choice(["before", "after"]), other["id"])))
    return {"entries": entries, "services": services, "groups": groups, "rules": rules, "moves": moves, "permit": rng.random() < 0.15}


def _spec_text(spec: Any) -> str:
    if spec[0] == "net":
        net = ipaddress.ip_network(spec[1])
        if net.version == 4 and random.random() < 0.3:
            return f"ip {net.network_address} {net.netmask}"
        return f"ip {spec[1]}"
    if spec[0] == "range":
        return f"range {spec[1]} {spec[2]}"
    return f'member "{spec[1]}"'


def _service_text(entry: Any) -> str:
    if entry[0] in ("tcp", "udp"):
        low, high = entry[1]
        text = f"{entry[0]} dst-port {low}" + (f" {high}" if high != low or random.random() < 0.5 else "")
        if entry[2] is not None:
            text += f" src-port {entry[2][0]} {entry[2][1]}"
        return text
    if entry[0] == "icmp":
        return "icmp" if entry[1] is None else f"icmp type {entry[1]}" + (" code 0 5" if random.random() < 0.3 else "")
    return f"protocol {entry[1]}"


def _side_text(field: str, spec: Any) -> str:
    if spec[0] == "any":
        return f'{field}-addr "Any"'
    if spec[0] == "any6":
        return f'{field}-addr "IPv6-any"'
    if spec[0] == "entry":
        return f'{field}-addr "{spec[1]}"'
    if spec[0] == "net":
        return f"{field}-ip {spec[1]}"
    return f"{field}-range {spec[1]} {spec[2]}"


def _name_of(spec: Any) -> str:
    return {"any": "Any", "any6": "IPv6-any"}.get(spec[0], spec[1] if len(spec) > 1 else "")


def render(conf: Dict[str, Any], rng: random.Random) -> str:
    random.seed(rng.random())
    out = ["Building configuration..", 'hostname "fw"']
    for zone in ZONES:
        out += [f'zone "{zone}"', '  vrouter "trust-vr"', "exit"]
    for index, zone in enumerate(ZONES):
        out += [f"interface ethernet0/{index}", f'  zone  "{zone}"', f"  ip address 10.9.{index}.1 255.255.255.0", "exit"]
    for name, entry in conf["entries"].items():
        head = f'address "{name}"' if rng.random() < 0.7 else f'address id {rng.randint(1, 99)} "{name}"'
        out.append(head + (" ipv6" if entry["six"] else ""))
        out += ["  " + _spec_text(spec) for spec in entry["specs"]]
        out += ["  exclude " + _spec_text(spec) for spec in entry["exclude"]]
        if entry["bad"]:
            out.append(rng.choice(["  wildcard 10.0.0.1 0.0.255.0", "  country XX"]))
        out.append("exit")
    for name, found in conf["services"].items():
        out += [f'service "{name}"'] + ["  " + _service_text(entry) for entry in found] + ["exit"]
    for name, members in conf["groups"].items():
        out += [f'servgroup "{name}"'] + [f'  service "{member}"' for member in members] + ["exit"]
    out.append("policy-global")
    for rule in conf["rules"]:
        place = rule.get("place")
        where = "" if not place else " top" if place == "top" else f" {place[0]} {place[1]}"
        if rule["one_line"]:
            zones = ""
            if rule["src_zones"] and rule["dst_zones"]:
                zones = f' from-zone "{rule["src_zones"][0]}" to-zone "{rule["dst_zones"][0]}"'
            else:
                rule["src_zones"], rule["dst_zones"] = [], []
            out.append(f'  rule id {rule["id"]}{where} from "{_name_of(rule["src"][0])}" to "{_name_of(rule["dst"][0])}"{zones} '
                       f'service "{rule["services"][0]}" {rule["action"]}')  # fmt: skip
            continue
        out.append(f"  rule id {rule['id']}{where}")
        if not rule["enabled"]:
            out.append("    disable")
        out.append(f"    action {rule['action']}")
        out += [f'    src-zone "{z}"' for z in rule["src_zones"]] or (['    src-zone "Any"'] if rng.random() < 0.3 else [])
        out += [f'    dst-zone "{z}"' for z in rule["dst_zones"]]
        out += ["    " + _side_text("src", s) for s in rule["src"]]
        out += ["    " + _side_text("dst", s) for s in rule["dst"]]
        out += [f'    service "{s}"' for s in rule["services"]]
        if rule["bad"]:
            out.append(rng.choice(['    application "BitTorrent"', '    schedule "nights"', '    role "staff"']))
        out.append(f'    name "r{rule["id"]}"')
        out.append("  exit")
    for ident, where in conf["moves"]:
        out.append(f"  move {ident} " + (where if isinstance(where, str) else f"{where[0]} {where[1]}"))
    if conf["permit"]:
        out.append("  default-action permit")
    out.append("exit")
    return "\n".join(out) + "\nend\n"


def conf_packet(rng: random.Random) -> Optional[Tuple[Packet, str, str]]:
    src, dst = rng.choice(POOL), rng.choice(POOL)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if ":" in src else "icmp", "47", "50"])
    pkt = Packet("", "", src, dst, proto, rng.choice([1023, 1024, 40000]), rng.choice(PORTS), rng.choice([0, 8, 3, 13]))
    return pkt, rng.choice(ZONES), rng.choice(ZONES)


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_hillstone.parse(text.encode(), report), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def test_parsed_configurations_decide_like_the_judge() -> None:
    compared = 0
    for seed in range(250):
        rng = random.Random(seed)
        conf = random_conf(rng)
        text = render(conf, rng)
        assert cli.detect_format(text.encode()) == "hillstone", text
        model, _ = parse(text)
        judge = Judge(conf)
        by_name = {rule.name: rule for rule in model.rules}
        for rule in conf["rules"]:
            name = f"r{rule['id']}"
            if rule["bad"] and name in by_name:
                found = by_name[name]
                assert found.unsupported or found.schedule or found.users != [ANY], (seed, rule)  # (not converted as it is)
        for _ in range(300):
            found = conf_packet(rng)
            if found is None:
                continue
            pkt, ingress, egress = found
            verdict = judge.allows(pkt, ingress, egress)
            if verdict is None:
                continue
            pkt.in_if, pkt.out_if = ingress, egress
            compared += 1
            assert model_allows(model, pkt) == verdict, (seed, pkt, text, json.dumps(conf, default=str))
    assert compared > 30000


@pytest.mark.parametrize("seed", range(60))
def test_a_configuration_read_and_written_again_decides_the_same(seed: int) -> None:
    """StoneOS -> model -> StoneOS commands: the commands, read strictly, decide as the judge of the first one."""
    rng = random.Random(7000 + seed)
    conf = random_conf(rng)
    model, _ = parse(render(conf, rng))
    text, report = emit(model)
    config = StoneOS(text)
    for rule in conf["rules"]:
        name = f"r{rule['id']}" if not rule["one_line"] else f"rule {rule['id']}"
        if report.item("rule", name).disabled:
            rule["bad"] = True  # (written disabled, and said: the judge does not decide what reaches it)
    judge = Judge(conf)
    names = {zone: zone if zone in PREDEFINED_ZONES else f"FWS_{zone}" for zone in ZONES}
    for _ in range(300):
        found = conf_packet(rng)
        if found is None:
            continue
        pkt, ingress, egress = found
        verdict = judge.allows(pkt, ingress, egress)
        if verdict is None:
            continue
        assert config.allows(pkt, names[ingress], names[egress]) == verdict, (seed, pkt, text)


def test_the_parser_reads_what_the_emitter_writes() -> None:
    for seed in range(30):
        rng = random.Random(9000 + seed)
        model = zoned(random_model(rng))
        text, report = emit(model)
        back, _ = parse(text)
        assert len(back.rules) == sum(len(item.emitted_as) and int(item.emitted_as[0].split()[0]) for item in report.items.values()
                                      if item.kind == "rule" and item.emitted_as)  # fmt: skip
        config = StoneOS(text)
        for _ in range(200):
            pkt = random_packet(rng, rng.choice([4, 6]))
            ingress, egress = f"FWS_{pkt.in_if}", f"FWS_{pkt.out_if}"
            verdict = config.allows(pkt, ingress, egress)
            pkt.in_if, pkt.out_if = ingress, egress
            assert model_allows(back, pkt) == verdict, (seed, pkt, text)


# -- the sample, and what is read ------------------------------------------------------------------------------


def sample() -> Tuple[Policy, Report]:
    return parse((DATA / "hillstone_sample.conf").read_text())


def rule_named(model: Policy, name: str) -> Rule:
    return next(r for r in model.rules if r.name == name)


def verdict(model: Policy, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "trust", egress: str = "untrust",
            icmp_type: int = 0) -> bool:  # fmt: skip
    return model_allows(model, Packet(ingress, egress, src, dst, proto, 40000, dport, icmp_type))


def test_detection_and_errors() -> None:
    assert cli.detect_format((DATA / "hillstone_sample.conf").read_bytes()) == "hillstone"
    with pytest.raises(ParseError):
        parse("hostname x\nlogging on\n")
    assert not parse_hillstone.looks_like_hillstone("rule id 1\n")  # (one sign is not enough)


def test_sample_order_moves_and_names() -> None:
    model, report = sample()
    names = [r.name for r in model.rules]
    assert names[0] == "inside-ping"  # (move 14 top)
    assert names.index("lab-to-inside") == names.index("inside-to-servers") - 1  # (move 8 before 4)
    assert "rule 13" in names  # (a rule in one line, without a name)
    assert rule_named(model, "rule 13").src_zones == ["trust"] and rule_named(model, "rule 13").dst_zones == ["lab"]
    assert len(model.rules) == 14  # (the rule id 7 of policy-group is a reference, not a rule)
    assert rule_named(model, "p2p").source_ids["hillstone.rule_id"] == "7"
    assert "HILLSTONE_SOURCE" in codes(report)


def test_sample_objects() -> None:
    model, _ = sample()
    assert model.addresses["mail-srv"].value == "10.20.0.25/32"  # (address id N "name", a dotted mask)
    assert model.addresses["lab-pool"].kind == AddressKind.RANGE
    assert sorted(model.address_groups["servers"].members) == ["10.20.0.40/31", "mail-srv", "web-srv"]
    assert model.address_groups["inside-no-printers"].members == ["10.10.0.0-10.10.0.199", "10.10.0.210-10.10.0.255"]
    assert model.addresses["update-site"].kind == AddressKind.FQDN
    assert model.address_groups["wild-hosts"].unsupported and model.address_groups["blocked-country"].unsupported
    assert model.services["app-ports"].entries[0].src_ports == "1024-65535"
    assert model.services["ping-reply"].entries[0].icmp_code == 0
    assert model.services["gre-tunnel"].entries[0].ip_protocol == 47
    assert model.service_groups["admin-group"].members == ["web-group", "SSH"]  # (a predefined name in lower case)
    assert model.services["SSH"].builtin == "hillstone"
    assert model.zones["lab"].interfaces == ["ethernet0/3"]


def test_sample_rules_and_defaults() -> None:
    model, report = sample()
    assert model.default_interzone == model.default_intrazone == Action.DENY
    assert verdict(model, "10.10.0.7", "192.0.2.1", dport=443)
    assert not verdict(model, "10.10.0.7", "10.10.0.8", dport=443, egress="trust")  # (inside a zone: denied)
    assert verdict(model, "10.10.0.7", "10.10.0.8", proto="icmp", egress="trust", icmp_type=8)  # (inside-ping)
    assert rule_named(model, "lab-to-inside").action == Action.RESET_CLIENT
    assert not rule_named(model, "lab-updates").enabled
    assert rule_named(model, "app-clients").schedule == "office-hours"
    assert rule_named(model, "p2p").unsupported and rule_named(model, "to-branch-vpn").unsupported
    assert rule_named(model, "contractors-out").users == ["role contractors"]
    assert rule_named(model, "inside-to-web").log_end and rule_named(model, "block-country").log_end
    assert rule_named(model, "v6-out").destinations == ["::/0"]
    assert rule_named(model, "tunnels-to-partners").src_zones == ["lab", "dmz"]
    assert "HILLSTONE_ANY_IPV4" in {f.code for f in report.item("rule", "block-country").findings}
    assert "HILLSTONE_DNAT_INSIDE" in {f.code for f in report.item("rule", "inside-to-servers").findings}
    assert {"HILLSTONE_PREDEFINED", "HILLSTONE_SCHEDULE", "HILLSTONE_NAT_ORDER", "HILLSTONE_REJECT"} <= codes(report)


def test_sample_nat() -> None:
    model, report = sample()
    nat = {n.name: n for n in model.nat_rules}
    assert nat["dnatrule 1"].destination_translation == DestNat("web-srv", "8080")
    assert nat["dnatrule 1"].destinations == ["pub-web"] and nat["dnatrule 1"].service == "HTTP"
    assert nat["dnatrule 2"].destinations == ["203.0.113.11"] and nat["dnatrule 2"].destination_translation == DestNat("10.20.0.25")
    assert nat["dnatrule 3"].destination_translation is not None and nat["dnatrule 3"].destination_translation.spread
    assert nat["dnatrule 4"].unsupported  # (NAT64)
    assert nat["snatrule 1"].source_translation is None and not nat["snatrule 1"].unsupported  # (no-trans)
    snat2 = nat["snatrule 2"].source_translation
    assert snat2 is not None and snat2.kind == SnatKind.INTERFACE and nat["snatrule 2"].dst_zones == ["untrust"]
    snat3 = nat["snatrule 3"].source_translation
    assert snat3 is not None and snat3.kind == SnatKind.DYNAMIC_PORT and snat3.addresses == ["snat-pool"]
    assert not nat["snatrule 4"].enabled
    assert nat["bnatrule 1"].unsupported
    assert all(n.combines for n in model.nat_rules)
    order = [n.name for n in model.nat_rules if not n.name.startswith("bnat")]
    assert order == ["dnatrule 1", "dnatrule 2", "dnatrule 3", "dnatrule 4", "snatrule 1", "snatrule 2", "snatrule 3", "snatrule 4"]
    assert not model.lookup_after_dnat  # (the rules name the address before DNAT, as the model does)


BASE = """zone "trust"
exit
zone "untrust"
exit
interface ethernet0/1
  zone  "trust"
exit
interface ethernet0/2
  zone  "untrust"
exit
address "net"
  ip 10.0.0.0/24
exit
"""


def conf_text(policy: str, rest: str = "") -> str:
    return BASE + rest + "policy-global\n" + policy + "exit\n"


def test_default_action_permit_and_any_zone() -> None:
    model, _ = parse(conf_text('  rule id 1\n    action deny\n    src-addr "net"\n    dst-addr "Any"\n    service "Any"\n  exit\n'
                               "  default-action permit\n"))  # fmt: skip
    assert model.default_interzone == model.default_intrazone == Action.ALLOW
    assert model.rules[0].src_zones == [ANY] and model.rules[0].dst_zones == [ANY]
    assert not verdict(model, "10.0.0.1", "192.0.2.1", ingress="untrust", egress="trust")
    assert verdict(model, "192.0.2.1", "10.0.0.1", ingress="untrust", egress="untrust")


def test_any_is_ipv4_and_ipv6_any_is_ipv6() -> None:
    model, _ = parse(conf_text('  rule id 1\n    action permit\n    src-addr "Any"\n    dst-addr "Any"\n    service "Any"\n  exit\n'))
    assert verdict(model, "10.0.0.1", "192.0.2.1")
    assert not verdict(model, "2001:db8::1", "2001:db8::2")


def test_what_is_never_read_wider() -> None:
    text = conf_text('  rule id 1\n    action permit\n    src-addr "net"\n    dst-addr "Any"\n    service "NETBIOS-X"\n  exit\n'
                     '  rule id 2\n    action permit\n    src-addr "nobody"\n    dst-addr "Any"\n    service "Any"\n  exit\n'
                     '  rule id 3\n    action permit\n    src-addr "net"\n    dst-addr "Any"\n    service "Any"\n    qos-mode x\n  exit\n'
                     '  rule id 4\n    src-addr "net"\n    dst-addr "Any"\n    service "Any"\n  exit\n'
                     '  rule id 5\n    action webauth\n    src-addr "net"\n    dst-addr "Any"\n    service "Any"\n  exit\n')  # fmt: skip
    model, _ = parse(text)
    assert all(r.unsupported for r in model.rules), [(r.name, r.unsupported) for r in model.rules]


def test_zone_pair_policies_of_stoneos_4() -> None:
    text = BASE + 'policy from "trust" to "untrust"\n  rule id 1 from "net" to "Any" service "HTTP" permit\nexit\n' \
        'policy-global\n  rule id 2 from "Any" to "Any" service "Any" deny\nexit\n'
    model, report = parse(text)
    assert [r.src_zones for r in model.rules] == [["trust"], [ANY]] and model.rules[0].dst_zones == ["untrust"]
    assert "HILLSTONE_ZONE_PAIR" in codes(report)


def test_rule_blocks_typed_without_indentation() -> None:
    text = 'zone "trust"\nexit\naddress "net"\nip 10.0.0.0/24\nexit\npolicy-global\nrule id 1\naction permit\nsrc-zone "trust"\n' \
        'src-addr "net"\ndst-addr "Any"\nservice "HTTP"\nexit\nrule id 2 top\naction deny\nsrc-addr "Any"\ndst-addr "Any"\n' \
        'service "Any"\nexit\nexit\n'
    model, _ = parse(text)
    assert [r.name for r in model.rules] == ["rule 2", "rule 1"]
    assert model.addresses["net"].value == "10.0.0.0/24" and model.rules[1].services == ["HTTP"]


def test_exclusions_and_nesting() -> None:
    text = conf_text('  rule id 1\n    action permit\n    src-addr "a"\n    dst-addr "Any"\n    service "Any"\n  exit\n',
                     'address "b"\n  member "net"\n  exclude ip 10.0.0.128/25\nexit\naddress "a"\n  member "b"\n  member "b"\n'
                     '  range 192.0.2.1 192.0.2.3\nexit\naddress "loop"\n  member "loop"\nexit\n')  # fmt: skip
    model, _ = parse(text)
    assert verdict(model, "10.0.0.5", "192.0.2.9") and not verdict(model, "10.0.0.200", "192.0.2.9")
    assert verdict(model, "192.0.2.2", "192.0.2.9")
    assert "itself" in model.address_groups["loop"].unsupported or model.address_groups["loop"].members == ["loop"]


def test_nat_forms() -> None:
    rest = 'address "pub"\n  ip 203.0.113.5/32\nexit\nip vrouter "trust-vr"\n' \
        '  snatrule id 2 ingress-interface ethernet0/1 from "net" to "Any" service "Any" trans-to ip 203.0.113.9 mode dynamicip\n' \
        '  snatrule id 1 top from "net" to "pub" service "Any" trans-to 203.0.113.7\n' \
        '  dnatrule id 1 from "Any" to "pub" service "HTTP" trans-to ip 10.0.0.9 port 8080\n' \
        '  dnatrule id 2 from "Any" to "pub" service "Any" trans-to "10.0.0.10" evr "other-vr"\nexit\n' \
        'ip vrouter "other-vr"\n  snatrule id 1 from "Any" to "Any" service "Any" eif ethernet0/9 trans-to eif-ip mode dynamicport\nexit\n'
    model, report = parse(conf_text("", rest))
    nat = {n.name: n for n in model.nat_rules}
    assert [n.name for n in model.nat_rules] == ["dnatrule 1", "dnatrule 2", "snatrule 1", "snatrule 2", "snatrule 1-2"]
    assert nat["snatrule 2"].src_zones == ["trust"]
    snat2 = nat["snatrule 2"].source_translation
    assert snat2 is not None and snat2.kind == SnatKind.DYNAMIC
    assert "HILLSTONE_SNAT_MODE" in {f.code for f in report.item("nat", "snatrule 1").findings}
    assert nat["dnatrule 1"].destination_translation == DestNat("10.0.0.9", "8080")
    assert nat["dnatrule 2"].unsupported  # (to another virtual router)
    assert nat["snatrule 1-2"].unsupported  # (an interface in no zone)
    assert "HILLSTONE_VROUTER" in codes(report)


# -- the emitter ----------------------------------------------------------------------------------------------


def test_emitted_sample_and_where_rules_go() -> None:
    model, report = sample()
    text = cli.convert(model, "hillstone", report, Options(policy_id_start=500))
    config = StoneOS(text)
    assert config.rules[0]["id"] == "500" and config.rules[0]["name"] == "FWS_inside-ping"
    assert [r["name"] for r in config.rules if r["name"].startswith("FWS_tunnels")] == ["FWS_tunnels-to-partners_1", "FWS_tunnels-to-partners_2"]
    assert "FWS_lab" in config.zones and "\nzone \"trust\"" not in text  # (predefined zones are not created)
    assert "HILLSTONE_LOAD" in codes(report) and "HILLSTONE_ZONES" in codes(report)
    assert any(line.startswith("dnatrule id 500 ") and "port 8080" in line for line in config.dnat)
    assert any("trans-to eif-ip mode dynamicport" in line and "eif ethernet0/0" in line for line in config.snat)
    assert report.item("nat", "dnatrule 3").skipped and report.item("nat", "bnatrule 1").skipped
    assert "save" not in text.split()


def named(p: Policy) -> Policy:
    for item in list(p.rules) + list(p.nat_rules):
        item.origin = item.origin or item.name
    return p


def test_emitter_defaults_and_intrazone() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    p.zones["inside"] = Zone("inside", ["port1"])
    p.zones["outside"] = Zone("outside", ["port2"])
    p.rules.append(Rule("web", src_zones=["inside"], dst_zones=["outside"], services=["any"]))
    named(p)
    report = Report()
    text = cli.convert(p, "hillstone", report)
    config = StoneOS(text)
    assert [r["name"] for r in config.rules] == ["FWS_web", "FWS_web_v6", "FWS_intrazone_inside", "FWS_intrazone_inside_v6",
                                                 "FWS_intrazone_outside", "FWS_intrazone_outside_v6"]  # fmt: skip
    assert "INTRAZONE_RULES_ADDED" in codes(report) and "IP_VERSION_SPLIT" in codes(report)
    p.default_interzone = p.default_intrazone = Action.ALLOW
    report = Report()
    config = StoneOS(cli.convert(p, "hillstone", report))
    assert config.default_permit and "HILLSTONE_DEFAULT_PERMIT" in codes(report)


def test_emitter_ipv4_only_policy_and_what_it_cannot_write() -> None:
    p = Policy(vendor="panos")
    p.zones["a"] = Zone("a")
    p.zones["b"] = Zone("b")
    p.services["v6ping"] = Service("v6ping", [ServiceEntry(Protocol.ICMP6, icmp_type=128)])
    p.services["odd"] = Service("odd", [ServiceEntry(Protocol.ICMP, icmp_type=0)])
    p.addresses["net"] = Address("net", AddressKind.NETWORK, "10.0.0.0/24")
    p.rules.append(Rule("any-out", src_zones=["a"], dst_zones=["b"], sources=["net"], destinations=["192.0.2.0/24"]))
    p.rules.append(Rule("reply", src_zones=["a"], dst_zones=["b"], sources=["net"], destinations=["net"], services=["odd"]))
    p.rules.append(Rule("reset", src_zones=["a"], dst_zones=["b"], action=Action.RESET_BOTH, negate_destination=True, destinations=["net"]))
    named(p)
    report = Report()
    text = cli.convert(p, "hillstone", report)
    config = StoneOS(text)
    assert [r["name"] for r in config.rules] == ["FWS_any-out", "FWS_reply", "FWS_reset"]
    assert not config.rules[1]["enabled"] and report.item("rule", "reply").disabled
    assert {"REJECT_AS_DENY", "NEGATION_EXPANDED"} <= {f.code for f in report.item("rule", "reset").findings}
    assert "HILLSTONE_IPV4_ONLY" not in codes(report)  # (the allow rule names its sources)
    p.rules[0].sources = [ANY]
    report = Report()
    cli.convert(p, "hillstone", report)
    assert "HILLSTONE_IPV4_ONLY" in codes(report)
    p.rules.append(Rule("ping6", services=["v6ping"]))
    named(p)
    report = Report()
    text = cli.convert(p, "hillstone", report)
    assert report.item("rule", "ping6").disabled and "IPv6-any" in text


def test_emitter_nat() -> None:
    p = Policy(vendor="panos")
    p.zones["inside"] = Zone("inside", ["port1"])
    p.zones["outside"] = Zone("outside", ["port2"])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80")])
    p.nat_rules.append(NatRule("in", destinations=["203.0.113.5"], service="web", destination_translation=DestNat("10.0.0.5", "8080"),
                               src_zones=["outside"]))  # fmt: skip
    p.nat_rules.append(NatRule("out", sources=["10.0.0.0/24"], dst_zones=["outside"], source_translation=SourceNat(SnatKind.INTERFACE)))
    p.nat_rules.append(NatRule("pool", sources=["10.0.1.0/24"], source_translation=SourceNat(SnatKind.DYNAMIC, ["198.51.100.8-198.51.100.9"])))
    p.nat_rules.append(NatRule("exempt", sources=["10.0.2.0/24"], destinations=["192.0.2.0/24"]))
    p.nat_rules.append(NatRule("static", sources=["10.0.0.7"], source_translation=SourceNat(SnatKind.STATIC, ["203.0.113.7"], bidirectional=True)))
    named(p)
    report = Report()
    config = StoneOS(cli.convert(p, "hillstone", report))
    assert config.dnat[0].startswith("dnatrule id 10000 from \"Any\" to ") and config.dnat[0].endswith("port 8080")
    assert "HILLSTONE_NAT_ZONE" in {f.code for f in report.item("nat", "in").findings}
    assert config.snat[0].endswith("eif port2 trans-to eif-ip mode dynamicport")
    assert config.snat[1].endswith("mode dynamicip") and "HILLSTONE_NAT_ZONE" not in {f.code for f in report.item("nat", "pool").findings}
    assert config.snat[2].endswith("no-trans") and config.dnat[1].endswith("no-trans")
    assert config.snat[3].endswith("mode static") and config.dnat[2].startswith('dnatrule id 10002 from "Any" to "FWS_nat-static-outside"')


def test_emitter_names_and_prefix() -> None:
    p = Policy(vendor="panos")
    p.zones['we"ird zone'] = Zone('we"ird zone')
    p.rules.append(Rule("a rule; with words", src_zones=['we"ird zone']))
    text = cli.convert(p, "hillstone", Report(), Options(object_prefix="X-"))
    config = StoneOS(text)
    assert "X-we_ird_zone" in config.zones and config.rules[0]["name"].startswith("X-a_rule__with_words")
    with pytest.raises(FwshiftError):
        cli.convert(p, "hillstone", Report(), Options(object_prefix="1bad prefix"))


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "hillstone_sample.conf").read_bytes()
    for target in cli.VENDORS:
        report = Report()
        policy = cli.load(data, "hillstone", report)
        assert cli.convert(policy, target, report), target


def test_same_vendor_keeps_predefined_services_and_any() -> None:
    model, report = sample()
    text = cli.convert(model, "hillstone", report)
    assert 'service "HTTP"' in text and 'service "FWS_HTTP"' not in text
    assert 'src-addr "Any"' in text and 'dst-addr "IPv6-any"' in text
    back, _ = parse(text)
    assert rule_named(back, "FWS_inside-to-web").services == ["FWS_web-group", "DNS"]


def test_scope_rules_are_written_per_zone() -> None:
    p = Policy(vendor="panos")
    for zone in ("a", "b", "c"):
        p.zones[zone] = Zone(zone)
    p.rules.append(Rule("inside", src_zones=[ANY], scope=RuleScope.INTRAZONE, sources=["10.0.0.0/8"], destinations=["10.0.0.0/8"]))
    p.rules.append(Rule("between", src_zones=["a", "b"], dst_zones=["a", "b"], scope=RuleScope.INTERZONE, sources=["10.0.0.0/8"],
                        destinations=["10.0.0.0/8"]))  # fmt: skip
    config = StoneOS(cli.convert(p, "hillstone", Report()))
    pairs = [(r["src_zone"], r["dst_zone"]) for r in config.rules]
    assert pairs[:3] == [("FWS_a", "FWS_a"), ("FWS_b", "FWS_b"), ("FWS_c", "FWS_c")]
    assert pairs[3:5] == [("FWS_a", "FWS_b"), ("FWS_b", "FWS_a")]
