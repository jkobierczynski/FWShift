# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Phoenix Contact mGuard: parser, emitter, and packet-level equivalence with judges of their own.

``MGuard`` reads the gaiconfig script the emitter writes strictly, as an mGuard of the reading of Phoenix Contact's
gaiconfig User Guides would take it (a table and its fields as the guides list them, values of the documented kinds, a
group created before a field refers to it by its name, every call but the last with ``--silent``), and decides packets:
the table of the pair of zones, first match from the top, ``EXT_IF`` for the external interface, ports for tcp and udp
only, what no row matches dropped.

A random configuration profile is a plain description that ``render`` writes as an ``.atv`` file and ``Judge`` decides
packets from with the same reading (rule sets entered in place, port forwarding before the packet filter). None of it
shares code with the parser or the emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import os
import random
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows, model_verdict, random_model, random_packet

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import mguard as parse_mguard
from fwshift.report import Report, Severity

# -- the reader of the emitted script --------------------------------------------------------------------------------

RULE_FIELDS = ["PROTO", "FROM_IP", "FROM_PORT", "IN_IP", "IN_PORT", "TARGET_REF", "LOG", "COMMENT"]
FIELDS = {
    "FW_INCOMING": ["EXT_IF"] + RULE_FIELDS, "FW_OUTGOING": RULE_FIELDS, "FW_INCOMING_WAN_DMZ": RULE_FIELDS,
    "FW_INCOMING_DMZ_LAN": RULE_FIELDS, "FW_OUTGOING_DMZWAN": RULE_FIELDS, "FW_OUTGOING_LANDMZ": RULE_FIELDS,
    "FW_PORTFORWARDING": ["PROTO", "SRC_IP", "SRC_PORT", "IN_IP", "IN_PORT", "OUT_IP", "OUT_PORT", "LOG", "COMMENT"],
    "FW_1TO1_NAT": ["LOCAL_NET", "REMOTE_NET", "MASK", "ENABLE_ARP", "COMMENT"],
    "FW_NAT": ["EXT_IF", "IN_IP", "COMMENT"],
    "FW_GROUP_IP": ["NAME", "COMMENT"], "FW_GROUP_PORT": ["NAME", "COMMENT"],
}  # fmt: skip
# The table of each pair of zones (the manual: incoming WAN -> LAN, outgoing LAN -> WAN, the four DMZ directions).
TABLE = {("external", "internal"): "FW_INCOMING", ("internal", "external"): "FW_OUTGOING", ("external", "dmz"): "FW_INCOMING_WAN_DMZ",
         ("dmz", "internal"): "FW_INCOMING_DMZ_LAN", ("dmz", "external"): "FW_OUTGOING_DMZWAN", ("internal", "dmz"): "FW_OUTGOING_LANDMZ"}  # fmt: skip
IP_FIELDS = {"FROM_IP", "IN_IP", "SRC_IP"}
PORT_FIELDS = {"FROM_PORT", "IN_PORT", "SRC_PORT"}
NUMBERS = {"tcp": "6", "udp": "17", "icmp": "1", "gre": "47"}


def v4(text: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(text, strict=False)


def port_ok(text: str) -> bool:
    return text == "any" or bool(re.fullmatch(r"\d{1,5}(:\d{1,5})?", text)) and all(int(p) <= 65535 for p in text.split(":"))


class MGuard:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tables: Dict[str, List[Dict[str, Any]]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}  # name -> row
        self.checked: Set[Tuple[str, str]] = set()  # (table, name) the script makes sure are free
        env: Dict[str, int] = {}
        calls: List[List[str]] = []
        assert text.startswith("#!/bin/sh\n") and "\nset -u\n" in text
        for line in text.splitlines():
            found = re.fullmatch(r"named (FW_GROUP_IP|FW_GROUP_PORT) (\S+) && fail .*", line)
            if found:
                self.checked.add((found.group(1), shlex.split(found.group(2))[0]))
                continue
            found = re.fullmatch(r"(\w+)=\$\(rows (\w+)\)", line)
            if found:
                env[found.group(1)] = len(self.tables.get(found.group(2), []))
                continue
            found = re.fullmatch(r"(\w+)=\$\(\((\w+)\+1\)\)", line)
            if found:
                env[found.group(1)] = env[found.group(2)] + 1
                continue
            if line.startswith("gc "):
                args = [re.sub(r"\$(\w+)", lambda m: str(env[m.group(1)]), a) for a in shlex.split(line[3:])]
                calls.append(args)
                self._call(args)
        assert calls, text
        assert all("--silent" in c for c in calls[:-1]) and "--silent" not in calls[-1], "every call but the last is silent"
        if any(self.tables.get(t) for t in FIELDS if not t.startswith("FW_GROUP")):
            assert re.search(r"^for t in [A-Z0-9_ ]+; do$", text, re.MULTILINE), "the tables are checked before anything is written"
        self._validate()

    def _call(self, args: List[str]) -> None:
        current: Optional[Dict[str, Any]] = None
        path = ""
        i = 0
        while i < len(args):
            option = args[i]
            if option == "--silent":
                i += 1
            elif option == "--goto":
                path, i = args[i + 1], i + 2
            elif option == "--add-row":
                parts = path.split(".")
                if len(parts) == 1:
                    assert path in FIELDS, path
                    current = {"fields": {}, "refs": {}, "entries": []}
                    self.tables.setdefault(path, []).append(current)
                else:
                    table, index, sub = parts
                    assert table in ("FW_GROUP_IP", "FW_GROUP_PORT") and sub == "ENTRY", path
                    parent = self.tables[table][int(index)]
                    current = {"fields": {}, "entry_of": table}
                    parent["entries"].append(current)
                i += 1
            elif option == "--set":
                name, value = args[i + 1], args[i + 2]
                assert name.startswith(".") and current is not None, args
                field = name[1:]
                if "entry_of" in current:
                    assert field == ("IP" if current["entry_of"] == "FW_GROUP_IP" else "PORT"), field
                else:
                    table = path.split(".")[0]
                    assert field in FIELDS[table], (table, field)
                assert field not in current["fields"], f"{field} given twice"
                current["fields"][field] = value
                if field == "NAME":
                    table = path.split(".")[0]
                    assert (table, value) in self.checked, f"the script does not check that {value} is free"
                    assert value.lower() not in {n.lower() for n in self.groups}, f"group {value} twice"
                    assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", value), value
                    self.groups[value] = dict(current, table=table)
                    self.groups[value] = current
                    current["table"] = table
                i += 3
            elif option == "--set-refname":
                target, group = args[i + 1], args[i + 2]
                table, index, field = target.split(".")
                row = self.tables[table][int(index)]
                assert group in self.groups, f"{group} does not exist when {target} refers to it"
                kind = self.groups[group]["table"]
                assert (field in IP_FIELDS and kind == "FW_GROUP_IP") or (field in PORT_FIELDS and kind == "FW_GROUP_PORT"), (field, kind)
                row["refs"][field] = group
                i += 3
            else:
                raise AssertionError(f"option {option} is not one the script may use")

    def _validate(self) -> None:
        for table, rows in self.tables.items():
            for row in rows:
                portless = table == "FW_PORTFORWARDING" and row["fields"].get("PROTO") == "gre"
                missing = [f for f in FIELDS[table] if f not in row["fields"] and not (portless and f in ("SRC_PORT", "IN_PORT", "OUT_PORT"))]
                assert not missing, (table, missing, row)
                fields = row["fields"]
                if table.startswith("FW_GROUP"):
                    assert row["entries"], f"group {fields['NAME']} has no entries"
                    for entry in row["entries"]:
                        value = entry["fields"]["IP" if table == "FW_GROUP_IP" else "PORT"]
                        if table == "FW_GROUP_PORT":
                            assert re.fullmatch(r"\d+(-\d+)?", value), value
                        elif "-" in value and not re.search(r"[a-z]", value):
                            a, b = value.split("-")
                            assert ipaddress.IPv4Address(a) < ipaddress.IPv4Address(b), value
                        elif not re.search(r"[a-z]", value):
                            v4(value)
                    continue
                for name, value in fields.items():
                    if name in IP_FIELDS and name not in row["refs"]:
                        assert value == "%extern" and table == "FW_PORTFORWARDING" and name == "IN_IP" or v4(value), value
                        assert value != "0.0.0.0/32", f"{table} {name}: a placeholder without a reference"
                    if name in PORT_FIELDS and name not in row["refs"]:
                        assert port_ok(value), (name, value)
                if table in TABLE.values():
                    assert fields["PROTO"] in ("tcp", "udp", "icmp", "gre", "all"), fields
                    assert fields["TARGET_REF"] in ("ACCEPT", "DROP", "REJECT") and fields["LOG"] in ("yes", "no")
                    if fields["PROTO"] not in ("tcp", "udp"):
                        assert fields["FROM_PORT"] == fields["IN_PORT"] == "any" and not set(row["refs"]) & PORT_FIELDS, fields
                if table == "FW_INCOMING":
                    assert fields["EXT_IF"] in ("ext1", "ext2", "all")
                if table == "FW_PORTFORWARDING":
                    assert fields["PROTO"] in ("tcp", "udp", "gre")
                    assert fields["PROTO"] == "gre" or (fields["IN_PORT"].isdigit() and fields["OUT_PORT"].isdigit())
                    assert fields["PROTO"] != "gre" or not {"SRC_PORT", "IN_PORT", "OUT_PORT"} & set(fields)
                    ipaddress.IPv4Address(fields["OUT_IP"])
                if table == "FW_NAT":
                    assert fields["EXT_IF"] in ("ext1", "ext2", "dmz0", "int", "all")

    # -- deciding ------------------------------------------------------------------------------------------------

    def _ip(self, row: Dict[str, Any], name: str, address: str) -> bool:
        if name in row["refs"]:
            group = self.groups[row["refs"][name]]
            for entry in group["entries"]:
                value = entry["fields"]["IP"]
                if re.search(r"[a-z]", value):
                    continue  # (a host name: no address of the tests)
                if "-" in value:
                    a, b = value.split("-")
                    if ipaddress.IPv4Address(a) <= ipaddress.IPv4Address(address) <= ipaddress.IPv4Address(b):
                        return True
                elif ipaddress.IPv4Address(address) in v4(value):
                    return True
            return False
        return ipaddress.IPv4Address(address) in v4(row["fields"][name])

    def _port(self, row: Dict[str, Any], name: str, port: int) -> bool:
        if name in row["refs"]:
            for entry in self.groups[row["refs"][name]]["entries"]:
                low, _, high = entry["fields"]["PORT"].partition("-")
                if int(low) <= port <= int(high or low):
                    return True
            return False
        value = row["fields"][name]
        if value == "any":
            return True
        low, _, high = value.partition(":")
        return int(low) <= port <= int(high or low)

    def allows(self, pkt: Packet, src: str, dst: str) -> bool:
        table = TABLE.get((src, dst))
        if table is None:
            return False
        for row in self.tables.get(table, []):
            fields = row["fields"]
            if table == "FW_INCOMING" and fields["EXT_IF"] != "all" and fields["EXT_IF"] != {"external": "ext1", "external2": "ext2"}[src]:
                continue
            proto = fields["PROTO"]
            if proto != "all" and NUMBERS[proto] != NUMBERS.get(pkt.proto, pkt.proto):
                continue
            if not self._ip(row, "FROM_IP", pkt.src) or not self._ip(row, "IN_IP", pkt.dst):
                continue
            if proto in ("tcp", "udp") and not (self._port(row, "FROM_PORT", pkt.sport) and self._port(row, "IN_PORT", pkt.dport)):
                continue
            return bool(fields["TARGET_REF"] == "ACCEPT")
        return False


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    report = Report()
    return cli.convert(model, "mguard", report, options or Options()), report


# -- random models through the emitter --------------------------------------------------------------------------------

ZMAP = {"eth0": "internal", "eth1": "external", "eth2": "dmz"}


def _matches(model: Policy, rule: Rule, pkt: Packet) -> bool:
    one = copy.copy(model)
    one.rules = [dataclass_copy(rule, enabled=True)]
    return model_verdict(one, pkt) is not None


def dataclass_copy(rule: Rule, **changes: Any) -> Rule:
    out = copy.deepcopy(rule)
    for key, value in changes.items():
        setattr(out, key, value)
    return out


def flagged(report: Report, rule: Rule) -> bool:
    item = report.item("rule", rule.origin)
    return (item.skipped and any(f.severity == Severity.REVIEW for f in item.findings)) or any(f.severity >= Severity.APPROX for f in item.findings)


def compare(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> Tuple[int, int]:
    """The script against the model, IPv4 between two zones: equal, or a rule that decides it is flagged."""
    config = MGuard(text)
    same = differ = 0
    for _ in range(packets):
        pkt = random_packet(rng, 4)
        if pkt.in_if == pkt.out_if:
            continue  # (inside one zone: not forwarded, or between VLANs of the internal side)
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 0, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        got = config.allows(pkt, ZMAP[pkt.in_if], ZMAP[pkt.out_if])
        want = model_allows(model, pkt)
        if got == want:
            same += 1
            continue
        excused = False
        for rule in model.rules:
            loose = dataclass_copy(rule, services=[ANY], negate_service=False)  # (a row written for all of ICMP, or a protocol left out)
            if flagged(report, rule) and _matches(model, loose, pkt):
                excused = True
            if rule.enabled and _matches(model, rule, pkt):
                break
        assert excused, (seed, pkt, got, want, text)
        differ += 1
    return same, differ


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = random_model(rng)
    for zone in ZMAP:
        model.zones[zone] = Zone(zone)
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW
    text, report = emit(model, Options(zone_map=dict(ZMAP)))
    same, differ = compare(model, report, text, rng, seed)
    assert same > differ, (seed, same, differ)  # (most packets are decided alike; the rest by a rule the report flags)


# -- random configuration profiles -------------------------------------------------------------------------------------

POOL = ["192.168.1.5", "192.168.1.9", "192.168.1.130", "192.168.2.20", "172.16.0.7", "198.51.100.4", "198.51.100.77", "203.0.113.9"]
NETS = ["192.168.1.0/24", "192.168.1.128/25", "192.168.2.0/24", "172.16.0.0/16", "198.51.100.0/24", "198.51.100.64/26", "192.168.1.5/32"]
PORTS = [22, 53, 80, 102, 161, 443, 502, 8443, 20005, 47808]
GROUPS = {"cell": ["192.168.1.0/25", "192.168.2.16-192.168.2.40"], "remote": ["198.51.100.0/26", "203.0.113.9"]}
PORT_GROUPS = {"web": ["80", "443"], "high": ["20000-20010", "8443"]}
SERVICES = {"ssh": 22, "domain": 53, "http": 80, "snmp": 161, "https": 443}


def _in_spec(address: str, spec: Tuple[str, str]) -> bool:
    kind, value = spec
    if kind == "group":
        for entry in GROUPS[value]:
            if "-" in entry:
                a, b = entry.split("-")
                if ipaddress.IPv4Address(a) <= ipaddress.IPv4Address(address) <= ipaddress.IPv4Address(b):
                    return True
            elif ipaddress.IPv4Address(address) in v4(entry):
                return True
        return False
    return ipaddress.IPv4Address(address) in v4(value)


def _port_in_spec(port: int, spec: Tuple[str, str]) -> bool:
    kind, value = spec
    if kind == "any":
        return True
    if kind == "group":
        return any(int(e.split("-")[0]) <= port <= int(e.split("-")[-1]) for e in PORT_GROUPS[value])
    if kind == "name":
        return port == SERVICES[value]
    low, _, high = value.partition(":")
    return int(low) <= port <= int(high or low)


def _row_matches(row: Dict[str, Any], pkt: Packet) -> bool:
    proto = row["proto"]
    if proto != "all" and NUMBERS[proto] != NUMBERS.get(pkt.proto, pkt.proto):
        return False
    if not _in_spec(pkt.src, row["src"]) or not _in_spec(pkt.dst, row["dst"]):
        return False
    return proto not in ("tcp", "udp") or (_port_in_spec(pkt.sport, row["sport"]) and _port_in_spec(pkt.dport, row["dport"]))


class Judge:
    """What the device does with a packet that opens a connection, from the description of a random profile."""

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.conf = conf

    def allows(self, pkt: Packet, src: str, dst: str) -> bool:
        for forward in self.conf["forwards"]:
            if src == "external" and dst == forward["zone"] and NUMBERS[forward["proto"]] == NUMBERS.get(pkt.proto, pkt.proto) \
                    and _in_spec(pkt.src, forward["src"]) and pkt.dst == forward["in_ip"] \
                    and (forward["proto"] == "gre" or pkt.dport == forward["in_port"]):
                return True  # (port forwarding skips the packet filter)
        table = TABLE.get((src, dst))
        if table is None:
            return False
        if table in ("FW_INCOMING", "FW_OUTGOING"):
            mode = self.conf["global"][table]
            if mode == "accept":
                return True
            if mode == "drop":
                return False
            if mode == "ping":
                return pkt.proto == "icmp" and pkt.icmp_type == 8
        for row in self.conf["tables"].get(table, []):
            if not _row_matches(row, pkt):
                continue
            if row["action"] in ("ACCEPT", "DROP", "REJECT"):
                return bool(row["action"] == "ACCEPT")
            ruleset = self.conf["rulesets"][row["action"]]
            if ruleset["state"] != "active":
                continue  # (no influence)
            for inner in ruleset["rows"]:
                if _row_matches(inner, pkt):
                    return bool(inner["action"] == "ACCEPT")
        return False


def random_conf(rng: random.Random, nat: bool = True) -> Dict[str, Any]:
    def address(narrow: bool = True) -> Tuple[str, str]:
        roll = rng.random()
        if roll < 0.3 or not narrow:
            return ("lit", "0.0.0.0/0")
        if roll < 0.5:
            return ("group", rng.choice(list(GROUPS)))
        return ("lit", rng.choice(NETS + POOL))

    def port() -> Tuple[str, str]:
        roll = rng.random()
        if roll < 0.4:
            return ("any", "any")
        if roll < 0.55:
            return ("group", rng.choice(list(PORT_GROUPS)))
        if roll < 0.7:
            return ("name", rng.choice(list(SERVICES)))
        if roll < 0.85:
            low = rng.choice(PORTS)
            return ("lit", f"{low}:{low + rng.choice([0, 10, 400])}")
        return ("lit", str(rng.choice(PORTS)))

    def row(src_any: bool = False) -> Dict[str, Any]:
        proto = rng.choice(["tcp", "tcp", "udp", "icmp", "gre", "all"])
        return {"proto": proto, "src": address(not src_any), "dst": address(), "sport": port() if rng.random() < 0.2 else ("any", "any"),
                "dport": port(), "action": rng.choice(["ACCEPT", "ACCEPT", "DROP", "REJECT"]), "ext_if": rng.choice(["ext1", "all"])}  # fmt: skip

    rulesets: Dict[str, Dict[str, Any]] = {}
    for index in range(rng.randint(0, 2)):
        rulesets[f"set{index}"] = {"state": rng.choice(["active", "active", "inactive", "disabled"]),
                                    "rows": [row(src_any=True) for _ in range(rng.randint(0, 3))]}  # fmt: skip
    tables: Dict[str, List[Dict[str, Any]]] = {}
    for table in TABLE.values():
        if rng.random() < 0.35 and table not in ("FW_INCOMING", "FW_OUTGOING"):
            continue
        rows = [row() for _ in range(rng.randint(0, 6))]
        for entering in rows:
            if rulesets and rng.random() < 0.25:
                entering.update(proto="all", dst=("lit", "0.0.0.0/0"), sport=("any", "any"), dport=("any", "any"), action=rng.choice(list(rulesets)))
        tables[table] = rows
    forwards: List[Dict[str, Any]] = []
    if nat:
        for index in range(rng.randint(0, 2)):
            proto = rng.choice(["tcp", "udp", "gre"])
            forwards.append({"proto": proto, "src": address(), "in_ip": "203.0.113.2" if index == 0 else "203.0.113.9",
                             "in_port": rng.choice(PORTS), "out_ip": rng.choice(["192.168.1.9", "172.16.0.7"]),
                             "out_port": rng.choice(PORTS)})  # fmt: skip
            forwards[-1]["zone"] = "dmz" if forwards[-1]["out_ip"].startswith("172.") else "internal"
    glob = {t: rng.choice(["rules", "rules", "rules", "accept", "drop", "ping"]) for t in ("FW_INCOMING", "FW_OUTGOING")}
    return {"rulesets": rulesets, "tables": tables, "forwards": forwards, "global": glob}


def _value(spec: Tuple[str, str], rids: Dict[str, str], ref: bool) -> str:
    kind, value = spec
    if kind == "group":
        return f'{{\n  rowref = "{rids[value]}"\n}}' if ref else f'"{value}"'
    return f'"{value}"'


def render(conf: Dict[str, Any], rng: random.Random) -> str:
    rids: Dict[str, str] = {}
    counter = [100]

    def rid(name: str) -> str:
        counter[0] += 1
        rids[name] = f"MAI{counter[0]:010d}"
        return rids[name]

    out = ["#version 10.4.1.default", "// random profile of the tests", 'NETWORKMODE = "router"', 'ROUTER_MODE = "static"',
           'MY_LOCAL_IP = "192.168.1.1"', 'MY_LOCAL_NET = "255.255.255.0"', 'MY_ROUTER_IP = "203.0.113.2"', 'MY_ROUTER_NET = "255.255.255.0"',
           'DMZ_ALIASES = {', '  {', '    DMZ_IP = "172.16.0.1"', '    DMZ_NET = "255.255.0.0"', '  }', '}']  # fmt: skip
    for table, mode in conf["global"].items():
        out.append(f'{table}_GLOBAL = "{mode}"')
    out.append("FW_GROUP_IP = {")
    for name, entries in GROUPS.items():
        out += ["  {", f'    {{ rid = "{rid(name)}" }}', f'    NAME = "{name}"', '    COMMENT = ""', "    ENTRY = {"]
        out += [f'      {{\n        IP = "{e}"\n      }}' for e in entries]
        out += ["    }", "  }"]
    out += ["}", "FW_GROUP_PORT = {"]
    for name, entries in PORT_GROUPS.items():
        out += ["  {", f'    {{ rid = "{rid(name)}" }}', f'    NAME = "{name}"', "    ENTRY = {"]
        out += [f'      {{ PORT = "{e}" }}' for e in entries]
        out += ["    }", "  }"]
    out.append("}")

    def row_lines(row: Dict[str, Any], table: str, indent: str) -> List[str]:
        ref = rng.random() < 0.7
        lines = [indent + "{"]
        if table == "FW_INCOMING":
            lines.append(f'{indent}  EXT_IF = "{row["ext_if"]}"')
        sport = row["sport"][1] if row["sport"][0] != "group" else row["sport"]
        dport = row["dport"][1] if row["dport"][0] != "group" else row["dport"]
        lines += [f'{indent}  PROTO = "{row["proto"]}"', f'{indent}  FROM_IP = {_value(row["src"], rids, ref)}',
                  f'{indent}  FROM_PORT = {_value(sport, rids, ref) if isinstance(sport, tuple) else chr(34) + sport + chr(34)}',
                  f'{indent}  IN_IP = {_value(row["dst"], rids, ref)}',
                  f'{indent}  IN_PORT = {_value(dport, rids, ref) if isinstance(dport, tuple) else chr(34) + dport + chr(34)}']  # fmt: skip
        if row["action"] in conf["rulesets"]:
            lines.append(f'{indent}  TARGET_REF = {{ rowref = "{rids[row["action"]]}" }}' if ref else f'{indent}  TARGET_REF = "{row["action"]}"')
        else:
            lines.append(f'{indent}  TARGET_REF = "{row["action"]}"')
        lines += [f'{indent}  COMMENT = "a \\"quoted\\" comment"', f'{indent}  LOG = "{rng.choice(["yes", "no"])}"', indent + "}"]
        return lines

    out.append("FW_RULESETS = {")
    for name, ruleset in conf["rulesets"].items():
        out += ["  {", f'    {{ rid = "{rid(name)}" }}', f'    FRIENDLY_NAME = "{name}"', f'    SET_ACTIVE = "{ruleset["state"]}"',
                '    CONTROL = "none"', '    TIMEOUT = "0"', "    SET = {"]  # fmt: skip
        for inner in ruleset["rows"]:
            out += row_lines(inner, "SET", "      ")
        out += ["    }", "  }"]
    out.append("}")
    for table, rows in conf["tables"].items():
        out.append(f"{table} = {{")
        for row in rows:
            out += row_lines(row, table, "  ")
        out.append("}")
    if conf["forwards"]:
        out.append("FW_PORTFORWARDING = {")
        for forward in conf["forwards"]:
            in_ip = "%extern" if forward["in_ip"] == "203.0.113.2" else forward["in_ip"]
            out += ["  {", f'    PROTO = "{forward["proto"]}"', f'    SRC_IP = {_value(forward["src"], rids, True)}', '    SRC_PORT = "any"',
                    f'    IN_IP = "{in_ip}"', f'    IN_PORT = "{forward["in_port"]}"', f'    OUT_IP = "{forward["out_ip"]}"',
                    f'    OUT_PORT = "{forward["out_port"]}"', '    COMMENT = ""', '    LOG = "no"', "  }"]  # fmt: skip
        out.append("}")
    return "\n".join(out) + "\n"


def conf_packet(rng: random.Random) -> Tuple[Packet, str, str]:
    src, dst = rng.sample(["internal", "external", "dmz"], 2)
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47"])
    pkt = Packet(src, dst, rng.choice(POOL), rng.choice(POOL + ["203.0.113.2"]), proto, rng.choice([1024, 40000, 80]),
                 rng.choice(PORTS + [8000, 20003]), rng.choice([0, 8]))  # fmt: skip
    return pkt, src, dst


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_mguard.parse(text.encode("utf-8"), report), report


@pytest.mark.parametrize("seed", range(30))
def test_parsed_profiles_decide_like_the_judge(seed: int) -> None:
    rng = random.Random(1000 + seed)
    conf = random_conf(rng)
    text = render(conf, rng)
    model, _ = parse(text)
    assert not [r.name for r in model.rules if r.unsupported], text
    judge = Judge(conf)
    for _ in range(400):
        pkt, src, dst = conf_packet(rng)
        assert model_allows(model, pkt) == judge.allows(pkt, src, dst), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(20))
def test_a_profile_read_and_written_again_decides_the_same(seed: int) -> None:
    rng = random.Random(5000 + seed)
    conf = random_conf(rng)
    for table in conf["global"]:
        if conf["global"][table] == "ping":
            conf["global"][table] = "rules"  # (an ICMP type cannot be written: tested elsewhere)
    text = render(conf, rng)
    model, report = parse(text)
    script = cli.convert(model, "mguard", report)
    config = MGuard(script)
    judge = Judge(conf)
    forwarded = {(f["in_ip"], f["in_port"]) for f in conf["forwards"]}
    for _ in range(400):
        pkt, src, dst = conf_packet(rng)
        if pkt.dst in {"203.0.113.2", "203.0.113.9"} and src == "external":
            if any(pkt.dst == ip for ip, _ in forwarded):
                continue  # (port forwarding: the reader decides the packet filter only; see test_emitter_port_forwarding)
        assert config.allows(pkt, src, dst) == judge.allows(pkt, src, dst), (seed, pkt, text, script)


# -- the sample ----------------------------------------------------------------------------------------------------------


def sample() -> Tuple[Policy, Report]:
    return parse((DATA / "mguard_sample.atv").read_text(encoding="utf-8"))


def rule_named(model: Policy, name: str) -> Rule:
    return next(r for r in model.rules if r.name == name)


def codes(report: Report) -> Set[str]:
    return {f.code for f in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def test_detection() -> None:
    data = (DATA / "mguard_sample.atv").read_bytes()
    assert parse_mguard.looks_like_mguard(data) and cli.detect_format(data) == "mguard"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != "mguard_sample.atv":
            assert not parse_mguard.looks_like_mguard(path.read_bytes()), path.name
    assert not parse_mguard.looks_like_mguard(b'#version 1.2.3\nfoo = "x"\n')
    with pytest.raises(ParseError):
        parse('#version 8.6.1.default\nFW_INCOMING = {\n  {\n    PROTO = "tcp\n')
    with pytest.raises(ParseError):
        parse("#version 8.6.1.default\nFW_INCOMING = { ; }\n")
    with pytest.raises(ParseError):
        parse('HOSTNAME = "x"\n')


def test_the_file_syntax() -> None:
    pragmas, variables = parse_mguard.read_profile(
        '#version 10.5.0.default\n// a comment\nA = "x \\"y\\" \\\\ z"\nB = {\n  value = "on"\n  uuid = "u"\n}\n'
        'T = {\n  {\n    { rid = "R1" }\n    F = { rowref = "R2" }\n    N = {\n      { G = "1" }\n    }\n  }\n}\nA = "later"\n'
    )
    assert pragmas == {"version": "10.5.0.default"}
    assert variables["A"].text == "later" and variables["B"].text == "on"
    rows = variables["T"].rows
    assert rows is not None and rows[0].rid == "R1" and rows[0].items["F"].ref == "R2"
    nested = rows[0].items["N"].rows
    assert nested is not None and nested[0].items["G"].text == "1"
    assert parse_mguard.read_profile('A = "a\\nb"')[1]["A"].text == "a\\nb"  # (only a quote and a backslash are escaped)


def test_sample_zones_order_and_rules() -> None:
    model, report = sample()
    assert list(model.zones) == ["internal", "external", "dmz"] and model.vendor == "mguard"
    names = [r.name for r in model.rules]
    assert names[:2] == ["portforward-1", "portforward-2"]  # (port forwarding skips the packet filter: first)
    assert names.index("incoming-1") < names.index("outgoing-1") < names.index("wan-dmz-1") < names.index("lan-dmz-1")
    first = rule_named(model, "incoming-1")
    assert first.sources == ["scada"] and first.destinations == ["plc_cell1"] and first.action == Action.ALLOW and first.log_end
    assert first.src_zones == ["external"] and first.dst_zones == ["internal"]
    assert model.services[first.services[0]].entries == [ServiceEntry(Protocol.TCP, "502")]
    assert first.description == 'Modbus/TCP from "SCADA" to the PLCs'
    assert rule_named(model, "incoming-3").action == Action.DROP
    assert rule_named(model, "incoming-4").action == Action.RESET_BOTH
    assert model.services[rule_named(model, "incoming-4").services[0]].entries == [ServiceEntry(Protocol.UDP, "161")]
    assert model.services[rule_named(model, "incoming-7").services[0]].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    web = model.services[rule_named(model, "outgoing-3").services[0]]
    assert web.entries == [ServiceEntry(Protocol.TCP, "80,443")]
    assert rule_named(model, "outgoing-1").dst_zones == ["external", "internal"]  # (LOCAL_ALIASES: VLANs are routed)
    assert "MGUARD_INTERNAL_ROUTED" in codes(report)
    assert rule_named(model, "incoming-9").unsupported
    assert model.default_interzone == Action.DENY and model.default_intrazone == Action.DENY


def test_sample_groups_and_rule_sets() -> None:
    model, report = sample()
    assert model.address_groups["plc_cell1"].members == ["192.168.10.20-192.168.10.29", "192.168.10.40"]
    assert model.addresses["historian.example.com"].kind == AddressKind.FQDN
    assert model.addresses["historian.example.com"].fqdn_family == 4
    switched = rule_named(model, "incoming-5.maintenance-1")
    assert switched.unsupported and "MGUARD_RULESET_SWITCHED" in {f.code for f in report.item("rule", switched.origin).findings}
    vendor = [r for r in model.rules if r.name.startswith("incoming-6.vendor")]
    assert [r.action for r in vendor] == [Action.ALLOW, Action.DROP]
    assert all(r.sources == ["vendor_vpn"] for r in vendor)  # (the rule that enters the set limits its rules)
    assert model.services[vendor[0].services[0]].entries == [ServiceEntry(Protocol.TCP, "102,20000-20010")]
    assert not any(r.name in ("incoming-5", "incoming-6") for r in model.rules)


def test_sample_nat() -> None:
    model, report = sample()
    nats = {n.name: n for n in model.nat_rules}
    assert set(nats) == {"portforward-1", "portforward-2", "1to1-1", "masquerade-1", "masquerade-2"}
    forward = nats["portforward-1"]
    assert forward.destinations == ["mguard-extern"] and model.addresses["mguard-extern"].value == "203.0.113.2"
    assert forward.destination_translation == DestNat("192.168.10.30", "443") and forward.dst_zones == ["internal"]
    assert nats["portforward-2"].dst_zones == ["dmz"] and nats["portforward-2"].destination_translation == DestNat("172.16.30.20", "")
    one = nats["1to1-1"]
    assert one.sources == ["192.168.10.48/29"] and one.source_translation == SourceNat(SnatKind.STATIC, ["203.0.113.8/29"], bidirectional=True)
    assert nats["masquerade-2"].dst_zones == ["internal"] and nats["masquerade-1"].source_translation is not None
    assert nats["masquerade-1"].source_translation.interface_address == "203.0.113.2"
    # 1:1 NAT: the incoming rules name the real address; the model names the address as it arrives.
    assert rule_named(model, "incoming-8").destinations == ["192.168.10.50", "203.0.113.10"] and model.lookup_after_dnat
    assert rule_named(model, "outgoing-4").destinations == ["192.168.10.0/24"]  # (not from the external side)
    forward_rule = rule_named(model, "portforward-1")
    assert parse_mguard.FORWARD_TAG in forward_rule.tags and forward_rule.action == Action.ALLOW


def test_sample_notes() -> None:
    _, report = sample()
    found = codes(report)
    assert {"MGUARD_USER_FIREWALL", "MGUARD_VPN_FIREWALL", "MGUARD_MANAGEMENT_ACCESS", "MGUARD_PORTS_IGNORED", "MGUARD_HOSTNAME",
            "MGUARD_DEFAULT_LOG", "MGUARD_SOURCE", "MGUARD_IPV4_ONLY"} <= found  # fmt: skip


BASE = '#version 8.6.1.default\nNETWORKMODE = "{mode}"\nMY_ROUTER_IP = "203.0.113.2"\n'
ROW = '{{\n PROTO = "{proto}"\n FROM_IP = "{src}"\n FROM_PORT = "any"\n IN_IP = "0.0.0.0/0"\n IN_PORT = "{port}"\n TARGET_REF = "{action}"\n LOG = "no"\n COMMENT = ""\n}}'


def profile(body: str, mode: str = "router") -> Tuple[Policy, Report]:
    return parse(BASE.format(mode=mode) + body)


def test_global_settings() -> None:
    rows = "FW_INCOMING = {\n" + ROW.format(proto="tcp", src="0.0.0.0/0", port="22", action="ACCEPT") + "\n}\n"
    model, report = profile('FW_INCOMING_GLOBAL = "accept"\n' + rows)
    assert [r.name for r in model.rules] == ["incoming-global", "incoming-1"]
    assert model.rules[0].action == Action.ALLOW and not model.rules[1].enabled
    model, _ = profile('FW_INCOMING_GLOBAL = "ping"\n' + rows)
    assert [r.action for r in model.rules if r.enabled] == [Action.ALLOW, Action.DROP]
    assert model.services[model.rules[0].services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    model, _ = profile('FW_INCOMING_GLOBAL = "drop"\n' + rows)
    assert model.rules[0].action == Action.DROP and not model.rules[1].enabled
    model, _ = profile(rows)
    assert [r.name for r in model.rules] == ["incoming-1"] and model.rules[0].enabled


def test_what_is_never_read_wider() -> None:
    rows = ("FW_INCOMING = {\n" + ROW.format(proto="sctp", src="0.0.0.0/0", port="any", action="ACCEPT") + "\n"
            + ROW.format(proto="tcp", src="2001:db8::/32", port="any", action="ACCEPT") + "\n"
            + ROW.format(proto="tcp", src="0.0.0.0/0", port="nosuchservice", action="ACCEPT") + "\n"
            + ROW.format(proto="tcp", src="0.0.0.0/0", port="80", action="MAYBE") + "\n}\n")  # fmt: skip
    model, report = profile(rows)
    assert all(r.unsupported for r in model.rules), [(r.name, r.unsupported) for r in model.rules]
    assert "MGUARD_UNREAD" in codes(report)
    extra = "FW_OUTGOING = {\n{\n PROTO = \"all\"\n FROM_IP = \"0.0.0.0/0\"\n FROM_PORT = \"any\"\n IN_IP = \"0.0.0.0/0\"\n" \
            " IN_PORT = \"any\"\n TARGET_REF = \"ACCEPT\"\n FROM_MAC = \"00:00:00:00:00:00\"\n}\n}\n"
    model, _ = profile(extra)
    assert model.rules[0].unsupported  # (a field FWShift does not know)


def test_stealth_mode_reads_no_nat_and_extern_without_address() -> None:
    nat = 'FW_PORTFORWARDING = {\n{\n PROTO = "tcp"\n SRC_IP = "0.0.0.0/0"\n SRC_PORT = "any"\n IN_IP = "%extern"\n IN_PORT = "80"\n' \
          ' OUT_IP = "192.168.1.5"\n OUT_PORT = "80"\n}\n}\n'
    model, report = profile(nat, mode="stealth")
    assert not model.nat_rules and "MGUARD_NAT_STEALTH" in codes(report)
    model, report = parse('#version 8.6.1.default\nNETWORKMODE = "router"\nROUTER_MODE = "dhcp"\n' + nat)
    assert model.addresses["mguard-extern"].kind == AddressKind.UNSUPPORTED
    from fwshift import transform

    assert "mguard-extern" in transform.tainted_addresses(model)


# -- the emitter ---------------------------------------------------------------------------------------------------------


def test_emitted_sample_is_what_an_mguard_takes() -> None:
    model, report = sample()
    script = cli.convert(model, "mguard", report)
    config = MGuard(script)
    incoming = config.tables["FW_INCOMING"]
    assert incoming[0]["refs"] == {"FROM_IP": "fws_scada", "IN_IP": "fws_plc_cell1"}
    assert [r["fields"]["COMMENT"].split(":")[0] for r in incoming][:2] == ["incoming-1", "incoming-2"]
    assert config.tables["FW_PORTFORWARDING"][0]["fields"]["IN_IP"] == "%extern"
    assert config.tables["FW_PORTFORWARDING"][0]["fields"]["LOG"] == "yes"
    assert config.tables["FW_1TO1_NAT"][0]["fields"] == {"LOCAL_NET": "192.168.10.48", "REMOTE_NET": "203.0.113.8", "MASK": "29",
                                                          "ENABLE_ARP": "yes", "COMMENT": "1to1-1: HMI subnet published"}  # fmt: skip
    assert [r["fields"]["EXT_IF"] for r in config.tables["FW_NAT"]] == ["ext1", "int"]
    # The rule of the 1:1 NAT names the real address again, as the mGuard wants.
    hmi = next(r for r in incoming if r["fields"]["COMMENT"].startswith("incoming-8"))
    assert hmi["fields"]["IN_IP"] == "192.168.10.50" and hmi["fields"]["IN_PORT"] == "8000:8080"
    assert report.item("rule", "portforward-1").skipped  # (the port forwarding lets it through by itself)
    assert report.item("rule", "incoming-5.maintenance-1").skipped
    assert "MGUARD_LOAD" in codes(report)
    pkt = Packet("eth1", "eth0", "198.51.100.3", "192.168.10.25", "tcp", 40000, 502)
    assert config.allows(pkt, "external", "internal")
    pkt.dport = 503
    assert not config.allows(pkt, "external", "internal")


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "mguard_sample.atv").read_bytes()
    for target in cli.VENDORS:
        report = Report()
        policy = cli.load(data, "mguard", report)
        assert cli.convert(policy, target, report), target


def _policy(*rules: Rule, zones: Tuple[str, ...] = ("trust", "untrust", "dmz")) -> Policy:
    p = Policy(vendor="panos")
    for zone in zones:
        p.zones[zone] = Zone(zone)
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def test_emitter_zones_guessed_and_unknown() -> None:
    p = _policy(Rule("out", ["trust"], ["untrust"], ["10.0.0.0/8"], [ANY]), Rule("lab", ["lab"], ["untrust"]), zones=("trust", "untrust", "lab"))
    text, report = emit(p)
    assert "MGUARD_ZONES_GUESSED" in codes(report)
    assert MGuard(text).tables["FW_OUTGOING"][0]["fields"]["FROM_IP"] == "10.0.0.0/8"
    assert report.item("rule", "lab").skipped and "MGUARD_ZONE_UNKNOWN" in codes(report)
    text, report = emit(p, Options(zone_map={"lab": "dmz"}))
    assert MGuard(text).tables["FW_OUTGOING_DMZWAN"]


def test_emitter_rows_per_protocol_and_negation() -> None:
    p = _policy(Rule("mixed", ["untrust"], ["trust"], ["10.0.0.0/8"], ["192.168.1.0/24"], ["svc"]),
                Rule("not", ["trust"], ["untrust"], ["10.1.0.0/16"], [ANY], action=Action.DROP, negate_source=True))  # fmt: skip
    p.services["svc"] = Service("svc", [ServiceEntry(Protocol.TCP, "80,443"), ServiceEntry(Protocol.UDP, "53"), ServiceEntry(Protocol.ICMP),
                                        ServiceEntry(Protocol.TCP, "22", "1024-65535")])  # fmt: skip
    text, report = emit(p)
    config = MGuard(text)
    rows = config.tables["FW_INCOMING"]
    assert [r["fields"]["PROTO"] for r in rows] == ["tcp", "udp", "tcp", "icmp"]
    assert rows[0]["refs"] == {"IN_PORT": "fws_svc"} and rows[2]["fields"]["FROM_PORT"] == "1024:65535"
    assert "MGUARD_ROWS_SPLIT" in codes(report) and "NEGATION_EXPANDED" in codes(report)
    out = config.tables["FW_OUTGOING"][0]
    assert out["refs"]["FROM_IP"] and config.allows(Packet("", "", "10.2.0.1", "198.51.100.8", "udp", 1, 1), "internal", "external") is False
    assert config.allows(Packet("", "", "10.1.0.1", "198.51.100.8", "udp", 1, 1), "internal", "external") is False  # (no row: dropped)


def test_emitter_what_it_cannot_write() -> None:
    p = _policy(Rule("ping", ["untrust"], ["trust"], services=["ping"]), Rule("noping", ["untrust"], ["trust"], services=["ping"], action=Action.DROP),
                Rule("six", ["untrust"], ["trust"], ["2001:db8::/32"]), Rule("half", ["untrust"], ["trust"], ["2001:db8::/32", "10.0.0.0/8"]),
                Rule("off", ["untrust"], ["trust"], enabled=False), Rule("esp", ["untrust"], ["trust"], services=["esp"]),
                Rule("inside", ["trust"], ["trust"], ["10.0.0.0/8"]), Rule("negsvc", ["untrust"], ["trust"], services=["esp"], negate_service=True))  # fmt: skip
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["esp"] = Service("esp", [ServiceEntry(Protocol.IP, ip_protocol=50)])
    text, report = emit(p)
    item = report.item
    assert item("rule", "ping").skipped and item("rule", "six").skipped and item("rule", "esp").skipped and item("rule", "inside").skipped
    assert item("rule", "off").skipped and item("rule", "off").status == "skipped" and item("rule", "negsvc").skipped
    assert "MGUARD_ICMP_TYPE" in {f.code for f in item("rule", "noping").findings}
    assert "MGUARD_IPV6" in {f.code for f in item("rule", "half").findings}
    rows = MGuard(text).tables["FW_INCOMING"]
    assert [r["fields"]["COMMENT"] for r in rows] == ["noping", "half"] and rows[0]["fields"]["PROTO"] == "icmp"


def test_emitter_tables_that_decide_more() -> None:
    p = _policy(Rule("dmz-out", ["dmz"], ["untrust"]), Rule("dmz-out-deny", ["dmz"], ["untrust"], action=Action.DROP),
                zones=("trust", "untrust", "dmz", "ext2"))  # fmt: skip
    p.rules.append(Rule("backup", ["ext2"], ["trust"], origin="backup"))
    text, report = emit(p, Options(zone_map={"ext2": "external2"}))
    assert report.item("rule", "dmz-out").skipped and "MGUARD_TABLE_WIDER" in codes(report)
    config = MGuard(text)
    assert [r["fields"]["COMMENT"] for r in config.tables["FW_OUTGOING_DMZWAN"]] == ["dmz-out-deny"]
    assert config.tables["FW_INCOMING"][0]["fields"]["EXT_IF"] == "ext2"


def test_emitter_default_allow_and_prefix() -> None:
    p = _policy(Rule("deny", ["untrust"], ["trust"], ["10.0.0.0/8"], action=Action.DROP))
    p.default_interzone = Action.ALLOW
    text, report = emit(p, Options(object_prefix="cell7_"))
    config = MGuard(text)
    assert config.tables["FW_INCOMING"][-1]["fields"]["TARGET_REF"] == "ACCEPT" and "MGUARD_DEFAULT_ALLOW" in codes(report)
    assert config.allows(Packet("", "", "192.0.2.1", "192.168.1.1", "tcp", 1, 80), "external", "internal")
    with pytest.raises(FwshiftError):
        emit(p, Options(object_prefix="1bad"))


def test_emitter_port_forwarding() -> None:
    def forward_policy(allow: bool) -> Policy:
        p = _policy(Rule("web-in", ["untrust"], ["dmz"], [ANY], ["198.51.100.10"], ["https"], action=Action.ALLOW if allow else Action.DROP))
        p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
        p.nat_rules.append(NatRule("pub", ["untrust"], ["untrust"], [ANY], ["198.51.100.10"], "https",
                                   destination_translation=DestNat("172.16.0.10"), origin="pub"))  # fmt: skip
        p.zone_networks = {"dmz": ["172.16.0.0/16"], "untrust": ["0.0.0.0/0"]}
        return p

    text, report = emit(forward_policy(True))
    row = MGuard(text).tables["FW_PORTFORWARDING"][0]["fields"]
    assert (row["IN_IP"], row["IN_PORT"], row["OUT_IP"], row["OUT_PORT"]) == ("198.51.100.10", "443", "172.16.0.10", "443")
    assert "MGUARD_FORWARD_ALLOWED" in codes(report)
    text, report = emit(forward_policy(False))
    assert "FW_PORTFORWARDING" not in MGuard(text).tables and report.item("nat", "pub").skipped
    assert "MGUARD_FORWARD_BLOCKED" in codes(report)


def test_emitter_masquerade_and_what_nat_it_cannot_write() -> None:
    p = _policy(Rule("out", ["trust"], ["untrust"]))
    p.nat_rules.append(NatRule("hide", [ANY], ["untrust"], ["10.0.0.0/8", "192.168.0.0/16"],
                               source_translation=SourceNat(SnatKind.INTERFACE), origin="hide"))  # fmt: skip
    p.nat_rules.append(NatRule("pool", [ANY], ["untrust"], ["10.0.0.0/8"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.5"]),
                               origin="pool"))  # fmt: skip
    text, report = emit(p)
    config = MGuard(text)
    nat = config.tables["FW_NAT"][0]
    assert nat["fields"]["EXT_IF"] == "ext1" and nat["refs"]["IN_IP"] in config.groups
    assert report.item("nat", "pool").skipped


def test_the_script_runs(tmp_path: Path) -> None:
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no sh")
    model, report = sample()
    script = tmp_path / "load.sh"
    script.write_text(cli.convert(model, "mguard", report), encoding="utf-8")
    dry = subprocess.run([sh, str(script)], env={**os.environ, "DRY_RUN": "1"}, capture_output=True, text=True, timeout=60)
    assert dry.returncode == 0, dry.stderr
    assert dry.stderr.count("gaiconfig --") == script.read_text(encoding="utf-8").count("\ngc ")
    # A stand-in for gaiconfig: every table is empty, every name free; the calls are written down.
    log = tmp_path / "calls"
    fake = tmp_path / "bin" / "gaiconfig"
    fake.parent.mkdir()
    fake.write_text(f'#!/bin/sh\necho "$*" >> {shlex.quote(str(log))}\ncase "$1" in --get-rowcount) echo 0;; --get) echo rules;; esac\n',
                    encoding="utf-8")  # fmt: skip
    fake.chmod(0o755)
    run = subprocess.run([sh, str(script)], env={**os.environ, "PATH": f"{fake.parent}{os.pathsep}{os.environ['PATH']}"},
                         capture_output=True, text=True, timeout=60)  # fmt: skip
    assert run.returncode == 0, run.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert sum(1 for c in calls if "--add-row" in c or "--set-refname" in c) == script.read_text(encoding="utf-8").count("\ngc ")
    # A table with rows stops it before anything is written.
    log.unlink()
    fake.write_text(f'#!/bin/sh\necho "$*" >> {shlex.quote(str(log))}\ncase "$1" in --get-rowcount) echo 2;; --get) echo rules;; esac\n',
                    encoding="utf-8")  # fmt: skip
    run = subprocess.run([sh, str(script)], env={**os.environ, "PATH": f"{fake.parent}{os.pathsep}{os.environ['PATH']}"},
                         capture_output=True, text=True, timeout=60)  # fmt: skip
    assert run.returncode == 1 and "FWSHIFT_APPEND" in run.stderr
    assert not any("--add-row" in c for c in log.read_text(encoding="utf-8").splitlines())


def test_scope_rules() -> None:
    p = _policy(Rule("between", ["trust", "untrust"], ["trust", "untrust"], ["10.0.0.0/8"], scope=RuleScope.INTERZONE))
    p.rules[0].origin = "between"
    config = MGuard(emit(p)[0])
    assert config.tables["FW_INCOMING"] and config.tables["FW_OUTGOING"]
    p.addresses["host"] = Address("host", AddressKind.NETWORK, "10.0.0.1")
    assert emit(p)[0]
