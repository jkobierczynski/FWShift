# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared helpers: load the synthetic samples and read back emitted configuration."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fwshift import cli
from fwshift.model import Policy
from fwshift.netutil import parse_literal
from fwshift.options import Options
from fwshift.parsers.fortios import Block, parse_tree
from fwshift.report import Report

DATA = Path(__file__).parent / "data"


def load(name: str, **kwargs: str) -> Tuple[Policy, Report]:
    data = (DATA / name).read_bytes()
    report = Report()
    return cli.load(data, cli.detect_format(data), report, **kwargs), report


def run(name: str, target: str, options: Optional[Options] = None, **kwargs: str) -> Tuple[str, Report]:
    policy, report = load(name, **kwargs)
    return cli.convert(policy, target, report, options), report


class PanConfig:
    """Emitted PAN-OS set commands, indexed by object kind and name."""

    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        self.entries: Dict[str, Dict[str, List[List[str]]]] = {}
        for line in self.lines:
            words = shlex.split(line)
            assert words[0] == "set", line
            words = words[1:]
            if words[0] in ("vsys", "device-group"):
                words = words[2:]
            elif words[0] == "shared":
                words = words[1:]
            if words[0] in ("rulebase", "pre-rulebase", "post-rulebase"):
                kind, name, rest = words[1], words[3], words[4:]
            else:
                kind, name, rest = words[0], words[1], words[2:]
            self.entries.setdefault(kind, {}).setdefault(name, []).append(rest)

    def names(self, kind: str) -> List[str]:
        return list(self.entries.get(kind, {}))

    def get(self, kind: str, name: str, *path: str) -> Optional[List[str]]:
        """Values of an attribute, without list brackets; None if the attribute is absent."""
        for rest in self.entries.get(kind, {}).get(name, []):
            if tuple(rest[: len(path)]) == path:
                return [w for w in rest[len(path) :] if w not in ("[", "]")]
        return None


class FortiConfig:
    """Emitted FortiOS configuration, read back with fwshift's own tree parser."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.tree: Block = parse_tree(text)

    def table(self, path: str) -> Dict[str, Block]:
        block = self.tree.children.get(path)
        return dict(block.entries) if block else {}

    def policies(self) -> Dict[str, Block]:
        """Policies by name. With 'edit 0' the tree merges entries, so split the text instead."""
        out: Dict[str, Block] = {}
        section = self.text.split("config firewall policy\n", 1)
        if len(section) < 2:
            return out
        body = section[1].split("\nend\n", 1)[0]
        for chunk in body.split("    next"):
            if "edit" not in chunk:
                continue
            entry = parse_tree("config x\n" + chunk + "\nnext\nend\n").children["x"]
            block = next(iter(entry.entries.values()))
            out[block.get("name")] = block
        return out



class CheckPointScript:
    """Emitted mgmt_cli script, replayed call by call the way a management server would take it.

    Every reference must name something created earlier in the script (or passed
    in as existing), names must be unique, and a numbered position must exist.
    """

    def __init__(self, text: str, existing: Tuple[str, ...] = ("Network",), layer: str = "Network") -> None:
        self.text = text
        self.layer = layer
        self.calls: List[List[str]] = []
        self.objects: Dict[str, Dict[str, object]] = {name: {"kind": "existing"} for name in existing}
        self.layers: Dict[str, List[Dict[str, object]]] = {layer: []}
        self.nat: List[Dict[str, object]] = []
        for line in text.splitlines():
            if line.startswith("zone "):
                words = shlex.split(line)
                self.objects.setdefault(words[1], {"kind": "security-zone"})
            elif line.startswith("m "):
                words = shlex.split(line)[1:]
                self.calls.append(words)
                self._apply(words)

    @staticmethod
    def _fields(words: List[str]) -> Dict[str, object]:
        """``key value`` pairs; ``key.N value`` collects a list."""
        assert len(words) % 2 == 0, words
        out: Dict[str, object] = {}
        for key, value in zip(words[0::2], words[1::2]):
            base, dot, index = key.rpartition(".")
            if dot and index.isdigit():
                listed = out.setdefault(base, [])
                assert isinstance(listed, list) and len(listed) == int(index) - 1, words
                listed.append(value)
            else:
                assert key not in out, words
                out[key] = value
        return out

    def _known(self, names: object) -> None:
        for name in names if isinstance(names, list) else [names]:
            assert name in self.objects, f"'{name}' is used before it is created"

    def _apply(self, words: List[str]) -> None:
        assert words[0] == "add", words
        kind, fields = words[1], self._fields(words[2:])
        if kind == "access-rule":
            layer = str(fields["layer"])
            assert layer in self.layers, f"layer '{layer}' does not exist"
            for column in ("source", "destination", "service"):
                # A server stores a cell the call leaves out as None, which matches nothing (R82.20): every rule
                # names all three. Any matches everything; it is read here as an empty cell.
                assert column in fields, f"rule {fields.get('name')!r} leaves {column} out, which is stored as None"
                if fields[column] == ["Any"]:
                    del fields[column]
                else:
                    assert "Any" not in fields[column], words
                    self._known(fields[column])
            if "inline-layer" in fields:
                assert fields["action"] == "Apply Layer" and fields["inline-layer"] in self.layers, words
            position = str(fields["position"])
            rules = self.layers[layer]
            if position == "bottom":
                rules.append(fields)
            else:
                assert 1 <= int(position) <= len(rules) + 1, words
                rules.insert(int(position) - 1, fields)
            return
        if kind == "nat-rule":
            for column in ("original-source", "original-destination", "original-service", "translated-source",
                           "translated-destination", "translated-service"):  # fmt: skip
                # every cell is written; Any and Original are read as a cell left empty
                assert column in fields, f"NAT rule leaves {column} out"
                if fields[column] in ("Any", "Original"):
                    del fields[column]
                else:
                    self._known(fields[column])
            self.nat.append(fields)
            return
        name = str(fields["name"])
        assert name not in self.objects, f"'{name}' is created twice"
        self._known(fields.get("members", []))
        fields["kind"] = kind
        self.objects[name] = fields
        if kind == "access-layer":
            assert fields.get("add-default-rule") == "false", words
            self.layers[name] = []

    def names(self, kind: str) -> List[str]:
        return [name for name, fields in self.objects.items() if fields["kind"] == kind]

    def rules(self, layer: str = "") -> List[Dict[str, object]]:
        return self.layers[layer or self.layer]

    def rule(self, name: str, layer: str = "") -> Dict[str, object]:
        found = [rule for rule in self.rules(layer) if rule["name"] == name]
        assert len(found) == 1, (name, layer, [rule["name"] for rule in self.rules(layer)])
        return found[0]


class AsaConfig:
    """Emitted ASA commands, read the way an ASA would take them, with enough of an ASA to judge a packet.

    This is not fwshift's parser: it knows the forms the emitter writes and nothing else, and it
    is strict about them. An object has to exist before it is used, a name is given once, an
    object group has members, and a bound access list exists.
    """

    PROTOCOLS = {"icmp": 1, "igmp": 2, "ipinip": 4, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmp6": 58,
                 "eigrp": 88, "ospf": 89, "pim": 103, "sctp": 132}  # fmt: skip

    def __init__(self, text: str, intra_interface: bool = False) -> None:
        self.text = text
        self.intra_interface = intra_interface
        self.networks: Dict[str, List[str]] = {}  # object or group -> address literals; "fqdn" for a host name
        self.services: Dict[str, List[Dict[str, Any]]] = {}  # object or group -> what it matches
        self.kinds: Dict[str, str] = {}  # name -> the command that created it
        self.acls: Dict[str, List[Dict[str, Any]]] = {}
        self.bound: Dict[str, str] = {}
        self.global_acl = ""
        self.nat: List[List[str]] = []
        self.remarks: List[str] = []
        current = ""
        for line in text.splitlines():
            assert line == line.rstrip() and "\t" not in line and line.isprintable(), repr(line)
            if line.startswith("!"):
                continue
            words = line.split()
            if line.startswith(" "):
                self._child(current, words, line)
                continue
            self._check_open(current)
            current = ""
            if words[0] in ("object", "object-group"):
                assert len(words) == 3 and words[1] in ("network", "service"), line
                current = words[2]
                assert current not in self.kinds, f"'{current}' is defined twice"
                assert len(current) <= 64 and current not in ("any", "any4", "any6", "interface", "host"), line
                self.kinds[current] = f"{words[0]} {words[1]}"
                (self.networks if words[1] == "network" else self.services)[current] = []  # type: ignore[arg-type]
            elif words[0] == "access-list":
                self._access_list(words, line)
            elif words[0] == "access-group":
                assert words[1] in self.acls, f"access-group for '{words[1]}', which does not exist"
                if words[2:] == ["global"]:
                    assert not self.global_acl, line
                    self.global_acl = words[1]
                else:
                    assert len(words) == 5 and words[2:4] == ["in", "interface"] and words[4] not in self.bound, line
                    self.bound[words[4]] = words[1]
            elif words[0] == "nat":
                self._nat(words, line)
            else:
                raise AssertionError(f"unexpected line: {line}")
        self._check_open(current)

    def _check_open(self, name: str) -> None:
        if name:
            content = self.networks.get(name) if name in self.networks else self.services.get(name)
            assert content, f"'{name}' has no content"

    def _kind(self, name: str, *kinds: str) -> str:
        assert self.kinds.get(name) in kinds, f"'{name}' is used as {' or '.join(kinds)} but is {self.kinds.get(name)}"
        return self.kinds[name]

    @staticmethod
    def _port_range(words: List[str]) -> Tuple[Tuple[int, int], List[str]]:
        operator, first = words[0], int(words[1])
        assert 0 <= first <= 65535, words
        if operator == "eq":
            return (first, first), words[2:]
        if operator == "lt":
            return (0, first - 1), words[2:]
        if operator == "gt":
            return (first + 1, 65535), words[2:]
        assert operator == "range" and first <= int(words[2]) <= 65535, words
        return (first, int(words[2])), words[3:]

    def _service_spec(self, words: List[str], line: str) -> Dict[str, Any]:
        """``tcp source gt 1023 destination eq 25``, ``icmp 8 0``, ``47``, ``ip``."""
        protocol, rest = words[0], words[1:]
        spec: Dict[str, Any] = {"protocol": protocol, "src": None, "dst": None, "icmp": None}
        if protocol in ("tcp", "udp", "sctp"):
            for side, key in (("source", "src"), ("destination", "dst")):
                if rest[:1] == [side]:
                    spec[key], rest = self._port_range(rest[1:])
        elif protocol in ("icmp", "icmp6"):
            spec["icmp"] = [int(word) for word in rest]
            assert len(rest) <= 2, line
            rest = []
        else:
            assert protocol == "ip" or protocol in self.PROTOCOLS or 0 < int(protocol) < 256, line
        assert not rest, line
        return spec

    def _child(self, name: str, words: List[str], line: str) -> None:
        assert name, f"line outside an object: {line}"
        kind = self.kinds[name]
        if words[0] == "description":
            assert len(line) <= 214, line
            return
        if kind == "object network":
            assert not self.networks[name], f"second value for '{name}'"
            if words[0] == "host":
                literal = words[1]
                assert len(words) == 2 and "/" not in literal
            elif words[0] == "subnet":
                literal = f"{words[1]}/{words[2]}" if len(words) == 3 else words[1]
                assert "/" in literal
            elif words[0] == "range":
                literal = f"{words[1]}-{words[2]}"
                assert len(words) == 3
            else:
                assert words[0] == "fqdn" and len(words) == 3 and words[1] in ("v4", "v6"), line
                self.networks[name] = [f"fqdn {words[1]} {words[2]}"]
                return
            assert parse_literal(literal) is not None, line
            self.networks[name] = [literal]
        elif kind == "object-group network":
            if words[0] == "group-object":
                self._kind(words[1], "object-group network")
                self.networks[name] += self.networks[words[1]]
            elif words[1] == "object":
                assert words[0] == "network-object" and len(words) == 3, line
                self._kind(words[2], "object network")
                self.networks[name] += self.networks[words[2]]
            else:
                assert words[0] == "network-object", line
                self.networks[name].append(self._literal(words[1:], line)[0])
        elif kind == "object service":
            assert words[0] == "service" and not self.services[name], line
            self.services[name] = [self._service_spec(words[1:], line)]
        else:
            assert kind == "object-group service", line
            if words[0] == "group-object":
                self._kind(words[1], "object-group service")
                self.services[name] += self.services[words[1]]
            elif words[1] == "object":
                assert words[0] == "service-object" and len(words) == 3, line
                self._kind(words[2], "object service")
                self.services[name] += self.services[words[2]]
            else:
                assert words[0] == "service-object", line
                self.services[name].append(self._service_spec(words[1:], line))

    @staticmethod
    def _literal(words: List[str], line: str) -> Tuple[str, List[str]]:
        """An address spelled out: ``host X``, ``A MASK`` or an IPv6 prefix."""
        if words[0] == "host":
            literal, rest = words[1], words[2:]
            assert "/" not in literal, line
        elif ":" in words[0]:
            literal, rest = words[0], words[1:]
            assert "/" in literal, line
        else:
            literal, rest = f"{words[0]}/{words[1]}", words[2:]
        assert parse_literal(literal) is not None, line
        return literal, rest

    def _address(self, words: List[str], line: str) -> Tuple[List[str], List[str]]:
        if words[0] in ("any", "any4", "any6"):
            return {"any": ["0.0.0.0/0", "::/0"], "any4": ["0.0.0.0/0"], "any6": ["::/0"]}[words[0]], words[1:]
        if words[0] == "object":
            self._kind(words[1], "object network")
            return self.networks[words[1]], words[2:]
        if words[0] == "object-group":
            self._kind(words[1], "object-group network")
            return self.networks[words[1]], words[2:]
        literal, rest = self._literal(words, line)
        return [literal], rest

    def _access_list(self, words: List[str], line: str) -> None:
        entries = self.acls.setdefault(words[1], [])
        if words[2] == "remark":
            text = line.split(" remark ", 1)[1]
            assert 0 < len(text) <= 100, line
            self.remarks.append(text)
            return
        assert words[2] == "extended" and words[3] in ("permit", "deny"), line
        entry: Dict[str, Any] = {"permit": words[3] == "permit", "line": line}
        rest = words[4:]
        if rest[0] in ("object", "object-group"):
            self._kind(rest[1], f"{rest[0]} service")
            entry["services"], rest, inline = self.services[rest[1]], rest[2:], None
        else:
            inline, rest = {"protocol": rest[0], "src": None, "dst": None, "icmp": None}, rest[1:]
            assert inline["protocol"] == "ip" or inline["protocol"] in self.PROTOCOLS or 0 < int(inline["protocol"]) < 256
            entry["services"] = [inline]
        operators = ("eq", "lt", "gt", "range")
        entry["src"], rest = self._address(rest, line)
        if rest[0] in operators:
            assert inline is not None and inline["protocol"] in ("tcp", "udp", "sctp"), line
            inline["src"], rest = self._port_range(rest)
        entry["dst"], rest = self._address(rest, line)
        if rest[:1] and rest[0] in operators:
            assert inline is not None and inline["protocol"] in ("tcp", "udp", "sctp"), line
            inline["dst"], rest = self._port_range(rest)
        elif inline is not None and inline["protocol"] in ("icmp", "icmp6") and rest[:1] and rest[0].isdigit():
            count = 2 if rest[1:2] and rest[1].isdigit() else 1
            inline["icmp"], rest = [int(word) for word in rest[:count]], rest[count:]
        entry["log"] = None
        if rest[:1] == ["log"]:
            entry["log"], rest = rest[1:2] != ["disable"], rest[2:] if rest[1:2] == ["disable"] else rest[1:]
        entry["inactive"] = rest == ["inactive"]
        assert rest in ([], ["inactive"]), line
        entries.append(entry)

    def _nat(self, words: List[str], line: str) -> None:
        """Check the references of a twice NAT line; the line itself is kept as words."""
        assert words[1].startswith("(") and words[1].endswith(")") and words[1].count(",") == 1, line
        assert words[2] == "source" and words[3] in ("static", "dynamic"), line
        rest = words[4:]
        if "description" in rest:
            rest = rest[: rest.index("description")]
        position = 0
        while position < len(rest):
            word = rest[position]
            if word in ("destination", "service"):
                first = 2 if word == "destination" else 1
                assert word != "destination" or rest[position + 1] == "static", line
                for name in rest[position + first : position + first + 2]:
                    self._kind(name, *(("object service",) if word == "service" else ("object network", "object-group network")))
                position += first + 2
            elif word in ("any", "interface", "pat-pool", "unidirectional", "no-proxy-arp", "route-lookup", "inactive"):
                position += 1
            else:
                self._kind(word, "object network", "object-group network")
                position += 1
        self.nat.append(words)

    @staticmethod
    def _within(address: str, literals: List[str]) -> bool:
        probe = parse_literal(address)
        assert probe is not None
        for literal in literals:
            interval = parse_literal(literal)
            if interval is not None and interval[0] == probe[0] and interval[1] <= probe[1] <= interval[2]:
                return True
        return False

    def _service_matches(self, spec: Dict[str, Any], pkt: Any) -> bool:
        protocol = spec["protocol"]
        if protocol == "ip":
            return True
        number = self.PROTOCOLS.get(protocol) or int(protocol)
        packet = self.PROTOCOLS.get(pkt.proto) or int(pkt.proto)
        if number != packet:
            return False
        if spec["src"] and not spec["src"][0] <= pkt.sport <= spec["src"][1]:
            return False
        if spec["dst"] and not spec["dst"][0] <= pkt.dport <= spec["dst"][1]:
            return False
        return not spec["icmp"] or spec["icmp"][0] == pkt.icmp_type

    def verdict(self, pkt: Any) -> Optional[Dict[str, Any]]:
        """The entry that decides about a packet that opens a connection, if any."""
        for acl in (self.bound.get(pkt.in_if, ""), self.global_acl):
            for entry in self.acls.get(acl, []):
                if entry["inactive"] or not self._within(pkt.src, entry["src"]) or not self._within(pkt.dst, entry["dst"]):
                    continue
                if any(self._service_matches(spec, pkt) for spec in entry["services"]):
                    return entry
        return None

    def allows(self, pkt: Any) -> bool:
        if pkt.in_if == pkt.out_if and not self.intra_interface:
            return False  # an ASA does not send traffic back out of the interface it came in on
        entry = self.verdict(pkt)
        return entry is not None and bool(entry["permit"])


class SophosConfig:
    """An Entities.xml read the way an import would take it, with nothing of fwshift's own parser.

    Strict where a firewall is: every name that is used must have been defined above it (or be passed
    in as existing), names are unique whatever their case, a host is of the IP version of what uses
    it, and only elements and values that the documentation of the XML API shows are accepted.
    Rules are kept in the order the firewall evaluates them: each IP version has its own rulebase,
    and Position (Top, Bottom, After, Before) is carried out entity by entity.
    """

    PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
    ICMP_TYPES = {0, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18} | set(range(30, 41))
    ICMP6_TYPES = {0, 1, 2, 3, 4, 100, 101, 200, 201} | set(range(128, 159))
    RULE_HEAD = ["Name", "Description", "IPFamily", "Status", "Position", "PolicyType", "After", "Before", "NetworkPolicy"]
    MATCH = ["Action", "LogTraffic", "SkipLocalDestined", "SourceZones", "DestinationZones", "Schedule", "SourceNetworks",
             "DestinationNetworks", "Services", "Exclusions"]  # fmt: skip
    PROFILES = {"WebFilter", "ApplicationControl", "IntrusionPrevention", "ScanVirus", "ZeroDayProtection", "ProxyMode",
                "DecryptHTTPS", "ScanSMTP", "ScanSMTPS", "ScanIMAP", "ScanIMAPS", "ScanPOP3", "ScanPOP3S", "ScanFTP",
                "MinimumSourceHBPermitted", "MinimumDestHBPermitted"}  # fmt: skip
    NAT_HEAD = ["Name", "Description", "IPFamily", "Status", "Position", "After", "Before", "LinkedFirewallrule",
                "TranslatedDestination", "TranslatedService", "OriginalSourceNetworks", "OriginalDestinationNetworks",
                "OriginalServices", "InboundInterfaces", "OutboundInterfaces", "OverrideInterfaceNATPolicy",
                "TranslatedSource", "NATMethod"]  # fmt: skip

    def __init__(self, text: str, existing_hosts: Tuple[str, ...] = (), zones: Optional[Tuple[str, ...]] = None,
                 interfaces: Optional[Tuple[str, ...]] = None, resolved: Optional[Dict[str, List[str]]] = None) -> None:  # fmt: skip
        import xml.etree.ElementTree as ET

        self.text = text
        self.zones, self.interfaces = zones, interfaces
        self.resolved = resolved or {}  # what a host name stands for, for a test that wants one to match
        self.hosts: Dict[str, Dict[str, Any]] = {name: {"kind": "existing"} for name in existing_hosts}
        self.services: Dict[str, Dict[str, Any]] = {}
        self.rules: Dict[int, List[Dict[str, Any]]] = {4: [], 6: []}
        self.nat: Dict[int, List[Dict[str, Any]]] = {4: [], 6: []}
        self._names: Dict[str, set] = {"host": {name.lower() for name in existing_hosts}, "service": set(), "rule": set(),
                                       "nat": set()}  # fmt: skip
        assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>\n'), text[:60]
        root = ET.fromstring(text.encode("utf-8"))
        assert root.tag == "Configuration" and root.get("APIVersion"), root.attrib
        self.api_version = root.get("APIVersion")
        handlers = {"IPHost": self._ip_host, "IPHostGroup": self._host_group, "FQDNHost": self._fqdn_host,
                    "FQDNHostGroup": self._fqdn_group, "Services": self._service, "ServiceGroup": self._service_group,
                    "FirewallRule": self._rule, "NATRule": self._nat_rule, "Zone": self._zone, "Interface": self._interface}  # fmt: skip
        self.defined_zones: List[str] = []  # what a file written by hand for a test defines; fwshift writes neither
        self.interface_zone: Dict[str, str] = {}
        for entity in root:
            assert entity.tag in handlers, f"entity <{entity.tag}> is not one this reader knows"
            assert entity.get("transactionid") == "", entity.tag
            handlers[entity.tag](entity)

    # -- reading ----------------------------------------------------------

    @staticmethod
    def _text(element: Any, tag: str) -> str:
        found = element.findall(tag)
        assert len(found) == 1, f"<{element.tag}> needs one <{tag}>, has {len(found)}"
        assert len(found[0]) == 0, f"<{tag}> holds elements"
        return (found[0].text or "").strip()

    def _name(self, element: Any, space: str, limit: int = 60) -> str:
        name = self._text(element, "Name")
        assert name and len(name) <= limit and "," not in name and name == name.strip(), f"name '{name}'"
        # Words the format uses where a name of this kind can stand.
        words = {"host": ("any", "original", "masq", "none"), "service": ("any", "original", "none"), "rule": ("none",)}
        assert name.lower() not in words.get(space, ()), f"'{name}' is a word of the format"
        assert name.lower() not in self._names[space], f"{space} '{name}' is defined twice"
        self._names[space].add(name.lower())
        return name

    @staticmethod
    def _only(element: Any, allowed: List[str]) -> None:
        tags = [child.tag for child in element]
        assert all(tag in allowed for tag in tags), f"<{element.tag}> holds {[t for t in tags if t not in allowed]}"
        assert len(tags) == len(set(tags)), f"<{element.tag}> holds an element twice: {tags}"

    def _family(self, element: Any) -> int:
        family = self._text(element, "IPFamily")
        assert family in ("IPv4", "IPv6"), family
        return 4 if family == "IPv4" else 6

    def _zone(self, element: Any) -> None:
        self.defined_zones.append(self._text(element, "Name"))

    def _interface(self, element: Any) -> None:
        self.interface_zone[self._text(element, "Name")] = self._text(element, "NetworkZone")

    def _ip_host(self, element: Any) -> None:
        import ipaddress

        name, version = self._name(element, "host"), self._family(element)
        kind = self._text(element, "HostType")

        def address(tag: str) -> int:
            parsed = ipaddress.ip_address(self._text(element, tag))
            assert parsed.version == version, f"host '{name}': {parsed} in an IPv{version} host"
            return int(parsed)

        if kind == "IP":
            self._only(element, ["Name", "IPFamily", "HostType", "IPAddress"])
            first = last = address("IPAddress")
            assert first != 0, f"host '{name}' is the unspecified address"
        elif kind == "Network":
            self._only(element, ["Name", "IPFamily", "HostType", "IPAddress", "Subnet"])
            subnet = self._text(element, "Subnet")
            if version == 4:
                assert subnet.count(".") == 3, f"IPv4 subnet '{subnet}' is not a mask"
            else:
                assert subnet.isdigit(), f"IPv6 subnet '{subnet}' is not a prefix length"
            network = ipaddress.ip_network(f"{self._text(element, 'IPAddress')}/{subnet}", strict=True)
            assert network.version == version and network.prefixlen > 0, f"host '{name}' is every address"
            assert network.num_addresses > 1, f"network '{name}' of one address"
            first, last = int(network.network_address), int(network.broadcast_address)
        else:
            assert kind == "IPRange", f"host type '{kind}'"
            self._only(element, ["Name", "IPFamily", "HostType", "StartIPAddress", "EndIPAddress"])
            first, last = address("StartIPAddress"), address("EndIPAddress")
            assert first < last, f"range '{name}' is not a range"
        self.hosts[name] = {"kind": "ip", "version": version, "first": first, "last": last, "type": kind}

    def _members(self, element: Any, path: str, child: str) -> List[str]:
        holders = element.findall(path)
        assert len(holders) == 1, f"<{element.tag}> needs one <{path}>"
        assert all(member.tag == child for member in holders[0]), f"<{path}> holds something else than <{child}>"
        names = [(member.text or "").strip() for member in holders[0]]
        assert names and all(names), f"<{path}> is empty"
        assert len(names) == len(set(names)), f"<{path}> lists a name twice: {names}"
        return names

    def _host_group(self, element: Any) -> None:
        self._only(element, ["Name", "IPFamily", "Description", "HostList"])
        name, version = self._name(element, "host"), self._family(element)
        members = self._members(element, "HostList", "Host")
        for member in members:
            assert member in self.hosts, f"group '{name}': host '{member}' is used before it is created"
            held = self.hosts[member]
            assert held["kind"] in ("ip", "existing"), f"group '{name}' holds '{member}', which is no IP host"
            assert held.get("version", version) == version, f"group '{name}' holds a host of the other IP version"
        self.hosts[name] = {"kind": "group", "version": version, "members": members}

    def _fqdn_host(self, element: Any) -> None:
        self._only(element, ["Name", "Description", "FQDN"])
        name, fqdn = self._name(element, "host"), self._text(element, "FQDN")
        assert fqdn and " " not in fqdn and "." in fqdn, fqdn
        self.hosts[name] = {"kind": "fqdn", "fqdn": fqdn}

    def _fqdn_group(self, element: Any) -> None:
        self._only(element, ["Name", "Description", "FQDNHostList"])
        name = self._name(element, "host")
        members = self._members(element, "FQDNHostList", "FQDNHost")
        for member in members:
            assert self.hosts.get(member, {}).get("kind") == "fqdn", f"group '{name}': '{member}' is no host name"
        self.hosts[name] = {"kind": "fqdngroup", "members": members}

    @staticmethod
    def _ports(text: str) -> Tuple[int, int]:
        first, _, last = text.partition(":")
        assert first.isdigit() and (last.isdigit() or ":" not in text), f"ports '{text}'"
        low, high = int(first), int(last or first)
        assert 1 <= low <= high <= 65535, f"ports '{text}'"
        return low, high

    def _service(self, element: Any) -> None:
        from fwshift.appmap import SOPHOS_PROTOCOL_NAMES

        self._only(element, ["Name", "Type", "ServiceDetails"])
        name, kind = self._name(element, "service", 50), self._text(element, "Type")
        holders = element.findall("ServiceDetails")
        assert len(holders) == 1 and len(holders[0]) and all(d.tag == "ServiceDetail" for d in holders[0]), name
        details: List[Dict[str, Any]] = []
        for detail in holders[0]:
            if kind == "TCPorUDP":
                self._only(detail, ["SourcePort", "DestinationPort", "Protocol"])
                protocol = self._text(detail, "Protocol")
                assert protocol in ("TCP", "UDP"), protocol
                details.append({"protocol": protocol.lower(), "src": self._ports(self._text(detail, "SourcePort")),
                                "dst": self._ports(self._text(detail, "DestinationPort"))})  # fmt: skip
            elif kind == "IP":
                self._only(detail, ["ProtocolName"])
                named = self._text(detail, "ProtocolName")
                numbers = {value: key for key, value in SOPHOS_PROTOCOL_NAMES.items()}
                if named.startswith("IPProto"):
                    assert named[7:].isdigit() and 143 <= int(named[7:]) <= 255, named
                    numbers[named] = int(named[7:])
                assert named in numbers, f"protocol name '{named}'"
                details.append({"number": numbers[named]})
            else:
                assert kind in ("ICMP", "ICMPv6"), f"service type '{kind}'"
                self._only(detail, [f"{kind}Type", f"{kind}Code"])
                icmp_type, code = int(self._text(detail, f"{kind}Type")), int(self._text(detail, f"{kind}Code"))
                assert icmp_type == -1 or icmp_type in (self.ICMP_TYPES if kind == "ICMP" else self.ICMP6_TYPES), icmp_type
                assert -1 <= code <= 15 and (icmp_type != -1 or code == -1), code
                details.append({"icmp": "icmp" if kind == "ICMP" else "icmp6", "type": icmp_type, "code": code})
        assert len({repr(sorted(d.items())) for d in details}) == len(details), f"service '{name}' has a detail twice"
        self.services[name] = {"kind": "service", "type": kind, "details": details}

    def _service_group(self, element: Any) -> None:
        self._only(element, ["Name", "Description", "ServiceList"])
        name = self._name(element, "service", 50)
        members = self._members(element, "ServiceList", "Service")
        for member in members:
            assert self.services.get(member, {}).get("kind") == "service", f"service group '{name}': '{member}' is no service"
        self.services[name] = {"kind": "group", "members": members}

    def _networks(self, element: Any, path: str, version: int, where: str) -> Optional[List[str]]:
        if element.find(path) is None:
            return None  # any
        names = self._members(element, path, "Network")
        for name in names:
            assert name in self.hosts, f"{where}: host '{name}' is used before it is created"
            assert self.hosts[name].get("version", version) == version, f"{where}: '{name}' is of the other IP version"
        return names

    def _service_list(self, element: Any, path: str, where: str) -> Optional[List[str]]:
        if element.find(path) is None:
            return None
        names = self._members(element, path, "Service")
        for name in names:
            assert name in self.services, f"{where}: service '{name}' is used before it is created"
        return names

    def _zone_list(self, element: Any, path: str, where: str) -> Optional[List[str]]:
        if element.find(path) is None:
            return None
        names = self._members(element, path, "Zone")
        assert self.zones is None or all(name in self.zones for name in names), f"{where}: zone of {names} does not exist"
        assert not [name for name in names if name.lower() in ("any", "none")], f"{where}: {names} holds a word of the format"
        return names

    def _place(self, element: Any, rules: List[Dict[str, Any]], rule: Dict[str, Any]) -> None:
        position = self._text(element, "Position")
        anchors = {"After": element.findall("After"), "Before": element.findall("Before")}
        assert position in ("Top", "Bottom", "After", "Before"), position
        for word, found in anchors.items():
            assert len(found) == (1 if position == word else 0), f"<{word}> with position {position}"
        if position == "Top":
            rules.insert(0, rule)
        elif position == "Bottom":
            rules.append(rule)
        else:
            anchor = self._text(anchors[position][0], "Name")
            index = [other["name"] for other in rules].index(anchor)  # ValueError: no such rule of this IP version
            rules.insert(index + (1 if position == "After" else 0), rule)

    def _rule(self, element: Any) -> None:
        self._only(element, self.RULE_HEAD)
        tags = [child.tag for child in element]
        assert tags == sorted(tags, key=self.RULE_HEAD.index), f"order of {tags}"
        name, version = self._name(element, "rule"), self._family(element)
        where = f"rule '{name}'"
        status = self._text(element, "Status")
        assert status in ("Enable", "Disable") and self._text(element, "PolicyType") == "Network", where
        assert len(self._text(element, "Description")) <= 255
        block = element.find("NetworkPolicy")
        assert block is not None
        self._only(block, self.MATCH + sorted(self.PROFILES))
        action = self._text(block, "Action")
        assert action in ("Accept", "Drop", "Reject"), action
        assert self._text(block, "LogTraffic") in ("Enable", "Disable")
        assert self._text(block, "Schedule") == "All The Time"
        rule: Dict[str, Any] = {
            "name": name, "version": version, "enabled": status == "Enable", "action": action,
            "log": self._text(block, "LogTraffic") == "Enable", "description": self._text(element, "Description"),
            "src_zones": self._zone_list(block, "SourceZones", where), "dst_zones": self._zone_list(block, "DestinationZones", where),
            "sources": self._networks(block, "SourceNetworks", version, where),
            "destinations": self._networks(block, "DestinationNetworks", version, where),
            "services": self._service_list(block, "Services", where), "exclusions": {},
            "profiles": {child.tag: (child.text or "") for child in block if child.tag in self.PROFILES},
        }  # fmt: skip
        exclusions = block.find("Exclusions")
        if exclusions is not None:
            self._only(exclusions, ["SourceZones", "DestinationZones", "SourceNetworks", "DestinationNetworks", "Services"])
            assert len(exclusions), f"{where}: empty <Exclusions>"
            for child in exclusions:
                if child.tag.endswith("Zones"):
                    rule["exclusions"][child.tag] = self._zone_list(exclusions, child.tag, where)
                elif child.tag == "Services":
                    rule["exclusions"][child.tag] = self._service_list(exclusions, child.tag, where)
                else:
                    rule["exclusions"][child.tag] = self._networks(exclusions, child.tag, version, where)
        self._place(element, self.rules[version], rule)

    def _nat_rule(self, element: Any) -> None:
        self._only(element, self.NAT_HEAD)
        name, version = self._name(element, "nat"), self._family(element)
        where = f"NAT rule '{name}'"
        assert self._text(element, "Status") in ("Enable", "Disable")
        assert self._text(element, "LinkedFirewallrule") == "None" and self._text(element, "OverrideInterfaceNATPolicy") == "Disable"
        source, destination = self._text(element, "TranslatedSource"), self._text(element, "TranslatedDestination")
        service = self._text(element, "TranslatedService")
        # What a rule translates to is an address, a range or (a destination) a host name: not a network.
        if source not in ("Original", "MASQ"):
            held = self.hosts.get(source, {})
            assert held.get("kind") in ("ip", "existing") and held.get("version", version) == version, f"{where}: source '{source}'"
            assert held.get("type") != "Network", f"{where}: translated source '{source}' is a network"
        if destination != "Original":
            held = self.hosts.get(destination, {})
            assert held.get("kind") in ("ip", "fqdn", "existing") and held.get("version", version) == version, f"{where}: '{destination}'"
            assert held.get("type") != "Network", f"{where}: translated destination '{destination}' is a network"
        if service != "Original":
            assert destination != "Original" and self.services.get(service, {}).get("kind") == "service", f"{where}: '{service}'"
        interfaces: Dict[str, Optional[List[str]]] = {}
        for tag in ("InboundInterfaces", "OutboundInterfaces"):
            interfaces[tag] = None
            if element.find(tag) is not None:
                interfaces[tag] = self._members(element, tag, "Interface")
                assert self.interfaces is None or all(i in self.interfaces for i in interfaces[tag] or []), f"{where}: {tag}"
                assert not [i for i in interfaces[tag] or [] if i.lower() in ("any", "none")], f"{where}: {tag} holds a word"
        method = element.find("NATMethod")
        if method is not None:
            assert (method.text or "") in ("Round-robin", "First_alive", "Random", "StickyIP", "OnetoOne"), method.text
            assert destination != "Original"
        if destination != "Original":
            assert interfaces["OutboundInterfaces"] is None, f"{where}: an outbound interface with destination NAT"
        rule = {
            "name": name, "version": version, "enabled": self._text(element, "Status") == "Enable",
            "sources": self._networks(element, "OriginalSourceNetworks", version, where),
            "destinations": self._networks(element, "OriginalDestinationNetworks", version, where),
            "services": self._service_list(element, "OriginalServices", where),
            "inbound": interfaces["InboundInterfaces"], "outbound": interfaces["OutboundInterfaces"],
            "source": source, "destination": destination, "service": service, "method": method.text if method is not None else "",
            "description": self._text(element, "Description"),
        }  # fmt: skip
        self._place(element, self.nat[version], rule)

    # -- what the firewall would do ---------------------------------------

    def _host_matches(self, name: str, address: str) -> bool:
        held = self.hosts[name]
        probe = parse_literal(address)
        assert probe is not None
        if held["kind"] == "ip":
            return held["version"] == probe[0] and held["first"] <= probe[1] <= held["last"]
        if held["kind"] in ("group", "fqdngroup"):
            return any(self._host_matches(member, address) for member in held["members"])
        for literal in self.resolved.get(name, []):
            interval = parse_literal(literal)
            assert interval is not None
            if interval[0] == probe[0] and interval[1] <= probe[1] <= interval[2]:
                return True
        return False

    def _service_matches(self, name: str, pkt: Any) -> bool:
        held = self.services[name]
        if held["kind"] == "group":
            return any(self._service_matches(member, pkt) for member in held["members"])
        number = self.PROTOCOLS.get(pkt.proto) or int(pkt.proto)
        for detail in held["details"]:
            if "protocol" in detail:
                if detail["protocol"] == pkt.proto and detail["dst"][0] <= pkt.dport <= detail["dst"][1] \
                        and detail["src"][0] <= pkt.sport <= detail["src"][1]:
                    return True
            elif "number" in detail:
                if detail["number"] == number:
                    return True
            elif detail["icmp"] == pkt.proto and detail["type"] in (-1, pkt.icmp_type):
                return True
        return False

    @staticmethod
    def _version(pkt: Any) -> int:
        probe = parse_literal(pkt.src)
        assert probe is not None
        return probe[0]

    def _criteria(self, rule: Dict[str, Any], pkt: Any) -> Dict[str, bool]:
        """Whether each criterion of a rule (or of its exclusions) holds for a packet; None in the rule is any."""

        def holds(kind: str, listed: Optional[List[str]]) -> bool:
            if listed is None:
                return True
            if kind == "SourceZones":
                return pkt.in_if in listed
            if kind == "DestinationZones":
                return pkt.out_if in listed
            if kind == "Services":
                return any(self._service_matches(name, pkt) for name in listed)
            return any(self._host_matches(name, pkt.src if kind == "SourceNetworks" else pkt.dst) for name in listed)

        return {"match": all(holds(kind, rule[key]) for kind, key in (
            ("SourceZones", "src_zones"), ("DestinationZones", "dst_zones"), ("SourceNetworks", "sources"),
            ("DestinationNetworks", "destinations"), ("Services", "services"))),
            # A rule is skipped only for traffic that matches every kind of exclusion it has.
            "excluded": bool(rule["exclusions"]) and all(holds(kind, listed) for kind, listed in rule["exclusions"].items())}  # fmt: skip

    def deciding(self, pkt: Any) -> Optional[Dict[str, Any]]:
        """The rule that decides about a packet: first match in the rulebase of its IP version."""
        for rule in self.rules[self._version(pkt)]:
            if rule["enabled"]:
                found = self._criteria(rule, pkt)
                if found["match"] and not found["excluded"]:
                    return rule
        return None

    def allows(self, pkt: Any) -> bool:
        rule = self.deciding(pkt)
        return rule is not None and rule["action"] == "Accept"  # what no rule matches is dropped

    def translating(self, pkt: Any) -> Optional[Dict[str, Any]]:
        """The NAT rule that applies to a packet: the first that matches, whatever it translates."""
        for rule in self.nat[self._version(pkt)]:
            if not rule["enabled"]:
                continue
            if rule["inbound"] is not None and pkt.in_if not in rule["inbound"]:
                continue
            if rule["outbound"] is not None and pkt.out_if not in rule["outbound"]:
                continue
            if rule["sources"] is not None and not any(self._host_matches(name, pkt.src) for name in rule["sources"]):
                continue
            if rule["destinations"] is not None and not any(self._host_matches(name, pkt.dst) for name in rule["destinations"]):
                continue
            if rule["services"] is not None and not any(self._service_matches(name, pkt) for name in rule["services"]):
                continue
            return rule
        return None

    def span(self, name: str) -> str:
        """The addresses of an IP host as fwshift writes a literal: ``first-last``, or the one address."""
        import ipaddress

        held = self.hosts[name]
        if held["kind"] != "ip":
            return name
        make = ipaddress.IPv4Address if held["version"] == 4 else ipaddress.IPv6Address
        first, last = str(make(held["first"])), str(make(held["last"]))
        return first if first == last else f"{first}-{last}"


class CiscoConfig:
    """What ``--to fmc`` or ``--to fdm`` wrote, read the way the manager would take it.

    This is not fwshift's parser, and not the loader of the script either: it reads the policy the
    script carries, or the import file, and is strict the way the managers are documented to be.
    An object exists before it is used (for a Management Center: it was created by an earlier
    call), a name is given once whatever its case, a group has members and holds no group of ports
    and no host name, and a rule only says what a rule of that manager can say.
    """

    NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
    FMC_NETWORKS = {"Host": "host", "Network": "network", "Range": "range", "FQDN": "fqdn", "NetworkGroup": "group"}
    FMC_PORTS = {"ProtocolPortObject": "port", "ICMPV4Object": "icmp4", "ICMPV6Object": "icmp6", "PortObjectGroup": "group"}
    FMC_PATHS = {"Host": "object/hosts", "Network": "object/networks", "Range": "object/ranges", "FQDN": "object/fqdns",
                 "NetworkGroup": "object/networkgroups", "ProtocolPortObject": "object/protocolportobjects",
                 "ICMPV4Object": "object/icmpv4objects", "ICMPV6Object": "object/icmpv6objects",
                 "PortObjectGroup": "object/portobjectgroups"}  # fmt: skip
    PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}

    def __init__(self, text: str, zones: Optional[Tuple[str, ...]] = None, interfaces: Optional[Tuple[str, ...]] = None,
                 existing: Optional[Dict[str, List[str]]] = None, existing_ports: Optional[Dict[str, Dict[str, Any]]] = None,
                 resolved: Optional[Dict[str, List[str]]] = None, native: bool = False) -> None:  # fmt: skip
        import json

        self.text = text
        self.fdm = text.startswith("[")
        self.native = native  # names came from the same manager: they are what they are
        self.known_zones, self.known_interfaces = zones, interfaces
        self.resolved = resolved or {}
        self.networks: Dict[str, Dict[str, Any]] = {}
        self.ports: Dict[str, Dict[str, Any]] = {}
        self.rules: List[Dict[str, Any]] = []
        self.nat: List[Dict[str, Any]] = []
        self.zones: List[str] = []
        self.used_existing: List[str] = []
        self._folded: Dict[str, set] = {"network": set(), "port": set(), "rule": set(), "nat": set()}
        system = {"any-ipv4": ["0.0.0.0/0"], "any-ipv6": ["::/0"]}
        system.update(existing or {})
        self._system, self._system_ports = system, existing_ports or {}
        if self.fdm:
            for line in text.splitlines()[1:-1]:
                assert line.startswith("{") and (line.endswith("},") or line.endswith("}")), line[:80]
            entries = json.loads(text)
            assert isinstance(entries, list) and entries, "an import file is a list of objects"
            self._fdm(entries)
        else:
            assert text.startswith("#!/usr/bin/env python3\n"), text[:40]
            head, marker, tail = text.partition("\n# The policy, as data.")
            assert marker and "def main(" in head, "the script holds the loader and then the policy"
            lines = [line[3:] for line in tail.splitlines() if line.startswith("#: ")]
            assert all(line.startswith("#") for line in tail.splitlines()[1:] if line), "only comment lines after the loader"
            self.plan = json.loads("\n".join(lines))
            self._fmc(self.plan)

    # -- shared -----------------------------------------------------------

    def _name(self, name: Any, space: str, limit: int = 64, spaces: bool = False) -> str:
        import re

        assert isinstance(name, str) and name, f"name {name!r}"
        if not self.native:
            pattern = r"[A-Za-z0-9][A-Za-z0-9 ._-]*" if spaces else r"[A-Za-z0-9][A-Za-z0-9._-]*"
            assert re.fullmatch(pattern, name) and len(name) <= limit and name == name.strip(), f"{space} name '{name}'"
        assert name.lower() not in self._folded[space], f"{space} '{name}' is created twice"
        assert space != "network" or name.lower() not in {n.lower() for n in self._system}, f"'{name}' is an object of the manager"
        self._folded[space].add(name.lower())
        return name

    @staticmethod
    def _address(kind: str, value: Any) -> Dict[str, Any]:
        import ipaddress

        assert isinstance(value, str) and value == value.strip(), value
        if kind == "host":
            first = last = int(ipaddress.ip_address(value))
            version = ipaddress.ip_address(value).version
        elif kind == "network":
            network = ipaddress.ip_network(value, strict=True)
            assert "/" in value and network.num_addresses > 1 and network.prefixlen > 0, f"network '{value}'"
            first, last, version = int(network.network_address), int(network.broadcast_address), network.version
        else:
            assert kind == "range" and value.count("-") == 1, f"range '{value}'"
            low, high = (ipaddress.ip_address(part) for part in value.split("-"))
            assert low.version == high.version and int(low) < int(high), f"range '{value}'"
            first, last, version = int(low), int(high), low.version
        return {"kind": kind, "intervals": [(version, first, last)]}

    @staticmethod
    def _port(value: Any) -> Tuple[int, int]:
        assert isinstance(value, str) and value and all(part.isdigit() for part in value.split("-")), f"port '{value}'"
        parts = [int(part) for part in value.split("-")]
        assert len(parts) in (1, 2) and 1 <= parts[0] <= parts[-1] <= 65535 and (len(parts) == 1 or parts[0] < parts[1]), value
        return parts[0], parts[-1]

    def _system_network(self, name: str) -> None:
        if name not in self.networks:
            assert name in self._system, f"network object '{name}' is used and neither created nor on the manager already"
            self.networks[name] = {"kind": "existing", "intervals": [parse_literal(v) for v in self._system[name]]}
            self.used_existing.append(name)

    def _zone(self, name: Any, where: str) -> str:
        assert isinstance(name, str) and name and name.lower() != "any", f"{where}: zone {name!r}"
        assert self.known_zones is None or name in self.known_zones, f"{where}: zone '{name}' does not exist"
        if name not in self.zones:
            self.zones.append(name)
        return name

    # -- a Management Center ----------------------------------------------

    def _fmc_ref(self, ref: Any, where: str, kinds: Tuple[str, ...]) -> str:
        assert isinstance(ref, dict) and set(ref) == {"@ref", "name"}, f"{where}: {ref}"
        kind, name = ref["@ref"], ref["name"]
        assert kind in kinds, f"{where}: a {kind} where one of {kinds} is expected"
        if kind == "SecurityZone":
            assert name in self.plan["zones"], f"{where}: zone '{name}' is not among the zones of the script"
            return self._zone(name, where)
        table = self.networks if kind in self.FMC_NETWORKS else self.ports
        if name not in table:
            listed = {"type": kind, "name": name} in self.plan["existing"]
            assert listed, f"{where}: {kind} '{name}' is used before a call created it"
            if kind in self.FMC_NETWORKS:
                self._system_network(name)
            else:
                assert name in self._system_ports, f"{where}: port object '{name}' is not on the manager"
                self.ports[name] = dict(self._system_ports[name])
        held = table[name]
        expected = (self.FMC_NETWORKS if kind in self.FMC_NETWORKS else self.FMC_PORTS)[kind]
        assert held["kind"] in (expected, "existing") or held.get("fmc") == kind, f"{where}: '{name}' is a {held['kind']}, not a {kind}"
        return name

    def _fmc(self, plan: Dict[str, Any]) -> None:
        assert set(plan) == {"format", "generator", "policy", "description", "default_action", "zones", "existing", "steps",
                             "rules", "nat"} and plan["format"] == 1, sorted(plan)  # fmt: skip
        assert plan["default_action"] == "BLOCK" and isinstance(plan["policy"], str) and 0 < len(plan["policy"]) <= 50
        assert all(isinstance(zone, str) and zone for zone in plan["zones"]) and len(set(plan["zones"])) == len(plan["zones"])
        seen_paths: List[str] = []
        for step in plan["steps"]:
            assert set(step) == {"what", "type", "path", "items"} and step["items"], step.get("what")
            kind = step["type"]
            assert self.FMC_PATHS[kind] == step["path"], step
            assert kind == "NetworkGroup" or step["path"] not in seen_paths, f"{step['path']} in two steps"
            seen_paths.append(step["path"])
            created: List[Tuple[str, Dict[str, Any]]] = []
            for item in step["items"]:
                assert item["type"] == kind, item
                where = f"{kind} '{item.get('name')}'"
                assert len(item.get("description", "x")) <= 200 and item.get("description", "x") != "", where
                if kind in self.FMC_NETWORKS:
                    name = self._name(item["name"], "network")
                    if kind == "NetworkGroup":
                        assert set(item) <= {"type", "name", "description", "objects"} and item["objects"], where
                        members = [self._fmc_ref(ref, where, ("Host", "Network", "Range", "NetworkGroup")) for ref in item["objects"]]
                        assert len(set(members)) == len(members), f"{where} lists a member twice"
                        created.append((name, {"kind": "group", "members": members}))
                    elif kind == "FQDN":
                        assert set(item) <= {"type", "name", "description", "value", "dnsResolution"}, where
                        assert item["dnsResolution"] in ("IPV4_ONLY", "IPV6_ONLY", "IPV4_AND_IPV6") and "." in item["value"], where
                        created.append((name, {"kind": "fqdn", "fqdn": item["value"], "resolution": item["dnsResolution"]}))
                    else:
                        assert set(item) <= {"type", "name", "description", "value"}, where
                        created.append((name, self._address(self.FMC_NETWORKS[kind], item["value"])))
                else:
                    name = self._name(item["name"], "port")
                    if kind == "PortObjectGroup":
                        assert set(item) <= {"type", "name", "description", "objects"} and item["objects"], where
                        members = [self._fmc_ref(ref, where, ("ProtocolPortObject", "ICMPV4Object", "ICMPV6Object"))
                                   for ref in item["objects"]]  # fmt: skip
                        assert len(set(members)) == len(members), f"{where} lists a member twice"
                        created.append((name, {"kind": "group", "members": members}))
                    elif kind == "ProtocolPortObject":
                        assert set(item) <= {"type", "name", "description", "protocol", "port"}, where
                        assert item["protocol"] in ("TCP", "UDP"), where
                        low, high = self._port(item["port"]) if "port" in item else (0, 65535)
                        created.append((name, {"kind": "port", "protocol": item["protocol"].lower(), "low": low, "high": high}))
                    else:
                        assert set(item) <= {"type", "name", "description", "icmpType", "code"}, where
                        assert "code" not in item or "icmpType" in item, f"{where}: a code without a type"
                        for key in ("icmpType", "code"):
                            assert key not in item or (isinstance(item[key], str) and item[key].isdigit() and int(item[key]) < 256), where
                        created.append((name, {"kind": "icmp4" if kind == "ICMPV4Object" else "icmp6",
                                               "type": int(item["icmpType"]) if "icmpType" in item else None,
                                               "code": int(item["code"]) if "code" in item else None}))  # fmt: skip
            # What one call creates is there for the next call, not for itself.
            for name, held in created:
                held["fmc"] = kind
                (self.networks if kind in self.FMC_NETWORKS else self.ports)[name] = held
        for rule in plan["rules"]:
            self.rules.append(self._fmc_rule(rule))
        for rule in plan["nat"]:
            self.nat.append(self._fmc_nat(rule))

    def _fmc_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {"type", "name", "enabled", "action", "logBegin", "logEnd", "sendEventsToFMC", "logFiles", "sourceZones",
                   "destinationZones", "sourceNetworks", "destinationNetworks", "sourcePorts", "destinationPorts", "newComments"}  # fmt: skip
        assert rule["type"] == "AccessRule" and set(rule) <= allowed, sorted(set(rule) - allowed)
        name = self._name(rule["name"], "rule", 50, spaces=True)
        where = f"rule '{name}'"
        assert rule["action"] in ("ALLOW", "TRUST", "BLOCK", "BLOCK_RESET"), where
        for key in ("enabled", "logBegin", "logEnd", "sendEventsToFMC", "logFiles"):
            assert isinstance(rule[key], bool), f"{where}: {key}"
        assert not (rule["action"].startswith("BLOCK") and rule["logEnd"]), f"{where}: a blocked connection has no end to log"
        assert rule["sendEventsToFMC"] == (rule["logBegin"] or rule["logEnd"]), where
        assert all(isinstance(c, str) and 0 < len(c) <= 500 for c in rule.get("newComments", [])), where
        out: Dict[str, Any] = {"name": name, "enabled": rule["enabled"], "log": rule["logBegin"] or rule["logEnd"],
                               "action": {"ALLOW": "allow", "TRUST": "trust", "BLOCK": "block", "BLOCK_RESET": "reset"}[rule["action"]],
                               "comment": " ".join(rule.get("newComments", []))}  # fmt: skip
        for key, short in (("sourceZones", "src_zones"), ("destinationZones", "dst_zones")):
            out[short] = None
            if key in rule:
                assert set(rule[key]) == {"objects"} and rule[key]["objects"], f"{where}: {key}"
                out[short] = [self._fmc_ref(ref, where, ("SecurityZone",)) for ref in rule[key]["objects"]]
        for key, short in (("sourceNetworks", "sources"), ("destinationNetworks", "destinations")):
            out[short] = None
            if key in rule:
                assert set(rule[key]) == {"objects"} and rule[key]["objects"], f"{where}: {key} that names nothing"
                out[short] = [self._fmc_ref(ref, where, tuple(self.FMC_NETWORKS)) for ref in rule[key]["objects"]]
        for key, short in (("sourcePorts", "src_ports"), ("destinationPorts", "dst_ports")):
            out[short] = None
            if key in rule:
                assert set(rule[key]) <= {"objects", "literals"} and all(rule[key].values()), f"{where}: {key}"
                listed: List[Any] = [self._fmc_ref(ref, where, tuple(self.FMC_PORTS)) for ref in rule[key].get("objects", [])]
                for literal in rule[key].get("literals", []):
                    assert set(literal) == {"type", "protocol"} and literal["type"] == "PortLiteral", f"{where}: {literal}"
                    number = int(literal["protocol"])
                    assert isinstance(literal["protocol"], str) and 1 < number < 256 and number not in (6, 17, 58), f"{where}: {literal}"
                    listed.append(number)
                out[short] = listed
        if out["src_ports"] is not None:
            # Source and destination ports of one rule are of one transport protocol.
            protocols = {p for name_ in out["src_ports"] + (out["dst_ports"] or []) for p in self._port_protocols(name_)}
            assert protocols in ({"tcp"}, {"udp"}), f"{where}: source ports with {sorted(map(str, protocols))}"
        return out

    def _port_protocols(self, name: Any) -> List[Any]:
        if isinstance(name, int):
            return [name]
        held = self.ports[name]
        if held["kind"] == "group":
            return [p for member in held["members"] for p in self._port_protocols(member)]
        return [held["protocol"] if held["kind"] == "port" else held["kind"]]

    def _nat_checks(self, out: Dict[str, Any], where: str) -> Dict[str, Any]:
        """What the documentation of both managers says about the fields of a manual NAT rule."""
        for name in (out["osrc"], out["tsrc"], out["odst"], out["tdst"], out["pool"]):
            if name is not None:
                assert self._kinds(name) <= {"host", "network", "range", "existing"}, f"{where}: '{name}' holds a host name"
                versions = {i[0] for i in self.span_of(name)}
                assert len(versions) == 1, f"{where}: '{name}' holds IPv4 and IPv6 addresses"
        ports = [out[key] for key in ("osp", "tsp", "odp", "tdp") if out[key] is not None]
        assert len({self.ports[name]["protocol"] for name in ports}) <= 1, f"{where}: ports of two protocols"
        for name in ports:
            assert self.ports[name]["kind"] == "port" and (self.ports[name]["low"], self.ports[name]["high"]) != (0, 65535), \
                f"{where}: '{name}' is every port"
        assert (out["osp"] is None) == (out["tsp"] is None) and (out["odp"] is None) == (out["tdp"] is None), f"{where}: half a port translation"
        if out["to_interface"]:
            assert out["tsrc"] is None and out["dst_if"], f"{where}: the interface address of no interface"
        if out["from_interface"]:
            assert out["odst"] is None and out["tdst"] is not None and out["odp"] is not None and out["src_if"], where
        else:
            assert (out["odst"] is None) == (out["tdst"] is None), f"{where}: half a destination translation"
        if out["pool"] is not None:
            assert not out["static"] and out["tsrc"] is None and self._kinds(out["pool"]) <= {"host", "range"}, f"{where}: pool"
        if not out["static"]:
            assert not out["unidirectional"], f"{where}: unidirectional is said of a static rule"
            assert out["to_interface"] or out["pool"] is not None or (out["tsrc"] is not None and self._kinds(out["tsrc"]) <= {"host", "range"}), \
                f"{where}: a dynamic rule translates to hosts and ranges"
        elif not out["to_interface"]:
            assert (out["osrc"] is None) == (out["tsrc"] is None) or self.fdm is False, f"{where}: a static rule maps a source to a source"
            assert out["tsrc"] is not None or out["osrc"] is None, f"{where}: static NAT to nothing"
        return out

    def _kinds(self, name: str) -> set:
        held = self.networks[name]
        if held["kind"] == "group":
            return {kind for member in held["members"] for kind in self._kinds(member)}
        return {held["kind"]}

    def _fmc_nat(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        flags = {"enabled", "unidirectional", "interfaceInTranslatedSource", "interfaceInOriginalDestination", "noProxyArp",
                 "routeLookup", "dns", "fallThrough", "netToNet", "interfaceIpv6"}  # fmt: skip
        refs = {"originalSource": "osrc", "translatedSource": "tsrc", "originalDestination": "odst", "translatedDestination": "tdst"}
        ports = {"originalSourcePort": "osp", "translatedSourcePort": "tsp", "originalDestinationPort": "odp",
                 "translatedDestinationPort": "tdp"}  # fmt: skip
        allowed = {"type", "natType", "description", "sourceInterface", "destinationInterface", "patOptions"} | flags | set(refs) | set(ports)
        assert rule["type"] == "FTDManualNatRule" and set(rule) <= allowed and flags <= set(rule), sorted(set(rule) ^ allowed)
        where = f"NAT rule {len(self.nat) + 1}"
        assert rule["natType"] in ("STATIC", "DYNAMIC") and all(isinstance(rule[flag], bool) for flag in flags), where
        assert not (rule["dns"] or rule["fallThrough"] or rule["netToNet"] or rule["interfaceIpv6"]), where
        assert len(rule.get("description", "x")) <= 200, where
        out: Dict[str, Any] = {"name": f"nat-{len(self.nat) + 1}", "enabled": rule["enabled"], "static": rule["natType"] == "STATIC",
                               "unidirectional": rule["unidirectional"], "to_interface": rule["interfaceInTranslatedSource"],
                               "from_interface": rule["interfaceInOriginalDestination"], "pool": None,
                               "description": rule.get("description", "")}  # fmt: skip
        for key, short in (("sourceInterface", "src_if"), ("destinationInterface", "dst_if")):
            out[short] = self._fmc_ref(rule[key], where, ("SecurityZone",)) if key in rule else ""
        for key, short in refs.items():
            out[short] = self._fmc_ref(rule[key], where, tuple(self.FMC_NETWORKS)) if key in rule else None
        for key, short in ports.items():
            out[short] = self._fmc_ref(rule[key], where, ("ProtocolPortObject",)) if key in rule else None
        if "patOptions" in rule:
            options = rule["patOptions"]
            assert set(options) == {"patPoolAddress", "interfacePat", "includeReserve", "roundRobin", "extendedPat", "flatPortRange"}, where
            assert not any(options[key] for key in options if key != "patPoolAddress"), where
            out["pool"] = self._fmc_ref(options["patPoolAddress"], where, tuple(self.FMC_NETWORKS))
        assert out["osrc"] is not None, f"{where}: a Management Center wants an original source"
        return self._nat_checks(out, where)

    # -- a Device Manager -------------------------------------------------

    def _fdm_ref(self, ref: Any, where: str, kinds: Tuple[str, ...]) -> str:
        assert isinstance(ref, dict) and set(ref) == {"type", "name"}, f"{where}: {ref}"
        kind, name = ref["type"], ref["name"]
        assert kind in kinds, f"{where}: a {kind} where one of {kinds} is expected"
        if kind == "securityzone":
            return self._zone(name, where)
        if kind == "physicalinterface":
            assert isinstance(name, str) and name and (self.known_interfaces is None or name in self.known_interfaces), f"{where}: {name}"
            return name
        if kind in ("networkobject", "networkobjectgroup"):
            if name not in self.networks:
                self._system_network(name)
            held = self.networks[name]
            assert (held["kind"] == "group") == (kind == "networkobjectgroup") or held["kind"] == "existing", f"{where}: '{name}' as {kind}"
            return name
        if name not in self.ports:
            assert name in self._system_ports, f"{where}: port object '{name}' is used before it is created"
            self.ports[name] = dict(self._system_ports[name])
        assert self.ports[name]["fdm"] == kind, f"{where}: '{name}' is a {self.ports[name]['fdm']}, not a {kind}"
        return name

    def _fdm(self, entries: List[Any]) -> None:
        from fwshift.appmap import FDM_ICMP6_CODES, FDM_ICMP6_TYPES, FDM_ICMP_CODES, FDM_ICMP_TYPES, FDM_PROTOCOLS

        head = entries[0]
        assert set(head) == {"type", "hardwareModel", "softwareVersion", "apiVersion", "configType", "exportType"}, sorted(head)
        assert head["type"] == "metadata" and head["apiVersion"] == "latest" and head["configType"] == "DELTA_CONFIG", head
        assert all(isinstance(head[key], str) and head[key] for key in head)
        self.metadata = head
        port_objects = ("tcpportobject", "udpportobject", "protocolobject", "icmpv4portobject", "icmpv6portobject")
        stage = 0  # objects, then rules, then NAT rules
        for entry in entries[1:]:
            assert set(entry) <= {"type", "action", "data", "parentName"} and entry["type"] == "identitywrapper", entry
            assert entry["action"] == "CREATE" and list(entry)[-1] == "data", entry
            data = entry["data"]
            kind = data["type"]
            where = f"{kind} '{data.get('name')}'"
            assert "id" not in data and "version" not in data, f"{where}: an id or a version of another device"
            assert 0 < len(data.get("description", "x")) <= 200 and ";" not in data.get("description", ""), where
            order = 1 if kind == "accessrule" else 2 if kind == "manualnatrule" else 0
            assert order >= stage, f"{where} after what uses it"
            stage = order
            assert ("parentName" in entry) == (kind == "manualnatrule"), where
            if kind == "networkobject":
                assert set(data) <= {"type", "name", "description", "subType", "value", "dnsResolution"}, where
                name = self._name(data["name"], "network")
                if data["subType"] == "FQDN":
                    assert data["dnsResolution"] in ("IPV4_ONLY", "IPV6_ONLY", "IPV4_AND_IPV6") and "." in data["value"], where
                    self.networks[name] = {"kind": "fqdn", "fqdn": data["value"], "resolution": data["dnsResolution"]}
                else:
                    assert data["subType"] in ("HOST", "NETWORK", "RANGE") and "dnsResolution" not in data, where
                    self.networks[name] = self._address(data["subType"].lower(), data["value"])
            elif kind == "networkobjectgroup":
                assert set(data) <= {"type", "name", "description", "objects"} and data["objects"], where
                name = self._name(data["name"], "network")
                members = [self._fdm_ref(ref, where, ("networkobject",)) for ref in data["objects"]]
                assert len(set(members)) == len(members) and "fqdn" not in {self.networks[m]["kind"] for m in members}, where
                self.networks[name] = {"kind": "group", "members": members}
            elif kind in ("tcpportobject", "udpportobject"):
                assert set(data) <= {"type", "name", "description", "port"}, where
                low, high = self._port(data["port"])
                self.ports[self._name(data["name"], "port")] = {"kind": "port", "protocol": kind[:3], "low": low, "high": high, "fdm": kind}
            elif kind == "protocolobject":
                assert set(data) <= {"type", "name", "description", "protocol"} and data["protocol"] in FDM_PROTOCOLS, where
                assert data["protocol"] not in ("TCP", "UDP"), where
                self.ports[self._name(data["name"], "port")] = {"kind": "protocol", "number": FDM_PROTOCOLS[data["protocol"]], "fdm": kind}
            elif kind in ("icmpv4portobject", "icmpv6portobject"):
                prefix = kind[:6]
                types, codes = (FDM_ICMP_TYPES, FDM_ICMP_CODES) if prefix == "icmpv4" else (FDM_ICMP6_TYPES, FDM_ICMP6_CODES)
                assert set(data) <= {"type", "name", "description", f"{prefix}Type", f"{prefix}Code"}, where
                type_name = data[f"{prefix}Type"]
                assert type_name == "ANY" or type_name in types, f"{where}: type {type_name}"
                if f"{prefix}Code" in data:
                    assert type_name != "ANY" and codes[data[f"{prefix}Code"]][0] == types[type_name], f"{where}: code"
                self.ports[self._name(data["name"], "port")] = {
                    "kind": "icmp4" if prefix == "icmpv4" else "icmp6", "type": None if type_name == "ANY" else types[type_name],
                    "code": codes[data[f"{prefix}Code"]][1] if f"{prefix}Code" in data else None, "fdm": kind}  # fmt: skip
            elif kind == "portobjectgroup":
                assert set(data) <= {"type", "name", "description", "objects"} and data["objects"], where
                name = self._name(data["name"], "port")
                members = [self._fdm_ref(ref, where, port_objects) for ref in data["objects"]]
                assert len(set(members)) == len(members), where
                self.ports[name] = {"kind": "group", "members": members, "fdm": kind}
            elif kind == "accessrule":
                self.rules.append(self._fdm_rule(data, port_objects))
            else:
                assert kind == "manualnatrule" and entry["parentName"] == "NGFW-Before-Auto-NAT-Policy", where
                self.nat.append(self._fdm_nat(data))

    def _fdm_rule(self, rule: Dict[str, Any], port_objects: Tuple[str, ...]) -> Dict[str, Any]:
        lists = ("sourceZones", "destinationZones", "sourceNetworks", "destinationNetworks", "sourcePorts", "destinationPorts")
        assert set(rule) == {"type", "name", "ruleAction", "eventLogAction"} | set(lists), sorted(rule)
        name = self._name(rule["name"], "rule", 128)
        where = f"rule '{name}'"
        assert rule["ruleAction"] in ("PERMIT", "TRUST", "DENY") and rule["eventLogAction"] in ("LOG_FLOW_END", "LOG_BOTH", "LOG_NONE"), where
        out: Dict[str, Any] = {"name": name, "enabled": True, "log": rule["eventLogAction"] != "LOG_NONE", "comment": "",
                               "action": {"PERMIT": "allow", "TRUST": "trust", "DENY": "block"}[rule["ruleAction"]]}  # fmt: skip
        kinds = {"Zones": ("securityzone",), "Networks": ("networkobject", "networkobjectgroup"), "Ports": port_objects + ("portobjectgroup",)}
        short = {"sourceZones": "src_zones", "destinationZones": "dst_zones", "sourceNetworks": "sources",
                 "destinationNetworks": "destinations", "sourcePorts": "src_ports", "destinationPorts": "dst_ports"}  # fmt: skip
        for key in lists:
            assert isinstance(rule[key], list), f"{where}: {key}"
            listed = [self._fdm_ref(ref, where, next(v for k, v in kinds.items() if key.endswith(k))) for ref in rule[key]]
            assert len(set(listed)) == len(listed), f"{where}: {key} names something twice"
            out[short[key]] = listed or None  # an empty list is any
        if out["src_ports"] is not None:
            protocols = {p for name_ in out["src_ports"] + (out["dst_ports"] or []) for p in self._port_protocols(name_)}
            assert protocols in ({"tcp"}, {"udp"}), f"{where}: source ports with {sorted(map(str, protocols))}"
        return out

    def _fdm_nat(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        flags = {"enabled", "unidirectional", "interfaceInTranslatedSource", "interfaceInOriginalDestination", "noProxyArp",
                 "routeLookup", "dns", "netToNet", "interfaceIPv6"}  # fmt: skip
        refs = {"originalSource": "osrc", "translatedSource": "tsrc", "originalDestination": "odst", "translatedDestination": "tdst"}
        ports = {"originalSourcePort": "osp", "translatedSourcePort": "tsp", "originalDestinationPort": "odp",
                 "translatedDestinationPort": "tdp"}  # fmt: skip
        allowed = {"type", "name", "natType", "description", "sourceInterface", "destinationInterface", "patOptions"} | flags | set(refs) | set(ports)
        assert set(rule) <= allowed and flags <= set(rule), sorted(set(rule) ^ allowed)
        name = self._name(rule["name"], "nat", 128)
        where = f"NAT rule '{name}'"
        assert rule["natType"] in ("STATIC", "DYNAMIC") and all(isinstance(rule[flag], bool) for flag in flags), where
        assert not (rule["dns"] or rule["netToNet"] or rule["interfaceIPv6"]), where
        out: Dict[str, Any] = {"name": name, "enabled": rule["enabled"], "static": rule["natType"] == "STATIC",
                               "unidirectional": rule["unidirectional"], "to_interface": rule["interfaceInTranslatedSource"],
                               "from_interface": rule["interfaceInOriginalDestination"], "pool": None,
                               "description": rule.get("description", "")}  # fmt: skip
        for key, short in (("sourceInterface", "src_if"), ("destinationInterface", "dst_if")):
            out[short] = self._fdm_ref(rule[key], where, ("physicalinterface",)) if key in rule else ""
        for key, short in refs.items():
            out[short] = self._fdm_ref(rule[key], where, ("networkobject", "networkobjectgroup")) if key in rule else None
        for key, short in ports.items():
            out[short] = self._fdm_ref(rule[key], where, ("tcpportobject", "udpportobject")) if key in rule else None
            if out[short] is not None:
                assert self.ports[out[short]]["low"] == self.ports[out[short]]["high"], f"{where}: {key} is not one port"
        if "patOptions" in rule:
            options = rule["patOptions"]
            assert set(options) == {"type", "patPoolAddress", "interfacePat", "roundRobin", "flat", "extended", "includeReserve"}, where
            assert options["type"] == "patoptions" and not any(options[k] for k in options if k not in ("type", "patPoolAddress")), where
            out["pool"] = self._fdm_ref(options["patPoolAddress"], where, ("networkobject", "networkobjectgroup"))
        return self._nat_checks(out, where)

    # -- what the firewall would do ---------------------------------------

    def span_of(self, name: str) -> List[Tuple[int, int, int]]:
        """The addresses of a network object or group; a host name stands for what a test says it resolves to."""
        held = self.networks[name]
        if held["kind"] == "group":
            return [interval for member in held["members"] for interval in self.span_of(member)]
        if held["kind"] == "fqdn":
            wanted = {"IPV4_ONLY": (4,), "IPV6_ONLY": (6,)}.get(held["resolution"], (4, 6))
            found = [parse_literal(literal) for literal in self.resolved.get(name, [])]
            return [interval for interval in found if interval is not None and interval[0] in wanted]
        return list(held["intervals"])

    def _in(self, names: Optional[List[str]], address: str) -> bool:
        if names is None:
            return True
        probe = parse_literal(address)
        assert probe is not None
        return any(i[0] == probe[0] and i[1] <= probe[1] <= i[2] for name in names for i in self.span_of(name))

    def _port_matches(self, name: Any, pkt: Any, source: bool) -> bool:
        number = self.PROTOCOLS.get(pkt.proto) or int(pkt.proto)
        if isinstance(name, int):
            return name == number
        held = self.ports[name]
        if held["kind"] == "group":
            return any(self._port_matches(member, pkt, source) for member in held["members"])
        if held["kind"] == "port":
            return held["protocol"] == pkt.proto and held["low"] <= (pkt.sport if source else pkt.dport) <= held["high"]
        if held["kind"] == "protocol":
            return held["number"] == number
        return pkt.proto == ("icmp" if held["kind"] == "icmp4" else "icmp6") and held["type"] in (None, pkt.icmp_type)

    def deciding(self, pkt: Any) -> Optional[Dict[str, Any]]:
        """The rule that decides about a packet that opens a connection: the first that matches."""
        for rule in self.rules:
            if not rule["enabled"]:
                continue
            if rule["src_zones"] is not None and pkt.in_if not in rule["src_zones"]:
                continue
            if rule["dst_zones"] is not None and pkt.out_if not in rule["dst_zones"]:
                continue
            if not self._in(rule["sources"], pkt.src) or not self._in(rule["destinations"], pkt.dst):
                continue
            if rule["src_ports"] is not None and not any(self._port_matches(name, pkt, True) for name in rule["src_ports"]):
                continue
            if rule["dst_ports"] is not None and not any(self._port_matches(name, pkt, False) for name in rule["dst_ports"]):
                continue
            return rule
        return None

    def allows(self, pkt: Any) -> bool:
        rule = self.deciding(pkt)
        return rule is not None and rule["action"] in ("allow", "trust")  # what no rule matches is blocked

    def translating(self, pkt: Any) -> Optional[Dict[str, Any]]:
        """The manual NAT rule that applies to a packet that opens a connection: the first that matches."""
        for rule in self.nat:
            if not rule["enabled"]:
                continue
            if rule["src_if"] and pkt.in_if != rule["src_if"]:
                continue
            # A rule that translates the destination decides where the packet leaves by: it does not ask.
            if rule["dst_if"] and rule["tdst"] == rule["odst"] and pkt.out_if != rule["dst_if"]:
                continue
            if rule["osrc"] is not None and not self._in([rule["osrc"]], pkt.src):
                continue
            if rule["odst"] is not None and not self._in([rule["odst"]], pkt.dst):
                continue
            if rule["odp"] is not None and not self._port_matches(rule["odp"], pkt, False):
                continue
            if rule["osp"] is not None and not self._port_matches(rule["osp"], pkt, True):
                continue
            return rule
        return None


_LITERALS: Dict[str, Any] = {}


def _literal(text: str) -> Any:
    """parse_literal, remembered: the judges ask for the same few addresses a million times."""
    if text not in _LITERALS:
        _LITERALS[text] = parse_literal(text)
    return _LITERALS[text]


class PfSense:
    """A pfSense firewall, as far as its ``config.xml`` says what it does with a packet it forwards.

    Written from pfSense's own ``filter.inc`` and from pf, and not from the parser of FWShift: it reads
    the XML itself. What it does not know raises, so that a test never passes on something it took
    for something else. Host names in aliases match nothing here.
    """

    PRIVATE = ("10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
    NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132, "esp": 50, "ah": 51, "gre": 47, "etherip": 97,
               "ipv6": 41, "igmp": 2, "pim": 103, "ospf": 89, "carp": 112, "pfsync": 240}  # fmt: skip
    ICMP = {"echorep": 0, "unreach": 3, "squench": 4, "redir": 5, "althost": 6, "echoreq": 8, "routeradv": 9, "routersol": 10,
            "timex": 11, "paramprob": 12, "timereq": 13, "timerep": 14, "inforeq": 15, "inforep": 16, "maskreq": 17,
            "maskrep": 18, "trace": 30, "dataconv": 31, "mobredir": 32, "ipv6-where": 33, "ipv6-here": 34,
            "mobregreq": 35, "mobregrep": 36, "skip": 39, "photuris": 40}  # fmt: skip
    ICMP6 = {"unreach": 1, "toobig": 2, "timex": 3, "paramprob": 4, "echoreq": 128, "echorep": 129, "groupqry": 130,
             "listqry": 130, "grouprep": 131, "listenrep": 131, "groupterm": 132, "listendone": 132, "routersol": 133,
             "routeradv": 134, "neighbrsol": 135, "neighbradv": 136, "redir": 137, "routrrenum": 138, "wrureq": 139,
             "wrurep": 140, "fqdnreq": 139, "fqdnrep": 140, "niqry": 139, "nirep": 140, "mtraceresp": 200, "mtrace": 201}  # fmt: skip
    KNOWN = {"id", "tracker", "type", "interface", "ipprotocol", "statetype", "protocol", "icmptype", "source", "destination",
             "disabled", "log", "descr", "floating", "quick", "direction", "associated-rule-id", "created", "updated", "tag",
             "max", "max-src-nodes", "max-src-conn", "max-src-states", "statetimeout", "gateway", "sched", "os", "tagged",
             "target", "local-port", "natreflection", "nordr", "nosync"}  # fmt: skip

    def __init__(self, text: str) -> None:
        import xml.etree.ElementTree as ET

        self.root = ET.fromstring(text)
        assert self.root.tag == "pfsense", self.root.tag
        self._cache: Dict[str, Any] = {}

    # -- reading ---------------------------------------------------------------------------------

    def restore(self, text: str) -> None:
        """What Diagnostics > Backup & Restore does with a file, once per area: the area is replaced."""
        import xml.etree.ElementTree as ET

        other = ET.fromstring(text)
        assert other.tag == "pfsense", other.tag
        for area in ("aliases", "nat", "filter"):
            new = other.find(area)
            if new is None or (len(new) == 0 and not (new.text or "").strip()):
                continue  # an area that is not in the file, or is empty, is refused: the old one stays
            assert f"<{area}>" in text
            old = self.root.find(area)
            if old is not None:
                self.root.remove(old)
            self.root.append(new)
        self._cache = {}

    def _t(self, node: Any, tag: str) -> str:
        if node is None:
            return ""
        texts = self._cache.setdefault("texts", {})
        key = (id(node), tag)
        if key not in texts:
            found = node.findall(tag)
            assert len(found) <= 1, f"<{tag}> twice"
            texts[key] = (found[0].text or "").strip() if found else ""
        return texts[key]  # type: ignore[no-any-return]

    def _has(self, node: Any, tag: str) -> bool:
        if node is None:
            return False
        flags = self._cache.setdefault("flags", {})
        key = (id(node), tag)
        if key not in flags:
            flags[key] = node.find(tag) is not None
        return flags[key]  # type: ignore[no-any-return]

    def _find(self, node: Any, tag: str) -> Any:
        found = self._cache.setdefault("nodes", {})
        key = (id(node), tag)
        if key not in found:
            found[key] = node.find(tag)
        return found[key]

    def version(self) -> float:
        return float(self._t(self.root, "version") or 99)

    def interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Enabled interfaces: key -> description, addresses, whether it has a gateway."""
        import ipaddress

        if "interfaces" in self._cache:
            return self._cache["interfaces"]  # type: ignore[no-any-return]
        out: Dict[str, Dict[str, Any]] = {}
        self._cache["interfaces"] = out
        for node in self.root.find("interfaces") if self.root.find("interfaces") is not None else []:
            if not self._has(node, "enable"):
                continue
            entry: Dict[str, Any] = {"descr": self._t(node, "descr") or node.tag.upper(), "v4": None, "v6": None, "vips": []}
            address, bits = self._t(node, "ipaddr"), self._t(node, "subnet")
            if address and address[0].isdigit() and bits:
                entry["v4"] = ipaddress.ip_interface(f"{address}/{bits}")
            address, bits = self._t(node, "ipaddrv6"), self._t(node, "subnetv6")
            if ":" in address and bits:
                entry["v6"] = ipaddress.ip_interface(f"{address}/{bits}")
            entry["gateway"] = bool(self._t(node, "gateway")) or self._t(node, "ipaddr") in ("dhcp", "pppoe", "pptp", "l2tp", "ppp")
            entry["blockpriv"] = self._has(node, "blockpriv")
            out[node.tag] = entry
        vips = self.root.findall("virtualip/vip")
        parents = {"_vip" + self._t(vip, "uniqid"): self._t(vip, "interface") for vip in vips if self._t(vip, "uniqid")}
        for vip in vips:
            owner = out.get(parents.get(self._t(vip, "interface"), self._t(vip, "interface")))
            if owner is not None:
                owner["vips"].append((ipaddress.ip_interface(f"{self._t(vip, 'subnet')}/{self._t(vip, 'subnet_bits') or 32}"), self._t(vip, "mode")))
        return out

    def key(self, zone: str) -> str:
        """The interface a description (or a key) stands for."""
        for key, entry in self.interfaces().items():
            if zone in (key, entry["descr"]):
                return key
        raise AssertionError(f"no interface {zone}")

    def groups(self) -> Dict[str, List[str]]:
        if "groups" not in self._cache:
            self._cache["groups"] = {
                self._t(entry, "ifname"): self._t(entry, "members").split() for entry in self.root.findall("ifgroups/ifgroupentry")
            }
        return self._cache["groups"]  # type: ignore[no-any-return]

    def aliases(self) -> Dict[str, Tuple[str, List[str]]]:
        if "aliases" not in self._cache:
            self._cache["aliases"] = {
                self._t(alias, "name"): (self._t(alias, "type"), self._t(alias, "address").split()) for alias in self.root.findall("aliases/alias")
            }
        return self._cache["aliases"]  # type: ignore[no-any-return]

    # -- matching --------------------------------------------------------------------------------

    @staticmethod
    def _within(address: str, network: str) -> bool:
        a, b = _literal(address), _literal(network)
        return a is not None and b is not None and a[0] == b[0] and b[1] <= a[1] <= b[2]

    def _alias_holds(self, name: str, address: str, seen: Tuple[str, ...] = ()) -> bool:
        kind, entries = self.aliases()[name]
        assert kind in ("host", "network"), f"alias {name} of type {kind} as an address"
        for entry in entries:
            if entry in self.aliases():
                if entry not in seen and self._alias_holds(entry, address, seen + (name,)):
                    return True
            elif _literal(entry) is not None and "-" not in entry:
                if self._within(address, entry):
                    return True
            else:
                assert not entry[0].isdigit() and ":" not in entry, f"entry {entry} of alias {name}"  # a host name
        return False

    def _ports_of(self, text: str, seen: Tuple[str, ...] = ()) -> Optional[List[Tuple[int, int]]]:
        """Port ranges of a port, a range or an alias; None when pfSense cannot resolve it."""
        if text in self.aliases():
            kind, entries = self.aliases()[text]
            if kind != "port" or text in seen or not entries:
                return None
            out: List[Tuple[int, int]] = []
            for entry in entries:
                found = self._ports_of(entry, seen + (text,))
                if found is None:
                    return None
                out += found
            return out
        names = {"http": 80, "https": 443, "ssh": 22, "smtp": 25, "domain": 53}  # /etc/services, as far as the tests go
        if text in names:
            return [(names[text], names[text])]
        first, _, last = text.replace(":", "-").partition("-")
        if not first.isdigit() or (last and not last.isdigit()):
            return None
        return [(int(first), int(last or first))]

    def _network(self, word: str, family: int) -> Optional[List[str]]:
        """The networks a word of pfSense stands for; None when it stands for nothing of this IP version."""
        interfaces = self.interfaces()
        which = "v4" if family == 4 else "v6"
        if word == "(self)":
            out = [str(entry[which].ip) for entry in interfaces.values() if entry[which] is not None]
            for entry in interfaces.values():
                out += [str(vip.ip) for vip, mode in entry["vips"] if vip.version == family and mode in ("carp", "ipalias")]
            return out
        if word.endswith("ip") and word[:-2] in interfaces:
            own = interfaces[word[:-2]][which]
            return [str(own.ip)] if own is not None else None
        members = self.groups().get(word, [word])
        out = []
        for key in members:
            entry = interfaces.get(key)
            if entry is None:
                continue
            if entry[which] is not None:
                out.append(str(entry[which].network))
            out += [str(vip.network) for vip, _ in entry["vips"] if vip.version == family]
        return out or None

    def _side(self, node: Any, address: str, family: int) -> Optional[bool]:
        """Whether an address matches a side of a rule; None when the rule is not loaded for this IP version."""
        negated = self._has(node, "not")
        if node is None:
            return None
        if self._has(node, "any"):
            return True
        word = self._t(node, "network")
        if word:
            networks = self._network(word, family)
            if networks is None:
                return None
            return any(self._within(address, network) for network in networks) != negated
        text = self._t(node, "address")
        if not text:
            return None
        if text in self.aliases():
            if self.aliases()[text][0] not in ("host", "network"):
                return None
            return self._alias_holds(text, address) != negated
        literal = _literal(text)
        if literal is None or "-" in text or literal[0] != family:
            return None
        return self._within(address, text) != negated

    def _matches(self, rule: Any, pkt: Any, src: str, dst: str, dport: int) -> Optional[bool]:
        """Whether a rule matches; None when pfSense does not load it (for this IP version)."""
        unknown = self._cache.setdefault("tags", {}).setdefault(id(rule), {child.tag for child in rule} - self.KNOWN)
        assert not unknown and not self._t(rule, "os"), unknown
        if self._t(rule, "tagged"):
            return False  # no packet of the tests carries a mark of another rule
        family = 6 if ":" in src else 4
        wanted = {"inet6": [6], "inet46": [4, 6]}.get(self._t(rule, "ipprotocol"), [4])
        if family not in wanted:
            return False
        source = self._side(self._find(rule, "source"), src, family)
        destination = self._side(self._find(rule, "destination"), dst, family)
        if source is None or destination is None:
            return None
        protocol = self._t(rule, "protocol")
        sport_text, dport_text = self._t(self._find(rule, "source"), "port"), self._t(self._find(rule, "destination"), "port")
        if not protocol and (sport_text or dport_text):
            return bool(source and destination and pkt.proto == "tcp")  # filter.inc: proto tcp, and no port without a protocol
        ok = True
        if protocol in ("tcp", "udp", "tcp/udp", "sctp"):
            for text, port in ((sport_text, pkt.sport), (dport_text, dport)):
                if text:
                    ranges = self._ports_of(text)
                    if ranges is None:
                        return None
                    ok = ok and any(low <= port <= high for low, high in ranges)
            ok = ok and pkt.proto in protocol.split("/")
        elif protocol == "icmp":
            table, name = (self.ICMP6, "icmp6") if family == 6 else (self.ICMP, "icmp")
            types = [word for word in self._t(rule, "icmptype").split(",") if word and word != "any"]
            ok = pkt.proto == name and (not types or pkt.icmp_type in [table[word] for word in types])
        elif protocol and protocol != "any":
            ok = str(self.NUMBERS[protocol]) == str(self.NUMBERS.get(pkt.proto, pkt.proto))
        return bool(ok and source and destination)

    # -- the ruleset -----------------------------------------------------------------------------

    def _on(self, rule: Any, key: str) -> bool:
        """Whether a rule is for an interface."""
        names = self._t(rule, "interface")
        if self._has(rule, "floating"):
            if names == "any" and self.version() <= 22.2:
                return False  # pfSense 2.6 looks for an interface called "any", and has none
            if names in ("", "any"):
                return True
            listed = names.split(",")
        else:
            listed = [names]
        return any(key == name or key in self.groups().get(name, []) for name in listed)

    def _ordered(self) -> List[Any]:
        """User rules in the order pfSense writes them: floating, groups, interfaces."""
        if "ordered" in self._cache:
            return self._cache["ordered"]  # type: ignore[no-any-return]
        rules = [rule for rule in self.root.findall("filter/rule") if not self._has(rule, "disabled")]
        floating = [rule for rule in rules if self._has(rule, "floating")]
        groups = list(self.groups())
        tier = [rule for rule in rules if not self._has(rule, "floating") and self._t(rule, "interface") in groups]
        if self.version() > 23.3:
            tier.sort(key=lambda rule: groups.index(self._t(rule, "interface")))
        rest = [rule for rule in rules if not self._has(rule, "floating") and self._t(rule, "interface") not in groups]
        self._cache["ordered"] = floating + tier + rest
        return floating + tier + rest

    def _decide(self, direction: str, key: str, pkt: Any, src: str, dst: str, dport: int) -> Optional[bool]:
        """What the user rules say about a packet that arrives on or leaves by an interface; None when none matches."""
        rule = self._deciding(direction, key, pkt, src, dst, dport)
        return None if rule is None else (self._t(rule, "type") or "pass") == "pass"

    def _deciding(self, direction: str, key: str, pkt: Any, src: str, dst: str, dport: int) -> Any:
        """The user rule that decides about a packet that arrives on or leaves by an interface, or None."""
        last: Any = None
        for rule in self._ordered():
            floating = self._has(rule, "floating")
            if floating:
                way = (self._t(rule, "direction") or "any") if self._t(rule, "floating") == "yes" else "in"
                if way not in (direction, "any"):
                    continue
            elif direction != "in":
                continue
            kind = self._t(rule, "type") or "pass"
            if kind == "match" or not self._on(rule, key):
                continue
            if not self._matches(rule, pkt, src, dst, dport):
                continue
            if not floating or self._has(rule, "quick"):
                return rule
            last = rule
        return last

    # -- NAT -------------------------------------------------------------------------------------

    def _arriving(self, key: str, pkt: Any) -> Tuple[str, int, bool, str]:
        """(destination, port, whether the packet is passed without a rule, the rule) after port forwards and 1:1 NAT."""
        import ipaddress

        if ":" in pkt.dst:
            return pkt.dst, pkt.dport, False, ""
        interfaces = self.interfaces()
        system = self.root.find("system")
        for rule in self.root.findall("nat/rule"):
            if self._has(rule, "disabled"):
                continue
            where = self._t(rule, "interface") or "wan"
            own = self._t(rule, "natreflection")
            on = [where]
            if own in ("purenat",) or (not own and not self._has(system, "disablenatreflection") and self._has(system, "enablenatreflectionpurenat")):
                on += [other for other, entry in interfaces.items() if other != where and not entry["gateway"]]
            else:
                assert own in ("disable", "") and (own or self._has(system, "disablenatreflection")), "NAT reflection by proxy"
            on = [member for name in on for member in self.groups().get(name, [name])]  # a group: each of its interfaces
            if key not in on or not any(name in interfaces for name in on):
                continue
            if not self._matches(rule, pkt, pkt.src, pkt.dst, pkt.dport):
                continue
            if self._has(rule, "nordr"):
                return pkt.dst, pkt.dport, False, self._t(rule, "descr")
            target = self._t(rule, "target")
            if target.endswith("ip") and target[:-2] in interfaces:
                target = str(interfaces[target[:-2]]["v4"].ip)
            elif target in self.aliases():
                target = self.aliases()[target][1][0]
            port = pkt.dport
            local, listed = self._t(rule, "local-port"), self._t(self._find(rule, "destination"), "port")
            if local and listed and self._t(rule, "protocol") in ("tcp", "udp", "tcp/udp", "sctp"):
                if listed in self.aliases():
                    # An alias of ports goes to the same ports, or all of it to the one port that is given.
                    assert local == listed or local.isdigit(), "port forward to an alias of ports"
                    port = pkt.dport if local == listed else int(local)
                else:
                    assert local.isdigit(), "port forward to an alias of ports"
                    port = int(local) + (pkt.dport - int(listed.split("-")[0]))
            return target, port, self._t(rule, "associated-rule-id") == "pass" and key == where, self._t(rule, "descr")
        for rule in self.root.findall("nat/onetoone"):
            if self._has(rule, "disabled") or (self._t(rule, "interface") or "wan") != key:
                continue
            inside = self._t(self._find(rule, "source"), "address")
            assert inside and self._has(self._find(rule, "destination"), "any") and not self._has(rule, "nobinat"), "1:1 rule the judge does not know"
            reflection = self._t(rule, "natreflection")
            assert reflection == "disable" or (not reflection and not self._has(system, "enablebinatreflection")), "1:1 NAT with reflection"
            network = ipaddress.ip_network(inside, strict=False)
            outside = ipaddress.ip_network(f"{self._t(rule, 'external')}/{network.prefixlen}", strict=False)
            address = ipaddress.ip_address(pkt.dst)
            if address in outside:
                return str(network.network_address + (int(address) - int(outside.network_address))), pkt.dport, False, self._t(rule, "descr")
        return pkt.dst, pkt.dport, False, ""

    def _leaving(self, key: str, pkt: Any, dst: str, dport: int) -> Tuple[str, str]:
        """(source after 1:1 NAT and outbound NAT on the interface a packet leaves by, the rule)."""
        import ipaddress

        if ":" in pkt.src:
            return pkt.src, ""
        interfaces = self.interfaces()
        for rule in self.root.findall("nat/onetoone"):
            if self._has(rule, "disabled") or (self._t(rule, "interface") or "wan") != key:
                continue
            network = ipaddress.ip_network(self._t(self._find(rule, "source"), "address"), strict=False)
            outside = ipaddress.ip_network(f"{self._t(rule, 'external')}/{network.prefixlen}", strict=False)
            address = ipaddress.ip_address(pkt.src)
            if address in network:
                return str(outside.network_address + (int(address) - int(network.network_address))), self._t(rule, "descr")
        outbound = self.root.find("nat/outbound")
        mode = self._t(outbound, "mode") or "automatic"
        if mode in ("advanced", "hybrid"):
            for rule in outbound.findall("rule") if outbound is not None else []:
                if self._has(rule, "disabled") or self._t(rule, "interface") != key:
                    continue
                if not self._outbound_side(self._t(self._find(rule, "source"), "network"), pkt.src):
                    continue
                target = self._find(rule, "destination")
                network = self._t(target, "network") or self._t(target, "address")
                assert not self._has(target, "not"), "negated destination in outbound NAT"
                if not self._has(target, "any") and not self._outbound_side(network, dst):
                    continue
                protocol = self._t(rule, "protocol")
                if protocol and pkt.proto not in protocol.split("/"):
                    continue
                for text, port in ((self._t(rule, "sourceport"), pkt.sport), (self._t(rule, "dstport"), dport)):
                    if text:
                        ranges = self._ports_of(text)
                        assert ranges is not None, text
                        if pkt.proto not in ("tcp", "udp") or not any(low <= port <= high for low, high in ranges):
                            break
                else:
                    if self._has(rule, "nonat"):
                        return pkt.src, self._t(rule, "descr")
                    to, bits = self._t(rule, "target"), self._t(rule, "target_subnet")
                    if to == "other-subnet":
                        to, bits = self._t(rule, "targetip"), self._t(rule, "targetip_subnet")
                    if not to or (to.endswith("ip") and to[:-2] in interfaces):
                        return str(interfaces[key]["v4"].ip) if interfaces[key]["v4"] is not None else "MASQ", self._t(rule, "descr")
                    if to in self.aliases():
                        return ",".join(self.aliases()[to][1]), self._t(rule, "descr")
                    return (to if not bits or bits == "32" else f"{to}/{bits}"), self._t(rule, "descr")
        if mode in ("automatic", "hybrid") and interfaces[key]["gateway"]:
            inside = [str(entry["v4"].network) for other, entry in interfaces.items() if not entry["gateway"] and entry["v4"] is not None]
            gateways = {self._t(g, "name"): self._t(g, "interface") for g in self.root.findall("gateways/gateway_item")}
            for route in self.root.findall("staticroutes/route"):
                via = interfaces.get(gateways.get(self._t(route, "gateway"), ""))
                if via is not None and not via["gateway"] and not self._has(route, "disabled"):
                    inside.append(self._t(route, "network"))
            if any(self._within(pkt.src, network) for network in inside):
                return str(interfaces[key]["v4"].ip) if interfaces[key]["v4"] is not None else "MASQ", "automatic"
        return pkt.src, ""

    def _outbound_side(self, text: str, address: str) -> bool:
        if text == "any":
            return True
        if text in self.aliases():
            return self._alias_holds(text, address)
        networks = self._network(text, 4) if text == "(self)" or text in self.interfaces() or text in self.groups() else [text]
        return any(self._within(address, network) for network in networks or [])

    # -- verdicts --------------------------------------------------------------------------------

    def allows(self, pkt: Any) -> bool:
        """Whether a packet that opens a connection gets through: in on one interface, out by another."""
        arrival, departure = self.key(pkt.in_if), self.key(pkt.out_if)
        if ":" in pkt.src and not self._has(self.root.find("system"), "ipv6allow"):
            return False
        dst, dport, passed, _ = self._arriving(arrival, pkt)
        if not passed:
            if self.interfaces()[arrival]["blockpriv"] and any(self._within(pkt.src, network) for network in self.PRIVATE):
                return False
            if not self._decide("in", arrival, pkt, pkt.src, dst, dport):
                return False  # the default is to block
        src, _ = self._leaving(departure, pkt, dst, dport)
        if "," in src or "/" in src or src == "MASQ":
            src = pkt.src if src == "MASQ" else src.split(",")[0].split("/")[0]
        return self._decide("out", departure, pkt, src, dst, dport) is not False  # the default is to pass what leaves

    def deciding(self, pkt: Any) -> str:
        """The description of the rule that decides about a packet: the one that blocks it when it leaves, or
        the one of the interface it arrives on; "" when no rule matches."""
        arrival, departure = self.key(pkt.in_if), self.key(pkt.out_if)
        dst, dport, passed, name = self._arriving(arrival, pkt)
        src, _ = self._leaving(departure, pkt, dst, dport)
        if "," in src or "/" in src or src == "MASQ":
            src = pkt.src if src == "MASQ" else src.split(",")[0].split("/")[0]
        leaving = self._deciding("out", departure, pkt, src, dst, dport)
        if leaving is not None and self._t(leaving, "type") != "pass":
            return self._t(leaving, "descr")
        if passed:
            return name
        rule = self._deciding("in", arrival, pkt, pkt.src, dst, dport)
        return "" if rule is None else self._t(rule, "descr")

    def translation(self, pkt: Any) -> Tuple[str, str, str]:
        """(source, destination, port) a forwarded packet has when it leaves; "Original" for what stays."""
        dst, dport, _, _ = self._arriving(self.key(pkt.in_if), pkt)
        src, _ = self._leaving(self.key(pkt.out_if), pkt, dst, dport)
        return (
            "Original" if src == pkt.src else src, "Original" if dst == pkt.dst else dst,
            "Original" if dport == pkt.dport else str(dport),
        )  # fmt: skip


# -- SonicWall ---------------------------------------------------------------------------------------

# What SonicOS lets through between two zones by itself, by their security types (as documented for these).
SONICWALL_DEFAULT_ALLOW = {("trusted", "untrusted"), ("trusted", "public"), ("wireless", "untrusted"), ("wireless", "public"),
                           ("public", "untrusted")}  # fmt: skip


def _sw_in(address: str, interval: Tuple[int, int, int]) -> bool:
    import ipaddress

    ip = ipaddress.ip_address(address)
    return ip.version == interval[0] and interval[1] <= int(ip) <= interval[2]


def _sw_proto(pkt: Any) -> int:
    return {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}.get(pkt.proto, 0) or int(pkt.proto)


class SonicWallCli:
    """Emitted SonicOS commands, read strictly (only the grammar FWShift writes), and what a firewall would decide.

    ``zone_types`` gives the security type of each zone of the target (trusted, untrusted, public, wireless, ...):
    what no rule of a pair matches is decided by the default of SonicOS for those types. ``interfaces`` maps the
    interfaces a NAT policy names to their zones."""

    def __init__(self, text: str, zone_types: Optional[Dict[str, str]] = None, interfaces: Optional[Dict[str, str]] = None,
                 builtin: Optional[Dict[str, List[Tuple[int, int, int]]]] = None) -> None:  # fmt: skip
        import re

        self.zone_types = zone_types or {}
        self.iface_zone = interfaces or {}
        self.addresses: Dict[Tuple[str, int], List[Tuple[int, int, int]]] = {}  # (name, version or 0 for fqdn)
        self.fqdn: Dict[str, str] = {}
        self.groups: Dict[Tuple[str, int], List[Tuple[str, str]]] = {}  # members: (kind, name)
        # The default services of SonicOS a converted SonicWall policy names (as the documentation names them).
        self.services: Dict[str, Tuple[str, int, int]] = {"Ping": ("ICMP8", 0, 0), "HTTP": ("TCP", 80, 80), "HTTPS": ("TCP", 443, 443),
                                                         "SSH": ("TCP", 22, 22), "SMTP (Send E-Mail)": ("TCP", 25, 25)}  # fmt: skip
        self.service_groups: Dict[str, List[Tuple[str, str]]] = {}
        self.rules: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = {}
        self.nat: List[Dict[str, Any]] = []
        for name, intervals in (builtin or {}).items():
            self.addresses[(name, 4)] = intervals
        lines = text.splitlines()
        assert lines[0] == "configure terminal" and lines[-2:] == ["commit", "exit"], (lines[:1], lines[-2:])
        quoted = r'"([^"\\]+)"'
        ref = r'(any|name "[^"]+"|group "[^"]+")'
        index = 1
        while index < len(lines) - 2:
            line = lines[index]
            index += 1
            words = shlex.split(line)
            block: List[str] = []
            while index < len(lines) - 2 and lines[index].startswith("    "):
                block.append(lines[index].strip())
                index += 1
            if block:
                assert block[-1] == "exit", (line, block)
                block = block[:-1]
            if words[0] == "address-object":
                kind, name = words[1], words[2]
                assert not block and len(name) <= 32 and not re.search(r'["\'\\]', name), line
                zone_at = words.index("zone")
                assert len(words) == zone_at + 2, line
                body = words[3:zone_at]
                if kind == "fqdn":
                    assert body[0] == "domain" and len(body) == 2, line
                    self.fqdn[name] = body[1]
                    self.addresses[(name, 0)] = []
                    continue
                version = int(kind[-1])
                if body[0] == "host":
                    literal = parse_literal(body[1])
                elif body[0] == "range":
                    literal = parse_literal(f"{body[1]}-{body[2]}")
                else:
                    assert body[0] == "network", line
                    literal = parse_literal(f"{body[1]}/{body[2].lstrip('/')}" if version == 6 else f"{body[1]}/{body[2]}")
                    if version == 4:
                        import ipaddress

                        literal = parse_literal(str(ipaddress.ip_network(f"{body[1]}/{body[2]}")))
                assert literal is not None and literal[0] == version, line
                assert (name, version) not in self.addresses, f"defined twice: {name}"
                self.addresses[(name, version)] = [literal]
            elif words[0] == "address-group":
                version, name = int(words[1][-1]), words[2]
                members: List[Tuple[str, str]] = []
                for entry in block:
                    inner = shlex.split(entry)
                    assert inner[0] in ("address-object", "address-group") and len(inner) == 3, entry
                    member_version = 0 if inner[1] == "fqdn" else int(inner[1][-1])
                    key = (inner[2], member_version)
                    assert key in self.addresses or key in self.groups, f"group {name} names {inner[2]} before it exists"
                    members.append(("group" if inner[0] == "address-group" else "object", inner[2]))
                assert members, line
                self.groups[(name, version)] = members
            elif words[0] == "service-object":
                assert not block and len(words) == 5 and words[2] in ("TCP", "UDP"), line
                assert words[1] not in self.services, f"defined twice: {words[1]}"
                self.services[words[1]] = (words[2], int(words[3]), int(words[4]))
            elif words[0] == "service-group":
                members = []
                for entry in block:
                    inner = shlex.split(entry)
                    assert inner[0] in ("service-object", "service-group") and len(inner) == 2, entry
                    assert inner[1] in self.services or inner[1] in self.service_groups, f"{inner[1]} before it exists"
                    members.append(("group" if inner[0] == "service-group" else "object", inner[1]))
                self.service_groups[words[1]] = members
            elif words[0] == "access-rule":
                match = re.fullmatch(r"access-rule ipv([46]) from (\"[^\"]+\"|\S+) to (\"[^\"]+\"|\S+) action (allow|deny|discard) source address "
                                     + ref + " service " + ref + " destination address " + ref, line)  # fmt: skip
                assert match, line
                rule: Dict[str, Any] = {"version": int(match.group(1)), "action": match.group(4), "src": match.group(5),
                                        "service": match.group(6), "dst": match.group(7), "enabled": True}  # fmt: skip
                for entry in block:
                    if entry == "no enable":
                        rule["enabled"] = False
                    elif entry.startswith("priority manual "):
                        rule["priority"] = int(entry.split()[-1])
                    else:
                        assert re.fullmatch(r"name " + quoted, entry), entry
                        rule["name"] = shlex.split(entry)[1]
                key = (match.group(2).strip('"'), match.group(3).strip('"'), rule["version"])
                listed = self.rules.setdefault(key, [])
                assert rule.get("priority") == len(listed) + 1, (line, rule.get("priority"), len(listed))
                listed.append(rule)
            elif words[0] == "nat-policy":
                match = re.fullmatch(r"nat-policy inbound (\S+) outbound (\S+) source " + ref + r" translated-source (original|name \"[^\"]+\") "
                                     r"destination " + ref + r" translated-destination (original|name \"[^\"]+\") service " + ref
                                     + r" translated-service (original|name \"[^\"]+\")", line)  # fmt: skip
                assert match, line
                policy = dict(zip(("inbound", "outbound", "src", "tsrc", "dst", "tdst", "service", "tservice"), match.groups()))
                policy["enabled"] = "no enable" not in block
                for entry in block:
                    assert entry == "no enable" or re.fullmatch(r"(name|comment) " + quoted, entry) or entry == 'comment ""', entry
                self.nat.append(policy)
            else:
                raise AssertionError(f"unknown command: {line}")

    # -- matching ----------------------------------------------------------------------------------

    def _address(self, reference: str, address: str, version: int) -> bool:
        if reference == "any":
            return True
        kind, name = reference.split(" ", 1)
        name = name.strip('"')
        return self._member(kind, name, address, version, set())

    def _member(self, kind: str, name: str, address: str, version: int, seen: set) -> bool:
        if kind == "group":
            assert (name, version) in self.groups, f"unknown group {name}"
            if (name, version) in seen:
                return False
            return any(self._member(k, n, address, version, seen | {(name, version)}) for k, n in self.groups[(name, version)])
        intervals = self.addresses.get((name, version))
        if intervals is None:
            assert (name, 0) in self.addresses, f"unknown object {name}"
            return False  # a host name: resolved to nothing here
        return any(_sw_in(address, interval) for interval in intervals)

    def _service(self, reference: str, pkt: Any) -> bool:
        if reference == "any":
            return True
        kind, name = reference.split(" ", 1)
        return self._svc_member(kind, name.strip('"'), pkt)

    def _svc_member(self, kind: str, name: str, pkt: Any) -> bool:
        if kind == "group":
            return any(self._svc_member(k, n, pkt) for k, n in self.service_groups[name])
        protocol, low, high = self.services[name]
        if protocol == "ICMP8":
            return pkt.proto == "icmp" and pkt.icmp_type == 8
        return pkt.proto == protocol.lower() and low <= pkt.dport <= high

    def deciding(self, pkt: Any, src_zone: str, dst_zone: str) -> Optional[Dict[str, Any]]:
        version = 6 if ":" in pkt.src else 4
        for rule in self.rules.get((src_zone, dst_zone, version), []):
            if not rule["enabled"]:
                continue
            if self._address(rule["src"], pkt.src, version) and self._address(rule["dst"], pkt.dst, version) and self._service(rule["service"], pkt):
                return rule
        return None

    def allows(self, pkt: Any, src_zone: Optional[str] = None, dst_zone: Optional[str] = None) -> bool:
        src_zone = src_zone or pkt.in_if
        dst_zone = dst_zone or pkt.out_if
        rule = self.deciding(pkt, src_zone, dst_zone)
        if rule is not None:
            return bool(rule["action"] == "allow")
        if src_zone == dst_zone:
            return False
        return (self.zone_types.get(src_zone, ""), self.zone_types.get(dst_zone, "")) in SONICWALL_DEFAULT_ALLOW

    def translation(self, pkt: Any) -> Tuple[str, str, str]:
        """(source, destination, port) of a packet after the first NAT policy that matches it; "Original" for what stays."""
        for policy in self.nat:
            if not policy["enabled"]:
                continue
            if policy["inbound"] != "any" and self.iface_zone.get(policy["inbound"]) != pkt.in_if:
                continue
            if policy["outbound"] != "any" and self.iface_zone.get(policy["outbound"]) != pkt.out_if:
                continue
            if not (self._address(policy["src"], pkt.src, 4) and self._address(policy["dst"], pkt.dst, 4) and self._service(policy["service"], pkt)):
                continue
            return (self._moved(policy["tsrc"], policy["src"], pkt.src), self._moved(policy["tdst"], policy["dst"], pkt.dst),
                    self._port(policy["tservice"], pkt))  # fmt: skip
        return ("Original", "Original", "Original")

    def _moved(self, translated: str, original: str, address: str) -> str:
        import ipaddress

        if translated == "original":
            return "Original"
        target = self.addresses[(translated.split(" ", 1)[1].strip('"'), 4)][0]
        if original != "any" and original.startswith("name "):
            source = self.addresses.get((original.split(" ", 1)[1].strip('"'), 4), [None])[0]
            if source is not None and source[2] - source[1] == target[2] - target[1] and _sw_in(address, source):
                return str(ipaddress.ip_address(target[1] + int(ipaddress.ip_address(address)) - source[1]))
        return str(ipaddress.ip_address(target[1]))

    def _port(self, translated: str, pkt: Any) -> str:
        if translated == "original":
            return "Original"
        protocol, low, _ = self.services[translated.split(" ", 1)[1].strip('"')]
        return "Original" if low == pkt.dport else str(low)


class SonicWallExp:
    """What a SonicOS firewall decides by a settings export: decoded and read here without fwshift's parser.

    Per pair of zones the rows in their order, first match; what none matches, the default of SonicOS for the
    security types of the two zones."""

    TYPES = {"0": "untrusted", "1": "trusted", "2": "public", "4": "wireless", "5": "encrypted"}

    def __init__(self, data: bytes) -> None:
        import base64
        import re
        from urllib.parse import unquote

        text = base64.b64decode(data.strip().rstrip(b"&")).decode("utf-8")
        self.keys: Dict[str, str] = {}
        for part in text.split("&"):
            if part:
                key, _, value = part.partition("=")
                self.keys[key] = unquote(value)
        self.rows: Dict[str, Dict[int, Dict[str, str]]] = {}
        for key, value in self.keys.items():
            match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]*?)_([0-9]+)", key)
            if match:
                self.rows.setdefault(match.group(1), {}).setdefault(int(match.group(2)), {})["v"] = value

    def column(self, prefix: str) -> Dict[int, str]:
        return {index: row["v"] for index, row in self.rows.get(prefix, {}).items()}

    def zone_type(self, zone: str) -> str:
        defaults = {"LAN": "trusted", "WAN": "untrusted", "DMZ": "public", "WLAN": "wireless"}
        for index, name in self.column("zoneObjId").items():
            if name == zone:
                return defaults.get(name, self.TYPES.get(self.column("zoneObjZoneType").get(index, ""), ""))
        return defaults.get(zone, "")

    def _object(self, name: str, address: str, seen: frozenset = frozenset()) -> bool:
        import ipaddress

        for index, found in self.column("addrObjId").items():
            if found != name:
                continue
            kind = self.column("addrObjType")[index]
            ip1, ip2 = self.column("addrObjIp1")[index], self.column("addrObjIp2")[index]
            if ":" in address:
                return False
            value = int(ipaddress.ip_address(address))
            if kind == "1":
                return value == int(ipaddress.ip_address(ip1))
            if kind == "2":
                return int(ipaddress.ip_address(ip1)) <= value <= int(ipaddress.ip_address(ip2))
            if kind == "4":
                return ipaddress.ip_address(address) in ipaddress.ip_network(f"{ip1}/{ip2}")
            if kind == "8":
                if name in seen:
                    return False
                groups, atoms = self.column("addro_grpToGrp"), self.column("addro_atomToGrp")
                return any(self._object(atoms[k], address, seen | {name}) for k, g in groups.items() if g == name)
        raise AssertionError(f"object {name} is not in the export")

    def _service(self, name: str, pkt: Any) -> bool:
        if not name:
            return True
        for index, found in self.column("svcObjId").items():
            if found != name:
                continue
            if self.column("svcObjType")[index] == "2":
                groups, atoms = self.column("so_grpToGrp"), self.column("so_atomToGrp")
                return any(self._service(atoms[k], pkt) for k, g in groups.items() if g == name)
            protocol = int(self.column("svcObjIpType")[index])
            low, high = int(self.column("svcObjPort1")[index]), int(self.column("svcObjPort2")[index])
            if protocol in (6, 17):
                if low == 0 and high:
                    low = high  # as the published readers of the format show it: the one port of Port2
                return _sw_proto(pkt) == protocol and (low <= pkt.dport <= high or low == high == 0)
            return _sw_proto(pkt) == protocol
        raise AssertionError(f"service {name} is not in the export")

    def deciding(self, pkt: Any) -> Optional[int]:
        six = ":" in pkt.src
        tail = "V6" if six else ""
        actions = self.column(f"policyAction{tail}")
        rows = sorted(actions)
        if all(self.column(f"policyPriority{tail}").get(i, "").isdigit() for i in rows):
            pairs: Dict[Tuple[str, str], List[int]] = {}
            for i in rows:
                pairs.setdefault((self.column(f"policySrcZone{tail}")[i], self.column(f"policyDstZone{tail}")[i]), []).append(i)
            rows = [i for listed in pairs.values() for i in sorted(listed, key=lambda k: int(self.column(f"policyPriority{tail}")[k]))]
        # The default rule of a pair is at its bottom ("At the bottom of the table is the Any rule").
        default = self.column(f"policyDefaultRule{tail}")
        rows = [i for i in rows if default.get(i) != "1"] + [i for i in rows if default.get(i) == "1"]
        for i in rows:
            if self.column(f"policySrcZone{tail}")[i] != pkt.in_if or self.column(f"policyDstZone{tail}")[i] != pkt.out_if:
                continue
            if self.column(f"policyEnabled{tail}").get(i, "1") == "0":
                continue
            src, dst = self.column(f"policySrcNet{tail}").get(i, ""), self.column(f"policyDstNet{tail}").get(i, "")
            if src and not self._object(src, pkt.src):
                continue
            if dst and not self._object(dst, pkt.dst):
                continue
            if not self._service(self.column(f"policyDstSvc{tail}").get(i, ""), pkt):
                continue
            return i
        return None

    def allows(self, pkt: Any) -> bool:
        tail = "V6" if ":" in pkt.src else ""
        index = self.deciding(pkt)
        if index is not None:
            return self.column(f"policyAction{tail}")[index] == "2"
        if pkt.in_if == pkt.out_if:
            return False
        return (self.zone_type(pkt.in_if), self.zone_type(pkt.out_if)) in SONICWALL_DEFAULT_ALLOW


# -- WatchGuard --------------------------------------------------------------------------------------


class WatchGuardXml:
    """A Policy Manager configuration file, read here without fwshift's parser, and what a Firebox would decide.

    Policies in the order of the file, first match; a policy matches when a member of its From list holds the source
    at the interface the packet arrives on, a member of its To list the destination at the interface it leaves by,
    and its service the packet. ``kinds`` gives trusted/external/optional for interfaces the file does not list."""

    def __init__(self, text: str, kinds: Optional[Dict[str, str]] = None) -> None:
        import xml.etree.ElementTree as ET

        self.root = ET.fromstring(text)
        assert self.root.tag == "profile"
        self.kinds: Dict[str, str] = dict(kinds or {})
        for interface in self.root.findall("interface-list/interface"):
            for item in interface.iter():
                if item.tag in ("if-property", "vif-property"):
                    self.kinds[interface.findtext("name") or ""] = {"1": "trusted", "2": "external", "3": "optional"}.get(item.text or "", "custom")
        self.groups = {g.findtext("name"): g for g in self.root.findall("address-group-list/address-group")}
        self.aliases = {a.findtext("name"): a for a in self.root.findall("alias-list/alias")}
        self.services = {s.findtext("name"): s for s in self.root.findall("service-list/service")}
        self.nats = {n.findtext("name"): n for n in self.root.findall("nat-list/nat")}
        names = [a.findtext("name") for a in self.aliases.values()]
        assert len(names) == len(set(names)), "an alias defined twice"

    def _in_group(self, name: str, address: str) -> bool:
        import ipaddress

        if name == "Any":
            return True
        group = self.groups.get(name)
        assert group is not None, f"address group {name} is not in the file"
        ip = ipaddress.ip_address(address)
        for member in group.findall("addr-group-member/member"):
            kind = member.findtext("type")
            if kind == "1" and ip == ipaddress.ip_address(member.findtext("host-ip-addr") or ""):
                return True
            if kind == "2" and ip.version == 4 and ip in ipaddress.ip_network(f"{member.findtext('ip-network-addr')}/{member.findtext('ip-mask')}"):
                return True
            if kind == "3":
                first, last = ipaddress.ip_address(member.findtext("start-ip-addr") or ""), ipaddress.ip_address(member.findtext("end-ip-addr") or "")
                if first.version == ip.version and int(first) <= int(ip) <= int(last):
                    return True
        return False

    def _at(self, interface: str, actual: str) -> bool:
        low = interface.lower()
        if low == "any":
            return True
        if low in ("any-trusted", "any-external", "any-optional"):
            return self.kinds.get(actual) == low[4:]
        return interface == actual

    def _members(self, alias: str, seen: frozenset = frozenset()) -> List[Tuple[str, str, str, bool]]:
        """(address group, interface, user, whether it is a static NAT action) of an alias."""
        if alias in seen:
            return []
        node = self.aliases.get(alias)
        assert node is not None, f"alias {alias} is not in the file"
        out: List[Tuple[str, str, str, bool]] = []
        for member in node.findall("alias-member-list/alias-member"):
            if member.findtext("type") == "2":
                out += self._members(member.findtext("alias-name") or "", seen | {alias})
            else:
                snat = alias.endswith(".snat") and alias[:-5] in self.nats
                out.append((member.findtext("address") or "", member.findtext("interface") or "", member.findtext("user") or "Any", snat))
        return out

    def _service(self, name: str, pkt: Any) -> bool:
        service = self.services.get(name)
        assert service is not None, f"service {name} is not in the file"
        proto = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}.get(pkt.proto) or int(pkt.proto)
        for member in service.findall("service-item/member"):
            protocol = int(member.findtext("protocol") or "-1")
            if protocol == 0:
                return True
            if protocol != proto:
                continue
            if protocol in (6, 17):
                if member.findtext("type") == "2":
                    if int(member.findtext("start-server-port") or 0) <= pkt.dport <= int(member.findtext("end-server-port") or 0):
                        return True
                elif int(member.findtext("server-port") or 0) in (0, pkt.dport):
                    return True
            elif protocol in (1, 58):
                kind = int(member.findtext("icmp-type") or 255)
                if kind in (255, pkt.icmp_type):
                    return True
            else:
                return True
        return False

    def deciding(self, pkt: Any) -> Optional[Any]:
        for policy in self.root.findall("abs-policy-list/abs-policy"):
            if (policy.findtext("enabled") or "") != "true":
                continue
            froms = [m for a in policy.findall("from-alias-list/alias") for m in self._members(a.text or "")]
            tos = [m for a in policy.findall("to-alias-list/alias") for m in self._members(a.text or "")]
            if not any(user == "Any" and self._at(iface, pkt.in_if) and self._in_group(addr, pkt.src) for addr, iface, user, _ in froms):
                continue
            if not any(user == "Any" and (snat or self._at(iface, pkt.out_if)) and self._in_group(addr, pkt.dst) for addr, iface, user, snat in tos):
                continue
            if not self._service(policy.findtext("service") or "", pkt):
                continue
            return policy
        return None

    def allows(self, pkt: Any) -> bool:
        policy = self.deciding(pkt)
        return policy is not None and (policy.findtext("firewall") or "") in ("Allow", "Proxy")

    def translation(self, pkt: Any) -> Tuple[str, str]:
        """(destination, port) after the static NAT of the policy that decides; "Original" for what stays."""
        import ipaddress

        policy = self.deciding(pkt)
        if policy is None or (policy.findtext("firewall") or "") not in ("Allow", "Proxy"):
            return ("Original", "Original")
        for alias in policy.findall("to-alias-list/alias"):
            for addr, _, _, snat in self._members(alias.text or ""):
                if snat and self._in_group(addr, pkt.dst):
                    nat = next(n for n in self.nats.values() if any(m.findtext("ext-addr-name") == addr for m in n.iter("member")))
                    member = nat.find("nat-item/member")
                    assert member is not None
                    inside = self.groups[member.findtext("addr-name")].find("addr-group-member/member")
                    assert inside is not None
                    port = member.findtext("port") or "0"
                    return (str(ipaddress.ip_address(inside.findtext("host-ip-addr") or "")), "Original" if port == "0" else port)
        return ("Original", "Original")


# -- Barracuda CloudGen Firewall -------------------------------------------------------------------------


class BarracudaRest:
    """Forwarding rules of a CloudGen Firewall, read here without fwshift's parser: from answers of its REST API or from
    the script FWShift writes, whose rules are placed at the top of the list one after the other (the last call ends up
    first). What the firewall would decide: rules in order, first match, deactivated ones skipped; a rule of the IP version
    of the packet; its source object holds the source (an entry that names an interface only where the packet arrives),
    its destination object the destination, its service the packet; bi-directional rules the other way round as well.
    Pass passes, Block and Deny block, what no rule matches is blocked. The script creates its rules deactivated and
    activates them with PATCH calls afterwards; only the activations it makes count."""

    def __init__(self, text: str) -> None:
        import json
        import re

        self.networks: Dict[str, Dict[str, Any]] = {}
        self.services: Dict[str, Dict[str, Any]] = {}
        self.rules: List[Dict[str, Any]] = []
        if text.startswith("#!/bin/sh"):
            calls = re.findall(r"^call (POST|PATCH) (\S+) <<'FWSHIFT_JSON'\n(.*?)\nFWSHIFT_JSON$", text, re.S | re.M)
            assert calls, "no calls in the script"
            posted: List[Dict[str, Any]] = []
            for method, endpoint, body in calls:
                value = json.loads(body)
                if method == "PATCH":
                    assert endpoint.startswith("rules/") and value == {"deactivated": False}, (endpoint, value)
                    target = [r for r in posted if r["name"] == endpoint[len("rules/"):]]
                    assert len(target) == 1, endpoint
                    target[0]["deactivated"] = False
                elif endpoint == "objects/networks":
                    self._add(self.networks, value)
                elif endpoint == "objects/services":
                    self._add(self.services, value)
                else:
                    assert endpoint == "rules" and value["position"] == {"placement": "top"}, endpoint
                    assert value["deactivated"] is True, "a rule created active"
                    posted.append(value)
            self.rules = list(reversed(posted))
        else:
            decoder, position = json.JSONDecoder(), 0
            while True:
                while position < len(text) and text[position] in " \t\r\n":
                    position += 1
                if position >= len(text):
                    break
                value, position = decoder.raw_decode(text, position)
                if "rules" in value:
                    self.rules += value["rules"]
                elif "entries" in value:
                    self._add(self.services, value)
                else:
                    self._add(self.networks, value)
        names = [rule["name"] for rule in self.rules]
        assert len(names) == len(set(n.lower() for n in names)), "two rules of one name"

    @staticmethod
    def _add(store: Dict[str, Dict[str, Any]], value: Dict[str, Any]) -> None:
        assert value["name"].lower() not in {n.lower() for n in store}, f"object {value['name']} twice"
        store[value["name"]] = value

    def _holds(self, name: str, address: str, interface: Optional[str], seen: frozenset = frozenset()) -> bool:
        import ipaddress

        if name == "Any":
            return True
        assert name not in seen
        obj = self.networks[name]
        ip = ipaddress.ip_address(address)

        def inside(entry: Dict[str, Any]) -> bool:
            if "-" in entry["ip"]:
                first, last = (ipaddress.ip_address(part) for part in entry["ip"].split("-"))
                return first.version == ip.version and int(first) <= int(ip) <= int(last)
            net = ipaddress.ip_network(entry["ip"], strict=False)
            return net.version == ip.version and ip in net

        for item in obj.get("excluded", []):
            if inside(item["entry"]):
                return False
        for item in obj.get("included", []):
            if "references" in item:
                if self._holds(item["references"], address, interface, seen | {name}):
                    return True
                continue
            entry = item["entry"]
            if entry.get("interface") and interface is not None and entry["interface"] != interface:
                continue
            if inside(entry):
                return True
        return False

    def _service(self, name: str, pkt: Any) -> bool:
        if name == "Any":
            return True
        numbers = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmp6", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmp6"}
        for item in self.services[name]["entries"]:
            if "references" in item:
                if self._service(item["references"], pkt):
                    return True
                continue
            entry = item["entry"]
            protocol = numbers.get(str(entry["protocol"]).lower(), str(entry["protocol"]))
            if protocol != pkt.proto:
                continue
            if protocol not in ("tcp", "udp"):
                return True
            ports = entry["ports"]
            dport = pkt.dport
            if not ("*" in ports or any(int(p.split("-")[0]) <= dport <= int(p.split("-")[-1]) for p in ports)):
                continue
            client = entry.get("clientPortUsed")
            if client and not client["from"] <= pkt.sport <= client["to"]:
                continue
            return True
        return False

    def _interfaces(self, name: str, seen: frozenset = frozenset()) -> bool:
        if name == "Any" or name in seen:
            return False
        for item in self.networks[name].get("included", []):
            if "references" in item and self._interfaces(item["references"], seen | {name}):
                return True
            if "entry" in item and item["entry"].get("interface"):
                return True
        return False

    def deciding(self, pkt: Any) -> Optional[Dict[str, Any]]:
        import ipaddress

        version = ipaddress.ip_address(pkt.src).version
        for rule in self.rules:
            assert isinstance(rule["deactivated"], bool) and isinstance(rule.get("bidirectional", False), bool)
            if rule["deactivated"] is True or rule["ipVersion"] != f"IPv{version}":
                continue
            kind = rule["action"]["type"]
            assert kind in ("pass", "block", "deny"), f"the judge does not know action {kind}"
            src, dst, svc = (rule[key]["references"] for key in ("source", "destination", "service"))
            if self._holds(src, pkt.src, pkt.in_if) and self._holds(dst, pkt.dst, None) and self._service(svc, pkt):
                return rule
            if rule.get("bidirectional") is True:
                assert not self._interfaces(src) and not self._interfaces(dst), "a bi-directional rule with interfaces: not known"
                if self._holds(dst, pkt.src, None) and self._holds(src, pkt.dst, None) and self._service(svc, pkt):
                    return rule
        return None

    def allows(self, pkt: Any) -> bool:
        rule = self.deciding(pkt)
        return rule is not None and rule["action"]["type"] == "pass"


# -- Juniper SRX -------------------------------------------------------------------------------------


class JunosConfig:
    """An SRX configuration as 'display set' prints it, read here without fwshift's parser, and what the SRX would decide
    for a packet from zone ``pkt.in_if`` to zone ``pkt.out_if`` (no NAT): the policies of that pair of zones in order, then
    the global policies in order, first match, then the default policy. A deactivated statement is not there. Address
    names are looked up in the book of the zone, then in the global one; global policies use the global book."""

    APPS = {"junos-http": [("tcp", "80", None)], "junos-https": [("tcp", "443", None)], "junos-ssh": [("tcp", "22", None)],
            "junos-smtp": [("tcp", "25", None)], "junos-dns-udp": [("udp", "53", None)], "junos-dns-tcp": [("tcp", "53", None)],
            "junos-ntp": [("udp", "123", None)], "junos-icmp-all": [("icmp", "", None)], "junos-icmp-ping": [("icmp", "", 8)],
            "junos-icmp6-all": [("icmp6", "", None)]}

    def __init__(self, text: str) -> None:
        lines = [shlex.split(line) for line in text.splitlines() if line.strip() and not line.startswith("#")]
        off = {tuple(words[1:]) for words in lines if words[0] == "deactivate"}
        self.sets = [words[1:] for words in lines if words[0] == "set"
                     and not any(tuple(words[1:k + 1]) in off for k in range(1, len(words)))]  # fmt: skip
        assert all(words[0] in ("set", "deactivate") for words in lines), "a line that is neither set nor deactivate"
        self.books: Dict[str, Dict[str, List[str]]] = {}
        self.attached: Dict[str, str] = {}
        self.apps: Dict[str, Dict[str, Dict[str, str]]] = {}
        self.app_sets: Dict[str, List[str]] = {}
        self.policies: Dict[str, List[Tuple[str, List[List[str]]]]] = {}
        self.default = False
        for words in self.sets:
            if words[:2] == ["security", "address-book"]:
                book = words[2]
                if words[3] == "attach":
                    self.attached[words[5]] = book
                elif words[3] == "address" and words[5] != "description":
                    self.books.setdefault(book, {})[words[4]] = words[5:]
                elif words[3] == "address-set" and words[5] in ("address", "address-set"):
                    self.books.setdefault(book, {}).setdefault(words[4], ["set"]).append(words[6])
            elif words[:3] == ["security", "zones", "security-zone"] and len(words) > 6 and words[4] == "address-book":
                book = "zone " + words[3]
                self.attached[words[3]] = book
                if words[5] == "address":
                    self.books.setdefault(book, {})[words[6]] = words[7:]
                elif words[5] == "address-set":
                    self.books.setdefault(book, {}).setdefault(words[6], ["set"]).append(words[8])
            elif words[:2] == ["applications", "application"]:
                term, rest = (words[4], words[5:]) if words[3] == "term" else ("", words[3:])
                values = self.apps.setdefault(words[2], {}).setdefault(term, {})
                for index in range(0, len(rest), 2):
                    values[rest[index]] = rest[index + 1]
            elif words[:2] == ["applications", "application-set"]:
                self.app_sets.setdefault(words[2], []).append(words[4])
            elif words[:3] == ["security", "policies", "default-policy"]:
                self.default = words[3] == "permit-all"
            elif words[:3] == ["security", "policies", "from-zone"]:
                self._policy(f"{words[3]} {words[5]}", words[7], words[8:])
            elif words[:4] == ["security", "policies", "global", "policy"]:
                self._policy("global", words[4], words[5:])

    def _policy(self, context: str, name: str, rest: List[str]) -> None:
        listed = self.policies.setdefault(context, [])
        for known, statements in listed:
            if known == name:
                statements.append(rest)
                return
        listed.append((name, [rest]))

    def _holds(self, book_order: List[str], name: str, address: str, seen: frozenset = frozenset()) -> bool:
        import ipaddress

        ip = ipaddress.ip_address(address)
        if name == "any":
            return True
        if name in ("any-ipv4", "any-ipv6"):
            return ip.version == (4 if name == "any-ipv4" else 6)
        for book in book_order:
            value = self.books.get(book, {}).get(name)
            if value is None:
                continue
            assert (book, name) not in seen
            if value[0] == "set":
                return any(self._holds([book], member, address, seen | {(book, name)}) for member in value[1:])
            if value[0] == "range-address":
                first, last = ipaddress.ip_address(value[1]), ipaddress.ip_address(value[3])
                return first.version == ip.version and int(first) <= int(ip) <= int(last)
            assert value[0] != "dns-name", "the judge cannot resolve host names"
            net = ipaddress.ip_network(value[0] if "/" in value[0] else value[0] + ("/32" if ":" not in value[0] else "/128"))
            return net.version == ip.version and ip in net
        raise AssertionError(f"address {name} is in no book of {book_order}")

    def _app(self, name: str, pkt: Any) -> bool:
        if name == "any":
            return True
        if name in self.app_sets:
            return any(self._app(member, pkt) for member in self.app_sets[name])
        terms = [list(self.APPS[name])] if name in self.APPS else None
        if terms is not None:
            return any(self._entry(protocol, ports, "", kind, None, pkt) for protocol, ports, kind in terms[0])
        for values in self.apps[name].values():
            protocol = values["protocol"]
            kind = values.get("icmp-type", values.get("icmp6-type"))
            code = values.get("icmp-code", values.get("icmp6-code"))
            if "icmp6-type" in values:
                kind = {"echo-request": "128", "echo-reply": "129", "destination-unreachable": "1", "time-exceeded": "3"}.get(kind or "", kind)
            else:
                kind = {"echo-request": "8", "echo-reply": "0", "unreachable": "3", "time-exceeded": "11"}.get(kind or "", kind)
            if self._entry(protocol, values.get("destination-port", ""), values.get("source-port", ""), int(kind) if kind else None,
                           int(code) if code else None, pkt):  # fmt: skip
                return True
        return False

    @staticmethod
    def _entry(protocol: str, ports: str, source: str, kind: Optional[int], code: Optional[int], pkt: Any) -> bool:
        number = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmp6": "icmp6", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmp6",
                  "gre": "47", "esp": "50", "ospf": "89"}
        if number.get(protocol, protocol) != pkt.proto:
            return False
        if pkt.proto in ("tcp", "udp"):
            low, _, high = ports.partition("-")
            if ports and not int(low) <= pkt.dport <= int(high or low):
                return False
            low, _, high = source.partition("-")
            if source and not int(low) <= pkt.sport <= int(high or low):
                return False
            return True
        if pkt.proto in ("icmp", "icmp6"):
            return kind is None or pkt.icmp_type == kind  # packets here carry no code
        return True

    def deciding(self, pkt: Any) -> Optional[Tuple[str, str, bool]]:
        """(context, policy, permits) of the policy that decides; None for the default policy."""
        for context in (f"{pkt.in_if} {pkt.out_if}", "global"):
            for name, statements in self.policies.get(context, []):
                match: Dict[str, List[str]] = {}
                action = None
                for words in statements:
                    if words[0] == "match":
                        match.setdefault(words[1], []).append(words[2] if len(words) > 2 else "")
                    elif words[0] == "then" and words[1] in ("permit", "deny", "reject"):
                        action = words[1]
                    elif words[0] == "then" and words[1] in ("log", "count"):
                        pass
                    else:
                        assert words[0] == "description", f"the judge does not know {words}"
                assert action is not None and set(match) <= {"source-address", "destination-address", "application", "from-zone",
                                                             "to-zone", "source-address-excluded", "destination-address-excluded"}, (name, match)  # fmt: skip
                if context == "global":
                    if "from-zone" in match and pkt.in_if not in match["from-zone"]:
                        continue
                    if "to-zone" in match and pkt.out_if not in match["to-zone"]:
                        continue
                    src_books = dst_books = ["global"]
                else:
                    src_books = [self.attached[pkt.in_if], "global"] if pkt.in_if in self.attached else ["global"]
                    dst_books = [self.attached[pkt.out_if], "global"] if pkt.out_if in self.attached else ["global"]
                src = any(self._holds(src_books, n, pkt.src) for n in match["source-address"])
                if src == ("source-address-excluded" in match):
                    continue
                dst = any(self._holds(dst_books, n, pkt.dst) for n in match["destination-address"])
                if dst == ("destination-address-excluded" in match):
                    continue
                if not any(self._app(a, pkt) for a in match["application"]):
                    continue
                return context, name, action == "permit"
        return None

    def allows(self, pkt: Any) -> bool:
        found = self.deciding(pkt)
        return self.default if found is None else found[2]


# -- OPNsense ----------------------------------------------------------------------------------------


class OPNsense:
    """An OPNsense firewall (24.7 to 26.7), as far as its ``config.xml`` says what it does with a packet it forwards.

    Written from OPNsense's own code as the notes of the work on it describe it (filter.inc, filter.lib.inc, the models
    of Firewall/Filter, Alias and DNat, the rule classes) and from pf, not from the parser of FWShift: it reads the XML
    itself. Both kinds of filter rule, in the order of their priorities; aliases as pf tables, with what they leave out;
    port forwards in both forms, 1:1 NAT, outbound NAT of both kinds and the automatic one. What it does not know raises,
    so that a test never passes on something it took for something else. Host names in aliases match nothing here.
    """

    PRIVATE = {
        "1.0.4": ("10.0.0.0/8", "127.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7",
                  "fe80::/10", "::/128"),
        "1.0.5": ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "fd00::/8",
                  "fe80::/10", "::/128"),
        "1.0.6": ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fd00::/8", "fe80::/10"),
    }  # fmt: skip
    NUMBERS = PfSense.NUMBERS
    ICMP = PfSense.ICMP
    ICMP6 = PfSense.ICMP6
    MVC_FIELDS = {"enabled", "statetype", "sequence", "action", "quick", "interfacenot", "interface", "direction", "ipprotocol",
                  "protocol", "icmptype", "icmp6type", "source_net", "source_not", "source_port", "destination_net",
                  "destination_not", "destination_port", "log", "categories", "description", "received-on", "received-on-not",
                  "gateway", "sched"}  # fmt: skip
    LEGACY_FIELDS = {"type", "interface", "ipprotocol", "statetype", "protocol", "icmptype", "icmp6-type", "source", "destination",
                     "disabled", "log", "descr", "floating", "quick", "direction", "category", "interfacenot", "associated-rule-id",
                     "gateway"}  # fmt: skip
    SERVICES = {"http": 80, "https": 443, "ssh": 22, "smtp": 25, "domain": 53}

    def __init__(self, text: str) -> None:
        import xml.etree.ElementTree as ET

        self.root = ET.fromstring(text)
        assert self.root.tag == "opnsense", self.root.tag
        model = self.root.find("OPNsense/Firewall/Filter")
        assert model is not None and model.get("version") in self.PRIVATE, "a firewall model of 24.7 to 26.7"
        self.model = model.get("version", "")
        self._cache: Dict[str, Any] = {}

    # -- System > Configuration > Backups ----------------------------------------------------------------

    AREAS = {"aliases": ("aliases", "OPNsense/Firewall/Alias"), "nat": ("nat", "OPNsense/Firewall/Filter/snatrules",
             "OPNsense/Firewall/Filter/npt", "OPNsense/Firewall/Filter/onetoone"),
             "rules": ("filter", "OPNsense/Firewall/Filter/rules")}  # fmt: skip

    def restore(self, text: str, areas: Tuple[str, ...] = ("aliases", "nat", "rules")) -> None:
        """Restore one area after the other: the sections of the area the file has replace those of the firewall, those it
        does not have are deleted, and an area of which the file has no section is refused."""
        import xml.etree.ElementTree as ET

        other = ET.fromstring(text)
        for area in areas:
            sections = self.AREAS[area]
            if not any(other.find(path) is not None for path in sections):
                continue
            for path in sections:
                parent_path, _, tag = path.rpartition("/")
                parent = self.root.find(parent_path) if parent_path else self.root
                if parent is None:
                    parent = self.root
                    for part in parent_path.split("/"):
                        found = parent.find(part)
                        parent = found if found is not None else ET.SubElement(parent, part)
                old = parent.find(tag)
                if old is not None:
                    parent.remove(old)
                new = other.find(path)
                if new is not None:
                    parent.append(new)
        self._cache = {}

    # -- reading --------------------------------------------------------------------------------------

    @staticmethod
    def _t(node: Any, tag: str) -> str:
        if node is None:
            return ""
        found = node.findall(tag)
        assert len(found) <= 1, f"<{tag}> twice"
        return (found[0].text or "").strip() if found else ""

    @staticmethod
    def _set(value: str) -> bool:
        return value not in ("", "0")  # PHP's !empty()

    @staticmethod
    def _bool(node: Any, tag: str, default: bool) -> bool:
        """A BooleanField of the newer models: 1 is true, 0 and nothing false; absent, its default."""
        found = node.find(tag)
        return default if found is None else (found.text or "").strip() == "1"

    def newer(self) -> bool:
        return self.model >= "1.0.5"

    def ipv6(self) -> bool:
        if self.newer():
            return not self._set(self._t(self.root.find("OPNsense/Interfaces/settings"), "disableipv6"))
        return self.root.find("system/ipv6allow") is not None

    def interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Enabled interfaces of every kind: key -> description, addresses, whether it has a gateway, its settings."""
        import ipaddress

        if "interfaces" in self._cache:
            return self._cache["interfaces"]  # type: ignore[no-any-return]
        out: Dict[str, Dict[str, Any]] = {}
        self._cache["interfaces"] = out
        section = self.root.find("interfaces")
        for node in section if section is not None else []:
            if node.find("enable") is None:
                continue  # isset: <enable>0</enable> is enabled too
            entry: Dict[str, Any] = {"descr": self._t(node, "descr") or node.tag.upper(), "v4": None, "v6": None, "vips": [],
                                     "device": self._t(node, "if"), "type": self._t(node, "type"),
                                     "dynamic": self._set(self._t(node, "internal_dynamic")) or self._set(self._t(node, "virtual"))}  # fmt: skip
            address, bits = self._t(node, "ipaddr"), self._t(node, "subnet")
            if address and address[0].isdigit() and bits:
                entry["v4"] = ipaddress.ip_interface(f"{address}/{bits}")
            address, bits = self._t(node, "ipaddrv6"), self._t(node, "subnetv6")
            if ":" in address and bits:
                entry["v6"] = ipaddress.ip_interface(f"{address}/{bits}")
            gateway = self._t(node, "gateway")
            entry["gateway"] = (bool(gateway) and gateway.lower() != "none") or self._t(node, "ipaddr") in ("dhcp", "pppoe", "pptp", "l2tp", "ppp")
            for flag in ("blockpriv", "blockbogons"):
                found = node.find(flag)
                # 24.7 and 25.1 ask isset(), 25.7 and later !empty(); the file of 24.7 to 25.7 does not say which wrote it.
                entry[flag] = found is not None and (self._set((found.text or "").strip()) or not self.newer())
            out[node.tag] = entry
        for vip in self.root.findall("virtualip/vip"):
            owner = out.get(self._t(vip, "interface"))
            if owner is not None:
                owner["vips"].append((ipaddress.ip_interface(f"{self._t(vip, 'subnet')}/{self._t(vip, 'subnet_bits') or 32}"), self._t(vip, "mode")))
        return out

    def key(self, zone: str) -> str:
        for key, entry in self.interfaces().items():
            if zone in (key, entry["descr"]):
                return key
        raise AssertionError(f"no interface {zone}")

    def groups(self) -> Dict[str, Tuple[List[str], int]]:
        """Interface groups: name -> (members, sequence); the groups the system keeps of tunnels have sequence 0."""
        if "groups" not in self._cache:
            out: Dict[str, Tuple[List[str], int]] = {}
            for entry in self.root.findall("ifgroups/ifgroupentry"):
                members = [m.strip() for m in self._t(entry, "members").split(",") if m.strip()]
                out[self._t(entry, "ifname")] = (members, int(self._t(entry, "sequence") or 0))
            for key, interface in self.interfaces().items():
                prefix = {"openvpn": "ovpn", "wireguard": "wg"}.get(key)
                if interface["type"] == "group" and prefix and key not in out:
                    out[key] = ([k for k, e in self.interfaces().items() if e["device"].startswith(prefix)], 0)
            self._cache["groups"] = out
        return self._cache["groups"]  # type: ignore[no-any-return]

    def aliases(self) -> Dict[str, Tuple[str, List[str], bool]]:
        if "aliases" not in self._cache:
            self._cache["aliases"] = {
                self._t(a, "name"): (self._t(a, "type"), [line.strip() for line in (a.findtext("content") or "").splitlines() if line.strip()],
                                     self._bool(a, "enabled", True))
                for a in self.root.findall("OPNsense/Firewall/Alias/aliases/alias")
            }  # fmt: skip
        return self._cache["aliases"]  # type: ignore[no-any-return]

    # -- addresses --------------------------------------------------------------------------------------

    @staticmethod
    def _within(address: str, network: str) -> bool:
        a, b = _literal(address), _literal(network)
        return a is not None and b is not None and a[0] == b[0] and b[1] <= a[1] <= b[2]

    def _networks_of(self, key: str, family: int) -> List[str]:
        if key in self.groups():
            return [n for member in self.groups()[key][0] for n in self._networks_of(member, family)]
        entry = self.interfaces().get(key)
        assert entry is not None, f"no interface {key}"
        which = "v4" if family == 4 else "v6"
        out = [str(entry[which].network)] if entry[which] is not None else []
        return out + [str(vip.network) for vip, _ in entry["vips"] if vip.version == family]

    def _table(self, name: str, seen: Tuple[str, ...] = ()) -> List[Tuple[str, bool]]:
        """The entries of the pf table of an alias: its own and those of every alias it holds, with "leaves out"."""
        import ipaddress

        if name.startswith("__") and name.endswith("_network") and name not in self.aliases():
            key = name[2:-8]
            return [(n, False) for family in (4, 6) for n in self._networks_of(key, family)]
        kind, entries, enabled = self.aliases()[name]
        assert kind in ("host", "network", "networkgroup"), f"alias {name} of type {kind} as an address"
        if not enabled or name in seen:
            return []
        out: List[Tuple[str, bool]] = []
        for entry in entries:
            negated = entry.startswith("!")
            value = entry.lstrip("!")
            if value in self.aliases() or (value.startswith("__") and value.endswith("_network")):
                assert not negated, "an alias left out of another"
                out += self._table(value, seen + (name,))
            elif "-" in value and _literal(value) is not None:
                first, last = (ipaddress.ip_address(part) for part in value.split("-"))
                out += [(str(n), negated) for n in ipaddress.summarize_address_range(first, last)]
            elif _literal(value) is not None:
                out.append((value, negated))
            else:
                assert kind == "host" and not value[0].isdigit() and ":" not in value, f"entry {entry} of alias {name}"
        return out

    def _alias_holds(self, name: str, address: str) -> bool:
        best: Optional[Tuple[int, bool]] = None
        for network, negated in self._table(name):
            literal = _literal(network)
            if self._within(address, network):
                width = literal[2] - literal[1]
                if best is None or width < best[0] or (width == best[0] and negated):
                    best = (width, negated)
        return best is not None and not best[1]

    def _value_holds(self, value: str, address: str, family: int, link_local: bool = False) -> bool:
        """Whether an address is in what a rule names: any, a word of OPNsense, an alias, an address or network. In a rule
        for IPv6 only, the network of an interface comes with the link-local network (Rule.php, mapAddressInfo)."""
        interfaces = self.interfaces()
        if value == "any":
            return True
        if value == "(self)":
            which = "v4" if family == 4 else "v6"
            own = [str(e[which].ip) for e in interfaces.values() if e[which] is not None]
            own += [str(vip.ip) for e in interfaces.values() for vip, mode in e["vips"] if vip.version == family and mode in ("carp", "ipalias")]
            return address in own
        if value.endswith("ip") and value[:-2] in interfaces and re.fullmatch(r"wan|lan|opt\d+", value[:-2]):
            own = interfaces[value[:-2]]["v4" if family == 4 else "v6"]
            return own is not None and address == str(own.ip)
        if value in interfaces or value in self.groups():
            networks = self._networks_of(value, family) + (["fe80::/10"] if family == 6 and link_local else [])
            return any(self._within(address, network) for network in networks)
        if value in self.aliases() or (value.startswith("__") and value.endswith("_network")):
            return self._alias_holds(value, address)
        assert _literal(value) is not None and "-" not in value, f"'{value}' is nothing the judge knows"
        return self._within(address, value)

    def _ports(self, text: str, seen: Tuple[str, ...] = ()) -> Optional[List[Tuple[int, int]]]:
        """Port ranges of a port, a range, a name or an alias; None for an alias that holds no port (the rule is not loaded)."""
        if text in self.aliases():
            kind, entries, enabled = self.aliases()[text]
            assert kind == "port", f"alias {text} of type {kind} as ports"
            if not enabled or text in seen:
                return None
            out: List[Tuple[int, int]] = []
            for entry in entries:
                out += self._ports(entry, seen + (text,)) or []
            return out or None
        if text in self.SERVICES:
            return [(self.SERVICES[text],) * 2]
        first, _, last = text.replace(":", "-").partition("-")
        assert first.isdigit() and (not last or last.isdigit()), f"port {text}"
        return [(int(first), int(last or first))]

    # -- rules -------------------------------------------------------------------------------------------

    def _protocol_matches(self, protocol: str, types: List[int], pkt: Any) -> bool:
        if protocol in ("", "any"):
            return True
        if protocol in ("tcp", "udp", "tcp/udp"):
            return pkt.proto in protocol.split("/")
        if protocol == "icmp":
            return pkt.proto == "icmp" and (not types or pkt.icmp_type in types)
        if protocol == "ipv6-icmp":
            return pkt.proto == "icmp6" and (not types or pkt.icmp_type in types)
        return str(self.NUMBERS[protocol]) == str(self.NUMBERS.get(pkt.proto, pkt.proto))

    def _port_matches(self, protocol: str, text: str, port: int) -> Optional[bool]:
        if not text or protocol not in ("tcp", "udp", "tcp/udp"):
            return True  # OPNsense writes ports for TCP and UDP only
        ranges = self._ports(text)
        if ranges is None:
            return None
        return any(low <= port <= high for low, high in ranges)

    def _entries(self) -> List[Dict[str, Any]]:
        """The filter rules of the configuration, as dictionaries, in the order of their priorities."""
        if "entries" in self._cache:
            return self._cache["entries"]  # type: ignore[no-any-return]
        groups = self.groups()
        listed: List[Tuple[Tuple[int, int, int, int, int], Dict[str, Any]]] = []
        for index, node in enumerate(self.root.findall("OPNsense/Firewall/Filter/rules/rule")):
            unknown = {child.tag for child in node} - self.MVC_FIELDS
            assert not unknown, unknown
            if not self._bool(node, "enabled", True):
                continue
            names = [n.strip() for n in self._t(node, "interface").split(",") if n.strip()]
            negated = self._t(node, "interfacenot") == "1"
            if len(names) != 1 or negated:
                tier = (200000, 0)
            elif names[0] in groups:
                tier = (300000, groups[names[0]][1])
            else:
                tier = (400000, 0)
            protocol = self._t(node, "protocol").lower()
            numbers = [int(n) for n in self._t(node, "icmp6type").split(",") if n.strip()]
            names4 = [self.ICMP[n] for n in self._t(node, "icmptype").split(",") if n.strip()]
            sides = []
            for tag in ("source", "destination"):
                values = [v.strip() for v in (self._t(node, f"{tag}_net") or "any").split(",") if v.strip()]
                side_negated = self._t(node, f"{tag}_not") == "1"
                assert not (side_negated and len(values) > 1), "a negated list"
                sides.append((values, side_negated, self._t(node, f"{tag}_port")))
            received = [n.strip() for n in self._t(node, "received-on").split(",") if n.strip()]
            entry = {
                "descr": self._t(node, "description"), "action": self._t(node, "action") or "pass",
                "quick": self._bool(node, "quick", True), "interfaces": names, "interfacenot": negated,
                "direction": self._t(node, "direction") or "in", "families": {"inet6": [6], "inet46": [4, 6]}.get(self._t(node, "ipprotocol"), [4]),
                "inet6": self._t(node, "ipprotocol") in ("inet6", "inet46"),
                "protocol": protocol, "types": numbers if protocol == "ipv6-icmp" else names4, "source": sides[0], "destination": sides[1],
                "received": received, "received_not": self._t(node, "received-on-not") == "1",
            }  # fmt: skip
            listed.append(((tier[0], tier[1], 0, int(self._t(node, "sequence") or 1), index), entry))
        for index, node in enumerate(self.root.findall("filter/rule")):
            unknown = {child.tag for child in node} - self.LEGACY_FIELDS
            assert not unknown, unknown
            kind = self._t(node, "type") or "pass"
            assert kind in ("pass", "block", "reject", "match"), kind
            if self._set(self._t(node, "disabled")) or kind == "match":
                continue
            floating = node.find("floating") is not None
            interface = self._t(node, "interface")
            if floating and "any" in interface.split(","):
                continue  # OPNsense has no interface "any": it does not load the rule
            names = [n.strip() for n in interface.split(",") if n.strip()] if floating else [interface]
            tier = (200000, 0) if floating else (300000, groups[interface][1]) if interface in groups and interface not in ("openvpn", "wireguard") else (400000, 0)
            quick_node = node.find("quick")
            quick = (not floating) if quick_node is None else self._set((quick_node.text or "").strip())
            protocol = self._t(node, "protocol").lower()
            sides = []
            for tag in ("source", "destination"):
                side = node.find(tag)
                negated_node = side.find("not") if side is not None else None
                negated = negated_node is not None and (self._set((negated_node.text or "").strip()) or not self.newer())
                if side is None or side.find("any") is not None:
                    value = "any"
                else:
                    value = self._t(side, "network") or self._t(side, "address") or "any"
                sides.append(([value], negated, self._t(side, "port")))
            if protocol == "ipv6-icmp":
                types = [self.ICMP6[n] for n in [self._t(node, "icmp6-type")] if n]
            else:
                types = [self.ICMP[n] for n in self._t(node, "icmptype").split(",") if n.strip()]
            entry = {
                "descr": self._t(node, "descr"), "action": kind, "quick": quick, "interfaces": names,
                "interfacenot": self._set(self._t(node, "interfacenot")), "direction": self._t(node, "direction") or "in",
                "families": {"inet": [4], "inet6": [6]}.get(self._t(node, "ipprotocol"), [4, 6]), "protocol": protocol,
                "inet6": self._t(node, "ipprotocol") in ("inet6", "inet46"),  # (no family at all: one rule, not split)
                "types": types, "source": sides[0], "destination": sides[1], "received": [], "received_not": False,
            }  # fmt: skip
            listed.append(((tier[0], tier[1], 1, 0, index), entry))
        if self.newer():
            for index, node in enumerate(self.root.findall("nat/rule")):
                if self._t(node, "pass") != "rule" or self._set(self._t(node, "disabled")) or self._set(self._t(node, "nordr")):
                    continue
                source = node.find("source")
                target_port = self._t(node, "local-port")
                listed_port = self._t(node.find("destination"), "port")
                if target_port and "-" in listed_port and target_port.isdigit():
                    low, high = listed_port.split("-")
                    target_port = f"{target_port}-{int(target_port) + int(high) - int(low)}"
                entry = {
                    "descr": self._t(node, "descr") + " (registered)", "action": "pass", "quick": True,
                    "interfaces": [n.strip() for n in (self._t(node, "interface") or "wan").split(",")], "interfacenot": False,
                    "direction": "in", "families": {"inet6": [6], "inet46": [4, 6]}.get(self._t(node, "ipprotocol"), [4]), "inet6": False,
                    "protocol": self._t(node, "protocol").lower(), "types": [],
                    "source": ([self._t(source, "network") or "any"], self._set(self._t(source, "not")), self._t(source, "port")),
                    "destination": ([self._t(node, "target")], False, target_port or listed_port), "received": [], "received_not": False,
                }  # fmt: skip
                listed.append(((500000, 0, 0, int(self._t(node, "sequence") or 1), index), entry))
        listed.sort(key=lambda item: item[0])
        self._cache["entries"] = [entry for _, entry in listed]
        return self._cache["entries"]  # type: ignore[no-any-return]

    def _on(self, names: List[str], key: str) -> bool:
        if not names:
            return True
        return any(key == name or key in self.groups().get(name, ([], 0))[0] for name in names)

    def _matches(self, entry: Dict[str, Any], pkt: Any, src: str, dst: str, dport: int) -> Optional[bool]:
        family = 6 if ":" in src else 4
        if family not in entry["families"]:
            return False
        protocol = entry["protocol"]
        if protocol == "icmp" and family == 6:
            return False  # ICMP is of IPv4
        if not self._protocol_matches(protocol, entry["types"], pkt):
            return False
        for (values, negated, port_text), address, port in ((entry["source"], src, pkt.sport), (entry["destination"], dst, dport)):
            # An address of the other IP version: pf leaves that part of the rule out for this one.
            usable = [v for v in values if v == "any" or _literal(v) is None or _literal(v)[0] == family]
            if not usable:
                return False
            held = any(self._value_holds(v, address, family, entry["inet6"] and not negated) for v in usable)
            if held == negated:
                return False
            ok = self._port_matches(protocol, port_text, port)
            if ok is None:
                return None
            if not ok:
                return False
        return True

    def _deciding(self, direction: str, key: str, pkt: Any, src: str, dst: str, dport: int, arrival: str = "") -> Optional[Dict[str, Any]]:
        last: Optional[Dict[str, Any]] = None
        for entry in self._entries():
            if entry["direction"] not in (direction, "any"):
                continue
            if self._on(entry["interfaces"], key) == entry["interfacenot"]:
                continue
            if entry["received"] and self._on(entry["received"], arrival) == entry["received_not"]:
                continue
            if not self._matches(entry, pkt, src, dst, dport):
                continue
            if entry["quick"]:
                return entry
            last = entry
        return last

    # -- NAT -----------------------------------------------------------------------------------------------

    def _target(self, text: str, key: str) -> str:
        interfaces = self.interfaces()
        if not text:
            return str(interfaces[key]["v4"].ip)
        if text.endswith("ip") and text[:-2] in interfaces:
            return str(interfaces[text[:-2]]["v4"].ip)
        if text in self.aliases():
            return self.aliases()[text][1][0]
        return text

    def _forward_side(self, node: Any, address: str, port: int, protocol: str) -> Optional[bool]:
        if node is None:
            return True
        if self.newer():
            value = self._t(node, "network") or self._t(node, "address") or "any"
            negated = self._set(self._t(node, "not"))
        else:
            value = "any" if node.find("any") is not None else self._t(node, "network") or self._t(node, "address") or "any"
            negated = node.find("not") is not None
        if self._value_holds(value, address, 4) == negated:
            return False
        return self._port_matches(protocol, self._t(node, "port"), port)

    def _arriving(self, key: str, pkt: Any) -> Tuple[str, int, bool, str]:
        """(destination, port, whether the packet is passed without a rule, the rule) after port forwards and 1:1 NAT."""
        import ipaddress

        if ":" in pkt.dst:
            return pkt.dst, pkt.dport, False, ""
        forwards = list(enumerate(self.root.findall("nat/rule")))
        if self.newer():
            forwards.sort(key=lambda item: (int(self._t(item[1], "sequence") or 1), item[0]))
        system = self.root.find("system")
        for _, rule in forwards:
            if self._set(self._t(rule, "disabled")):
                continue
            reflection = self._t(rule, "natreflection")
            assert reflection == "disable" or (not reflection and system is not None and system.find("disablenatreflection") is not None), "NAT reflection"
            if key not in [m for n in (self._t(rule, "interface") or "wan").split(",") for m in self.groups().get(n.strip(), ([n.strip()], 0))[0]]:
                continue
            protocol = self._t(rule, "protocol").lower()
            if not self._protocol_matches(protocol, [], pkt):
                continue
            if not self._forward_side(rule.find("source"), pkt.src, pkt.sport, protocol):
                continue
            if not self._forward_side(rule.find("destination"), pkt.dst, pkt.dport, protocol):
                continue
            if self._set(self._t(rule, "nordr")):
                return pkt.dst, pkt.dport, False, self._t(rule, "descr")
            target = self._target(self._t(rule, "target"), key)
            port = pkt.dport
            local, listed = self._t(rule, "local-port"), self._t(rule.find("destination"), "port")
            if local and listed and protocol in ("tcp", "udp", "tcp/udp"):
                assert local.isdigit() and listed not in self.aliases(), "port forward with an alias of ports"
                port = int(local) + (pkt.dport - int(listed.replace(":", "-").split("-")[0]))
            passed = self._t(rule, "pass") == "pass" if self.newer() else self._t(rule, "associated-rule-id") == "pass"
            return target, port, passed, self._t(rule, "descr")
        for rule in self.root.findall("OPNsense/Firewall/Filter/onetoone/rule"):
            if not self._bool(rule, "enabled", True) or (self._t(rule, "interface") or "wan") != key or self._t(rule, "type") == "nat":
                continue
            assert self._t(rule, "destination_net") in ("", "any") and self._t(rule, "natreflection") in ("", "disable"), "1:1 rule the judge does not know"
            network = ipaddress.ip_network(self._t(rule, "source_net"), strict=False)
            outside = ipaddress.ip_network(f"{self._t(rule, 'external').split('/')[0]}/{network.prefixlen}", strict=False)
            address = ipaddress.ip_address(pkt.dst)
            if address in outside:
                return str(network.network_address + (int(address) - int(outside.network_address))), pkt.dport, False, self._t(rule, "description")
        return pkt.dst, pkt.dport, False, ""

    def _snat_matches(self, rule: Any, pkt: Any, dst: str, dport: int, mvc: bool) -> bool:
        protocol = self._t(rule, "protocol").lower()
        if not self._protocol_matches(protocol, [], pkt):
            return False
        if mvc:
            sides = ((self._t(rule, "source_net") or "any", self._t(rule, "source_not") == "1", self._t(rule, "source_port"), pkt.src, pkt.sport),
                     (self._t(rule, "destination_net") or "any", self._t(rule, "destination_not") == "1", self._t(rule, "destination_port"), dst, dport))  # fmt: skip
        else:
            source, destination = rule.find("source"), rule.find("destination")
            far = "any" if destination is None or destination.find("any") is not None else self._t(destination, "network") or self._t(destination, "address")
            near_not = source is not None and source.find("not") is not None and (self._set(self._t(source, "not")) or not self.newer())
            sides = ((self._t(source, "network") or "any", near_not, self._t(rule, "sourceport"), pkt.src, pkt.sport),
                     (far, destination is not None and self._set(self._t(destination, "not")), self._t(rule, "dstport"), dst, dport))  # fmt: skip
        for value, negated, port_text, address, port in sides:
            if self._value_holds(value, address, 4) == negated:
                return False
            if port_text and not self._port_matches(protocol, port_text, port):
                return False
        return True

    def _leaving(self, key: str, pkt: Any, dst: str, dport: int) -> Tuple[str, str]:
        """(source after 1:1 NAT and outbound NAT on the interface a packet leaves by, the rule)."""
        import ipaddress

        if ":" in pkt.src:
            return pkt.src, ""
        interfaces = self.interfaces()
        def one_to_one(kinds: Tuple[str, ...]) -> Optional[Tuple[str, str]]:
            for rule in self.root.findall("OPNsense/Firewall/Filter/onetoone/rule"):
                if not self._bool(rule, "enabled", True) or (self._t(rule, "interface") or "wan") != key or (self._t(rule, "type") or "binat") not in kinds:
                    continue
                network = ipaddress.ip_network(self._t(rule, "source_net"), strict=False)
                outside = ipaddress.ip_network(f"{self._t(rule, 'external').split('/')[0]}/{network.prefixlen}", strict=False)
                address = ipaddress.ip_address(pkt.src)
                if address in network:
                    return str(outside.network_address + (int(address) - int(network.network_address))), self._t(rule, "description")
            return None

        found = one_to_one(("binat",))  # pf looks at binat rules before nat rules
        if found is not None:
            return found
        mode = self._t(self.root.find("nat/outbound"), "mode") or "automatic"
        listed: List[Tuple[Any, bool]] = []
        if self.model != "1.0.6" or mode in ("advanced", "hybrid"):
            snat = list(enumerate(self.root.findall("OPNsense/Firewall/Filter/snatrules/rule")))
            snat.sort(key=lambda item: (int(self._t(item[1], "sequence") or 1), item[0]))
            listed += [(rule, True) for _, rule in snat]
        if mode in ("advanced", "hybrid"):
            listed += [(rule, False) for rule in self.root.findall("nat/outbound/rule")]
        for rule, mvc in listed:
            if (not self._bool(rule, "enabled", True)) if mvc else self._set(self._t(rule, "disabled")):
                continue
            if self._t(rule, "interface") != key or not self._snat_matches(rule, pkt, dst, dport, mvc):
                continue
            if self._set(self._t(rule, "nonat")):
                return pkt.src, self._t(rule, "description" if mvc else "descr")
            target = self._t(rule, "target")
            bits = "" if mvc else self._t(rule, "target_subnet")
            if not mvc and target == "other-subnet":
                target, bits = self._t(rule, "targetip"), self._t(rule, "targetip_subnet")
            if not mvc and not target:
                target = f"{key}ip"
            translated = self._target(target, key)
            if bits and bits != "32":
                translated = f"{translated}/{bits}"
            return translated, self._t(rule, "description" if mvc else "descr")
        if mode in ("automatic", "hybrid") and interfaces[key]["gateway"] and not interfaces[key]["device"].startswith("ovpn"):
            inside = [str(e["v4"].network) for e in interfaces.values() if not e["gateway"] and e["v4"] is not None] + ["127.0.0.0/8"]
            if any(self._within(pkt.src, network) for network in inside):
                return str(interfaces[key]["v4"].ip), "automatic"
        found = one_to_one(("nat",))  # one way: a nat rule of priority 500, after source NAT (50), manual (100), automatic (200)
        return found if found is not None else (pkt.src, "")

    # -- verdicts ------------------------------------------------------------------------------------------

    def allows(self, pkt: Any) -> bool:
        """Whether a packet that opens a connection gets through: in on one interface, out by another."""
        arrival, departure = self.key(pkt.in_if), self.key(pkt.out_if)
        if ":" in pkt.src and not self.ipv6():
            return False
        dst, dport, passed, _ = self._arriving(arrival, pkt)
        if not passed:
            entry = self.interfaces()[arrival]
            assert not entry["blockbogons"], "bogons"
            if entry["blockpriv"] and any(self._within(pkt.src, network) for network in self.PRIVATE[self.model]):
                return False
            rule = self._deciding("in", arrival, pkt, pkt.src, dst, dport)
            if rule is None or rule["action"] != "pass":
                return False  # the default is to block
        src, _ = self._leaving(departure, pkt, dst, dport)
        src = src.split("/")[0]
        rule = self._deciding("out", departure, pkt, src, dst, dport, arrival)
        return rule is None or rule["action"] == "pass"  # the default is to pass what leaves

    def deciding(self, pkt: Any) -> str:
        arrival, departure = self.key(pkt.in_if), self.key(pkt.out_if)
        dst, dport, passed, name = self._arriving(arrival, pkt)
        src, _ = self._leaving(departure, pkt, dst, dport)
        leaving = self._deciding("out", departure, pkt, src.split("/")[0], dst, dport, arrival)
        if leaving is not None and leaving["action"] != "pass":
            return str(leaving["descr"])
        if passed:
            return name
        rule = self._deciding("in", arrival, pkt, pkt.src, dst, dport)
        return "" if rule is None else str(rule["descr"])

    def translation(self, pkt: Any) -> Tuple[str, str, str]:
        dst, dport, _, _ = self._arriving(self.key(pkt.in_if), pkt)
        src, _ = self._leaving(self.key(pkt.out_if), pkt, dst, dport)
        return ("Original" if src == pkt.src else src, "Original" if dst == pkt.dst else dst,
                "Original" if dport == pkt.dport else str(dport))  # fmt: skip


class ForcepointSmc:
    """What a Forcepoint engine would do with a firewall policy, read from the answers of the SMC API.

    This is not fwshift's parser: it reads the answers (one JSON document per line, as the dump program writes them)
    on its own, and is strict: what it does not know, it refuses. Rules are first match in the order the engine sees
    them (template rules down to the insert point, the rules of the level below there, the rest of the template);
    Continue decides nothing; a jump goes into the sub-policy and on with the next rule when nothing there decides; a
    cell with NONE makes the rule match nothing; what no rule decides is discarded. A zone in a cell is the interface a
    packet arrives on (source) or leaves by (destination). NAT rules are first match, after the access rules, on the
    addresses before NAT.
    """

    ADDRESSES = ("host", "router", "network", "address_range", "group", "expression", "domain_name")
    SERVICES = ("tcp_service", "udp_service", "icmp_service", "icmp_ipv6_service", "ip_service", "service_group")
    NOTHING = ("default_nat_address_alias", "mgt_servers_alias", "local_cluster_alias", "internal_user_group", "application_situation")

    def __init__(self, text: str, policy: str = "") -> None:
        import json

        self.by_href: Dict[str, Dict[str, Any]] = {}
        self.lists: Dict[str, List[str]] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            answer = json.loads(line)
            assert isinstance(answer, dict), line[:80]
            if "fwshift_list" in answer:
                self.lists[answer["fwshift_list"]] = [entry["href"] for entry in answer["result"]]
            elif "fwshift_dump" not in answer:
                self.by_href[self._link(answer, "self")] = answer
        policies = [h for h in self.by_href if self.kind(h) == "fw_policy" and (not policy or self.by_href[h]["name"] == policy)]
        assert len(policies) == 1, policies
        levels = [policies[0]]
        while self.by_href[levels[-1]].get("template"):
            levels.append(self.by_href[levels[-1]]["template"])
            assert levels[-1] in self.by_href and len(levels) < 10, levels
        levels.reverse()
        self.rules = {4: self._order(levels, "fw_ipv4_access_rules"), 6: self._order(levels, "fw_ipv6_access_rules")}
        self.nat = {4: self._order(levels, "fw_ipv4_nat_rules"), 6: self._order(levels, "fw_ipv6_nat_rules")}

    @staticmethod
    def _link(obj: Dict[str, Any], rel: str) -> str:
        found = [entry["href"] for entry in obj.get("link", []) if entry.get("rel") == rel]
        assert len(found) == 1, (rel, obj)
        return str(found[0])

    @staticmethod
    def kind(href: str) -> str:
        return href.split("/elements/", 1)[1].split("/")[-2]

    def _list(self, level: str, rel: str) -> List[Dict[str, Any]]:
        where = self._link(self.by_href[level], rel)
        assert where in self.lists, f"the list {where} is not in the answers"
        return [self.by_href[href] for href in self.lists[where]]

    @staticmethod
    def _insert_point(entry: Dict[str, Any]) -> bool:
        return entry.get("type") in ("normal", "automatic") and "action" not in entry and "sources" not in entry

    def _order(self, levels: List[str], rel: str) -> List[Dict[str, Any]]:
        lists = [self._list(level, rel) for level in levels]

        def expand(index: int, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            for entry in entries:
                if not self._insert_point(entry):
                    out.append(entry)
                elif entry["type"] == "normal" and index + 1 < len(lists):
                    href = self._link(entry, "self")
                    out += expand(index + 1, [e for e in lists[index + 1] if e.get("parent_insert_point") == href])
            return out

        out = expand(0, lists[0])
        assert sum(1 for level in lists for e in level if not self._insert_point(e)) == len(out), "a rule of no insert point"
        return out

    # -- matching ------------------------------------------------------------------------------------------

    @staticmethod
    def _ip(text: str) -> Any:
        import ipaddress

        return ipaddress.ip_address(text)

    def address(self, href: str, ip: str, cell: bool) -> bool:
        import ipaddress

        obj, kind, probe = self.by_href[href], self.kind(href), self._ip(ip)
        if kind in ("host", "router"):
            values = [obj.get("address"), obj.get("ipv6_address")] + list(obj.get("secondary") or [])
            return any(value and self._ip(value) == probe for value in values)
        if kind == "network":
            for key in ("ipv4_network", "ipv6_network"):
                if obj.get(key):
                    net = ipaddress.ip_network(obj[key])
                    if probe.version != net.version or probe not in net:
                        continue
                    if cell and net.version == 4 and obj.get("broadcast") is False and net.prefixlen <= 30:
                        return probe not in (net.network_address, net.broadcast_address)
                    return True
            return False
        if kind == "address_range":
            low, high = (self._ip(part.strip()) for part in obj["ip_range"].split("-"))
            return low.version == probe.version and low <= probe <= high
        if kind == "group":
            return any(self.address(member, ip, False) for member in obj["element"])
        if kind == "expression":
            return self._expression(obj, ip)
        if kind == "domain_name":
            return False  # the test packets carry no resolved names
        assert kind in self.NOTHING or kind.endswith("alias"), f"an address of type {kind}"
        return False

    def _expression(self, obj: Dict[str, Any], ip: str) -> bool:
        parts = [self.address(href, ip, False) for href in obj.get("ne_ref") or []]
        parts += [self._expression(inner, ip) for inner in obj.get("sub_expression") or []]
        operator = obj.get("operator") or "none"
        if operator in ("none", "union"):
            return any(parts)
        if operator == "intersection":
            return all(parts)
        assert operator == "exclusion" and len(parts) == 1, obj
        return not parts[0]

    def _side(self, cell: Dict[str, Any], key: str, pkt: Any) -> bool:
        if cell.get("any"):
            return True
        ip, zone = (pkt.src, pkt.in_if) if key == "src" else (pkt.dst, pkt.out_if)
        for href in cell[key]:
            kind = self.kind(href)
            if kind == "interface_zone":
                if self.by_href[href]["name"] == zone:
                    return True
            elif kind == "match_expression":
                refs = self.by_href[href]["ref"]
                if all(self.by_href[r]["name"] == zone if self.kind(r) == "interface_zone" else self.address(r, ip, True) for r in refs):
                    return True
            elif self.address(href, ip, True):
                return True
        return False

    def service(self, href: str, pkt: Any) -> bool:
        obj, kind = self.by_href[href], self.kind(href)
        if kind in ("tcp_service", "udp_service"):
            if pkt.proto != kind[:3]:
                return False
            for low, high, port in (("min_dst_port", "max_dst_port", pkt.dport), ("min_src_port", "max_src_port", pkt.sport)):
                first = obj.get(low)
                if first in (None, ""):
                    continue
                last = obj.get(high) or first
                if not int(first) <= port <= int(last):
                    return False
            return True
        if kind in ("icmp_service", "icmp_ipv6_service"):
            proto = "icmp" if kind == "icmp_service" else "icmp6"
            code = obj.get("icmp_code")
            return pkt.proto == proto and obj["icmp_type"] == pkt.icmp_type and code in (None, 0)
        if kind == "ip_service":
            numbers = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
            return obj["protocol_number"] == numbers.get(pkt.proto, int(pkt.proto) if str(pkt.proto).isdigit() else -1)
        if kind == "service_group":
            return any(self.service(member, pkt) for member in obj["element"])
        assert kind in self.NOTHING, f"a service of type {kind}"
        return False

    def _matches(self, rule: Dict[str, Any], pkt: Any) -> bool:
        if rule.get("is_disabled") or any(rule[key].get("none") for key in ("sources", "destinations", "services")):
            return False
        if (rule.get("match_vpn_options") or {}).get("match_type") in ("normal", "mobile_vpn"):
            return False
        auth = rule.get("authentication_options") or {}
        if auth.get("require_auth") or auth.get("users"):
            return False
        services = rule["services"]
        return (self._side(rule["sources"], "src", pkt) and self._side(rule["destinations"], "dst", pkt)
                and (services.get("any") is True or any(self.service(href, pkt) for href in services["service"])))  # fmt: skip

    def _decide(self, rules: List[Dict[str, Any]], pkt: Any, depth: int = 0) -> Optional[bool]:
        assert depth < 8
        for rule in rules:
            if "sources" not in rule:
                continue  # a section
            if not self._matches(rule, pkt):
                continue
            actions = rule["action"]["action"]
            actions = [actions] if isinstance(actions, str) else actions
            if "jump" in actions:
                sub = rule["action"]["sub_policy"]
                rel = "fw_ipv4_access_rules" if ":" not in pkt.src else "fw_ipv6_access_rules"
                found = self._decide(self._list(sub, rel), pkt, depth + 1)
                if found is not None:
                    return found
                continue
            deciding = [a for a in actions if a in ("allow", "discard", "refuse")]
            assert set(actions) <= {"allow", "discard", "refuse", "continue", "apply_blacklist"}, actions
            if deciding:
                return deciding[0] == "allow"
        return None

    def allows(self, pkt: Any) -> bool:
        return bool(self._decide(self.rules[6 if ":" in pkt.src else 4], pkt))

    def deciding(self, pkt: Any) -> str:
        for rule in self.rules[6 if ":" in pkt.src else 4]:
            if "sources" in rule and self._decide([rule], pkt) is not None:
                return str(rule.get("name") or rule.get("tag"))
        return ""

    # -- NAT -----------------------------------------------------------------------------------------------

    def _first(self, value: Dict[str, Any], family: int) -> Any:
        """The address a translated value stands for, and the first address of its element."""
        import ipaddress

        if value.get("ip_descriptor"):
            return self._ip(value["ip_descriptor"].split("/")[0])
        obj, kind = self.by_href[value["element"]], self.kind(value["element"])
        if kind in ("host", "router"):
            return self._ip(obj["address"] if family == 4 else obj["ipv6_address"])
        if kind == "network":
            return ipaddress.ip_network(obj["ipv4_network" if family == 4 else "ipv6_network"]).network_address
        if kind == "address_range":
            return self._ip(obj["ip_range"].split("-")[0].strip())
        if kind == "group":
            starts = [self._first({"element": member}, family) for member in obj["element"]]
            return min(start for start in starts if start is not None)
        assert kind.endswith("alias"), kind
        return None

    def translation(self, pkt: Any) -> Tuple[str, str, str]:
        family = 6 if ":" in pkt.src else 4
        src, dst, dport = pkt.src, pkt.dst, pkt.dport
        for rule in self.nat[family]:
            used = rule.get("used_on") or {"any": True}
            if rule.get("is_disabled") or used.get("none") or not used.get("any"):
                continue
            if any(rule[key].get("none") for key in ("sources", "destinations", "services")):
                continue
            services = rule["services"]
            if not (self._side(rule["sources"], "src", pkt) and self._side(rule["destinations"], "dst", pkt)
                    and (services.get("any") or any(self.service(href, pkt) for href in services["service"]))):  # fmt: skip
                continue
            options = rule["options"]
            if options.get("static_dst_nat"):
                spec = options["static_dst_nat"]
                start, new = self._first(spec["original_value"], family), self._first(spec["translated_value"], family)
                dst = str(new + (int(self._ip(pkt.dst)) - int(start)))
                low, new_low = spec["original_value"].get("min_port"), spec["translated_value"].get("min_port")
                if new_low not in (None, ""):
                    dport = int(new_low) + (pkt.dport - int(low or pkt.dport))
            if options.get("static_src_nat"):
                spec = options["static_src_nat"]
                start, new = self._first(spec["original_value"], family), self._first(spec["translated_value"], family)
                src = str(new + (int(self._ip(pkt.src)) - int(start)))
            if options.get("dynamic_src_nat"):
                first = self._first(options["dynamic_src_nat"]["translation_values"][0], family)
                src = "MASQ" if first is None else str(first)
            break
        return ("Original" if src == pkt.src else src, "Original" if dst == pkt.dst else dst,
                "Original" if dport == pkt.dport else str(dport))  # fmt: skip
