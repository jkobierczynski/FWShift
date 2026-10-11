# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared helpers: load the synthetic samples and read back emitted configuration."""

from __future__ import annotations

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
                self._known(fields.get(column, []))
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
                if column in fields:
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
