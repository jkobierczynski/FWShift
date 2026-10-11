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
