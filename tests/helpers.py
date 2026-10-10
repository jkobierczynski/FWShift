# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared helpers: load the synthetic samples and read back emitted configuration."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fwshift import cli
from fwshift.model import Policy
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
