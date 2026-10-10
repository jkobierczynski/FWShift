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

