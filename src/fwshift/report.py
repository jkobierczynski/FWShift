# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Lossiness report: what was converted exactly, approximately, or not at all."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import AbstractSet, Any, Dict, List, Tuple


class Severity(IntEnum):
    INFO = 0  # exact, worth knowing
    APPROX = 1  # converted, but not with identical semantics
    REVIEW = 2  # a person has to look at this before it goes live


_LABEL = {Severity.INFO: "info", Severity.APPROX: "approximated", Severity.REVIEW: "needs-review"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _name(text: str) -> str:
    """A name as the conversion writes it: control characters replaced (see transform.harden)."""
    return _CONTROL.sub("_", text)


def _line(text: str) -> str:
    """A message on one line: text taken from the input cannot start a line of its own in the report."""
    return _CONTROL.sub(" ", text)

_KIND_TITLES = [
    ("rule", "Security rules"),
    ("nat", "NAT rules"),
    ("address", "Addresses"),
    ("address-group", "Address groups"),
    ("service", "Services"),
    ("service-group", "Service groups"),
]


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"severity": _LABEL[self.severity], "code": self.code, "message": self.message}


@dataclass
class Item:
    kind: str
    name: str
    findings: List[Finding] = field(default_factory=list)
    disabled: bool = False  # emitted, but switched off by the converter
    skipped: bool = False  # not emitted at all
    emitted_as: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        worst = max((f.severity for f in self.findings), default=Severity.INFO)
        return "exact" if worst == Severity.INFO else _LABEL[worst]


class Report:
    def __init__(self) -> None:
        self.source = ""
        self.target = ""
        self.items: Dict[Tuple[str, str], Item] = {}
        self.notes: List[Finding] = []

    def item(self, kind: str, name: str) -> Item:
        name = _name(name)
        key = (kind, name)
        if key not in self.items:
            self.items[key] = Item(kind, name)
        return self.items[key]

    def discard(self, kind: str, name: str) -> None:
        """Forget an item, with its findings: what it stood for is reported under another name."""
        self.items.pop((kind, _name(name)), None)

    def register(self, kind: str, names: List[str]) -> None:
        """Make the report list these items first, in this order (the order of the source)."""
        names = [_name(name) for name in names]
        ordered = {(kind, name): self.items.get((kind, name)) or Item(kind, name) for name in names}
        for key, item in self.items.items():
            ordered.setdefault(key, item)
        self.items = ordered

    def add(self, kind: str, name: str, severity: Severity, code: str, message: str) -> None:
        item, message = self.item(kind, name), _line(message)
        if not any(f.code == code and f.message == message for f in item.findings):
            item.findings.append(Finding(severity, code, message))

    def disable(self, kind: str, name: str, code: str, message: str) -> None:
        self.add(kind, name, Severity.REVIEW, code, message)
        self.item(kind, name).disabled = True

    def skip(self, kind: str, name: str, code: str, message: str, severity: Severity = Severity.REVIEW) -> None:
        self.add(kind, name, severity, code, message)
        self.item(kind, name).skipped = True

    def retract(self, kind: str, codes: AbstractSet[str]) -> None:
        """Withdraw findings that a later step has made moot; kind "note" withdraws notes for the whole policy."""
        if kind == "note":
            self.notes = [note for note in self.notes if note.code not in codes]
        for item in self.items.values():
            if item.kind == kind:
                item.findings = [f for f in item.findings if f.code not in codes]

    def note(self, severity: Severity, code: str, message: str) -> None:
        message = _line(message)
        if not any(f.code == code and f.message == message for f in self.notes):
            self.notes.append(Finding(severity, code, message))

    # -- output ---------------------------------------------------------

    def counts(self, kind: str) -> Dict[str, int]:
        out = {"total": 0, "exact": 0, "approximated": 0, "needs-review": 0, "skipped": 0, "disabled": 0}
        for item in self.items.values():
            if item.kind != kind:
                continue
            out["total"] += 1
            out[item.status] += 1
            if item.disabled and not item.skipped:
                out["disabled"] += 1
        return out

    @property
    def needs_review(self) -> bool:
        return any(f.severity == Severity.REVIEW for f in self.notes) or any(
            item.status in ("needs-review", "skipped") for item in self.items.values()
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "summary": {kind: self.counts(kind) for kind, _ in _KIND_TITLES},
            "notes": [f.to_dict() for f in self.notes],
            "items": [
                {
                    "kind": item.kind,
                    "name": item.name,
                    "status": item.status,
                    "disabled": item.disabled,
                    "emitted_as": item.emitted_as,
                    "findings": [f.to_dict() for f in item.findings],
                }
                for item in self.items.values()
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"

    def to_text(self) -> str:
        out: List[str] = ["FWShift conversion report", f"  source: {self.source}", f"  target: {self.target}", ""]
        out.append("Summary")
        for kind, title in _KIND_TITLES:
            c = self.counts(kind)
            if not c["total"]:
                continue
            line = (
                f"  {title + ':':<16} {c['total']:>5}   exact {c['exact']}, "
                f"approximated {c['approximated']}, needs review {c['needs-review']}"
            )
            if c["disabled"]:
                line += f" ({c['disabled']} emitted disabled)"
            line += f", skipped {c['skipped']}"
            out.append(line)
        if self.notes:
            out += ["", "Notes for the whole policy"]
            for f in sorted(self.notes, key=lambda f: -f.severity):
                out.append(f"  [{_LABEL[f.severity]}] {f.code}: {f.message}")
        for kind, title in _KIND_TITLES:
            flagged = [i for i in self.items.values() if i.kind == kind and (i.findings or i.skipped)]
            if not flagged:
                continue
            out += ["", title]
            for item in flagged:
                state = item.status + (", emitted disabled" if item.disabled and not item.skipped else "")
                line = f"  {item.name}  ->  {state}"
                if item.emitted_as and item.emitted_as != [item.name]:
                    line += "  (emitted as " + ", ".join(item.emitted_as) + ")"
                out.append(line)
                for f in item.findings:
                    out.append(f"      [{_LABEL[f.severity]}] {f.code}: {f.message}")
        return "\n".join(out) + "\n"
