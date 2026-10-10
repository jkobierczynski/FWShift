# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Object-name rules of the target platforms."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern, Set


@dataclass(frozen=True)
class NameRules:
    max_len: int
    invalid: Pattern[str]
    start_alnum: bool


# PAN-OS: letters, digits, space, hyphen, underscore and period; alphanumeric first.
PANOS = NameRules(63, re.compile(r"[^A-Za-z0-9 ._-]"), True)
# FortiOS: most printable characters, but not quotes, brackets, hash or backslash.
FORTIOS = NameRules(79, re.compile(r"[\"'<>()#\\\x00-\x1f]"), False)
FORTIOS_POLICY = NameRules(35, FORTIOS.invalid, False)


def clean(name: str, rules: NameRules) -> str:
    out = rules.invalid.sub("_", name).strip()
    if rules.start_alnum and not (out[:1].isascii() and out[:1].isalnum()):
        out = "x" + out
    if not out:
        out = "unnamed"
    return out[: rules.max_len].rstrip()


def unique(name: str, taken: Set[str], rules: NameRules) -> str:
    """Clean ``name``, make it unique against ``taken`` and record it there."""
    base = clean(name, rules)
    candidate = base
    counter = 2
    while candidate in taken:
        suffix = f"_{counter}"
        candidate = base[: rules.max_len - len(suffix)].rstrip() + suffix
        counter += 1
    taken.add(candidate)
    return candidate
