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
    start_letter: bool = False  # a letter first (an "x" is put in front otherwise)


# PAN-OS: letters, digits, space, hyphen, underscore and period; alphanumeric first.
PANOS = NameRules(63, re.compile(r"[^A-Za-z0-9 ._-]"), True)
# FortiOS: most printable characters, but not quotes, brackets, hash or backslash.
FORTIOS = NameRules(79, re.compile(r"[\"'<>()#\\\x00-\x1f]"), False)
FORTIOS_POLICY = NameRules(35, FORTIOS.invalid, False)
# Check Point: kept to letters, digits, underscore, hyphen and period, which every release accepts.
CHECKPOINT = NameRules(100, re.compile(r"[^A-Za-z0-9._-]"), True)
# Names that come from Check Point itself are valid there: only what would break the script is replaced,
# control characters and a leading hyphen (which mgmt_cli would read as a switch).
CHECKPOINT_NATIVE = NameRules(255, re.compile(r"[\x00-\x1f\x7f]|^-+"), False)
# Cisco ASA: letters, digits, underscore, hyphen and period, which every release accepts; alphanumeric first.
ASA = NameRules(64, re.compile(r"[^A-Za-z0-9._-]"), True)
# Names that come from an ASA are valid there: only what cannot stand in a command is replaced.
ASA_NATIVE = NameRules(64, re.compile(r"[^!-~]|[?\"]"), False)
# Rule names end up in remarks, which are free text.
ASA_TEXT = NameRules(80, re.compile(r"[\x00-\x1f\x7f]"), False)
# Sophos Firewall: kept to letters, digits, space, underscore, hyphen and period. A service name may have 50
# characters, a host or a rule 60: objects are kept to 50.
SOPHOS = NameRules(50, re.compile(r"[^A-Za-z0-9 ._-]"), True)
SOPHOS_RULE = NameRules(60, SOPHOS.invalid, True)
# Names that come from a Sophos Firewall are valid there: only what cannot stand in its XML, and the comma that
# separates names in its lists, is replaced.
SOPHOS_NATIVE = NameRules(60, re.compile("[\\x00-\\x1f\\x7f,\ufffe\uffff\ud800-\udfff]"), False)
# Cisco Secure Firewall, both managers: kept to letters, digits, underscore, hyphen and period, which both take
# for every kind of object. A rule of a Management Center may have 50 characters and spaces; a rule of a Device
# Manager has no spaces.
CISCO = NameRules(64, re.compile(r"[^A-Za-z0-9._-]"), True)
CISCO_FMC_RULE = NameRules(50, re.compile(r"[^A-Za-z0-9 ._-]"), True)
CISCO_FDM_RULE = NameRules(128, CISCO.invalid, True)
# Names that come from the same manager are valid there: only what its API refuses anywhere is replaced.
CISCO_NATIVE = NameRules(128, re.compile(r"[\x00-\x1f\x7f;]"), False)
# pfSense: an alias has up to 31 letters, digits and underscores (is_validaliasname). A name of digits only, a word
# of pf, a protocol and a service name are refused as well; the emitter sees to those.
PFSENSE = NameRules(31, re.compile(r"[^A-Za-z0-9_]"), True)
# OPNsense: as pfSense, with a letter first (AliasNameField).
OPNSENSE = NameRules(31, PFSENSE.invalid, True, True)
# The description of a rule is free text.
PFSENSE_TEXT = NameRules(200, re.compile(r"[\x00-\x1f\x7f]"), False)

# SonicWall: up to 32 printable characters (ASCII 32-126) for an address object, 50 for a group; no double quote,
# single quote or backslash. Everything is kept to 32.
SONICWALL = NameRules(32, re.compile(r"[^ -~]|[\"'\\]"), True)
SONICWALL_NATIVE = NameRules(32, SONICWALL.invalid, False)

# WatchGuard: no limit or character set of a name is published. Control characters are left out, and names are kept
# to 100 characters.
WATCHGUARD = NameRules(100, re.compile(r"[\x00-\x1f\x7f]"), False)

# Barracuda CloudGen Firewall: the REST API refuses some characters in a rule name and does not say which, nor how
# long a name may be. Names are kept to letters, digits, period, underscore and hyphen, and to 32 characters.
BARRACUDA = NameRules(32, re.compile(r"[^A-Za-z0-9._-]"), True)

# Juniper SRX: names of up to 63 characters that start with a letter or digit (third-party documentation; Juniper's own
# statement pages could not be read). Objects take letters, digits, ".", "_", "-", ":" and "/"; policies and NAT rules
# are kept to letters, digits, "_" and "-".
JUNOS = NameRules(63, re.compile(r"[^A-Za-z0-9._:/-]"), True)
JUNOS_RULE = NameRules(63, re.compile(r"[^A-Za-z0-9_-]"), True)


def clean(name: str, rules: NameRules) -> str:
    out = rules.invalid.sub("_", name).strip()
    if (rules.start_alnum and not (out[:1].isascii() and out[:1].isalnum())) or (rules.start_letter and not (out[:1].isascii() and out[:1].isalpha())):
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
