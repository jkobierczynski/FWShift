# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAN-OS set commands -> the XML configuration they stand for, which the PAN-OS parser reads.

What a firewall or Panorama prints with ``set cli config-output-format set`` and ``show config running`` (or ``show``
in configuration mode), and what FWShift's PAN-OS target writes: one ``set`` command per line, the words of the path
to a value of the configuration, then the value. A command is the XML path it names:

    set address web-server ip-netmask 10.20.2.10/32
    <address><entry name="web-server"><ip-netmask>10.20.2.10/32</ip-netmask></entry></address>

    set rulebase security rules allow-web from [ inside dmz ]
    <rulebase><security><rules><entry name="allow-web"><from><member>inside</member><member>dmz</member></from>...

One command may set several values of the same entry (``... rules r from trust to untrust action allow``), as the
CLI takes them. A value with spaces is in double quotes, and may run over several lines (a certificate, a banner);
a backslash is a character like any other (``"example\\domain users"``, as PAN-OS prints it).

Where the path begins: ``set shared ...`` is the shared configuration, ``set vsys NAME ...`` a virtual system,
``set device-group NAME ...`` a device group of Panorama, the objects and rules of a virtual system without one of
these are of ``vsys1`` (what a firewall with one virtual system prints), and the rest (``deviceconfig``, ``network``,
``template`` of Panorama, ...) belongs to the device. Which words are followed by the name of an entry, and which
values are lists of members, is PAN-OS's schema; this module knows the part of it the PAN-OS parser reads, and keeps
the rest as it comes. Commands other than ``set`` (``delete``, ``rename``) are not read, and said; what a session
prints around them (the prompt, ``[edit]``, ``show``) is left out.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Dict, Iterator, List, Optional, Tuple

from ..errors import ParseError
from ..report import Report, Severity

# Words followed by the name of an entry wherever they stand.
_ENTRIES = {
    "rules", "vsys", "device-group", "ethernet", "units", "virtual-router", "aggregate-ethernet", "loopback", "vlan",
    "devices", "template", "template-stack", "static-route", "log-settings-profiles", "custom-url-category",
}  # fmt: skip
# Words followed by the name of an entry where the objects of a virtual system, a device group or shared stand (in a
# rule, the same words are a value or a list: service, application, tag, schedule).
_OBJECTS = {
    "address", "address-group", "service", "service-group", "application", "application-group", "application-filter",
    "zone", "tag", "schedule", "external-list", "profile-group", "region", "dynamic-user-group",
}  # fmt: skip
# The first words of the objects and rules of a virtual system (a command without vsys NAME: of vsys1).
_VSYS_WORDS = _OBJECTS | {
    "rulebase", "pre-rulebase", "post-rulebase", "profiles", "import", "display-name", "setting", "log-settings", "user-id-agent", "user-id-collector",
    "authentication-object", "server-profile", "reports", "report-group", "pdf-summary-report", "email-scheduler",
    "global-protect", "captive-portal", "ocsp-responder", "ssl-decrypt", "certificate", "certificate-profile",
    "ssl-tls-service-profile", "response-page", "threats", "url-admin-override", "admin-role",
}  # fmt: skip
_CONFIG_WORDS = {"mgt-config", "readonly", "shared"}
# The words of a rule whose value is a list of members.
_RULE_MEMBERS = {"from", "to", "source", "destination", "source-user", "category", "hip-profiles", "source-hip",
                 "destination-hip", "application", "service", "tag", "source-imei", "source-imsi", "source-nw-slice"}  # fmt: skip
# Words whose value is a list of members wherever they stand.
_MEMBERS = {"static", "members", "group", "subcategory", "technology", "risk", "member", "negate-member"}
# The interfaces of a zone (zone NAME network layer3 [ ... ]).
_ZONE_NETWORK = {"layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"}
# Where the tags of an entry are a list (elsewhere, tag is an entry of its own, or a VLAN number).
_TAGGED = {"address", "address-group", "service", "service-group", "application-group", "application-filter",
           "application", "external-list", "schedule"}  # fmt: skip
# The profiles of a rule (profile-setting profiles virus [ ... ]) are lists; profiles TYPE NAME elsewhere are entries.
_PROFILE_TYPES = {"virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering",
                  "dns-security", "sctp-protection", "gtp"}  # fmt: skip
# Words that are followed by one value, then perhaps by more words of the same entry (``disabled yes description x``).
_LEAVES = {
    "action", "disabled", "description", "log-setting", "log-start", "log-end", "rule-type", "negate-source",
    "negate-destination", "schedule", "icmp-unreachable", "group-tag", "negate", "ip-netmask", "ip-range", "fqdn",
    "ip-wildcard", "color", "comments", "port", "source-port", "nat-type", "to-interface", "translated-port",
    "bi-directional", "filter", "parent-dg", "ip-address", "metric", "comment", "translated-address", "distribution",
    "direction", "ip-dscp", "ip-precedence", "disable-server-response-inspection",
}  # fmt: skip
# Free text, where a value in [ ] unquoted is text too (description [legacy]).
_TEXT = {"description", "comment", "comments"}
# What the parts of a rule hold, as far as the parser reads them: a word that is not one of them, after such a part in
# one command, is of the rule again (... profile-setting group default log-setting fwd).
_CHILDREN = {
    "profile-setting": {"group", "profiles"}, "profiles": _PROFILE_TYPES, "qos": {"marking"},
    "marking": {"ip-dscp", "ip-precedence", "follow-c2s-flow"}, "follow-c2s-flow": set(), "target": {"devices", "negate", "tags"},
    "devices/entry": {"vsys"}, "vsys/entry": set(), "option": {"disable-server-response-inspection"},
    "source-translation": {"dynamic-ip-and-port", "dynamic-ip", "static-ip"},
    "dynamic-ip-and-port": {"translated-address", "interface-address"}, "interface-address": {"interface", "ip", "floating-ip"},
    "dynamic-ip": {"translated-address", "fallback"}, "fallback": {"translated-address", "interface-address"},
    "static-ip": {"translated-address", "bi-directional"},
    "destination-translation": {"translated-address", "translated-port", "dns-rewrite"}, "dns-rewrite": {"direction"},
    "dynamic-destination-translation": {"translated-address", "translated-port", "distribution"},
}  # fmt: skip
# Elements whose value is an element of its own (qos marking follow-c2s-flow: <marking><follow-c2s-flow/></marking>).
_FLAG_HOLDERS = {"marking", "override"}
# What a session prints around the commands, and the commands of a session that change nothing.
_SESSION = {"show", "configure", "exit", "quit", "top", "up", "run", "commit", "Entering", "save", "validate"}

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*$")
_PROMPT = re.compile(r"[^\s#>]*@[^\s#>]*[#>][ \t]*")  # (admin@PA-VM# set ..., copied from a session)
_DEPTH = 64

_TOP_WORDS = ("rulebase", "pre-rulebase", "post-rulebase", "vsys", "device-group", "shared", "zone", "address", "address-group",
              "service", "service-group", "deviceconfig", "mgt-config", "application-group", "application-filter", "tag",
              "profiles", "profile-group", "schedule", "external-list", "readonly", "network", "template", "template-stack")  # fmt: skip
_TOP_LINE = re.compile(rb"^(?:[^\s#>]*@[^\s#>]*[#>]\s*)?set (" + b"|".join(w.encode() for w in _TOP_WORDS) + rb") ", re.M)
# FortiOS (whose policies have set service ..., set schedule ...): config SECTION, then edit/next/end lines.
_FORTIOS_CONFIG = re.compile(rb"^[ \t]*config [a-z][a-z0-9 -]*\r?$", re.M)
_FORTIOS_END = re.compile(rb"^[ \t]*(next|end)[ \t]*\r?$", re.M)

Word = Tuple[str, bool]  # (the word, whether it was in quotes)


def looks_like_set(data: bytes) -> bool:
    """Set commands of PAN-OS: a line ``set WORD`` whose first word is one PAN-OS has at the top of its configuration."""
    head = data[:2_000_000]
    if _FORTIOS_CONFIG.search(head) and _FORTIOS_END.search(head):
        return False
    return bool(_TOP_LINE.search(head))


def commands(text: str) -> Iterator[Tuple[int, List[Word]]]:
    """The commands of the text: (number of the line it begins on, its words). A command ends where a line ends
    outside quotes; a double-quoted string is one word and may run over lines; [ and ] outside quotes are words of
    their own. PAN-OS prints a quote inside a value as it is (``"the "office" LAN"``), so a quote ends the word where
    what follows it reads as words of a command: on the line, a space or a ] after it and the rest of the line in
    words; at the end of a line, the next line a command (or the end of the text). Once a value has run over a line,
    only the end of a line ends it."""
    position, length, number = 0, len(text), 1
    while position < length:
        # The start of a line: a comment, or the prompt of a session before the command.
        end = text.find("\n", position)
        end = length if end < 0 else end
        line = text[position:end]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            position, number = end + 1, number + 1
            continue
        position += len(line) - len(line.lstrip())
        match = _PROMPT.match(text, position)
        if match:
            position = match.end()
        start_line = number
        out: List[Word] = []
        while position < length and text[position] != "\n":
            char = text[position]
            if char in " \t\r":
                position += 1
                continue
            if char == '"':
                begin = search = position + 1
                line_end = text.find("\n", position)
                line_end = length if line_end < 0 else line_end
                # Free text as the last value of the line (as PAN-OS prints it): it ends at the end of the line, also
                # where a quote in it is followed by words ("Server "web 1" and "web 2"").
                text_to_end = bool(out) and out[-1][0] in _TEXT and not out[-1][1] and text[begin:line_end].rstrip().endswith('"')
                while True:
                    close = text.find('"', search)
                    if close < 0:
                        raise ParseError(f"line {start_line}: a quote is not closed")
                    after = text[close + 1:close + 2]
                    crossed = "\n" in text[begin:close]
                    close_end = text.find("\n", close)
                    if not text[close + 1:length if close_end < 0 else close_end].strip():  # (at the end of its line)
                        if _command_follows(text, close + 1):
                            break
                    elif after in (" ", "\t", "\r", "]") and not crossed and not text_to_end and _words_follow(text, close + 1):
                        break
                    search = close + 1
                word = text[begin:close]
                if _COMMAND_INSIDE.search(word):
                    raise ParseError(f"line {start_line}: a quote is not closed (the value runs into the commands after it)")
                number += word.count("\n")
                out.append((word, True))
                position = close + 1
                continue
            if char in "[]":
                out.append((char, False))
                position += 1
                continue
            begin = position
            while position < length and text[position] not in ' \t\r\n"[]':
                position += 1
            out.append((text[begin:position], False))
        position, number = position + 1, number + 1
        if out:
            yield start_line, out


_COMMAND_START = re.compile(r"[ \t]*(?:[^\s#>]*@[^\s#>]*[#>]|set |delete |rename |move |edit |unset |#|\[edit|show\b|configure\b|exit\b|quit\b|commit\b|Entering configuration)")
_COMMAND_INSIDE = re.compile(r"\n[ \t]*(?:[^\s#>]*@[^\s#>]*[#>][ \t]*)?set (?:" + "|".join(_TOP_WORDS) + ") ")


def _command_follows(text: str, position: int) -> bool:
    """Whether a command, or the end of the text, comes after the end of the line at ``position``."""
    while position < len(text):
        end = text.find("\n", position)
        end = len(text) if end < 0 else end
        if text[position:end].strip():
            return bool(_COMMAND_START.match(text, position))
        position = end + 1
    return True


def _words_follow(text: str, position: int, stop: int = -1, budget: Optional[List[int]] = None) -> bool:
    """Whether the rest of the line from ``position`` reads as words: each quote that begins a word comes after a space
    or a [, and ends where the rest reads as words in turn (one that does not end on the line begins a value that
    runs over lines)."""
    if stop < 0:
        stop = text.find("\n", position)
        stop = len(text) if stop < 0 else stop
    budget = budget if budget is not None else [200]  # (a line of many quotes: no more than this many tries)
    while position < stop:
        if text[position] != '"':
            position += 1
            continue
        if text[position - 1] not in " \t[":
            return False
        search = position + 1
        while True:
            close = text.find('"', search, stop)
            if close < 0:
                return True
            budget[0] -= 1
            if close + 1 >= stop or (text[close + 1] in " \t\r]" and (budget[0] <= 0 or _words_follow(text, close + 1, stop, budget))):
                return True
            search = close + 1
    return True


class _Tree:
    def __init__(self) -> None:
        self.config = ET.Element("config")
        self.devices = ET.SubElement(ET.SubElement(self.config, "devices"), "entry", name="localhost.localdomain")
        self.index: Dict[Tuple[int, str, str], ET.Element] = {}  # (parent, tag, name) -> element

    def child(self, parent: ET.Element, tag: str, name: Optional[str] = None) -> ET.Element:
        key = (id(parent), tag, "" if name is None else "\0" + name)
        found = self.index.get(key)
        if found is None:
            found = ET.SubElement(parent, tag, name=name) if name is not None else ET.SubElement(parent, tag)
            self.index[key] = found
        return found

    def entry(self, parent: ET.Element, tag: str, name: str) -> ET.Element:
        return self.child(self.child(parent, tag), "entry", name)


def _top(lineage: List[str]) -> bool:
    """Where the objects of a virtual system, a device group or the shared configuration stand."""
    return lineage[-1] == "shared" or (lineage[-1] == "entry" and lineage[-2] in ("vsys", "device-group"))


def _rule(lineage: List[str]) -> str:
    """'security', 'nat', ... where the path is at a rule of that rulebase, else ''."""
    if len(lineage) >= 4 and lineage[-1] == "entry" and lineage[-2] == "rules":
        return lineage[-3]
    return ""


def _is_entry_word(word: str, lineage: List[str]) -> bool:
    if word in _OBJECTS:
        return _top(lineage)
    if word == "tunnel":
        return lineage[-1] == "interface"
    if word == "ip":  # (the addresses of an interface or a unit: ip 10.0.0.1/24, an entry each)
        return lineage[-1] in ("layer3", "entry") and "interface" in lineage
    if word in _ENTRIES:
        return True
    if word in _PROFILE_TYPES:
        return lineage[-1] == "profiles" and lineage[-2] != "profile-setting"
    return False


def _is_member_word(word: str, lineage: List[str]) -> bool:
    parent, grandparent = lineage[-1], lineage[-2]
    rule = _rule(lineage)
    if rule and word in _RULE_MEMBERS:
        return not (word == "service" and rule == "nat")  # (the service of a NAT rule is one, not a list)
    if word == "tag":
        return parent == "entry" and grandparent in _TAGGED
    if word in _ZONE_NETWORK:
        return lineage[-3:] == ["zone", "entry", "network"]
    if word == "interface":
        return parent == "entry" and grandparent == "virtual-router"
    if word == "translated-address":
        return parent in ("dynamic-ip-and-port", "dynamic-ip")
    if word in _MEMBERS:
        return True
    if word in _PROFILE_TYPES:
        return parent == "profiles" and grandparent == "profile-setting"
    return False


_BOMS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))


def _decode(data: bytes) -> str:
    for bom, codec in _BOMS:
        if data.startswith(bom):
            try:
                return data.decode(codec)
            except UnicodeDecodeError as error:
                raise ParseError(f"not readable as {codec.upper()}: {error}") from None
    return data.decode("utf-8-sig", errors="replace")


def is_xml(data: bytes) -> bool:
    """Whether the data is XML (in UTF-8, or UTF-16 or UTF-32 with a byte order mark), not set commands."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            head = data[: 4096 - 4096 % 4]
            return head.decode(codec, errors="ignore").lstrip("﻿ \t\r\n").startswith("<")
    return data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<")


def to_xml(data: bytes, report: Report) -> bytes:
    """The XML configuration the set commands stand for (the <config> element)."""
    text = _decode(data).replace("\r\n", "\n")
    tree = _Tree()
    skipped: Dict[str, int] = {}
    read = 0
    for number, parts in commands(text):
        first, quoted = parts[0]
        if first != "set" or quoted:
            if first == "[" and not quoted and len(parts) > 3 and parts[1][0] == "edit":
                level = "[edit " + " ".join(word for word, _ in parts[2:-1]) + "]"
                skipped[level] = skipped.get(level, 0) + 1  # (what a show prints after it is relative to it)
            elif quoted or (first not in _SESSION and first != "["):
                skipped[first] = skipped.get(first, 0) + 1
            continue
        if len(parts) >= 2 and parts[1] == ("cli", False):
            continue  # (set cli config-output-format set: of the session, not of the configuration)
        if len(parts) < 3:
            continue
        _command(tree, parts[1:], number)
        read += 1
    if not read:
        raise ParseError("no set commands of a PAN-OS configuration found")
    if skipped:
        report.note(Severity.REVIEW, "SET_COMMANDS_NOT_READ",
                    "commands other than set are not read (a configuration printed in set format has none), and what "
                    "follows an [edit LEVEL] of a session is relative to that level: "
                    + ", ".join(f"{word} ({count})" for word, count in sorted(skipped.items())))  # fmt: skip
    report.note(Severity.INFO, "PANOS_SET_FORMAT", f"read from {read} set commands (PAN-OS's set format), as the XML they stand for")
    out: bytes = ET.tostring(tree.config, encoding="utf-8")
    return out


def _values(rest: List[Word], position: int, number: int) -> Tuple[List[str], int]:
    """The value at ``position``: one word, or a list [ ... ]; and the position after it."""
    word, quoted = rest[position]
    if word == "[" and not quoted:
        values: List[str] = []
        position += 1
        while position < len(rest) and rest[position] != ("]", False):
            if rest[position] == ("[", False):
                raise ParseError(f"line {number}: a list inside a list")
            values.append(rest[position][0])
            position += 1
        if position >= len(rest):
            raise ParseError(f"line {number}: a list [ ... ] is not closed")
        return values, position + 1
    if word == "]" and not quoted:
        raise ParseError(f"line {number}: a ] without its [")
    return [word], position + 1


def _command(tree: _Tree, path: List[Word], number: int) -> None:
    head = path[0][0]
    if head in ("vsys", "device-group"):
        node = tree.entry(tree.devices, head, path[1][0])
        lineage, rest = ["", "config", "devices", "entry", head, "entry"], path[2:]
    elif head == "shared":
        node, lineage, rest = tree.child(tree.config, "shared"), ["", "config", "shared"], path[1:]
    elif head in _CONFIG_WORDS:
        node, lineage, rest = tree.config, ["", "config"], path
    elif head in _VSYS_WORDS:
        node, lineage, rest = tree.entry(tree.devices, "vsys", "vsys1"), ["", "config", "devices", "entry", "vsys", "entry"], path
    else:  # (deviceconfig, network, template, log-collector, ...: of the device)
        node, lineage, rest = tree.devices, ["", "config", "devices", "entry"], path
    base = len(lineage)
    frames: List[Tuple[ET.Element, List[str]]] = []  # (where the path was, before each step into a part)
    position = 0
    while position < len(rest):
        if len(lineage) - base > _DEPTH:
            raise ParseError(f"line {number}: a path deeper than {_DEPTH} elements")
        word, quoted = rest[position]
        # Several values in one command: back out of a part of a rule that does not hold this word.
        while frames and not _rule(lineage) and any(_rule(f[1]) for f in frames):
            key = lineage[-1] if lineage[-1] != "entry" else lineage[-2] + "/entry"
            if key not in _CHILDREN or word in _CHILDREN[key]:
                break
            node, lineage = frames.pop()
        remaining = len(rest) - position - 1
        if word in ("[", "]") and not quoted:
            raise ParseError(f"line {number}: a list where a word of the path was expected")
        if remaining >= 1 and _is_member_word(word, lineage):
            values, position = _values(rest, position + 1, number)
            holder = tree.child(node, word)
            present = {m.text for m in holder.findall("member")}
            for value in values:
                if value not in present:
                    ET.SubElement(holder, "member").text = value
                    present.add(value)
            continue
        if remaining >= 1 and _is_entry_word(word, lineage):
            names, after = _values(rest, position + 1, number)
            if rest[position + 1] == ("[", False):
                for name in names:  # (several entries at once: target devices SERIAL vsys [ vsys1 vsys2 ])
                    tree.entry(node, word, name)
                position = after
                continue
            frames.append((node, list(lineage)))
            node = tree.entry(node, word, names[0])
            lineage = lineage + [word, "entry"]
            position = after
            continue
        valid = bool(_NAME.match(word))
        single = (word in _LEAVES or (word == "service" and _rule(lineage) == "nat")
                  or (word in ("interface", "ip", "floating-ip") and lineage[-1] in ("interface-address", "nexthop"))
                  or (word == "interface" and lineage[-2:] == ["static-route", "entry"]))  # fmt: skip
        if remaining >= 1 and rest[position + 1] == ("[", False):
            values, position = _values(rest, position + 1, number)
            if word in _TEXT:
                tree.child(node, word).text = "[" + " ".join(values) + "]"  # (unquoted text in brackets: text)
                continue
            if single and word != "translated-address":
                if len(values) != 1:
                    raise ParseError(f"line {number}: {word} takes one value, not a list")
                tree.child(node, word).text = values[0]
                continue
            holder = tree.child(node, word) if valid else tree.child(node, "entry", word)
            for value in values:
                ET.SubElement(holder, "member").text = value
            continue
        if remaining == 0:
            tree.child(node, word) if valid else tree.child(node, "entry", word)  # (an element without a value)
            position += 1
            continue
        if remaining == 1 or single:
            value, value_quoted = rest[position + 1]
            if value == "]" and not value_quoted:
                raise ParseError(f"line {number}: a ] without its [")
            if not valid:
                ET.SubElement(tree.child(node, "entry", word), "value").text = value
            elif word in _FLAG_HOLDERS and not value_quoted and _NAME.match(value):
                tree.child(tree.child(node, word), value)
            else:
                tree.child(node, word).text = value
            position += 2
            continue
        frames.append((node, list(lineage)))
        if valid:
            node = tree.child(node, word)
            lineage = lineage + [word]
        else:
            node = tree.child(node, "entry", word)
            lineage = lineage + ["entry", "entry"]
        position += 1
