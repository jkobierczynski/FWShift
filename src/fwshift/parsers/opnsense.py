# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""OPNsense parser: ``config.xml`` (OPNsense 24.7 to 26.7) -> neutral model.

OPNsense comes from the same line as pfSense and writes the same kind of pf ruleset, so this parser is the pfSense
parser with what OPNsense does otherwise. The configuration is first brought into the form the pfSense reader reads;
where OPNsense decides differently, the reader is overridden. What differs:

* Flags: most elements count as set only when they hold something other than ``0`` (pfSense: when they are there).
  ``not`` of a source or destination changed to that in 26.1.
* A rule without ``ipprotocol`` is for IPv4 and IPv6; a floating rule without a direction is for incoming traffic;
  ports count only for TCP and UDP. A rule on an interface tab can be "not quick" and for outgoing traffic.
* Rules of the newer kind (``OPNsense/Firewall/Filter/rules``, "Rules [new]") come before the others in each tier,
  by their sequence number; the rules of interface groups by the sequence of the group. Since 26.1 a port forward
  can register a rule of its own, after every other rule.
* Aliases are kept in ``OPNsense/Firewall/Alias``, one entry per line, with ``!`` to leave addresses out.
* 1:1 NAT, NPt and the newer outbound NAT rules are kept under ``OPNsense/Firewall/Filter``; port forwards in
  ``<nat>``, of a newer form from 26.1.
* "Block private networks" has a list of networks of its own per series; IPv6 interface networks include fe80::/10.
"""

from __future__ import annotations

import copy
import html
import ipaddress
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import transform, xmlread
from ..errors import ParseError
from ..model import ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, NatRule, Policy, Rule, SnatKind, SourceNat
from ..netutil import Interval, int_to_ip, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity
from . import pfsense as _pf
from .pfsense import ICMP6_TYPES, KEY, SYSTEM_GROUPS, _child, _children, _clean, _has, _short, _text

_RULE_TYPES = ("pass", "block", "reject", "match")
_PORTED = ("tcp", "udp", "tcp/udp")
_ICMP6_NAMES = {number: name for name, number in reversed(list(ICMP6_TYPES.items()))}
_DYNAMIC_ZONES = {"openvpn": "OpenVPN", "enc0": "IPsec", "wireguard": "WireGuard", "pppoe": "PPPoE", "l2tp": "L2TP"}
_UNREAD_TYPES = {
    "url": "a list on a web server", "urltable": "a list on a web server", "urljson": "a list on a web server",
    "geoip": "the countries of a GeoIP database", "asn": "the networks of autonomous systems",
    "mac": "the addresses of MAC addresses the firewall sees", "dynipv6host": "a suffix of the prefix a provider delegates",
    "authgroup": "the clients of a VPN that logged in", "external": "addresses other software puts in it",
    "internal": "addresses OPNsense fills in itself",
}  # fmt: skip
# "Block private networks" per series (filter.lib.inc).
_PRIVATE: Dict[Tuple[int, ...], List[str]] = {
    (1, 0, 4): ["10.0.0.0/8", "127.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                "fc00::/7", "fe80::/10", "::/128"],  # 24.7 to 25.7, which the file does not tell apart: what any of them blocks
    (1, 0, 5): ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
                "fd00::/8", "fe80::/10", "::/128"],
    (1, 0, 6): ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fd00::/8", "fe80::/10"],
}  # fmt: skip
_EMPTY_TABLE = "is disabled, an empty table that matches nothing"
_SERIES: Dict[Tuple[int, ...], str] = {(1, 0, 4): "24.7 to 25.7", (1, 0, 5): "26.1", (1, 0, 6): "26.7"}
# Rule fields the model has no place for that narrow what a rule matches.
_MVC_NARROWING = {"tos": "the type of service (tos)", "prio": "the priority (prio)", "os": "the operating system (os)",
                  "tagged": "a mark set by another rule (tagged)", "tcpflags1": "TCP flags (tcpflags)",
                  "tcpflags2": "TCP flags (tcpflags)", "max-pkt-rate-number": "a rate of packets (max-pkt-rate)"}  # fmt: skip
_LEGACY_NARROWING = {"tos": "the type of service (tos)", "prio": "the priority (prio)"}
_MVC_HANDLING = ("gateway", "replyto", "tag", "set-prio", "set-prio-low", "divert-to", "shaper1", "shaper2", "overload",
                 "max", "max-src-nodes", "max-src-conn", "max-src-states", "statetimeout", "allowopts", "disablereplyto")  # fmt: skip


def looks_like_opnsense(data: bytes) -> bool:
    head = data[:8192].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    head = re.sub(rb"<\?.*?\?>|<!--.*?-->", b"", head, flags=re.S).lstrip()
    return head.startswith((b"<opnsense>", b"<opnsense "))


def parse(data: bytes, report: Report, interface_addresses: Sequence[str] = ()) -> Policy:
    root = xmlread.fromstring(data, "the configuration files of OPNsense")
    if not isinstance(root.tag, str) or root.tag != "opnsense":
        raise ParseError(f"not an OPNsense configuration: the first element is <{str(root.tag)[:40]}>, not <opnsense>")
    model = root.find("OPNsense/Firewall/Filter")
    text = model.get("version", "") if model is not None else ""
    if not re.fullmatch(r"\d+\.\d+\.\d+", text):
        raise ParseError(
            "the configuration has no version of the firewall model (OPNsense/Firewall/Filter version): it was written "
            "by OPNsense before 24.7, or is not a whole configuration. FWShift reads 24.7 and later"
        )
    version = tuple(int(part) for part in text.split("."))
    if version < (1, 0, 4):
        raise ParseError(f"the configuration was written by OPNsense before 24.7 (firewall model {text}); FWShift reads 24.7 and later")
    before = (len(report.notes), {key: len(item.findings) for key, item in report.items.items()})
    norm = _Normalizer(root, version)
    norm.run()
    policy = _Reader(root, report, interface_addresses, norm).build()
    _rebrand(policy, report, before)
    return policy


def _rebrand(p: Policy, report: Report, before: Tuple[int, Dict[Tuple[str, str], int]]) -> None:
    """The pfSense reader speaks of pfSense; what it says holds for OPNsense, which writes pf the same way."""
    count, items = before
    for finding in report.notes[count:]:
        finding.message = finding.message.replace("pfSense", "OPNsense")
    for key, item in report.items.items():
        for finding in item.findings[items.get(key, 0) :]:
            finding.message = finding.message.replace("pfSense", "OPNsense")
    for thing in list(p.rules) + list(p.nat_rules):  # (the reader gives them their descriptions; aliases have their own)
        thing.description = thing.description.replace("pfSense", "OPNsense")


def _empty(value: Optional[str]) -> bool:
    """PHP's empty() for the text of an element: nothing, or "0"."""
    return (value or "").strip() in ("", "0")


def _bool(node: Optional[ET.Element], tag: str, default: bool) -> bool:
    """A BooleanField of the newer models: 1 is true, 0 and nothing are false; absent, its default."""
    found = node.find(tag) if node is not None else None
    return default if found is None else (found.text or "").strip() == "1"


def _set(node: ET.Element, tag: str, text: str = "") -> ET.Element:
    found = node.find(tag)
    if found is None:
        found = ET.SubElement(node, tag)
    found.text = text
    return found


def _drop(node: ET.Element, tag: str) -> None:
    for child in node.findall(tag):
        node.remove(child)


class _Normalizer:
    """Brings an OPNsense configuration into the form the pfSense reader reads, and keeps what that form has no place
    for (identities, categories, what a rule matches that the model cannot say) for the reader."""

    def __init__(self, root: ET.Element, version: Tuple[int, ...]) -> None:
        self.root, self.version = root, version
        self.newer = version >= (1, 0, 5)  # 26.1 and later
        self.series = _SERIES.get(version[:3], "after 26.7")
        self.future = version > (1, 0, 6)
        self.categories: Dict[str, str] = {}
        self.uuid: Dict[int, str] = {}
        self.tags: Dict[int, List[str]] = {}
        self.extra: Dict[int, List[str]] = {}
        self.handling: Dict[int, Dict[str, str]] = {}
        self.received: Dict[int, Tuple[List[str], bool]] = {}
        self.snat: List[ET.Element] = []
        self.one_to_one: List[Tuple[ET.Element, str]] = []
        self.npt = 0
        self.dead: List[str] = []
        self.ambiguous: List[str] = []
        self.not_loaded: List[str] = []
        self.empty: List[str] = []  # rules that match nothing in OPNsense
        self.dynamic: Dict[str, str] = {}  # dynamic interfaces (tunnels) -> zone
        self.dynamic_groups: List[str] = []  # those of them that are groups of the system (openvpn, wireguard)
        self.group_names: Set[str] = set()
        self.group_sequence: Dict[str, int] = {}
        self.familyless: Set[int] = set()  # rules of the old kind without ipprotocol
        self.odd: List[str] = []  # disabled rules of a type OPNsense does not have
        self.forwards = 0  # port forwards that register a rule of their own

    # -- the pieces ---------------------------------------------------------------------------------

    def run(self) -> None:
        root = self.root
        for category in root.findall("OPNsense/Firewall/Category/categories/category"):
            name = (category.findtext("name") or "").strip()
            if category.get("uuid") and name:
                self.categories[category.get("uuid", "")] = name
        _drop(root, "version")  # (the pfSense reader takes it for a version of pfSense)
        groups = root.find("ifgroups")
        if groups is not None:
            entries = groups.findall("ifgroupentry")
            for entry in entries:
                groups.remove(entry)
                members = entry.find("members")
                if members is not None:
                    members.text = " ".join(m.strip() for m in (members.text or "").split(","))
            entries.sort(key=lambda e: self._number(e.findtext("sequence"), 0))
            groups.extend(entries)
            self.group_names = {(e.findtext("ifname") or "").strip() for e in entries}
            self.group_sequence = {(e.findtext("ifname") or "").strip(): self._number(e.findtext("sequence"), 0) for e in entries}
        self._interfaces()
        self._system()
        legacy = root.find("aliases")
        if legacy is not None and len(legacy):
            self.dead.append("<aliases> (aliases of the old kind, which OPNsense migrated and no longer reads)")
        nat = root.find("nat")
        registered = self._nat(nat) if nat is not None else []
        self._filter(registered)
        for element in root.iter():
            if element.text and element.text.strip():
                element.text = html.escape(element.text, quote=False)  # (the pfSense reader decodes text once more)
        for element in self.snat + [node for node, _ in self.one_to_one]:
            for child in element.iter():
                if child.text and child.text.strip():
                    child.text = html.escape(child.text, quote=False)

    @staticmethod
    def _number(text: Optional[str], default: int) -> int:
        try:
            return int((text or "").strip())
        except ValueError:
            return default

    def _interfaces(self) -> None:
        section = self.root.find("interfaces")
        for node in list(section) if section is not None else []:
            key = str(node.tag)
            if (node.findtext("gateway") or "").strip().lower() == "none":
                _drop(node, "gateway")
            for flag in ("blockpriv", "blockbogons"):
                found = node.find(flag)
                if found is None or not _empty(found.text):
                    continue
                if self.newer:
                    node.remove(found)  # 25.7 and later: empty() is off
                else:
                    self.ambiguous.append(f"{flag} of {key}")  # 24.7 and 25.1 read it as set, 25.7 as not
            dynamic = not _empty(node.findtext("internal_dynamic")) or not _empty(node.findtext("virtual"))
            if dynamic and key not in self.group_names and not KEY.fullmatch(key) and node.find("enable") is not None:
                self.dynamic[key] = _DYNAMIC_ZONES.get(key, re.sub(r"[^A-Za-z0-9_]", "", node.findtext("descr") or "") or key.upper())
                if (node.findtext("type") or "").strip() == "group":
                    self.dynamic_groups.append(key)

    def _system(self) -> None:
        system = self.root.find("system")
        if system is None:
            return
        for flag in ("disablenatreflection", "enablebinatreflection", "disablefilter"):
            found = system.find(flag)
            if found is not None and _empty(found.text):
                system.remove(found)

    def _network_word(self, word: str) -> bool:
        return (word == "(self)" or KEY.fullmatch(word) is not None or (word.endswith("ip") and KEY.fullmatch(word[:-2]) is not None)
                or word in self.group_names or word in self.dynamic or word in SYSTEM_GROUPS or word in ("pptp",))  # fmt: skip

    def _side(self, side: Optional[ET.Element], newer_not: bool) -> None:
        """A source or destination: ``not`` as the series reads it, and ``network`` or ``address`` by what it holds; one that
        names nothing is any."""
        if side is None:
            return
        if not any((side.findtext(tag) or "").strip() for tag in ("network", "address")) and side.find("any") is None:
            _drop(side, "network")
            _drop(side, "address")
            ET.SubElement(side, "any")
        found = side.find("not")
        if found is not None and newer_not and _empty(found.text):
            side.remove(found)
        network = (side.findtext("network") or "").strip()
        address = (side.findtext("address") or "").strip()
        if side.find("network") is not None and network in ("", "any") and not address:
            _drop(side, "network")
            _drop(side, "address")
            if side.find("any") is None:
                ET.SubElement(side, "any")
            return
        if network and not self._network_word(network):
            _drop(side, "network")
            _drop(side, "address")
            _set(side, "address", network)
        elif address and self._network_word(address) and not network:
            _drop(side, "address")
            _set(side, "network", address)

    def _record(self, node: ET.Element, source: ET.Element, extra: List[str], tags: List[str],
                handling: Optional[Dict[str, str]] = None) -> None:  # fmt: skip
        if source.get("uuid"):
            self.uuid[id(node)] = source.get("uuid", "")
        if extra:
            self.extra[id(node)] = list(extra)
        if tags:
            self.tags[id(node)] = list(tags)
        if handling:
            self.handling[id(node)] = dict(handling)

    # -- filter rules ---------------------------------------------------------------------------------

    def _icmp(self, node: ET.Element, protocol: str, families: str, label: str) -> Optional[str]:
        """ICMP of the right IP version: the families left, or None when the rule matches nothing."""
        if protocol == "icmp":
            if families == "inet6":
                self.empty.append(f"'{_short(label)}' (ICMP in a rule for IPv6 only)")
                return None
            return "inet"
        if protocol == "ipv6-icmp":
            if families == "inet":
                self.empty.append(f"'{_short(label)}' (ICMPv6 in a rule for IPv4 only)")
                return None
            _set(node, "protocol", "icmp")  # (the pfSense reader takes icmp in an IPv6 rule for ICMPv6)
            return "inet6"
        return families

    def _legacy(self, rule: ET.Element) -> List[Tuple[ET.Element, str, str]]:
        """A rule of <filter>: (the rule as the pfSense reader reads it, tier, interface), two for a quick rule of a tab for
        both directions; none when it matches nothing."""
        label = (rule.findtext("descr") or "").strip() or "rule"
        kind = (rule.findtext("type") or "").strip()
        if kind not in ("",) + _RULE_TYPES and not _empty(rule.findtext("disabled")):
            self.odd.append(f"'{_short(label)}' (type '{_short(kind, 20)}')")  # disabled: OPNsense comments it out
            return []
        if kind not in ("",) + _RULE_TYPES:
            raise ParseError(
                f"rule '{_short(label)}' has type '{_short(kind, 20)}': OPNsense writes it into the ruleset as it is, pf "
                "refuses the whole ruleset, and the firewall keeps the one it had. The file does not say what runs"
            )
        _set(rule, "type", kind or "pass")
        for flag in ("disabled", "log", "disablereplyto"):
            found = rule.find(flag)
            if found is not None and _empty(found.text):
                rule.remove(found)
        extra: List[str] = []
        interfacenot = rule.find("interfacenot")
        if interfacenot is not None:
            if not _empty(interfacenot.text):
                extra.append("it is for every interface but the one it names (interfacenot)")
            rule.remove(interfacenot)
        for key, text in _LEGACY_NARROWING.items():
            if not _empty(rule.findtext(key)):
                extra.append(f"it matches {text} '{_short((rule.findtext(key) or '').strip(), 30)}'")
        floating = rule.find("floating") is not None
        interface = (rule.findtext("interface") or "").strip()
        tier = "floating" if floating else ("group" if interface in self.group_names else "interface")
        if floating and "any" in [k.strip() for k in interface.split(",")]:
            self.not_loaded.append(f"'{_short(label)}' (interface 'any', which OPNsense does not have)")
            return []
        direction = (rule.findtext("direction") or "").strip() or "in"
        quick_node = rule.find("quick")
        quick = (not floating) if quick_node is None else not _empty(quick_node.text)
        _drop(rule, "quick")
        both = not floating and direction == "any" and quick
        if both:
            direction = "in"  # and a copy for what leaves, below: the rule keeps its place among the rules of its tier
        if not floating and (direction != "in" or not quick):
            floating = True  # pf has no tabs: a rule of an interface that is not quick, or is for what leaves, is a floating rule
        if floating:
            _set(rule, "floating", "yes")
            _set(rule, "direction", direction)
            if quick:
                _set(rule, "quick", "yes")
        families = (rule.findtext("ipprotocol") or "").strip() or "inet46"
        protocol = (rule.findtext("protocol") or "").strip().lower()
        if protocol:
            _set(rule, "protocol", protocol)
        left = self._icmp(rule, protocol, families, label)
        if left is None:
            return []
        if protocol == "ipv6-icmp":
            _drop(rule, "icmptype")  # (that is the type of ICMP for IPv4)
            if rule.findtext("icmp6-type"):
                _set(rule, "icmptype", (rule.findtext("icmp6-type") or "").strip())
        if not (rule.findtext("ipprotocol") or "").strip():
            self.familyless.add(id(rule))  # no family at all: one rule, which OPNsense does not split by IP version
        _set(rule, "ipprotocol", left)
        for name in ("source", "destination"):
            side = rule.find(name)
            if side is None:
                side = ET.SubElement(rule, name)  # (one that is not there is any)
            self._side(side, self.newer)
            if side is not None and protocol not in _PORTED:
                _drop(side, "port")  # OPNsense writes ports only for TCP and UDP
        tags = [t.strip() for t in (rule.findtext("category") or "").split(",") if t.strip()]
        self._record(rule, rule, extra, tags)
        out = [(rule, tier, interface)]
        if both:
            out.append((self._leaving_copy(rule, rule, extra, tags), tier, interface))
        return out

    def _leaving_copy(self, node: ET.Element, source: ET.Element, extra: List[str], tags: List[str],
                      handling: Optional[Dict[str, str]] = None) -> ET.Element:  # fmt: skip
        """The half for what leaves of a quick rule of a tab for both directions."""
        copied = copy.deepcopy(node)
        _set(copied, "floating", "yes")
        _set(copied, "direction", "out")
        _set(copied, "quick", "yes")
        _set(copied, "descr", ((node.findtext("descr") or "").strip() or "rule") + " (leaving)")
        self._record(copied, source, extra, tags, handling)
        if id(node) in self.familyless:
            self.familyless.add(id(copied))
        return copied

    def _mvc(self, rule: ET.Element) -> List[Tuple[ET.Element, str, str]]:
        """A rule of OPNsense/Firewall/Filter/rules, as rules of <filter>: one per source and destination it lists."""

        def text(name: str) -> str:
            return (rule.findtext(name) or "").strip()

        def flag(name: str, default: bool) -> bool:
            return _bool(rule, name, default)

        label = text("description") or "rule"
        action = text("action") or "pass"
        if action not in ("pass", "block", "reject") and not flag("enabled", True):
            self.odd.append(f"'{_short(label)}' (action '{_short(action, 20)}')")
            return []
        if action not in ("pass", "block", "reject"):
            raise ParseError(f"rule '{_short(label)}' has action '{_short(action, 20)}', which OPNsense does not have")
        interfaces = [k.strip() for k in text("interface").split(",") if k.strip()]
        interfacenot = flag("interfacenot", False)
        floating = len(interfaces) != 1 or interfacenot
        grouped = not floating and (interfaces[0] in self.group_names or interfaces[0] in self.dynamic_groups)
        tier = "floating" if floating else ("group" if grouped else "interface")
        direction = text("direction") or "in"
        quick = flag("quick", True)
        families = text("ipprotocol") or "inet"
        protocol = text("protocol").lower()
        protocol = "" if protocol in ("", "any") else protocol
        extra: List[str] = []
        if interfacenot:
            extra.append("it is for every interface but the one it names (interfacenot)")
        for key, what in _MVC_NARROWING.items():
            if text(key):
                extra.append(f"it matches {what} '{_short(text(key), 30)}'")
        handling = {key: text(key) for key in _MVC_HANDLING if text(key) and text(key) != "0"}
        state = text("statetype")
        if state and state != "keep":
            handling["statetype"] = state if state == "none" else f"{state} state"
        tags = [self.categories.get(u.strip(), u.strip()) for u in text("categories").split(",") if u.strip()]
        sources = [s.strip() for s in (text("source_net") or "any").split(",") if s.strip()]
        destinations = [d.strip() for d in (text("destination_net") or "any").split(",") if d.strip()]
        out: List[Tuple[ET.Element, str, str]] = []
        for source in sources:
            for destination in destinations:
                node = ET.Element("rule")
                _set(node, "type", action)
                _set(node, "interface", ",".join(interfaces))
                both = not floating and direction == "any" and quick
                if floating or (direction != "in" and not both) or not quick:
                    _set(node, "floating", "yes")
                    _set(node, "direction", direction)
                    if quick:
                        _set(node, "quick", "yes")
                if protocol:
                    _set(node, "protocol", protocol)
                left = self._icmp(node, protocol, families, label)
                if left is None:
                    return []
                _set(node, "ipprotocol", left)
                if protocol == "icmp" and text("icmptype"):
                    _set(node, "icmptype", text("icmptype"))
                if protocol == "ipv6-icmp" and text("icmp6type"):
                    names = [_ICMP6_NAMES.get(int(n), f"type{n}") if n.strip().isdigit() else n.strip() for n in text("icmp6type").split(",")]
                    _set(node, "icmptype", ",".join(names))
                for side_name, value, negated, port in (("source", source, flag("source_not", False), text("source_port")),
                                                        ("destination", destination, flag("destination_not", False), text("destination_port"))):  # fmt: skip
                    side = ET.SubElement(node, side_name)
                    if value == "any":
                        ET.SubElement(side, "any")
                    else:
                        _set(side, "network" if self._network_word(value) else "address", value)
                    if negated:
                        ET.SubElement(side, "not")
                    if port and protocol in _PORTED:
                        _set(side, "port", port)
                if not flag("enabled", True):
                    _set(node, "disabled", "1")
                if flag("log", False):
                    _set(node, "log", "1")
                if text("sched"):
                    _set(node, "sched", text("sched"))
                _set(node, "descr", label if text("description") else "")
                received = text("received-on")
                if received and direction == "out":
                    self.received[id(node)] = ([k.strip() for k in received.split(",") if k.strip()], flag("received-on-not", False))
                self._record(node, rule, extra, tags, handling)
                key = interfaces[0] if interfaces and tier == "group" else ""
                out.append((node, tier, key))
                if both:
                    out.append((self._leaving_copy(node, rule, extra, tags, handling), tier, key))
        return out

    def _filter(self, registered: List[ET.Element]) -> None:
        section = self.root.find("filter")
        if section is None:
            section = ET.SubElement(self.root, "filter")
        legacy = [node for node in section.findall("rule")]
        for node in legacy:
            section.remove(node)
        model = self.root.find("OPNsense/Firewall/Filter/rules")
        newer_kind = sorted(model.findall("rule") if model is not None else [],
                            key=lambda r: self._number(r.findtext("sequence"), 1))  # fmt: skip
        mvc = [item for node in newer_kind for item in self._mvc(node)]
        old = [item for node in legacy for item in self._legacy(node)]
        order: List[ET.Element] = [node for node, tier, _ in mvc + old if tier == "floating"]
        # Group rules: by the sequence of their group (300000 + sequence; the groups of the system, OpenVPN and WireGuard,
        # have 0), and of one value the newer kind first, by its own sequence, then the old kind in the order of the file.
        grouped = [((self.group_sequence.get(key, 0), 0, n), node) for n, (node, tier, key) in enumerate(mvc) if tier == "group"]
        grouped += [((self.group_sequence.get(key, 0), 1, n), node) for n, (node, tier, key) in enumerate(old) if tier == "group"]
        order += [node for _, node in sorted(grouped, key=lambda item: item[0])]
        order += [node for node, tier, _ in mvc if tier == "interface"]
        order += [node for node, tier, _ in old if tier == "interface"]
        order += registered
        section.extend(order)

    # -- NAT ----------------------------------------------------------------------------------------

    def _nat(self, nat: ET.Element) -> List[ET.Element]:
        """Bring the NAT rules into the pfSense reader's form; returns the filter rules port forwards register."""
        registered: List[ET.Element] = []
        forwards: List[ET.Element] = []
        copies: Set[int] = set()
        for node in nat.findall("rule"):
            nat.remove(node)
            keys = [k.strip() for k in (node.findtext("interface") or "").split(",") if k.strip()]
            if len(keys) < 2:
                forwards.append(node)
                continue
            for number, key in enumerate(keys):  # a port forward on several interfaces: one for each, as pf has them
                copied = copy.deepcopy(node)
                _set(copied, "interface", key)
                forwards.append(copied)
                if number:
                    copies.add(id(copied))
        for node in forwards:
            for flag in ("disabled", "nordr", "log"):
                found = node.find(flag)
                if found is not None and _empty(found.text):
                    node.remove(found)
            for side in ("source", "destination"):
                if node.find(side) is None:
                    ET.SubElement(node, side)
                self._side(node.find(side), self.newer)
            if (node.findtext("ipprotocol") or "").strip() == "":
                _set(node, "ipprotocol", "inet")
            mode = (node.findtext("pass") or "").strip()
            _drop(node, "pass")
            if mode == "pass":
                _set(node, "associated-rule-id", "pass")
            elif mode == "rule" and node.find("disabled") is None and node.find("nordr") is None:
                registered += self._registered(node)
                self.forwards += id(node) not in copies
            elif self.newer and (node.findtext("associated-rule-id") or "").strip() not in ("", "pass"):
                _drop(node, "associated-rule-id")
        if self.newer:
            forwards.sort(key=lambda r: self._number(r.findtext("sequence"), 1))
        nat.extend(forwards)
        outbound = nat.find("outbound")
        for node in outbound.findall("rule") if outbound is not None else []:
            for flag in ("disabled", "nonat", "staticnatport", "log"):
                found = node.find(flag)
                if found is not None and _empty(found.text):
                    node.remove(found)
            self._side(node.find("destination"), self.newer)
            source = node.find("source")
            negated = source.find("not") if source is not None else None
            if negated is not None and (not self.newer or not _empty(negated.text)):
                self.extra[id(node)] = ["a negated source in a NAT rule"]
        for old in ("onetoone", "npt"):
            stale = nat.findall(old)
            if stale:
                self.dead.append(f"<nat><{old}> ({len(stale)}: rules of the old kind, which OPNsense migrated and no longer reads)")
                for node in stale:
                    nat.remove(node)
        model = self.root.find("OPNsense/Firewall/Filter")
        if model is not None:
            snat = sorted(model.findall("snatrules/rule"), key=lambda r: self._number(r.findtext("sequence"), 1))
            self.snat = [self._snat(node) for node in snat]
            binat = sorted(model.findall("onetoone/rule"), key=lambda r: self._number(r.findtext("sequence"), 1))
            self.one_to_one = [self._binat(node) for node in binat]
            self.npt = len(model.findall("npt/rule"))
        return registered

    def _registered(self, forward: ET.Element) -> List[ET.Element]:
        """The rule a port forward registers ("Register rule", 26.1 and later): pass in on its interface, to its target."""
        out: List[ET.Element] = []
        target = (forward.findtext("target") or "").strip()
        destination = forward.find("destination")
        port = (destination.findtext("port") or "").strip() if destination is not None else ""
        local = (forward.findtext("local-port") or "").strip()
        if local and port:
            first, _, last = port.partition("-")
            if local.isdigit() and first.isdigit() and last.isdigit():
                local = f"{local}-{int(local) + int(last) - int(first)}"
        for key in [k.strip() for k in (forward.findtext("interface") or "wan").split(",") if k.strip()]:
            node = ET.Element("rule")
            _set(node, "type", "pass")
            _set(node, "interface", key)
            _set(node, "ipprotocol", (forward.findtext("ipprotocol") or "inet").strip())
            protocol = (forward.findtext("protocol") or "").strip().lower()
            if protocol and protocol != "any":
                _set(node, "protocol", protocol)
            original = forward.find("source")
            source = copy.deepcopy(original) if original is not None else ET.Element("source")
            if protocol not in _PORTED:
                _drop(source, "port")
            node.append(source)
            side = ET.SubElement(node, "destination")
            _set(side, "address", target)
            if (local or port) and protocol in _PORTED:
                _set(side, "port", local or port)
            descr = (forward.findtext("descr") or "").strip() or "port forward"
            _set(node, "descr", f"{descr} (rule the port forward registers)")
            self._record(node, forward, [], [t.strip() for t in (forward.findtext("category") or "").split(",") if t.strip()])
            out.append(node)
        return out

    def _snat(self, rule: ET.Element) -> ET.Element:
        """A rule of OPNsense/Firewall/Filter/snatrules as an outbound NAT rule of the pfSense reader."""

        def text(name: str) -> str:
            return (rule.findtext(name) or "").strip()

        node = ET.Element("rule")
        if not _bool(rule, "enabled", True):
            _set(node, "disabled", "1")
        if text("nonat") == "1":
            _set(node, "nonat", "1")
        _set(node, "interface", text("interface"))
        _set(node, "ipprotocol", text("ipprotocol") or "inet")
        protocol = text("protocol").lower()
        if protocol and protocol != "any":
            _set(node, "protocol", protocol)
        source = ET.SubElement(node, "source")
        _set(source, "network", text("source_net") or "any")
        destination = ET.SubElement(node, "destination")
        if (text("destination_net") or "any") == "any":
            ET.SubElement(destination, "any")
        else:
            _set(destination, "network", text("destination_net"))
        if text("destination_not") == "1":
            ET.SubElement(destination, "not")
        if text("source_port"):
            _set(node, "sourceport", text("source_port"))
        if text("destination_port"):
            _set(node, "dstport", text("destination_port"))
        target = text("target")
        if target:
            address, _, bits = target.partition("/")
            _set(node, "target", address)
            if bits:
                _set(node, "target_subnet", bits)
        if text("target_port"):
            _set(node, "natport", text("target_port"))
        if text("staticnatport") == "1":
            _set(node, "staticnatport", "1")
        if text("poolopts"):
            _set(node, "poolopts", text("poolopts"))
        _set(node, "descr", text("description"))
        extra = ["a negated source in a NAT rule"] if text("source_not") == "1" else []
        self._record(node, rule, extra, [])
        return node

    def _binat(self, rule: ET.Element) -> Tuple[ET.Element, str]:
        """A rule of OPNsense/Firewall/Filter/onetoone as a 1:1 rule of the pfSense reader, with its type."""

        def text(name: str) -> str:
            return (rule.findtext(name) or "").strip()

        node = ET.Element("onetoone")
        if not _bool(rule, "enabled", True):
            _set(node, "disabled", "1")
        _set(node, "interface", text("interface") or "wan")
        external = text("external")
        _set(node, "external", external.split("/")[0])
        source = ET.SubElement(node, "source")
        _set(source, "address", text("source_net"))
        if text("source_not") == "1":
            ET.SubElement(source, "not")
        destination = ET.SubElement(node, "destination")
        if (text("destination_net") or "any") == "any":
            ET.SubElement(destination, "any")
        else:
            _set(destination, "address", text("destination_net"))
        if text("destination_not") == "1":
            ET.SubElement(destination, "not")
        _set(node, "ipprotocol", "inet6" if ":" in external else "inet")
        if text("natreflection"):
            _set(node, "natreflection", text("natreflection"))
        _set(node, "descr", text("description"))
        self._record(node, rule, [], [])
        return node, text("type") or "binat"


class _Reader(_pf._Reader):
    def __init__(self, root: ET.Element, report: Report, interface_addresses: Sequence[str], norm: _Normalizer) -> None:
        super().__init__(root, report, interface_addresses)
        self.p.vendor = "opnsense"
        self.norm = norm
        if norm.newer:
            settings = root.find("OPNsense/Interfaces/settings")
            self.ipv6 = settings is None or _empty(html.unescape(settings.findtext("disableipv6") or ""))
        self.not_loaded += norm.not_loaded
        self.received: Dict[str, Tuple[List[str], bool]] = {}
        self.disabled_aliases: List[str] = []
        self.raw_aliases: Dict[str, Tuple[str, List[str], str, bool]] = {}
        self.rule_family = ""  # ipprotocol of the rule being read

    # -- interfaces and aliases -------------------------------------------------------------------

    def _zone(self, key: str) -> Optional[str]:
        interface = self.interfaces.get(key)
        if interface is not None:
            return interface.zone if interface.enabled else None
        return self.norm.dynamic.get(key)

    def _zones_of(self, key: str) -> List[str]:
        found = super()._zones_of(key)
        prefix = {"openvpn": "ovpn", "wireguard": "wg"}.get(key)
        if prefix and found:
            # An assigned tunnel interface is also a member of the group OPNsense keeps for them all.
            found += [i.zone for i in self.interfaces.values() if i.enabled and i.device.startswith(prefix) and i.zone not in found]
        return found

    def _address(self, side: _pf._Side, text: str, family: int) -> None:
        if text in self.raw_aliases and not self.raw_aliases[text][3]:
            if side.negated:
                side.members, side.negated = [ANY_V4 if family == 4 else ANY_V6], False  # not an empty table: everything
            else:
                side.missing = f"alias '{_short(text, 40)}' {_EMPTY_TABLE}"
            return
        super()._address(side, text, family)

    def _network(self, side: _pf._Side, word: str, family: int) -> None:
        super()._network(side, word, family)
        if side.problem:
            return
        if word.endswith("ip") and KEY.fullmatch(word[:-2]) and not side.members and side.negated:
            # "(vtnet0)": an interface without an address of an IP version matches nothing of it, and "not" it everything.
            side.members, side.negated, side.missing = [ANY_V4 if family == 4 else ANY_V6], False, ""
            return
        interface = KEY.fullmatch(word) is not None or word in self.groups or word in self.norm.dynamic
        if family == 6 and interface and self.rule_family in ("inet6", "inet46") and not side.negated:
            # In a rule for IPv6 (inet46 is split in two first), OPNsense adds the link-local network to that of an
            # interface, as a rule of its own. ("not" applies to the network of the interface alone, which leaves the
            # link-local network out anyway.) A rule of the old kind without a family is not split, and gets nothing.
            side.members, side.missing = transform.dedupe(side.members + ["fe80::/10"]), ""

    def _aliases(self) -> None:
        raw: Dict[str, Tuple[str, List[str], str, bool]] = {}
        for alias in _children(self.root.find("OPNsense/Firewall/Alias/aliases"), "alias"):
            name = _text(alias, "name")
            if name:
                found = _child(alias, "content")
                content = [line.strip() for line in _clean(found.text if found is not None else "").splitlines()]
                enabled = _bool(alias, "enabled", True)
                raw[name] = (_text(alias, "type").lower(), [line for line in content if line], _text(alias, "description"), enabled)
        self.raw_aliases = raw
        for name, (kind, entries, _, enabled) in raw.items():
            if kind == "port":
                # A disabled alias of ports is empty: a rule that names it is not loaded, an alias that holds it leaves it out.
                kept = [e for e in entries if not (e in raw and raw[e][0] == "port" and not raw[e][3])]
                self.port_aliases[name] = kept if enabled else []
            elif kind in ("url_ports", "urltable_ports"):
                self.port_aliases[name] = None
            else:
                self.address_aliases[name] = kind
        for interface in self.interfaces.values():
            name = f"__{interface.key}_network"
            if interface.enabled and name not in raw:
                self.address_aliases[name] = "internal"
        for name in list(self.address_aliases):
            self._alias_group(name)

    def _alias_group(self, name: str) -> None:
        if name in self.p.address_groups:
            return
        kind, entries, description, enabled = self.raw_aliases.get(name, ("internal", [], "", True))
        group = AddressGroup(name, description=description)
        self.p.address_groups[name] = group
        if name.startswith("__") and name.endswith("_network") and name not in self.raw_aliases:
            key = name[2:-8]
            group.description = f"the networks of interface {key}"
            group.builtin = "opnsense"
            interface = self.interfaces[key]
            for family in (4, 6):
                if interface.kind(family) and interface.net(family) is None:
                    group.unsupported = (f"the IPv{family} network of interface {interface.zone} is not in the configuration "
                                         f"({interface.kind(family)}); give it with --interface-address")
                group.members += _pf._Reader._networks(self, interface, family)  # (the link-local network is not in it)
            return
        if kind in _UNREAD_TYPES:
            group.unsupported = f"an alias of type '{kind}' ({_UNREAD_TYPES[kind]}), whose addresses are not in the configuration"
            return
        if kind not in ("host", "network", "networkgroup"):
            group.unsupported = f"an alias of type '{_short(kind, 30)}', which FWShift does not know"
            return
        if not enabled:
            self.disabled_aliases.append(name)
            group.unsupported = "the alias is disabled: OPNsense keeps it as an empty table, and a rule that names it matches nothing"
            return
        entries_seen, hosts, problem = self._flat(name, ())
        if problem:
            group.unsupported = problem
            return
        if any(negated for _, negated in entries_seen):
            if hosts:
                group.unsupported = "it holds host names and leaves addresses out ('!'), which cannot be worked out"
                return
            group.members = [interval_text(i) for i in self._effective(entries_seen)]
            group.description = (description + " " if description else "") + "(with what it leaves out taken away)"
            return
        for entry in entries:
            if entry in self.address_aliases:
                self._alias_group(entry)
                if self.raw_aliases.get(entry, ("", [], "", True))[3]:
                    group.members.append(entry)  # (a disabled alias inside another one adds nothing to it)
                continue
            interval = parse_literal(entry)
            if interval is not None:
                group.members.append(interval_text(interval))
                continue
            group.members.append(self._host(entry))
        group.members = transform.dedupe(group.members)

    def _host(self, entry: str) -> str:
        host = entry.rstrip(".").lower()
        name = host if host not in self.p.address_groups and host not in self.port_aliases else f"host {host}"
        self.p.addresses.setdefault(name, Address(name, AddressKind.FQDN, host))
        return name

    @staticmethod
    def _cidrs(intervals: List[Interval]) -> List[Interval]:
        """Intervals as the networks pf puts into a table for them (it has no ranges)."""
        out: List[Interval] = []
        for version, first, last in intervals:
            for network in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)):
                out.append((version, int(network.network_address), int(network.broadcast_address)))
        return out

    def _flat(self, name: str, stack: Tuple[str, ...]) -> Tuple[List[Tuple[Interval, bool]], List[str], str]:
        """(entries with whether they leave out, host names, problem) of an alias and of every alias it holds."""
        if name in stack:
            return [], [], ""
        if len(stack) > transform.MAX_NESTING:
            return [], [], f"aliases nested more than {transform.MAX_NESTING} deep"
        kind, entries, _, enabled = self.raw_aliases.get(name, ("internal", [], "", True))
        out: List[Tuple[Interval, bool]] = []
        hosts: List[str] = []
        if name.startswith("__") and name.endswith("_network") and name not in self.raw_aliases:
            group = self.p.address_groups.get(name)
            for member in group.members if group is not None else []:
                found, complete = transform.known_intervals(self.p, member)
                if not complete:
                    return [], [], f"the networks of interface {name[2:-8]} are not in the configuration"
                out += [(i, False) for i in found]
            return out, hosts, ""
        if not enabled:
            return [], [], ""
        if kind in _UNREAD_TYPES or kind not in ("host", "network", "networkgroup"):
            return [], [], f"it holds alias '{_short(name, 30)}' of type '{_short(kind, 30)}', whose addresses are not in the configuration"
        for entry in entries:
            negated = entry.startswith("!")
            value = entry[1:].strip() if negated else entry
            if value in self.address_aliases:
                if negated:
                    return [], [], f"it leaves out alias '{_short(value, 30)}', which cannot be worked out"
                self._alias_group(value)
                inner, more, problem = self._flat(value, stack + (name,))
                if problem:
                    return [], [], problem
                out += inner
                hosts += more
                continue
            if value in self.port_aliases:
                return [], [], f"its entry '{_short(entry, 40)}' is an alias of ports"
            interval = parse_literal(value)
            if interval is not None:
                out += [(i, negated) for i in self._cidrs([interval])]
                continue
            if kind == "host" and _pf._HOST_NAME.fullmatch(value) and not negated:
                hosts.append(self._host(value))
                continue
            return [], [], f"its entry '{_short(entry, 40)}' is neither an address, a network nor an alias FWShift can read"
        return out, hosts, ""

    @staticmethod
    def _effective(entries: List[Tuple[Interval, bool]]) -> List[Interval]:
        """What a table of pf holds: an address is in it when the most specific entry that holds it does not leave it
        out. Entries from the widest to the narrowest; of two alike, the one that leaves out last."""

        def width(interval: Interval) -> int:
            return interval[2] - interval[1]

        result: List[Interval] = []
        for interval, negated in sorted(entries, key=lambda item: (-width(item[0]), item[1])):
            result = subtract(result, [interval]) if negated else normalize(result + [interval])
        return result

    # -- rules ----------------------------------------------------------------------------------

    def _rule_node(self, node: ET.Element, label: str) -> List[Rule]:
        self.rule_family = "" if id(node) in self.norm.familyless else _text(node, "ipprotocol")
        rules = super()._rule_node(node, label)
        self.rule_family = ""
        key = id(node)
        for rule in rules:
            if key in self.norm.uuid:
                rule.source_ids["opnsense.uuid"] = self.norm.uuid[key]
            rule.tags = transform.dedupe(rule.tags + self.norm.tags.get(key, []))
            rule.unsupported = transform.dedupe(rule.unsupported + self.norm.extra.get(key, []))
            rule.handling.update(self.norm.handling.get(key, {}))
            if rule.description == "a pfSense rule without a description":
                rule.description = "an OPNsense rule without a description"
            if key in self.norm.received:
                self.received[rule.origin] = self.norm.received[key]
        return rules

    def _leaving(self, items: List[_pf._Read]) -> List[Rule]:
        out = super()._leaving(items)
        for rule in out:
            found = self.received.get(rule.origin)
            if found is None:
                continue
            keys, negated = found
            if negated:
                rule.unsupported.append("it is for traffic that did not arrive on the interfaces it names (received-on, negated)")
                continue
            zones = transform.dedupe([zone for key in keys for zone in self._zones_of(key)])
            if zones:
                rule.src_zones = zones  # (received-on: the interface the traffic arrived on)
            else:
                rule.unsupported.append("it is for traffic that arrived on an interface OPNsense does not have (received-on)")
        return out

    def _ordered(self, read: List[_pf._Read]) -> List[Rule]:
        incoming = [item for item in read if not item.floating or item.direction in ("in", "any")]
        quick = [item for item in incoming if item.floating and item.quick]
        late = [item for item in incoming if item.floating and not item.quick]
        tabs = [item for item in incoming if not item.floating]  # (the configuration is in the order of the tiers)
        out: List[Rule] = self._leaving([item for item in read if item.floating and item.direction in ("out", "any")])
        out += self._private()
        for item in quick + tabs + list(reversed(late)):
            for rule in item.rules:
                rule.src_zones = list(item.zones)
                out.append(rule)
        if late:
            self.report.note(
                Severity.INFO, "FLOATING_LAST_MATCH",
                f"{len(late)} rule{'s are' if len(late) != 1 else ' is'} not 'quick' (floating rules, and rules of an "
                "interface with 'quick' off): such a rule decides only where no quick rule matched, and of several the "
                f"last one. In the converted policy {'they stand' if len(late) != 1 else 'it stands'} behind the quick "
                "rules, the last one first: " + ", ".join(f"'{_short(rule.name, 40)}'" for item in reversed(late) for rule in item.rules[:1]),
            )  # fmt: skip
        return out

    def _private(self) -> List[Rule]:
        out: List[Rule] = []
        networks = [n for n in _PRIVATE.get(self.norm.version[:3], _PRIVATE[(1, 0, 6)]) if self.ipv6 or ":" not in n]
        for interface in self.interfaces.values():
            if not (interface.enabled and interface.blockpriv):
                continue
            name = self._unique(f"Block private networks from {interface.zone}", self.rule_names)
            rule = Rule(name=name, origin=name, src_zones=[interface.zone], sources=list(networks), action=Action.DROP)
            rule.log_end = False
            rule.description = "what 'Block private networks' of the interface does on OPNsense"
            self.report.add(
                "rule", name, Severity.INFO, "AUTOMATIC_RULE",
                f"interface {interface.zone} has 'Block private networks' set: OPNsense drops what arrives there from those "
                f"networks (the list of {self.norm.series}) before any rule of the configuration. This rule stands for that",
            )  # fmt: skip
            out.append(rule)
        return out

    # -- NAT ------------------------------------------------------------------------------------

    def _nat(self) -> List[NatRule]:
        nat = _child(self.root, "nat")
        forwards = [rule for rule in (self._forward(node, n) for n, node in enumerate(_children(nat, "rule"), 1)) if rule]
        one_to_one: List[NatRule] = []
        one_way: List[NatRule] = []
        for number, (node, kind) in enumerate(self.norm.one_to_one, 1):
            halves = self._one_to_one(node, number)
            if kind == "nat":
                # One way: a "nat" rule for the source of what leaves only, after the others of its kind (priority 500).
                one_way += halves[1:] if len(halves) == 2 else halves
            else:
                one_to_one += halves
        outbound = _child(nat, "outbound")
        mode = _text(outbound, "mode") or "automatic"
        mvc: List[NatRule] = []
        if self.norm.snat:
            rendered = mode in ("advanced", "hybrid") or self.norm.version[:3] <= (1, 0, 5)
            if mode not in ("advanced", "hybrid") and self.norm.version[:3] == (1, 0, 5):
                self.report.note(
                    Severity.REVIEW, "OPNSENSE_SNAT_MODE",
                    f"outbound NAT is in mode '{mode}': OPNsense 26.1 up to 26.1.10 applies the rules of Source NAT in "
                    "every mode, 26.1.11 only in 'hybrid' and 'manual'. The file does not say which release wrote it; "
                    "they were converted as applied",
                )  # fmt: skip
            if rendered:
                for number, node in enumerate(self.norm.snat, 1):
                    rule = self._outbound(node, number)
                    if rule is not None:
                        mvc.append(rule)
        manual: List[NatRule] = []
        if mode in ("advanced", "hybrid"):
            manual = [rule for rule in (self._outbound(node, n) for n, node in enumerate(_children(outbound, "rule"), 1)) if rule]
        automatic = self._automatic() if mode in ("automatic", "hybrid") else []
        if self.norm.npt:
            self.report.note(
                Severity.REVIEW, "NPT_NOT_CONVERTED",
                f"{self.norm.npt} IPv6 prefix translation{'s' if self.norm.npt != 1 else ''} (NPt) of the configuration "
                f"{'are' if self.norm.npt != 1 else 'is'} not converted",
            )  # fmt: skip
        return forwards + one_to_one + mvc + manual + automatic + one_way

    def _translating_zones(self) -> Set[str]:
        zones = super()._translating_zones()
        mode = _text(_child(_child(self.root, "nat"), "outbound"), "mode") or "automatic"
        if mode in ("advanced", "hybrid") or self.norm.version[:3] <= (1, 0, 5):
            zones |= {z for node in self.norm.snat if not _has(node, "disabled") for z in self._zones_of(_text(node, "interface"))}
        zones |= {z for node, _ in self.norm.one_to_one if not _has(node, "disabled") for z in self._zones_of(_text(node, "interface") or "wan")}
        return zones

    def _outbound(self, node: ET.Element, number: int) -> Optional[NatRule]:
        nat = super()._outbound(node, number)
        if nat is None:
            return None
        nat.unsupported += self.norm.extra.get(id(node), [])
        target = _text(node, "target")
        key = _text(node, "interface")
        if nat.source_translation is not None and target.endswith("ip") and KEY.fullmatch(target[:-2]) and target[:-2] != key:
            # The address of another interface than the one the rule is on.
            other = self.interfaces.get(target[:-2])
            if other is None or not other.enabled or other.net4 is None:
                nat.unsupported.append(f"it translates to the address of interface {target[:-2]}, which is not in the configuration")
            else:
                kind = SnatKind.DYNAMIC if _has(node, "staticnatport") else SnatKind.DYNAMIC_PORT
                nat.source_translation = SourceNat(kind, [str(other.net4.ip)])
        if _text(node, "ipprotocol").lower() in ("", "inet"):
            # pf takes the IPv4 addresses of an alias in a rule for IPv4: so does the model.
            for attribute in ("sources", "destinations"):
                views = [self._view(member, 4) for member in getattr(nat, attribute)]
                if all(views):
                    setattr(nat, attribute, transform.dedupe([view for view in views if view]))
        return nat

    def _reflection(self, node: ET.Element, nat: NatRule, interface: _pf._Interface) -> None:
        own = _text(node, "natreflection").lower()
        off = _has(self.system, "disablenatreflection")
        if own == "disable" or (own not in ("purenat", "enable") and off):
            return
        inside = [i.zone for i in self.interfaces.values()
                  if i.enabled and not i.gateway and i.key != interface.key and (i.net4 or i.net6)]  # fmt: skip
        if inside:
            nat.src_zones = transform.dedupe(nat.src_zones + inside)
            self.report.add(
                "nat", nat.origin, Severity.INFO, "NAT_REFLECTION",
                "the port forward has NAT reflection: it also applies to what arrives on " + ", ".join(inside),
            )  # fmt: skip

    def _automatic(self) -> List[NatRule]:
        inside: List[str] = []
        for interface in self.interfaces.values():
            if interface.enabled and not interface.gateway:
                inside += [network for network in self._networks(interface, 4) if network not in inside]
        inside.append("127.0.0.0/8")
        tunnels = (self.root.find("OPNsense/OpenVPN/Instances/Instance") is not None
                   or bool(_children(_child(self.root, "openvpn"), "openvpn-server"))
                   or self.root.find("OPNsense/IPsec") is not None and self.root.find("OPNsense/IPsec/pools") is not None)  # fmt: skip
        out: List[NatRule] = []
        for interface in self.interfaces.values():
            if not (interface.enabled and interface.gateway) or interface.device.startswith("ovpn"):
                continue
            name = self._unique(f"Automatic outbound NAT on {interface.zone}", self.nat_names)
            nat = NatRule(name=name, origin=name, dst_zones=[interface.zone], sources=list(inside), destinations=["0.0.0.0/0"])
            nat.combines = True
            nat.description = "the rule OPNsense makes by itself for this interface (outbound NAT mode automatic or hybrid)"
            address = interface.net4
            nat.source_translation = SourceNat(
                SnatKind.INTERFACE, interface=interface.key, interface_address=str(address.ip) if address is not None else ""
            )
            self.report.add(
                "nat", name, Severity.INFO, "AUTOMATIC_RULE",
                "outbound NAT is automatic: OPNsense translates what leaves by an interface with an IPv4 gateway and comes "
                "from the networks of its other interfaces, or from the firewall itself. This rule stands for that",
            )  # fmt: skip
            if tunnels:
                self.report.add(
                    "nat", name, Severity.APPROX, "NAT_AUTOMATIC_SOURCES",
                    "OPNsense also translates what comes from the tunnel networks of OpenVPN and the pools of IPsec "
                    "clients, which this rule does not hold",
                )  # fmt: skip
            out.append(nat)
        return out

    # -- notes ----------------------------------------------------------------------------------

    def _notes(self) -> None:
        note = self.report.note
        norm = self.norm
        note(Severity.INFO, "OPNSENSE_VERSION",
             f"the configuration was written by OPNsense {norm.series} (firewall model "
             f"{'.'.join(str(n) for n in norm.version)}), and read as that series reads it")  # fmt: skip
        if norm.future:
            note(Severity.REVIEW, "OPNSENSE_VERSION_NEWER",
                 "the firewall model is newer than that of 26.7, the latest series FWShift knows: fields it added are "
                 "not read")  # fmt: skip
        empty = norm.empty + [text for text in self.not_loaded if _EMPTY_TABLE in text]
        self.not_loaded = [text for text in self.not_loaded if _EMPTY_TABLE not in text]
        if self.not_loaded:
            note(
                Severity.REVIEW, "RULE_NOT_LOADED",
                f"OPNsense does not load {len(self.not_loaded)} rule{'s' if len(self.not_loaded) != 1 else ''} of the "
                "configuration, which it cannot resolve; they are not converted: " + "; ".join(self.not_loaded[:20])
                + (f"; and {len(self.not_loaded) - 20} more" if len(self.not_loaded) > 20 else ""),
            )  # fmt: skip
        if empty:
            note(Severity.INFO, "OPNSENSE_RULE_EMPTY",
                 "rules that match nothing on OPNsense (a protocol of the other IP version, a disabled alias) were left out: "
                 + "; ".join(empty[:20]) + (f"; and {len(empty) - 20} more" if len(empty) > 20 else ""))  # fmt: skip
        if norm.dead:
            note(Severity.INFO, "OPNSENSE_OLD_SECTIONS",
                 "parts of the configuration OPNsense no longer reads were left out: " + "; ".join(norm.dead))
        if norm.ambiguous:
            note(Severity.REVIEW, "OPNSENSE_FLAG_UNCLEAR",
                 "empty flags that OPNsense 24.7 and 25.1 read as set and 25.7 as not, in a file that does not say which "
                 "of them wrote it; read as set (it blocks more): " + ", ".join(norm.ambiguous))  # fmt: skip
        if self.disabled_aliases:
            note(Severity.INFO, "OPNSENSE_DISABLED_ALIAS",
                 "disabled aliases are empty tables on OPNsense: rules that name one match nothing (and 'not' one "
                 "everything): " + ", ".join(self.disabled_aliases))  # fmt: skip
        if norm.odd:
            note(Severity.INFO, "OPNSENSE_DISABLED_ODD",
                 "disabled rules of a type OPNsense does not have, which it leaves out of the ruleset, were left out: "
                 + "; ".join(norm.odd[:20]))  # fmt: skip
        if norm.forwards:
            many = norm.forwards != 1
            note(Severity.INFO, "OPNSENSE_REGISTERED_RULE",
                 f"{norm.forwards} port forward{'s register' if many else ' registers'} a rule of "
                 f"{'their' if many else 'its'} own ('Register rule'), which OPNsense puts after every other rule; so "
                 "does the converted policy")  # fmt: skip
        if self.ipv6_dropped:
            note(
                Severity.INFO, "IPV6_NOT_ALLOWED",
                "IPv6 is switched off on this firewall (Interfaces > Settings, or 'Allow IPv6' before 26.1): it drops all "
                f"IPv6 traffic whatever the rules say. {self.ipv6_dropped} rule{'s' if self.ipv6_dropped != 1 else ''} for "
                "IPv6 or for both IP versions " + ("were" if self.ipv6_dropped != 1 else "was") + " read for IPv4 only",
            )  # fmt: skip
        if _has(self.system, "disablefilter"):
            note(Severity.REVIEW, "FILTER_DISABLED",
                 "packet filtering is switched off on this firewall: it routes everything and translates nothing. The "
                 "rules are converted as they stand in the configuration")  # fmt: skip
        bogons = [i.zone for i in self.interfaces.values() if i.enabled and i.blockbogons]
        if bogons:
            note(Severity.REVIEW, "BOGONS_NOT_CONVERTED",
                 "'Block bogon networks' is set on " + ", ".join(bogons) + ": OPNsense drops what arrives there from "
                 "addresses nobody has been given, by a list it downloads, which is not in the configuration")  # fmt: skip
        if _children(_child(self.root, "bridges"), "bridged"):
            note(Severity.REVIEW, "BRIDGE_NOT_CONVERTED",
                 "the firewall bridges interfaces; FWShift read the rules as those of routed interfaces")
        zones = self.root.findall("OPNsense/captiveportal/zones/zone")
        if any(_text(zone, "enabled") == "1" for zone in zones):
            note(Severity.REVIEW, "CAPTIVE_PORTAL",
                 "a captive portal is enabled: on its interfaces only clients that logged in get past the firewall, "
                 "which no rule says and which is not converted")  # fmt: skip
        note(
            Severity.INFO, "OPNSENSE_AUTOMATIC_RULES",
            "OPNsense has rules of its own before those of the configuration, which are not converted: it drops packets "
            "with a source that belongs to another interface (antispoof) and TCP and UDP from or to port 0; it passes "
            "the ICMPv6 messages IPv6 cannot do without (RFC 4890), DHCP, and the web interface on its first interface "
            "(anti-lockout); and it lets out whatever the firewall itself sends. Rules for the firewall itself ('This "
            "Firewall', the address of an interface) are converted as rules for those addresses",
        )
