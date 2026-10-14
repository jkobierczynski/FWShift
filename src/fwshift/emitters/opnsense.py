# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""OPNsense emitter: neutral model -> the areas *Aliases*, *NAT* and *Firewall Rules* of a ``config.xml``.

OPNsense writes the same kind of pf ruleset as pfSense, so what is written is what the pfSense emitter decides, in the
form OPNsense keeps it: the rules of the "Rules [new]" pages (``OPNsense/Firewall/Filter/rules``), aliases of the
newer model, outbound NAT and 1:1 NAT of the newer model, and port forwards in the form of the series written for
(``--target-version``, 24.7 to 26.7; 26.7 when not given).

Where OPNsense reads a file otherwise than pfSense, the writer follows OPNsense: every flag is ``1`` or ``0`` (an
empty element is "off"), protocols are in upper case, alias entries one per line. Identities are uuid5 values made from
what an object is, so that the same input gives the same file.

* A rule with one interface is a rule of that interface, one with several a floating rule: the pfSense emitter writes
  a rule on the tab of the interface traffic arrives on, and floating rules only for what leaves by an interface, which
  are evaluated apart from the others. The sequence numbers keep the order of the model.
* ICMP in a rule for both IP versions is two rules, one for ICMP and one for ICMPv6, as OPNsense has no protocol for
  both. Before 25.1 a rule is for one IP version, and ICMP types cannot be named (ICMPv6 types before 25.7): such a rule
  is written disabled.
"""

from __future__ import annotations

import copy
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, ANY_V6, Policy, Rule
from ..names import OPNSENSE, unique
from ..netutil import parse_literal
from ..options import Options
from ..parsers.pfsense import ICMP6_TYPES, KEY
from ..report import Report, Severity
from . import pfsense as _pf

# Series -> (model version of the firewall rules, the highest sequence number).
VERSIONS: Dict[str, Tuple[str, int]] = {
    "24.7": ("1.0.4", 99999), "25.1": ("1.0.4", 99999), "25.7": ("1.0.4", 99999),
    "26.1": ("1.0.5", 999999), "26.7": ("1.0.6", 999999),
}  # fmt: skip
DEFAULT_VERSION = "26.7"
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:fwshift:opnsense")
_STEP = 10


def _series(options: Options) -> str:
    version = options.target_version or DEFAULT_VERSION
    if version not in VERSIONS:
        raise FwshiftError(f"--target-version: '{version[:20]}' is no series of OPNsense FWShift writes; it writes " + ", ".join(VERSIONS))
    return version


def emit(policy: Policy, report: Report, options: Options) -> str:
    _series(options)
    before = (len(report.notes), {key: len(item.findings) for key, item in report.items.items()})
    text = _pf.emit_with(policy, report, options, _Emitter)
    count, items = before
    for finding in report.notes[count:]:
        finding.message = finding.message.replace("pfSense", "OPNsense")
    for key, item in report.items.items():
        for finding in item.findings[items.get(key, 0) :]:
            finding.message = finding.message.replace("pfSense", "OPNsense")
    return text


def _version(text: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _child(node: _pf._X, tag: str) -> Optional[_pf._X]:
    return next((child for child in node.children if child.tag == tag), None)


def _value(node: Optional[_pf._X], tag: str) -> str:
    found = _child(node, tag) if node is not None else None
    return found.text if found is not None else ""


def _has(node: Optional[_pf._X], tag: str) -> bool:
    return node is not None and _child(node, tag) is not None


def _side(node: Optional[_pf._X]) -> Tuple[str, bool, str]:
    """(network, negated, port) of a source or destination the pfSense emitter made."""
    if node is None or _has(node, "any"):
        return "any", _has(node, "not"), _value(node, "port")
    value = _value(node, "network") or _value(node, "address") or "any"
    return value, _has(node, "not"), _value(node, "port")


def _flag(value: bool) -> str:
    return "1" if value else "0"


def _text(text: str) -> str:
    """Text as an element can hold it (no control characters), on one line."""
    kept = "".join(c for c in text if (c >= " " or c == "\t") and c not in "￾￿" and not "\ud800" <= c <= "\udfff")
    return " ".join(kept.split())


def _add(parent: ET.Element, tag: str, text: str = "") -> ET.Element:
    node = ET.SubElement(parent, tag)
    if text:
        node.text = _text(text)
    return node


class _LinkLocal(_pf._Spec):
    """The network of an interface, as a word, for members that hold the link-local network with it: OPNsense adds
    fe80::/10 to such a word in a rule for IPv6."""


class _Wide(_pf._Spec):
    """The network of an interface, as a word, where its addresses are not known: in a rule for IPv6 OPNsense adds
    the link-local network to it, which the rule did not hold."""


def _interface_word(value: str) -> bool:
    return KEY.fullmatch(value) is not None


class _Emitter(_pf._Emitter):
    NAMES = OPNSENSE

    def __init__(self, p: Policy, report: Report, options: Options, interfaces: Dict[str, List[str]], keywords: Dict[str, str]) -> None:
        self.series = _series(options)
        self.model, self.top = VERSIONS[self.series]
        self.at = _version(self.series)
        self.received: Dict[str, List[str]] = {}  # rules for what leaves -> the interfaces it arrived on
        super().__init__(p, report, options, interfaces, keywords)
        self.ids: Dict[str, int] = {}

    @staticmethod
    def keywords_of(policy: Policy, interfaces: Dict[str, List[str]], options: Options) -> Dict[str, str]:
        """With the words of pfSense, the aliases OPNsense keeps of the networks of an interface (``__lan_network``),
        where the interface is the same one on the target."""
        out = _pf._keywords(policy, interfaces, options)
        if policy.vendor != "opnsense":
            return out
        for name, group in policy.address_groups.items():
            match = re.fullmatch(r"__(.+)_network", name)
            if group.builtin != "opnsense" or not match:
                continue
            zones = [zone.name for zone in policy.zones.values() if zone.interfaces == [match.group(1)]]
            if len(zones) == 1 and interfaces.get(options.zone_map.get(zones[0], zones[0])) == [match.group(1)]:
                out[name] = name
        return out

    def _own(self, member: str) -> bool:
        """Whether a member is one of the aliases OPNsense keeps of the networks of an interface."""
        return member.startswith("__") and self.keywords.get(member) == member

    def _families(self, member: str) -> Set[int]:
        return transform.families(self.p, member) if self._own(member) else super()._families(member)

    def _object_alias(self, name: str) -> str:
        return name if self._own(name) else super()._object_alias(name)

    def _group_entries(self, member: str) -> List[str]:
        return [member] if self._own(member) else super()._group_entries(member)

    def _define_objects(self) -> None:
        for name in self.keywords:
            if self._own(name):
                self.kinds[name] = "network"
        super()._define_objects()

    def _alias(self, name: str, kind: str, entries: List[str], description: str) -> None:
        """Host names stand in an alias of type host only: next to networks they get an alias of their own in it."""
        known = set(self.aliases) | set(self.p.addresses) | set(self.p.address_groups) | set(self.keywords)
        hosts = [entry for entry in entries if parse_literal(entry) is None and entry not in known]
        rest = [entry for entry in entries if entry not in hosts]
        if kind == "network" and hosts and any("/" in entry or self.kinds.get(entry) == "network" for entry in rest):
            inner = unique(f"{name[:24]}_hosts", self.taken, OPNSENSE)
            super()._alias(inner, "host", hosts, f"host names of {name}")
            entries = rest + [inner]
        super()._alias(name, kind, entries, description)

    def _as_network(self, value: str) -> str:
        return value  # OPNsense takes the words, the aliases and the addresses as they are

    def _members_spec(self, members: List[str], negated: bool, label: str, description: str) -> _pf._Spec:
        """The network of an interface is a word only where what OPNsense adds to it in a rule for IPv6 (fe80::/10) is
        what the members hold, or the rule is for IPv4 only."""
        link = [member for member in members if member != "fe80::/10"]
        if not negated and link and len(link) < len(members):
            words = transform.dedupe([self.keywords.get(member, "") for member in link])
            if len(words) == 1 and _interface_word(words[0]):
                families = frozenset(f for member in link for f in self._families(member)) | {6}
                return _LinkLocal("network", words[0], False, families)
        spec = super()._members_spec(members, negated, label, description)
        if spec.kind != "network" or spec.negated or not _interface_word(spec.value) or 6 not in spec.families:
            return spec
        if not all(transform.known_intervals(self.p, member)[1] for member in members):
            return _Wide(spec.kind, spec.value, spec.negated, spec.families)
        listed = [self._object_alias(member) for member in members]
        alias = listed[0] if len(listed) == 1 else self._list_alias(listed, label, description)
        return _pf._Spec("address", alias, False, spec.families)

    def _floating_block(self, rule: Rule) -> bool:
        """26.7 and later: also a rule that blocks for named source zones, as a rule for what leaves by the interfaces
        of its destination zones and arrived on those of its source zones (received-on)."""
        if super()._floating_block(rule):
            return True
        if self.at < (26, 7) or not rule.src_zones or ANY in rule.src_zones:
            return False
        trial = copy.copy(rule)
        trial.src_zones = [ANY]
        if not super()._floating_block(trial):
            return False
        reasons: List[transform.Reason] = []
        keys = self._keys(rule.src_zones, reasons)
        if reasons or not keys:
            return False
        self.received[rule.origin] = keys
        return True

    def _rule_node(
        self, rule: Rule, interface: str, cls: _pf._Class, source: _pf._Spec, destination: _pf._Spec, disabled: bool,
        note: str, leaving: bool = False,
    ) -> Optional[_pf._X]:  # fmt: skip
        node = super()._rule_node(rule, interface, cls, source, destination, disabled, note, leaving)
        families = source.families & destination.families & cls.families
        if node is not None and 6 in families and (isinstance(source, _Wide) or isinstance(destination, _Wide)):
            self.report.add(
                "rule", rule.origin, Severity.APPROX, "OPNSENSE_LINK_LOCAL",
                "the rule names the network of an interface whose IPv6 addresses are not in the configuration; in a rule "
                "for IPv6 OPNsense adds the link-local network (fe80::/10) to it, which the rule did not hold",
            )  # fmt: skip
        if node is not None and leaving and rule.origin in self.received:
            node.add("received-on", ",".join(self.received[rule.origin]))
        return node

    # -- what OPNsense cannot say -------------------------------------------------------------------

    def _rule_families(self, rule: Rule) -> FrozenSet[int]:
        def side(members: List[str], negated: bool) -> FrozenSet[int]:
            if negated or ANY in members:
                return _pf.BOTH
            return frozenset(f for member in members for f in ({4} if member == ANY_V4 else {6} if member == ANY_V6 else self._families(member)))

        return side(rule.sources, rule.negate_source) & side(rule.destinations, rule.negate_destination)

    def _classes(self, rule: Rule, reasons: List[transform.Reason]) -> List[_pf._Class]:
        classes = super()._classes(rule, reasons)
        families = self._rule_families(rule)
        for cls in classes:
            if cls.protocol == "sctp" and (cls.src or cls.dst):
                reasons.append(("OPNSENSE_SCTP_PORTS", "a rule of OPNsense names ports for TCP and UDP only, not for SCTP"))
            if cls.protocol == "icmp" and cls.icmp:
                if 4 in cls.families & families and self.at < (25, 1):
                    reasons.append(("OPNSENSE_ICMP_TYPES", f"a rule of OPNsense {self.series} names no ICMP types (25.1 and later do)"))
                if 6 in cls.families & families and self.at < (25, 7):
                    reasons.append(("OPNSENSE_ICMP_TYPES", f"a rule of OPNsense {self.series} names no ICMPv6 types (25.7 and later do)"))
        return classes

    # -- writing ----------------------------------------------------------------------------------

    def _uuid(self, kind: str, name: str) -> str:
        key = f"{kind}:{name}"
        self.ids[key] = self.ids.get(key, 0) + 1
        return str(uuid.uuid5(_NAMESPACE, f"{key}:{self.ids[key]}"))

    def _alias_node(self, x: _pf._X) -> ET.Element:
        name = _value(x, "name")
        node = ET.Element("alias", uuid=self._uuid("alias", name))
        _add(node, "enabled", "1")
        _add(node, "name", name)
        _add(node, "type", _value(x, "type"))
        _add(node, "proto")
        _add(node, "interface")
        _add(node, "counters", "0")
        _add(node, "updatefreq")
        content = _add(node, "content")
        content.text = "\n".join(_value(x, "address").split()) or None
        _add(node, "categories")
        _add(node, "description", _value(x, "descr")[:255])
        return node

    def _filter_rules(self, nodes: List[_pf._X]) -> List[ET.Element]:
        out: List[ET.Element] = []
        for x in nodes:
            word = _value(x, "ipprotocol") or "inet"
            protocol = _value(x, "protocol")
            split = word == "inet46" and (protocol == "icmp" or self.at < (25, 1))
            for family in (["inet", "inet6"] if split else [word]):
                out.append(self._filter_rule(x, family, protocol))
        if len(out) > self.top:
            raise FwshiftError(f"the policy needs {len(out)} rules, and OPNsense {self.series} numbers them up to {self.top}")
        step = _STEP if len(out) * _STEP <= self.top else 1
        for number, node in enumerate(out, 1):
            sequence = node.find("sequence")
            assert sequence is not None
            sequence.text = str(number * step)
        return out

    def _filter_rule(self, x: _pf._X, family: str, protocol: str) -> ET.Element:
        description = _value(x, "descr")
        node = ET.Element("rule", uuid=self._uuid("rule", description))
        _add(node, "enabled", _flag(not _has(x, "disabled")))
        if self.at >= (25, 1):
            _add(node, "statetype", "keep")
        _add(node, "sequence", "0")
        _add(node, "action", _value(x, "type"))
        _add(node, "quick", "1")
        if self.at >= (25, 1):
            _add(node, "interfacenot", "0")
        _add(node, "interface", _value(x, "interface"))
        _add(node, "direction", "out" if _value(x, "direction") == "out" else "in")
        if _value(x, "received-on"):
            _add(node, "received-on", _value(x, "received-on"))
            _add(node, "received-on-not", "0")
        _add(node, "ipprotocol", family)
        icmp = [name for name in _value(x, "icmptype").split(",") if name]
        if protocol == "icmp" and family == "inet6":
            _add(node, "protocol", "IPV6-ICMP")
            if icmp and self.at >= (25, 7):
                _add(node, "icmp6type", ",".join(str(ICMP6_TYPES[name]) for name in icmp))
        else:
            _add(node, "protocol", protocol.upper() if protocol else "any")
            if protocol == "icmp" and icmp and self.at >= (25, 1):
                _add(node, "icmptype", ",".join(icmp))
        for tag, side in (("source", _child(x, "source")), ("destination", _child(x, "destination"))):
            network, negated, port = _side(side)
            _add(node, f"{tag}_net", network)
            _add(node, f"{tag}_not", _flag(negated))
            _add(node, f"{tag}_port", port)
        _add(node, "log", _flag(_has(x, "log")))
        _add(node, "categories")
        _add(node, "description", description[:255])
        return node

    @staticmethod
    def _legacy_side(parent: ET.Element, tag: str, side: Optional[_pf._X]) -> None:
        node = _add(parent, tag)
        network, negated, port = _side(side)
        if network == "any":
            _add(node, "any", "1")
        elif side is not None and _has(side, "network"):
            _add(node, "network", network)
        else:
            _add(node, "address", network)
        if negated:
            _add(node, "not", "1")
        if port:
            _add(node, "port", port)

    def _forward(self, x: _pf._X, number: int) -> ET.Element:
        description = _value(x, "descr")
        newer = self.at >= (26, 1)
        node = ET.Element("rule", uuid=self._uuid("forward", description)) if newer else ET.Element("rule")
        if newer:
            _add(node, "sequence", str(number * _STEP))
            _add(node, "disabled", _flag(_has(x, "disabled")))
            _add(node, "nordr", "0")
        elif _has(x, "disabled"):
            _add(node, "disabled", "1")
        _add(node, "interface", _value(x, "interface"))
        _add(node, "ipprotocol", _value(x, "ipprotocol") or "inet")
        _add(node, "protocol", _value(x, "protocol") or "any")
        for tag in ("source", "destination"):
            side = _child(x, tag)
            if newer:
                network, negated, port = _side(side)
                part = _add(node, tag)
                _add(part, "network", network)
                _add(part, "port", port)
                _add(part, "not", _flag(negated))
            else:
                self._legacy_side(node, tag, side)
        _add(node, "target", _value(x, "target"))
        if _value(x, "local-port"):
            _add(node, "local-port", _value(x, "local-port"))
        if newer:
            _add(node, "log", "0")
            _add(node, "category")
        _add(node, "descr", description)
        _add(node, "natreflection", "disable")
        if newer:
            _add(node, "pass")
        else:
            _add(node, "associated-rule-id")
        return node

    def _snat(self, x: _pf._X, number: int) -> ET.Element:
        description = _value(x, "descr")
        node = ET.Element("rule", uuid=self._uuid("snat", description))
        _add(node, "enabled", _flag(not _has(x, "disabled")))
        _add(node, "nonat", _flag(_has(x, "nonat")))
        _add(node, "sequence", str(number * _STEP))
        interface = _value(x, "interface")
        _add(node, "interface", interface)
        _add(node, "ipprotocol", _value(x, "ipprotocol") or "inet")
        protocol = _value(x, "protocol")
        _add(node, "protocol", protocol.upper() if protocol else "any")
        _add(node, "source_net", _value(_child(x, "source"), "network") or "any")
        _add(node, "source_not", "0")
        _add(node, "source_port", _value(x, "sourceport").replace(":", "-"))
        destination, negated, _ = _side(_child(x, "destination"))
        _add(node, "destination_net", destination)
        _add(node, "destination_not", _flag(negated))
        _add(node, "destination_port", _value(x, "dstport").replace(":", "-"))
        target, bits = _value(x, "target"), _value(x, "target_subnet")
        if target == f"{interface}ip" and self.at >= (26, 1):
            target = ""  # the address of the interface the rule is on
        elif target and bits and bits != "32" and not target.endswith("ip"):
            target = f"{target}/{bits}"
        _add(node, "target", "" if _has(x, "nonat") else target)
        _add(node, "target_port")
        _add(node, "staticnatport", _flag(_has(x, "staticnatport")))
        if _value(x, "poolopts"):
            _add(node, "poolopts", _value(x, "poolopts"))
        _add(node, "log", "0")
        _add(node, "categories")
        _add(node, "description", description[:255])
        return node

    def _binat(self, x: _pf._X, number: int) -> ET.Element:
        description = _value(x, "descr")
        node = ET.Element("rule", uuid=self._uuid("onetoone", description))
        _add(node, "enabled", _flag(not _has(x, "disabled")))
        _add(node, "log", "0")
        _add(node, "sequence", str(number * _STEP))
        _add(node, "interface", _value(x, "interface"))
        _add(node, "type", "binat")
        source, _, _ = _side(_child(x, "source"))
        _add(node, "source_net", source)
        _add(node, "source_not", "0")
        destination, negated, _ = _side(_child(x, "destination"))
        _add(node, "destination_net", destination)
        _add(node, "destination_not", _flag(negated))
        _add(node, "external", _value(x, "external"))
        _add(node, "natreflection", "disable")
        _add(node, "categories")
        _add(node, "description", description[:255])
        return node

    # -- output ------------------------------------------------------------------------------------

    def run(self) -> str:
        nat = self._nat()
        written = {nat_rule.origin for nat_rule in self.p.nat_rules if not self.report.item("nat", nat_rule.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        for rule in self.p.rules:
            self._rule(rule)
        self._default()
        self._notes()
        root = ET.Element("opnsense")
        firewall = ET.SubElement(ET.SubElement(root, "OPNsense"), "Firewall")
        model = ET.SubElement(firewall, "Alias", version="1.0.1")
        filter_model = ET.SubElement(firewall, "Filter", version=self.model)
        rules = list(self.floating)
        for interface in transform.dedupe([i for names in self.interfaces.values() for i in names] + list(self.tabs)):
            rules += self.tabs.get(interface, [])
        ET.SubElement(filter_model, "rules").extend(self._filter_rules(rules))
        if self.aliases:
            ET.SubElement(ET.SubElement(model, "geoip"), "url")
            listed = ET.SubElement(model, "aliases")
            listed.extend(self._alias_node(x) for x in self.aliases.values())
        else:
            firewall.remove(model)
        if nat.children:
            outbound = _child(nat, "outbound")
            section = ET.SubElement(root, "nat")
            mode = ET.SubElement(section, "outbound")
            _add(mode, "mode", _value(outbound, "mode"))
            forwards = [child for child in nat.children if child.tag == "rule"]
            section.extend(self._forward(x, n) for n, x in enumerate(forwards, 1))
            snat = [child for child in outbound.children if child.tag == "rule"] if outbound is not None else []
            ET.SubElement(filter_model, "snatrules").extend(self._snat(x, n) for n, x in enumerate(snat, 1))
            ET.SubElement(filter_model, "npt")
            binat = [child for child in nat.children if child.tag == "onetoone"]
            ET.SubElement(filter_model, "onetoone").extend(self._binat(x, n) for n, x in enumerate(binat, 1))
        ET.indent(root, space="  ")
        head = [
            '<?xml version="1.0"?>',
            "<!-- Generated by FWShift - review the conversion report before restoring this.",
            f"     The areas Aliases, NAT and Firewall Rules of an OPNsense {self.series} configuration, for System, Configuration,",
            "     Backups: restore this file once per area, the aliases first, then apply the changes.",
            "     Each restore REPLACES that area of the firewall: every alias, every NAT rule and the outbound NAT mode, and",
            "     the rules of both rule pages. -->",
        ]
        return "\n".join(head) + "\n" + ET.tostring(root, encoding="unicode") + "\n"

    def _notes(self) -> None:
        super()._notes()
        replaced = [note for note in self.report.notes if note.code == "PFSENSE_RESTORE"]
        self.report.retract("note", {"PFSENSE_RESTORE"})
        forwards, one_to_one, outbound = self.nat_counts
        if forwards or one_to_one or outbound:
            mode = (
                f"sets outbound NAT to manual mode with the {outbound} rule{'s' if outbound != 1 else ''} of the source"
                if outbound else "switches outbound NAT off, as the source translates no source address"
            )  # fmt: skip
            nat_text = (
                f"The NAT area holds {forwards} port forward{'s' if forwards != 1 else ''} and {one_to_one} 1:1 "
                f"rule{'s' if one_to_one != 1 else ''}, and {mode}; it removes every rule of NPt"
            )
        else:
            nat_text = "There is no NAT area in the file: the NAT of the firewall stays as it is"
        if replaced:
            self.report.note(
                Severity.REVIEW, "OPNSENSE_RESTORE",
                f"the output holds the areas Aliases, NAT and Firewall Rules of an OPNsense configuration, for {self.series} "
                f"(--target-version). Under System > Configuration > Backups, restore the file once per area, the "
                "aliases first. Each restore replaces that area of the firewall with what the file holds: every alias "
                "and every NAT rule that is there now is gone, and the Firewall Rules area replaces the rules of both "
                "rule pages ('Rules' and 'Rules [new]'), with the setting to bypass the rules for static routes. What the interfaces say (Block private networks, Block bogon "
                "networks) stays as it is on the firewall. " + nat_text + ". OPNsense does not check what it restores and "
                "does not load it until the rules are applied or the firewall restarts; keep a backup, and look at the "
                "rules before anything depends on them",
            )  # fmt: skip
