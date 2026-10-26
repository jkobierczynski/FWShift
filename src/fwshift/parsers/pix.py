# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco PIX 6.x parser: ``write terminal`` / ``show running-config`` of a PIX Firewall 6.x -> neutral model.

PIX 7.0 and later write the configuration of an ASA (interface sections with ``nameif`` under them); FWShift reads
those with ``--from asa``. This parser takes the reader of the ASA (``parsers/asa.py``) for what the two share: names,
object groups, access list entries, routes, and how an entry becomes rules. It adds what only a PIX 6.x has.

How PIX behaviour is mapped onto the neutral model:

* Interfaces are named by ``nameif <hardware> <name> security<level>``; the names are the zones.
* An interface with an access list (``access-group <list> in interface <name>``) is decided by it, first match,
  then denied. For that interface the PIX ignores ``conduit`` and ``outbound`` (Cisco's command reference, 6.3,
  access-group: "overrides the conduit and outbound command statements for the specified interface_name").
* An interface without an access list lets traffic out to interfaces of a lower security level, as far as
  ``outbound``/``apply`` lists allow (those are not converted: such an implicit rule is written disabled), and in to
  interfaces of a higher level only where a ``conduit`` permits it. A conduit is global: it applies to every
  interface without an access list. Conduits are read in the order of the configuration, first match (assumed;
  Cisco's documentation does not say).
* No traffic passes between interfaces of the same security level, nor back out of the interface it came in on
  (PIX 6.x has no ``same-security-traffic``).
* Access lists and conduits name the address a host has where the traffic arrives: for a host behind a static
  translation, its global (mapped) address. That is the address as it arrives, which is what the model wants: the
  rules are not rewritten. This is the opposite of ASA 8.3 and later (Cisco's ASA 8.3 migration guide: before 8.3
  "you used to have to specify the mapped addresses and ports in an access list"). The destination zone of a permit
  entry is the interface behind the static that publishes its destination, else the one its routes lead to.
* NAT is mandatory: a PIX 6.x behaves as ``nat-control`` does on later releases (Cisco: nat-control "ensures that the
  translation behavior is the same as PIX Firewall versions earlier than 7.0"). A connection from a higher to a lower
  security level passes only if a translation covers its source (``nat`` with a ``global`` on the outgoing
  interface, a ``static``, an exemption, an identity ``nat 0``); one from a lower to a higher level only to an address
  a static (or an exemption) publishes there. The implicit rules are limited to the sources translations cover; an
  access list entry or conduit that permits more than translations cover keeps its match and is reported.
* NAT is one ordered list, as Cisco documents the order: exemptions (``nat 0 access-list``), statics (addresses, then
  ports), policy NAT (``nat N access-list``), then ``nat N``, the most specific network first. A connection can use
  a static for its destination and a ``nat`` for its source at once.
* ``fixup``, ``established``, ``alias``, ``aaa``, ``filter`` and ``shun`` are reported, not converted.
* PIX 6.x has no IPv6: ``any`` is every IPv4 address.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    Action,
    Address,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, Interval, interval_text, intersect, is_number, netmask_to_cidr, normalize, parse_literal, size
from ..netutil import subtract, within
from ..report import Report, Severity
from . import asa
from .asa import _Ace, _Cursor, _Entry, _Interface, _unique, read_entries

_HEADER = re.compile(r"PIX Version (\d+)\.(\d+)")
_NAMEIF = re.compile(r"nameif (\S+) (\S+) security(\d{1,3})\s*$")
_LEVEL = re.compile(r"security(\d{1,3})")
_ONE_IF = re.compile(r"\(([^,()\s]+)\)")
_STATIC_FLAGS = ("dns", "norandomseq")
_NOT_CONVERTED = (("aaa", "authentication"), ("aaa", "authorization"), ("filter",), ("alias",), ("shun",))

Box = Tuple[List[Interval], List[Interval]]  # (sources, destinations) a translation covers together


def looks_like_pix(text: str) -> bool:
    """A configuration of a PIX 6.x: its ``PIX Version`` line says 6 or earlier, or (without a version line) it names
    its interfaces with ``nameif <hardware> <name> security<level>`` at the start of a line, which only PIX 6.x
    writes. ``PIX Version 7`` and later are configurations of an ASA."""
    nameif = False
    for line in text.splitlines()[:5000]:
        found = _HEADER.match(line)
        if found:
            return int(found.group(1)) < 7
        if line.startswith(("ASA Version ", "NGFW Version ")):
            return False
        if _NAMEIF.match(line):
            nameif = True
    return nameif


def parse(data: bytes, report: Report) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    entries = read_entries(text)
    try:
        return _Pix(entries, report).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ParseError(f"the configuration could not be read ({type(exc).__name__}: {exc})") from None


@dataclass
class _Global:
    kind: str  # interface, one (a PAT address), range (a pool)
    first: str = ""
    last: str = ""


@dataclass
class _NatLine:
    interface: str
    nat_id: str
    order: int
    text: str
    real: str = ""  # a network, as the model writes it
    acl: str = ""
    prefix: int = 0
    outside: bool = False
    ignored: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)


class _Pix(asa._Builder):
    def __init__(self, entries: List[_Entry], report: Report) -> None:
        super().__init__(entries, report)
        self.p.vendor = "pix"
        self.globals: Dict[Tuple[str, str], List[_Global]] = {}  # (interface, nat id) -> its global statements
        self.published: List[Tuple[str, List[Interval], str]] = []  # (mapped interface, mapped addresses, real interface)
        self.out_cov: Dict[Tuple[str, str], List[Interval]] = {}  # (from, to): sources translated on the way
        self.in_cov: Dict[Tuple[str, str], List[Interval]] = {}  # (from, to): destinations published there
        self.boxes_out: Dict[Tuple[str, str], List[Box]] = {}
        self.boxes_in: Dict[Tuple[str, str], List[Box]] = {}
        self.pending_nat: List[NatRule] = []
        self.applied: Dict[str, List[str]] = {}  # interface -> outbound lists applied to it
        self.implicit: Set[str] = set()
        self.untranslated: List[str] = []
        self.with_list: Set[str] = set()

    # -- version and interfaces -------------------------------------------

    def _version(self) -> None:
        version: Optional[Tuple[int, int]] = None
        for entry in self.entries:
            if entry.words[1:2] == ["Version"] and entry.words[0] in ("ASA", "NGFW"):
                raise ParseError(f"this is the configuration of an ASA or FTD ('{entry.text[:40]}'): read it with --from asa")
            found = _HEADER.match(entry.text)
            if found:
                version = (int(found.group(1)), int(found.group(2)))
                self.p.scope = " ".join(entry.words[:3])
                break
        if version is not None and version >= (7, 0):
            raise ParseError(f"PIX {version[0]}.{version[1]} writes the configuration of an ASA (interface sections with "
                             "nameif under them): read it with --from asa")  # fmt: skip
        if version is None:
            self.report.note(Severity.INFO, "PIX_VERSION_ASSUMED",
                             "the input has no 'PIX Version' line; it was read as the configuration of a PIX 6.x")  # fmt: skip
        self.modern_nat = False  # access lists name the addresses as they arrive (mapped ones)
        self.any_both = False  # no IPv6
        self.p.lookup_after_dnat = False

    def _interfaces(self) -> None:
        hardware: Dict[str, _Interface] = {}
        unread: List[str] = []
        for entry in self.entries:
            words = entry.words
            if words[0] == "nameif" and len(words) == 4:
                found = _LEVEL.fullmatch(words[3])
                if found is None or int(found.group(1)) > 100:
                    unread.append(entry.text[:60])
                    continue
                interface = hardware.setdefault(words[1], _Interface(words[1]))
                interface.nameif, interface.level = words[2], int(found.group(1))
            elif words[0] == "interface" and len(words) >= 2:
                # interface ethernet0 auto [shutdown]; interface ethernet0 vlan10 logical [shutdown]
                key = words[2] if len(words) > 3 and words[3] == "logical" else words[1]
                interface = hardware.setdefault(key, _Interface(key))
                interface.shutdown = interface.shutdown or "shutdown" in words[2:]
        by_name = {interface.nameif: interface for interface in hardware.values() if interface.nameif}
        for entry in self._top("ip", "address"):
            words = entry.words
            named = by_name.get(words[2]) if len(words) > 2 else None
            if named is None or len(words) < 5:
                continue
            network = parse_literal(netmask_to_cidr(self._ip(words[3]), words[4]) or "")
            if network is not None and parse_literal(self._ip(words[3])) is not None:
                named.address = self._ip(words[3])
                named.networks.append(network)
        for interface in hardware.values():
            if not interface.nameif or interface.nameif in self.interfaces:
                continue
            self.interfaces[interface.nameif] = interface
            if interface.shutdown:
                self.unrouted += interface.networks
            else:
                for network in interface.networks:
                    self.routes.setdefault(network, []).append(interface.nameif)
                    self.connected.add(network)
            self.nameifs.append(interface.nameif)
            self.declared += 1
            self.p.zones[interface.nameif] = Zone(interface.nameif, [interface.hardware])
        if unread:
            self.report.note(Severity.REVIEW, "PIX_INTERFACE_UNREAD",
                             "nameif lines that could not be read; their interfaces are not zones: " + "; ".join(unread[:4]))  # fmt: skip
        super()._interfaces()  # routes; the interface lines of a PIX have nothing under them and are passed over

    def _address(self, cursor: _Cursor, problems: List[str], in_group: bool = False) -> str:
        if not in_group and cursor.peek() == "interface":
            cursor.take()
            nameif = cursor.take()
            name = self._interface_object(nameif)
            if name is None:
                problems.append(f"the address of interface '{nameif[:40]}', which is not in the configuration")
                return ANY
            return name
        return super()._address(cursor, problems, in_group)

    def _interface_object(self, nameif: str) -> Optional[str]:
        """The object for the address of an interface (an access list entry says ``interface <name>``)."""
        interface = self.interfaces.get(nameif)
        if interface is None or not interface.address:
            return None
        if nameif not in self.interface_objects:
            name = _unique(f"{nameif}-interface", self.address_names)
            # As for an ASA: the keyword "interface", which the emitter for an ASA writes so again.
            self.p.addresses[name] = Address(
                name, AddressKind.NETWORK, f"{interface.address}/32",
                f"address of interface {nameif} when the configuration was read", raw=f"interface {nameif}", builtin="asa",
            )  # fmt: skip
            self.interface_objects[nameif] = name
        return self.interface_objects[nameif]

    def _level(self, nameif: str) -> Optional[int]:
        interface = self.interfaces.get(nameif)
        return interface.level if interface is not None else None

    # -- NAT, read before the rules: they decide where traffic goes and what passes ----

    def _access_lists(self) -> None:
        super()._access_lists()
        self._read_nat()

    def _intervals(self, member: str) -> Optional[List[Interval]]:
        if member in (ANY, ANY_V4):
            return [FULL_V4]
        if member == ANY_V6:
            return []
        found, complete = transform.known_intervals(self.p, member)
        return normalize(found) if complete else None

    def _read_nat(self) -> None:
        nat_lines: List[_NatLine] = []
        statics: List[NatRule] = []
        ports: List[NatRule] = []
        for entry in self.entries:
            words = entry.words
            if len(words) < 3 or not words[1].startswith("("):
                continue
            if words[0] == "global":
                self._global(entry)
            elif words[0] == "nat":
                nat_lines.append(self._nat_line(entry, len(nat_lines)))
            elif words[0] == "static":
                rule = self._static(entry, len(statics) + len(ports) + 1)
                (ports if rule.destination_translation is not None and rule.service != ANY else statics).append(rule)
        exempt: List[NatRule] = []
        policy: List[NatRule] = []
        regular: List[Tuple[Tuple[int, int, int], List[NatRule]]] = []
        first_seen: Dict[str, int] = {}
        for line in nat_lines:
            first_seen.setdefault(line.interface, len(first_seen))
            if line.acl and line.nat_id == "0":
                exempt += self._exemption(line)
            elif line.acl:
                policy += self._policy_nat(line)
            else:
                # nat N: the most specific network on an interface first (best match); then the order of the file.
                regular.append(((first_seen[line.interface], -line.prefix, line.order), self._regular_nat(line)))
        regular.sort(key=lambda item: item[0])
        self._nat_coverage([line for line in nat_lines if not line.acl and line.real and not line.problems])
        self.pending_nat = exempt + statics + ports + policy + [nat for _, rules in regular for nat in rules]
        for nat in self.pending_nat:
            nat.origin = nat.name
            nat.combines = True  # a static for the destination and a nat for the source can both apply
        for (interface, nat_id), _ in self.globals.items():
            if nat_id != "0" and not any(line.nat_id == nat_id for line in nat_lines):
                self.report.note(Severity.INFO, "PIX_GLOBAL_UNUSED",
                                 f"global ({interface}) {nat_id} has no nat statement with that id: it translates nothing")  # fmt: skip

    def _global(self, entry: _Entry) -> None:
        words = entry.words
        pair = _ONE_IF.fullmatch(words[1])
        if pair is None or len(words) < 4:
            self.report.note(Severity.REVIEW, "PIX_NAT_UNREAD", f"a global statement could not be read: '{entry.text[:60]}'")
            return
        interface, nat_id, spec = pair.group(1), words[2], words[3]
        found: Optional[_Global] = None
        if spec == "interface":
            found = _Global("interface")
        else:
            first, _, last = self._ip(spec).partition("-")
            one, other = parse_literal(first), parse_literal(last) if last else None
            if one is not None and one[1] == one[2] and "/" not in first:
                if not last:
                    found = _Global("one", first)
                elif other is not None and other[1] == other[2] and other[1] >= one[1]:
                    found = _Global("range", first, last) if other[1] > one[1] else _Global("one", first)
        if found is None:
            self.report.note(Severity.REVIEW, "PIX_NAT_UNREAD", f"a global statement could not be read: '{entry.text[:60]}'")
            return
        self.globals.setdefault((interface, nat_id), []).append(found)

    def _nat_line(self, entry: _Entry, order: int) -> _NatLine:
        words = entry.words
        pair = _ONE_IF.fullmatch(words[1])
        line = _NatLine(pair.group(1) if pair else "", words[2] if len(words) > 2 else "", order, entry.text)
        if pair is None or len(words) < 4 or not is_number(line.nat_id):
            line.problems.append(f"NAT line '{entry.text[:60]}'")
            return line
        cursor = _Cursor(words[3:])
        if cursor.peek() == "access-list":
            cursor.take()
            line.acl = cursor.take()
            if line.acl not in self.acls:
                line.problems.append(f"access list '{line.acl[:40]}', which is not in the configuration")
        else:
            address, mask = cursor.take(), cursor.take()
            address, mask = ("0.0.0.0" if address == "0" else self._ip(address)), ("0.0.0.0" if mask == "0" else mask)
            network = netmask_to_cidr(address, mask) if mask else None
            interval = parse_literal(network or "")
            if network is None or interval is None or interval[0] != 4:
                line.problems.append(f"network '{address[:20]} {mask[:20]}'")
            else:
                line.real = ANY_V4 if network == ANY_V4 else network[:-3] if network.endswith("/32") else network
                line.prefix = int(network.rpartition("/")[2])
        numbers = 0
        while not cursor.done:
            word = cursor.take()
            if word == "outside":
                line.outside = True
            elif word in _STATIC_FLAGS:
                line.ignored.append(word)
            elif is_number(word) and numbers < 2:
                numbers += 1
                if word != "0":
                    line.ignored.append(f"connection limits ({word})")
            else:
                line.problems.append(f"'{' '.join([word] + cursor.rest())[:40]}' in a NAT line")
        if line.outside:
            line.problems.append("outside NAT (a nat statement for a lower security interface with 'outside')")
        return line

    def _translation(self, interface: str, nat_id: str, nat: NatRule) -> Optional[SourceNat]:
        """What the global statements of one interface and id translate a source to."""
        found = self.globals.get((interface, nat_id), [])
        pools = [g for g in found if g.kind == "range"]
        pats = [g for g in found if g.kind == "one"]
        if pools:
            if pats or any(g.kind == "interface" for g in found):
                self.report.add("nat", nat.name, Severity.APPROX, "PIX_PAT_FALLBACK",
                                f"the PIX hands out the addresses of the pool and, when they run out, translates to the PAT "
                                f"address of global ({interface}) {nat_id}; only the pool is converted")  # fmt: skip
            return SourceNat(SnatKind.DYNAMIC, [f"{g.first}-{g.last}" for g in pools])
        if pats:
            if any(g.kind == "interface" for g in found):
                self.report.add("nat", nat.name, Severity.APPROX, "PIX_PAT_FALLBACK",
                                f"global ({interface}) {nat_id} names PAT addresses and the interface; only the addresses "
                                "are converted")  # fmt: skip
            return SourceNat(SnatKind.DYNAMIC_PORT, [g.first for g in pats])
        if found:
            return self._interface_pat(interface)
        return None

    def _exempt_targets(self, interface: str) -> List[str]:
        return [n for n in self.nameifs if n != interface and n in self.interfaces]

    def _acl_boxes(self, line: _NatLine, nat_base: str, translate: bool) -> List[Tuple[_Ace, NatRule, Optional[Box]]]:
        """One NAT rule per entry of the access list of a nat statement, with the addresses it covers."""
        out: List[Tuple[_Ace, NatRule, Optional[Box]]] = []
        denied = False
        for ace in self.acls.get(line.acl, []):
            nat = NatRule(name=_unique(f"{nat_base}-{ace.number}", self.nat_names), src_zones=[self._zone(line.interface)])
            nat.sources, nat.destinations = [ace.source], [ace.destination]
            nat.unsupported += list(line.problems) + [f"access list entry with {problem}" for problem in ace.problems]
            nat.enabled = not ace.inactive
            if denied:
                nat.unsupported.append(f"an entry after a deny entry of access list '{line.acl}': what the deny takes out "
                                       "goes on to the other NAT rules, which a first-match list cannot say")  # fmt: skip
            if not ace.allow:
                denied = True
                nat.unsupported.append(f"a deny entry of access list '{line.acl}' (traffic that goes on to the other NAT rules)")
            if ace.services != [ANY]:
                if translate:
                    nat.service = ace.services[0] if len(ace.services) == 1 else ANY
                    if len(ace.services) != 1:
                        nat.unsupported.append("an access list entry of several services")
                else:
                    nat.unsupported.append("ports in a NAT exemption list, which the PIX does not take")
            sources, destinations = self._intervals(ace.source), self._intervals(ace.destination)
            box = (sources, destinations) if sources is not None and destinations is not None and not nat.unsupported else None
            out.append((ace, nat, box))
        if not out:
            nat = NatRule(name=_unique(nat_base, self.nat_names), src_zones=[self._zone(line.interface)])
            nat.unsupported += line.problems or [f"access list '{line.acl}' has no entries"]
            out.append((_Ace(line.acl, 0, "permit"), nat, None))
        return out

    def _exemption(self, line: _NatLine) -> List[NatRule]:
        out: List[NatRule] = []
        for _, nat, box in self._acl_boxes(line, f"nat0-{line.interface}", translate=False):
            nat.description = f"nat ({line.interface}) 0 access-list {line.acl}: not translated"
            out.append(nat)
            if box is not None and nat.enabled:
                for other in self._exempt_targets(line.interface):
                    self.boxes_out.setdefault((line.interface, other), []).append(box)
                    self.boxes_in.setdefault((other, line.interface), []).append((box[1], box[0]))
        return out

    def _policy_nat(self, line: _NatLine) -> List[NatRule]:
        out: List[NatRule] = []
        targets = self._targets(line)
        for _, nat, box in self._acl_boxes(line, f"nat{line.nat_id}-{line.interface}", translate=True):
            nat.description = f"nat ({line.interface}) {line.nat_id} access-list {line.acl}"
            if not targets:
                nat.unsupported.append(f"no global statement with id {line.nat_id}: nothing to translate to")
                out.append(nat)
                continue
            for index, target in enumerate(targets):
                copy_ = nat if index == 0 else copy.deepcopy(nat)
                if index:
                    copy_.name = _unique(f"{nat.name}-{target}", self.nat_names)
                copy_.dst_zones = [self._zone(target)]
                copy_.source_translation = self._translation(target, line.nat_id, copy_)
                out.append(copy_)
                if box is not None and copy_.enabled:
                    self.boxes_out.setdefault((line.interface, target), []).append(box)
        return out

    def _nat_coverage(self, lines: List[_NatLine]) -> None:
        """The sources the nat statements of an interface translate towards each interface of a lower level. The PIX
        takes the statement that matches a source best (the most specific network); it translates only if that
        statement has a global on the outgoing interface (or is nat 0). A less specific statement is not tried
        (assumed)."""
        for interface in transform.dedupe([line.interface for line in lines]):
            level = self._level(interface)
            own = sorted((line for line in lines if line.interface == interface), key=lambda line: (-line.prefix, line.order))
            for target in self._exempt_targets(interface):
                other = self._level(target)
                if level is None or other is None or other >= level:
                    continue
                taken: List[Interval] = []
                for line in own:
                    network = self._intervals(line.real) or []
                    if line.nat_id == "0" or (target, line.nat_id) in self.globals:
                        self.out_cov.setdefault((interface, target), []).extend(subtract(network, taken))
                    taken += network

    def _targets(self, line: _NatLine) -> List[str]:
        """The interfaces whose global statements a nat statement translates to: those of its id on interfaces of a
        lower security level (towards a higher one a nat statement applies only with 'outside', which is not read)."""
        level = self._level(line.interface)
        if level is None:
            return []
        out: List[str] = []
        for interface, nat_id in self.globals:
            other = self._level(interface)
            if nat_id == line.nat_id and other is not None and other < level:
                out.append(interface)
        return out

    def _regular_nat(self, line: _NatLine) -> List[NatRule]:
        base = f"nat{line.nat_id}-{line.interface}"
        if line.problems or not line.real:
            nat = NatRule(name=_unique(base, self.nat_names), src_zones=[self._zone(line.interface)] if line.interface else [ANY])
            nat.unsupported += line.problems or [f"NAT line '{line.text[:60]}'"]
            return [nat]
        if line.nat_id == "0":
            # Identity: translated to itself, for connections the inside opens (towards every lower interface).
            nat = NatRule(name=_unique(base, self.nat_names), src_zones=[self._zone(line.interface)], sources=[line.real],
                          description=f"nat ({line.interface}) 0: not translated")  # fmt: skip
            self._ignored(nat, line.ignored)
            return [nat]
        targets = self._targets(line)
        if not targets:
            nat = NatRule(name=_unique(base, self.nat_names), src_zones=[self._zone(line.interface)], sources=[line.real])
            nat.unsupported.append(f"no global statement with id {line.nat_id}: nothing to translate to")
            return [nat]
        out: List[NatRule] = []
        for target in targets:
            name = _unique(base if len(targets) == 1 else f"{base}-{target}", self.nat_names)
            nat = NatRule(name=name, src_zones=[self._zone(line.interface)], dst_zones=[self._zone(target)], sources=[line.real])
            nat.description = f"nat ({line.interface}) {line.nat_id} with global ({target}) {line.nat_id}"
            nat.source_translation = self._translation(target, line.nat_id, nat)
            self._ignored(nat, line.ignored)
            out.append(nat)
        return out

    def _ignored(self, nat: NatRule, ignored: List[str]) -> None:
        if ignored:
            self.report.add("nat", nat.name, Severity.INFO, "ATTRIBUTES_IGNORED",
                            "NAT options without an equivalent were ignored: " + ", ".join(transform.dedupe(ignored)))  # fmt: skip

    def _static(self, entry: _Entry, number: int) -> NatRule:
        words = entry.words
        pair = asa._IF_PAIR.fullmatch(words[1])
        nat = NatRule(name=_unique(f"static-{number}", self.nat_names))
        problems = nat.unsupported
        if pair is None:
            problems.append(f"NAT line '{entry.text[:60]}'")
            return nat
        real_if, mapped_if = self._zone(pair.group(1)), self._zone(pair.group(2))
        nat.src_zones, nat.dst_zones = [real_if], [mapped_if]
        cursor = _Cursor(words[2:])
        protocol = cursor.take() if cursor.peek() in ("tcp", "udp") else ""
        mapped_word = cursor.take()
        mapped_port = asa._port(cursor.take()) if protocol else None
        acl = ""
        real_word = ""
        if cursor.peek() == "access-list":
            cursor.take()
            acl = cursor.take()
        else:
            real_word = cursor.take()
        real_port = asa._port(cursor.take()) if protocol and not acl else None
        mask = "255.255.255.255"
        ignored: List[str] = []
        numbers = 0
        while not cursor.done:
            word = cursor.take()
            if word == "netmask" and not cursor.done:
                mask = cursor.take()
            elif word in _STATIC_FLAGS:
                ignored.append(word)
            elif is_number(word) and numbers < 2:
                numbers += 1
                if word != "0":
                    ignored.append(f"connection limits ({word})")
            else:
                problems.append(f"'{' '.join([word] + cursor.rest())[:40]}' in a static")
        self._ignored(nat, ignored)
        if protocol and (mapped_port is None or (real_port is None and not acl)):
            problems.append(f"a port that could not be read in '{entry.text[:60]}'")
            return nat
        # The mapped side: an address (with the netmask: a network), or the address of the mapped interface.
        if mapped_word == "interface":
            mapped = self._interface_address(nat, mapped_if)
            mapped_intervals = self._intervals(mapped) if mapped != ANY else None
        else:
            mapped = self._network(self._ip(mapped_word), mask, problems)
            mapped_intervals = self._intervals(mapped) if mapped else None
        if acl:
            return self._policy_static(nat, acl, mapped, mapped_intervals, real_if, mapped_if, protocol)
        real = self._network(self._ip(real_word), mask, problems)
        real_intervals = self._intervals(real) if real else None
        if problems or not real or not mapped:
            return nat
        if protocol:
            # A published port: connections come in on the mapped interface, for the mapped address and port (the
            # model's NAT rules name the zone of the original destination, which is the mapped interface).
            assert mapped_port is not None and real_port is not None
            nat.src_zones, nat.dst_zones = [mapped_if], [mapped_if]
            nat.destinations = [mapped]
            nat.service = self._inline_service([ServiceEntry(Protocol(protocol), dst_ports=str(mapped_port))])
            nat.destination_translation = DestNat(real, "" if real_port == mapped_port else str(real_port))
            if mapped_intervals:
                self.published.append((mapped_if, mapped_intervals, real_if))
                self.in_cov.setdefault((mapped_if, real_if), []).extend(mapped_intervals)
            return nat
        if real_intervals and mapped_intervals and sum(size(i) for i in real_intervals) != sum(size(i) for i in mapped_intervals):
            problems.append("a translation between networks of different sizes")
            return nat
        nat.sources = [real]
        if mapped != real:
            nat.source_translation = SourceNat(SnatKind.STATIC, [mapped], bidirectional=True)
        else:
            nat.description = f"static ({real_if},{mapped_if}) {mapped} {real}: not translated"
        if mapped_intervals:
            self.published.append((mapped_if, mapped_intervals, real_if))
            self.in_cov.setdefault((mapped_if, real_if), []).extend(mapped_intervals)
        if real_intervals:
            self.out_cov.setdefault((real_if, mapped_if), []).extend(real_intervals)
        return nat

    def _network(self, address: str, mask: str, problems: List[str]) -> str:
        network = netmask_to_cidr(address, mask)
        start = parse_literal(address)
        if network is None or start is None or start[0] != 4 or "/" in address or "-" in address:
            problems.append(f"address '{address[:20]}' with netmask '{mask[:20]}'")
            return ""
        net = parse_literal(network)
        if net is None or net[1] != start[1]:
            problems.append(f"address '{address[:20]}', which is not the first of its netmask '{mask[:20]}'")
            return ""
        return address if network.endswith("/32") else network

    def _policy_static(self, nat: NatRule, acl: str, mapped: str, mapped_intervals: Optional[List[Interval]], real_if: str,
                       mapped_if: str, protocol: str) -> NatRule:  # fmt: skip
        """``static (real,mapped) <mapped> access-list <list>``: the first permit entry is what is translated. A PIX takes
        one source per policy static; more entries are reported."""
        problems = nat.unsupported
        aces = self.acls.get(acl, [])
        if acl not in self.acls:
            problems.append(f"access list '{acl[:40]}', which is not in the configuration")
        elif protocol:
            problems.append("a static of a port with an access list")
        elif len(aces) != 1 or not aces[0].allow or aces[0].problems or aces[0].services != [ANY]:
            problems.append(f"access list '{acl[:40]}' of a policy static that is not one permit entry for addresses")
        if problems or not mapped:
            return nat
        ace = aces[0]
        nat.sources, nat.destinations = [ace.source], [ace.destination]
        real_intervals, remote = self._intervals(ace.source), self._intervals(ace.destination)
        if real_intervals is None or mapped_intervals is None or sum(map(size, real_intervals)) != sum(map(size, mapped_intervals)):
            problems.append("a translation between networks of different sizes")
            return nat
        nat.source_translation = SourceNat(SnatKind.STATIC, [mapped])
        self.report.add("nat", nat.name, Severity.APPROX, "NAT_REVERSE_DIRECTION",
                        f"the static also lets '{ace.destination}' open connections to '{mapped}'; that direction is not "
                        "converted")  # fmt: skip
        if remote is not None:
            self.boxes_out.setdefault((real_if, mapped_if), []).append((real_intervals, remote))
            self.boxes_in.setdefault((mapped_if, real_if), []).append((remote, mapped_intervals))
            self.published.append((mapped_if, mapped_intervals, real_if))
        return nat

    def _nat(self) -> None:
        self.p.nat_rules = self.pending_nat

    # -- security rules ---------------------------------------------------

    def _egress_pix(self, source: str, destination: str) -> Optional[List[str]]:
        """Interfaces traffic arriving on ``source`` for ``destination`` leaves by: the real interface of a static
        that publishes the address there, else where the routes lead. None when that is not known."""
        if destination in (ANY, ANY_V4, ANY_V6):
            return None
        remaining = self._intervals(destination)
        if not remaining:
            return None
        zones: List[str] = []
        for mapped_if, mapped, real_if in self.published:
            if mapped_if != source or not intersect(remaining, mapped):
                continue
            if real_if not in zones:
                zones.append(real_if)
            remaining = subtract(remaining, mapped)
        if remaining:
            routed = self._routed(remaining)
            if routed is None:
                return None
            zones += [zone for zone in routed if zone not in zones]
        return [zone for zone in zones if zone in self.nameifs]

    def _place(self, ace: _Ace, src: List[str], dst: List[str]) -> List[Tuple[List[str], List[str], RuleScope, bool]]:
        if not ace.allow or not self.complete or ANY not in dst:
            return super()._place(ace, src, dst)
        sources = self.nameifs if ANY in src else src
        egress = {source: self._egress_pix(source, ace.destination) for source in sources}
        if all(zones is None for zones in egress.values()):
            return super()._place(ace, src, dst)
        self.egress_by_route = True
        leaving: Dict[Tuple[str, ...], List[str]] = {}
        for source in sources:
            blocked = self._blocked(source)
            candidates = egress[source]
            leaving.setdefault(tuple(n for n in (candidates if candidates is not None else self.nameifs) if n not in blocked), []).append(source)
        out: List[Tuple[List[str], List[str], RuleScope, bool]] = []
        for leaves, members in leaving.items():
            if leaves:
                everywhere = ANY in src and len(members) == len(self.nameifs)
                out.append(([ANY] if everywhere else members, list(leaves), RuleScope.UNIVERSAL, True))
        return out

    def _rules(self) -> None:
        for entry in self._top("access-group"):
            if len(entry.words) >= 5 and entry.words[2] == "in" and entry.words[3] == "interface":
                self.with_list.add(entry.words[4])
        self._outbound_lists()
        super()._rules()
        self._conduits()
        self._check_translations()

    def _outbound_lists(self) -> None:
        lists: Dict[str, List[str]] = {}
        for entry in self._top("outbound"):
            if len(entry.words) > 2:
                lists.setdefault(entry.words[1], []).append(" ".join(entry.words[2:]))
        ignored: List[str] = []
        for entry in self._top("apply"):
            words = entry.words
            pair = _ONE_IF.fullmatch(words[1]) if len(words) > 3 else None
            if pair is None:
                continue
            nameif, list_id, mode = pair.group(1), words[2], words[3]
            if nameif in self.with_list:
                ignored.append(f"{list_id} on {nameif}")
                continue
            entries = lists.get(list_id, [])
            self.applied.setdefault(nameif, []).append(
                f"outbound list {list_id} ({mode}: " + ("; ".join(entries[:4]) or "no entries") + (" ..." if len(entries) > 4 else "") + ")"
            )
        if self.applied:
            self.report.note(Severity.REVIEW, "PIX_OUTBOUND",
                             "outbound lists (outbound and apply) limit what interfaces without an access list let out: "
                             + "; ".join(f"{name}: {', '.join(texts)}" for name, texts in self.applied.items())
                             + ". The PIX decides them by the best match, not in order; they are not converted, and the "
                             "implicit rules of those interfaces are written disabled. Write their restrictions as rules")  # fmt: skip
        if ignored:
            self.report.note(Severity.INFO, "PIX_CONDUIT_IGNORED",
                             "outbound lists applied to interfaces with an access list are ignored by the PIX: " + ", ".join(ignored))  # fmt: skip

    def _implicit_permits(self, has_inbound: Set[str], v6_only: Set[str]) -> None:
        if not self.complete:
            return
        for nameif in self.nameifs:
            level = self._level(nameif)
            if nameif in has_inbound or level is None:
                continue
            for other in self.nameifs:
                other_level = self._level(other)
                if other == nameif or other_level is None or other_level >= level:
                    continue
                covered = normalize(self.out_cov.get((nameif, other), []))
                # A translation for some destinations only (an exemption, policy NAT) matters where they lie behind
                # this interface, or where the routes do not tell.
                boxes = [box for box in self.boxes_out.get((nameif, other), []) if subtract(box[0], covered)
                         and (self._routed(box[1]) is None or other in (self._routed(box[1]) or []))]  # fmt: skip
                if not covered and not boxes:
                    self.untranslated.append(f"{nameif} to {other}")
                    continue
                pieces: List[Tuple[List[str], List[str]]] = []
                if covered:
                    pieces.append(([ANY_V4] if covered == [FULL_V4] else [interval_text(i) for i in covered], [ANY_V4]))
                for box_sources, box_destinations in boxes:
                    rest = subtract(box_sources, covered)
                    pieces.append(([interval_text(i) for i in rest], [ANY_V4] if normalize(box_destinations) == [FULL_V4]
                                   else [interval_text(i) for i in normalize(box_destinations)]))  # fmt: skip
                for sources, destinations in pieces:
                    rule = Rule(name=_unique(f"implicit-{nameif}-{other}", self.rule_names), src_zones=[nameif], dst_zones=[other],
                                sources=sources, destinations=destinations)  # fmt: skip
                    rule.origin = rule.name
                    rule.log_end = False
                    rule.description = "PIX implicit rule: traffic to an interface of a lower security level, from what a translation covers"
                    if nameif in self.applied:
                        rule.unsupported.append(f"{', '.join(self.applied[nameif])} applied to {nameif}, which is not converted")
                    self.p.rules.append(rule)
                    self.implicit.add(rule.origin)
                    what = "every source" if sources == [ANY_V4] else "the sources a translation covers"
                    self.report.add("rule", rule.origin, Severity.INFO, "IMPLICIT_PERMIT",
                                    f"interface '{nameif}' (security level {level}) has no access list: the PIX lets its traffic "
                                    f"out to '{other}' (security level {other_level}), for {what} (NAT is mandatory). This rule "
                                    "says so")  # fmt: skip

    # -- conduits ---------------------------------------------------------

    def _conduits(self) -> None:
        lines = self._top("conduit")
        if not lines:
            return
        open_ifs = [n for n in self.nameifs if n in self.interfaces and n not in self.with_list]
        ignored = [n for n in self.nameifs if n in self.with_list]
        if ignored:
            self.report.note(Severity.INFO, "PIX_CONDUIT_IGNORED",
                             "the PIX ignores conduits for interfaces with an access list: " + ", ".join(ignored))  # fmt: skip
        for number, entry in enumerate(lines, 1):
            ace = self._conduit_ace(number, entry.words[1:])
            leaving: Dict[Tuple[str, ...], List[str]] = {}
            for source in open_ifs:
                level = self._level(source)
                higher = [n for n in self.nameifs if (self._level(n) or 0) > (level or 0) and n in self.interfaces]
                if not higher or level is None:
                    continue
                egress = self._egress_pix(source, ace.destination) if ace.allow else None
                leaves = tuple(zone for zone in (egress if egress is not None else higher) if zone in higher)
                if leaves:
                    leaving.setdefault(leaves, []).append(source)
            if not leaving:
                self.without_effect += 1
            for leaves, members in leaving.items():
                rule = self._new_rule(ace, f"conduit-{number}", members, list(leaves), RuleScope.UNIVERSAL)
                rule.egress_implied = True
                self.p.rules.append(rule)
                self.report.add("rule", rule.origin, Severity.INFO, "PIX_CONDUIT",
                                f"from the conduit '{entry.text[:80]}', which applies to every interface without an access "
                                "list, towards the interfaces of a higher security level its destination is behind")  # fmt: skip

    def _conduit_ace(self, number: int, words: List[str]) -> _Ace:
        """A conduit names the global address (the destination) before the foreign one (the source); written the
        other way round it is an access list entry."""
        cursor = _Cursor(words)
        head = [cursor.take(), cursor.take()]
        destination = self._address_words(cursor)
        destination_ports = self._port_words(cursor)
        source = self._address_words(cursor)
        source_ports = self._port_words(cursor)
        return self._ace("conduit", number, head + source + source_ports + destination + destination_ports + cursor.rest())

    @staticmethod
    def _address_words(cursor: _Cursor) -> List[str]:
        word = cursor.take()
        if word == "any" or not word:
            return [word] if word else []
        return [word, cursor.take()]

    def _port_words(self, cursor: _Cursor) -> List[str]:
        if cursor.peek() in asa._OPERATORS:
            return [cursor.take() for _ in range(3 if cursor.peek() == "range" else 2)]
        if cursor.peek() == "object-group" and cursor.peek(1) in self.port_groups:
            return [cursor.take(), cursor.take()]
        return []

    # -- what NAT lets through --------------------------------------------

    def _rule_intervals(self, members: Sequence[str]) -> Optional[List[Interval]]:
        out: List[Interval] = []
        for member in members:
            found = self._intervals(member)
            if found is None:
                return None
            out += found
        return normalize(out)

    def _check_translations(self) -> None:
        for rule in self.p.rules:
            if rule.action != Action.ALLOW or not rule.enabled or rule.origin in self.implicit or rule.unsupported:
                continue
            sources, destinations = self._rule_intervals(rule.sources), self._rule_intervals(rule.destinations)
            src_zones = self.nameifs if ANY in rule.src_zones else rule.src_zones
            dst_zones = self.nameifs if ANY in rule.dst_zones else rule.dst_zones
            missing: List[str] = []
            for source in src_zones:
                for target in dst_zones:
                    level, other = self._level(source), self._level(target)
                    if source == target or level is None or other is None or level == other:
                        continue
                    if sources is None or destinations is None:
                        missing.append(f"{source} to {target} (the addresses cannot be told)")
                        continue
                    if level > other:
                        rest = subtract(sources, self.out_cov.get((source, target), []))
                        for box_sources, box_destinations in self.boxes_out.get((source, target), []):
                            if within(destinations, box_destinations):
                                rest = subtract(rest, box_sources)
                        side = "sources"
                    else:
                        rest = subtract(destinations, self.in_cov.get((source, target), []))
                        for box_sources, box_destinations in self.boxes_in.get((source, target), []):
                            if within(sources, box_sources):
                                rest = subtract(rest, box_destinations)
                        side = "destinations"
                    if rest:
                        shown = ", ".join(interval_text(i) for i in rest[:3]) + (" ..." if len(rest) > 3 else "")
                        missing.append(f"{source} to {target}: {side} {shown}")
            if missing:
                self.report.add("rule", rule.origin, Severity.REVIEW, "PIX_TRANSLATION_REQUIRED",
                                "NAT is mandatory on a PIX 6.x: it passes a connection to a lower security level only from a "
                                "source a translation covers, and to a higher one only to an address a static or an exemption "
                                "publishes. No translation covers " + "; ".join(missing[:4])
                                + (" ..." if len(missing) > 4 else "") + ". The PIX drops that traffic, the converted rule "
                                "allows it: narrow the rule, or add the translation on the target")  # fmt: skip

    # -- what else to tell ------------------------------------------------

    def _notes(self) -> None:
        super()._notes()
        self.report.retract("note", {"ICMP_STATELESS", "VPN_BYPASS", "NO_INTERFACES", "RULE_WITHOUT_EFFECT", "EGRESS_BY_ROUTE"})
        p = self.p
        if p.rules and not self.complete:
            self.report.note(Severity.REVIEW, "NO_INTERFACES",
                             "the input does not show the interfaces of the PIX (fewer than two 'nameif' lines). A PIX does not "
                             "send traffic back out of the interface it came in on, nor between interfaces of the same security "
                             "level; the rules were read without that limit, and without the translations NAT requires")  # fmt: skip
        if self.egress_by_route:
            self.report.note(Severity.INFO, "EGRESS_BY_ROUTE",
                             "a PIX access list names no outgoing interface. For permit entries with destination addresses the "
                             "destination zone was taken from the statics that publish them and from the interface addresses "
                             "and static routes in the configuration")  # fmt: skip
        if self.without_effect:
            self.report.note(Severity.INFO, "RULE_WITHOUT_EFFECT",
                             f"{self.without_effect} permit entries or conduits can match no traffic the PIX forwards (same "
                             "interface, same security level, or no interface they apply to) and were left out")  # fmt: skip
        if self.untranslated:
            self.report.note(Severity.INFO, "PIX_NO_TRANSLATION",
                             "no translation (nat with a global, static, exemption) covers traffic from " + ", ".join(self.untranslated)
                             + ": the PIX passes none of it, and no implicit rule was written for it")  # fmt: skip
        allows_icmp = any(rule.enabled and rule.action == Action.ALLOW and self._passes_icmp(rule) for rule in p.rules)
        if allows_icmp:
            self.report.note(Severity.APPROX, "ICMP_STATELESS",
                             "a PIX 6.x keeps no state for ICMP: the reply to a permitted ICMP request got through only where "
                             "an access list or conduit permitted the reply too. Every target lets the replies to a permitted "
                             "request through by itself")  # fmt: skip
        bypass = [e.text for e in self.entries if e.words[:3] == ["sysopt", "connection", "permit-ipsec"]
                  or e.words[:3] in (["sysopt", "connection", "permit-pptp"], ["sysopt", "connection", "permit-l2tp"])]  # fmt: skip
        if bypass and p.rules:
            self.report.note(Severity.APPROX, "VPN_BYPASS",
                             f"'{bypass[0]}' lets traffic that arrives through VPN tunnels past the access lists and conduits. "
                             "The converted rules do not allow that traffic; add rules for it on the target")  # fmt: skip
        fixups = [" ".join(e.words[2:4]) for e in self.entries if e.words[:2] == ["fixup", "protocol"] and len(e.words) > 2]
        off = [" ".join(e.words[3:5]) for e in self.entries if e.words[:3] == ["no", "fixup", "protocol"] and len(e.words) > 3]
        if fixups or off:
            self.report.note(Severity.INFO, "PIX_FIXUP",
                             "application inspection (fixup) is not converted; the targets inspect with helpers of their own. "
                             + (f"On: {', '.join(fixups)}. " if fixups else "") + (f"Off: {', '.join(off)}." if off else ""))  # fmt: skip
        established = [e.text for e in self.entries if e.words[0] == "established"]
        if established:
            self.report.note(Severity.REVIEW, "PIX_ESTABLISHED",
                             "the established command lets connections in that belong to connections out ("
                             + "; ".join(t[:60] for t in established[:3]) + "). It is not converted: the result does not "
                             "allow those connections; write rules for them if they are needed")  # fmt: skip
        other = [e.text for e in self.entries if any(tuple(e.words[: len(first)]) == first for first in _NOT_CONVERTED)]
        if other:
            self.report.note(Severity.REVIEW, "PIX_NOT_CONVERTED",
                             "commands that change what passes are not converted (authentication, URL and Java filtering, "
                             "DNS doctoring, shunning): " + "; ".join(t[:60] for t in other[:5]) + (" ..." if len(other) > 5 else ""))  # fmt: skip
