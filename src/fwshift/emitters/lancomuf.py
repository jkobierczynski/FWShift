# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""LANCOM R&S Unified Firewall emitter: neutral model -> a shell script that creates desktop objects, user-defined
services and desktop connections through the REST API of LCOS FX.

Design rules:

* The desktop only allows, and has no order: a connection between two desktop objects lets through the services on it,
  in their directions, and what no connection allows is blocked. A rule of the model that allows is written as what it
  matches without what the blocking rules above it match (boxes of addresses and services, :mod:`fwshift.regions`, as
  for AWS security groups); a blocking rule is written as what it takes away from the rules below it. That is exact as
  long as nothing has to be left out, and what is left out (IPv6, ICMP types, source ports, protocols the firewall has no
  name for) only makes the result allow less, with a finding.
* Zones are interfaces: a desktop object names the interface it is connected through, and the firewall takes its
  addresses there only. The source of a piece is written as network objects at the interface of its source zone, the
  destination at that of its destination zone (``--interface-map``, or the zone's own name); a side for every zone at
  interface ``any``.
* A connection joins two objects. The addresses of a side are written as one network object per prefix, and a piece as
  a connection between each source and each destination object; a connection that exists already (the same two
  objects) gets the service as one more rule, in its direction.
* Every service is written as a user-defined service of its own (TCP and UDP port ranges, ICMP, GRE, ESP, AH, IGMP,
  OSPF, VRRP), so that the script needs the id of nothing it did not create.
* NAT: masquerading (source NAT to the outgoing interface) is written on the services of the connections whose
  traffic a NAT rule translates whole, as the first NAT rule that matches; other NAT is not written.
* The script adds, and deletes nothing: it looks first whether a name it would create is taken and stops if one is,
  then creates objects, services and connections, each call after the one before. Activating the configuration is
  left to a person.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Rule, ServiceEntry, SnatKind
from ..names import LANCOM_UF, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity

_INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}")
_PROTOCOL_NAMES = {1: "icmp", 47: "gre", 50: "esp", 51: "ah", 2: "igmp", 89: "ospf", 112: "vrrp"}
_MAX_PAIRS = 256  # connections one piece of a rule may need
_TEXT = re.compile(r"[^A-Za-z0-9 ._,:;()/+=#*!?&%<>@'-]")
_ALWAYS = [{"repeattype": "weekly", "starttime": "00:00:00", "endtime": "23:59:59", "startweekday": day, "endweekday": day}
           for day in range(7)]  # fmt: skip
_NAT_WORDS = {frozenset(): "none", frozenset({"ab"}): "left", frozenset({"ba"}): "right", frozenset({"ab", "ba"}): "both"}
_DIRECTION_WORDS = {frozenset({"ab"}): "leftToRight", frozenset({"ba"}): "rightToLeft", frozenset({"ab", "ba"}): "both"}

Entry = Tuple[str, int, int]  # protocol name, first and last destination port (0, 0 where there are none)


def emit(policy: Policy, report: Report, options: Options) -> str:
    for zone, interface in options.interface_map.items():
        if interface.lower() != "any" and not _INTERFACE.fullmatch(interface):
            raise FwshiftError(f"--interface-map: '{interface[:40]}' is not the name of an interface of a Unified Firewall")
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _text(value: str, limit: int = 255) -> str:
    """Free text the script can carry inside a here-document and JSON without escapes."""
    return _TEXT.sub("_", " ".join(value.split()))[:limit]


_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_RANGE = re.compile(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\d{2}:\d{2}(?::\d{2})?) - (Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\d{2}:\d{2}(?::\d{2})?)")


def _timeranges(schedule: str) -> Optional[List[Dict[str, object]]]:
    """The time ranges of a schedule as a LANCOM source writes it ("Mon 06:00:00 - Mon 22:00:00; ..."); None for others."""
    out: List[Dict[str, object]] = []
    for part in schedule.split("; "):
        match = _RANGE.fullmatch(part.strip())
        if not match:
            return None
        out.append({"repeattype": "weekly", "starttime": match.group(2), "endtime": match.group(4),
                    "startweekday": _DAYS.index(match.group(1)), "endweekday": _DAYS.index(match.group(3))})  # fmt: skip
    return out or None


def _cidrs(interval: Interval) -> List[str]:
    version, first, last = interval
    return [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]


@dataclass
class _Network:
    name: str
    var: str
    interface: str
    cidr: str
    index: int


@dataclass
class _Service:
    name: str
    var: str
    entries: Tuple[Entry, ...]


@dataclass
class _Connection:
    a: _Network
    b: _Network
    rules: Dict[str, Dict[str, Set[str]]] = field(default_factory=dict)  # service var -> {"dirs", "nat", "log"}
    origins: List[str] = field(default_factory=list)


@dataclass
class _Piece:
    src_zone: str
    dst_zone: str
    box: regions.Box
    origin: str
    log: bool
    times: str = ""  # the time ranges of the rule as JSON, "" for always


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "lancom-uf"
        self.prefix = options.object_prefix or "fws-"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.denies: List[Tuple[List[str], List[str], List[regions.Box], str]] = []
        self.pieces: List[_Piece] = []
        self.names: Set[str] = set()
        self.networks: Dict[Tuple[str, str, str], _Network] = {}
        self.services: Dict[Tuple[Entry, ...], _Service] = {}
        self.connections: Dict[Tuple[str, str], _Connection] = {}
        self.interfaces: Set[str] = set()
        self.comments: List[str] = []
        self.counter = 0
        self.lost_v6: Set[str] = set()
        self.lost_part: Set[str] = set()
        self.by_origin: Dict[str, Rule] = {rule.origin: rule for rule in p.rules}
        self.by_cidr: Dict[str, str] = {}
        self.labels: Set[str] = set()
        for address in p.addresses.values():
            interval = parse_literal(address.value) if address.kind == AddressKind.NETWORK else None
            if interval is not None and interval[0] == 4 and address.name not in self.taint_a:
                self.by_cidr.setdefault(_cidrs(interval)[0], address.name)

    # -- top level --------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._nat()
        self._notes()
        return self._script()

    def _var(self) -> str:
        self.counter += 1
        return f"ID_{self.counter}"

    def _name(self, label: str) -> str:
        """A name of the prefix and the label, unique without regard to case."""
        base = clean(self.prefix + label, LANCOM_UF)
        candidate, counter = base, 2
        while candidate.lower() in self.names:
            tail = f"_{counter}"
            candidate = base[: LANCOM_UF.max_len - len(tail)].rstrip() + tail
            counter += 1
        self.names.add(candidate.lower())
        return candidate

    # -- what a rule matches ----------------------------------------------------------------------

    def _addresses(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found += [FULL_V4, FULL_V6]
                continue
            intervals = transform.address_intervals(self.p, member) if member not in self.taint_a else None
            if intervals is None:
                if member not in self.taint_a:
                    address = self.p.addresses.get(member)
                    what = "a host name" if address is not None and address.kind == AddressKind.FQDN else "addresses that are not known"
                    reasons.append(("UNCONVERTIBLE_OBJECT", f"the {side} '{member}' holds {what}; a desktop object of the firewall "
                                    "names addresses"))  # fmt: skip
                return None
            found += intervals
        found = normalize(found)
        return subtract([FULL_V4, FULL_V6], found) if negated else found

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[regions.Services]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        entries: List[ServiceEntry] = []
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.services != [ANY]:
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        found = regions.ALL_SERVICES if lowered is None and rule.services == [ANY] else regions.service_set(entries)
        if found is None:
            reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
            return None
        return regions.ALL_SERVICES.minus(found) if rule.negate_service else found

    def _boxes(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[regions.Box]]:
        sources = self._addresses(rule.sources, rule.negate_source, "source", reasons)
        destinations = self._addresses(rule.destinations, rule.negate_destination, "destination", reasons)
        services = self._services(rule, reasons)
        if sources is None or destinations is None or services is None:
            return None
        out: List[regions.Box] = []
        for version in (4, 6):
            src, dst = regions.addresses(sources, version), regions.addresses(destinations, version)
            if src and dst and not services.empty():
                out.append((version, src, dst, services))
        return out

    # -- rules ------------------------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            self.comments.append(f"rule {rule.name}: disabled in the source, not written")
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        times = ""
        ranges = _timeranges(rule.schedule) if self.native and rule.schedule and rule.action == Action.ALLOW else None
        if ranges is not None:
            times = json.dumps(ranges)
            reasons = [reason for reason in reasons if reason[0] != "SCHEDULE"]
            self.report.add("rule", rule.origin, Severity.INFO, "SCHEDULE_KEPT",
                            "the schedule of the rule is written as the time ranges of the service on its connections")  # fmt: skip
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        allow = rule.action == Action.ALLOW
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule for every zone: a desktop connection joins two objects, "
                                "each at one interface"))  # fmt: skip
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule for every zone: taken out of the rules below it for every pair of "
                                "zones, which blocks more")  # fmt: skip
            pairs = [([ANY], [ANY])]
        boxes = self._boxes(rule, reasons)
        reasons = list(dict.fromkeys(reasons))
        if reasons or boxes is None:
            if allow:
                for code, message in reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")]:
                    self.report.skip("rule", rule.origin, code, message + "; the rule is not written")
            else:
                transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")])
            self.comments.append(f"rule {rule.name}: not written, see the report")
            return
        if not boxes:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation, the rule matches no connection", Severity.INFO)  # fmt: skip
            return
        if not allow:
            for src_zones, dst_zones in pairs:
                self.denies.append((src_zones, dst_zones, boxes, rule.origin))
            item.emitted_as.append("taken out of the rules below it")
            if rule.action != Action.DROP:
                self.report.add("rule", rule.origin, Severity.INFO, "ACTION_DROP",
                                f"action {rule.action.value}: the firewall drops what it does not allow")  # fmt: skip
            return
        self._allow(rule, pairs, boxes, times)

    def _allow(self, rule: Rule, pairs: List[Tuple[List[str], List[str]]], boxes: List[regions.Box], times: str = "") -> None:
        cut_any = False
        subtracted = False
        written = 0
        for src_zones, dst_zones in pairs:
            for src in src_zones:
                for dst in dst_zones:
                    cuts: List[regions.Box] = []
                    for deny_src, deny_dst, deny_boxes, _ in self.denies:
                        if not ((ANY in deny_src or src in deny_src or src == ANY) and (ANY in deny_dst or dst in deny_dst or dst == ANY)):
                            continue
                        if (src == ANY and ANY not in deny_src) or (dst == ANY and ANY not in deny_dst):
                            cut_any = True
                        cuts += deny_boxes
                    left = regions.minus_all(boxes, cuts)
                    if left is None:
                        self.report.skip("rule", rule.origin, "LANCOM_TOO_COMPLEX",
                                         "what the rule allows without what the blocking rules above it block falls apart into "
                                         "more pieces than are written; the rule is not written")  # fmt: skip
                        self.comments.append(f"rule {rule.name}: not written, see the report")
                        return
                    if len(left) != len(boxes) or any(a != b for a, b in zip(left, boxes)):
                        subtracted = True
                    for box in left:
                        if box[0] == 6:
                            self.lost_v6.add(rule.origin)
                            continue
                        self.pieces.append(_Piece(src, dst, box, rule.origin, rule.log_end or rule.log_start, times))
                        written += 1
        if subtracted:
            self.report.add("rule", rule.origin, Severity.INFO, "DENY_SUBTRACTED",
                            "the firewall has no rule that blocks: the rule is written without what the blocking rules above "
                            "it match")  # fmt: skip
        if cut_any:
            self.report.add("rule", rule.origin, Severity.APPROX, "DENY_ZONE_WIDENED",
                            "a blocking rule above it for some zones is taken out of this rule for every zone, since an object "
                            "at interface 'any' cannot leave a zone out: the rule allows less")  # fmt: skip
        if rule.origin in self.lost_v6:
            self.report.add("rule", rule.origin, Severity.APPROX if written else Severity.REVIEW, "IPV6_NOT_WRITTEN",
                            "the rule allows IPv6, and desktop objects of the firewall hold IPv4 addresses: the IPv6 part is not "
                            "written" + ("" if written else ", and nothing else is left: the rule is not written"))  # fmt: skip
            if not written:
                self.report.item("rule", rule.origin).skipped = True
        if not written and rule.origin not in self.lost_v6:
            self.report.skip("rule", rule.origin, "SHADOWED_BY_DENY",
                             "everything the rule allows is blocked by the rules above it; there is nothing to write", Severity.INFO)  # fmt: skip

    # -- pieces into objects and connections -------------------------------------------------------

    def _interface(self, zone: str) -> Optional[str]:
        if zone == ANY:
            return "any"
        interface = self.options.interface_map.get(zone, zone)
        if not _INTERFACE.fullmatch(interface) and interface.lower() != "any":
            return None
        if interface.lower() != "any" and zone not in self.options.interface_map:
            self.interfaces.add(interface)
        return interface

    def _entries(self, svc: regions.Services) -> Tuple[Tuple[Entry, ...], bool]:
        """What of a set of services a user-defined service can say, and whether something was left out."""
        out: List[Entry] = []
        dropped = svc.rest
        for number in sorted(svc.protocols):
            for rect in svc.protocols[number]:
                if number in (6, 17):
                    if (rect[0], rect[1]) != (0, 65535):
                        dropped = True
                        continue
                    low, high = max(rect[2], 1), rect[3]
                    if low > high:
                        continue
                    out.append(("tcp" if number == 6 else "udp", low, high))
                elif number == 1:
                    if regions.icmp_values(rect[0], rect[1]) == [None] and regions.icmp_values(rect[2], rect[3]) == [None]:
                        out.append(("icmp", 0, 0))
                    else:
                        dropped = True
                elif number == 58:
                    continue  # (ICMPv6 never meets an IPv4 packet)
                elif number in _PROTOCOL_NAMES and rect == regions.WHOLE:
                    out.append((_PROTOCOL_NAMES[number], 0, 0))
                else:
                    dropped = True
        if svc.rest:
            for number, name in ((6, "tcp"), (17, "udp")):
                if number not in svc.protocols:
                    out.append((name, 1, 65535))
            for number, name in _PROTOCOL_NAMES.items():
                if number not in svc.protocols:
                    out.append((name, 0, 0))
        merged: List[Entry] = []
        for name in sorted({e[0] for e in out}):
            ranges = regions.merge_ranges([(e[1], e[2]) for e in out if e[0] == name])
            merged += [(name, low, high) for low, high in ranges]
        return tuple(merged), dropped

    def _network(self, interface: str, cidr: str, label: str, twin: bool = False) -> _Network:
        """The network object of a prefix at an interface; ``twin``: a second one of the same, for a connection of the
        addresses with themselves (a connection joins two objects)."""
        key = (interface.lower(), cidr, "twin" if twin else "")
        if key not in self.networks:
            if label and (parse_literal(label) is not None or label in self.labels):
                label = f"{label}-{interface}" if parse_literal(label) is None else ""
            self.labels.add(label)
            name = self._name((label or f"{cidr.replace('/', '_')}-{interface}") + (" (2)" if twin else ""))
            self.networks[key] = _Network(name, self._var(), interface, cidr, len(self.networks))
        return self.networks[key]

    def _service(self, entries: Tuple[Entry, ...]) -> _Service:
        if entries not in self.services:
            label = ",".join(f"{e[0]}{'' if e[1] == 0 else f'-{e[1]}' if e[1] == e[2] else f'-{e[1]}-{e[2]}'}" for e in entries)
            self.services[entries] = _Service(self._name(label[:48] if len(entries) < 4 else f"svc-{len(self.services) + 1}"),
                                              self._var(), entries)  # fmt: skip
        return self.services[entries]

    def _labels(self, origin: str, intervals: List[Interval], side: str) -> List[Tuple[str, str]]:
        """(prefix, label) per network: the name of the one object of the model the side names, where it is just that."""
        rule = self.by_origin.get(origin)
        cidrs = [c for i in intervals for c in _cidrs(i)]
        if rule is not None and len(cidrs) == 1:
            members = rule.sources if side == "source" else rule.destinations
            negated = rule.negate_source if side == "source" else rule.negate_destination
            if len(members) == 1 and members[0] != ANY and not negated:
                found = transform.address_intervals(self.p, members[0])
                if found is not None and normalize([i for i in found if i[0] == 4]) == intervals:
                    return [(cidrs[0], members[0])]
        return [(c, self.by_cidr.get(c, "")) for c in cidrs]

    def _write_pieces(self) -> None:
        for piece in self.pieces:
            version, src, dst, svc = piece.box
            entries, dropped = self._entries(svc)
            if dropped and piece.origin not in self.lost_part:
                self.lost_part.add(piece.origin)
                self.report.add("rule", piece.origin, Severity.APPROX if entries else Severity.REVIEW, "LANCOM_PART_NOT_WRITTEN",
                                "part of what the rule allows cannot be said by a user-defined service (source ports, ICMP types, "
                                "every protocol but some, a protocol the firewall has no name for) and is not written; the "
                                "converted rule allows less")  # fmt: skip
            if not entries:
                continue
            src_if, dst_if = self._interface(piece.src_zone), self._interface(piece.dst_zone)
            if src_if is None or dst_if is None:
                bad = piece.src_zone if src_if is None else piece.dst_zone
                self.report.skip("rule", piece.origin, "INTERFACE_UNKNOWN",
                                 f"zone '{bad}' is no name of an interface of the firewall: give it with --interface-map; the rule "
                                 "is not written")  # fmt: skip
                continue
            sources = self._labels(piece.origin, src, "source")
            destinations = self._labels(piece.origin, dst, "destination")
            if len(sources) * len(destinations) > _MAX_PAIRS:
                self.report.skip("rule", piece.origin, "LANCOM_TOO_COMPLEX",
                                 f"the rule needs {len(sources)} source and {len(destinations)} destination objects, more "
                                 f"connections than the {_MAX_PAIRS} written for one rule; the rule is not written")  # fmt: skip
                continue
            service = self._service(entries)
            item = self.report.item("rule", piece.origin)
            for cidr_a, label_a in sources:
                a = self._network(src_if, cidr_a, label_a)
                for cidr_b, label_b in destinations:
                    b = self._network(dst_if, cidr_b, label_b)
                    if b is a:
                        b = self._network(dst_if, cidr_b, label_b, twin=True)
                    key = (a.var, b.var)
                    direction = "ab"
                    if key not in self.connections and (b.var, a.var) in self.connections:
                        key, direction = (b.var, a.var), "ba"
                    conn = self.connections.setdefault(key, _Connection(a, b))
                    entry = conn.rules.setdefault(f"{service.var}|{piece.times}", {"dirs": set(), "nat": set(), "log": set()})
                    entry["dirs"].add(direction)
                    if piece.log:
                        entry["log"].add(direction)
                    if piece.origin not in conn.origins:
                        conn.origins.append(piece.origin)
                    label = f"{a.name} > {b.name}: {service.name}"
                    if label not in item.emitted_as:
                        item.emitted_as.append(label)
                    self._piece_nat.setdefault((key, f"{service.var}|{piece.times}", direction), []).append(piece)
        for origin in dict.fromkeys(piece.origin for piece in self.pieces):
            item = self.report.item("rule", origin)
            if not item.emitted_as and not item.skipped:
                self.report.skip("rule", origin, "NOTHING_WRITTEN",
                                 "nothing of what the rule allows can be written on the desktop (see the findings above); the "
                                 "rule is not written")  # fmt: skip

    _piece_nat: Dict[Tuple[Tuple[str, str], str, str], List[_Piece]]

    # -- NAT ----------------------------------------------------------------------------------------

    def _nat_box(self, nat: NatRule) -> Optional[List[regions.Box]]:
        reasons: List[transform.Reason] = []
        sources = self._addresses(nat.sources, False, "source", reasons)
        destinations = self._addresses(nat.destinations, False, "destination", reasons)
        if nat.service == ANY:
            services: Optional[regions.Services] = regions.ALL_SERVICES
        else:
            flat = transform.flatten_services(self.p, nat.service)
            services = regions.service_set(flat) if flat is not None else None
        if sources is None or destinations is None or services is None or reasons:
            return None
        return [(4, regions.addresses(sources, 4), regions.addresses(destinations, 4), services)]

    def _nat(self) -> None:
        self._piece_nat = {}
        self._write_pieces()
        boxes: List[Tuple[NatRule, Optional[List[regions.Box]]]] = [(nat, self._nat_box(nat)) for nat in self.p.nat_rules]
        used: Dict[str, int] = {}
        partial: Set[str] = set()
        for (key, var, direction), pieces in self._piece_nat.items():
            for piece in pieces:
                for nat, nat_boxes in boxes:
                    if not nat.enabled or nat.unsupported or nat_boxes is None:
                        continue
                    zones_meet = (ANY in nat.src_zones or piece.src_zone in nat.src_zones or piece.src_zone == ANY) and \
                        (ANY in nat.dst_zones or piece.dst_zone in nat.dst_zones or piece.dst_zone == ANY)  # fmt: skip
                    if not zones_meet or not any(regions.box_and(piece.box, b) for b in nat_boxes):
                        continue
                    whole = (ANY in nat.src_zones or piece.src_zone in nat.src_zones) and \
                        (ANY in nat.dst_zones or piece.dst_zone in nat.dst_zones) and \
                        regions.minus_all([piece.box], nat_boxes) == []  # fmt: skip
                    masquerade = nat.destination_translation is None and nat.source_translation is not None and \
                        nat.source_translation.kind == SnatKind.INTERFACE and not nat.source_translation.addresses and \
                        not nat.source_translation.bidirectional  # fmt: skip
                    if whole and masquerade:
                        self.connections[key].rules[var]["nat"].add(direction)
                        used[nat.origin] = used.get(nat.origin, 0) + 1
                    elif masquerade:
                        partial.add(nat.origin)
                    break  # the first NAT rule that matches decides
        for nat, nat_boxes in boxes:
            masquerade = nat.destination_translation is None and nat.source_translation is not None and \
                nat.source_translation.kind == SnatKind.INTERFACE and not nat.source_translation.addresses  # fmt: skip
            if nat.origin in partial:
                self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_PARTIAL",
                                "the NAT rule translates part of the traffic of a connection service only: masquerading is set "
                                "per service of a connection, and is not written for that part. Set it by hand where needed")  # fmt: skip
            if nat.origin in used:
                self.report.item("nat", nat.origin).emitted_as.append(f"masquerading on {used[nat.origin]} services of connections")
                continue
            if nat.origin in partial:
                continue
            if not masquerade:
                why = ("it translates the destination (DMZ / port forwarding), whose keys in the API are not known" if
                       nat.destination_translation is not None else "it translates to an address of its own (NAT source IP), "
                       "whose key in the API is not known")  # fmt: skip
            elif not nat.enabled:
                why = "it is disabled"
            else:
                why = "no connection written carries the traffic it translates"
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             f"not converted: {why}. Set NAT on the service of the connection by hand (Advanced tab)",
                             Severity.REVIEW if masquerade is False or nat.enabled else Severity.INFO)  # fmt: skip

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "LANCOM_UF_LOAD",
            "the output is a shell script that creates network objects, user-defined services and desktop connections through "
            "the REST API of the firewall, with curl (section 10). Run it with DRY_RUN=1 first. It stops before it creates "
            "anything when a name it would create is taken, and at the first call the firewall refuses; nothing takes effect "
            "until the configuration is activated (Activate). LANCOM publishes the API by the examples of its LMC add-ins: "
            "the paths and keys of networks, connections and user-defined services follow them; assumed are the base path and "
            "the header of the token, that a created object's answer carries its id, the interface 'any' for a network, a "
            "user-defined service of a protocol without ports, and the names of protocols other than TCP and UDP",
        )  # fmt: skip
        if self.p.default_interzone == Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTERZONE_DEFAULT",
                             "the source allows what no rule matches; the firewall blocks what no connection allows. Add the "
                             "connections that allow it if that was intended")  # fmt: skip
        elif self.p.default_intrazone == Action.ALLOW or any(zone.intrazone_allow for zone in self.p.zones.values()):
            self.report.note(Severity.REVIEW, "INTERZONE_DEFAULT",
                             "the source allows traffic inside a zone that no rule matches; the firewall blocks it when it "
                             "passes the firewall (between two interfaces of a zone) and no connection allows it. Add the "
                             "connections that allow it if that was intended")  # fmt: skip
        if self.interfaces:
            self.report.note(Severity.REVIEW, "INTERFACES_REQUIRED",
                             "the objects written are connected through these interfaces of the firewall, which must exist under "
                             "these names (or give the right names with --interface-map): " + ", ".join(sorted(self.interfaces)))  # fmt: skip

    # -- the script ---------------------------------------------------------------------------------

    def _script(self) -> str:
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: desktop objects, user-defined services and desktop connections for a LANCOM R&S",
            "# Unified Firewall (LCOS FX), created through its REST API. Read the report first: what is left out is listed there.",
            "#",
            "#   DRY_RUN=1 sh THIS_FILE                                     prints the calls, makes none",
            "#   UF_API=https://FIREWALL:3438/api UF_TOKEN=... sh THIS_FILE",
            "#",
            "# UF_API is the address of the REST API up to the /model part of its paths, as its documentation on the firewall",
            "# shows it (Help > REST API Documentation). UF_AUTH replaces the header that carries the token",
            "# (default: Authorization: Bearer $UF_TOKEN); UF_CURL_OPTS adds options for curl, such as --cacert FILE.",
            "# Needs curl 7.76 or later and python3 (to read the ids from the answers).",
            "#",
            "# First every name is looked up: if one is taken, nothing is created. Then the network objects, the services and",
            "# the connections, one call each, in that order; the script stops at the first call the firewall refuses, and",
            "# what was created before it stays. Nothing is deleted. Nothing takes effect until you click Activate.",
            "set -eu",
            'DRY_RUN="${DRY_RUN:-}"',
            "COUNT=0",
            'if [ -z "$DRY_RUN" ]; then',
            '  : "${UF_API:?set UF_API to https://<firewall>:<port>/<path> of the REST API}"',
            '  if [ -z "${UF_AUTH:-}" ]; then : "${UF_TOKEN:?set UF_TOKEN to an auth token of the REST API}"; UF_AUTH="Authorization: Bearer $UF_TOKEN"; fi',
            "  HEADERS=$(mktemp) NAMES=$(mktemp)",
            "  trap 'rm -f \"$HEADERS\" \"$NAMES\"' EXIT",
            "  printf '%s\\nContent-Type: application/json\\nAccept: application/json\\n' \"$UF_AUTH\" > \"$HEADERS\"",
            "fi",
            "api() {",
            '  METHOD=$1 WHERE=$2',
            "  shift 2",
            "  # shellcheck disable=SC2086",
            '  curl -sS --fail-with-body ${UF_CURL_OPTS:-} -X "$METHOD" -H "@$HEADERS" "$@" "$UF_API/model/$WHERE"',
            "}",
            "names_free() {",
            "  # The names on stdin must not be taken in the collection $1.",
            '  if [ -n "$DRY_RUN" ]; then printf \'GET model/%s (are these names free?)\\n\' "$1"; cat; printf \'\\n\'; return 0; fi',
            '  cat > "$NAMES"',
            '  ANSWER=$(api GET "$1")',
            "  printf '%s' \"$ANSWER\" | python3 -I -c '",
            "import json, sys",
            "answer = json.load(sys.stdin)",
            "items = answer if isinstance(answer, list) else next((v for v in answer.values() if isinstance(v, list)), [answer])",
            "taken = {str(i.get(\"name\", \"\")).lower() for i in items if isinstance(i, dict)}",
            "mine = [line.strip() for line in open(sys.argv[1], encoding=\"utf-8\") if line.strip()]",
            "clash = [name for name in mine if name.lower() in taken]",
            "if clash:",
            "    sys.exit(\"these names are taken in \" + sys.argv[2] + \": \" + \", \".join(clash) + \" (convert with --target-prefix)\")",
            "' \"$NAMES\" \"$1\"",
            "}",
            "create() {",
            "  # POST the JSON on stdin to the collection $1, and keep the id of what was created in the variable $2.",
            "  COUNT=$((COUNT + 1))",
            '  if [ -n "$DRY_RUN" ]; then printf \'POST model/%s\\n\' "$1"; cat; printf \'\\n\'; eval "$2=dry-run-id-$COUNT"; return 0; fi',
            '  ANSWER=$(api POST "$1" --data-binary @-)',
            "  ID=$(printf '%s' \"$ANSWER\" | python3 -I -c '",
            "import json, sys",
            "answer = json.load(sys.stdin)",
            "if isinstance(answer, dict) and isinstance(answer.get(\"data\"), dict):",
            "    answer = answer[\"data\"]",
            "found = [answer.get(k) for k in (\"id\", \"uuid\", \"_id\") if isinstance(answer, dict) and isinstance(answer.get(k), str)]",
            "if not found:",
            "    sys.exit(\"the answer names no id of what was created\")",
            "print(found[0])",
            "')",
            '  printf \'created %s %s\\n\' "$1" "$ID"',
            '  eval "$2=\\$ID"',
            "}",
            "",
        ]
        if self.comments:
            out += [f"# {_text(comment, 200)}" for comment in self.comments]
            out.append("")
        networks = list(self.networks.values())
        services = list(self.services.values())
        if networks:
            out += ["names_free networks <<'FWSHIFT_NAMES'", *[n.name for n in networks], "FWSHIFT_NAMES"]
        if services:
            out += ["names_free userdefined-services <<'FWSHIFT_NAMES'", *[s.name for s in services], "FWSHIFT_NAMES"]
        out.append("")
        out.append("# Network objects.")
        for net in networks:
            body = {
                "name": net.name, "type": "network", "icon": "network", "interface": net.interface, "ipv4": net.cidr,
                "description": "FWShift", "tags": [], "color": 7891540, "top": 60 + 70 * (net.index % 10),
                "left": 120 + 240 * (net.index // 10), "layer": 0, "nologin": False, "exemptFromIdps": False, "exemptFromAv": False,
            }  # fmt: skip
            out += [f"create networks {net.var} <<FWSHIFT_JSON", json.dumps(body), "FWSHIFT_JSON"]
        out.append("")
        out.append("# User-defined services.")
        for svc in services:
            entries: List[Dict[str, object]] = []
            for name, low, high in svc.entries:
                entry: Dict[str, object] = {"protocol": name, "noproxy": True}
                if name in ("tcp", "udp"):
                    entry["portfrom"], entry["portto"] = low, high
                entries.append(entry)
            out += [f"create userdefined-services {svc.var} <<FWSHIFT_JSON",
                    json.dumps({"name": svc.name, "userdefined": True, "services": entries}), "FWSHIFT_JSON"]  # fmt: skip
        out.append("")
        out.append("# Desktop connections, each with its services.")
        by_var = {s.var: s for s in services}
        for (var_a, var_b), conn in self.connections.items():
            rules = []
            for rule_key, entry_sets in conn.rules.items():
                var, _, times = rule_key.partition("|")
                rules.append({
                    "uniqueId": f"${{{var}}}", "dmz": False, "natactive": _NAT_WORDS[frozenset(entry_sets["nat"])],
                    "editable": True, "timeranges": json.loads(times) if times else _ALWAYS, "action": _DIRECTION_WORDS[frozenset(entry_sets["dirs"])],
                    "log": bool(entry_sets["log"]), "applicationfilter": {"useconnection": True, "activeprofiles": []},
                    "useConnection": False, "useConnectionTrafficShaping": False,
                    "trafficShaping": {"trafficGroup": "", "outgoingDscp": None},
                })  # fmt: skip
                assert var in by_var
            points = [{"x": conn.a.index // 10 * 240 + 120, "type": "linepoint", "y": 60 + 70 * (conn.a.index % 10)},
                      {"x": conn.b.index // 10 * 240 + 120, "type": "linepoint", "y": 60 + 70 * (conn.b.index % 10)}]  # fmt: skip
            body = {
                "obja": f"${{{var_a}}}", "objb": f"${{{var_b}}}", "rules": rules,
                "description": _text("FWShift: " + ", ".join(conn.origins)), "color": 1562591, "points": points, "blockall": False,
                "webfiltersettings": [], "applicationfilter": {"mode": "off", "activeprofiles": []}, "appfilterRoutingProfiles": [],
                "trafficShaping": {"trafficGroup": "", "outgoingDscp": None},
            }  # fmt: skip
            out += [f"# {conn.a.name} - {conn.b.name}", "create desktop-connections CONNECTION <<FWSHIFT_JSON", json.dumps(body),
                    "FWSHIFT_JSON"]  # fmt: skip
        out.append("")
        out.append("echo 'Done. Look at the desktop, then click Activate.'")
        return "\n".join(out) + "\n"
