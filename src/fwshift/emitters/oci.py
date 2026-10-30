# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Oracle Cloud Infrastructure network security groups emitter: neutral model -> a shell script of OCI CLI calls.

Design rules (those of the AWS target, whose security groups an NSG resembles):

* An NSG only allows, and the rules of the NSGs of a VNIC are one set without order. A rule of the model that allows is
  written as what it matches without what the blocking rules above it match (boxes of sources, destinations and
  services, :mod:`fwshift.regions`); blocking rules are written as what they take away. That is exact, as long as no
  part has to be left out (a piece of a service an NSG rule cannot say is reported).
* A security rule names one side only: an ingress rule its source, an egress rule its destination; the other side is
  the VNIC. Every piece is written on both sides, as an ingress rule of the NSGs of its destinations and an egress rule
  of the NSGs of its sources; a connection passes when both ends allow it. Every rule is stateful. Unlike a security
  group, an NSG rule takes a source port range as well.
* The NSGs are cut by addresses: every address lies in exactly one NSG per IP version (or in several, when one would hold
  more than the 120 rules an NSG takes; a VNIC is put in all of them). The script creates the NSGs without VNICs;
  the report and the script say which addresses each one is for.
* Zones become the networks behind them (``--zone-network``), as for AWS.
* New NSGs are created, nothing that exists is changed: the script stops when an NSG of the same name exists in the VCN.
  NAT is not written (the internet gateway and the NAT gateways do it); the rules are for the private addresses. No
  security list is written or changed: a security list applies to a whole subnet and cannot be cut by address, and
  associating one replaces the lists of the subnet.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, FrozenSet, List, Optional, Set, Tuple

from .. import names, regions, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, interval_text, normalize, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_RULES_PER_NSG = 120  # ingress and egress together
_NSGS_PER_VNIC = 5
_PER_CALL = 25  # rules per AddNetworkSecurityGroupSecurityRules
_DESCRIPTION = re.compile(r"[^A-Za-z0-9 ._\-:/()#,@\[\]+=;{}!$*]")
# protocol ("all", or the number), then for TCP and UDP the source and the destination port range, for ICMP the type and
# the code (-1 where there is none)
Perm = Tuple[str, int, int, int, int]
_ALL: Perm = ("all", -1, -1, -1, -1)


def emit(policy: Policy, report: Report, options: Options) -> str:
    return _Emitter(prepare(policy, report, options), report, options, transform.rule_zones(policy)).run()


def prepare(policy: Policy, report: Report, options: Options) -> Policy:
    """The policy as the NSGs see it (a copy): zones mapped, the destinations after NAT."""
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)  # refuses networks that contradict each other
    # The internet gateway translates public addresses to private ones before a VNIC sees a connection, and a NAT
    # gateway translates sources after: the rules see the private addresses. The NAT rules are not written.
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return p


def _description(text: str) -> str:
    return _DESCRIPTION.sub("_", text)[:255]


def _cidrs(interval: Interval) -> List[str]:
    version, first, last = interval
    return [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]


def _cidrs_all(intervals: List[Interval]) -> List[str]:
    return [c for interval in intervals for c in _cidrs(interval)]


@dataclass
class _Piece:
    """Part of what a rule allows, and how an NSG rule says its services."""

    box: regions.Box
    perms: List[Perm]
    origin: str
    name: str


@dataclass
class _Group:
    name: str
    var: str
    attach: List[Interval]
    inbound: Dict[Tuple[int, Perm], List[Interval]] = field(default_factory=dict)  # (version, perm) -> sources
    outbound: Dict[Tuple[int, Perm], List[Interval]] = field(default_factory=dict)
    rules_in: Dict[Tuple[int, Perm], List[str]] = field(default_factory=dict)  # the rules each comes from
    rules_out: Dict[Tuple[int, Perm], List[str]] = field(default_factory=dict)
    parts: List[Tuple[str, str, List[Dict[str, object]]]] = field(default_factory=list)  # (name, variable, its rules)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options, self.source_zones = p, report, options, source_zones
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))
        self.denies: List[regions.Box] = []
        self.pieces: List[_Piece] = []
        self.comments: List[str] = []
        self.dropped: Set[str] = set()
        self.inside = self._inside()

    def _inside(self) -> Optional[List[Interval]]:
        """The addresses inside the VCN, where the VNICs are: the networks of --inside-zone, and for an OCI source the VCN
        it was read from. None when not known: then every address gets an NSG, and both ends say everything."""
        found: List[Interval] = []
        for zone in self.options.inside_zones:
            if zone not in self.spaces:
                raise FwshiftError(f"--inside-zone {zone}: give the networks behind it with --zone-network")
            found += self.spaces[zone]
        vcns = [name for name, group in self.p.address_groups.items() if group.builtin == "oci" and not group.unsupported]
        for name in vcns:
            found += transform.known_intervals(self.p, name)[0]
        return normalize(found) if self.options.inside_zones or vcns else None

    # -- what a rule matches --------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found = [FULL_V4, FULL_V6]
                break
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; an NSG rule names "
                                    "addresses"))  # fmt: skip
                return None
            found += intervals
        found = normalize(found)
        return subtract([FULL_V4, FULL_V6], found) if negated else found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: List[Interval], reasons: List[transform.Reason]) -> List[Interval]:
        """The addresses of one side, kept to the zones of the rule (as the AWS and NSX emitters do)."""
        if rule.action == Action.ALLOW:
            missing = [zone for zone in zones if zone not in self.spaces]
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and an NSG names no zone: give the "
                                f"networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return found
            kept = intersect(found, normalize([i for zone in zones for i in self.spaces[zone]]))
            if kept != found:
                self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} in zone {', '.join(zones)} is written as the addresses of the networks given for it "
                                "with --zone-network")  # fmt: skip
            return kept
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others):
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; an NSG names no zone, and it "
                            "blocks that traffic in every zone. Give the networks behind every zone with --zone-network to keep "
                            "it to its zones")  # fmt: skip
            return found
        kept = subtract(found, normalize([i for zone in others for i in self.spaces[zone]]))
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
        return kept

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        # (A rule for traffic inside its zones names the zones once: its destination zones say nothing.)
        zones = rule.src_zones if source or rule.scope == RuleScope.INTRAZONE else rule.dst_zones
        side = "source" if source else "destination"
        found = self._resolve(members, negated, side, reasons)
        if found is None:
            return None
        if ANY in zones or (not source and rule.egress_implied and rule.scope != RuleScope.INTRAZONE):
            return found
        return self._confine(rule, side, zones, found, reasons)

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
        allow = rule.action == Action.ALLOW
        if any(e.protocol == Protocol.SCTP and (e.dst_ports or e.src_ports) for e in entries):
            if allow:
                reasons.append(("SERVICE_SCTP", "SCTP ports: an NSG rule has ports for TCP and UDP only, and would allow every SCTP port"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "SERVICE_SCTP",
                                "the rule blocks certain SCTP ports; it is written for every SCTP port, which blocks more")  # fmt: skip
                sctp = [e for e in entries if e.protocol == Protocol.SCTP and (e.dst_ports or e.src_ports)]
                entries = [e for e in entries if e not in sctp] if rule.negate_service else \
                    [_without_ports(e) if e in sctp else e for e in entries]
        found = regions.ALL_SERVICES if lowered is None and rule.services == [ANY] else regions.service_set(entries)
        if found is None:
            reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
            return None
        if rule.negate_service:
            found = regions.ALL_SERVICES.minus(found)
        return found

    def _region(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[regions.Box]]:
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        services = self._services(rule, reasons)
        if sources is None or destinations is None or services is None:
            return None
        out: List[regions.Box] = []
        for version in (4, 6):
            src, dst = regions.addresses(sources, version), regions.addresses(destinations, version)
            if src and dst and not services.empty():
                out.append((version, src, dst, services))
        return out

    # -- rules ----------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.comments.append(f"rule {rule.name}: {'disabled by the audit' if by_audit else 'disabled in the source'}, not written")
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: an NSG names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written for every pair of its zones, which blocks more")  # fmt: skip
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": an NSG rule names addresses"))
        boxes = self._region(rule, reasons)
        if fqdn:
            reasons = [reason for reason in reasons if reason[0] != "ADDRESS_UNKNOWN"]
        reasons = list(dict.fromkeys(reasons))
        if reasons or boxes is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")])
            self.comments.append(f"rule {rule.name}: not written, see the report")
            return
        if not boxes:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation and the networks of its zones, the rule matches no connection", Severity.INFO)  # fmt: skip
            return
        if not allow:
            self.denies += boxes
            item.emitted_as.append("taken out of the rules below it")
            if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH, Action.DENY):
                self.report.add("rule", rule.origin, Severity.INFO, "ACTION_DROP",
                                f"action {rule.action.value}: an NSG drops what it does not allow, without an answer")  # fmt: skip
            return
        self._allow(boxes, rule.origin, rule.name)

    def _allow(self, boxes: List[regions.Box], origin: str, name: str) -> None:
        left = regions.minus_all(boxes, self.denies)
        if left is None:
            self.report.disable("rule", origin, "OCI_TOO_COMPLEX",
                                "what the rule allows without what the blocking rules above it block falls apart into more pieces "
                                "than are written; the rule is not written")  # fmt: skip
            self.comments.append(f"rule {name}: not written, see the report")
            return
        if not left:
            self.report.skip("rule", origin, "SHADOWED_BY_DENY",
                             "everything the rule allows is blocked by the rules above it; there is nothing to write", Severity.INFO)  # fmt: skip
            return
        if len(left) != len(boxes) or any(a != b for a, b in zip(left, boxes)):
            self.report.add("rule", origin, Severity.INFO, "DENY_SUBTRACTED",
                            "an NSG cannot block: the rule is written without what the blocking rules above it match")  # fmt: skip
        for box in left:
            perms, dropped = self._perms(box)
            if dropped and origin not in self.dropped:
                self.dropped.add(origin)
                self.report.add("rule", origin, Severity.REVIEW, "OCI_PART_NOT_WRITTEN",
                                "part of what the rule allows cannot be said by an NSG rule (every protocol but some, ports of SCTP "
                                "or many ICMP codes) and is not written; the converted rule allows less")  # fmt: skip
            if perms:
                self.pieces.append(_Piece(box, perms, origin, name))

    @staticmethod
    def _perms(box: regions.Box) -> Tuple[List[Perm], bool]:
        version, _, _, svc = box
        if svc.everything():
            return [_ALL], False
        icmp, foreign = (1, 58) if version == 4 else (58, 1)
        out: List[Perm] = []
        dropped = False
        ports: Dict[str, List[Tuple[int, int, int, int]]] = {"6": [], "17": []}
        listed = set(svc.protocols)
        for number in sorted(listed):
            if number == foreign:
                continue
            for rect in svc.protocols[number]:
                if number in (6, 17):
                    ports[str(number)].append(rect)
                elif number == icmp:
                    types = regions.icmp_values(rect[0], rect[1])
                    codes = regions.icmp_values(rect[2], rect[3])
                    if types is None or codes is None:
                        continue
                    if types == [None] and codes == [None]:
                        out.append((str(icmp), -1, -1, -1, -1))
                        continue
                    if types == [None]:
                        types = list(range(256))
                    if len(types) * len(codes) > 256:
                        dropped = True
                        continue
                    out += [(str(icmp), kind if kind is not None else -1, code if code is not None else -1, -1, -1)
                            for kind in types for code in codes]  # fmt: skip
                elif rect != regions.WHOLE:
                    dropped = True
                else:
                    out.append((str(number), -1, -1, -1, -1))
        if svc.rest:
            for label in ("6", "17"):
                if int(label) not in listed:
                    ports[label].append(regions.WHOLE)
            if icmp not in listed:
                out.append((str(icmp), -1, -1, -1, -1))
            dropped = True  # every other protocol but some: an NSG rule says "all" or one protocol
        for label in ("6", "17"):
            by_source: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
            for rect in ports[label]:
                by_source.setdefault((rect[0], rect[1]), []).append((rect[2], rect[3]))
            for (low, high), destinations in by_source.items():
                out += [(label, low, high, d_low, d_high) for d_low, d_high in regions.merge_ranges(destinations)]
        return sorted(set(out), key=_perm_key), dropped

    def _fqdn(self, members: List[str]) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        todo = list(members)
        while todo:
            member = todo.pop()
            if member in seen:
                continue
            seen.add(member)
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                out.append(member)
            elif member in self.p.address_groups:
                todo += self.p.address_groups[member].members
        return sorted(out)

    def _defaults(self) -> None:
        """What no rule matches: allowed where the source allows it, as a last rule."""
        inter = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.universe, self.report)
        everything = [(v, [regions.full(v)], [regions.full(v)], regions.ALL_SERVICES) for v in (4, 6)]
        if inter and all(decided.values()):
            self._allow(everything, "(default)", "default")
            self.report.note(Severity.REVIEW, "OCI_DEFAULT_ALLOW",
                             "the source allows what no rule matches: written as rules that allow everything the blocking rules do "
                             "not block")  # fmt: skip
            return
        open_zones = [zone for zone in self.universe if decided[zone]]
        same: List[regions.Box] = []
        missing: List[str] = []
        for zone in self.universe:
            if inter and decided[zone]:
                continue
            if zone not in self.spaces:
                missing.append(zone)
                continue
            for version in (4, 6):
                space = regions.addresses(self.spaces[zone], version)
                if space:
                    same.append((version, space, space, regions.ALL_SERVICES))
        if inter:
            if missing:
                self.report.note(Severity.REVIEW, "OCI_DEFAULT_NOT_WRITTEN",
                                 "the source allows what no rule matches between zones, and blocks it inside some zones; that "
                                 "needs the networks of those zones (--zone-network), and these have none: " + ", ".join(missing)
                                 + ". It is not written")  # fmt: skip
                return
            left = regions.minus_all(everything, same, limit=4096)
            if left:
                self._allow(left, "(default)", "default")
            self.report.note(Severity.REVIEW, "OCI_DEFAULT_ALLOW",
                             "the source allows what no rule matches between zones: written as rules that allow it")  # fmt: skip
            return
        written = [box for box in same for zone in open_zones if zone in self.spaces
                   and box[1] == regions.addresses(self.spaces[zone], box[0])]  # fmt: skip
        if written:
            self._allow(written, "(default)", "default")
        lost = [zone for zone in open_zones if zone not in self.spaces]
        if lost:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic inside them without a rule; without their networks (--zone-network) that is "
                             "not written: " + ", ".join(lost))  # fmt: skip

    # -- NSGs -------------------------------------------------------------------------

    def _groups(self) -> List[_Group]:
        """Cut the addresses where pieces begin and end; an address gets the pieces whose sources or destinations hold it."""
        groups: List[_Group] = []
        contents: Dict[FrozenSet[Tuple[str, int, Perm, Tuple[Interval, ...]]], _Group] = {}
        empty_attach: List[Interval] = []
        for version in (4, 6):
            top = regions.full(version)[2]
            cuts = {0, top + 1}
            inside = None if self.inside is None else regions.addresses(self.inside, version)
            for interval in inside or []:
                cuts.update((interval[1], interval[2] + 1))
            mine = [(index, piece) for index, piece in enumerate(self.pieces) if piece.box[0] == version]
            for _, piece in mine:
                for interval in piece.box[1] + piece.box[2]:
                    cuts.update((interval[1], interval[2] + 1))
            bounds = sorted(cuts)
            position = {value: index for index, value in enumerate(bounds)}
            inbound: List[Set[int]] = [set() for _ in range(len(bounds) - 1)]
            outbound: List[Set[int]] = [set() for _ in range(len(bounds) - 1)]
            for index, piece in mine:
                for interval in piece.box[2]:
                    for segment in range(position[interval[1]], position[interval[2] + 1]):
                        inbound[segment].add(index)
                for interval in piece.box[1]:
                    for segment in range(position[interval[1]], position[interval[2] + 1]):
                        outbound[segment].add(index)
            profiles: Dict[Tuple[FrozenSet[int], FrozenSet[int]], List[Interval]] = {}
            for segment in range(len(bounds) - 1):
                interval = (version, bounds[segment], bounds[segment + 1] - 1)
                if inside is not None and not intersect([interval], inside):
                    continue  # outside the VCN: no VNIC there gets an NSG
                key = (frozenset(inbound[segment]), frozenset(outbound[segment]))
                profiles.setdefault(key, []).append(interval)
            for (ins, outs), segments in profiles.items():
                if not ins and not outs:
                    empty_attach += segments
                    continue
                group = _Group("", "", normalize(segments))
                for index in sorted(ins):
                    piece = self.pieces[index]
                    for perm in piece.perms:
                        group.inbound.setdefault((version, perm), []).extend(piece.box[1])
                        group.rules_in.setdefault((version, perm), []).append(piece.name)
                for index in sorted(outs):
                    piece = self.pieces[index]
                    for perm in piece.perms:
                        # Inside the VCN the ingress rules of the destination's NSG decide: egress may allow it all. (Not its
                        # public addresses: what is sent there comes back through the internet gateway.)
                        group.outbound.setdefault((version, perm), []).extend(piece.box[2] + (inside or []))
                        group.rules_out.setdefault((version, perm), []).append(piece.name)
                group.inbound = _without_covered({key: normalize(value) for key, value in group.inbound.items()})
                group.outbound = _without_covered({key: normalize(value) for key, value in group.outbound.items()})
                content = frozenset([("in", v, perm, tuple(ivs)) for (v, perm), ivs in group.inbound.items()]
                                    + [("out", v, perm, tuple(ivs)) for (v, perm), ivs in group.outbound.items()])  # fmt: skip
                if content in contents:
                    known = contents[content]
                    known.attach = normalize(known.attach + group.attach)
                    continue
                contents[content] = group
                groups.append(group)
        groups.sort(key=lambda g: g.attach[0])
        if empty_attach:
            groups.append(_Group("", "", normalize(empty_attach)))
        self._names(groups)
        return groups

    def _names(self, groups: List[_Group]) -> None:
        known: Dict[Tuple[Interval, ...], str] = {}
        for name in sorted(self.p.address_groups) + sorted(self.p.addresses):
            if name in self.taint_a:
                continue
            intervals, complete = transform.known_intervals(self.p, name)
            if complete and intervals:
                for version in (4, 6):
                    mine = tuple(regions.addresses(intervals, version))
                    if mine:
                        known.setdefault(mine, name)
        taken: Set[str] = set()
        prefix = self.options.object_prefix or "fwshift-"
        number = 0
        for group in groups:
            if not group.inbound and not group.outbound:
                label = "no-rules"
            else:
                label = known.get(tuple(group.attach), "") or self._zone_of(group.attach) or "addresses"
                if {i[0] for i in group.attach} == {6}:
                    label += "-ipv6"
            base = names.clean(re.sub(r"[^A-Za-z0-9._-]+", "-", prefix + label).strip("-") or "fwshift", names.OCI)
            rules = self._security_rules(group)
            chunks = [rules[start:start + _RULES_PER_NSG] for start in range(0, len(rules), _RULES_PER_NSG)] or [[]]
            for index, chunk in enumerate(chunks, 1):
                candidate, counter = base if index == 1 else f"{base}-part{index}", 2
                while candidate.lower() in taken:
                    candidate = f"{base}-{counter}" if index == 1 else f"{base}-part{index}-{counter}"
                    counter += 1
                taken.add(candidate.lower())
                number += 1
                group.parts.append((candidate, f"G{number}", chunk))
            group.name, group.var = group.parts[0][0], group.parts[0][1]

    def _zone_of(self, attach: List[Interval]) -> str:
        for zone in sorted(self.spaces):
            if attach and all(intersect([interval], self.spaces[zone]) == [interval] for interval in attach):
                return zone
        return ""

    def _security_rules(self, group: _Group) -> List[Dict[str, object]]:
        """The rules of an NSG as AddSecurityRuleDetails, one per address block."""
        out: List[Dict[str, object]] = []
        for direction, entries, rules in (("INGRESS", group.inbound, group.rules_in), ("EGRESS", group.outbound, group.rules_out)):
            side = "source" if direction == "INGRESS" else "destination"
            for (version, perm) in sorted(entries, key=lambda k: (k[0], _perm_key(k[1]))):
                description = _description("FWShift: " + ", ".join(transform.dedupe(rules[(version, perm)])))
                for cidr in _cidrs_all(entries[(version, perm)]):
                    item: Dict[str, object] = {"description": description, "direction": direction, "isStateless": False,
                                               "protocol": perm[0], side: cidr, side + "Type": "CIDR_BLOCK"}  # fmt: skip
                    item.update(_options(perm))
                    out.append(item)
        return out

    # -- output -----------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: on OCI the internet gateway translates public addresses and a NAT gateway translates "
                             "sources, outside the NSGs. Set them up there; the rules were written for the private addresses, which "
                             "is what the NSGs see")  # fmt: skip
        groups = self._groups()
        self._emitted(groups)
        self._notes(groups)
        return self._script(groups)

    def _emitted(self, groups: List[_Group]) -> None:
        by_rule: Dict[str, List[str]] = {}
        origins = {piece.name: piece.origin for piece in self.pieces}
        for group in groups:
            for rules in list(group.rules_in.values()) + list(group.rules_out.values()):
                for rule in rules:
                    if group.name not in by_rule.setdefault(origins[rule], []):
                        by_rule[origins[rule]].append(group.name)
        for origin, written in by_rule.items():
            if origin != "(default)":
                self.report.item("rule", origin).emitted_as.append("NSGs " + ", ".join(written))

    def _script(self, groups: List[_Group]) -> str:
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: OCI network security groups for one VCN, created with the OCI CLI. Read the report",
            "# first: what is not written is listed there.",
            "#",
            "#   DRY_RUN=1 sh THIS_FILE                                   prints the calls, makes none (no OCI access needed)",
            "#   COMPARTMENT_ID=ocid1.compartment... VCN_ID=ocid1.vcn... sh THIS_FILE",
            "#                                                            creates the NSGs and their rules",
            "#",
            "# OCI_OPTS adds options to every call, for example OCI_OPTS='--profile PROD --region eu-frankfurt-1'.",
            "#",
            "# The NSGs are created WITHOUT VNICs: nothing changes for any traffic until VNICs are put in them. Put each VNIC",
            "# in every NSG whose list (# attach ...) holds one of its addresses, and in no other. The security lists of the",
            "# subnets keep applying: OCI allows what a rule of either allows. An NSG of the same name in the VCN stops the",
            "# script before anything is created; a call OCI refuses stops it where it is (delete the NSGs it made with",
            "# oci network nsg delete --nsg-id ... --force, and run it again). Every rule is stateful.",
            "set -u",
            'DRY_RUN="${DRY_RUN:-}"',
            'OCI_OPTS="${OCI_OPTS:-}"',
            'if [ -z "$DRY_RUN" ]; then',
            '  : "${COMPARTMENT_ID:?set COMPARTMENT_ID to the OCID of the compartment for the NSGs, or DRY_RUN=1 to print the calls}"',
            '  : "${VCN_ID:?set VCN_ID to the OCID of the VCN, or DRY_RUN=1 to print the calls}"',
            "else",
            '  COMPARTMENT_ID="${COMPARTMENT_ID:-ocid1.compartment.oc1..dryrun}"',
            '  VCN_ID="${VCN_ID:-ocid1.vcn.oc1..dryrun}"',
            "fi",
            "fail() { printf 'FAILED: %s\\n' \"$*\" >&2; exit 1; }",
            "show() { printf 'oci' >&2; printf ' %s' \"$@\" >&2; printf '\\n' >&2; }",
            "# free NAME: stops the script when the VCN has an NSG of that name that is not terminated",
            "free() {",
            '  if [ -n "$DRY_RUN" ]; then return 0; fi',
            '  found=$(oci network nsg list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --display-name "$1" --all '
            "--query \"length(data[?\\\"lifecycle-state\\\" != 'TERMINATED'])\" --raw-output $OCI_OPTS) || fail \"nsg list: $found\"",
            '  case "$found" in ""|0) return 0 ;; esac',
            '  fail "an NSG named $1 exists in $VCN_ID already; nothing was created"',
            "}",
            "# nsg NAME: creates an NSG without rules and prints its OCID",
            "nsg() {",
            '  if [ -n "$DRY_RUN" ]; then show network nsg create --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" '
            "--display-name \"$1\"; printf 'ocid1.networksecuritygroup.dryrun.%s\\n' \"$1\"; return 0; fi",
            '  id=$(oci network nsg create --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --display-name "$1" '
            "--freeform-tags '{\"fwshift\":\"generated\"}' --wait-for-state AVAILABLE --query data.id --raw-output $OCI_OPTS) "
            '|| fail "nsg create $1"',
            '  case "$id" in ocid1.networksecuritygroup.*) ;; *) fail "nsg create $1: no OCID in the answer" ;; esac',
            "  printf 'created %s %s\\n' \"$1\" \"$id\" >&2",
            "  printf '%s\\n' \"$id\"",
            "}",
            "# rules NSG: adds the rules on standard input, a JSON list of at most 25 (AddSecurityRuleDetails)",
            "rules() {",
            "  json=$(cat)",
            '  if [ -n "$DRY_RUN" ]; then show network nsg rules add --nsg-id "$1" --security-rules "$json"; return 0; fi',
            '  oci network nsg rules add --nsg-id "$1" --security-rules "$json" $OCI_OPTS >/dev/null || fail "nsg rules add $1"',
            "}",
            "",
            "# No NSG of these names may exist.",
        ]
        out += [f"free '{name}'" for group in groups for name, _, _ in group.parts]
        out += ["", "# The NSGs, each with the addresses of the VNICs it is for."]
        for group in groups:
            attach = " ".join(interval_text(i) for i in group.attach)
            for name, var, _ in group.parts:
                out.append(f"# attach {name}: {attach}")
                out.append(f"{var}=$(nsg '{name}') || exit 1")
        out += ["", "# Their rules: ingress rules name the sources, egress rules the destinations."]
        for group in groups:
            for _, var, chunk in group.parts:
                for start in range(0, len(chunk), _PER_CALL):
                    out.append(f"rules \"${var}\" <<'FWSHIFT_JSON'")
                    out.append(json.dumps(chunk[start:start + _PER_CALL], ensure_ascii=True, sort_keys=True))
                    out.append("FWSHIFT_JSON")
        if self.comments:
            out += ["", "# Not written:"] + [f"#   {line}" for line in self.comments]
        out += ["", "echo 'Done. Put the VNICs in the NSGs the comments above name; until then nothing changes.' >&2"]
        return "\n".join(out) + "\n"

    def _notes(self, groups: List[_Group]) -> None:
        self.report.note(
            Severity.REVIEW, "OCI_LOAD",
            "the output is a shell script of OCI CLI calls (section 10): DRY_RUN=1 prints them, COMPARTMENT_ID and VCN_ID "
            "create the NSGs and their rules. It creates new NSGs only, and stops if an NSG of the same name exists in the VCN. "
            "The NSGs have no VNICs when it is done: nothing changes until VNICs are put in them",
        )  # fmt: skip
        if groups:
            count = sum(len(g.parts) for g in groups)
            self.report.note(
                Severity.REVIEW, "OCI_ATTACH",
                f"{count} NSG{'' if count == 1 else 's'}: put each VNIC in the NSGs whose '# attach' line lists its addresses, and take it "
                "out of the others; a VNIC with addresses of both IP versions is in an NSG for each. An NSG applies to the whole "
                "VNIC: a VNIC with several addresses of one IP version in different NSGs gives each address the rules of all of "
                "them, so give such addresses the same NSG. 'oci network vnic update --nsg-ids' replaces the NSGs of a VNIC: it is "
                "left to you",
            )  # fmt: skip
            self.report.note(
                Severity.REVIEW, "OCI_SECURITY_LISTS",
                "the security lists of the VNICs' subnets keep applying, and OCI allows what a rule of a security list or of an NSG "
                "allows: for the VNICs to be held to what the NSGs allow, their subnets need security lists that allow no more "
                "(the default security list of a VCN allows SSH from anywhere and every egress)",
            )  # fmt: skip
        split = [f"{g.name} ({len(g.parts)} NSGs)" for g in groups if len(g.parts) > 1]
        crowded = [g.name for g in groups if len(g.parts) > _NSGS_PER_VNIC - 1]
        if split:
            self.report.note(Severity.REVIEW, "OCI_RULE_LIMIT",
                             f"an NSG takes {_RULES_PER_NSG} rules, so these were split and a VNIC goes in every part: " + ", ".join(split)
                             + (f". A VNIC can be in {_NSGS_PER_VNIC} NSGs, one of them for its other IP version: these need too "
                                "many: " + ", ".join(crowded) if crowded else ""))  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; an NSG does not. VCN flow logs record the connections of the subnets or "
                             "VNICs instead")  # fmt: skip


def _options(perm: Perm) -> Dict[str, object]:
    protocol, a, b, c, d = perm
    if protocol in ("6", "17"):
        node: Dict[str, object] = {}
        if (c, d) != (0, 65535):
            node["destinationPortRange"] = {"max": d, "min": c}
        if (a, b) != (0, 65535):
            node["sourcePortRange"] = {"max": b, "min": a}
        return {"tcpOptions" if protocol == "6" else "udpOptions": node} if node else {}
    if protocol in ("1", "58") and a >= 0:
        icmp: Dict[str, object] = {"type": a}
        if b >= 0:
            icmp["code"] = b
        return {"icmpOptions": icmp}
    return {}


def _without_covered(entries: Dict[Tuple[int, Perm], List[Interval]]) -> Dict[Tuple[int, Perm], List[Interval]]:
    """Leave out the addresses of a protocol entry that the entry for all protocols holds already."""
    out: Dict[Tuple[int, Perm], List[Interval]] = {}
    for (version, perm), intervals in entries.items():
        every = entries.get((version, _ALL), [])
        rest = intervals if perm == _ALL else subtract(intervals, every)
        if rest:
            out[(version, perm)] = rest
    return out


def _perm_key(perm: Perm) -> Tuple[int, int, int, int, int, int]:
    order = {"all": 0, "6": 1, "17": 2, "1": 3, "58": 4}
    return (order.get(perm[0], 5), int(perm[0]) if perm[0].isdigit() else -1, perm[1], perm[2], perm[3], perm[4])


def _without_ports(entry: ServiceEntry) -> ServiceEntry:
    out = copy.copy(entry)
    out.src_ports, out.dst_ports = "", ""
    return out
