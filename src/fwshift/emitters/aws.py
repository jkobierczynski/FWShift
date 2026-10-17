# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS EC2 security groups emitter: neutral model -> a shell script of AWS CLI calls.

Design rules:

* A security group only allows, and the rules of the groups of an interface are one set without order. A rule of the
  model that allows is written as what it matches without what the blocking rules above it match (boxes of sources,
  destinations and services, :mod:`fwshift.regions`); blocking rules are written as what they take away. That is
  exact, as long as no part has to be left out (a piece of a service a security group cannot say is reported).
* A rule of a security group names one side only: an inbound rule its sources, an outbound rule its destinations; the
  other side is the interface the group is attached to. Every piece is written on both sides: as an inbound rule of
  the groups of its destinations and as an outbound rule of the groups of its sources. A connection passes when both
  ends allow it, so each end may let through only what the policy allows between the two, and does.
* The groups are cut by addresses: every address lies in exactly one group per IP version, and a group holds the
  pieces whose sources or destinations hold its addresses. The script creates the groups without members; the
  report and the script say which addresses each one is for. An address that no rule names gets a group without
  rules.
* Zones become the networks behind them (``--zone-network``), as for NSX.
* New groups are created, nothing that exists is changed: the script stops when a group of the same name exists.
  NAT is not written (the internet gateway and the NAT gateways do it); the rules are for the private addresses.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, FrozenSet, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, interval_text, normalize, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_QUOTA = 60  # rules per group, direction and IP version, unless the quota was raised
_PER_CALL = 50  # address ranges per call
_DESCRIPTION = re.compile(r"[^A-Za-z0-9 ._\-:/()#,@\[\]+=;{}!$*]")
Perm = Tuple[str, int, int]  # protocol (AWS spelling, "-1" for all), from port, to port (-1 where AWS has none)


def emit(policy: Policy, report: Report, options: Options) -> str:
    return _Emitter(prepare(policy, report, options), report, options, transform.rule_zones(policy)).run()


def prepare(policy: Policy, report: Report, options: Options) -> Policy:
    """The policy as the security groups see it (a copy): zones mapped, the destinations after NAT."""
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)  # refuses networks that contradict each other
    # The internet gateway translates public addresses to private ones before a group sees a connection, and a NAT
    # gateway translates sources after: the groups see the private addresses. The NAT rules are not written.
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


@dataclass
class _Piece:
    """Part of what a rule allows, and how a security group says its services."""

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
        """The addresses inside the VPC, where the interfaces are: the networks of --inside-zone, and for an AWS source the
        VPC it was read from. None when not known: then every address gets a group, and both ends say everything."""
        found: List[Interval] = []
        for zone in self.options.inside_zones:
            if zone not in self.spaces:
                raise FwshiftError(f"--inside-zone {zone}: give the networks behind it with --zone-network")
            found += self.spaces[zone]
        vpcs = [name for name, group in self.p.address_groups.items() if group.builtin == "aws" and not group.unsupported]
        for name in vpcs:
            found += transform.known_intervals(self.p, name)[0]
        return normalize(found) if self.options.inside_zones or vpcs else None

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
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; a security group "
                                    "rule names addresses"))  # fmt: skip
                return None
            found += intervals
        found = normalize(found)
        return subtract([FULL_V4, FULL_V6], found) if negated else found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: List[Interval], reasons: List[transform.Reason]) -> List[Interval]:
        """The addresses of one side, kept to the zones of the rule (as the NSX and Barracuda emitters do)."""
        if rule.action == Action.ALLOW:
            missing = [zone for zone in zones if zone not in self.spaces]
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and a security group names no zone: give "
                                f"the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
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
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a security group names no zone, "
                            "and it blocks that traffic in every zone. Give the networks behind every zone with --zone-network "
                            "to keep it to its zones")  # fmt: skip
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
        if any(e.src_ports for e in entries):
            if allow:
                reasons.append(("SOURCE_PORTS", "source ports: a security group rule matches destination ports only"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "SOURCE_PORTS_WIDENED",
                                "the rule blocks certain source ports only; it is written for every source port, which blocks more")  # fmt: skip
                # (Under a negation, an entry that is left out makes the rule block more; one widened, less.)
                entries = [e for e in entries if not e.src_ports] if rule.negate_service else [_without_source_ports(e) for e in entries]
        if any(e.protocol == Protocol.SCTP and e.dst_ports for e in entries):
            if allow:
                reasons.append(("SERVICE_SCTP", "SCTP ports: a security group ignores the ports of SCTP, and would allow every one"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "SERVICE_SCTP",
                                "the rule blocks certain SCTP ports; it is written for every SCTP port, which blocks more")  # fmt: skip
                sctp = [e for e in entries if e.protocol == Protocol.SCTP and e.dst_ports]
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
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a security group names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written for every pair of its zones, which blocks more")  # fmt: skip
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": a security group names addresses"))
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
                                f"action {rule.action.value}: a security group drops what it does not allow, without an answer")  # fmt: skip
            return
        self._allow(boxes, rule.origin, rule.name)

    def _allow(self, boxes: List[regions.Box], origin: str, name: str) -> None:
        left = regions.minus_all(boxes, self.denies)
        if left is None:
            self.report.disable("rule", origin, "AWS_TOO_COMPLEX",
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
                            "a security group cannot block: the rule is written without what the blocking rules above it match")  # fmt: skip
        for box in left:
            perms, dropped = self._perms(box)
            if dropped and origin not in self.dropped:
                self.dropped.add(origin)
                self.report.add("rule", origin, Severity.REVIEW, "AWS_PART_NOT_WRITTEN",
                                "part of what the rule allows cannot be said by a security group (every protocol but some, a range "
                                "of source ports, ports of SCTP or many ICMP codes) and is not written; the converted rule allows "
                                "less")  # fmt: skip
            if perms:
                self.pieces.append(_Piece(box, perms, origin, name))

    @staticmethod
    def _perms(box: regions.Box) -> Tuple[List[Perm], bool]:
        version, _, _, svc = box
        if svc.everything():
            return [("-1", -1, -1)], False
        icmp, foreign = (1, 58) if version == 4 else (58, 1)
        out: List[Perm] = []
        dropped = False
        ports: Dict[str, List[Tuple[int, int]]] = {"tcp": [], "udp": []}
        listed = set(svc.protocols)
        for number in sorted(listed):
            if number == foreign:
                continue
            for rect in svc.protocols[number]:
                if number in (6, 17):
                    if (rect[0], rect[1]) != (0, 65535):
                        dropped = True
                        continue
                    ports["tcp" if number == 6 else "udp"].append((rect[2], rect[3]))
                elif number == icmp:
                    label = "icmp" if number == 1 else "icmpv6"
                    types = regions.icmp_values(rect[0], rect[1])
                    codes = regions.icmp_values(rect[2], rect[3])
                    if types is None or codes is None:
                        continue
                    if types == [None] and codes == [None]:
                        out.append((label, -1, -1))
                        continue
                    if types == [None]:
                        types = list(range(256))
                    if len(types) * len(codes) > 256:
                        dropped = True
                        continue
                    out += [(label, kind if kind is not None else -1, code if code is not None else -1) for kind in types for code in codes]
                elif rect != regions.WHOLE:
                    dropped = True
                else:
                    out.append((str(number), -1, -1))
        if svc.rest:
            for number, label in ((6, "tcp"), (17, "udp")):
                if number not in listed:
                    ports[label].append((0, 65535))
            if icmp not in listed:
                out.append(("icmp" if icmp == 1 else "icmpv6", -1, -1))
            dropped = True  # every other protocol but some: a security group says "all protocols" or one
        for label in ("tcp", "udp"):
            out += [(label, low, high) for low, high in regions.merge_ranges(ports[label])]
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
            self.report.note(Severity.REVIEW, "AWS_DEFAULT_ALLOW",
                             "the source allows what no rule matches: written as rules that allow everything the blocking rules do "
                             "not block")  # fmt: skip
            return
        open_zones = [zone for zone in self.universe if decided[zone]]
        same: List[regions.Box] = []
        missing: List[str] = []
        for zone in self.universe:
            if inter and decided[zone]:
                continue  # (between zones the source allows, and inside this one too: nothing to leave out)
            if zone not in self.spaces:
                missing.append(zone)
                continue
            for version in (4, 6):
                space = regions.addresses(self.spaces[zone], version)
                if space:
                    same.append((version, space, space, regions.ALL_SERVICES))
        if inter:
            if missing:
                self.report.note(Severity.REVIEW, "AWS_DEFAULT_NOT_WRITTEN",
                                 "the source allows what no rule matches between zones, and blocks it inside some zones; that "
                                 "needs the networks of those zones (--zone-network), and these have none: " + ", ".join(missing)
                                 + ". It is not written")  # fmt: skip
                return
            left = regions.minus_all(everything, same, limit=4096)
            if left:
                self._allow(left, "(default)", "default")
            self.report.note(Severity.REVIEW, "AWS_DEFAULT_ALLOW",
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

    # -- groups -----------------------------------------------------------------------

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
                    continue  # outside the VPC: no interface there gets a group
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
                        # Inside the VPC the inbound rules of the destination's group decide: outbound may allow it all. (Not its
                        # public addresses: what is sent there comes back through the internet gateway from the source's
                        # public address, which the inbound rules may allow for other reasons.)
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
        # Groups before single objects, and among them the ones that do not hold every address of others.
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
        for number, group in enumerate(groups, 1):
            if not group.inbound and not group.outbound:
                label = "no-rules"
            else:
                label = known.get(tuple(group.attach), "") or self._zone_of(group.attach) or "addresses"
                if {i[0] for i in group.attach} == {6}:
                    label += "-ipv6"
            base = re.sub(r"[^A-Za-z0-9._-]+", "-", prefix + label).strip("-")[:200] or "fwshift"
            if base.lower().startswith("sg-"):
                base = "fwshift-" + base
            candidate, counter = base, 2
            while candidate.lower() in taken:
                candidate = f"{base}-{counter}"
                counter += 1
            taken.add(candidate.lower())
            group.name, group.var = candidate, f"G{number}"

    def _zone_of(self, attach: List[Interval]) -> str:
        for zone in sorted(self.spaces):
            if attach and all(intersect([interval], self.spaces[zone]) == [interval] for interval in attach):
                return zone
        return ""

    # -- output -----------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: on AWS the internet gateway translates public addresses and a NAT gateway translates "
                             "sources, outside the security groups. Set them up there; the rules were written for the private "
                             "addresses, which is what the groups see")  # fmt: skip
        groups = self._groups()
        self._emitted(groups)
        self._notes(groups)
        return self._script(groups)

    def _emitted(self, groups: List[_Group]) -> None:
        by_rule: Dict[str, List[str]] = {}
        names = {piece.name: piece.origin for piece in self.pieces}
        for group in groups:
            for rules in list(group.rules_in.values()) + list(group.rules_out.values()):
                for rule in rules:
                    if group.name not in by_rule.setdefault(names[rule], []):
                        by_rule[names[rule]].append(group.name)
        for origin, written in by_rule.items():
            if origin != "(default)":
                self.report.item("rule", origin).emitted_as.append("security groups " + ", ".join(written))

    def _permissions(self, entries: Dict[Tuple[int, Perm], List[Interval]], rules: Dict[Tuple[int, Perm], List[str]]) -> List[List[Dict[str, object]]]:
        """The JSON of --ip-permissions, in calls of at most _PER_CALL address ranges."""
        calls: List[List[Dict[str, object]]] = [[]]
        used = 0
        for (version, perm) in sorted(entries, key=lambda k: (k[0], _perm_key(k[1]))):
            description = _description("FWShift: " + ", ".join(transform.dedupe(rules[(version, perm)])))
            cidrs = [c for interval in entries[(version, perm)] for c in _cidrs(interval)]
            for start in range(0, len(cidrs), _PER_CALL):
                chunk = cidrs[start:start + _PER_CALL]
                if used and used + len(chunk) > _PER_CALL:
                    calls.append([])
                    used = 0
                item: Dict[str, object] = {"IpProtocol": perm[0]}
                if perm[0] != "-1" and perm[0] in ("tcp", "udp", "icmp", "icmpv6"):
                    item["FromPort"], item["ToPort"] = perm[1], perm[2]
                key, inner = ("IpRanges", "CidrIp") if version == 4 else ("Ipv6Ranges", "CidrIpv6")
                item[key] = [{inner: cidr, "Description": description} for cidr in chunk]
                calls[-1].append(item)
                used += len(chunk)
        return [call for call in calls if call]

    def _script(self, groups: List[_Group]) -> str:
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: AWS EC2 security groups for one VPC, created with the AWS CLI. Read the report first:",
            "# what is not written is listed there.",
            "#",
            "#   DRY_RUN=1 sh THIS_FILE                 prints the calls, makes none (no AWS access needed)",
            "#   VPC_ID=vpc-... CHECK=1 sh THIS_FILE    sends every call with --dry-run: AWS checks the permissions",
            "#   VPC_ID=vpc-... sh THIS_FILE            creates the groups and their rules",
            "#",
            "# AWS_OPTS adds options to every call, for example AWS_OPTS='--region eu-west-1 --profile prod'.",
            "#",
            "# The groups are created WITHOUT members: nothing changes for any traffic until they are attached. Attach each",
            "# group to the network interfaces whose private addresses are listed after it (# attach ...): an interface gets",
            "# every group whose list holds one of its addresses, and then no other groups. A group of the same name in the",
            "# VPC stops the script before anything is created; a call AWS refuses stops it where it is (delete the groups",
            "# it made with aws ec2 delete-security-group --group-id ... and run it again).",
            "set -u",
            'DRY_RUN="${DRY_RUN:-}"',
            'CHECK="${CHECK:-}"',
            'AWS_OPTS="${AWS_OPTS:-}"',
            'if [ -z "$DRY_RUN" ]; then',
            '  : "${VPC_ID:?set VPC_ID to the id of the VPC (vpc-...), or DRY_RUN=1 to print the calls}"',
            "else",
            '  VPC_ID="${VPC_ID:-vpc-DRYRUN}"',
            "fi",
            "fail() { printf 'FAILED: %s\\n' \"$*\" >&2; exit 1; }",
            "show() { printf 'aws ec2' >&2; printf ' %s' \"$@\" >&2; printf '\\n' >&2; }",
            "# change CALL ARGS...: a call that changes something",
            "change() {",
            '  if [ -n "$DRY_RUN" ]; then show "$@"; return 0; fi',
            '  if [ -n "$CHECK" ]; then',
            '    out=$(aws ec2 "$@" --dry-run $AWS_OPTS 2>&1)',
            '    case "$out" in *DryRunOperation*) printf \'checked: %s\\n\' "$1" >&2; return 0 ;; esac',
            '    fail "aws ec2 $1: $out"',
            "  fi",
            '  aws ec2 "$@" $AWS_OPTS >/dev/null || fail "aws ec2 $1"',
            "}",
            "# free NAME: stops the script when the VPC has a group of that name",
            "free() {",
            '  if [ -n "$DRY_RUN" ]; then return 0; fi',
            '  found=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=$1" '
            "--query 'SecurityGroups[0].GroupId' --output text $AWS_OPTS) || fail \"describe-security-groups: $found\"",
            '  [ "$found" = None ] || fail "a group named $1 exists in $VPC_ID already ($found); nothing was created"',
            "}",
            "# revoke GROUP PERMISSIONS: takes an outbound rule off a new group; a rule that is not there is fine",
            "revoke() {",
            '  out=$(aws ec2 revoke-security-group-egress --group-id "$1" --ip-permissions "$2" $AWS_OPTS 2>&1) && return 0',
            '  case "$out" in *InvalidPermission.NotFound*|*InvalidParameterValue*) return 0 ;; esac',
            '  fail "revoke-security-group-egress $1: $out"',
            "}",
            "# group NAME DESCRIPTION: creates a group without rules and prints its id",
            "group() {",
            '  if [ -n "$DRY_RUN" ]; then show create-security-group --group-name "$1" --description "$2" --vpc-id "$VPC_ID"; '
            "printf 'sg-dryrun-%s\\n' \"$1\"; return 0; fi",
            '  if [ -n "$CHECK" ]; then change create-security-group --group-name "$1" --description "$2" --vpc-id "$VPC_ID"; '
            "printf '%s\\n' \"$STAND_IN\"; return 0; fi",
            '  id=$(aws ec2 create-security-group --group-name "$1" --description "$2" --vpc-id "$VPC_ID" '
            "--tag-specifications '[{\"ResourceType\":\"security-group\",\"Tags\":[{\"Key\":\"fwshift\",\"Value\":\"generated\"}]}]' "
            '--query GroupId --output text $AWS_OPTS) || fail "create-security-group $1"',
            '  aws ec2 wait security-group-exists --group-ids "$id" $AWS_OPTS || fail "group $id did not appear"',
            "  # A new group allows everything outbound (IPv4, and IPv6 where the VPC has it): take that off, and make sure.",
            '  revoke "$id" \'[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]\'',
            '  revoke "$id" \'[{"IpProtocol":"-1","Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]\'',
            '  left=$(aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$id" '
            "--query 'length(SecurityGroupRules[?IsEgress])' --output text $AWS_OPTS) || fail \"describe-security-group-rules $id\"",
            '  [ "$left" = 0 ] || fail "group $id still has $left outbound rules; it was not given any others"',
            "  printf 'created %s %s\\n' \"$1\" \"$id\" >&2",
            "  printf '%s\\n' \"$id\"",
            "}",
            'ingress() { perms=$(cat); change authorize-security-group-ingress --group-id "$1" --ip-permissions "$perms"; }',
            'egress() { perms=$(cat); change authorize-security-group-egress --group-id "$1" --ip-permissions "$perms"; }',
            'STAND_IN=""',
            'if [ -z "$DRY_RUN" ] && [ -n "$CHECK" ]; then',
            '  STAND_IN=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=default" '
            "--query 'SecurityGroups[0].GroupId' --output text $AWS_OPTS) || fail \"no default group in $VPC_ID\"",
            "fi",
            "",
            "# No group of these names may exist.",
        ]
        out += [f"free '{group.name}'" for group in groups]
        out += ["", "# The groups, each with the private addresses of the network interfaces it is for."]
        for group in groups:
            attach = " ".join(interval_text(i) for i in group.attach)
            short = attach if len(attach) <= 160 else attach[:150].rsplit(" ", 1)[0] + " ..."
            description = _description(f"FWShift: for the interfaces of {short}")
            out.append(f"# attach {group.name}: {attach}")
            out.append(f"{group.var}=$(group '{group.name}' '{description}') || exit 1")
        out += ["", "# Their rules: inbound rules name the sources, outbound rules the destinations."]
        for group in groups:
            for word, entries, rules in (("ingress", group.inbound, group.rules_in), ("egress", group.outbound, group.rules_out)):
                for call in self._permissions(entries, rules):
                    out.append(f"{word} \"${group.var}\" <<'FWSHIFT_JSON'")
                    out.append(json.dumps(call, ensure_ascii=True))
                    out.append("FWSHIFT_JSON")
        if self.comments:
            out += ["", "# Not written:"] + [f"#   {line}" for line in self.comments]
        out += ["", "echo 'Done. Attach the groups to the network interfaces the comments above name; until then nothing changes.' >&2"]
        return "\n".join(out) + "\n"

    def _notes(self, groups: List[_Group]) -> None:
        self.report.note(
            Severity.REVIEW, "AWS_LOAD",
            "the output is a shell script of AWS CLI calls (section 10): DRY_RUN=1 prints them, CHECK=1 with VPC_ID sends each "
            "with --dry-run, VPC_ID alone creates the groups and their rules. It creates new groups only, and stops if a group "
            "of the same name exists. The groups have no members when it is done: nothing changes until they are attached",
        )  # fmt: skip
        if groups:
            self.report.note(
                Severity.REVIEW, "AWS_ATTACH",
                f"{len(groups)} group{'' if len(groups) == 1 else 's'}: attach each to the network interfaces whose private addresses its '# attach' line lists, "
                "and take the other groups off those interfaces; an interface with addresses of both IP versions gets a group "
                "for each. A group applies to the whole interface: an interface with several addresses of one IP version in "
                "different groups gives each address the rules of all of them, so give such addresses the same group. Attaching "
                "(aws ec2 modify-network-interface-attribute --groups ...) replaces the groups of an interface: it is left to you",
            )  # fmt: skip
        over = []
        for group in groups:
            for word, entries in (("inbound", group.inbound), ("outbound", group.outbound)):
                for version in (4, 6):
                    count = sum(len(_cidrs_all(ivs)) for (v, _), ivs in entries.items() if v == version)
                    if count > _QUOTA:
                        over.append(f"{group.name} ({count} {word} IPv{version})")
        if over:
            self.report.note(Severity.REVIEW, "AWS_RULE_QUOTA",
                             f"these groups have more rules than the default quota of {_QUOTA} per direction and IP version; AWS "
                             "refuses the call that goes over it unless the quota was raised (a group whose addresses are not in the "
                             "VPC is never attached, and its call can be taken out of the script): " + ", ".join(over))  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; a security group does not. VPC Flow Logs record the connections of the "
                             "interfaces instead")  # fmt: skip


def _without_covered(entries: Dict[Tuple[int, Perm], List[Interval]]) -> Dict[Tuple[int, Perm], List[Interval]]:
    """Leave out the addresses of a protocol entry that the entry for all protocols holds already."""
    out: Dict[Tuple[int, Perm], List[Interval]] = {}
    for (version, perm), intervals in entries.items():
        every = entries.get((version, ("-1", -1, -1)), [])
        rest = intervals if perm[0] == "-1" else subtract(intervals, every)
        if rest:
            out[(version, perm)] = rest
    return out


def _cidrs_all(intervals: List[Interval]) -> List[str]:
    return [c for interval in intervals for c in _cidrs(interval)]


def _perm_key(perm: Perm) -> Tuple[int, str, int, int]:
    order = {"-1": 0, "tcp": 1, "udp": 2, "icmp": 3, "icmpv6": 4}
    return (order.get(perm[0], 5), perm[0].zfill(3), perm[1], perm[2])


def _without_source_ports(entry: ServiceEntry) -> ServiceEntry:
    out = copy.copy(entry)
    out.src_ports = ""
    return out


def _without_ports(entry: ServiceEntry) -> ServiceEntry:
    out = copy.copy(entry)
    out.src_ports, out.dst_ports = "", ""
    return out

