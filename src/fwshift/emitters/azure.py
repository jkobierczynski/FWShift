# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Azure network security groups emitter: neutral model -> an ARM template.

Design rules:

* One network security group per zone of the model that has networks (``--zone-network``; with ``--inside-zone`` only
  those zones), to be associated with the subnets of that zone. The template defines the rules inline: deploying it
  creates the groups, or replaces the rules of groups of the same name.
* A group is checked where traffic leaves (outbound) and where it arrives (inbound), and both must allow. Each group's
  outbound list holds the rules of the model for traffic from its zone, in their order, each kept to its destination
  zones by their networks; its inbound list the rules for traffic into its zone, kept to their source zones. Both ends
  then give the model's verdict, and so does the pair.
* A rule becomes one security rule per protocol, IP version and service tag or application security group, at
  consecutive priorities from 100. The model's default ends each list, at the highest priorities, above Azure's own
  default rules.
* What a security rule cannot say (ICMP types, ICMPv6, protocols other than TCP, UDP, ICMP, ESP and AH, host names,
  users) makes an allow rule not written, or a blocking rule block more; a rule that is not written is listed in the
  template's metadata and in the report. A group has no rule that is off.
* NAT is not written; the rules are for what a group sees: the translated destination of what comes in, the
  untranslated source of what goes out.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import AbstractSet, Any, Dict, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, Policy, Rule, RuleScope
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

API_VERSION = "2024-05-01"
_MAX_RULES = 2000  # security rules of one group, inbound and outbound together
_MAX_ASGS = 100  # application security groups named by the rules of one group
_MAX_PREFIXES = 4000  # addresses of one side of one rule
_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)
    # A group sees the private destination of what comes in (after the translation) and the private source of what goes
    # out (before it). The NAT rules are not written.
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


def _name(text: str, limit: int = 80) -> str:
    cleaned = _NAME.sub("-", text).strip("-.")
    cleaned = re.sub(r"^[^A-Za-z0-9]+", "", cleaned)[:limit]
    cleaned = re.sub(r"[^A-Za-z0-9_]+$", "", cleaned)
    return cleaned or "x"


def _cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in intervals:
        out += [str(n) for n in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
    return out


@dataclass
class _Side:
    """One side of a rule as a group can say it: every address, address blocks per IP version, and the service tags and
    application security groups (of an Azure source) a rule names one at a time."""

    every: bool = False
    blocks: Dict[int, List[Interval]] = field(default_factory=lambda: {4: [], 6: []})
    native: List[Tuple[str, str]] = field(default_factory=list)  # ("tag", name) or ("asg", id)

    def empty(self) -> bool:
        return not self.every and not self.blocks[4] and not self.blocks[6] and not self.native


Entry = Tuple[str, str, str]  # protocol (Tcp, Udp, Icmp, Esp, Ah, *), source ports, destination ports ("" for every one)


@dataclass
class _Nsg:
    name: str
    zone: str  # "" for the one group of a policy without zones
    networks: List[Interval]
    rules: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: {"Inbound": [], "Outbound": []})
    names: Set[str] = field(default_factory=set)
    counters: Dict[str, int] = field(default_factory=dict)  # name -> the last number given to it


@dataclass
class _Prepared:
    rule: Rule
    entries: List[Entry]
    sources: _Side
    destinations: _Side
    src_zones: List[str]
    dst_zones: List[str]


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "azure"
        self.taint_a = transform.tainted_addresses(p, keep_dynamic=self.native)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))
        self.inside = transform.intrazone_decisions(p, options.zone_map, source_zones, self.universe, report)
        for zone in options.inside_zones:
            if zone not in self.spaces:
                raise FwshiftError(f"--inside-zone {zone}: give the networks behind it with --zone-network")
        self.not_written: List[str] = []
        self.dropped: Set[str] = set()
        self.reasons: Dict[str, List[transform.Reason]] = {}
        self.written: Dict[str, List[str]] = {}
        self.prepared: List[_Prepared] = []
        self.native_cut: Set[str] = set()
        prefix = options.object_prefix
        zones = [z for z in self.universe if z in self.spaces and (not options.inside_zones or z in options.inside_zones)]
        if zones:
            self.nsgs = [_Nsg(_name(prefix + z), z, normalize(self.spaces[z])) for z in zones]
        else:
            self.nsgs = [_Nsg(_name(prefix + (options.target_policy or "FWShift")), "", [])]
        seen: Set[str] = set()
        for nsg in self.nsgs:
            base, counter = nsg.name, 2
            while nsg.name.lower() in seen:
                nsg.name = _name(f"{base}-{counter}")
                counter += 1
            seen.add(nsg.name.lower())

    # -- sides --------------------------------------------------------------------------

    def _resolve(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[_Side]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        side = "source" if source else "destination"
        out = _Side()
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                out.every = True
                found = [FULL_V4, FULL_V6]
                break
            group = self.p.address_groups.get(member)
            if group is not None and self.native and group.dynamic_filter.startswith(("azure-tag:", "azure-asg:")):
                kind, _, value = group.dynamic_filter.partition(":")
                out.native.append(("tag" if kind == "azure-tag" else "asg", value))
                continue
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; a security rule names "
                                    "addresses"))  # fmt: skip
                return None
            found += intervals
        if negated:
            if out.native:
                reasons.append(("ADDRESS_NOT_WRITTEN", f"a negated {side} with a service tag or an application security group"))
                return None
            found = subtract([FULL_V4, FULL_V6], normalize(found))
            out.every = False
        found = normalize(found)
        if found == [FULL_V4, FULL_V6]:
            out.every = True
        else:
            out.every = False
            out.blocks = {v: [i for i in found if i[0] == v] for v in (4, 6)}
        return out

    def _confine(self, out: _Side, space: List[Interval]) -> Optional[_Side]:
        """A side kept to some addresses (the networks of a zone, or every address of some IP versions); None when it
        holds a service tag or an application security group, which cannot be cut."""
        if normalize(space) == [FULL_V4, FULL_V6]:
            return out
        if out.native:
            return None
        everything = [FULL_V4, FULL_V6] if out.every else out.blocks[4] + out.blocks[6]
        kept = intersect(everything, space)
        result = _Side(every=normalize(kept) == [FULL_V4, FULL_V6], blocks={v: [i for i in kept if i[0] == v] for v in (4, 6)})
        return result

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[Entry]]:
        allow = rule.action == Action.ALLOW
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
            svc = regions.service_set(entries)
        elif rule.services == [ANY]:
            svc = regions.ALL_SERVICES
        else:
            entries = []
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
            svc = regions.service_set(entries)
        if svc is None:
            reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
            return None
        if rule.negate_service:
            svc = regions.ALL_SERVICES.minus(svc)
        return self._entries(rule, svc, allow)

    def _entries(self, rule: Rule, svc: regions.Services, allow: bool) -> List[Entry]:
        """A set of services as the protocols and ports of security rules. What cannot be said: an allow rule leaves it
        out, a blocking rule blocks more (an ICMP type: all of ICMP) or leaves out what nothing can allow anyway."""
        out: List[Entry] = []
        left_out, widened = False, False
        listed = set(svc.protocols)
        for number, label in ((6, "Tcp"), (17, "Udp")):
            rects = svc.of(number)
            by_source: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
            for rect in rects:
                by_source.setdefault((rect[0], rect[1]), []).append((rect[2], rect[3]))
            for (low, high), ranges in sorted(by_source.items()):
                source = "" if (low, high) == (0, 65535) else (str(low) if low == high else f"{low}-{high}")
                ports = regions.merge_ranges(ranges)
                if ports == [(0, 65535)]:
                    out.append((label, source, ""))
                else:
                    out.append((label, source, ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ports)))
        icmp = svc.of(1)
        if icmp:
            if any(regions.icmp_values(r[0], r[1]) != [None] or regions.icmp_values(r[2], r[3]) != [None] for r in icmp):
                if allow:
                    left_out = True
                else:
                    widened = True
                    out.append(("Icmp", "", ""))
            else:
                out.append(("Icmp", "", ""))
        for number, label in ((50, "Esp"), (51, "Ah")):
            if svc.of(number):
                out.append((label, "", ""))
        if svc.of(58) or any(n not in (1, 6, 17, 50, 51, 58) for n in listed) or (svc.rest and allow):
            left_out = left_out or allow  # (ICMPv6 and other protocols: no security rule says them, and nothing allows them)
        everything = {("Tcp", "", ""), ("Udp", "", ""), ("Icmp", "", "")}
        # ('*' matches TCP, UDP and ICMP as documented, and perhaps more, as the default DenyAll rules suggest: an allow
        # rule names the three, a blocking rule may block more.)
        if not allow and everything <= set(out):
            out = [("*", "", "")] + [e for e in out if e not in everything]
        if left_out and rule.origin not in self.dropped:
            self.dropped.add(rule.origin)
            self.report.add("rule", rule.origin, Severity.APPROX, "AZURE_PART_NOT_WRITTEN",
                            "part of what the rule allows cannot be said by a security rule (ICMP types, ICMPv6, protocols other "
                            "than TCP, UDP, ICMP, ESP and AH) and is not written: the converted rule allows less")  # fmt: skip
        if widened:
            self.report.add("rule", rule.origin, Severity.APPROX, "ICMP_TYPE_WIDENED",
                            "the rule blocks certain ICMP types; a security rule matches all of ICMP, which blocks more")  # fmt: skip
        return out

    # -- rules -----------------------------------------------------------------------------

    def _reasons(self, rule: Rule) -> List[transform.Reason]:
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": a security rule names addresses"))
        return reasons

    def _rule(self, rule: Rule) -> None:
        """Read what a rule matches once; the lists of the groups take it from there."""
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.not_written.append(f"{rule.name}: {'disabled by the audit' if by_audit else 'disabled in the source'}")
            return
        reasons = self._reasons(rule)
        entries = self._services(rule, reasons)
        sources = self._resolve(rule, True, reasons)
        destinations = self._resolve(rule, False, reasons)
        if self._fqdn(rule.sources + rule.destinations):
            reasons = [r for r in reasons if r[0] != "ADDRESS_UNKNOWN"]
        src_zones, dst_zones = list(rule.src_zones), [ANY] if rule.egress_implied else list(rule.dst_zones)
        missing = [z for z in src_zones + dst_zones if z != ANY and z not in self.spaces]
        if self.nsgs[0].zone and missing or not self.nsgs[0].zone and (src_zones + dst_zones != [ANY, ANY] or rule.scope != RuleScope.UNIVERSAL):
            if rule.action == Action.ALLOW:
                reasons.append(("ZONE_NETWORK_MISSING", f"the rule is for zone {', '.join(transform.dedupe(missing)) or 'pairs'}, and a "
                                "security rule names no zone: give the networks behind it with --zone-network"))  # fmt: skip
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                                f"the rule blocks traffic of zone {', '.join(transform.dedupe(missing)) or 'pairs'}; a security rule names "
                                "no zone, and without the networks of the zones it blocks that traffic in every zone, which is more")  # fmt: skip
                src_zones = [ANY] if any(z in missing for z in src_zones) or not self.nsgs[0].zone else src_zones
                dst_zones = [ANY] if any(z in missing for z in dst_zones) or not self.nsgs[0].zone else dst_zones
                if not self.nsgs[0].zone:
                    rule = copy.copy(rule)
                    rule.scope = RuleScope.UNIVERSAL
        if reasons or entries is None or sources is None or destinations is None:
            self._not_written(rule, reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")])
            return
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value} becomes Deny: a security group has no reject")  # fmt: skip
        if not entries:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING", "nothing of what the rule matches can be said by a security rule",
                             Severity.INFO)  # fmt: skip
            return
        self.prepared.append(_Prepared(rule, entries, sources, destinations, src_zones, dst_zones))

    def _applies(self, item: "_Prepared", own: str, remote: str, inbound: bool) -> bool:
        """Whether a rule is for traffic between the group's zone and a remote zone ("" for addresses of no zone)."""
        src, dst = (remote, own) if inbound else (own, remote)
        scope = item.rule.scope
        if scope == RuleScope.INTRAZONE:
            return src == dst and bool(src) and (ANY in item.src_zones or src in item.src_zones)
        if scope == RuleScope.INTERZONE and src == dst:
            return False
        src_ok = ANY in item.src_zones or (bool(src) and src in item.src_zones)
        dst_ok = ANY in item.dst_zones or (bool(dst) and dst in item.dst_zones)
        return src_ok and dst_ok

    def _lists(self, nsg: _Nsg) -> None:
        """The two lists of a group. For each remote zone in turn (the zones of the default route last), the rules for
        traffic between it and the group's zone, kept to its networks, and its default; then the default of the source.
        Each block decides every address of its zone, so the last block needs no cutting: what reaches it is from the zone
        of the default route, or of no zone."""
        if not nsg.zone:
            for direction in ("Inbound", "Outbound"):
                for item in self.prepared:
                    self._write(item.rule, nsg, direction, item.sources, item.destinations, item.entries)
                self._default(nsg, direction, self.p.default_interzone, "fwshift-default", "", None)
            return
        given = self.options.zone_networks
        rest = {z: sorted({i[0] for i in map(parse_literal, given[z]) if i in (FULL_V4, FULL_V6)}) for z in self.universe if z in given}
        rest = {z: v for z, v in rest.items() if v}
        # A zone of the default route of one IP version may hold networks of the other: those come with the other zones.
        part = {z: [i for i in self.spaces[z] if i[0] not in rest.get(z, [])] for z in self.universe if z in self.spaces}
        blocks: List[Tuple[str, List[Interval], bool]] = [(z, part[z], False) for z in self.universe if part.get(z)]
        blocks += [(z, [regions.full(v) for v in rest[z]], True) for z in sorted(rest, key=lambda z: self.universe.index(z))]
        covered = sorted({v for versions in rest.values() for v in versions})
        uncovered = [v for v in (4, 6) if v not in covered]
        if uncovered:
            blocks.append(("", [regions.full(v) for v in uncovered], True))
        for direction in ("Inbound", "Outbound"):
            inbound = direction == "Inbound"
            for remote, space, tail in blocks:
                for item in self.prepared:
                    if not self._applies(item, nsg.zone, remote, inbound):
                        continue
                    far = item.sources if inbound else item.destinations
                    cut = self._confine(far, space)
                    if cut is None:
                        self._native_cut(item.rule)
                        continue
                    src, dst = (cut, item.destinations) if inbound else (item.sources, cut)
                    self._write(item.rule, nsg, direction, src, dst, item.entries)
                if not tail:
                    access = self._intrazone(nsg) if remote == nsg.zone else self.p.default_interzone
                    self._default(nsg, direction, access, "fwshift-zone-" + remote, remote, space)
            last = self.p.default_interzone
            if nsg.zone in rest and self._intrazone(nsg) != last:
                # What reaches the end in the IP versions of the group's own zone of the default route is from that zone.
                if set(rest[nsg.zone]) == {4, 6}:
                    last = self._intrazone(nsg)
                else:
                    self._default(nsg, direction, self._intrazone(nsg), "fwshift-zone-" + nsg.zone, nsg.zone,
                                  [regions.full(v) for v in rest[nsg.zone]])  # fmt: skip
            self._default(nsg, direction, last, "fwshift-default", "", None)

    def _intrazone(self, nsg: _Nsg) -> Action:
        """What no rule matches inside the group's zone, as the source decides it (transform.intrazone_decisions)."""
        return Action.ALLOW if self.inside.get(nsg.zone, self.p.default_intrazone == Action.ALLOW) else Action.DENY

    def _native_cut(self, rule: Rule) -> None:
        if rule.origin in self.native_cut:
            return
        self.native_cut.add(rule.origin)
        if rule.action == Action.ALLOW:
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_DYNAMIC",
                            "a service tag or an application security group cannot be cut down to the networks of a zone: the rule "
                            "is written only where no zone has to cut it (traffic of the zone of the default route), and allows "
                            "less")  # fmt: skip
        else:
            self.report.add("rule", rule.origin, Severity.REVIEW, "ZONE_DYNAMIC",
                            "a service tag or an application security group cannot be cut down to the networks of a zone: the rule "
                            "is written only where no zone has to cut it (traffic of the zone of the default route); traffic of "
                            "other zones it blocked is not blocked by it")  # fmt: skip

    def _write(self, rule: Rule, nsg: _Nsg, direction: str, src: _Side, dst: _Side, entries: List[Entry]) -> None:
        if src.empty() or dst.empty():
            return
        access = "Allow" if rule.action == Action.ALLOW else "Deny"
        for source, destination in self._pairs(src, dst):
            for protocol, source_ports, destination_ports in entries:
                body: Dict[str, Any] = {"protocol": protocol, "access": access, "direction": direction}
                body.update(self._ports("source", source_ports))
                body.update(self._ports("destination", destination_ports))
                body.update(source)
                body.update(destination)
                nsg.rules[direction].append({"name": rule.name, "origin": rule.origin, "description": rule.description, "properties": body})
                self.written.setdefault(rule.origin, []).append(nsg.name)

    @staticmethod
    def _ports(side: str, ports: str) -> Dict[str, Any]:
        parts = ports.split(",") if ports else []
        if len(parts) > 1:
            return {f"{side}PortRanges": parts}
        return {f"{side}PortRange": parts[0] if parts else "*"}

    def _pairs(self, src: _Side, dst: _Side) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Source and destination fields for the security rules of one rule: one version of addresses at a time, one service
        tag or application security group at a time."""
        out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        for source_version, source in self._fields("source", src):
            for destination_version, destination in self._fields("destination", dst):
                if source_version and destination_version and source_version != destination_version:
                    continue
                out.append((source, destination))
        return out

    @staticmethod
    def _fields(side: str, value: _Side) -> List[Tuple[int, Dict[str, Any]]]:
        out: List[Tuple[int, Dict[str, Any]]] = []
        if value.every:
            out.append((0, {f"{side}AddressPrefix": "*"}))
        else:
            for version in (4, 6):
                cidrs = _cidrs(value.blocks[version])
                for start in range(0, len(cidrs), _MAX_PREFIXES):
                    chunk = cidrs[start:start + _MAX_PREFIXES]
                    out.append((version, {f"{side}AddressPrefix": chunk[0]} if len(chunk) == 1 else {f"{side}AddressPrefixes": chunk}))
        for kind, name in value.native:
            if kind == "tag":
                out.append((0, {f"{side}AddressPrefix": name}))
            elif name.lower().startswith("/subscriptions/"):
                out.append((0, {f"{side}ApplicationSecurityGroups": [{"id": name}]}))
            else:
                # (from a template: no subscription; the group of that name in the resource group deployed to)
                last = name.rstrip("/").rsplit("/", 1)[-1].replace("'", "''")
                expression = f"[resourceId('Microsoft.Network/applicationSecurityGroups', '{last}')]"
                out.append((0, {f"{side}ApplicationSecurityGroups": [{"id": expression}]}))
        return out

    def _not_written(self, rule: Rule, reasons: List[transform.Reason]) -> None:
        transform.disable_rule(self.report, rule, list(dict.fromkeys(reasons)))
        self.not_written.append(f"{rule.name}: " + "; ".join(message for _, message in dict.fromkeys(reasons))[:400])

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

    # -- the defaults ------------------------------------------------------------------------

    def _default(self, nsg: _Nsg, direction: str, action: Action, name: str, zone: str, networks: Optional[List[Interval]]) -> None:
        """What no rule above decides: of one remote zone, or of every address."""
        access = "Allow" if action == Action.ALLOW else "Deny"
        inbound = direction == "Inbound"
        remote = "source" if inbound else "destination"
        near = "destination" if inbound else "source"
        sides: List[Dict[str, Any]] = [{}]
        if networks is not None:
            sides = []
            for version in (4, 6):
                cidrs = _cidrs([i for i in networks if i[0] == version])
                for start in range(0, len(cidrs), _MAX_PREFIXES):
                    chunk = cidrs[start:start + _MAX_PREFIXES]
                    sides.append({f"{remote}AddressPrefix": chunk[0]} if len(chunk) == 1 else {f"{remote}AddressPrefixes": chunk})
        for side in sides:
            for protocol in ("*", "Esp", "Ah"):
                body: Dict[str, Any] = {"protocol": protocol, "access": access, "direction": direction, "sourcePortRange": "*",
                                        "destinationPortRange": "*", f"{near}AddressPrefix": "*"}  # fmt: skip
                body.update(side or {f"{remote}AddressPrefix": "*"})
                what = f"traffic of zone {zone}" if zone else "what no rule matches"
                nsg.rules[direction].append({"name": name, "origin": "", "description": f"the default of the source for {what}: "
                                             f"{access.lower()}", "properties": body})  # fmt: skip

    # -- output ------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        for nsg in self.nsgs:
            self._lists(nsg)
        for item in self.prepared:
            written = transform.dedupe(self.written.get(item.rule.origin, []))
            if written:
                self.report.item("rule", item.rule.origin).emitted_as.append("security rules of " + ", ".join(written))
            else:
                self.report.skip("rule", item.rule.origin, "MATCHES_NOTHING",
                                 "after the negation and the networks of its zones, the rule matches no connection here", Severity.INFO)  # fmt: skip
        resources: List[Dict[str, Any]] = []
        networks: Dict[str, List[str]] = {}
        for nsg in self.nsgs:
            rules: List[Dict[str, Any]] = []
            count = len(nsg.rules["Inbound"]) + len(nsg.rules["Outbound"])
            asgs = {str(a.get("id")).lower() for d in ("Inbound", "Outbound") for entry in nsg.rules[d] for side in ("source", "destination")
                    for a in entry["properties"].get(f"{side}ApplicationSecurityGroups", [])}  # fmt: skip
            if count > _MAX_RULES or len(asgs) > _MAX_ASGS:
                self.report.note(Severity.REVIEW, "AZURE_TOO_MANY_RULES",
                                 f"group {nsg.name} would have {count} security rules and name {len(asgs)} application security groups; "
                                 f"Azure allows {_MAX_RULES} and {_MAX_ASGS} in one group. It is not written")  # fmt: skip
                continue
            for direction in ("Inbound", "Outbound"):
                for entry in nsg.rules[direction]:
                    description = (entry["name"] + (": " + entry["description"] if entry["description"] else ""))[:140]
                    rules.append({"name": self._rule_name(nsg, entry["name"], direction),
                                  "properties": dict({"description": description}, **entry["properties"])})  # fmt: skip
            self._renumber(rules)
            resource: Dict[str, Any] = {
                "type": "Microsoft.Network/networkSecurityGroups", "apiVersion": API_VERSION, "name": nsg.name,
                "location": "[parameters('location')]", "tags": {"generator": "FWShift"},
                "properties": {"securityRules": rules},
            }  # fmt: skip
            resources.append(resource)
            if nsg.zone:
                networks[nsg.name] = _cidrs(nsg.networks)
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: a network security group does no NAT (a load balancer, a NAT gateway or a public "
                             "address does). The rules were written for what the groups see")  # fmt: skip
        self._notes(resources)
        template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "metadata": {"generator": "FWShift", "comment": "Generated by FWShift - review the conversion report before deploying this.",
                         "networks": networks, "notWritten": self.not_written},
            "parameters": {"location": {"type": "string", "defaultValue": "[resourceGroup().location]"}},
            "resources": resources,
        }  # fmt: skip
        return json.dumps(template, indent=2, ensure_ascii=False) + "\n"

    @staticmethod
    def _renumber(rules: List[Dict[str, Any]]) -> None:
        """Priorities per direction: 100, 110, ... and the last rule at 4096; packed by one where there are many."""
        for direction in ("Inbound", "Outbound"):
            mine = [r for r in rules if r["properties"]["direction"] == direction]
            count = len(mine)
            step = 10 if 100 + 10 * (count - 1) <= 4096 else 1
            for index, rule in enumerate(mine):
                rule["properties"]["priority"] = 100 + step * index if step == 10 else 4096 - (count - 1 - index)
            if mine:
                mine[-1]["properties"]["priority"] = 4096

    def _rule_name(self, nsg: _Nsg, base: str, direction: str) -> str:
        """A name of at most 80 characters, unique in the group: the rule's name, then a number."""
        stem = _name(f"{base}-{'in' if direction == 'Inbound' else 'out'}")
        candidate = stem
        counter = nsg.counters.get(stem.lower(), 1)
        while candidate.lower() in nsg.names:
            counter += 1
            number = f"-{counter}"
            candidate = _name(stem[:80 - len(number)]) + number
        nsg.counters[stem.lower()] = counter
        nsg.names.add(candidate.lower())
        return candidate

    def _notes(self, resources: List[Dict[str, Any]]) -> None:
        self.report.note(
            Severity.REVIEW, "AZURE_LOAD",
            "the output is an ARM template (section 10): look at it with az deployment group what-if, deploy it with az "
            "deployment group create (incremental mode, never complete), then associate each group with the subnets of its "
            "zone (its networks are in the template's metadata). Deploying it replaces all rules of groups of the same name",
        )  # fmt: skip
        self.report.note(
            Severity.INFO, "AZURE_DEFAULTS_OVERRIDDEN",
            "each list ends in the default of the source, which comes before the default rules of Azure: they no longer let "
            "the virtual network, the load balancer's health probes or the internet through unless a rule does",
        )  # fmt: skip
        if any(nsg.zone == "" for nsg in self.nsgs) and resources:
            self.report.note(Severity.REVIEW, "AZURE_ONE_GROUP",
                             "no zone has networks (--zone-network): one group holds every rule, inbound and outbound; associate "
                             "it with every subnet the policy is for")  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; a security rule does not. Flow logs of the virtual network record the "
                             "connections instead")  # fmt: skip
