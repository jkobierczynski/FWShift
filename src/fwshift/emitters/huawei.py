# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Huawei USG emitter: neutral model -> commands for the system view of a USG6000, USG6000E or USG9500 (VRP V500,
V600).

Design rules:

* The zones of the model become security zones: ``trust``, ``untrust`` and ``dmz`` as they are, others as new zones
  with the prefix and a priority of their own. Which interfaces go in them is a comment.
* Each rule becomes a rule of ``security-policy`` in the order of the model, with the zones, address sets (objects of
  the model, groups as groups, literals in the rule), service sets and the action; logging is ``policy logging``, a
  rule the target cannot say is written ``disable`` and listed. A rule that holds traffic inside its zones only, or
  between them only, is written per zone (a rule of a USG matches every pair of its zones).
* What no rule matches: ``default action permit`` where the source allows between zones; traffic inside a zone, which
  a USG passes, gets a rule that denies it at the end where the source denies it.
* Destination NAT is done before the security policy, which names the inside address: the rules are written for it.
  Destination NAT becomes ``nat server``, source NAT rules of ``nat-policy`` (easy-ip, an address pool, no-nat).
* New names only, with a prefix (``FWS_`` or ``--target-prefix``). A USG adds new rules after the ones it has;
  ``rule move`` puts them before others.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, subtract
from ..options import Options
from ..report import Report, Severity

_PREDEFINED_ZONES = ("trust", "untrust", "dmz")
_NOTHING = ["0.0.0.0 32"]  # (an address no forwarded packet has: a side that cannot be written)
_TAKEN_PRIORITIES = {100, 85, 50, 5}


def _printable(text: str) -> str:
    return "".join(c if c.isprintable() and c not in '"?' else " " for c in text)  # (? asks VRP for help)


def _cidrs(interval: Interval) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    first, last = int_to_ip(interval[0], interval[1]), int_to_ip(interval[0], interval[2])
    return list(ipaddress.summarize_address_range(first, last))


@dataclass
class _Out:
    zones: List[str] = field(default_factory=list)
    objects: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    nat: List[str] = field(default_factory=list)
    servers: List[str] = field(default_factory=list)
    pools: List[str] = field(default_factory=list)
    not_written: List[str] = field(default_factory=list)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or "FWS_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,15}", prefix):
        raise FwshiftError("--target-prefix for Huawei: up to 16 letters, digits, periods, underscores and hyphens, starting with a letter")
    probe = _Emitter(p, Report(), options)
    probe._zones()
    written = {nat.origin for nat in p.nat_rules if probe.nat_lines(nat)}
    written -= {nat.origin for nat in p.nat_rules if not probe.nat_lines(nat)}  # (all the rules of an origin, or none)
    translated = {o for o in written if any(n.origin == o and (n.destination_translation is not None or transform.bidirectional_pair(p, n) is not None)
                                             for n in p.nat_rules)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.prefix = options.object_prefix or "FWS_"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        used += [z for n in p.nat_rules for z in n.src_zones + n.dst_zones if z != ANY]
        self.zones = transform.dedupe(list(p.zones) + used)
        self.zone_names: Dict[str, str] = {}
        self.out = _Out()
        self.names: Set[str] = set()
        self.address_sets: Dict[str, str] = {}  # model name or interval key -> address set
        self.service_sets: Dict[str, str] = {}
        self.nat_cache: Dict[str, List[str]] = {}
        self.counter = 0
        self.inside_decided: Set[str] = set()
        self.current: Optional[NatRule] = None  # zones whose traffic inside the zone a rule written decides whole

    def _name(self, label: str, limit: int = 31) -> str:
        base = (self.prefix + re.sub(r"[^A-Za-z0-9_.-]", "_", label))[:limit] or self.prefix + "x"
        name, counter = base, 2
        while name.lower() in self.names:
            name = f"{base[: limit - 4]}_{counter}"
            counter += 1
        self.names.add(name.lower())
        return name

    # -- zones -------------------------------------------------------------------------------

    def _zones(self) -> None:
        priority = 80
        for zone in self.zones:
            if zone in _PREDEFINED_ZONES:
                self.zone_names[zone] = zone
                continue
            name = self._name(zone)
            while priority in _TAKEN_PRIORITIES:
                priority -= 1
            if priority < 1:
                raise FwshiftError("more zones than a USG has priorities for (1 to 100)")
            self.zone_names[zone] = name
            self.out.zones += [f"firewall zone name {name}", f" set priority {priority}"]
            if name != zone:
                self.out.zones.append(f" description {_printable(zone).strip()[:120] or 'zone'}")
            self.out.zones.append(" quit")
            priority -= 1

    # -- addresses ---------------------------------------------------------------------------

    @staticmethod
    def _entries(intervals: List[Interval]) -> List[str]:
        out = []
        for interval in intervals:
            nets = _cidrs(interval)
            if interval[0] == 4 and len(nets) > 1:
                out.append(f"range {int_to_ip(4, interval[1])} {int_to_ip(4, interval[2])}")
                continue
            for net in nets:
                if net.version == 4:
                    out.append(f"{net.network_address} mask {net.prefixlen}")
                else:
                    out.append(f"{net.network_address}/{net.prefixlen}")
        return out

    def _address_set(self, key: str, label: str, intervals: List[Interval]) -> str:
        if key in self.address_sets:
            return self.address_sets[key]
        name = self._name(label)
        self.address_sets[key] = name
        self.out.objects.append(f"ip address-set {name} type object")
        self.out.objects += [f" address {index} {entry}" for index, entry in enumerate(self._entries(intervals))]
        self.out.objects.append(" quit")
        return name

    def _member(self, member: str, reasons: List[transform.Reason]) -> Optional[List[str]]:
        """The rule lines' values for one member: ``address-set X`` or ``A LEN``."""
        if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
            reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: written with addresses only"))
            return None
        intervals, known = transform.known_intervals(self.p, member)
        if not known:
            reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
            return None
        intervals = normalize(intervals)
        if not intervals:
            return []
        if member not in self.p.addresses and member not in self.p.address_groups and len(intervals) == 1:
            nets = _cidrs(intervals[0])
            if intervals[0][0] == 4 and len(nets) == 1:
                return [f"{nets[0].network_address} {nets[0].prefixlen}"]
        return [f"address-set {self._address_set('m:' + member, member, intervals)}"]

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[List[str]]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        if not negated:
            if ANY in members:
                return []
            out: List[str] = []
            for member in members:
                found = self._member(member, reasons)
                if found is None:
                    return None
                out += found
            return transform.dedupe(out) if out else list(_NOTHING)
        found_v: Dict[int, List[Interval]] = {4: [], 6: []}
        for member in members:
            if member == ANY:
                found_v = {4: [FULL_V4], 6: [FULL_V6]}
                break
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
                return None
            for interval in intervals:
                found_v[interval[0]].append(interval)
        left = subtract([FULL_V4], found_v[4]) + subtract([FULL_V6], found_v[6])
        if not left:
            return list(_NOTHING)
        key = "n:" + ",".join(f"{i[0]}-{i[1]}-{i[2]}" for i in left)
        return [f"address-set {self._address_set(key, ('not-' + '-'.join(members))[:40], left)}"]

    # -- services ----------------------------------------------------------------------------

    def _service_lines(self, entries: List[ServiceEntry]) -> Optional[List[str]]:
        out = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                line = f"protocol {entry.protocol.value}"
                if entry.src_ports:
                    line += " source-port " + " ".join(p.replace("-", " to ") for p in entry.src_ports.split(","))
                if entry.dst_ports:
                    line += " destination-port " + " ".join(p.replace("-", " to ") for p in entry.dst_ports.split(","))
                out.append(line)
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                line = "protocol " + ("icmp" if entry.protocol == Protocol.ICMP else "icmpv6")
                if entry.icmp_type is not None:
                    line += f" icmp-type {entry.icmp_type}" + ("" if entry.icmp_code is None else f" {entry.icmp_code}")
                elif entry.icmp_code is not None:
                    return None
                out.append(line)
            elif entry.ip_protocol is None or entry.ip_protocol == 0:
                return None  # (every protocol: no service set says it; the rule says any. 0 may be read as every protocol)
            else:
                out.append(f"protocol {entry.ip_protocol}")
        return out

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[str]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            return self._service_of(entries, "apps-" + "-".join(rule.applications)[:30], reasons) if entries else None
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: a service set of a USG lists what it matches"))
            return None
        if rule.services == [ANY]:
            return []
        out: List[str] = []
        for name in rule.services:
            if name in self.service_sets:
                out.append(self.service_sets[name])
                continue
            flat = transform.flatten_services(self.p, name)
            if flat is None:
                if name not in self.taint_s:
                    reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                return None
            if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in flat):
                return []  # (every protocol)
            found = self._service_of(flat, name, reasons)
            if found is None:
                return None
            self.service_sets[name] = found[0]
            out += found
        return transform.dedupe(out)

    def _service_of(self, entries: List[ServiceEntry], label: str, reasons: List[transform.Reason]) -> Optional[List[str]]:
        lines = self._service_lines(entries)
        if lines is None:
            reasons.append(("SERVICE_NOT_WRITTEN", "an ICMP code without a type, or a service a service set cannot say"))
            return None
        key = "e:" + "|".join(lines)
        if key in self.service_sets:
            return [self.service_sets[key]]
        name = self._name(label)
        self.service_sets[key] = name
        self.out.objects.append(f"ip service-set {name} type object")
        self.out.objects += [f" service {index} {line}" for index, line in enumerate(lines)]
        self.out.objects.append(" quit")
        return [name]

    # -- rules ------------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> List[Tuple[List[str], List[str]]]:
        """The zones of the rules a rule of the model becomes."""
        sources = [z for z in rule.src_zones if z != ANY] if ANY not in rule.src_zones else list(self.zones)
        destinations = [z for z in rule.dst_zones if z != ANY] if ANY not in rule.dst_zones else list(self.zones)
        if rule.scope == RuleScope.INTRAZONE:
            return [([z], [z]) for z in sources]
        if rule.scope == RuleScope.INTERZONE and set(sources) & set(destinations):
            return [([z], [d for d in destinations if d != z]) for z in sources if [d for d in destinations if d != z]]
        if not self.zones:
            return [([], [])]  # (no zone is known: HUAWEI_NO_ZONES)
        return [(sources, destinations)]  # (any zone is every zone written: a rule without zones takes in local too)

    def _rule(self, rule: Rule) -> None:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.schedule:
            reasons.append(("SCHEDULE", f"schedule {rule.schedule} is not converted"))
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        services = self._services(rule, reasons)
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY", f"action {rule.action.value}: written as deny")
        pairs = self._pairs(rule)
        if not reasons and rule.enabled and sources == [] and destinations == [] and services == [] and rule.applications == [ANY]:
            for src_zones, dst_zones in pairs:
                inside = set(src_zones or self.zones) & set(dst_zones or self.zones)
                self.inside_decided |= inside
        if not pairs:
            reasons.append(("NOT_WRITTEN", "traffic inside or between zones, and no zone is known"))
            pairs = [([], [])]
        reasons = list(dict.fromkeys(reasons))
        disabled = bool(reasons) or sources is None or destinations is None or services is None
        if disabled:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.out.not_written.append(f"{rule.name}: " + "; ".join(m for _, m in reasons)[:300])
        for index, (src_zones, dst_zones) in enumerate(pairs):
            name = self._name(rule.name if len(pairs) == 1 else f"{rule.name}_{index + 1}", 63)
            lines = [f" rule name {name}"]
            if disabled or not rule.enabled:
                lines.append("  disable")  # (first: commands take effect at once)
            if _printable(rule.description).strip():
                lines.append(f"  description {_printable(rule.description).strip()[:120]}")
            lines += [f"  source-zone {self.zone_names[z]}" for z in src_zones]
            lines += [f"  destination-zone {self.zone_names[z]}" for z in dst_zones]
            lines += [f"  source-address {value}" for value in (_NOTHING if sources is None else sources)]
            lines += [f"  destination-address {value}" for value in (_NOTHING if destinations is None else destinations)]
            lines += [f"  service {value}" for value in services or []]
            lines.append("  action " + ("permit" if rule.action == Action.ALLOW else "deny"))
            if rule.log_start or rule.log_end:
                lines.append("  policy logging")
            lines.append("  quit")
            self.out.rules += lines
        self.report.item("rule", rule.origin).emitted_as.append(f"{len(pairs)} rules of the security policy")

    def _defaults(self) -> None:
        inter = self.p.default_interzone == Action.ALLOW
        added = []
        for zone in self.zones:
            found = self.p.zones.get(zone)
            intra = self.p.default_intrazone == Action.ALLOW if found is None or found.intrazone_allow is None else found.intrazone_allow
            if not intra and zone not in self.inside_decided:
                name = self._name(f"intrazone_{zone}", 63)
                self.out.rules += [f" rule name {name}", f"  source-zone {self.zone_names[zone]}", f"  destination-zone {self.zone_names[zone]}",
                                   "  action deny", "  quit"]  # fmt: skip
                added.append(zone)
        if added:
            self.report.note(Severity.INFO, "INTRAZONE_RULES_ADDED",
                             "a USG passes traffic inside a zone that no rule matches; the source does not: rules that deny it were "
                             "added at the end for " + ", ".join(added[:12]) + (" ..." if len(added) > 12 else ""))  # fmt: skip
        if not self.zones:
            self.report.note(Severity.REVIEW, "HUAWEI_NO_ZONES",
                             "the source names no zones: the rules are written without zones, so they match between every pair "
                             "of zones and to the firewall itself (local), and traffic inside a zone that no rule matches passes; "
                             "give the rules their zones (--zone-map, or edit them)")  # fmt: skip
        elif not added and not inter:
            self.report.note(Severity.INFO, "HUAWEI_INTRAZONE",
                             "traffic inside a zone that no rule matches passes, as on the source, as long as the firewall does not "
                             "have default packet-filter intrazone enable")  # fmt: skip
        if inter:
            self.out.rules.append(" default action permit")
            self.report.note(Severity.REVIEW, "HUAWEI_DEFAULT_PERMIT",
                             "the source allows what no rule matches between zones: the output sets default action permit, which "
                             "is the firewall's default for every zone pair, also of rules that are not part of this policy")  # fmt: skip

    # -- NAT ---------------------------------------------------------------------------------

    def _addresses_of(self, members: List[str]) -> Optional[List[str]]:
        if ANY in members:
            return []
        out: List[str] = []
        for member in members:
            found = self._member(member, [])
            if found is None:
                return None
            out += found
        return out

    def nat_lines(self, nat: NatRule) -> List[str]:
        key = nat.origin + "\0" + nat.name
        if key not in self.nat_cache:
            self.current = nat
            self.nat_cache[key] = self._nat_lines(nat)
        return self.nat_cache[key]

    def _exempted(self, outer: Interval) -> bool:
        """An exemption above this NAT rule in the model that names its address: a USG does nat server first."""
        for other in self.p.nat_rules:
            if other.source_translation is None and other.destination_translation is None and other.enabled and not other.unsupported:
                if ANY in other.destinations or any(i[0] == outer[0] and i[1] <= outer[2] and outer[1] <= i[2]
                                                    for member in other.destinations for i in transform.known_intervals(self.p, member)[0]):
                    return True  # fmt: skip
            if other is self.current:
                return False
        return False

    def _nat_lines(self, nat: NatRule) -> List[str]:
        if not nat.enabled or nat.unsupported:
            return []
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is not None:
            inside, outside = pair
            if inside[1] != inside[2] or nat.src_zones != [ANY] or nat.dst_zones != [ANY] or nat.destinations != [ANY] or nat.service != ANY \
                    or self._exempted(outside):
                return []  # (nat server takes no condition but the zone of the inbound half)
            return [f"nat server {self._name('srv')} global {int_to_ip(4, outside[1])} inside {int_to_ip(4, inside[1])}"]
        dnat = nat.destination_translation
        if dnat is not None and nat.source_translation is None and len(nat.destinations) == 1:
            outer = transform.known_intervals(self.p, nat.destinations[0])[0]
            inner = transform.known_intervals(self.p, dnat.address)[0] if dnat.address else []
            if len(outer) != 1 or len(inner) != 1 or outer[0][1] != outer[0][2] or inner[0][1] != inner[0][2] or outer[0][0] != 4:
                return []
            if nat.sources != [ANY] or nat.dst_zones != [ANY] or (ANY not in nat.src_zones and len(nat.src_zones) != 1) or self._exempted(outer[0]):
                return []  # (nat server takes no condition but one source zone; an exemption above it would not stop it)
            zone = f" zone {self.zone_names[nat.src_zones[0]]}" if nat.src_zones != [ANY] else ""
            entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else []
            if nat.service != ANY and not entries:
                return []  # (a service that cannot be read, or none: never every protocol)
            assert entries is not None
            if dnat.port:
                if len(entries) != 1 or entries[0].protocol not in (Protocol.TCP, Protocol.UDP) or not entries[0].dst_ports.isdigit() \
                        or entries[0].src_ports or not dnat.port.isdigit():
                    return []
                return [f"nat server {self._name('srv')}{zone} protocol {entries[0].protocol.value} global {int_to_ip(4, outer[0][1])} "
                        f"{entries[0].dst_ports} inside {int_to_ip(4, inner[0][1])} {dnat.port} no-reverse"]  # fmt: skip
            if entries:
                return []
            return [f"nat server {self._name('srv')}{zone} global {int_to_ip(4, outer[0][1])} inside {int_to_ip(4, inner[0][1])} no-reverse"]
        snat = nat.source_translation
        if dnat is not None or nat.service != ANY:
            return []
        sources = self._addresses_of(nat.sources)
        destinations = self._addresses_of(nat.destinations)
        if sources is None or destinations is None:
            return []
        lines = [f" rule name {self._name('nat_' + nat.name, 63)}"]
        lines += [f"  source-zone {self.zone_names[z]}" for z in nat.src_zones if z in self.zone_names]
        lines += [f"  destination-zone {self.zone_names[z]}" for z in nat.dst_zones if z in self.zone_names]
        lines += [f"  source-address {v}" for v in sources] + [f"  destination-address {v}" for v in destinations]
        if snat is None:
            lines.append("  action no-nat")
        elif snat.kind == SnatKind.INTERFACE:
            lines.append("  action source-nat easy-ip")
        elif snat.kind in (SnatKind.DYNAMIC, SnatKind.DYNAMIC_PORT) and snat.addresses:
            pool: List[Interval] = []
            for member in snat.addresses:
                found, known = transform.known_intervals(self.p, member)
                if not known:
                    return []
                pool += [i for i in found if i[0] == 4]
            if not pool:
                return []
            name = self._name("pool")
            self.out.pools += [f"nat address-group {name}", " mode pat" if snat.kind == SnatKind.DYNAMIC_PORT else " mode no-pat local"]
            self.out.pools += [f" section {index} {int_to_ip(4, i[1])} {int_to_ip(4, i[2])}" for index, i in enumerate(normalize(pool))]
            self.out.pools.append(" quit")
            lines.append(f"  action source-nat address-group {name}")
        else:
            return []
        return lines + ["  quit"]

    # -- output ------------------------------------------------------------------------------

    def run(self) -> str:
        self._zones()
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            lines = self.nat_lines(nat)
            if not lines:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: a USG writes nat server for one address or port, and source NAT to the interface, "
                                 "to an address pool or none for addresses and zones")  # fmt: skip
                continue
            self.report.item("nat", nat.origin).emitted_as.append("nat server" if lines[0].startswith("nat server") else "nat-policy")
            (self.out.servers if lines[0].startswith("nat server") else self.out.nat).extend(lines)
        out = ["# Generated by FWShift: commands for the system view of a Huawei USG (security-policy). Read the report first:",
               "# what is not written is listed there. New rules come after the rules the firewall has (rule move puts them",
               f"# before others). Every name starts with {self.prefix}. Check, then save.", "system-view"]  # fmt: skip
        out += self.out.zones + self.out.objects
        if self.out.rules:
            out += ["security-policy"] + self.out.rules + [" quit"]
        out += self.out.pools
        if self.out.nat:
            out += ["nat-policy"] + self.out.nat + [" quit"]
        out += self.out.servers
        tail = ["# Put the interfaces in their zones (this changes traffic at once):"]
        for zone in self.zones:
            found = self.p.zones.get(zone)
            interfaces = [self.options.interface_map.get(i, i) for i in (found.interfaces if found else [])]
            for interface in interfaces:
                tail.append(f"#   firewall zone {'name ' if zone not in _PREDEFINED_ZONES else ''}{self.zone_names[zone]} / add interface {_printable(interface)}")
            if not interfaces:
                tail.append(f"#   zone {self.zone_names[zone]}: no interface is known")
        if self.out.not_written:
            tail += ["# Written disabled:"] + [f"#   {_printable(line)}" for line in self.out.not_written]
        self._notes()
        return "\n".join(out + ["return"] + tail) + "\n"

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "HUAWEI_LOAD",
                         "the output is commands for the system view (section 10): new zones, address and service sets, rules, NAT; "
                         "a USG adds new rules after the ones it has, and nat server and nat-policy take effect at once. Check, "
                         "then save")  # fmt: skip
        if any(line.startswith(" address ") and "/" in line for line in self.out.objects):
            self.report.note(Severity.REVIEW, "HUAWEI_IPV6",
                             "IPv6 entries of address sets are written as ADDRESS/LENGTH; Huawei's documentation FWShift could read "
                             "does not show their form: check them on the firewall")  # fmt: skip
        if any(r.enabled and (r.log_start or r.log_end) for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules have policy logging")
