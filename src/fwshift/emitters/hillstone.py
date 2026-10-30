# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hillstone StoneOS emitter: neutral model -> commands for the configuration mode of StoneOS 5.x (E-, T- and
X-series, CloudEdge).

Design rules:

* The zones of the model become zones: ``trust``, ``untrust`` and ``dmz`` as they are, others new with the prefix.
  Which interfaces go in them is in the report: binding an interface changes traffic at once.
* Address entries for the objects of the model (one entry per object and IP version, its addresses written out) and
  for negations (what is left of the IP version); services for the services and groups of the model, flattened.
  ``Any``, ``IPv6-any``, ``ICMP`` and the predefined services of a Hillstone source are referred to as they are.
* Each rule becomes rules of ``policy-global`` in the order of the model: one per pair of zones (a rule names one
  source and one destination zone) and per IP version it matches (an entry is of one IP version; ``Any`` is IPv4,
  ``IPv6-any`` IPv6). Each new rule gets the next id from 10000 (``--policy-id-start``) and goes after the rules the
  firewall has, which is where StoneOS puts a new rule; ``move ID top`` or ``move ID before ID`` puts it elsewhere.
  A rule the target cannot say is written ``disable`` and listed in the report.
* What no rule matches: StoneOS denies it, between zones and inside one. ``default-action permit`` where the source
  allows it between zones; rules at the end for the zones in which the source decides otherwise inside the zone.
* The policy names the destination before DNAT and the zone after it (the reading of the parser), as the model does:
  rules are written as they are. Destination NAT becomes ``dnatrule``, source NAT ``snatrule``, in a block of the
  virtual router trust-vr; a rule of both kinds is one of each, which StoneOS (5.0 and later) applies to the same
  connection.
* New names only, with a prefix (``FWS_`` or ``--target-prefix``); nothing is changed or deleted, and nothing is saved.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, List, Optional, Set, Tuple, Union

from .. import names, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, subtract
from ..options import Options
from ..parsers.hillstone import PREDEFINED
from ..report import Report, Severity

_PREDEFINED_ZONES = ("trust", "untrust", "dmz")
_ANY_NAME = {4: "Any", 6: "IPv6-any"}
_FIRST_ID = 10000
# The ICMP types a service of StoneOS takes, with codes 0 to 5 (Hillstone's documentation of the service book).
_ICMP_TYPES = (3, 4, 5, 8, 11, 12, 13, 15)
_NOTHING: Tuple[str, ...] = ("ip", "0.0.0.0/32")  # (an address no forwarded packet has: a side that cannot be written)

Ref = Tuple[str, ...]  # ("addr", name) | ("ip", cidr) | ("range", first, last)


def _text(text: str, limit: int = 255) -> str:
    """Free text in double quotes: no quotes, backslashes or control characters, and not longer than StoneOS takes."""
    return " ".join("".join(c if c.isprintable() and c not in '"\\?' else " " for c in text).split())[:limit].strip()


def _cidrs(interval: Interval) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    return list(ipaddress.summarize_address_range(int_to_ip(interval[0], interval[1]), int_to_ip(interval[0], interval[2])))


def _entry_lines(intervals: List[Interval]) -> List[str]:
    out = []
    for interval in normalize(intervals):
        nets = _cidrs(interval)
        if len(nets) == 1:
            out.append(f"  ip {nets[0]}")
        else:
            out.append(f"  range {int_to_ip(interval[0], interval[1])} {int_to_ip(interval[0], interval[2])}")
    return out


@dataclass
class _Out:
    zones: List[str] = field(default_factory=list)
    objects: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    nat: List[str] = field(default_factory=list)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or "FWS_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,15}", prefix):
        raise FwshiftError("--target-prefix for Hillstone: up to 16 letters, digits, periods, underscores and hyphens, starting with a letter")
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones = source_zones
        self.prefix = options.object_prefix or "FWS_"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        used += [z for n in p.nat_rules for z in n.src_zones + n.dst_zones if z != ANY]
        self.zones = transform.target_zones(p, options.zone_map, used, [])
        self.zone_names: Dict[str, str] = {}
        self.out = _Out()
        self.names: Set[str] = set()
        self.entries: Dict[str, str] = {}  # key -> address entry or service
        self.services: Dict[str, Optional[List[str]]] = {}  # model service -> service references
        self.next_id = options.policy_id_start if options.policy_id_start > 0 else _FIRST_ID
        self.next_snat = self.next_dnat = self.next_id
        self.first_id = self.next_id
        self.inside_decided: Set[str] = set()
        self.families = self._families()
        self.fqdn_v4: Set[str] = set()

    def _name(self, label: str, limit: int = 63) -> str:
        base = names.clean(self.prefix + label, names.HILLSTONE)[:limit]
        name, counter = base, 2
        while name.lower() in self.names:
            name = f"{base[: limit - 4]}_{counter}"
            counter += 1
        self.names.add(name.lower())
        return name

    def _families(self) -> Set[int]:
        """The IP versions rules are written for: IPv6 only where the policy names an IPv6 address or ICMPv6, or lets
        through what no rule matches."""
        if self.p.default_interzone == Action.ALLOW or self.p.default_intrazone == Action.ALLOW:
            return {4, 6}
        for rule in self.p.rules:
            for member in rule.sources + rule.destinations:
                if member != ANY and 6 in transform.families(self.p, member):
                    return {4, 6}
            for service in rule.services:
                if any(e.protocol == Protocol.ICMP6 for e in transform.flatten_services(self.p, service) or []):
                    return {4, 6}
        return {4}

    # -- zones -----------------------------------------------------------------------------------

    def _zones(self) -> None:
        for zone in self.zones:
            if zone in _PREDEFINED_ZONES:
                self.zone_names[zone] = zone
                continue
            name = self._name(zone)
            self.zone_names[zone] = name
            self.out.zones += [f'zone "{name}"']
            if name != zone and _text(zone):
                self.out.zones.append(f'  description "{_text(zone)}"')
            self.out.zones.append("exit")

    # -- addresses -------------------------------------------------------------------------------

    def _walk(self, member: str, seen: Optional[Set[str]] = None) -> Tuple[List[Interval], List[str], bool]:
        """(addresses, host name objects, whether that is all) of a member of a rule."""
        seen = seen or set()
        if member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.FQDN:
                return [], [member], True
            found, known = transform.known_intervals(self.p, member)
            return found, [], known
        if member in self.p.address_groups:
            group = self.p.address_groups[member]
            if member in seen or group.unsupported or group.dynamic_filter:
                return [], [], False
            intervals: List[Interval] = []
            hosts: List[str] = []
            complete = True
            for inner in group.members:
                got, got_hosts, known = self._walk(inner, seen | {member})
                intervals += got
                hosts += got_hosts
                complete = complete and known
            return intervals, list(dict.fromkeys(hosts)), complete
        found, known = transform.known_intervals(self.p, member)
        return found, [], known

    def _host_family(self, host: str) -> int:
        return self.p.addresses[host].fqdn_family or 4

    def _entry(self, key: str, label: str, family: int, intervals: List[Interval], hosts: List[str]) -> str:
        if key in self.entries:
            return self.entries[key]
        name = self._name(label if family == 4 else f"{label}_v6")
        self.entries[key] = name
        self.out.objects.append(f'address "{name}"' + (" ipv6" if family == 6 else ""))
        self.out.objects += _entry_lines([i for i in intervals if i[0] == family])
        self.out.objects += [f'  host "{_text(self.p.addresses[h].value, 255)}"' for h in hosts]
        self.out.objects.append("exit")
        return name

    def _refs(self, members: List[str], negated: bool, family: int, rule: Optional[Rule], reasons: List[transform.Reason]) -> Optional[List[Ref]]:
        """The values of one side of a rule for one IP version; [] when it holds nothing of that version."""
        if not negated:
            if ANY in members:
                return [("addr", _ANY_NAME[family])]
            out: List[Ref] = []
            for member in members:
                intervals, hosts, known = self._walk(member)
                if not known:
                    reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
                    return None
                mine = normalize([i for i in intervals if i[0] == family])
                hosts = [h for h in hosts if self._host_family(h) == family]
                if hosts and rule is not None and any(not self.p.addresses[h].fqdn_family for h in hosts):
                    self.fqdn_v4.add(rule.origin)
                if not mine and not hosts:
                    continue
                if member in self.p.addresses or member in self.p.address_groups:
                    out.append(("addr", self._entry(f"m:{member}:{family}", member, family, mine, hosts)))
                    continue
                for interval in mine:
                    if interval in (FULL_V4, FULL_V6):
                        out.append(("addr", _ANY_NAME[family]))
                        continue
                    nets = _cidrs(interval)
                    if len(nets) == 1:
                        out.append(("ip", str(nets[0])))
                    else:
                        out.append(("range", str(int_to_ip(family, interval[1])), str(int_to_ip(family, interval[2]))))
            return list(dict.fromkeys(out))
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                return []
            intervals, hosts, known = self._walk(member)
            if not known or hosts:
                reasons.append(("FQDN_NOT_SUPPORTED" if hosts else "ZONE_DYNAMIC",
                                f"every address but '{member}', which holds a host name or members only its platform knows"))  # fmt: skip
                return None
            found += intervals
        left = subtract([FULL_V4 if family == 4 else FULL_V6], [i for i in found if i[0] == family])
        if not left:
            return []
        if left in ([FULL_V4], [FULL_V6]):
            return [("addr", _ANY_NAME[family])]  # (nothing of this IP version is taken out)
        if rule is not None:
            self.report.add("rule", rule.origin, Severity.INFO, "NEGATION_EXPANDED",
                            "a rule of StoneOS cannot negate: written as an address entry of the addresses that are left")  # fmt: skip
        key = "n:" + ",".join(f"{i[0]}-{i[1]}-{i[2]}" for i in left)
        return [("addr", self._entry(key, ("not-" + "-".join(members))[:40], family, left, []))]

    # -- services --------------------------------------------------------------------------------

    @staticmethod
    def _ports(ports: str) -> List[str]:
        return [part.replace("-", " ") for part in ports.split(",")] if ports else ["0 65535"]

    def _service_lines(self, entries: List[ServiceEntry]) -> Optional[Tuple[List[str], bool, bool]]:
        """(lines of a service, whether ICMP of every type is in it, whether every protocol is); None if it cannot be
        written."""
        lines: List[str] = []
        icmp = every = False
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                for dst in self._ports(entry.dst_ports):
                    for src in self._ports(entry.src_ports) if entry.src_ports else [""]:
                        line = f"  {entry.protocol.value} dst-port {dst}"
                        lines.append(line + (f" src-port {src}" if src else ""))
            elif entry.protocol == Protocol.SCTP:
                if entry.dst_ports or entry.src_ports:
                    return None
                lines.append("  protocol 132")
            elif entry.protocol == Protocol.ICMP:
                if entry.icmp_type is None:
                    if entry.icmp_code is not None:
                        return None
                    icmp = True
                    continue
                if entry.icmp_type not in _ICMP_TYPES or (entry.icmp_code is not None and entry.icmp_code > 5):
                    return None
                codes = "" if entry.icmp_code is None else f" code {entry.icmp_code} {entry.icmp_code}"
                lines.append(f"  icmp type {entry.icmp_type}{codes}")
            elif entry.protocol == Protocol.ICMP6:
                return None
            elif entry.ip_protocol is None:
                every = True
            elif entry.ip_protocol in (6, 17):
                lines.append(f"  {'tcp' if entry.ip_protocol == 6 else 'udp'} dst-port 0 65535")
            elif entry.ip_protocol == 1:
                icmp = True
            elif entry.ip_protocol in (0, 58):
                return None
            else:
                lines.append(f"  protocol {entry.ip_protocol}")
        return list(dict.fromkeys(lines)), icmp, every

    def _service_refs(self, name: str, reasons: List[transform.Reason]) -> Optional[List[str]]:
        if name in self.services:
            found = self.services[name]
            if found is None:
                reasons.append(("SERVICE_NOT_WRITTEN", f"service '{name}' cannot be written: ICMPv6, an ICMP type or code a "
                                "service of StoneOS does not take, SCTP with ports, or protocol 0"))  # fmt: skip
            return found
        service = self.p.services.get(name)
        if service is not None and service.builtin == "hillstone" and name in PREDEFINED:
            self.services[name] = [name]
            return [name]
        flat = transform.flatten_services(self.p, name)
        if flat is None:
            if name not in self.taint_s:
                reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
            return None
        found_refs = self._entries_service(flat, name)
        self.services[name] = found_refs
        if found_refs is None:
            return self._service_refs(name, reasons)
        return found_refs

    def _entries_service(self, entries: List[ServiceEntry], label: str) -> Optional[List[str]]:
        written = self._service_lines(entries)
        if written is None:
            return None
        lines, icmp, every = written
        if every:
            return ["Any"]
        out: List[str] = []
        if lines:
            key = "e:" + "|".join(lines)
            if key not in self.entries:
                name = self._name(label)
                self.entries[key] = name
                self.out.objects += [f'service "{name}"'] + lines + ["exit"]
            out.append(self.entries[key])
        if icmp:
            out.append("ICMP")
        return out

    def _rule_services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[str]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
            refs = self._entries_service(entries, "apps-" + "-".join(rule.applications)[:30])
            if refs is None:
                reasons.append(("SERVICE_NOT_WRITTEN", "the ports of the applications cannot be written"))
            return refs
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: a rule of StoneOS lists the services it matches"))
            return None
        if ANY in rule.services:
            return ["Any"]
        out: List[str] = []
        for name in rule.services:
            found = self._service_refs(name, reasons)
            if found is None:
                return None
            if found == ["Any"]:
                return ["Any"]
            out += found
        return list(dict.fromkeys(out))

    # -- rules -----------------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> Optional[List[Tuple[Optional[str], Optional[str]]]]:
        """The (source zone, destination zone) of each rule a rule of the model becomes; None for "any zone"."""
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            every = list(self.zones)
            if not every:
                return None
            sources = every if ANY in rule.src_zones else [z for z in rule.src_zones if z != ANY]
            destinations = every if ANY in rule.dst_zones else [z for z in rule.dst_zones if z != ANY]
            if rule.scope == RuleScope.INTRAZONE:
                return [(z, z) for z in sources]
            return [(a, b) for a in sources for b in destinations if a != b]
        out: List[Tuple[Optional[str], Optional[str]]] = []
        for src, dst in pairs:
            for a in [None] if ANY in src else src:
                for b in [None] if ANY in dst else dst:
                    out.append((a, b))
        return out

    def _rule(self, rule: Rule) -> None:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        services = self._rule_services(rule, reasons)
        sides: Dict[int, Tuple[Optional[List[Ref]], Optional[List[Ref]]]] = {}
        for family in sorted(self.families):
            sides[family] = (self._refs(rule.sources, rule.negate_source, family, rule, reasons),
                             self._refs(rule.destinations, rule.negate_destination, family, rule, reasons))  # fmt: skip
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY", f"action {rule.action.value}: written as deny")
        pairs = self._pairs(rule)
        if pairs is None:
            reasons.append(("NOT_WRITTEN", "traffic inside or between zones, and no zone is known"))
            pairs = [(None, None)]
        broken = services is None or any(src is None or dst is None for src, dst in sides.values())
        versions = [f for f, (src, dst) in sides.items() if src and dst]
        reasons = list(dict.fromkeys(reasons))
        if not versions and not reasons and not broken:
            self.report.skip("rule", rule.origin, "NO_COMMON_FAMILY",
                             "no IP version has addresses on both sides (after negation): the rule matches nothing", Severity.INFO)  # fmt: skip
            return
        disabled = bool(reasons) or broken
        if disabled:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            if not versions:
                versions = [4]
        if len(versions) == 2:
            self.report.add("rule", rule.origin, Severity.INFO, "IP_VERSION_SPLIT",
                            "an address entry of StoneOS is of one IP version: written as an IPv4 and an IPv6 rule")  # fmt: skip
        if rule.origin in self.fqdn_v4:
            self.report.add("rule", rule.origin, Severity.APPROX if rule.action == Action.ALLOW else Severity.REVIEW, "HILLSTONE_FQDN",
                            "a host name is written into an IPv4 address entry: the rule matches the IPv4 addresses it resolves "
                            "to, not its IPv6 ones" + ("" if rule.action == Action.ALLOW else ", and so blocks less"))  # fmt: skip
        if not disabled and rule.enabled and services == ["Any"] and rule.applications == [ANY] \
                and all(sides[f][0] == [("addr", _ANY_NAME[f])] and sides[f][1] == [("addr", _ANY_NAME[f])] for f in self.families):
            for src_zone, dst_zone in pairs:
                inside = ({src_zone} if src_zone else set(self.zones)) & ({dst_zone} if dst_zone else set(self.zones))
                self.inside_decided |= inside
        count = 0
        for family in versions:
            src, dst = sides[family]
            for src_zone, dst_zone in pairs:
                label = rule.name + ("_v6" if family == 6 else "")
                name = self._name(label if len(pairs) == 1 else f"{label}_{count + 1}")
                lines = [f"  rule id {self.next_id}"]
                self.next_id += 1
                count += 1
                if disabled or not rule.enabled:
                    lines.append("    disable")
                lines.append(f'    name "{name}"')
                lines.append("    action " + ("permit" if rule.action == Action.ALLOW else "deny"))
                if src_zone:
                    lines.append(f'    src-zone "{self.zone_names[src_zone]}"')
                if dst_zone:
                    lines.append(f'    dst-zone "{self.zone_names[dst_zone]}"')
                lines += self._side_lines("src", src or [_NOTHING])
                lines += self._side_lines("dst", dst or [_NOTHING])
                lines += [f'    service "{s}"' for s in services or ["Any"]]
                if rule.log_start:
                    lines.append("    log session-start")
                if rule.log_end or rule.log_start:
                    lines.append("    log session-end" if rule.action == Action.ALLOW else "    log policy-deny")
                if _text(rule.description):
                    lines.append(f'    description "{_text(rule.description)}"')
                lines.append("  exit")
                self.out.rules += lines
        self.report.item("rule", rule.origin).emitted_as.append(f"{count} rule{'s' if count > 1 else ''} of policy-global")

    @staticmethod
    def _side_lines(side: str, refs: List[Ref]) -> List[str]:
        out = []
        for ref in refs:
            if ref[0] == "addr":
                out.append(f'    {side}-addr "{ref[1]}"')
            elif ref[0] == "ip":
                out.append(f"    {side}-ip {ref[1]}")
            else:
                out.append(f"    {side}-range {ref[1]} {ref[2]}")
        return out

    def _default_rule(self, zone: str, allow: bool) -> None:
        for family in sorted(self.families):
            name = self._name(f"intrazone_{zone}" + ("_v6" if family == 6 else ""))
            self.out.rules += [f"  rule id {self.next_id}", f'    name "{name}"', "    action " + ("permit" if allow else "deny"),
                               f'    src-zone "{self.zone_names[zone]}"', f'    dst-zone "{self.zone_names[zone]}"',
                               f'    src-addr "{_ANY_NAME[family]}"', f'    dst-addr "{_ANY_NAME[family]}"', '    service "Any"', "  exit"]  # fmt: skip
            self.next_id += 1

    def _defaults(self) -> None:
        inter = self.p.default_interzone == Action.ALLOW
        inside = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        added = []
        for zone in self.zones:
            if inside[zone] != inter and zone not in self.inside_decided:
                self._default_rule(zone, inside[zone])
                added.append(zone)
        if added:
            self.report.note(Severity.INFO, "INTRAZONE_RULES_ADDED",
                             "StoneOS decides traffic inside a zone as it decides traffic between zones; the source does not: "
                             "rules for it were added at the end for " + ", ".join(added[:12]) + (" ..." if len(added) > 12 else ""))  # fmt: skip
        if inter:
            self.out.rules.append("  default-action permit")
            self.report.note(Severity.REVIEW, "HILLSTONE_DEFAULT_PERMIT",
                             "the source allows what no rule matches: the output sets default-action permit, which is the "
                             "firewall's default for all traffic, also of rules that are not part of this policy")  # fmt: skip
        if not self.zones:
            self.report.note(Severity.REVIEW, "HILLSTONE_NO_ZONES",
                             "the source names no zones: the rules are written without zones, so they match between every pair "
                             "of zones and inside every zone; give them zones (--zone-map, or edit them)")  # fmt: skip

    # -- NAT -------------------------------------------------------------------------------------

    def _operand(self, members: List[str], family: int, label: str) -> Optional[str]:
        """One address of a NAT rule: Any, or an address entry for what the members hold."""
        if ANY in members:
            return _ANY_NAME[family]
        intervals: List[Interval] = []
        for member in members:
            got, got_hosts, known = self._walk(member)
            if not known or got_hosts:
                return None
            intervals += got
        mine = normalize([i for i in intervals if i[0] == family])
        if not mine or len(mine) != len(normalize(intervals)):
            return None
        if mine in ([FULL_V4], [FULL_V6]):
            return _ANY_NAME[family]
        if len(members) == 1 and (members[0] in self.p.addresses or members[0] in self.p.address_groups):
            return self._entry(f"m:{members[0]}:{family}", members[0], family, mine, [])
        key = "l:" + ",".join(f"{i[0]}-{i[1]}-{i[2]}" for i in mine)
        return self._entry(key, label, family, mine, [])

    def _family_of(self, nat: NatRule) -> int:
        found: Set[int] = set()
        for member in nat.sources + nat.destinations:
            if member != ANY:
                found |= transform.families(self.p, member)
        if nat.destination_translation is not None and nat.destination_translation.address:
            found |= transform.families(self.p, nat.destination_translation.address)
        if nat.source_translation is not None:
            for member in nat.source_translation.addresses:
                found |= transform.families(self.p, member)
        return 6 if found == {6} else 4 if found <= {4} else 0

    def _nat_service(self, nat: NatRule) -> Optional[str]:
        if nat.service == ANY:
            return "Any"
        refs = self._service_refs(nat.service, [])
        return refs[0] if refs is not None and len(refs) == 1 else None

    def _egress(self, nat: NatRule) -> Tuple[Optional[str], bool]:
        """The egress interface of an SNAT rule: (interface, whether the zones of the rule are said exactly)."""
        if nat.dst_zones == [ANY]:
            return None, True
        interfaces = [self.options.interface_map.get(i, i) for zone in nat.dst_zones
                      for i in transform.target_interfaces(self.p, self.options.zone_map, zone)]  # fmt: skip
        snat = nat.source_translation
        if not interfaces and len(nat.dst_zones) == 1 and snat is not None and snat.interface:
            interfaces = [self.options.interface_map.get(snat.interface, snat.interface)]  # (a zone the source knows by its interface)
        if len(nat.dst_zones) == 1 and len(interfaces) == 1:
            return interfaces[0], True
        return None, False

    def _nat_lines(self, nat: NatRule) -> Tuple[List[str], str]:
        """The lines of one NAT rule of the model, or none and why."""
        if not nat.enabled:
            return [], "the rule is disabled on the source"
        if nat.unsupported:
            return [], "not converted on the source: " + "; ".join(nat.unsupported)[:200]
        family = self._family_of(nat)
        if not family:
            return [], "IPv4 and IPv6 in one rule"
        service = self._nat_service(nat)
        if service is None:
            return [], f"service '{nat.service}' cannot be written as one service of StoneOS"
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is not None:
            if nat.service != ANY or nat.destinations != [ANY]:
                return [], "a static NAT for both directions with a service or a destination"
            inside, outside = pair
            inner = self._entry(f"l:{inside[0]}-{inside[1]}-{inside[2]}", f"nat-{nat.name}-inside", 4, [inside], [])
            outer = self._entry(f"l:{outside[0]}-{outside[1]}-{outside[2]}", f"nat-{nat.name}-outside", 4, [outside], [])
            pair_lines = [f'  snatrule id {self.next_snat} from "{inner}" to "Any" service "Any" trans-to address-book "{outer}" mode static',
                          f'  dnatrule id {self.next_dnat} from "Any" to "{outer}" service "Any" trans-to "{inner}"']  # fmt: skip
            self.next_snat += 1
            self.next_dnat += 1
            return pair_lines, ""
        source = self._operand(nat.sources, family, f"nat-{nat.name}-from")
        destination = self._operand(nat.destinations, family, f"nat-{nat.name}-to")
        if source is None or destination is None:
            return [], "an address of the rule cannot be written as one address entry of one IP version"
        dnat, snat = nat.destination_translation, nat.source_translation
        lines: List[str] = []
        head = f'from "{source}" to "{destination}" service "{service}"'
        if dnat is None and snat is None:
            lines.append(f"  dnatrule id {self.next_dnat} {head} no-trans")
            lines.append(f"  snatrule id {self.next_snat} {head} no-trans")
        if dnat is not None:
            if dnat.spread:
                return [], "a translation to one of several addresses per connection"
            target = self._operand([dnat.address], family, f"nat-{nat.name}-dnat") if dnat.address else None
            if target is None:
                return [], f"the translated address '{dnat.address}' cannot be written as one address entry"
            lines.append(f'  dnatrule id {self.next_dnat} {head} trans-to "{target}"' + (f" port {dnat.port}" if dnat.port else ""))
        if snat is not None:
            eif, exact = self._egress(nat)
            if snat.kind == SnatKind.INTERFACE:
                if eif is None:
                    return [], "source NAT to the interface address, and the egress interface is not known (one zone with one interface)"
                trans = "trans-to eif-ip mode dynamicport"
            else:
                pool = self._operand(snat.addresses, family, f"nat-{nat.name}-pool") if snat.addresses else None
                if pool is None:
                    return [], "the translated addresses cannot be written as one address entry"
                mode = {SnatKind.STATIC: "static", SnatKind.DYNAMIC: "dynamicip", SnatKind.DYNAMIC_PORT: "dynamicport"}[snat.kind]
                trans = f'trans-to address-book "{pool}" mode {mode}'
            if not exact:
                self.report.add("nat", nat.origin, Severity.APPROX, "HILLSTONE_NAT_ZONE",
                                "the destination zones of the rule are not one zone with one known interface: the snatrule "
                                "names no egress interface and translates traffic to every zone")  # fmt: skip
            lines.append(f"  snatrule id {self.next_snat} {head}" + (f" eif {eif}" if eif else "") + f" {trans}")
        if nat.src_zones != [ANY]:
            self.report.add("nat", nat.origin, Severity.APPROX, "HILLSTONE_NAT_ZONE",
                            "the rule is for traffic from " + ", ".join(nat.src_zones) + "; the rule written applies to traffic "
                            "from every zone")  # fmt: skip
        if dnat is not None and nat.dst_zones != [ANY]:
            self.report.add("nat", nat.origin, Severity.APPROX, "HILLSTONE_NAT_ZONE",
                            "the destination zones of the rule are not written: a dnatrule names none")
        if any(line.startswith("  dnatrule") for line in lines):
            self.next_dnat += 1
        if any(line.startswith("  snatrule") for line in lines):
            self.next_snat += 1
        return lines, ""

    # -- output ----------------------------------------------------------------------------------

    def run(self) -> str:
        self._zones()
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        written: Set[str] = set()
        for nat in self.p.nat_rules:
            lines, why = self._nat_lines(nat)
            if not lines:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", f"not converted: {why}")
                continue
            written.add(nat.origin)
            self.report.item("nat", nat.origin).emitted_as.append(" and ".join(line.split()[0] for line in lines))
            self.out.nat += lines
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        out = ["configure"] + self.out.zones + self.out.objects
        if self.out.rules:
            out += ["policy-global"] + self.out.rules + ["exit"]
        if self.out.nat:
            out += ['ip vrouter "trust-vr"'] + self.out.nat + ["exit"]
        out.append("end")
        self._notes()
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        last = self.next_id - 1
        self.report.note(Severity.REVIEW, "HILLSTONE_LOAD",
                         "the output is commands for the configuration mode of StoneOS (section 10): new zones, address entries, "
                         "services, rules of policy-global and NAT rules of trust-vr; they take effect as they are entered, and "
                         f"nothing is saved. The rules have the ids {self.first_id} to {max(last, self.first_id)} (they must be free: "
                         "show policy) and go after the rules the firewall has; move ID top puts one first")  # fmt: skip
        bindings = []
        for zone in self.zones:
            interfaces = [self.options.interface_map.get(i, i) for i in transform.target_interfaces(self.p, self.options.zone_map, zone)]
            bindings += [f'interface {_text(i, 60)} / zone "{self.zone_names[zone]}"' for i in interfaces]
        if bindings:
            self.report.note(Severity.INFO, "HILLSTONE_ZONES",
                             "put the interfaces in their zones (this changes traffic at once): " + "; ".join(bindings[:20])
                             + (" ..." if len(bindings) > 20 else ""))  # fmt: skip
        if self.families == {4} and any(ANY in r.sources + r.destinations for r in self.p.rules if r.enabled and r.action == Action.ALLOW):
            self.report.note(Severity.APPROX, "HILLSTONE_IPV4_ONLY",
                             "the policy names no IPv6 address: rules that match any address are written for IPv4 only (Any); "
                             "IPv6 traffic meets the firewall's default, deny")  # fmt: skip
        if any(r.enabled and (r.log_start or r.log_end) for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules have log lines")
