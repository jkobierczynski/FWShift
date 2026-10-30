# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Zyxel ZLD emitter: neutral model -> a script of CLI commands for a USG FLEX, ATP or VPN firewall with ZLD 4.x or 5.x.

Design rules:

* The output is commands of configuration mode, as the CLI Reference Guide writes them: ``configure terminal``,
  objects, zones, rules, NAT, each block ended by ``exit``. It is pasted into the console or run as a shell script;
  nothing is deleted, nothing is saved (``write`` is left to the person).
* Every object is new and has the prefix (``FWS_`` or ``--target-prefix``): address objects and groups
  (``address-object``, ``address6-object``, ``object-group address``, ``object-group address6``), service objects
  and groups. A rule names one source, one destination and one service, so lists become groups; a negated side
  becomes the ranges it leaves.
* Zones: the zones a ZLD firewall comes with (``LAN1``, ``WAN``, ``DMZ`` ...) and the zones ``--zone-map`` names are
  taken as they are; every other zone is created with the prefix and no member (putting interfaces in it changes
  traffic at once, so that is a comment at the end).
* Each rule of the model becomes ``secure-policy insert N`` (IPv4) and ``secure-policy6 insert N`` (IPv6), one per
  pair of zones and IP version, numbered from ``--policy-id-start`` (1: before the rules the firewall has), each after
  the one before it. A rule that cannot be written as it is, is written ``no activate`` and listed. Every rule is
  written ``no activate`` first and activated last.
* After the rules, the source's default for every pair of the zones written (inside a zone as the source decides it),
  so that the rules the firewall already has decide only traffic of zones the conversion does not know.
* Destination NAT is done before the security policy, which names the inside address: the rules are written for it.
  Destination NAT and 1:1 NAT become ``ip virtual-server`` on the interfaces of the incoming zone; source NAT becomes
  a policy route with ``next-hop auto`` and ``snat``.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import AbstractSet, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, subtract
from ..options import Options
from ..parsers.zyxel import SYSTEM_ZONES
from ..report import Report, Severity

_FULL = {4: FULL_V4, 6: FULL_V6}
_OBJECT = {4: "address-object", 6: "address6-object"}
_GROUP = {4: "object-group address", 6: "object-group address6"}
_LIST = {4: "secure-policy", 6: "secure-policy6"}
_SOURCE = {4: "sourceip", 6: "sourceip6"}
_DESTINATION = {4: "destinationip", 6: "destinationip6"}
_NOTHING = {4: "0.0.0.0", 6: "::"}  # (an address no forwarded packet has: a side that cannot be written, in a rule written inactive)


def _text(text: str, limit: int = 60) -> str:
    """Free text for a description: printable ASCII, no double quote, quoted when it has a space."""
    clean = "".join(c if " " <= c <= "~" and c not in '"?' else " " for c in text).strip()[:limit].strip()
    return f'"{clean}"' if " " in clean else clean


def activate(text: str) -> str:
    """The output as it is once its interfaces are put in their zones: the commented ``zone NAME / interface IF`` lines at
    its end switched on (for reading it back: ``convert --compare``)."""
    return re.sub(r"^#   zone (\S+) / interface (\S+)$", r"zone \1\n interface \2\nexit", text, flags=re.M)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or "FWS_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,11}", prefix):
        raise FwshiftError("--target-prefix for Zyxel: up to 12 letters, digits, underscores and hyphens, starting with a letter")
    probe = _Emitter(p, Report(), options, source_zones)
    written = {nat.origin for nat in p.nat_rules if probe.nat_lines(nat)}
    written -= {nat.origin for nat in p.nat_rules if not probe.nat_lines(nat)}  # (all the rules of an origin, or none)
    translated = {o for o in written if any(n.origin == o and (n.destination_translation is not None or
                                                               (n.source_translation is not None and n.source_translation.bidirectional))
                                             for n in p.nat_rules)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
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
        self.names: Set[str] = set()
        self.objects: List[str] = []
        self.zone_lines: List[str] = []
        self.rules: List[str] = []
        self.servers: List[str] = []
        self.routes: List[str] = []
        self.not_written: List[str] = []
        self.addresses: Dict[Tuple[str, int], Optional[str]] = {}  # (key, IP version) -> object or group
        self.kinds: Dict[str, str] = {}  # object or group name -> "object" or "group"
        self.service_names: Dict[str, Optional[str]] = {}  # key -> service object or group ("" for every protocol)
        start = options.policy_id_start or 1
        self.position = {4: start, 6: start}
        self.route_position = start
        self.decided: Dict[int, Set[Tuple[str, str]]] = {4: set(), 6: set()}
        self.nat_cache: Dict[str, List[str]] = {}
        self.nat_interfaces: Set[str] = set()
        self.counter = 0
        self._zones()

    def _name(self, label: str, limit: int = 31) -> str:
        base = (self.prefix + re.sub(r"[^A-Za-z0-9_-]", "_", label))[:limit]
        name, counter = base, 2
        while name.lower() in self.names:
            name = f"{base[: limit - 4]}_{counter}"
            counter += 1
        self.names.add(name.lower())
        return name

    # -- zones ----------------------------------------------------------------------------------------------

    def _zones(self) -> None:
        kept = set(SYSTEM_ZONES) | set(self.options.zone_map.values())
        for zone in self.zones:
            if zone in kept and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,30}", zone) and zone.lower() not in ("any", "zywall", "device"):
                self.zone_names[zone] = zone
                continue
            name = self._name(zone)
            self.zone_names[zone] = name
            self.zone_lines += [f"zone {name}", "exit"]

    def _zone(self, zone: str) -> str:
        return "any" if zone == ANY else self.zone_names[zone]

    # -- addresses ------------------------------------------------------------------------------------------

    @staticmethod
    def _value(interval: Interval) -> str:
        first, last = int_to_ip(interval[0], interval[1]), int_to_ip(interval[0], interval[2])
        if interval[1] == interval[2]:
            return str(first)
        nets = list(ipaddress.summarize_address_range(first, last))
        return str(nets[0]) if len(nets) == 1 else f"{first}-{last}"

    def _single(self, interval: Interval, label: str) -> str:
        key = (f"i:{interval[0]}:{interval[1]}:{interval[2]}", interval[0])
        found = self.addresses.get(key)
        if found:
            return found
        name = self._name(label)
        self.addresses[key] = name
        self.kinds[name] = "object"
        self.objects.append(f"{_OBJECT[interval[0]]} {name} {self._value(interval)}")
        return name

    def _group(self, key: Tuple[str, int], label: str, members: List[str]) -> str:
        """A group of objects and groups made already (one IP version)."""
        found = self.addresses.get(key)
        if found:
            return found
        family = key[1]
        name = self._name(label)
        self.addresses[key] = name
        self.kinds[name] = "group"
        self.objects.append(f"{_GROUP[family]} {name}")
        for member in transform.dedupe(members):
            self.objects.append(f" {'object-group' if self.kinds[member] == 'group' else _OBJECT[family]} {member}")
        self.objects.append("exit")
        return name

    def _intervals_object(self, intervals: List[Interval], family: int, label: str) -> str:
        if len(intervals) == 1:
            return self._single(intervals[0], label)
        members = [self._single(i, f"{label}_{index + 1}") for index, i in enumerate(intervals)]
        key = ("r:" + ",".join(f"{i[1]}-{i[2]}" for i in intervals), family)
        return self._group(key, label, members)

    def _member(self, member: str, family: int, reasons: List[transform.Reason]) -> Optional[str]:
        """The object or group for a member of a rule, in one IP version; '' when it has no address of that version."""
        key = (member, family)
        if key in self.addresses:
            return self.addresses[key]
        if member in self.taint_a:
            return None  # (said by blocking_reasons)
        if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
            reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: the form of an address object of a host name is not "
                                                  "in the documentation FWShift could read"))  # fmt: skip
            return None
        intervals, known = transform.known_intervals(self.p, member)
        if not known:
            reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
            return None
        intervals = normalize([i for i in intervals if i[0] == family])
        if not intervals:
            return ""
        out: Optional[str]
        group = self.p.address_groups.get(member)
        if group is not None and group.members and not group.unsupported:
            names: List[str] = []
            for inner in group.members:
                found = self._member(inner, family, reasons)
                if found is None:
                    return None
                if found:
                    names.append(found)
            out = self._group((f"g:{member}", family), member if family == 4 or (member, 4) not in self.addresses else f"{member}_6", names)
        else:
            label = member if member in self.p.addresses else member.replace(".", "_").replace(":", "_").replace("/", "_")
            if family == 6 and (member, 4) in self.addresses:
                label += "_6"
            out = self._intervals_object(intervals, family, label)
        self.addresses[key] = out
        return out

    def _union(self, members: List[str], family: int) -> Tuple[List[Interval], bool]:
        out: List[Interval] = []
        complete = True
        for member in members:
            if member == ANY:
                return [_FULL[family]], True
            intervals, known = transform.known_intervals(self.p, member)
            complete = complete and known
            out += [i for i in intervals if i[0] == family]
        return normalize(out), complete

    def _families(self, rule: Rule) -> Set[int]:
        out = {4, 6}
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            found: Set[int] = set()
            if not negated:
                for member in members:
                    found |= transform.families(self.p, member)
            else:
                for family in (4, 6):
                    intervals, complete = self._union(members, family)
                    if subtract([_FULL[family]], intervals) or not complete:
                        found.add(family)
            out &= found
        return out

    def _side(self, rule: Rule, source: bool, family: int, reasons: List[transform.Reason], label: str) -> Optional[str]:
        """The object of one side of a rule in one IP version; '' for any."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        intervals, complete = self._union(members, family)
        if not negated:
            if intervals == [_FULL[family]]:
                return ""
            names: List[str] = []
            for member in members:
                found = self._member(member, family, reasons)
                if found is None:
                    return None
                if found:
                    names.append(found)
            names = transform.dedupe(names)
            if len(names) == 1:
                return names[0]
            if not names:
                return None
            return self._group(("s:" + "\0".join(names), family), f"{label}_{'src' if source else 'dst'}", names)
        if not complete:
            reasons.append(("ZONE_DYNAMIC", "a negated side whose members are not all known as addresses"))
            return None
        left = subtract([_FULL[family]], intervals)
        if not left:
            return None
        if left == [_FULL[family]]:
            return ""  # (the members have no address of this version: every one of it)
        return self._intervals_object(left, family, f"not_{'_'.join(members)}"[:24])

    def _nothing(self, family: int) -> str:
        key = ("nothing", family)
        if key not in self.addresses:
            name = self._name("nothing" if family == 4 else "nothing6")
            self.addresses[key] = name
            self.kinds[name] = "object"
            self.objects.append(f"{_OBJECT[family]} {name} {_NOTHING[family]}")
        found = self.addresses[key]
        assert found is not None
        return found

    # -- services -------------------------------------------------------------------------------------------

    @staticmethod
    def _specs(entry: ServiceEntry) -> Optional[List[str]]:
        """The definitions of service objects for one entry; [''] for every protocol; None if a service object cannot say it."""
        if entry.protocol in (Protocol.TCP, Protocol.UDP):
            if entry.src_ports:
                return None
            if not entry.dst_ports:
                return [f"{entry.protocol.value} range 1 65535"]
            out = []
            for part in entry.dst_ports.split(","):
                first, _, last = part.partition("-")
                if first == "0" and last.isdigit() and int(last) > 0:
                    first = "1"  # (port 0 is no port a connection uses, and ZLD takes 1 to 65535: ZYXEL_PORT_ZERO)
                if not first.isdigit() or int(first) == 0 or (last and not last.isdigit()):
                    return None
                out.append(f"{entry.protocol.value} eq {first}" if not last or last == first else f"{entry.protocol.value} range {first} {last}")
            return out
        if entry.protocol == Protocol.SCTP:
            return None if entry.dst_ports or entry.src_ports else ["protocol 132"]
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            only_code = (Protocol.ICMP, 0), (Protocol.ICMP, 8), (Protocol.ICMP6, 128), (Protocol.ICMP6, 129)  # (echo: code 0 is its only code)
            if entry.icmp_code is not None and not (entry.icmp_code == 0 and (entry.protocol, entry.icmp_type) in only_code):
                return None
            if entry.icmp_type is None:
                return ["protocol 1" if entry.protocol == Protocol.ICMP else "protocol 58"]
            return [("icmp " if entry.protocol == Protocol.ICMP else "icmpv6 ") + str(entry.icmp_type)]
        if entry.ip_protocol is None:
            return [""]
        if entry.ip_protocol == 0:
            return None  # (0 may be read as every protocol)
        return [f"protocol {entry.ip_protocol}"]

    def _spec_object(self, spec: str, label: str) -> str:
        key = "spec:" + spec
        found = self.service_names.get(key)
        if found:
            return found
        name = self._name(label)
        self.service_names[key] = name
        self.kinds[name] = "service"
        self.objects.append(f"service-object {name} {spec}")
        return name

    def _service_group(self, key: str, label: str, members: List[str]) -> str:
        found = self.service_names.get(key)
        if found:
            return found
        name = self._name(label)
        self.service_names[key] = name
        self.kinds[name] = "service-group"
        self.objects.append(f"object-group service {name}")
        for member in transform.dedupe(members):
            self.objects.append(f" {'object-group' if self.kinds[member] == 'service-group' else 'service-object'} {member}")
        self.objects.append("exit")
        return name

    def _entries_object(self, entries: List[ServiceEntry], label: str, reasons: List[transform.Reason]) -> Optional[str]:
        specs: List[str] = []
        for entry in entries:
            found = self._specs(entry)
            if found is None:
                reasons.append(("SERVICE_NOT_WRITTEN", f"service {label}: source ports, an ICMP code, SCTP ports or protocol 0, which a "
                                                       "service object cannot say"))  # fmt: skip
                return None
            specs += found
        if "" in specs:
            return ""
        specs = transform.dedupe(specs)
        if not specs:
            reasons.append(("SERVICE_NOT_WRITTEN", f"service {label} has no entries"))
            return None
        if len(specs) == 1:
            return self._spec_object(specs[0], label)
        members = [self._spec_object(spec, re.sub(r"\s+", "_", spec.replace(" eq ", "_").replace(" range ", "_"))) for spec in specs]
        return self._service_group("e:" + "|".join(specs), label, members)

    def _service(self, name: str, reasons: List[transform.Reason]) -> Optional[str]:
        """The service object or group for a service of the model; '' for every protocol."""
        key = "m:" + name
        if key in self.service_names:
            return self.service_names[key]
        group = self.p.service_groups.get(name)
        out: Optional[str]
        if group is not None and name not in self.p.services:
            members: List[str] = []
            for inner in group.members:
                found = self._service(inner, reasons)
                if found is None or found == "":
                    out = found
                    break
                members.append(found)
            else:
                if not members:
                    reasons.append(("SERVICE_UNKNOWN", f"service group '{name}' is empty"))
                    return None
                out = members[0] if len(members) == 1 else self._service_group(key, name, members)
        else:
            flat = transform.flatten_services(self.p, name)
            if flat is None:
                if name not in self.taint_s:
                    reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                return None
            out = self._entries_object(flat, name, reasons)
        if out is not None:
            self.service_names[key] = out
        return out

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[str]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
            return self._entries_object(entries, ("apps_" + "_".join(rule.applications))[:24], reasons)
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: a service object of ZLD lists what it matches"))
            return None
        if rule.services == [ANY]:
            return ""
        names: List[str] = []
        for name in rule.services:
            found = self._service(name, reasons)
            if found is None:
                return None
            if found == "":
                return ""
            names.append(found)
        names = transform.dedupe(names)
        if len(names) == 1:
            return names[0]
        return self._service_group("r:" + "\0".join(names), f"{rule.name}_svc", names)

    def _source_port(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[Tuple[Optional[str], str]]:
        """(service, ``sourceport`` line) for a rule whose services all have one protocol, TCP or UDP, and one range of source
        ports, which the rule's sourceport says; None for any other rule."""
        if rule.services == [ANY] or rule.negate_service or rule.applications != [ANY]:
            return None
        flat: List[ServiceEntry] = []
        for name in rule.services:
            found = transform.flatten_services(self.p, name)
            if not found:
                return None
            flat += found
        kinds = {e.protocol for e in flat}
        ports = {e.src_ports for e in flat}
        if len(kinds) != 1 or len(ports) != 1 or kinds & {Protocol.TCP, Protocol.UDP} != kinds or "" in ports:
            return None
        port = ports.pop()
        first, _, last = port.partition("-")
        first = "1" if first == "0" and last.isdigit() and int(last) > 0 else first
        if "," in port or not first.isdigit() or int(first) == 0 or (last and not last.isdigit()):
            return None
        kind = kinds.pop().value
        line = f"sourceport {kind} eq {first}" if not last or last == first else f"sourceport {kind} range {first} {last}"
        stripped = [ServiceEntry(e.protocol, e.dst_ports) for e in flat]
        return self._entries_object(stripped, "_".join(rule.services)[:20] + "_dst", reasons), line

    def _no_service(self) -> str:
        return self._spec_object("protocol 255", "noservice")

    # -- rules ----------------------------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> List[Tuple[str, str]]:
        sources = [ANY] if ANY in rule.src_zones else list(rule.src_zones)
        destinations = [ANY] if ANY in rule.dst_zones else list(rule.dst_zones)
        if rule.scope == RuleScope.INTRAZONE:
            return [(z, z) for z in (self.zones if sources == [ANY] else sources)]
        if rule.scope == RuleScope.INTERZONE:
            sources = self.zones if sources == [ANY] else sources
            destinations = self.zones if destinations == [ANY] else destinations
            return [(s, d) for s in sources for d in destinations if s != d]
        return [(s, d) for s in sources for d in destinations]

    def _write(self, family: int, name: str, description: str, pair: Tuple[str, str], source: str, destination: str, service: str,
               action: str, log: bool, active: bool, sourceport: str = "") -> None:  # fmt: skip
        lines = [f"{_LIST[family]} insert {self.position[family]}", f" name {name}", " no activate"]
        self.position[family] += 1
        if description:
            lines.append(f" description {description}")
        if pair[0] != ANY:
            lines.append(f" from {self._zone(pair[0])}")
        if pair[1] != ANY:
            lines.append(f" to {self._zone(pair[1])}")
        if source:
            lines.append(f" {_SOURCE[family]} {source}")
        if destination:
            lines.append(f" {_DESTINATION[family]} {destination}")
        if service:
            lines.append(f" service {service}")
        if sourceport:
            lines.append(f" {sourceport}")
        lines += [f" action {action}", " log" if log else " no log"]
        if active:
            lines.append(" activate")
        self.rules += lines + ["exit"]

    def _rule(self, rule: Rule) -> None:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        sourced = self._source_port(rule, reasons)
        service, sourceport = sourced if sourced is not None else (self._services(rule, reasons), "")
        if service and any(re.match(r"0-|.*,0-", e.dst_ports) for name in rule.services for e in transform.flatten_services(self.p, name) or []
                           if e.protocol in (Protocol.TCP, Protocol.UDP)):  # fmt: skip
            self.report.add("rule", rule.origin, Severity.APPROX, "ZYXEL_PORT_ZERO",
                            "a range of ports from 0: written from 1, as ZLD takes ports 1 to 65535; port 0 is no port a connection uses")  # fmt: skip
        families = sorted(self._families(rule))
        if not families:
            reasons.append(("NOT_WRITTEN", "the sources and the destinations have no IP version in common: the rule matches nothing"))
            families = [4]
        pairs = self._pairs(rule)
        if not pairs:
            reasons.append(("NOT_WRITTEN", "traffic inside or between zones, and no zone is known"))
            pairs = [(ANY, ANY)]
        sides: Dict[int, Tuple[Optional[str], Optional[str]]] = {}
        for family in families:
            sides[family] = (self._side(rule, True, family, reasons, rule.name), self._side(rule, False, family, reasons, rule.name))
        reasons = list(dict.fromkeys(reasons))
        disabled = bool(reasons) or service is None or any(s is None or d is None for s, d in sides.values())
        if disabled:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.not_written.append(f"{rule.name}: " + "; ".join(m for _, m in reasons)[:300])
        action = {Action.ALLOW: "allow", Action.DENY: "deny", Action.DROP: "deny"}.get(rule.action, "reject")
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "ZYXEL_REJECT",
                            f"action {rule.action.value}: written as reject, which answers the sender (TCP reset or ICMP unreachable)")  # fmt: skip
        count = 0
        total = len(pairs) * len(families)
        for pair in pairs:
            for family in families:
                source, destination = sides[family]
                count += 1
                name = self._name(rule.name if total == 1 else f"{rule.name}_{count}", 30)
                self._write(family, name, _text(rule.description), pair, self._nothing(family) if source is None else source,
                            self._nothing(family) if destination is None else destination,
                            self._no_service() if service is None else service, action, rule.log_start or rule.log_end,
                            rule.enabled and not disabled, sourceport if service is not None else "")  # fmt: skip
                if rule.enabled and not disabled and source == "" and destination == "" and service == "" and not sourceport \
                        and rule.applications == [ANY]:
                    self.decided[family].add(pair)
        self.report.item("rule", rule.origin).emitted_as.append(f"{total} rules of the security policy")

    def _defaults(self) -> None:
        inside = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        inter = self.p.default_interzone == Action.ALLOW
        written = 0
        for source in self.zones:
            for destination in self.zones:
                allow = inside[source] if source == destination else inter
                for family in (4, 6):
                    decided = self.decided[family]
                    if (source, destination) in decided or (ANY, destination) in decided or (source, ANY) in decided or (ANY, ANY) in decided:
                        continue
                    written += 1
                    self._write(family, self._name(f"default_{written}", 30), _text(f"FWShift default {source} to {destination}"),
                                (source, destination), "", "", "", "allow" if allow else "deny", False, True)  # fmt: skip
        if written:
            self.report.note(Severity.INFO, "ZYXEL_DEFAULT_RULES",
                             f"after the converted rules, {written} rules that do what the source does with traffic no rule matches, for "
                             "every pair of the zones written (inside a zone as the source decides it): the rules the firewall already "
                             "has decide only traffic of zones the conversion does not know")  # fmt: skip
        if not self.zones:
            self.report.note(Severity.REVIEW, "ZYXEL_NO_ZONES",
                             "the source names no zones: the rules are written from any to any, and what they do not match is decided by "
                             "the rules the firewall has and by its default rule; give the rules zones (--zone-map)")  # fmt: skip

    # -- NAT ------------------------------------------------------------------------------------------------

    def _interfaces(self, zones: List[str]) -> Optional[List[str]]:
        """The interfaces of the zones, as the target names them; None when they are not known."""
        if ANY in zones:
            return [self.options.nat_zone] if self.options.nat_zone else None
        out: List[str] = []
        for zone in zones:
            found = [self.options.interface_map.get(i, i) for i in transform.target_interfaces(self.p, self.options.zone_map, zone)]
            if not found:
                return [self.options.nat_zone] if self.options.nat_zone and len(zones) == 1 else None
            out += found
        out = transform.dedupe(out)
        if any(not re.fullmatch(r"[!-~]{1,31}", i) or i[0] in "#!" or '"' in i or "?" in i for i in out):
            return None  # (not a word a command can take)
        self.nat_interfaces.update(out)
        return out

    def _host(self, member: str) -> Optional[Interval]:
        intervals = transform.address_intervals(self.p, member)
        if not intervals or len(intervals) != 1 or intervals[0][0] != 4:
            return None
        return intervals[0]

    def nat_lines(self, nat: NatRule) -> List[str]:
        key = nat.origin + "\0" + nat.name
        if key not in self.nat_cache:
            self.nat_cache[key] = self._nat_lines(nat)
        return self.nat_cache[key]

    def _nat_lines(self, nat: NatRule) -> List[str]:
        if nat.unsupported:
            return []
        flag = "" if nat.enabled else " deactivate"
        snat, dnat = nat.source_translation, nat.destination_translation
        if snat is not None and snat.kind == SnatKind.STATIC and snat.bidirectional and dnat is None:
            if nat.destinations != [ANY] or nat.service != ANY or len(nat.sources) != 1 or len(snat.addresses) != 1:
                return []
            inside, outside = self._host(nat.sources[0]), self._host(snat.addresses[0])
            interfaces = self._interfaces(nat.dst_zones)
            if inside is None or outside is None or inside[2] - inside[1] != outside[2] - outside[1] or interfaces is None or inside == FULL_V4:
                return []
            if nat.src_zones != [ANY]:
                self.report.add("nat", nat.origin, Severity.APPROX, "ZYXEL_NAT_ZONES",
                                "a 1:1 NAT of ZLD names the outside interface only: the zones of the inside host are not a condition")  # fmt: skip
            original = self._value(outside) if outside[1] == outside[2] else self._member(snat.addresses[0], 4, [])
            mapped = self._value(inside) if inside[1] == inside[2] else self._member(nat.sources[0], 4, [])
            if not original or not mapped:
                return []
            lines = []
            for index, interface in enumerate(interfaces):
                name = self._name(nat.name if len(interfaces) == 1 else f"{nat.name}_{index + 1}")
                lines.append(f"ip virtual-server {name} interface {interface} original-ip {original} map-to {mapped} map-type any nat-1-1-map{flag}")
            return lines
        if dnat is not None and snat is None:
            if len(nat.destinations) != 1 or nat.sources != [ANY] or not dnat.address or dnat.spread:
                return []
            if nat.dst_zones != [ANY] and not set(nat.dst_zones) <= set(nat.src_zones):
                return []
            outer = self._host(nat.destinations[0]) if nat.destinations[0] not in (ANY,) else FULL_V4
            inner = self._host(dnat.address)
            if outer is None or inner is None or inner[1] != inner[2] or (outer[1] != outer[2] and outer != FULL_V4):
                return []
            interfaces = self._interfaces(nat.src_zones)
            if interfaces is None:
                return []
            mapping = self._mapping(nat)
            if mapping is None:
                return []
            original = "any" if outer == FULL_V4 else self._value(outer)
            lines = []
            for index, interface in enumerate(interfaces):
                name = self._name(nat.name if len(interfaces) == 1 else f"{nat.name}_{index + 1}")
                lines.append(f"ip virtual-server {name} interface {interface} original-ip {original} map-to {self._value(inner)} {mapping}{flag}")
            return lines
        if dnat is None and (snat is None or not snat.bidirectional):
            return self._route_lines(nat)
        return []

    def _mapping(self, nat: NatRule) -> Optional[str]:
        """``map-type ...`` of a virtual server for the service and the port of a destination NAT."""
        dnat = nat.destination_translation
        assert dnat is not None
        if nat.service == ANY:
            return None if dnat.port else "map-type any"
        entries = transform.flatten_services(self.p, nat.service)
        if not entries or any(e.protocol not in (Protocol.TCP, Protocol.UDP) or e.src_ports for e in entries):
            return None
        ports = {e.dst_ports for e in entries}
        kinds = {e.protocol for e in entries}
        if len(ports) != 1 or len(entries) != len(kinds):
            return None
        port = ports.pop()
        protocol = "any" if len(kinds) == 2 else kinds.pop().value
        if not port or "," in port:
            return None
        first, _, last = port.partition("-")
        if not last or last == first:
            mapped = dnat.port or first
            if not mapped.isdigit():
                return None
            return f"map-type port protocol {protocol} original-port {first} mapped-port {mapped}"
        if dnat.port and dnat.port != first:
            return None
        return f"map-type ports protocol {protocol} original-port-begin {first} original-port-end {last} mapped-port-begin {first}"

    def _route_lines(self, nat: NatRule) -> List[str]:
        """A policy route with next-hop auto and SNAT, one per incoming interface; without SNAT for a rule that translates
        nothing (it keeps the SNAT of the routes below it from applying to its traffic)."""
        snat = nat.source_translation
        reasons: List[transform.Reason] = []
        sides: List[str] = []
        for members in (nat.sources, nat.destinations):
            if ANY in members:
                sides.append("any")
                continue
            names = []
            for member in members:
                found = self._member(member, 4, reasons)
                if found is None:
                    return []
                if found:
                    names.append(found)
            if not names or any(transform.families(self.p, m) - {4} for m in members):
                return []
            names = transform.dedupe(names)
            sides.append(names[0] if len(names) == 1 else self._group(("n:" + "\0".join(names), 4), f"{nat.name}_{len(sides)}", names))
        service = "any"
        if nat.service != ANY:
            found = self._service(nat.service, reasons)
            if found is None:
                return []
            service = found or "any"
        if snat is None:
            translation = ""
        elif snat.kind == SnatKind.INTERFACE:
            translation = "snat outgoing-interface"
        elif snat.addresses:
            pool: List[Interval] = []
            for member in snat.addresses:
                found_intervals, known = transform.known_intervals(self.p, member)
                if not known:
                    return []
                pool += [i for i in found_intervals if i[0] == 4]
            pool = normalize(pool)
            if len(pool) != 1:
                return []
            named = self._member(snat.addresses[0], 4, []) if len(snat.addresses) == 1 else None
            translation = f"snat pool {named or self._single(pool[0], f'{nat.name}_pool')}"
        else:
            return []
        interfaces: List[str] = []
        if nat.src_zones != [ANY]:
            found_interfaces = self._interfaces(nat.src_zones)
            if found_interfaces is None:
                return []
            interfaces = found_interfaces
        if snat is not None and snat.kind not in (SnatKind.INTERFACE, SnatKind.DYNAMIC_PORT):
            self.report.add("nat", nat.origin, Severity.APPROX, "ZYXEL_SNAT_POOL_PORTS",
                            f"source NAT of kind {snat.kind.value} written as SNAT to a pool, which the documentation does not say "
                            "translates ports or not")  # fmt: skip
        if snat is None:
            self.report.add("nat", nat.origin, Severity.APPROX, "ZYXEL_EXEMPTION",
                            "a rule that translates nothing, written as a policy route without SNAT: it keeps the source NAT of the policy "
                            "routes below it from applying, not virtual servers, 1:1 NAT or the default SNAT of a WAN trunk")  # fmt: skip
        elif nat.dst_zones != [ANY]:
            self.report.add("nat", nat.origin, Severity.APPROX, "ZYXEL_SNAT_EGRESS",
                            "a policy route cannot name the interface traffic leaves by: the source NAT applies wherever routing sends "
                            "the traffic it matches")  # fmt: skip
        lines: List[str] = []
        for interface in interfaces or [""]:
            lines += [f"policy insert {self.route_position}", " deactivate", f" description {_text('FWShift ' + nat.name)}"]
            self.route_position += 1
            if interface:
                lines.append(f" interface {interface}")
            lines += [f" source {sides[0]}", f" destination {sides[1]}", f" service {service}", " next-hop auto"]
            lines += [f" {translation}"] if translation else []
            if nat.enabled:
                lines.append(" no deactivate")
            lines.append("exit")
        return lines

    # -- output ---------------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            lines = self.nat_lines(nat)
            if not lines:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: ZLD writes a virtual server for one address or port (or a range of ports) arriving on the "
                                 "interfaces of a zone, a 1:1 NAT of one address or range, and source NAT to the outgoing interface or "
                                 "to one pool by a policy route")  # fmt: skip
                continue
            routed = lines[0].startswith("policy ")
            self.report.item("nat", nat.origin).emitted_as.append("policy route" if routed else "virtual server")
            (self.routes if routed else self.servers).extend(lines)
        start = self.options.policy_id_start or 1
        out = ["# Generated by FWShift: commands for the CLI of a Zyxel firewall with ZLD 4.x or 5.x (USG FLEX, ATP, VPN).",
               "# Read the report first: what is not written is listed there. Nothing is deleted and nothing is saved.",
               f"# The rules are inserted from position {start} of the security policy on, each after the one before it,",
               f"# before the rules the firewall has. Every name starts with {self.prefix}. Check, then save with write.",
               "configure terminal"]  # fmt: skip
        out += self.objects + self.zone_lines + self.rules + self.servers + self.routes + ["exit"]
        tail = ["# Put the interfaces in their zones (this changes traffic at once):"]
        for zone in self.zones:
            interfaces = [self.options.interface_map.get(i, i) for i in transform.target_interfaces(self.p, self.options.zone_map, zone)]
            for interface in interfaces:
                tail.append(f"#   zone {self.zone_names[zone]} / interface {_text(interface, 31)}")
            if not interfaces:
                tail.append(f"#   zone {self.zone_names[zone]}: no interface is known")
        if self.not_written:
            tail += ["# Written inactive:"] + [f"#   {_text(line, 300).strip(chr(34))}" for line in self.not_written]
        self._notes()
        return "\n".join(out + tail) + "\n"

    def _notes(self) -> None:
        start = self.options.policy_id_start or 1
        self.report.note(Severity.REVIEW, "ZYXEL_LOAD",
                         "the output is a script of CLI commands (section 10): new objects, zones without members, rules inserted from "
                         f"position {start} of the security policy on (before the rules the firewall has, which still decide what these do "
                         "not match), virtual servers and policy routes, which take effect at once. Check, then save with write")  # fmt: skip
        if any(r.enabled and (r.log_start or r.log_end) for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules have log")
        if self.nat_interfaces and self.p.vendor != "zyxel":
            self.report.note(Severity.REVIEW, "ZYXEL_NAT_INTERFACES",
                             "virtual servers and policy routes name the interfaces of the zones as the source names them (after "
                             "--interface-map): check that the firewall has them (ge1, wan1 ...): "
                             + ", ".join(sorted(self.nat_interfaces)[:12]))  # fmt: skip
        if self.servers:
            self.report.note(Severity.INFO, "ZYXEL_NAT_WRITTEN",
                             "virtual servers are done before the security policy, whose rules name the inside address: the rules were "
                             "written for it")  # fmt: skip
