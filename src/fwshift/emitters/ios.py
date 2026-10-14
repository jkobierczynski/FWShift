# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco IOS and IOS XE emitter: neutral model -> configuration commands for the zone-based policy firewall.

Design rules:

* The zones of the model become zones of the zone-based firewall (``zone security``); a rule becomes an access list
  and an inspect class map that matches it, put in the inspect policy of every zone pair the rule applies to, in the
  order of the model. ``class-default`` ends each policy with the default of the source.
* Allow rules inspect (stateful) what can be inspected: TCP, UDP and ICMP. The rest of what they allow (GRE, ESP,
  other protocols) is let through with ``pass``, which is one way: the replies need a pass the other way, which is not
  written (the converted policy allows less), and said. Blocking rules drop.
* Inside one zone IOS passes everything unless a zone pair from the zone to itself says otherwise: such a pair is
  written where the source decides traffic inside a zone otherwise.
* Addresses are object groups (IPv4) or entries of the list (IPv6, which classic IOS has no object groups for), with
  wildcard masks; services are the entries of the list, with ports, ICMP types and protocol numbers. What is
  negated becomes the addresses or services that are left (a list may deny what its class does not take).
* Nothing changes traffic until interfaces are put in the zones: the ``zone-member security`` lines are comments to
  move into the interfaces, as are the NAT commands and the interfaces' ``ip nat inside``/``outside``. The class maps
  see the inside address of a static translation, so the rules are written for it.
* New names only, all of them with a prefix (``FWS-`` or ``--target-prefix``): IOS adds entries to a list that
  exists, so a name that is taken must be checked before loading.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Rule, RuleScope, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, subtract
from ..options import Options
from ..report import Report, Severity

_MAX_ENTRIES = 4000  # entries of one access list
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,31}")
_TCP_UDP_ICMP = regions.Services({6: [regions.WHOLE], 17: [regions.WHOLE], 1: [regions.WHOLE], 58: [regions.WHOLE]}, False)


def _nets(interval: Interval) -> List[ipaddress.IPv4Network]:
    first, last = ipaddress.IPv4Address(interval[1]), ipaddress.IPv4Address(interval[2])
    return [net for net in ipaddress.summarize_address_range(first, last) if isinstance(net, ipaddress.IPv4Network)]


def _wildcard(interval: Interval) -> List[str]:
    """IPv4 address and wildcard pairs (``host A`` for one address) for an interval."""
    out = []
    for net in _nets(interval):
        if net.num_addresses == 1:
            out.append(f"host {net.network_address}")
        elif net.prefixlen == 0:
            out.append("any")
        else:
            out.append(f"{net.network_address} {net.hostmask}")
    return out


def _prefixes(interval: Interval) -> List[str]:
    out = []
    for net in ipaddress.summarize_address_range(int_to_ip(6, interval[1]), int_to_ip(6, interval[2])):
        out.append(f"host {net.network_address}" if net.num_addresses == 1 else "any" if net.prefixlen == 0 else str(net))
    return out


def _printable(text: str) -> str:
    return "".join(c if c.isprintable() else " " for c in text)


def _ports(low: int, high: int) -> str:
    if (low, high) == (0, 65535):
        return ""
    if low == high:
        return f" eq {low}"
    if low == 0:
        return f" lt {high + 1}"
    if high == 65535:
        return f" gt {low - 1}"
    return f" range {low} {high}"


@dataclass
class _Class:
    """A class map and the access lists it matches."""

    name: str
    action: str  # inspect, pass, drop
    log: bool
    origin: str
    acls: List[Tuple[str, str, List[str]]] = field(default_factory=list)  # (name, ip|ipv6, entries)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or ""
    if prefix and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,15}", prefix):
        raise FwshiftError("--target-prefix for IOS: up to 16 letters, digits, periods, underscores and hyphens, starting with a letter")
    planner = _Emitter(p, report, options)
    written = {nat.origin for nat in p.nat_rules if planner.nat_lines(nat)}
    transform.to_post_nat_lookup(p, report, {o for o in written if _translates_destination(p, o)})
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _translates_destination(p: Policy, origin: str) -> bool:
    for nat in p.nat_rules:
        if nat.origin == origin:
            return nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None
    return False


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.prefix = options.object_prefix or "FWS-"
        if not self.prefix.endswith(("-", "_", ".")):
            self.prefix += "-"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.zones = transform.dedupe(list(p.zones) + used)
        self.zone_names: Dict[str, str] = {}
        taken: Set[str] = set()
        for zone in self.zones:
            # (with the prefix, as every name written: a zone that exists, or the default zone of IOS XE, would take in
            # interfaces or zone pairs of the router)
            name = (self.prefix + re.sub(r"[^A-Za-z0-9_.-]", "-", zone))[:32]
            base, counter = name, 2
            while name.lower() in taken or name.lower() in ("self", "default"):
                name = f"{base[:28]}-{counter}"
                counter += 1
            taken.add(name.lower())
            self.zone_names[zone] = name
        self.counter = 0
        self.groups: Dict[Tuple[Interval, ...], str] = {}
        self.lines_groups: List[str] = []
        self.not_written: List[str] = []
        self.nat_names: List[str] = []
        self.nat_cache: Dict[str, List[str]] = {}

    def _next(self) -> str:
        self.counter += 1
        return f"{self.prefix}R{self.counter}"

    # -- addresses and services --------------------------------------------------------------

    def _resolve(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Dict[int, List[Interval]]]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        side = "source" if source else "destination"
        found: Dict[int, List[Interval]] = {4: [], 6: []}
        for member in members:
            if member == ANY:
                found = {4: [FULL_V4], 6: [FULL_V6]}
                break
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: an access list of IOS names addresses"))
                return None
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"the {side} '{member}' holds members only its platform knows; an access list names addresses"))
                return None
            for interval in intervals:
                found[interval[0]].append(interval)
        found = {v: normalize(ivs) for v, ivs in found.items()}
        if negated:
            found = {4: subtract([FULL_V4], found[4]), 6: subtract([FULL_V6], found[6])}
        return found

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[regions.Services]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            svc = regions.service_set(entries) if entries else None
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
        return regions.ALL_SERVICES.minus(svc) if rule.negate_service else svc

    def _group(self, intervals: List[Interval]) -> str:
        key = tuple(intervals)
        if key in self.groups:
            return self.groups[key]
        name = f"{self.prefix}N{len(self.groups) + 1}"
        self.groups[key] = name
        self.lines_groups.append(f"object-group network {name}")
        for interval in intervals:
            if interval[1] == interval[2]:
                self.lines_groups.append(f" host {int_to_ip(4, interval[1])}")
                continue
            nets = _nets(interval)
            if len(nets) == 1:
                self.lines_groups.append(f" {nets[0].network_address} {nets[0].netmask}")
            else:
                self.lines_groups.append(f" range {int_to_ip(4, interval[1])} {int_to_ip(4, interval[2])}")
        return name

    def _sides(self, version: int, intervals: List[Interval]) -> List[str]:
        if version == 4:
            if intervals == [FULL_V4]:
                return ["any"]
            if len(intervals) == 1 and len(_wildcard(intervals[0])) == 1:
                return _wildcard(intervals[0])
            return [f"object-group {self._group(intervals)}"]
        return [text for interval in intervals for text in _prefixes(interval)]

    @staticmethod
    def _service_parts(svc: regions.Services, version: int) -> Optional[Tuple[List[Tuple[str, str, str]], bool]]:
        """(protocol, source part, destination part) per entry of a list, and whether they are exclusions."""
        found = regions.entries_of(svc, version, limit=_MAX_ENTRIES)
        if found is None:
            return None
        entries, negated = found
        out: List[Tuple[str, str, str]] = []
        names = {"tcp": "tcp", "udp": "udp", "sctp": "sctp" if version == 6 else "132"}
        for entry in entries:
            kind = entry.protocol.value
            if kind in names:
                for sport in (entry.src_ports or "0-65535").split(","):
                    s_low, _, s_high = sport.partition("-")
                    for dport in (entry.dst_ports or "0-65535").split(","):
                        d_low, _, d_high = dport.partition("-")
                        if kind == "sctp" and ((int(s_low), int(s_high or s_low)) != (0, 65535) or (int(d_low), int(d_high or d_low)) != (0, 65535)):
                            return None  # (IOS takes ports for TCP and UDP only)
                        out.append((names[kind], _ports(int(s_low), int(s_high or s_low)), _ports(int(d_low), int(d_high or d_low))))
            elif kind in ("icmp", "icmp6"):
                if (kind == "icmp") != (version == 4):
                    continue
                tail = "" if entry.icmp_type is None else f" {entry.icmp_type}" + ("" if entry.icmp_code is None else f" {entry.icmp_code}")
                out.append(("icmp", "", tail))
            else:
                number = entry.ip_protocol
                if number == 0:
                    return None  # (IOS may read protocol 0 as every protocol)
                out.append(("ip" if version == 4 else "ipv6", "", "") if number is None else (str(number), "", ""))
        return out, negated

    def _acl(self, version: int, svc: regions.Services, src: List[Interval], dst: List[Interval],
             reasons: List[transform.Reason]) -> Optional[List[str]]:  # fmt: skip
        """Entries of a list that permits what a class takes: ``svc`` from ``src`` to ``dst``."""
        parts = self._service_parts(svc, version)
        if parts is None:
            reasons.append(("SERVICE_NOT_WRITTEN", "the services of the rule are too many, SCTP with ports (which IOS does not filter) or "
                            "protocol 0"))
            return None
        entries, negated = parts
        sources, destinations = self._sides(version, src), self._sides(version, dst)
        out: List[str] = []
        anything = "ip" if version == 4 else "ipv6"
        for s in sources:
            for d in destinations:
                if negated:  # (every service but the entries; no entries: every service)
                    out += [f"deny {protocol} {s}{sport} {d}{dport}" for protocol, sport, dport in entries]
                    out.append(f"permit {anything} {s} {d}")
                else:  # (no entries: nothing of this IP version)
                    out += [f"permit {protocol} {s}{sport} {d}{dport}" for protocol, sport, dport in entries]
        if len(out) > _MAX_ENTRIES:
            reasons.append(("LIST_TOO_LONG", f"more than {_MAX_ENTRIES} entries in its access list"))
            return None
        return out

    # -- rules ------------------------------------------------------------------------------

    def _classes(self, rule: Rule) -> List[_Class]:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.schedule:
            reasons.append(("SCHEDULE", f"schedule {rule.schedule} is not converted"))
        src = self._resolve(rule, True, reasons)
        dst = self._resolve(rule, False, reasons)
        svc = self._services(rule, reasons)
        if reasons or src is None or dst is None or svc is None:
            transform.disable_rule(self.report, rule, list(dict.fromkeys(reasons)) or [("NOT_WRITTEN", "the rule cannot be written")])
            self.not_written.append(f"{rule.name}: " + "; ".join(m for _, m in dict.fromkeys(reasons))[:300])
            return []
        if not rule.enabled:
            self.report.skip("rule", rule.origin, "DISABLED_NOT_WRITTEN", "disabled in the source; a zone-based firewall has no disabled class: not written",
                             Severity.INFO)  # fmt: skip
            return []
        allow = rule.action == Action.ALLOW
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY",
                            f"action {rule.action.value}: the zone-based firewall drops without an answer")  # fmt: skip
        pieces: List[Tuple[str, regions.Services]] = []
        if allow:
            inspected = svc.and_(_TCP_UDP_ICMP)
            passed = svc.minus(_TCP_UDP_ICMP)
            if not inspected.empty():
                pieces.append(("inspect", inspected))
            if not passed.empty():
                pieces.append(("pass", passed))
                self.report.add("rule", rule.origin, Severity.APPROX, "IOS_PASS",
                                "protocols other than TCP, UDP and ICMP are let through with pass, which is one way: their replies need "
                                "a pass from the other zone, which is not written, so the converted rule allows less")  # fmt: skip
            if rule.log_start or rule.log_end:
                self.report.add("rule", rule.origin, Severity.INFO, "IOS_LOG_ALLOW",
                                "logging of what the rule allows is not written (inspect logs through a parameter map)")  # fmt: skip
        else:
            pieces.append(("drop", svc))
        out: List[_Class] = []
        for action, part in pieces:
            item = _Class(self._next(), action, bool((rule.log_start or rule.log_end) and action != "inspect"), rule.origin)
            failed = False
            for version in (4, 6):
                if not src[version] or not dst[version]:
                    continue
                entries = self._acl(version, part, src[version], dst[version], reasons)
                if entries is None:
                    failed = True
                    break
                if entries:
                    item.acls.append((item.name if version == 4 else f"{item.name}-V6", "ip" if version == 4 else "ipv6", entries))
            if failed:
                transform.disable_rule(self.report, rule, list(dict.fromkeys(reasons)))
                self.not_written.append(f"{rule.name}: " + "; ".join(m for _, m in dict.fromkeys(reasons))[:300])
                return []
            if item.acls:
                out.append(item)
        if not out:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING", "the rule matches no connection of either IP version here", Severity.INFO)
        return out

    def _intra(self, zone: str, default: bool) -> bool:
        found = self.p.zones.get(zone)
        return default if found is None or found.intrazone_allow is None else found.intrazone_allow

    def _applies(self, rule: Rule, source: str, destination: str) -> bool:
        if rule.scope == RuleScope.INTRAZONE:  # (inside each of its source zones, whatever its destination zones say)
            return source == destination and (ANY in rule.src_zones or source in rule.src_zones)
        if rule.scope == RuleScope.INTERZONE and source == destination:
            return False
        return (ANY in rule.src_zones or source in rule.src_zones) and (ANY in rule.dst_zones or destination in rule.dst_zones)

    # -- NAT ---------------------------------------------------------------------------------

    def _interface(self, zone: str) -> str:
        found = self.p.zones.get(zone)
        names = [self.options.interface_map.get(i, i) for i in (found.interfaces if found else [])]
        return names[0] if len(names) == 1 and re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]*", names[0]) else ""

    def nat_lines(self, nat: NatRule) -> List[str]:
        """The commands for a NAT rule; empty when it cannot be written."""
        key = nat.origin + "\0" + nat.name
        if key not in self.nat_cache:
            self.nat_cache[key] = self._nat_lines(nat)
        return self.nat_cache[key]

    def _nat_lines(self, nat: NatRule) -> List[str]:
        if not nat.enabled or nat.unsupported:
            return []
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is not None and pair[0][0] == 4:
            inside, outside = pair
            if inside[1] == inside[2]:
                return [f"ip nat inside source static {int_to_ip(4, inside[1])} {int_to_ip(4, outside[1])}"]
            nets = _nets(inside)
            if len(nets) == 1 and (outside[1] & (nets[0].num_addresses - 1)) == 0:
                return [f"ip nat inside source static network {nets[0].network_address} {int_to_ip(4, outside[1])} /{nets[0].prefixlen}"]
            return []
        dnat = nat.destination_translation
        if dnat is not None and nat.source_translation is None and len(nat.destinations) == 1:
            outer = transform.known_intervals(self.p, nat.destinations[0])[0]
            inner = transform.known_intervals(self.p, dnat.address)[0] if dnat.address else []
            if len(outer) != 1 or len(inner) != 1 or outer[0][1] != outer[0][2] or inner[0][1] != inner[0][2] or outer[0][0] != 4:
                return []
            entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else []
            if dnat.port and entries and len(entries) == 1 and entries[0].protocol.value in ("tcp", "udp") and entries[0].dst_ports.isdigit() \
                    and not entries[0].src_ports and dnat.port.isdigit():
                return [f"ip nat inside source static {entries[0].protocol.value} {int_to_ip(4, inner[0][1])} {dnat.port} "
                        f"{int_to_ip(4, outer[0][1])} {entries[0].dst_ports} extendable"]  # fmt: skip
            return []
        snat = nat.source_translation
        if snat is None or nat.destination_translation is not None or nat.service != ANY:
            return []
        if snat.kind == SnatKind.INTERFACE and len(nat.dst_zones) == 1 and nat.dst_zones[0] != ANY:
            interface = self._interface(nat.dst_zones[0])
            if not interface:
                return []
            acl = self._nat_acl(nat)
            return [] if acl is None else acl + [f"ip nat inside source list {acl[0].split()[-1]} interface {interface} overload"]
        if snat.kind == SnatKind.DYNAMIC_PORT and len(snat.addresses) == 1:
            pool = transform.known_intervals(self.p, snat.addresses[0])[0]
            if len(pool) != 1 or pool[0][0] != 4:
                return []
            acl = self._nat_acl(nat)
            if acl is None:
                return []
            first, last = pool[0][1], pool[0][2]
            length = min(32 - (first ^ last).bit_length(), 30)
            name = acl[0].split()[-1] + "-POOL"
            return acl + [f"ip nat pool {name} {int_to_ip(4, first)} {int_to_ip(4, last)} prefix-length {length}",
                          f"ip nat inside source list {acl[0].split()[-1]} pool {name} overload"]  # fmt: skip
        return []

    def _nat_acl(self, nat: NatRule) -> Optional[List[str]]:
        src: List[Interval] = []
        dst: List[Interval] = []
        for member in nat.sources:
            if member == ANY:
                src = [FULL_V4]
                break
            found, known = transform.known_intervals(self.p, member)
            if not known:
                return None
            src += [i for i in found if i[0] == 4]
        for member in nat.destinations:
            if member == ANY:
                dst = [FULL_V4]
                break
            found, known = transform.known_intervals(self.p, member)
            if not known:
                return None
            dst += [i for i in found if i[0] == 4]
        src, dst = normalize(src), normalize(dst)
        if not src or not dst:
            return None
        name = f"{self.prefix}NAT{len(self.nat_names) + 1}"
        self.nat_names.append(name)
        lines = [f"ip access-list extended {name}"]
        for s in src:
            for s_text in _wildcard(s):
                for d in dst:
                    for d_text in _wildcard(d):
                        lines.append(f" permit ip {s_text} {d_text}")
        return lines

    # -- output ------------------------------------------------------------------------------

    def run(self) -> str:
        self.nat_names = []
        classes: Dict[str, List[_Class]] = {}
        for rule in self.p.rules:
            classes[rule.origin + "\0" + rule.name] = self._classes(rule)
        default_inter = self.p.default_interzone == Action.ALLOW
        default_intra = self.p.default_intrazone == Action.ALLOW
        pairs: List[Tuple[str, str, List[Tuple[_Class, Rule]]]] = []
        for source in self.zones:
            for destination in self.zones:
                found = [(c, rule) for rule in self.p.rules for c in classes[rule.origin + "\0" + rule.name] if self._applies(rule, source, destination)]
                default = self._intra(source, default_intra) if source == destination else default_inter
                if not found and ((source == destination and default) or (source != destination and not default)):
                    continue  # (what IOS does without a zone pair is the default here)
                pairs.append((source, destination, found))
        out = ["! Generated by FWShift: the zone-based policy firewall of Cisco IOS / IOS XE. Read the report first: what is",
               "! not written is listed there. Nothing below changes traffic until interfaces are put in the zones (the",
               "! commented lines at the end). IOS adds entries to an access list or class map of the same name: check that no",
               f"! name starting with {self.prefix} is taken (show running-config | include {self.prefix}).", "!"]  # fmt: skip
        body: List[str] = []
        written_classes: Set[str] = set()
        for _, _, found in pairs:
            for item, _ in found:
                if item.name in written_classes:
                    continue
                written_classes.add(item.name)
                for name, kind, entries in item.acls:
                    body.append(f"ip access-list extended {name}" if kind == "ip" else f"ipv6 access-list {name}")
                    body += [f" {entry}" for entry in entries]
                body.append(f"class-map type inspect match-any {item.name}")
                body += [f" match access-group name {name}" for name, _, _ in item.acls]
                body.append("!")
        intra = False
        for index, (source, destination, found) in enumerate(pairs, 1):
            policy = f"{self.prefix}PM{index}"
            default = self._intra(source, default_intra) if source == destination else default_inter
            intra = intra or source == destination
            if default:
                any_name = f"{self.prefix}ANY{index}"
                body += [f"ip access-list extended {any_name}", " permit tcp any any", " permit udp any any", " permit icmp any any",
                         f"ipv6 access-list {any_name}-V6", " permit tcp any any", " permit udp any any", " permit icmp any any",
                         f"class-map type inspect match-any {any_name}", f" match access-group name {any_name}",
                         f" match access-group name {any_name}-V6", "!"]  # fmt: skip
            body.append(f"policy-map type inspect {policy}")
            for item, _ in found:
                body += [f" class type inspect {item.name}", f"  {item.action}" + (" log" if item.log else "")]
            if default:
                body += [f" class type inspect {any_name}", "  inspect"]
            body += [" class class-default", "  pass" if default else "  drop"]
            body.append("!")
        for zone in self.zones:
            body.append(f"zone security {self.zone_names[zone]}")
            if self.zone_names[zone] != zone:
                body.append(f" description {_printable(zone)[:180]}")
        body.append("!")
        for index, (source, destination, _) in enumerate(pairs, 1):
            zs, zd = self.zone_names[source], self.zone_names[destination]
            body += [f"zone-pair security {self.prefix}ZP{index}-{zs}-{zd}"[:128] + f" source {zs} destination {zd}",
                     f" service-policy type inspect {self.prefix}PM{index}"]  # fmt: skip
        body.append("!")
        nat_lines: List[str] = []
        for nat in self.p.nat_rules:
            lines = self.nat_lines(nat)
            if lines:
                nat_lines += lines
                self.report.item("nat", nat.origin).emitted_as.append("ip nat inside source")
            else:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: IOS writes static translations of one address, network or port, and port translation "
                                 "to an interface or a pool for a list of sources and destinations")  # fmt: skip
        tail = ["! Put each interface in its zone; this changes traffic at once (between zones only what the policies let",
                "! through passes; between an interface in a zone and one in none nothing does):"]  # fmt: skip
        for zone in self.zones:
            found_zone = self.p.zones.get(zone)
            interfaces = [self.options.interface_map.get(i, i) for i in (found_zone.interfaces if found_zone else [])]
            if not interfaces:
                tail.append(f"! zone {self.zone_names[zone]}: no interface is known; put its interfaces in it")
            for interface in interfaces:
                tail += [f"! interface {_printable(interface)}", f"!  zone-member security {self.zone_names[zone]}"]
        if nat_lines:
            inside = transform.dedupe([z for nat in self.p.nat_rules if self.nat_lines(nat) for z in nat.src_zones if z != ANY])
            outside = transform.dedupe([z for nat in self.p.nat_rules if self.nat_lines(nat) for z in nat.dst_zones if z != ANY])
            tail += ["!", "! NAT, which changes traffic at once on interfaces with ip nat inside or outside:"]
            tail += [f"! {line}" for line in nat_lines]
            for zone in inside:
                tail.append(f"! (the interfaces of zone {self.zone_names.get(zone, zone)}: ip nat inside)")
            for zone in outside:
                tail.append(f"! (the interfaces of zone {self.zone_names.get(zone, zone)}: ip nat outside)")
        if self.not_written:
            tail += ["!", "! Not written:"] + [f"!   {''.join(c if c.isprintable() else ' ' for c in line)}" for line in self.not_written]
        self._notes(intra)
        return "\n".join(out + self.lines_groups + (["!"] if self.lines_groups else []) + body + tail + ["end"]) + "\n"

    def _notes(self, intra: bool) -> None:
        self.report.note(Severity.REVIEW, "IOS_LOAD",
                         "the output is configuration commands for the zone-based firewall (section 10): paste them in configuration "
                         "mode; nothing changes until interfaces are put in the zones (zone-member security, commented at the end). "
                         f"Names start with {self.prefix}: IOS adds to an access list or class map that exists")  # fmt: skip
        self.report.note(Severity.REVIEW, "IOS_ZONE_MEMBERS",
                         "an interface in a zone passes only what the zone pairs let through, and nothing to an interface in no zone; "
                         "traffic to and from the router itself (the self zone) is not written. Put every interface that forwards "
                         "traffic in a zone")  # fmt: skip
        if intra:
            self.report.note(Severity.INFO, "IOS_INTRAZONE",
                             "zone pairs from a zone to itself decide traffic inside a zone (IOS 15.0(1)M and IOS XE); IOS passes "
                             "it otherwise")  # fmt: skip
        if any(self.nat_lines(nat) for nat in self.p.nat_rules):
            self.report.note(Severity.REVIEW, "IOS_ZBFW_NAT",
                             "the class maps were written for the inside address of a static translation (the destination after "
                             "translation), as the zone-based firewall is read to see it. Cisco does not document this; check one "
                             "translated connection on the router")  # fmt: skip
        if any(r.enabled and (r.log_start or r.log_end) for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their drop and pass actions log")
