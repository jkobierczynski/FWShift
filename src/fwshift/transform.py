# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Target-independent passes over the neutral model, shared by the emitters."""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from enum import Enum
from typing import AbstractSet, Any, Dict, List, Mapping, Optional, Set, Tuple, TypeVar

from .appmap import entries_for, valid_ports
from .errors import FwshiftError
from .model import (
    ANY,
    ANY_V4,
    APP_DEFAULT,
    L4_PROTOCOLS,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    Service,
    ServiceEntry,
    ServiceGroup,
    SnatKind,
)
from .names import NameRules, clean, unique
from .netutil import FULL_V4, FULL_V6, Interval, is_number, normalize, overlaps, parse_literal, size, within
from .report import Report, Severity

Reason = Tuple[str, str]
G = TypeVar("G", AddressGroup, ServiceGroup)


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HOST_NAME = re.compile(r"[A-Za-z0-9_*]([A-Za-z0-9_*.-]*[A-Za-z0-9_*])?\.?")
_FREE_TEXT = ("description", "raw")  # written as comments only, and cleaned where they are written

# -- what no output may be built from -------------------------------------


def _without_control(value: Any, free_text: bool = False) -> Any:
    """The value with control characters taken out of every string that is a name or part of one."""
    if isinstance(value, Enum):
        return value
    if isinstance(value, str):
        return value if free_text else _CONTROL.sub("_", value)
    if isinstance(value, list):
        return [_without_control(item) for item in value]
    if isinstance(value, dict):
        out: Dict[Any, Any] = {}
        for key, item in value.items():
            cleaned = _without_control(key)
            if cleaned in out:
                raise FwshiftError(f"two names differ only in control characters: {cleaned!r}")
            out[cleaned] = _without_control(item)
        return out
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for item in dataclasses.fields(value):
            setattr(value, item.name, _without_control(getattr(value, item.name), item.name in _FREE_TEXT))
    return value


def check_words(values: Mapping[str, str]) -> None:
    """Refuse option values that cannot stand on one line of output (option -> value)."""
    for option, value in values.items():
        if _CONTROL.search(value):
            raise FwshiftError(f"{option}: control characters are not allowed in '{_CONTROL.sub('?', value)[:40]}'")


def harden(p: Policy, report: Report) -> None:
    """Make the model safe to write out, whatever the input held.

    Every output format is line-based: a line break inside a name would start a
    line of its own in the result. Control characters in names become ``_``, a
    host name that is not one makes its object unusable, and so do ports that
    are not ports. A parser that validates its input leaves nothing to do here.
    """
    _without_control(p)
    for address in p.addresses.values():
        if address.kind == AddressKind.FQDN and not _HOST_NAME.fullmatch(address.value):
            address.kind, address.raw = AddressKind.UNSUPPORTED, "host name with characters no host name has"
        elif address.kind in (AddressKind.NETWORK, AddressKind.RANGE) and parse_literal(address.value) is None:
            address.kind, address.raw = AddressKind.UNSUPPORTED, "address that could not be read"
        else:
            continue
        report.add("address", address.name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{address.raw}: not converted")
    for kind, origins in (("rule", [r.origin for r in p.rules]), ("NAT rule", [n.origin for n in p.nat_rules])):
        twice = sorted({origin for origin in origins if origin and origins.count(origin) > 1})
        if twice:
            raise FwshiftError(f"two {kind}s share the name {twice[0]!r} once control characters are replaced")
    for nat in p.nat_rules:
        port = nat.destination_translation.port if nat.destination_translation else ""
        if port and not (is_number(port) and 0 < int(port) < 65536):
            reason = f"translated port '{port[:20]}' is not one port"
            if reason not in nat.unsupported:
                nat.unsupported.append(reason)
    for service in p.services.values():
        bad = [ports for e in service.entries for ports in (e.dst_ports, e.src_ports) if ports and not valid_ports(ports)]
        if bad and not service.unsupported:
            service.unsupported = "ports that could not be read"
            report.add("service", service.name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{service.unsupported}: not converted")


# -- resolution -----------------------------------------------------------


def address_intervals(p: Policy, ref: str, _seen: Optional[Set[str]] = None) -> Optional[List[Interval]]:
    """IP ranges a rule member stands for, or None when that cannot be known statically."""
    if ref == ANY:
        return [FULL_V4, FULL_V6]
    if ref in p.addresses:
        address = p.addresses[ref]
        if address.kind in (AddressKind.NETWORK, AddressKind.RANGE):
            interval = parse_literal(address.value)
            return [interval] if interval else None
        return None
    if ref in p.address_groups:
        group = p.address_groups[ref]
        seen = _seen or set()
        if group.dynamic_filter or group.unsupported or ref in seen:
            return None
        out: List[Interval] = []
        for member in group.members:
            resolved = address_intervals(p, member, seen | {ref})
            if resolved is None:
                return None
            out += resolved
        return out
    interval = parse_literal(ref)
    return [interval] if interval else None


def known_intervals(p: Policy, ref: str, _seen: Optional[Set[str]] = None) -> Tuple[List[Interval], bool]:
    """(IP ranges that can be read off a rule member, whether that is all of it).

    Unlike :func:`address_intervals` this does not give up on a group that holds
    an FQDN or another member without static addresses: it returns the rest.
    """
    if ref in p.address_groups:
        group = p.address_groups[ref]
        seen = _seen or set()
        if ref in seen:
            return [], False
        out: List[Interval] = []
        complete = not (group.dynamic_filter or group.unsupported)
        for member in group.members:
            intervals, member_complete = known_intervals(p, member, seen | {ref})
            out += intervals
            complete = complete and member_complete
        return out, complete
    resolved = address_intervals(p, ref)
    return (resolved, True) if resolved is not None else ([], False)


def families(p: Policy, ref: str, _seen: Optional[Set[str]] = None) -> Set[int]:
    """IP versions (4, 6) a rule member can match."""
    if ref == ANY:
        return {4, 6}
    if ref in p.addresses:
        address = p.addresses[ref]
        if address.kind in (AddressKind.NETWORK, AddressKind.RANGE):
            interval = parse_literal(address.value)
            return {interval[0]} if interval else {4}
        if address.kind == AddressKind.FQDN:
            return {address.fqdn_family} if address.fqdn_family else {4, 6}
        return {4}
    if ref in p.address_groups:
        seen = _seen or set()
        if ref in seen:
            return set()
        out: Set[int] = set()
        for member in p.address_groups[ref].members:
            out |= families(p, member, seen | {ref})
        return out or {4}
    interval = parse_literal(ref)
    return {interval[0]} if interval else {4}


def flatten_services(p: Policy, ref: str, _seen: Optional[Set[str]] = None) -> Optional[List[ServiceEntry]]:
    """All protocol/port entries behind a service or service group; None if unresolvable."""
    if ref in p.services:
        return list(p.services[ref].entries) or None
    if ref in p.service_groups:
        seen = _seen or set()
        if ref in seen:
            return None
        out: List[ServiceEntry] = []
        for member in p.service_groups[ref].members:
            resolved = flatten_services(p, member, seen | {ref})
            if resolved is None:
                return None
            out += resolved
        return out or None
    return None


def topo_groups(groups: Mapping[str, G]) -> List[G]:
    """Groups ordered so that every nested group comes before the group using it."""
    out: List[G] = []
    done: Set[str] = set()

    def visit(name: str, stack: Tuple[str, ...]) -> None:
        if name in done or name in stack or name not in groups:
            return
        for member in groups[name].members:
            visit(member, stack + (name,))
        done.add(name)
        out.append(groups[name])

    for name in groups:
        visit(name, ())
    return out


# -- preparation ----------------------------------------------------------


def apply_zone_map(p: Policy, zone_map: Mapping[str, str]) -> None:
    if not zone_map:
        return
    for rule in list(p.rules) + list(p.nat_rules):
        rule.src_zones = _dedupe([zone_map.get(z, z) for z in rule.src_zones])
        rule.dst_zones = _dedupe([zone_map.get(z, z) for z in rule.dst_zones])


def ensure_references(p: Policy, report: Report) -> None:
    """Give every dangling reference a placeholder object so the output stays loadable."""

    def need_address(ref: str, where: str) -> None:
        if ref == ANY or ref in p.addresses or ref in p.address_groups or parse_literal(ref) is not None:
            return
        p.addresses[ref] = Address(ref, AddressKind.UNSUPPORTED, "", raw="not defined in the input")
        report.add(
            "address",
            ref,
            Severity.REVIEW,
            "UNDEFINED_REFERENCE",
            f"used by {where} but not an address object in the input (a region, an external list or a "
            "missing object); emitted as a placeholder that matches nothing",
        )

    def need_service(ref: str, where: str) -> None:
        if ref in (ANY, APP_DEFAULT) or ref in p.services or ref in p.service_groups:
            return
        p.services[ref] = Service(ref, [])
        report.add(
            "service",
            ref,
            Severity.REVIEW,
            "UNDEFINED_REFERENCE",
            f"used by {where} but not defined in the input; emitted as a placeholder",
        )

    for group in list(p.address_groups.values()):
        for member in group.members:
            need_address(member, f"address group '{group.name}'")
    for sgroup in list(p.service_groups.values()):
        for member in sgroup.members:
            need_service(member, f"service group '{sgroup.name}'")
    for rule in p.rules:
        for member in rule.sources + rule.destinations:
            need_address(member, f"rule '{rule.name}'")
        for member in rule.services:
            need_service(member, f"rule '{rule.name}'")
    for nat in p.nat_rules:
        members = nat.sources + nat.destinations
        if nat.source_translation:
            members = members + nat.source_translation.addresses
        if nat.destination_translation:
            members = members + [nat.destination_translation.address]
        for member in members:
            need_address(member, f"NAT rule '{nat.name}'")
        need_service(nat.service, f"NAT rule '{nat.name}'")


def tainted_addresses(
    p: Policy, keep_dynamic: bool = False, keep: AbstractSet[str] = frozenset()
) -> Dict[str, str]:
    """Address objects and groups whose content cannot be converted -> reason.

    ``keep`` names objects the target has as they are (predefined ones): they are never tainted.
    """
    out: Dict[str, str] = {}
    for address in p.addresses.values():
        if address.kind == AddressKind.UNSUPPORTED and address.name not in keep:
            out[address.name] = address.raw or "unsupported address type"
    for group in p.address_groups.values():
        if group.name in keep:
            continue
        if group.unsupported:
            out[group.name] = group.unsupported
        elif group.dynamic_filter:
            if not keep_dynamic:
                out[group.name] = "dynamic address group, members are not known statically"
        elif not group.members:
            out[group.name] = "empty address group"
    changed = True
    while changed:
        changed = False
        for group in p.address_groups.values():
            if group.name in out or group.name in keep:
                continue
            bad = [m for m in group.members if m in out]
            if bad:
                out[group.name] = f"contains '{bad[0]}' ({out[bad[0]]})"
                changed = True
    return out


def tainted_services(
    p: Policy, extra: Optional[Mapping[str, str]] = None, keep: AbstractSet[str] = frozenset()
) -> Dict[str, str]:
    out: Dict[str, str] = dict(extra or {})
    for service in p.services.values():
        if service.name in keep:
            continue
        if service.unsupported:
            out[service.name] = service.unsupported
        elif not service.entries and service.name not in out:
            out[service.name] = "unsupported or undefined service"
    for group in p.service_groups.values():
        if not group.members and group.name not in keep:
            out[group.name] = "empty service group"
    changed = True
    while changed:
        changed = False
        for group in p.service_groups.values():
            if group.name in out or group.name in keep:
                continue
            bad = [m for m in group.members if m in out]
            if bad:
                out[group.name] = f"contains '{bad[0]}' ({out[bad[0]]})"
                changed = True
    return out


def is_placeholder_group(group: AddressGroup, keep_dynamic: bool = False) -> bool:
    """True when the group has to be emitted as a placeholder object instead of a group."""
    if group.unsupported:
        return True
    if group.dynamic_filter:
        return not keep_dynamic
    return not group.members


def blocking_reasons(rule: Rule, taint_a: Mapping[str, str], taint_s: Mapping[str, str]) -> List[Reason]:
    """Reasons a rule cannot be enforced on any target as it stands."""
    out: List[Reason] = [("UNSUPPORTED_MATCH", f"not converted: {text}") for text in rule.unsupported]
    for members, taint in ((rule.sources, taint_a), (rule.destinations, taint_a), (rule.services, taint_s)):
        for member in members:
            if member in taint:
                out.append(("UNCONVERTIBLE_OBJECT", f"references '{member}': {taint[member]}"))
    if rule.schedule:
        out.append(("SCHEDULE", f"schedule '{rule.schedule}' is not converted; the rule would apply at all times"))
    return out


def disable_rule(report: Report, rule: Rule, reasons: List[Reason]) -> None:
    """Record that the rule is emitted disabled, and why."""
    suffix = ""
    if rule.action != Action.ALLOW:
        suffix = " This deny rule is NOT enforced until fixed; allow rules below it may match more traffic."
    for code, message in reasons:
        report.disable("rule", rule.origin, code, message + "." + suffix)


def note_profiles(report: Report, rule: Rule) -> None:
    if rule.profiles:
        listed = ", ".join(f"{k}={v}" for k, v in sorted(rule.profiles.items()))
        report.add(
            "rule",
            rule.origin,
            Severity.APPROX,
            "PROFILES_NOT_CONVERTED",
            f"security profiles are not converted ({listed}); attach equivalent inspection on the target",
        )


def note_fqdn_families(p: Policy, rule: Rule, report: Report, target: str) -> None:
    """Report an FQDN the source resolved for one IP version where the rule can match the other.

    For a target that resolves every FQDN for both IP versions.
    """

    def single_family(members: List[str], seen: Tuple[str, ...] = ()) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for member in members:
            address = p.addresses.get(member)
            if address is not None and address.kind == AddressKind.FQDN and address.fqdn_family:
                out[member] = address.fqdn_family
            elif member in p.address_groups and member not in seen:
                out.update(single_family(p.address_groups[member].members, seen + (member,)))
        return out

    def versions_here(member: str, seen: Tuple[str, ...] = ()) -> Set[int]:
        """IP versions a member matches on the target."""
        address = p.addresses.get(member)
        if address is not None and address.kind == AddressKind.FQDN:
            return {4, 6}
        if member in p.address_groups and member not in seen:
            out: Set[int] = set()
            for inner in p.address_groups[member].members:
                out |= versions_here(inner, seen + (member,))
            return out
        return families(p, member)

    sides = (
        (rule.sources, rule.destinations, rule.negate_destination),
        (rule.destinations, rule.sources, rule.negate_source),
    )
    for side, other, other_negated in sides:
        for name, family in single_family(side).items():
            opposite = 6 if family == 4 else 4
            if other_negated or any(opposite in versions_here(m) for m in other):
                report.add(
                    "rule",
                    rule.origin,
                    Severity.APPROX,
                    "FQDN_FAMILY",
                    f"'{name}' was resolved for IPv{family} only on the source; {target} resolves an FQDN for "
                    f"both IP versions and this rule can match IPv{opposite}",
                )


def merged_zones(p: Policy, zone_map: Mapping[str, str], source_zones: AbstractSet[str]) -> Set[str]:
    """Target zone names that --zone-map makes out of more than one source zone or interface."""
    sources: Dict[str, Set[str]] = {}
    for name in list(p.zones) + list(zone_map) + sorted(source_zones):
        sources.setdefault(zone_map.get(name, name), set()).add(name)
    return {target for target, names in sources.items() if len(names) > 1}


def intrazone_allow_zones(
    p: Policy, zone_map: Mapping[str, str], source_zones: AbstractSet[str], report: Report
) -> List[str]:
    """Target names of the zones that allow traffic between their own interfaces.

    ``source_zones`` holds the zone and interface names of the rules before the
    zone map was applied. A zone that the map merges with another zone or
    interface is left out: an intrazone allow on the merged zone would open
    traffic between the two.
    """
    merged = merged_zones(p, zone_map, source_zones)
    out: List[str] = []
    for zone in p.zones.values():
        if not zone.intrazone_allow:
            continue
        target = zone_map.get(zone.name, zone.name)
        if target in merged:
            report.note(
                Severity.REVIEW,
                "INTRAZONE_ALLOW_MERGED",
                f"zone '{zone.name}' allows traffic between its interfaces on the source, but --zone-map merges "
                f"it with other zones into '{target}'; no intrazone allow rule was written for it",
            )
        elif target not in out:
            out.append(target)
    return out


def lower_applications(
    rule: Rule, app_ports: Mapping[str, List[str]], report: Report, reasons: List[Reason]
) -> Optional[List[Tuple[str, List[ServiceEntry]]]]:
    """Application match of a rule, for a target that can only match protocols and ports.

    Returns None when the services of the rule apply as they are, otherwise one
    (application, protocol/port entries) pair per application that is in the
    port table. Findings are recorded; ``reasons`` receives what makes the rule
    unenforceable (an unknown application, "any application on its default ports").
    """
    apps, services = rule.applications, rule.services
    deny = rule.action != Action.ALLOW
    if apps == [ANY]:
        if services == [APP_DEFAULT]:
            reasons.append(("APP_DEFAULT_ANY", "'any' application on its default ports has no layer-4 equivalent"))
            return []
        return None
    if services not in ([APP_DEFAULT], [ANY]):
        report.add(
            "rule",
            rule.origin,
            Severity.REVIEW if deny else Severity.APPROX,
            "APP_FILTER_DROPPED",
            "application match "
            + ", ".join(apps)
            + " dropped; the rule now matches everything on its services"
            + (" and so blocks more than the source rule" if deny else ""),
        )
        return None
    known: List[Tuple[str, List[ServiceEntry]]] = []
    unknown: List[str] = []
    for app in apps:
        entries = entries_for(app, dict(app_ports))
        if entries is None:
            unknown.append(app)
        else:
            known.append((app, entries))
    if unknown:
        reasons.append(
            ("APP_UNKNOWN", "no port mapping for application(s) " + ", ".join(unknown) + "; supply one with --app-map")
        )
    if known:
        names = ", ".join(app for app, _ in known)
        if not deny:
            extra = " (the source matched them on any port)" if services == [ANY] else ""
            text = (
                f"applications {names} reduced to their well-known ports{extra}; layer-7 identification "
                "is lost, add application control if it is needed"
            )
        elif services == [ANY]:
            text = (
                f"the source blocked applications {names} on every port; only their well-known ports are "
                "blocked now, so the same applications on other ports are no longer stopped by this rule"
            )
        else:
            text = (
                f"the source blocked applications {names}; everything on their well-known ports is "
                "blocked now, which is more than the source rule did"
            )
        report.add("rule", rule.origin, Severity.REVIEW if deny else Severity.APPROX, "APP_TO_PORTS", text)
    return known


def zone_pairs(rule: Rule) -> Optional[List[Tuple[List[str], List[str]]]]:
    """(source zones, destination zones) combinations of a rule for platforms without rule types.

    None when the rule type cannot be expressed as a list of zone pairs.
    """
    src, dst = rule.src_zones, rule.dst_zones
    if rule.scope == RuleScope.INTRAZONE:
        if ANY in src:
            return None
        return [([zone], [zone]) for zone in src]
    if rule.scope == RuleScope.INTERZONE:
        if ANY in src or ANY in dst:
            return None
        if not set(src) & set(dst):
            return [(src, dst)]
        pairs = [([zone], [d for d in dst if d != zone]) for zone in src]
        return [pair for pair in pairs if pair[1]]
    return [(src, dst)]


def prune_unused(p: Policy) -> int:
    """Drop objects no rule reaches, directly or through groups; return how many were dropped."""
    addresses: Set[str] = set()
    services: Set[str] = set()

    def walk_address(ref: str) -> None:
        if ref in addresses:
            return
        if ref in p.addresses:
            addresses.add(ref)
        elif ref in p.address_groups:
            addresses.add(ref)
            for member in p.address_groups[ref].members:
                walk_address(member)

    def walk_service(ref: str) -> None:
        if ref in services:
            return
        if ref in p.services:
            services.add(ref)
        elif ref in p.service_groups:
            services.add(ref)
            for member in p.service_groups[ref].members:
                walk_service(member)

    for rule in p.rules:
        for member in rule.sources + rule.destinations:
            walk_address(member)
        for member in rule.services:
            walk_service(member)
    for nat in p.nat_rules:
        members = nat.sources + nat.destinations
        if nat.source_translation:
            members = members + nat.source_translation.addresses
        if nat.destination_translation:
            members = members + [nat.destination_translation.address]
        for member in members:
            walk_address(member)
        walk_service(nat.service)

    before = len(p.addresses) + len(p.address_groups) + len(p.services) + len(p.service_groups)
    p.addresses = {n: o for n, o in p.addresses.items() if n in addresses}
    p.address_groups = {n: o for n, o in p.address_groups.items() if n in addresses}
    p.services = {n: o for n, o in p.services.items() if n in services}
    p.service_groups = {n: o for n, o in p.service_groups.items() if n in services}
    return before - (len(p.addresses) + len(p.address_groups) + len(p.services) + len(p.service_groups))


# -- NAT ------------------------------------------------------------------


def bidirectional_pair(p: Policy, nat: NatRule) -> Optional[Tuple[Interval, Interval]]:
    """(inside, outside) address of a bi-directional static NAT whose inbound half can be a virtual IP."""
    translation = nat.source_translation
    if translation is None or translation.kind != SnatKind.STATIC or not translation.bidirectional:
        return None
    if len(nat.sources) != 1 or len(translation.addresses) != 1:
        return None
    inside = address_intervals(p, nat.sources[0])
    outside = address_intervals(p, translation.addresses[0])
    if not inside or not outside or len(inside) != 1 or len(outside) != 1:
        return None
    if inside[0][0] != 4 or outside[0][0] != 4 or size(inside[0]) != size(outside[0]) or inside[0] == FULL_V4:
        return None
    return inside[0], outside[0]


@dataclass
class DestinationTranslation:
    """One destination NAT, as security rules see it."""

    nat: NatRule
    pre: str  # address before translation
    post: str  # address after translation
    port: str  # translated port, if the port changes
    zones: List[str]  # source zones the translation applies to
    arrival_zones: List[str]  # zones the traffic meant for it normally arrives from


def destination_translations(p: Policy, only: Optional[Set[str]] = None) -> List[DestinationTranslation]:
    """Every destination NAT of the policy; the inbound half of a bi-directional static NAT counts as one.

    ``only`` limits the result to NAT rules with these origins.
    """
    out: List[DestinationTranslation] = []
    for nat in p.nat_rules:
        if not nat.enabled or (only is not None and nat.origin not in only):
            continue
        dnat, snat = nat.destination_translation, nat.source_translation
        if dnat is not None:
            if len(nat.destinations) == 1:
                out.append(
                    DestinationTranslation(nat, nat.destinations[0], dnat.address, dnat.port, nat.src_zones, nat.src_zones)
                )
        elif (
            snat is not None
            and snat.kind == SnatKind.STATIC
            and snat.bidirectional
            and len(nat.sources) == 1
            and len(snat.addresses) == 1
        ):
            # Inbound, the static rule applies from every zone; the public address
            # itself sits in the zone the rule translates towards.
            out.append(DestinationTranslation(nat, snat.addresses[0], nat.sources[0], "", [ANY], nat.dst_zones))
    return out


def _addresses_meet(p: Policy, a: List[str], b: List[str]) -> bool:
    """Whether two address lists can match the same address; what is not known statically is taken to."""
    if ANY in a or ANY in b:
        return True
    first = [known_intervals(p, member) for member in a]
    second = [known_intervals(p, member) for member in b]
    if not all(complete for _, complete in first + second):
        return True
    return overlaps([i for intervals, _ in first for i in intervals], [i for intervals, _ in second for i in intervals])


def _services_meet(p: Policy, a: str, b: str) -> bool:
    first, second = _l4_ranges(p, [a]), _l4_ranges(p, [b])
    if a == ANY or b == ANY or first is None or second is None:
        return True
    return any(
        low <= last and start <= high
        for protocol, ranges in first.items()
        for start, last in ranges
        for low, high in second.get(protocol, [])
    )


@dataclass
class _Inbound:
    """A destination translation as PREROUTING or a virtual IP sees it: what it matches, where it sends it."""

    rule: NatRule
    src_zones: List[str]
    dst_zones: List[str]
    sources: List[str]
    destinations: List[str]  # before translation
    service: str
    address: str  # after translation
    implicit: bool  # the inbound half of a bi-directional static NAT


def _inbound(nat: NatRule) -> List[_Inbound]:
    dnat, snat = nat.destination_translation, nat.source_translation
    if dnat is not None:
        return [_Inbound(nat, nat.src_zones, nat.dst_zones, nat.sources, nat.destinations, nat.service, dnat.address, False)]
    if snat is not None and snat.kind == SnatKind.STATIC and snat.bidirectional and len(nat.sources) == 1:
        return [_Inbound(nat, [ANY], nat.dst_zones, [ANY], list(snat.addresses), ANY, nat.sources[0], True)]
    return []


def _outbound(nat: NatRule) -> Optional[Tuple[List[str], bool]]:
    """(destinations as POSTROUTING or central SNAT sees them, whether the source is translated), if the rule
    has an entry there: a source translation, or a rule without any translation."""
    dnat = nat.destination_translation
    if nat.source_translation is None and dnat is not None:
        return None
    return ([dnat.address] if dnat is not None else nat.destinations), nat.source_translation is not None


def _zone_after(p: Policy, inbound: _Inbound) -> List[str]:
    """Zones the translated traffic can leave towards, as far as the policy tells; "any" when it does not."""
    if inbound.implicit:
        return inbound.rule.src_zones  # the inside host of a static NAT lives where its rule comes from
    zones: List[str] = []
    for rule in p.rules:
        # Security rules name the original destination and the zone it is reached in after NAT. Every
        # allow rule that can match this traffic counts, also one that names no destination at all.
        if not rule.enabled or rule.action != Action.ALLOW or not _zones_meet(rule.src_zones, inbound.src_zones):
            continue
        # A rule may name the original address or, once rewritten for this target, the translated one;
        # either way its zone is where the translated address is reached.
        named = inbound.destinations + [inbound.address]
        if rule.negate_destination or _addresses_meet(p, rule.destinations, named):
            zones += rule.dst_zones
    if not zones:
        return inbound.dst_zones  # no rule lets it in: taken to stay in the zone of the original address
    return [ANY] if ANY in zones else _dedupe(zones)


def _claims(p: Policy, earlier: NatRule, inbound: _Inbound) -> bool:
    """Whether a rule without destination translation matched, on the source, traffic this translation matches."""
    return (
        earlier.destination_translation is None
        and _zones_meet(earlier.src_zones, inbound.src_zones)
        and _zones_meet(earlier.dst_zones, inbound.dst_zones)
        and _addresses_meet(p, earlier.sources, inbound.sources)
        and _addresses_meet(p, earlier.destinations, inbound.destinations)
        and _services_meet(p, earlier.service, inbound.service)
    )


def _covers(p: Policy, outer: List[str], inner: List[str]) -> bool:
    """Whether every address of ``inner`` is in ``outer``, as far as that can be known."""
    if ANY in outer:
        return True
    if ANY in inner:
        return False
    first = [known_intervals(p, member) for member in outer]
    second = [known_intervals(p, member) for member in inner]
    if not all(complete for _, complete in first + second):
        return False
    return within([i for intervals, _ in second for i in intervals], [i for intervals, _ in first for i in intervals])


def _zones_cover(outer: List[str], inner: List[str]) -> bool:
    return ANY in outer or (ANY not in inner and set(inner) <= set(outer))


def _listed(names: List[str]) -> str:
    names = _dedupe(names)
    return ", ".join(f"'{name}'" for name in names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")


def note_nat_order(
    p: Policy, report: Report, written: AbstractSet[str], target: str, tied: AbstractSet[str] = frozenset()
) -> None:
    """Report what changes when NAT rules move between "first match" and "one rule of each direction".

    ``written`` holds the origins of the NAT rules the target gets; ``target`` is
    "first-match" (PAN-OS, Check Point) or "per-direction" (iptables, FortiOS).
    ``tied`` names rules whose source translation the target ties to the original
    destination of the rule itself, so that it cannot touch other traffic.
    Two rules that both carry ``combines`` applied together on the source.

    The comparison goes by zones, addresses and services, and assumes an overlap
    where it cannot tell. It finds pairs of rules whose interplay changes; it
    does not prove that there are no others.
    """
    enabled = [nat for nat in p.nat_rules if nat.enabled]
    rules = [nat for nat in enabled if nat.origin in written]
    # 0. A rule that is not written no longer claims its traffic: translating rules below it get it.
    for index, missing in enumerate(enabled):
        translates = missing.source_translation is not None or missing.destination_translation is not None
        if missing.origin in written or (missing.combines and not translates):
            continue
        for later in enabled[index + 1 :]:
            if later.origin not in written or (later.source_translation is None and later.destination_translation is None):
                continue
            both_ways = (missing.destination_translation is None) != (later.destination_translation is None)
            if missing.combines and later.combines and both_ways:
                continue  # the source applied the two together anyway
            if (
                _zones_meet(missing.src_zones, later.src_zones)
                and _zones_meet(missing.dst_zones, later.dst_zones)
                and _addresses_meet(p, missing.sources, later.sources)
                and _addresses_meet(p, missing.destinations, later.destinations)
                and _services_meet(p, missing.service, later.service)
            ):
                report.add(
                    "nat",
                    later.origin,
                    Severity.REVIEW,
                    "NAT_ORDER",
                    f"NAT rule '{missing.name}' above this one is not converted. On the source it matched part of "
                    "this traffic first; that traffic now reaches this rule and is translated by it",
                )
    if target == "first-match":
        dnat = [n for n in rules if n.combines and n.destination_translation is not None and n.source_translation is None]
        snat = [n for n in rules if n.combines and n.source_translation is not None and n.destination_translation is None]
        if dnat and snat:
            report.note(
                Severity.APPROX,
                "NAT_ORDER",
                "the source applies a destination NAT rule and a source NAT rule to the same connection. The "
                "target applies one NAT rule, the first that matches: a connection that needed both translations "
                "gets the destination translation only. Combine the two in one rule where that matters",
            )
        return
    position = {id(nat): index for index, nat in enumerate(rules)}
    for later in rules:
        # 1. Traffic that an earlier rule claimed on the source and left with its destination,
        #    and that a destination translation of this rule now changes.
        claimed = [
            earlier.name
            for inbound in _inbound(later)
            for earlier in rules[: position[id(later)]]
            if not (earlier.combines and later.combines)
            and not _two_halves(earlier, later)
            and _claims(p, earlier, inbound)
        ]
        if claimed:
            one = len(_dedupe(claimed)) == 1
            report.add(
                "nat",
                later.origin,
                Severity.REVIEW,
                "NAT_ORDER",
                f"on the source, NAT rule{'' if one else 's'} {_listed(claimed)} above this one "
                f"match{'es' if one else ''} part of its traffic first, and that traffic keeps its destination. The "
                "target translates destinations apart from sources: the destination translation of this rule "
                "applies to that traffic as well",
            )
    # 2. Traffic a rule sends to a translated address. On the target the entries for source NAT are
    #    matched after that, on the new destination, in the order of the rules.
    added: List[Tuple[NatRule, _Inbound, NatRule]] = []  # (rule, its translation, rule that now translates the source)
    for first in rules:
        own = _outbound(first)
        for inbound in _inbound(first):
            leaves_to = _zone_after(p, inbound)
            keeps_own = own is not None and not inbound.implicit  # the rule translates the source itself
            ahead: List[str] = []  # entries that come before its own
            quiet: List[NatRule] = []  # entries without NAT met so far
            for other in rules:
                if other is first:
                    if keeps_own:
                        break  # its own entry: nothing below it is reached
                    continue
                entry = _outbound(other)
                if entry is None or other.origin in tied or (other.combines and first.combines):
                    continue
                destinations, translates = entry
                if not _zones_meet(other.src_zones, inbound.src_zones) or not _zones_meet(other.dst_zones, leaves_to):
                    continue
                if not _addresses_meet(p, other.sources, inbound.sources) or not _addresses_meet(p, destinations, [inbound.address]):
                    continue
                if position[id(other)] < position[id(first)] and _claims(p, other, inbound):
                    continue  # it claimed this traffic on the source too: reported under 1.
                if keeps_own:
                    ahead.append(other.name)
                elif not translates:
                    quiet.append(other)
                elif not any(
                    # An entry without NAT further up that takes all of what this one would translate.
                    _zones_cover(shield.src_zones, other.src_zones)
                    and _zones_cover(shield.dst_zones, leaves_to)
                    and shield.service == ANY
                    and (_covers(p, shield.sources, other.sources) or _covers(p, shield.sources, inbound.sources))
                    and _covers(p, shield.destinations, [inbound.address])
                    for shield in quiet
                ):
                    added.append((first, inbound, other))
            if ahead:
                one = len(_dedupe(ahead)) == 1
                report.add(
                    "nat",
                    first.origin,
                    Severity.REVIEW,
                    "NAT_ORDER",
                    f"this rule translates destination and source. The target matches source translations after "
                    f"the destination was translated to '{inbound.address}', in the order of the rules: there NAT "
                    f"rule{'' if one else 's'} {_listed(ahead)} above this one match{'es' if one else ''} first, and "
                    "the source translation of this rule does not apply",
                )
    # One finding per rule on the side with fewer rules: one port forward above ten hide rules is one finding.
    forwarding = _dedupe([first.origin for first, _, _ in added])
    translating = _dedupe([other.origin for _, _, other in added])
    if added and len(forwarding) <= len(translating):
        for origin in forwarding:
            others = [other.name for first, _, other in added if first.origin == origin]
            addresses = _dedupe([inbound.address for first, inbound, _ in added if first.origin == origin])
            one = len(_dedupe(others)) == 1
            report.add(
                "nat",
                origin,
                Severity.REVIEW,
                "NAT_ORDER",
                f"on the source, the traffic this rule forwards to {', '.join(addresses)} keeps its source address. "
                "The target translates sources apart from destinations, after the destination: there NAT "
                f"rule{'' if one else 's'} {_listed(others)} translate{'s' if one else ''} the source of that traffic "
                "as well",
            )
    else:
        for origin in translating:
            sent = _dedupe([f"'{first.name}' (to {inbound.address})" for first, inbound, other in added if other.origin == origin])
            listed = ", ".join(sent[:3]) + (f" and {len(sent) - 3} more" if len(sent) > 3 else "")
            report.add(
                "nat",
                origin,
                Severity.REVIEW,
                "NAT_ORDER",
                f"on the source, traffic forwarded by NAT rule{'s' if len(sent) > 1 else ''} {listed} keeps its "
                "source address. The target translates sources apart from destinations, after the destination: "
                "this rule translates the source of that traffic as well",
            )


def _two_halves(earlier: NatRule, later: NatRule) -> bool:
    """True when the rules are the two directions of one static NAT: a host out, and in to the same host."""
    for out, back in ((earlier, later), (later, earlier)):
        snat, dnat = out.source_translation, back.destination_translation
        if snat is not None and dnat is not None and out.destination_translation is None and back.source_translation is None:
            if snat.kind == SnatKind.STATIC and snat.addresses == back.destinations and out.sources == [dnat.address]:
                return True
    return False


def _zones_meet(a: List[str], b: List[str]) -> bool:
    return ANY in a or ANY in b or bool(set(a) & set(b))


def _reachable_names(p: Policy, members: List[str]) -> Set[str]:
    """The members and everything they contain through address groups."""
    out: Set[str] = set()
    todo = list(members)
    while todo:
        name = todo.pop()
        if name in out:
            continue
        out.add(name)
        if name in p.address_groups:
            todo += p.address_groups[name].members
    return out


def to_post_nat_lookup(p: Policy, report: Report, written: Set[str]) -> None:
    """Prepare the rules for a target that looks them up after destination NAT.

    ``written`` holds the origins of the NAT rules the target will really get.
    When the source is a platform of the same kind, what its parser did to reach
    the pre-NAT model is undone here, so the findings about it are withdrawn.
    """
    same_kind = p.lookup_after_dnat
    if same_kind:
        report.retract("rule", {"NAT_PORT_TRANSLATION", "NAT_DESTINATION_REWRITTEN", "NAT_REDIRECT"})
    rewrite_destinations(p, report, to_post_nat=True, only=written, quiet_when_covered=same_kind)


def rewrite_destinations(
    p: Policy,
    report: Report,
    to_post_nat: bool,
    only: Optional[Set[str]] = None,
    report_deny: bool = True,
    quiet_when_covered: bool = False,
) -> None:
    """Translate security-rule destinations between pre-NAT and post-NAT addressing.

    The neutral model matches pre-NAT addresses. FortiOS looks policies up after
    destination NAT, against the mapped address. An emitter targeting FortiOS
    calls this with ``to_post_nat=True``, a parser reading FortiOS with ``False``.

    For each destination NAT:

    * a rule that covers the address of the side being left gets the address of
      the other side;
    * an allow rule that covers only the other side would start to match the
      translated traffic, and is reported;
    * a negated destination that would change meaning disables the rule.

    Matching is done on addresses and source zones only, so every change is
    reported for review.
    """
    for translation in destination_translations(p, only):
        nat, pre_ref, post_ref, port = translation.nat, translation.pre, translation.post, translation.port
        pre, post = address_intervals(p, pre_ref), address_intervals(p, post_ref)
        if not pre or not post:
            continue  # nothing to go by
        if FULL_V4 in normalize(pre):
            if not to_post_nat:
                _note_redirect(p, report, translation, post)
            continue  # a redirect of every destination: there is no address to put in its place
        old, new, new_ref = (pre, post, post_ref) if to_post_nat else (post, pre, pre_ref)
        old_side, new_side = ("pre-NAT", "post-NAT") if to_post_nat else ("post-NAT", "pre-NAT")
        for rule in p.rules:
            if ANY in rule.destinations or ANY_V4 in rule.destinations:
                continue  # covers the pre-NAT and the post-NAT address alike
            if not _zones_meet(translation.zones, rule.src_zones):
                continue
            # Read what can be read: a group holding an FQDN still names its other members.
            resolved = [(member,) + known_intervals(p, member) for member in rule.destinations]
            known = [interval for _, intervals, _ in resolved for interval in intervals]
            if rule.negate_destination:
                # A negated list matches the translated traffic unless it names the address looked at.
                if within(old, known) != within(new, known):
                    rule.unsupported.append(
                        f"negated destination that names only one of the addresses of NAT rule '{nat.name}' "
                        f"({pre_ref}, {post_ref})"
                    )
                continue
            hits = [(member, complete) for member, intervals, complete in resolved if overlaps(intervals, old)]
            if not hits:
                if not overlaps(known, new) or not _zones_meet(translation.arrival_zones, rule.src_zones):
                    continue
                allow = rule.action == Action.ALLOW
                if to_post_nat:
                    text = (
                        f"the destination covers '{post_ref}', the address NAT rule '{nat.name}' translates "
                        f"'{pre_ref}' to. The target looks rules up after that translation, so traffic sent to "
                        f"'{pre_ref}' now matches this rule; on the source it did not"
                        + ("" if allow else ". This rule now blocks that traffic before the rules below see it")
                    )
                elif not allow and not report_deny:
                    continue  # the caller reports deny rules itself (FortiOS: together with match-vip)
                elif pre_ref in _reachable_names(p, rule.destinations):
                    continue  # the policy names the virtual IP itself: FortiOS applied it to that traffic
                else:
                    text = (
                        f"the destination covers '{pre_ref}', the external address of NAT rule '{nat.name}', "
                        f"but not '{post_ref}' behind it. The source looks rules up after the translation and "
                        "did not apply this rule to that traffic; the converted rule does"
                    )
                report.add("rule", rule.origin, Severity.REVIEW, "NAT_ADDRESS_EXPOSED", text)
                continue
            destinations = list(rule.destinations)
            # A source of the same kind: a rule that already names the new side only loses a dead address.
            silent = quiet_when_covered and overlaps(known, new)
            for member, complete in hits:
                intervals = known_intervals(p, member)[0]
                if to_post_nat and complete and normalize(intervals) == normalize(old):
                    destinations[destinations.index(member)] = new_ref
                    how = f"replaced {old_side} destination '{member}' with {new_side} '{new_ref}'"
                elif within(new, known):
                    continue  # the rule names the other address already
                else:
                    destinations.append(new_ref)
                    how = f"added {new_side} destination '{new_ref}' next to '{member}'"
                if not silent:
                    report.add(
                        "rule",
                        rule.origin,
                        Severity.APPROX,
                        "NAT_DESTINATION_REWRITTEN",
                        f"{how} because of NAT rule '{nat.name}'; check that this rule is meant "
                        "to cover the translated traffic",
                    )
            rule.destinations = _dedupe(destinations)
            if port and not quiet_when_covered and _port_concerns(p, rule, nat, port, to_post_nat):
                report.add(
                    "rule",
                    rule.origin,
                    Severity.REVIEW,
                    "NAT_PORT_TRANSLATION",
                    f"NAT rule '{nat.name}' also translates the port to {port}; "
                    f"the service of this rule still names the {old_side} port and must be adjusted",
                )


def _note_redirect(p: Policy, report: Report, translation: DestinationTranslation, post: List[Interval]) -> None:
    """A destination NAT without a destination address, read from a platform that looks rules up after it."""
    nat = translation.nat
    target = translation.post + (f":{translation.port}" if translation.port else "")
    for rule in p.rules:
        if ANY in rule.destinations or ANY_V4 in rule.destinations or rule.negate_destination:
            continue
        if not _zones_meet(translation.zones, rule.src_zones):
            continue
        known = [interval for member in rule.destinations for interval in known_intervals(p, member)[0]]
        if overlaps(known, post):
            report.add(
                "rule",
                rule.origin,
                Severity.REVIEW,
                "NAT_REDIRECT",
                f"NAT rule '{nat.name}' sends traffic for every destination to {target}, and the source applied "
                "this rule to it after that translation. The converted rule still names the translated address"
                + (" and port" if translation.port else "")
                + ": a platform that looks rules up before NAT will not match the redirected traffic with it",
            )


def _l4_ranges(p: Policy, names: List[str]) -> Optional[Dict[Protocol, List[Tuple[int, int]]]]:
    """Destination port ranges per protocol of a service list; None when it is not just TCP/UDP/SCTP ports."""
    out: Dict[Protocol, List[Tuple[int, int]]] = {}
    for name in names:
        entries = flatten_services(p, name)
        if entries is None:
            return None
        for entry in entries:
            if entry.protocol not in L4_PROTOCOLS:
                return None
            for part in (entry.dst_ports or "1-65535").split(","):
                first, _, last = part.partition("-")
                if not is_number(first) or not is_number(last or first):
                    return None
                out.setdefault(entry.protocol, []).append((int(first), int(last or first)))
    return out


def _port_concerns(p: Policy, rule: Rule, nat: NatRule, port: str, to_post_nat: bool) -> bool:
    """Whether a port translation can touch what the services of a rule match."""
    rule_ports = _l4_ranges(p, rule.services)
    nat_ports = _l4_ranges(p, [nat.service])
    if rule_ports is None or not is_number(port):
        return True
    if to_post_nat:
        # The rule names ports of the original packet: does it meet what the NAT rule matches?
        if nat_ports is None:
            return True
        return any(
            low <= last and first <= high
            for protocol, ranges in nat_ports.items()
            for first, last in ranges
            for low, high in rule_ports.get(protocol, [])
        )
    # The rule names ports after translation: does it meet the translated port?
    protocols = list(nat_ports) if nat_ports else list(rule_ports)
    return any(low <= int(port) <= high for protocol in protocols for low, high in rule_ports.get(protocol, []))


# -- names ----------------------------------------------------------------


def sanitize_names(
    p: Policy,
    obj_rules: NameRules,
    rule_rules: NameRules,
    report: Report,
    reserved_addresses: AbstractSet[str] = frozenset(),
    reserved_services: AbstractSet[str] = frozenset(),
    one_namespace: bool = False,
    prefix: str = "",
    keep: AbstractSet[str] = frozenset(),
) -> None:
    """Rename objects and rules that the target platform would reject.

    Reserved names are names the target predefines: an object of the source that
    happens to carry one is renamed, so that it neither redefines the predefined
    object nor is mistaken for it. With ``one_namespace`` a service may not carry
    the name of an address either. ``prefix`` is put in front of every object
    name; objects in ``keep`` exist on the target as they are and keep theirs.
    """
    address_map = _rename(
        [(n, "address") for n in p.addresses] + [(n, "address-group") for n in p.address_groups],
        obj_rules,
        report,
        reserved_addresses,
        prefix,
        keep,
    )
    if one_namespace:
        used = {address_map.get(name, name) for name in list(p.addresses) + list(p.address_groups)}
        reserved_services = set(reserved_services) | used
    service_map = _rename(
        [(n, "service") for n in p.services] + [(n, "service-group") for n in p.service_groups],
        obj_rules,
        report,
        reserved_services,
        prefix,
        keep,
    )

    rename_objects(p, address_map, service_map)
    taken: Set[str] = set()
    for rule in p.rules:
        rule.name = unique(rule.name, taken, rule_rules)
    taken = set()
    for nat in p.nat_rules:
        nat.name = unique(nat.name, taken, obj_rules)


def rename_objects(p: Policy, address_map: Mapping[str, str], service_map: Mapping[str, str]) -> None:
    """Rename objects (old name -> new name) and everything that refers to them."""

    def amap(items: List[str]) -> List[str]:
        return [address_map.get(i, i) for i in items]

    def smap(items: List[str]) -> List[str]:
        return [service_map.get(i, i) for i in items]

    addresses: Dict[str, Address] = {}
    for address in p.addresses.values():
        address.name = address_map.get(address.name, address.name)
        addresses[address.name] = address
    p.addresses = addresses
    address_groups: Dict[str, AddressGroup] = {}
    for group in p.address_groups.values():
        group.name = address_map.get(group.name, group.name)
        group.members = amap(group.members)
        address_groups[group.name] = group
    p.address_groups = address_groups
    services: Dict[str, Service] = {}
    for service in p.services.values():
        service.name = service_map.get(service.name, service.name)
        services[service.name] = service
    p.services = services
    service_groups: Dict[str, ServiceGroup] = {}
    for sgroup in p.service_groups.values():
        sgroup.name = service_map.get(sgroup.name, sgroup.name)
        sgroup.members = smap(sgroup.members)
        service_groups[sgroup.name] = sgroup
    p.service_groups = service_groups
    for rule in p.rules:
        rule.sources, rule.destinations = amap(rule.sources), amap(rule.destinations)
        rule.services = smap(rule.services)
    for nat in p.nat_rules:
        nat.sources, nat.destinations = amap(nat.sources), amap(nat.destinations)
        nat.service = service_map.get(nat.service, nat.service)
        if nat.source_translation:
            nat.source_translation.addresses = amap(nat.source_translation.addresses)
        if nat.destination_translation:
            translated = nat.destination_translation.address
            nat.destination_translation.address = address_map.get(translated, translated)


def _rename(
    names: List[Tuple[str, str]],
    rules: NameRules,
    report: Report,
    reserved: AbstractSet[str],
    prefix: str = "",
    keep: AbstractSet[str] = frozenset(),
) -> Dict[str, str]:
    """Old name -> new name for every object that cannot keep its name."""
    stays = {
        name
        for name, _ in names
        if name in keep or (not prefix and clean(name, rules) == name and name not in reserved)
    }
    taken = set(stays) | set(reserved)
    mapping: Dict[str, str] = {}
    for name, kind in names:
        if name in stays:
            continue
        new = unique(prefix + name, taken, rules)
        mapping[name] = new
        report.item(kind, name).emitted_as = [new]
        if new != prefix + name:
            report.add(kind, name, Severity.INFO, "RENAMED", f"renamed to '{new}' to fit the target's naming rules")
    return mapping


def _dedupe(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


dedupe = _dedupe

__all__ = [
    "Reason",
    "address_intervals",
    "apply_zone_map",
    "bidirectional_pair",
    "check_words",
    "blocking_reasons",
    "dedupe",
    "destination_translations",
    "disable_rule",
    "ensure_references",
    "families",
    "flatten_services",
    "harden",
    "intrazone_allow_zones",
    "is_placeholder_group",
    "known_intervals",
    "lower_applications",
    "merged_zones",
    "note_fqdn_families",
    "note_nat_order",
    "note_profiles",
    "prune_unused",
    "rename_objects",
    "rewrite_destinations",
    "sanitize_names",
    "tainted_addresses",
    "tainted_services",
    "to_post_nat_lookup",
    "topo_groups",
    "zone_pairs",
]
