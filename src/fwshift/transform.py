# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Target-independent passes over the neutral model, shared by the emitters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import AbstractSet, Dict, List, Mapping, Optional, Set, Tuple, TypeVar

from .model import (
    ANY,
    ANY_V4,
    APP_DEFAULT,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    NatRule,
    Policy,
    Rule,
    RuleScope,
    Service,
    ServiceEntry,
    ServiceGroup,
    SnatKind,
)
from .names import NameRules, clean, unique
from .netutil import FULL_V4, FULL_V6, Interval, normalize, overlaps, parse_literal, within
from .report import Report, Severity

Reason = Tuple[str, str]
G = TypeVar("G", AddressGroup, ServiceGroup)


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


def tainted_addresses(p: Policy, keep_dynamic: bool = False) -> Dict[str, str]:
    """Address objects and groups whose content cannot be converted -> reason."""
    out: Dict[str, str] = {}
    for address in p.addresses.values():
        if address.kind == AddressKind.UNSUPPORTED:
            out[address.name] = address.raw or "unsupported address type"
    for group in p.address_groups.values():
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
            if group.name in out:
                continue
            bad = [m for m in group.members if m in out]
            if bad:
                out[group.name] = f"contains '{bad[0]}' ({out[bad[0]]})"
                changed = True
    return out


def tainted_services(p: Policy, extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    out: Dict[str, str] = dict(extra or {})
    for service in p.services.values():
        if service.unsupported:
            out[service.name] = service.unsupported
        elif not service.entries and service.name not in out:
            out[service.name] = "unsupported or undefined service"
    for group in p.service_groups.values():
        if not group.members:
            out[group.name] = "empty service group"
    changed = True
    while changed:
        changed = False
        for group in p.service_groups.values():
            if group.name in out:
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


def rewrite_destinations(p: Policy, report: Report, to_post_nat: bool, only: Optional[Set[str]] = None) -> None:
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
            continue
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
                elif not allow:
                    continue  # reported by the FortiOS parser together with match-vip
                elif pre_ref in _reachable_names(p, rule.destinations):
                    continue  # the policy names the virtual IP itself: FortiOS applied it to that traffic
                else:
                    text = (
                        f"the destination covers '{pre_ref}', the external address of NAT rule '{nat.name}', "
                        f"but not '{post_ref}' behind it. FortiOS looks policies up after the translation and "
                        "did not apply this policy to that traffic; the converted rule does"
                    )
                report.add("rule", rule.origin, Severity.REVIEW, "NAT_ADDRESS_EXPOSED", text)
                continue
            destinations = list(rule.destinations)
            for member, complete in hits:
                intervals = known_intervals(p, member)[0]
                if to_post_nat and complete and normalize(intervals) == normalize(old):
                    destinations[destinations.index(member)] = new_ref
                    how = f"replaced {old_side} destination '{member}' with {new_side} '{new_ref}'"
                else:
                    destinations.append(new_ref)
                    how = f"added {new_side} destination '{new_ref}' next to '{member}'"
                report.add(
                    "rule",
                    rule.origin,
                    Severity.APPROX,
                    "NAT_DESTINATION_REWRITTEN",
                    f"{how} because of NAT rule '{nat.name}'; check that this rule is meant "
                    "to cover the translated traffic",
                )
            rule.destinations = _dedupe(destinations)
            if port:
                report.add(
                    "rule",
                    rule.origin,
                    Severity.REVIEW,
                    "NAT_PORT_TRANSLATION",
                    f"NAT rule '{nat.name}' also translates the port to {port}; "
                    f"the service of this rule still names the {old_side} port and must be adjusted",
                )


# -- names ----------------------------------------------------------------


def sanitize_names(
    p: Policy,
    obj_rules: NameRules,
    rule_rules: NameRules,
    report: Report,
    reserved_addresses: AbstractSet[str] = frozenset(),
    reserved_services: AbstractSet[str] = frozenset(),
) -> None:
    """Rename objects and rules that the target platform would reject.

    Reserved names are names the target predefines: an object of the source that
    happens to carry one is renamed, so that it neither redefines the predefined
    object nor is mistaken for it.
    """
    address_map = _rename(
        [(n, "address") for n in p.addresses] + [(n, "address-group") for n in p.address_groups],
        obj_rules,
        report,
        reserved_addresses,
    )
    service_map = _rename(
        [(n, "service") for n in p.services] + [(n, "service-group") for n in p.service_groups],
        obj_rules,
        report,
        reserved_services,
    )

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

    taken: Set[str] = set()
    for rule in p.rules:
        rule.name = unique(rule.name, taken, rule_rules)
        rule.sources, rule.destinations = amap(rule.sources), amap(rule.destinations)
        rule.services = smap(rule.services)
    taken = set()
    for nat in p.nat_rules:
        nat.name = unique(nat.name, taken, obj_rules)
        nat.sources, nat.destinations = amap(nat.sources), amap(nat.destinations)
        nat.service = service_map.get(nat.service, nat.service)
        if nat.source_translation:
            nat.source_translation.addresses = amap(nat.source_translation.addresses)
        if nat.destination_translation:
            translated = nat.destination_translation.address
            nat.destination_translation.address = address_map.get(translated, translated)


def _rename(
    names: List[Tuple[str, str]], rules: NameRules, report: Report, reserved: AbstractSet[str]
) -> Dict[str, str]:
    taken = {name for name, _ in names if clean(name, rules) == name and name not in reserved}
    taken_before = set(taken)
    taken |= set(reserved)
    mapping: Dict[str, str] = {}
    for name, kind in names:
        if name in taken_before:
            continue
        new = unique(name, taken, rules)
        mapping[name] = new
        report.add(kind, name, Severity.INFO, "RENAMED", f"renamed to '{new}' to fit the target's naming rules")
        report.item(kind, name).emitted_as = [new]
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
    "blocking_reasons",
    "dedupe",
    "destination_translations",
    "disable_rule",
    "ensure_references",
    "families",
    "flatten_services",
    "is_placeholder_group",
    "known_intervals",
    "note_profiles",
    "prune_unused",
    "rewrite_destinations",
    "sanitize_names",
    "tainted_addresses",
    "tainted_services",
    "topo_groups",
    "zone_pairs",
]
