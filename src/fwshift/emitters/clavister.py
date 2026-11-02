# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Clavister cOS Core emitter: neutral model -> a CLI script (``.sgs``, run with ``script -execute``).

Design rules:

* The script only adds: address objects, services, interface groups, new IP rule sets with the prefix (``fws_``, or
  ``--target-prefix``), and two Goto rules at the top of ``main`` (one for IPv4, one for IPv6) that send what arrives on
  the interfaces of the policy to ``<prefix>rules``. Nothing is deleted, and nothing is activated: cOS Core takes changes
  only with ``activate``, and goes back to the configuration before unless ``commit`` follows within the timeout (CLI
  Reference Guide, activate and commit). Interfaces, routes and management are never touched.
* The rules are classic IP rules (``IPRule``), which keep the model's two lists apart. cOS Core remembers a SAT rule until
  the next Allow or NAT rule that matches the *untranslated* addresses completes it (Administration Guide 14.00, 8.4); its
  rules name the interface the destination is routed to before translation, the model the zone after it. So:

  - each destination NAT rule of the model is a SAT rule at the top of ``<prefix>rules`` (the first one that matches
    translates: assumed, from the older guides), and after all of them a Goto rule with the same match to a rule set of
    its own, ``<prefix>d_<rule>``, which holds the rules of the model that apply to the zone the translated address is
    routed to, in their order, with the untranslated addresses and any interface, then the policy's default. The traffic a
    SAT rule translates is decided there and nowhere else (that the SAT carries over into the Goto's rule set is assumed);
  - the other NAT rules (source translation, or none) are entries of ``<prefix>snat``, in their order, with Action NAT
    or Allow, followed by an Allow of everything; a rule of the model that allows traffic one of them may take is a Goto
    rule to that rule set. A Goto rule is exact by itself: the entries see only what the Goto rule matched.

* An IP rule is IPv4 or IPv6, never both: a rule of the model becomes one per IP version it can match. NAT and SAT are
  IPv4 only on cOS Core: NAT rules of IPv6 are not written.
* After the rules: what the policy does inside a zone where that differs, then its default between the interfaces of
  the policy, and last a Return rule for everything else (traffic to the firewall itself, to interfaces the policy does
  not name), which goes back to ``main`` after the Goto rules.
* A rule the target cannot say is written disabled (``set IPRule N -disable``) and listed; one whose fields cannot be
  written at all is a disabled rule that matches nothing (``0.0.0.0``), so that its place stays visible.
* The CLI syntax is that of the CLI Reference Guide (14.00, 15.00) for each object; the ServiceICMP value
  ``MessageTypes=Specific`` and ``NATAction=UseSenderAddress`` are **not confirmed** (the guide names the properties,
  not those values).
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, Service, ServiceEntry, SnatKind
from ..names import CLAVISTER, CLAVISTER_TEXT, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text, normalize, size, subtract
from ..options import Options
from ..parsers.clavister import ICMP6_TYPES, ICMP_TYPES, Match, match_and, zones_cover
from ..report import Report, Severity

ALL_NETS = {4: "all-nets", 6: "all-nets6"}
_ICMP_NAMES = {number: name for name, number in ICMP_TYPES.items()}
_ICMP6_NAMES = {number: name for name, number in ICMP6_TYPES.items()}
_RESERVED = {"any", "core", "all-nets", "all-nets6", "all_services", "main", "localhost", "localhost6"}


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or "fws_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,15}", prefix):
        raise FwshiftError("--target-prefix for Clavister: up to 16 letters, digits, periods, underscores and hyphens, starting "
                           "with a letter")  # fmt: skip
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, prefix, source_zones).run()


@dataclass
class _Piece:
    """One IP rule of cOS Core to write."""

    name: str
    action: str
    src_if: str
    dst_if: str
    family: int
    sources: str
    destinations: str
    service: str
    log: bool
    enabled: bool
    comment: str = ""
    extra: str = ""


@dataclass
class _Plan:
    """What a rule of the model becomes, worked out once for the rule set and for the rule sets of translations."""

    rule: Rule
    enabled: bool
    action: str
    log: bool
    comment: str
    pairs: List[Tuple[List[str], List[str]]]
    families: List[int]
    sources: Dict[int, str]
    destinations: Dict[int, str]
    service: str
    services: List[str]
    placeholder: bool = False


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, prefix: str, source_zones: Set[str]) -> None:
        self.p, self.report, self.options, self.prefix = p, report, options, prefix
        self.source_zones = source_zones
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        self.zones = transform.target_zones(p, options.zone_map, used, [])
        self.taken: Set[str] = set(_RESERVED)
        self.objects: List[str] = []
        self.groups: List[str] = []
        self.sets: Dict[str, List[str]] = {}
        self.address_refs: Dict[Tuple[str, int], Optional[str]] = {}
        self.literal_refs: Dict[Tuple[Interval, ...], str] = {}
        self.service_refs: Dict[str, Optional[str]] = {}
        self.if_groups: Dict[Tuple[str, ...], str] = {}
        self.interface_names: Dict[str, List[str]] = {}
        self.ruleset = self._name("rules")
        self.allow_set = ""
        self.allow_nat: List[NatRule] = []
        self.allow_fields: Dict[str, Tuple[str, str, str, str, str]] = {}
        self.zone_group = ""
        self.nothing = ""
        self.ipv6_nat: List[str] = []
        self.written_nat: List[NatRule] = []

    # -- names --------------------------------------------------------------------------------------------------

    def _name(self, label: str) -> str:
        base = clean(self.prefix + re.sub(r"[^A-Za-z0-9_.-]", "_", label), CLAVISTER)
        name, counter = base, 2
        while name.lower() in self.taken:
            suffix = f"_{counter}"
            name = base[: CLAVISTER.max_len - len(suffix)] + suffix
            counter += 1
        self.taken.add(name.lower())
        return name

    @staticmethod
    def _text(text: str) -> str:
        return clean(" ".join(text.split()), CLAVISTER_TEXT).strip() if text.strip() else ""

    # -- interfaces ---------------------------------------------------------------------------------------------

    def interfaces(self, zone: str) -> List[str]:
        if zone in self.interface_names:
            return self.interface_names[zone]
        names = [self.options.interface_map.get(i, i) for i in transform.target_interfaces(self.p, self.options.zone_map, zone)]
        if not names:
            names = [self.options.interface_map.get(zone, zone)]
        out = [re.sub(r"[^A-Za-z0-9_.-]", "_", n)[:63] or "unnamed" for n in transform.dedupe(names)]
        self.interface_names[zone] = out
        return out

    def _all_interfaces(self) -> List[str]:
        out: List[str] = []
        for zone in self.zones:
            out += self.interfaces(zone)
        return transform.dedupe(out)

    def _if_ref(self, zones: List[str]) -> str:
        """The value of SourceInterface or DestinationInterface for zones of the model: an interface, or a group."""
        if ANY in zones:
            return self.zone_group or "any"
        names = transform.dedupe([i for z in zones for i in self.interfaces(z)])
        if len(names) == 1:
            return names[0]
        key = tuple(sorted(names))
        if key not in self.if_groups:
            name = self._name("if_" + "_".join(key)[:40])
            self.groups.append(f"add InterfaceGroup {name} Members={','.join(names)}")
            self.if_groups[key] = name
        return self.if_groups[key]

    # -- addresses ----------------------------------------------------------------------------------------------

    def _literal(self, intervals: List[Interval], label: str) -> str:
        """An object (or a group of them) for addresses of one IP version that no object of the model holds as they are."""
        key = tuple(normalize(intervals))
        if key in self.literal_refs:
            return self.literal_refs[key]
        family = key[0][0]
        kind = "IP4Address" if family == 4 else "IP6Address"
        names: List[str] = []
        for interval in key:
            name = self._name(label if len(key) == 1 else f"{label}_{len(names) + 1}")
            self.objects.append(f"add Address {kind} {name} Address={_value(interval)}")
            names.append(name)
        if len(names) == 1:
            ref = names[0]
        else:
            ref = self._name(label)
            self.groups.append(f"add Address {'IP4Group' if family == 4 else 'IP6Group'} {ref} Members={','.join(names)}")
        self.literal_refs[key] = ref
        return ref

    def _member_ref(self, member: str, family: int, seen: Tuple[str, ...] = ()) -> Optional[str]:
        """The object for the addresses of one IP version a member of the model stands for; None when it has none."""
        key = (member, family)
        if key in self.address_refs:
            return self.address_refs[key]
        ref: Optional[str] = None
        if member in self.p.addresses:
            address = self.p.addresses[member]
            intervals = transform.address_intervals(self.p, member) or []
            if address.builtin == "clavister" and member not in _RESERVED and intervals and intervals[0][0] == family:
                ref = member
            elif intervals and intervals[0][0] == family:
                if intervals[0] in (FULL_V4, FULL_V6):
                    ref = ALL_NETS[family]
                else:
                    ref = self._name(member)
                    kind = "IP4Address" if family == 4 else "IP6Address"
                    comment = f" Comments=\"{self._text(address.description)}\"" if self._text(address.description) else ""
                    self.objects.append(f"add Address {kind} {ref} Address={_value(intervals[0])}{comment}")
        elif member in self.p.address_groups and member not in seen:
            group = self.p.address_groups[member]
            members = [r for r in (self._member_ref(m, family, seen + (member,)) for m in group.members) if r is not None]
            members = transform.dedupe(members)
            if ALL_NETS[family] in members:
                ref = ALL_NETS[family]
            elif members:
                ref = self._name(member if family == 4 or not self._has_family(member, 4) else member + "_v6")
                kind = "IP4Group" if family == 4 else "IP6Group"
                self.groups.append(f"add Address {kind} {ref} Members={','.join(members)}")
        else:
            intervals = [i for i in (transform.address_intervals(self.p, member) or []) if i[0] == family]
            if intervals:
                ref = ALL_NETS[family] if intervals[0] in (FULL_V4, FULL_V6) else self._literal(intervals, member)
        self.address_refs[key] = ref
        return ref

    def _has_family(self, member: str, family: int) -> bool:
        return family in transform.families(self.p, member)

    def _side(self, members: List[str], negated: bool, label: str, reasons: List[transform.Reason], word: str) -> Dict[int, str]:
        """The address object of each IP version for one side of a rule; a version that is missing matches nothing."""
        out: Dict[int, str] = {}
        for member in members:
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("CLAVISTER_FQDN", f"the {word} holds the host name {member}, which is not written"))
                return {}
        if negated:
            found: Dict[int, List[Interval]] = {4: [], 6: []}
            for member in members:
                intervals = transform.address_intervals(self.p, member)
                if intervals is None:
                    reasons.append(("CLAVISTER_NEGATION", f"a negated {word} whose addresses cannot be read"))
                    return {}
                for interval in intervals:
                    found[interval[0]].append(interval)
            for family, full in ((4, FULL_V4), (6, FULL_V6)):
                left = subtract([full], found[family])
                if left:
                    out[family] = ALL_NETS[family] if left == [full] else self._literal(left, f"{label}_not")
            return out
        for family in (4, 6):
            refs = []
            for member in members:
                if member == ANY:
                    refs = [ALL_NETS[family]]
                    break
                ref = self._member_ref(member, family)
                if ref is not None:
                    refs.append(ref)
            refs = transform.dedupe(refs)
            if ALL_NETS[family] in refs:
                out[family] = ALL_NETS[family]
            elif len(refs) == 1:
                out[family] = refs[0]
            elif refs:
                name = self._name(label)
                self.groups.append(f"add Address {'IP4Group' if family == 4 else 'IP6Group'} {name} Members={','.join(refs)}")
                out[family] = name
        return out

    def _placeholder(self) -> str:
        if not self.nothing:
            self.nothing = self._name("nothing")
            self.objects.append(f"add Address IP4Address {self.nothing} Address=0.0.0.0")
        return self.nothing

    # -- services -----------------------------------------------------------------------------------------------

    def _service_lines(self, name: str, entries: List[ServiceEntry]) -> Optional[List[Tuple[str, str]]]:
        """(label, properties) of the services of cOS Core for entries of the model; None when one cannot be written,
        [] when they are every service."""
        out: List[Tuple[str, str]] = []
        ports: Dict[Tuple[str, str], List[Protocol]] = {}
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                ports.setdefault((entry.dst_ports, entry.src_ports), []).append(entry.protocol)
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                table = _ICMP_NAMES if entry.protocol == Protocol.ICMP else _ICMP6_NAMES
                kind = "ServiceICMP" if entry.protocol == Protocol.ICMP else "ServiceICMPv6"
                if entry.icmp_type is None:
                    if entry.icmp_code is not None:
                        return None
                    out.append((kind, "MessageTypes=All"))
                elif entry.icmp_type in table:
                    props = f"MessageTypes=Specific {table[entry.icmp_type]}=Yes"
                    if entry.icmp_code is not None:
                        props += f" {table[entry.icmp_type]}Codes={entry.icmp_code}"
                    out.append((kind, props))
                else:
                    return None
            elif entry.protocol == Protocol.SCTP:
                if entry.dst_ports or entry.src_ports:
                    return None
                out.append(("ServiceIPProto", "IPProto=132"))
            elif entry.ip_protocol is None:
                return []
            else:
                out.append(("ServiceIPProto", f"IPProto={entry.ip_protocol}"))
        for (dst, src), protocols in ports.items():
            kind = "TCPUDP" if set(protocols) == {Protocol.TCP, Protocol.UDP} else protocols[0].value.upper()
            props = f"Type={kind} DestinationPorts={dst or '0-65535'}"
            if src:
                props += f" SourcePorts={src}"
            out.insert(0, ("ServiceTCPUDP", props))
        return list(dict.fromkeys(out))

    def _service_ref(self, name: str) -> Optional[str]:
        """The service of cOS Core for a service (or group) of the model: all_services for every service; None when it
        cannot be written."""
        if name == ANY:
            return "all_services"
        if name in self.service_refs:
            return self.service_refs[name]
        ref: Optional[str] = None
        service = self.p.services.get(name)
        if service is not None and service.builtin == "clavister" and name not in _RESERVED:
            ref = name
        else:
            flat = transform.flatten_services(self.p, name)
            if flat is not None:
                lines = self._service_lines(name, flat)
                if lines == []:
                    ref = "all_services"
                elif lines is not None:
                    names: List[str] = []
                    for kind, props in lines:
                        label = name if len(lines) == 1 else f"{name}_{len(names) + 1}"
                        object_name = self._name(label)
                        self.objects.append(f"add Service {kind} {object_name} {props}")
                        names.append(object_name)
                    if len(names) == 1:
                        ref = names[0]
                    else:
                        ref = self._name(name + "_grp" if name + "_grp" not in self.taken else name)
                        self.groups.append(f"add Service ServiceGroup {ref} Members={','.join(names)}")
        self.service_refs[name] = ref
        return ref

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[str]]:
        """The services of the model a rule matches, one by one (applications as the ports of the table)."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
            name = f"{rule.name}-apps"
            self.p.services[name] = Service(name, entries)
            return [name]
        if rule.negate_service:
            reasons.append(("CLAVISTER_NEGATED_SERVICE", "a negated service: a rule of cOS Core names the services it matches"))
            return None
        return list(rule.services)

    def _service_of(self, names: List[str], label: str, reasons: List[transform.Reason]) -> Optional[str]:
        refs = []
        for name in names:
            ref = self._service_ref(name)
            if ref is None:
                reasons.append(("CLAVISTER_SERVICE", f"service '{name}' cannot be written (an ICMP type cOS Core does not name, "
                                "an ICMP code without a type, or SCTP ports)"))  # fmt: skip
                return None
            refs.append(ref)
        refs = transform.dedupe(refs)
        if "all_services" in refs:
            return "all_services"
        if len(refs) == 1:
            return refs[0]
        name = self._name(label)
        self.groups.append(f"add Service ServiceGroup {name} Members={','.join(refs)}")
        return name

    # -- NAT ----------------------------------------------------------------------------------------------------

    def _zone_of(self, member: str) -> Optional[List[str]]:
        """The zones a translated address is routed to, from the networks the source or --zone-network gives."""
        found = transform.address_intervals(self.p, member)
        if not found:
            return None
        networks: List[Tuple[Interval, str]] = []
        for source in (self.p.zone_networks, self.options.zone_networks):
            for zone, nets in source.items():
                target = self.options.zone_map.get(zone, zone) if source is self.p.zone_networks else zone
                for net in nets:
                    for interval in transform.address_intervals(self.p, net) or []:
                        networks.append((interval, target))
        zones: List[str] = []
        for interval in found:
            best: Optional[Tuple[int, str]] = None
            for network, zone in networks:
                if network[0] == interval[0] and network[1] <= interval[1] and interval[2] <= network[2]:
                    if best is None or size(network) < best[0]:
                        best = (size(network), zone)
            if best is None:
                return None
            zones.append(best[1])
        return transform.dedupe(zones)

    def nat_problem(self, nat: NatRule) -> Optional[str]:
        """Why a NAT rule cannot be written; None when it can."""
        if nat.unsupported:
            return "not converted: " + "; ".join(nat.unsupported)
        members = nat.sources + nat.destinations
        snat, dnat = nat.source_translation, nat.destination_translation
        members += (snat.addresses if snat else []) + ([dnat.address] if dnat else [])
        for member in members:
            if member in self.taint_a:
                return f"references '{member}': {self.taint_a[member]}"
        if nat.service in self.taint_s:
            return f"references '{nat.service}': {self.taint_s[nat.service]}"
        for member in nat.sources + nat.destinations:
            if member != ANY and transform.families(self.p, member) == {6}:
                return "NAT of IPv6: cOS Core translates IPv4 only"
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                return f"the host name {member}, which is not written"
        if dnat is not None:
            after = transform.address_intervals(self.p, dnat.address)
            if dnat.spread or not after or len(after) != 1 or after[0][0] != 4:
                return "destination NAT to something other than one IPv4 address or range"
            if size(after[0]) > 1:
                before = [i for m in nat.destinations for i in (transform.address_intervals(self.p, m) or [])]
                if len(before) != 1 or size(before[0]) != size(after[0]):
                    return "destination NAT to a range of another size than what it translates"
            if dnat.port:
                entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else None
                if not entries or len({e.dst_ports for e in entries}) != 1 or not re.fullmatch(r"\d+", entries[0].dst_ports) \
                        or not re.fullmatch(r"\d+", dnat.port):
                    return "a port translation of a service that is not one single port (cOS Core moves a range as a block)"
        if snat is not None:
            if snat.kind == SnatKind.STATIC:
                if dnat is not None:
                    return "a static source translation together with a destination translation"
                if len(snat.addresses) != 1:
                    return "a static source translation to several objects"
            elif snat.kind == SnatKind.INTERFACE:
                if snat.addresses:
                    return "a translation to the interface with addresses"
            elif len(snat.addresses) != 1:
                return "a source translation to a pool of addresses (cOS Core needs a NAT pool object, which is not written)"
            else:
                after = transform.address_intervals(self.p, snat.addresses[0])
                if not after or len(after) != 1 or size(after[0]) != 1 or after[0][0] != 4:
                    return "a source translation to more than one address (a NAT pool, which is not written)"
        if snat is None and dnat is None:
            return None
        return None

    def _nat_fields(self, nat: NatRule) -> Optional[Tuple[str, str, str, str, str]]:
        """(SourceInterface, SourceNetwork, DestinationInterface, DestinationNetwork, Service) of the IPv4 part of a NAT rule's
        match; None, and the rule skipped, when it cannot be written."""
        reasons: List[transform.Reason] = []
        sources = self._side(nat.sources, False, f"{nat.name}_src", reasons, "source")
        destinations = self._side(nat.destinations, False, f"{nat.name}_dst", reasons, "destination")
        service = self._service_of([nat.service], f"{nat.name}_svc", reasons)
        if reasons or 4 not in sources or 4 not in destinations or service is None:
            why = "; ".join(m for _, m in reasons) or "nothing of it is IPv4"
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", "not converted: " + why)
            return None
        # Before translation the destination is routed to core (an address of the firewall) or to an interface (an
        # address it publishes); the model does not say which, and the address decides it: any.
        dst_if = "any" if nat.destination_translation is not None or ANY in nat.dst_zones else self._if_ref(nat.dst_zones)
        return self._if_ref(nat.src_zones), sources[4], dst_if, destinations[4], service

    def _sat_extra(self, nat: NatRule) -> str:
        dnat, snat = nat.destination_translation, nat.source_translation
        if dnat is not None:
            after = transform.address_intervals(self.p, dnat.address) or []
            if size(after[0]) > 1:
                target = self._literal([(4, after[0][1], after[0][1])], nat.name + "_base")
            else:
                target = self._member_ref(dnat.address, 4) or self._literal(after, nat.name + "_to")
            extra = f"SATTranslate=DestinationIP SATTranslateToIP={target}"
            before = [i for m in nat.destinations for i in (transform.address_intervals(self.p, m) or [])]
            if size(after[0]) == 1 and sum(size(i) for i in before) > 1:
                extra += " SATAllToOne=Yes"
            if dnat.port:
                extra += f" SATTranslateToPort={dnat.port}"
            return extra
        assert snat is not None
        after = transform.address_intervals(self.p, snat.addresses[0]) or []
        before = [i for m in nat.sources for i in (transform.address_intervals(self.p, m) or [])]
        target = self._member_ref(snat.addresses[0], 4) or ""
        if size(after[0]) > 1:
            target = self._literal([(4, after[0][1], after[0][1])], nat.name + "_base")
        extra = f"SATTranslate=SourceIP SATTranslateToIP={target}"
        if size(after[0]) == 1 and sum(size(i) for i in before) > 1:
            extra += " SATAllToOne=Yes"
        return extra

    def _source_action(self, nat: NatRule) -> Tuple[str, str]:
        """(action, properties) of the IP rule that completes a NAT rule's translation of the source."""
        snat = nat.source_translation
        if snat is None or snat.kind == SnatKind.STATIC:
            return "Allow", ""
        if snat.kind == SnatKind.INTERFACE:
            return "NAT", ""
        ref = self._member_ref(snat.addresses[0], 4) or ""
        return "NAT", f"NATAction=UseSenderAddress NATSenderAddress={ref}"

    # -- writing ------------------------------------------------------------------------------------------------

    def _write(self, piece: _Piece, ruleset: str = "") -> str:
        ruleset = ruleset or self.ruleset
        lines = self.sets.setdefault(ruleset, [])
        index = sum(1 for line in lines if line.startswith("add "))
        index += 1
        kind = "GotoRule" if piece.action.startswith("Goto ") else "IPRule"
        words = [f"add {kind} Index={index}", f"Name={piece.name}"]
        if kind == "IPRule":
            words.append(f"Action={piece.action}")
        words += [f"SourceInterface={piece.src_if}", f"SourceNetwork={piece.sources}", f"DestinationInterface={piece.dst_if}",
                  f"DestinationNetwork={piece.destinations}", f"Service={piece.service}"]  # fmt: skip
        if kind == "GotoRule":
            words.append(f"RuleSet={piece.action.split()[1]}")
        if piece.extra:
            words.append(piece.extra)
        words.append("LogEnabled=" + ("Yes" if piece.log else "No"))
        if piece.comment:
            words.append(f'Comments="{piece.comment}"')
        lines.append(" ".join(words))
        if not piece.enabled:
            lines.append(f"set {kind} {index} -disable")
        return f"{ruleset} {index} ({piece.name})"

    @staticmethod
    def _action(rule: Rule) -> str:
        if rule.action == Action.ALLOW:
            return "Allow"
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            return "Reject"
        return "Drop"

    def _pairs(self, rule: Rule, reasons: List[transform.Reason]) -> List[Tuple[List[str], List[str]]]:
        pairs = transform.zone_pairs(rule)
        if pairs is not None:
            return pairs
        zones = self.zones
        if not zones:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone, and the policy names no zone"))
            return [(rule.src_zones, rule.dst_zones)]
        if rule.scope.value == "intrazone":
            return [([z], [z]) for z in zones]
        sources = zones if ANY in rule.src_zones else rule.src_zones
        destinations = zones if ANY in rule.dst_zones else rule.dst_zones
        return [([z], [d for d in destinations if d != z]) for z in sources if [d for d in destinations if d != z]]

    # -- rules --------------------------------------------------------------------------------------------------

    def _plan(self, rule: Rule) -> Optional[_Plan]:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value} becomes Reject, which answers the sender only")  # fmt: skip
        label = rule.name
        shape: List[transform.Reason] = []
        sources = self._side(rule.sources, rule.negate_source, f"{label}_src", shape, "source")
        destinations = self._side(rule.destinations, rule.negate_destination, f"{label}_dst", shape, "destination")
        services = self._services(rule, reasons)
        service = self._service_of(services, f"{label}_svc", shape) if services is not None else None
        pairs = self._pairs(rule, reasons)
        reasons += shape
        families: List[int] = [f for f in (4, 6) if f in sources and f in destinations]
        if not reasons and services is not None and not families:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING", "the sources and destinations have no IP version in common: "
                             "the rule matches nothing", Severity.INFO)  # fmt: skip
            return None
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        plan = _Plan(rule, rule.enabled and not reasons, self._action(rule), rule.log_start or rule.log_end,
                     self._text(rule.description), pairs, families, sources, destinations, service or "", services or [])  # fmt: skip
        plan.placeholder = service is None or not families or not pairs
        if not rule.enabled and not reasons:
            self.report.add("rule", rule.origin, Severity.INFO, "CLAVISTER_DISABLED", "disabled in the source; written disabled")
        return plan

    def _body(self, plan: _Plan) -> None:
        """The rule in the rule set, for traffic no SAT rule translated: an allowing rule that NAT rules may take traffic
        of is a Goto rule to the rule set of the source translations."""
        rule = plan.rule
        item = self.report.item("rule", rule.origin)
        if plan.placeholder:
            piece = _Piece(self._name(rule.name), plan.action, "any", "any", 4, self._placeholder(), self._placeholder(), "all_services",
                           plan.log, False, plan.comment)  # fmt: skip
            item.emitted_as.append(self._write(piece) + ", a placeholder, disabled")
            return
        for src_zones, dst_zones in plan.pairs:
            src_if, dst_if = self._if_ref(src_zones), self._if_ref(dst_zones)
            for family in plan.families:
                name = self._name(rule.name if family == 4 or 4 not in plan.families else f"{rule.name}_v6")
                action = plan.action
                if family == 4 and plan.enabled and rule.action == Action.ALLOW and self.allow_set and self._snat_meets(plan, src_zones, dst_zones):
                    action = f"Goto {self.allow_set}"
                piece = _Piece(name, action, src_if, dst_if, family, plan.sources[family], plan.destinations[family], plan.service,
                               plan.log, plan.enabled, plan.comment)  # fmt: skip
                item.emitted_as.append(self._write(piece))

    def _snat_meets(self, plan: _Plan, src_zones: List[str], dst_zones: List[str]) -> bool:
        rule = plan.rule
        if rule.negate_source or rule.negate_destination:
            return True
        for nat in self.allow_nat:
            for service in plan.services or [ANY]:
                first = Match(list(src_zones), list(dst_zones), list(rule.sources), list(rule.destinations), service)
                second = Match(list(nat.src_zones), list(nat.dst_zones), list(nat.sources), list(nat.destinations), nat.service)
                if match_and(self.p, first, second) is not None:
                    return True
        return False

    def _dnat_set(self, nat: NatRule, ruleset: str, plans: List[_Plan]) -> None:
        """The rule set for the traffic one SAT rule translates: the rules of the model in their order, for the zone the
        translated address is routed to, with the source translation of the NAT rule; then the policy's default."""
        after = self._translated_zone(nat)
        allow, extra = self._source_action(nat)
        for plan in plans:
            rule = plan.rule
            if not plan.enabled or plan.placeholder or 4 not in plan.families:
                continue
            for src_zones, dst_zones in plan.pairs:
                if not self._may_meet(plan, src_zones, nat):
                    continue
                if ANY not in dst_zones and (after is None or not zones_cover(dst_zones, after)):
                    if after is not None and not set(after) & set(dst_zones):
                        continue
                    blocking = rule.action != Action.ALLOW
                    self.report.add("rule", rule.origin, Severity.REVIEW, "CLAVISTER_DNAT_ZONE",
                                    f"the zone NAT rule {nat.name} translates to is not known (no network of a zone, "
                                    "--zone-network, holds it) or only partly among the zones of this rule: for the translated "
                                    "traffic the rule is " + ("written, and may block more" if blocking else "not written"))  # fmt: skip
                    if not blocking:
                        continue
                action, props = (allow, extra) if rule.action == Action.ALLOW else (plan.action, "")
                piece = _Piece(self._name(f"{nat.name}_{rule.name}"), action, self._if_ref(src_zones), "any", 4, plan.sources[4],
                               plan.destinations[4], plan.service, plan.log, True, plan.comment, props)  # fmt: skip
                self._write(piece, ruleset)
        between = self.p.default_interzone == Action.ALLOW
        if after is not None and len(after) == 1 and self.zones:
            decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, Report())
            zone = after[0]
            if zone in decided and decided[zone] != between:
                action, props = (allow, extra) if decided[zone] else ("Drop", "")
                self._write(_Piece(self._name(f"{nat.name}_inside"), action, self._if_ref([zone]), "any", 4, "all-nets", "all-nets",
                                   "all_services", False, True, "", props), ruleset)  # fmt: skip
        action, props = (allow, extra) if between else ("Drop", "")
        self._write(_Piece(self._name(f"{nat.name}_default"), action, "any", "any", 4, "all-nets", "all-nets", "all_services", False,
                           True, "", props), ruleset)  # fmt: skip

    def _translated_zone(self, nat: NatRule) -> Optional[List[str]]:
        """The zones the translated address of a destination NAT rule is routed to: from the networks of the zones (the
        source's, --zone-network), else from the rules that allow traffic to it (said); None when neither tells."""
        assert nat.destination_translation is not None
        after = self._zone_of(nat.destination_translation.address)
        if after is not None:
            return after
        zones: List[str] = []
        named = list(nat.destinations) + [nat.destination_translation.address]
        for rule in self.p.rules:
            if not rule.enabled or rule.action != Action.ALLOW or rule.negate_destination or ANY in rule.destinations:
                continue
            if ANY not in rule.src_zones and ANY not in nat.src_zones and not set(rule.src_zones) & set(nat.src_zones):
                continue
            first = [i for m in rule.destinations for i in (transform.address_intervals(self.p, m) or [])]
            second = [i for m in named for i in (transform.address_intervals(self.p, m) or [])]
            if any(a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2] for a in first for b in second):
                zones += rule.dst_zones
        zones = transform.dedupe(zones)
        if not zones or ANY in zones:
            return None
        self.report.add("nat", nat.origin, Severity.APPROX, "CLAVISTER_DNAT_ZONE_FROM_RULES",
                        f"no network of a zone holds {nat.destination_translation.address}: the zone it is routed to is taken "
                        f"from the rules that allow traffic to it ({', '.join(zones)}); give --zone-network to say it")  # fmt: skip
        return zones

    def _may_meet(self, plan: _Plan, src_zones: List[str], nat: NatRule) -> bool:
        rule = plan.rule
        if rule.negate_source or rule.negate_destination:
            return True
        for service in plan.services or [ANY]:
            first = Match(list(src_zones), [ANY], list(rule.sources), list(rule.destinations), service)
            second = Match(list(nat.src_zones), [ANY], list(nat.sources), list(nat.destinations), nat.service)
            if match_and(self.p, first, second) is not None:
                return True
        return False

    # -- what no rule decides -----------------------------------------------------------------------------------

    def _defaults(self) -> None:
        if not self.zones:
            self.report.note(Severity.REVIEW, "CLAVISTER_NO_ZONES",
                             "the source names no zones: the rules name the interface 'any', and the policy's default is not "
                             "written (it would also decide traffic to the firewall itself); what no rule of the new rule set "
                             "matches goes back to main. Give the rules zones, or map them with --zone-map")  # fmt: skip
        else:
            between = self.p.default_interzone == Action.ALLOW
            decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
            for zone in self.zones:
                if decided[zone] != between:
                    ref = self._if_ref([zone])
                    for family in (4, 6):
                        self._write(_Piece(self._name(f"inside_{zone}" + ("" if family == 4 else "_v6")),
                                           "Allow" if decided[zone] else "Drop", ref, ref, family, ALL_NETS[family], ALL_NETS[family],
                                           "all_services", False, True))  # fmt: skip
            for family in (4, 6):
                self._write(_Piece(self._name("default" + ("" if family == 4 else "_v6")), "Allow" if between else "Drop",
                                   self.zone_group, self.zone_group, family, ALL_NETS[family], ALL_NETS[family], "all_services",
                                   False, True))  # fmt: skip
        lines = self.sets[self.ruleset]
        for family in (4, 6):
            index = sum(1 for line in lines if line.startswith("add ")) + 1
            lines.append(f"add ReturnRule Index={index} Name={self._name('return' + ('' if family == 4 else '_v6'))} "
                         f"SourceInterface=any SourceNetwork={ALL_NETS[family]} DestinationInterface=any "
                         f"DestinationNetwork={ALL_NETS[family]} Service=all_services LogEnabled=No")  # fmt: skip

    # -- output -------------------------------------------------------------------------------------------------

    def run(self) -> str:
        if self.zones:
            self.zone_group = self._name("zones")
            self.groups.append(f"add InterfaceGroup {self.zone_group} Members={','.join(self._all_interfaces())}")
        self.sets[self.ruleset] = []
        # NAT rules that can be written: destination translations as SAT rules at the top, each followed (after all of
        # them) by a Goto rule to the rule set that decides what it translates; the others in a rule set of their own,
        # in their order, that the allowing rules go to.
        dnat: List[Tuple[NatRule, Tuple[str, str, str, str, str]]] = []
        for nat in self.p.nat_rules:
            problem = self.nat_problem(nat)
            if problem is not None:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED" if nat.unsupported or "references" in problem
                                 else "CLAVISTER_NAT_FORM", problem)  # fmt: skip
                if "IPv6" in problem:
                    self.ipv6_nat.append(nat.origin)
                continue
            fields = self._nat_fields(nat)
            if fields is None:
                continue
            self.written_nat.append(nat)
            if nat.destination_translation is not None:
                dnat.append((nat, fields))
            else:
                self.allow_nat.append(nat)
                self.allow_fields[nat.origin] = fields
        written = {n.origin for n in self.written_nat}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=frozenset(n.origin for n in self.allow_nat))
        plans = [plan for plan in (self._plan(rule) for rule in self.p.rules) if plan is not None]
        if self.allow_nat:
            self.allow_set = self._name("snat")
            self.sets[self.allow_set] = []
            for nat in self.allow_nat:
                src_if, sources, dst_if, destinations, service = self.allow_fields[nat.origin]
                item = self.report.item("nat", nat.origin)
                snat = nat.source_translation
                if snat is not None and snat.kind == SnatKind.STATIC:
                    item.emitted_as.append(self._write(_Piece(self._name(f"{nat.name}_sat"), "SAT", src_if, dst_if, 4, sources,
                                                              destinations, service, False, nat.enabled, "", self._sat_extra(nat)),
                                                       self.allow_set))  # fmt: skip
                    if snat.bidirectional:
                        self.report.add("nat", nat.origin, Severity.REVIEW, "CLAVISTER_BIDIRECTIONAL",
                                        "a static translation in both directions: only the source SAT is written; connections "
                                        "to the translated address need a SAT rule of their own")  # fmt: skip
                action, extra = self._source_action(nat)
                item.emitted_as.append(self._write(_Piece(self._name(nat.name), action, src_if, dst_if, 4, sources, destinations, service,
                                                          False, nat.enabled, self._text(nat.description), extra), self.allow_set))  # fmt: skip
                if not nat.enabled:
                    self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written disabled")
            for family in (4, 6):
                self._write(_Piece(self._name("snat_allow" + ("" if family == 4 else "_v6")), "Allow", "any", "any", family,
                                   ALL_NETS[family], ALL_NETS[family], "all_services", False, True), self.allow_set)  # fmt: skip
        for nat, (src_if, sources, dst_if, destinations, service) in dnat:
            item = self.report.item("nat", nat.origin)
            item.emitted_as.append(self._write(_Piece(self._name(f"{nat.name}_sat"), "SAT", src_if, dst_if, 4, sources, destinations,
                                                      service, False, nat.enabled, self._text(nat.description), self._sat_extra(nat))))  # fmt: skip
            if not nat.enabled:
                self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written disabled")
        for nat, (src_if, sources, dst_if, destinations, service) in dnat:
            target = self._name(f"d_{nat.name}")
            self.sets[target] = []
            self._write(_Piece(self._name(f"{nat.name}_goto"), f"Goto {target}", src_if, dst_if, 4, sources, destinations, service,
                               False, nat.enabled))  # fmt: skip
            self._dnat_set(nat, target, plans)
        for plan in plans:
            self._body(plan)
        self._defaults()
        self._notes()
        out = list(self.objects) + list(self.groups)
        for name in self.sets:
            out.append(f'add IPRuleSet {name} Comments="Written by FWShift"')
        for name, lines in list(self.sets.items())[1:] + list(self.sets.items())[:1]:
            out.append(f"cc IPRuleSet {name}")
            out += lines
            out.append("cc")
        out.append("cc IPRuleSet main")
        source = self.zone_group or "any"
        for index, family in ((1, 4), (2, 6)):
            out.append(f"add GotoRule Index={index} Name={self._name('goto' + ('' if family == 4 else '_v6'))} SourceInterface={source} "
                       f"SourceNetwork={ALL_NETS[family]} DestinationInterface=any DestinationNetwork={ALL_NETS[family]} "
                       f"Service=all_services RuleSet={self.ruleset} LogEnabled=No")  # fmt: skip
        out.append("cc")
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        interfaces = self._all_interfaces()
        count = sum(1 for lines in self.sets.values() for line in lines if line.startswith("add "))
        self.report.note(Severity.REVIEW, "CLAVISTER_LOAD",
                         f"the output is a cOS Core CLI script (section 10): it adds objects, the rule set {self.ruleset} "
                         f"(and {len(self.sets) - 1} rule sets it sends traffic to; {count} entries in all), and two Goto rules "
                         "at the top of main that send what arrives on the interfaces of the policy there. It deletes nothing "
                         "and activates nothing: run it with 'script -execute -name=FILE', read the changes, then 'activate' "
                         "and, within the timeout, 'commit' (without commit cOS Core goes back to the configuration before). "
                         "Traffic the new rule set does not decide (to the firewall itself, to other interfaces) returns to main "
                         "after the Goto rules")  # fmt: skip
        if interfaces:
            self.report.note(Severity.REVIEW, "INTERFACES_REQUIRED",
                             "zones are written as the interfaces of the firewall; these names must be its interfaces (Ethernet, "
                             "VLAN, tunnels), or cOS Core refuses the rules that name them. Map them with --zone-map or "
                             "--interface-map: " + ", ".join(interfaces[:20]) + (" ..." if len(interfaces) > 20 else ""))  # fmt: skip
        if self.ipv6_nat:
            self.report.note(Severity.INFO, "CLAVISTER_IPV4_NAT", "cOS Core translates IPv4 only: NAT rules of IPv6 are not "
                             "written: " + ", ".join(transform.dedupe(self.ipv6_nat)[:12]))  # fmt: skip
        if any(n.destination_translation is not None for n in self.written_nat):
            self.report.note(Severity.INFO, "CLAVISTER_SAT_ORDER",
                             "destination NAT is written as SAT rules at the top of the rule set, each followed by a Goto rule "
                             "to a rule set that decides the traffic it translates: the rules of the policy, for the zone the "
                             "translated address is routed to, with the untranslated addresses. Of several SAT rules that match, "
                             "the first one translates, and the SAT carries over into the rule set of the Goto (both assumed)")  # fmt: skip
        if self.allow_set:
            self.report.note(Severity.INFO, "CLAVISTER_SNAT_SET",
                             f"source NAT is written in the rule set {self.allow_set}, one entry per NAT rule in their order and an "
                             "Allow at the end; a rule that allows traffic a NAT rule may translate is a Goto rule to it. The log "
                             "setting of such a rule is that of the Goto rule")  # fmt: skip


def _value(interval: Interval) -> str:
    """An address, network or range as the Address property of an IP4Address or IP6Address takes it."""
    text = interval_text(interval)
    if "-" in text or "/" in text:
        return text
    return str(int_to_ip(interval[0], interval[1]))

