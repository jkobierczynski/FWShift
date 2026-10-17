# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Juniper emitter: neutral model -> ``set`` commands for an SRX (Junos OS), for ``load set``.

Design rules:

* Nothing is ever widened silently. A policy whose match cannot be expressed is written and then
  deactivated (``deactivate security policies ...``), and reported.
* Junos looks policies up per pair of zones, and only then in the global policies. A rule of the
  model for given zones becomes a policy in each pair of zones it covers, in the order of the
  model; zone "any" stands for every zone the policy knows. The rules at the end of the model that
  are for every zone become global policies, which come last anyway.
* Policies are looked up after destination NAT: they name the translated destination.
* Objects go into the global address book, which global policies and NAT rules require.
* NAT: destination NAT and the inbound half of a bi-directional static NAT become destination and
  static NAT rules, source NAT source NAT rules, in rule sets per zone (and pair of zones), in the
  order of the model. Junos applies one destination and one source translation to a connection.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, ANY_V6, Action, AddressGroup, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..names import JUNOS, JUNOS_RULE, NameRules, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text, normalize, parse_literal, size, subtract
from ..options import Options
from ..report import Report, Severity

_RESERVED_PREFIXES = ("junos-", "junos_", "static_nat_", "incoming_nat_")
_ZONE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
_PLACEHOLDER = "192.0.0.8/32"
_MAX_EXCLUDED = 10


def _q(text: str) -> str:
    """A value in double quotes, as a set line takes it."""
    cleaned = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", text).split())
    return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    zones = transform.dedupe([options.zone_map.get(z, z) for z in p.zones])
    transform.apply_zone_map(p, options.zone_map)
    for zone in zones + [z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]:
        if not _ZONE.fullmatch(zone) or zone in ("junos-host", "any"):
            raise FwshiftError(f"zone '{zone[:40]}' cannot be the name of a security zone of an SRX: give it another name "
                               "with --zone-map")  # fmt: skip
    transform.ensure_references(p, report)
    native = p.vendor == "junos"
    keep = {n for n, s in p.services.items() if s.builtin == "junos"} | {n for n, g in p.service_groups.items() if g.builtin == "junos"}
    _rename_reserved(p, report, keep)
    transform.sanitize_names(p, JUNOS, JUNOS_RULE, report, reserved_addresses={"any", "any-ipv4", "any-ipv6"},
                             reserved_services={"any"}, prefix=options.object_prefix, keep=keep)  # fmt: skip
    probe = _Emitter(p, Report(), options, zones, native, keep)
    written = {nat.origin for nat in p.nat_rules if probe.nat_plan(nat)[0] is None
               and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, zones, native, keep).run()


def _rename_reserved(p: Policy, report: Report, keep: Set[str]) -> None:
    """Names Junos keeps for itself (junos-..., static_nat_...) are not taken by an object of the source."""
    taken = {n.lower() for n in list(p.addresses) + list(p.address_groups) + list(p.services) + list(p.service_groups)}
    address_map: Dict[str, str] = {}
    service_map: Dict[str, str] = {}
    for names, mapping, kind in ((list(p.addresses) + list(p.address_groups), address_map, "address"),
                                 (list(p.services) + list(p.service_groups), service_map, "service")):  # fmt: skip
        for name in names:
            if name in keep or not clean(name, JUNOS).lower().startswith(_RESERVED_PREFIXES):
                continue
            new = "x" + name
            while new.lower() in taken:
                new = "x" + new
            taken.add(new.lower())
            mapping[name] = new
            report.add(kind, name, Severity.INFO, "RENAMED", f"renamed to '{new}': Junos keeps names that start like this for itself")
    if address_map or service_map:
        transform.rename_objects(p, address_map, service_map)


@dataclass
class _NatLine:
    kind: str  # static, destination, source
    context: Tuple[str, ...]  # (from zone,) or (from zone, to zone)
    nat: NatRule
    lines: List[str] = field(default_factory=list)  # what follows "rule NAME"


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, zones: List[str], native: bool, keep: Set[str]) -> None:
        self.p, self.report, self.options, self.native, self.keep = p, report, options, native, keep
        used = [z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(zones + used)
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s: Dict[str, str] = {}
        self.object_names: Set[str] = {n.lower() for n in list(p.addresses) + list(p.address_groups) + list(p.services)
                                       + list(p.service_groups)}  # fmt: skip
        self.policy_names: Set[str] = set()
        self.objects: List[str] = []
        self.applications: List[str] = []
        self.policies: List[str] = []
        self.nat_lines: List[str] = []
        self.literals: Dict[str, str] = {}
        self.svc_written: Set[str] = set()
        self.any_services: Set[str] = set()
        self.pools: Dict[str, str] = {}
        self.pool_names: Set[str] = set()
        self.pool_lines: List[str] = []
        self.set_names: Set[str] = set()
        self.used_zones: Set[str] = set()
        self._tail_found: Optional[int] = None
        self.static_pairs = self._static_pairs()

    def _name(self, label: str, rules: NameRules = JUNOS, taken: Optional[Set[str]] = None) -> str:
        taken = self.object_names if taken is None else taken
        base = clean(label, rules)
        if base.lower().startswith(_RESERVED_PREFIXES):
            base = clean("x" + base, rules)
        candidate, counter = base, 2
        while candidate.lower() in taken:
            tail = f"_{counter}"
            candidate = base[: rules.max_len - len(tail)] + tail
            counter += 1
        taken.add(candidate.lower())
        return candidate

    # -- top level --------------------------------------------------------------------------------

    def run(self) -> str:
        self._addresses()
        self._services()
        self._nat()
        for index, rule in enumerate(self.p.rules):
            self._rule(rule, index >= self._tail())
        self._notes()
        default = []
        if self.p.default_interzone == Action.ALLOW and self.p.default_intrazone == Action.ALLOW:
            default = ["set security policies default-policy permit-all"]
        return "\n".join(self.applications + self.objects + self.policies + default + self.nat_lines) + "\n"

    def _tail(self) -> int:
        """Where the global policies begin. Junos looks at them after the policies of the pair of zones, so only rules at
        the end of the model can be global; of the places that leaves, the one that needs the fewest policies, and of
        those the latest."""
        if self._tail_found is not None:
            return self._tail_found
        rules = self.p.rules
        in_pairs = [len(self._pairs(rule)) for rule in rules]
        in_global = [1 if rule.scope == RuleScope.UNIVERSAL else max(1, len(self._pairs(rule))) for rule in rules]
        best, cost = len(rules), sum(in_pairs)
        running = cost
        for start in range(len(rules) - 1, -1, -1):
            running += in_global[start] - in_pairs[start]
            if running < cost:
                best, cost = start, running
        self._tail_found = best
        return best

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "JUNOS_LOAD",
            "the output is set commands for 'load set' (section 10): 'configure private', 'load set terminal' or "
            "'load set FILE', then 'show | compare', 'commit check' and 'commit confirmed'. New policies go to the end of "
            "their pair of zones, after the policies the firewall has there, and the global policies after those: move "
            "them with 'insert ... before' where the firewall's own should not come first. Objects go into the global "
            "address book, which a firewall with address books in its zones does not accept. Assumed: names of up to 63 "
            "characters, 'match from-zone' and 'match to-zone' in global policies, and the definitions of the predefined "
            "applications the policies use",
        )  # fmt: skip
        zones = sorted(self.used_zones)
        if zones and not self.native:
            self.report.note(Severity.REVIEW, "ZONES_REQUIRED",
                             "the policies and NAT rules name these security zones, which must exist on the SRX (or be "
                             "renamed with --zone-map): " + ", ".join(zones))  # fmt: skip
        if self.p.default_interzone == Action.ALLOW and self.p.default_intrazone == Action.ALLOW:
            transform.note_closed_zones(self.p, self.options.zone_map, self.report)  # (permit-all: inside those zones too)
            self.report.note(Severity.REVIEW, "DEFAULT_PERMIT",
                             "the source allows what no rule matches: written as 'default-policy permit-all', which applies to "
                             "the whole SRX")  # fmt: skip
        elif self.p.default_interzone == Action.ALLOW or self.p.default_intrazone == Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTERZONE_DEFAULT",
                             "the source allows what no rule matches between zones or inside one, and not both; the default "
                             "policy of an SRX is one for both, and denies. Add policies if that was intended")  # fmt: skip

    # -- addresses --------------------------------------------------------------------------------

    def _address_line(self, name: str, value: str) -> None:
        self.objects.append(f"set security address-book global address {name} {value}")

    def _value(self, interval: Interval) -> str:
        version, first, last = interval
        nets = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
        if len(nets) == 1:
            return str(nets[0])
        return f"range-address {int_to_ip(version, first)} to {int_to_ip(version, last)}"

    def _addresses(self) -> None:
        for address in self.p.addresses.values():
            name = address.name
            if address.kind == AddressKind.UNSUPPORTED or name in self.taint_a:
                reason = self.taint_a.get(name) or address.raw or "address that could not be converted"
                self._address_line(name, _PLACEHOLDER)
                self.objects.append(f"set security address-book global address {name} description "
                                    + _q(f"FWSHIFT PLACEHOLDER, matches nothing: {reason}"[:200]))  # fmt: skip
                self.taint_a.setdefault(name, reason)
            elif address.kind == AddressKind.FQDN:
                family = {4: " ipv4-only", 6: " ipv6-only"}.get(address.fqdn_family, "")
                self._address_line(name, f"dns-name {address.value}{family}")
            else:
                interval = parse_literal(address.value)
                if interval is None:
                    self.taint_a[name] = "address that could not be read"
                    self._address_line(name, _PLACEHOLDER)
                    continue
                self._address_line(name, self._value(interval))
            if address.description:
                self.objects.append(f"set security address-book global address {name} description {_q(address.description[:200])}")
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a)), **self.taint_a}
        for group in self._groups_in_order():
            if group.name in self.taint_a or not group.members:
                reason = self.taint_a.get(group.name) or "a group without members"
                placeholder = self._name(f"{group.name}.placeholder")
                self._address_line(placeholder, _PLACEHOLDER)
                self.objects.append(f"set security address-book global address-set {group.name} address {placeholder}")
                self.objects.append(f"set security address-book global address-set {group.name} description "
                                    + _q(f"FWSHIFT PLACEHOLDER, matches nothing: {reason}"[:200]))  # fmt: skip
                self.taint_a.setdefault(group.name, reason)
                continue
            for member in group.members:
                if member in self.p.address_groups:
                    self.objects.append(f"set security address-book global address-set {group.name} address-set {member}")
                else:
                    self.objects.append(f"set security address-book global address-set {group.name} address {self._leaf(member)}")
            if group.description:
                self.objects.append(f"set security address-book global address-set {group.name} description {_q(group.description[:200])}")

    def _groups_in_order(self) -> List[AddressGroup]:
        """Address sets after the sets they hold."""
        done: List[str] = []
        seen: Set[str] = set()

        def visit(name: str, path: Set[str]) -> None:
            if name in seen or name in path:
                return
            for member in self.p.address_groups[name].members:
                if member in self.p.address_groups:
                    visit(member, path | {name})
            seen.add(name)
            done.append(name)

        for name in self.p.address_groups:
            visit(name, set())
        return [self.p.address_groups[name] for name in done]

    def _leaf(self, member: str) -> str:
        """The name of an address object for a member: the object itself, or one for a literal."""
        if member in self.p.addresses:
            return member
        if member in self.literals:
            return self.literals[member]
        interval = parse_literal(member)
        assert interval is not None, member
        name = self._name(f"{self.options.object_prefix}{interval_text(interval).replace('/', '_')}")
        self._address_line(name, self._value(interval))
        self.literals[member] = name
        return name

    # -- services ---------------------------------------------------------------------------------

    def _terms(self, entries: List[ServiceEntry]) -> Tuple[List[List[str]], str]:
        """The statements of an application, one list per term."""
        out: List[List[str]] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                for dst in (entry.dst_ports.split(",") if entry.dst_ports else ["0-65535"]):
                    for src in (entry.src_ports.split(",") if entry.src_ports else [""]):
                        term = [f"protocol {entry.protocol.value}", f"destination-port {dst}"]
                        if src:
                            term.append(f"source-port {src}")
                        out.append(term)
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                word = "icmp" if entry.protocol == Protocol.ICMP else "icmp6"
                term = [f"protocol {word}"]
                if entry.icmp_type is not None:
                    term.append(f"{word}-type {entry.icmp_type}")
                    if entry.icmp_code is not None:
                        term.append(f"{word}-code {entry.icmp_code}")
                elif entry.icmp_code is not None:
                    return [], "an ICMP code without a type"
                out.append(term)
            elif entry.protocol == Protocol.SCTP:
                if entry.dst_ports or entry.src_ports:
                    return [], "SCTP ports"
                out.append(["protocol 132"])
            else:
                if entry.ip_protocol is None:
                    return [], "every protocol, which is the application any"
                if entry.ip_protocol == 0:
                    return [], "IP protocol 0"
                out.append([f"protocol {entry.ip_protocol}"])
        unique: List[List[str]] = []
        for term in out:
            if term not in unique:
                unique.append(term)
        return unique, ""

    def _application(self, name: str, terms: List[List[str]]) -> None:
        if len(terms) == 1:
            for statement in terms[0]:
                self.applications.append(f"set applications application {name} {statement}")
            return
        for number, term in enumerate(terms, start=1):
            for statement in term:
                self.applications.append(f"set applications application {name} term t{number} {statement}")

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for service in self.p.services.values():
            if service.name in self.keep and self.native:
                self.svc_written.add(service.name)  # predefined on the SRX as on the source
                continue
            if service.unsupported or not service.entries:
                bad[service.name] = service.unsupported or "a service without content"
                continue
            if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in service.entries):
                self.any_services.add(service.name)
                continue
            terms, problem = self._terms(service.entries)
            if problem:
                bad[service.name] = problem
                self.report.add("service", service.name, Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: not written, and the policies that use it are deactivated")  # fmt: skip
                continue
            self._application(service.name, terms)
            self.svc_written.add(service.name)
        for group in self.p.service_groups.values():
            if group.name in self.keep and self.native:
                self.svc_written.add(group.name)
                continue
            if any(member in self.any_services for member in group.members):
                self.any_services.add(group.name)
                continue
            if any(member in bad for member in group.members) or not group.members:
                bad[group.name] = "it holds a service that is not written" if group.members else "a group without members"
                continue
            missing = [m for m in group.members if m not in self.p.services and m not in self.p.service_groups]
            if missing:
                bad[group.name] = f"it holds '{missing[0]}', which is not defined"
                continue
            for member in group.members:
                kind = "application-set" if member in self.p.service_groups else "application"
                self.applications.append(f"set applications application-set {group.name} {kind} {member}")
            self.svc_written.add(group.name)
        self.taint_s = transform.tainted_services(self.p, bad, keep=self.keep if self.native else set())

    def _rule_services(self, rule: Rule, reasons: List[transform.Reason]) -> List[str]:
        if any(s in self.taint_s for s in rule.services):
            return ["any"]  # deactivated, for the reason the service gives
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is None:
            if ANY in rule.services or any(s in self.any_services for s in rule.services):
                return ["any"]
            if all(s in self.svc_written for s in rule.services):
                return list(rule.services)
            entries = [e for s in rule.services for e in (transform.flatten_services(self.p, s) or [])]
        else:
            entries = [e for _, found in lowered for e in found]
        if not entries or any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return ["any"]
        terms, problem = self._terms(entries)
        if problem:
            reasons.append(("UNCONVERTIBLE_OBJECT", f"the services of the rule hold {problem}"))
            return ["any"]
        name = self._name(f"{self.options.object_prefix}{rule.name}-app")
        self._application(name, terms)
        return [name]

    # -- policies ---------------------------------------------------------------------------------

    def _side(self, rule: Rule, members: List[str], negated: bool, side: str,
              reasons: List[transform.Reason]) -> Optional[Tuple[List[str], bool]]:  # fmt: skip
        """(address names, whether the side is written negated); None when a negation leaves nothing."""
        if not negated:
            names: List[str] = []
            for member in members:
                if member == ANY:
                    return ["any"], False
                names.append("any-ipv4" if member == ANY_V4 else "any-ipv6" if member == ANY_V6
                             else member if member in self.p.address_groups else self._leaf(member))  # fmt: skip
            return list(dict.fromkeys(names)), False
        intervals: List[Interval] = []
        static = True
        for member in members:
            found = transform.address_intervals(self.p, member) if member not in self.taint_a else None
            if found is None:
                static = False
                if member not in self.taint_a:
                    reasons.append(("NEGATION_NOT_STATIC", f"the {side} is negated and holds a host name: what it leaves "
                                    "cannot be written as addresses"))  # fmt: skip
                continue
            intervals += found
        if static and ANY not in members and len(members) <= _MAX_EXCLUDED and all(i[0] == 4 for i in intervals) and intervals:
            return [member if member in self.p.address_groups else self._leaf(member) for member in members], True
        left = subtract([FULL_V4, FULL_V6], intervals)
        if not left:
            return None
        self.report.add("rule", rule.origin, Severity.INFO, "NEGATION_EXPANDED",
                        f"a negated {side} that Junos cannot negate (IPv6, a host name, more than {_MAX_EXCLUDED} addresses) is "
                        "written as the addresses that are left")  # fmt: skip
        if left == [FULL_V4, FULL_V6]:
            return ["any"], False
        return [self._leaf(interval_text(i)) for i in normalize(left)], False

    def _pairs(self, rule: Rule) -> List[Tuple[str, str]]:
        sources = self.universe if ANY in rule.src_zones else rule.src_zones
        destinations = self.universe if ANY in rule.dst_zones else rule.dst_zones
        pairs = [(a, b) for a in sources for b in destinations]
        if rule.scope == RuleScope.INTRAZONE:
            pairs = [(a, a) for a in sources]
        elif rule.scope == RuleScope.INTERZONE:
            pairs = [(a, b) for a, b in pairs if a != b]
        return pairs

    def _rule(self, rule: Rule, global_policy: bool) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated application cannot be written: Junos has no negation of applications"))
        applications = self._rule_services(rule, reasons)
        sources = self._side(rule, rule.sources, rule.negate_source, "source", reasons)
        destinations = self._side(rule, rule.destinations, rule.negate_destination, "destination", reasons)
        if sources is None or destinations is None:
            self.report.skip("rule", rule.origin, "NO_COMMON_FAMILY", "a negation leaves no address: the rule matches nothing", Severity.INFO)
            return
        if not self.universe:
            contexts = ["global"]
        elif global_policy:
            if rule.scope == RuleScope.UNIVERSAL:
                contexts = ["global"]
                self.used_zones.update(z for z in rule.src_zones + rule.dst_zones if z != ANY)
            else:
                contexts = [f"global {a} {b}" for a, b in self._pairs(rule)]
                for a, b in self._pairs(rule):
                    self.used_zones.update((a, b))
                if not contexts:
                    self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY", "the zones of the rule leave no pair of zones: it "
                                     "matches nothing", Severity.INFO)  # fmt: skip
                    return
        else:
            pairs = self._pairs(rule)
            if not pairs:
                self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY", "the zones of the rule leave no pair of zones: it matches "
                                 "nothing", Severity.INFO)  # fmt: skip
                return
            contexts = [f"from-zone {a} to-zone {b}" for a, b in pairs]
            for a, b in pairs:
                self.used_zones.update((a, b))
            if ANY in rule.src_zones or ANY in rule.dst_zones:
                self.report.add("rule", rule.origin, Severity.INFO, "ZONES_EXPANDED",
                                "a rule for every zone is written for each pair of the zones the policy knows ("
                                + ", ".join(self.universe) + "); traffic of other zones of the SRX is not matched by it")  # fmt: skip
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION", f"action {rule.action.value} becomes reject, "
                            "which answers the client only")  # fmt: skip
        reasons = list(dict.fromkeys(reasons))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        if len(contexts) > 1:
            self.report.add("rule", rule.origin, Severity.INFO, "RULE_SPLIT", f"written as {len(contexts)} policies, one per pair of zones")
        action = "permit" if rule.action == Action.ALLOW else "deny" if rule.action in (Action.DROP, Action.DENY) else "reject"
        description = " ".join(rule.description.split())
        if reasons:
            description = f"FWSHIFT inactive, see the report. {description}".strip()
        for number, context in enumerate(contexts, start=1):
            label = rule.name if len(contexts) == 1 else f"{rule.name}-{number}"
            name = self._name(label, JUNOS_RULE, self.policy_names)
            where = f"set security policies {'global' if context.startswith('global') else context} policy {name}"
            lines = []
            if context == "global":
                lines += [f"{where} match from-zone {z}" for z in rule.src_zones if z != ANY]
                lines += [f"{where} match to-zone {z}" for z in rule.dst_zones if z != ANY]
            elif context.startswith("global "):
                _, a, b = context.split(" ")
                lines += [f"{where} match from-zone {a}", f"{where} match to-zone {b}"]
            if description:
                lines.append(f"{where} description {_q(description[:200])}")
            lines += [f"{where} match source-address {n}" for n in sources[0]]
            lines += [f"{where} match destination-address {n}" for n in destinations[0]]
            lines += [f"{where} match application {n}" for n in applications]
            if sources[1]:
                lines.append(f"{where} match source-address-excluded")
            if destinations[1]:
                lines.append(f"{where} match destination-address-excluded")
            lines.append(f"{where} then {action}")
            if rule.log_start:
                lines.append(f"{where} then log session-init")
            if rule.log_end:
                lines.append(f"{where} then log session-close")
            if not rule.enabled or reasons:
                lines.append("deactivate " + where[len("set "):])
            self.policies += lines
            item.emitted_as.append(name)

    # -- NAT --------------------------------------------------------------------------------------

    def _prefixes(self, members: List[str]) -> Optional[List[str]]:
        """The prefixes a NAT rule can match for a list of members; None when they are not static addresses."""
        if ANY in members:
            return []
        out: List[str] = []
        for member in members:
            if member in (ANY_V4, ANY_V6):
                out.append("0.0.0.0/0" if member == ANY_V4 else "::/0")
                continue
            found = transform.address_intervals(self.p, member) if member not in self.taint_a else None
            if found is None:
                return None
            for version, first, last in normalize(found):
                out += [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
        return out

    def _nat_service(self, nat: NatRule) -> Tuple[Optional[List[str]], str]:
        """The protocol and port statements of a NAT rule's service; None with the reason when it has none."""
        if nat.service == ANY:
            return [], ""
        entries = transform.flatten_services(self.p, nat.service) if nat.service not in self.taint_s else None
        if not entries:
            return None, "its service cannot be written"
        ports = {e.dst_ports for e in entries}
        if len(ports) != 1 or any(e.src_ports for e in entries) or any(e.protocol not in (Protocol.TCP, Protocol.UDP) for e in entries):
            return None, "a NAT rule of Junos matches one port range of TCP or UDP"
        port = ports.pop()
        if "," in port:
            return None, "a NAT rule of Junos matches one port range"
        out = [f"match protocol {e.protocol.value}" for e in entries]
        if port:
            low, _, high = port.partition("-")
            out.append(f"match destination-port {low}" + (f" to {high}" if high else ""))
        return list(dict.fromkeys(out)), ""

    def _zones(self, zones: List[str]) -> List[str]:
        return list(self.universe) if ANY in zones else list(zones)

    def _static_pairs(self) -> Dict[str, str]:
        """Destination NAT rules and the static source NAT that undoes them for the other way: together, a static NAT of
        Junos (origin -> origin, both ways)."""
        out: Dict[str, str] = {}
        outbound: Dict[Tuple[Interval, Interval], NatRule] = {}
        for nat in self.p.nat_rules:
            snat = nat.source_translation
            if (snat is None or snat.kind != SnatKind.STATIC or snat.bidirectional or nat.destination_translation is not None
                    or nat.src_zones != [ANY] or nat.dst_zones != [ANY] or nat.destinations != [ANY] or nat.service != ANY
                    or len(nat.sources) != 1 or len(snat.addresses) != 1 or nat.unsupported):  # fmt: skip
                continue
            inside, outside = transform.address_intervals(self.p, nat.sources[0]), transform.address_intervals(self.p, snat.addresses[0])
            if inside and outside and len(inside) == 1 and len(outside) == 1:
                outbound[(inside[0], outside[0])] = nat
        for nat in self.p.nat_rules:
            dnat = nat.destination_translation
            if dnat is None or nat.source_translation is not None or dnat.port or dnat.spread or nat.service != ANY:
                continue
            if nat.sources != [ANY] or len(nat.destinations) != 1 or nat.unsupported:
                continue
            outside, inside = transform.address_intervals(self.p, nat.destinations[0]), transform.address_intervals(self.p, dnat.address)
            if not inside or not outside or len(inside) != 1 or len(outside) != 1:
                continue
            partner = outbound.get((inside[0], outside[0]))
            # Junos applies static NAT before destination NAT: an earlier destination NAT for this traffic would lose.
            earlier = self.p.nat_rules[: self.p.nat_rules.index(nat)]
            shadows = any(other.enabled and other.destination_translation is not None
                          and transform._zones_meet(other.src_zones, nat.src_zones)
                          and transform._addresses_meet(self.p, other.destinations, nat.destinations) for other in earlier)  # fmt: skip
            if partner is not None and not shadows and partner.enabled == nat.enabled and len(self._nets(inside[0])) == 1 and len(self._nets(outside[0])) == 1:
                out[nat.origin] = partner.origin
                out[partner.origin] = nat.origin
                del outbound[(inside[0], outside[0])]
        return out

    def nat_plan(self, nat: NatRule) -> Tuple[Optional[str], List[_NatLine], List[Tuple[Severity, str, str]]]:
        """(why it cannot be written, its lines per rule set, findings)."""
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in nat.sources + nat.destinations if m in self.taint_a]
        findings: List[Tuple[Severity, str, str]] = []
        sources = self._prefixes(nat.sources)
        destinations = self._prefixes(nat.destinations)
        if sources is None or destinations is None:
            problems.append("the addresses it matches are not static addresses")
        service, why = self._nat_service(nat)
        if service is None:
            problems.append(why)
        if not self.universe:
            problems.append("the policy names no zones, and a NAT rule set of Junos names the zone its traffic comes from")
        if problems:
            return "; ".join(transform.dedupe(problems)), [], findings
        assert sources is not None and destinations is not None and service is not None
        match = [f"match source-address {s}" for s in sources] + [f"match destination-address {d}" for d in destinations] + service
        out: List[_NatLine] = []
        dnat, snat = nat.destination_translation, nat.source_translation
        if nat.origin in self.static_pairs:
            partner = self.static_pairs[nat.origin]
            if dnat is None:
                findings.append((Severity.INFO, "NAT_STATIC", f"written with '{partner}' as one static NAT rule of Junos"))
                return None, out, findings
            outside = (transform.address_intervals(self.p, nat.destinations[0]) or [])[0]
            inside = (transform.address_intervals(self.p, dnat.address) or [])[0]
            for zone in self._zones(nat.src_zones):
                out.append(_NatLine("static", (zone,), nat, [f"match destination-address {self._nets(outside)[0]}",
                                                             f"then static-nat prefix {self._nets(inside)[0]}"]))  # fmt: skip
            findings.append((Severity.INFO, "NAT_STATIC", f"written with '{partner}' as one static NAT rule of Junos, which "
                             "translates both ways"))  # fmt: skip
            return None, out, findings
        if dnat is not None:
            post = transform.address_intervals(self.p, dnat.address)
            if not post or len(post) != 1:
                return "the translated destination is not one address or range", [], findings
            if len(destinations) != 1 or "/" not in destinations[0]:
                return "a destination NAT rule of Junos matches one destination prefix", [], findings
            if size(post[0]) > 1 and not dnat.spread:
                return "a translation address for address of several addresses (static NAT is bi-directional on Junos)", [], findings
            pool = self._pool(nat, "destination", [self._range(post[0])], dnat.port)
            for zone in self._zones(nat.src_zones):
                out.append(_NatLine("destination", (zone,), nat, match + [f"then destination-nat pool {pool}"]))
        if snat is not None:
            post_match = list(match)
            if dnat is not None:
                post_interval = transform.address_intervals(self.p, dnat.address) or []
                post_match = [line for line in match if not line.startswith("match destination-address")]
                post_match += [f"match destination-address {n}" for i in post_interval for n in self._nets(i)]
                if dnat.port:
                    post_match = [line for line in post_match if not line.startswith("match destination-port")]
                    low, _, high = dnat.port.partition("-")
                    post_match.append(f"match destination-port {low}" + (f" to {high}" if high else ""))
                findings.append((Severity.APPROX, "NAT_AFTER_DNAT", "the source translation of this rule is matched after its "
                                 "destination translation, by the translated destination; it also applies to traffic sent "
                                 "to that address directly"))  # fmt: skip
            if snat.kind == SnatKind.STATIC and snat.bidirectional:
                pair = transform.bidirectional_pair(self.p, nat)
                if pair is None:
                    return "a bi-directional static NAT that is not one address or network for another of the same size", [], findings
                inside, outside = pair
                if not self._nets(inside)[0:1] or len(self._nets(inside)) != 1 or len(self._nets(outside)) != 1:
                    return "static NAT of Junos maps one prefix to another", [], findings
                for zone in self._zones(nat.dst_zones):
                    out.append(_NatLine("static", (zone,), nat, [f"match destination-address {self._nets(outside)[0]}",
                                                                 f"then static-nat prefix {self._nets(inside)[0]}"]))  # fmt: skip
                findings.append((Severity.APPROX, "NAT_BIDIRECTIONAL", "written as static NAT, which translates both ways; "
                                 "the outbound way applies to traffic to every zone"))  # fmt: skip
                return None, out, findings
            if snat.kind == SnatKind.INTERFACE:
                then = "then source-nat interface"
            else:
                pool_addresses: List[str] = []
                for address in snat.addresses:
                    found = transform.address_intervals(self.p, address)
                    if not found:
                        return f"translated address '{address}' is not a static address", [], findings
                    pool_addresses += [self._range(i) for i in normalize(found)]
                if snat.kind == SnatKind.STATIC:
                    hosts = [i for s in nat.sources for i in (transform.address_intervals(self.p, s) or [])]
                    if len(hosts) != 1 or size(hosts[0]) != 1 or len(pool_addresses) != 1 or "to" in pool_addresses[0]:
                        return "static source NAT of several addresses (a source pool of Junos picks an address per connection)", [], findings
                if not pool_addresses:
                    return "source NAT without a translated address", [], findings
                pool = self._pool(nat, "source", pool_addresses, "", no_translation=snat.kind in (SnatKind.DYNAMIC, SnatKind.STATIC))
                then = f"then source-nat pool {pool}"
            for a in self._zones(nat.src_zones):
                for b in self._zones(nat.dst_zones):
                    out.append(_NatLine("source", (a, b), nat, post_match + [then]))
        if dnat is None and snat is None:
            for a in self._zones(nat.src_zones):
                for b in self._zones(nat.dst_zones):
                    out.append(_NatLine("source", (a, b), nat, match + ["then source-nat off"]))
            findings.append((Severity.INFO, "NAT_EXEMPTION", "a rule without translation, written as 'source-nat off'"))
        return None, out, findings

    @staticmethod
    def _nets(interval: Interval) -> List[str]:
        version, first, last = interval
        return [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]

    def _range(self, interval: Interval) -> str:
        nets = self._nets(interval)
        if len(nets) == 1:
            return nets[0]
        version, first, last = interval
        return f"{int_to_ip(version, first)}/{32 if version == 4 else 128} to {int_to_ip(version, last)}/{32 if version == 4 else 128}"

    def _pool(self, nat: NatRule, kind: str, addresses: List[str], port: str, no_translation: bool = False) -> str:
        key = f"{kind} {addresses} {port} {no_translation}"
        if key in self.pools:
            return self.pools[key]
        name = self._name(f"{self.options.object_prefix}{nat.name}-pool", JUNOS_RULE, self.pool_names)
        self.pools[key] = name
        for address in addresses:
            self.pool_lines.append(f"set security nat {kind} pool {name} address {address}" + (f" port {port}" if port else ""))
        if no_translation:
            self.pool_lines.append(f"set security nat {kind} pool {name} port no-translation")
        return name

    def _nat(self) -> None:
        planned: List[_NatLine] = []
        for nat in self.p.nat_rules:
            problem, lines, findings = self.nat_plan(nat)
            if problem is not None:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", f"not converted: {problem}")
                continue
            for severity, code, message in findings:
                self.report.add("nat", nat.origin, severity, code, message)
            planned += lines
        written = {line.nat.origin for line in planned}
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        sets: Dict[Tuple[str, Tuple[str, ...]], str] = {}
        rule_names: Dict[Tuple[str, Tuple[str, ...]], Set[str]] = {}
        out: List[str] = []
        for line in planned:
            key = (line.kind, line.context)
            if key not in sets:
                label = f"fwshift-{line.kind}-" + "-".join(line.context)
                sets[key] = self._name(label, JUNOS_RULE, self.set_names)
                base = f"set security nat {line.kind} rule-set {sets[key]}"
                out.append(f"{base} from zone {line.context[0]}")
                if line.kind == "source":
                    out.append(f"{base} to zone {line.context[1]}")
                self.used_zones.update(line.context)
            rule_name = self._name(line.nat.name, JUNOS_RULE, rule_names.setdefault(key, set()))
            base = f"set security nat {line.kind} rule-set {sets[key]} rule {rule_name}"
            out += [f"{base} {statement}" for statement in line.lines]
            if not line.nat.enabled:
                out.append("deactivate " + base[len("set "):])
            item = self.report.item("nat", line.nat.origin)
            item.emitted_as.append(f"{line.kind} {sets[key]} {rule_name}")
        self.nat_lines = self.pool_lines + out
