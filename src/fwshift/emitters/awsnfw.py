# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS Network Firewall emitter: neutral model -> a shell script of AWS CLI calls that creates a stateful rule group and a
firewall policy.

Design rules:

* One new firewall policy, attached to no firewall: creating it changes no traffic. Its stateless default actions send
  every packet (and every fragment) to the stateful engine; it has no stateless rules.
* One stateful rule group of Suricata rules (more when one would be too large), in ``STRICT_ORDER``: the rules of the
  model in their order, each for the first packet of a connection (``flow:to_server``). A pass on that packet passes
  the flow, its replies too, and a drop drops it, which is the model's connection. What no rule matches is the model's
  default: ``aws:drop_strict``, or no default action, which passes it.
* A rule names one protocol: a rule of the model becomes a rule per protocol (and set of source ports) it holds. Objects
  become IP set variables of the rule group (``$NAME``), negation ``!``; zones become the networks behind them
  (``--zone-network``), as for NSX and Google Cloud. Applications become their ports: the application protocols of
  Suricata are identified only once data flows, after the first packet has decided.
* A rule that cannot be written is not written; the script lists it, and the report says why. The script never changes
  or deletes what exists: it stops when a rule group or policy of the same name exists.
* NAT is not written (Network Firewall does none: the internet gateway and NAT gateways translate): the rules are for
  the private addresses, which is what the firewall sees.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, List, Optional, Set, Tuple

from .. import names, regions, transform
from ..model import ANY, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_RULES_LIMIT = 1_500_000  # characters of a rules string (AWS takes 2,000,000), kept clear of the limit
_GROUP_RULES = 10_000  # rules of one rule group
_INLINE = 12  # address blocks written in a rule; more become a variable (one per list, whatever rules use it)
_RESERVED = {"home_net", "external_net"}  # Suricata variables of Network Firewall itself
_EVERYTHING = [FULL_V4, FULL_V6]
_TEXT = re.compile(r"[^A-Za-z0-9 ._:/,=+@#-]")


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)  # refuses networks that contradict each other
    # The internet gateway translates public addresses before the firewall sees a connection, a NAT gateway translates
    # sources after it: the firewall sees the private addresses. The NAT rules are not written.
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    plan = _Planner(p, report, options, source_zones).run()
    return _script(plan, options, report)


def policy_name(options: Options) -> str:
    base = options.target_policy if options.target_policy and options.target_policy != "FWShift" else "fwshift"
    name = re.sub(r"[^A-Za-z0-9-]+", "-", (options.object_prefix or "") + base).strip("-")
    return name[:100].rstrip("-") or "fwshift"


@dataclass
class _Line:
    text: str
    variables: List[str]  # the IP set variables it names
    ports: List[str]  # the port variables it names


@dataclass
class Plan:
    lines: List[_Line] = field(default_factory=list)
    ip_sets: Dict[str, List[str]] = field(default_factory=dict)  # variable -> CIDR blocks
    not_written: List[str] = field(default_factory=list)
    default_drop: bool = True


@dataclass
class _Spec:
    """One protocol of a rule, as a Suricata rule says it."""

    protocol: str  # tcp, udp, icmp, ip
    sports: str  # Suricata port expression
    dports: str
    options: str  # ip_proto, itype, icode


class _Planner:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options, self.source_zones = p, report, options, source_zones
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))
        self.out = Plan(default_drop=p.default_interzone != Action.ALLOW)
        self.variable_of: Dict[str, str] = {}  # model object -> variable
        self.taken: Set[str] = set(_RESERVED)
        self.sid = 0

    # -- variables ------------------------------------------------------------------

    def _variable(self, label: str, intervals: List[Interval], key: str = "") -> str:
        if key and key in self.variable_of:
            return self.variable_of[key]
        base = names.clean(label, names.AWSNFW_VARIABLE)
        if base.lower() in _RESERVED:
            base = "FWS_" + base
        candidate, counter = base, 2
        while candidate.lower() in self.taken:
            suffix = f"_{counter}"
            candidate = base[: names.AWSNFW_VARIABLE.max_len - len(suffix)] + suffix
            counter += 1
        self.taken.add(candidate.lower())
        self.out.ip_sets[candidate] = _cidrs(intervals)
        if key:
            self.variable_of[key] = candidate
        return candidate

    # -- sides -----------------------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found = list(_EVERYTHING)
                break
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: a rule of Network Firewall names addresses (a domain "
                                "list matches TLS and HTTP names, which is something else)"))  # fmt: skip
                return None
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; a rule of Network "
                                    "Firewall names addresses"))  # fmt: skip
                return None
            found += intervals
        found = normalize(found)
        return subtract(_EVERYTHING, found) if negated else found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: List[Interval], reasons: List[transform.Reason]) -> List[Interval]:
        allow = rule.action == Action.ALLOW
        missing = [zone for zone in zones if zone not in self.spaces]
        if allow:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and a rule of Network Firewall names no zone: "
                                f"give the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
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
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a rule of Network Firewall names no "
                            "zone, and it blocks that traffic in every zone. Give the networks behind every zone with --zone-network "
                            "to keep it to its zones")  # fmt: skip
            return found
        kept = subtract(found, normalize([i for zone in others for i in self.spaces[zone]]))
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
        return kept

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Tuple[str, List[str]]]:
        """The Suricata expression of one side and the variables it names; None when it holds no address."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        zones = rule.src_zones if source or rule.scope == RuleScope.INTRAZONE else rule.dst_zones
        side = "source" if source else "destination"
        if ANY in zones or (not source and rule.egress_implied and rule.scope != RuleScope.INTRAZONE):
            if ANY in members:
                return ("any", []) if not negated else None
            whole = self._resolve(members, False, side, reasons)
            if whole is None:
                return "any", []
            if negated and whole == _EVERYTHING:
                return None
            if not negated and whole == _EVERYTHING:
                return "any", []
            parts: List[str] = []
            variables: List[str] = []
            literals: List[Interval] = []
            for member in members:
                if member in self.p.addresses or member in self.p.address_groups:
                    intervals, _ = transform.known_intervals(self.p, member)
                    if not intervals:
                        continue  # (an object with no address: it adds nothing)
                    name = self._variable(member, normalize(intervals), key=member)
                    parts.append("$" + name)
                    variables.append(name)
                else:
                    interval = parse_literal(member)
                    if interval is None:
                        reasons.append(("ADDRESS_NOT_WRITTEN", f"'{member}' cannot be written"))
                        return "any", []
                    literals.append(interval)
            blocks = _cidrs(literals)
            if len(blocks) > _INLINE:
                name = self._variable(f"{rule.name}_{'SRC' if source else 'DST'}", normalize(literals), key="\x00" + ",".join(blocks))
                parts.append("$" + name)
                variables.append(name)
            else:
                parts += blocks
            if not parts:
                return ("any", []) if negated else None
            text = parts[0] if len(parts) == 1 else "[" + ",".join(parts) + "]"
            return ("!" + text if negated else text), variables
        found = self._resolve(members, negated, side, reasons)
        if found is None:
            return "any", []
        kept = normalize(self._confine(rule, side, zones, found, reasons))
        if kept == _EVERYTHING:
            return "any", []
        if not kept:
            return None
        blocks = _cidrs(kept)
        if len(blocks) > _INLINE:
            name = self._variable(f"{rule.name}_{'SRC' if source else 'DST'}", kept, key="\x00" + ",".join(blocks))
            return "$" + name, [name]
        return (blocks[0] if len(blocks) == 1 else "[" + ",".join(blocks) + "]"), []

    # -- services ----------------------------------------------------------------------

    def _specs(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[_Spec]]:
        allow = rule.action == Action.ALLOW
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        entries: List[ServiceEntry] = []
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.services == [ANY]:
            if rule.negate_service:
                return []
            return [_Spec("ip", "any", "any", "")]
        else:
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        if rule.negate_service:
            found = regions.service_set(entries)
            if found is None:
                reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
                return None
            return self._set_specs(rule, regions.ALL_SERVICES.minus(found), reasons)
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return [_Spec("ip", "any", "any", "")]
        specs: List[_Spec] = []
        ports: Dict[Tuple[str, str], List[Tuple[int, int]]] = {}
        sctp_widened = False
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                ranges = _ranges(entry.dst_ports)
                if ranges is None:
                    reasons.append(("SERVICE_UNKNOWN", f"ports '{entry.dst_ports}' cannot be read"))
                    return None
                ports.setdefault((entry.protocol.value, entry.src_ports), []).extend(ranges)
            elif entry.protocol == Protocol.SCTP:
                if entry.dst_ports or entry.src_ports:
                    if allow:
                        reasons.append(("SERVICE_SCTP", "SCTP ports: Network Firewall does not inspect SCTP, and can only name it as "
                                        "IP protocol 132"))  # fmt: skip
                        return None
                    sctp_widened = True
                specs.append(_Spec("ip", "any", "any", "ip_proto:132; "))
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                extra = f"ip_proto:{1 if entry.protocol == Protocol.ICMP else 58}; "
                if entry.icmp_type is not None:
                    extra += f"itype:{entry.icmp_type}; "
                    if entry.icmp_code is not None:
                        extra += f"icode:{entry.icmp_code}; "
                specs.append(_Spec("icmp", "any", "any", extra))
            else:
                specs.append(_Spec("ip", "any", "any", f"ip_proto:{entry.ip_protocol}; "))
        if sctp_widened:
            self.report.add("rule", rule.origin, Severity.APPROX, "SERVICE_SCTP",
                            "the rule blocks certain SCTP ports; Network Firewall names SCTP as IP protocol 132 only, so it blocks "
                            "every SCTP port, which is more")  # fmt: skip
        layer4: List[_Spec] = []
        for (protocol, src), ranges in ports.items():
            source_ranges = _ranges(src) if src else [(0, 65535)]
            if source_ranges is None:
                reasons.append(("SERVICE_UNKNOWN", f"source ports '{src}' cannot be read"))
                return None
            layer4.append(_Spec(protocol, _port_expression(source_ranges), _port_expression(_merge(ranges)), ""))
        out: List[_Spec] = []
        for spec in layer4 + specs:
            if spec not in out:
                out.append(spec)
        return out

    def _set_specs(self, rule: Rule, svc: regions.Services, reasons: List[transform.Reason]) -> Optional[List[_Spec]]:
        """Rules for a set of services (what a negated service leaves): per protocol, and every other protocol as ip with the
        listed ones excluded (ip_proto:!N)."""
        allow = rule.action == Action.ALLOW
        if svc.everything():
            return [_Spec("ip", "any", "any", "")]
        specs: List[_Spec] = []
        listed = sorted(svc.protocols)
        widened = False
        for number in listed:
            rects = svc.of(number)
            if not rects:
                continue
            if number in (6, 17):
                by_source: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
                for rect in rects:
                    by_source.setdefault((rect[0], rect[1]), []).append((rect[2], rect[3]))
                for (low, high), ports in sorted(by_source.items()):
                    specs.append(_Spec("tcp" if number == 6 else "udp", _port_expression([(low, high)]), _port_expression(ports), ""))
            elif number in (1, 58):
                whole_types: Set[int] = set()
                pairs: Set[Tuple[int, int]] = set()
                for rect in rects:
                    types, codes = regions.icmp_values(rect[0], rect[1]), regions.icmp_values(rect[2], rect[3])
                    if types is None or codes is None:
                        continue
                    listed_types = list(range(256)) if types == [None] else [t for t in types if t is not None]
                    if codes == [None]:
                        whole_types.update(listed_types)
                    else:
                        pairs.update((t, c) for t in listed_types for c in codes if c is not None)
                pairs = {(t, c) for t, c in pairs if t not in whole_types}
                if len(pairs) > 32:
                    if allow:
                        reasons.append(("AWSNFW_SERVICE_NOT_WRITTEN", "what the negated service leaves of ICMP is more types and codes than are "
                                        "written"))  # fmt: skip
                        return None
                    widened, whole_types, pairs = True, set(range(256)), set()
                for expression in _type_ranges(sorted(whole_types)):
                    specs.append(_Spec("icmp", "any", "any", f"ip_proto:{number}; " + (f"itype:{expression}; " if expression else "")))
                for kind, code in sorted(pairs):
                    specs.append(_Spec("icmp", "any", "any", f"ip_proto:{number}; itype:{kind}; icode:{code}; "))
            elif number == 132 and rects != [regions.WHOLE]:
                if allow:
                    reasons.append(("SERVICE_SCTP", "SCTP ports: Network Firewall does not inspect SCTP, and can only name it as IP "
                                    "protocol 132"))  # fmt: skip
                    return None
                widened = True
                specs.append(_Spec("ip", "any", "any", "ip_proto:132; "))
            else:
                specs.append(_Spec("ip", "any", "any", f"ip_proto:{number}; "))
        if svc.rest:
            specs.append(_Spec("ip", "any", "any", "".join(f"ip_proto:!{number}; " for number in listed)))
        if widened:
            self.report.add("rule", rule.origin, Severity.APPROX, "AWSNFW_BLOCKS_MORE",
                            "what the negated service leaves holds many ICMP types or SCTP ports; the rule blocks all of ICMP, or of "
                            "SCTP, there, which blocks more")  # fmt: skip
        self.report.add("rule", rule.origin, Severity.INFO, "AWSNFW_NEGATED_SERVICE",
                        "a negated service is written as what it leaves: a rule per protocol, and for the protocols it does not name "
                        "one with ip_proto:!N for each it does")  # fmt: skip
        return specs

    # -- rules ---------------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.out.not_written.append(f"{rule.name}: {'disabled by the audit' if by_audit else 'disabled in the source'}")
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a rule of Network Firewall names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written as a rule for every pair of its zones, which blocks more")  # fmt: skip
        specs = self._specs(rule, reasons)
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        reasons = list(dict.fromkeys(reasons))
        if reasons or specs is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.out.not_written.append(f"{rule.name}: " + "; ".join(message for _, message in reasons)[:300])
            return
        if sources is None or destinations is None or not specs:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation and the networks of its zones, the rule matches no connection", Severity.INFO)  # fmt: skip
            return
        action = {Action.ALLOW: "pass", Action.DROP: "drop", Action.DENY: "drop"}.get(rule.action, "reject")
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value}: reject sends a TCP reset to the client only")  # fmt: skip
        if action == "reject" and any(spec.protocol != "tcp" for spec in specs):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY",
                            "a reject of Network Firewall is for TCP; for the rule's other protocols it is written as drop, which "
                            "answers nothing")  # fmt: skip
        message = _message(rule.name)
        for spec in specs:
            self.sid += 1
            verb = action if action != "reject" or spec.protocol == "tcp" else "drop"
            text = (f"{verb} {spec.protocol} {sources[0]} {spec.sports} -> {destinations[0]} {spec.dports} "
                    f'(msg:"{message}"; flow:to_server; {spec.options}sid:{self.sid}; rev:1;)')  # fmt: skip
            self.out.lines.append(_Line(text, sources[1] + destinations[1], []))
        item.emitted_as.append(f"{len(specs)} rule{'s' if len(specs) != 1 else ''} of the rule group (sid "
                               + (f"{self.sid}" if len(specs) == 1 else f"{self.sid - len(specs) + 1}-{self.sid}") + ")")  # fmt: skip

    def _intrazone(self) -> None:
        """Traffic inside a zone that no rule matches, where the source decides it otherwise than between zones: rules for
        the networks of each such zone to themselves, after the rules of the model (as for Google Cloud)."""
        inter = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.universe, self.report)
        written: List[str] = []
        blocked: List[str] = []
        opened: List[str] = []
        for zone in self.universe:
            allow = decided[zone]
            if allow == inter:
                continue
            if zone not in self.spaces:
                (blocked if allow else opened).append(zone)
                continue
            blocks = _cidrs(normalize(self.spaces[zone]))
            if not blocks:
                continue
            if len(blocks) > _INLINE:
                name = self._variable(f"zone_{zone}", normalize(self.spaces[zone]), key="\x00" + ",".join(blocks))
                expression, variables = "$" + name, [name]
            else:
                expression, variables = (blocks[0] if len(blocks) == 1 else "[" + ",".join(blocks) + "]"), []
            self.sid += 1
            text = (f"{'pass' if allow else 'drop'} ip {expression} any -> {expression} any "
                    f'(msg:"{_message("fwshift-intrazone-" + zone)}"; flow:to_server; sid:{self.sid}; rev:1;)')  # fmt: skip
            self.out.lines.append(_Line(text, variables, []))
            written.append(zone)
        if written:
            self.report.note(Severity.INFO, "INTRAZONE_WRITTEN",
                             "the source decides traffic inside a zone that no rule matches otherwise than between zones; Network "
                             "Firewall has no zones, so that was written as rules for the networks of each zone to themselves "
                             "(--zone-network), after the rules of the policy: " + ", ".join(written))  # fmt: skip
        if blocked:
            self.report.note(Severity.REVIEW, "INTRAZONE_DEFAULT",
                             "the source allows traffic inside these zones that no rule matches, and blocks it between zones; Network "
                             "Firewall has no zones, and without their networks (--zone-network) the converted policy blocks it: "
                             + ", ".join(blocked))  # fmt: skip
        if opened:
            self.report.note(Severity.REVIEW, "INTRAZONE_DENY_NOT_WRITTEN",
                             "the source blocks traffic inside these zones that no rule matches, and allows it between zones; Network "
                             "Firewall has no zones, and without their networks (--zone-network) the converted policy ALLOWS it: give "
                             "their networks, or a rule that blocks it: " + ", ".join(opened))  # fmt: skip

    def run(self) -> Plan:
        for rule in self.p.rules:
            self._rule(rule)
        self._intrazone()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: Network Firewall does no NAT (the internet gateway and NAT gateways do, outside it). The "
                             "rules were written for the private addresses, which is what the firewall sees")  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; a pass rule of Network Firewall does not, a drop or reject rule sends an alert "
                             "when the firewall has alert logging configured")  # fmt: skip
        return self.out


def _type_ranges(types: List[int]) -> List[str]:
    """ICMP types as itype expressions: N, <N, >N and N<>M, whose comparisons are strict; "" for every type."""
    out: List[str] = []
    for low, high in _merge([(t, t) for t in types]):
        if (low, high) == (0, 255):
            out.append("")
        elif low == high:
            out.append(str(low))
        elif low == 0:
            out.append(f"<{high + 1}")
        elif high == 255:
            out.append(f">{low - 1}")
        else:
            out.append(f"{low - 1}<>{high + 1}")
    return out


def _ranges(ports: str) -> Optional[List[Tuple[int, int]]]:
    if not ports:
        return [(0, 65535)]
    out: List[Tuple[int, int]] = []
    for part in ports.split(","):
        first, _, last = part.strip().partition("-")
        if not first.isdigit() or not (last or first).isdigit():
            return None
        low, high = int(first), int(last or first)
        if not 0 <= low <= high <= 65535:
            return None
        out.append((low, high))
    return out


def _merge(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for low, high in sorted(ranges):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return out


def _port_expression(ranges: List[Tuple[int, int]]) -> str:
    ranges = _merge(ranges)
    if ranges == [(0, 65535)]:
        return "any"
    parts = [str(low) if low == high else f"{low}:{high}" for low, high in ranges]
    return parts[0] if len(parts) == 1 else "[" + ",".join(parts) + "]"


def _cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in normalize(intervals):
        out += [str(n) for n in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
    return out


def _message(text: str) -> str:
    return _TEXT.sub("_", text)[:200] or "fwshift"


def _groups(plan: Plan) -> List[Tuple[List[_Line], Dict[str, List[str]]]]:
    """The rules in groups that stay below the size of a rules string and the number of rules a group may hold."""
    out: List[Tuple[List[_Line], Dict[str, List[str]]]] = []
    current: List[_Line] = []
    size = 0
    for line in plan.lines:
        if current and (size + len(line.text) + 1 > _RULES_LIMIT or len(current) >= _GROUP_RULES):
            out.append((current, {}))
            current, size = [], 0
        current.append(line)
        size += len(line.text) + 1
    if current or not out:
        out.append((current, {}))
    for lines, sets in out:
        for line in lines:
            for name in line.variables:
                sets[name] = plan.ip_sets[name]
    return out


def _script(plan: Plan, options: Options, report: Report) -> str:
    name = policy_name(options)
    groups = _groups(plan)
    group_names = [f"{name}-rules" + (f"-{index}" if index > 1 else "") for index in range(1, len(groups) + 1)]
    defaults = ["aws:drop_strict"] if plan.default_drop else []
    report.note(
        Severity.REVIEW, "AWSNFW_LOAD",
        "the output is a shell script of AWS CLI calls (section 10): DRY_RUN=1 prints them, CHECK=1 sends each with --dry-run, "
        f"without either it creates the stateful rule group{'s' if len(groups) != 1 else ''} {', '.join(group_names)} and the firewall "
        f"policy {name}, and stops if one of that name exists. The policy is attached to no firewall: nothing changes until you "
        "associate it (aws network-firewall associate-firewall-policy)",
    )  # fmt: skip
    report.note(
        Severity.REVIEW, "AWSNFW_ORDER",
        "the policy decides every packet the firewall sees, in strict order: no stateless rules (every packet goes to the "
        "stateful engine), the rules of the model in their order, each for the first packet of a connection (flow:to_server), "
        + ("then aws:drop_strict for what no rule passed" if plan.default_drop else "and no default action, so what no rule "
           "matches passes, as in the source") + ". Check it against what the firewall's route tables send through it",
    )  # fmt: skip
    if len(groups) > 1:
        report.note(Severity.INFO, "AWSNFW_SPLIT",
                    f"the rules did not fit in one rule group (2,000,000 characters, or {_GROUP_RULES} rules, as written here): they are in "
                    f"{len(groups)} groups, in order")  # fmt: skip
    if len(plan.lines) > 30000:
        report.note(Severity.REVIEW, "AWSNFW_CAPACITY",
                    f"{len(plan.lines)} rules: more than the 30,000 that the stateful rule groups of one policy may hold by default; AWS "
                    "refuses the policy unless the quota was raised")  # fmt: skip
    out = [
        "#!/bin/sh",
        "# Generated by FWShift: an AWS Network Firewall policy and its stateful rule group, created with the AWS CLI. Read the",
        "# report first: what is not written is listed there.",
        "#",
        "#   DRY_RUN=1 sh THIS_FILE    prints the calls, makes none (no AWS access needed)",
        "#   CHECK=1 sh THIS_FILE      sends every call with --dry-run: AWS checks the requests and the permissions",
        "#   sh THIS_FILE              creates the rule group and the policy",
        "#",
        "# AWS_OPTS adds options to every call, for example AWS_OPTS='--region eu-west-1 --profile prod'.",
        "#",
        "# The policy is attached to no firewall: nothing changes for any traffic until you associate it:",
        "#   aws network-firewall associate-firewall-policy --firewall-name FIREWALL --firewall-policy-arn ARN",
        "# A rule group or policy of the same name stops the script before anything is created; a call AWS refuses stops it",
        "# where it is (delete what it made with aws network-firewall delete-rule-group / delete-firewall-policy and run it",
        "# again).",
        "set -u",
        'DRY_RUN="${DRY_RUN:-}"',
        'CHECK="${CHECK:-}"',
        'AWS_OPTS="${AWS_OPTS:-}"',
        "fail() { printf 'FAILED: %s\\n' \"$*\" >&2; exit 1; }",
        "show() { printf 'aws network-firewall' >&2; printf ' %s' \"$@\" >&2; printf '\\n' >&2; }",
        'TMP=$(mktemp -d) || fail "mktemp"',
        "trap 'rm -rf \"$TMP\"' EXIT",
        "# free_group NAME / free_policy NAME: stop the script when one of that name exists",
        "free_group() {",
        '  if [ -n "$DRY_RUN" ]; then return 0; fi',
        '  if aws network-firewall describe-rule-group --rule-group-name "$1" --type STATEFUL $AWS_OPTS >/dev/null 2>&1; then',
        '    fail "a rule group named $1 exists already; nothing was created"',
        "  fi",
        "}",
        "free_policy() {",
        '  if [ -n "$DRY_RUN" ]; then return 0; fi',
        '  if aws network-firewall describe-firewall-policy --firewall-policy-name "$1" $AWS_OPTS >/dev/null 2>&1; then',
        '    fail "a firewall policy named $1 exists already; nothing was created"',
        "  fi",
        "}",
        "# group NAME CAPACITY FILE: creates a stateful rule group and prints its ARN",
        "group() {",
        '  if [ -n "$DRY_RUN" ]; then',
        '    show create-rule-group --rule-group-name "$1" --type STATEFUL --capacity "$2" --rule-group "file://$3"',
        "    printf 'arn:aws:network-firewall:dryrun:000000000000:stateful-rulegroup/%s\\n' \"$1\"",
        "    return 0",
        "  fi",
        '  if [ -n "$CHECK" ]; then',
        '    arn=$(aws network-firewall create-rule-group --rule-group-name "$1" --type STATEFUL --capacity "$2" --rule-group "file://$3" \\',
        '      --dry-run --query RuleGroupResponse.RuleGroupArn --output text $AWS_OPTS) || fail "create-rule-group $1 (dry run)"',
        "    printf 'checked: rule group %s\\n' \"$1\" >&2",
        "  else",
        '    arn=$(aws network-firewall create-rule-group --rule-group-name "$1" --type STATEFUL --capacity "$2" --rule-group "file://$3" \\',
        "      --description 'Generated by FWShift' --tags Key=fwshift,Value=generated \\",
        '      --query RuleGroupResponse.RuleGroupArn --output text $AWS_OPTS) || fail "create-rule-group $1"',
        "    printf 'created %s\\n' \"$arn\" >&2",
        "  fi",
        "  printf '%s\\n' \"$arn\"",
        "}",
        "# policy NAME FILE CHECKFILE: creates the firewall policy (with CHECK, checks it without its rule groups, which a dry run",
        "# does not create)",
        "policy() {",
        '  if [ -n "$DRY_RUN" ]; then show create-firewall-policy --firewall-policy-name "$1" --firewall-policy "file://$2"; return 0; fi',
        '  if [ -n "$CHECK" ]; then',
        '    aws network-firewall create-firewall-policy --firewall-policy-name "$1" --firewall-policy "file://$3" --dry-run $AWS_OPTS >/dev/null \\',
        '      || fail "create-firewall-policy $1 (dry run)"',
        "    printf 'checked: firewall policy %s\\n' \"$1\" >&2",
        "    return 0",
        "  fi",
        '  aws network-firewall create-firewall-policy --firewall-policy-name "$1" --firewall-policy "file://$2" \\',
        "    --description 'Generated by FWShift; review the conversion report before associating it' \\",
        '    --tags Key=fwshift,Value=generated $AWS_OPTS >/dev/null || fail "create-firewall-policy $1"',
        "  printf 'created firewall policy %s\\n' \"$1\" >&2",
        "}",
        "",
        "# No rule group or policy of these names may exist.",
    ]
    out += [f"free_group {shlex.quote(g)}" for g in group_names]
    out += [f"free_policy {shlex.quote(name)}", ""]
    for index, ((lines, sets), group_name) in enumerate(zip(groups, group_names), 1):
        body: Dict[str, object] = {}
        if sets:
            body["RuleVariables"] = {"IPSets": {key: {"Definition": sets[key]} for key in sorted(sets)}}
        rules = "\n".join(line.text for line in lines) + ("\n" if lines else "")
        if not lines:
            rules = 'pass ip 0.0.0.0/32 any -> 0.0.0.0/32 any (msg:"fwshift: no rules"; flow:to_server; sid:1; rev:1;)\n'
        body["RulesSource"] = {"RulesString": rules}
        body["StatefulRuleOptions"] = {"RuleOrder": "STRICT_ORDER"}
        capacity = max(100, 2 * max(len(lines), 1))
        out.append(f"# Rule group {index}: {len(lines)} rules, in the order of the policy.")
        out.append(f"cat > \"$TMP/group{index}.json\" <<'FWSHIFT_JSON'")
        out.append(json.dumps(body, indent=1, ensure_ascii=True))
        out.append("FWSHIFT_JSON")
        out.append(f"G{index}=$(group {shlex.quote(group_name)} {capacity} \"$TMP/group{index}.json\") || exit 1")
        out.append("")
    references = ",".join('{"ResourceArn":"${G%d}","Priority":%d}' % (index, 100 * index) for index in range(1, len(groups) + 1))
    common = ('"StatelessDefaultActions":["aws:forward_to_sfe"],"StatelessFragmentDefaultActions":["aws:forward_to_sfe"],'
              + (f'"StatefulDefaultActions":{json.dumps(defaults)},' if defaults else "")
              + '"StatefulEngineOptions":{"RuleOrder":"STRICT_ORDER"}')  # fmt: skip
    out += [
        "# The policy: every packet to the stateful engine, the rule groups in strict order, then the default of the source.",
        "cat > \"$TMP/policy.json\" <<FWSHIFT_JSON",
        "{" + common + ',"StatefulRuleGroupReferences":[' + references + "]}",
        "FWSHIFT_JSON",
        "cat > \"$TMP/policy-check.json\" <<'FWSHIFT_JSON'",
        "{" + common + "}",
        "FWSHIFT_JSON",
        f"policy {shlex.quote(name)} \"$TMP/policy.json\" \"$TMP/policy-check.json\"",
    ]
    if plan.not_written:
        out += ["", "# Not written:"] + ["#   " + _comment(line) for line in plan.not_written]
    out += ["", "echo 'Done. Associate the policy with a firewall when you are ready; until then nothing changes.' >&2"]
    return "\n".join(out) + "\n"


def _comment(text: str) -> str:
    return "".join(c if c.isprintable() else " " for c in text)
