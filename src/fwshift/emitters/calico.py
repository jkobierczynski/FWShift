# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Calico emitter: neutral model -> one GlobalNetworkPolicy of projectcalico.org/v3, as JSON.

Design rules:

* Calico's rules are first match (Allow and Deny decide), so the model's list is written as it is: one rule of the
  model becomes a Calico rule per IP version and per kind of service, in order, with the source and destination as
  ``nets`` (or ``notNets`` where that is shorter), the ports, ICMP type and code, or the protocol number.
* The same list is the policy's ingress and its egress rules. A connection between two endpoints the policy applies
  to is checked at both ends, and both give the model's verdict; one from or to elsewhere is checked at the one end.
* The policy applies to the endpoints that carry the label ``fwshift/policy`` with its name: creating it changes no
  traffic until pods (or host endpoints) are labelled. It stands in the default tier with order 100, and ends with
  the model's default, so that it decides everything for those endpoints.
* Calico has no zones: a rule between zones is written for the networks behind them (``--zone-network``), as for
  NSX; an allow rule whose zones have none is not written. Calico has no disabled rule either: a rule that cannot be
  written, or is disabled, is left out and named in the policy's annotations and the report.
* NAT is not Calico's: kube-proxy and the gateways translate before the policy sees a connection, so the rules are
  written for the translated addresses and the NAT rules are not written.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Set

from .. import names, transform
from ..model import ANY, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

LABEL = "fwshift/policy"
ORDER = 100
_FULL = {4: FULL_V4, 6: FULL_V6}
Match = Dict[str, Any]  # the protocol, ICMP and port fields of a Calico rule; "_version" when it holds for one IP version


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = prepare(policy, report, options)
    return _Emitter(p, report, options).run()


def prepare(policy: Policy, report: Report, options: Options) -> Policy:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)  # refuses networks that contradict each other
    # kube-proxy and the gateways translate before the policy sees a connection: the rules are written for what they
    # translate to, and the NAT rules are not written.
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return p


def policy_name(options: Options) -> str:
    text = re.sub(r"[^a-z0-9.-]+", "-", (options.target_policy or "fwshift").lower()).strip("-.")
    return names.clean(text or "fwshift", names.KUBERNETES).rstrip("-.") or "fwshift"


def cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in normalize(intervals):
        out += [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
    return out


def _ports(text: str) -> List[Any]:
    out: List[Any] = []
    for part in text.split(","):
        first, _, last = part.partition("-")
        out.append(int(first) if not last or first == last else f"{int(first)}:{int(last)}")
    return out


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used + list(options.zone_networks))
        self.rules: List[Dict[str, Any]] = []
        self.left_out: List[str] = []
        self.name = policy_name(options)

    # -- addresses ------------------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[Dict[int, List[Interval]]]:
        found: Dict[int, List[Interval]] = {4: [], 6: []}
        for member in members:
            if member == ANY:
                found = {4: [FULL_V4], 6: [FULL_V6]}
                break
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; a Calico rule names "
                                    "networks"))  # fmt: skip
                return None
            for interval in intervals:
                found[interval[0]].append(interval)
        found = {v: normalize(ivs) for v, ivs in found.items()}
        if negated:
            found = {v: subtract([_FULL[v]], found[v]) for v in (4, 6)}
        return found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: Dict[int, List[Interval]],
                 reasons: List[transform.Reason]) -> Dict[int, List[Interval]]:  # fmt: skip
        """The addresses of one side, kept to the zones of the rule (as the NSX emitter does)."""
        missing = [zone for zone in zones if zone not in self.spaces]
        if rule.action == Action.ALLOW:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and a Calico rule names no zone: give the "
                                f"networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return found
            space = normalize([i for zone in zones for i in self.spaces[zone]])
            kept = {v: intersect(ivs, space) for v, ivs in found.items()}
            if kept != found:
                self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} in zone {', '.join(zones)} is written as the addresses of the networks given for it "
                                "with --zone-network")  # fmt: skip
            return kept
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others):
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a Calico rule names no zone, and "
                            "it blocks that traffic in every zone. Give the networks behind every zone with --zone-network to "
                            "keep it to its zones")  # fmt: skip
            return found
        away = normalize([i for zone in others for i in self.spaces[zone]])
        kept = {v: subtract(ivs, away) for v, ivs in found.items()}
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
        return kept

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Dict[int, List[Interval]]]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        zones = rule.src_zones if source or rule.scope == RuleScope.INTRAZONE else rule.dst_zones
        side = "source" if source else "destination"
        found = self._resolve(members, negated, side, reasons)
        if found is None:
            return None
        if ANY in zones or (not source and rule.egress_implied and rule.scope != RuleScope.INTRAZONE):
            return found
        return self._confine(rule, side, zones, found, reasons)

    @staticmethod
    def _nets(intervals: List[Interval], version: int) -> Dict[str, Any]:
        """The fields of a source or destination for one IP version: nothing for all of it, nets or notNets."""
        if intervals == [_FULL[version]]:
            return {}
        positive = cidrs(intervals)
        negative = cidrs(subtract([_FULL[version]], intervals))
        return {"notNets": negative} if len(negative) < len(positive) else {"nets": positive}

    # -- services -------------------------------------------------------------------

    def _matches(self, rule: Rule, reasons: List[transform.Reason]) -> List[Match]:
        """The service fields of the Calico rules one rule of the model becomes ([{}] for every service)."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        entries: List[ServiceEntry] = []
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return []
        elif rule.services != [ANY]:
            for service in rule.services:
                flat = transform.flatten_services(self.p, service)
                if flat is None:
                    if service not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{service}' cannot be read"))
                    return []
                entries += flat
        else:
            return [{}] if not rule.negate_service else []
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return [{}] if not rule.negate_service else []
        if rule.negate_service:
            if len(entries) == 1 and self._protocol_only(entries[0]):
                return [{"notProtocol": self._protocol(entries[0])}]
            reasons.append(("SERVICE_NEGATE", "a negated service that is more than one protocol: a Calico rule negates one "
                            "protocol (notProtocol), or ports of one protocol"))  # fmt: skip
            return []
        out: List[Match] = []
        for entry in entries:
            match: Match = {"protocol": self._protocol(entry)}
            if entry.protocol == Protocol.IP and not 1 <= int(entry.ip_protocol or 0) <= 255:
                reasons.append(("SERVICE_PROTOCOL", f"IP protocol {entry.ip_protocol}: a Calico rule takes 1 to 255"))
                continue
            if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                if entry.dst_ports:
                    match["destination"] = {"ports": _ports(entry.dst_ports)}
                if entry.src_ports:
                    match["source"] = {"ports": _ports(entry.src_ports)}
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                match["_version"] = 4 if entry.protocol == Protocol.ICMP else 6
                if entry.icmp_type is not None:
                    if entry.icmp_type > 254:
                        reasons.append(("SERVICE_ICMP", f"ICMP type {entry.icmp_type}: a Calico rule takes 0 to 254"))
                        continue
                    match["icmp"] = {"type": entry.icmp_type}
                    if entry.icmp_code is not None:
                        match["icmp"]["code"] = entry.icmp_code
            if match not in out:
                out.append(match)
        return out

    @staticmethod
    def _protocol_only(entry: ServiceEntry) -> bool:
        if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
            return not entry.dst_ports and not entry.src_ports
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            return entry.icmp_type is None
        return entry.ip_protocol is not None

    @staticmethod
    def _protocol(entry: ServiceEntry) -> Any:
        return {Protocol.TCP: "TCP", Protocol.UDP: "UDP", Protocol.SCTP: "SCTP", Protocol.ICMP: "ICMP",
                Protocol.ICMP6: "ICMPv6"}.get(entry.protocol, entry.ip_protocol)  # fmt: skip

    # -- rules ----------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.left_out.append(f"{rule.name} ({'disabled by the audit' if by_audit else 'disabled in the source'})")
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a Calico rule names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written for every pair of its zones, which blocks more")  # fmt: skip
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": a Calico rule names networks (domain "
                            "names are a feature of Calico Enterprise and Cloud)"))  # fmt: skip
        matches = self._matches(rule, reasons)
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        if fqdn:
            reasons = [reason for reason in reasons if reason[0] != "ADDRESS_UNKNOWN"]
        reasons = list(dict.fromkeys(reasons))
        if reasons or sources is None or destinations is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")])
            self.left_out.append(f"{rule.name} (not written, see the report)")
            return
        written = self._write(rule, sources, destinations, matches)
        if not written:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation and the networks of its zones, the rule matches no connection", Severity.INFO)  # fmt: skip
            return
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH, Action.DENY):
            self.report.add("rule", rule.origin, Severity.INFO, "ACTION_DROP",
                            f"action {rule.action.value}: Calico's Deny drops, without an answer")  # fmt: skip
        first = len(self.rules) - written + 1
        item.emitted_as.append(f"rule {first}" if written == 1 else f"rules {first}-{len(self.rules)}")

    def _write(self, rule: Rule, sources: Dict[int, List[Interval]], destinations: Dict[int, List[Interval]], matches: List[Match]) -> int:
        action = "Allow" if rule.action == Action.ALLOW else "Deny"
        whole = all(sources[v] == [_FULL[v]] and destinations[v] == [_FULL[v]] for v in (4, 6))
        count = 0
        for match in matches:
            versions = [match["_version"]] if "_version" in match else [4, 6]
            if whole and "_version" not in match:
                versions = [0]  # (every address of both versions: one rule)
            for version in versions:
                if version and (not sources[version] or not destinations[version]):
                    continue
                body: Dict[str, Any] = {"action": action}
                if version:
                    body["ipVersion"] = version
                for key, value in match.items():
                    if key == "_version":
                        continue
                    body[key] = copy.deepcopy(value)
                for key, found in (("source", sources), ("destination", destinations)):
                    if version:
                        fields = self._nets(found[version], version)
                        if fields:
                            body.setdefault(key, {}).update(fields)
                body["metadata"] = {"annotations": {"fwshift/rule": rule.name[:250]}}
                self.rules.append(self._ordered(body))
                count += 1
        return count

    @staticmethod
    def _ordered(body: Dict[str, Any]) -> Dict[str, Any]:
        order = ["action", "ipVersion", "protocol", "notProtocol", "icmp", "source", "destination", "metadata"]
        return {key: body[key] for key in order if key in body}

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

    # -- output ---------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        default = "Allow" if self.p.default_interzone == Action.ALLOW else "Deny"
        self.rules.append({"action": default, "metadata": {"annotations": {"fwshift/rule": "(default of the source policy)"}}})
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: Calico does not translate addresses (kube-proxy, the cloud's load balancers and the "
                             "gateways do). The rules were written for the addresses it translates to, which is what Calico sees")  # fmt: skip
        self._notes()
        annotations = {"fwshift/generated": "FWShift - review the conversion report before applying this"}
        if self.left_out:
            annotations["fwshift/not-written"] = "; ".join(self.left_out)[:200000]
        body = {
            "apiVersion": "projectcalico.org/v3",
            "kind": "GlobalNetworkPolicy",
            "metadata": {"name": self.name, "annotations": annotations},
            "spec": {
                "tier": "default",
                "order": ORDER,
                "selector": f"{LABEL} == '{self.name}'",
                "types": ["Ingress", "Egress"],
                "ingress": self.rules,
                "egress": copy.deepcopy(self.rules),
            },
        }
        return json.dumps(body, indent=2, ensure_ascii=False) + "\n"

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "CALICO_LOAD",
            f"the output is one GlobalNetworkPolicy ({self.name}) for calicoctl apply -f FILE, or kubectl apply -f FILE where the "
            f"Calico API server is installed. It applies to the endpoints labelled {LABEL}={self.name} and to nothing else: "
            f"label the pods it is for (kubectl label pod POD {LABEL}={self.name}). It stands in the default tier with order "
            f"{ORDER}, before the Kubernetes network policies (order 1000), and ends with the source's default, so that it "
            "decides everything for those endpoints; a policy of the same name is replaced",
        )  # fmt: skip
        if self.p.default_intrazone != self.p.default_interzone:
            self.report.note(Severity.REVIEW, "INTRAZONE_DEFAULT",
                             "the source treats traffic inside a zone and between zones differently when no rule matches; Calico "
                             "has no zones, and the default of traffic between zones was written")  # fmt: skip
        transform.note_closed_zones(self.p, self.options.zone_map, self.report, list(self.options.zone_networks))
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                             "written for that: " + ", ".join(open_zones))  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; the Calico rules written do not (a rule with action Log before a rule "
                             "would log what it matches)")  # fmt: skip
        if self.p.vendor in ("kubernetes", "calico"):
            self.report.note(Severity.INFO, "CALICO_SELECTORS_AS_NETS",
                             "the selectors of the source were worked out as the pods' addresses when it was exported; the rules "
                             "name those addresses, not labels, and do not follow pods that are created or move")  # fmt: skip
