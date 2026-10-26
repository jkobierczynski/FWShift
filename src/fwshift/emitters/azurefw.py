# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Azure Firewall emitter: neutral model -> an ARM template that creates a new firewall policy with rule collection groups.

Design rules:

* One new firewall policy (tier Standard) with its rule collection groups, associated with no firewall: deploying the
  template changes no traffic until a person associates the policy with a firewall or a secured hub.
* Each rule of the model becomes one network rule collection with the rule's action, at the next priority. The rules of
  a collection have one action and no order among themselves, so the network rules a rule of the model becomes (one per
  set of protocols and ports, and per kind of address: addresses, IP groups, FQDNs, service tags) together match what it
  matches, and the collections keep the order of the model. Groups of at most 2 MB hold the collections, in order.
* A network rule names no zone: zones become the networks behind them (``--zone-network``), as for Google Cloud. It
  holds IPv4 only, destination ports only, no ICMP types, and protocols TCP, UDP, ICMP or every one. What it cannot say
  makes an allow rule allow less and a blocking rule block more, both said; what cannot be said at all leaves the rule
  out, listed in the template's metadata and in the report. Azure Firewall has no rule that is switched off.
* The model's default is Azure's own (deny) unless it allows: then a last collection allows the rest.
* A NAT rule that translates the destination becomes a DNAT rule. Azure Firewall allows what a DNAT rule translates
  without asking the network rules: the DNAT rule is written only where the model allows all it translates.
  Source NAT is Azure's own (to the firewall's addresses) and not written.
* Service tags and IP groups of an Azure Firewall source are written as what they are.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from dataclasses import dataclass, field
from typing import AbstractSet, Any, Dict, List, Optional, Set, Tuple

from .. import names, regions, transform
from ..model import ANY, Action, AddressKind, NatRule, Policy, Rule, RuleScope
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, parse_literal, subtract, within
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

API_VERSION = "2024-05-01"
_MAX_GROUP_BYTES = 1_900_000  # a rule collection group of at most 2 MB (assumed limit, with room)
_MAX_GROUPS = 90  # rule collection groups of one policy
_MAX_DNAT_PORTS = 64  # single ports one NAT rule of the model may become
_NATIVE_VENDOR = "azure-firewall"


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)
    # The rules match the addresses as they arrive (what a DNAT rule translates never meets them), which is the model's
    # side of NAT: no rewriting.
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


def policy_name(options: Options) -> str:
    return clean((options.object_prefix or "") + (options.target_policy or "FWShift"))


def clean(text: str) -> str:
    return names.clean(text, names.AZURE_FIREWALL).rstrip(".-") or "x"


def _cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in intervals:
        out += [str(n) for n in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
    return ["*" if c == "0.0.0.0/0" else c[:-3] if c.endswith("/32") else c for c in out]


def _intervals(texts: List[str]) -> List[Interval]:
    return normalize([i for i in (parse_literal(t) for t in texts) if i is not None])


@dataclass
class _Side:
    """One side of a rule as Azure Firewall can say it."""

    v4: List[Interval] = field(default_factory=list)
    v6: bool = False  # the side held IPv6 addresses, which are not written
    ip_groups: List[str] = field(default_factory=list)  # ids
    fqdns: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not self.v4 and not self.ip_groups and not self.fqdns and not self.tags

    def native(self) -> bool:
        return bool(self.ip_groups or self.fqdns or self.tags)


Layer4 = Tuple[List[str], List[str]]  # (ipProtocols, destinationPorts)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options, self.source_zones = p, report, options, source_zones
        self.native = p.vendor == _NATIVE_VENDOR
        self.taint_a = transform.tainted_addresses(p, keep_dynamic=self.native)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))
        self.name = policy_name(options)
        self.collections: List[Tuple[Dict[str, Any], str]] = []  # (collection, origin of the rule of the model or "")
        self.nat_collections: List[Tuple[Dict[str, Any], str]] = []
        self.not_written: List[str] = []
        self.taken: Set[str] = set()
        self.ipv6 = False
        self.fqdn = False

    # -- names ---------------------------------------------------------------------------

    def _unique(self, base: str) -> str:
        stem = clean(base)
        candidate, counter = stem, 2
        while candidate.lower() in self.taken:
            suffix = f"-{counter}"
            candidate = clean(stem[: 80 - len(suffix)]) + suffix
            counter += 1
        self.taken.add(candidate.lower())
        return candidate

    # -- sides ---------------------------------------------------------------------------

    def _leaves(self, member: str) -> List[str]:
        """The member, and what the groups among it hold, without the groups that are resolved further."""
        out: List[str] = []
        todo, seen = [member], set()
        while todo:
            name = todo.pop(0)
            if name in seen:
                continue
            seen.add(name)
            group = self.p.address_groups.get(name)
            if group is not None and not group.dynamic_filter and not group.unsupported:
                todo += group.members
            else:
                out.append(name)
        return out

    def _resolve(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[_Side]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        label = "source" if source else "destination"
        out = _Side()
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found = [FULL_V4, FULL_V6]
                out = _Side()
                break
            for leaf in self._leaves(member):
                group = self.p.address_groups.get(leaf)
                address = self.p.addresses.get(leaf)
                if group is not None and self.native and group.dynamic_filter.startswith(("azure-tag:", "azure-ipgroup:")):
                    kind, _, value = group.dynamic_filter.partition(":")
                    if kind == "azure-ipgroup":
                        out.ip_groups.append(value)
                    elif source:
                        reasons.append(("AZFW_SOURCE_TAG", f"service tag {value} in the source: a network rule of Azure Firewall takes "
                                        "service tags as destinations only"))  # fmt: skip
                        return None
                    else:
                        out.tags.append(value)
                    continue
                if address is not None and address.kind == AddressKind.FQDN:
                    if source:
                        reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {leaf} in the source: a network rule of Azure "
                                        "Firewall takes FQDNs as destinations only"))  # fmt: skip
                        return None
                    if address.fqdn_family != 6:
                        out.fqdns.append(address.value)
                    if address.fqdn_family != 4:
                        out.v6 = True
                    continue
                intervals, known = transform.known_intervals(self.p, leaf)
                if not known:
                    if leaf not in self.taint_a and member not in self.taint_a:
                        reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {label} '{leaf}' are not known; a rule of Azure "
                                        "Firewall names addresses"))  # fmt: skip
                    return None
                found += intervals
        found = normalize(found)
        if negated:
            if out.native():
                reasons.append(("ADDRESS_NOT_WRITTEN", f"a negated {label} with an FQDN, a service tag or an IP group"))
                return None
            found = subtract([FULL_V4, FULL_V6], found)
        out.v4 = [i for i in found if i[0] == 4]
        out.v6 = out.v6 or any(i[0] == 6 for i in found)
        out.ip_groups, out.fqdns, out.tags = (transform.dedupe(out.ip_groups), transform.dedupe(out.fqdns), transform.dedupe(out.tags))
        return out

    def _confine(self, rule: Rule, side: _Side, zones: List[str], label: str, reasons: List[transform.Reason]) -> _Side:
        """A side kept to the networks of its zones; a blocking rule whose zones cannot be cut blocks more."""
        if ANY in zones:
            return side
        allow = rule.action == Action.ALLOW
        missing = [zone for zone in zones if zone not in self.spaces]
        if allow:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING", f"the {label} of the rule is in zone {', '.join(zones)}, and a rule of Azure "
                                f"Firewall names no zone: give the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return side
            if side.native():
                reasons.append(("ZONE_DYNAMIC", f"the {label} of the rule is in zone {', '.join(zones)}, and an FQDN, a service tag "
                                "or an IP group cannot be cut down to the networks of a zone"))  # fmt: skip
                return side
            space = normalize([i for zone in zones for i in self.spaces[zone]])
            return _Side(intersect(side.v4, space), side.v6 and any(i[0] == 6 for i in space))
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others) or side.native():
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {label} is in zone {', '.join(zones)}; a rule of Azure Firewall names no "
                            "zone, and it blocks that traffic in every zone. Give the networks behind every zone with --zone-network "
                            "to keep it to its zones")  # fmt: skip
            return side
        away = normalize([i for zone in others for i in self.spaces[zone]])
        return _Side(subtract(side.v4, away), side.v6, side.ip_groups, side.fqdns, side.tags)

    # -- services ------------------------------------------------------------------------

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

    def _layer4(self, rule: Rule, svc: regions.Services) -> List[Layer4]:
        """The protocols and ports of network rules. An allow rule leaves out what cannot be said; a blocking rule blocks
        more."""
        allow = rule.action == Action.ALLOW
        if svc.everything():
            return [(["Any"], ["*"])]
        left_out, widened, out = False, False, []
        ports: Dict[int, List[str]] = {}
        for number in (6, 17):
            rects = svc.of(number)
            if any((r[0], r[1]) != (0, 65535) for r in rects):
                if allow:
                    rects = [r for r in rects if (r[0], r[1]) == (0, 65535)]
                    left_out = True
                else:
                    widened = True
            if rects:
                merged = regions.merge_ranges([(r[2], r[3]) for r in rects])
                if merged and merged[0][0] == 0:
                    merged[0] = (1, merged[0][1])  # (port 0 is no port a packet has)
                ports[number] = ["*"] if merged == [(1, 65535)] else [str(a) if a == b else f"{a}-{b}" for a, b in merged if b >= 1]
        if 6 in ports and 17 in ports and ports[6] == ports[17]:
            out.append((["TCP", "UDP"], ports[6]))
        else:
            out += [([label], ports[n]) for n, label in ((6, "TCP"), (17, "UDP")) if n in ports and ports[n]]
        icmp = svc.of(1)
        if icmp:
            if any(regions.icmp_values(r[0], r[1]) != [None] or regions.icmp_values(r[2], r[3]) != [None] for r in icmp):
                if allow:
                    left_out = True
                else:
                    widened = True
                    out.append((["ICMP"], ["*"]))
            else:
                out.append((["ICMP"], ["*"]))
        others = [n for n in svc.protocols if svc.of(n) and n not in (1, 6, 17, 58)]
        if others or svc.rest:
            if allow:
                left_out = True
            else:
                widened = True
                out = [(["Any"], ["*"])]
        if svc.of(58) and allow:
            self.ipv6 = True
            self.report.add("rule", rule.origin, Severity.APPROX, "AZFW_IPV6_NOT_WRITTEN",
                            "the rule allows ICMPv6; Azure Firewall filters IPv4 only, and that part is not written")  # fmt: skip
        if left_out:
            self.report.add("rule", rule.origin, Severity.APPROX, "AZFW_PART_NOT_WRITTEN",
                            "part of what the rule allows cannot be said by a network rule of Azure Firewall (source ports, ICMP types, "
                            "protocols other than TCP, UDP and ICMP unless every one) and is not written: the converted rule allows less")  # fmt: skip
        if widened:
            self.report.add("rule", rule.origin, Severity.APPROX, "AZFW_BLOCKS_MORE",
                            "the rule blocks certain source ports, ICMP types or protocols; a network rule of Azure Firewall blocks every "
                            "source port, all of ICMP or every protocol there, which blocks more")  # fmt: skip
        return out

    # -- rules ---------------------------------------------------------------------------

    def _reasons(self, rule: Rule) -> List[transform.Reason]:
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        return reasons

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.not_written.append(f"{rule.name}: {'disabled by the audit' if by_audit else 'disabled in the source'}")
            return
        allow = rule.action == Action.ALLOW
        reasons = self._reasons(rule)
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a rule of Azure Firewall names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written as a rule for every pair of its zones, which blocks more")  # fmt: skip
        svc = self._services(rule, reasons)
        sources = self._resolve(rule, True, reasons)
        destinations = self._resolve(rule, False, reasons)
        if sources is not None:
            sources = self._confine(rule, sources, rule.src_zones, "source", reasons)
        if destinations is not None:
            destinations = self._confine(rule, destinations, [ANY] if rule.egress_implied else rule.dst_zones, "destination", reasons)
        layer4 = self._layer4(rule, svc) if svc is not None else []
        if destinations is not None and destinations.fqdns and not allow and any(p != ["TCP"] and p != ["UDP"] and p != ["TCP", "UDP"]
                                                                                for p, _ in layer4):  # fmt: skip
            reasons.append(("AZFW_FQDN_PROTOCOL", "an FQDN in a network rule is for TCP and UDP; the rule blocks other protocols to it"))
        reasons = list(dict.fromkeys(reasons))
        if reasons or svc is None or sources is None or destinations is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.not_written.append(f"{rule.name}: " + "; ".join(message for _, message in reasons)[:400])
            return
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY",
                            f"action {rule.action.value}: a rule of Azure Firewall denies, and whether it answers is not documented")  # fmt: skip
        if sources.v6 and destinations.v6:  # (an IPv6 part only where both sides hold IPv6 addresses)
            self.ipv6 = True
            if allow:
                self.report.add("rule", rule.origin, Severity.APPROX, "AZFW_IPV6_NOT_WRITTEN",
                                "the rule allows IPv6 too; Azure Firewall filters IPv4 only, and the IPv6 part is not written")  # fmt: skip
        rules = self._network_rules(rule, sources, destinations, layer4, allow)
        if not rules and any(f.code in ("AZFW_PART_NOT_WRITTEN", "AZFW_IPV6_NOT_WRITTEN") for f in item.findings):
            self.report.skip("rule", rule.origin, "AZFW_NOT_WRITTEN",
                             "nothing of what the rule allows can be said by a network rule of Azure Firewall (IPv6, source ports, ICMP "
                             "types, some protocols): not written")  # fmt: skip
            self.not_written.append(f"{rule.name}: what it allows cannot be said by a network rule of Azure Firewall")
            return
        if not rules:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation, the networks of its zones, IPv4 and what a network rule can say, the rule matches no "
                             "connection here", Severity.INFO)  # fmt: skip
            return
        name = self._unique(rule.name)
        collection = {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": name, "priority": 0,
                      "action": {"type": "Allow" if allow else "Deny"}, "rules": rules}  # fmt: skip
        self.collections.append((collection, rule.origin))

    def _network_rules(self, rule: Rule, sources: _Side, destinations: _Side, layer4: List[Layer4], allow: bool) -> List[Dict[str, Any]]:
        froms: List[Dict[str, Any]] = []
        if sources.v4:
            froms.append({"sourceAddresses": _cidrs(sources.v4)})
        if sources.ip_groups:
            froms.append({"sourceIpGroups": [self._ip_group(i) for i in sources.ip_groups]})
        tos: List[Tuple[str, Dict[str, Any]]] = []
        if destinations.v4:
            tos.append(("addresses", {"destinationAddresses": _cidrs(destinations.v4)}))
        if destinations.tags:
            tos.append(("tags", {"destinationAddresses": list(destinations.tags)}))
        if destinations.ip_groups:
            tos.append(("groups", {"destinationIpGroups": [self._ip_group(i) for i in destinations.ip_groups]}))
        if destinations.fqdns:
            tos.append(("fqdns", {"destinationFqdns": list(destinations.fqdns)}))
        out: List[Dict[str, Any]] = []
        description = " ".join(rule.description.split())[:1000]
        fqdn_left_out = False
        for source in froms:
            for kind, destination in tos:
                for protocols, ports in layer4:
                    if kind == "fqdns" and not set(protocols) <= {"TCP", "UDP"}:
                        fqdn_left_out = True  # (an allow rule: a blocking one was not written, above)
                        continue
                    body: Dict[str, Any] = {"ruleType": "NetworkRule", "name": ""}
                    if description:
                        body["description"] = description
                    body["ipProtocols"] = list(protocols)
                    body.update(source)
                    body.update(destination)
                    body["destinationPorts"] = list(ports)
                    if kind == "fqdns":
                        self.fqdn = True
                    out.append(body)
        if fqdn_left_out:
            self.report.add("rule", rule.origin, Severity.APPROX, "AZFW_PART_NOT_WRITTEN",
                            "an FQDN in a network rule is for TCP and UDP: what the rule allows to it of other protocols is not "
                            "written, and the converted rule allows less")  # fmt: skip
        for index, body in enumerate(out):
            body["name"] = clean(rule.name if index == 0 else f"{rule.name[:72]}-{index + 1}")
        return out

    @staticmethod
    def _ip_group(ident: str) -> str:
        if ident.lower().startswith("/subscriptions/") or ident.startswith("["):
            return ident
        last = ident.rstrip("/").rsplit("/", 1)[-1].replace("'", "''")
        return f"[resourceId('Microsoft.Network/ipGroups', '{last}')]"

    # -- inside a zone, and the default ------------------------------------------------------

    def _intrazone(self) -> None:
        """What no rule matches inside a zone, where the source decides it otherwise than between zones: a collection for
        the networks of each such zone to themselves, after the rules of the model and before its default."""
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
            cidrs = _cidrs([i for i in self.spaces[zone] if i[0] == 4])
            if not cidrs:
                continue
            rule = {"ruleType": "NetworkRule", "name": clean(f"fwshift-intrazone-{zone}"), "ipProtocols": ["Any"],
                    "sourceAddresses": cidrs, "destinationAddresses": cidrs, "destinationPorts": ["*"]}  # fmt: skip
            self.collections.append(({"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": self._unique(f"fwshift-intrazone-{zone}"),
                                      "priority": 0, "action": {"type": "Allow" if allow else "Deny"}, "rules": [rule]}, ""))  # fmt: skip
            written.append(zone)
        if written:
            self.report.note(Severity.INFO, "INTRAZONE_WRITTEN",
                             "the source decides traffic inside a zone that no rule matches otherwise than between zones; Azure Firewall "
                             "has no zones, so that was written as rules for the networks of each zone to themselves (--zone-network), "
                             "after the rules of the policy: " + ", ".join(written))  # fmt: skip
        if blocked:
            self.report.note(Severity.REVIEW, "INTRAZONE_DEFAULT",
                             "the source allows traffic inside these zones that no rule matches, and blocks it between zones; Azure "
                             "Firewall has no zones, and without their networks (--zone-network) the converted policy blocks it: " +
                             ", ".join(blocked))  # fmt: skip
        if opened:
            self.report.note(Severity.REVIEW, "INTRAZONE_DENY_NOT_WRITTEN",
                             "the source blocks traffic inside these zones that no rule matches, and allows it between zones; Azure "
                             "Firewall has no zones, and without their networks (--zone-network) the converted policy ALLOWS it: give "
                             "their networks, or a rule that blocks it: " + ", ".join(opened))  # fmt: skip

    def _default(self) -> None:
        if self.p.default_interzone != Action.ALLOW:
            return
        rule = {"ruleType": "NetworkRule", "name": "fwshift-default-allow", "ipProtocols": ["Any"], "sourceAddresses": ["*"],
                "destinationAddresses": ["*"], "destinationPorts": ["*"]}  # fmt: skip
        self.collections.append(({"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": self._unique("fwshift-default-allow"),
                                  "priority": 0, "action": {"type": "Allow"}, "rules": [rule]}, ""))  # fmt: skip
        self.report.note(Severity.INFO, "AZFW_DEFAULT_ALLOW",
                         "the source allows what no rule matches; Azure Firewall denies it, so a last rule collection allows every "
                         "protocol from every address to every address. It comes before the application rules and the built-in "
                         "infrastructure rule collection of Azure")  # fmt: skip

    # -- NAT ---------------------------------------------------------------------------

    def _nat(self, nat: NatRule) -> None:
        if not nat.enabled:
            self.report.skip("nat", nat.origin, "AZFW_NAT_NOT_WRITTEN", "disabled in the source; Azure Firewall has no rule that is off",
                             Severity.INFO)  # fmt: skip
            return
        if nat.source_translation is None and nat.destination_translation is None:
            self.report.skip("nat", nat.origin, "AZFW_NAT_NOT_WRITTEN",
                             "a NAT rule that translates nothing (an exemption): Azure Firewall leaves the source of traffic to its "
                             "private ranges as it is, which the policy's SNAT settings choose, not a rule. Not written")  # fmt: skip
            return
        if nat.source_translation is not None and nat.destination_translation is None:
            self.report.skip("nat", nat.origin, "AZFW_SNAT_NOT_WRITTEN",
                             "source NAT is not a rule of Azure Firewall: it translates the source of what goes to public addresses "
                             "(outside its private ranges) to its own public address by itself. Not written")  # fmt: skip
            return
        why = self._nat_problem(nat)
        if why:
            self.report.skip("nat", nat.origin, "AZFW_NAT_NOT_WRITTEN", f"not written: {why}")
            return
        plan = self._dnat_plan(nat)
        if isinstance(plan, str):
            self.report.skip("nat", nat.origin, "AZFW_NAT_NOT_WRITTEN", f"not written: {plan}")
            return
        blocked = self._dnat_blocked(nat, plan)
        if blocked:
            self.report.skip("nat", nat.origin, "AZFW_DNAT_NOT_ALLOWED",
                             "Azure Firewall allows what a DNAT rule translates, before any network rule; the policy does not allow "
                             f"all this NAT rule translates ({blocked}), so it is not written. Write the DNAT rule by hand for what "
                             "the policy allows")  # fmt: skip
            return
        sources, destinations, ports, translated, fqdn, port = plan
        rules: List[Dict[str, Any]] = []
        for destination in destinations:
            for protocols, original in ports:
                body: Dict[str, Any] = {"ruleType": "NatRule", "name": "", "ipProtocols": protocols}
                body.update(sources)
                body["destinationAddresses"] = [destination]
                body["destinationPorts"] = [str(original)]
                if fqdn:
                    body["translatedFqdn"] = translated
                else:
                    body["translatedAddress"] = translated
                body["translatedPort"] = port or str(original)
                rules.append(body)
        for index, body in enumerate(rules):
            body["name"] = clean(nat.name if index == 0 else f"{nat.name[:72]}-{index + 1}")
        if nat.source_translation is not None:
            self.report.add("nat", nat.origin, Severity.INFO, "AZFW_DNAT_SNAT",
                            "the rule translates the source too; Azure Firewall translates the source of DNAT traffic to one of its "
                            "own addresses, which a rule does not choose")  # fmt: skip
        collection = {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": self._unique(nat.name), "priority": 0,
                      "action": {"type": "DNAT"}, "rules": rules}  # fmt: skip
        self.nat_collections.append((collection, nat.origin))

    def _nat_problem(self, nat: NatRule) -> str:
        if nat.unsupported:
            return "; ".join(nat.unsupported)
        tainted = [m for m in nat.sources + nat.destinations if m in self.taint_a]
        if tainted:
            return f"references '{tainted[0]}': {self.taint_a[tainted[0]]}"
        translation = nat.destination_translation
        assert translation is not None
        if translation.spread:
            return "it translates to one of several addresses per connection, which a DNAT rule does not"
        return ""

    def _dnat_plan(self, nat: NatRule) -> Any:
        """(source fields, destination addresses, [(protocols, port)], translated, is an FQDN, translated port), or why not."""
        translation = nat.destination_translation
        assert translation is not None
        target = self.p.addresses.get(translation.address)
        fqdn = False
        if target is not None and target.kind == AddressKind.FQDN:
            translated, fqdn = target.value, True
        else:
            intervals = transform.address_intervals(self.p, translation.address)
            if not intervals or len(intervals) != 1 or intervals[0][0] != 4 or intervals[0][1] != intervals[0][2]:
                return f"it translates to '{translation.address}', and a DNAT rule translates to one IPv4 address or an FQDN"
            translated = str(int_to_ip(4, intervals[0][1]))
        if ANY in nat.destinations:
            return "it is for every destination address; a DNAT rule is for an address of the firewall"
        destinations: List[str] = []
        for member in nat.destinations:
            intervals = transform.address_intervals(self.p, member)
            if intervals is None:
                return f"the addresses of the destination '{member}' are not known"
            for version, first, last in normalize(intervals):
                if version != 4:
                    continue
                if last - first >= 16:
                    return f"destination '{member}' is more addresses than the firewall has"
                destinations += [str(int_to_ip(4, n)) for n in range(first, last + 1)]
        if not destinations:
            return "it has no IPv4 destination, and Azure Firewall translates IPv4 only"
        sources: Dict[str, Any]
        group = None
        if nat.sources == [ANY]:
            found: List[Interval] = [FULL_V4]
        else:
            found = []
            groups: List[str] = []
            for member in nat.sources:
                record = self.p.address_groups.get(member)
                if record is not None and self.native and record.dynamic_filter.startswith("azure-ipgroup:"):
                    groups.append(record.dynamic_filter.partition(":")[2])
                    continue
                intervals = transform.address_intervals(self.p, member)
                if intervals is None:
                    return f"the addresses of the source '{member}' are not known"
                found += intervals
            if groups:
                if found:
                    return "its sources mix addresses and IP groups"
                group = groups
        if group is not None:
            sources = {"sourceIpGroups": [self._ip_group(i) for i in group]}
        else:
            found = [i for i in normalize(found) if i[0] == 4]
            if ANY not in nat.src_zones:
                missing = [zone for zone in nat.src_zones if zone not in self.spaces]
                if missing:
                    return (f"it is for traffic from zone {', '.join(nat.src_zones)}, and a DNAT rule names no zone: give the networks "
                            f"behind {', '.join(missing)} with --zone-network")  # fmt: skip
                found = intersect(found, normalize([i for zone in nat.src_zones for i in self.spaces[zone]]))
            if not found:
                return "no IPv4 source is left"
            sources = {"sourceAddresses": _cidrs(found)}
        if nat.service == ANY:
            return "it is for every service; a DNAT rule is for TCP or UDP ports"
        entries = transform.flatten_services(self.p, nat.service)
        svc = regions.service_set(entries) if entries else None
        if svc is None or svc.rest or any(n not in (6, 17) for n in svc.protocols if svc.of(n)):
            return "its service is not TCP or UDP ports"
        by_port: Dict[int, List[str]] = {}
        for number, label in ((6, "TCP"), (17, "UDP")):
            for rect in svc.of(number):
                if (rect[0], rect[1]) != (0, 65535):
                    return "it names source ports, which a DNAT rule does not"
                if rect[3] - rect[2] >= _MAX_DNAT_PORTS:
                    return f"it is for more than {_MAX_DNAT_PORTS} ports"
                for port in range(max(rect[2], 1), rect[3] + 1):
                    by_port.setdefault(port, []).append(label)
        if not by_port or len(by_port) > _MAX_DNAT_PORTS:
            return f"it is for no port, or for more than {_MAX_DNAT_PORTS}"
        if max(by_port) > 63999 or (translation.port and int(translation.port) > 63999):
            return "a NAT rule of Azure Firewall takes ports 1 to 63999 only"
        ports = [(sorted(set(labels), key=["TCP", "UDP"].index), port) for port, labels in sorted(by_port.items())]
        return sources, destinations, ports, translated, fqdn, translation.port

    def _dnat_blocked(self, nat: NatRule, plan: Any) -> str:
        """Why the model does not allow all a NAT rule translates ('' when it does): its rules, first match, on the
        addresses before NAT, for the IPv4 part Azure Firewall sees."""
        sources_field, destinations = plan[0], plan[1]
        src: Optional[List[Interval]] = None  # (an IP group: the addresses only Azure knows)
        if "sourceIpGroups" not in sources_field:
            src = _intervals(["0.0.0.0/0" if c == "*" else c for c in sources_field["sourceAddresses"]])
        dst = _intervals(destinations)
        entries = transform.flatten_services(self.p, nat.service) or []
        svc = regions.service_set(entries)
        if svc is None:
            return "its service cannot be read"
        if src is None:
            # Only an allow rule of the model for every source, before anything that blocks, covers an IP group.
            src_box = [FULL_V4]
        else:
            src_box = src
        remaining: List[regions.Box] = [(4, src_box, dst, svc)]
        target = parse_literal(str(plan[3])) if not plan[4] else None
        for rule in self.p.rules:
            if not rule.enabled:
                continue
            allow = rule.action == Action.ALLOW
            box = self._box(rule)
            zones = self._zones_hold(rule, nat, target, src)
            if box is None or rule.unsupported or rule.users != [ANY] or rule.url_categories != [ANY] or rule.scope != RuleScope.UNIVERSAL:
                if not allow and zones != "none" and (box is None or any(regions.box_and(r, box) for r in remaining)):
                    return f"rule {rule.name} may block part of it"
                continue
            if not any(regions.box_and(r, box) for r in remaining):
                continue
            if not allow:
                if zones != "none":
                    return f"rule {rule.name} blocks part of it"
                continue
            if zones != "all" or (src is None and not within([FULL_V4], box[1])):
                continue
            cut = regions.minus_all(remaining, [box])
            if cut is None:
                return "the rules that allow it cut it into too many pieces"
            remaining = cut
            if not remaining:
                return ""
        if self.p.default_interzone == Action.ALLOW:
            return ""
        return "part of it reaches the policy's default, which blocks"

    def _box(self, rule: Rule) -> Optional[regions.Box]:
        """What a rule matches, IPv4, on the addresses as they arrive, without its zones; None when it cannot be read."""
        sides: List[List[Interval]] = []
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            found: List[Interval] = []
            for member in members:
                intervals = [FULL_V4, FULL_V6] if member == ANY else transform.address_intervals(self.p, member)
                if intervals is None:
                    return None
                found += intervals
            found = normalize(found)
            if negated:
                found = subtract([FULL_V4, FULL_V6], found)
            sides.append([i for i in found if i[0] == 4])
        if rule.services == [ANY]:
            svc: Optional[regions.Services] = regions.ALL_SERVICES
        else:
            entries = []
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    return None
                entries += flat
            svc = regions.service_set(entries)
        if svc is None or rule.applications != [ANY]:
            return None
        if rule.negate_service:
            svc = regions.ALL_SERVICES.minus(svc)
        return (4, sides[0], sides[1], svc)

    def _zones_hold(self, rule: Rule, nat: NatRule, target: Optional[Interval], sources: Optional[List[Interval]]) -> str:
        """Whether the zones of a rule hold the traffic of a NAT rule: "all", "some" (maybe) or "none"."""
        verdicts = []
        # Source zones: those of the NAT rule, or the networks of the rule's zones around its sources.
        if ANY in rule.src_zones:
            verdicts.append("all")
        elif ANY not in nat.src_zones and set(nat.src_zones) <= set(rule.src_zones):
            verdicts.append("all")
        elif sources is not None and all(z in self.spaces for z in rule.src_zones) and \
                within(sources, normalize([i for z in rule.src_zones for i in self.spaces[z]])):  # fmt: skip
            verdicts.append("all")
        elif ANY not in nat.src_zones and not set(nat.src_zones) & set(rule.src_zones) and all(z in self.spaces for z in rule.src_zones) \
                and sources is not None and not intersect(sources, normalize([i for z in rule.src_zones for i in self.spaces[z]])):  # fmt: skip
            verdicts.append("none")
        else:
            verdicts.append("some")
        # Destination zone: the model's is the zone after NAT, where the translated address lies.
        if ANY in rule.dst_zones or rule.egress_implied:
            verdicts.append("all")
        elif target is not None and all(z in self.spaces for z in self.universe if z) and any(within([target], self.spaces[z])
                                                                                             for z in rule.dst_zones if z in self.spaces):  # fmt: skip
            verdicts.append("all")
        elif target is not None and all(z in self.spaces for z in rule.dst_zones) and \
                not any(within([target], self.spaces[z]) for z in rule.dst_zones) and \
                any(within([target], space) for space in self.spaces.values()):  # fmt: skip
            verdicts.append("none")
        else:
            verdicts.append("some")
        if "none" in verdicts:
            return "none"
        return "all" if verdicts == ["all", "all"] else "some"

    # -- output ------------------------------------------------------------------------------

    def run(self) -> str:
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {origin for _, origin in self.nat_collections}
        for rule in self.p.rules:
            dnat = rule.source_ids.get("azurefw.dnat", "") if self.native else ""
            if dnat and dnat in written and rule.enabled:
                # (what a DNAT rule translates, Azure Firewall allows by itself: the rule of the model that says so is that DNAT rule)
                self.report.item("rule", rule.origin).emitted_as.append(f"DNAT rule {dnat}")
                continue
            self._rule(rule)
        self._intrazone()
        self._default()
        groups = self._groups()
        resources: List[Dict[str, Any]] = [{
            "type": "Microsoft.Network/firewallPolicies", "apiVersion": API_VERSION, "name": self.name,
            "location": "[parameters('location')]", "tags": {"generator": "FWShift"},
            "properties": dict({"sku": {"tier": "Standard"}, "threatIntelMode": "Alert"},
                               **({"dnsSettings": {"enableProxy": True}} if self.fqdn else {})),
        }]  # fmt: skip
        previous = f"[resourceId('Microsoft.Network/firewallPolicies', '{self.name}')]"
        for group_name, priority, collections in groups:
            resources.append({
                "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups", "apiVersion": API_VERSION,
                "name": f"{self.name}/{group_name}", "dependsOn": [previous],
                "properties": {"priority": priority, "ruleCollections": collections},
            })  # fmt: skip
            # (groups of one policy are deployed one after the other: Azure refuses changes to a policy in parallel)
            previous = f"[resourceId('Microsoft.Network/firewallPolicies/ruleCollectionGroups', '{self.name}', '{group_name}')]"
        self._notes()
        template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "metadata": {"generator": "FWShift", "comment": "Generated by FWShift - review the conversion report before deploying this.",
                         "firewallPolicy": self.name, "notWritten": self.not_written},
            "parameters": {"location": {"type": "string", "defaultValue": "[resourceGroup().location]"}},
            "resources": resources,
        }  # fmt: skip
        return json.dumps(template, indent=2, ensure_ascii=False) + "\n"

    def _groups(self) -> List[Tuple[str, int, List[Dict[str, Any]]]]:
        """The collections in groups of at most 2 MB, DNAT first; priorities in steps of 10 (of 1 where there are many)."""
        out: List[Tuple[str, int, List[Dict[str, Any]]]] = []
        batches: List[Tuple[str, List[Tuple[Dict[str, Any], str]]]] = []
        if self.nat_collections:
            batches.append(("fwshift-dnat", self.nat_collections))
        current: List[Tuple[Dict[str, Any], str]] = []
        size = 0
        for entry in self.collections:
            length = len(json.dumps(entry[0]))
            if current and (size + length > _MAX_GROUP_BYTES or len(current) >= 64901):
                batches.append(("", current))
                current, size = [], 0
            current.append(entry)
            size += length
        if current:
            batches.append(("", current))
        number = 0
        for index, (label, batch) in enumerate(batches):
            if not label:
                number += 1
                label = f"fwshift-network-{number}"
            if index >= _MAX_GROUPS:
                for collection, origin in batch:
                    if origin:
                        self.report.skip("rule" if collection["ruleCollectionType"].endswith("FilterRuleCollection") else "nat", origin,
                                         "AZFW_TOO_LARGE", f"more than {_MAX_GROUPS} rule collection groups of 2 MB; not written")  # fmt: skip
                continue
            step = 10 if 100 + 10 * (len(batch) - 1) <= 65000 else 1
            for position, (collection, origin) in enumerate(batch):
                collection["priority"] = 100 + step * position
                if origin:
                    kind = "nat" if collection["ruleCollectionType"] == "FirewallPolicyNatRuleCollection" else "rule"
                    self.report.item(kind, origin).emitted_as.append(f"rule collection {collection['name']} of group {label}")
            out.append((label, 100 + 100 * index, [c for c, _ in batch]))
        if len(batches) > _MAX_GROUPS:
            self.report.note(Severity.REVIEW, "AZFW_TOO_LARGE",
                             f"the policy needs {len(batches)} rule collection groups of at most 2 MB; Azure allows {_MAX_GROUPS} in a "
                             "policy. The rules of the groups beyond are not written")  # fmt: skip
        return out

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "AZFW_LOAD",
            f"the output is an ARM template (section 10) that creates firewall policy {self.name} with its rule collection groups; "
            "look at it with az deployment group what-if, deploy it with az deployment group create (incremental mode), then "
            "associate the policy with a firewall or a secured hub. Nothing changes before that. Deploying it where a policy of "
            "that name exists changes that policy",
        )  # fmt: skip
        self.report.note(
            Severity.INFO, "AZFW_TARGET_SNAT",
            "Azure Firewall translates the source of what goes to a public address (outside RFC 1918 and RFC 6598, or the private "
            "ranges set on the policy) to its own public address, and, community sources say, the source of DNAT traffic to one of "
            "its private addresses: servers may see other source addresses than with the source",
        )  # fmt: skip
        self.report.note(
            Severity.INFO, "AZFW_TARGET_DEFAULTS",
            "the policy is written with network rules only; after them Azure Firewall still allows the FQDNs of its built-in "
            "infrastructure rule collection, then denies. Threat intelligence is set to Alert, which blocks nothing",
        )  # fmt: skip
        if self.ipv6:
            self.report.note(Severity.INFO, "AZFW_TARGET_IPV6",
                             "the policy holds IPv6; Azure Firewall filters IPv4 only, and the IPv6 parts of the rules are not written "
                             "(blocking rules lose nothing by it: the firewall forwards no IPv6)")  # fmt: skip
        if self.fqdn:
            self.report.note(Severity.INFO, "AZFW_DNS_PROXY",
                             "network rules name FQDNs: the policy enables DNS proxy, which they need. Clients must use the firewall as "
                             "their DNS server for the names to resolve to the same addresses")  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; a rule of Azure Firewall does not choose: its diagnostic settings send the logs "
                             "of every rule (AZFWNetworkRule, AZFWNatRule) to a workspace")  # fmt: skip
