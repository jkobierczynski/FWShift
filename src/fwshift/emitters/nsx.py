# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VMware NSX emitter: neutral model -> the body of one hierarchical PATCH of the Policy API.

Design rules:

* One JSON document for ``PATCH /policy/api/v1/infra``: the services, the groups (in domain ``default``) and one
  new security policy of category Application holding every rule in order. A PATCH creates or updates the
  objects it names and leaves everything else alone.
* The distributed firewall has no zones. A rule of the model between zones is written for the networks behind
  them (``--zone-network``); an allow rule whose zones have no networks given is written disabled.
* Objects of the model become groups (addresses of one IP version per expression, nested groups by path) and
  services (at most 15 ports per entry). Addresses that are a rule's own (a zone's networks cut out, a negation
  worked out) are written in the rule, as NSX allows.
* What the model denies by default becomes a last rule of the policy that drops everything; NSX's own default
  rule allows.
* NAT is on the gateways of NSX, not in the distributed firewall: it is not written.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, ANY_V4, ANY_V6, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, intersect, normalize, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_MAX_PORT_VALUES = 15  # per port list of an entry; a range counts as two
_MAX_LIST = 128  # members of a rule's source, destination or service list
_DOMAIN = "/infra/domains/default"
# Ids of services NSX predefines (a created service of the same id would try to change it).
_NSX_SERVICE_IDS = {
    "HTTP", "HTTPS", "SSH", "DNS", "DNS-UDP", "ICMP-ALL", "ICMPv6-ALL", "NTP", "LDAP", "LDAP-UDP", "LDAP-over-SSL", "RDP",
    "SMTP", "SMTP_TLS", "SNMP", "SNMP-Send", "MySQL", "MS-SQL-S", "MS-SQL-M", "KERBEROS", "AD_Server", "CIM-HTTP", "FTP",
    "TFTP", "Syslog", "Syslog_(TCP)", "Syslog_(UDP)", "Telnet", "POP3", "IMAP", "HTTP-alt",
}  # fmt: skip


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks)  # refuses networks that contradict each other
    # The gateways translate before the distributed firewall sees a connection: it sees the address of the workload.
    # The NAT rules are not written (they belong on the gateway); the rules are written for what they translate to.
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _id(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_.-")
    return cleaned[:64] or "x"


def _port_lists(ports: str) -> List[List[str]]:
    """A port list as lists of at most 15 values, a range counting as two."""
    if not ports:
        return [[]]
    out: List[List[str]] = [[]]
    used = 0
    for part in ports.split(","):
        need = 2 if "-" in part else 1
        if used + need > _MAX_PORT_VALUES:
            out.append([])
            used = 0
        out[-1].append(part)
        used += need
    return out


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "nsx"
        self.taint_a = transform.tainted_addresses(p, keep_dynamic=self.native)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used + list(options.zone_networks))
        self.ids: Set[str] = set()  # of groups and of the policy
        self.service_id_set: Set[str] = {i.lower() for i in _NSX_SERVICE_IDS}
        self.group_ids: Dict[str, str] = {}  # model name -> group id
        self.service_ids: Dict[str, str] = {}
        self.groups: List[Dict[str, Any]] = []
        self.services: List[Dict[str, Any]] = []
        self.rules: List[Dict[str, Any]] = []
        self.rule_ids: Set[str] = set()
        self.zoned = 0

    def _unique(self, base: str, taken: Set[str]) -> str:
        candidate, counter = base, 2
        while candidate.lower() in taken:
            suffix = f"-{counter}"
            candidate = base[: 64 - len(suffix)] + suffix
            counter += 1
        taken.add(candidate.lower())
        return candidate

    # -- objects ------------------------------------------------------------------

    def group_path(self, name: str, stack: Tuple[str, ...] = ()) -> str:
        if name in self.group_ids:
            return f"{_DOMAIN}/groups/{self.group_ids[name]}"
        ident = self._unique(_id(self.options.object_prefix + name), self.ids)
        self.group_ids[name] = ident
        body: Dict[str, Any] = {"resource_type": "Group", "id": ident, "display_name": (self.options.object_prefix + name)[:255]}
        expression: List[Dict[str, Any]] = []
        description = ""
        if name in self.taint_a:
            description = f"FWSHIFT PLACEHOLDER: {self.taint_a[name]}"
        elif name in self.p.address_groups and self.p.address_groups[name].dynamic_filter.startswith("nsx:") and self.native:
            expression = json.loads(self.p.address_groups[name].dynamic_filter[4:])
            for item in expression:
                if isinstance(item, dict) and item.get("resource_type") == "PathExpression":
                    item["paths"] = [self.group_path(str(path)[len("fwshift-group:"):], stack + (name,))
                                     if str(path).startswith("fwshift-group:") else path for path in item.get("paths") or []]  # fmt: skip
            description = self.p.address_groups[name].description
        elif name in self.p.address_groups:
            group = self.p.address_groups[name]
            description = group.description
            literals: Dict[int, List[str]] = {4: [], 6: []}
            nested: List[str] = []
            for member in group.members:
                if member in self.p.address_groups and member not in stack:
                    nested.append(self.group_path(member, stack + (name,)))
                    continue
                intervals, _ = transform.known_intervals(self.p, member)
                for interval in intervals:
                    literals[interval[0]].append(interval_text(interval))
            expression = self._expression(literals, nested)
        else:
            intervals, _ = transform.known_intervals(self.p, name)
            literals = {4: [], 6: []}
            for interval in intervals:
                literals[interval[0]].append(interval_text(interval))
            expression = self._expression(literals, [])
            if name in self.p.addresses:
                description = self.p.addresses[name].description
        body["expression"] = expression
        if description:
            body["description"] = description[:1024]
        self.groups.append({"resource_type": "ChildGroup", "Group": body})
        return f"{_DOMAIN}/groups/{ident}"

    @staticmethod
    def _expression(literals: Dict[int, List[str]], nested: List[str]) -> List[Dict[str, Any]]:
        parts: List[Dict[str, Any]] = []
        for version in (4, 6):
            if literals[version]:
                parts.append({"resource_type": "IPAddressExpression", "ip_addresses": transform.dedupe(literals[version])})
        if nested:
            parts.append({"resource_type": "PathExpression", "paths": transform.dedupe(nested)})
        out: List[Dict[str, Any]] = []
        for index, part in enumerate(parts):
            if index:
                out.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
            out.append(part)
        return out

    def service_path(self, name: str, stack: Tuple[str, ...] = ()) -> str:
        if name in self.service_ids:
            return f"/infra/services/{self.service_ids[name]}"
        builtin = (self.p.services.get(name) or self.p.service_groups.get(name))
        if self.native and builtin is not None and builtin.builtin == "nsx" and name not in self.taint_s:
            self.service_ids[name] = name  # NSX has it: referred to by its id
            return f"/infra/services/{name}"
        ident = self._unique(_id(self.options.object_prefix + name), self.service_id_set)
        self.service_ids[name] = ident
        body: Dict[str, Any] = {"resource_type": "Service", "id": ident, "display_name": (self.options.object_prefix + name)[:255]}
        entries: List[Dict[str, Any]] = []
        if name in self.taint_s:
            body["description"] = f"FWSHIFT PLACEHOLDER: {self.taint_s[name]}"
            entries = [{"resource_type": "IPProtocolServiceEntry", "id": "placeholder", "protocol_number": 255}]
        elif name in self.p.service_groups:
            for index, member in enumerate(self.p.service_groups[name].members):
                if member in stack:
                    continue
                entries.append({"resource_type": "NestedServiceServiceEntry", "id": f"nested-{index + 1}",
                                "nested_service_path": self.service_path(member, stack + (name,))})  # fmt: skip
        else:
            entries = self.entries(self.p.services[name].entries, name)
        body["service_entries"] = entries
        self.services.append({"resource_type": "ChildService", "Service": body})
        return f"/infra/services/{ident}"

    def entries(self, entries: List[ServiceEntry], label: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                for dst in _port_lists(entry.dst_ports):
                    for src in _port_lists(entry.src_ports):
                        out.append({"resource_type": "L4PortSetServiceEntry", "l4_protocol": entry.protocol.value.upper(),
                                    "destination_ports": dst, "source_ports": src})  # fmt: skip
            elif entry.protocol == Protocol.SCTP:
                out.append({"resource_type": "IPProtocolServiceEntry", "protocol_number": 132})
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                item: Dict[str, Any] = {"resource_type": "ICMPTypeServiceEntry",
                                        "protocol": "ICMPv4" if entry.protocol == Protocol.ICMP else "ICMPv6"}  # fmt: skip
                if entry.icmp_type is not None:
                    item["icmp_type"] = entry.icmp_type
                    if entry.icmp_code is not None:
                        item["icmp_code"] = entry.icmp_code
                out.append(item)
            elif entry.ip_protocol:
                out.append({"resource_type": "IPProtocolServiceEntry", "protocol_number": entry.ip_protocol})
        for index, item in enumerate(out):
            item["id"] = f"{_id(label)[:40]}-{index + 1}"
        return out

    # -- rules --------------------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[Dict[int, List[Interval]]]:
        """The addresses of one side, per IP version; None when they are not known here."""
        found: Dict[int, List[Interval]] = {4: [], 6: []}
        for member in members:
            if member == ANY:
                found = {4: [FULL_V4], 6: [FULL_V6]}
                break
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"the {side} '{member}' holds members NSX finds itself; with the zones of the "
                                "rule it cannot be cut down to their networks"))  # fmt: skip
                return None
            for interval in intervals:
                found[interval[0]].append(interval)
        found = {v: normalize(ivs) for v, ivs in found.items()}
        if negated:
            found = {4: subtract([FULL_V4], found[4]), 6: subtract([FULL_V6], found[6])}
        return found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: Dict[int, List[Interval]],
                 reasons: List[transform.Reason]) -> Dict[int, List[Interval]]:  # fmt: skip
        """The addresses of one side, kept to the zones of the rule (as the Barracuda emitter does)."""
        allow = rule.action == Action.ALLOW
        missing = [zone for zone in zones if zone not in self.spaces]
        if allow:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and a rule of the distributed firewall "
                                f"names no zone: give the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
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
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a rule of the distributed "
                            "firewall names no zone, and it blocks that traffic in every zone. Give the networks behind every "
                            "zone with --zone-network to keep it to its zones")  # fmt: skip
            return found
        away = normalize([i for zone in others for i in self.spaces[zone]])
        kept = {v: subtract(ivs, away) for v, ivs in found.items()}
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
        return kept

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Tuple[List[str], bool]]:
        """What a rule's side is written as (paths, addresses or ANY) and whether it is excluded; None if it is
        empty (the rule matches nothing)."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        zones = rule.src_zones if source else rule.dst_zones
        side = "source" if source else "destination"
        if ANY in zones or (not source and rule.egress_implied):
            if ANY in members:
                return (["ANY"], False) if not negated else None
            out: List[str] = []
            for member in members:
                if member in (ANY_V4, ANY_V6):
                    out.append(member)
                elif member in self.p.addresses or member in self.p.address_groups:
                    out.append(self.group_path(member))
                else:
                    interval = parse_literal(member)
                    if interval is None:
                        reasons.append(("ADDRESS_NOT_WRITTEN", f"'{member}' cannot be written"))
                        continue
                    out.append(interval_text(interval))
            return transform.dedupe(out), negated
        self.zoned += 1
        found = self._resolve(members, negated, side, reasons)
        if found is None:
            return ([self.group_path(m) if m in self.p.address_groups or m in self.p.addresses else m for m in members]
                    or ["ANY"], negated)  # (the rule is written disabled)  # fmt: skip
        kept = self._confine(rule, side, zones, found, reasons)
        if kept == {4: [FULL_V4], 6: [FULL_V6]}:
            return ["ANY"], False
        literals = [interval_text(i) for v in (4, 6) for i in kept[v]]
        if not literals:
            return None
        if len(literals) > _MAX_LIST:
            name = f"{rule.name}.{side}"
            ident = self._unique(_id(self.options.object_prefix + name), self.ids)
            per = {v: [interval_text(i) for i in kept[v]] for v in (4, 6)}
            self.groups.append({"resource_type": "ChildGroup", "Group": {
                "resource_type": "Group", "id": ident, "display_name": (self.options.object_prefix + name)[:255],
                "expression": self._expression(per, [])}})  # fmt: skip
            return [f"{_DOMAIN}/groups/{ident}"], False
        return literals, False

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service cannot be written: a rule of NSX has no negation of services"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a rule of the distributed firewall names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written as a rule for every pair of its zones, which blocks more")  # fmt: skip
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": a group of NSX holds addresses; a "
                            "domain name needs a context profile, which is not written"))  # fmt: skip
        services, service_entries = self._services(rule, reasons)
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        if sources is None or destinations is None:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation and the networks of its zones, a side of the rule holds no address", Severity.INFO)  # fmt: skip
            return
        reasons = list(dict.fromkeys(reasons))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        action = {Action.ALLOW: "ALLOW", Action.DROP: "DROP"}.get(rule.action, "REJECT")
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value} becomes REJECT, which answers the client only")  # fmt: skip
        ident = self._unique(_id(rule.name), self.rule_ids)
        body: Dict[str, Any] = {
            "resource_type": "Rule", "id": ident, "display_name": rule.name[:255],
            "sequence_number": 10 * (len(self.rules) + 1),
            "source_groups": sources[0], "sources_excluded": sources[1],
            "destination_groups": destinations[0], "destinations_excluded": destinations[1],
            "services": services, "action": action, "direction": "IN_OUT",
            "ip_protocol": rule.handling.get("nsx.ip_protocol", "IPV4_IPV6") if self.native else "IPV4_IPV6",
            "scope": self._scope(rule), "logged": bool(rule.log_start or rule.log_end),
            "disabled": bool(reasons) or not rule.enabled, "tag": re.sub(r"[^A-Za-z0-9_-]", "_", rule.name)[:32],
        }  # fmt: skip
        if service_entries:
            body["service_entries"] = service_entries
        notes = []
        if reasons:
            notes.append("FWSHIFT disabled, see the report: " + "; ".join(message for _, message in reasons))
        elif not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            notes.append("disabled by the audit" if by_audit else "disabled in the source")
        if rule.description:
            notes.append(rule.description)
        if notes:
            body["notes"] = " | ".join(notes)[:2048]
        for key in ("source_groups", "destination_groups", "services"):
            if len(body[key]) > _MAX_LIST:
                transform.disable_rule(self.report, rule, [("LIST_TOO_LONG", f"more than {_MAX_LIST} entries in {key}")])
                body["disabled"] = True
        self.rules.append(body)
        item.emitted_as.append(f"rule {ident}")

    def _scope(self, rule: Rule) -> List[str]:
        """Where the rule is enforced: everywhere, or for an NSX source the groups it was applied to there."""
        names = rule.handling.get("nsx.applied_to", "") if self.native else ""
        if not names:
            return ["ANY"]
        return [self.group_path(name) for name in names.split("\x1f") if name]

    def _fqdn(self, members: List[str]) -> List[str]:
        """The host name objects among the members and in the groups they hold."""
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

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Tuple[List[str], List[Dict[str, Any]]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
                return ["ANY"], []
            if not entries:
                return ["ANY"], []
            if any(e.protocol == Protocol.SCTP and (e.dst_ports or e.src_ports) for e in entries):
                reasons.append(("SERVICE_SCTP", "SCTP ports: a service of NSX matches TCP and UDP ports only"))
            return [], self.entries(entries, f"{rule.name}.app")
        if rule.services == [ANY]:
            return ["ANY"], []
        paths: List[str] = []
        for name in rule.services:
            flat = transform.flatten_services(self.p, name) or []
            if any(e.protocol == Protocol.SCTP and (e.dst_ports or e.src_ports) for e in flat):
                reasons.append(("SERVICE_SCTP", f"service '{name}' has SCTP ports: a service of NSX matches TCP and UDP ports only"))
            if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in flat):
                return ["ANY"], []
            paths.append(self.service_path(name))
        return transform.dedupe(paths), []

    # -- output -------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        if self.p.default_interzone != Action.ALLOW:
            self.rules.append({
                "resource_type": "Rule", "id": self._unique("fwshift-default-deny", self.rule_ids),
                "display_name": "fwshift-default-deny", "sequence_number": 10 * (len(self.rules) + 1),
                "source_groups": ["ANY"], "sources_excluded": False, "destination_groups": ["ANY"], "destinations_excluded": False,
                "services": ["ANY"], "action": "DROP",
                "direction": "IN_OUT", "ip_protocol": "IPV4_IPV6", "scope": ["ANY"], "logged": False, "disabled": False,
                "notes": "FWShift: what no rule above allows is dropped, as the source policy does",
            })  # fmt: skip
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: NAT of NSX is on the Tier-0 and Tier-1 gateways, outside the distributed firewall. "
                             "Set it up there; the rules were written for the addresses it translates to, which is what the "
                             "distributed firewall sees")  # fmt: skip
        self._notes()
        policy_id = self._unique(_id(self.options.target_policy or "FWShift"), self.ids)
        policy = {
            "resource_type": "SecurityPolicy", "id": policy_id, "display_name": (self.options.target_policy or "FWShift")[:255],
            "category": "Application", "sequence_number": 1, "stateful": True, "scope": ["ANY"],
            "description": "Generated by FWShift - review the conversion report before loading this.",
            "rules": self.rules,
        }  # fmt: skip
        domain = {"resource_type": "ChildResourceReference", "id": "default", "target_type": "Domain",
                  "children": self.groups + [{"resource_type": "ChildSecurityPolicy", "SecurityPolicy": policy}]}  # fmt: skip
        body = {"resource_type": "Infra", "children": self.services + [domain]}
        return json.dumps(body, indent=2, ensure_ascii=False) + "\n"

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW,
            "NSX_LOAD",
            "the output is the body of one hierarchical PATCH of the Policy API: curl -X PATCH -H 'Content-Type: "
            "application/json' --data @FILE https://MANAGER/policy/api/v1/infra. It creates or updates the services, the "
            "groups and one security policy of category Application (sequence number 1: give it the place you want), and "
            "leaves everything else alone, except objects of the same id, which it changes: give --target-prefix to keep "
            "the new ones apart. There is no dry run: load it on a lab manager first",
        )
        if self.p.default_interzone != Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "NSX_DEFAULT_DENY",
                "the source denies what no rule allows: the policy ends in fwshift-default-deny, which drops every "
                "connection no rule above it allows, for all workloads. It ends the Application category: policies after it "
                "and the default layer-3 rule are never reached",
            )
        if self.p.default_intrazone != self.p.default_interzone:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_DEFAULT",
                "the source treats traffic inside a zone and between zones differently when no rule matches; the "
                "distributed firewall has no zones, and the default of traffic between zones was written",
            )
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                             "written for that: " + ", ".join(open_zones))  # fmt: skip
