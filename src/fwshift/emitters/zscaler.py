# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Zscaler Internet Access (ZIA) emitter: neutral model -> a shell script that creates IP groups, network services and
Cloud Firewall filtering rules through the ZIA API, with curl and jq.

Design rules:

* ZIA filters traffic from its locations (and Client Connector) to the internet, nothing else. The zones inside
  (``--inside-zone``; from a ZIA source every zone but ``internet``) are locations of the tenant, by the same name; the
  others are the internet. A rule from inside to outside is written; a rule from outside (inbound) or between zones
  inside is not, since that traffic never passes ZIA: ZSCALER_INBOUND and ZSCALER_INTERNAL say what is lost. Without
  ``--inside-zone`` every zone is taken as a location and the destination zones are not looked at.
* A rule names the locations of its source zones, looked up by name when the script runs (at most eight); a rule
  from every inside zone names none and applies to every location and to Client Connector traffic.
* Addresses are IPv4: an IPv6 part is not written (APPROX for an allow rule, REVIEW for a blocking one). A side that is
  one address object of the model becomes an IP group; anything else is written into the rule (``srcIps``,
  ``destAddresses``, which take ranges and, as destinations, FQDNs). Negation is written as the addresses left.
* A custom network service holds TCP and UDP ports (source ports with destination ports); ICMP, GRE and ESP are ZIA's
  predefined ICMP_ANY, GRE_PROTOCOL and ESP_PROTOCOL, looked up by name. ICMP types, ICMPv6, SCTP and other protocols
  cannot be written: such a rule is created disabled.
* Rules are created at ``--policy-id-start`` (default 1) and below, in the order of the model, with the prefix
  ``--object-prefix`` (default ``fws-``) on every name. A rule that cannot be written as it is, is created disabled,
  with placeholders (192.0.0.8) where a side cannot be written. Nothing is changed or deleted; the script refuses a
  name that is taken, and writes down what it created. The default rule of the tenant cannot be set through the API:
  where the model blocks what no rule matches, a rule that blocks everything follows the converted rules, disabled.
* Activation (``POST /status/activate``) is left to the person. A legacy API session that ends (logout or its
  timeout) activates what it changed: ZSCALER_LOAD says so.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, ANY_V6, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..names import ZSCALER, ZSCALER_RULE, clean
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity

INTERNET = "internet"
ROAMING = "road-warrior"
_PLACEHOLDER = "192.0.0.8"
_MAX_LOCATIONS = 8
_MAX_ADDRESSES = 1000
_PREDEFINED = {"icmp": "ICMP_ANY", 47: "GRE_PROTOCOL", 50: "ESP_PROTOCOL"}
_ACTION = {Action.ALLOW: "ALLOW", Action.DROP: "BLOCK_DROP", Action.DENY: "BLOCK_DROP", Action.RESET_CLIENT: "BLOCK_RESET",
           Action.RESET_SERVER: "BLOCK_RESET", Action.RESET_BOTH: "BLOCK_RESET"}  # fmt: skip


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


class _Step:
    """One call of the script: a lookup of something the tenant has, or the creation of something new."""

    def __init__(self, kind: str, path: str, name: str, var: str, body: Optional[Dict[str, Any]] = None) -> None:
        self.kind, self.path, self.name, self.var, self.body = kind, path, name, var, body


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "zscaler"
        self.prefix = options.object_prefix if options.object_prefix else "fws-"
        self.start = options.policy_id_start or 1
        if self.start < 1:
            raise FwshiftError("--policy-id-start: the order of a ZIA rule starts at 1")
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p, keep={n for n, s in p.services.items() if s.builtin == "zscaler" and s.entries})
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used)
        self.zones_known = True
        if options.inside_zones:
            missing = [z for z in options.inside_zones if z not in self.universe]
            if missing:
                raise FwshiftError(f"--inside-zone {missing[0]}: no such zone in the policy")
            self.inside = list(options.inside_zones)
        elif self.native or (p.vendor == "meraki" and INTERNET in self.universe):
            self.inside = [z for z in self.universe if z != INTERNET]  # (both name the outside "internet")
        else:
            self.inside = list(self.universe)
            self.zones_known = False
        self.outside = [z for z in self.universe if z not in self.inside]
        self.steps: List[_Step] = []
        self.lookups: Dict[Tuple[str, str], str] = {}
        self.groups: Dict[Tuple[str, str], str] = {}  # (side, object of the model) -> variable of the IP group
        self.service_vars: Dict[str, List[str]] = {}
        self.object_names: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.rules: List[Tuple[str, Dict[str, Any]]] = []  # (name, body), in the order of the model
        self.not_written: List[str] = []
        self.lost: Dict[str, int] = {"inbound": 0, "internal": 0}
        self.locations_used: Set[str] = set()
        self.v6_dropped = False

    # -- names, steps ---------------------------------------------------------------------------------

    def _var(self) -> str:
        return f"ID_{len(self.steps) + 1}"

    def _name(self, label: str, rules: Any, taken: Set[str]) -> str:
        base = clean(f"{self.prefix}{label}", rules)
        name, counter = base, 2
        while name.lower() in taken:
            tail = f"_{counter}"
            name = base[: rules.max_len - len(tail)].rstrip() + tail
            counter += 1
        taken.add(name.lower())
        return name

    def _lookup(self, path: str, name: str) -> str:
        key = (path, name)
        if key not in self.lookups:
            var = self._var()
            self.steps.append(_Step("need", path, name, var))
            self.lookups[key] = var
        return self.lookups[key]

    def _create(self, path: str, label: str, body: Dict[str, Any]) -> str:
        var = self._var()
        name = self._name(label, ZSCALER, self.object_names)
        body = {"name": name, **body}
        self.steps.append(_Step("create", path, name, var, body))
        return var

    # -- zones ----------------------------------------------------------------------------------------

    def _locations(self, rule: Rule, zones: List[str], reasons: List[transform.Reason]) -> Optional[List[str]]:
        """The variables of the locations a rule names; [] for all of them."""
        if ANY in zones or set(zones) >= set(self.inside):
            return []
        named = [z for z in zones if z != ROAMING]
        if len(named) != len(zones):
            reasons.append(("ZSCALER_ROAD_WARRIOR", "Client Connector traffic outside a location (zone road-warrior) together with some "
                            "locations only: a rule cannot name it"))  # fmt: skip
            return None
        if len(named) > _MAX_LOCATIONS:
            reasons.append(("ZSCALER_LOCATIONS", f"more than {_MAX_LOCATIONS} locations"))
            return None
        self.locations_used.update(named)
        return [self._lookup("/locations", z) for z in named]

    # -- addresses ------------------------------------------------------------------------------------

    def _resolve(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Tuple[List[Interval], List[str], bool]]:
        """(IPv4 addresses, FQDNs, every address) of one side; None when it cannot be written."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        side = "source" if source else "destination"
        if ANY in members and not negated:
            return [FULL_V4], [], True
        found: List[Interval] = []
        names: List[str] = []
        for member in members:
            if member == ANY:
                found += [FULL_V4, FULL_V6]
                continue
            if member in (ANY_V4, ANY_V6):
                found.append(FULL_V4 if member == ANY_V4 else FULL_V6)
                continue
            if member in self.taint_a:
                return None  # (blocking_reasons says why)
            address = self.p.addresses.get(member)
            if address is not None and address.kind == AddressKind.FQDN:
                if source or negated:
                    reasons.append(("FQDN_NOT_SUPPORTED", f"host name {address.value} as the {side}: ZIA takes FQDNs as destinations only"))
                    return None
                names.append(address.value)
                continue
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member in self.p.address_groups and source:
                    reasons.append(("FQDN_NOT_SUPPORTED", f"'{member}' holds host names, which ZIA takes as destinations only"))
                    return None
                if member in self.p.address_groups:
                    names += self._group_names(member)
                else:
                    reasons.append(("UNCONVERTIBLE_OBJECT", f"'{member}' cannot be read"))
                    return None
            found += intervals
        found = normalize(found)
        if negated:
            found = subtract([FULL_V4, FULL_V6], found)
            self.report.add("rule", rule.origin, Severity.INFO, "NEGATION_EXPANDED",
                            f"ZIA has no negation: 'not {side} {', '.join(members)[:80]}' is written as the addresses that are left")  # fmt: skip
        v4 = [i for i in found if i[0] == 4]
        if len(v4) != len(found):
            self.v6_dropped = True
            if rule.action == Action.ALLOW:
                self.report.add("rule", rule.origin, Severity.APPROX, "ZSCALER_IPV6",
                                f"the IPv6 addresses of the {side} are not written (ZIA's addresses in a rule and in IP groups are "
                                "IPv4): the rule allows less")  # fmt: skip
            else:
                self.report.add("rule", rule.origin, Severity.REVIEW, "ZSCALER_IPV6",
                                f"the IPv6 addresses of the {side} are not written (ZIA's addresses in a rule and in IP groups are "
                                "IPv4): what the rule blocks of IPv6 is not blocked")  # fmt: skip
        return v4, names, v4 == [FULL_V4] and not names

    def _group_names(self, group: str, seen: Optional[Set[str]] = None) -> List[str]:
        seen = seen or set()
        out: List[str] = []
        for member in self.p.address_groups[group].members:
            address = self.p.addresses.get(member)
            if address is not None and address.kind == AddressKind.FQDN:
                out.append(address.value)
            elif member in self.p.address_groups and member not in seen:
                out += self._group_names(member, seen | {group})
        return out

    def _side(self, rule: Rule, source: bool, cell: Tuple[List[Interval], List[str], bool]) -> Dict[str, Any]:
        """The fields of a rule for one side: an IP group, or addresses in the rule."""
        intervals, names, every = cell
        if every:
            return {}
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        side = "source" if source else "destination"
        literals = [interval_text(i) for i in intervals] + names
        if len(members) == 1 and not negated and members[0] != ANY and parse_literal(members[0]) is None:
            key = (side, members[0])
            if key not in self.groups:
                if source:
                    self.groups[key] = self._create("/ipSourceGroups", members[0], {"ipAddresses": literals, "description": "FWShift"})
                else:
                    kind = "DSTN_FQDN" if names and not intervals else "DSTN_IP"
                    if names and intervals:
                        return {"destAddresses": literals}  # (a group is of addresses or of FQDNs, not both)
                    self.groups[key] = self._create("/ipDestinationGroups", members[0], {"type": kind, "addresses": literals,
                                                                                         "description": "FWShift"})  # fmt: skip
            return {"srcIpGroups" if source else "destIpGroups": [{"id": self.groups[key]}]}
        return {"srcIps" if source else "destAddresses": literals}

    # -- services -------------------------------------------------------------------------------------

    def _entries(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[Tuple[str, List[ServiceEntry]]]]:
        """(label, entries) per service of the rule; [] for every service; None when they cannot be read."""
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: ZIA has no negation"))
            return None
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [e for _, found in lowered for e in found]
            return [(f"{rule.name}.svc", entries)] if entries else None
        if rule.services == [ANY]:
            return []
        out: List[Tuple[str, List[ServiceEntry]]] = []
        for name in rule.services:
            if name in self.taint_s:
                return None
            flat = transform.flatten_services(self.p, name)
            if flat is None:
                reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                return None
            out.append((name, flat))
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for _, flat in out for e in flat):
            return []
        return out

    def _service_ids(self, rule: Rule, services: List[Tuple[str, List[ServiceEntry]]], reasons: List[transform.Reason]) -> List[str]:
        out: List[str] = []
        for label, entries in services:
            if label in self.service_vars:
                out += self.service_vars[label]
                continue
            found = self.p.services.get(label)
            if self.native and found is not None and found.builtin == "zscaler":
                self.service_vars[label] = [self._lookup("/networkServices", label)]
                out += self.service_vars[label]
                continue
            variables: List[str] = []
            ports: Dict[Tuple[str, str], Optional[List[Dict[str, int]]]] = {}  # (Tcp or Udp, source ports) -> ports, None for all
            for entry in entries:
                if entry.protocol in (Protocol.TCP, Protocol.UDP):
                    ranges = [_range(p) for p in (entry.dst_ports + "," + entry.src_ports).split(",") if p]
                    if any(r is None for r in ranges):
                        reasons.append(("SERVICE_NOT_WRITTEN", "port 0, which ZIA does not take"))
                        return []
                    key = ("Tcp" if entry.protocol == Protocol.TCP else "Udp", entry.src_ports)
                    known = ports.setdefault(key, [])
                    if not entry.dst_ports:
                        ports[key] = None
                    elif known is not None:
                        known += [r for r in (_range(p) for p in entry.dst_ports.split(",")) if r is not None]
                elif entry.protocol == Protocol.ICMP and entry.icmp_type is None and entry.icmp_code is None:
                    variables.append(self._lookup("/networkServices", _PREDEFINED["icmp"]))
                elif entry.protocol == Protocol.IP and entry.ip_protocol in (47, 50):
                    variables.append(self._lookup("/networkServices", _PREDEFINED[entry.ip_protocol]))
                else:
                    what = ("an ICMP type" if entry.protocol == Protocol.ICMP else "ICMPv6" if entry.protocol == Protocol.ICMP6 else
                            "SCTP" if entry.protocol == Protocol.SCTP else f"IP protocol {entry.ip_protocol}")  # fmt: skip
                    reasons.append(("SERVICE_NOT_WRITTEN", f"{what}: a network service of ZIA holds TCP and UDP ports, and the "
                                    "predefined ICMP_ANY, GRE_PROTOCOL and ESP_PROTOCOL"))  # fmt: skip
                    return []
            pieces: Dict[str, Dict[str, Any]] = {}  # source ports -> body
            for (word, sources), listed in ports.items():
                body = pieces.setdefault(sources, {})
                body[f"dest{word}Ports"] = _merge(listed) if listed is not None else [{"start": 1, "end": 65535}]
                if sources:
                    body[f"src{word}Ports"] = _merge([r for r in (_range(p) for p in sources.split(",")) if r is not None])
            for index, fields in enumerate(pieces.values()):
                body = {key: fields[key] for key in sorted(fields)}
                body["type"] = "CUSTOM"
                body["description"] = "FWShift"
                variables.append(self._create("/networkServices", label + (f".{index + 1}" if len(pieces) > 1 else ""), body))
            self.service_vars[label] = list(dict.fromkeys(variables))
            out += self.service_vars[label]
        return list(dict.fromkeys(out))

    # -- rules ----------------------------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        if rule.source_ids.get("zscaler.default") and self.native:
            self.report.skip("rule", rule.origin, "ZSCALER_DEFAULT_RULE",
                             f"the default rule of the source ({_ACTION.get(rule.action, 'BLOCK_DROP')}): the API cannot change the "
                             "default rule; set its action by hand if the tenant's differs", Severity.REVIEW)  # fmt: skip
            return
        if rule.source_ids.get("zscaler.predefined") and self.native:
            self.report.skip("rule", rule.origin, "ZSCALER_PREDEFINED", "a predefined rule: every tenant has it, and it cannot be created; "
                             "its place among the converted rules is the tenant's", Severity.REVIEW)  # fmt: skip
            return
        if rule.scope == RuleScope.INTRAZONE:
            self.lost["internal"] += 1
            self.report.skip("rule", rule.origin, "ZSCALER_INTERNAL", "a rule for traffic inside a zone, which does not pass ZIA")
            return
        src = rule.src_zones
        dst = rule.dst_zones
        from_inside = [ANY] if ANY in src else [z for z in src if z in self.inside]
        from_outside = ANY in src or any(z in self.outside for z in src)
        if from_outside:
            self.lost["inbound"] += 1
            if not from_inside:
                deny = rule.action != Action.ALLOW
                self.report.skip("rule", rule.origin, "ZSCALER_INBOUND",
                                 "a rule for traffic from the internet: ZIA does not let in connections from the internet"
                                 + (", so what it blocks stays blocked" if deny else "; what it allows has to reach the servers another way"),
                                 Severity.INFO if deny else Severity.REVIEW)  # fmt: skip
                return
            if self.zones_known and ANY not in src:
                self.report.add("rule", rule.origin, Severity.INFO if rule.action != Action.ALLOW else Severity.REVIEW, "ZSCALER_INBOUND",
                                "the part of the rule from the internet is not written: ZIA does not let in connections from there")  # fmt: skip
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        for given, code, label in ((rule.users, "USER_MATCH", "source user match"), (rule.url_categories, "URL_CATEGORY", "URL category match")):
            if given != [ANY]:
                reasons.append((code, f"{label} {', '.join(given)[:80]} is not converted"))
        if self.zones_known:
            to_outside = ANY in dst or any(z in self.outside for z in dst)
            to_inside = ANY in dst or any(z in self.inside for z in dst)
            if not to_outside:
                self.lost["internal"] += 1
                self.report.skip("rule", rule.origin, "ZSCALER_INTERNAL",
                                 "a rule between zones inside: traffic between locations does not pass ZIA, and is not filtered there")  # fmt: skip
                return
            if to_inside:
                self.lost["internal"] += 1
                self.report.add("rule", rule.origin, Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW, "ZSCALER_INTERNAL",
                                "written for traffic to the internet only: the part between zones inside does not pass ZIA")  # fmt: skip
            if ANY not in dst and not set(dst) >= set(self.outside):
                self.report.add("rule", rule.origin, Severity.REVIEW if rule.action == Action.ALLOW else Severity.APPROX, "ZSCALER_DESTINATION_ZONE",
                                f"destination zones {', '.join(dst)[:80]}: ZIA tells no zones outside apart, the rule is written for "
                                "traffic to the internet as a whole")  # fmt: skip
        locations = self._locations(rule, from_inside, reasons)
        source = self._resolve(rule, True, reasons)
        destination = self._resolve(rule, False, reasons)
        services = self._entries(rule, reasons)
        body: Dict[str, Any] = {}
        if locations:
            body["locations"] = [{"id": v} for v in locations]
        for cell, is_source in ((source, True), (destination, False)):
            key = "srcIps" if is_source else "destAddresses"
            if cell is None:
                body[key] = [_PLACEHOLDER]
                reasons = reasons or [("UNCONVERTIBLE_OBJECT", f"the {key} cannot be written")]
            elif not cell[0] and not cell[1] and not cell[2]:
                if not reasons:
                    self.report.skip("rule", rule.origin, "ZSCALER_IPV6_ONLY", "the rule matches IPv6 only on one side, which ZIA's rules "
                                     "cannot name: not written")  # fmt: skip
                    self.not_written.append(f"{rule.name}: IPv6 only")
                    return
                body[key] = [_PLACEHOLDER]
            else:
                if len(cell[0]) + len(cell[1]) > _MAX_ADDRESSES:
                    reasons.append(("ZSCALER_ADDRESSES", f"more than {_MAX_ADDRESSES} addresses on a side"))
                    body[key] = [_PLACEHOLDER]
                    continue
                body.update(self._side(rule, is_source, cell))
        if services:
            ids = self._service_ids(rule, services, reasons)
            if ids:
                body["nwServices"] = [{"id": v} for v in ids]
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION", f"action {rule.action.value}: written as BLOCK_RESET")
        reasons = list(dict.fromkeys(reasons))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        action = _ACTION[rule.action]
        if self.native and rule.action == Action.DENY:
            action = "BLOCK_ICMP"  # (what the parser reads as deny)
        name = self._name(rule.name, ZSCALER_RULE, self.rule_names)
        description = " ".join(rule.description.split())
        if reasons:
            description = f"FWSHIFT inactive, see the report. {description}".strip()
        head: Dict[str, Any] = {"name": name, "order": 0, "rank": 7, "action": action, "state": "ENABLED" if rule.enabled and not reasons else "DISABLED"}
        if description:
            head["description"] = description[:10240]
        self.rules.append((name, {**head, **body}))
        self.report.item("rule", rule.origin).emitted_as.append(name)

    def _default(self) -> None:
        last = self.p.rules[-1] if self.p.rules else None
        if self.native and last is not None and last.source_ids.get("zscaler.default"):
            return
        if self.p.default_interzone == Action.ALLOW:
            self.report.note(Severity.REVIEW, "ZSCALER_DEFAULT_RULE",
                             "the source allows what no rule matches; the default rule of the tenant decides that traffic, and the API "
                             "cannot change it: set its action to Allow by hand if that was intended")  # fmt: skip
            return
        name = self._name("block the rest", ZSCALER_RULE, self.rule_names)
        self.rules.append((name, {"name": name, "order": 0, "rank": 7, "action": "BLOCK_DROP", "state": "DISABLED",
                                  "description": "FWSHIFT: what the converted policy does not allow. Enable after looking at the rules below"}))  # fmt: skip
        self.report.note(Severity.REVIEW, "ZSCALER_BLOCK_RULE",
                         f"the source blocks what no rule matches. Rule {name} that does so follows the converted rules, disabled: until it "
                         "is enabled, the rules of the tenant below it and its default rule decide that traffic")  # fmt: skip

    # -- output ---------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        if self.rules:
            self._default()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: ZIA translates the source to its own public addresses by itself, and its NAT control "
                             "policy redirects outbound traffic only")  # fmt: skip
        self._notes()
        return self._script()

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "ZSCALER_LOAD",
                         "the output is a shell script for the ZIA API (curl and jq, section 10): it looks up the locations and "
                         "predefined services it names, creates IP groups, network services and firewall filtering rules from order "
                         f"{self.start} on, refuses a name that is taken, and changes or deletes nothing. It does not activate: "
                         "POST /status/activate is left to you, but a legacy API session that ends (logout or timeout) activates "
                         "what it changed. Run it with DRY_RUN=1 first")  # fmt: skip
        if not self.zones_known and self.universe:
            self.report.note(Severity.REVIEW, "ZSCALER_INSIDE",
                             "no --inside-zone: every zone was taken as a location of ZIA, and every rule as one to the internet; ZIA "
                             "does not filter traffic between locations or from the internet. Name the zones inside with --inside-zone")  # fmt: skip
        if self.lost["inbound"] or self.lost["internal"]:
            self.report.note(Severity.REVIEW, "ZSCALER_LOST",
                             f"ZIA filters traffic from locations to the internet only: {self.lost['inbound']} rules for traffic from the "
                             f"internet and {self.lost['internal']} for traffic between or inside zones inside are not written, or only in "
                             "part. That traffic needs a firewall of its own at the sites")  # fmt: skip
        if self.locations_used:
            self.report.note(Severity.REVIEW, "ZSCALER_LOCATIONS_REQUIRED",
                             "rules name these locations, which must exist on the tenant under these names: " + ", ".join(sorted(self.locations_used)))  # fmt: skip

    def _script(self) -> str:
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: IP groups, network services and Cloud Firewall filtering rules for Zscaler Internet",
            "# Access, created through the ZIA API. Read the report first: what is disabled or left out is listed there.",
            "#",
            "#   DRY_RUN=1 sh THIS_FILE                                                   prints the calls, makes none",
            "#   ZIA_BASE=https://api.zsapi.net/zia/api/v1 ZIA_TOKEN=... sh THIS_FILE      OneAPI (ZIdentity) token",
            "#   ZIA_BASE=https://zsapi.<cloud>.net/api/v1 ZIA_SESSION=... sh THIS_FILE     JSESSIONID of a legacy session",
            "#",
            "# Nothing is activated: POST /status/activate is left to you. A legacy session that ends (logout, or its",
            "# timeout) activates what was changed in it. The script stops at the first call that is refused, and at a name",
            "# that is taken; what it created is in $JOURNAL (path, id, name), to delete again if need be.",
            "set -eu",
            'DRY_RUN="${DRY_RUN:-}"',
            'JOURNAL="${JOURNAL:-zia-fwshift-created.txt}"',
            'OUT=$(mktemp -d)',
            "trap 'rm -rf \"$OUT\"' EXIT",
            'if [ -z "$DRY_RUN" ]; then',
            '  : "${ZIA_BASE:?set ZIA_BASE to the base URL of the ZIA API}"',
            '  command -v jq >/dev/null || { echo "jq is needed" >&2; exit 1; }',
            '  if [ -n "${ZIA_TOKEN:-}" ]; then AUTH="Authorization: Bearer $ZIA_TOKEN"',
            '  elif [ -n "${ZIA_SESSION:-}" ]; then AUTH="Cookie: JSESSIONID=$ZIA_SESSION"',
            '  else echo "set ZIA_TOKEN (OneAPI) or ZIA_SESSION (legacy API session)" >&2; exit 1; fi',
            "fi",
            "call() {  # call METHOD PATH [BODY-FILE]: the answer on stdout",
            "  tries=0",
            "  while :; do",
            '    if [ -n "${3:-}" ]; then',
            '      code=$(curl -sS -o "$OUT/answer" -D "$OUT/headers" -w \'%{http_code}\' -X "$1" -H "$AUTH" -H \'Content-Type: application/json\' \\',
            '             --data-binary @"$3" "$ZIA_BASE$2")',
            "    else",
            '      code=$(curl -sS -o "$OUT/answer" -D "$OUT/headers" -w \'%{http_code}\' -X "$1" -H "$AUTH" "$ZIA_BASE$2")',
            "    fi",
            '    case "$code" in',
            '      2??) cat "$OUT/answer"; sleep 1; return 0 ;;',
            '      429) tries=$((tries+1)); [ "$tries" -le 5 ] || { echo "rate limited: $1 $2" >&2; return 1; }',
            '           wait=$(sed -n \'s/^[Rr]etry-[Aa]fter: *\\([0-9]*\\).*/\\1/p\' "$OUT/headers"); sleep "${wait:-2}" ;;',
            '      *) echo "HTTP $code on $1 $2:" >&2; cat "$OUT/answer" >&2; return 1 ;;',
            "    esac",
            "  done",
            "}",
            "lookup() {  # lookup PATH NAME: the id of the entry of exactly that name, or nothing (the name is compared here)",
            '  case "$1" in /firewallFilteringRules) query="" ;; *) query="?search=$(jq -rn --arg v "$2" \'$v|@uri\')&pageSize=1000" ;; esac',
            '  answer=$(call GET "$1$query")',
            '  printf \'%s\' "$answer" | jq -r --arg n "$2" \'[.[] | select(.name == $n) | .id][0] // empty\'',
            "}",
            "need() {  # need PATH NAME DRY-ID: the id of an entry the tenant must have",
            '  if [ -n "$DRY_RUN" ]; then printf \'GET %s (name %s)\\n\' "$1" "$2" >&2; echo "$3"; return 0; fi',
            '  id=$(lookup "$1" "$2")',
            '  [ -n "$id" ] || { echo "not on the tenant: $2 ($1)" >&2; return 1; }',
            '  echo "$id"',
            "}",
            "create() {  # create PATH NAME BODY-FILE DRY-ID: the id of the new entry; refuses a name that is taken",
            '  if [ -n "$DRY_RUN" ]; then printf \'POST %s\\n\' "$1" >&2; cat "$3" >&2; printf \'\\n\' >&2; echo "$4"; return 0; fi',
            '  taken=$(lookup "$1" "$2")',
            '  [ -z "$taken" ] || { echo "the name is taken: $2 ($1); nothing of it is changed" >&2; return 1; }',
            '  answer=$(call POST "$1" "$3")',
            '  id=$(printf \'%s\' "$answer" | jq -r \'.id // empty\')',
            '  [ -n "$id" ] || { echo "no id in the answer to POST $1" >&2; return 1; }',
            '  printf \'%s %s %s\\n\' "$1" "$id" "$2" >> "$JOURNAL"',
            '  echo "$id"',
            "}",
            "",
        ]
        number = 0
        for step in self.steps:
            number += 1
            if step.kind == "need":
                out.append(f"{step.var}=$(need {step.path} {_quote(step.name)} {number})")
                continue
            assert step.body is not None
            out += [f"cat > \"$OUT/{number}.json\" <<FWSHIFT_JSON", _body(step.body), "FWSHIFT_JSON",
                    f"{step.var}=$(create {step.path} {_quote(step.name)} \"$OUT/{number}.json\" {number})"]  # fmt: skip
        out.append("")
        out.append(f"# Firewall filtering rules, from order {self.start} on, in the order of the converted policy.")
        for index, (name, rule_body) in enumerate(self.rules):
            number += 1
            rule_body = dict(rule_body, order=self.start + index)
            out += [f"cat > \"$OUT/{number}.json\" <<FWSHIFT_JSON", _body(rule_body), "FWSHIFT_JSON",
                    f"ID_{number}=$(create /firewallFilteringRules {_quote(name)} \"$OUT/{number}.json\" {number})"]  # fmt: skip
        out.append('echo "done: nothing is active until the changes are activated (POST /status/activate)" >&2')
        if self.not_written:
            out += ["# Not written:"] + [f"#   {''.join(c if c.isprintable() else ' ' for c in line)}" for line in self.not_written]
        return "\n".join(out) + "\n"


def _range(text: str) -> Optional[Dict[str, int]]:
    low, _, high = text.partition("-")
    first, last = int(low), int(high or low)
    if first < 1:
        return None
    return {"start": first} if first == last else {"start": first, "end": last}


def _merge(ranges: List[Dict[str, int]]) -> List[Dict[str, int]]:
    """Port ranges sorted, merged where they meet."""
    spans = sorted((r["start"], r.get("end", r["start"])) for r in ranges)
    merged: List[List[int]] = []
    for first, last in spans:
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    return [{"start": a} if a == b else {"start": a, "end": b} for a, b in merged]


def _quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def _body(body: Dict[str, Any]) -> str:
    """The JSON of a body for an unquoted here-document: ids are the variables of earlier calls, the rest is literal."""
    text = json.dumps(body, ensure_ascii=True, separators=(", ", ": "))
    text = text.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`")
    return re.sub(r'\{"id": "(ID_[0-9]+)"\}', lambda m: '{"id": ${' + m.group(1) + '}}', text)
