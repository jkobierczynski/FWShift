# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cato Networks emitter: neutral model -> a shell script that adds WAN Firewall and Internet Firewall rules through the
GraphQL API (``addRule``), with curl.

Design rules:

* The zones inside (``--inside-zone``; from a Cato source the sites and ``remote-users``) are sites, written as a site by
  name, or as the networks of ``--zone-network`` where those are given and the source is not Cato. The other zones are
  the internet. A rule between zones inside is a WAN Firewall rule, a rule from inside to the internet an Internet
  Firewall rule (a rule to both becomes one of each). A rule from the internet is not written: these policies decide
  nothing that comes from the internet.
* A column of Cato holds alternatives ("these sites, or these addresses"); the model wants sites and addresses at once.
  Where the networks of the zone are not known, the column names the sites and an exception skips the rule for every
  IPv4 address outside the rule's addresses; a negated column is an exception of what it names. Exceptions apply each
  on its own, so the rule applies where none of them matches, which is the model's conjunction. ``remote-users`` as a
  source is the connection origins of the Cato client, in a rule of its own; as a destination it cannot be written.
* The API names IPv4 addresses and ranges only: IPv6 is left out (``CATO_IPV6``). Services are custom services
  (TCP, UDP, TCP_UDP, ICMP with ports or a port range; all ports of a protocol are written as 1-65535); ICMP types,
  source ports and other protocols cannot be written.
* Rules are added one after the other from a position (``CATO_WAN_POSITION``, ``CATO_IF_POSITION``; by default last in
  the policy), each after the one added before it, with a prefix in its name. Nothing is changed or removed, and no
  revision is published: that is left to a person. Defaults that differ from Cato's (an Internet Firewall that ends
  in allow, a WAN Firewall that ends in block) are written as a last rule that is switched off.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import names, transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, Policy, Protocol, Rule, RuleScope, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, parse_literal, subtract, within
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

INTERNET = "internet"
REMOTE = "remote-users"
REMOTE_ORIGINS = ["REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER"]
MAX_CONDITIONS = 64  # "Each rule can have a maximum of 64 conditions", exceptions included
_WAN = "wanFirewall"
_IF = "internetFirewall"
QUERY = {
    _WAN: "mutation fwshiftAddRule($accountId: ID!, $policy: WanFirewallPolicyMutationInput, $input: WanFirewallAddRuleInput!) { "
          "policy(accountId: $accountId) { wanFirewall(input: $policy) { addRule(input: $input) { rule { rule { id } } status "
          "errors { errorCode errorMessage } } } } }",
    _IF: "mutation fwshiftAddRule($accountId: ID!, $policy: InternetFirewallPolicyMutationInput, $input: InternetFirewallAddRuleInput!) { "
         "policy(accountId: $accountId) { internetFirewall(input: $policy) { addRule(input: $input) { rule { rule { id } } status "
         "errors { errorCode errorMessage } } } } }",
}  # fmt: skip


class _NotWritten(Exception):
    pass


Cell = Dict[str, Any]


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _address_values(intervals: List[Interval]) -> Cell:
    """IPv4 intervals as the ip, subnet and ipRange fields of a column."""
    out: Cell = {}
    for interval in normalize(intervals):
        first, last = int_to_ip(4, interval[1]), int_to_ip(4, interval[2])
        if interval[1] == interval[2]:
            out.setdefault("ip", []).append(str(first))
            continue
        networks = list(ipaddress.summarize_address_range(first, last))
        if len(networks) == 1:
            out.setdefault("subnet", []).append(str(networks[0]))
        else:
            out.setdefault("ipRange", []).append({"from": str(first), "to": str(last)})
    return out


def _count(cell: Cell) -> int:
    return sum(len(v) for v in cell.values() if isinstance(v, list))


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used + list(options.zone_networks))
        if options.inside_zones:
            missing = [z for z in options.inside_zones if z not in self.universe]
            if missing:
                raise FwshiftError(f"--inside-zone {missing[0]}: no such zone in the policy")
            self.inside = list(options.inside_zones)
        elif p.vendor == "cato":
            self.inside = [z for z in self.universe if z != INTERNET]
        else:
            # The zones behind the default route, or named internet, are the internet; without any, every zone is a site.
            default = [z for z in self.universe if z.lower() == INTERNET
                       or any(n.strip() in ("0.0.0.0/0", "::/0") for n in options.zone_networks.get(z, []))]
            self.inside = [z for z in self.universe if z not in default]
            if default:
                self.report.note(Severity.INFO, "CATO_INTERNET_BY_ROUTE",
                                 "no --inside-zone: the zones behind the default route (or named internet) are the internet, the others sites: "
                                 + ", ".join(default[:12]))  # fmt: skip
            elif self.universe:
                self.report.note(Severity.REVIEW, "CATO_INSIDE",
                                 "no --inside-zone: every zone was taken as a site; a zone that is the internet then gets WAN "
                                 "Firewall rules, which Cato never matches for traffic to the internet")  # fmt: skip
        self.outside = [z for z in self.universe if z not in self.inside]
        self.sites = [z for z in self.inside if z != REMOTE]
        self.spaces = zone_spaces({z: n for z, n in options.zone_networks.items() if z in self.sites}, options.zone_excluded) \
            if p.vendor != "cato" else {}  # fmt: skip
        self.by_name = [z for z in self.sites if z not in self.spaces]
        self.bodies: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {_WAN: [], _IF: []}
        self.taken: Dict[str, Set[str]] = {_WAN: set(), _IF: set()}
        self.not_written: List[str] = []
        self.prefix = options.object_prefix or "fws-"

    # -- columns ------------------------------------------------------------------------------------

    def _addresses(self, rule: Rule, source: bool) -> Tuple[List[Interval], List[str], bool]:
        """(IPv4 and IPv6 intervals, host names, every address) of one side."""
        members = rule.sources if source else rule.destinations
        if ANY in members:
            return [FULL_V4, FULL_V6], [], True
        found: List[Interval] = []
        hosts: List[str] = []
        for member in members:
            address = self.p.addresses.get(member)
            if address is not None and address.kind == AddressKind.FQDN:
                hosts.append(address.value)
                continue
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                names_inside = self._fqdns(member)
                if names_inside is None:
                    raise _NotWritten(f"'{member}' holds members whose addresses are not known")
                hosts += names_inside
            found += intervals
        return normalize(found), transform.dedupe(hosts), False

    def _fqdns(self, name: str) -> Optional[List[str]]:
        """The host names in a group whose other members all have addresses; None when some member has neither."""
        out: List[str] = []
        todo, seen = [name], set()
        while todo:
            current = todo.pop()
            if current in seen:
                continue
            seen.add(current)
            group = self.p.address_groups.get(current)
            address = self.p.addresses.get(current)
            if group is not None:
                if group.unsupported or group.dynamic_filter:
                    return None
                todo += group.members
            elif address is not None and address.kind == AddressKind.FQDN:
                out.append(address.value)
            elif not transform.known_intervals(self.p, current)[1]:
                return None
        return out

    def _site(self, zone: str) -> Dict[str, str]:
        """A site by name: from a Cato source the site's own name (the interface of its zone), else the zone's name."""
        found = self.p.zones.get(zone)
        name = found.interfaces[0] if self.p.vendor == "cato" and found is not None and len(found.interfaces) == 1 else zone
        return {"by": "NAME", "input": name}

    def _known_space(self, zones: List[str]) -> Optional[List[Interval]]:
        """The IPv4 networks of sites written by name, where --zone-network (or the source) gives them for all of them."""
        out: List[Interval] = []
        for zone in zones:
            networks = self.options.zone_networks.get(zone)
            if not networks:
                return None
            out += [i for i in (parse_literal(n) for n in networks) if i is not None and i[0] == 4]
        return normalize(out)

    def _six(self, rule: Rule, side: str, negated: bool) -> None:
        wider = negated
        severity = Severity.REVIEW if (rule.action == Action.ALLOW) == wider else Severity.APPROX
        self.report.add("rule", rule.origin, severity, "CATO_IPV6",
                        f"IPv6 addresses of the {side} are left out: the Cato API takes IPv4 addresses only; the rule "
                        + ("now matches them as well" if wider else "no longer matches them"))  # fmt: skip

    def _column(self, rule: Rule, zones: List[str], source: bool, internet: bool, why: List[str]) -> List[Tuple[Cell, List[str], List[Cell]]]:
        """The variants of a column: (column, connection origins, exceptions of that column)."""
        side = "source" if source else "destination"
        negated = rule.negate_source if source else rule.negate_destination
        intervals, hosts, every = self._addresses(rule, source)
        v4 = [i for i in intervals if i[0] == 4]
        if not every and any(i[0] == 6 for i in intervals):
            self._six(rule, side, negated)
        if hosts and not (internet and not source):
            raise _NotWritten(f"host names as the {side}: Cato takes them as destinations on the internet only")
        if every and negated:
            raise _NotWritten(f"every address but every address as the {side}")
        if not every and not negated and not v4 and not hosts:
            raise _NotWritten(f"no IPv4 address as the {side}")
        out: List[Tuple[Cell, List[str], List[Cell]]] = []
        if internet and not source:
            named_cell: Cell = dict(_address_values(v4), **({"fqdn": hosts} if hosts else {}))
            if negated:
                return [({}, [], [named_cell] if named_cell else [])]
            return [({} if every else named_cell, [], [])]
        whole = ANY in zones or set(zones) >= set(self.inside)
        if REMOTE in zones and not whole and not source:
            # A column cannot name every remote user; every destination of the WAN but the other sites says it.
            missing = [z for z in self.sites if z not in zones]
            other: Cell = {"site": [self._site(z) for z in missing if z in self.by_name]} if any(z in self.by_name for z in missing) else {}
            for key, values in _address_values([i for z in missing if z not in self.by_name for i in self.spaces.get(z, []) if i[0] == 4]).items():
                other.setdefault(key, []).extend(values)
            self.report.add("rule", rule.origin, Severity.INFO, "CATO_REMOTE_DESTINATION",
                            f"the {side} includes remote users, which a column cannot name: written as every destination with an "
                            "exception for the sites that are not in the rule")  # fmt: skip
            exceptions_out = ([_address_values(v4)] if negated and v4 else []) + ([other] if other else [])
            return [({} if every or negated else _address_values(v4), [], exceptions_out)]
        groups: List[Tuple[List[str], List[str]]] = []  # (sites, origins)
        if whole:
            groups.append(([], []))
        else:
            sites = [z for z in zones if z in self.sites]
            if sites:
                groups.append((sites, []))
            if REMOTE in zones:
                groups.append(([], list(REMOTE_ORIGINS)))
        for sites, origins in groups:
            named = [z for z in sites if z in self.by_name]
            netted = [z for z in sites if z not in self.by_name]
            if named and netted:
                raise _NotWritten(f"sites by name ({', '.join(named[:4])}) and by networks ({', '.join(netted[:4])}) on one side")
            if netted:
                space = normalize([i for z in netted for i in self.spaces.get(z, []) if i[0] == 4])
                if every:
                    kept = space
                elif negated:
                    kept = subtract(space, v4)
                else:
                    kept = intersect(space, v4)
                if not kept:
                    continue  # (nothing of the side is in these zones)
                self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} in zone {', '.join(netted)} is written as the addresses of the networks given for it")  # fmt: skip
                out.append((_address_values(kept), origins, []))
                continue
            cell: Cell = {"site": [self._site(z) for z in named]} if named else {}
            exceptions: List[Cell] = []
            known = self._known_space(named)
            if not every and not negated and named and known is not None and within(v4, known):
                # Every address lies in the networks of these sites: the addresses alone say where they are.
                self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} lies in the networks of zone {', '.join(named)}: written as its addresses")  # fmt: skip
                out.append((_address_values(v4), origins, []))
                continue
            if not every:
                if negated:
                    if v4:  # (nothing of IPv4 to leave out: the rule applies to all of it)
                        exceptions.append(_address_values(v4))
                elif sites or origins:
                    exceptions.append(_address_values(subtract([FULL_V4], v4)))
                    self.report.add("rule", rule.origin, Severity.INFO, "CATO_ZONE_EXCEPTION",
                                    f"the {side} is kept to its zones by naming them and an exception for every IPv4 address outside "
                                    "its addresses (a column of Cato holds alternatives)")  # fmt: skip
                else:
                    cell = _address_values(v4)
            out.append((cell, origins, exceptions))
        if not out and groups:
            raise _NotWritten(f"none of the addresses of the {side} lies in the networks of its zones")
        return out

    # -- services -------------------------------------------------------------------------------------

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[Cell]]:
        """The custom services of a rule ([] for every service), or None."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.services == [ANY]:
            return []
        else:
            entries = []
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return []
        ports: Dict[str, List[Tuple[int, int]]] = {"TCP": [], "UDP": []}
        out: List[Cell] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                if entry.src_ports:
                    reasons.append(("SERVICE_NOT_WRITTEN", "source ports: a service of Cato has destination ports only"))
                    return None
                for part in (entry.dst_ports or "1-65535").split(","):
                    low, _, high = part.partition("-")
                    first, last = max(int(low), 1), int(high or low)
                    if first <= last:  # (port 0 alone: no service of Cato names it)
                        ports[entry.protocol.value.upper()].append((first, last))
            elif entry.protocol == Protocol.ICMP and entry.icmp_type is None and entry.icmp_code is None:
                if {"protocol": "ICMP"} not in out:
                    out.append({"protocol": "ICMP"})
            else:
                reasons.append(("SERVICE_NOT_WRITTEN", "an ICMP type, ICMPv6, SCTP or another IP protocol: a custom service of Cato is "
                                "TCP, UDP or ICMP"))  # fmt: skip
                return None
        spans = {kind: [(i[1], i[2]) for i in normalize([(0, a, b) for a, b in found])] for kind, found in ports.items()}
        groups = [("TCP_UDP", spans["TCP"])] if spans["TCP"] == spans["UDP"] else [("TCP", spans["TCP"]), ("UDP", spans["UDP"])]
        for protocol, found in groups:
            singles = [a for a, b in found if a == b]
            if singles:
                out.append({"protocol": protocol, "port": singles})
            out += [{"protocol": protocol, "portRange": {"from": a, "to": b}} for a, b in found if a != b]
        if not out:
            reasons.append(("SERVICE_NOT_WRITTEN", "port 0 only"))
            return None
        return out

    # -- rules ----------------------------------------------------------------------------------------

    def _name(self, policy: str, rule: Rule, count: int) -> str:
        text = self.prefix + rule.name + (f" ({count})" if count > 1 else "")
        return names.unique(text, self.taken[policy], names.CATO)

    def _rule(self, rule: Rule) -> None:
        if self.p.vendor == "cato" and rule.source_ids.get("cato.local"):
            self.report.skip("rule", rule.origin, "CATO_LOCAL", "traffic inside one network range does not reach Cato: not written", Severity.INFO)
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        for given, label in ((rule.users, "source users"), (rule.url_categories, "URL categories")):
            if given != [ANY]:
                reasons.append(("UNSUPPORTED_MATCH", f"{label} {', '.join(given)[:80]} are not converted"))
        pairs = transform.zone_pairs(rule)
        written: List[Tuple[str, Dict[str, Any]]] = []
        why: List[str] = []
        try:
            if pairs is None:
                raise _NotWritten("a rule type that is not a list of zone pairs")
            services = self._services(rule, reasons)
            if services is None:
                raise _NotWritten("its services cannot be written" + (f": {reasons[-1][1]}" if reasons else ""))
            for src_zones, dst_zones in pairs:
                # (a policy without zones: "any" is every site, written as no site)
                src = (list(self.universe) or [ANY]) if ANY in src_zones else src_zones
                dst = (list(self.universe) or [ANY]) if ANY in dst_zones else dst_zones
                if rule.scope == RuleScope.INTRAZONE:
                    src = dst = [src_zones[0]]
                from_outside = [z for z in src if z in self.outside]
                src_inside = [z for z in src if z in self.inside or z == ANY]
                if from_outside:
                    deny = rule.action != Action.ALLOW
                    self.report.add("rule", rule.origin, Severity.INFO if deny else Severity.REVIEW, "CATO_FROM_INTERNET",
                                    f"traffic from zone {', '.join(from_outside[:6])} is not written: the WAN and Internet Firewall decide "
                                    "traffic from sites and remote users only; from the internet only Remote Port Forwarding lets "
                                    "traffic in" + ("" if deny else ", which is not written"))  # fmt: skip
                if not src_inside:
                    continue
                to_inside = [z for z in dst if z in self.inside or z == ANY]
                to_outside = [z for z in dst if z in self.outside]
                if to_inside:
                    written += self._pieces(rule, _WAN, src_inside, to_inside, services, why)
                if to_outside:
                    if set(to_outside) < set(self.outside):
                        self.report.add("rule", rule.origin, Severity.REVIEW if rule.action == Action.ALLOW else Severity.APPROX,
                                        "CATO_INTERNET_ZONES", f"the rule is for zone {', '.join(to_outside)} of the internet only; the "
                                        "Internet Firewall has one internet, and the rule is written for all of it")  # fmt: skip
                    written += self._pieces(rule, _IF, src_inside, to_outside, services, why)
        except _NotWritten as error:
            why.append(str(error))
            written = []
        if why and not written:
            self.report.skip("rule", rule.origin, "CATO_NOT_WRITTEN", "not written: " + "; ".join(why)[:400]
                             + (" This deny rule is NOT enforced; rules below it may let more through." if rule.action != Action.ALLOW else ""))  # fmt: skip
            self.not_written.append(f"{rule.name}: " + "; ".join(why)[:300])
            return
        if why:
            self.report.add("rule", rule.origin, Severity.REVIEW, "CATO_PART_NOT_WRITTEN", "a part of the rule is not written: " + "; ".join(why)[:400])
        if not written:
            if not self.report.item("rule", rule.origin).findings:
                self.report.skip("rule", rule.origin, "CATO_NOT_WRITTEN", "not written: it matches no traffic Cato's firewalls decide", Severity.INFO)
            else:
                self.report.item("rule", rule.origin).skipped = True
            return
        enabled = rule.enabled and not reasons
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY", f"action {rule.action.value}: written as BLOCK")
        counts = {_WAN: 0, _IF: 0}
        for policy, body in written:
            counts[policy] += 1
            body["name"] = self._name(policy, rule, counts[policy])
            body["enabled"] = enabled
            self.bodies[policy].append((rule.origin, body))
            self.report.item("rule", rule.origin).emitted_as.append(body["name"])

    def _pieces(self, rule: Rule, policy: str, src: List[str], dst: List[str], services: List[Cell], why: List[str]) -> List[Tuple[str, Dict[str, Any]]]:
        internet = policy == _IF
        sources = self._column(rule, src, True, False, why)
        try:
            destinations = self._column(rule, dst, False, internet, why)
        except _NotWritten as error:
            why.append(str(error))
            return []
        out: List[Tuple[str, Dict[str, Any]]] = []
        for scell, origins, sexc in sources:
            for dcell, _, dexc in destinations:
                exceptions: List[Dict[str, Any]] = [{"source": c} for c in sexc] + [{"destination": c} for c in dexc]
                if rule.negate_service:
                    if not services:
                        raise _NotWritten("every service but every service")
                    exceptions.append({"service": {"custom": services}})
                for number, exception in enumerate(exceptions, 1):
                    exception["name"] = f"fwshift {number}"
                body: Dict[str, Any] = {"name": "", "description": rule.description[:250], "enabled": True,
                                        "action": "ALLOW" if rule.action == Action.ALLOW else "BLOCK"}
                if not internet:
                    body["direction"] = "TO"
                body["source"] = scell
                body["destination"] = dcell
                body["service"] = {"custom": [] if rule.negate_service else services}
                if origins:
                    body["connectionsOriginList"] = list(origins)
                body["tracking"] = {"event": {"enabled": bool(rule.log_start or rule.log_end)}}
                body["exceptions"] = exceptions
                conditions = _count(scell) + _count(dcell) + len(body["service"]["custom"]) + sum(
                    _count(e.get("source", {})) + _count(e.get("destination", {})) + len((e.get("service") or {}).get("custom", [])) for e in exceptions)
                if conditions > MAX_CONDITIONS:
                    raise _NotWritten(f"{conditions} objects in one rule of Cato (with its exceptions), more than {MAX_CONDITIONS}")
                out.append((policy, body))
        return out

    # -- defaults -------------------------------------------------------------------------------------

    def _is_default_allow(self, body: Dict[str, Any]) -> bool:
        return body["action"] == "ALLOW" and body["enabled"] and not _count(body["source"]) and not _count(body["destination"]) \
            and not body["service"]["custom"] and not body.get("connectionsOriginList") and not body["exceptions"]  # fmt: skip

    def _defaults(self) -> None:
        ended = False
        while self.bodies[_IF] and self._is_default_allow(self.bodies[_IF][-1][1]):
            origin, body = self.bodies[_IF].pop()
            self.taken[_IF].discard(body["name"])
            item = self.report.item("rule", origin)
            item.emitted_as = [n for n in item.emitted_as if n != body["name"]]
            self.report.add("rule", origin, Severity.INFO, "CATO_DEFAULT_ALLOW", "allows everything to the internet at the end: what the "
                            "implicit allow of the Internet Firewall does, so it is not written")  # fmt: skip
            ended = True
        if self.outside and self.p.default_interzone != Action.ALLOW and not ended:
            body = {"name": names.unique(self.prefix + "block the rest to the internet", self.taken[_IF], names.CATO),
                    "description": "the source blocks what no rule matches; switch on after review", "enabled": False, "action": "BLOCK",
                    "source": {}, "destination": {}, "service": {"custom": []}, "tracking": {"event": {"enabled": False}}, "exceptions": []}
            self.bodies[_IF].append(("", body))
            self.report.note(Severity.REVIEW, "CATO_INTERNET_DEFAULT",
                             "the source blocks what no rule matches; the Internet Firewall allows it (implicit any-any allow). A last "
                             "rule that blocks the rest to the internet is written switched off: with it on, everything to the internet "
                             "that no rule above it allows is blocked, also what existing rules below the position do not block")  # fmt: skip
        allowed = transform.intrazone_decisions(self.p, {}, frozenset(), self.inside, self.report)
        opened = [z for z in self.sites if allowed.get(z)]
        closed = [z for z in self.inside if not allowed.get(z)]
        for zone in opened:
            if zone in self.by_name:
                source: Cell = {"site": [self._site(zone)]}
            else:
                source = _address_values([i for i in self.spaces.get(zone, []) if i[0] == 4])
            if not source:
                continue
            body = {"name": names.unique(f"{self.prefix}inside {zone}", self.taken[_WAN], names.CATO),
                    "description": "the source allows traffic inside the zone that no rule matches", "enabled": True, "action": "ALLOW",
                    "direction": "TO", "source": source, "destination": dict(source), "service": {"custom": []},
                    "tracking": {"event": {"enabled": False}}, "exceptions": []}  # fmt: skip
            self.bodies[_WAN].append(("", body))
        if opened:
            self.report.note(Severity.INFO, "CATO_INTRAZONE", "the source allows traffic inside a zone that no rule matches; between two "
                             "network ranges of one site it passes the WAN Firewall, so a rule at the end allows it: " + ", ".join(opened[:12]))  # fmt: skip
        if self.p.default_interzone == Action.ALLOW and len(self.inside) > 1:
            body = {"name": names.unique(self.prefix + "allow the rest between sites", self.taken[_WAN], names.CATO),
                    "description": "the source allows what no rule matches; switch on after review", "enabled": False, "action": "ALLOW",
                    "direction": "TO", "source": {}, "destination": {}, "service": {"custom": []}, "tracking": {"event": {"enabled": False}},
                    "exceptions": []}  # fmt: skip
            self.bodies[_WAN].append(("", body))
            self.report.note(Severity.REVIEW, "CATO_WAN_DEFAULT",
                             "the source allows what no rule matches; the WAN Firewall blocks it (implicit any-any block). A last rule "
                             "that allows the rest between sites is written switched off")  # fmt: skip
        if closed and self.p.vendor != "cato":
            self.report.note(Severity.REVIEW, "CATO_INTRAZONE_DEFAULT",
                             "the source blocks traffic inside a zone that no rule matches; inside one network range of a site the "
                             "traffic does not reach Cato and passes: " + ", ".join(closed[:12]))  # fmt: skip

    # -- output -----------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            snat = nat.source_translation
            if nat.destination_translation is None and snat is not None and snat.kind in (SnatKind.INTERFACE, SnatKind.DYNAMIC_PORT):
                self.report.skip("nat", nat.origin, "CATO_NAT", "not written: Cato translates traffic to the internet to the addresses "
                                 "of the account by itself", Severity.INFO)  # fmt: skip
            else:
                self.report.skip("nat", nat.origin, "CATO_NAT", "not written: the WAN and Internet Firewall do no NAT; traffic from the "
                                 "internet comes in by Remote Port Forwarding, and other translations are settings of the sites, "
                                 "which the script does not change")  # fmt: skip
        self._notes()
        return self._script()

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "CATO_LOAD",
                         "the output is a shell script for the Cato GraphQL API (section 10): it adds WAN Firewall and Internet Firewall "
                         "rules from a position, each after the one before it, and changes nothing else; it does not publish the "
                         "revision, which a person reviews and publishes")  # fmt: skip
        if self.by_name and self.p.vendor != "cato" and any(self.bodies.values()):
            self.report.note(Severity.REVIEW, "CATO_SITE_NAMES",
                             "zones are written as sites by name, which must exist in the account (map them with --zone-map, or give "
                             "their networks with --zone-network): " + ", ".join(self.by_name[:12]))  # fmt: skip
        if not self.outside:
            self.report.note(Severity.INFO, "CATO_NO_INTERNET", "no zone is the internet: no Internet Firewall rules are written")
        if any(body["tracking"]["event"]["enabled"] for bodies in self.bodies.values() for _, body in bodies):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules generate events")

    def _script(self) -> str:
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: rules for the WAN Firewall and the Internet Firewall of a Cato Networks account, added through",
            "# the GraphQL API with curl. Read the report first: what is not written is listed there and at the end of this file.",
            "# It only adds rules; it changes and removes nothing, and it does not publish: the rules land in an unpublished",
            "# revision, which you review in the Cato Management Application and publish (or discard) yourself.",
            "# Usage: CATO_API_KEY=... CATO_ACCOUNT_ID=12345 [CATO_API_URL=https://api.catonetworks.com/api/v1/graphql2]",
            "#        [CATO_WAN_POSITION=LAST_IN_POLICY] [CATO_WAN_REF=<rule or section id>] [CATO_WAN_REVISION=<revision id>]",
            "#        [CATO_IF_POSITION=LAST_IN_POLICY] [CATO_IF_REF=<rule or section id>] [CATO_IF_REVISION=<revision id>]",
            "#        [DRY_RUN=1] sh this-file",
            "# A position is FIRST_IN_POLICY, LAST_IN_POLICY, FIRST_IN_SECTION, LAST_IN_SECTION, BEFORE_RULE or AFTER_RULE; the ones",
            "# of a section or a rule need its id as the REF. Every rule after the first goes right after the one added before it.",
            "# DRY_RUN=1 only writes the rules, and needs no key. The ids of the rules added are written to created.txt.",
            "set -eu",
            'OUT="${OUT:-cato-$(date +%Y%m%d%H%M%S)}"',
            'mkdir -p "$OUT"',
            'CATO_API_URL="${CATO_API_URL:-https://api.catonetworks.com/api/v1/graphql2}"',
            'CATO_WAN_POSITION="${CATO_WAN_POSITION:-LAST_IN_POLICY}"; CATO_WAN_REF="${CATO_WAN_REF:-}"; CATO_WAN_REVISION="${CATO_WAN_REVISION:-}"',
            'CATO_IF_POSITION="${CATO_IF_POSITION:-LAST_IN_POLICY}"; CATO_IF_REF="${CATO_IF_REF:-}"; CATO_IF_REVISION="${CATO_IF_REVISION:-}"',
            "WAN_PREV=; IF_PREV=",
            f"Q_WAN='{QUERY[_WAN]}'",
            f"Q_IF='{QUERY[_IF]}'",
            "check() {  # check NAME VALUE KIND",
            '  case "$3" in',
            '    position) case "$2" in FIRST_IN_POLICY|LAST_IN_POLICY|FIRST_IN_SECTION|LAST_IN_SECTION|BEFORE_RULE|AFTER_RULE) return 0 ;; esac ;;',
            '    id) case "$2" in *[!A-Za-z0-9_=-]*) ;; *) return 0 ;; esac ;;',
            "  esac",
            '  echo "$1: not a valid value: $2" >&2; exit 1',
            "}",
            "add() {  # add wanFirewall|internetFirewall RULE-FILE: adds one rule after the one added before it, and keeps its id",
            '  if [ "$1" = wanFirewall ]; then q=$Q_WAN; prev=$WAN_PREV; pos=$CATO_WAN_POSITION; ref=$CATO_WAN_REF; rev=$CATO_WAN_REVISION',
            '  else q=$Q_IF; prev=$IF_PREV; pos=$CATO_IF_POSITION; ref=$CATO_IF_REF; rev=$CATO_IF_REVISION; fi',
            '  if [ -n "$prev" ]; then at="{\\"position\\":\\"AFTER_RULE\\",\\"ref\\":\\"$prev\\"}"',
            '  elif [ -n "$ref" ]; then at="{\\"position\\":\\"$pos\\",\\"ref\\":\\"$ref\\"}"',
            '  else at="{\\"position\\":\\"$pos\\"}"; fi',
            '  if [ -n "$rev" ]; then policy="{\\"revision\\":{\\"id\\":\\"$rev\\"}}"; else policy=null; fi',
            "  { printf '{\"query\":\"%s\",\"variables\":{\"accountId\":\"%s\",\"policy\":%s,\"input\":{\"at\":%s,\"rule\":' \"$q\" \"$CATO_ACCOUNT_ID\" \"$policy\" \"$at\"",
            "    cat \"$2\"; printf '}}}\\n'; } > \"$OUT/request.json\"",
            "  tries=0",
            "  while :; do",
            "    code=$(curl -sS -o \"$OUT/last.json\" -w '%{http_code}' -X POST -H \"x-api-key: $CATO_API_KEY\" -H 'Content-Type: application/json' \\",
            '           --data-binary @"$OUT/request.json" "$CATO_API_URL")',
            '    case "$code" in',
            "      200) break ;;",
            '      429|502|503) tries=$((tries+1)); [ "$tries" -le 5 ] || { echo "HTTP $code: giving up at $2" >&2; exit 1; }; sleep $((tries*5)) ;;',
            '      *) echo "HTTP $code at $2:" >&2; cat "$OUT/last.json" >&2; exit 1 ;;',
            "    esac",
            "  done",
            "  flat=$(tr -d ' \\t\\r\\n' < \"$OUT/last.json\")",
            "  case \"$flat\" in *'\"status\":\"SUCCESS\"'*) ;; *) echo \"refused at $2:\" >&2; cat \"$OUT/last.json\" >&2; exit 1 ;; esac",
            "  id=$(printf '%s' \"$flat\" | sed -n 's/.*\"rule\":{\"rule\":{\"id\":\"\\([^\"]*\\)\"}.*/\\1/p')",
            '  [ -n "$id" ] || { echo "no rule id in the answer at $2" >&2; exit 1; }',
            '  echo "$1 $id $2" >> "$OUT/created.txt"',
            '  if [ "$1" = wanFirewall ]; then WAN_PREV=$id; else IF_PREV=$id; fi',
            "}",
        ]
        files: List[Tuple[str, str]] = []
        for policy, tag in ((_WAN, "wan"), (_IF, "internet")):
            for number, (_, body) in enumerate(self.bodies[policy], 1):
                path = f"$OUT/{tag}-{number:03d}.json"
                text = json.dumps(body, ensure_ascii=True)
                out += [f"cat > \"{path}\" <<'FWSHIFT_EOF'", text, "FWSHIFT_EOF"]
                files.append((policy, path))
        out += ['if [ "${DRY_RUN:-0}" = 1 ]; then echo "DRY_RUN: the rules are in $OUT"; exit 0; fi',
                ': "${CATO_API_KEY:?set CATO_API_KEY}"', ': "${CATO_ACCOUNT_ID:?set CATO_ACCOUNT_ID}"',
                'case "$CATO_ACCOUNT_ID" in *[!0-9]*) echo "CATO_ACCOUNT_ID: digits" >&2; exit 1 ;; esac',
                'check CATO_WAN_POSITION "$CATO_WAN_POSITION" position; check CATO_IF_POSITION "$CATO_IF_POSITION" position',
                'for v in "$CATO_WAN_REF" "$CATO_IF_REF" "$CATO_WAN_REVISION" "$CATO_IF_REVISION"; do [ -z "$v" ] || check id "$v" id; done',
                'case "$CATO_WAN_POSITION" in *_SECTION|*_RULE) [ -n "$CATO_WAN_REF" ] || { echo "CATO_WAN_POSITION $CATO_WAN_POSITION needs CATO_WAN_REF" >&2; exit 1; } ;; esac',
                'case "$CATO_IF_POSITION" in *_SECTION|*_RULE) [ -n "$CATO_IF_REF" ] || { echo "CATO_IF_POSITION $CATO_IF_POSITION needs CATO_IF_REF" >&2; exit 1; } ;; esac']  # fmt: skip
        for policy, path in files:
            out.append(f'add {policy} "{path}"')
        out.append('echo "done: $(wc -l < "$OUT/created.txt" 2>/dev/null || echo 0) rules added; review and publish the revision"')
        if self.not_written:
            out += ["# Not written:"] + [f"#   {''.join(c if c.isprintable() else ' ' for c in line)}" for line in self.not_written]
        return "\n".join(out) + "\n"

