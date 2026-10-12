# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Barracuda emitter: neutral model -> a shell script that creates forwarding rules through the REST API of a
CloudGen Firewall.

Design rules:

* Nothing is ever widened silently. A rule whose match cannot be expressed is created with
  ``"deactivated": true`` and reported.
* The script makes one call per object and rule with curl, and stops at the first one the
  firewall refuses. Objects come first, then the rules, each placed at the top of the rule list
  (the one placement the documentation shows), last rule first: they end up in the order of the
  model, above the rules the firewall has.
* A rule of the firewall names no zones: the way out is its routes. A zone of the source of a rule
  is written as the interface of the entries of its source object, where the interface is known
  (``--interface-map``, or a CloudGen source), otherwise as the networks behind the zone
  (``--zone-network``); a zone of the destination as its networks. Where neither is given, an
  allowing rule is created deactivated, and a blocking rule blocks for every zone.
* A rule is of one IP version; a rule of the model that holds both becomes two.
* There is no negation and no range in an object: a negated list is written as the addresses that
  are left, a range as the networks that make it up.
* What the model denies by default, the firewall blocks only at the end of its own rule list,
  below the rules it has: a rule that blocks everything follows the converted rules, deactivated,
  for a person to switch on once the rules below it have been looked at.
* NAT is not written: how the API spells the action Dst NAT, Map and a connection object is not
  known.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, ANY_V6, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..names import BARRACUDA, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_RESERVED = {"Any", "World", "Internet", "Trusted_LAN", "Trusted_Networks", "Localnet", "Specialnet"}
_PLACEHOLDER = (4, int(ipaddress.ip_address("192.0.0.8")), int(ipaddress.ip_address("192.0.0.8")))
_MAX_ENTRIES = 5000
_INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,30}")

Entries = List[Tuple[Interval, str]]  # addresses, each with the interface of its entry ("" for none)


def emit(policy: Policy, report: Report, options: Options) -> str:
    zone_spaces(options.zone_networks)  # refuses networks that contradict each other
    for zone, interface in options.interface_map.items():
        if not _INTERFACE.fullmatch(interface):
            raise FwshiftError(f"--interface-map: '{interface[:40]}' is not the name of an interface of a CloudGen Firewall")
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    transform.sanitize_names(p, BARRACUDA, BARRACUDA, report, reserved_addresses=_RESERVED, reserved_services={"Any"},
                             prefix=options.object_prefix, fold_case=True)  # fmt: skip
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _json(body: Dict[str, Any]) -> str:
    return json.dumps(body, ensure_ascii=True, separators=(", ", ": "))


def _entries_json(entries: Entries, comment: str = "") -> List[Dict[str, Any]]:
    """Included entries: one per network, a range as the networks that make it up."""
    out: List[Dict[str, Any]] = []
    for (version, first, last), interface in entries:
        for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)):
            text = str(net.network_address) if net.num_addresses == 1 else str(net)
            entry: Dict[str, Any] = {"ip": text}
            if interface:
                entry["interface"] = interface
            if comment:
                entry["comment"] = comment
            out.append({"entry": entry})
    return out


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "barracuda"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s: Dict[str, str] = {}
        self.object_names: Set[str] = {n.lower() for n in list(p.addresses) + list(p.address_groups) + list(p.services)
                                       + list(p.service_groups)} | {n.lower() for n in _RESERVED}  # fmt: skip
        self.rule_names: Set[str] = {"fwshift-block", "fwshift-block-v6"}
        self.objects: List[Tuple[str, str]] = []  # (endpoint, body)
        self.rules: List[Tuple[str, Dict[str, Any], bool]] = []  # (name, body, to be active), in the order of the model
        self.single: Dict[str, Tuple[int, List[Interval]]] = {}  # named object -> (its IP version, its addresses), when of one
        self.svc_written: Set[str] = set()
        self.spaces = zone_spaces(options.zone_networks)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used + list(options.zone_networks))
        self.interfaces: Set[str] = set()
        self.any_services: Set[str] = set()
        self._origin = ""

    def _object_name(self, label: str) -> str:
        return _unique(label, self.object_names)

    # -- top level --------------------------------------------------------------------------------

    def run(self) -> str:
        self._address_objects()
        self._services()
        for rule in self.p.rules:
            self._rule(rule)
        if self.rules:
            self._block_rules()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: on a CloudGen Firewall NAT is the action of a rule (Dst NAT, Map) or its connection "
                             "object, and how the REST API spells those is not known. Set it on the rule by hand")  # fmt: skip
        self._notes()
        return self._script()

    def _script(self) -> str:
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: forwarding rules for a Barracuda CloudGen Firewall, created through its",
            "# REST API. Read the report first: what is deactivated or left out is listed there.",
            "#",
            "#   DRY_RUN=1 sh THIS_FILE                       prints the calls, makes none",
            "#   BARRACUDA=https://FIREWALL:8443 TOKEN=... sh THIS_FILE",
            "#",
            "# Objects first; then every rule, deactivated, at the top of the list, last rule first; then the rules that",
            "# are to be active are activated, first rule first. The calls stop at the first one the firewall refuses:",
            "# what was created before it stays, and of the rules only those above it in the list are active.",
            "set -eu",
            'DRY_RUN="${DRY_RUN:-}"',
            'if [ -z "$DRY_RUN" ]; then',
            '  : "${BARRACUDA:?set BARRACUDA to https://<firewall>:<port> of the REST API}"',
            '  : "${TOKEN:?set TOKEN to an access token of the REST API}"',
            '  HEADERS=$(mktemp)',
            "  trap 'rm -f \"$HEADERS\"' EXIT",
            "  printf 'X-API-Token: %s\\nContent-Type: application/json\\nAccept: application/json\\n' \"$TOKEN\" > \"$HEADERS\"",
            "fi",
            "call() {",
            '  if [ -n "$DRY_RUN" ]; then printf \'%s %s\\n\' "$1" "$2"; cat; printf \'\\n\'; return 0; fi',
            '  curl -sS --fail-with-body -X "$1" -H "@$HEADERS" --data-binary @- "$BARRACUDA/rest/config/v1/forwarding-firewall/$2"',
            "  printf '\\n'",
            "}",
            "",
        ]
        for endpoint, body in self.objects:
            out += [f"call POST {endpoint} <<'FWSHIFT_JSON'", body, "FWSHIFT_JSON"]
        out.append("")
        out.append("# Rules, deactivated: each goes to the top of the list, last rule first.")
        for _, body, _ in reversed(self.rules):
            out += ["call POST rules <<'FWSHIFT_JSON'", _json(body), "FWSHIFT_JSON"]
        out.append("")
        out.append("# The rules that are to be active, first rule first.")
        for name, _, active in self.rules:
            if active:
                out += [f"call PATCH rules/{name} <<'FWSHIFT_JSON'", _json({"deactivated": False}), "FWSHIFT_JSON"]
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "BARRACUDA_LOAD",
            "the output is a shell script that creates network objects, service objects and forwarding rules through the REST "
            "API of the firewall, with curl (section 10). Run it with DRY_RUN=1 first. The rules go to the top of the rule list, "
            "above the rules the firewall has, deactivated, and are then activated in order, first rule first: if a call is "
            "refused the script stops, and only the rules above that one are active, with the rules the firewall had below "
            "them. Barracuda documents the API by examples: assumed are the keys of a service "
            "object and its entries (protocol, ports, client ports), the interface of an entry of a network object, the IP version and "
            "action types of a rule other than block, and names of up to 32 letters, digits, periods, underscores and hyphens",
        )  # fmt: skip
        if self.rules:
            self.report.note(
                Severity.REVIEW, "BLOCK_RULE_INACTIVE",
                "the source blocks what no rule matches. The rules FWSHIFT-BLOCK and FWSHIFT-BLOCK-v6 that do so follow the "
                "converted rules, deactivated: until they are activated, the rules the firewall has below them decide that "
                "traffic. Look at those rules (management access, the default rules) and activate the two",
            )  # fmt: skip
        if self.p.default_interzone == Action.ALLOW or self.p.default_intrazone == Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTERZONE_DEFAULT",
                             "the source allows what no rule matches; the firewall blocks it at the end of its rule list. Add a "
                             "rule that allows it if that was intended")  # fmt: skip
        if self.interfaces and not self.native:
            self.report.note(Severity.REVIEW, "INTERFACES_REQUIRED",
                             "the source objects of rules name these interfaces of the firewall, which must exist under these "
                             "names: " + ", ".join(sorted(self.interfaces)))  # fmt: skip

    # -- objects ----------------------------------------------------------------------------------

    def _network(self, name: str, entries: Entries, comment: str) -> None:
        body: Dict[str, Any] = {"name": name, "included": _entries_json(entries)}
        if comment:
            body["comment"] = " ".join(comment.split())[:200]
        self.objects.append(("objects/networks", _json(body)))

    def _address_objects(self) -> None:
        names = list(self.p.addresses) + list(self.p.address_groups)
        for name in names:
            address = self.p.addresses.get(name)
            reason = self.taint_a.get(name, "")
            intervals = None if reason else transform.address_intervals(self.p, name)
            if address is not None and address.kind == AddressKind.FQDN:
                reason = reason or "a host name: how the API spells a hostname object is not known"
            elif intervals is None and not reason:
                reason = "a group that holds a host name: how the API spells a hostname object is not known"
            description = (address.description if address else self.p.address_groups[name].description) or ""
            if reason:
                self.taint_a[name] = reason
                self._network(name, [(_PLACEHOLDER, "")], " ".join(f"FWSHIFT PLACEHOLDER, matches nothing: {reason}".split()))
                continue
            assert intervals is not None
            merged = normalize(intervals)
            if not merged:
                self.taint_a[name] = "a group without addresses"
                self._network(name, [(_PLACEHOLDER, "")], "FWSHIFT PLACEHOLDER, matches nothing: a group without addresses")
                continue
            self._network(name, [(i, "") for i in merged], description)
            versions = {i[0] for i in merged}
            if len(versions) == 1:
                self.single[name] = (versions.pop(), merged)
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a)), **self.taint_a}

    # -- services ---------------------------------------------------------------------------------

    def _service_entries(self, entries: List[ServiceEntry]) -> Tuple[List[Dict[str, Any]], str]:
        out: List[Dict[str, Any]] = []
        for entry in entries:
            if entry.src_ports and entry.protocol not in (Protocol.TCP, Protocol.UDP):
                return [], "source ports of a protocol other than TCP and UDP"
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                ports = entry.dst_ports.split(",") if entry.dst_ports else ["*"]
                for client in entry.src_ports.split(",") if entry.src_ports else [""]:
                    found: Dict[str, Any] = {"protocol": entry.protocol.value, "ports": ports}
                    if client:
                        low, _, high = client.partition("-")
                        found["clientPortUsed"] = {"from": int(low), "to": int(high or low)}
                    out.append({"entry": found})
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                if entry.icmp_type is not None or entry.icmp_code is not None:
                    return [], "an ICMP type or code: a service entry of the firewall matches every ICMP type"
                out.append({"entry": {"protocol": "icmp" if entry.protocol == Protocol.ICMP else "icmpv6"}})
            elif entry.protocol == Protocol.SCTP:
                if entry.dst_ports:
                    return [], "SCTP ports"
                out.append({"entry": {"protocol": "132"}})
            else:
                if entry.ip_protocol is None:
                    return [], "every protocol, which is the service Any and not an entry"
                if entry.ip_protocol == 0:
                    return [], "IP protocol 0"
                if entry.ip_protocol in (6, 17):
                    out.append({"entry": {"protocol": "tcp" if entry.ip_protocol == 6 else "udp", "ports": ["*"]}})
                else:
                    out.append({"entry": {"protocol": str(entry.ip_protocol)}})
        unique_out = list({json.dumps(e, sort_keys=True): e for e in out}.values())
        return unique_out, ""

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for name in list(self.p.services) + list(self.p.service_groups):
            service = self.p.services.get(name)
            if service is not None and service.unsupported:
                bad[name] = service.unsupported
                continue
            flat = transform.flatten_services(self.p, name)
            if not flat:
                bad[name] = "a service without content"
                continue
            if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in flat):
                bad[name] = "every protocol: rules that use it are written with the service Any instead"
                continue
            entries, problem = self._service_entries(flat)
            if problem:
                bad[name] = problem
                self.report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: not written, and the rules that use it are deactivated")  # fmt: skip
                continue
            self.objects.append(("objects/services", _json({"name": name, "entries": entries})))
            self.svc_written.add(name)
        every = {n for n, why in bad.items() if why.startswith("every protocol")}
        self.taint_s = transform.tainted_services(self.p, {n: why for n, why in bad.items() if n not in every})
        self.any_services = every

    def _rule_service(self, rule: Rule, reasons: List[transform.Reason]) -> Dict[int, Optional[str]]:
        """The service a rule refers to, per IP version; None where none of its entries is of that version (ICMP)."""
        every: Dict[int, Optional[str]] = {4: "Any", 6: "Any"}
        if any(s in self.taint_s for s in rule.services):
            return every  # the rule is deactivated, for the reason the service gives
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        named = ""
        if lowered is None:
            if ANY in rule.services or any(s in self.any_services for s in rule.services):
                return every
            if len(rule.services) == 1 and rule.services[0] in self.svc_written:
                named = rule.services[0]
            entries = [e for s in rule.services for e in (transform.flatten_services(self.p, s) or [])]
        else:
            entries = [e for _, found in lowered for e in found]
        if not entries or any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return every
        out: Dict[int, Optional[str]] = {}
        for version in (4, 6):
            other = Protocol.ICMP6 if version == 4 else Protocol.ICMP
            mine = [e for e in entries if e.protocol != other]
            if not mine:
                out[version] = None
                continue
            if named and len(mine) == len(entries):
                out[version] = named
                continue
            written, problem = self._service_entries(mine)
            if problem:
                reasons.append(("UNCONVERTIBLE_OBJECT", f"the services of the rule hold {problem}"))
                return every
            label = f"{self.options.object_prefix}{rule.name}.svc" + (".v6" if version == 6 else "")
            if version == 6 and out.get(4) and mine == [e for e in entries if e.protocol != Protocol.ICMP6]:
                out[version] = out[4]  # the same entries as for IPv4
                continue
            name = self._object_name(label)
            self.objects.append(("objects/services", _json({"name": name, "entries": written})))
            out[version] = name
        return out

    # -- rules ------------------------------------------------------------------------------------

    def _addresses(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Dict[int, List[Interval]]:
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found += [FULL_V4, FULL_V6]
                continue
            if member in (ANY_V4, ANY_V6):
                found.append(FULL_V4 if member == ANY_V4 else FULL_V6)
                continue
            intervals = transform.address_intervals(self.p, member) if member not in self.taint_a else None
            if intervals is None:
                if member not in self.taint_a:
                    reasons.append(("UNCONVERTIBLE_OBJECT", f"the {side} holds a host name ('{member}'), which is not written"))
                found.append(_PLACEHOLDER)  # the rule is deactivated; the placeholder keeps it in its place
                continue
            found += intervals
        if negated:
            found = subtract([FULL_V4, FULL_V6], found)
            if members != [ANY]:
                self.report.add("rule", self._origin, Severity.INFO, "NEGATION_EXPANDED",
                                f"the firewall has no negation in a rule: 'not {side} {', '.join(members)}' is written as the "
                                "addresses that are left")  # fmt: skip
        merged = normalize(found)
        return {v: [i for i in merged if i[0] == v] for v in (4, 6)}

    def _interface(self, zone: str) -> str:
        if zone in self.options.interface_map:
            return self.options.interface_map[zone]
        if self.native and zone in self.p.zones and _INTERFACE.fullmatch(zone):
            return zone
        return ""

    def _confine(self, rule: Rule, side: str, zones: List[str], found: Dict[int, List[Interval]],
                 reasons: List[transform.Reason]) -> Dict[int, Entries]:  # fmt: skip
        """The addresses of one side, kept to the zones of the rule."""
        plain = {v: [(i, "") for i in ivs] for v, ivs in found.items()}
        if ANY in zones or (side == "destination" and rule.egress_implied):
            return plain  # egress_implied: the zones are where the destination is routed to, which the firewall does as well
        allow = rule.action == Action.ALLOW
        if side == "source":
            interfaces = [self._interface(zone) for zone in zones]
            if all(interfaces):
                self.interfaces.update(interfaces)
                return {v: [(i, f) for f in dict.fromkeys(interfaces) for i in ivs] for v, ivs in found.items()}
        where = "its interface with --interface-map, or " if side == "source" else ""
        missing = [zone for zone in zones if zone not in self.spaces]
        if allow:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and a rule of the firewall names no zone: "
                                f"give {where}the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return plain
            space = normalize([i for zone in zones for i in self.spaces[zone]])
            kept = {v: intersect(ivs, space) for v, ivs in found.items()}
            if kept != found:
                placed = normalize([i for space_of in self.spaces.values() for i in space_of])
                lost = [i for v, ivs in found.items() for i in subtract(ivs, kept[v])]
                nowhere = subtract(lost, placed)
                self.report.add("rule", rule.origin, Severity.APPROX if nowhere else Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} in zone {', '.join(zones)} is written as the addresses of the networks given for it "
                                "with --zone-network" + (", without the addresses that lie in none of the networks given"
                                                         if nowhere else ""))  # fmt: skip
            return {v: [(i, "") for i in ivs] for v, ivs in kept.items()}
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others):
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a rule of the firewall names no "
                            f"zone, and it blocks that traffic in every zone. Give {where}the networks behind every zone with "
                            "--zone-network to keep it to its zones")  # fmt: skip
            return plain
        away = normalize([i for zone in others for i in self.spaces[zone]])
        kept = {v: subtract(ivs, away) for v, ivs in found.items()}
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
        return {v: [(i, "") for i in ivs] for v, ivs in kept.items()}

    def _side_ref(self, rule: Rule, label: str, members: List[str], negated: bool, entries: Entries, version: int,
                  confined: bool) -> str:  # fmt: skip
        """The name a rule refers to for one side: the object of the model when it is just that, else one of the rule."""
        full = FULL_V4 if version == 4 else FULL_V6
        if [i for i, _ in entries] == [full] and not any(f for _, f in entries):
            return "Any"
        if len(members) == 1 and not negated and not confined and members[0] in self.single and members[0] not in self.taint_a:
            object_version, intervals = self.single[members[0]]
            if object_version == version and normalize([i for i, _ in entries]) == intervals:
                return members[0]
        name = self._object_name(f"{self.options.object_prefix}{rule.name}.{label}" + (".v6" if version == 6 else ""))
        if len(entries) > _MAX_ENTRIES:
            raise FwshiftError(f"rule '{rule.name[:40]}' would need an object of more than {_MAX_ENTRIES} entries")
        self._network(name, entries, "")
        return name

    def _rule(self, rule: Rule) -> None:
        self._origin = rule.origin
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service cannot be written: the firewall has no negation in a rule"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a rule of the firewall names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written as a rule for every pair of its zones, which blocks more")  # fmt: skip
        services = self._rule_service(rule, reasons)
        sources = self._confine(rule, "source", rule.src_zones, self._addresses(rule.sources, rule.negate_source, "source", reasons), reasons)
        destinations = self._confine(rule, "destination", rule.dst_zones,
                                     self._addresses(rule.destinations, rule.negate_destination, "destination", reasons), reasons)  # fmt: skip
        versions = [v for v in (4, 6) if sources[v] and destinations[v] and services[v] is not None]
        if not versions and reasons:
            # Deactivated anyway: kept in its place, with sides that match nothing.
            sources[4] = sources[4] or [(_PLACEHOLDER, "")]
            destinations[4] = destinations[4] or [(_PLACEHOLDER, "")]
            services[4] = services[4] or "Any"
            versions = [4]
        if not versions:
            self.report.skip("rule", rule.origin, "NO_COMMON_FAMILY",
                             "no IP version has addresses on both sides (after negation and the zones): the rule matches nothing",
                             Severity.INFO)  # fmt: skip
            return
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value} becomes Deny, which answers the client only")  # fmt: skip
        reasons = list(dict.fromkeys(reasons))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        if len(versions) == 2:
            self.report.add("rule", rule.origin, Severity.INFO, "IP_VERSION_SPLIT",
                            "a rule of the firewall is of one IP version: written as an IPv4 and an IPv6 rule")  # fmt: skip
        kind = "pass" if allow else "block" if rule.action in (Action.DROP, Action.DENY) else "deny"
        description = " ".join(rule.description.split())
        if reasons:
            description = f"FWSHIFT inactive, see the report. {description}".strip()
        for version in versions:
            confined_src = rule.src_zones != [ANY] or rule.negate_source
            confined_dst = rule.dst_zones != [ANY] or rule.negate_destination
            src = self._side_ref(rule, "src", rule.sources, rule.negate_source, sources[version], version, confined_src)
            dst = self._side_ref(rule, "dst", rule.destinations, rule.negate_destination, destinations[version], version, confined_dst)
            name = _unique(rule.name + ("-v6" if version == 6 and len(versions) == 2 else ""), self.rule_names)
            body: Dict[str, Any] = {
                "name": name, "ipVersion": f"IPv{version}", "deactivated": True,
                "bidirectional": False, "source": {"references": src}, "destination": {"references": dst},
                "service": {"references": services[version]}, "action": {"type": kind}, "position": {"placement": "top"},
            }  # fmt: skip
            if description:
                body["comment"] = description[:200]
            self.rules.append((name, body, rule.enabled and not reasons))
            item.emitted_as.append(name)

    def _block_rules(self) -> None:
        for version in (4, 6):
            name = "FWSHIFT-BLOCK" + ("-v6" if version == 6 else "")
            self.rules.append((name, {
                "name": name,
                "ipVersion": f"IPv{version}", "deactivated": True, "bidirectional": False,
                "source": {"references": "Any"}, "destination": {"references": "Any"}, "service": {"references": "Any"},
                "action": {"type": "block"}, "position": {"placement": "top"},
                "comment": "FWSHIFT: what the converted policy does not allow. Activate after looking at the rules below",
            }, False))  # fmt: skip


def _unique(label: str, taken: Set[str]) -> str:
    """A name the firewall takes, unique against ``taken`` without regard to case, and recorded there."""
    base = clean(label, BARRACUDA)
    candidate, counter = base, 2
    while candidate.lower() in taken:
        tail = f"_{counter}"
        candidate = base[: BARRACUDA.max_len - len(tail)] + tail
        counter += 1
    taken.add(candidate.lower())
    return candidate
