# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Phoenix Contact mGuard emitter: neutral model -> a shell script of ``gaiconfig`` calls, to run on an mGuard
(firmware 8.x to 10.x) as root or admin, that adds IP groups, port groups, rows of the packet filter and NAT rows.

Design rules:

* ``gaiconfig`` is the command line Phoenix Contact documents for changing single variables and rows (the gaiconfig
  User Guides): ``--goto TABLE --add-row --set .FIELD value`` appends a row, ``--set-refname`` points a field at a
  row by its name (an IP or port group), ``--get-rowcount`` counts rows, ``--silent`` writes without reconfiguring the
  services. A configuration profile can only be loaded whole (Management >> Configuration Profiles); a fragment of one
  is not documented, so the output does not touch any variable it does not add.
* Only rows are added, after the rows the tables have; nothing is changed or deleted, and no interface, route or
  access to the mGuard itself is touched. The script stops before it writes anything when a group name is taken, or
  when a table it adds to has rows (they would be checked first) unless ``FWSHIFT_APPEND=yes`` is set.
  ``DRY_RUN=1`` prints the calls.
* The zones of the model are the mGuard's: ``internal``, ``external``, ``external2`` and ``dmz``. Others are mapped by
  ``--zone-map``, or by their names where that is plain (``trust``, ``inside``, ``lan`` -> internal; ``untrust``,
  ``outside``, ``wan`` -> external; ``dmz``), which the report says. A rule goes to the table of each pair of zones it
  names: external -> internal ``FW_INCOMING`` (``EXT_IF`` ext1, ext2 or all), internal -> external ``FW_OUTGOING``,
  and the four DMZ tables. ``FW_OUTGOING`` also decides traffic between VLANs of the internal side.
* A row has one protocol, one source and destination (an address, a network, or an IP group) and one source and
  destination port (a port, ``a:b`` or a port group, tcp and udp only): a rule becomes a row per protocol and set of
  source ports, in every table it needs. Negation is written as the IPv4 addresses that are left. The mGuard filters
  IPv4: the IPv6 part of a rule is left out, and said. An ICMP type cannot be matched: an allow rule leaves it out, a
  blocking rule blocks all of ICMP.
* The mGuard has no rule that is switched off: what cannot be written (or is disabled on the source) is left out and
  listed as skipped, with the warning for blocking rules.
* NAT: a bi-directional static NAT of one network becomes 1:1 NAT (``FW_1TO1_NAT``), whose incoming rules name the real
  address: the rules are rewritten for it, as for FortiOS. A destination NAT of one port (or GRE) to one address
  becomes port forwarding (``FW_PORTFORWARDING``), which skips the packet filter: it is written only where the rules
  of the model allow all of what it forwards. Source NAT to the address of the interface the traffic leaves by
  becomes IP masquerading (``FW_NAT``). Other NAT is not written.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import names, regions, transform
from ..errors import FwshiftError
from ..model import ANY, ANY_V4, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, Interval, int_to_ip, normalize, subtract
from ..options import Options
from ..parsers.mguard import DMZ, EXTERN, EXTERNAL, EXTERNAL2, FORWARD_TAG, INTERNAL
from ..report import Report, Severity

ZONES = (INTERNAL, EXTERNAL, EXTERNAL2, DMZ)
# The table of each pair of zones (source, destination).
TABLE_OF = {
    (EXTERNAL, INTERNAL): "FW_INCOMING", (EXTERNAL2, INTERNAL): "FW_INCOMING",
    (INTERNAL, EXTERNAL): "FW_OUTGOING", (INTERNAL, EXTERNAL2): "FW_OUTGOING", (INTERNAL, INTERNAL): "FW_OUTGOING",
    (EXTERNAL, DMZ): "FW_INCOMING_WAN_DMZ", (EXTERNAL2, DMZ): "FW_INCOMING_WAN_DMZ",
    (DMZ, INTERNAL): "FW_INCOMING_DMZ_LAN",
    (DMZ, EXTERNAL): "FW_OUTGOING_DMZWAN", (DMZ, EXTERNAL2): "FW_OUTGOING_DMZWAN",
    (INTERNAL, DMZ): "FW_OUTGOING_LANDMZ",
}  # fmt: skip
TABLES = ("FW_INCOMING", "FW_OUTGOING", "FW_INCOMING_WAN_DMZ", "FW_INCOMING_DMZ_LAN", "FW_OUTGOING_DMZWAN", "FW_OUTGOING_LANDMZ")
NAT_TABLES = ("FW_1TO1_NAT", "FW_PORTFORWARDING", "FW_NAT")
_GUESS = (
    (INTERNAL, re.compile(r"(int(ern(al)?)?|inside|trust(ed)?|lan\d*|private|local|internal\d*)", re.I)),
    (EXTERNAL2, re.compile(r"(ext(ern(al)?)?[-_ ]?2|external[-_ ]?2|wan[-_ ]?2)", re.I)),
    (EXTERNAL, re.compile(r"(ext(ern(al)?)?1?|outside|untrust(ed)?|wan1?|internet|public|external1?)", re.I)),
    (DMZ, re.compile(r"dmz\d*", re.I)),
)
_MAX_PORTS_PER_FORWARD = 16

Ref = Tuple[str, str]  # ("lit", value) | ("group", name)


def _comment(text: str, limit: int = 120) -> str:
    return " ".join("".join(c if c.isprintable() else " " for c in text).split())[:limit].strip()


def _cidrs(interval: Interval) -> List[str]:
    return [str(net) for net in ipaddress.summarize_address_range(int_to_ip(interval[0], interval[1]), int_to_ip(interval[0], interval[2]))]


def _entry_text(interval: Interval) -> str:
    """An entry of an IP group: an address, a network, or a range."""
    nets = _cidrs(interval)
    if len(nets) == 1:
        return nets[0][:-3] if nets[0].endswith("/32") else nets[0]
    return f"{int_to_ip(4, interval[1])}-{int_to_ip(4, interval[2])}"


@dataclass
class Group:
    table: str  # FW_GROUP_IP or FW_GROUP_PORT
    name: str
    comment: str
    entries: List[str]


@dataclass
class Row:
    table: str
    fields: List[Tuple[str, str]]
    refs: List[Tuple[str, str]] = field(default_factory=list)  # (field, group name)


@dataclass
class Plan:
    groups: List[Group] = field(default_factory=list)
    rows: Dict[str, List[Row]] = field(default_factory=dict)


def guess_zones(p: Policy, given: Dict[str, str]) -> Dict[str, str]:
    """The mGuard zone of each zone of the model that ``--zone-map`` does not map, where its name says it plainly."""
    seen: List[str] = list(p.zones)
    for rule in p.rules:
        seen += rule.src_zones + rule.dst_zones
    for nat in p.nat_rules:
        seen += nat.src_zones + nat.dst_zones
    out: Dict[str, str] = {}
    for zone in dict.fromkeys(seen):
        if zone == ANY or zone in given or zone in ZONES:
            continue
        for target, pattern in _GUESS:
            if pattern.fullmatch(zone.strip()):
                out[zone] = target
                break
    return out


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    prefix = options.object_prefix or "fws_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,11}", prefix):
        raise FwshiftError("--target-prefix for the mGuard: up to 12 letters, digits, periods, underscores and hyphens, starting with a letter")
    guessed = guess_zones(p, options.zone_map)
    transform.apply_zone_map(p, {**guessed, **options.zone_map})
    transform.ensure_references(p, report)
    if guessed:
        report.note(Severity.REVIEW, "MGUARD_ZONES_GUESSED",
                    "zones taken for the mGuard's by their names (check them, or give --zone-map ZONE=internal|external|external2|dmz): "
                    + ", ".join(f"{a}={b}" for a, b in guessed.items()))  # fmt: skip
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, prefix, {**guessed, **options.zone_map}).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, prefix: str, zone_map: Dict[str, str]) -> None:
        self.p, self.report, self.options, self.prefix, self.zone_map = p, report, options, prefix, zone_map
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = {z for r in p.rules for z in r.src_zones + r.dst_zones} | {z for n in p.nat_rules for z in n.src_zones + n.dst_zones}
        used |= {zone_map.get(z, z) for z in p.zones}
        self.present = [INTERNAL, EXTERNAL] + [z for z in (EXTERNAL2, DMZ) if z in used]
        self.externals = [z for z in (EXTERNAL, EXTERNAL2) if z in self.present]
        self.plan = Plan()
        self.taken: Set[str] = set()
        self.ip_groups: Dict[Tuple[str, ...], str] = {}
        self.port_groups: Dict[str, str] = {}
        self.forwards: Set[str] = set()  # names of NAT rules written as port forwarding
        self.ipv6_any = False

    # -- names ---------------------------------------------------------------------------------------------------

    def _name(self, label: str) -> str:
        return names.unique(self.prefix + label, self.taken, names.MGUARD)

    def _row(self, table: str, fields: List[Tuple[str, str]], refs: List[Tuple[str, str]]) -> None:
        self.plan.rows.setdefault(table, []).append(Row(table, fields, refs))

    # -- addresses -----------------------------------------------------------------------------------------------

    def _walk(self, member: str, seen: Optional[Set[str]] = None) -> Tuple[List[Interval], List[str], bool]:
        """(addresses, host names, whether that is all) of a member."""
        seen = seen or set()
        if member == ANY:
            return [FULL_V4, regions.full(6)], [], True
        if member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.FQDN:
                return [], [address.value], True
            if address.builtin == "mguard" and address.raw.startswith(EXTERN) and address.kind == AddressKind.UNSUPPORTED:
                return [], [], False
            found, known = transform.known_intervals(self.p, member)
            return found, [], known
        if member in self.p.address_groups:
            group = self.p.address_groups[member]
            if member in seen or group.unsupported or group.dynamic_filter:
                return [], [], False
            out: List[Interval] = []
            hosts: List[str] = []
            complete = True
            for inner in group.members:
                got, got_hosts, known = self._walk(inner, seen | {member})
                out += got
                hosts += got_hosts
                complete = complete and known
            return out, list(dict.fromkeys(hosts)), complete
        found, known = transform.known_intervals(self.p, member)
        return found, [], known

    def _side(self, members: List[str], negated: bool, rule: Optional[Rule], label: str, flags: Set[str],
              reasons: List[transform.Reason]) -> Optional[List[Ref]]:  # fmt: skip
        """The source or destination of a row: [] when it holds no IPv4 address, None when it cannot be written."""
        if not negated and ANY in members:
            self.ipv6_any = self.ipv6_any or (rule is not None and rule.action == Action.ALLOW and rule.enabled)
            return [("lit", ANY_V4)]
        intervals: List[Interval] = []
        hosts: List[str] = []
        for member in members:
            got, got_hosts, known = self._walk(member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows, or an address the profile does not hold"))
                return None
            intervals += got
            hosts += got_hosts
        v4 = normalize([i for i in intervals if i[0] == 4])
        if any(i[0] == 6 for i in intervals) and not negated:
            flags.add("v6")
        if negated:
            if hosts:
                reasons.append(("FQDN_NOT_SUPPORTED", f"every address but {', '.join(members)}, which holds a host name"))
                return None
            v4 = subtract([FULL_V4], v4)
            flags.add("negated")
            hosts = []
        if hosts:
            flags.add("hosts")
        if not v4 and not hosts:
            return []
        if v4 == [FULL_V4] and not hosts:
            return [("lit", ANY_V4)]
        named_group = len(members) == 1 and not negated and members[0] in self.p.address_groups
        if len(v4) == 1 and not hosts and len(_cidrs(v4[0])) == 1 and not named_group:
            return [("lit", _entry_text(v4[0]))]
        entries = [_entry_text(i) for i in v4] + list(dict.fromkeys(hosts))
        key = tuple(entries)
        if key not in self.ip_groups:
            single = len(members) == 1 and not negated and (members[0] in self.p.addresses or members[0] in self.p.address_groups)
            name = self._name(members[0] if single else (f"{rule.name}_{label}" if rule else label))
            self.ip_groups[key] = name
            comment = f"FWShift: {members[0] if single else ('not ' if negated else '') + ', '.join(members)}"
            self.plan.groups.append(Group("FW_GROUP_IP", name, _comment(comment), entries))
        return [("group", self.ip_groups[key])]

    # -- services ------------------------------------------------------------------------------------------------

    def _port_ref(self, ports: str, label: str) -> Ref:
        """A port field: any, a port, a range, or a port group."""
        if not ports:
            return ("lit", "any")
        parts = ports.split(",")
        if len(parts) == 1:
            return ("lit", parts[0].replace("-", ":"))
        if ports not in self.port_groups:
            name = self._name(label)
            self.port_groups[ports] = name
            self.plan.groups.append(Group("FW_GROUP_PORT", name, _comment(f"FWShift: {label}"), parts))
        return ("group", self.port_groups[ports])

    @staticmethod
    def _merge_ports(lists: List[str]) -> str:
        """The union of port lists (empty: every port)."""
        if any(not ports for ports in lists):
            return ""
        spans: List[Tuple[int, int]] = []
        for ports in lists:
            for part in ports.split(","):
                low, _, high = part.partition("-")
                spans.append((int(low), int(high or low)))
        merged = regions.merge_ranges(spans)
        if merged == [(0, 65535)]:
            return ""
        return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in merged)

    def _services(self, rule: Rule, reasons: List[transform.Reason], flags: Set[str]) -> Optional[List[Tuple[str, Ref, Ref]]]:
        """(protocol, source port, destination port) of each row a rule becomes."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        entries: List[ServiceEntry] = []
        label = rule.services[0] if len(rule.services) == 1 and rule.services[0] != ANY else rule.name
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
            label = "apps_" + "_".join(rule.applications)[:20]
        elif rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: a row of the mGuard names the protocol and ports it matches"))
            return None
        elif ANY in rule.services:
            return [("all", ("lit", "any"), ("lit", "any"))]
        else:
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        deny = rule.action != Action.ALLOW
        by_key: Dict[Tuple[str, str], List[str]] = {}
        other: List[str] = []
        for entry in entries:
            protocol, ip = entry.protocol, entry.ip_protocol
            if protocol == Protocol.IP and ip in (6, 17):
                protocol, entry = (Protocol.TCP if ip == 6 else Protocol.UDP), ServiceEntry(Protocol.TCP if ip == 6 else Protocol.UDP)
            if protocol in (Protocol.TCP, Protocol.UDP):
                by_key.setdefault((protocol.value, entry.src_ports), []).append(entry.dst_ports)
            elif protocol == Protocol.ICMP or (protocol == Protocol.IP and ip == 1):
                if protocol == Protocol.ICMP and (entry.icmp_type is not None or entry.icmp_code is not None):
                    flags.add("icmp-deny" if deny else "icmp-allow")
                    if not deny:
                        continue
                other.append("icmp")
            elif protocol == Protocol.ICMP6 or (protocol == Protocol.IP and ip == 58):
                flags.add("v6")
            elif protocol == Protocol.IP and ip is None:
                other.append("all")
            elif protocol == Protocol.IP and ip == 47:
                other.append("gre")
            else:
                number = ip if protocol == Protocol.IP else 132
                flags.add(f"proto-deny:{number}" if deny else f"proto-allow:{number}")
                if deny:
                    other.append("all")
        if "all" in other:
            return [("all", ("lit", "any"), ("lit", "any"))]
        out: List[Tuple[str, Ref, Ref]] = []
        for (proto, src_ports), dst_lists in by_key.items():
            dst = self._merge_ports(dst_lists)
            out.append((proto, self._port_ref(src_ports, f"{label}_src"), self._port_ref(dst, label)))
        for proto in dict.fromkeys(other):
            out.append((proto, ("lit", "any"), ("lit", "any")))
        return out

    # -- rules ---------------------------------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> Tuple[List[Tuple[str, str]], List[str]]:
        """(pairs of mGuard zones, zones that are not the mGuard's)."""
        unknown = [z for z in rule.src_zones + rule.dst_zones if z != ANY and z not in ZONES]
        sources = list(self.present) if ANY in rule.src_zones else [z for z in rule.src_zones if z in ZONES]
        destinations = list(self.present) if ANY in rule.dst_zones else [z for z in rule.dst_zones if z in ZONES]
        if rule.scope == RuleScope.INTRAZONE:
            pairs = [(z, z) for z in sources if ANY in rule.dst_zones or z in destinations]
        else:
            pairs = [(a, b) for a in sources for b in destinations if rule.scope != RuleScope.INTERZONE or a != b]
        return pairs, list(dict.fromkeys(unknown))

    def _covered(self, table: str) -> Set[Tuple[str, str]]:
        return {pair for pair, name in TABLE_OF.items() if name == table and pair[0] in self.present and pair[1] in self.present}

    def _skip(self, rule: Rule, reasons: List[transform.Reason], severity: Severity = Severity.REVIEW) -> None:
        suffix = "" if rule.action == Action.ALLOW else " This deny rule is NOT enforced; rules below it may match more traffic."
        for code, message in reasons:
            self.report.skip("rule", rule.origin, code, message + "." + suffix, severity)

    def _rule(self, rule: Rule) -> None:
        if not rule.enabled:
            self.report.skip("rule", rule.origin, "MGUARD_DISABLED_LEFT_OUT",
                             "disabled on the source; the mGuard has no rule that is switched off: left out", Severity.INFO)  # fmt: skip
            return
        if FORWARD_TAG in rule.tags and rule.name in self.forwards:
            self.report.skip("rule", rule.origin, "MGUARD_FORWARD_RULE",
                             "the port forwarding of the same name lets this traffic through by itself: not written as a row", Severity.INFO)  # fmt: skip
            return
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        pairs, unknown = self._pairs(rule)
        if unknown:
            reasons.append(("MGUARD_ZONE_UNKNOWN", f"{', '.join(unknown)}: not {'a zone' if len(unknown) == 1 else 'zones'} of the mGuard "
                            "(internal, external, external2, dmz); give the mGuard's zone with --zone-map"))  # fmt: skip
        flags: Set[str] = set()
        services = self._services(rule, reasons, flags)
        source = self._side(rule.sources, rule.negate_source, rule, "src", flags, reasons)
        destination = self._side(rule.destinations, rule.negate_destination, rule, "dst", flags, reasons)
        if reasons or services is None or source is None or destination is None:
            self._skip(rule, list(dict.fromkeys(reasons)) or [("MGUARD_NOT_WRITTEN", "the rule cannot be written")])
            return
        allow = rule.action == Action.ALLOW
        if not source or not destination:
            self.report.skip("rule", rule.origin, "MGUARD_IPV6",
                             "the rule matches IPv6 only (after negation), and the mGuard filters IPv4: not written"
                             + ("" if allow else ". This deny rule is NOT enforced"), Severity.REVIEW)  # fmt: skip
            return
        if not services:
            self.report.skip("rule", rule.origin, "MGUARD_NOT_WRITTEN",
                             "none of its services can be written (ICMP types, ICMPv6, other IP protocols)", Severity.REVIEW)  # fmt: skip
            return
        tables: Dict[str, List[Tuple[str, str]]] = {}
        unforwarded: List[str] = []
        for pair in pairs:
            table = TABLE_OF.get(pair)
            if table is None:
                unforwarded.append(f"{pair[0]} -> {pair[1]}")
                continue
            tables.setdefault(table, []).append(pair)
        only_inside = tables.get("FW_OUTGOING") == [(INTERNAL, INTERNAL)]
        if only_inside:
            del tables["FW_OUTGOING"]  # (between VLANs of the internal side only: see MGUARD_VLAN_ROUTING)
        if only_inside and not tables:
            self.report.skip("rule", rule.origin, "MGUARD_INTERNAL_ROUTING",
                             "traffic between networks of the internal side only: the mGuard decides it by the outgoing rules, which "
                             "decide traffic to the external side as well; not written" + ("" if allow else ". This deny rule is NOT enforced"))  # fmt: skip
            return
        if not tables:
            self.report.skip("rule", rule.origin, "MGUARD_NOT_FORWARDED",
                             "the mGuard forwards no traffic between these zones (" + ", ".join(unforwarded[:6]) + "): nothing to write",
                             Severity.INFO)  # fmt: skip
            return
        wider: List[str] = []
        for table, have in tables.items():
            missing = self._covered(table) - set(have) - {(INTERNAL, INTERNAL)}
            if table == "FW_INCOMING":
                missing = set()  # (EXT_IF says which external interface)
            if missing:
                wider.append(f"{table} also decides " + ", ".join(f"{a} -> {b}" for a, b in sorted(missing)))
        if wider and allow:
            self.report.skip("rule", rule.origin, "MGUARD_TABLE_WIDER",
                             "; ".join(wider) + ", which the rule does not name: not written, as it would allow more", Severity.REVIEW)  # fmt: skip
            return
        if wider:
            self.report.add("rule", rule.origin, Severity.REVIEW, "MGUARD_TABLE_WIDER", "; ".join(wider) + ": the row blocks there as well")
        self._findings(rule, flags, allow)
        action = "ACCEPT" if allow else ("REJECT" if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH) else "DROP")
        log = "yes" if rule.log_start or rule.log_end else "no"
        comment = _comment(f"{rule.name}: {rule.description}" if rule.description else rule.name)
        written: List[str] = []
        for table, have in tables.items():
            for proto, from_port, in_port in services:
                fields: List[Tuple[str, str]] = []
                refs: List[Tuple[str, str]] = []
                if table == "FW_INCOMING":
                    sources = {a for a, _ in have}
                    fields.append(("EXT_IF", "all" if sources >= {EXTERNAL, EXTERNAL2} else ("ext2" if sources == {EXTERNAL2} else "ext1")))
                fields.append(("PROTO", proto))
                for name, ref in (("FROM_IP", source[0]), ("FROM_PORT", from_port), ("IN_IP", destination[0]), ("IN_PORT", in_port)):
                    if ref[0] == "group":
                        refs.append((name, ref[1]))
                        fields.append((name, "0.0.0.0/32" if name.endswith("_IP") else "0"))  # (until the reference is set)
                    else:
                        fields.append((name, ref[1]))
                fields += [("TARGET_REF", action), ("LOG", log), ("COMMENT", comment)]
                self._row(table, fields, refs)
                written.append(table)
        counts = {t: written.count(t) for t in dict.fromkeys(written)}
        self.report.item("rule", rule.origin).emitted_as.append(", ".join(f"{n} row{'s' if n > 1 else ''} of {t}" for t, n in counts.items()))
        if len(written) > 1:
            self.report.add("rule", rule.origin, Severity.INFO, "MGUARD_ROWS_SPLIT",
                            "a row of the mGuard has one protocol and is in one table: written as " + ", ".join(f"{n} rows of {t}" if n > 1 else f"a row of {t}"
                                                                                                    for t, n in counts.items()))  # fmt: skip
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "MGUARD_REJECT", f"action {rule.action.value}: written as Reject")

    def _findings(self, rule: Rule, flags: Set[str], allow: bool) -> None:
        origin = rule.origin
        if "negated" in flags:
            self.report.add("rule", origin, Severity.INFO, "NEGATION_EXPANDED",
                            "a row of the mGuard cannot negate: written as an IP group of the IPv4 addresses that are left")  # fmt: skip
        if "v6" in flags:
            self.report.add("rule", origin, Severity.APPROX if allow else Severity.REVIEW, "MGUARD_IPV6",
                            "the IPv6 part of the rule (addresses, ICMPv6) is left out: the mGuard filters IPv4"
                            + ("" if allow else "; IPv6 traffic is not blocked by it"))  # fmt: skip
        if "hosts" in flags:
            ipv4 = all(a.fqdn_family == 4 for a in self.p.addresses.values() if a.kind == AddressKind.FQDN)
            self.report.add("rule", origin, Severity.INFO if ipv4 else Severity.APPROX if allow else Severity.REVIEW, "MGUARD_HOSTNAME",
                            "host names are written into an IP group: the mGuard resolves them for IPv4 with its own DNS settings "
                            "(an FL MGUARD 2000 takes none)" + ("" if allow else "; Phoenix advises against them in blocking rules"))  # fmt: skip
        if "icmp-allow" in flags:
            self.report.add("rule", origin, Severity.REVIEW, "MGUARD_ICMP_TYPE",
                            "a row cannot match an ICMP type or code: the ICMP of the rule is left out, so it allows less")
        if "icmp-deny" in flags:
            self.report.add("rule", origin, Severity.REVIEW, "MGUARD_ICMP_TYPE",
                            "a row cannot match an ICMP type or code: written for all of ICMP, so it blocks more")
        protocols = sorted({f.split(":")[1] for f in flags if f.startswith("proto-")})
        if protocols:
            if allow:
                self.report.add("rule", origin, Severity.REVIEW, "MGUARD_PROTOCOL",
                                f"IP protocols {', '.join(protocols)}: a row takes tcp, udp, icmp, gre or all; left out, so it allows less")  # fmt: skip
            else:
                self.report.add("rule", origin, Severity.REVIEW, "MGUARD_PROTOCOL",
                                f"IP protocols {', '.join(protocols)}: a row takes tcp, udp, icmp, gre or all; written as all, so it blocks more")  # fmt: skip

    def _defaults(self) -> None:
        if self.p.default_interzone != Action.ALLOW:
            return
        for table in TABLES:
            covered = self._covered(table)
            if not covered:
                continue
            fields: List[Tuple[str, str]] = []
            if table == "FW_INCOMING":
                fields.append(("EXT_IF", "all"))
            fields += [("PROTO", "all"), ("FROM_IP", ANY_V4), ("FROM_PORT", "any"), ("IN_IP", ANY_V4), ("IN_PORT", "any"),
                       ("TARGET_REF", "ACCEPT"), ("LOG", "no"), ("COMMENT", "FWShift: the default of the source, allow")]  # fmt: skip
            self._row(table, fields, [])
        self.report.note(Severity.REVIEW, "MGUARD_DEFAULT_ALLOW",
                         "the source allows what no rule matches: a row that accepts everything ends each table written")

    # -- NAT -----------------------------------------------------------------------------------------------------

    def _nat_side(self, members: List[str], label: str) -> Optional[Ref]:
        flags: Set[str] = set()
        reasons: List[transform.Reason] = []
        found = self._side(members, False, None, label, flags, reasons)
        if found is None or not found or "v6" in flags or "hosts" in flags:
            return None
        return found[0]

    def _box(self, members: List[str], negated: bool) -> Optional[List[Interval]]:
        intervals: List[Interval] = []
        for member in members:
            got, hosts, known = self._walk(member)
            if not known or hosts:
                return None
            intervals += [i for i in got if i[0] == 4]
        v4 = normalize(intervals)
        return subtract([FULL_V4], v4) if negated else v4

    def _post_zones(self, nat: NatRule) -> List[str]:
        """The zone the translated address of a destination NAT lies in: by the networks of the zones (longest prefix),
        else the destination zones of the rule that are the internal side or the DMZ; [] when it is not known."""
        assert nat.destination_translation is not None
        target = transform.address_intervals(self.p, nat.destination_translation.address) or []
        matches: List[Tuple[int, str]] = []  # (size of the network, zone)
        for zone, nets in {**self.p.zone_networks, **self.options.zone_networks}.items():
            for net in nets:
                for interval in transform.address_intervals(self.p, net) or []:
                    if target and all(interval[0] == t[0] and interval[1] <= t[1] and t[2] <= interval[2] for t in target):
                        matches.append((interval[2] - interval[1], self.zone_map.get(zone, zone)))
        if matches:
            smallest = min(size for size, _ in matches)
            return list(dict.fromkeys(zone for size, zone in matches if size == smallest))
        return [z for z in nat.dst_zones if z in (INTERNAL, DMZ)]

    def _forward_allowed(self, nat: NatRule) -> str:
        """Why the rules of the model do not allow all of what a port forwarding forwards; '' when they do."""
        post = self._post_zones(nat)
        entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else [ServiceEntry(Protocol.IP)]
        sources, destinations = self._box(nat.sources, False), self._box(nat.destinations, False)
        services = regions.service_set(entries) if entries else None
        if sources is None or destinations is None or services is None:
            return "what it forwards cannot be read"
        remaining: List[regions.Box] = [(4, sources, destinations, services)]
        for rule in self.p.rules:
            if not rule.enabled or not remaining:
                continue
            if ANY not in rule.src_zones and not set(rule.src_zones) & set(nat.src_zones) and ANY not in nat.src_zones:
                continue
            if ANY not in rule.dst_zones and post and not set(rule.dst_zones) & set(post):
                continue
            covers = ANY in rule.dst_zones or (bool(post) and set(post) <= set(rule.dst_zones))
            if rule.scope == RuleScope.INTRAZONE:
                continue
            rule_sources = self._box(rule.sources, rule.negate_source)
            rule_destinations = self._box(rule.destinations, rule.negate_destination)
            flat: Optional[List[ServiceEntry]] = [ServiceEntry(Protocol.IP)] if ANY in rule.services else []
            for name in [] if ANY in rule.services else rule.services:
                found = transform.flatten_services(self.p, name)
                flat = None if found is None or flat is None else flat + found
            rule_services = regions.service_set(flat) if flat else None
            readable = not (rule.unsupported or rule.schedule or rule.users != [ANY] or rule.applications != [ANY]
                            or rule.url_categories != [ANY] or rule.negate_service)  # fmt: skip
            if rule_sources is None or rule_destinations is None or rule_services is None or not readable:
                if any(regions.box_and(box, (4, [FULL_V4], [FULL_V4], regions.ALL_SERVICES)) for box in remaining):
                    return f"rule {rule.name} may decide part of it and cannot be read exactly"
                continue
            cut: regions.Box = (4, rule_sources, rule_destinations, rule_services)
            if not any(regions.box_and(box, cut) for box in remaining):
                continue
            if rule.action != Action.ALLOW:
                return f"rule {rule.name} blocks part of it"
            if not covers:
                return f"rule {rule.name} may decide part of it, and the zone the forwarded traffic goes to is not known"
            left = regions.minus_all(remaining, [cut])
            if left is None:
                return "too many pieces to follow"
            remaining = [box for box in left if not regions.empty(box)]
        if remaining and self.p.default_interzone != Action.ALLOW:
            return "no rule allows part of it"
        return ""

    def _forward(self, nat: NatRule) -> str:
        dnat = nat.destination_translation
        assert dnat is not None
        if dnat.spread:
            return "a translation to one of several addresses"
        target = transform.address_intervals(self.p, dnat.address)
        if not target or len(target) != 1 or target[0][0] != 4 or target[0][1] != target[0][2]:
            return f"the translated address '{dnat.address}' is not one IPv4 address"
        if len(nat.destinations) != 1 or nat.destinations[0] == ANY:
            return "port forwarding takes one address it is for"
        member = nat.destinations[0]
        address = self.p.addresses.get(member)
        if address is not None and address.builtin == "mguard" and address.raw.startswith(EXTERN):
            in_ip = EXTERN
        else:
            found = transform.address_intervals(self.p, member)
            if not found or len(found) != 1 or found[0][0] != 4 or found[0][1] != found[0][2]:
                return "the address it is for is not one IPv4 address"
            in_ip = str(int_to_ip(4, found[0][1]))
        entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else None
        if not entries:
            return "port forwarding takes tcp or udp with a port, or gre"
        kinds = {(e.protocol, e.ip_protocol) for e in entries}
        if len(kinds) != 1:
            return "port forwarding takes one protocol"
        entry = entries[0]
        rows: List[Tuple[str, str, str]] = []  # (proto, in port, out port)
        src_ports = ""
        if entry.protocol == Protocol.IP and entry.ip_protocol == 47:
            rows.append(("gre", "", ""))
        elif entry.protocol in (Protocol.TCP, Protocol.UDP):
            src_list = {e.src_ports for e in entries}
            if len(src_list) != 1:
                return "port forwarding takes one set of source ports"
            src_ports = src_list.pop()
            ports: List[int] = []
            for e in entries:
                if not e.dst_ports:
                    return "port forwarding takes the ports it forwards, one by one"
                for part in e.dst_ports.split(","):
                    low, _, high = part.partition("-")
                    ports += list(range(int(low), int(high or low) + 1))
                    if len(ports) > _MAX_PORTS_PER_FORWARD:
                        return f"more than {_MAX_PORTS_PER_FORWARD} ports (port forwarding takes one port a row)"
            ports = sorted(set(ports))
            if dnat.port and len(ports) > 1:
                return "several ports translated to one"
            rows += [(entry.protocol.value, str(port), dnat.port or str(port)) for port in ports]
        else:
            return "port forwarding takes tcp, udp or gre"
        if ANY not in nat.src_zones and not set(nat.src_zones) & set(self.externals):
            return "port forwarding is for traffic that arrives on the external side"
        source = self._nat_side(nat.sources, f"{nat.name}_src")
        if source is None:
            return "its sources cannot be written as one IPv4 address, network or IP group"
        why = self._forward_allowed(nat)
        if why:
            self.report.skip("nat", nat.origin, "MGUARD_FORWARD_BLOCKED",
                             f"port forwarding skips the packet filter, and the rules of the model do not allow all of what it would "
                             f"forward ({why}): not written, as it would let in more")  # fmt: skip
            return "-"
        src_ref = self._port_ref(src_ports, f"{nat.name}_srcports")
        implied = [r for r in self.p.rules if FORWARD_TAG in r.tags and r.name == nat.name]  # (a port forwarding of an mGuard source)
        log = "yes" if implied and (implied[0].log_start or implied[0].log_end) else "no"
        target_ip = str(int_to_ip(4, target[0][1]))
        for proto, in_port, out_port in rows:
            fields = [("PROTO", proto)]
            refs: List[Tuple[str, str]] = []
            for name, ref in (("SRC_IP", source), ("SRC_PORT", src_ref)):
                if name == "SRC_PORT" and proto == "gre":
                    continue  # (GRE has no ports: the fields keep what the mGuard puts in a new row)
                if ref[0] == "group":
                    refs.append((name, ref[1]))
                    fields.append((name, "0.0.0.0/32" if name == "SRC_IP" else "0"))
                else:
                    fields.append((name, ref[1]))
            fields.append(("IN_IP", in_ip))
            if proto != "gre":
                fields.append(("IN_PORT", in_port))
            fields.append(("OUT_IP", target_ip))
            if proto != "gre":
                fields.append(("OUT_PORT", out_port))
            fields += [("LOG", log), ("COMMENT", _comment(f"{nat.name}: {nat.description}" if nat.description else nat.name))]
            self._row("FW_PORTFORWARDING", fields, refs)
        self.forwards.add(nat.name)
        self.report.add("nat", nat.origin, Severity.INFO, "MGUARD_FORWARD_ALLOWED",
                        "port forwarding skips the packet filter; the rules of the model allow all of what it forwards")  # fmt: skip
        if len(rows) > 1:
            self.report.add("nat", nat.origin, Severity.INFO, "MGUARD_ROWS_SPLIT", f"one port a row: {len(rows)} rows of FW_PORTFORWARDING")
        if ANY in nat.src_zones:
            self.report.add("nat", nat.origin, Severity.APPROX, "MGUARD_NAT_ZONES",
                            "the rule is for traffic from every zone; port forwarding applies to what arrives for its address")  # fmt: skip
        return ""

    def _one_to_one(self, nat: NatRule, pair: Tuple[Interval, Interval]) -> str:
        inside, outside = pair
        nets = [_cidrs(inside), _cidrs(outside)]
        if len(nets[0]) != 1 or len(nets[1]) != 1:
            return "1:1 NAT maps one network to one network of the same size"
        if nat.service != ANY or nat.destinations != [ANY]:
            return "1:1 NAT has no service or destination"
        local, remote = ipaddress.IPv4Network(nets[0][0]), ipaddress.IPv4Network(nets[1][0])
        self._row("FW_1TO1_NAT", [("LOCAL_NET", str(local.network_address)), ("REMOTE_NET", str(remote.network_address)),
                                  ("MASK", str(local.prefixlen)), ("ENABLE_ARP", "yes"),
                                  ("COMMENT", _comment(f"{nat.name}: {nat.description}" if nat.description else nat.name))], [])  # fmt: skip
        if (ANY not in nat.src_zones and nat.src_zones != [INTERNAL]) or (ANY not in nat.dst_zones and not set(nat.dst_zones) <= set(self.externals)):
            self.report.add("nat", nat.origin, Severity.APPROX, "MGUARD_NAT_ZONES",
                            "1:1 NAT maps between the internal and the external side; the zones of the rule are "
                            + ", ".join(nat.src_zones) + " -> " + ", ".join(nat.dst_zones))  # fmt: skip
        return ""

    def _masquerade(self, nat: NatRule) -> str:
        if nat.destinations != [ANY] or nat.service != ANY:
            return "IP masquerading has no destination or service"
        zones = [z for z in nat.dst_zones if z != ANY]
        if ANY in nat.dst_zones or not zones:
            return "IP masquerading names the interface the traffic leaves by: the rule names no zone"
        if set(zones) == set(self.externals) and len(zones) > 1:
            ext_if = "all"
        elif len(zones) == 1 and zones[0] in ZONES:
            ext_if = {INTERNAL: "int", EXTERNAL: "ext1", EXTERNAL2: "ext2", DMZ: "dmz0"}[zones[0]]
        else:
            return "IP masquerading names one interface (or all external ones)"
        source = self._nat_side(nat.sources, f"{nat.name}_src")
        if source is None:
            return "its sources cannot be written as one IPv4 address, network or IP group"
        fields = [("EXT_IF", ext_if), ("IN_IP", "0.0.0.0/32" if source[0] == "group" else source[1]),
                  ("COMMENT", _comment(f"{nat.name}: {nat.description}" if nat.description else nat.name))]  # fmt: skip
        self._row("FW_NAT", fields, [("IN_IP", source[1])] if source[0] == "group" else [])
        if nat.src_zones != [ANY]:
            self.report.add("nat", nat.origin, Severity.APPROX, "MGUARD_NAT_ZONES",
                            "the rule is for traffic from " + ", ".join(nat.src_zones) + "; IP masquerading applies to traffic from every zone")
        return ""

    def _nat(self) -> Set[str]:
        written: Set[str] = set()
        for nat in self.p.nat_rules:
            if not nat.enabled:
                why = "the rule is disabled on the source"
            elif nat.unsupported:
                why = "not converted on the source: " + "; ".join(nat.unsupported)[:200]
            else:
                pair = transform.bidirectional_pair(self.p, nat)
                dnat, snat = nat.destination_translation, nat.source_translation
                if pair is not None:
                    why = self._one_to_one(nat, pair)
                elif dnat is not None and snat is None:
                    why = self._forward(nat)
                elif snat is not None and dnat is None and snat.kind == SnatKind.INTERFACE:
                    why = self._masquerade(nat)
                elif dnat is None and snat is None:
                    why = "a rule that translates nothing (an exemption): the mGuard has none"
                else:
                    why = "the mGuard translates a source only to the address of an interface, or a network 1:1"
            if why == "-":
                continue
            if why:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED", f"not converted: {why}")
                continue
            written.add(nat.origin)
        return written

    # -- output --------------------------------------------------------------------------------------------------

    def run(self) -> str:
        written = self._nat()
        static = {n.origin for n in self.p.nat_rules if n.origin in written and transform.bidirectional_pair(self.p, n) is not None}
        transform.to_post_nat_lookup(self.p, self.report, static)
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        for nat in self.p.nat_rules:
            if nat.origin in written:
                kind = "1:1 NAT" if nat.origin in static else ("port forwarding" if nat.name in self.forwards else "IP masquerading")
                self.report.item("nat", nat.origin).emitted_as.append(kind)
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        self._notes()
        return _script(self.plan, self.prefix)

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "MGUARD_LOAD",
                         "the output is a shell script of gaiconfig calls, to run on the mGuard as root or admin (section 10): DRY_RUN=1 "
                         "prints them. It adds groups and rows after the rows the tables have, and stops before it writes anything when "
                         "a group name is taken or a table it adds to has rows (FWSHIFT_APPEND=yes adds after them). The rows take effect "
                         "with the last call, and only where FW_INCOMING_GLOBAL and FW_OUTGOING_GLOBAL are 'rules'")  # fmt: skip
        if self.plan.rows.get("FW_OUTGOING"):
            self.report.note(Severity.APPROX, "MGUARD_VLAN_ROUTING",
                             "the outgoing rows also decide connections from one VLAN of the internal side to another, which the mGuard "
                             "routes when it has more than one internal network: there they match as they do towards the external side")  # fmt: skip
        if self.ipv6_any:
            self.report.note(Severity.APPROX, "MGUARD_IPV4_ONLY",
                             "the mGuard filters IPv4: rules that match any address are written for 0.0.0.0/0, and match no IPv6")
        if any(r.enabled and (r.log_start or r.log_end) for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rows have LOG yes")


def _script(plan: Plan, prefix: str) -> str:
    out = [
        "#!/bin/sh",
        "# Generated by FWShift: rows for the packet filter (and NAT) of a Phoenix Contact mGuard, added with gaiconfig.",
        "# Read the report first: what is not written is listed there.",
        "#",
        "#   DRY_RUN=1 sh THIS_FILE            prints the gaiconfig calls; runs anywhere",
        "#   sh THIS_FILE                      on the mGuard (SSH, as root or admin): adds the groups and rows",
        "#   FWSHIFT_APPEND=yes sh THIS_FILE   also when the tables have rows: the new ones go after them",
        "#",
        "# Nothing is changed or deleted, and no interface, route or access to the mGuard is touched. Every call but the last",
        "# writes with --silent; the last one reconfigures, and the rows take effect then. A call gaiconfig refuses stops the",
        f"# script: what was written before is stored but not active (the groups start with '{prefix}', the rows' comments",
        "# with the names of the rules); remove it in the web interface, or run the script again after fixing the cause.",
        "set -u",
        'DRY_RUN="${DRY_RUN:-}"',
        'FWSHIFT_APPEND="${FWSHIFT_APPEND:-}"',
        "fail() { printf 'FAILED: %s\\n' \"$*\" >&2; exit 1; }",
        "gc() {",
        '  if [ -n "$DRY_RUN" ]; then printf \'gaiconfig\' >&2; printf \' %s\' "$@" >&2; printf \'\\n\' >&2; return 0; fi',
        '  gaiconfig "$@" >/dev/null || fail "gaiconfig $*"',
        "}",
        "rows() {",
        '  if [ -n "$DRY_RUN" ]; then echo 0; return 0; fi',
        '  gaiconfig --get-rowcount "$1" || fail "gaiconfig --get-rowcount $1"',
        "}",
        "named() {",
        '  [ -z "$DRY_RUN" ] && gaiconfig --get "$1" 2>/dev/null | grep -F -q "NAME = \\"$2\\""',
        "}",
        'if [ -z "$DRY_RUN" ] && ! command -v gaiconfig >/dev/null 2>&1; then fail "gaiconfig not found: run this on the mGuard"; fi',
    ]
    tables = [t for t in TABLES + NAT_TABLES if plan.rows.get(t)]
    calls: List[List[str]] = []  # (the lines of each call, so that the last one can lose --silent)
    body: List[str] = []
    if tables:
        out += [
            f"for t in {' '.join(tables)}; do",
            '  n=$(rows "$t")',
            '  if [ "$n" != 0 ] && [ "$FWSHIFT_APPEND" != yes ]; then',
            '    fail "$t has $n rows, which the mGuard would check before the new ones; nothing was written (FWSHIFT_APPEND=yes adds after them)"',
            "  fi",
            "done",
        ]
    for group in plan.groups:
        kind = "an IP group" if group.table == "FW_GROUP_IP" else "a port group"
        out.append(f"named {group.table} {shlex.quote(group.name)} && fail {shlex.quote(f'{kind} named {group.name} exists; nothing was written')}")
    for table in ("FW_GROUP_IP", "FW_GROUP_PORT"):
        groups = [g for g in plan.groups if g.table == table]
        if not groups:
            continue
        field_name = "IP" if table == "FW_GROUP_IP" else "PORT"
        body += ["", f"# {table}", f"N=$(rows {table})"]
        for group in groups:
            body.append(f"gc --silent --goto {table} --add-row --set .NAME {shlex.quote(group.name)} --set .COMMENT {shlex.quote(group.comment)}")
            calls.append([body[-1]])
            for entry in group.entries:
                body.append(f'gc --silent --goto "{table}.$N.ENTRY" --add-row --set .{field_name} {shlex.quote(entry)}')
                calls.append([body[-1]])
            body.append("N=$((N+1))")
    for table in tables:
        body += ["", f"# {table}", f"N=$(rows {table})"]
        for row in plan.rows[table]:
            sets = " ".join(f"--set .{name} {shlex.quote(value)}" for name, value in row.fields)
            body.append(f"gc --silent --goto {table} --add-row {sets}")
            calls.append([body[-1]])
            for name, ref_name in row.refs:
                body.append(f'gc --silent --set-refname "{table}.$N.{name}" {shlex.quote(ref_name)}')
                calls.append([body[-1]])
            body.append("N=$((N+1))")
    if calls:
        last = calls[-1][0]
        index = len(body) - 1 - body[::-1].index(last)
        body[index] = last.replace("gc --silent ", "gc ", 1)
    out += body
    out += [
        "",
        'if [ -z "$DRY_RUN" ]; then',
        "  for v in FW_INCOMING_GLOBAL FW_OUTGOING_GLOBAL; do",
        '    g=$(gaiconfig --get "$v" 2>/dev/null || true)',
        '    [ "$g" = rules ] || printf \'NOTE: %s is %s: the rows take effect only with "Use the firewall ruleset below" (rules)\\n\' "$v" "$g" >&2',
        "  done",
        "fi",
        "echo 'Done. Check the tables in the web interface (Network Security >> Packet Filter, Network >> NAT).' >&2",
    ]
    if not calls:
        out.insert(-1, "echo 'Nothing to add: every rule is in the report.' >&2")
    return "\n".join(out) + "\n"
