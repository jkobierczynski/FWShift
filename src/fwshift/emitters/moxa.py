# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Moxa industrial secure router emitter: neutral model -> CLI commands for the Layer 3 policy and NAT of a router with
Moxa's classic router firmware (EDR-810, EDR-G902/G903, TN-4900), as Moxa's *Industrial Secure Router CLI Command Set*
manual writes them.

Design rules:

* The output is commands of global configuration mode, pasted into the console (serial, Telnet or SSH) after
  ``configure``: each policy ``firewall N`` with its sub-commands and ``exit``, then the NAT rules. It is not a file to
  import: an imported configuration file replaces the router's configuration. Nothing is deleted, nothing is saved.
* A policy of the router has one protocol (``all``, ``tcp``, ``udp`` or ``icmp``), one source and one destination
  (``all``, ``single`` or ``range`` of IPv4 addresses), one source and one destination port (``all``, ``single``,
  ``range``) and one pair of interfaces (``lan``, ``wan1``, ``wan2`` or ``all``). A rule of the model becomes one policy
  for every combination of its pieces, in its place; a negated side becomes the ranges it leaves.
* The policies are numbered from ``--policy-id-start`` (default 1). ``firewall N`` enters the policy N when it exists,
  so on a router that has policies the start must be above the last of them (``show firewall``); policies after them
  only decide what those do not.
* Each policy is first written to match nothing (``src-ip single 0.0.0.0``), and its source is set last: a policy
  that is half entered decides no packet. A rule that cannot be written keeps that source and is switched off with
  ``firewall N disable``.
* Zones are the interfaces: a zone of the model must be ``lan``, ``wan1`` or ``wan2`` (``--zone-map``); a rule for
  another zone is written disabled. Traffic inside one interface does not pass the router.
* The router lets through what no policy matches (assumed, as for the parser): after the converted rules, a policy
  that drops is written for every pair of interfaces when the source denies what no rule matches.
* Port forwarding and 1-to-1 NAT are done before the Layer 3 policy (assumed), whose policies name the inside address:
  the rules are written for it. NAT rules are appended (``ip nat ...`` without an index).
"""

from __future__ import annotations

import copy
from typing import AbstractSet, Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, Interval, int_to_ip, normalize, subtract
from ..options import Options
from ..parsers.moxa import INTERFACE_WORDS
from ..report import Report, Severity

# Policies one rule may become before it is written disabled instead: the router holds a few hundred in all
# (256 on an EDR-G903, Moxa's manual).
MAX_PIECES = 32
LIMIT = 256
_NOTHING = "src-ip single 0.0.0.0"

_Piece = Tuple[str, str, str]  # (protocol, src-port words, dst-port words)


def _text(text: str, limit: int = 120) -> str:
    return "".join(c if " " <= c <= "~" else " " for c in text).strip()[:limit]


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    probe = _Emitter(p, Report(), options, source_zones)
    written = {nat.origin for nat in p.nat_rules if probe.nat_line(nat)}
    translated = {o for o in written if any(n.origin == o and (n.destination_translation is not None or
                                                               (n.source_translation is not None and n.source_translation.bidirectional))
                                             for n in p.nat_rules)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones = source_zones
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.index = options.policy_id_start or 1
        self.lines: List[str] = []
        self.nat: List[str] = []
        self.not_written: List[str] = []
        self.used: List[str] = []  # the interface words the rules name
        self.decided: Set[Tuple[str, str]] = set()
        self.unknown_zones: List[str] = []
        self.logged: List[str] = []

    # -- pieces of a rule -------------------------------------------------------------------------------------

    @staticmethod
    def _word(zone: str) -> Optional[str]:
        if zone == ANY:
            return "all"
        return zone.lower() if zone.lower() in INTERFACE_WORDS else None

    def _pairs(self, rule: Rule, reasons: List[transform.Reason]) -> List[Tuple[str, str]]:
        words: Dict[str, Optional[str]] = {z: self._word(z) for z in rule.src_zones + rule.dst_zones}
        bad = [z for z, w in words.items() if w is None]
        if bad:
            self.unknown_zones += [z for z in bad if z not in self.unknown_zones]
            reasons.append(("MOXA_ZONE", "zones " + ", ".join(bad[:4]) + ": a policy names the interfaces lan, wan1, wan2 or all (give "
                                         "--zone-map ZONE=lan|wan1|wan2)"))  # fmt: skip
            return [("all", "all")]
        sources = ["all"] if ANY in rule.src_zones else [str(words[z]) for z in rule.src_zones]
        destinations = ["all"] if ANY in rule.dst_zones else [str(words[z]) for z in rule.dst_zones]
        if rule.scope == RuleScope.INTRAZONE:
            pairs = [(s, s) for s in (list(INTERFACE_WORDS) if sources == ["all"] else sources)]
        elif rule.scope == RuleScope.INTERZONE:
            sources = list(INTERFACE_WORDS) if sources == ["all"] else sources
            destinations = list(INTERFACE_WORDS) if destinations == ["all"] else destinations
            pairs = [(s, d) for s in sources for d in destinations if s != d]
        else:
            pairs = [(s, d) for s in sources for d in destinations]
        kept = [(s, d) for s, d in pairs if s == "all" or s != d]
        if len(kept) < len(pairs):
            severity = Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW
            self.report.add("rule", rule.origin, severity, "MOXA_INTRAZONE",
                            "traffic inside one interface does not pass the router's policies: the part of the rule inside "
                            + ", ".join(sorted({s for s, d in pairs if s == d and s != "all"})) + " is not written"
                            + (", and the router does not block it" if rule.action != Action.ALLOW else ""))  # fmt: skip
        return kept

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        """The IPv4 ranges of one side, [FULL_V4] for any; None when they cannot be known."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        out: List[Interval] = []
        for member in members:
            if member == ANY:
                out = [FULL_V4]
                break
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: a policy names IPv4 addresses only"))
                return None
            if member in self.taint_a:
                return None  # (said by blocking_reasons)
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
                return None
            out += [i for i in intervals if i[0] == 4]
        out = normalize(out)
        if negated:
            out = subtract([FULL_V4], out)
        return out

    def _port_words(self, ports: str, rule: Rule) -> Optional[List[str]]:
        """The ``single``/``range`` words for a port list of the model (``all``); None for what cannot be said. A range from
        port 0 is written from 1 (port 0 is no port a connection uses)."""
        if not ports:
            return ["all"]
        out = []
        for part in ports.split(","):
            first, _, last = part.partition("-")
            if not first.isdigit() or (last and not last.isdigit()) or (first == "0" and (not last or last == "0")):
                return None
            if first == "0":
                first = "1"
                self.report.add("rule", rule.origin, Severity.APPROX, "MOXA_PORT_ZERO", "a range of ports from 0, written from 1; port 0 is no port a connection uses")
            out.append(f"single {first}" if not last or last == first else f"range {first} {last}")
        return out

    def _pieces(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[_Piece]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries: List[ServiceEntry] = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: a policy names one protocol and its ports"))
            return None
        elif rule.services == [ANY]:
            return [("all", "all", "all")]
        else:
            entries = []
            for name in rule.services:
                if name in self.taint_s:
                    return None  # (said by blocking_reasons)
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        out: List[_Piece] = []
        six = False
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                src, dst = self._port_words(entry.src_ports, rule), self._port_words(entry.dst_ports, rule)
                if src is None or dst is None:
                    reasons.append(("SERVICE_NOT_WRITTEN", "a port list that cannot be read"))
                    return None
                out += [(entry.protocol.value, s, d) for s in src for d in dst]
            elif entry.protocol == Protocol.ICMP:
                if entry.icmp_type is not None or entry.icmp_code is not None:
                    reasons.append(("SERVICE_NOT_WRITTEN", "an ICMP type or code: a policy matches every ICMP message or none"))
                    return None
                out.append(("icmp", "all", "all"))
            elif entry.protocol == Protocol.ICMP6:
                six = True
            elif entry.protocol == Protocol.IP and entry.ip_protocol in (None, 6, 17, 1):
                out.append(({None: "all", 6: "tcp", 17: "udp", 1: "icmp"}[entry.ip_protocol], "all", "all"))
            elif entry.protocol == Protocol.IP and entry.ip_protocol == 58:
                six = True
            else:
                what = "SCTP" if entry.protocol == Protocol.SCTP else f"IP protocol {entry.ip_protocol}"
                reasons.append(("SERVICE_NOT_WRITTEN", f"{what}: a policy names all, TCP, UDP or ICMP"))
                return None
        if six:
            self.report.add("rule", rule.origin, Severity.INFO, "MOXA_IPV6_SERVICE", "ICMPv6 is IPv6, which the router's policies do not filter: not written")
        if ("all", "all", "all") in out:
            return [("all", "all", "all")]
        out = list(dict.fromkeys(out))
        if not out:
            reasons.append(("NOT_WRITTEN", "no service the router's IPv4 policies can match"))
            return None
        return out

    # -- writing ----------------------------------------------------------------------------------------------

    @staticmethod
    def _address_words(interval: Interval) -> str:
        if interval == FULL_V4:
            return "all"
        first, last = int_to_ip(4, interval[1]), int_to_ip(4, interval[2])
        return f"single {first}" if first == last else f"range {first} {last}"

    def _policy(self, action: str, pair: Tuple[str, str], source: str, destination: str, piece: _Piece, active: bool) -> int:
        """Write one policy; its index."""
        index = self.index
        self.index += 1
        protocol, src_port, dst_port = piece
        lines = [f"firewall {index}", f" {_NOTHING}", f" action {action}", f" protocol {protocol}", f" dst-ip {destination}"]
        if src_port != "all":
            lines.append(f" src-port {src_port}")
        if dst_port != "all":
            lines.append(f" dst-port {dst_port}")
        lines.append(f" interface {pair[0]} {pair[1]}")
        if active:
            lines.append(f" src-ip {source}")
        lines.append("exit")
        if not active:
            lines.append(f"firewall {index} disable")
        self.lines += lines
        for word in pair:
            if word != "all" and word not in self.used:
                self.used.append(word)
        return index

    def _families(self, rule: Rule) -> Set[int]:
        """The IP versions a rule can match (a negated side: both)."""
        out = {4, 6}
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            if not negated:
                found: Set[int] = set()
                for member in members:
                    found |= transform.families(self.p, member)
                out &= found
        return out

    def _rule(self, rule: Rule) -> None:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        pairs = self._pairs(rule, reasons)
        pieces = self._pieces(rule, reasons)
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        if (sources == [] or destinations == []) and not reasons:
            reasons.append(("NOT_WRITTEN", "the rule matches no IPv4 address: the router's policies are IPv4"))

        total = len(pairs) * len(sources or [()]) * len(destinations or [()]) * len(pieces or [()])
        if not reasons and total > MAX_PIECES:
            reasons.append(("MOXA_TOO_MANY", f"the rule would need {total} policies (more than {MAX_PIECES})"))
        reasons = list(dict.fromkeys(reasons))
        disabled = bool(reasons) or pieces is None or not sources or not destinations
        if disabled:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
        action = "accept" if rule.action == Action.ALLOW else "drop"
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.APPROX, "MOXA_RESET_AS_DROP", f"action {rule.action.value} written as drop, which answers nobody")
        if (rule.log_start or rule.log_end) and rule.enabled and not disabled and pairs:
            self.logged.append(rule.name)
        if not disabled and pairs and rule.action != Action.ALLOW and 6 in self._families(rule):
            self.report.add("rule", rule.origin, Severity.REVIEW, "MOXA_IPV4_ONLY",
                            "the rule also blocks IPv6, which the router's policies do not filter: only its IPv4 part is written")  # fmt: skip
        if not pairs:
            self.report.item("rule", rule.origin).emitted_as.append("nothing (traffic inside one interface)")
            return
        indexes: List[int] = []
        if disabled:
            piece = (pieces or [("all", "all", "all")])[0]
            destination = self._address_words(destinations[0]) if destinations else "single 0.0.0.0"
            indexes.append(self._policy(action, pairs[0], "single 0.0.0.0", destination, piece, False))
            self.not_written.append(f"firewall {indexes[0]} ({rule.name}): " + "; ".join(m for _, m in reasons)[:300])
        else:
            assert pieces is not None and sources and destinations
            for pair in pairs:
                for src in sources:
                    for dst in destinations:
                        for piece in pieces:
                            indexes.append(self._policy(action, pair, self._address_words(src), self._address_words(dst), piece, rule.enabled))
                if rule.enabled and sources == [FULL_V4] and destinations == [FULL_V4] and pieces == [("all", "all", "all")]:
                    self.decided.add(pair)
        first, last = indexes[0], indexes[-1]
        self.report.item("rule", rule.origin).emitted_as.append(f"firewall {first}" if first == last else f"firewall {first}-{last}")

    def _defaults(self) -> None:
        if self.p.default_interzone == Action.ALLOW:
            if self.p.vendor != "moxa":
                self.report.note(Severity.INFO, "MOXA_DEFAULT_RULES",
                                 "the source lets through what no rule matches, as the router does (assumed): no policy is written for it")  # fmt: skip
            return
        # (the interfaces of the zones the source knows, after --zone-map, and those the rules name; none at all: every pair)
        known = [self.options.zone_map.get(z, z).lower() for z in self.p.zones] + list(self.used)
        words = [w for w in INTERFACE_WORDS if w in known]
        zoned = bool(self.p.zones) or any(z != ANY for r in self.p.rules for z in r.src_zones + r.dst_zones)
        pairs = [(s, d) for s in words for d in words if s != d] if zoned else [("all", "all")]
        written = 0
        for pair in pairs:
            if pair in self.decided or ("all", "all") in self.decided or (pair[0], "all") in self.decided or ("all", pair[1]) in self.decided:
                continue
            self._policy("drop", pair, "all", "all", ("all", "all", "all"), True)
            written += 1
        if written:
            self.report.note(Severity.INFO, "MOXA_DEFAULT_RULES",
                             f"after the converted rules, {written} policies that drop what no rule matches between the interfaces written, as "
                             "the source does: the router lets it through (assumed)")  # fmt: skip
        inside = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, [w for w in words], self.report)
        closed = [zone for zone, allow in inside.items() if not allow]
        if closed:
            self.report.note(Severity.REVIEW, "MOXA_INTRAZONE_NOT_BLOCKED",
                             "the source blocks traffic inside these zones that no rule matches; traffic inside one interface does not "
                             "pass the router's policies: " + ", ".join(closed))  # fmt: skip

    # -- NAT --------------------------------------------------------------------------------------------------

    def _host(self, member: str) -> Optional[str]:
        intervals = transform.address_intervals(self.p, member)
        if not intervals or len(intervals) != 1 or intervals[0][0] != 4 or intervals[0][1] != intervals[0][2]:
            return None
        return str(int_to_ip(4, intervals[0][1]))

    @staticmethod
    def _wan(zones: List[str]) -> Optional[str]:
        """The WAN number of one zone (``1``, ``2``), ``auto`` for any; None otherwise."""
        if zones == [ANY]:
            return "auto"
        if len(zones) == 1 and zones[0].lower() in ("wan1", "wan2"):
            return zones[0][-1]
        if sorted(z.lower() for z in zones) == ["wan1", "wan2"]:
            return "auto"
        return None

    def nat_line(self, nat: NatRule, report: Optional[Report] = None) -> str:
        """The ``ip nat`` command for a NAT rule; '' when the router cannot say it."""
        found: List[Tuple[Severity, str, str]] = []
        line = self._nat_line(nat, found)
        if line and report is not None:
            for severity, code, message in found:
                report.add("nat", nat.origin, severity, code, message)
        return line

    def _nat_line(self, nat: NatRule, found: List[Tuple[Severity, str, str]]) -> str:
        if nat.unsupported or not nat.enabled:
            return ""
        snat, dnat = nat.source_translation, nat.destination_translation
        if nat.src_zones not in ([ANY], ["lan"]) and not (dnat is not None and snat is None):
            return ""
        if snat is not None and snat.kind == SnatKind.STATIC and snat.bidirectional and dnat is None:
            if nat.destinations != [ANY] or nat.service != ANY or len(nat.sources) != 1 or len(snat.addresses) != 1:
                return ""
            inside, outside, wan = self._host(nat.sources[0]), self._host(snat.addresses[0]), self._wan(nat.dst_zones)
            if inside is None or outside is None or wan in (None, "auto"):
                return ""
            return f"ip nat static inside lan {inside} outside wan {wan} {outside}"
        if dnat is not None and snat is None:
            wan = self._wan(nat.src_zones)
            if nat.sources != [ANY] or len(nat.destinations) != 1 or wan in (None, "auto") or dnat.spread:
                return ""
            if nat.dst_zones not in ([ANY], ["lan"]):
                return ""
            inside = self._host(dnat.address)
            if inside is None:
                return ""
            destination = nat.destinations[0]
            address = self.p.addresses.get(destination)
            own = address is not None and address.builtin == "moxa" and address.raw == f"interface wan {wan}"
            if nat.service == ANY:
                outside = self._host(destination)
                if dnat.port or outside is None:
                    return ""
                found.append((Severity.APPROX, "MOXA_ONE_TO_ONE", "destination NAT of every port written as 1-to-1 NAT, which also "
                              "translates the connections the inside host opens to the outside address"))  # fmt: skip
                return f"ip nat static inside lan {inside} outside wan {wan} {outside}"
            entries = transform.flatten_services(self.p, nat.service)
            if not entries or any(e.protocol not in (Protocol.TCP, Protocol.UDP) or e.src_ports for e in entries):
                return ""
            ports = {e.dst_ports for e in entries}
            kinds = {e.protocol for e in entries}
            if len(ports) != 1 or len(entries) != len(kinds):
                return ""
            port = ports.pop()
            if not port.isdigit() or int(port) == 0:
                return ""
            inner = dnat.port or port
            if not inner.isdigit():
                return ""
            if not own:
                where = "any address" if destination == ANY else f"'{destination}'"
                found.append((Severity.REVIEW, "MOXA_FORWARD_ADDRESS", f"a port forward of the router is for the address of WAN {wan}; the "
                              f"source forwards {where}: check that WAN {wan} has that address"))  # fmt: skip
            protocol = "all" if len(kinds) == 2 else kinds.pop().value
            if protocol == "all":
                found.append((Severity.INFO, "MOXA_FORWARD_ALL", "TCP and UDP written as protocol all (assumed to be TCP and UDP)"))
            return f"ip nat static {protocol} inside lan {inside} {inner} outside wan {wan} {port}"
        if dnat is None and snat is not None and snat.kind == SnatKind.INTERFACE:
            wan = self._wan(nat.dst_zones)
            if wan is None or nat.destinations != [ANY] or nat.service != ANY:
                return ""
            intervals: List[Interval] = []
            for member in nat.sources:
                found_intervals = transform.address_intervals(self.p, member)
                if found_intervals is None:
                    return ""
                intervals += [i for i in found_intervals if i[0] == 4]
            intervals = normalize(intervals)
            if len(intervals) != 1 or intervals[0] == FULL_V4:
                return ""
            first, last = int_to_ip(4, intervals[0][1]), int_to_ip(4, intervals[0][2])
            if wan == "auto" and nat.dst_zones == [ANY]:
                found.append((Severity.INFO, "MOXA_NAT_AUTO", "to any zone: written as outside wan auto, the address of whichever WAN "
                              "interface the traffic leaves by"))  # fmt: skip
            return f"ip nat dynamic inside lan {first} {last} outside wan {wan}"
        return ""

    # -- output -----------------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            if not nat.enabled and not nat.unsupported:
                self.report.skip("nat", nat.origin, "MOXA_NAT_DISABLED", "disabled in the source: not written", Severity.INFO)
                continue
            line = self.nat_line(nat, self.report)
            if not line:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: the router writes a port forward of one TCP or UDP port of a WAN interface's address to "
                                 "a host on LAN, a 1-to-1 NAT of one LAN host to one outside address on a WAN, and N-to-1 NAT of one "
                                 "range of LAN addresses to the address of a WAN interface")  # fmt: skip
                continue
            self.report.item("nat", nat.origin).emitted_as.append(line.split(" inside")[0])
            self.nat.append(line)
        start = self.options.policy_id_start or 1
        out = ["! Generated by FWShift: CLI commands for the Layer 3 policy and NAT of a Moxa industrial secure router",
               "! (EDR-810, EDR-G902/G903, TN-4900 with the classic router firmware). Paste them into the console after",
               "! logging in; read the report first, what is not written is listed there. Nothing is deleted or saved.",
               f"! The policies are numbered from {start} on: firewall N changes a policy that exists at N, so on a router",
               "! with policies give --policy-id-start one above the last index that show firewall lists.",
               "configure"]  # fmt: skip
        out += self.lines + self.nat + ["exit"]
        if self.index - start > LIMIT:
            self.report.note(Severity.REVIEW, "MOXA_TOO_MANY_POLICIES",
                             f"{self.index - start} policies written; a router holds a few hundred (256 on an EDR-G903): check the "
                             "limit of the model")  # fmt: skip
        if self.not_written:
            out += ["! Written disabled, matching nothing:"] + [f"!   {_text(line, 300)}" for line in self.not_written]
        self._notes()
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        start = self.options.policy_id_start or 1
        self.report.note(Severity.REVIEW, "MOXA_LOAD",
                         "the output is CLI commands for the console (section 10), not a file to import: an import replaces the "
                         f"configuration. Policies are numbered from {start}; firewall N changes a policy that exists at N, so on a router "
                         "with policies give --policy-id-start above the last index. NAT rules are appended after the router's own. "
                         "Commands take effect as they are entered: turn on Setting Check for the firewall and NAT first")  # fmt: skip
        if self.unknown_zones:
            self.report.note(Severity.REVIEW, "MOXA_ZONES",
                             "zones that are not interfaces of the router (lan, wan1, wan2); their rules are written disabled: give "
                             "--zone-map ZONE=lan|wan1|wan2 for " + ", ".join(self.unknown_zones[:12]))  # fmt: skip
        if any(n.destination_translation is not None for n in self.p.nat_rules) and self.nat:
            self.report.note(Severity.INFO, "MOXA_NAT_WRITTEN",
                             "port forwards and 1-to-1 NAT are read as done before the Layer 3 policy (assumed): the policies were written "
                             "for the inside address")  # fmt: skip
        if self.logged:
            self.report.note(Severity.INFO, "MOXA_LOG_NOT_WRITTEN",
                             "rules of the source log; the CLI manual FWShift read shows no logging of a policy: set it in the web console "
                             f"for the policies of {len(self.logged)} rules: " + ", ".join(self.logged[:8]) + (" ..." if len(self.logged) > 8 else ""))  # fmt: skip
        if self.p.vendor != "moxa":
            self.report.note(Severity.INFO, "MOXA_IPV4", "the router's policies and NAT are IPv4: rules for IPv6 only are not written")

