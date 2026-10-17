# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""iptables emitter: neutral model -> ``iptables-restore`` / ``ip6tables-restore`` input.

Design rules:

* One file per IP version: ``iptables`` gets the IPv4 half of every rule,
  ``ip6tables`` the IPv6 half.
* Only the ``FORWARD`` chain and, for IPv4, the ``nat`` table are written. The
  file never touches ``INPUT`` or ``OUTPUT``.
* The model is connection-based: the chain starts by accepting established
  connections, and the rules that follow decide about new ones.
* iptables has no object groups and no disabled rules. A rule with several
  sources, destinations or services becomes a short user-defined chain per
  list, which is exact and avoids multiplying rules; a rule that cannot be
  enforced is written as a comment, so it is visible and not loaded.
* ``FORWARD`` sees packets after destination NAT: rules are rewritten to the
  translated address, as for every platform that looks policy up after NAT.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import (
    ANY,
    L4_PROTOCOLS,
    Action,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    ServiceEntry,
    SnatKind,
)
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, parse_literal, range_text, size
from ..options import Options
from ..report import Report, Severity

Problem = Tuple[str, str, Severity]
Finding = Tuple[Severity, str, str]
# (why the rule cannot be written, PREROUTING lines, POSTROUTING lines, findings)
Plan = Tuple[Optional[Problem], List[str], List[str], List[Finding]]
_INLINE_LIMIT = 16  # more combinations than this go into chains instead of separate rules
_MULTIPORT_SLOTS = 15  # ports per multiport match; a range takes two


def emit(policy: Policy, report: Report, options: Options, family: int = 4) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    emitter = _Emitter(p, report, options, family)
    # FORWARD sees the post-NAT destination. Rewrite only for translations that are really written.
    written = {
        nat.origin
        for nat in p.nat_rules
        if emitter.nat_plan(nat)[0] is None
        and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)
    }
    transform.to_post_nat_lookup(p, report, written if family == 4 else set())
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, family).run()


def emit_v6(policy: Policy, report: Report, options: Options) -> str:
    return emit(policy, report, options, family=6)


def valid_interface(name: str) -> bool:
    return 0 < len(name) <= 15 and not any(c.isspace() or c in '/!"' for c in name) and not name.endswith("+")


def _comment(text: str) -> str:
    cleaned = " ".join(text.replace('"', "'").replace("\\", "/").split())[:200]
    return f'-m comment --comment "{cleaned}"'


def _port_fragments(proto: str, ports: str, destination: bool) -> List[str]:
    """Match fragments for a port list, split so that no multiport match exceeds its limit."""
    if not ports:
        return [""]
    items = [item.replace("-", ":") for item in ports.split(",")]
    single, multi = ("--dport", "--dports") if destination else ("--sport", "--sports")
    if len(items) == 1:
        return [f"-m {proto} {single} {items[0]}"]
    out: List[str] = []
    chunk: List[str] = []
    slots = 0
    for item in items:
        need = 2 if ":" in item else 1
        if chunk and slots + need > _MULTIPORT_SLOTS:
            out.append(f"-m multiport {multi} {','.join(chunk)}")
            chunk, slots = [], 0
        chunk.append(item)
        slots += need
    out.append(f"-m multiport {multi} {','.join(chunk)}")
    return out


def entry_fragments(entries: List[ServiceEntry], family: int) -> List[str]:
    """iptables match fragments for protocol/port entries; "" matches every protocol."""
    out: List[str] = []
    # Entries of one protocol with the same source ports share one port list.
    merged: Dict[Tuple[str, str], List[str]] = {}
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            ports = merged.setdefault((entry.protocol.value, entry.src_ports), [])
            ports += [port for port in (entry.dst_ports.split(",") if entry.dst_ports else [""]) if port not in ports]
    for (proto, src_ports), ports in merged.items():
        dst_ports = "" if "" in ports else ",".join(ports)
        for dst in _port_fragments(proto, dst_ports, True):
            for src in _port_fragments(proto, src_ports, False):
                out.append(" ".join(part for part in (f"-p {proto}", dst, src) if part))
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            continue
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            if (entry.protocol == Protocol.ICMP) != (family == 4):
                continue  # ICMP belongs to IPv4, ICMPv6 to IPv6
            proto, module, option = ("icmp", "icmp", "--icmp-type") if family == 4 else ("ipv6-icmp", "icmp6", "--icmpv6-type")
            fragment = f"-p {proto}"
            if entry.icmp_type is not None:
                code = f"/{entry.icmp_code}" if entry.icmp_code is not None else ""
                fragment += f" -m {module} {option} {entry.icmp_type}{code}"
            out.append(fragment)
        elif entry.ip_protocol:
            out.append(f"-p {entry.ip_protocol}")
        else:
            out.append("")
    return transform.dedupe(out)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, family: int) -> None:
        self.p, self.report, self.options, self.family = p, report, options, family
        self.full = FULL_V4 if family == 4 else FULL_V6
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.chains: List[str] = []
        self.filter: List[str] = []
        self.prerouting: List[str] = []
        self.postrouting: List[str] = []
        self.chain_counter = 0
        self.tied: Set[str] = set()  # NAT rules whose source half is bound to their own original destination
        self.leaves: Dict[str, List[Tuple[str, object]]] = {}
        self.other_family = 0

    # -- addresses and services -------------------------------------------

    def _leaves(self, member: str, seen: Tuple[str, ...] = ()) -> List[Tuple[str, object]]:
        """What a rule member stands for: ("any", None), ("interval", Interval) or ("fqdn", name)."""
        if member in self.leaves:
            return self.leaves[member]
        if member == ANY:
            return [("any", None)]
        if member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.FQDN:
                return [("fqdn", member)] if address.fqdn_family in (0, self.family) else []
            interval = parse_literal(address.value) if address.kind != AddressKind.UNSUPPORTED else None
            return [("interval", interval)] if interval else []
        if member in self.p.address_groups:
            if member in seen:
                return []
            out: List[Tuple[str, object]] = []
            for inner in self.p.address_groups[member].members:
                out += self._leaves(inner, seen + (member,))
            # Each group is walked once and gives each of its addresses once: nesting that fans out
            # would otherwise double the work with every level.
            self.leaves[member] = list(dict.fromkeys(out))
            return self.leaves[member]
        interval = parse_literal(member)
        return [("interval", interval)] if interval else []

    def _address_fragments(self, members: List[str], source: bool) -> Tuple[List[str], bool, List[str]]:
        """(match fragments of this IP version, whether the list covers everything, FQDN objects used)."""
        flag, range_flag = ("-s", "--src-range") if source else ("-d", "--dst-range")
        out: List[str] = []
        names: List[str] = []
        for kind, value in [leaf for member in members for leaf in self._leaves(member)]:
            if kind == "any":
                return [""], True, []
            if kind == "fqdn":
                assert isinstance(value, str)
                out.append(f"{flag} {self.p.addresses[value].value}")
                names.append(value)
                continue
            assert isinstance(value, tuple)
            version, first, last = value
            if version != self.family:
                continue
            if (version, first, last) == self.full:
                return [""], True, []
            networks = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
            if len(networks) == 1:
                out.append(f"{flag} {networks[0]}")
            else:
                out.append(f"-m iprange {range_flag} {range_text((version, first, last))}")
        return transform.dedupe(out), False, names

    def _side(self, rule: Rule, source: bool) -> Tuple[Optional[List[str]], bool, List[str]]:
        """(fragments or None if this side can match nothing of this IP version, negated, FQDN objects)."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        fragments, everything, names = self._address_fragments(members, source)
        if negated:
            if everything:
                return None, False, names  # "not any" matches nothing
            if not fragments:
                return [""], False, names  # the excluded list names nothing of this IP version
            return fragments, True, names
        return (fragments or None), False, names

    def _service_fragments(self, rule: Rule, reasons: List[transform.Reason]) -> List[str]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            return entry_fragments([entry for _, entries in lowered for entry in entries], self.family)
        if rule.services == [ANY]:
            return [""]
        entries: List[ServiceEntry] = []
        for service in rule.services:
            entries += transform.flatten_services(self.p, service) or []
        return entry_fragments(entries, self.family)

    # -- security rules ---------------------------------------------------

    def _describe(self, rule: Rule) -> str:
        parts = [
            f"from {','.join(rule.src_zones)} to {','.join(rule.dst_zones)}",
            ("source not " if rule.negate_source else "source ") + ",".join(rule.sources),
            ("destination not " if rule.negate_destination else "destination ") + ",".join(rule.destinations),
            ("service not " if rule.negate_service else "service ") + ",".join(rule.services),
        ]
        if rule.applications != [ANY]:
            parts.append("application " + ",".join(rule.applications))
        parts.append("action " + rule.action.value)
        return " ".join((f'"{rule.name}" ' + "; ".join(parts)).split())

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(
                ("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted")
            )
        services = self._service_fragments(rule, reasons)
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(
                ("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as interface pairs")
            )
        bad = [z for z in rule.src_zones + rule.dst_zones if z != ANY and not valid_interface(z)]
        if bad:
            reasons.append(
                ("INTERFACE_NAME", "'" + "', '".join(bad) + "' cannot be an interface name; map it with --zone-map")
            )
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
            self.filter.append(f"# FWSHIFT disabled, see the report: {self._describe(rule)}")
            return
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in self.report.item("rule", rule.origin).findings)
            self.filter.append(f"# disabled {'by the audit' if by_audit else 'in the source'}: {self._describe(rule)}")
            return
        if pairs is not None and not pairs:
            self.report.skip(
                "rule",
                rule.origin,
                "RULE_TYPE_EMPTY",
                f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing",
                Severity.INFO,
            )
            return
        sources, source_negated, names_s = self._side(rule, True)
        destinations, destination_negated, names_d = self._side(rule, False)
        service_negated = rule.negate_service
        if service_negated and not services:
            services, service_negated = [""], False  # the excluded services do not exist in this IP version
        elif service_negated and "" in services:
            services = []  # "not any service" matches nothing
        if sources is None or destinations is None or not services:
            self.other_family += 1
            self.report.skip(
                "rule",
                rule.origin,
                "NOT_THIS_IP_VERSION",
                f"nothing in this rule can match IPv{self.family}; it is written for the other IP version only",
                Severity.INFO,
            )
            return
        for name in transform.dedupe(names_s + names_d):
            self.report.add(
                "rule",
                rule.origin,
                Severity.APPROX,
                "FQDN_RESOLVED_ONCE",
                f"'{name}' is a host name: iptables resolves it once, when the rules are loaded, and keeps the "
                "addresses it got then",
            )
        if rule.action == Action.ALLOW:
            verdict, state = "ACCEPT", "-m conntrack --ctstate NEW"
        elif rule.action == Action.DROP:
            verdict, state = "DROP", ""
        elif rule.action == Action.DENY:
            verdict, state = "REJECT", ""
        else:
            # A negated list matches the other protocols as well: a TCP reset cannot answer those.
            tcp_only = not service_negated and all(fragment.startswith("-p tcp") for fragment in services)
            verdict, state = ("REJECT --reject-with tcp-reset" if tcp_only else "REJECT"), ""
            if not tcp_only:
                self.report.add(
                    "rule",
                    rule.origin,
                    Severity.INFO,
                    "RESET_ACTION",
                    f"action {rule.action.value} becomes a plain REJECT: a TCP reset can only answer TCP",
                )
        entries: List[str] = []
        for src_zones, dst_zones in pairs or []:
            for src_zone in src_zones:
                for dst_zone in dst_zones:
                    parts = ["-A FORWARD"]
                    parts += [f"-i {src_zone}"] if src_zone != ANY else []
                    parts += [f"-o {dst_zone}"] if dst_zone != ANY else []
                    entries.append(" ".join(parts))
        dimensions = [
            (sources, source_negated),
            (destinations, destination_negated),
            (services, service_negated),
        ]
        tail = " ".join(part for part in (state, _comment(rule.name)) if part)
        combinations = len(entries) * len(sources) * len(destinations) * len(services)
        inline = combinations <= _INLINE_LIMIT and not service_negated
        inline = inline and all(not negated or len(fragments) == 1 for fragments, negated in dimensions[:2])
        restricting = [(fragments, negated) for fragments, negated in dimensions if fragments != [""] or negated]
        if inline or not restricting:
            for entry in entries:
                for source in sources:
                    for destination in destinations:
                        for service in services:
                            matches = [_negate(source) if source_negated else source,
                                       _negate(destination) if destination_negated else destination, service]  # fmt: skip
                            self.filter.append(" ".join(part for part in [entry, *matches, tail, f"-j {verdict}"] if part))
            item.emitted_as.append(f"{combinations} FORWARD rule" + ("s" if combinations != 1 else ""))
            return
        # One chain per list: a packet walks source -> destination -> service and falls
        # back into FORWARD as soon as one of them does not match.
        self.chain_counter += 1
        names = [f"FWS{self.chain_counter}" + (f"-{index}" if index else "") for index in range(len(restricting))]
        self.chains += names
        for entry in entries:
            self.filter.append(" ".join(part for part in (entry, tail, f"-j {names[0]}") if part))
        for index, (fragments, negated) in enumerate(restricting):
            target = names[index + 1] if index + 1 < len(names) else verdict
            if negated:
                self.filter += [f"-A {names[index]} {fragment} -j RETURN" for fragment in fragments]
                self.filter.append(f"-A {names[index]} -j {target}")
            else:
                self.filter += [f"-A {names[index]} {fragment} -j {target}" for fragment in fragments]
        item.emitted_as.append(f"chain {names[0]}")

    # -- NAT --------------------------------------------------------------

    def nat_plan(self, nat: NatRule) -> Plan:
        """What a NAT rule becomes, or why it cannot be written. No side effects."""
        findings: List[Finding] = []
        source, destination = nat.source_translation, nat.destination_translation

        def fail(code: str, message: str, severity: Severity = Severity.REVIEW) -> Plan:
            return (code, message, severity), [], [], []

        if self.family != 4:
            return fail("NAT_IPV6", "NAT rules are written for IPv4 only (--to iptables)", Severity.INFO)
        members = nat.sources + nat.destinations
        members = members + (source.addresses if source else []) + ([destination.address] if destination else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        bad = [z for z in nat.src_zones + nat.dst_zones if z != ANY and not valid_interface(z)]
        if bad:
            problems.append("'" + "', '".join(bad) + "' cannot be an interface name; map it with --zone-map")
        if problems:
            return fail("NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
        sources, _, names_s = self._address_fragments(nat.sources, True)
        destinations, _, names_d = self._address_fragments(nat.destinations, False)
        if not sources or not destinations or names_s or names_d:
            return fail("NAT_ADDRESSES", "the rule needs static IPv4 addresses as source and destination")
        services = [""]
        entries: List[ServiceEntry] = []
        if nat.service != ANY:
            entries = transform.flatten_services(self.p, nat.service) or []
            if not entries or any(e.protocol not in L4_PROTOCOLS for e in entries):
                return fail("NAT_SERVICE", f"service '{nat.service}' is not a TCP, UDP or SCTP service")
            services = entry_fragments(entries, 4)
        tail = _comment(nat.name)
        prerouting: List[str] = []
        postrouting: List[str] = []
        post_destinations = destinations
        if destination is not None:
            mapped = transform.address_intervals(self.p, destination.address)
            if not mapped or len(mapped) != 1 or mapped[0][0] != 4 or mapped[0] == FULL_V4:
                return fail("NAT_DESTINATION", "the translated address must be one IPv4 address or range")
            if destination.port and services == [""]:
                return fail("NAT_PORT", "a port translation needs a TCP, UDP or SCTP service on the rule")
            to = range_text(mapped[0]) + (f":{destination.port}" if destination.port else "")
            if destinations == [""] and not self.p.lookup_after_dnat:
                findings.append(
                    (Severity.REVIEW, "NAT_ANY_DESTINATION", "the rule translates traffic to every destination; "
                     "the security rules were not adjusted to the translated address")  # fmt: skip
                )
            if size(mapped[0]) > 1:
                findings.append(
                    (Severity.APPROX, "NAT_RANGE", "DNAT to a range picks an address per connection; it is not a "
                     "fixed one-to-one mapping")  # fmt: skip
                )
            for zone in nat.src_zones:
                for src in sources:
                    for dst in destinations:
                        for service in services:
                            parts = ["-A PREROUTING", f"-i {zone}" if zone != ANY else "", src, dst, service, tail,
                                     f"-j DNAT --to-destination {to}"]  # fmt: skip
                            prerouting.append(" ".join(part for part in parts if part))
            post_destinations, _, _ = self._address_fragments([destination.address], False)
        if source is not None or destination is None:
            target = "ACCEPT"
            if source is not None:
                addresses = [a.split("/")[0] if source.kind == SnatKind.INTERFACE and a not in self.p.addresses else a
                             for a in source.addresses]  # fmt: skip
                pool: List[Interval] = []
                for address in addresses:
                    resolved = transform.address_intervals(self.p, address)
                    if not resolved or any(i[0] != 4 for i in resolved):
                        return fail("NAT_POOL", f"translated address '{address}' is not a static IPv4 address")
                    pool += resolved
                if source.kind == SnatKind.INTERFACE and not pool:
                    target = "MASQUERADE"
                elif len(pool) != 1:
                    return fail("NAT_POOL", "source NAT needs exactly one translated address or range")
                else:
                    target = f"SNAT --to-source {range_text(pool[0])}"
                    if source.kind == SnatKind.STATIC and size(pool[0]) > 1:
                        findings.append(
                            (Severity.APPROX, "NAT_STATIC_RANGE", "static NAT of several addresses becomes SNAT to "
                             "a range, which does not promise that each host keeps the same translated address")  # fmt: skip
                        )
            if nat.src_zones != [ANY]:
                # With explicit source addresses the interface adds little; with "any" it was the only limit.
                severity = Severity.REVIEW if sources == [""] else Severity.APPROX
                findings.append(
                    (severity, "NAT_INPUT_INTERFACE", "the rule applied to traffic from "
                     + ", ".join(nat.src_zones) + " only; POSTROUTING cannot match the input interface, so it "
                     "applies to traffic from every interface")  # fmt: skip
                )
            out_zones, post_services = nat.dst_zones, services
            original = [""]  # match on where the connection was going before its destination was translated
            if destination is not None:
                # POSTROUTING sees the packet after its destination was translated: the new address,
                # the new port, and the interface that leads there, which the rule does not name.
                if destination.port:
                    moved = [ServiceEntry(e.protocol, destination.port, e.src_ports) for e in entries]
                    post_services = entry_fragments(moved, 4)
                if destinations != [""] and all(fragment.startswith("-d ") for fragment in destinations):
                    # Only connections that came for the original address, not ones sent to the new one directly.
                    original = [f"-m conntrack --ctorigdst {fragment[3:]}" for fragment in destinations]
                else:
                    findings.append(
                        (Severity.APPROX, "NAT_AFTER_DNAT", "the source translation of this rule is matched after "
                         "its destination translation; it also applies to traffic from the same sources that is "
                         "sent to the translated address directly")  # fmt: skip
                    )
                if nat.dst_zones != [ANY]:
                    out_zones = [ANY]
                    findings.append(
                        (Severity.APPROX, "NAT_OUTPUT_INTERFACE", "the rule also translates the destination, so "
                         "the traffic does not leave by " + ", ".join(nat.dst_zones) + "; its source translation "
                         "is written for every output interface")  # fmt: skip
                    )
            for zone in out_zones:
                for src in sources:
                    for dst in post_destinations:
                        for service in post_services:
                            for came_for in original:
                                parts = ["-A POSTROUTING", f"-o {zone}" if zone != ANY else "", src, dst, service,
                                         came_for, tail, f"-j {target}"]  # fmt: skip
                                postrouting.append(" ".join(part for part in parts if part))
            if source is not None and source.kind == SnatKind.STATIC and source.bidirectional:
                pair = transform.bidirectional_pair(self.p, nat)
                if pair is None or not nat.enabled:
                    findings.append(
                        (Severity.REVIEW, "NAT_BIDIRECTIONAL", "bi-directional static NAT: the inbound direction "
                         "could not be written and is missing")  # fmt: skip
                    )
                else:
                    inside, outside = pair
                    prerouting.append(
                        f"-A PREROUTING -d {range_text(outside)} {_comment(nat.name + ' inbound')} "
                        f"-j DNAT --to-destination {range_text(inside)}"
                    )
                    findings.append(
                        (Severity.INFO, "NAT_BIDIRECTIONAL", "bi-directional static NAT written as an SNAT rule "
                         "plus a DNAT rule for the inbound direction")  # fmt: skip
                    )
        return None, prerouting, postrouting, findings

    def _nat(self, nat: NatRule) -> None:
        problem, prerouting, postrouting, findings = self.nat_plan(nat)
        if problem is not None:
            self.report.skip("nat", nat.origin, *problem)
            return
        item = self.report.item("nat", nat.origin)
        for severity, code, message in findings:
            self.report.add("nat", nat.origin, severity, code, message)
        if any("--ctorigdst" in line for line in postrouting):
            self.tied.add(nat.origin)  # its source half only matches what came for its own original destination
        self.prerouting += prerouting if nat.enabled else ["# disabled in the source: " + line for line in prerouting]
        self.postrouting += postrouting if nat.enabled else ["# disabled in the source: " + line for line in postrouting]
        if not nat.enabled:
            self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written as a comment")
            return
        item.emitted_as += ([f"{len(prerouting)} PREROUTING"] if prerouting else []) + (
            [f"{len(postrouting)} POSTROUTING"] if postrouting else []
        )

    # -- output -----------------------------------------------------------

    def run(self) -> str:
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=self.tied)
        for rule in self.p.rules:
            self._rule(rule)
        self._notes()
        tool = "iptables" if self.family == 4 else "ip6tables"
        policy = "ACCEPT" if self.p.default_interzone == Action.ALLOW else "DROP"
        out = [
            "# Generated by FWShift - review the conversion report before loading this.",
            f"# FORWARD chain{' and nat table' if self.prerouting or self.postrouting else ''} for {tool}-restore.",
            "# It does not contain INPUT or OUTPUT: load it with --noflush, or merge it into your ruleset.",
            "*filter",
            f":FORWARD {policy} [0:0]",
        ]
        out += [f":{name} - [0:0]" for name in self.chains]
        out += [
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A FORWARD -m conntrack --ctstate INVALID -j DROP",
        ]
        out += self.filter + ["COMMIT"]
        if self.prerouting or self.postrouting:
            out += ["*nat", ":PREROUTING ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]"]
            out += self.prerouting + self.postrouting + ["COMMIT"]
        return "\n".join(out) + "\n"

    def _matches_ipv6(self, rule: Rule) -> bool:
        """Whether a rule can match an IPv6 packet: both its sides have to."""
        sides = ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination))
        return all(negated or any(6 in transform.families(self.p, m) for m in members) for members, negated in sides)

    def _notes(self) -> None:
        tool = "iptables" if self.family == 4 else "ip6tables"
        self.report.note(
            Severity.REVIEW,
            "IPTABLES_LOAD",
            f"the output holds the FORWARD chain only. Plain '{tool}-restore' replaces the whole filter table, "
            f"INPUT and OUTPUT included: check it with '{tool}-restore --test', then load it with "
            f"'{tool}-restore --noflush' on a host whose FORWARD chain is empty, or merge it by hand",
        )
        interfaces = transform.dedupe(
            [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        )
        if interfaces and self.p.vendor != "iptables":
            self.report.note(
                Severity.REVIEW,
                "INTERFACES_REQUIRED",
                "zones are written as interface names; map each zone to its interface with --zone-map: "
                + ", ".join(interfaces),
            )
        if self.p.default_intrazone == Action.ALLOW and self.p.default_interzone != Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_DEFAULT",
                "the source allows traffic inside a zone unless a rule denies it; here traffic that leaves by "
                "the interface it came in on is dropped unless a rule allows it",
            )
        if self.p.default_interzone == Action.ALLOW and self.p.default_intrazone != Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_DEFAULT",
                "the source accepts traffic between zones that no rule matches, but not inside a zone. The FORWARD "
                "policy is ACCEPT and cannot tell the two apart: traffic that leaves by the interface it came in "
                "on is accepted as well",
            )
        transform.note_closed_zones(self.p, self.options.zone_map, self.report, list(self.options.zone_networks))
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_ALLOW",
                "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                "written for that: " + ", ".join(open_zones),
            )
        if self.other_family:
            other = "ip6tables" if self.family == 4 else "iptables"
            self.report.note(
                Severity.INFO,
                "OTHER_IP_VERSION",
                f"{self.other_family} rule{'s match' if self.other_family != 1 else ' matches'} the other IP version "
                f"only; convert with --to {other} as well",
            )
        elif self.family == 4 and any(self._matches_ipv6(rule) for rule in self.p.rules):
            self.report.note(
                Severity.INFO,
                "OTHER_IP_VERSION",
                "some rules also match IPv6; convert with --to ip6tables as well to get that half",
            )
        if any(r.log_start or r.log_end for r in self.p.rules):
            self.report.note(
                Severity.INFO,
                "LOGGING_NOT_CONVERTED",
                "logging settings of the rules are not converted; add LOG or NFLOG rules where needed",
            )


def _negate(fragment: str) -> str:
    """``-s X`` -> ``! -s X``; ``-m iprange --src-range X`` -> ``-m iprange ! --src-range X``."""
    if fragment.startswith("-m iprange "):
        return fragment.replace("-m iprange ", "-m iprange ! ", 1)
    return f"! {fragment}" if fragment else fragment

