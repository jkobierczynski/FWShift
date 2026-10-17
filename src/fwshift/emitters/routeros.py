# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""MikroTik RouterOS emitter: neutral model -> a script for ``/import`` (RouterOS 6 or 7).

Design rules:

* Nothing the script adds changes traffic until the person switches it on. The rules go into chains of their own
  (``fwshift-forward``, ``fwshift-dstnat``, ``fwshift-srcnat``), and the script ends with the jumps to them from the
  built-in chains, disabled: enabled in Safe Mode, one change switches the policy on. A script that stops half-way
  leaves traffic as it was.
* The script never writes ``input`` or ``output``, and never removes anything. It starts with a check that stops it
  when the objects of an earlier conversion are still there.
* Zones become interface lists, address lists of more than one entry become address lists, both under a prefix of
  their own (``fws-``), so they do not meet the lists of the router.
* The model is connection-based: the chain starts by accepting established connections and dropping invalid ones,
  and ends with the default of the policy, so that forward does not go on to its own rules for what the policy did
  not decide.
* RouterOS has one protocol per rule: a rule of the model becomes a rule per protocol, or a short chain of its own
  where that would be many.
* The forward chain sees packets after destination NAT: rules are rewritten to the translated address, as for every
  platform that looks policy up after NAT.
"""

from __future__ import annotations

import copy
import ipaddress
import shlex
from typing import AbstractSet, Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, L4_PROTOCOLS, Action, NatRule, Policy, Protocol, Rule, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, interval_text
from ..options import Options
from ..report import Report, Severity
from . import iptables as _iptables

CHAIN = "fwshift-forward"
_INLINE_LIMIT = 16  # more rules than this for one rule of the model go into a chain of its own
_PORTS_PER_RULE = 15
_NAMED = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 47: "gre", 50: "ipsec-esp", 51: "ipsec-ah", 89: "ospf", 132: "sctp"}
Side = Optional[List[str]]  # None: nothing of this IP version; []: any address of it; else the properties to match
_GUARD = (':if ([:len [/{} firewall filter find where chain="fwshift-forward"]] > 0) do={{ :error "FWShift objects '
          'of an earlier conversion are on this router: remove them first (see the report)" }}')  # fmt: skip


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    emitter = _Emitter(p, report, options)
    emitter.source_zones = source_zones
    # The forward chain sees the post-NAT destination. Rewrite only for translations that are really written.
    written = {
        nat.origin
        for nat in p.nat_rules
        if emitter.plan(nat)[0] is None
        and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)
    }
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _text(value: str, limit: int = 255) -> Tuple[str, bool]:
    """A quoted string RouterOS reads back as it is, and whether characters had to be replaced: ``?`` (help on a
    terminal), control characters and characters beyond ASCII become ``_``; ``"``, ``\\`` and ``$`` are escaped."""
    out: List[str] = []
    changed = False
    for char in value[:limit]:
        if char in '"\\$':
            out.append("\\" + char)
        elif char == "?" or ord(char) < 32 or ord(char) > 126:
            out.append("_")
            changed = True
        else:
            out.append(char)
    return '"' + "".join(out) + '"', changed or len(value) > limit


def _entries_text(interval: Interval) -> List[str]:
    """Address list entries for an interval: an IPv4 range as it is, an IPv6 range as the prefixes it is made of."""
    version, first, last = interval
    if version == 4:
        return [interval_text(interval)]
    return [str(net) if net.prefixlen < 128 else str(net.network_address)
            for net in ipaddress.summarize_address_range(int_to_ip(6, first), int_to_ip(6, last))]  # fmt: skip


def service_fragments(entries: List[ServiceEntry], family: int) -> List[List[str]]:
    """RouterOS properties per rule for protocol/port entries of one IP version; [] matches every protocol."""
    out: List[List[str]] = []
    merged: Dict[Tuple[str, str], List[str]] = {}
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            ports = merged.setdefault((entry.protocol.value, entry.src_ports), [])
            ports += [port for port in (entry.dst_ports.split(",") if entry.dst_ports else [""]) if port not in ports]
    for (proto, src_ports), ports in merged.items():
        chunks = [[]] if "" in ports else [ports[i : i + _PORTS_PER_RULE] for i in range(0, len(ports), _PORTS_PER_RULE)]
        src = src_ports.split(",") if src_ports else []
        src_chunks = [src[i : i + _PORTS_PER_RULE] for i in range(0, len(src), _PORTS_PER_RULE)] or [[]]
        for chunk in chunks:
            for src_chunk in src_chunks:
                parts = [f"protocol={proto}"]
                parts += [f"dst-port={','.join(chunk)}"] if chunk else []
                parts += [f"src-port={','.join(src_chunk)}"] if src_chunk else []
                out.append(parts)
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            continue
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            if (entry.protocol == Protocol.ICMP) != (family == 4):
                continue  # ICMP belongs to IPv4, ICMPv6 to IPv6
            parts = [f"protocol={'icmp' if family == 4 else 'icmpv6'}"]
            if entry.icmp_type is not None:
                code = "0-255" if entry.icmp_code is None else str(entry.icmp_code)
                parts.append(f"icmp-options={entry.icmp_type}:{code}")
            out.append(parts)
        elif entry.ip_protocol:
            if (entry.ip_protocol == 1 and family == 6) or (entry.ip_protocol == 58 and family == 4):
                continue
            out.append([f"protocol={_NAMED.get(entry.ip_protocol, str(entry.ip_protocol))}"])
        else:
            out.append([])
    unique: List[List[str]] = []
    for parts in out:
        if parts not in unique:
            unique.append(parts)
    return unique


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones: AbstractSet[str] = frozenset()  # zone names of the rules before --zone-map (set by emit)
        self.prefix = options.object_prefix or "fws-"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.leaves = _iptables._Emitter(p, Report(), options, 4)  # what a member stands for, and the NAT planner
        self.families = [4, 6]
        if p.scope in ("IPv4", "IPv6"):
            self.families = [4 if p.scope == "IPv4" else 6]
        self.zone_lists: Dict[str, str] = {}
        self.zone_names: Set[str] = set()
        self.zone_lines: List[str] = []
        self.guessed: List[str] = []  # zones written with their own name as the interface
        self.lists: Dict[Tuple[int, Tuple[str, ...]], str] = {}
        self.list_names: Dict[int, Set[str]] = {4: set(), 6: set()}
        self.list_lines: Dict[int, List[str]] = {4: [], 6: []}
        self.body: List[str] = []
        self.nat_lines: List[str] = []
        self.chains = 0
        self.changed: List[str] = []
        self.fqdn: Set[str] = set()
        self.tied: Set[str] = set()
        self.written_families: Set[int] = set()
        self.origdst = False

    # -- names ----------------------------------------------------------------------------

    def _q(self, value: str, limit: int = 255) -> str:
        text, changed = _text(value, limit)
        if changed and value not in self.changed:
            self.changed.append(value)
        return text

    def _safe(self, name: str, taken: Set[str]) -> str:
        """A list name that needs no quotes: letters, digits, '.', '_' and '-', at most 63 characters."""
        clean = "".join(c if c.isascii() and (c.isalnum() or c in "._-") else "_" for c in name)[:63]
        if clean != name and name not in self.changed:
            self.changed.append(name)
        candidate, counter = clean, 2
        while candidate.lower() in taken:
            candidate = f"{clean[:58]}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _zone(self, zone: str) -> str:
        """The interface list of a zone, made on first use."""
        if zone in self.zone_lists:
            return self.zone_lists[zone]
        name = self._safe(self.prefix + zone, self.zone_names)
        self.zone_lists[zone] = name
        interfaces = transform.target_interfaces(self.p, self.options.zone_map, zone)
        if not interfaces:
            interfaces = [zone]
            self.guessed.append(zone)
        self.zone_lines.append(f"/interface list add name={name} comment=\"fwshift\"")
        for interface in transform.dedupe([self.options.interface_map.get(i, i) for i in interfaces]):
            self.zone_lines.append(f"/interface list member add list={name} interface={self._q(interface, 63)} comment=\"fwshift\"")
        return name

    def _address_list(self, family: int, entries: List[str], base: str) -> str:
        key = (family, tuple(entries))
        if key in self.lists:
            return self.lists[key]
        name = self._safe(base, self.list_names[family])
        self.lists[key] = name
        menu = "/ip" if family == 4 else "/ipv6"
        for entry in entries:
            self.list_lines[family].append(f"{menu} firewall address-list add list={name} address={self._q(entry)}")
        return name

    # -- addresses and services ---------------------------------------------------------

    def _side(self, rule: Rule, source: bool, family: int, number: int) -> Side:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        intervals: List[Interval] = []
        hosts: List[str] = []
        for kind, value in [leaf for member in members for leaf in self.leaves._leaves(member)]:
            if kind == "any":
                return None if negated else []
            if kind == "fqdn":
                assert isinstance(value, str)
                address = self.p.addresses[value]
                if address.fqdn_family in (0, family):
                    hosts.append(address.value)
                    self.fqdn.add(address.value)
                continue
            assert isinstance(value, tuple)
            if value[0] != family:
                continue
            if value in (FULL_V4, FULL_V6):
                return None if negated else []
            intervals.append(value)
        if not intervals and not hosts:
            return [] if negated else None
        word = "src" if source else "dst"
        bang = "!" if negated else ""
        entries = transform.dedupe([text for interval in intervals for text in _entries_text(interval)] + hosts)
        if len(entries) == 1 and not hosts and len(_entries_text(intervals[0])) == 1:
            return [f"{word}-address={bang}{entries[0]}"]
        groups = [m for m in members if m in self.p.address_groups]
        base = self.prefix + (groups[0] if len(members) == 1 and groups else f"r{number}-{word}")
        name = self._address_list(family, entries, base)
        return [f"{word}-address-list={bang}{name}"]

    def _entries(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[ServiceEntry]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            return [entry for _, entries in lowered for entry in entries]
        if rule.services == [ANY]:
            return None
        entries: List[ServiceEntry] = []
        for service in rule.services:
            entries += transform.flatten_services(self.p, service) or []
        return entries

    # -- security rules -----------------------------------------------------------------

    def _describe(self, rule: Rule) -> str:
        return _iptables._Emitter._describe(self.leaves, rule)

    def _verdict(self, rule: Rule, fragments: List[List[str]], negated: bool) -> List[str]:
        if rule.action == Action.ALLOW:
            return ["action=accept"]
        if rule.action == Action.DROP:
            return ["action=drop"]
        if rule.action == Action.DENY:
            return ["action=reject"]
        if not negated and fragments and all(f and f[0] == "protocol=tcp" for f in fragments):
            return ["action=reject", "reject-with=tcp-reset"]
        self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                        f"action {rule.action.value} becomes a plain reject: a TCP reset can only answer TCP")  # fmt: skip
        return ["action=reject"]

    def _rule(self, rule: Rule, number: int) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        entries = self._entries(rule, reasons)
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as interface pairs"))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
            self.body.append(f"# FWSHIFT disabled, see the report: {self._describe(rule)}")
            return
        if pairs is not None and not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                             f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing",
                             Severity.INFO)  # fmt: skip
            return
        heads: List[Tuple[int, List[str], List[List[str]], bool]] = []  # IP version, addresses, services, negated
        self.fqdn = set()
        for family in self.families:
            src = self._side(rule, True, family, number)
            dst = self._side(rule, False, family, number)
            negated = rule.negate_service
            if entries is None:
                fragments: List[List[str]] = [] if negated else [[]]
            else:
                fragments = service_fragments(entries, family)
                if negated and [] in fragments:
                    fragments = []
                elif negated and not fragments:
                    fragments, negated = [[]], False  # the excluded services do not exist in this IP version
            if src is None or dst is None or not fragments:
                continue
            heads.append((family, src + dst, fragments, negated))
        if not heads:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "nothing in this rule can match a packet of the IP versions written", Severity.INFO)  # fmt: skip
            return
        zones: List[List[str]] = []
        for src_zones, dst_zones in pairs or []:
            for src_zone in src_zones:
                for dst_zone in dst_zones:
                    parts = [f"in-interface-list={self._zone(src_zone)}"] if src_zone != ANY else []
                    parts += [f"out-interface-list={self._zone(dst_zone)}"] if dst_zone != ANY else []
                    zones.append(parts)
        tail = []
        if rule.log_start:
            tail += ["log=yes", f"log-prefix={self._q(rule.name, 32)}"]
        tail.append(f"comment={self._q(rule.name)}")
        disabled = [] if rule.enabled else ["disabled=yes"]
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.body.append(f"# disabled {'by the audit' if by_audit else 'in the source'}: {self._describe(rule)}")
        count = 0
        for family, addresses, fragments, negated in heads:
            menu = f"/{'ip' if family == 4 else 'ipv6'} firewall filter add"
            self.written_families.add(family)
            verdict = self._verdict(rule, fragments, negated)
            if not negated and len(zones) * len(fragments) <= _INLINE_LIMIT:
                for zone in zones:
                    for fragment in fragments:
                        self.body.append(" ".join([menu, f"chain={CHAIN}"] + zone + addresses + fragment + verdict + tail + disabled))
                        count += 1
                continue
            self.chains += 1
            chain = f"fwshift-r{self.chains}"
            for zone in zones:
                self.body.append(" ".join([menu, f"chain={CHAIN}"] + zone + addresses + ["action=jump", f"jump-target={chain}"]
                                          + [f"comment={self._q(rule.name)}"] + disabled))  # fmt: skip
                count += 1
            if negated:
                # The services a packet must not have: the chain returns on each of them, and decides for the rest.
                for fragment in fragments:
                    self.body.append(" ".join([menu, f"chain={chain}"] + fragment + ["action=return"]))
                self.body.append(" ".join([menu, f"chain={chain}"] + verdict + tail))
            else:
                for fragment in fragments:
                    self.body.append(" ".join([menu, f"chain={chain}"] + fragment + verdict + tail))
            item.emitted_as.append(f"chain {chain}" + (" (IPv6)" if family == 6 else ""))
        if count:
            item.emitted_as.append(f"{count} {CHAIN} rule" + ("s" if count != 1 else ""))
        for name in sorted(self.fqdn):
            self.report.add("rule", rule.origin, Severity.INFO, "ROUTEROS_FQDN",
                            f"'{name}' is a host name in an address list: the router resolves it and keeps the list "
                            "up to date")  # fmt: skip

    # -- NAT ----------------------------------------------------------------------------

    def plan(self, nat: NatRule) -> _iptables.Plan:
        """What a NAT rule becomes (as iptables lines of the planner), or why it cannot be written."""
        tokens: Dict[str, str] = {}
        clone = copy.copy(nat)
        for attr in ("src_zones", "dst_zones"):
            names = []
            for zone in getattr(nat, attr):
                if zone == ANY:
                    names.append(zone)
                    continue
                tokens.setdefault(zone, f"fwsz{len(tokens)}")
                names.append(tokens[zone])
            setattr(clone, attr, names)
        problem, prerouting, postrouting, findings = self.leaves.nat_plan(clone)
        back = {token: zone for zone, token in tokens.items()}

        def named(message: str) -> str:
            for token, zone in sorted(back.items(), key=lambda item: -len(item[0])):
                message = message.replace(token, zone)
            return message.replace("--to iptables", "--to routeros").replace("POSTROUTING", "chain srcnat").replace(
                "PREROUTING", "chain dstnat")  # fmt: skip

        if problem is not None:
            code, message, severity = problem
            return (code, named(message), severity), [], [], []
        pre = [self._nat_line(line, back, nat.name) for line in prerouting]
        post = [self._nat_line(line, back, nat.name) for line in postrouting]
        fixed = [(s, c, named(m)) for s, c, m in findings]
        return None, pre, post, fixed

    def _nat_line(self, line: str, back: Dict[str, str], name: str) -> str:
        """One iptables NAT line of the planner as the properties of a RouterOS NAT rule. The words are the closed
        set the planner writes."""
        words = shlex.split(line)
        chain = "fwshift-dstnat" if words[1] == "PREROUTING" else "fwshift-srcnat"
        out: List[str] = [f"chain={chain}"]
        action: List[str] = []
        i = 2
        while i < len(words):
            word = words[i]
            value = words[i + 1] if i + 1 < len(words) else ""
            if word in ("-i", "-o"):
                key = "in-interface-list" if word == "-i" else "out-interface-list"
                out.append(f"{key}={self._zone(back.get(value, value))}")
            elif word in ("-s", "-d"):
                out.append(f"{'src' if word == '-s' else 'dst'}-address={value[:-3] if value.endswith('/32') else value}")
            elif word == "-p":
                out.append(f"protocol={value}")
            elif word == "-m":
                if value == "iprange" and i + 3 < len(words):
                    out.append(f"{'src' if words[i + 2] == '--src-range' else 'dst'}-address={words[i + 3]}")
                    i += 4
                    continue
                if value == "conntrack" and i + 3 < len(words) and words[i + 2] == "--ctorigdst":
                    self.origdst = True  # (a NAT rule of RouterOS cannot match the destination before translation)
                    i += 4
                    continue
                if value == "comment" and i + 3 < len(words):
                    i += 4  # (the name is written as it is, below)
                    continue
                if value in ("tcp", "udp", "sctp", "multiport"):
                    i += 2
                    continue
                raise ValueError(f"unexpected match module {value}")
            elif word in ("--dport", "--dports", "--sport", "--sports"):
                out.append(f"{'dst' if word.startswith('--d') else 'src'}-port={value.replace(':', '-')}")
            elif word == "-j":
                if value == "DNAT":
                    address, _, port = words[i + 3].partition(":")
                    action = ["action=dst-nat", f"to-addresses={address}"] + ([f"to-ports={port}"] if port else [])
                    i += 4
                    continue
                if value == "SNAT":
                    action = ["action=src-nat", f"to-addresses={words[i + 3]}"]
                    i += 4
                    continue
                action = [{"MASQUERADE": "action=masquerade", "ACCEPT": "action=accept"}[value]]
            else:
                raise ValueError(f"unexpected word {word}")
            i += 2
        out += action + [f"comment={self._q(name)}"]
        return " ".join(out)

    def _nat(self) -> None:
        for nat in self.p.nat_rules:
            self.origdst = False
            problem, pre, post, findings = self.plan(nat)
            if problem is not None:
                self.report.skip("nat", nat.origin, *problem)
                continue
            item = self.report.item("nat", nat.origin)
            for severity, code, message in findings:
                self.report.add("nat", nat.origin, severity, code, message)
            if self.origdst:
                self.report.add("nat", nat.origin, Severity.APPROX, "NAT_AFTER_DNAT",
                                "the source translation of this rule is matched after its destination translation; a "
                                "NAT rule of RouterOS cannot match the destination a connection had before it, so it "
                                "also applies to traffic from the same sources sent to the translated address directly")  # fmt: skip
            self.nat_lines += [f"/ip firewall nat add {line}" + ("" if nat.enabled else " disabled=yes") for line in pre + post]
            if not nat.enabled:
                self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written disabled")
            else:
                item.emitted_as += ([f"{len(pre)} dstnat"] if pre else []) + ([f"{len(post)} srcnat"] if post else [])

    # -- output -------------------------------------------------------------------------

    def _defaults(self) -> None:
        """The end of the chain: what the policy does inside a zone and between zones when no rule decides."""
        zones = transform.target_zones(self.p, self.options.zone_map, [z for r in self.p.rules for z in r.src_zones + r.dst_zones if z != ANY], [])
        between = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, zones, self.report)
        for family in self.families:
            menu = f"/{'ip' if family == 4 else 'ipv6'} firewall filter add chain={CHAIN}"
            for zone in zones:
                inside = decided[zone]
                if inside != between:
                    name = self._zone(zone)
                    action = "accept" if inside else "drop"
                    self.body.append(f"{menu} in-interface-list={name} out-interface-list={name} action={action} "
                                     f"comment=\"fwshift: inside zone {self._q(zone)[1:-1]}\"")  # fmt: skip
            self.body.append(f"{menu} action={'accept' if between else 'drop'} comment=\"fwshift: default\"")

    def run(self) -> str:
        self._nat()
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=self.tied)
        for number, rule in enumerate(self.p.rules, 1):
            self._rule(rule, number)
        self._defaults()
        self._notes()
        out = [
            "# Generated by FWShift - review the conversion report before loading this.",
            "# A script for /import on RouterOS 6 or 7: /import file-name=FILE verbose=yes",
            "# Nothing in it changes traffic until the disabled jump rules at its end are enabled (in Safe Mode).",
        ]
        out += [_GUARD.format("ip" if family == 4 else "ipv6") for family in self.families]
        out += self.zone_lines
        for family in self.families:
            out += self.list_lines[family]
        for family in self.families:
            menu = f"/{'ip' if family == 4 else 'ipv6'} firewall filter add chain={CHAIN}"
            out.append(f"{menu} action=accept connection-state=established,related,untracked comment=\"fwshift: replies\"")
            out.append(f"{menu} action=drop connection-state=invalid comment=\"fwshift: invalid\"")
        out += self.body
        out += self.nat_lines
        out.append("# Switch the policy on: enable these in Safe Mode, and move them to where they belong in their chains.")
        for family in self.families:
            menu = "/ip" if family == 4 else "/ipv6"
            out.append(f"{menu} firewall filter add chain=forward action=jump jump-target={CHAIN} disabled=yes "
                       "comment=\"fwshift: enable to switch the policy on\"")  # fmt: skip
        chains = {line.split("chain=", 1)[1].split(" ", 1)[0] for line in self.nat_lines}
        for chain, builtin in (("fwshift-dstnat", "dstnat"), ("fwshift-srcnat", "srcnat")):
            if chain in chains:
                out.append(f"/ip firewall nat add chain={builtin} action=jump jump-target={chain} disabled=yes "
                           "comment=\"fwshift: enable to switch the NAT rules on\"")  # fmt: skip
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        prefix = self.prefix
        removal = [
            '/ip firewall filter remove [find where chain~"^fwshift-" or jump-target~"^fwshift-"]',
            '/ipv6 firewall filter remove [find where chain~"^fwshift-" or jump-target~"^fwshift-"]',
            '/ip firewall nat remove [find where chain~"^fwshift-" or jump-target~"^fwshift-"]',
            f'/ip firewall address-list remove [find where list~"^{prefix}"]',
            f'/ipv6 firewall address-list remove [find where list~"^{prefix}"]',
            f'/interface list member remove [find where list~"^{prefix}"]',
            f'/interface list remove [find where name~"^{prefix}"]',
        ]
        default = "accept" if self.p.default_interzone == Action.ALLOW else "drop"
        self.report.note(
            Severity.REVIEW,
            "ROUTEROS_LOAD",
            "load the script with '/import file-name=FILE verbose=yes'. It stops at its first lines when objects of an "
            "earlier conversion are on the router, and at the first line the router refuses (lines before it stay; on "
            "RouterOS 6 the /ipv6 lines need the ipv6 package). "
            f"Nothing changes traffic until the disabled jump rules at its end are enabled: enable them in Safe Mode, "
            "and move each to where it belongs in its chain (in forward, after the rules that accept established "
            f"connections). Chain {CHAIN} ends with an explicit {default}, so the rules of forward after the jump "
            "are no longer reached by forwarded traffic. To take a conversion away again: " + "; ".join(removal),
        )
        if self.guessed or (self.zone_lists and self.p.vendor != "routeros"):
            listed = self.guessed or sorted(self.zone_lists)
            self.report.note(
                Severity.REVIEW,
                "INTERFACES_REQUIRED",
                "zones are written as interface lists, whose members must be interfaces of the router, or the import "
                "stops. Check the members, and map the zones with --zone-map (or the interfaces with --interface-map): "
                + ", ".join(listed),
            )
        if len(self.families) == 1:
            other = 6 if self.families == [4] else 4
            self.report.note(
                Severity.REVIEW,
                "ONE_IP_VERSION",
                f"the source policy is for IPv{self.families[0]} only: the script writes /{'ip' if other == 6 else 'ipv6'} "
                f"firewall filter only, and the router goes on forwarding IPv{other} as its own rules say",
            )
        if any(r.log_start for r in self.p.rules):
            self.report.note(
                Severity.INFO,
                "ROUTEROS_LOG",
                "rules that log the start of a connection have log=yes: the router logs the first packet of each "
                "connection they accept (and every packet a deny rule drops)",
            )
        if self.changed:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_TEXT",
                "names and comments with characters RouterOS cannot take in a script ('?', control characters, "
                "characters beyond ASCII), or longer than it takes, were changed: " + ", ".join(self.changed[:10]),
            )
