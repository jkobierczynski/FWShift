# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""nftables emitter: neutral model -> a ruleset for ``nft -f``.

Design rules:

* One table, ``inet fwshift``, for both IP versions. The file first creates it, then deletes it, then writes it
  again: ``nft -f`` loads a file as one transaction, so the table is replaced at once and nothing else is touched.
* Only the forward hook and, for IPv4, the NAT chains at prerouting and postrouting are written. The file never
  filters traffic of the host itself.
* The model is connection-based: the chain starts by accepting established connections, and the rules that follow
  decide about new ones.
* Lists of interfaces, addresses and ports become anonymous sets, so a rule of the model stays one line per IP
  version and protocol. A rule that cannot be enforced is written as a comment, so it is visible and not loaded.
* The forward hook sees packets after destination NAT: rules are rewritten to the translated address, as for
  every platform that looks policy up after NAT.
"""

from __future__ import annotations

import copy
import shlex
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, L4_PROTOCOLS, Action, Policy, Protocol, Rule, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text
from ..options import Options
from ..report import Report, Severity
from . import iptables as _iptables

Side = Optional[Tuple[List[str], bool]]  # None: nothing of this IP version; ([], False): any address of it


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    planner = _iptables._Emitter(p, Report(), options, 4)
    # The forward hook sees the post-NAT destination. Rewrite only for translations that are really written.
    written = {
        nat.origin
        for nat in p.nat_rules
        if planner.nat_plan(nat)[0] is None
        and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)
    }
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def valid_interface(name: str) -> bool:
    return _iptables.valid_interface(name) and not any(c in name for c in "*\\'")


def _quote(text: str, limit: int = 120, end: str = "") -> str:
    """A string nft reads back as it is: no double quotes or control characters, at most ``limit`` bytes (with
    ``end``, which follows the text)."""
    cleaned = " ".join(text.replace('"', "'").replace("\\", "/").split())
    while len((cleaned + end).encode("utf-8")) > limit:
        cleaned = cleaned[:-1]
    return f'"{cleaned}{end}"'


def _set(items: List[str]) -> str:
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _ports(text: str) -> str:
    return _set([part for part in text.split(",")])


def service_fragments(entries: List[ServiceEntry], family: int) -> List[str]:
    """nft match fragments for protocol/port entries of one IP version; "" matches every protocol."""
    out: List[str] = []
    merged: Dict[Tuple[str, str], List[str]] = {}
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            ports = merged.setdefault((entry.protocol.value, entry.src_ports), [])
            ports += [port for port in (entry.dst_ports.split(",") if entry.dst_ports else [""]) if port not in ports]
    for (proto, src_ports), ports in merged.items():
        parts = []
        if "" not in ports:
            parts.append(f"{proto} dport {_set(ports)}")
        if src_ports:
            parts.append(f"{proto} sport {_ports(src_ports)}")
        out.append(" ".join(parts) or f"meta l4proto {proto}")
    icmp_types: List[str] = []
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            continue
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            if (entry.protocol == Protocol.ICMP) != (family == 4):
                continue  # ICMP belongs to IPv4, ICMPv6 to IPv6
            word = "icmp" if family == 4 else "icmpv6"
            if entry.icmp_type is None:
                out.append(f"meta l4proto {'icmp' if family == 4 else 'ipv6-icmp'}")
            elif entry.icmp_code is not None:
                out.append(f"{word} type {entry.icmp_type} {word} code {entry.icmp_code}")
            else:
                icmp_types.append(str(entry.icmp_type))
        elif entry.ip_protocol:
            out.append(f"meta l4proto {entry.ip_protocol}")
        else:
            out.append("")
    if icmp_types:
        out.append(f"{'icmp' if family == 4 else 'icmpv6'} type {_set(transform.dedupe(icmp_types))}")
    return transform.dedupe(out)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.leaves = _iptables._Emitter(p, Report(), options, 4)  # what a member stands for
        self.planner = self.leaves
        self.forward: List[str] = []
        self.chains: Dict[str, List[str]] = {}
        self.prerouting: List[str] = []
        self.postrouting: List[str] = []
        self.tied: Set[str] = set()
        self.log_end_only = 0

    # -- addresses and services -------------------------------------------

    def _elements(self, members: List[str]) -> Tuple[Dict[int, List[str]], bool, List[str]]:
        """(set elements per IP version, whether the list covers everything, FQDN objects used)."""
        out: Dict[int, List[str]] = {4: [], 6: []}
        names: List[str] = []
        for kind, value in [leaf for member in members for leaf in self.leaves._leaves(member)]:
            if kind == "any":
                return {4: [], 6: []}, True, []
            if kind == "fqdn":
                assert isinstance(value, str)
                names.append(value)
                continue
            assert isinstance(value, tuple)
            interval: Interval = value
            if interval in (FULL_V4, FULL_V6):
                out[interval[0]] = ["*"]  # every address of this version
                continue
            if out[interval[0]] != ["*"]:
                out[interval[0]].append(interval_text(interval))
        return {f: transform.dedupe(v) for f, v in out.items()}, False, names

    def _side(self, rule: Rule, source: bool, family: int, elements: Tuple[Dict[int, List[str]], bool, List[str]]) -> Side:
        negated = rule.negate_source if source else rule.negate_destination
        per_family, everything, _ = elements
        mine = per_family[family]
        if everything or mine == ["*"]:
            return None if negated else ([], False)
        if negated:
            return (mine, True) if mine else ([], False)
        return (mine, False) if mine else None

    def _entries(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[ServiceEntry]]:
        """The protocol/port entries of a rule; None for any service."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            return [entry for _, entries in lowered for entry in entries]
        if rule.services == [ANY]:
            return None
        entries: List[ServiceEntry] = []
        for service in rule.services:
            entries += transform.flatten_services(self.p, service) or []
        return entries

    # -- security rules ---------------------------------------------------

    def _describe(self, rule: Rule) -> str:
        return _iptables._Emitter._describe(self.leaves, rule)

    def _rule(self, rule: Rule) -> None:
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
        bad = [z for z in rule.src_zones + rule.dst_zones if z != ANY and not valid_interface(z)]
        if bad:
            reasons.append(("INTERFACE_NAME", "'" + "', '".join(bad) + "' cannot be an interface name; map it with --zone-map"))
        sources = self._elements(rule.sources)
        destinations = self._elements(rule.destinations)
        fqdn = transform.dedupe(sources[2] + destinations[2])
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": an nftables rule matches "
                            "addresses only; resolve it into an address object or a set kept up to date by a script"))  # fmt: skip
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
            self.forward.append(f"# FWSHIFT disabled, see the report: {self._describe(rule)}")
            return
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.forward.append(f"# disabled {'by the audit' if by_audit else 'in the source'}: {self._describe(rule)}")
            return
        if pairs is not None and not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                             f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing",
                             Severity.INFO)  # fmt: skip
            return
        heads: List[Tuple[str, List[str], bool]] = []  # per IP version: address part, service fragments, negated
        for family in (4, 6):
            src = self._side(rule, True, family, sources)
            dst = self._side(rule, False, family, destinations)
            negated = rule.negate_service
            if entries is None:
                fragments = [] if negated else [""]  # "not any service" matches nothing
            else:
                fragments = service_fragments(entries, family)
                if negated and "" in fragments:
                    fragments = []
                elif negated and not fragments:
                    fragments, negated = [""], False  # the excluded services do not exist in this IP version
            if src is None or dst is None or not fragments:
                continue
            word = "ip" if family == 4 else "ip6"
            parts = []
            for (members, excluded), which in ((src, "saddr"), (dst, "daddr")):
                if members:
                    parts.append(f"{word} {which} {'!= ' if excluded else ''}{_set(members)}")
            head = " ".join(parts)
            implied = "icmp type " if family == 4 else "icmpv6 type "  # (an ICMP type match keeps to its IP version)
            if not head and (negated or not all(f.startswith(implied) for f in fragments)):
                head = f"meta nfproto ipv{family}"
            heads.append((head, fragments, negated))
        if not heads:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "nothing in this rule can match a packet of either IP version", Severity.INFO)  # fmt: skip
            return
        if len(heads) == 2 and all(h[0].startswith("meta nfproto ") for h in heads) and heads[0][2] == heads[1][2]:
            heads = [("", transform.dedupe(heads[0][1] + heads[1][1]), heads[0][2])]  # one line for both versions
        verdict = self._verdict(rule, [f for _, fragments, negated in heads for f in (fragments if not negated else ["!"])])
        state = "ct state new " if rule.action == Action.ALLOW else ""
        log = ""
        if rule.log_start:
            log = f"log prefix {_quote(rule.name.replace('$', '_'), 64, end=': ')} "  # (nft expands $NAME in a prefix)
        elif rule.log_end:
            self.log_end_only += 1
        tail = f"{state}counter {log}{verdict} comment {_quote(rule.name)}"
        zones = []
        for src_zones, dst_zones in pairs or []:
            parts = []
            if ANY not in src_zones:
                parts.append("iifname " + _set([f'"{z}"' for z in src_zones]))
            if ANY not in dst_zones:
                parts.append("oifname " + _set([f'"{z}"' for z in dst_zones]))
            zones.append(" ".join(parts))
        count = 0
        chain = ""
        if any(negated for _, _, negated in heads):
            # The services a packet must not have: a chain returns on each of them, and decides for the rest.
            chain = f"fws{len(self.chains) + 1}"
            body = transform.dedupe([f"{f} return" for _, fragments, negated in heads if negated for f in fragments])
            self.chains[chain] = body + [tail]
            item.emitted_as.append(f"chain {chain}")
        for zone in zones:
            for head, fragments, negated in heads:
                if negated:
                    self.forward.append(" ".join(p for p in (zone, head, f"jump {chain}") if p))
                    count += 1
                    continue
                for fragment in fragments:
                    self.forward.append(" ".join(p for p in (zone, head, fragment, tail) if p))
                    count += 1
        if not chain or any(not negated for _, _, negated in heads):
            item.emitted_as.append(f"{count} forward rule" + ("s" if count != 1 else ""))

    def _verdict(self, rule: Rule, fragments: List[str]) -> str:
        if rule.action == Action.ALLOW:
            return "accept"
        if rule.action == Action.DROP:
            return "drop"
        if rule.action == Action.DENY:
            return "reject"
        tcp_only = bool(fragments) and all(f.startswith("tcp ") or f == "meta l4proto tcp" for f in fragments)
        if tcp_only:
            return "reject with tcp reset"
        self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                        f"action {rule.action.value} becomes a plain reject: a TCP reset can only answer TCP")  # fmt: skip
        return "reject"

    # -- NAT --------------------------------------------------------------

    def _nat(self) -> None:
        for nat in self.p.nat_rules:
            problem, prerouting, postrouting, findings = self.planner.nat_plan(nat)
            if problem is not None:
                code, message, severity = problem
                self.report.skip("nat", nat.origin, code, message.replace("--to iptables", "--to nftables"), severity)
                continue
            item = self.report.item("nat", nat.origin)
            for severity, code, message in findings:
                self.report.add("nat", nat.origin, severity, code, message.replace("POSTROUTING", "postrouting"))
            if any("--ctorigdst" in line for line in postrouting):
                self.tied.add(nat.origin)
            pre = [_nat_line(line) for line in prerouting]
            post = [_nat_line(line) for line in postrouting]
            if not nat.enabled:
                pre = ["# disabled in the source: " + line for line in pre]
                post = ["# disabled in the source: " + line for line in post]
                self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written as a comment")
            else:
                item.emitted_as += ([f"{len(pre)} prerouting"] if pre else []) + ([f"{len(post)} postrouting"] if post else [])
            self.prerouting += pre
            self.postrouting += post

    # -- output -----------------------------------------------------------

    def run(self) -> str:
        self._nat()
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=self.tied)
        for rule in self.p.rules:
            self._rule(rule)
        self._notes()
        policy = "accept" if self.p.default_interzone == Action.ALLOW else "drop"
        nat = bool(self.prerouting or self.postrouting)
        out = [
            "# Generated by FWShift - review the conversion report before loading this.",
            f"# The forward hook{' and the NAT chains' if nat else ''} of table inet fwshift. Check it with "
            "'nft -c -f FILE', load it with 'nft -f FILE':",
            "# the table is replaced as a whole, in one transaction, and no other table is touched.",
            "table inet fwshift",
            "delete table inet fwshift",
            "table inet fwshift {",
            "\tchain forward {",
            f"\t\ttype filter hook forward priority filter; policy {policy};",
            "\t\tct state established,related accept",
            "\t\tct state invalid drop",
        ]
        out += ["\t\t" + line for line in self.forward]
        out.append("\t}")
        for name, body in self.chains.items():
            out += ["", f"\tchain {name} {{"] + ["\t\t" + line for line in body] + ["\t}"]
        if self.prerouting:
            out += ["", "\tchain prerouting {", "\t\ttype nat hook prerouting priority dstnat; policy accept;"]
            out += ["\t\t" + line for line in self.prerouting] + ["\t}"]
        if self.postrouting:
            out += ["", "\tchain postrouting {", "\t\ttype nat hook postrouting priority srcnat; policy accept;"]
            out += ["\t\t" + line for line in self.postrouting] + ["\t}"]
        out.append("}")
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW,
            "NFT_LOAD",
            "the output is one table, inet fwshift, which replaces itself when loaded: check it with 'nft -c -f FILE', "
            "load it with 'nft -f FILE'. Other tables stay as they are, but every base chain at the forward hook sees "
            "each packet: the drop policy here drops what this table does not accept even where another table "
            "(firewalld, Docker, libvirt, iptables-nft) accepts it, and a drop in another table still wins over an "
            "accept here",
        )
        interfaces = transform.dedupe(
            [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        )
        if interfaces and self.p.vendor not in ("iptables", "nftables"):
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
                "the source accepts traffic between zones that no rule matches, but not inside a zone. The forward "
                "policy is accept and cannot tell the two apart: traffic that leaves by the interface it came in "
                "on is accepted as well",
            )
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "INTRAZONE_ALLOW",
                "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                "written for that: " + ", ".join(open_zones),
            )
        if self.p.scope in ("IPv4", "IPv6") and self.p.vendor in ("iptables", "nftables"):
            other = "IPv6" if self.p.scope == "IPv4" else "IPv4"
            action = "accepts" if self.p.default_interzone == Action.ALLOW else "drops"
            self.report.note(
                Severity.REVIEW,
                "ONE_IP_VERSION",
                f"the source policy is for {self.p.scope} only; table inet fwshift sees {other} as well, and its "
                f"policy {action} forwarded {other} traffic that no rule matches",
            )
        if self.log_end_only:
            self.report.note(
                Severity.INFO,
                "LOGGING_AT_END",
                f"{self.log_end_only} rule{'s log' if self.log_end_only != 1 else ' logs'} the end of a connection "
                "on the source; an nftables rule logs the packet it matches, so only rules that log the start of a "
                "connection got a log statement. Connection ends are in the conntrack events (conntrack -E, ulogd)",
            )
        if any(r.log_start for r in self.p.rules):
            self.report.note(
                Severity.INFO,
                "LOG_STATEMENTS",
                "rules that log the start of a connection have a log statement, which writes a line to the kernel "
                "log for the first packet of each connection they accept (and for every packet a deny rule drops)",
            )


def _nat_line(line: str) -> str:
    """One iptables NAT line of the planner (``-A PREROUTING -i X -d Y -p tcp -m tcp --dport 80 ... -j DNAT
    --to-destination Z``) in nft syntax. The words are the closed set the planner writes."""
    prefix = ""
    if line.startswith("# "):
        prefix, _, line = line.partition(": ")
        prefix += ": "
    words = shlex.split(line)
    out: List[str] = []
    comment = ""
    verdict = ""
    proto = ""
    i = 2  # after -A CHAIN
    while i < len(words):
        word = words[i]
        value = words[i + 1] if i + 1 < len(words) else ""
        if word == "-i":
            out.append(f'iifname "{value}"')
        elif word == "-o":
            out.append(f'oifname "{value}"')
        elif word == "-s":
            out.append(f"ip saddr {value}")
        elif word == "-d":
            out.append(f"ip daddr {value}")
        elif word == "-p":
            proto = value
            out.append(f"meta l4proto {value}")
        elif word == "-m":
            if value == "iprange" and i + 3 < len(words):
                out.append(f"ip {'saddr' if words[i + 2] == '--src-range' else 'daddr'} {words[i + 3]}")
                i += 4
                continue
            if value == "conntrack" and i + 3 < len(words) and words[i + 2] == "--ctorigdst":
                out.append(f"ct original ip daddr {words[i + 3]}")
                i += 4
                continue
            if value == "comment" and i + 3 < len(words):
                comment = words[i + 3]
                i += 4
                continue
            if value in ("tcp", "udp", "sctp", "multiport"):
                i += 2
                continue
            raise ValueError(f"unexpected match module {value}")
        elif word in ("--dport", "--dports", "--sport", "--sports"):
            ports = value.replace(":", "-")
            out.append(f"{proto} {'dport' if word.startswith('--d') else 'sport'} {_ports(ports)}")
        elif word == "-j":
            target = value
            if target == "DNAT":
                verdict = f"dnat ip to {words[i + 3]}"
                i += 4
                continue
            if target == "SNAT":
                verdict = f"snat ip to {words[i + 3]}"
                i += 4
                continue
            verdict = {"MASQUERADE": "masquerade", "ACCEPT": "accept"}[target]
        else:
            raise ValueError(f"unexpected word {word}")
        i += 2
    # A port match implies its protocol: the explicit one is dropped where a port match follows.
    if any(part.split(" ", 1)[0] in ("tcp", "udp", "sctp") for part in out):
        out = [part for part in out if not part.startswith("meta l4proto ")]
    if not any(part.startswith(("ip saddr", "ip daddr", "ct original ip daddr")) for part in out):
        out.insert(0, "meta nfproto ipv4")  # the planner writes IPv4 NAT; the table is inet
    text = " ".join(out + ["counter", verdict] + ([f"comment {_quote(comment)}"] if comment else []))
    return prefix + text
