# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Windows Defender Firewall emitter: neutral model -> a PowerShell script of ``New-NetFirewallRule`` calls.

Design rules:

* A host firewall filters the connections of the host itself, inbound and outbound, and its rules name remote and
  local addresses and ports, a direction and profiles; no zones. The zone ``Host`` (of a Windows source, or a zone
  ``--zone-map`` names ``Host``) is the host; ``Domain``, ``Private`` and ``Public`` (likewise) are the networks of
  the interfaces in each profile, and become ``-Profile``. Each rule of the model is written for every way the host
  can be one of its ends: a rule to ``Host`` inbound, from ``Host`` outbound, and between two other zones both (the
  host as the destination, inbound, and as the source, outbound). Other zones become the networks behind them
  (``--zone-network``), as for AWS: the remote side is kept to the remote zone's networks, the local side to the
  networks of the zone the host is in; an allowing rule whose zones have no networks is written disabled, a
  blocking one blocks in every zone.
* Windows has no rule order: a block rule beats every allow rule, and what none matches gets the default of the
  profile (inbound blocked, outbound allowed, unless changed). First match becomes that as follows. A block rule is
  written without what the allow rules above it match (the reverse of the AWS target, whose allow rules lose the
  deny rules above them). A written block and the allow rules below it need nothing more: the block wins. Part of a
  block that Windows cannot say (every protocol but some, ports of SCTP, many ICMP codes), and a rule that blocks
  everything below allow rules (a cleanup rule, whose cut would fall apart into many pieces), are not written but
  left to the default of the profile: then the allow rules below them are written without what they match. That is
  exact for inbound connections and, where the profile's default outbound action is Block, for outbound ones; the
  report names the profiles whose outbound connections need it (``WINFW_DEFAULT_OUTBOUND``), and so does the script
  when it runs.
* What is lost: the order of the source (a rule may become several, and block rules lose the parts the rules above
  them allowed), and whatever the host's own rules do: Windows evaluates the rules written here together with every
  other rule of the host, so a block rule of the host beats an allow rule written here, and an allow rule of the host
  lets through what the policy only denies by default. Programs, services, users and IPsec of a Windows source are
  not in the model and not written.
* The script creates rules in one rule group (``FWShift``, or ``--target-prefix``), changes no profile setting and
  deletes nothing. It stops before it creates anything when a rule of that group or name exists, and ``-DryRun``
  shows what it would create (``-WhatIf``). NAT is not written: the host sees the addresses after it.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, List, Optional, Sequence, Set, Tuple

from .. import names, regions, transform
from ..model import ANY, Action, AddressKind, Policy, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, intersect, normalize, range_text, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

HOST = "Host"
PROFILES = ("Domain", "Private", "Public")
KEYWORD_PREFIX = "windows-firewall:"
_MAX_ICMP = 300  # ICMP types and codes listed in one rule; more are not written
_LIMIT = 512  # pieces a rule may fall apart into
Key = Tuple[str, str]  # (direction "in"/"out", profile)
Keyword = Tuple[str, int]  # (word, IP version)
_PS_QUOTES = "'‘’‚‛"  # PowerShell ends a single-quoted string at any of these


def emit(policy: Policy, report: Report, options: Options) -> str:
    return _Emitter(prepare(policy, report, options), report, options, transform.rule_zones(policy)).run()


def prepare(policy: Policy, report: Report, options: Options) -> Policy:
    """The policy as the host sees it (a copy): zones mapped, the destinations after NAT."""
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks, options.zone_excluded)  # refuses networks that contradict each other
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return p


def _ps(text: str) -> str:
    """A PowerShell string in single quotes: control characters out, every kind of single quote doubled."""
    text = "".join(" " if ord(c) < 32 or ord(c) == 127 or c in "\x85  " else c for c in text)
    return "'" + "".join(c + c if c in _PS_QUOTES else c for c in text) + "'"


@dataclass(frozen=True)
class _Side:
    intervals: Tuple[Interval, ...]
    keywords: Tuple[Keyword, ...] = ()


@dataclass
class _Piece:
    """Part of what a rule matches for one direction and profile: (IP version, remote, local, services) and the address
    keywords of the remote side."""

    box: regions.Box
    keywords: Tuple[str, ...] = ()

    def remote(self) -> List[Interval]:
        return [regions.full(self.box[0])] if self.keywords else self.box[1]

    def full(self) -> bool:
        v = self.box[0]
        return not self.keywords and self.box[1] == [regions.full(v)] and self.box[2] == [regions.full(v)] and self.box[3].everything()


def _meets(a: _Piece, b: _Piece) -> bool:
    """Whether two pieces can match one connection (a keyword taken as every address)."""
    if a.box[0] != b.box[0]:
        return False
    return bool(intersect(a.remote(), b.remote())) and bool(intersect(a.box[2], b.box[2])) and a.box[3].meets(b.box[3])


@dataclass
class _Spec:
    protocol: str  # "" for any
    local_ports: Tuple[str, ...] = ()
    remote_ports: Tuple[str, ...] = ()
    icmp: Tuple[str, ...] = ()


@dataclass
class _Row:
    spec: _Spec
    versions: Set[int]
    remote: List[Interval]
    local: List[Interval]
    keywords: Set[Keyword] = field(default_factory=set)


@dataclass
class _Written:
    rule: Rule
    allow: bool
    enabled: bool = True
    pieces: Dict[Key, List[_Piece]] = field(default_factory=dict)
    synthetic: bool = False  # the default of the source, not a rule of it


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options, self.source_zones = p, report, options, source_zones
        self.keyword_groups = {name for name, group in p.address_groups.items()
                               if group.builtin == "windows-firewall" and group.dynamic_filter.startswith(KEYWORD_PREFIX)}  # fmt: skip
        self.taint_a = transform.tainted_addresses(p, keep=self.keyword_groups)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))
        mapped = {value.lower() for value in options.zone_map.values()}
        self.special = {z for z in self.universe
                        if z.lower() in {HOST.lower()} | {x.lower() for x in PROFILES} and (p.vendor == "windows-firewall" or z.lower() in mapped)}  # fmt: skip
        self.written: List[_Written] = []
        self.comments: List[str] = []
        self.deferred: Dict[Key, List[_Piece]] = {}
        self.allows_above: Dict[Key, List[_Piece]] = {}
        self.outbound_deferred: Set[str] = set()
        prefix = options.object_prefix or "FWShift"
        self.group = names.clean(prefix, names.WINFW_TEXT)
        self.name_prefix = names.clean(prefix, names.WINFW)
        self.taken: Set[str] = set()

    # -- zones ------------------------------------------------------------------------------------

    def _role(self, zone: str) -> Tuple[str, str]:
        """("any" | "host" | "profile" | "zone", the canonical name)."""
        if zone == ANY:
            return "any", ANY
        if zone in self.special:
            if zone.lower() == HOST.lower():
                return "host", HOST
            return "profile", next(name for name in PROFILES if name.lower() == zone.lower())
        return "zone", zone

    def _confine(self, rule: Rule, side: str, zone: str, found: List[Interval], reasons: List[transform.Reason]) -> List[Interval]:
        """The addresses of one side, kept to the networks of a zone (as the AWS emitter does)."""
        if rule.action == Action.ALLOW:
            if zone not in self.spaces:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {zone}, and a rule of Windows Firewall names no zone: give the "
                                f"networks behind {zone} with --zone-network (or --zone-map it to Host or a profile)"))  # fmt: skip
                return found
            kept = intersect(found, normalize(self.spaces[zone]))
            if kept != found:
                self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} in zone {zone} is written as the addresses of the networks given for it with "
                                "--zone-network")  # fmt: skip
            return kept
        others = [z for z in self.universe if z != zone and z not in self.special]
        if not others or any(z not in self.spaces for z in others):
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {zone}; a rule of Windows Firewall names no zone, and "
                            "it blocks that traffic in every zone. Give the networks behind every zone with --zone-network to "
                            "keep it to its zones")  # fmt: skip
            return found
        kept = subtract(found, normalize([i for z in others for i in self.spaces[z]]))
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {zone} is written without the networks given for the other zones with "
                            "--zone-network")  # fmt: skip
        return kept

    # -- what a rule matches ----------------------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[_Side]:
        found: List[Interval] = []
        keywords: List[Keyword] = []
        for member in members:
            if member == ANY:
                found = [FULL_V4, FULL_V6]
                keywords = []
                break
            if member in self.keyword_groups:
                word = member.rstrip("46")
                family = member[len(word):]
                keywords += [(word, int(family))] if family else [(word, 4), (word, 6)]
                continue
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; a rule of Windows "
                                    "Firewall names addresses"))  # fmt: skip
                return None
            found += intervals
        if negated and keywords:
            reasons.append(("WINFW_KEYWORD", f"the {side} is a negated list that holds an address keyword, which Windows cannot negate"))
            return None
        found = normalize(found)
        if negated:
            found = subtract([FULL_V4, FULL_V6], found)
        return _Side(tuple(found), tuple(sorted(set(keywords))))

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[regions.Services]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        entries: List[ServiceEntry] = []
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.services != [ANY]:
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        found = regions.ALL_SERVICES if lowered is None and rule.services == [ANY] else regions.service_set(entries)
        if found is None:
            reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
            return None
        return regions.ALL_SERVICES.minus(found) if rule.negate_service else found

    def _pieces(self, rule: Rule, reasons: List[transform.Reason], quiet: bool = False) -> Optional[Dict[Key, List[_Piece]]]:
        allow = rule.action == Action.ALLOW
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with zone any: a rule of Windows Firewall names no zones"))
                return None
            if not quiet:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule with zone any: written for every pair of zones, which blocks more")  # fmt: skip
            pairs = [(rule.src_zones, rule.dst_zones)]
        services = self._services(rule, reasons)
        sources = self._resolve(rule.sources, rule.negate_source, "source", reasons)
        destinations = self._resolve(rule.destinations, rule.negate_destination, "destination", reasons)
        if services is None or sources is None or destinations is None:
            return None
        out: Dict[Key, List[_Piece]] = {}
        for src_zones, dst_zones in pairs:
            for s in src_zones:
                for d in dst_zones:
                    # Outbound: the host in s sends to d. Inbound: the host in d receives from s.
                    for direction, local_zone, remote_zone, local, remote in (("out", s, d, sources, destinations),
                                                                               ("in", d, s, destinations, sources)):  # fmt: skip
                        if not self._direction(rule, direction, local_zone, remote_zone, local, remote, services, reasons, out):
                            return None
        return out

    def _direction(self, rule: Rule, direction: str, local_zone: str, remote_zone: str, local: _Side, remote: _Side,
                   services: regions.Services, reasons: List[transform.Reason], out: Dict[Key, List[_Piece]]) -> bool:  # fmt: skip
        remote_role, remote_name = self._role(remote_zone)
        local_role, _ = self._role(local_zone)
        if remote_role == "host":
            return True  # (the host to itself)
        if local.keywords:
            reasons.append(("WINFW_KEYWORD", "an address keyword on the side of the host: Windows takes keywords for remote addresses only"))
            return False
        dst_side = "destination"
        implied = rule.egress_implied and rule.scope != RuleScope.INTRAZONE
        local_found = list(local.intervals)
        if local_role in ("zone", "profile") and not (implied and direction == "in"):
            local_found = self._confine(rule, dst_side if direction == "in" else "source", local_zone, local_found, reasons)
        remote_found = list(remote.intervals)
        if remote_role == "zone" and not (implied and direction == "out"):
            if remote.keywords:
                reasons.append(("WINFW_KEYWORD", f"an address keyword in zone {remote_zone}, which cannot be kept to the zone's networks"))
                return False
            remote_found = self._confine(rule, dst_side if direction == "out" else "source", remote_zone, remote_found, reasons)
        profiles = [remote_name] if remote_role == "profile" else list(PROFILES)
        for version in (4, 6):
            r, l = regions.addresses(remote_found, version), regions.addresses(local_found, version)
            words = tuple(sorted(word for word, v in remote.keywords if v == version))
            if (r or words) and l and not services.empty():
                piece = _Piece((version, r, l, services), words)
                for profile in profiles:
                    out.setdefault((direction, profile), []).append(piece)
        return True

    # -- what Windows can say ---------------------------------------------------------------------

    @staticmethod
    def _parts(box: regions.Box) -> Tuple[Optional[regions.Box], Optional[regions.Box]]:
        """The part of a box a rule of Windows Firewall can say, and the rest (every protocol but some, SCTP ports, more
        ICMP types and codes than are listed)."""
        version, remote, local, svc = box
        if svc.everything():
            return box, None
        own, foreign = (1, 58) if version == 4 else (58, 1)
        good: Dict[int, List[Tuple[int, int, int, int]]] = {}
        bad: Dict[int, List[Tuple[int, int, int, int]]] = {}
        for number, rects in svc.protocols.items():
            if number == foreign or not rects:
                bad[number] = []
                continue
            if number == 132 and any(rect != regions.WHOLE for rect in rects):
                bad[number], good[number] = list(rects), []
            elif number == own and _icmp_count(rects) > _MAX_ICMP:
                bad[number], good[number] = list(rects), []
            else:
                good[number], bad[number] = list(rects), []
        writable = regions.Services({n: r for n, r in good.items() if r}, False)
        rest = regions.Services(bad, svc.rest)
        return ((version, remote, local, writable) if not writable.empty() else None,
                (version, remote, local, rest) if not rest.empty() else None)  # fmt: skip

    @staticmethod
    def _specs(svc: regions.Services, version: int, inbound: bool) -> List[_Spec]:
        if svc.everything():
            return [_Spec("")]
        own = 1 if version == 4 else 58
        out: List[_Spec] = []
        for number in sorted(svc.protocols):
            rects = svc.protocols[number]
            if not rects:
                continue
            if number in (6, 17):
                label = "TCP" if number == 6 else "UDP"
                by_source: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
                for rect in rects:
                    by_source.setdefault((rect[0], rect[1]), []).append((rect[2], rect[3]))
                for (low, high), ranges in sorted(by_source.items()):
                    sources = () if (low, high) == (0, 65535) else (_port_text(low, high),)
                    merged = regions.merge_ranges(ranges)
                    dests = () if merged == [(0, 65535)] else tuple(_port_text(a, b) for a, b in merged)
                    out.append(_Spec(label, dests, sources) if inbound else _Spec(label, sources, dests))
            elif number == own:
                entries: List[str] = []
                every = False
                for rect in rects:
                    types, codes = regions.icmp_values(rect[0], rect[1]), regions.icmp_values(rect[2], rect[3])
                    if types == [None] and codes == [None]:
                        every = True
                        break
                    for kind in (list(range(256)) if types == [None] else types or []):
                        for code in codes or []:
                            entries.append(str(kind) if code is None else f"{kind}:{code}")
                label = "ICMPv4" if number == 1 else "ICMPv6"
                out.append(_Spec(label) if every else _Spec(label, icmp=tuple(dict.fromkeys(entries))))
            elif number in (1, 58):
                continue  # (the ICMP of the other IP version)
            else:
                out.append(_Spec(str(number)))
        return out

    # -- rules ------------------------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.comments.append(f"rule {rule.name}: {'disabled by the audit' if by_audit else 'disabled in the source'}, not written")
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": a rule of Windows Firewall names "
                            "addresses"))  # fmt: skip
        pieces = self._pieces(rule, reasons)
        if fqdn:
            reasons = [reason for reason in reasons if reason[0] != "ADDRESS_UNKNOWN"]
        reasons = list(dict.fromkeys(reasons))
        if reasons or pieces is None:
            self._disable(rule, reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")])
            return
        if not pieces:
            self.report.skip("rule", rule.origin, "WINFW_NOTHING_TO_WRITE",
                             "the rule matches no connection to or from the host (only the host to itself, or nothing after the "
                             "negation and the networks of its zones)", Severity.INFO)  # fmt: skip
            return
        if rule.action != Action.ALLOW and rule.action != Action.DROP:
            self.report.add("rule", rule.origin, Severity.INFO, "ACTION_DROP",
                            f"action {rule.action.value}: a block rule of Windows Firewall drops without an answer")  # fmt: skip
        if rule.action == Action.ALLOW:
            self._allow(rule, pieces)
        else:
            self._block(rule, pieces)

    def _disable(self, rule: Rule, reasons: List[transform.Reason]) -> None:
        transform.disable_rule(self.report, rule, reasons)
        scratch: List[transform.Reason] = []
        pieces = self._pieces(rule, scratch, quiet=True)
        if pieces:
            self.written.append(_Written(rule, rule.action == Action.ALLOW, False, pieces))
        else:
            self.comments.append(f"rule {rule.name}: not written, see the report")

    def _allow(self, rule: Rule, pieces: Dict[Key, List[_Piece]], synthetic: bool = False) -> None:
        out: Dict[Key, List[_Piece]] = {}
        cut = dropped = False
        for key, found in pieces.items():
            kept: List[_Piece] = []
            for piece in found:
                cuts = [d for d in self.deferred.get(key, []) if _meets(d, piece)]
                if cuts and (piece.keywords or any(d.keywords for d in cuts)) and not any(d.full() for d in cuts):
                    self._disable(rule, [("WINFW_KEYWORD_ORDER", "a block rule above it that is left to the default of the profile "
                                          "meets it, and one of the two names an address keyword: what is left cannot be worked out")])  # fmt: skip
                    return
                boxes = [piece.box]
                if cuts:
                    left = [] if any(d.full() for d in cuts) else regions.minus_all([piece.box], [d.box for d in cuts], _LIMIT)
                    if left is None:
                        self._disable(rule, [("WINFW_TOO_COMPLEX", "without what the block rules above it that are left to the "
                                              "default of the profile match, the rule falls apart into more pieces than are written")])  # fmt: skip
                        return
                    boxes, cut = left, True
                for box in boxes:
                    writable, rest = self._parts(box)
                    if rest is not None:
                        dropped = True
                    if writable is not None:
                        kept.append(_Piece(writable, piece.keywords))
            if kept:
                out[key] = kept
        for key, found in pieces.items():
            self.allows_above.setdefault(key, []).extend(found)
        if cut:
            self.report.add("rule", rule.origin, Severity.INFO, "WINFW_ALLOW_CUT",
                            "block rules above it are left to the default of the profile (they are not written): the rule is "
                            "written without what they match")  # fmt: skip
        if dropped:
            self.report.add("rule", rule.origin, Severity.REVIEW, "WINFW_PART_NOT_WRITTEN",
                            "part of what the rule allows cannot be said by a rule of Windows Firewall (every protocol but some, "
                            "ports of SCTP, more ICMP types and codes than are listed) and is not written; the converted rule "
                            "allows less")  # fmt: skip
        if not out:
            self.report.skip("rule", rule.origin, "SHADOWED_BY_DENY",
                             "everything the rule allows is blocked by the rules above it; there is nothing to write", Severity.INFO)  # fmt: skip
            return
        self.written.append(_Written(rule, True, True, out, synthetic))

    def _block(self, rule: Rule, pieces: Dict[Key, List[_Piece]]) -> None:
        out: Dict[Key, List[_Piece]] = {}
        deferred: Dict[Key, List[_Piece]] = {}
        cut = False
        for key, found in pieces.items():
            for piece in found:
                meeting = [a for a in self.allows_above.get(key, []) if _meets(a, piece)]
                if meeting and (piece.keywords or any(a.keywords for a in meeting)):
                    self._disable(rule, [("WINFW_KEYWORD_ORDER", "allow rules above it meet it, and one of them or the rule names "
                                          "an address keyword: what they leave of it cannot be worked out")])  # fmt: skip
                    return
                boxes = [piece.box]
                if meeting:
                    left = None if piece.full() else regions.minus_all([piece.box], [a.box for a in meeting], _LIMIT)
                    if left is None:
                        deferred.setdefault(key, []).append(piece)  # (a cleanup rule, or one that falls apart)
                        continue
                    boxes, cut = left, True
                for box in boxes:
                    writable, rest = self._parts(box)
                    if writable is not None:
                        out.setdefault(key, []).append(_Piece(writable, piece.keywords))
                    if rest is not None:
                        deferred.setdefault(key, []).append(_Piece(rest, piece.keywords))
        if any(p.keywords for found in deferred.values() for p in found):
            self._disable(rule, [("WINFW_KEYWORD_ORDER", "part of the rule cannot be written and names an address keyword, which "
                                  "the allow rules below it cannot be cut by")])  # fmt: skip
            return
        for key, found in deferred.items():
            self.deferred.setdefault(key, []).extend(found)
        if cut:
            self.report.add("rule", rule.origin, Severity.INFO, "WINFW_BLOCK_CUT",
                            "Windows decides block rules before allow rules: the rule is written without what the allow rules "
                            "above it match")  # fmt: skip
        if deferred:
            outbound = sorted({key[1] for key in deferred if key[0] == "out"})
            self.outbound_deferred.update(outbound)
            what = "all of it" if not out else "part of it (every protocol but some, ports of SCTP, many ICMP codes, or all "\
                "it blocks below allow rules)"  # fmt: skip
            message = (f"{what} is left to the default of the profile, which blocks it inbound; the allow rules below it are "
                       "written without it")  # fmt: skip
            if outbound:
                message += (". Outbound it is blocked only where the profile's default outbound action is Block ("
                            + ", ".join(outbound) + ")")  # fmt: skip
            self.report.add("rule", rule.origin, Severity.REVIEW if outbound else Severity.INFO, "WINFW_LEFT_TO_DEFAULT", message)
        if out:
            self.written.append(_Written(rule, False, True, out))
        elif not deferred:
            self.report.skip("rule", rule.origin, "WINFW_SHADOWED_BY_ALLOW",
                             "the allow rules above it allow everything it blocks; there is nothing to write", Severity.INFO)  # fmt: skip

    def _fqdn(self, members: List[str]) -> List[str]:
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

    def _defaults(self) -> None:
        """What no rule matches: allowed where the source allows it, as allow rules after the others (as the AWS emitter)."""
        keys = [(d, p) for d in ("in", "out") for p in PROFILES]
        inter = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.universe, self.report)
        zones = [z for z in self.universe if z not in self.special]
        same: List[regions.Box] = []
        missing: List[str] = []
        for zone in zones:
            if bool(decided.get(zone)) == inter:
                continue  # (inside it as between zones: nothing of its own to write)
            if zone not in self.spaces:
                missing.append(zone)
                continue
            for version in (4, 6):
                space = regions.addresses(self.spaces[zone], version)
                if space:
                    same.append((version, space, space, regions.ALL_SERVICES))
        boxes: Optional[List[regions.Box]] = same
        if inter:
            if missing:
                self.report.note(Severity.REVIEW, "WINFW_DEFAULT_NOT_WRITTEN",
                                 "the source allows what no rule matches between zones, and blocks it inside some zones; that needs "
                                 "the networks of those zones (--zone-network), and these have none: " + ", ".join(missing)
                                 + ". It is not written")  # fmt: skip
                return
            everything = [(v, [regions.full(v)], [regions.full(v)], regions.ALL_SERVICES) for v in (4, 6)]
            boxes = regions.minus_all(everything, same, limit=4096)
            self.report.note(Severity.REVIEW, "WINFW_DEFAULT_ALLOW",
                             "the source allows what no rule matches: written as allow rules for every connection, in both "
                             "directions, which the block rules beat")  # fmt: skip
        elif missing:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic inside them without a rule; without their networks (--zone-network) that is "
                             "not written: " + ", ".join(missing))  # fmt: skip
        if boxes is None:
            self.report.note(Severity.REVIEW, "WINFW_DEFAULT_NOT_WRITTEN",
                             "what the source allows by default falls apart into more pieces than are written; it is not written")  # fmt: skip
            return
        if boxes:
            name = "(default)"
            self._allow(Rule(name=name, origin=name), {key: [_Piece(box) for box in boxes] for key in keys}, True)
            self.report.discard("rule", name)

    # -- output -----------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: Windows Firewall does no NAT. The rules were written for the addresses the host sees, "
                             "after the translation")  # fmt: skip
        outbound = self._outbound_open()
        lines = self._commands()
        self._notes(outbound)
        return self._script(lines, outbound)

    def _outbound_open(self) -> List[str]:
        """The profiles in which some outbound connection is allowed by no rule written: the policy denies it, and Windows
        lets it through unless the profile's default outbound action is Block."""
        out: List[str] = []
        for profile in PROFILES:
            allowed = [piece.box for w in self.written if w.allow and w.enabled for piece in w.pieces.get(("out", profile), [])
                       if not piece.keywords]  # fmt: skip
            left = regions.minus_all([(v, [regions.full(v)], [regions.full(v)], regions.ALL_SERVICES) for v in (4, 6)], allowed, 4096)
            if left is None or left or profile in self.outbound_deferred:
                out.append(profile)
        return out

    def _rows(self, written: _Written, direction: str) -> List[Tuple[str, List[_Row]]]:
        """(the profiles, the rows of New-NetFirewallRule) of one rule for one direction."""
        by_profile: Dict[str, List[_Piece]] = {p: written.pieces.get((direction, p), []) for p in PROFILES}
        groups: Dict[Tuple[object, ...], List[str]] = {}
        for profile in PROFILES:
            found = by_profile[profile]
            if found:
                groups.setdefault(tuple(sorted(_piece_key(piece) for piece in found)), []).append(profile)
        out: List[Tuple[str, List[_Row]]] = []
        for profiles in groups.values():
            pieces = by_profile[profiles[0]]
            rows: List[_Row] = []
            for piece in pieces:
                version, remote, local, svc = piece.box
                for spec in self._specs(svc, version, direction == "in"):
                    rows.append(_Row(spec, {version}, list(remote), list(local), {(w, version) for w in piece.keywords}))
            label = "Any" if len(profiles) == len(PROFILES) else ",".join(profiles)
            out.append((label, _merge(rows)))
        return out

    def _commands(self) -> List[str]:
        lines: List[str] = []
        for written in self.written:
            rule = written.rule
            calls: List[str] = []
            for direction in ("in", "out"):
                for profiles, rows in self._rows(written, direction):
                    for row in rows:
                        calls.append(self._call(written, direction, profiles, row))
            total = len(calls)
            emitted: List[str] = []
            for number, call in enumerate(calls, 1):
                display = rule.name if total == 1 else f"{rule.name} ({number})"
                display = names.clean(display, names.WINFW_TEXT)
                if display.lower() == "all":
                    display = "All (rule)"
                name = names.unique(f"{self.name_prefix}-{rule.name}" + ("" if total == 1 else f"-{number}"), self.taken, names.WINFW)
                emitted.append(name)
                lines.append(call.replace("@NAME@", _ps(name)).replace("@DISPLAY@", _ps(display)))
            if not written.synthetic:
                self.report.item("rule", rule.origin).emitted_as.extend(emitted)
        return lines

    def _call(self, written: _Written, direction: str, profiles: str, row: _Row) -> str:
        parts = ["Name = @NAME@", "DisplayName = @DISPLAY@"]
        description = f"FWShift: {written.rule.name}"
        if written.rule.description:
            description += f": {written.rule.description}"
        parts.append(f"Description = {_ps(description[:1000])}")
        parts.append(f"Direction = '{'Inbound' if direction == 'in' else 'Outbound'}'")
        parts.append(f"Action = '{'Allow' if written.allow else 'Block'}'")
        parts.append(f"Enabled = '{'True' if written.enabled else 'False'}'")
        parts.append(f"Profile = '{profiles}'")
        spec = row.spec
        if spec.protocol:
            parts.append(f"Protocol = '{spec.protocol}'")
        if spec.local_ports:
            parts.append("LocalPort = " + _array(spec.local_ports))
        if spec.remote_ports:
            parts.append("RemotePort = " + _array(spec.remote_ports))
        if spec.icmp:
            parts.append("IcmpType = " + _array(spec.icmp))
        family_bound = spec.protocol in ("ICMPv4", "ICMPv6")
        remote_any = not row.keywords and _whole(row.remote, row.versions)
        local_any = _whole(row.local, row.versions)
        if len(row.versions) == 1 and remote_any and local_any and not family_bound:
            local_any = False  # (one IP version: one side says which)
        if not local_any:
            parts.append("LocalAddress = " + _array(_addresses(row.local, row.versions)))
        if not remote_any:
            listed = _addresses(row.remote, row.versions) if row.remote else []
            parts.append("RemoteAddress = " + _array(listed + _keyword_texts(row.keywords)))
        return "Add-Rule @{ " + "; ".join(parts) + " }"

    def _script(self, lines: List[str], outbound: List[str]) -> str:
        out = [
            "# Generated by FWShift: Windows Defender Firewall rules for one host, created with New-NetFirewallRule. Read the",
            "# report first: what is not written is listed there.",
            "#",
            "#   powershell -ExecutionPolicy Bypass -File THIS_FILE -DryRun   shows what it would create (-WhatIf), creates nothing",
            "#   powershell -ExecutionPolicy Bypass -File THIS_FILE           creates the rules (as administrator)",
            "#",
            "# -PolicyStore names another store than the local one (PersistentStore), such as a GPO: -PolicyStore 'example.com\\GPO'.",
            f"# Every rule is created in the rule group {self.group}; nothing is deleted and no profile setting is changed. A rule of",
            "# that group, or of one of its names, stops the script before anything is created; a call Windows refuses stops it",
            f"# where it is. To take the rules away again: Remove-NetFirewallRule -Group {_ps(self.group)}",
            "#",
            "# Windows evaluates these rules together with every other rule of the host: a block rule beats an allow rule, and",
            "# what no rule matches gets the profile's default. Block rules are written without what the allow rules above them",
            "# allowed in the source; see the report.",
            "[CmdletBinding()]",
            "param([switch]$DryRun, [string]$PolicyStore = 'PersistentStore')",
            "Set-StrictMode -Version 2.0",
            "$ErrorActionPreference = 'Stop'",
            f"$Group = {_ps(self.group)}",
            f"$NamePrefix = {_ps(self.name_prefix + '-')}",
            "# The profiles in which the policy denies outbound connections no rule allows: their default must be Block.",
            "$OutboundBlock = @(" + ", ".join(_ps(p) for p in outbound) + ")",
            "$Created = 0",
            "function Add-Rule([hashtable]$Rule) {",
            "    if ($DryRun) { New-NetFirewallRule @Rule -Group $Group -PolicyStore $PolicyStore -WhatIf; return }",
            "    $null = New-NetFirewallRule @Rule -Group $Group -PolicyStore $PolicyStore",
            "    $script:Created++",
            "}",
            "if (-not $DryRun) {",
            "    $taken = @(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction SilentlyContinue |",
            "        Where-Object { $_.Group -eq $Group -or $_.Name -like ($NamePrefix + '*') })",
            "    if ($taken.Count -gt 0) {",
            "        throw ('rules of the group ' + $Group + ' or named ' + $NamePrefix + '... exist in ' + $PolicyStore + ' already (' +",
            "            $taken[0].Name + '); nothing was created')",
            "    }",
            "}",
            "foreach ($fwProfile in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {",
            "    $name = [string]$fwProfile.Name",
            "    if ([string]$fwProfile.Enabled -eq 'False') { Write-Warning ('the firewall is off in the profile ' + $name + ': no rule applies there') }",
            "    if ([string]$fwProfile.DefaultInboundAction -eq 'Allow') {",
            "        Write-Warning ('the profile ' + $name + ' allows inbound connections no rule blocks; this policy needs Block ' +",
            "            '(Set-NetFirewallProfile -Name ' + $name + ' -DefaultInboundAction Block)')",
            "    }",
            "    if ($OutboundBlock -contains $name -and [string]$fwProfile.DefaultOutboundAction -ne 'Block') {",
            "        Write-Warning ('the profile ' + $name + ' allows outbound connections that this policy denies; to deny them ' +",
            "            'set Set-NetFirewallProfile -Name ' + $name + ' -DefaultOutboundAction Block')",
            "    }",
            "}",
            "",
        ]
        out += lines
        if self.comments:
            out += ["", "# Not written:"] + [f"#   {_comment(line)}" for line in self.comments]
        out += ["", "if (-not $DryRun) { Write-Host ('Done: ' + $Created + ' rules created in the group ' + $Group) }"]
        return "\n".join(out) + "\n"

    def _notes(self, outbound: List[str]) -> None:
        self.report.note(
            Severity.REVIEW, "WINFW_LOAD",
            f"the output is a PowerShell script of New-NetFirewallRule calls (section 10): -DryRun shows what it would create, "
            f"without it it creates the rules, as administrator, in the rule group {self.group}. It deletes nothing, changes no "
            "profile setting, and stops before it creates anything when a rule of that group exists",
        )  # fmt: skip
        self.report.note(
            Severity.REVIEW, "WINFW_HOST_RULES",
            "Windows evaluates the rules written here together with every other rule of the host: a block rule of the host "
            "beats an allow rule written here, and an allow rule of the host lets through what the policy only denies by default. "
            "Check the host's own rules (Get-NetFirewallRule -PolicyStore ActiveStore) before it goes live",
        )  # fmt: skip
        if outbound:
            self.report.note(
                Severity.REVIEW, "WINFW_DEFAULT_OUTBOUND",
                "the policy denies outbound connections that no rule allows, and Windows allows them unless the profile's default "
                "outbound action is Block. The script changes no profile: set it where the policy needs it (Set-NetFirewallProfile "
                "-Name NAME -DefaultOutboundAction Block), which also blocks what the host's own rules do not allow: "
                + ", ".join(outbound),
            )  # fmt: skip
        self.report.note(
            Severity.INFO, "WINFW_DEFAULT_INBOUND",
            "inbound connections that no rule allows are left to the default of the profile, Block, as Windows has it unless "
            "changed; the script warns when a profile allows them",
        )  # fmt: skip
        hosts = sorted(self.special)
        if hosts:
            self.report.note(Severity.INFO, "WINFW_ZONES",
                             "read as the host and as profiles: " + ", ".join(hosts) + "; every other zone is the networks given "
                             "for it (--zone-network)")  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; a rule of Windows Firewall does not. Logging of dropped and allowed "
                             "connections is a setting of each profile (Set-NetFirewallProfile -LogBlocked True)")  # fmt: skip


def _port_text(low: int, high: int) -> str:
    return str(low) if low == high else f"{low}-{high}"


def _icmp_count(rects: Sequence[Tuple[int, int, int, int]]) -> int:
    total = 0
    for rect in rects:
        types, codes = regions.icmp_values(rect[0], rect[1]), regions.icmp_values(rect[2], rect[3])
        if types == [None] and codes == [None]:
            continue
        total += (256 if types == [None] else len(types or [])) * (1 if codes == [None] else len(codes or []))
    return total


def _piece_key(piece: _Piece) -> Tuple[object, ...]:
    version, remote, local, svc = piece.box
    services = (tuple(sorted((n, tuple(sorted(r))) for n, r in svc.protocols.items())), svc.rest)
    return (version, tuple(remote), tuple(local), services, piece.keywords)


def _merge(rows: List[_Row]) -> List[_Row]:
    """Rows with the same services: the same local addresses join their remote ones, the same remote ones their local ones,
    and a row of each IP version joins into one (a connection has one IP version, so nothing is matched that was not)."""
    out: List[_Row] = []
    for row in rows:
        for other in out:
            if other.spec == row.spec and other.versions == row.versions:
                if other.local == row.local:
                    other.remote = normalize(other.remote + row.remote)
                    other.keywords |= row.keywords
                    break
                if other.remote == row.remote and other.keywords == row.keywords:
                    other.local = normalize(other.local + row.local)
                    break
        else:
            out.append(row)
    joined: List[_Row] = []
    for row in out:
        for other in joined:
            if other.spec == row.spec and not (other.versions & row.versions):
                other.versions |= row.versions
                other.remote = normalize(other.remote + row.remote)
                other.local = normalize(other.local + row.local)
                other.keywords |= row.keywords
                break
        else:
            joined.append(row)
    return joined


def _whole(intervals: List[Interval], versions: Set[int]) -> bool:
    return normalize(intervals) == normalize([regions.full(v) for v in sorted(versions)])


def _addresses(intervals: List[Interval], versions: Set[int]) -> List[str]:
    out: List[str] = []
    for interval in normalize(intervals):
        if interval == regions.full(interval[0]):
            out.append(range_text(interval))  # (all of one IP version, as a range)
        else:
            out.append(interval_text(interval))
    return out


def _keyword_texts(keywords: Set[Keyword]) -> List[str]:
    out: List[str] = []
    for word in sorted({w for w, _ in keywords}):
        versions = {v for w, v in keywords if w == word}
        out.append(word if versions == {4, 6} else f"{word}{next(iter(versions))}")
    return out


def _array(values: Sequence[str]) -> str:
    return "@(" + ", ".join(_ps(v) for v in values) + ")"


def _comment(text: str) -> str:
    return "".join(" " if ord(c) < 32 or ord(c) == 127 or c in "\x85  " else c for c in text)
