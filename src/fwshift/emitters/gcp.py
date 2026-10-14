# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Google Cloud emitter: neutral model -> a shell script of gcloud commands that creates a network firewall policy.

Design rules:

* One new global network firewall policy, associated with nothing: creating it changes no traffic. Its rules are the
  rules of the model in their order, at priorities from 1000 in steps of 10, and end in the model's default for
  everything; nothing reaches the predefined goto_next rules.
* A rule of a network firewall policy is checked where a connection leaves an instance (egress) and where it arrives
  (ingress). Each rule of the model is written both ways, with the same sources and destinations: a connection between
  two instances then passes the model's verdict twice, one from or to outside once.
* A rule holds addresses of one IP version: a rule of the model becomes a rule per IP version and direction. Zones
  become the networks behind them (``--zone-network``), as for NSX; negation becomes the addresses that are left.
* What a rule cannot say: Google Cloud does not filter ICMP types or source ports. An allow rule leaves such a part
  out; a blocking rule blocks more (all of ICMP, every source port). A rule that cannot be written is not written,
  and listed in the script and the report.
* NAT is not written (an external address of an instance is a static NAT that Google Cloud does): the rules are for
  the internal addresses, which is what the firewall sees.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .. import regions, transform
from ..model import ANY, Action, AddressKind, Policy, RuleScope, Rule
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_MAX_RANGES = 5000  # addresses of one side of a rule
_FIRST, _STEP = 1000, 10


@dataclass
class Planned:
    """A rule of the network firewall policy."""

    priority: int
    direction: str  # INGRESS, EGRESS
    action: str  # allow, deny
    sources: List[str]
    destinations: List[str]
    layer4: List[Tuple[str, List[str]]]  # (protocol, ports)
    disabled: bool = False
    log: bool = False
    description: str = ""
    origin: str = ""


@dataclass
class Plan:
    rules: List[Planned] = field(default_factory=list)
    not_written: List[str] = field(default_factory=list)


def plan(policy: Policy, report: Report, options: Options) -> Plan:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    zone_spaces(options.zone_networks)
    # The firewall sees the internal address of an instance: the rules are for what NAT translates to.
    translated = {nat.origin for nat in p.nat_rules
                  if nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return _Planner(p, report, options).run()


def emit(policy: Policy, report: Report, options: Options) -> str:
    found = plan(policy, report, options)
    _notes(report, options)
    return _script(found, options)


class _Planner:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.spaces = zone_spaces(options.zone_networks)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used + list(options.zone_networks))
        self.out = Plan()
        self.priority = _FIRST

    # -- sides ---------------------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[Dict[int, List[Interval]]]:
        found: Dict[int, List[Interval]] = {4: [], 6: []}
        for member in members:
            if member == ANY:
                found = {4: [FULL_V4], 6: [FULL_V6]}
                break
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: the rules are written with addresses"))
                return None
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"the {side} '{member}' holds members only its platform knows; a rule of Google Cloud "
                                "names addresses"))  # fmt: skip
                return None
            for interval in intervals:
                found[interval[0]].append(interval)
        found = {v: normalize(ivs) for v, ivs in found.items()}
        if negated:
            found = {4: subtract([FULL_V4], found[4]), 6: subtract([FULL_V6], found[6])}
        return found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: Dict[int, List[Interval]],
                 reasons: List[transform.Reason]) -> Dict[int, List[Interval]]:  # fmt: skip
        if ANY in zones:
            return found
        allow = rule.action == Action.ALLOW
        missing = [zone for zone in zones if zone not in self.spaces]
        if allow:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING", f"the {side} of the rule is in zone {', '.join(zones)}, and a rule of Google "
                                f"Cloud names no zone: give the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return found
            space = normalize([i for zone in zones for i in self.spaces[zone]])
            return {v: intersect(ivs, space) for v, ivs in found.items()}
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others):
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a rule of Google Cloud names no "
                            "zone, and it blocks that traffic in every zone. Give the networks behind every zone with "
                            "--zone-network to keep it to its zones")  # fmt: skip
            return found
        away = normalize([i for zone in others for i in self.spaces[zone]])
        return {v: subtract(ivs, away) for v, ivs in found.items()}

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Dict[int, List[Interval]]]:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        zones = rule.src_zones if source else rule.dst_zones
        side = "source" if source else "destination"
        found = self._resolve(members, negated, side, reasons)
        if found is None:
            return None
        return self._confine(rule, side, zones, found, reasons)

    # -- services --------------------------------------------------------------------

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[regions.Services]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            svc = regions.service_set(entries) if entries else None
        elif rule.services == [ANY]:
            svc = regions.ALL_SERVICES
        else:
            entries = []
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
            svc = regions.service_set(entries)
        if svc is None:
            reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
            return None
        return regions.ALL_SERVICES.minus(svc) if rule.negate_service else svc

    def _layer4(self, rule: Rule, svc: regions.Services, version: int) -> List[Tuple[str, List[str]]]:
        """The protocols and ports of one IP version. An allow rule leaves out what cannot be said; a blocking rule blocks
        more."""
        allow = rule.action == Action.ALLOW
        if svc.everything():
            return [("all", [])]
        out: List[Tuple[str, List[str]]] = []
        left_out, widened = False, False
        for number in sorted(n for n in svc.protocols if svc.of(n)):
            rects = svc.of(number)
            if number in (6, 17, 132):
                if any((r[0], r[1]) != (0, 65535) for r in rects):
                    if allow:
                        rects = [r for r in rects if (r[0], r[1]) == (0, 65535)]
                        left_out = True
                    else:
                        widened = True
                if not rects:
                    continue
                ports = regions.merge_ranges([(r[2], r[3]) for r in rects])
                label = {6: "tcp", 17: "udp", 132: "sctp"}[number]
                out.append((label, [] if ports == [(0, 65535)] else [str(a) if a == b else f"{a}-{b}" for a, b in ports]))
            elif number in (1, 58):
                if (number == 1) != (version == 4):
                    continue  # (the ICMP of the other IP version meets no packet of this one)
                if any(regions.icmp_values(r[0], r[1]) != [None] or regions.icmp_values(r[2], r[3]) != [None] for r in rects):
                    if allow:
                        left_out = True
                        continue
                    widened = True
                out.append(("icmp" if number == 1 else "58", []))
            else:
                out.append((str(number), []))
        if svc.rest:
            if allow:
                left_out = True  # (every other protocol, but not all of them: Google Cloud names protocols one by one)
            else:
                widened = True
                out = [("all", [])]
        if left_out:
            self.report.add("rule", rule.origin, Severity.APPROX, "GCP_PART_NOT_WRITTEN",
                            "part of what the rule allows cannot be said by a rule of Google Cloud (ICMP types, source ports, "
                            "every protocol but some) and is not written: the converted rule allows less")  # fmt: skip
        if widened:
            self.report.add("rule", rule.origin, Severity.APPROX, "GCP_BLOCKS_MORE",
                            "the rule blocks certain ICMP types, source ports or protocols; a rule of Google Cloud blocks all of "
                            "ICMP, every source port or every protocol there, which blocks more")  # fmt: skip
        return out

    # -- rules ------------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a rule of Google Cloud names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written as a rule for every pair of its zones, which blocks more")  # fmt: skip
        svc = self._services(rule, reasons)
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        reasons = list(dict.fromkeys(reasons))
        if reasons or svc is None or sources is None or destinations is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.out.not_written.append(f"{rule.name}: " + "; ".join(message for _, message in reasons)[:300])
            return
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY",
                            f"action {rule.action.value}: a rule of Google Cloud denies without an answer")  # fmt: skip
        written = 0
        cidrs = {v: (_cidrs(sources[v]), _cidrs(destinations[v])) for v in (4, 6) if sources[v] and destinations[v]}
        if any(len(a) > _MAX_RANGES or len(b) > _MAX_RANGES for a, b in cidrs.values()):  # (before any of it is written)
            transform.disable_rule(self.report, rule, [("LIST_TOO_LONG", f"more than {_MAX_RANGES} address ranges on one side")])
            self.out.not_written.append(f"{rule.name}: more than {_MAX_RANGES} address ranges on one side")
            return
        for version, (src_cidrs, dst_cidrs) in cidrs.items():
            layer4 = self._layer4(rule, svc, version)
            if not layer4:
                continue
            for direction in ("INGRESS", "EGRESS"):
                self.out.rules.append(Planned(self.priority, direction, "allow" if allow else "deny", src_cidrs, dst_cidrs, layer4,
                                              disabled=not rule.enabled, log=bool(rule.log_start or rule.log_end),
                                              description=rule.name, origin=rule.origin))  # fmt: skip
                self.priority += _STEP
                written += 1
        if written:
            item.emitted_as.append(f"{written} rules of the policy")
        elif any(f.code == "GCP_PART_NOT_WRITTEN" for f in item.findings):
            self.report.skip("rule", rule.origin, "GCP_NOT_WRITTEN",
                             "nothing of what the rule allows can be said by a rule of Google Cloud (ICMP types, source ports, every "
                             "protocol but some): not written")  # fmt: skip
            self.out.not_written.append(f"{rule.name}: what it allows cannot be said by a rule of Google Cloud")
        else:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation, the networks of its zones and the protocols of each IP version, the rule matches "
                             "no connection here", Severity.INFO)  # fmt: skip

    def run(self) -> Plan:
        for rule in self.p.rules:
            self._rule(rule)
        action = "allow" if self.p.default_interzone == Action.ALLOW else "deny"
        for version, everything in ((4, "0.0.0.0/0"), (6, "::/0")):
            for direction in ("INGRESS", "EGRESS"):
                self.out.rules.append(Planned(self.priority, direction, action, [everything], [everything], [("all", [])],
                                              description=f"fwshift-default-{action}", origin=""))  # fmt: skip
                self.priority += _STEP
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: an external address of an instance, Cloud NAT and the load balancers translate, outside "
                             "the firewall. The rules were written for the internal addresses, which is what the firewall sees")  # fmt: skip
        if self.p.default_intrazone != self.p.default_interzone:
            self.report.note(Severity.REVIEW, "INTRAZONE_DEFAULT",
                             "the source treats traffic inside a zone and between zones differently when no rule matches; a "
                             "network firewall policy has no zones, and the default of traffic between zones was written")  # fmt: skip
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                             "written for that: " + ", ".join(open_zones))  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules have logging enabled")
        return self.out


def _cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in intervals:
        out += [str(n) for n in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
    return out


def policy_name(options: Options) -> str:
    name = (options.object_prefix or "") + (options.target_policy if options.target_policy and options.target_policy != "FWShift" else "fwshift")
    name = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    if not name or not name[0].isalpha():
        name = "fwshift-" + name
    return name[:63].rstrip("-") or "fwshift"


def _notes(report: Report, options: Options) -> None:
    report.note(
        Severity.REVIEW, "GCP_LOAD",
        "the output is a shell script of gcloud commands (section 10): DRY_RUN=1 prints them, without it it creates a new global "
        f"network firewall policy ({policy_name(options)}) with its rules, and stops if a policy of that name exists. It is "
        "associated with no network: nothing changes until you associate it",
    )  # fmt: skip
    report.note(
        Severity.REVIEW, "GCP_ORDER",
        "the policy decides every connection of the network it is associated with: it ends in the default of the source. With "
        "the network's enforcement order AFTER_CLASSIC_FIREWALL (the default) the VPC firewall rules of the network decide "
        "first; set it to BEFORE_CLASSIC_FIREWALL (gcloud compute networks update NETWORK "
        "--network-firewall-policy-enforcement-order=BEFORE_CLASSIC_FIREWALL), or remove the VPC firewall rules",
    )  # fmt: skip


def _script(found: Plan, options: Options) -> str:
    name = policy_name(options)
    out = [
        "#!/bin/sh",
        "# Generated by FWShift: a Google Cloud network firewall policy, created with gcloud. Read the report first: what is",
        "# not written is listed there.",
        "#",
        "#   DRY_RUN=1 sh THIS_FILE                              prints the commands; needs no access to Google Cloud",
        "#   GCLOUD_OPTS='--project my-project' sh THIS_FILE     creates the policy and its rules",
        "#",
        "# The policy is associated with no network: nothing changes for any traffic until you associate it:",
        f"#   gcloud compute network-firewall-policies associations create --firewall-policy {name} --network NETWORK --global-firewall-policy",
        "# It decides every connection of that network. Set the network's enforcement order to BEFORE_CLASSIC_FIREWALL, or",
        "# the VPC firewall rules of the network decide first. A policy of the same name stops the script before anything is",
        "# created; a command gcloud refuses stops it where it is (delete the policy and run it again).",
        "set -u",
        'DRY_RUN="${DRY_RUN:-}"',
        'GCLOUD_OPTS="${GCLOUD_OPTS:-}"',
        f"POLICY={shlex.quote(name)}",
        "fail() { printf 'FAILED: %s\\n' \"$*\" >&2; exit 1; }",
        "run() {",
        '  if [ -n "$DRY_RUN" ]; then printf \'gcloud\' >&2; printf \' %s\' "$@" >&2; printf \'\\n\' >&2; return 0; fi',
        '  gcloud "$@" $GCLOUD_OPTS --quiet >/dev/null || fail "gcloud $1 $2 $3 $4"',
        "}",
        'if [ -z "$DRY_RUN" ] && gcloud compute network-firewall-policies describe "$POLICY" --global $GCLOUD_OPTS >/dev/null 2>&1; then',
        '  fail "a network firewall policy named $POLICY exists already; nothing was created"',
        "fi",
        "",
        'run compute network-firewall-policies create "$POLICY" --global '
        + shlex.quote("--description=Generated by FWShift; review the conversion report before associating it"),
        "",
    ]
    for rule in found.rules:
        layer4 = ",".join(f"{protocol}:{port}" if ports else protocol for protocol, ports in rule.layer4 for port in (ports or [""]))
        args = ['--firewall-policy="$POLICY"', "--global-firewall-policy", f"--direction={rule.direction}", f"--action={rule.action}",
                "--src-ip-ranges=" + ",".join(rule.sources), "--dest-ip-ranges=" + ",".join(rule.destinations),
                f"--layer4-configs={layer4}"]  # fmt: skip
        if rule.disabled:
            args.append("--disabled")
        if rule.log:
            args.append("--enable-logging")
        description = _description(rule.description)
        if description:
            args.append(shlex.quote(f"--description={description}"))
        out.append(f"run compute network-firewall-policies rules create {rule.priority} " + " ".join(args))
    if found.not_written:
        out += ["", "# Not written:"] + ["#   " + _comment(line) for line in found.not_written]
    out += ["", "echo 'Done. Associate the policy with the network when you are ready; until then nothing changes.' >&2"]
    return "\n".join(out) + "\n"


def _description(text: str) -> str:
    return "".join(c if c.isprintable() else " " for c in text)[:1000]


def _comment(text: str) -> str:
    return "".join(c if c.isprintable() else " " for c in text)
