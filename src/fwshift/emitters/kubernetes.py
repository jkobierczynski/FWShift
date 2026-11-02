# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Kubernetes NetworkPolicy emitter: neutral model -> a ``List`` of NetworkPolicies of networking.k8s.io/v1, as JSON.

Design rules:

* A NetworkPolicy only allows, and the policies of a pod are one union without order: what the AWS target does for
  security groups holds here. A rule of the model that allows is written as what it matches without what the blocking
  rules above it match (:mod:`fwshift.regions`); what remains of its sources and destinations is written as
  ``ipBlock`` with ``except`` where that is shorter than a list of blocks.
* An ingress rule names the sources and the ports; the destination is the pods the policy selects. An egress rule
  names the destinations. Every piece is written on both sides, as an ingress rule of the policy of its destinations
  and an egress rule of the policy of its sources: a connection between pods passes both, each lets through only what
  the model allows between the two, which is exact.
* The pods are cut by address as the AWS target cuts interfaces: every address lies in exactly one group, and a
  group is a policy that selects the pods labelled ``fwshift/group=<name>``. The policy names the addresses its pods
  are for (an annotation and the report); labelling the pods is left to a person, so that applying the file changes
  no traffic. Every policy has both types, so a labelled pod is isolated both ways.
* NetworkPolicy matches TCP, UDP and SCTP ports, or every protocol: ICMP and other protocols on their own, and source
  ports, cannot be written (an allow rule that needs them is written without that part, or not at all, and said).
* No namespace is written: ``kubectl apply -n NAMESPACE -f FILE`` puts the policies in the namespace of the pods. Zones
  become the networks behind them (``--zone-network``), as for NSX and AWS. NAT is not written.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import names, regions, transform
from ..errors import FwshiftError
from ..model import ANY, Action, Policy, Rule, RuleScope, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, interval_text, normalize, subtract
from ..options import Options
from ..report import Report, Severity
from . import aws as _aws

LABEL = "fwshift/group"
_FULL = {4: FULL_V4, 6: FULL_V6}
_NAMES = {"tcp": "TCP", "udp": "UDP", "sctp": "SCTP"}


def emit(policy: Policy, report: Report, options: Options) -> str:
    return _Emitter(_aws.prepare(policy, report, options), report, options, transform.rule_zones(policy)).run()


def _cidr_list(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in normalize(intervals):
        out += [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]
    return out


def ip_blocks(intervals: List[Interval]) -> List[Dict[str, Any]]:
    """Peers for a set of addresses: one ipBlock per CIDR, or a CIDR with exceptions where that is shorter."""
    out: List[Dict[str, Any]] = []
    for version in (4, 6):
        mine = normalize([i for i in intervals if i[0] == version])
        if not mine:
            continue
        plain = _cidr_list(mine)
        first, last = int_to_ip(version, mine[0][1]), int_to_ip(version, mine[-1][2])
        cover = ipaddress.ip_network(f"{first}/{first.max_prefixlen}")
        while last not in cover:
            cover = cover.supernet()
        hull = (version, int(cover.network_address), int(cover.broadcast_address))
        holes = _cidr_list(subtract([hull], mine))
        if holes and len(holes) + 1 < len(plain):
            out.append({"ipBlock": {"cidr": str(cover), "except": holes}})
        else:
            out += [{"ipBlock": {"cidr": cidr}} for cidr in plain]
    return out


class _Emitter(_aws._Emitter):
    """The AWS emitter's cutting of rules and addresses, with NetworkPolicy's words and limits."""

    def _inside(self) -> Optional[List[Interval]]:
        """The addresses of the pods, every one of which gets a group: the networks of --inside-zone, and for a Kubernetes or
        Calico source the pods it was read from. None when not known: then every address gets a group."""
        found: List[Interval] = []
        for zone in self.options.inside_zones:
            if zone not in self.spaces:
                raise FwshiftError(f"--inside-zone {zone}: give the networks behind it with --zone-network")
            found += self.spaces[zone]
        pods = [name for name, group in self.p.address_groups.items() if group.builtin == "kubernetes" and not group.unsupported]
        for name in pods:
            found += transform.known_intervals(self.p, name)[0]
        return normalize(found) if self.options.inside_zones or pods else None

    # -- what a rule matches --------------------------------------------------------

    def _resolve(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found = [FULL_V4, FULL_V6]
                break
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ADDRESS_UNKNOWN", f"the addresses of the {side} '{member}' are not known; a NetworkPolicy "
                                    "written by FWShift names addresses"))  # fmt: skip
                return None
            found += intervals
        found = normalize(found)
        return subtract([FULL_V4, FULL_V6], found) if negated else found

    def _confine(self, rule: Rule, side: str, zones: List[str], found: List[Interval], reasons: List[transform.Reason]) -> List[Interval]:
        if rule.action == Action.ALLOW:
            missing = [zone for zone in zones if zone not in self.spaces]
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the {side} of the rule is in zone {', '.join(zones)}, and a NetworkPolicy names no zone: give "
                                f"the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return found
            kept = intersect(found, normalize([i for zone in zones for i in self.spaces[zone]]))
            if kept != found:
                self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the {side} in zone {', '.join(zones)} is written as the addresses of the networks given for it "
                                "with --zone-network")  # fmt: skip
            return kept
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others):
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; a NetworkPolicy names no zone, "
                            "and it blocks that traffic in every zone. Give the networks behind every zone with --zone-network "
                            "to keep it to its zones")  # fmt: skip
            return found
        kept = subtract(found, normalize([i for zone in others for i in self.spaces[zone]]))
        if kept != found:
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the {side} in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
        return kept

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
        if any(e.src_ports for e in entries):
            if rule.action == Action.ALLOW:
                reasons.append(("SOURCE_PORTS", "source ports: a NetworkPolicy matches destination ports only"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "SOURCE_PORTS_WIDENED",
                                "the rule blocks certain source ports only; it is written for every source port, which blocks more")  # fmt: skip
                entries = [e for e in entries if not e.src_ports] if rule.negate_service else [_aws._without_source_ports(e) for e in entries]
        found = regions.ALL_SERVICES if lowered is None and rule.services == [ANY] else regions.service_set(entries)
        if found is None:
            reasons.append(("SERVICE_UNKNOWN", "a service of the rule cannot be read"))
            return None
        if rule.negate_service:
            found = regions.ALL_SERVICES.minus(found)
        return found

    # -- rules ----------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.comments.append(f"{rule.name} ({'disabled by the audit' if by_audit else 'disabled in the source'})")
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        allow = rule.action == Action.ALLOW
        if rule.scope != RuleScope.UNIVERSAL:
            if allow:
                reasons.append(("RULE_TYPE", f"{rule.scope.value} rule: a NetworkPolicy names no zones"))
            else:
                self.report.add("rule", rule.origin, Severity.APPROX, "RULE_TYPE",
                                f"{rule.scope.value} rule: written for every pair of its zones, which blocks more")  # fmt: skip
        fqdn = self._fqdn(rule.sources + rule.destinations)
        if fqdn:
            reasons.append(("FQDN_NOT_SUPPORTED", "host name object " + ", ".join(fqdn) + ": a NetworkPolicy names addresses"))
        boxes = self._region(rule, reasons)
        if fqdn:
            reasons = [reason for reason in reasons if reason[0] != "ADDRESS_UNKNOWN"]
        reasons = list(dict.fromkeys(reasons))
        if reasons or boxes is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "what the rule matches cannot be read")])
            self.comments.append(f"{rule.name} (not written, see the report)")
            return
        if not boxes:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                             "after the negation and the networks of its zones, the rule matches no connection", Severity.INFO)  # fmt: skip
            return
        if not allow:
            self.denies += boxes
            item.emitted_as.append("taken out of the rules below it")
            return
        self._allow(boxes, rule.origin, rule.name)

    def _allow(self, boxes: List[regions.Box], origin: str, name: str) -> None:
        left = regions.minus_all(boxes, self.denies)
        if left is None:
            self.report.disable("rule", origin, "K8S_TOO_COMPLEX",
                                "what the rule allows without what the blocking rules above it block falls apart into more pieces "
                                "than are written; the rule is not written")  # fmt: skip
            self.comments.append(f"{name} (not written, see the report)")
            return
        if not left:
            self.report.skip("rule", origin, "SHADOWED_BY_DENY",
                             "everything the rule allows is blocked by the rules above it; there is nothing to write", Severity.INFO)  # fmt: skip
            return
        if len(left) != len(boxes) or any(a != b for a, b in zip(left, boxes)):
            self.report.add("rule", origin, Severity.INFO, "DENY_SUBTRACTED",
                            "a NetworkPolicy cannot block: the rule is written without what the blocking rules above it match")  # fmt: skip
        for box in left:
            perms, dropped = self._perms(box)
            if dropped and origin not in self.dropped:
                self.dropped.add(origin)
                self.report.add("rule", origin, Severity.REVIEW, "K8S_PART_NOT_WRITTEN",
                                "part of what the rule allows cannot be said by a NetworkPolicy (ICMP or another protocol on its "
                                "own, every protocol but some, a range of source ports) and is not written; the converted rule "
                                "allows less")  # fmt: skip
            if perms:
                self.pieces.append(_aws._Piece(box, perms, origin, name))

    @staticmethod
    def _perms(box: regions.Box) -> Tuple[List[_aws.Perm], bool]:
        """What a NetworkPolicy port list can say of a set of services: every protocol, or TCP, UDP and SCTP ports."""
        _, _, _, svc = box
        if svc.everything():
            return [("-1", -1, -1)], False
        out: List[_aws.Perm] = []
        dropped = bool(svc.rest)
        for number, label in ((6, "tcp"), (17, "udp"), (132, "sctp")):
            ranges: List[Tuple[int, int]] = []
            for rect in svc.of(number):
                if (rect[0], rect[1]) != (0, 65535):
                    dropped = True
                    continue
                ranges.append((rect[2], rect[3]))
            out += [(label, low, high) for low, high in regions.merge_ranges(ranges)]
        if any(rects for number, rects in svc.protocols.items() if number not in (6, 17, 132)):
            dropped = True
        return sorted(set(out), key=_aws._perm_key), dropped

    def _defaults(self) -> None:
        """What no rule matches: allowed where the source allows it, as rules that allow."""
        inter = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.universe, self.report)
        everything = [(v, [regions.full(v)], [regions.full(v)], regions.ALL_SERVICES) for v in (4, 6)]
        if inter and all(decided.values()):
            self._allow(everything, "(default)", "default")
            self.report.note(Severity.REVIEW, "K8S_DEFAULT_ALLOW",
                             "the source allows what no rule matches: written as rules that allow everything the blocking rules do "
                             "not block")  # fmt: skip
            return
        open_zones = [zone for zone in self.universe if decided[zone]]
        same: List[regions.Box] = []
        missing: List[str] = []
        for zone in self.universe:
            if inter and decided[zone]:
                continue
            if zone not in self.spaces:
                missing.append(zone)
                continue
            for version in (4, 6):
                space = regions.addresses(self.spaces[zone], version)
                if space:
                    same.append((version, space, space, regions.ALL_SERVICES))
        if inter:
            if missing:
                self.report.note(Severity.REVIEW, "K8S_DEFAULT_NOT_WRITTEN",
                                 "the source allows what no rule matches between zones, and blocks it inside some zones; that needs "
                                 "the networks of those zones (--zone-network), and these have none: " + ", ".join(missing)
                                 + ". It is not written")  # fmt: skip
                return
            left = regions.minus_all(everything, same, limit=4096)
            if left:
                self._allow(left, "(default)", "default")
            self.report.note(Severity.REVIEW, "K8S_DEFAULT_ALLOW",
                             "the source allows what no rule matches between zones: written as rules that allow it")  # fmt: skip
            return
        written = [box for box in same for zone in open_zones if zone in self.spaces
                   and box[1] == regions.addresses(self.spaces[zone], box[0])]  # fmt: skip
        if written:
            self._allow(written, "(default)", "default")
        lost = [zone for zone in open_zones if zone not in self.spaces]
        if lost:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic inside them without a rule; without their networks (--zone-network) that is "
                             "not written: " + ", ".join(lost))  # fmt: skip

    # -- groups ---------------------------------------------------------------------

    def _names(self, groups: List[_aws._Group]) -> None:
        known: Dict[Tuple[Interval, ...], str] = {}
        for name in sorted(self.p.address_groups) + sorted(self.p.addresses):
            if name in self.taint_a:
                continue
            intervals, complete = transform.known_intervals(self.p, name)
            if complete and intervals:
                for version in (4, 6):
                    mine = tuple(regions.addresses(intervals, version))
                    if mine:
                        known.setdefault(mine, name)
        taken: Set[str] = set()
        prefix = (self.options.object_prefix or "fwshift-").lower()
        for number, group in enumerate(groups, 1):
            if not group.inbound and not group.outbound:
                label = "no-rules"
            else:
                label = known.get(tuple(group.attach), "") or self._zone_of(group.attach) or "addresses"
                if {i[0] for i in group.attach} == {6}:
                    label += "-ipv6"
            base = re.sub(r"[^a-z0-9.-]+", "-", (prefix + label).lower()).strip("-.")[:56].strip("-.") or "fwshift"
            if not base[0].isalnum():
                base = "x" + base
            candidate, counter = base, 2
            while candidate in taken:
                candidate = f"{base}-{counter}"
                counter += 1
            taken.add(candidate)
            group.name, group.var = names.clean(candidate, names.KUBERNETES_LABEL), f"G{number}"

    # -- output ---------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                             "not converted: a NetworkPolicy does not translate addresses (kube-proxy, the cloud's load "
                             "balancers and the gateways do). The rules were written for the addresses it translates to, which "
                             "is what the policies see")  # fmt: skip
        groups = self._groups()
        by_rule: Dict[str, List[str]] = {}
        origins = {piece.name: piece.origin for piece in self.pieces}
        for group in groups:
            for rules in list(group.rules_in.values()) + list(group.rules_out.values()):
                for written_name in rules:
                    if group.name not in by_rule.setdefault(origins[written_name], []):
                        by_rule[origins[written_name]].append(group.name)
        for origin, written in by_rule.items():
            if origin != "(default)":
                self.report.item("rule", origin).emitted_as.append("NetworkPolicies " + ", ".join(written))
        self._k8s_notes(groups)
        items = [self._policy(group) for group in groups]
        document: Dict[str, Any] = {"apiVersion": "v1", "kind": "List", "metadata": {"annotations": {
            "fwshift/generated": "FWShift - review the conversion report before applying this"}}, "items": items}  # fmt: skip
        if self.comments:
            document["metadata"]["annotations"]["fwshift/not-written"] = "; ".join(self.comments)[:200000]
        return json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    @staticmethod
    def _rules(entries: Dict[Tuple[int, _aws.Perm], List[Interval]], key: str) -> List[Dict[str, Any]]:
        """Rules of one direction: the ports that share the same peers in one rule."""
        by_perm: Dict[_aws.Perm, List[Interval]] = {}
        for (_, perm), intervals in entries.items():
            by_perm.setdefault(perm, []).extend(intervals)
        by_peers: Dict[Tuple[Interval, ...], List[_aws.Perm]] = {}
        for perm, intervals in by_perm.items():
            by_peers.setdefault(tuple(normalize(intervals)), []).append(perm)
        out: List[Dict[str, Any]] = []
        for peers, perms in sorted(by_peers.items(), key=lambda item: (sorted(map(_aws._perm_key, item[1])), item[0])):
            rule: Dict[str, Any] = {}
            if list(peers) != [FULL_V4, FULL_V6]:
                rule[key] = ip_blocks(list(peers))
            if ("-1", -1, -1) not in perms:
                ports: List[Dict[str, Any]] = []
                for label, low, high in sorted(perms, key=_aws._perm_key):
                    port: Dict[str, Any] = {"protocol": _NAMES[label]}
                    low = max(low, 1)  # (a NetworkPolicy names ports 1 to 65535; port 0 is no port a connection uses)
                    if high < low:
                        continue
                    if (low, high) != (1, 65535):
                        port["port"] = low
                        if high != low:
                            port["endPort"] = high
                    ports.append(port)
                rule["ports"] = ports
            out.append(rule)
        return out

    def _policy(self, group: _aws._Group) -> Dict[str, Any]:
        attach = " ".join(interval_text(i) for i in group.attach)
        rules = sorted(set(r for found in list(group.rules_in.values()) + list(group.rules_out.values()) for r in found))
        annotations = {"fwshift/addresses": attach[:200000], "fwshift/rules": ", ".join(rules)[:200000]}
        spec: Dict[str, Any] = {"podSelector": {"matchLabels": {LABEL: group.name}}, "policyTypes": ["Ingress", "Egress"]}
        ingress, egress = self._rules(group.inbound, "from"), self._rules(group.outbound, "to")
        if ingress:
            spec["ingress"] = ingress
        if egress:
            spec["egress"] = egress
        name = names.clean(group.name.lower().replace("_", "-"), names.KUBERNETES).strip("-.") or "fwshift"
        return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": name, "labels": {"app.kubernetes.io/managed-by": "fwshift"}, "annotations": annotations},
                "spec": spec}  # fmt: skip

    def _k8s_notes(self, groups: List[_aws._Group]) -> None:
        self.report.note(
            Severity.REVIEW, "K8S_LOAD",
            "the output is a List of NetworkPolicies for kubectl apply -n NAMESPACE -f FILE (kubectl apply --dry-run=server checks "
            "it first). It names no namespace: apply it in the namespace of the pods it is for, and in each such namespace. "
            "Policies of the same name are replaced; nothing else is changed. A policy selects the pods labelled "
            f"{LABEL}=<its group>, and no pod has that label yet: nothing changes until pods are labelled",
        )  # fmt: skip
        if self.inside is not None:
            self.report.note(
                Severity.REVIEW, "K8S_EVERY_POD",
                "only the addresses of the pods (" + ("--inside-zone" if self.options.inside_zones else "of the source") + ") get "
                "groups, and an egress rule leaves a connection to them to the ingress rules of the destination's policy: every "
                "one of those pods must get its label, or connections to it are allowed that the source did not allow",
            )  # fmt: skip
        if groups:
            self.report.note(
                Severity.REVIEW, "K8S_LABEL_PODS",
                f"{len(groups)} group{'' if len(groups) == 1 else 's'}: label each pod with {LABEL}=<group> of the policy whose "
                "fwshift/addresses annotation holds the pod's address (kubectl label pod POD ...). A pod's address changes "
                "when it is created again: label the pods through their Deployment or StatefulSet template, where every "
                "address the template's pods get must be in that group. A pod with addresses of both IP versions needs a "
                "group that holds both",
            )  # fmt: skip
        self.report.note(
            Severity.REVIEW, "K8S_IPBLOCK_PODS",
            "the peers are written as ipBlock. Whether an ipBlock matches the addresses of pods depends on the network "
            "plugin (the Kubernetes documentation says ipBlock is meant for addresses outside the cluster); where it does not, "
            "rules between pods allow nothing",
        )  # fmt: skip
        self.report.note(
            Severity.INFO, "K8S_PLATFORM_ALLOWS",
            "a NetworkPolicy always allows traffic between a pod and the node it runs on, and a pod to itself; and it is only "
            "guaranteed to decide TCP, UDP and SCTP (for ICMP and other protocols the network plugin decides)",
        )  # fmt: skip
        if any(rule.log_start or rule.log_end for rule in self.p.rules if rule.enabled):
            self.report.note(Severity.INFO, "LOGGING_NOT_CONVERTED",
                             "rules of the source log; a NetworkPolicy does not (some network plugins can log on their own)")  # fmt: skip
