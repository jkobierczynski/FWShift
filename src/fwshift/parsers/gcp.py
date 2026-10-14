# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Google Cloud firewall parser: the JSON of gcloud for one VPC network -> neutral model.

What is read: the answers of ``gcloud compute firewall-rules list``, ``gcloud compute network-firewall-policies
describe`` (global and regional; each policy with its rules and associations), ``gcloud compute networks describe``
(the enforcement order) and ``gcloud compute instances list`` (which addresses each tag and service account stands
for), as a JSON object with those answers under the keys ``firewall-rules``, ``network-firewall-policies``,
``networks`` and ``instances``, or in one JSON array, or alone. Each object is told by its ``kind`` or its keys.

How Google Cloud decides, and how that is mapped onto the neutral model:

* A connection between two instances passes the egress rules of the sender and the ingress rules of the receiver; one
  from outside the ingress rules only, one to outside the egress rules only. A rule applies to the instances its
  targets name (tags, service accounts, every instance) and, for a regional policy, to those of its region.
* The steps, in the order of the network (``networkFirewallPolicyEnforcementOrder``, ``AFTER_CLASSIC_FIREWALL`` when
  not given): the VPC firewall rules, then the global network firewall policy, then the regional ones; or the
  policies first (``BEFORE_CLASSIC_FIREWALL``). What no rule of a step decides goes to the next step; at the end an
  ingress connection to an instance is denied and an egress one allowed. VPC rules: the lowest priority number
  first, a deny before an allow of the same priority. Policy rules: by priority; ``goto_next`` leaves the policy for
  the next step.
* The model is one first-match list without zones: the ingress rules (destinations: the addresses of the instances
  they apply to), the egress rules (sources: likewise), and for connections between instances every egress rule
  that denies and, for each that allows, the ingress rules cut to it. ``goto_next`` is the rules after it in its
  policy without what it matches.
* A tag or a service account as a source is the primary internal addresses of the instances that carry it. An
  external address of an instance is a static NAT of its internal address, which the rules see.
* What the export does not resolve (secure tags, address groups, host names, region codes, threat intelligence, the
  network context of a source) makes its rule not converted; nothing unknown is read as any address.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import ANY, Action, AddressGroup, NatRule, Policy, Protocol, Rule, Service, ServiceEntry, SnatKind, SourceNat
from ..netutil import Interval, interval_text, intersect, normalize, parse_literal
from ..report import Report, Severity

_MAX_COMPOSED = 5000  # rules for connections between instances
_RESERVED = 2147483548  # policy priorities from here on are Google's own (the goto_next rules at the end)
_NAMES = {"tcp": 6, "udp": 17, "icmp": 1, "esp": 50, "ah": 51, "sctp": 132, "ipip": 4, "gre": 47, "icmpv6": 58, "ipv6-icmp": 58}
_UNRESOLVED = ("srcSecureTags", "srcAddressGroups", "srcFqdns", "srcRegionCodes", "srcThreatIntelligences", "srcNetworks",
               "destAddressGroups", "destFqdns", "destRegionCodes", "destThreatIntelligences")  # fmt: skip

Cell = Optional[Dict[int, List[Interval]]]  # addresses per IP version; None: not known here


def looks_like_gcp(data: bytes) -> bool:
    """JSON of gcloud with firewall rules or network firewall policies of Google Cloud in it."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    if b'"compute#firewall"' in head or b'"compute#firewallPolicy"' in head:
        return True
    return b'"IPProtocol"' in head and (b'"allowed"' in head or b'"denied"' in head) and b'"network"' in head


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [v for v in _list(value) if isinstance(v, dict)]


def _last(url: Any) -> str:
    return str(url or "").rstrip("/").rsplit("/", 1)[-1]


@dataclass
class _Found:
    firewalls: List[Dict[str, Any]] = field(default_factory=list)
    policies: List[Dict[str, Any]] = field(default_factory=list)
    networks: List[Dict[str, Any]] = field(default_factory=list)
    instances: List[Dict[str, Any]] = field(default_factory=list)
    instances_given: bool = False
    incomplete: bool = False
    effective: bool = False  # the answer of get-effective-firewalls


class _Collector:
    def __init__(self) -> None:
        self.found = _Found()
        self.seen: Set[int] = set()

    def walk(self, node: Any, depth: int = 0) -> None:
        if depth > 64:
            raise ParseError("JSON nested deeper than an answer of gcloud")
        if isinstance(node, list):
            for item in node:
                self.walk(item, depth + 1)
            return
        if not isinstance(node, dict):
            return
        if node.get("nextPageToken"):
            self.found.incomplete = True
        if isinstance(node.get("firewallPolicys"), list) or (isinstance(node.get("firewalls"), list) and not node.get("kind")):
            # gcloud ... get-effective-firewalls: the VPC rules and every policy that applies to the network, by type.
            for rule in _dicts(node.get("firewalls")):
                self.found.firewalls.append(rule)
            for policy in _dicts(node.get("firewallPolicys")):
                self.found.policies.append(dict(policy, _effective=str(policy.get("type") or "")))
            self.found.effective = True
            return
        kind = str(node.get("kind") or "")
        if kind == "compute#firewall" or (not kind and ("allowed" in node or "denied" in node) and "network" in node):
            self.found.firewalls.append(node)
            return
        if kind in ("compute#firewallPolicy",) or (not kind and isinstance(node.get("rules"), list) and ("associations" in node or "parent" in node)):
            self.found.policies.append(node)
            return
        if kind == "compute#network" or (not kind and "networkFirewallPolicyEnforcementOrder" in node):
            self.found.networks.append(node)
            return
        if kind == "compute#instance" or (not kind and isinstance(node.get("networkInterfaces"), list)):
            self.found.instances_given = True
            self.found.instances.append(node)
            return
        for key, value in node.items():
            if key == "instances" or (key == "items" and kind == "compute#instanceList"):
                self.found.instances_given = True
            if isinstance(value, (list, dict)):
                self.walk(value, depth + 1)


@dataclass
class _Vm:
    name: str
    region: str
    tags: Set[str]
    accounts: Set[str]
    primary: List[Interval]  # what a source tag or service account stands for
    addresses: List[Interval]  # what a rule that applies to the instance protects
    public: List[Tuple[Interval, Interval]]  # (internal, external)
    unknown: bool = False  # its tags or service accounts are not known (a plan)


@dataclass
class _Item:
    """One rule of an evaluation list."""

    name: str
    policy: str  # "" for a VPC firewall rule
    action: str  # allow, deny, goto
    src: Cell
    dst: Cell
    services: Optional[regions.Services]
    service_names: List[str]
    problems: List[str]
    enabled: bool = True
    log: bool = False
    description: str = ""
    ids: Dict[str, str] = field(default_factory=dict)
    boxes: Optional[List[regions.Box]] = None
    cut: bool = False  # cut by goto_next rules above it


def parse(data: bytes, report: Report, network: str = "") -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    try:
        collector = _Collector()
        collector.walk(document)
        found = collector.found
        if not found.firewalls and not found.policies:
            raise ParseError("no firewall rules or network firewall policies found; expected the JSON of 'gcloud compute "
                             "firewall-rules list --format=json' or of 'gcloud compute network-firewall-policies describe'")  # fmt: skip
        return _Builder(found, report, network).build()
    except ParseError:
        raise
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


def _same(a: regions.Services, b: regions.Services) -> bool:
    return a.minus(b).empty() and b.minus(a).empty()


class _Builder:
    def __init__(self, found: _Found, report: Report, network: str) -> None:
        self.found, self.report, self.wanted = found, report, network
        self.p = Policy(vendor="gcp")
        self.taken: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.services: Dict[str, Tuple[List[str], Optional[regions.Services], str]] = {}
        self.named: Dict[Tuple[Interval, ...], str] = {}  # addresses -> the address group that stands for them
        self.network = ""
        self.order = "AFTER_CLASSIC_FIREWALL"
        self.vms: List[_Vm] = []
        self.known = found.instances_given
        self.notes: Dict[str, List[str]] = {}

    # -- names ---------------------------------------------------------------------

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    # -- the network -----------------------------------------------------------------

    def build(self) -> Policy:
        self._network()
        self._instances()
        ingress, egress = self._lists()
        everyone = self._all_addresses()
        if self.known:
            self._compose(egress, ingress, everyone)
        for item in ingress:
            self._emit_item(item, "in")
        for item in egress:
            self._emit_item(item, "out")
        self._nat()
        self._notes()
        return self.p

    def _network(self) -> None:
        names: Dict[str, str] = {}  # lower-case name -> as written
        for rule in self.found.firewalls:
            name = _last(rule.get("network") or "default")
            names.setdefault(name.lower(), name)
        if not names:  # (only policies: the networks they are associated with)
            for policy in self.found.policies:
                if self._hierarchical(policy):
                    continue
                for association in _dicts(policy.get("associations")):
                    name = _last(association.get("attachmentTarget"))
                    if name:
                        names.setdefault(name.lower(), name)
        if self.wanted:
            wanted = _last(self.wanted)
            if wanted.lower() not in names and not any(_last(n.get("selfLink") or n.get("name")).lower() == wanted.lower() for n in self.found.networks):
                raise ParseError(f"--policy: no firewall rule or policy of network '{wanted[:60]}' in the export; it holds "
                                 + (", ".join(sorted(names.values())) or "none"))  # fmt: skip
            self.network = wanted
        elif len(names) > 1:
            raise ParseError(f"the export holds firewall rules of several networks ({', '.join(sorted(names.values())[:5])}): name the one "
                             "to read with --policy")  # fmt: skip
        else:
            self.network = next(iter(names.values()), "default")
        self.p.scope = self.network
        found = [n for n in self.found.networks if _last(n.get("selfLink") or n.get("name")).lower() == self.network.lower()]
        if found:
            order = str(found[0].get("networkFirewallPolicyEnforcementOrder") or "AFTER_CLASSIC_FIREWALL").upper()
            if order not in ("AFTER_CLASSIC_FIREWALL", "BEFORE_CLASSIC_FIREWALL"):
                raise ParseError(f"network {self.network}: enforcement order '{order[:40]}' is not one FWShift knows")
            self.order = order
        elif self.found.policies:
            self._say("GCP_ORDER_ASSUMED", self.network)

    @staticmethod
    def _hierarchical(policy: Dict[str, Any]) -> bool:
        """A policy of an organization or a folder: it applies to every network below it."""
        if policy.get("_effective"):
            return str(policy["_effective"]) == "HIERARCHY"
        return bool(policy.get("parent")) or any(str(a.get("attachmentTarget") or "").startswith(("organizations/", "folders/"))
                                                  for a in _dicts(policy.get("associations")))  # fmt: skip

    def _strings(self, value: Any, what: str, problems: List[str]) -> List[str]:
        """The entries of a list of names or addresses; one that is not text cannot be read (never 'any')."""
        out = []
        for item in _list(value):
            if not isinstance(item, str) or not item.strip():
                problems.append(f"{what}: an entry that is not a name or an address ({json.dumps(item)[:20]})")
                continue
            out.append(item)
        return out

    @staticmethod
    def _unknown(rule: Dict[str, Any], problems: List[str]) -> None:
        """What a plan of Terraform does not know yet (fwshiftUnknown): the rule cannot be worked out."""
        unknown = [str(v) for v in _list(rule.get("fwshiftUnknown"))]
        if unknown:
            problems.append(", ".join(unknown)[:120] + ": not known before the plan is applied")

    @staticmethod
    def _every(ranges: Dict[int, List[Interval]]) -> Cell:
        """Every address, of IPv6 when the other side of the rule is IPv6 only, else of IPv4 (a rule holds one version)."""
        if ranges[6] and not ranges[4]:
            return {4: [], 6: [regions.full(6)]}
        return {4: [regions.full(4)], 6: []}

    def _mine(self, url: Any) -> bool:
        return _last(url or "default").lower() == self.network.lower()

    def _instances(self) -> None:
        for instance in self.found.instances:
            name = str(instance.get("name") or "?")
            zone = _last(instance.get("zone"))
            region = zone.rsplit("-", 1)[0]  # (a zone is its region and a letter: europe-west1-b)
            tags = {str(t) for t in _list((instance.get("tags") or {}).get("items")) if t}
            accounts = {str(a.get("email")) for a in _dicts(instance.get("serviceAccounts")) if a.get("email")}
            for nic in _dicts(instance.get("networkInterfaces")):
                if not self._mine(nic.get("network")):
                    continue
                primary: List[Interval] = []
                addresses: List[Interval] = []
                public: List[Tuple[Interval, Interval]] = []
                for key in ("networkIP", "ipv6Address"):
                    text = str(nic.get(key) or "")
                    if text:
                        interval = parse_literal(text)
                        if interval is None or interval[1] != interval[2]:
                            raise ParseError(f"instance {name}: '{text[:60]}' is not an address")
                        primary.append(interval)
                addresses += primary
                for alias in _dicts(nic.get("aliasIpRanges")):
                    interval = parse_literal(str(alias.get("ipCidrRange") or ""))
                    if interval is None:
                        raise ParseError(f"instance {name}: alias range '{str(alias.get('ipCidrRange'))[:60]}' cannot be read")
                    addresses.append(interval)
                    self._say("GCP_ALIAS_RANGES", name)
                for config in _dicts(nic.get("accessConfigs")):
                    outside = parse_literal(str(config.get("natIP") or ""))
                    inside = parse_literal(str(nic.get("networkIP") or ""))
                    if outside is not None and inside is not None and outside[1] == outside[2]:
                        public.append((inside, outside))
                self.vms.append(_Vm(name, region, tags, accounts, normalize(primary), normalize(addresses), public,
                                    unknown=bool(_list(instance.get("fwshiftUnknown")))))  # fmt: skip

    def _all_addresses(self) -> Cell:
        if not self.known:
            return None
        found = normalize([i for vm in self.vms for i in vm.addresses])
        return {v: regions.addresses(found, v) for v in (4, 6)}

    # -- addresses -------------------------------------------------------------------

    def _group(self, label: str, intervals: List[Interval], description: str) -> str:
        key = tuple(normalize(intervals))
        if key in self.named:
            return self.named[key]
        name = self._unique(label, self.taken)
        self.p.address_groups[name] = AddressGroup(name, [interval_text(i) for i in key], description)
        self.named[key] = name
        return name

    def _targets(self, tags: List[str], accounts: List[str], region: str, label: str) -> Cell:
        """The addresses a rule applies to; None without the instances."""
        if not self.known:
            return None
        if (tags or accounts) and any(vm.unknown for vm in self.vms if not region or vm.region == region):
            return None  # (an instance whose tags or service accounts are not known)
        chosen = [vm for vm in self.vms if (not region or vm.region == region)
                  and ((not tags and not accounts) or vm.tags & set(tags) or vm.accounts & set(accounts))]  # fmt: skip
        found = normalize([i for vm in chosen for i in vm.addresses])
        if found:
            self._group(label, found, "the instances of " + label)
        return {v: regions.addresses(found, v) for v in (4, 6)}

    def _sources_of(self, tags: List[str], accounts: List[str]) -> Cell:
        if not self.known or any(vm.unknown for vm in self.vms):
            return None
        chosen = [vm for vm in self.vms if vm.tags & set(tags) or vm.accounts & set(accounts)]
        found = normalize([i for vm in chosen for i in vm.primary])
        if found:
            label = "sources " + " ".join([f"tag:{t}" for t in tags] + [f"account:{a}" for a in accounts])
            self._group(label[:120], found, "the primary addresses of the instances of " + label)
        return {v: regions.addresses(found, v) for v in (4, 6)}

    @staticmethod
    def _ranges(values: List[str], what: str, problems: List[str]) -> Dict[int, List[Interval]]:
        out: Dict[int, List[Interval]] = {4: [], 6: []}
        for text in values:
            interval = parse_literal(text)
            if interval is None:
                problems.append(f"{what} '{text[:60]}' cannot be read")
                continue
            out[interval[0]].append(interval)
        return {v: normalize(ivs) for v, ivs in out.items()}

    @staticmethod
    def _union(a: Cell, b: Cell) -> Cell:
        if a is None or b is None:
            return None
        return {v: normalize(a[v] + b[v]) for v in (4, 6)}

    @staticmethod
    def _and(a: Cell, b: Cell) -> Cell:
        if a is None or b is None:
            return None
        return {v: intersect(a[v], b[v]) for v in (4, 6)}

    # -- services ----------------------------------------------------------------------

    def _service(self, entries_in: List[Dict[str, Any]], key_name: str, problems: List[str]) -> Tuple[List[str], Optional[regions.Services]]:
        key = json.dumps(entries_in, sort_keys=True, default=str)
        if key in self.services:
            names, found, problem = self.services[key]
            if problem:
                problems.append(problem)
            return names, found
        entries: List[ServiceEntry] = []
        labels: List[str] = []
        problem = ""
        every = False
        if not entries_in:
            problem = "a rule without a protocol"
        for item in entries_in:
            protocol = str(item.get(key_name) or "").strip().lower()
            ports = [v for v in _list(item.get("ports")) if isinstance(v, str) and v.strip()]
            if len(ports) != len(_list(item.get("ports"))):
                problem = "a port that is not a number or a range"  # (never read as every port)
            number = _NAMES.get(protocol, int(protocol) if protocol.isdigit() and int(protocol) <= 255 else None)
            if protocol == "all":
                every = True
                labels.append("all")
                if ports:
                    problem = "ports with protocol all"
                continue
            if number is None:
                problem = f"protocol '{protocol[:20]}' cannot be read"
                continue
            if ports and number not in (6, 17, 132):
                problem = f"ports with protocol {protocol}, which only TCP, UDP and SCTP have"
                continue
            spec = ""
            for text in ports:
                first, _, last = text.partition("-")
                if not first.isdigit() or not (last or first).isdigit() or not 0 <= int(first) <= int(last or first) <= 65535:
                    problem = f"port '{text[:20]}' cannot be read"
                spec = (spec + "," if spec else "") + text
            if number in (6, 17, 132):
                kind = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[number]
                entries.append(ServiceEntry(kind, dst_ports=spec))
                labels.append(f"{kind.value}-{spec or 'all'}")
            elif number == 1:
                entries.append(ServiceEntry(Protocol.ICMP))  # (Google Cloud does not filter ICMP types)
                labels.append("icmp")
            elif number == 58:
                entries.append(ServiceEntry(Protocol.ICMP6))
                labels.append("icmpv6")
            else:
                entries.append(ServiceEntry(Protocol.IP, ip_protocol=number))
                labels.append(f"ip-{number}")
        if problem:
            self.services[key] = ([ANY], None, problem)
            problems.append(problem)
            return [ANY], None
        if every:
            self.services[key] = ([ANY], regions.ALL_SERVICES, "")
            return [ANY], regions.ALL_SERVICES
        found = regions.service_set(entries)
        name = self._unique("_".join(transform.dedupe(labels))[:80] or "service", self.taken_services)
        self.p.services[name] = Service(name, entries)
        self.services[key] = ([name], found, "")
        return [name], found

    # -- the rules ------------------------------------------------------------------------

    def _vpc_items(self) -> Tuple[List[_Item], List[_Item]]:
        ingress: List[_Item] = []
        egress: List[_Item] = []
        rules = [r for r in self.found.firewalls if self._mine(r.get("network"))]

        def order(rule: Dict[str, Any]) -> Tuple[int, int, str]:
            number = rule.get("priority", 1000)
            value = number if isinstance(number, int) and not isinstance(number, bool) else 1 << 20
            return (value, 0 if rule.get("denied") else 1, str(rule.get("name") or ""))

        for rule in sorted(rules, key=order):
            name = str(rule.get("name") or "rule")
            problems: List[str] = []
            number = rule.get("priority", 1000)
            if not isinstance(number, int) or isinstance(number, bool) or not 0 <= number <= 65535:
                problems.append(f"priority '{str(number)[:20]}' cannot be read")
            direction = str(rule.get("direction") or "INGRESS").upper()
            if direction not in ("INGRESS", "EGRESS"):
                problems.append(f"direction '{direction[:20]}' cannot be read")
            allowed, denied = _dicts(rule.get("allowed")), _dicts(rule.get("denied"))
            if bool(allowed) == bool(denied):
                problems.append("a rule with both allowed and denied, or neither")
            services, found = self._service(allowed or denied, "IPProtocol", problems)
            self._unknown(rule, problems)
            tags = self._strings(rule.get("targetTags"), "target tags", problems)
            accounts = self._strings(rule.get("targetServiceAccounts"), "target service accounts", problems)
            label = " ".join([f"tag:{t}" for t in tags] + [f"account:{a}" for a in accounts]) or "every instance"
            targets = self._targets(tags, accounts, "", f"targets {label}"[:120])
            source_texts = self._strings(rule.get("sourceRanges"), "source ranges", problems)
            dest_texts = self._strings(rule.get("destinationRanges"), "destination ranges", problems)
            source_ranges = self._ranges(source_texts, "source range", problems)
            dest_ranges = self._ranges(dest_texts, "destination range", problems)
            source_tags = self._strings(rule.get("sourceTags"), "source tags", problems)
            source_accounts = self._strings(rule.get("sourceServiceAccounts"), "source service accounts", problems)
            if direction == "EGRESS":
                if source_tags or source_accounts:
                    problems.append("source tags or service accounts in an egress rule")
                # (no destination: every address of the IP version of the rule; IPv4 unless its source ranges are IPv6)
                peer: Cell = dest_ranges if _list(rule.get("destinationRanges")) else self._every(source_ranges)
                own: Cell = self._and(targets, source_ranges) if _list(rule.get("sourceRanges")) else targets
                src, dst = own, peer
            else:
                if _list(rule.get("sourceRanges")) or not (source_tags or source_accounts):
                    # (no source at all: every address of the IP version of the rule; IPv4 unless its destination ranges are IPv6)
                    peer = source_ranges if _list(rule.get("sourceRanges")) else self._every(dest_ranges)
                else:
                    peer = {4: [], 6: []}
                if source_tags or source_accounts:
                    peer = self._union(peer, self._sources_of(source_tags, source_accounts))
                own = self._and(targets, dest_ranges) if _list(rule.get("destinationRanges")) else targets
                src, dst = peer, own
            if rule.get("disabled") not in (None, True, False):
                problems.append(f"disabled '{str(rule.get('disabled'))[:20]}' cannot be read")
            item = _Item(name, "", "deny" if denied else "allow", src, dst, found, services, problems,
                         enabled=rule.get("disabled") is not True, log=bool((rule.get("logConfig") or {}).get("enable")),
                         description=str(rule.get("description") or ""),
                         ids={"gcp.firewall": name, "gcp.priority": str(number), "gcp.direction": direction})  # fmt: skip
            (egress if direction == "EGRESS" else ingress).append(item)
        return ingress, egress

    def _policy_items(self, policy: Dict[str, Any], problem: str = "") -> Tuple[List[_Item], List[_Item]]:
        ingress: List[_Item] = []
        egress: List[_Item] = []
        name = str(policy.get("shortName") or policy.get("displayName") or policy.get("name") or "policy")
        region = _last(policy.get("region")) if policy.get("region") else ""
        rules = [r for r in _dicts(policy.get("rules"))]
        if any(not isinstance(r.get("priority"), int) or isinstance(r.get("priority"), bool) for r in rules):
            raise ParseError(f"network firewall policy {name}: a rule without a priority that can be read")
        numbers = [r["priority"] for r in rules]
        if len(numbers) != len(set(numbers)):
            raise ParseError(f"network firewall policy {name}: two rules with one priority, which a policy does not hold")
        for rule in sorted(rules, key=lambda r: r["priority"]):
            number = rule["priority"]
            if number >= _RESERVED:
                continue  # (Google's goto_next rules at the end: what reaches them goes on to the next step anyway)
            problems: List[str] = [problem] if problem else []
            direction = str(rule.get("direction") or "").upper()
            action = str(rule.get("action") or "").lower()
            if direction not in ("INGRESS", "EGRESS"):
                problems.append(f"direction '{direction[:20]}' cannot be read")
            if action not in ("allow", "deny", "goto_next"):
                problems.append(f"action '{action[:30]}' is not converted" if action else "a rule without an action")
            match: Dict[str, Any] = rule["match"] if isinstance(rule.get("match"), dict) else {}
            services, found = self._service(_dicts(match.get("layer4Configs")), "ipProtocol", problems)
            if rule.get("targetType") not in (None, "", "INSTANCES"):
                problems.append(f"target type {str(rule.get('targetType'))[:30]}: not instances")
            self._unknown(rule, problems)
            accounts = self._strings(rule.get("targetServiceAccounts"), "target service accounts", problems)
            resources = self._strings(rule.get("targetResources"), "target resources", problems)
            if resources and not any(self._mine(r) for r in resources):
                continue  # (a rule of a hierarchical policy for other networks)
            secure = [t for t in _dicts(rule.get("targetSecureTags")) if str(t.get("state") or "EFFECTIVE").upper() != "INEFFECTIVE"]
            if _dicts(rule.get("targetSecureTags")) and not secure:
                continue  # (every target tag is ineffective: the rule is ignored)
            if secure:
                problems.append("targets secure tags, which the export does not resolve to instances")
            label = " ".join([f"account:{a}" for a in accounts]) or "every instance"
            targets = self._targets([], accounts, region, f"targets {label}" + (f" in {region}" if region else ""))
            unresolved = [key for key in _UNRESOLVED if _list(match.get(key))]
            for key in ("srcNetworkType", "destNetworkType", "srcNetworkContext", "destNetworkContext"):
                if match.get(key) not in (None, "", "UNSPECIFIED"):
                    unresolved.append(key)
            if unresolved:
                problems.append("matches " + ", ".join(unresolved) + ", which the export does not resolve to addresses")
            src_ranges = self._ranges(self._strings(match.get("srcIpRanges"), "source ranges", problems), "source range", problems)
            dst_ranges = self._ranges(self._strings(match.get("destIpRanges"), "destination ranges", problems), "destination range", problems)
            if rule.get("disabled") not in (None, True, False):
                problems.append(f"disabled '{str(rule.get('disabled'))[:20]}' cannot be read")
            src: Cell
            dst: Cell
            if direction == "INGRESS":
                if not _list(match.get("srcIpRanges")) and not unresolved:
                    problems.append("an ingress rule without a source")
                src, dst = src_ranges, (self._and(targets, dst_ranges) if _list(match.get("destIpRanges")) else targets)
            else:
                if not _list(match.get("destIpRanges")) and not unresolved:
                    problems.append("an egress rule without a destination")
                src, dst = (self._and(targets, src_ranges) if _list(match.get("srcIpRanges")) else targets), dst_ranges
            title = str(rule.get("ruleName") or "") or str(number)
            item = _Item(f"{name}:{title}", name + ("@" + region if region else ""), "goto" if action == "goto_next" else action or "deny",
                         src, dst, found, services, problems, enabled=rule.get("disabled") is not True, log=bool(rule.get("enableLogging")),
                         description=str(rule.get("description") or ""),
                         ids={"gcp.policy": name, "gcp.priority": str(number), "gcp.direction": direction})  # fmt: skip
            if region:
                item.ids["gcp.region"] = region
            (egress if direction == "EGRESS" else ingress).append(item)
        return ingress, egress

    def _stage(self, policy: Dict[str, Any]) -> str:
        """Where a policy is evaluated: hierarchy, system, global, regional; "" when it does not apply to the network."""
        kind = str(policy.get("_effective") or "")
        if kind:
            if kind == "HIERARCHY":
                return "hierarchy"
            if kind.startswith("SYSTEM"):
                return "system"
            if kind == "NETWORK":
                return "global"
            if kind == "NETWORK_REGIONAL":
                return "regional"
            return "unknown"
        if self._hierarchical(policy):
            return "hierarchy"
        if not any(self._mine(a.get("attachmentTarget")) for a in _dicts(policy.get("associations"))):
            return ""
        return "regional" if policy.get("region") else "global"

    def _lists(self) -> Tuple[List[_Item], List[_Item]]:
        vpc_in, vpc_out = self._vpc_items()
        steps: Dict[str, Tuple[List[_Item], List[_Item]]] = {k: ([], []) for k in ("hierarchy", "system", "global", "regional")}
        globals_seen = 0
        regions_seen: List[str] = []
        for policy in self.found.policies:
            name = str(policy.get("shortName") or policy.get("displayName") or policy.get("name") or "?")
            stage = self._stage(policy)
            if not stage:
                self._say("GCP_POLICY_NOT_ASSOCIATED", name)
                continue
            if not isinstance(policy.get("rules"), list):
                self._say("GCP_POLICY_WITHOUT_RULES", name)
            problem = ""
            if stage == "unknown":
                problem = f"a policy of type '{str(policy.get('_effective'))[:30]}', which FWShift does not know"
                stage = "hierarchy"
            elif stage == "regional" and not policy.get("region"):
                problem = "a regional policy whose region the export does not say"
            elif _list(policy.get("fwshiftUnknown")):
                problem = ", ".join(str(v) for v in _list(policy.get("fwshiftUnknown")))[:60] + " of the policy: not known before the plan is applied"
            if stage == "hierarchy" and not policy.get("_effective"):
                self._say("GCP_HIERARCHICAL_READ", name)
            if stage == "global" and not policy.get("_effective"):
                globals_seen += 1
            if stage == "regional" and policy.get("region") and not policy.get("_effective"):
                regions_seen.append(_last(policy.get("region")))
            items_in, items_out = self._policy_items(policy, problem)
            steps[stage][0].extend(self._goto(items_in))
            steps[stage][1].extend(self._goto(items_out))
        if globals_seen > 1:
            raise ParseError(f"network {self.network}: several global network firewall policies are associated with it, which Google "
                             "Cloud does not allow; the export is not of one moment")  # fmt: skip
        if len(regions_seen) != len(set(regions_seen)):
            self._say("GCP_REGIONAL_SEVERAL", ", ".join(sorted(set(r for r in regions_seen if regions_seen.count(r) > 1))))
        first_in = steps["hierarchy"][0] + steps["system"][0]
        first_out = steps["hierarchy"][1] + steps["system"][1]
        policies_in, policies_out = steps["global"][0] + steps["regional"][0], steps["global"][1] + steps["regional"][1]
        if self.order == "BEFORE_CLASSIC_FIREWALL":
            ingress, egress = first_in + policies_in + vpc_in, first_out + policies_out + vpc_out
        else:
            ingress, egress = first_in + vpc_in + policies_in, first_out + vpc_out + policies_out
        everyone = self._all_addresses()
        full = {4: [regions.full(4)], 6: [regions.full(6)]}
        ingress.append(_Item("implied deny ingress", "", "deny", full, everyone, regions.ALL_SERVICES, [ANY], [],
                             description="what no rule decides: an ingress connection to an instance is denied"))  # fmt: skip
        egress.append(_Item("implied allow egress", "", "allow", everyone, full, regions.ALL_SERVICES, [ANY], [],
                            description="what no rule decides: an egress connection from an instance is allowed"))  # fmt: skip
        for item in ingress + egress:
            if item.boxes is None and not item.cut:
                item.boxes = self._boxes(item)
        return ingress, egress

    def _boxes(self, item: _Item) -> Optional[List[regions.Box]]:
        if item.src is None or item.dst is None or item.services is None or item.problems:
            return None
        return [(v, item.src[v], item.dst[v], item.services) for v in (4, 6) if item.src[v] and item.dst[v]]

    def _goto(self, items: List[_Item]) -> List[_Item]:
        """The rules of one policy, each without what the goto_next rules above it match; the goto_next rules themselves
        are not rules of the model (what they match goes on to the next step)."""
        cuts: List[regions.Box] = []
        unknown = ""
        out: List[_Item] = []
        for item in items:
            if not item.enabled:
                if item.action != "goto":
                    out.append(item)  # (as written, disabled)
                continue
            boxes = self._boxes(item)
            if unknown:
                item.problems.append(f"after goto_next rule {unknown}, whose match cannot be worked out")
                boxes = None
            elif cuts and boxes is not None:
                boxes = regions.minus_all(boxes, cuts, limit=2000)
                if boxes is None:
                    item.problems.append("what the goto_next rules above it take away is too complex to work out")
                item.cut = True
            item.boxes = boxes
            if item.action == "goto":
                if boxes is None:
                    unknown = item.name
                else:
                    cuts += boxes
                continue
            out.append(item)
        return out

    # -- the model --------------------------------------------------------------------

    def _side(self, intervals: List[Interval]) -> List[str]:
        key = tuple(normalize(intervals))
        if key in self.named:
            return [self.named[key]]
        return [interval_text(i) for i in key]

    def _service_names(self, svc: regions.Services, item: _Item, version: int) -> Optional[Tuple[List[str], bool]]:
        if item.services is not None and _same(svc, item.services):
            return item.service_names, False
        if _same(svc, regions.ALL_SERVICES):
            return [ANY], False
        found = regions.entries_of(svc, version)
        if found is None:
            return None
        entries, negated = found
        if not entries:
            return ([ANY], False) if negated else None
        key = json.dumps([[e.protocol.value, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code, e.ip_protocol] for e in entries])
        for name, service in self.p.services.items():
            if service.description == key:
                return [name], negated
        name = self._unique("svc-" + "-".join(e.protocol.value + (e.dst_ports or "") for e in entries[:3]), self.taken_services)
        self.p.services[name] = Service(name, entries, description=key)
        return [name], negated

    def _rule(self, base: str, item: _Item, sources: List[str], destinations: List[str], services: List[str], negated: bool,
              allow: bool) -> Rule:  # fmt: skip
        rule = Rule(self._unique(base, self.rule_names), sources=sources, destinations=destinations, services=services,
                    action=Action.ALLOW if allow else Action.DENY)  # fmt: skip
        rule.origin = rule.name
        rule.negate_service = negated
        rule.enabled = item.enabled
        rule.log_end = item.log
        rule.description = item.description
        rule.source_ids = dict(item.ids)
        rule.unsupported = list(dict.fromkeys(item.problems))
        self.p.rules.append(rule)
        return rule

    def _emit_boxes(self, base: str, item: _Item, boxes: List[regions.Box], allow: bool) -> int:
        count = 0
        groups: List[Tuple[regions.Services, List[regions.Box]]] = []
        for box in boxes:
            if regions.empty(box):
                continue
            for svc, members in groups:
                if _same(svc, box[3]):
                    members.append(box)
                    break
            else:
                groups.append((box[3], [box]))
        for _, same in groups:
            versions = [b[0] for b in same]
            batches = [same] if len(versions) == len(set(versions)) else [[b] for b in same]
            for batch in batches:
                names = self._service_names(batch[0][3], item, batch[0][0])
                if names is None:  # (what is left of the services cannot be written: one rule that is not converted)
                    rule = self._rule(base, item, [ANY], [ANY], item.service_names, False, allow)
                    rule.unsupported.append("the services left after the rules above it cannot be written as services")
                    count += 1
                    continue
                sources = [s for b in batch for s in self._side(b[1])]
                destinations = [d for b in batch for d in self._side(b[2])]
                self._rule(base, item, transform.dedupe(sources), transform.dedupe(destinations), names[0], names[1], allow)
                count += 1
        return count

    def _emit_item(self, item: _Item, word: str) -> None:
        base = f"{item.name} ({word})" if item.policy or item.name.startswith("implied") else f"{item.name}"
        if item.enabled and item.boxes is not None:
            if not self._emit_boxes(base, item, item.boxes, item.action == "allow") and not item.name.startswith("implied"):
                self.report.skip("rule", base, "GCP_NO_INSTANCE",
                                 "the rule applies to no instance of the export (or what it matches is all taken by the "
                                 "goto_next rules above it, or its two sides are of different IP versions): left out",
                                 Severity.INFO)  # fmt: skip
            return
        # Not worked out (or disabled in the source): one rule as written, with what is known of its sides.
        sources = self._side(item.src[4] + item.src[6]) if item.src is not None and (item.src[4] or item.src[6]) else [ANY]
        destinations = self._side(item.dst[4] + item.dst[6]) if item.dst is not None and (item.dst[4] or item.dst[6]) else [ANY]
        rule = self._rule(base, item, sources, destinations, item.service_names, False, item.action == "allow")
        if item.enabled and (item.src is None or item.dst is None) and not item.problems:
            rule.unsupported.append("the instances it applies to are not known without the instances in the export")

    def _compose(self, egress: List[_Item], ingress: List[_Item], everyone: Cell) -> None:
        """Connections between instances: each egress rule that denies, and for each that allows, the ingress rules cut to
        it. Rules that cannot be worked out take part as rules that are not converted."""
        assert everyone is not None
        inside = [(v, [regions.full(v)], everyone[v], regions.ALL_SERVICES) for v in (4, 6) if everyone[v]]
        inside_src = [(v, everyone[v], [regions.full(v)], regions.ALL_SERVICES) for v in (4, 6) if everyone[v]]
        count = 0
        said: Set[str] = set()
        for out_item in egress:
            if not out_item.enabled:
                continue
            if out_item.boxes is None:
                self._rule(f"{out_item.name} (between instances)", out_item, [ANY], [ANY], out_item.service_names, False,
                           out_item.action == "allow")  # fmt: skip
                continue
            out_boxes = [b for b in (regions.box_and(a, c) for a in out_item.boxes for c in inside) if b is not None]
            if not out_boxes:
                continue
            if out_item.action != "allow":
                count += self._emit_boxes(f"{out_item.name} (between instances)", out_item, out_boxes, False)
                continue
            for in_item in ingress:
                if not in_item.enabled:
                    continue
                if count >= _MAX_COMPOSED:
                    blocker = Rule(self._unique("between instances: the rest", self.rule_names), action=Action.DENY,
                                   sources=[self._group("every instance", [i for v in (4, 6) for i in everyone[v]], "every instance")],
                                   destinations=[self._group("every instance", [i for v in (4, 6) for i in everyone[v]], "every instance")])  # fmt: skip
                    blocker.origin = blocker.name
                    blocker.description = "more combinations of egress and ingress rules than are converted: the rest is blocked"
                    self.p.rules.append(blocker)
                    self._say("GCP_COMPOSED_LEFT_OUT", "between instances")
                    return
                if in_item.boxes is None:
                    if in_item.name in said:
                        continue
                    said.add(in_item.name)
                    rule = self._rule(f"{out_item.name}+{in_item.name}", in_item, [ANY], [ANY], in_item.service_names, False,
                                      in_item.action == "allow")  # fmt: skip
                    if not rule.unsupported:
                        rule.unsupported.append("not worked out")
                    continue
                in_boxes = [b for b in (regions.box_and(a, c) for a in in_item.boxes for c in inside_src) if b is not None]
                both = [b for b in (regions.box_and(a, c) for a in out_boxes for c in in_boxes) if b is not None and not regions.empty(b)]
                if not both:
                    continue
                merged = _Item(f"{out_item.name}+{in_item.name}", in_item.policy, in_item.action, None, None, None, in_item.service_names,
                               [], description=f"egress rule {out_item.name} and ingress rule {in_item.name}", ids=dict(in_item.ids))  # fmt: skip
                merged.services = in_item.services
                count += self._emit_boxes(merged.name, merged, both, in_item.action == "allow")
        self._say("GCP_COMPOSED", str(count))

    # -- NAT and notes -------------------------------------------------------------------

    def _nat(self) -> None:
        pairs = [(inside, outside, vm.name) for vm in self.vms for inside, outside in vm.public]
        for inside, outside, name in pairs:
            nat_name = self._unique(f"external-{interval_text(outside)}", {n.name.lower() for n in self.p.nat_rules})
            nat = NatRule(nat_name, sources=[interval_text(inside)], description=f"external address of instance {name}")
            nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(outside)], bidirectional=True)
            nat.origin = nat_name
            self.p.nat_rules.append(nat)
        if pairs:
            self.p.lookup_after_dnat = True
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False, report_deny=False)
            self.report.retract("rule", {"NAT_DESTINATION_REWRITTEN", "NAT_ADDRESS_EXPOSED"})
            self.report.note(Severity.INFO, "GCP_EXTERNAL_ADDRESSES",
                             "the external addresses of the instances are static NAT of their internal addresses; the firewall "
                             "rules see the internal address. The rules that name an internal address name its external address "
                             "as well, as the model has rules before NAT")  # fmt: skip
            self.report.note(Severity.REVIEW, "GCP_HAIRPIN",
                             "connections from an instance to the external address of another are not converted as Google Cloud "
                             "decides them (they leave the network and come back from the sender's external address); the "
                             "converted policy treats them as connections to the internal address, which may allow more")  # fmt: skip

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "GCP_SOURCE",
                         f"network {self.network}, enforcement order {self.order}: "
                         + ("network firewall policies, then the VPC firewall rules" if self.order == "BEFORE_CLASSIC_FIREWALL"
                            else "the VPC firewall rules, then the network firewall policies")
                         + "; what none decides is denied for ingress to an instance and allowed for egress from one")  # fmt: skip
        if self.found.effective:
            self.report.note(Severity.INFO, "GCP_EFFECTIVE",
                             "the answer of get-effective-firewalls: its hierarchical policies come first, in the order of the "
                             "answer, then its system policies, then the network's own rules and policies")  # fmt: skip
        else:
            self.report.note(Severity.REVIEW, "GCP_NOT_IN_EXPORT",
                             "hierarchical firewall policies (of the organization and its folders) and regional system policies "
                             "are evaluated before all of these and are not in a project's export unless added to it; neither is "
                             "a firewall endpoint that a rule sends traffic to. Check them with gcloud compute networks "
                             "get-effective-firewalls")  # fmt: skip
        self.report.note(Severity.INFO, "GCP_UNFILTERED",
                         "the firewall never filters traffic to the metadata server (169.254.169.254, fd20:ce::254), and Google "
                         "Cloud blocks some traffic itself (outbound TCP 25 to the internet, protocols an external address does "
                         "not carry); the converted policy says nothing about it. Connections where neither end is an instance "
                         "of the network are not the firewall's: the converted policy denies them")  # fmt: skip
        if not self.known:
            self.report.note(Severity.REVIEW, "GCP_NO_INSTANCES",
                             "the instances (gcloud compute instances list) are not in the export: which addresses a rule's "
                             "targets and its source tags and service accounts stand for is not known, and those rules are not "
                             "converted; connections between instances are not worked out. Add that answer")  # fmt: skip
        if self.found.incomplete:
            self.report.note(Severity.REVIEW, "GCP_INCOMPLETE_EXPORT",
                             "an answer says there is more to fetch (nextPageToken): what was left out is missing from the "
                             "converted policy")  # fmt: skip
        texts = {
            "GCP_ORDER_ASSUMED": (Severity.REVIEW, "the network (gcloud compute networks describe) is not in the export: its "
                                  "enforcement order was taken to be AFTER_CLASSIC_FIREWALL, the default"),
            "GCP_POLICY_NOT_ASSOCIATED": (Severity.INFO, "network firewall policies not associated with the network, and not read"),
            "GCP_HIERARCHICAL_READ": (Severity.REVIEW, "policies of an organization or a folder, read as the first step, before "
                                      "every other, in the order of the export (the organization's first): that they reach this "
                                      "network and the order of their folders are not checked"),
            "GCP_POLICY_WITHOUT_RULES": (Severity.REVIEW, "policies without their rules (an answer of list, not of describe): "
                                         "their rules are missing from the converted policy"),
            "GCP_REGIONAL_SEVERAL": (Severity.REVIEW, "several regional network firewall policies of one region: they were read "
                                     "in the order of the export"),
            "GCP_ALIAS_RANGES": (Severity.INFO, "alias IP ranges of these instances are addresses the rules that apply to them "
                                 "protect; as a source tag they are not"),
            "GCP_COMPOSED": (Severity.INFO, "connections between instances pass the egress rules of one and the ingress rules of "
                             "the other: rules that say what both allow, in the order of the two"),
            "GCP_COMPOSED_LEFT_OUT": (Severity.REVIEW, f"more than {_MAX_COMPOSED} combinations of egress and ingress rules: the "
                                      "rest of the connections between instances is blocked"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))
