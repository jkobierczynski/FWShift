# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Forcepoint NGFW parser: the answers of the SMC REST API for one firewall policy -> neutral model.

The input is what ``smc_dump.py`` writes (``fwshift script forcepoint-dump``): the answers of the API one after the
other, the policy, its templates up to the top, their rule lists (each list answer with the key ``fwshift_list``
naming the list it is), every rule, every sub-policy a rule jumps to, and every element a rule or element names.
Elements are found by their ``self`` link.

What the SMC does, as far as it decides what passes (the notes of the work on it have the sources):

* **Order.** A policy is based on a template, a template on another, up to a predefined one. The rules of the top
  template come first; at each insert point of a template stand the rules of the level below that were added there
  (``parent_insert_point``), then the template goes on. Access rules are first match.
* **Actions.** Allow, Discard and Refuse decide. Continue decides nothing: it sets defaults (logging among them) for
  the rules below it that match the same traffic. Jump goes into a sub-policy; when nothing there matches, the next
  rule decides. VPN actions, block lists and forced next hops are not converted.
* **Cells.** ANY, NONE (the rule is ignored), or members, which are ORed: addresses, zones, users, network
  applications, URL categories; a match expression is one row whose parts are ANDed. An expression combines
  addresses with union, intersection and exclusion. IPv4 and IPv6 rules are separate lists.
* **NAT.** Access rules match the addresses before NAT; NAT rules are first match, applied after an access rule
  allowed the connection; one rule translates source and destination together.
* What no rule decides is discarded.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    ServiceGroup,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, intersect, normalize, parse_literal, subtract
from ..report import Report, Severity
from .cisco import _documents

Obj = Dict[str, Any]
_ACCESS = (("fw_ipv4_access_rules", 4), ("fw_ipv6_access_rules", 6))
_NAT = (("fw_ipv4_nat_rules", 4), ("fw_ipv6_nat_rules", 6))
_DECIDING = {"allow": Action.ALLOW, "discard": Action.DROP, "refuse": Action.RESET_CLIENT}
_VPN = ("apply_vpn", "enforce_vpn", "forward_vpn")
_NOT_CONVERTED = {
    "apply_vpn": "a VPN action (Apply VPN)", "enforce_vpn": "a VPN action (Enforce VPN)", "forward_vpn": "a VPN action (Forward VPN)",
    "blacklist": "a block list (it discards what the dynamic block list holds, and lets the rest go on)",
    "block_list": "a block list (it discards what the dynamic block list holds, and lets the rest go on)",
    "apply_blacklist": "a block list (it discards what the dynamic block list holds, and lets the rest go on)",
    "forced_next_hop": "a forced next hop", "explicit_proxy_jump": "a jump to an explicit proxy", "terminate": "the action Terminate",
}  # fmt: skip
_LOGGED = ("stored", "essential", "alert", "transient")
_SERVICE_GROUPS = ("service_group", "tcp_service_group", "udp_service_group", "icmp_service_group", "icmp_ipv6_service_group",
                   "ip_service_group")  # fmt: skip
_ENGINES = ("single_fw", "fw_cluster", "virtual_fw", "master_engine", "single_layer2", "layer2_cluster", "single_ips", "ips_cluster",
            "router", "netlink", "engine", "fw_single", "cluster_virtual_interface")  # fmt: skip
_MAX_DEPTH = 8  # sub-policies in sub-policies, and templates on templates
_MAX_COPIES = 64  # model rules one rule of the SMC becomes


def looks_like_forcepoint(data: bytes) -> bool:
    """The answers of the SMC API (hrefs into ``/elements/``, a firewall policy among them), or its XML export."""
    head = data[:262144]
    if re.search(rb"^\s*(?:<\?xml[^>]*\?>\s*)?(?:<!--.*?-->\s*)*(?:<!DOCTYPE\s+generic_import_export[^>]*>\s*)?<generic_import_export[\s>]", head, re.S):
        return True
    return head.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] in (b"{", b"[") and (b'"fwshift_list"' in head or b"/elements/fw_policy/" in head)


def parse(data: bytes, report: Report, policy: str = "") -> Policy:
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"<"):
        raise ParseError(
            "this is the XML export of the Security Management Center (Export Elements): Forcepoint does not document it, "
            "and FWShift does not guess at it. Take the policy from the SMC API instead: 'fwshift script forcepoint-dump' "
            "writes the program that does"
        )
    documents = _documents(data)
    if not documents:
        raise ParseError("the input is empty")
    try:
        source = _Source(documents)
        if not source.of("fw_policy"):
            raise ParseError(
                "no firewall policy in the input: expected the answers of the SMC API for one, as the program of "
                "'fwshift script forcepoint-dump' writes them"
            )
        return _Reader(source, report, policy).build()
    except ParseError:
        raise
    except (TypeError, AttributeError, KeyError, IndexError, ValueError, RecursionError) as exc:
        raise ParseError(f"the input is not shaped like the answers of the SMC API ({type(exc).__name__}: {str(exc)[:80]})") from None


def _kind(href: str) -> str:
    """The type of what an href points to: the segment before its last one, after ``/elements/``."""
    _, sep, rest = href.partition("/elements/")
    parts = [part for part in rest.split("/") if part] if sep else []
    return parts[-2] if len(parts) >= 2 else ""


def _links(obj: Obj) -> List[Any]:
    links = obj.get("link")
    return links if isinstance(links, list) else []


def _self(obj: Obj) -> str:
    for link in _links(obj):
        if isinstance(link, dict) and link.get("rel") == "self" and isinstance(link.get("href"), str):
            return str(link["href"])
    return ""


def _link(obj: Obj, rel: str) -> str:
    for link in _links(obj):
        if isinstance(link, dict) and link.get("rel") == rel and isinstance(link.get("href"), str):
            return str(link["href"])
    return ""


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> Obj:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _short(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _port(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _ports_meet(first: str, second: str) -> bool:
    """Whether two port lists ("" for all) have a port in common."""
    if not first or not second:
        return True

    def ranges(text: str) -> List[Tuple[int, int]]:
        out = []
        for part in text.split(","):
            low, _, high = part.partition("-")
            out.append((int(low), int(high or low)))
        return out

    return any(a <= d and c <= b for a, b in ranges(first) for c, d in ranges(second))


class _Source:
    """The answers of the input, indexed: elements by their self link, rule lists by the list they are."""

    def __init__(self, documents: List[Any]) -> None:
        self.by_href: Dict[str, Obj] = {}
        self.lists: Dict[str, List[str]] = {}
        self.unnamed_lists = 0
        stack = list(reversed(documents))
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(reversed(item))
                continue
            if not isinstance(item, dict):
                continue
            if "result" in item and isinstance(item.get("result"), list):
                where = _str(item.get("fwshift_list"))
                if not where:
                    self.unnamed_lists += 1
                    continue
                self.lists[where] = [str(entry["href"]) for entry in item["result"] if isinstance(entry, dict) and isinstance(entry.get("href"), str)]
                continue
            href = _self(item)
            if href:
                self.by_href.setdefault(href, item)

    def of(self, kind: str) -> List[Tuple[str, Obj]]:
        return [(href, obj) for href, obj in self.by_href.items() if _kind(href) == kind]


class _Cell:
    """One way a cell of a rule can match: zones, addresses (or users), applications, ... All of it ANDed."""

    def __init__(self) -> None:
        self.zones: List[str] = [ANY]
        self.members: List[str] = [ANY]
        self.negated = False
        self.users: List[str] = [ANY]
        self.services: List[str] = [ANY]
        self.applications: List[str] = [ANY]
        self.urls: List[str] = [ANY]


class _Reader:
    def __init__(self, source: _Source, report: Report, policy: str) -> None:
        self.source, self.report, self.wanted = source, report, policy
        self.p = Policy(vendor="forcepoint", default_intrazone=Action.DROP, default_interzone=Action.DROP)
        self.names: Set[str] = set()  # names of address objects and groups
        self.service_names: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.addresses: Dict[Tuple[str, bool], Tuple[str, str]] = {}  # (href, in a rule cell) -> (member, problem)
        self.services: Dict[str, Tuple[str, str, str]] = {}  # href -> (kind, name, problem)
        self.missing: List[str] = []
        self.continues: List[str] = []
        self.templates_missing: List[str] = []
        self.tail_families: Set[int] = set()  # IP versions whose template rules are not in the input
        self.placed_last: List[str] = []
        self.automatic = 0
        self.none_cells: List[str] = []
        self.broadcast_in_groups: List[str] = []
        self.engines: Set[str] = set()
        self.no_vpn: List[str] = []
        self.views: Dict[Tuple[str, int], str] = {}  # (member, IP version) -> the group made of its part of that version

    # -- the policy and its templates ---------------------------------------------------------------

    def build(self) -> Policy:
        href, policy = self._policy()
        self.p.scope = _str(policy.get("name"))
        levels = self._levels(href, policy)
        for rel, family in _ACCESS:
            entries = self._effective(levels, rel, family)
            self.p.rules += self._access(entries, family, [])
            if family in self.tail_families:
                self.p.rules += self._template_tail(family)
        for rel, family in _NAT:
            for entry, entry_href in self._effective(levels, rel, family):
                nat = self._nat(entry, entry_href, family)
                if nat is not None:
                    self.p.nat_rules.append(nat)
        self._notes()
        return self.p

    def _policy(self) -> Tuple[str, Obj]:
        policies = self.source.of("fw_policy")
        if self.wanted:
            found = [(href, obj) for href, obj in policies if _str(obj.get("name")) == self.wanted]
            if not found:
                raise ParseError(f"--policy: no firewall policy '{_short(self.wanted, 40)}' in the input; it holds "
                                 + ", ".join(sorted(_str(obj.get("name")) or href for href, obj in policies)))  # fmt: skip
            return found[0]
        if len(policies) > 1:
            raise ParseError("the input holds several firewall policies (" + ", ".join(sorted(_str(obj.get("name")) for _, obj in policies))
                             + "); name the one to read with --policy")  # fmt: skip
        return policies[0]

    def _levels(self, href: str, policy: Obj) -> List[Tuple[str, Obj]]:
        """The policy and its templates, the top template first."""
        levels: List[Tuple[str, Obj]] = [(href, policy)]
        current = policy
        seen = {href}
        while True:
            template = _str(current.get("template"))
            if not template:
                break
            if template in seen or len(levels) > _MAX_DEPTH:
                raise ParseError("the templates of the policy are based on each other in a circle, or nested too deeply")
            seen.add(template)
            obj = self.source.by_href.get(template)
            if obj is None:
                self.templates_missing.append(template)
                self.tail_families.update((4, 6))
                break
            levels.append((template, obj))
            current = obj
        return list(reversed(levels))

    def _entries(self, level: Obj, rel: str) -> Optional[List[Tuple[Obj, str]]]:
        """The entries of one rule list of a policy, template or sub-policy; None when the input does not hold it."""
        where = _link(level, rel)
        if not where or where not in self.source.lists:
            if level.get("system") is not True:
                self.missing.append(f"the list {rel} of '{_short(_str(level.get('name')), 40)}'")
            return None
        out: List[Tuple[Obj, str]] = []
        for href in self.source.lists[where]:
            obj = self.source.by_href.get(href)
            if obj is None:
                self.missing.append(f"rule {href}")
                obj = {"fwshift_missing": href}
            out.append((obj, href))
        return out

    @staticmethod
    def _insert_point(obj: Obj) -> bool:
        return obj.get("type") in ("normal", "automatic") and "action" not in obj and "sources" not in obj

    def _effective(self, levels: List[Tuple[str, Obj]], rel: str, family: int) -> List[Tuple[Obj, str]]:
        """The entries of a rule list in the order the engine sees them: insert points replaced by the level below.

        A level whose list the input does not hold is left out: the rules of the level below then stand alone. For
        access rules of a template, the rules of the predefined template below its insert point are assumed."""
        lists: List[List[Tuple[Obj, str]]] = []
        for number, (_, level) in enumerate(levels):
            found = self._entries(level, rel)
            if found is not None:
                lists.append(found)
            elif number < len(levels) - 1 and "access" in rel:
                self.tail_families.add(family)
        if not lists:
            return []
        placed: Set[str] = set()
        parent: Dict[str, str] = {}
        for index in range(1, len(lists)):
            # Rules that name no insert point (the input does not say): the only insert point of the level above takes them.
            points = [h for o, h in lists[index - 1] if self._insert_point(o) and o.get("type") == "normal"]
            for obj, href in lists[index]:
                parent[href] = _str(obj.get("parent_insert_point")) or (points[0] if len(points) == 1 else "")

        def expand(index: int, entries: List[Tuple[Obj, str]]) -> List[Tuple[Obj, str]]:
            out: List[Tuple[Obj, str]] = []
            for obj, href in entries:
                if not self._insert_point(obj):
                    out.append((obj, href))
                    placed.add(href)
                    continue
                if obj.get("type") == "automatic":
                    self.automatic += 1
                    continue
                if index + 1 < len(lists):
                    below = [(o, h) for o, h in lists[index + 1] if parent.get(h) == href]
                    out += expand(index + 1, below)
                    placed.update(h for _, h in below)
            return out

        out = expand(0, lists[0])
        lost = [(o, h) for level in lists for o, h in level if h not in placed and not self._insert_point(o)]
        if lost:
            self.placed_last += [_str(o.get("name")) or f"Rule @{_str(o.get('tag'))}" for o, _ in lost]
            out += lost
        return out

    def _template_tail(self, family: int) -> List[Rule]:
        """What the predefined Firewall Template does below its insert point, where the input does not hold it."""
        out: List[Rule] = []
        ident = self._service_object("Ident", [ServiceEntry(Protocol.TCP, "113")], "the Ident service of the SMC")
        literal = ANY_V4 if family == 4 else ANY_V6
        for name, action, services in (("Refuse Ident", Action.RESET_CLIENT, [ident]), ("Discard all", Action.DROP, [ANY])):
            rule = Rule(name=self._unique(f"Firewall Template: {name}" + (" (IPv6)" if family == 6 else ""), self.rule_names))
            rule.origin = rule.name
            rule.sources, rule.services, rule.action = [literal], list(services), action
            rule.log_start = True
            rule.description = "a rule of the predefined Firewall Template, which the input does not hold"
            self.report.add("rule", rule.origin, Severity.REVIEW, "TEMPLATE_RULE_ASSUMED",
                            "the access rules of the template of the policy are not in the input: this rule stands for what the predefined "
                            "Firewall Template does below its insert point, as Forcepoint documents it")  # fmt: skip
            out.append(rule)
        return out

    # -- access rules ---------------------------------------------------------------------------------

    def _unique(self, name: str, taken: Set[str]) -> str:
        name = " ".join(name.split()) or "unnamed"
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name} {counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    @staticmethod
    def _section(obj: Obj) -> bool:
        return "action" not in obj and not any(key in obj for key in ("sources", "destinations", "services")) and "fwshift_missing" not in obj

    def _access(self, entries: List[Tuple[Obj, str]], family: int, stack: List[str],
                inherited: Optional[List[Tuple[Obj, str]]] = None) -> List[Rule]:
        out: List[Rule] = []
        section = ""
        continues: List[Tuple[Obj, str]] = list(inherited or [])
        for obj, href in entries:
            if "fwshift_missing" in obj:
                rule = Rule(name=self._unique(f"Rule {href.rsplit('/', 1)[-1]}", self.rule_names), action=Action.DROP)
                rule.origin = rule.name
                rule.unsupported.append("the rule is not in the input")
                out.append(rule)
                continue
            if self._insert_point(obj):
                continue
            if self._section(obj):
                section = _str(obj.get("comment")) or _str(obj.get("name"))
                continue
            verbs = self._verbs(obj)
            if verbs == ["continue"]:
                if obj.get("is_disabled") is not True:
                    continues.append((obj, href))
                    self.continues.append(_str(obj.get("name")) or f"Rule @{_str(obj.get('tag'))}")
                continue
            out += self._rule(obj, href, family, section, continues, stack)
        return out

    @staticmethod
    def _verbs(obj: Obj) -> List[str]:
        action = _dict(obj.get("action"))
        value = action.get("action")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        return []

    def _rule(self, obj: Obj, href: str, family: int, section: str, continues: List[Tuple[Obj, str]], stack: List[str]) -> List[Rule]:
        tag = _str(obj.get("tag"))
        label = _str(obj.get("name")) or f"Rule @{tag}"
        name = self._unique(label, self.rule_names)
        base = Rule(name=name, origin=name)
        base.enabled = obj.get("is_disabled") is not True
        base.description = _str(obj.get("comment"))
        if section:
            base.tags = [section]
        base.source_ids = {"forcepoint.rule_href": href}
        if tag:
            base.source_ids["forcepoint.rule_tag"] = tag
        verbs = self._verbs(obj)
        jump = "jump" in verbs
        decisive = [verb for verb in verbs if verb in _DECIDING]
        unknown = [verb for verb in verbs if verb not in _DECIDING and verb not in _NOT_CONVERTED and verb not in ("jump", "continue")]
        base.action = _DECIDING[decisive[0]] if decisive else Action.DROP
        for verb in verbs:
            if verb in _NOT_CONVERTED:
                base.unsupported.append(f"it has {_NOT_CONVERTED[verb]}")
        if unknown or not verbs:
            base.unsupported.append(f"its action ({', '.join(unknown) or 'none'}) is none FWShift knows")
        if "refuse" in decisive:
            self.report.add("rule", name, Severity.APPROX, "REFUSE_ACTION",
                            "Refuse answers the sender with an ICMP error (whether a TCP connection gets a reset is not "
                            "documented); converted as a reset to the client")  # fmt: skip
        action = _dict(obj.get("action"))
        self._handling(base, action, name)
        self._logging(base, obj, continues)
        validity = [self._element_name(h) for h in obj.get("rule_validity_times") or [] if isinstance(h, str)]
        if validity:
            base.schedule = ", ".join(validity)
        vpn = _dict(obj.get("match_vpn_options"))
        kind = _str(vpn.get("match_type"))
        if kind in ("normal", "mobile_vpn"):
            base.unsupported.append("it matches traffic of VPNs only (Source VPN)")
        elif kind == "no_vpn":
            self.no_vpn.append(name)
        elif kind:
            base.unsupported.append(f"a Source VPN match '{_short(kind, 20)}'")
        auth = _dict(obj.get("authentication_options"))
        users = [self._element_name(h) for h in auth.get("users") or [] if isinstance(h, str)]
        if auth.get("require_auth") is True or users:
            base.users = users or ["(authenticated users)"]
            if auth.get("methods"):
                base.handling["authentication"] = ", ".join(self._element_name(h) for h in auth["methods"] if isinstance(h, str))
        cells: Dict[str, Optional[List[_Cell]]] = {}
        problems: List[str] = []
        for key, what in (("sources", "source"), ("destinations", "destination"), ("services", "service")):
            cells[key] = self._cell(obj.get(key), what, problems)
        if any(cells[key] is None for key in cells):
            # A cell with NONE: the engine ignores the rule.
            base.enabled = False
            self.none_cells.append(name)
            cells = {key: value if value is not None else [_Cell()] for key, value in cells.items()}
        base.unsupported += problems
        copies = self._copies(base, cells["sources"] or [_Cell()], cells["destinations"] or [_Cell()], cells["services"] or [_Cell()], family)
        if not jump:
            return copies
        target = _str(action.get("sub_policy"))
        # The Continue rules above the jump rule hold in the sub-policy too, for what the jump rule matches.
        reaching = [(other, other_href) for other, other_href in continues if self._may_overlap(other, obj)]
        inner = self._sub_policy(target, family, stack + [href], reaching) if target else None
        if inner is None:
            for rule in copies:
                rule.unsupported.append("it jumps to a sub-policy the input does not hold" if target else "it jumps to no sub-policy")
                rule.action = Action.DROP
            return copies
        out: List[Rule] = []
        for parent in copies:
            for child in inner:
                combined = self._combine(parent, child)
                if combined is not None:
                    out.append(combined)
        if copies and not out:
            self.report.add("rule", name, Severity.INFO, "JUMP_EMPTY", "nothing the sub-policy holds matches what the jump rule does")
        return out

    def _sub_policy(self, href: str, family: int, stack: List[str], continues: List[Tuple[Obj, str]]) -> Optional[List[Rule]]:
        if href in stack or len(stack) > _MAX_DEPTH:
            raise ParseError("sub-policies jump to each other in a circle, or are nested too deeply")
        obj = self.source.by_href.get(href)
        if obj is None:
            self.missing.append(f"sub-policy {href}")
            return None
        rel = "fw_ipv4_access_rules" if family == 4 else "fw_ipv6_access_rules"
        entries = self._entries(obj, rel)
        if entries is None:
            return None
        return self._access(entries, family, stack + [href], continues)

    def _handling(self, rule: Rule, action: Obj, name: str) -> None:
        for key in ("deep_inspection", "file_filtering", "decrypting", "dos_protection"):
            if action.get(key) is True:
                rule.profiles[key] = "on"
        if _str(action.get("forward_to")) or action.get("forward_to"):
            rule.handling["forward_to"] = str(action.get("forward_to"))[:80]
            self.report.add("rule", name, Severity.INFO, "FORWARD_TO",
                            "the rule forwards what it allows to a host or proxy, which the NAT rules then do not see; not converted")  # fmt: skip
        tracking = _dict(action.get("connection_tracking_options"))
        for key in ("src_limit", "dst_limit"):
            value = tracking.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                rule.handling[key] = str(value)
                self.report.add("rule", name, Severity.APPROX, "CONNECTION_LIMIT",
                                f"the rule limits concurrent connections ({key} {value}): connections beyond it are refused "
                                "or discarded, which is not converted")  # fmt: skip
        if _str(tracking.get("state")) in ("no", "loose", "strict"):
            rule.handling["connection_tracking"] = _str(tracking.get("state"))

    def _logging(self, rule: Rule, obj: Obj, continues: List[Tuple[Obj, str]]) -> None:
        options = _dict(obj.get("options"))
        level = _str(options.get("log_level")) or "undefined"
        closing = options.get("log_closing_mode") is True or options.get("log_accounting_info_mode") is True
        if level == "undefined":
            for other, _ in reversed(continues):
                if self._may_overlap(other, obj):
                    inherited = _dict(other.get("options"))
                    level = _str(inherited.get("log_level")) or "undefined"
                    closing = closing or inherited.get("log_closing_mode") is True
                    if level != "undefined":
                        break
        rule.log_start = level in _LOGGED
        rule.log_end = closing and level not in ("none", "undefined")
        if level == "transient":
            rule.handling["log_level"] = "transient"

    def _may_overlap(self, first: Obj, second: Obj) -> bool:
        """Whether two rules may match the same traffic, by their cells: True unless a cell of each is known to be apart."""
        for key in ("sources", "destinations"):
            a, b = self._cell_intervals(first.get(key)), self._cell_intervals(second.get(key))
            if a is not None and b is not None and not intersect(a, b):
                return False
        a_entries, b_entries = self._cell_entries(first.get("services")), self._cell_entries(second.get("services"))
        if a_entries is not None and b_entries is not None:
            return any(self._entries_meet(x, y) for x in a_entries for y in b_entries)
        return True

    def _cell_intervals(self, value: Any) -> Optional[List[Interval]]:
        """The addresses a source or destination cell matches; None for all of them, or not known."""
        if not isinstance(value, dict) or value.get("any") is True or value.get("none") is True:
            return None
        refs = value.get("src") if "src" in value else value.get("dst")
        if not isinstance(refs, list) or not refs:
            return None
        found: List[Interval] = []
        for ref in refs:
            if not isinstance(ref, str):
                return None
            kind = _kind(ref)
            if kind == "match_expression":
                obj = self.source.by_href.get(ref) or {}
                parts = [r for r in obj.get("ref") or [] if isinstance(r, str) and _kind(r) != "interface_zone" and "user" not in _kind(r)]
                if len(parts) != 1:
                    return None
                ref, kind = parts[0], _kind(parts[0])
            if kind == "interface_zone" or "user" in kind:
                return None
            member, problem = self._address(ref, cell=True)
            known, complete = transform.known_intervals(self.p, member) if member and not problem else ([], False)
            if not complete:
                return None
            found += known
        return normalize(found)

    def _cell_entries(self, value: Any) -> Optional[List[ServiceEntry]]:
        """The ports a service cell matches; None for all of them, or not known."""
        if not isinstance(value, dict) or value.get("any") is True or value.get("none") is True:
            return None
        refs = value.get("service")
        if not isinstance(refs, list) or not refs:
            return None
        found: List[ServiceEntry] = []
        for ref in refs:
            if not isinstance(ref, str):
                return None
            kind, name, problem = self._service(ref)
            entries = transform.flatten_services(self.p, name) if kind == "service" and name and not problem else None
            if entries is None:
                return None
            found += entries
        return found

    @staticmethod
    def _entries_meet(first: ServiceEntry, second: ServiceEntry) -> bool:
        if Protocol.IP in (first.protocol, second.protocol):
            numbers = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.ICMP: 1, Protocol.ICMP6: 58}
            a = first.ip_protocol if first.protocol == Protocol.IP else numbers.get(first.protocol)
            b = second.ip_protocol if second.protocol == Protocol.IP else numbers.get(second.protocol)
            return a is None or b is None or a == b
        if first.protocol != second.protocol:
            return False
        if first.protocol in (Protocol.ICMP, Protocol.ICMP6):
            return first.icmp_type is None or second.icmp_type is None or first.icmp_type == second.icmp_type
        return all(_ports_meet(a, b) for a, b in ((first.dst_ports, second.dst_ports), (first.src_ports, second.src_ports)))

    # -- cells ----------------------------------------------------------------------------------------

    def _cell(self, value: Any, what: str, problems: List[str]) -> Optional[List[_Cell]]:
        """The ways a cell matches; None for NONE."""
        if not isinstance(value, dict):
            problems.append(f"its {what} cell cannot be read")
            return [_Cell()]
        if value.get("none") is True:
            return None
        if value.get("any") is True:
            return [_Cell()]
        key = {"source": "src", "destination": "dst", "service": "service"}[what]
        members = value.get(key)
        if not isinstance(members, list) or not members:
            problems.append(f"its {what} cell holds nothing FWShift can read")
            return [_Cell()]
        hrefs = [str(member) for member in members if isinstance(member, str)]
        if len(hrefs) != len(members):
            problems.append(f"its {what} cell holds {len(members) - len(hrefs)} member(s) FWShift cannot read")
        if what == "service":
            return self._service_cell(hrefs, problems)
        return self._address_cell(hrefs, what, problems)

    def _address_cell(self, hrefs: List[str], what: str, problems: List[str]) -> List[_Cell]:
        zones: List[str] = []
        users: List[str] = []
        members: List[str] = []
        rows: List[_Cell] = []
        single_negation: Optional[str] = None
        for href in hrefs:
            kind = _kind(href)
            obj = self.source.by_href.get(href)
            if kind == "interface_zone":
                zones.append(self._zone(href, problems))
            elif kind == "match_expression":
                rows.append(self._row(href, what, problems))
            elif "user" in kind and obj is not None:
                users.append(self._element_name(href))
            elif kind == "expression" and len(hrefs) == 1 and obj is not None and self._lone_exclusion(obj):
                single_negation = href
            else:
                member, problem = self._address(href, cell=True)
                if problem:
                    problems.append(f"{what} '{_short(self._element_name(href), 40)}': {problem}")
                if member:
                    members.append(member)
        out: List[_Cell] = []
        if single_negation is not None:
            obj = self.source.by_href[single_negation]
            operand = str((obj.get("ne_ref") or [""])[0])
            member, problem = self._address(operand, cell=False)  # an element in an expression, not in the cell itself
            if problem:
                problems.append(f"{what} '{_short(self._element_name(single_negation), 40)}': {problem}")
            cell = _Cell()
            cell.members, cell.negated = [member or ANY], True
            return [cell]
        if zones:
            cell = _Cell()
            cell.zones = transform.dedupe(zones)
            out.append(cell)
        if members:
            cell = _Cell()
            cell.members = transform.dedupe(members)
            out.append(cell)
        if users:
            cell = _Cell()
            cell.users = transform.dedupe(users)
            out.append(cell)
        out += rows
        if not out:
            problems.append(f"its {what} cell holds nothing FWShift can read")
        return out or [_Cell()]

    def _row(self, href: str, what: str, problems: List[str]) -> _Cell:
        """A match expression: one row of the cell, whose parts are ANDed."""
        cell = _Cell()
        obj = self.source.by_href.get(href)
        if obj is None:
            self.missing.append(f"match expression {href}")
            problems.append(f"{what}: a match expression that is not in the input")
            return cell
        kinds: Dict[str, List[str]] = {}
        refs = _list(obj.get("ref"))
        if not refs or not all(isinstance(ref, str) for ref in refs):
            problems.append(f"{what}: match expression '{_short(_str(obj.get('name')), 40)}' holds nothing, or what FWShift cannot read")
        for ref in refs:
            if not isinstance(ref, str):
                continue
            kind = _kind(ref)
            part = "zone" if kind == "interface_zone" else "user" if "user" in kind else "service" if self._is_service(kind) else "address"
            kinds.setdefault(part, []).append(ref)
        if any(len(refs) > 1 for refs in kinds.values()):
            problems.append(f"{what}: match expression '{_short(_str(obj.get('name')), 40)}' holds two elements of one kind")
        if "zone" in kinds:
            cell.zones = [self._zone(ref, problems) for ref in kinds["zone"]]
        if "user" in kinds:
            cell.users = [self._element_name(ref) for ref in kinds["user"]]
        if "address" in kinds:
            names = []
            for ref in kinds["address"]:
                member, problem = self._address(ref, cell=True)
                if problem:
                    problems.append(f"{what} '{_short(self._element_name(ref), 40)}': {problem}")
                if member:
                    names.append(member)
            cell.members = names or [ANY]
        if "service" in kinds:
            problems.append(f"{what}: match expression '{_short(_str(obj.get('name')), 40)}' names a service")
        return cell

    @staticmethod
    def _is_service(kind: str) -> bool:
        return kind.endswith("_service") or kind in _SERVICE_GROUPS or kind in ("application_situation", "url_category", "url_category_group")

    def _service_cell(self, hrefs: List[str], problems: List[str]) -> List[_Cell]:
        services: List[str] = []
        applications: List[str] = []
        urls: List[str] = []
        for href in hrefs:
            kind, name, problem = self._service(href)
            if problem:
                problems.append(f"service '{_short(self._element_name(href), 40)}': {problem}")
            if kind == "service" and name:
                services.append(name)
            elif kind == "application":
                applications.append(name)
            elif kind == "url":
                urls.append(name)
        out: List[_Cell] = []
        if services:
            cell = _Cell()
            cell.services = transform.dedupe(services)
            out.append(cell)
        if applications:
            cell = _Cell()
            cell.applications = transform.dedupe(applications)
            out.append(cell)
        if urls:
            cell = _Cell()
            cell.urls = transform.dedupe(urls)
            out.append(cell)
        if not out:
            problems.append("its service cell holds nothing FWShift can read")
        return out or [_Cell()]

    def _copies(self, base: Rule, sources: List[_Cell], destinations: List[_Cell], services: List[_Cell], family: int) -> List[Rule]:
        combos = [(s, d, v) for s in sources for d in destinations for v in services]
        if len(combos) > _MAX_COPIES:
            base.unsupported.append(f"its cells hold zones, addresses, users and applications in {len(combos)} combinations")
            combos = combos[:1]
        out: List[Rule] = []
        for number, (s, d, v) in enumerate(combos):
            rule = Rule(name=base.name)
            for key, value in vars(base).items():
                if key != "name":
                    setattr(rule, key, value if not isinstance(value, (list, dict)) else type(value)(value))
            if number:
                rule.name = rule.origin = self._unique(f"{base.name} ({number + 1})", self.rule_names)
            rule.src_zones, rule.sources, rule.negate_source = list(s.zones), list(s.members), s.negated
            rule.dst_zones, rule.destinations, rule.negate_destination = list(d.zones), list(d.members), d.negated
            users = s.users if s.users != [ANY] else d.users
            if s.users != [ANY] or d.users != [ANY]:
                rule.users = list(users)
            rule.services, rule.applications, rule.url_categories = list(v.services), list(v.applications), list(v.urls)
            self._pin(rule, family)
            out.append(rule)
        if len(out) > 1:
            self.report.add("rule", base.origin, Severity.INFO, "RULE_SPLIT",
                            f"the cells hold zones, addresses, users or applications side by side (ORed): the rule is "
                            f"{len(out)} rules, one per combination")  # fmt: skip
        return out

    def _pin(self, rule: Rule, family: int) -> None:
        """Say in the rule itself which IP version it is for: in the model "any" is both."""
        literal = ANY_V4 if family == 4 else ANY_V6
        if rule.sources == [ANY] and not rule.negate_source:
            rule.sources = [literal]
            return
        if rule.destinations == [ANY] and not rule.negate_destination:
            rule.destinations = [literal]
            return
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            if not negated and all(transform.families(self.p, member) == {family} for member in members):
                return
        for attribute, flag in (("sources", "negate_source"), ("destinations", "negate_destination")):
            members = getattr(rule, attribute)
            if getattr(rule, flag):
                continue
            views = [self._view(member, family) for member in members]
            if all(views):
                setattr(rule, attribute, transform.dedupe([view for view in views if view]))
                return
        for attribute, flag in (("sources", "negate_source"), ("destinations", "negate_destination")):
            # A negated side: what it leaves of the addresses of this IP version, as a group of ranges.
            members = getattr(rule, attribute)
            known = self._static(members) if getattr(rule, flag) else None
            if known is None:
                continue
            rest = subtract([FULL_V4 if family == 4 else FULL_V6], [i for i in known if i[0] == family])
            key = ("not " + "\n".join(members), family)
            if key not in self.views:
                name = self._object_name(f"not {', '.join(members)} IPv{family}", self.names)
                self.p.address_groups[name] = AddressGroup(name, [interval_text(i) for i in rest],
                                                           f"the IPv{family} addresses outside {', '.join(members)}")  # fmt: skip
                self.views[key] = name
            setattr(rule, attribute, [self.views[key]])
            setattr(rule, flag, False)
            return
        self.report.add("rule", rule.origin, Severity.APPROX, "IP_FAMILY",
                        f"a rule of the IPv{family} list whose addresses do not say so (host names, or both sides "
                        f"negated): here it also matches IPv{10 - family} traffic of the same names")  # fmt: skip

    def _view(self, member: str, family: int) -> Optional[str]:
        """The addresses of one IP version of a member, as an object; None when it has none, or cannot be cut."""
        families = transform.families(self.p, member)
        if families == {family}:
            return member
        intervals, complete = transform.known_intervals(self.p, member)
        if not complete:
            return None
        kept = [i for i in intervals if i[0] == family]
        if not kept:
            return None
        key = (member, family)
        if key not in self.views:
            # A name of its own: an element of the SMC may be called so already.
            name = self._object_name(f"{member} IPv{family}", self.names)
            self.p.address_groups[name] = AddressGroup(name, [interval_text(i) for i in normalize(kept)], f"the IPv{family} addresses of {member}")
            self.views[key] = name
        return self.views[key]

    # -- a jump: the rules of a sub-policy, limited to what the jump rule matches ---------------------

    def _static(self, members: List[str]) -> Optional[List[Interval]]:
        intervals: List[Interval] = []
        for member in members:
            known, complete = transform.known_intervals(self.p, member)
            if not complete:
                return None
            intervals += known
        return normalize(intervals)

    def _both(self, outer: List[str], outer_negated: bool, inner: List[str], inner_negated: bool) -> Tuple[Optional[List[str]], bool, bool]:
        """Addresses two lists match at once: (members, negated, expressible); None matches nothing."""
        if outer in ([ANY], [ANY_V4], [ANY_V6]) and not outer_negated and (inner != [ANY] or outer == [ANY]):
            if outer == [ANY] or inner_negated or inner == [ANY]:
                return (list(inner) if inner != [ANY] else list(outer)), inner_negated, True
        if inner in ([ANY], [ANY_V4], [ANY_V6]) and not inner_negated and not outer_negated and inner == [ANY]:
            return list(outer), outer_negated, True
        if not outer_negated and not inner_negated and set(outer) == set(inner):
            return list(inner), False, True
        if outer_negated and inner_negated:
            return transform.dedupe(outer + inner), True, True
        first, second = self._static(outer), self._static(inner)
        if first is None or second is None:
            return list(inner), inner_negated, False
        if outer_negated:
            first = subtract([FULL_V4, FULL_V6], first)
        if inner_negated:
            second = subtract([FULL_V4, FULL_V6], second)
        common = intersect(first, second)
        if not common:
            return None, False, True
        if not inner_negated and common == normalize(second):
            return list(inner), False, True
        if not outer_negated and common == normalize(first):
            return list(outer), False, True
        return [interval_text(i) for i in common], False, True

    def _combine(self, parent: Rule, child: Rule) -> Optional[Rule]:
        out = Rule(name=self._unique(f"{parent.name} / {child.name}", self.rule_names))
        out.origin = child.origin if child.origin else out.name
        out.action, out.log_start, out.log_end = child.action, child.log_start, child.log_end
        out.description, out.tags = child.description, child.tags or parent.tags
        out.enabled = parent.enabled and child.enabled
        out.unsupported = transform.dedupe(parent.unsupported + child.unsupported)
        out.schedule = ", ".join(s for s in (parent.schedule, child.schedule) if s)
        out.profiles = {**parent.profiles, **child.profiles}
        out.handling = {**parent.handling, **child.handling}
        out.source_ids = dict(child.source_ids)
        if "forcepoint.rule_href" in parent.source_ids:
            out.source_ids["forcepoint.jump_href"] = parent.source_ids["forcepoint.rule_href"]
        for attribute in ("src_zones", "dst_zones", "users", "applications", "url_categories"):
            outer, inner = getattr(parent, attribute), getattr(child, attribute)
            if outer == [ANY]:
                value = list(inner)
            elif inner == [ANY] or set(inner) == set(outer):
                value = list(outer)
            elif attribute.endswith("zones"):
                value = [item for item in inner if item in outer]
                if not value:
                    return None
            else:
                value = list(inner)
                out.unsupported.append(f"{attribute.replace('_', ' ')} limited both by the jump rule and by the rule of the sub-policy")
            setattr(out, attribute, value)
        for attribute, flag in (("sources", "negate_source"), ("destinations", "negate_destination")):
            members, negated, expressible = self._both(getattr(parent, attribute), getattr(parent, flag), getattr(child, attribute), getattr(child, flag))
            if members is None:
                return None
            if not expressible:
                out.unsupported.append(f"{attribute[:-1]} limited both by the jump rule and by the rule of the sub-policy")
            setattr(out, attribute, members)
            setattr(out, flag, negated)
        if parent.services == [ANY]:
            out.services = list(child.services)
        elif child.services == [ANY] or set(child.services) == set(parent.services):
            out.services = list(parent.services)
        elif self._services_within(child.services, parent.services):
            out.services = list(child.services)
        elif self._services_within(parent.services, child.services):
            out.services = list(parent.services)
        else:
            out.services = list(child.services)
            out.unsupported.append("service limited both by the jump rule and by the rule of the sub-policy")
        if out.name != out.origin:
            self.report.add("rule", out.origin, Severity.INFO, "JUMP_FLATTENED",
                            f"a rule of a sub-policy, reached by the jump rule '{_short(parent.name, 40)}': it is that rule "
                            "limited to what the jump rule matches")  # fmt: skip
        return out

    def _services_within(self, inner: List[str], outer: List[str]) -> bool:
        """Whether everything the services ``inner`` match, ``outer`` matches too (ports of TCP, UDP and SCTP only)."""
        ranges: List[Dict[Tuple[str, Optional[int]], List[Tuple[int, int]]]] = []
        for services in (inner, outer):
            found: Dict[Tuple[str, Optional[int]], List[Tuple[int, int]]] = {}
            for service in services:
                entries = transform.flatten_services(self.p, service)
                if entries is None:
                    return False
                for entry in entries:
                    if entry.src_ports:
                        return False
                    key = (entry.protocol.value, entry.ip_protocol if entry.protocol == Protocol.IP else entry.icmp_type)
                    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6, Protocol.IP):
                        if entry.icmp_code is not None:
                            return False
                        found.setdefault(key, []).append((0, 0))
                        continue
                    for part in (entry.dst_ports or "1-65535").split(","):
                        first, _, last = part.partition("-")
                        found.setdefault(key, []).append((int(first), int(last or first)))
            ranges.append(found)
        return all(
            any(low <= first and last <= high for low, high in ranges[1].get(key, []))
            or (key[0] in ("icmp", "icmp6") and any(low <= first and last <= high for low, high in ranges[1].get((key[0], None), [])))
            for key, parts in ranges[0].items()
            for first, last in parts
        )

    # -- elements -------------------------------------------------------------------------------------

    def _element_name(self, href: str) -> str:
        obj = self.source.by_href.get(href)
        name = _str(obj.get("name")) if obj is not None else ""
        return name or href.rsplit("/", 1)[-1]

    def _zone(self, href: str, problems: List[str]) -> str:
        obj = self.source.by_href.get(href)
        if obj is None:
            self.missing.append(f"zone {href}")
            problems.append(f"zone {href.rsplit('/', 1)[-1]} is not in the input")
        name = self._element_name(href)
        self.p.zones.setdefault(name, Zone(name, []))
        return name

    def _object_name(self, base: str, taken: Set[str]) -> str:
        return self._unique(base or "unnamed", taken)

    def _placeholder(self, href: str, why: str) -> Tuple[str, str]:
        name = self._object_name(self._element_name(href), self.names)
        self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=why)
        return name, why

    def _address(self, href: str, cell: bool) -> Tuple[str, str]:
        """(member, problem) for an address element; a member that cannot be converted is a placeholder."""
        key = (href, cell)
        if key in self.addresses:
            return self.addresses[key]
        if (href, not cell) in self.addresses and not self._broadcast_differs(href):
            self.addresses[key] = self.addresses[(href, not cell)]
            return self.addresses[key]
        self.addresses[key] = ("", "an element that holds itself")  # until it is read, for a group in a circle
        self.addresses[key] = self._read_address(href, cell)
        return self.addresses[key]

    def _broadcast_differs(self, href: str) -> bool:
        obj = self.source.by_href.get(href)
        return obj is not None and _kind(href) == "network" and obj.get("broadcast") is False and bool(_str(obj.get("ipv4_network")))

    def _read_address(self, href: str, cell: bool) -> Tuple[str, str]:
        kind = _kind(href)
        obj = self.source.by_href.get(href)
        if obj is None:
            self.missing.append(f"{kind or 'element'} {href}")
            return self._placeholder(href, "an element the input does not hold")
        name = _str(obj.get("name")) or href.rsplit("/", 1)[-1]
        if kind in ("host", "router"):
            values = [v for v in (_str(obj.get("address")), _str(obj.get("ipv6_address"))) if v]
            values += [str(v) for v in obj.get("secondary") or [] if isinstance(v, str)]
            literals = []
            for value in values:
                try:
                    literals.append(str(ipaddress.ip_address(value)))
                except ValueError:
                    return self._placeholder(href, f"the address '{_short(value, 40)}' cannot be read")
            if not literals:
                return self._placeholder(href, "a host without an address")
            return self._literals(name, literals, _str(obj.get("comment"))), ""
        if kind == "network":
            literals = []
            for field_name in ("ipv4_network", "ipv6_network"):
                value = _str(obj.get(field_name))
                if not value:
                    continue
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError:
                    return self._placeholder(href, f"the network '{_short(value, 40)}' cannot be read")
                if cell and network.version == 4 and obj.get("broadcast") is False and network.prefixlen <= 30:
                    # Without "broadcast" the network in a rule cell leaves out its network and broadcast addresses.
                    literals.append(f"{network.network_address + 1}-{network.broadcast_address - 1}")
                else:
                    literals.append(str(network))
            if not literals:
                return self._placeholder(href, "a network without an address")
            suffix = " (in rules)" if cell and self._broadcast_differs(href) else ""
            return self._literals(name + suffix, literals, _str(obj.get("comment"))), ""
        if kind == "address_range":
            value = _str(obj.get("ip_range"))
            interval = parse_literal(value)
            if interval is None or "-" not in value:
                return self._placeholder(href, f"the range '{_short(value, 40)}' cannot be read")
            return self._literals(name, [value.replace(" ", "")], _str(obj.get("comment"))), ""
        if kind == "group":
            members: List[str] = []
            problems: List[str] = []
            for ref in obj.get("element") or []:
                if not isinstance(ref, str):
                    continue
                if _kind(ref) in ("interface_zone",) or "user" in _kind(ref):
                    problems.append(f"it holds '{_short(self._element_name(ref), 40)}', which is not an address")
                    continue
                if self._broadcast_differs(ref):
                    self.broadcast_in_groups.append(name)
                member, problem = self._address(ref, cell=False)
                if problem:
                    problems.append(problem)
                if member and member not in members:
                    members.append(member)
            group_name = self._object_name(name, self.names)
            group = AddressGroup(group_name, members, _str(obj.get("comment")))
            if problems:
                group.unsupported = f"{problems[0]}"
            if not members and not problems:
                group.unsupported = "an empty group, which matches nothing"
            self.p.address_groups[group_name] = group
            return group_name, ""
        if kind == "expression":
            intervals, problem = self._expression(obj, [href])
            if intervals is None:
                return self._placeholder(href, problem)
            group_name = self._object_name(name, self.names)
            group = AddressGroup(group_name, [interval_text(i) for i in intervals], (_str(obj.get("comment")) + " " if obj.get("comment") else "")
                                 + "(the addresses of the expression)")  # fmt: skip
            if not intervals:
                group.unsupported = "an expression that holds no address"
            self.p.address_groups[group_name] = group
            return group_name, ""
        if kind == "domain_name":
            hosts = [name] + [str(entry.get("name") if isinstance(entry, dict) else entry) for entry in obj.get("domain_name_entry") or []]
            hosts = [host.strip().rstrip(".").lower() for host in hosts if isinstance(host, str) and host.strip()]
            names = []
            for host in transform.dedupe(hosts):
                object_name = self._object_name(host, self.names)
                self.p.addresses[object_name] = Address(object_name, AddressKind.FQDN, host, _str(obj.get("comment")))
                names.append(object_name)
            if len(names) == 1:
                return names[0], ""
            group_name = self._object_name(name + " (names)", self.names)
            self.p.address_groups[group_name] = AddressGroup(group_name, names, "the names of domain name " + name)
            return group_name, ""
        if kind.endswith("alias") or kind == "alias":
            return self._placeholder(href, "an alias, whose value is set per engine, and the input holds no engine")
        if kind in ("ip_list", "country", "ip_country_group"):
            return self._placeholder(href, f"a {kind.replace('_', ' ')}, whose addresses are not in the input")
        if kind in _ENGINES:
            self.engines.add(name)
            return self._placeholder(href, "an engine (its addresses are those of its interfaces, which the input does not hold)")
        return self._placeholder(href, f"an element of type '{_short(kind, 30)}', which FWShift does not read")

    def _literals(self, name: str, literals: List[str], description: str) -> str:
        if len(literals) == 1:
            object_name = self._object_name(name, self.names)
            interval = parse_literal(literals[0])
            kind = AddressKind.RANGE if "-" in literals[0] else AddressKind.NETWORK
            value = literals[0]
            if interval is not None and kind == AddressKind.NETWORK and "/" not in value:
                value = f"{value}/{32 if interval[0] == 4 else 128}"
            self.p.addresses[object_name] = Address(object_name, kind, value, description)
            return object_name
        group_name = self._object_name(name, self.names)
        self.p.address_groups[group_name] = AddressGroup(group_name, transform.dedupe(literals), description)
        return group_name

    @staticmethod
    def _lone_exclusion(obj: Obj) -> bool:
        refs = [ref for ref in obj.get("ne_ref") or [] if isinstance(ref, str)]
        return _str(obj.get("operator")) == "exclusion" and len(refs) == 1 and not obj.get("sub_expression")

    def _expression(self, obj: Obj, stack: List[str]) -> Tuple[Optional[List[Interval]], str]:
        """The addresses of an expression, both IP versions; (None, why) when they cannot be worked out."""
        if len(stack) > _MAX_DEPTH:
            return None, "expressions nested too deeply"
        operator = _str(obj.get("operator")) or "none"
        operands: List[List[Interval]] = []
        for ref in obj.get("ne_ref") or []:
            if not isinstance(ref, str):
                continue
            if ref in stack:
                return None, "an expression that holds itself"
            found, problem = self._intervals(ref, stack + [ref])
            if found is None:
                return None, problem
            operands.append(found)
        for inner in obj.get("sub_expression") or []:
            if not isinstance(inner, dict):
                return None, "a part of the expression cannot be read"
            found, problem = self._expression(inner, stack + ["sub"])
            if found is None:
                return None, problem
            operands.append(found)
        if not operands:
            return None, "an expression with nothing in it"
        if operator in ("none", "union"):
            if operator == "none" and len(operands) > 1:
                return None, "an expression without an operator that combines several elements"
            return normalize([i for part in operands for i in part]), ""
        if operator == "intersection":
            result = operands[0]
            for part in operands[1:]:
                result = intersect(result, part)
            return normalize(result), ""
        if operator == "exclusion":
            if len(operands) > 1:
                return None, "an exclusion of several elements, whose meaning Forcepoint does not document"
            return subtract([FULL_V4, FULL_V6], operands[0]), ""
        return None, f"an expression with the operator '{_short(operator, 20)}'"

    def _intervals(self, href: str, stack: List[str]) -> Tuple[Optional[List[Interval]], str]:
        kind = _kind(href)
        obj = self.source.by_href.get(href)
        if obj is None:
            self.missing.append(f"{kind or 'element'} {href}")
            return None, "it holds an element the input does not hold"
        if kind == "expression":
            return self._expression(obj, stack)
        if kind in ("host", "router", "network", "address_range", "group"):
            member, problem = self._address(href, cell=False)
            if problem:
                return None, problem
            intervals, complete = transform.known_intervals(self.p, member)
            if not complete:
                return None, f"it holds '{_short(self._element_name(href), 40)}', whose addresses are not all known"
            return normalize(intervals), ""
        return None, f"it holds '{_short(self._element_name(href), 40)}' of type '{_short(kind, 30)}', which has no addresses FWShift knows"

    # -- services -------------------------------------------------------------------------------------

    def _service_object(self, name: str, entries: List[ServiceEntry], description: str = "") -> str:
        for existing in self.p.services.values():
            if existing.name.split(" (")[0] == name and existing.entries == entries:
                return existing.name
        object_name = self._object_name(name, self.service_names)
        self.p.services[object_name] = Service(object_name, entries, description)
        return object_name

    def _service(self, href: str) -> Tuple[str, str, str]:
        """(kind, name, problem): kind "service", "application" or "url"."""
        if href in self.services:
            return self.services[href]
        self.services[href] = ("service", "", "a service group that holds itself")
        self.services[href] = self._read_service(href)
        return self.services[href]

    def _unusable_service(self, href: str, why: str) -> Tuple[str, str, str]:
        name = self._object_name(self._element_name(href), self.service_names)
        self.p.services[name] = Service(name, [], unsupported=why)
        return "service", name, why

    def _read_service(self, href: str) -> Tuple[str, str, str]:
        kind = _kind(href)
        obj = self.source.by_href.get(href)
        if obj is None:
            self.missing.append(f"{kind or 'service'} {href}")
            return self._unusable_service(href, "a service the input does not hold")
        name = _str(obj.get("name")) or href.rsplit("/", 1)[-1]
        description = _str(obj.get("comment"))
        if obj.get("protocol_agent_ref"):
            description = (description + " " if description else "") + "(with a protocol agent)"
        if kind in ("tcp_service", "udp_service"):
            protocol = Protocol.TCP if kind == "tcp_service" else Protocol.UDP
            ports = []
            for low_key, high_key in (("min_dst_port", "max_dst_port"), ("min_src_port", "max_src_port")):
                low, high = _port(obj.get(low_key)), _port(obj.get(high_key))
                if low is None and obj.get(low_key) not in (None, ""):
                    return self._unusable_service(href, f"the port '{_short(str(obj.get(low_key)), 20)}' cannot be read")
                if low is None and high is not None:
                    return self._unusable_service(href, f"a range of ports up to {high} without its first port")
                if low is None:
                    ports.append("")
                    continue
                high = low if high is None or high == 0 else high
                if not (0 <= low <= high <= 65535):
                    return self._unusable_service(href, f"the ports {low}-{high} cannot be read")
                low = max(low, 1)
                if high < low:
                    return self._unusable_service(href, "port 0, which no connection has")
                ports.append("" if (low, high) == (1, 65535) else str(low) if low == high else f"{low}-{high}")
            entry = ServiceEntry(protocol, ports[0], ports[1])
            object_name = self._object_name(name, self.service_names)
            self.p.services[object_name] = Service(object_name, [entry], description, builtin="forcepoint" if obj.get("system") is True else "")
            return "service", object_name, ""
        if kind in ("icmp_service", "icmp_ipv6_service"):
            protocol = Protocol.ICMP if kind == "icmp_service" else Protocol.ICMP6
            icmp_type, code = obj.get("icmp_type"), obj.get("icmp_code")
            if not isinstance(icmp_type, int) or isinstance(icmp_type, bool) or not 0 <= icmp_type <= 255:
                return self._unusable_service(href, "an ICMP service without a type FWShift can read")
            if code is not None and (not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255):
                return self._unusable_service(href, "an ICMP code FWShift cannot read")
            object_name = self._object_name(name, self.service_names)
            self.p.services[object_name] = Service(object_name, [ServiceEntry(protocol, icmp_type=icmp_type, icmp_code=code)], description)
            return "service", object_name, ""
        if kind == "ip_service":
            number = _port(obj.get("protocol_number"))
            if number is None or not 0 <= number <= 255:
                return self._unusable_service(href, "an IP service without a protocol number")
            entry = {6: ServiceEntry(Protocol.TCP), 17: ServiceEntry(Protocol.UDP), 1: ServiceEntry(Protocol.ICMP),
                     58: ServiceEntry(Protocol.ICMP6)}.get(number, ServiceEntry(Protocol.IP, ip_protocol=number))  # fmt: skip
            object_name = self._object_name(name, self.service_names)
            self.p.services[object_name] = Service(object_name, [entry], description)
            return "service", object_name, ""
        if kind in _SERVICE_GROUPS:
            members: List[str] = []
            problems: List[str] = []
            for ref in obj.get("element") or []:
                if not isinstance(ref, str):
                    continue
                inner_kind, member, problem = self._service(ref)
                if inner_kind != "service":
                    problems.append(f"it holds '{_short(self._element_name(ref), 40)}', which is no service of ports")
                elif member:
                    members.append(member)
                if problem:
                    problems.append(problem)
            object_name = self._object_name(name, self.service_names)
            self.p.service_groups[object_name] = ServiceGroup(object_name, transform.dedupe(members), description)
            if problems or not members:
                stand_in = self._unusable_service(href, problems[0] if problems else "an empty group, which matches nothing")
                self.p.service_groups[object_name].members.append(stand_in[1])
            return "service", object_name, ""
        if kind == "application_situation":
            return "application", name, ""
        if kind in ("url_category", "url_category_group"):
            return "url", name, ""
        return self._unusable_service(href, f"an element of type '{_short(kind, 30)}', which FWShift does not read as a service")

    # -- NAT ------------------------------------------------------------------------------------------

    def _nat(self, obj: Obj, href: str, family: int) -> Optional[NatRule]:
        if "fwshift_missing" in obj:
            nat = NatRule(name=self._unique(f"NAT rule {href.rsplit('/', 1)[-1]}", self.nat_names))
            nat.origin = nat.name
            nat.unsupported.append("the NAT rule is not in the input")
            return nat
        if self._insert_point(obj) or "options" not in obj and not any(key in obj for key in ("sources", "destinations", "services")):
            return None
        tag = _str(obj.get("tag"))
        name = self._unique(_str(obj.get("name")) or f"NAT rule @{tag}", self.nat_names)
        nat = NatRule(name=name, origin=name, enabled=obj.get("is_disabled") is not True)
        nat.description = _str(obj.get("comment"))
        used = obj.get("used_on")
        if isinstance(used, dict) and used.get("none") is True:
            nat.enabled = False
        elif isinstance(used, (dict, str)) and not (isinstance(used, dict) and used.get("any") is True):
            engine = used.get("firewall_ref") if isinstance(used, dict) else used
            self.report.add("nat", name, Severity.INFO, "NAT_ENGINE",
                            f"the NAT rule applies on engine '{_short(self._element_name(str(engine)), 40)}' only")  # fmt: skip
        problems: List[str] = []
        for key, what, attribute in (("sources", "source", "sources"), ("destinations", "destination", "destinations")):
            cell = obj.get(key)
            members: List[str] = [ANY]
            if not isinstance(cell, dict):
                problems.append(f"its {what} cell cannot be read")
            elif cell.get("none") is True:
                nat.enabled = False
            elif isinstance(cell, dict) and cell.get("any") is not True:
                members = []
                refs = cell.get("src" if key == "sources" else "dst")
                refs = refs if isinstance(refs, list) else []
                if not refs or not all(isinstance(ref, str) for ref in refs):
                    problems.append(f"its {what} cell holds nothing, or what FWShift cannot read")
                for ref in refs:
                    if not isinstance(ref, str):
                        continue
                    if _kind(ref) in ("interface_zone", "match_expression") or "user" in _kind(ref):
                        problems.append(f"{what} '{_short(self._element_name(ref), 40)}', which is no address")
                        continue
                    member, problem = self._address(ref, cell=True)  # (a cell of a rule: a network without broadcast leaves it out)
                    if problem:
                        problems.append(f"{what} '{_short(self._element_name(ref), 40)}': {problem}")
                    if member:
                        members.append(member)
                members = members or [ANY]
            setattr(nat, attribute, members)
        cell = obj.get("services")
        if not isinstance(cell, dict):
            problems.append("its service cell cannot be read")
        elif cell.get("none") is True:
            nat.enabled = False
        elif cell.get("any") is not True:
            services = []
            refs = _list(cell.get("service"))
            if not refs or not all(isinstance(ref, str) for ref in refs):
                problems.append("its service cell holds nothing, or what FWShift cannot read")
            for ref in refs:
                if not isinstance(ref, str):
                    continue
                kind, member, problem = self._service(ref)
                if kind != "service":
                    problems.append(f"service '{_short(self._element_name(ref), 40)}', which is no service of ports")
                elif member:
                    services.append(member)
                if problem:
                    problems.append(problem)
            if len(services) == 1:
                nat.service = services[0]
            elif services:
                group = self._object_name(f"{name} services", self.service_names)
                self.p.service_groups[group] = ServiceGroup(group, transform.dedupe(services), f"the services of NAT rule {name}")
                nat.service = group
        options = _dict(obj.get("options"))
        for key in ("dynamic_dst_nat", "proxy_dst_nat"):
            if options.get(key):
                problems.append({"dynamic_dst_nat": "a translation of the destination to a pool (server pool)",
                                 "proxy_dst_nat": "a translation to a proxy"}[key])  # fmt: skip
        if options.get("static_dst_nat"):
            self._dst_nat(nat, options["static_dst_nat"], problems, family)
        if options.get("static_src_nat"):
            self._static_src(nat, options["static_src_nat"], problems, family)
        if options.get("dynamic_src_nat"):
            self._dynamic_src(nat, options["dynamic_src_nat"], problems, family)
        if family == 6 and (nat.source_translation is not None or nat.destination_translation is not None):
            problems.append("IPv6 NAT")
        nat.unsupported += problems
        self._pin_nat(nat, family)
        return nat

    def _pin_nat(self, nat: NatRule, family: int) -> None:
        """Say in the NAT rule which IP version it is for, as for an access rule: its sources, or its destinations."""
        if nat.sources == [ANY]:
            nat.sources = [ANY_V4 if family == 4 else ANY_V6]
            return
        for attribute in ("sources", "destinations"):
            members = getattr(nat, attribute)
            if all(transform.families(self.p, member) == {family} for member in members):
                return
            views = [self._view(member, family) for member in members]
            if all(views):
                setattr(nat, attribute, transform.dedupe([view for view in views if view]))
                return
        self.report.add("nat", nat.origin, Severity.APPROX, "IP_FAMILY",
                        f"a NAT rule of the IPv{family} list whose addresses do not say so (host names): here it also "
                        f"matches IPv{10 - family} traffic of the same names")  # fmt: skip

    def _value(self, value: Any, problems: List[str], what: str, family: int) -> str:
        """A translated (or original) value: an element or an address. With an element the SMC gives its address as well
        (ip_descriptor), which is what is translated: the first address of a host, not its other ones."""
        if not isinstance(value, dict):
            problems.append(f"its {what} cannot be read")
            return ""
        element = _str(value.get("element"))
        descriptor = _str(value.get("ip_descriptor"))
        if element:
            kind = _kind(element)
            if kind.endswith("alias") or kind == "alias":
                return "alias:" + self._element_name(element)
            member, problem = self._address(element, cell=False)
            if problem:
                problems.append(f"{what}: {problem}")
                return member
            intervals, complete = transform.known_intervals(self.p, member)
            literal = parse_literal(descriptor) if descriptor else None
            if literal is not None and complete and normalize(intervals) != [literal]:
                return descriptor  # one address of the element
            obj = self.source.by_href.get(element) or {}
            primary = _str(obj.get("address") if family == 4 else obj.get("ipv6_address"))
            if kind in ("host", "router") and not descriptor and primary and complete and len(normalize(intervals)) > 1:
                return primary
            return member
        if parse_literal(descriptor) is None:
            problems.append(f"its {what} '{_short(descriptor, 40)}' cannot be read")
            return ""
        return descriptor

    def _dst_nat(self, nat: NatRule, spec: Any, problems: List[str], family: int) -> None:
        if not isinstance(spec, dict):
            problems.append("its destination translation cannot be read")
            return
        translated = self._value(spec.get("translated_value"), problems, "translated destination", family)
        if translated.startswith("alias:"):
            problems.append(f"a destination translated to {translated[6:]}, an alias whose value is set per engine")
            return
        original = _dict(spec.get("original_value"))
        translated_spec = _dict(spec.get("translated_value"))
        port = ""
        low, high = _port(original.get("min_port")), _port(original.get("max_port"))
        new_low, new_high = _port(translated_spec.get("min_port")), _port(translated_spec.get("max_port"))
        if new_low is not None:
            new_high = new_low if new_high is None else new_high
            if low is None:
                # No original port: every port of the connection goes to the translated one.
                if new_low == new_high:
                    port = str(new_low)
                else:
                    problems.append(f"every port translated to {new_low}-{new_high}, which the model cannot say")
            else:
                high = low if high is None else high
                if new_low == low and new_high == high:
                    port = ""
                elif new_low == new_high:
                    port = str(new_low)  # (every original port to one)
                else:
                    problems.append(f"ports {low}-{high} translated to {new_low}-{new_high}, which the model cannot say")
        if translated:
            nat.destination_translation = DestNat(translated, port)

    def _static_src(self, nat: NatRule, spec: Any, problems: List[str], family: int) -> None:
        if not isinstance(spec, dict):
            problems.append("its source translation cannot be read")
            return
        translated = self._value(spec.get("translated_value"), problems, "translated source", family)
        if translated.startswith("alias:"):
            problems.append(f"a source translated to {translated[6:]}, an alias whose value is set per engine")
            return
        if translated:
            nat.source_translation = SourceNat(SnatKind.STATIC, [translated])

    def _dynamic_src(self, nat: NatRule, spec: Any, problems: List[str], family: int) -> None:
        if not isinstance(spec, dict):
            problems.append("its source translation cannot be read")
            return
        pool: List[str] = []
        before = len(problems)
        for value in spec.get("translation_values") or []:
            translated = self._value(value, problems, "translated source", family)
            if translated.startswith("alias:"):
                alias = translated[6:]
                match = re.fullmatch(r"\$\$ Interface ID (\S+)\.ip", alias)
                if alias == "$$ Default NAT Address" or match:
                    nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=f"Interface ID {match.group(1)}" if match else "")
                    self.report.add("nat", nat.origin, Severity.APPROX, "NAT_INTERFACE_ALIAS",
                                    f"the source is translated to {alias}, the address of an interface of the engine: "
                                    "converted as the address of the interface the traffic leaves by")  # fmt: skip
                    return
                problems.append(f"a source translated to {alias}, an alias whose value is set per engine")
                continue
            if translated:
                pool.append(translated)
            if isinstance(value, dict):
                low, high = _port(value.get("min_port")), _port(value.get("max_port"))
                if (low, high) not in ((None, None), (1024, 65535)):
                    self.report.add("nat", nat.origin, Severity.INFO, "NAT_SOURCE_PORT",
                                    f"the source ports are taken from {low}-{high}; the model has no place for that")  # fmt: skip
        if pool:
            nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, transform.dedupe(pool))
        elif len(problems) == before:
            problems.append("a source translation to no address")

    # -- notes ----------------------------------------------------------------------------------------

    def _notes(self) -> None:
        note = self.report.note
        if self.missing:
            note(Severity.REVIEW, "MISSING_ELEMENTS",
                 f"{len(self.missing)} thing{'s' if len(self.missing) != 1 else ''} the policy names {'are' if len(self.missing) != 1 else 'is'} "
                 "not in the input; what names them is not converted: " + "; ".join(transform.dedupe(self.missing)[:12])
                 + ("; ..." if len(set(self.missing)) > 12 else ""))  # fmt: skip
        if self.source.unnamed_lists:
            note(Severity.REVIEW, "LIST_NOT_PLACED",
                 f"{self.source.unnamed_lists} list answer{'s' if self.source.unnamed_lists != 1 else ''} without the key "
                 "fwshift_list: which rule list they are is not known, and they were not read. Take the input with the "
                 "program of 'fwshift script forcepoint-dump'")  # fmt: skip
        if self.tail_families:
            versions = " and ".join(f"IPv{f}" for f in sorted(self.tail_families))
            note(Severity.REVIEW, "TEMPLATE_RULES_NOT_READ",
                 f"the {versions} access rules of a template of the policy are not in the input: its rules above the "
                 "insert point (for the traffic of the engine with the SMC, mostly) are not read, and the rules below it "
                 "were taken as those of the predefined Firewall Template (refuse Ident, discard and log the rest)")  # fmt: skip
        if self.placed_last:
            note(Severity.REVIEW, "RULE_ORDER",
                 "rules that name no insert point of their template, or one it does not have, were put at the end of "
                 "the rules of the policy: " + ", ".join(f"'{_short(n, 40)}'" for n in self.placed_last[:10]))  # fmt: skip
        if self.continues:
            note(Severity.INFO, "CONTINUE_RULE",
                 "Continue rules decide nothing: they set defaults (logging, inspection, timeouts) for the rules below "
                 "them that match the same traffic. Their logging was given to those rules: "
                 + ", ".join(f"'{_short(n, 40)}'" for n in self.continues[:10]))  # fmt: skip
        if self.none_cells:
            note(Severity.INFO, "NONE_CELL",
                 "rules with a cell set to NONE, which the engine ignores; converted disabled: "
                 + ", ".join(f"'{_short(n, 40)}'" for n in self.none_cells[:10]))  # fmt: skip
        if self.automatic:
            note(Severity.INFO, "AUTOMATIC_RULES",
                 "the automatic rules of the engine (at the insert point for them) are for traffic to and from the "
                 "engine itself, and are not converted")  # fmt: skip
        if self.no_vpn:
            note(Severity.INFO, "SOURCE_VPN_NONE",
                 "rules that match traffic that comes through no VPN (Source VPN: not via VPN); converted for all "
                 "traffic, as the model has no VPNs: " + ", ".join(f"'{_short(n, 40)}'" for n in self.no_vpn[:10]))  # fmt: skip
        if self.broadcast_in_groups:
            note(Severity.INFO, "NETWORK_BROADCAST",
                 "networks without 'broadcast' in groups: Forcepoint documents the option for rule cells, and in a "
                 "group they were taken whole: " + ", ".join(transform.dedupe(self.broadcast_in_groups)[:10]))  # fmt: skip
        if self.p.zones:
            note(Severity.INFO, "FORCEPOINT_ZONES",
                 "zones are bound to interfaces on the engine, which the input does not hold: the zones of the policy "
                 "have no interfaces here")  # fmt: skip
        note(Severity.REVIEW, "FORCEPOINT_ELEMENT_NAT",
             "element-based NAT (NAT set on an element) and the default NAT of the engine are not in the policy, and not "
             "read: they translate after the NAT rules, and an element with static NAT also matches its public address "
             "in the access rules")  # fmt: skip
        note(Severity.INFO, "FORCEPOINT_AUTOMATIC",
             "what the engine does by itself is not converted: antispoofing (from its routing), the automatic rules for "
             "its own traffic, and replies of allowed connections, which the model allows with them")  # fmt: skip
