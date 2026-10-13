# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The equivalence check: every connection whose verdict differs between two policies.

Each policy is read with the audit's sets, in the model's own convention (destinations as the
model holds them, see ``_Reader``). For every pair of zones the connections a policy allows are a
union of boxes (IP version, sources, destinations, services), from above (what it might allow) and
from below (what it surely allows):

* an allow rule adds what it matches without what the blocking rules above it match: from above,
  without what those surely match; from below, what it surely matches without all they might;
* a rule the model does not hold exactly (``unsupported``) may match anything in its zones, and may
  allow or block it;
* what no rule decides is allowed where the policy's default allows it.

A connection the second policy surely allows and the first cannot is *opened*, for certain; one the
second might allow and the first does not surely allow is opened possibly. *Closed* is the same the
other way round.

Applications, users, URL categories and schedules are labels of a connection: the comparison is
made for each combination of the labels the rules of a pair of zones use. An application is one
label, on its default ports (from the application map) or not; a connection may carry several
users, categories or schedules at once, and these are compared by name (what a user group, a
schedule or a custom category holds is not in the model). Objects both policies define alike but
that cannot be read (a region, a dynamic group, a host name), and rules both hold alike but not
exactly, are labels too: alike in both, they decide alike. A difference is certain only where it
holds whatever the labels other than the application are. Where there would be too many
combinations, the labels are not combined and what depends on them counts from above only.
"""

from __future__ import annotations

import copy
import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from . import appmap, regions
from .audit import _ALL_SERVICES, _DIFFERENT, _OTHER, _SAME, Reading, Services, _Match, _Reader, _union
from .errors import FwshiftError
from .matrix import service_items
from .model import ANY, APP_DEFAULT, Action, Policy, Rule
from .netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, subtract

Box = regions.Box
OTHER = "(other zones)"
ELSEWHERE = "(elsewhere)"
_LIMIT = 4096  # pieces a set may fall into before it is not followed in detail
_MAX_ATOMS = 256  # combinations of labels per pair of zones
_MAX_WORK = 40000  # combinations times rules per pair of zones, above which the labels are not combined
_MAX_LABELS = 5  # names of one kind of multi-valued label (users, categories, schedules) that are combined
_MAX_UNKNOWN = 6  # labels for objects and rules that both policies hold alike but that cannot be read
_SHOWN = 12  # lines of one kind per pair of zones in the text
_NO_APP = "\0other"


# -- labels ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Atom:
    """One combination of labels a connection can carry."""

    app: str = _NO_APP  # an application the rules name, or none of them
    default_ports: Optional[bool] = None  # for an application some rule allows on its default ports: whether it is on them
    users: FrozenSet[str] = frozenset()
    categories: FrozenSet[str] = frozenset()
    schedules: FrozenSet[str] = frozenset()
    # Objects and rules that both policies hold alike but that cannot be read: "src:NAME", "dst:NAME", "svc:NAME" for
    # an object the source, the destination or the service of the connection is in; "rule:NAME" for a rule that
    # matches it, "allows:NAME" for such a rule that allows it.
    unknown: FrozenSet[str] = frozenset()


def _base(atom: Atom) -> Tuple[str, Optional[bool]]:
    return atom.app, atom.default_ports


@dataclass
class _Labels:
    """The labels the rules of one pair of zones use, and the atoms they make."""

    apps: Dict[str, bool] = field(default_factory=dict)  # application -> some rule allows it on its default ports
    users: Set[str] = field(default_factory=set)
    categories: Set[str] = field(default_factory=set)
    schedules: Set[str] = field(default_factory=set)
    unknown: Set[str] = field(default_factory=set)

    def add(self, rule: Rule, labels: FrozenSet[str] = frozenset()) -> None:
        self.unknown |= labels
        if rule.applications != [ANY]:
            for app in rule.applications:
                self.apps[app] = self.apps.get(app, False) or rule.services == [APP_DEFAULT]
        if rule.users != [ANY]:
            self.users.update(rule.users)
        if rule.url_categories != [ANY]:
            self.categories.update(rule.url_categories)
        if rule.schedule:
            self.schedules.add(rule.schedule)

    def atoms(self, rules: int) -> Tuple[List[Atom], Set[str]]:
        """(the atoms, the kinds of label that are not combined because they are too many)."""
        dropped: Set[str] = set()
        apps: List[Tuple[str, Optional[bool]]] = [(_NO_APP, None)]
        for app, default in sorted(self.apps.items()):
            apps += [(app, True), (app, False)] if default else [(app, None)]

        def subsets(names: Set[str], kind: str, limit: int) -> List[FrozenSet[str]]:
            if len(names) > limit:
                dropped.add(kind)
                return [frozenset()]
            ordered = sorted(names)
            return [frozenset(c) for size in range(len(ordered) + 1) for c in itertools.combinations(ordered, size)]

        users = subsets(self.users, "users", _MAX_LABELS)
        categories = subsets(self.categories, "categories", _MAX_LABELS)
        schedules = subsets(self.schedules, "schedules", _MAX_LABELS)
        unknown = subsets(self.unknown, "objects", _MAX_UNKNOWN)
        total = len(apps) * len(users) * len(categories) * len(schedules) * len(unknown)
        if total > _MAX_ATOMS or total * max(rules, 1) > _MAX_WORK:
            return [Atom()], {"applications", "users", "categories", "schedules", "objects"}
        return [Atom(app, default, u, c, s, k) for (app, default) in apps for u in users for c in categories for s in schedules
                for k in unknown], dropped


def _matches(rule: Rule, atom: Atom, dropped: Set[str], labelled: bool = False) -> Optional[bool]:
    """Whether a rule matches connections with these labels: True, False, or None (it may). ``labelled``: the rule is a
    label itself, which says whether it matches where what it says cannot be read (any application on its default ports)."""
    unsure = False
    if rule.applications != [ANY]:
        if "applications" in dropped:
            unsure = True
        elif atom.app not in rule.applications:
            return False
        elif rule.services == [APP_DEFAULT] and atom.default_ports is False:
            return False
    elif rule.services == [APP_DEFAULT] and not labelled:
        unsure = True  # any application on its default ports: which ports is not known
    for values, wanted, kind in ((atom.users, rule.users, "users"), (atom.categories, rule.url_categories, "categories")):
        if wanted != [ANY]:
            if kind in dropped:
                unsure = True
            elif not values & set(wanted):
                return False
    if rule.schedule:
        if "schedules" in dropped:
            unsure = True
        elif rule.schedule not in atom.schedules:
            return False
    return None if unsure else True


# -- one policy ------------------------------------------------------------------------------------


@dataclass
class _Rule:
    match: _Match
    rule: Rule
    blocks: bool
    wild: bool = False  # the model does not hold it exactly: it may match anything in its zones, and allow or block it
    labels: FrozenSet[str] = frozenset()  # the objects of it that are labels, and its own label if it is one
    shared: str = ""  # a rule both policies hold alike that the comparison cannot read: its label name


def _uncertain(rule: Rule) -> bool:
    """A rule whose match the comparison cannot read but that both policies may hold alike."""
    return bool(rule.unsupported) or (rule.applications == [ANY] and rule.services == [APP_DEFAULT])


class _Side:
    """One policy, read for the comparison."""

    def __init__(self, p: Policy, reading: Optional[Reading]) -> None:
        self.p = p
        self.reader = _Reader(p, reading, as_written=True)
        self.zones = self.reader.zones
        self.rules = [_Rule(self.reader.match(rule, index), rule, rule.action != Action.ALLOW, bool(rule.unsupported))
                      for index, rule in enumerate(p.rules) if rule.enabled]  # fmt: skip
        self.names = [name for name in self.zones.names if name != _OTHER]
        self.cache: Dict[Tuple[int, str, str, bool, FrozenSet[str], bool], Tuple[List[Box], List[Box]]] = {}
        self.shared_addresses: Set[str] = set()
        self.shared_services: Set[str] = set()

    def unknown(self) -> Tuple[Set[str], Set[str]]:
        """The members of rules (addresses, services) that cannot be read."""
        addresses: Set[str] = set()
        services: Set[str] = set()
        for item in self.rules:
            for member in item.match.sources + item.match.destinations:
                if member != ANY and not self.reader._sure(member)[1]:
                    addresses.add(member)
            for member in item.rule.services:
                if member not in (ANY, APP_DEFAULT) and not self.reader.service_set([member])[1]:
                    services.add(member)
        return addresses, services

    def share(self, addresses: Set[str], services: Set[str], rules: Set[str]) -> None:
        """Take objects and rules both policies hold alike as labels."""
        self.shared_addresses, self.shared_services = addresses, services
        for item in self.rules:
            labels = {f"src:{m}" for m in item.match.sources if m in addresses}
            labels |= {f"dst:{m}" for m in item.match.destinations if m in addresses}
            labels |= {f"svc:{m}" for m in item.rule.services if m in services}
            if item.rule.name in rules and _uncertain(item.rule):
                item.shared = item.rule.name
                labels.add(f"rule:{item.rule.name}")
                if item.wild:
                    labels.add(f"allows:{item.rule.name}")
            item.labels = frozenset(labels)

    def _addresses(self, members: List[str], negated: bool, side: str, labels: FrozenSet[str]) -> Tuple[List[Interval], List[Interval]]:
        sure: List[Interval] = []
        complete = True
        for member in members:
            if member in self.shared_addresses:
                sure += [FULL_V4, FULL_V6] if f"{side}:{member}" in labels else []
            else:
                found, done = self.reader._sure(member)
                sure += found
                complete = complete and done
        sure = normalize(sure)
        if negated:
            left = subtract([FULL_V4, FULL_V6], sure)
            return left, (left if complete else [])
        return (sure if complete else [FULL_V4, FULL_V6]), sure

    def _services(self, item: _Rule, labels: FrozenSet[str]) -> Tuple[Services, Services]:
        rule = item.rule
        sets: List[Services] = []
        complete = True
        for name in rule.services:
            if name in self.shared_services:
                if f"svc:{name}" in labels:
                    sets.append(_ALL_SERVICES)
                continue
            found, done = self.reader.service_set([name])
            sets.append(found)
            complete = complete and done
        known = _union(sets)
        if rule.negate_service:
            left = _ALL_SERVICES.minus(known)
            return left, (left if complete else Services())
        return (known if complete else _ALL_SERVICES), known

    def boxes(self, item: _Rule, src: str, dst: str, own_ports: bool, universe: List[Box], atom: Atom,
              objects: bool) -> Tuple[List[Box], List[Box]]:  # fmt: skip
        """What a rule might and surely matches between two zones, as boxes. ``objects``: whether the objects that are
        labels are read by the labels of the atom (when they are not combined, they are read as they are)."""
        labels = atom.unknown & item.labels if objects else frozenset()
        key = (id(item), src, dst, own_ports, labels, objects)
        if key not in self.cache:
            m = item.match
            if objects and item.labels:
                src_over, src_under = self._addresses(m.sources, item.rule.negate_source, "src", labels)
                dst_over, dst_under = self._addresses(m.destinations, item.rule.negate_destination, "dst", labels)
                services_over, services_under = self._services(item, labels)
            else:
                src_over, src_under, dst_over, dst_under = m.src_over, m.src_under, m.dst_over, m.dst_under
                services_over, services_under = m.svc_over, m.svc_under
            if own_ports:
                services_over = services_under = _ALL_SERVICES  # (the application decides; its ports are its own)
            self.cache[key] = (_boxes(src_over, dst_over, services_over, universe), _boxes(src_under, dst_under, services_under, universe))
        return self.cache[key]

    def bits(self, zone: str) -> int:
        return self.zones.bits([zone]) if zone in self.zones.index else self.zones.other

    def applies(self, item: _Rule, src: str, dst: str, relation: int) -> bool:
        zones = item.match.zones
        return self.zones.possible(zones[0] & self.bits(src), zones[1] & self.bits(dst), zones[2] & relation)

    def default(self, src: str, relation: int) -> bool:
        if relation == _SAME:
            zone = self.p.zones.get(src)
            if zone is not None and zone.intrazone_allow is not None:
                return zone.intrazone_allow
            return self.p.default_intrazone == Action.ALLOW
        return self.p.default_interzone == Action.ALLOW


def _boxes(sources: List[Interval], destinations: List[Interval], services: Services, universe: List[Box]) -> List[Box]:
    out: List[Box] = []
    for space in universe:
        version = space[0]
        found = regions.box_and(space, (version, [i for i in sources if i[0] == version], [i for i in destinations if i[0] == version], services))
        if found is not None:
            out.append(found)
    return out


def _without(boxes: List[Box], cuts: Sequence[Box]) -> Optional[List[Box]]:
    """Boxes without the cuts that meet them; None when that falls into too many pieces."""
    out: List[Box] = []
    for box in boxes:
        meeting = [cut for cut in cuts if regions.box_and(box, cut) is not None]
        left = regions.minus_all([box], sorted(meeting, key=_weight, reverse=True), _LIMIT)
        if left is None:
            return None
        out += left
        if len(out) > _LIMIT * 4:
            return None
    return out


def _weight(box: Box) -> int:
    return sum(i[2] - i[1] + 1 for i in box[1]) * sum(i[2] - i[1] + 1 for i in box[2]) * box[3].volume(exact=False)


def _restricted(boxes: List[Box], services: Optional[Services]) -> List[Box]:
    if services is None:
        return boxes
    return [found for box in boxes for found in [regions.box_and(box, (box[0], box[1], box[2], services))] if found is not None]


@dataclass
class _Allowed:
    over: List[Box]
    under: List[Box]
    followed: bool = True  # False: a set fell into too many pieces and was taken whole (over) or as nothing (under)


@dataclass
class _Pair:
    """One pair of zones as one policy sees it."""

    src: str
    dst: str
    relation: int


def _allowed(side: _Side, pair: _Pair, atom: Atom, dropped: Set[str], universe: List[Box], services: Optional[Services]) -> _Allowed:
    """What one policy allows between two zones, for one combination of labels (whose connections use ``services``)."""
    allow_over: List[Box] = []
    allow_under: List[Box] = []
    block_over: List[Box] = []
    block_under: List[Box] = []
    decided_over: List[Box] = []
    decided_under: List[Box] = []
    followed = True
    objects = "objects" not in dropped
    space = _restricted(universe, services)
    for item in side.rules:
        if not side.applies(item, pair.src, pair.dst, pair.relation):
            continue
        labelled = _matches(item.rule, atom, dropped, bool(item.shared) and objects)
        if labelled is False:
            continue
        allows: Optional[bool] = not item.blocks  # None: it may allow or block
        if item.shared and objects:
            # A rule both hold alike but that cannot be read: by its labels, whether it matches, and how.
            if f"rule:{item.shared}" not in atom.unknown:
                continue
            if item.wild:
                over = under = list(space)
                allows = f"allows:{item.shared}" in atom.unknown
            else:
                found, _ = side.boxes(item, pair.src, pair.dst, True, universe, atom, objects)
                over = under = _restricted(found, services)
            if labelled is not True:
                under = []
        elif item.wild:
            over, under, allows = list(space), [], None
        else:
            own_ports = item.rule.applications != [ANY] and item.rule.services == [APP_DEFAULT] and bool(labelled)
            over, under = side.boxes(item, pair.src, pair.dst, own_ports, universe, atom, objects)
            over = _restricted(over, services)
            under = _restricted(under, services) if labelled is True and item.match.covers else []
        if not over:
            continue
        if allows is not True:
            block_over += over
            if allows is False:
                block_under += under
        if allows is not False:
            left = _without(over, block_under)
            if left is None:
                left, followed = over, False
            allow_over += left
            if under and allows:
                kept = _without(under, block_over)
                if kept is None:
                    kept, followed = [], False
                allow_under += kept
        decided_over += over
        decided_under += under
    if side.default(pair.src, pair.relation):
        left = _without(space, decided_under)
        if left is None:
            left, followed = list(space), False
        allow_over += left
        kept = _without(space, decided_over)
        if kept is None:
            kept, followed = [], False
        allow_under += kept
    return _Allowed(allow_over, allow_under, followed)


# -- the result ------------------------------------------------------------------------------------


@dataclass
class Difference:
    """Connections of one pair of zones whose verdict differs."""

    src: str
    dst: str
    inside: bool  # the two ends in one zone
    opened: bool  # allowed by the second policy, not by the first
    certain: bool
    condition: str  # the labels it holds for ("" for every connection)
    boxes: List[Box]
    first_rule: str = ""  # what decides a connection of it in each policy
    second_rule: str = ""
    atoms: List[Atom] = field(default_factory=list)  # the combinations of labels it holds for
    second_pair: str = ""  # the pair of zones as the second policy names it, where that differs

    def lines(self, limit: int = _SHOWN) -> List[str]:
        out: List[str] = []
        summary = _summary(self.boxes)
        for box in summary[:limit]:
            out.append(f"{_addresses(box[1])} -> {_addresses(box[2])}: {', '.join(_shown(box)[:8])}")
        if len(summary) > limit:
            out.append(f"and {len(summary) - limit} more")
        return out

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"from": self.src, "to": self.dst, "change": "opened" if self.opened else "closed",
                               "certain": self.certain, "connections": [
                                   {"version": box[0], "sources": [interval_text(i) for i in box[1]],
                                    "destinations": [interval_text(i) for i in box[2]], "services": _shown(box)}
                                   for box in _summary(self.boxes)],
                               "first_policy": self.first_rule, "second_policy": self.second_rule}  # fmt: skip
        if self.inside:
            out["inside_the_zone"] = True
        if self.condition:
            out["for"] = self.condition
        if self.second_pair:
            out["second_policy_zones"] = self.second_pair
        return out


def _shown(box: Box) -> List[str]:
    """The services of a box as text; the ICMP of the other IP version, which no packet of this one has, counts as in it."""
    svc = box[3]
    if svc.rest:
        svc = _join(svc, Services({58 if box[0] == 4 else 1: [regions.WHOLE]}))
    return service_items(svc)


def _addresses(intervals: List[Interval], limit: int = 4) -> str:
    if intervals in ([FULL_V4], [FULL_V6]):
        return "any"
    texts = [interval_text(i) for i in intervals]
    return ", ".join(texts[:limit]) + (f" and {len(texts) - limit} more" if len(texts) > limit else "")


def _summary(boxes: List[Box]) -> List[Box]:
    """Boxes of one sort joined where they have the same addresses."""
    joined: Dict[Tuple[int, Tuple[Interval, ...], Tuple[Interval, ...]], Services] = {}
    for version, src, dst, svc in boxes:
        key = (version, tuple(normalize(src)), tuple(normalize(dst)))
        joined[key] = svc if key not in joined else _join(joined[key], svc)
    by_services: Dict[Tuple[int, Tuple[Interval, ...], str], List[Interval]] = {}
    services: Dict[str, Services] = {}
    for (version, sources, targets), svc in joined.items():
        name = repr(sorted((n, sorted(r)) for n, r in svc.protocols.items())) + repr(svc.rest)
        services[name] = svc
        by_services.setdefault((version, sources, name), []).extend(targets)
    out = [(version, list(sources), normalize(targets), services[name]) for (version, sources, name), targets in by_services.items()]
    return sorted(out, key=lambda box: (box[0], box[1], box[2]))


def _join(a: Services, b: Services) -> Services:
    numbers = set(a.protocols) | set(b.protocols)
    return Services({n: a.of(n) + b.of(n) for n in numbers}, a.rest or b.rest)


@dataclass
class Comparison:
    first: str
    second: str
    differences: List[Difference] = field(default_factory=list)
    pairs: int = 0
    notes: List[str] = field(default_factory=list)
    not_followed: List[str] = field(default_factory=list)  # pairs of zones where a set was taken whole
    labels: Dict[Tuple[str, str, int], Tuple[Any, Set[str]]] = field(default_factory=dict)  # the labels of each pair, what was not combined
    by_name: List[str] = field(default_factory=list)  # kinds of label compared by name only (users, schedules, URL categories)

    @property
    def equal(self) -> bool:
        return not self.differences

    def counts(self) -> Dict[str, int]:
        out = {"opened, certain": 0, "opened, possible": 0, "closed, certain": 0, "closed, possible": 0}
        for difference in self.differences:
            out[f"{'opened' if difference.opened else 'closed'}, {'certain' if difference.certain else 'possible'}"] += 1
        return out

    def level(self) -> int:
        """The weight of the worst difference: 3 opened for certain, 2 opened possibly or closed for certain, 1 closed possibly, 0 none."""
        worst = 0
        for difference in self.differences:
            worst = max(worst, 3 if difference.opened and difference.certain else 2 if difference.opened or difference.certain else 1)
        return worst

    def to_dict(self) -> Dict[str, Any]:
        return {"first": self.first, "second": self.second, "equivalent": self.equal, "pairs_of_zones": self.pairs,
                "counts": self.counts(), "differences": [d.to_dict() for d in self.differences], "notes": self.notes,
                "compared_by_name_only": self.by_name, "not_followed_in_detail": self.not_followed}  # fmt: skip

    def summary(self) -> str:
        if self.equal:
            text = f"The two policies decide every connection alike ({self.pairs} pairs of zones compared)"
            if self.by_name:
                text += f", if the {', '.join(self.by_name)} of the same names hold the same in both (what they hold is not read)"
            return text + "."
        counts = self.counts()
        return (f"Connections whose verdict differs ({self.pairs} pairs of zones compared): "
                + ", ".join(f"{count} {name}" for name, count in counts.items() if count))  # fmt: skip

    def to_text(self) -> str:
        out = [f"first:  {self.first}", f"second: {self.second}", "", self.summary()]
        if not self.equal:
            out.append("  opened: the second policy allows it, the first does not; closed: the other way round")
            out.append("  certain: it holds whatever the policies cannot read; possible: it may (see the notes)")
            current = None
            for d in self.differences:
                pair = (d.src, d.dst, d.inside)
                if pair != current:
                    head = f"{d.src} -> {d.dst}" + (" (inside the zone)" if d.inside else "")
                    if d.src == d.dst and not d.inside:
                        head += " (between two of them)"
                    out += ["", head + (f" (the second policy: {d.second_pair})" if d.second_pair else "")]
                    current = pair
                text = f"  {'opened' if d.opened else 'closed'}, {'certain' if d.certain else 'possible'}"
                out.append(text + (f" (for {d.condition})" if d.condition else ""))
                out += [f"    {line}" for line in d.lines()]
                out.append(f"    first policy: {d.first_rule}; second policy: {d.second_rule}")
        if self.not_followed:
            out += ["", "Not followed in detail (too many pieces; what is shown is from above): " + ", ".join(self.not_followed[:12])]
        if self.notes:
            out += ["", "Notes"] + [f"  {note}" for note in self.notes]
        return "\n".join(out) + "\n"


# -- comparing -------------------------------------------------------------------------------------


def _definition(p: Policy, name: str, address: bool, seen: Tuple[str, ...] = ()) -> str:
    """An object with all that what it holds depends on, as text: alike in two policies when they define it alike."""
    if name in seen:
        return f"<{name}>"
    objects: Dict[str, Any] = dict(p.addresses) if address else dict(p.services)
    groups: Dict[str, Any] = dict(p.address_groups) if address else dict(p.service_groups)
    if name in objects:
        found = copy.copy(objects[name])
        found.description = ""
        found.tags = []
        return repr(found)
    if name in groups:
        group = copy.copy(groups[name])
        if getattr(group, "unsupported", ""):
            return f"<not read: {id(groups[name])}>"  # (what it holds depends on more than the model has: never alike)
        inner = [_definition(p, member, address, seen + (name,)) for member in group.members]
        extra = ""
        if address and group.dynamic_filter:
            # The members of a dynamic group are the objects that carry its tags: all tagged objects count.
            tagged = sorted((key, sorted(value.tags), _definition(p, key, True, seen + (name,)))
                            for key, value in list(p.addresses.items()) + list(p.address_groups.items()) if value.tags)  # fmt: skip
            extra = repr(tagged)
        group.description = ""
        group.tags = []
        group.members = []
        return repr(group) + repr(inner) + extra
    return f"?{name}"


def _rule_definition(rule: Rule, zones: Dict[str, str]) -> str:
    """A rule as text (its zones as the second policy names them), without what does not change what it does."""
    found = copy.copy(rule)
    found.src_zones = sorted({zones.get(z, z) for z in rule.src_zones})
    found.dst_zones = sorted({zones.get(z, z) for z in rule.dst_zones})
    for attribute in ("origin", "description", "tags", "source_ids", "hits", "install_on", "log_start", "log_end", "profiles"):
        if hasattr(found, attribute):
            setattr(found, attribute, type(getattr(found, attribute))())
    return repr(found)


def _point(box: Box) -> Tuple[int, int, int, int, int, int]:
    """A connection of a box: (version, source, destination, protocol, a, b)."""
    svc = box[3]
    for number in sorted(svc.protocols):
        if svc.protocols[number]:
            rect = svc.protocols[number][0]
            return box[0], box[1][0][1], box[2][0][1], number, rect[0], rect[2]
    number = next(n for n in range(256) if n not in svc.protocols)
    return box[0], box[1][0][1], box[2][0][1], number, 0, 0


def _holds(box: Box, point: Tuple[int, int, int, int, int, int]) -> bool:
    version, src, dst, number, a, b = point
    if box[0] != version or not any(i[1] <= src <= i[2] for i in box[1]) or not any(i[1] <= dst <= i[2] for i in box[2]):
        return False
    return any(r[0] <= a <= r[1] and r[2] <= b <= r[3] for r in box[3].of(number))


def _decider(side: _Side, pair: _Pair, atom: Atom, dropped: Set[str], point: Tuple[int, int, int, int, int, int]) -> str:
    """The rule that decides a connection, as far as the sets tell."""
    version = point[0]
    universe: List[Box] = [(version, [regions.full(version)], [regions.full(version)], _ALL_SERVICES)]
    objects = "objects" not in dropped
    maybe: List[str] = []
    for item in side.rules:
        if not side.applies(item, pair.src, pair.dst, pair.relation):
            continue
        labelled = _matches(item.rule, atom, dropped, bool(item.shared) and objects)
        if labelled is False:
            continue
        verdict = "blocks" if item.blocks else "allows"
        if item.shared and objects:
            if f"rule:{item.shared}" not in atom.unknown:
                continue
            if item.wild:
                verdict = "allows" if f"allows:{item.shared}" in atom.unknown else "blocks"
                if labelled is True:
                    return f"rule '{item.rule.name}' (not read exactly, alike in both) {verdict}"
                maybe.append(f"'{item.rule.name}' ({verdict})")
                continue
            over, _ = side.boxes(item, pair.src, pair.dst, True, universe, atom, objects)
            under = over if labelled is True else []
        elif item.wild:
            maybe.append(f"'{item.rule.name}' (not read exactly)")
            continue
        else:
            own_ports = item.rule.applications != [ANY] and item.rule.services == [APP_DEFAULT] and bool(labelled)
            over, under = side.boxes(item, pair.src, pair.dst, own_ports, universe, atom, objects)
            if not (labelled is True and item.match.covers):
                under = []
        if not any(_holds(box, point) for box in over):
            continue
        if any(_holds(box, point) for box in under):
            return f"rule '{item.rule.name}' {verdict}" + (f" (after {', '.join(maybe[:3])}, which may match)" if maybe else "")
        maybe.append(f"'{item.rule.name}' ({verdict})")
    verdict = "allows" if side.default(pair.src, pair.relation) else "blocks"
    return f"the default {verdict}" + (f" (unless {', '.join(maybe[:3])} matches)" if maybe else "")


def compare(first: Policy, second: Policy, first_label: str = "first", second_label: str = "second",
            readings: Tuple[Optional[Any], Optional[Any]] = (None, None), zone_map: Optional[Dict[str, str]] = None,
            zone_networks: Optional[Dict[str, List[str]]] = None, pairs: Optional[Sequence[Tuple[str, str]]] = None,
            app_ports: Optional[Dict[str, List[str]]] = None) -> Comparison:  # fmt: skip
    """Every connection whose verdict differs between two policies.

    ``zone_map`` gives the zones of the first as the second names them (several may become one); ``zone_networks``
    the addresses behind zones (by the names of the first), so that only connections that can happen are compared;
    ``pairs`` limits the comparison to some pairs of zones (by the names of the first). Raises FwshiftError when the
    two have nothing in common to compare.
    """
    from .emitters.asa import zone_spaces

    def read(value: Optional[Any]) -> Optional[Reading]:
        return value if isinstance(value, Reading) or value is None else Reading.of(value)

    mapping = dict(zone_map or {})
    a, b = _Side(first, read(readings[0])), _Side(second, read(readings[1]))
    result = Comparison(first_label, second_label)
    # What neither can read but both hold alike is the same in both: a label, not a difference.
    (a_addresses, a_services), (b_addresses, b_services) = a.unknown(), b.unknown()
    addresses = {n for n in a_addresses & b_addresses if _definition(a.p, n, True) == _definition(b.p, n, True)}
    services = {n for n in a_services & b_services if _definition(a.p, n, False) == _definition(b.p, n, False)}
    a_rules = {item.rule.name: _rule_definition(item.rule, mapping) for item in a.rules if _uncertain(item.rule)}
    b_rules = {item.rule.name: _rule_definition(item.rule, {}) for item in b.rules if _uncertain(item.rule)}
    rules = {name for name in a_rules.keys() & b_rules.keys() if a_rules[name] == b_rules[name]}
    a.share(addresses, services, rules)
    b.share(addresses, services, rules)
    # The zones: those of the first, and those only the second names; each as the second names it.
    names = list(a.names)
    image = {mapping.get(name, name) for name in names}
    names += [name for name in b.names if name not in image and name not in names]
    to_second = {name: mapping.get(name, name) for name in names}
    networks = dict(zone_networks or {})
    spaces = zone_spaces(networks) if networks else {}
    missing = [name for name in names if networks and name not in spaces]
    if missing:
        result.notes.append("No networks were given for zone(s) " + ", ".join(missing[:12]) + ": every address is compared there.")
    unknown = [name for name in networks if name not in names]
    if unknown:
        # (a zone neither names is one of the zones a rule for any zone reaches, in both)
        names += unknown
        to_second.update({name: name for name in unknown})
        result.notes.append("Networks were given for zone(s) neither policy names (compared as zones a rule for 'any' zone reaches): "
                            + ", ".join(unknown[:12]))  # fmt: skip
    every = bool(networks) and not missing
    families = [4, 6]
    for p in (first, second):
        if p.vendor in ("iptables", "nftables") and p.scope in ("IPv4", "IPv6"):
            families = [v for v in families if v == (4 if p.scope == "IPv4" else 6)]
    if not families:
        raise FwshiftError("the two policies are for different IP versions (one IPv4 only, the other IPv6 only): nothing to compare")
    if families != [4, 6]:
        result.notes.append(f"One of the policies is for IPv{families[0]} only: only that is compared.")
    rest = OTHER
    if every:
        taken = normalize([i for space in spaces.values() for i in space])
        left = subtract([regions.full(v) for v in families], taken)
        spaces[ELSEWHERE] = left
        rest = ELSEWHERE
    all_names = names + [rest]
    wanted = set(pairs) if pairs is not None else None
    for src in all_names:
        for dst in all_names:
            if wanted is not None and (src, dst) not in wanted:
                continue
            # (ICMP of the other IP version is no packet of this one)
            universe = [(v, [i for i in spaces.get(src, [regions.full(v)]) if i[0] == v],
                         [i for i in spaces.get(dst, [regions.full(v)]) if i[0] == v], Services({58 if v == 4 else 1: []}, True))
                        for v in families]  # fmt: skip
            universe = [box for box in universe if box[1] and box[2]]
            if not universe:
                continue
            if src == dst == rest:
                cases = [(_SAME, _SAME), (_DIFFERENT, _DIFFERENT)]  # (one zone nobody names, or two)
            else:
                first_relation = _SAME if src == dst else _DIFFERENT
                second_relation = _SAME if src == dst or to_second.get(src, src) == to_second.get(dst, dst) else _DIFFERENT
                cases = [(first_relation, second_relation)]
            for first_relation, second_relation in cases:
                result.pairs += 1
                _compare_pair(result, a, b, _Pair(src, dst, first_relation),
                              _Pair(to_second.get(src, src), to_second.get(dst, dst), second_relation), universe, dict(app_ports or {}))  # fmt: skip
    if result.pairs == 0:
        raise FwshiftError("no pair of zones with addresses to compare (the networks given leave none)")
    kinds = []
    for kind, attribute in (("users", "users"), ("URL categories", "url_categories")):
        if any(getattr(item.rule, attribute) != [ANY] for side in (a, b) for item in side.rules):
            kinds.append(kind)
    if any(item.rule.schedule for side in (a, b) for item in side.rules):
        kinds.append("schedules")
    result.by_name = kinds
    if kinds:
        result.notes.append(f"The {', '.join(kinds)} of the rules are compared by name: what a user group, a custom URL category or a "
                            "schedule holds is not in the model. Where the two define one of the same name differently, connections "
                            "may differ that are not shown.")  # fmt: skip
    if any(p.nat_rules for p in (first, second)):
        result.notes.append("The NAT rules are not compared; the rules are, as the model holds them (for a source that matches after "
                            "destination NAT, with the addresses before it as well).")  # fmt: skip
    if rest == OTHER:
        result.notes.append(f"{OTHER}: zones neither policy names, which a rule for 'any' zone reaches.")
    else:
        result.notes.append(f"{ELSEWHERE}: addresses in none of the networks given, compared as a zone neither policy names; where they "
                            "lie behind a zone, give them to it.")  # fmt: skip
    if not networks and (not a.names or not b.names) and (a.names or b.names):
        result.notes.append("One policy has zones and the other has none: give the networks behind the zones (--zone-network) so that "
                            "only connections that can happen are compared.")  # fmt: skip
    if any(item.wild for side in (a, b) for item in side.rules):
        result.notes.append("Rules the model does not hold exactly (unsupported) may match anything in their zones and allow or block it, "
                            "unless both policies hold them alike.")  # fmt: skip
    result.notes.append("Compared from the configurations: what the platforms do around the rules (routing, implicit rules, NAT that "
                        "fails) is not in it.")  # fmt: skip
    return result


def _ports(app: str, app_ports: Dict[str, List[str]]) -> Optional[Services]:
    """The default ports of an application, from the application map; None when it is not in it."""
    entries = appmap.entries_for(app, app_ports)
    return None if entries is None else regions.service_set(entries)


def _compare_pair(result: Comparison, a: _Side, b: _Side, first: _Pair, second: _Pair, universe: List[Box],
                  app_ports: Dict[str, List[str]]) -> None:  # fmt: skip
    labels = _Labels()
    applying = 0
    for side, pair in ((a, first), (b, second)):
        for item in side.rules:
            if side.applies(item, pair.src, pair.dst, pair.relation):
                labels.add(item.rule, item.labels)
                applying += 1
    atoms, dropped = labels.atoms(applying)
    result.labels[(first.src, first.dst, first.relation)] = (labels, dropped)
    label = f"{first.src} -> {first.dst}" + (" (inside)" if first.relation == _SAME and first.src == first.dst else "")
    if dropped:
        result.notes.append(f"{label}: too many combinations of {', '.join(sorted(dropped))} to compare one by one; what depends on "
                            "them counts as possible only.")  # fmt: skip
    found: Dict[Tuple[bool, bool, str], Tuple[List[Box], List[Atom]]] = {}
    unknown_ports: Set[str] = set()
    evaluated: List[Atom] = []
    for atom in atoms:
        # An application on its default ports uses those ports, on other ports the others: a connection of it
        # cannot be anything else. Where the application map does not have it, that is not known.
        services: Optional[Services] = None
        known = True
        if atom.default_ports is not None:
            ports = _ports(atom.app, app_ports)
            if ports is None:
                known = False
                unknown_ports.add(atom.app)
            else:
                services = ports if atom.default_ports else _ALL_SERVICES.minus(ports)
                if services.empty():
                    continue
        evaluated.append(atom)
        one = _allowed(a, first, atom, dropped, universe, services)
        two = _allowed(b, second, atom, dropped, universe, services)
        if not (one.followed and two.followed) and label not in result.not_followed:
            result.not_followed.append(label)
        for opened, gain, loss in ((True, two, one), (False, one, two)):
            certain = _without(gain.under, loss.over)
            if certain is None:
                certain = []
                if label not in result.not_followed:
                    result.not_followed.append(label)
            possible = _without(gain.over, loss.under)
            if possible is None:
                possible = list(gain.over)
                if label not in result.not_followed:
                    result.not_followed.append(label)
            if certain:
                fewer = _without(possible, certain)
                possible = fewer if fewer is not None else possible
            for is_certain, boxes in ((True, certain), (False, possible)):
                if not boxes:
                    continue
                key = (opened, is_certain and known, _key(boxes))
                if key not in found:
                    found[key] = (boxes, [])
                found[key][1].append(atom)
    # Certain only where it holds whatever the labels other than the application are (users, categories, schedules, the
    # objects and rules that cannot be read): a connection of that application has some of them, which is not known.
    variants: Dict[Tuple[str, Optional[bool]], List[Atom]] = {}
    for atom in evaluated:
        variants.setdefault(_base(atom), []).append(atom)
    for key in [key for key in found if key[1]]:
        boxes, with_atoms = found[key]
        if all(other in with_atoms for atom in with_atoms for other in variants[_base(atom)]):
            continue
        del found[key]
        weaker = (key[0], False, key[2])
        if weaker in found:
            found[weaker][1].extend(atom for atom in with_atoms if atom not in found[weaker][1])
        else:
            found[weaker] = (boxes, with_atoms)
    if unknown_ports:
        result.notes.append(f"{label}: the default ports of application(s) {', '.join(sorted(unknown_ports))} are not in the application "
                            "map (--app-map): what differs on or off them is possible only.")  # fmt: skip
    apps_used = any(atom.app != _NO_APP for atom in evaluated)
    renamed = (second.src, second.dst) != (first.src, first.dst)
    second_pair = f"{second.src} -> {second.dst}" + (" (inside the zone)" if second.relation == _SAME else "") if renamed else ""
    for (opened, is_sure, _), (boxes, with_atoms) in sorted(found.items(), key=lambda item: (not item[0][0], not item[0][1])):
        texts = _condition(with_atoms, evaluated, apps_used)
        condition = "; or ".join(texts[:4]) + (f"; and {len(texts) - 4} more" if len(texts) > 4 else "")
        point = _point(boxes[0])
        atom = with_atoms[0]
        result.differences.append(Difference(first.src, first.dst, first.relation == _SAME, opened, is_sure, condition, boxes,
                                             _decider(a, first, atom, dropped, point), _decider(b, second, atom, dropped, point),
                                             list(with_atoms), second_pair))  # fmt: skip


_ANY_VALUE = "\0*"
_WORDS = {"src": "the source in '{}'", "dst": "the destination in '{}'", "svc": "the service in '{}'",
          "rule": "rule '{}' (not read exactly) matching", "allows": "rule '{}' allowing"}  # fmt: skip


def _condition(atoms: List[Atom], evaluated: List[Atom], apps_used: bool) -> List[str]:
    """The labels a difference holds for, in as few words as they go: a kind of label that every value of is in it
    (whatever the others) is left out. Empty: every connection."""
    def key(atom: Atom) -> Tuple[Any, ...]:
        return ((atom.app, atom.default_ports), atom.users, atom.categories, atom.schedules, atom.unknown)

    held = {key(atom) for atom in atoms}
    every = {key(atom) for atom in evaluated}
    if held >= every:
        return []
    for dimension in range(5):
        def rest(item: Tuple[Any, ...]) -> Tuple[Any, ...]:
            return item[:dimension] + item[dimension + 1:]

        values: Dict[Tuple[Any, ...], Set[Any]] = {}
        for item in every:
            values.setdefault(rest(item), set()).add(item[dimension])
        if all(item[:dimension] + (value,) + item[dimension + 1:] in held for item in held for value in values[rest(item)]):
            held = {item[:dimension] + (_ANY_VALUE,) + item[dimension + 1:] for item in held}
            every = {item[:dimension] + (_ANY_VALUE,) + item[dimension + 1:] for item in every}
    texts: List[str] = []
    for application, users, categories, schedules, unknown in sorted(held, key=repr):
        parts: List[str] = []
        if application != _ANY_VALUE:
            app, default = application
            if app == _NO_APP:
                parts.append("other applications" if apps_used else "")
            else:
                parts.append(f"application {app}" + ("" if default is None else
                                                     " on its default ports" if default else " on other ports"))
        for label, value in (("users", users), ("URL categories", categories), ("schedules", schedules)):
            if value != _ANY_VALUE:
                parts.append(f"{label} {', '.join(sorted(value))}" if value else f"none of the {label} the rules name")
        if unknown != _ANY_VALUE:
            parts += [_WORDS[label.split(":", 1)[0]].format(label.split(":", 1)[1]) for label in sorted(unknown)]
            if not unknown:
                parts.append("none of what cannot be read")
        texts.append("; ".join(part for part in parts if part) or "every connection")
    return list(dict.fromkeys(texts))


def _key(boxes: List[Box]) -> str:
    return repr([(box[0], box[1], box[2], sorted((n, sorted(r)) for n, r in box[3].protocols.items()), box[3].rest) for box in _summary(boxes)])


def parse_zone_map(values: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for value in values:
        old, sep, new = value.partition("=")
        if not sep or not old or not new:
            raise FwshiftError(f"--zone-map expects FIRST=SECOND, got '{value[:60]}'")
        out[old] = new
    return out


__all__ = ["ELSEWHERE", "OTHER", "Atom", "Comparison", "Difference", "compare", "parse_zone_map"]
