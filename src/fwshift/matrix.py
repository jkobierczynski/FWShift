# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The zone matrix: what each zone may reach in each other zone, on which services, through which rules.

Built on the sets of the audit. An allow rule is shown with what the blocking rules above it
leave of it; rules that never match are left out. Where something cannot be read exactly the
matrix shows more, never less, and marks it: it is meant for the question "can A reach B at
all, and how", where an access that is missing from the answer is the costly mistake.

Zones are those of the policy, or networks given by the user (the zones of a zone and conduit
model need not be the interfaces of one firewall).
"""

from __future__ import annotations

import copy
import csv
import io
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import transform
from .audit import (
    _ALL_SERVICES,
    _DIFFERENT,
    _EVERY_ADDRESS,
    _MAX_BOXES,
    _OTHER,
    _PROTOCOL_NAMES,
    _SAME,
    _WHOLE,
    AuditConfig,
    Box,
    Reading,
    Services,
    _Audit,
    _blocks,
    _order_only,
    _rects_minus,
    _Sets,
    _spec_services,
    _union,
)
from .errors import FwshiftError
from .model import ANY, APP_DEFAULT, Action, Policy, Rule, SnatKind
from .netutil import FULL_V4, FULL_V6, Interval, intersect, interval_text, normalize, parse_literal, subtract

ELSEWHERE = "(elsewhere)"  # with zones given as networks: every address that lies in none of them
OTHER = "(other zones)"  # with the zones of the policy: the zones no rule names, which "any" takes in
DEFAULT = "(default)"  # what happens to traffic no rule decides

_IP_NAMES = {2: "igmp", 4: "ip-in-ip", 41: "ipv6-in-ip", 47: "gre", 50: "esp", 51: "ah", 88: "eigrp", 89: "ospf", 103: "pim", 112: "vrrp"}


# -- services as text ------------------------------------------------------------------------------


def _merged(ranges: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for low, high in sorted(ranges):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return out


def _span(low: int, high: int) -> str:
    return str(low) if low == high else f"{low}-{high}"


def service_items(services: Services) -> List[str]:
    """A set of services as a list of short texts: ``tcp/443``, ``udp/53``, ``icmp type 8``, ``any``."""
    if services.everything():
        return ["any"]
    if services.rest:
        return ["any except " + ", ".join(service_items(_ALL_SERVICES.minus(services)))]
    out: List[str] = []
    for number in sorted(services.protocols):
        rects = services.protocols[number]
        if not rects:
            continue
        name = _PROTOCOL_NAMES.get(number) or (f"ip/{number} ({_IP_NAMES[number]})" if number in _IP_NAMES else f"ip/{number}")
        if not _rects_minus([_WHOLE], rects):
            out.append(name)
        elif number in (6, 17, 132):
            by_source: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
            for rect in rects:
                by_source.setdefault((rect[0], rect[1]), []).append((rect[2], rect[3]))
            every = _merged(by_source.pop((0, 65535), []))
            out += [f"{name}/{_span(low, high)}" for low, high in every]
            for (first, last), ports in sorted(by_source.items()):
                for low, high in _merged(ports):
                    if not any(a <= low and high <= b for a, b in every):
                        out.append(f"{name}/{_span(low, high)} from port {_span(first, last)}")
        elif number in (1, 58):
            by_code: Dict[Tuple[int, int], List[Tuple[int, int]]] = {}
            for rect in rects:
                by_code.setdefault((rect[2], rect[3]), []).append((rect[0], rect[1]))
            for (first, last), kinds in sorted(by_code.items()):
                for low, high in _merged(kinds):
                    code = "" if (first, last) == (0, 65535) else f" code {_span(first, last)}"
                    out.append(f"{name} type {_span(low, high)}{code}")
        else:
            out.append(name)
    return out


def _listed(items: Sequence[str], limit: Optional[int]) -> str:
    if limit is None or len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def _members(names: Sequence[str], negated: bool, limit: int = 4) -> str:
    if list(names) == [ANY] and not negated:
        return "any"
    return ("not " if negated else "") + _listed(list(names), limit)


# -- what is in the matrix -------------------------------------------------------------------------


@dataclass
class Entry:
    """What one rule allows from one zone to another."""

    rule: str  # its name; DEFAULT for traffic that no rule decides (``default`` says which of the two it is)
    origin: str
    sources: str  # as the rule names them
    destinations: str
    services: Services
    applications: List[str] = field(default_factory=list)  # empty: any application
    app_default: bool = False  # the applications on their default ports: which ports is not in the model
    unread: List[str] = field(default_factory=list)  # services of the rule that could not be read: ``services`` then holds any
    known: Optional[Services] = None  # with ``unread``: the services of the rule that could be read
    conditions: List[str] = field(default_factory=list)  # users, URL categories, a schedule
    approximate: bool = False  # at most this: part of the rule, or of the blocks above it, could not be read exactly
    through_nat: List[str] = field(default_factory=list)  # NAT rules that put the destination in this zone
    risky: List[str] = field(default_factory=list)
    industrial: List[str] = field(default_factory=list)
    default: bool = False  # not a rule: what the policy does with traffic no rule decides

    @property
    def everything(self) -> bool:
        """Any service, without an application or a service of its own that narrows it."""
        return not self.applications and not self.unread and self.services.everything()

    def what(self, limit: Optional[int] = None) -> str:
        if self.unread:
            read = service_items(self.known) if self.known is not None and not self.known.empty() else []
            ports = _listed(read + [f"service '{name}' (not read)" for name in self.unread], limit)
        else:
            ports = _listed(service_items(self.services), limit)
        if not self.applications:
            return ports
        text = "applications " + _listed(self.applications, limit)
        if self.app_default:
            return text + " on their default ports"
        return text if self.services.everything() and not self.unread else f"{text} on {ports}"

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"rule": self.rule, "sources": self.sources, "destinations": self.destinations,
                               "allows": self.what(), "any_service": self.everything}  # fmt: skip
        if self.default:
            out["by_default"] = True
        if self.applications:
            out["applications"] = self.applications
        for key, value in (("services_not_read", self.unread), ("conditions", self.conditions), ("through_nat", self.through_nat),
                           ("risky", self.risky), ("industrial", self.industrial)):  # fmt: skip
            if value:
                out[key] = value
        if self.approximate:
            out["approximate"] = True
        return out


@dataclass
class Cell:
    src: str
    dst: str
    entries: List[Entry] = field(default_factory=list)

    @property
    def services(self) -> Services:
        """Every service some rule allows here for some pair of addresses (applications aside)."""
        return _union([entry.services for entry in self.entries])

    @property
    def everything(self) -> bool:
        return any(entry.everything for entry in self.entries)

    @property
    def approximate(self) -> bool:
        return any(entry.approximate for entry in self.entries)

    def items(self) -> List[str]:
        """What is allowed here, as short texts."""
        if self.everything:
            return ["any"]
        out: List[str] = []
        plain = [entry.known if entry.unread else entry.services for entry in self.entries if not entry.applications]
        if any(one is not None and not one.empty() for one in plain):
            out += service_items(_union([one for one in plain if one is not None]))
        for entry in self.entries:
            for item in ["app:" + name for name in entry.applications] + ["svc:" + name for name in entry.unread]:
                if item not in out:
                    out.append(item)
        return out

    def brief(self, width: int) -> str:
        """The cell of the grid: as much of what is allowed as fits."""
        items = self.items()
        mark = "~" if self.approximate else ""
        shown: List[str] = []
        for position, item in enumerate(items):
            rest = len(items) - position - 1
            if len(" ".join(shown + [item])) + (len(f" +{rest}") if rest else 0) + len(mark) > width:
                break
            shown.append(item)
        hidden = len(items) - len(shown)
        if not shown:
            more = f" +{hidden - 1}" if hidden > 1 else ""
            return _fit(items[0], max(width - len(more) - len(mark), 4)) + more + mark
        return " ".join(shown) + (f" +{hidden}" if hidden else "") + mark


@dataclass
class Matrix:
    vendor: str
    zones: List[str]
    by_network: bool
    cells: Dict[Tuple[str, str], Cell] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    rules: int = 0
    disabled: int = 0
    dead: int = 0
    networks: Dict[str, List[str]] = field(default_factory=dict)
    behind: Dict[str, List[str]] = field(default_factory=dict)
    other: str = OTHER  # the label of the zones nobody names (another one when a zone of the policy has that very name)
    reading: List[str] = field(default_factory=list)  # what the parser said about the policy as a whole
    not_read: List[str] = field(default_factory=list)  # rules of the source that are not in the model
    not_shown: List[str] = field(default_factory=list)  # rules that allow something and are in no cell

    def cell(self, src: str, dst: str) -> Cell:
        return self.cells.get((src, dst)) or Cell(src, dst)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "zones": self.zones,
            "zones_are": "networks" if self.by_network else "the zones of the policy",
            "rules": {"total": self.rules, "disabled": self.disabled, "never_match": self.dead},
            "conduits": [
                {"from": cell.src, "to": cell.dst, "allowed": cell.items(), "any_service": cell.everything,
                 "approximate": cell.approximate, "rules": [entry.to_dict() for entry in cell.entries]}
                for cell in self._ordered()
            ],
            "notes": self.notes,
            "from_reading": self.reading,
            "rules_not_read": self.not_read,
            "rules_in_no_conduit": self.not_shown,
        }  # fmt: skip
        if self.by_network:
            out["networks"] = self.networks
            out["behind"] = self.behind
        return out

    def _ordered(self) -> List[Cell]:
        return [self.cells[(src, dst)] for src in self.zones for dst in self.zones if (src, dst) in self.cells]

    def to_csv(self) -> str:
        """A line per rule and conduit, for a spreadsheet."""
        handle = io.StringIO()
        writer = csv.writer(handle, lineterminator="\r\n")  # (RFC 4180, as the other CSV files: 0.36.0)
        writer.writerow(["from", "to", "rule", "sources", "destinations", "allows", "any_service", "conditions", "through_nat",
                         "risky", "industrial", "approximate", "by_default"])  # fmt: skip
        for cell in self._ordered():
            for entry in cell.entries:
                writer.writerow([_plain(cell.src), _plain(cell.dst), _plain(entry.rule), _plain(entry.sources), _plain(entry.destinations),
                                 _plain(entry.what()), "yes" if entry.everything else "no", _plain("; ".join(entry.conditions)),
                                 _plain("; ".join(entry.through_nat)), _plain("; ".join(entry.risky)),
                                 _plain("; ".join(entry.industrial)), "yes" if entry.approximate else "no",
                                 "yes" if entry.default else "no"])  # fmt: skip
        return handle.getvalue()

    def to_text(self, summary: bool = False, width: int = 0) -> str:
        zones = self.zones
        out: List[str] = []
        if not zones:
            return "Nothing to show: no rule of the policy allows anything, and nothing is allowed by default.\n"
        if self.by_network:
            out.append("Zones (given as networks)")
            out += [f"  {zone}: {', '.join(self.networks[zone])}"
                    + (f" (behind zone {', '.join(self.behind[zone])} of the policy)" if zone in self.behind else "")
                    for zone in zones if zone in self.networks]  # fmt: skip
            if ELSEWHERE in zones:
                out.append(f"  {ELSEWHERE}: every other address")
            out.append("  (of two networks, one inside the other, the smaller one decides)")
            out.append("")
        column = width or max(16, min(24, max(len(zone) for zone in zones)))
        first = max(len(zone) for zone in zones)
        out.append("What each zone may reach (rows: from, columns: to)")
        out.append(("  " + " " * first + "".join(f"  {_fit(zone, column):<{column}}" for zone in zones)).rstrip())
        for src in zones:
            line = f"  {src:<{first}}"
            for dst in zones:
                cell = self.cells.get((src, dst))
                line += f"  {(cell.brief(column) if cell else '-'):<{column}}"
            out.append(line.rstrip())
        out.append("  -  nothing is allowed     any  every service     +N  and N more     ~  at most this (see the notes)")
        cells = self._ordered()

        def said(entry: Entry) -> str:
            if entry.default:
                text = f"  by default, what no rule decides: {entry.what(8)}"
            else:
                text = f"  rule '{_fit(entry.rule, 100)}': {_fit(entry.sources, 100)} -> {_fit(entry.destinations, 100)}: {entry.what(8)}"
            extra = list(entry.conditions) + [f"through NAT rule {_fit(nat, 60)}" for nat in entry.through_nat]
            return text + (f" ({'; '.join(extra)})" if extra else "") + (" ~" if entry.approximate else "")

        # A rule for every zone is in every conduit: where there are many conduits it is said once.
        everywhere: Dict[Tuple[str, str], int] = {}
        if not summary and len(cells) >= 9:
            for cell in cells:
                for entry in cell.entries:
                    key = (entry.origin, said(entry))
                    everywhere[key] = everywhere.get(key, 0) + 1
            everywhere = {key: count for key, count in everywhere.items() if count == len(cells)}
        if everywhere:
            out += ["", "In every conduit"] + [text for _, text in everywhere]
        out += ["", "Conduits"]
        if not cells:
            out.append("  none: no rule that was read allows anything between these zones")
        for cell in cells:
            special = (self.other,) + ((ELSEWHERE,) + tuple(zone for zone in zones if zone not in self.networks) if self.by_network else ())
            inside = cell.src == cell.dst and cell.src not in special
            out.append(f"{cell.src} -> {cell.dst}" + (" (inside the zone)" if inside else ""))
            out.append("  allowed: " + _listed(cell.items(), 12) + (" ~" if cell.approximate else ""))
            for label, found in (("cleartext or remote administration", _named(cell, "risky")),
                                 ("industrial protocols", _named(cell, "industrial"))):  # fmt: skip
                if found:
                    out.append(f"  {label}: {found}")
            if summary:
                continue
            own = [text for entry in cell.entries for text in [said(entry)] if (entry.origin, text) not in everywhere]
            out += own
            if everywhere:
                out.append(f"  and the {len(everywhere)} listed under 'In every conduit'")
        if self.not_read:
            out += ["", "Not in the matrix",
                    f"  {len(self.not_read)} rule(s) of the source could not be read; what they allow is not shown: "
                    + _listed([repr(_fit(name, 60)) for name in self.not_read], 8)]  # fmt: skip
        if self.reading:
            out += ["", "From reading the configuration"] + [f"  {note}" for note in self.reading]
        if self.notes:
            out += ["", "Notes"] + [f"  {note}" for note in self.notes]
        return "\n".join(out) + "\n"


def _plain(text: str) -> str:
    """A field of the CSV that no spreadsheet takes for a formula (also after spaces, or in full-width forms)."""
    from .export import formula_safe

    return formula_safe(text)


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _named(cell: Cell, what: str) -> str:
    found: Dict[str, List[str]] = {}
    for entry in cell.entries:
        for name in getattr(entry, what):
            found.setdefault(name, []).append("the default" if entry.default else repr(_fit(entry.rule, 60)))
    return "; ".join(f"{name} ({'' if rules == ['the default'] else 'rule '}{_listed(rules, 3)})" for name, rules in found.items())


# -- building it -----------------------------------------------------------------------------------


@dataclass
class NetworkZone:
    """A zone of the user's own: networks, and (if known) the zones of the policy they lie behind."""

    name: str
    networks: List[str] = field(default_factory=list)
    behind: List[str] = field(default_factory=list)  # empty: not known, so the zones of the policy do not place a rule


def _readable(text: str, limit: int = 40) -> str:
    """Text from the command line, for a message: on one line whatever it holds."""
    return "".join(letter if letter.isprintable() else "?" for letter in text[:limit])


def parse_networks(values: Sequence[str], option: str = "--network-zone") -> Dict[str, NetworkZone]:
    """``NAME[@ZONE[,ZONE...]]=NETWORK[,NETWORK...]``, repeatable: the zones of a matrix as networks."""
    out: Dict[str, NetworkZone] = {}
    for value in values:
        left, sep, networks = value.partition("=")
        name, at, behind = left.partition("@")
        name = name.strip()
        listed = [network.strip() for network in networks.split(",")]
        parsed = [parse_literal(network) for network in listed]
        zones = [zone.strip() for zone in behind.split(",")] if at else []
        if not sep or not name or any(one is None for one in parsed) or not all(zones):
            raise FwshiftError(f"{option} expects NAME=NETWORK[,NETWORK...] or NAME@ZONE=NETWORK[,NETWORK...], "
                               f"got '{_readable(value, 60)}'")  # fmt: skip
        if name in (ELSEWHERE, OTHER, ANY, DEFAULT) or not name.isprintable():
            raise FwshiftError(f"{option}: '{_readable(name)}' cannot be the name of a zone")
        zone = out.setdefault(name, NetworkZone(name))
        for one in parsed:
            text = interval_text(one) if one is not None else ""  # the network as it is, whatever host bits were given
            if text not in zone.networks:
                zone.networks.append(text)
        zone.behind += [z for z in dict.fromkeys(zones) if z not in zone.behind]
    return out


def _spaces(zones: Dict[str, NetworkZone]) -> Dict[str, List[Interval]]:
    """The addresses of each zone. Of two networks, one inside the other, the smaller one decides, as a route would."""
    given = {name: [interval for network in zone.networks for interval in [parse_literal(network)] if interval]
             for name, zone in zones.items()}  # fmt: skip
    names = list(given)
    for position, first in enumerate(names):
        for second in names[position + 1 :]:
            same = [interval for interval in given[first] if interval in given[second]]
            if same:
                raise FwshiftError(f"--network-zone: {interval_text(same[0])} is in zone '{_readable(first)}' and in zone "
                                   f"'{_readable(second)}'")  # fmt: skip
    raw = {name: normalize(listed) for name, listed in given.items()}
    out: Dict[str, List[Interval]] = {}
    for name, mine in raw.items():
        inner = [theirs for other, listed in raw.items() if other != name for theirs in listed
                 if any(a[0] == theirs[0] and a[1] <= theirs[1] and theirs[2] <= a[2] and a != theirs for a in mine)]  # fmt: skip
        out[name] = subtract(mine, normalize(inner))
    for position, first in enumerate(names):
        for second in names[position + 1 :]:
            shared = intersect(out[first], out[second])
            if shared:
                raise FwshiftError(f"--network-zone: {interval_text(shared[0])} is in zone '{_readable(first)}' and in zone "
                                   f"'{_readable(second)}'")  # fmt: skip
    return out


def _rest(sets: _Sets, boxes: List[Box], covers: Sequence[Box]) -> Optional[List[Box]]:
    """What is left of boxes without the covers, the largest first; None when it falls into too many pieces."""
    left = boxes
    for cover in sorted(covers, key=lambda box: -sets.weight(box)):
        left = sets.take(left, cover)[0]
        if not left:
            return []
        if len(left) > _MAX_BOXES:
            return None
    return left


class _Held:
    """What is being gathered for one rule in one cell."""

    __slots__ = ("entry", "first", "more", "nats", "approximate")

    def __init__(self, entry: Entry, services: Services) -> None:
        self.entry = entry
        # Mostly one set of services, and no NAT rule: with thousands of rules for every zone that is what counts.
        self.first = services
        self.more: Optional[Dict[int, Services]] = None
        self.nats: Optional[List[str]] = None
        self.approximate = False

    def add(self, services: Services) -> None:
        if services is not self.first:
            if self.more is None:
                self.more = {}
            self.more[id(services)] = services

    @property
    def parts(self) -> List[Services]:
        return [self.first] + (list(self.more.values()) if self.more else [])


Place = Tuple[str, str, str, bool]  # from, to, the NAT rule that puts the destination there, whether that is a guess


class _Builder:
    def __init__(self, p: Policy, config: AuditConfig, reading: Optional[Any], networks: Optional[Dict[str, NetworkZone]]) -> None:
        self.p = p
        read = Reading.of(reading) if reading is not None else None
        # Which rules never match is asked of the policy as it is.
        self.audit = _Audit(p, _order_only(config), read)
        self.audit.order()
        self.dead = {self.audit.matches[index].rule.origin or self.audit.matches[index].rule.name for index in self.audit.dead}
        self.sets = self.audit.sets
        self.zones = self.audit.reader.zones
        self.config = config
        known = [name for name in self.zones.names if name != _OTHER]
        self.other = OTHER
        while self.other in known:
            self.other += "*"  # a zone of the policy has that very name
        # An iptables ruleset is for one IP version (an nftables one, where only one version has a forward chain): what it does not decide in the other is not its default.
        self.families = [FULL_V4, FULL_V6]
        if p.vendor in ("iptables", "nftables") and p.scope in ("IPv4", "IPv6"):
            self.families = [FULL_V4 if p.scope == "IPv4" else FULL_V6]
        self.by_network = networks is not None
        self.spaces: Dict[str, List[Interval]] = {}
        self.behind: Dict[str, int] = {}  # zone of the user -> the zones of the policy it lies behind, as bits
        self.given = networks or {}
        self.unnamed: List[str] = []  # zones the user names that the policy does not
        if networks is not None:
            self.spaces = _spaces(networks)
            taken = normalize([interval for intervals in self.spaces.values() for interval in intervals])
            elsewhere = subtract(_EVERY_ADDRESS, taken)
            if elsewhere:
                self.spaces[ELSEWHERE] = elsewhere
            for name, zone in networks.items():
                # A zone the policy does not name is one of "the zones nobody names": a rule for any zone is for it.
                self.unnamed += [z for z in zone.behind if z not in known and z not in self.unnamed]
                if zone.behind:
                    self.behind[name] = self.zones.bits(zone.behind) | (self.zones.other if any(z not in known for z in zone.behind) else 0)
        self.limits = self._virtual_ips()
        self.translations = self._translations() if self.by_network and not p.lookup_after_dnat else []
        self.risky = {name: _union([s for spec in specs for s in [_spec_services(spec)] if s])
                      for name, specs in config.risky_services.items()}  # fmt: skip
        self.industrial = {name: _union([s for spec in specs for s in [_spec_services(spec)] if s])
                           for name, specs in config.industrial_services.items()}  # fmt: skip
        self.both_behind = 0  # while the default inside a zone is placed: the zone both ends have to lie behind
        self.same_unnamed = ""  # ... a zone the policy does not name, by its name
        self.rest: List[str] = []  # rows for the rest of a zone of the policy, as they come up
        self.found: Dict[Tuple[str, str], Dict[str, _Held]] = {}
        self.unfollowed: List[str] = []

    def _resolved(self, members: Sequence[str]) -> Optional[List[Interval]]:
        """The addresses of some members; None where one of them cannot be read."""
        out: List[Interval] = []
        for member in members:
            intervals = None if member == ANY else transform.address_intervals(self.p, member)
            if not intervals:
                return None
            out += intervals
        return normalize(out)

    def _virtual_ips(self) -> Dict[int, Tuple[List[Interval], bool]]:
        """Per allow rule that names a virtual IP: (where its traffic can end, whether that is known exactly).

        A FortiOS policy that names a virtual IP allows the traffic that virtual IP translates: at
        most everything sent to the address behind it. The name stays in the rule, so that a blocking
        policy for the same virtual IP above it is still seen to take its part.
        """
        p = self.p
        out: Dict[int, Tuple[List[Interval], bool]] = {}
        if not p.named_translations:
            return out
        behind = {t.pre: t.post for t in transform.destination_translations(p)}
        for match in self.audit.matches:
            rule = match.rule
            if _blocks(rule) or rule.negate_destination or not any(member in behind for member in match.destinations):
                continue
            ends: List[Interval] = []
            exact = True
            for member in match.destinations:
                if member in behind:
                    known = self._resolved([behind[member]])
                else:
                    sure, complete = self.audit.reader._sure(member)
                    known = sure if complete else None
                if known is None:
                    ends, exact = list(_EVERY_ADDRESS), False
                    break
                ends += known
            out[match.index] = (normalize(ends), exact)
        return out

    def _translations(self) -> List[Tuple[str, List[Interval], Optional[List[Interval]]]]:
        """Destination NAT of a source that matches its rules before it: (NAT rule, addresses before, addresses after).

        Every rule that translates a destination counts, whatever its shape: where the addresses
        before cannot be read they are taken to be any, where those after cannot, None.
        """
        out: List[Tuple[str, List[Interval], Optional[List[Interval]]]] = []
        for nat in self.p.nat_rules:
            dnat, snat = nat.destination_translation, nat.source_translation
            if not nat.enabled:
                continue
            if dnat is not None:
                before, after = self._resolved(nat.destinations), self._resolved([dnat.address])
            elif snat is not None and snat.kind == SnatKind.STATIC and snat.bidirectional:
                before, after = self._resolved(snat.addresses), self._resolved(nat.sources)  # the way in of a static NAT
            else:
                continue
            out.append((nat.name, before if before is not None else list(_EVERY_ADDRESS), after))
        return out

    # .. where a box lies

    def _zone_names(self, bits: int) -> List[str]:
        return [self.other if name == _OTHER else name for position, name in enumerate(self.zones.names) if bits >> position & 1]

    def _rest_label(self, name: str) -> str:
        """The row for "this zone of the policy, at an address that is in none of the networks given for it"."""
        label = self.other if name == self.other else f"({name}: other addresses)"
        if label not in self.behind:
            self.behind[label] = self.zones.other if name == self.other else self.zones.bits([name])
            self.rest.append(label)
        return label

    def _side(self, addresses: List[Interval], zone_bits: int, named: bool, explained: Sequence[Interval] = (),
              ended: bool = False) -> List[str]:  # fmt: skip
        """The zones of the user that one side of a box lies in.

        A zone that is known to lie behind zones of the policy takes a rule only when the rule is
        for one of those. What does not fit is not left out where that would hide something:

        * a zone of the policy that none of the zones given lies behind gets a row for itself
          ("the rest of the zone", which is then all of it), unless the addresses lie in a zone
          that is not tied to any zone of the policy (``ended``: or a NAT rule says where they end);
        * an address that the rule *names* and that lies, by the networks given, behind another
          zone than the rule is for, puts the rule in the row for the rest of its own zones: the
          networks given need not be all there is behind a zone. A rule for any address names none.
        """
        behind = self.behind
        fits: List[str] = []
        astray = free = False
        for zone, space in self.spaces.items():
            part = intersect(addresses, space)
            if not part:
                continue
            if zone not in behind:
                fits.append(zone)
                free = True
            elif behind[zone] & zone_bits:
                fits.append(zone)
            elif named and subtract(part, explained):
                astray = True
        if not behind or (free and not astray):
            return fits
        given = [bits for zone, bits in behind.items() if zone in self.spaces]
        for name in self._zone_names(zone_bits):
            bit = self.zones.other if name == self.other else self.zones.bits([name])
            if astray or not (free or ended or any(bits & bit for bits in given)):
                fits.append(self._rest_label(name))
        return fits

    def places(self, box: Box, named: Tuple[bool, bool] = (False, False)) -> List[Place]:
        """Every pair of zones a box reaches. ``named``: whether the rule names its sources, its destinations."""
        out: List[Place] = []
        possible = self.zones.possible
        if not self.by_network:
            bits = self.zones.bits
            for src in self._zone_names(box[0]):
                a = self.zones.other if src == self.other else bits([src])
                for dst in self._zone_names(box[1]):
                    b = self.zones.other if dst == self.other else bits([dst])
                    if possible(a, b, box[2]):
                        out.append((src, dst, "", False))
            return out
        behind, both = self.behind, self.both_behind
        # Where a source matches before destination NAT, the traffic ends where the translated address lies;
        # where that cannot be read, in any zone.
        through: List[Tuple[str, str, bool]] = []
        translated: List[Interval] = []
        for nat, before, after in self.translations:
            if intersect(box[4], before):
                translated += before
                through += [(zone, nat, after is None) for zone, space in self.spaces.items() if after is None or intersect(after, space)]
        sources = self._side(box[3], box[0], named[0])
        ended = any(zone not in behind or behind[zone] & box[1] for zone, _, _ in through)  # somewhere the rule is for
        targets = [(zone, "", False) for zone in self._side(box[4], box[1], named[1], normalize(translated), ended)]
        direct = {zone for zone, _, _ in targets}
        targets += [target for target in through if target[0] not in direct]
        seen = set()
        for src in sources:
            for dst, nat, unsure in targets:
                if (src, dst, nat) in seen or not possible(box[0] & behind.get(src, box[0]), box[1] & behind.get(dst, box[1]), box[2]):
                    continue
                if both and not (behind.get(src, 0) & both and behind.get(dst, 0) & both):
                    continue
                if self.same_unnamed and not all(z in self.given and self.same_unnamed in self.given[z].behind for z in (src, dst)):
                    continue  # (inside one zone the policy does not name: both ends behind that one)
                seen.add((src, dst, nat))
                out.append((src, dst, nat, unsure))
        return out

    def note(self, place: Place, entry: Entry, services: Services) -> None:
        src, dst, nat, guessed = place
        cell = self.found.setdefault((src, dst), {})
        held = cell.get(entry.origin)
        if held is None:
            held = cell[entry.origin] = _Held(entry, services)
        else:
            held.add(services)
        if guessed:
            held.approximate = True
        if nat:
            if held.nats is None:
                held.nats = []
            if nat not in held.nats:
                held.nats.append(nat)

    # .. the rules

    def rules(self) -> List[str]:
        """Place every rule that allows something. Returns the rules that ended up in no cell."""
        sets, audit = self.sets, self.audit
        nowhere: List[str] = []
        for match in audit.matches:
            rule = match.rule
            origin = rule.origin or rule.name
            # A rule the model does not hold exactly may match anything in its zones, and may allow it whatever its action.
            wild = bool(rule.unsupported)
            if not rule.enabled or (_blocks(rule) and not wild) or (origin in self.dead and not wild) or not match.over:
                continue
            covers = [cover for earlier in audit._near(match, audit.matches[: match.index])
                      if earlier.covers and _blocks(earlier.rule) and sets.may_meet(earlier, match)
                      for cover in [sets.cover(earlier, match)] if cover is not None]  # fmt: skip
            over = list(match.over)
            if wild:
                over = [(match.zones[0], match.zones[1], match.zones[2], [family], [family], _ALL_SERVICES) for family in self.families]
            left = _rest(sets, over, covers)
            by_application = rule.applications != [ANY] and rule.services == [APP_DEFAULT]  # said in so many words
            limit = self.limits.get(match.index)
            target_exact = match.dst_over == match.dst_under if limit is None else limit[1]
            exact = (match.src_over == match.src_under and target_exact and not match.loose
                     and not rule.unsupported and (by_application or match.svc_over.minus(match.svc_under).empty()))  # fmt: skip
            if wild:
                exact = False
            if left is None:
                left, exact = over, False
                self.unfollowed.append(rule.name)
            if limit is not None:
                left = [(box[0], box[1], box[2], box[3], ends, box[5]) for box in left for ends in [intersect(box[4], limit[0])] if ends]
            entry = Entry(
                rule.name, origin, _members(match.sources, rule.negate_source), _members(match.destinations, rule.negate_destination),
                Services(), [] if rule.applications == [ANY] else list(rule.applications), by_application,
                conditions=_conditions(rule), approximate=not exact,
            )  # fmt: skip
            if not by_application and not rule.negate_service:
                # Services that cannot be read are named, where the alternative is to call the rule open for everything.
                read = [(name, *audit.reader.service_set([name])) for name in rule.services if name != ANY]
                entry.unread = [name for name, _, complete in read if not complete]
                entry.known = _union([known for _, known, complete in read if complete]) if entry.unread else None
            placed = False
            named = (rule.sources != [ANY] and not rule.negate_source and match.src_over == match.src_under,
                     rule.destinations != [ANY] and not rule.negate_destination and match.dst_over == match.dst_under)  # fmt: skip
            for box in left:
                for place in self.places(box, named):
                    self.note(place, entry, box[5])
                    placed = True
            if not placed:
                nowhere.append(rule.name)
        return nowhere

    # .. what no rule decides

    def _undecided(self, boxes: List[Box]) -> Optional[List[Box]]:
        """What is left of boxes once every rule took what it surely takes."""
        covers: List[Box] = []
        possible = self.zones.possible
        for match in self.audit.matches:
            rule = match.rule
            if not match.covers or rule.applications != [ANY] or rule.users != [ANY] or rule.url_categories != [ANY] or rule.schedule:
                continue
            if any(possible(box[0] & match.zones[0], box[1] & match.zones[1], box[2] & match.zones[2]) for box in boxes):
                covers.append((match.zones[0], match.zones[1], match.zones[2], match.src_under, match.dst_under, match.svc_under))
        return _rest(self.sets, boxes, covers)

    def _allowed_inside(self, zone: str) -> bool:
        known = self.p.zones.get(zone)
        if known is not None and known.intrazone_allow is not None:
            return known.intrazone_allow
        return self.p.default_intrazone == Action.ALLOW

    def defaults(self) -> List[str]:
        """The traffic no rule decides, where the policy lets it through. Returns notes."""
        p, zones, notes = self.p, self.zones, []
        entry = Entry(DEFAULT, "\0default", "any", "any", Services(), default=True)
        loose = copy.copy(entry)
        loose.approximate = True
        between = p.default_interzone == Action.ALLOW

        def universe(src: int, dst: int, relation: int) -> List[Box]:
            return [(src, dst, relation, [family], [family], _ALL_SERVICES) for family in self.families]

        def add(boxes: List[Box]) -> None:
            left = self._undecided(boxes)
            for box in left if left is not None else boxes:
                for place in self.places(box):
                    self.note(place, entry if left is not None else loose, box[5])

        names = [name for name in zones.names if name != _OTHER]
        inside = [name for name in names if self._allowed_inside(name)]
        if self.by_network:
            if between:
                add(universe(zones.all, zones.all, _DIFFERENT))
            # Inside a zone of the policy: only between zones that are known to lie behind it.
            for name in inside:
                if sum(1 for bits in self.behind.values() if bits & zones.bits([name])):
                    self.both_behind = zones.bits([name])
                    add(universe(zones.bits([name]), zones.bits([name]), _SAME))
                    self.both_behind = 0
            # And inside a zone the policy does not name, where zones given lie behind it: it has the default too.
            if p.default_intrazone == Action.ALLOW:
                for name in self.unnamed:
                    self.both_behind, self.same_unnamed = zones.other, name
                    add(universe(zones.other, zones.other, _SAME))
                    self.both_behind, self.same_unnamed = 0, ""
            unbound = [zone for zone in self.spaces if zone not in self.behind]
            if (inside or p.default_intrazone == Action.ALLOW) and unbound:
                which = "every zone" if p.default_intrazone == Action.ALLOW and len(inside) == len(names) else "zone " + ", ".join(inside)
                notes.append(f"Traffic inside {which} of the policy that no rule decides is allowed. For {_listed(unbound, 6)} it is "
                             "not known which zone of the policy they lie behind (NAME@ZONE=... says it): what that default allows "
                             "them is NOT in the matrix.")  # fmt: skip
            return notes
        # The zones nobody names have the defaults too. They are in the matrix when a rule reaches them, or
        # when everything between zones is open anyway.
        others = between or any(self.other in pair for pair in self.found)
        bits = {name: zones.bits([name]) for name in names}
        if others:
            bits[_OTHER] = zones.other
        if between:
            for src, a in bits.items():
                for dst, b in bits.items():
                    if src != dst or src == _OTHER:
                        add(universe(a, b, _DIFFERENT))
        for name in inside:
            add(universe(bits[name], bits[name], _SAME))
        if others and p.default_intrazone == Action.ALLOW:
            add(universe(zones.other, zones.other, _SAME))
        return notes

    # .. the result

    def _entry(self, held: _Held, made: Dict[Tuple[object, ...], Entry]) -> Entry:
        """The entry of a cell; cells that hold the same of a rule share it."""
        parts = held.parts
        key = (held.entry.origin, held.entry.approximate or held.approximate, frozenset(map(id, parts)), tuple(held.nats or ()))
        entry = made.get(key)
        if entry is None:
            entry = made[key] = copy.copy(held.entry)
            entry.approximate = held.entry.approximate or held.approximate
            entry.through_nat = list(held.nats or ())
            entry.services = _union(parts)
            if not entry.everything:
                # ("Every protocol but ..." is as good as any: the lists are for rules that name what they allow.)
                wide = entry.services.rest
                entry.risky = [name for name, services in self.risky.items() if not wide and entry.services.meets(services)]
                entry.risky += [app for app in entry.applications if app in self.config.risky_applications and app not in entry.risky]
                entry.industrial = [name for name, services in self.industrial.items() if not wide and entry.services.meets(services)]
                entry.industrial += [app for app in entry.applications
                                     if app in self.config.industrial_applications and app not in entry.industrial]  # fmt: skip
        return entry

    def result(self) -> Matrix:
        p = self.p
        notes = []
        nowhere = self.rules()
        notes += self.defaults()
        order = {rule.origin or rule.name: position for position, rule in enumerate(p.rules)}
        names = list(self.spaces) if self.by_network else [name for name in self.zones.names if name != _OTHER]
        if not self.by_network and any(self.other in pair for pair in self.found):
            names.append(self.other)
        names += [label for label in self.rest if any(label in pair for pair in self.found)]
        matrix = Matrix(p.vendor, names, self.by_network, rules=len(p.rules), disabled=sum(1 for rule in p.rules if not rule.enabled),
                        dead=len(self.dead), other=self.other, not_shown=nowhere)  # fmt: skip
        made: Dict[Tuple[object, ...], Entry] = {}
        for (src, dst), cell in self.found.items():
            matrix.cells[(src, dst)] = Cell(src, dst, [self._entry(held, made) for _, held in
                                                       sorted(cell.items(), key=lambda item: order.get(item[0], len(order)))])  # fmt: skip
        if nowhere:
            notes.append(f"{len(nowhere)} rule(s) that allow something are in NO conduit: {_listed([repr(_fit(name, 60)) for name in nowhere], 8)}. "
                         "Their zones and their addresses do not go together with the networks given.")  # fmt: skip
        if self.by_network:
            matrix.networks = {name: list(zone.networks) for name, zone in self.given.items()}
            matrix.behind = {name: list(zone.behind) for name, zone in self.given.items() if zone.behind}
            unbound = [zone for zone in self.spaces if zone not in self.behind]
            if unbound:
                notes.insert(0, f"For {_listed(unbound, 6)} it is not known which zone of the policy they lie behind: a rule is shown "
                                "there wherever its addresses reach, whatever zones it names. A rule for 'any' address is then in "
                                "every such row or column. NAME@ZONE=NETWORK says which zone it is.")  # fmt: skip
            if self.unnamed:
                known = [name for name in self.zones.names if name != _OTHER]
                notes.append(f"The policy names no zone {_listed([repr(_readable(z)) for z in self.unnamed], 6)}"
                             + (f" (it names {_listed(known, 12)})" if known else "")
                             + ": only rules for 'any' zone are shown for what lies behind it. Check the spelling.")  # fmt: skip
            if any(label in names for label in self.rest):
                notes.append("(ZONE: other addresses): traffic of zone ZONE of the policy at addresses that are in none of the "
                             "networks given as lying behind it: all of the zone, where no zone given lies behind it; otherwise the "
                             "rules that name an address which lies, by the networks given, behind another zone than the rule is "
                             "for. The networks given need not be all there is behind a zone.")  # fmt: skip
            if self.translations:
                unread = sum(1 for _, _, after in self.translations if after is None)
                notes.append(f"{len(self.translations)} destination NAT rule(s): this source matches its rules on the address before "
                             "translation. A rule for a published address is also shown for the zone of the server behind it"
                             + (f"; for {unread} of them the translated address cannot be read, and the rule is shown for every "
                                "zone it could end in, marked ~." if unread else "."))  # fmt: skip
            elif p.lookup_after_dnat and any(nat.destination_translation for nat in p.nat_rules):
                notes.append("This source matches its rules after destination NAT: a published service is shown for the zone of the "
                             "server, not for the address it is published on.")  # fmt: skip
        elif names == [self.other]:
            notes.append("The policy names no zones, so the matrix has one cell. Give zones as networks with --network-zone "
                         "NAME=NETWORK[,NETWORK...] to see who reaches whom.")  # fmt: skip
        elif self.other in names:
            notes.append(f"{self.other}: zones the policy does not name. A rule for 'any' zone applies to them as well.")
        if len(self.families) == 1:
            notes.append(f"An {p.vendor} ruleset is for one IP version, here {p.scope}: the matrix says nothing about the other.")
        if self.dead:
            notes.append(f"{len(self.dead)} rule(s) never match and are left out; 'fwshift audit' names them.")
        if any(rule.unsupported and rule.enabled for rule in p.rules):
            notes.append("A rule the model does not hold exactly (its findings say why) is shown wherever its zones reach, on every "
                         "service, whatever its action, marked ~: what it really does is not known.")  # fmt: skip
        if any(cell.approximate for cell in matrix.cells.values()):
            notes.append("~ at most this. Part of the rule could not be read exactly (a host name, a dynamic or unsupported object, a "
                         "rule the parser reported as approximated), the blocking rules above it could not be followed, or the "
                         "address a NAT rule translates to cannot be read.")  # fmt: skip
        if any(entry.applications for cell in matrix.cells.values() for entry in cell.entries):
            notes.append("app:NAME: allowed for that application only. Which ports it uses is not looked up here.")
        if any(entry.unread for cell in matrix.cells.values() for entry in cell.entries):
            notes.append("svc:NAME: a service of the source that could not be read (an application or category of the vendor, a "
                         "service without ports). The rule allows that, whatever it is.")  # fmt: skip
        notes.append("The matrix shows what the policy can allow for some pair of addresses of two zones, not that every address may. "
                     "It is read from the configuration: routing, NAT that fails and what listens on a port are not in it.")  # fmt: skip
        matrix.notes = notes
        return matrix


def _conditions(rule: Rule) -> List[str]:
    out: List[str] = []
    if rule.users != [ANY]:
        out.append("users " + _listed(rule.users, 3))
    if rule.url_categories != [ANY]:
        out.append("URL categories " + _listed(rule.url_categories, 3))
    if rule.schedule:
        out.append(f"schedule {rule.schedule}")
    if rule.unsupported:
        out.append("only with " + _listed([str(reason) for reason in rule.unsupported], 2) + ", which is not in the model")
    return out


def build(p: Policy, config: Optional[AuditConfig] = None, reading: Optional[Any] = None,
          networks: Optional[Dict[str, NetworkZone]] = None) -> Matrix:  # fmt: skip
    """The matrix of a policy. ``reading`` is the report its parser filled; ``networks`` gives zones as networks."""
    matrix = _Builder(p, config or AuditConfig(), reading, networks if networks else None).result()
    if reading is not None:
        # What the parser said about the policy as a whole: tables it did not read, traffic the source lets
        # through outside its rules. None of that is in the matrix, and a reader of the matrix has to know.
        matrix.reading = [f"{note.code}: {note.message}" for note in reading.notes]
        matrix.not_read = [item.name for item in reading.items.values() if item.kind == "rule" and item.skipped]
    return matrix


__all__ = ["DEFAULT", "ELSEWHERE", "OTHER", "Cell", "Entry", "Matrix", "NetworkZone", "build", "parse_networks", "service_items"]
