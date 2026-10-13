# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""A zone and conduit model as a file, and a policy checked against it.

The model says which zone may open connections to which, on which services: the conduits of an
IEC 62443 zone and conduit model, kept next to the firewall that enforces them. A policy is checked
against it through its zone matrix (:mod:`fwshift.matrix`): every connection the policy can allow
between two zones must lie within a conduit between them. What it allows beyond is a finding; so is
a conduit the policy keeps closed.

The file is JSON::

    {
      "fwshift": "zone-conduit-model", "version": 1, "name": "Plant 1",
      "zones": [
        {"name": "enterprise", "networks": ["10.10.0.0/16"], "policy_zones": ["trust"], "sl_t": 2},
        {"name": "control", "networks": ["10.30.0.0/16"], "sl_t": 3, "inside": ["tcp/102", "tcp/502"]}
      ],
      "conduits": [
        {"name": "eng-to-plc", "from": "enterprise", "to": "control", "services": ["tcp/102", "tcp/502"]}
      ]
    }

Zones are networks (every zone has ``networks``; ``policy_zones`` says which zones of the policy they
lie behind), or zones of the policy (no zone has networks; ``policy_zones`` lists the zones of the
policy a zone of the model stands for, by default its own name; ``*`` stands for the zones the policy
does not name). ``from`` is the zone that opens the connection; ``both_ways`` makes a conduit hold the
other way round as well. ``inside`` lists what may pass between two addresses of one zone; without it
that traffic is not checked. ``sl_t`` (0 to 4), ``description`` and ``name`` are kept as documentation.

What the check rests on: the matrix shows what the policy can allow, more where it cannot be exact
(marked, and then a finding is "possible"), so a check that passes holds for the policy as the model of
FWShift reads it. The rules of the platform around the policy (implicit rules, routing) are not in it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from . import appmap, matrix
from .audit import _ALL_SERVICES, _LEVEL_NAMES, AuditConfig, Level, Services, _entry_services, _port_ranges, _union
from .errors import FwshiftError
from .matrix import DEFAULT, ELSEWHERE, Cell, Entry, Matrix, NetworkZone, service_items
from .model import Action, Policy, Protocol, ServiceEntry
from .netutil import parse_literal

FORMAT = "zone-conduit-model"
VERSION = 1

# -- services of a conduit -------------------------------------------------------------------------


@dataclass
class Allowed:
    """What a conduit (or the inside of a zone) lets through."""

    services: Services = field(default_factory=Services)
    applications: Set[str] = field(default_factory=set)
    unread: Set[str] = field(default_factory=set)  # services of the source FWShift cannot read, by name (svc:NAME)

    def add(self, other: "Allowed") -> None:
        self.services = _union([self.services, other.services])
        self.applications |= other.applications
        self.unread |= other.unread


def parse_service(spec: str, where: str) -> Allowed:
    """One service of a conduit: ``any``, ``tcp/443``, ``udp/161-162``, ``tcp`` (every port), ``icmp``, ``icmp/8``,
    ``icmp/3/4``, ``icmp6/128``, ``ip/47``, ``esp``, ``app:NAME``, ``svc:NAME``."""
    text = str(spec).strip()
    lowered = text.lower()
    if lowered.startswith("app:") and len(text) > 4:
        return Allowed(applications={text[4:]})
    if lowered.startswith("svc:") and len(text) > 4:
        return Allowed(unread={text[4:]})
    if lowered == "any":
        return Allowed(services=_ALL_SERVICES)
    protocol, _, rest = lowered.partition("/")
    numbers = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "sctp": Protocol.SCTP}
    found: Optional[Services] = None
    if protocol in numbers:
        if not rest or _port_ranges(rest) is not None:
            found = _entry_services(ServiceEntry(numbers[protocol], rest))
    elif protocol in ("icmp", "icmp6"):
        kind = Protocol.ICMP if protocol == "icmp" else Protocol.ICMP6
        parts = rest.split("/") if rest else []
        if len(parts) <= 2 and all(part.isdigit() and int(part) <= 255 for part in parts):
            found = _entry_services(ServiceEntry(kind, icmp_type=int(parts[0]) if parts else None,
                                                 icmp_code=int(parts[1]) if len(parts) > 1 else None))  # fmt: skip
    elif protocol == "ip" and rest:
        number = appmap.protocol_number(rest)
        if number is not None:
            found = _entry_services(ServiceEntry(Protocol.IP, ip_protocol=number))
    elif not rest:
        number = appmap.protocol_number(lowered) if lowered not in ("icmp", "icmp6") else None
        if number is not None and number not in (6, 17, 132):
            found = _entry_services(ServiceEntry(Protocol.IP, ip_protocol=number))
    if found is None:
        raise FwshiftError(f"{where}: service '{text[:40]}' cannot be read (any, tcp/443, udp/161-162, icmp/8, ip/47, app:NAME, "
                           "svc:NAME)")  # fmt: skip
    return Allowed(services=found)


def specs_of(services: Services) -> List[str]:
    """A set of services as services of a conduit (source ports left out, so never fewer)."""
    if services.everything() or services.rest:
        return ["any"]
    out: List[str] = []
    for number in sorted(services.protocols):
        rects = services.protocols[number]
        if not rects:
            continue
        if number in (6, 17, 132):
            name = {6: "tcp", 17: "udp", 132: "sctp"}[number]
            ports = matrix._merged((rect[2], rect[3]) for rect in rects)
            out += [name if ports == [(0, 65535)] else f"{name}/{matrix._span(low, high)}" for low, high in ports]
        elif number in (1, 58):
            name = "icmp" if number == 1 else "icmp6"
            kinds = matrix._merged((rect[0], rect[1]) for rect in rects)
            if kinds == [(0, 65535)]:
                out.append(name)
            else:
                out += [f"{name}/{kind}" for low, high in kinds for kind in range(max(low, 0), min(high, 255) + 1)]
        else:
            out.append(f"ip/{number}")
    return out


# -- the model -------------------------------------------------------------------------------------


@dataclass
class Zone:
    name: str
    networks: List[str] = field(default_factory=list)
    policy_zones: List[str] = field(default_factory=list)
    sl_t: Optional[int] = None
    description: str = ""
    inside: Optional[Allowed] = None
    inside_specs: List[str] = field(default_factory=list)


@dataclass
class Conduit:
    name: str
    src: str
    dst: str
    specs: List[str]
    allowed: Allowed
    both_ways: bool = False
    sl_t: Optional[int] = None
    description: str = ""


@dataclass
class ZoneModel:
    name: str
    zones: Dict[str, Zone]
    conduits: List[Conduit]
    by_network: bool

    def between(self, src: str, dst: str) -> List[Conduit]:
        """The conduits that let a zone open connections to another."""
        return [c for c in self.conduits if (c.src, c.dst) == (src, dst) or (c.both_ways and (c.dst, c.src) == (src, dst))]


_ZONE_KEYS = ("name", "networks", "policy_zones", "sl_t", "description", "inside")
_CONDUIT_KEYS = ("name", "from", "to", "services", "both_ways", "sl_t", "description")
_MODEL_KEYS = ("fwshift", "version", "name", "description", "zones", "conduits")
_RESERVED = (ELSEWHERE, matrix.OTHER, DEFAULT, "any")


def _strings(value: Any, where: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise FwshiftError(f"{where}: expected a list of strings")
    return [item.strip() for item in value]


def _level(value: Any, where: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 4:
        raise FwshiftError(f"{where}: sl_t is a security level from 0 to 4")
    return int(value)


def _keys(entry: Dict[str, Any], allowed: Sequence[str], where: str) -> None:
    extra = [key for key in entry if key not in allowed]
    if extra:
        raise FwshiftError(f"{where}: unknown key(s) {', '.join(repr(k) for k in extra[:4])} (known: {', '.join(allowed)})")


def load_model(text: str, where: str = "the zone and conduit model") -> ZoneModel:
    """Read and check a model file; every mistake is an error, rather than a check that passes by it."""
    def unique(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"the key '{key[:40]}' is given twice")
            out[key] = value
        return out

    try:
        document = json.loads(text, object_pairs_hook=unique)
    except ValueError as error:
        raise FwshiftError(f"{where}: not JSON ({str(error)[:120]})") from None
    if not isinstance(document, dict):
        raise FwshiftError(f"{where}: expected a JSON object with zones and conduits")
    _keys(document, _MODEL_KEYS, where)
    if document.get("fwshift", FORMAT) != FORMAT:
        raise FwshiftError(f"{where}: 'fwshift' must be '{FORMAT}'")
    if document.get("version", VERSION) != VERSION:
        raise FwshiftError(f"{where}: version {document.get('version')!r} is not known (this FWShift reads version {VERSION})")
    zones: Dict[str, Zone] = {}
    raw_zones = document.get("zones")
    if not isinstance(raw_zones, list) or not raw_zones:
        raise FwshiftError(f"{where}: 'zones' must be a list with at least one zone")
    for position, entry in enumerate(raw_zones, 1):
        here = f"{where}, zone {position}"
        if not isinstance(entry, dict):
            raise FwshiftError(f"{here}: expected an object")
        _keys(entry, _ZONE_KEYS, here)
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip() or not name.isprintable():
            raise FwshiftError(f"{here}: a zone needs a name")
        name = name.strip()
        here = f"{where}, zone '{name}'"
        if name in zones:
            raise FwshiftError(f"{here}: the name is used twice")
        if name in _RESERVED:
            raise FwshiftError(f"{here}: '{name}' cannot be the name of a zone")
        zone = Zone(name, sl_t=_level(entry.get("sl_t"), here), description=str(entry.get("description") or ""))
        if "networks" in entry:
            zone.networks = _strings(entry["networks"], f"{here}, networks")
            if not zone.networks:
                raise FwshiftError(f"{here}: networks is a list of at least one network (leave it out for zones of the policy)")
            for network in zone.networks:
                if parse_literal(network) is None:
                    raise FwshiftError(f"{here}: '{network[:40]}' is not a network")
        if "policy_zones" in entry:
            zone.policy_zones = _strings(entry["policy_zones"], f"{here}, policy_zones")
        if "inside" in entry:
            zone.inside_specs = _strings(entry["inside"], f"{here}, inside")
            zone.inside = Allowed()
            for spec in zone.inside_specs:
                zone.inside.add(parse_service(spec, f"{here}, inside"))
        zones[name] = zone
    with_networks = [zone.name for zone in zones.values() if zone.networks]
    if with_networks and len(with_networks) != len(zones):
        raise FwshiftError(f"{where}: either every zone has networks or none has; zone(s) "
                           + ", ".join(z for z in zones if z not in with_networks)[:200] + " have none")  # fmt: skip
    by_network = bool(with_networks)
    if not by_network:
        owner: Dict[str, str] = {}
        for zone in zones.values():
            zone.policy_zones = zone.policy_zones or [zone.name]
            for policy_zone in zone.policy_zones:
                if policy_zone in owner:
                    raise FwshiftError(f"{where}: zone '{policy_zone}' of the policy is in zone '{owner[policy_zone]}' and in zone "
                                       f"'{zone.name}' of the model")  # fmt: skip
                owner[policy_zone] = zone.name
    conduits: List[Conduit] = []
    raw_conduits = document.get("conduits", [])
    if not isinstance(raw_conduits, list):
        raise FwshiftError(f"{where}: 'conduits' must be a list")
    names: Set[str] = set()
    for position, entry in enumerate(raw_conduits, 1):
        here = f"{where}, conduit {position}"
        if not isinstance(entry, dict):
            raise FwshiftError(f"{here}: expected an object")
        _keys(entry, _CONDUIT_KEYS, here)
        src, dst = entry.get("from"), entry.get("to")
        name = str(entry.get("name") or f"{src} -> {dst}")
        here = f"{where}, conduit '{name}'"
        if name in names:
            raise FwshiftError(f"{here}: the name is used twice")
        names.add(name)
        for end in (src, dst):
            if not isinstance(end, str) or end not in zones:
                raise FwshiftError(f"{here}: '{end}' is not a zone of the model")
        if src == dst:
            raise FwshiftError(f"{here}: a conduit joins two zones; what may pass inside one is its 'inside'")
        if "services" not in entry:
            raise FwshiftError(f"{here}: a conduit needs its services (\"any\" for everything)")
        specs = _strings(entry["services"], f"{here}, services")
        allowed = Allowed()
        for spec in specs:
            allowed.add(parse_service(spec, here))
        both = entry.get("both_ways", False)
        if not isinstance(both, bool):
            raise FwshiftError(f"{here}: both_ways is true or false")
        conduits.append(Conduit(name, str(src), str(dst), specs, allowed, both, _level(entry.get("sl_t"), here),
                                str(entry.get("description") or "")))  # fmt: skip
    return ZoneModel(str(document.get("name") or ""), zones, conduits, by_network)


# -- the check -------------------------------------------------------------------------------------


@dataclass
class Finding:
    check: str
    level: Level
    src: str
    dst: str
    rule: str  # the rule (or the default) that allows it; for CONDUIT_CLOSED the conduit
    message: str
    items: List[str] = field(default_factory=list)
    possible: bool = False

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"check": self.check, "level": _LEVEL_NAMES[self.level], "from": self.src, "to": self.dst,
                               "rule": self.rule, "message": self.message, "services": self.items}  # fmt: skip
        if self.possible:
            out["possible"] = True
        return out


@dataclass
class ConduitState:
    conduit: Conduit
    allowed: List[str]  # what the policy allows of it
    closed: List[str]  # what of it the policy allows nowhere


@dataclass
class Check:
    model: ZoneModel
    matrix: Matrix
    findings: List[Finding] = field(default_factory=list)
    conduits: List[ConduitState] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    unchecked_inside: List[str] = field(default_factory=list)

    def fails(self, level: Optional[Level]) -> bool:
        return level is not None and any(f.level >= level for f in self.findings)

    def counts(self) -> Dict[str, int]:
        out = {name: 0 for name in _LEVEL_NAMES.values()}
        for finding in self.findings:
            out[_LEVEL_NAMES[finding.level]] += 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"model": self.model.name, "zones": list(self.model.zones), "counts": self.counts(),
                "findings": [f.to_dict() for f in self.findings],
                "conduits": [{"name": s.conduit.name, "from": s.conduit.src, "to": s.conduit.dst, "services": s.conduit.specs,
                              "both_ways": s.conduit.both_ways, "sl_t": s.conduit.sl_t, "allowed_by_the_policy": s.allowed,
                              "closed_by_the_policy": s.closed} for s in self.conduits],
                "inside_not_checked": self.unchecked_inside, "notes": self.notes}  # fmt: skip

    def to_text(self) -> str:
        counts = self.counts()
        out: List[str] = []
        breaking = [f for f in self.findings if f.check != "CONDUIT_CLOSED"]
        if not breaking:
            out.append("Result: every connection the policy can allow between zones lies within a conduit of the model.")
        else:
            sure = sum(1 for f in breaking if not f.possible)
            out.append(f"Result: the policy allows what the model does not, in {len(breaking)} place(s)"
                       + (f" ({len(breaking) - sure} possible)" if sure != len(breaking) else "") + ".")  # fmt: skip
        out.append("  findings: " + ", ".join(f"{name} {count}" for name, count in reversed(list(counts.items()))))
        if self.findings:
            out += ["", "Findings"]
            width = max(len(f.check) for f in self.findings)
            for f in sorted(self.findings, key=lambda f: (-f.level, f.src, f.dst)):
                out.append(f"  {_LEVEL_NAMES[f.level]:<6}  {f.check:<{width}}  {f.src} -> {f.dst}: {f.message}")
        out += ["", "Conduits"]
        if not self.conduits:
            out.append("  none")
        for state in self.conduits:
            c = state.conduit
            head = f"  {c.name}: {c.src} {'<->' if c.both_ways else '->'} {c.dst}" + (f" (SL-T {c.sl_t})" if c.sl_t is not None else "")
            out.append(head)
            out.append(f"    model: {', '.join(c.specs)}")
            out.append(f"    policy allows: {', '.join(state.allowed) or 'nothing of it'}")
            if state.closed:
                out.append(f"    closed by the policy: {', '.join(state.closed)}")
        if self.unchecked_inside:
            out += ["", "Inside these zones the traffic is not checked (no 'inside' in the model): " + ", ".join(self.unchecked_inside)]
        if self.notes:
            out += ["", "Notes"] + [f"  {note}" for note in self.notes]
        return "\n".join(out) + "\n"


def networks_of(model: ZoneModel) -> Optional[Dict[str, NetworkZone]]:
    if not model.by_network:
        return None
    return {zone.name: NetworkZone(zone.name, list(zone.networks), list(zone.policy_zones)) for zone in model.zones.values()}


def _default_ports(app: str, app_ports: Dict[str, List[str]]) -> Optional[Services]:
    entries = appmap.entries_for(app, app_ports)
    if entries is None:
        return None
    sets = [_entry_services(entry) for entry in entries]
    return None if any(one is None for one in sets) else _union([one for one in sets if one is not None])


def _projected(services: Services) -> Services:
    """Services with every source port (TCP, UDP, SCTP) and every ICMP code: what a service of a conduit says."""
    out: Dict[int, List[Tuple[int, int, int, int]]] = {}
    for number, rects in services.protocols.items():
        if number in (6, 17, 132):
            out[number] = [(0, 65535, rect[2], rect[3]) for rect in rects]
        elif number in (1, 58):
            out[number] = [(rect[0], rect[1], 0, 65535) for rect in rects]
        else:
            out[number] = list(rects)
    return Services(out, services.rest)


def _within(found: Optional[Services], services: Services) -> bool:
    return found is not None and found.minus(services).empty()


def _app_services(entry: Entry, app_ports: Dict[str, List[str]]) -> Services:
    """The ports an entry with applications uses, as far as they are known (on their default ports: from the map)."""
    if not entry.app_default:
        return entry.services
    found = [_default_ports(app, app_ports) for app in entry.applications]
    return _union([one for one in found if one is not None])


def _exceeds(entry: Entry, allowed: Allowed, app_ports: Dict[str, List[str]]) -> Tuple[List[str], bool]:
    """(what of an entry the allowed set does not hold, whether that cannot be told for sure)."""
    unsure = entry.approximate
    if entry.applications:
        missing = [app for app in entry.applications if app not in allowed.applications]
        if not entry.app_default and not entry.unread and entry.services.minus(allowed.services).empty():
            return [], False  # (on ports the conduit has, whatever the application)
        if entry.app_default:
            # An application on its default ports is within ports the conduit has for every application.
            missing = [app for app in missing if not _within(_default_ports(app, app_ports), allowed.services)]
        if not missing:
            return [], False
        ports = "" if entry.app_default or entry.services.everything() else " on " + ", ".join(service_items(entry.services)[:6])
        return [f"app:{app}{ports}" for app in missing], unsure
    out: List[str] = []
    if entry.unread:
        out += [f"svc:{name}" for name in entry.unread if name not in allowed.unread]
        if out:
            unsure = True
        plain = entry.known if entry.known is not None else Services()
    else:
        plain = entry.services
    rest = plain.minus(allowed.services)
    if not rest.empty():
        out = service_items(rest) + out
    return out, unsure and bool(out)


def _unbound(p: Policy, model: ZoneModel, found: Matrix, result: "Check") -> None:
    """Zones of networks that do not say which zones of the policy they lie behind: what the policy lets pass inside a zone
    of its own by default is not in the matrix there. Wherever it may reach beyond the model, that is a possible finding."""
    if not model.by_network:
        return
    open_inside = p.default_intrazone == Action.ALLOW or any(zone.intrazone_allow for zone in p.zones.values())
    unbound = [zone.name for zone in model.zones.values() if not zone.policy_zones]
    if not open_inside or not unbound:
        return
    why = ("possibly: the policy lets traffic pass inside a zone of its own unless a rule decides, and the model does not say "
           "which zones of the policy the networks of {} lie behind (policy_zones)")  # fmt: skip
    every = Allowed(services=_ALL_SERVICES)
    elsewhere = [ELSEWHERE] if ELSEWHERE in found.zones else []
    for src in unbound + elsewhere:
        for dst in unbound + elsewhere:
            if ELSEWHERE in (src, dst):
                if src != dst:
                    named = dst if src == ELSEWHERE else src
                    result.findings.append(Finding("NOT_IN_MODEL", Level.MEDIUM, src, dst, DEFAULT, why.format(named) + f"; {ELSEWHERE} is "
                                                   "in no zone of the model", ["any"], True))  # fmt: skip
                continue
            if src == dst:
                zone = model.zones[src]
                if zone.inside is not None and not _within(_ALL_SERVICES, zone.inside.services):
                    result.findings.append(Finding("INSIDE_EXCEEDED", Level.MEDIUM, src, dst, DEFAULT, why.format(src), ["any"], True))
                continue
            conduits = model.between(src, dst)
            if not conduits:
                result.findings.append(Finding("NO_CONDUIT", Level.MEDIUM, src, dst, DEFAULT, why.format(f"{src} and {dst}"), ["any"], True))
                continue
            allowed = Allowed()
            for conduit in conduits:
                allowed.add(conduit.allowed)
            if not every.services.minus(allowed.services).empty():
                result.findings.append(Finding("CONDUIT_EXCEEDED", Level.MEDIUM, src, dst, DEFAULT, why.format(f"{src} and {dst}"),
                                               ["any"], True))  # fmt: skip


def _said(entry: Entry) -> str:
    return "by default" if entry.default else f"rule '{entry.rule}'"


def check(p: Policy, model: ZoneModel, config: Optional[AuditConfig] = None, reading: Optional[Any] = None,
          built: Optional[Matrix] = None, app_ports: Optional[Dict[str, List[str]]] = None) -> Check:  # fmt: skip
    """Check a policy against a model. ``app_ports``: the application map (the default ports of applications)."""
    ports = dict(app_ports or {})
    found = built or matrix.build(p, config, reading, networks_of(model))
    result = Check(model, found)
    owner: Dict[str, str] = {}
    if model.by_network:
        owner = {zone: zone for zone in model.zones}
    else:
        owner = {policy_zone: zone.name for zone in model.zones.values() for policy_zone in zone.policy_zones}
        if "*" in owner:
            owner[found.other] = owner.pop("*")  # ("*": the zones the policy does not name, which a rule for any zone reaches)
        policy_zones = [z for z in found.zones if z != found.other]
        missing = [z for z in policy_zones if z not in owner]
        if missing:
            result.notes.append("Zones of the policy in no zone of the model (what they allow is outside the model): " + ", ".join(missing))
        unknown = sorted({z for z in owner if z not in policy_zones and z not in p.zones and z != found.other and
                          not any(z in r.src_zones + r.dst_zones for r in p.rules)})  # fmt: skip
        if unknown:
            result.notes.append("The policy names no zone " + ", ".join(repr(z) for z in unknown) + " that the model lists: only rules for "
                                "'any' zone are checked for it. Check the spelling.")  # fmt: skip
    by_pair: Dict[Tuple[str, str], List[Cell]] = {}
    for cell in found.cells.values():
        src, dst = owner.get(cell.src), owner.get(cell.dst)
        if src is None or dst is None:
            outside = [name for name, mapped in ((cell.src, src), (cell.dst, dst)) if mapped is None]
            for entry in cell.entries:
                result.findings.append(Finding("NOT_IN_MODEL", Level.MEDIUM if entry.approximate else Level.HIGH, src or cell.src, dst or cell.dst,
                                               entry.rule, f"{_said(entry)} allows {entry.what(8)}; {' and '.join(outside)} "
                                               f"{'is' if len(outside) == 1 else 'are'} in no zone of the model",
                                               service_items(entry.services)[:12], entry.approximate))  # fmt: skip
            continue
        by_pair.setdefault((src, dst), []).append(cell)
    for (src, dst), cells in sorted(by_pair.items()):
        entries = [entry for cell in cells for entry in cell.entries]
        if src == dst:
            zone = model.zones[src]
            if zone.inside is None:
                if src not in result.unchecked_inside:
                    result.unchecked_inside.append(src)
                continue
            allowed: Optional[Allowed] = zone.inside
            label = f"what zone {src} lets pass inside"
        else:
            conduits = model.between(src, dst)
            allowed = None
            if conduits:
                allowed = Allowed()
                for conduit in conduits:
                    allowed.add(conduit.allowed)
            label = "conduit " + ", ".join(repr(c.name) for c in conduits)
        for entry in entries:
            if allowed is None:
                result.findings.append(Finding("NO_CONDUIT", Level.MEDIUM if entry.approximate else Level.HIGH, src, dst, entry.rule,
                                               f"{_said(entry)} allows {entry.what(8)}; the model has no conduit from {src} to {dst}"
                                               + (" (at most this: part of it is not read exactly)" if entry.approximate else ""),
                                               service_items(entry.services)[:12], entry.approximate))  # fmt: skip
                continue
            beyond, unsure = _exceeds(entry, allowed, ports)
            if beyond:
                check_name = "INSIDE_EXCEEDED" if src == dst else "CONDUIT_EXCEEDED"
                result.findings.append(Finding(check_name, Level.MEDIUM if unsure else Level.HIGH, src, dst, entry.rule,
                                               f"{_said(entry)} allows {', '.join(beyond[:8])} beyond {label}"
                                               + (" (possibly: part of it is not read exactly)" if unsure else ""), beyond, unsure))  # fmt: skip
    _unbound(p, model, found, result)
    # The conduits the policy keeps closed, in part or all of them.
    for conduit in model.conduits:
        directions = [(conduit.src, conduit.dst)] + ([(conduit.dst, conduit.src)] if conduit.both_ways else [])
        entries = [entry for pair in directions for cell in by_pair.get(pair, []) for entry in cell.entries]
        plain = _union([entry.services for entry in entries if not entry.applications and not entry.unread]
                       + [entry.known for entry in entries if entry.unread and entry.known is not None])  # fmt: skip
        # (the ports of the applications the policy allows are in use: the traffic the conduit is for passes there; a conduit
        # names no source ports and no ICMP codes, so any of them open counts)
        used = _projected(_union([plain] + [_app_services(entry, ports) for entry in entries if entry.applications]))
        open_services = conduit.allowed.services.and_(used)
        everything = any(entry.everything for entry in entries)
        apps = {app for entry in entries for app in entry.applications}
        apps |= {app for app in conduit.allowed.applications if everything or _within(_default_ports(app, ports), used)}
        names = {name for entry in entries for name in entry.unread} | (set(conduit.allowed.unread) if everything else set())
        allowed_items = service_items(open_services) if not open_services.empty() else []
        allowed_items += [f"app:{a}" for a in sorted(conduit.allowed.applications & apps) if f"app:{a}" not in allowed_items]
        allowed_items += [f"svc:{n}" for n in sorted(conduit.allowed.unread & names)]
        closed_services = conduit.allowed.services.minus(used)
        closed = service_items(closed_services) if not closed_services.empty() else []
        closed += [f"app:{a}" for a in sorted(conduit.allowed.applications - apps)]
        closed += [f"svc:{n}" for n in sorted(conduit.allowed.unread - names)]
        result.conduits.append(ConduitState(conduit, allowed_items, closed))
        if closed:
            whole = not allowed_items
            result.findings.append(Finding("CONDUIT_CLOSED", Level.LOW, conduit.src, conduit.dst, conduit.name,
                                           f"conduit '{conduit.name}': the policy allows {'none of it' if whole else 'not all of it'}: "
                                           + ", ".join(closed[:8]) + " (traffic the model expects is blocked)", closed))  # fmt: skip
    if found.by_network and ELSEWHERE in found.zones:
        result.notes.append(f"{ELSEWHERE}: addresses in no zone of the model. A zone with 0.0.0.0/0 and ::/0 takes in every address no "
                            "other zone has.")  # fmt: skip
    if any(f.possible for f in result.findings):
        result.notes.append("possible: the matrix shows at most this where part of a rule (an object, the blocking rules above it, NAT) "
                            "cannot be read exactly; the check counts it, so that a check that passes holds for the policy as FWShift reads it.")  # fmt: skip
    result.notes.append("Directions: 'from' opens the connection; the replies of a connection the policy allows are not checked "
                        "separately.")  # fmt: skip
    result.notes.append("Security levels (sl_t) and descriptions are documentation: the check does not weigh them.")
    result.notes += [f"matrix: {note}" for note in found.notes if "~" in note or "NO conduit" in note or "NOT in the matrix" in note]
    return result


# -- a draft ---------------------------------------------------------------------------------------


def draft(found: Matrix, source: str = "") -> Dict[str, Any]:
    """A model that holds what the policy allows today: a start for a model, every conduit to be reviewed."""
    specials = {found.other, ELSEWHERE}
    zones: List[Dict[str, Any]] = []
    names = [zone for zone in found.zones if zone not in specials and not zone.startswith("(")]
    for name in names:
        entry: Dict[str, Any] = {"name": name}
        if found.by_network:
            entry["networks"] = list(found.networks.get(name, []))
            if found.behind.get(name):
                entry["policy_zones"] = list(found.behind[name])
        cell = found.cells.get((name, name))
        entry["inside"] = _cell_specs(cell) if cell is not None else []  # (nothing passes inside it: that is checked too)
        zones.append(entry)
    conduits: List[Dict[str, Any]] = []
    for (src, dst), cell in sorted(found.cells.items(), key=lambda item: (found.zones.index(item[0][0]), found.zones.index(item[0][1]))):
        if src == dst or src not in names or dst not in names:
            continue
        rules = list(dict.fromkeys("the default" if e.default else e.rule for e in cell.entries))
        conduit: Dict[str, Any] = {"name": f"{src}-to-{dst}", "from": src, "to": dst, "services": _cell_specs(cell),
                                   "description": "drafted from rule(s) " + ", ".join(rules[:6]) + (f" and {len(rules) - 6} more" if len(rules) > 6 else "")
                                   + (" (at most this: part of it is not read exactly)" if cell.approximate else "")}  # fmt: skip
        conduits.append(conduit)
    left_out = [zone for zone in found.zones if zone in specials or zone.startswith("(")]
    description = ("Drafted by FWShift from what the policy" + (f" {source}" if source else "") + " allows today: review every zone and "
                   "conduit, and keep only what the zones need.")  # fmt: skip
    if left_out:
        description += " Not in it: " + ", ".join(left_out) + "."
    return {"fwshift": FORMAT, "version": VERSION, "name": "draft", "description": description, "zones": zones, "conduits": conduits}


def _cell_specs(cell: Cell) -> List[str]:
    out: List[str] = []
    plain = _union([entry.services for entry in cell.entries if not entry.applications and not entry.unread]
                   + [entry.known for entry in cell.entries if entry.unread and entry.known is not None])  # fmt: skip
    if not plain.empty():
        out += specs_of(plain)
    for entry in cell.entries:
        if entry.applications and entry.app_default:
            out += [f"app:{app}" for app in entry.applications if f"app:{app}" not in out]
        elif entry.applications:
            out += [spec for spec in specs_of(entry.services) if spec not in out]
        out += [f"svc:{name}" for name in entry.unread if f"svc:{name}" not in out]
    return out or ["any"]


__all__ = ["FORMAT", "VERSION", "Allowed", "Check", "Conduit", "Finding", "Zone", "ZoneModel", "check", "draft", "load_model",
           "networks_of", "parse_service", "specs_of"]
