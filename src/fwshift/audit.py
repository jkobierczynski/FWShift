# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Audit of a policy: rules that allow too much, rules that never decide anything, loose ends.

The audit works on the neutral model, so it is the same for every vendor that can be read.
Three things are kept apart:

* **Checks** look at the policy and return findings. Each has a level and can be switched off.
* **Actions** say what is done with the findings of a check: report them, accept them (also per
  rule, with a reason), disable the rules, or - for shadowed rules - move them up.
* **Proof.** A rule is only called shadowed or redundant when that follows from what can be read
  off the model: zones, addresses, protocols and ports. Whatever cannot be read (a host name, an
  application on its default ports, a criterion the model does not hold) is taken on the side
  that makes the claim harder: the rule that is covered counts as matching everything it might,
  a rule that covers counts as matching only what it surely does.
"""

from __future__ import annotations

import copy
import datetime
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import transform
from .errors import FwshiftError
from .model import ANY, APP_DEFAULT, L4_PROTOCOLS, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry
from .netutil import FULL_V4, FULL_V6, Interval, intersect, interval_text, normalize, overlaps, size, subtract


class Level(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


_LEVEL_NAMES = {Level.INFO: "info", Level.LOW: "low", Level.MEDIUM: "medium", Level.HIGH: "high"}
_LEVELS = {name: level for level, name in _LEVEL_NAMES.items()}

OFF, ACCEPT, REPORT, DISABLE, REORDER = "off", "accept", "report", "disable", "reorder"
_FOR_RULES = (OFF, ACCEPT, REPORT, DISABLE)
_FOR_OTHERS = (OFF, ACCEPT, REPORT)


@dataclass(frozen=True)
class Check:
    level: Level
    title: str
    actions: Tuple[str, ...] = _FOR_RULES
    default: str = REPORT
    changes_nothing: bool = False  # disabling the rules it finds changes no verdict


CHECKS: Dict[str, Check] = {
    # Rules that allow a lot.
    "ANY_ANY_ANY": Check(Level.HIGH, "allow rule for any source, any destination and any service"),
    "ANY_SERVICE": Check(Level.MEDIUM, "allow rule for any service"),
    "ANY_TO_ANY": Check(Level.MEDIUM, "allow rule from any source to any destination"),
    "ANY_SOURCE": Check(Level.LOW, "allow rule from any source"),
    "ANY_DESTINATION": Check(Level.LOW, "allow rule to any destination"),
    "WIDE_NETWORK": Check(Level.LOW, "allow rule for a very large network"),
    "WIDE_PORTS": Check(Level.LOW, "allow rule for a very wide port range"),
    "RISKY_SERVICE": Check(Level.MEDIUM, "allow rule for a cleartext or remote administration protocol"),
    "INDUSTRIAL_SERVICE": Check(Level.LOW, "allow rule for an industrial control protocol"),
    "NO_LOG": Check(Level.LOW, "rule that does not log", _FOR_OTHERS),
    "NO_PROFILE": Check(Level.LOW, "allow rule without a security profile", _FOR_OTHERS),
    # The order of the rules.
    "SHADOWED_RULE": Check(Level.HIGH, "rule that never matches: earlier rules decide its traffic otherwise",
                           _FOR_RULES + (REORDER,), changes_nothing=True),  # fmt: skip
    "REDUNDANT_RULE": Check(Level.LOW, "rule that can go: other rules decide its traffic the same way", changes_nothing=True),
    "EMPTY_RULE": Check(Level.LOW, "rule that can match nothing by itself", changes_nothing=True),
    "OVERLAPPING_RULES": Check(Level.INFO, "rule that earlier rules with another action take part of", _FOR_OTHERS, OFF),
    "SHADOWED_NAT": Check(Level.MEDIUM, "NAT rule that never matches", _FOR_OTHERS),
    # Loose ends.
    "DISABLED_RULE": Check(Level.INFO, "rule that is disabled", _FOR_OTHERS),
    "NO_DESCRIPTION": Check(Level.INFO, "rule without a description", _FOR_OTHERS, OFF),
    "UNUSED_OBJECT": Check(Level.INFO, "objects that no rule uses", _FOR_OTHERS),
    "DUPLICATE_OBJECT": Check(Level.INFO, "objects with the same content under several names", _FOR_OTHERS),
    "EMPTY_GROUP": Check(Level.LOW, "group without members", _FOR_OTHERS),
    "DEFAULT_ALLOW": Check(Level.HIGH, "traffic that no rule matches is allowed", _FOR_OTHERS),
    # Use, from the hit counters of the firewall.
    "UNUSED_RULE": Check(Level.MEDIUM, "allow rule whose hit counter is zero"),
    "NO_USAGE_EVIDENCE": Check(Level.INFO, "rule whose use cannot be told: no counter, or one that has not counted long", _FOR_OTHERS),
    # Only after a conversion.
    "EXPOSED_BY_CONVERSION": Check(Level.HIGH, "blocking rule the conversion could not write, with allow rules below it", _FOR_OTHERS),
}

# Protocols that carry passwords in the clear or give a remote session, and what they run on.
RISKY_SERVICES: Dict[str, List[str]] = {
    "telnet": ["tcp/23"],
    "ftp": ["tcp/21"],
    "tftp": ["udp/69"],
    "rsh/rlogin/rexec": ["tcp/512-514"],
    "netbios": ["tcp/139", "udp/137-138"],
    "smb": ["tcp/445"],
    "rdp": ["tcp/3389", "udp/3389"],
    "vnc": ["tcp/5900-5909"],
    "snmp": ["udp/161"],
    "x11": ["tcp/6000-6009"],
}
RISKY_APPLICATIONS = ("telnet", "ftp", "tftp", "rlogin", "rsh", "rexec", "ms-rdp", "vnc", "ms-ds-smb", "netbios-ss", "snmp",
                      "snmpv1", "snmpv2")  # fmt: skip
# Control system protocols: nothing wrong with them, but where they cross a firewall is worth knowing.
INDUSTRIAL_SERVICES: Dict[str, List[str]] = {
    "modbus": ["tcp/502"],
    "s7/iso-tsap": ["tcp/102"],
    "dnp3": ["tcp/20000", "udp/20000"],
    "ethernet-ip": ["tcp/44818", "udp/44818", "udp/2222"],
    "opc-ua": ["tcp/4840"],
    "bacnet": ["udp/47808"],
    "iec-104": ["tcp/2404"],
    "profinet": ["udp/34962-34964", "tcp/34962-34964"],
    "fins": ["udp/9600"],
    "niagara-fox": ["tcp/1911", "tcp/4911"],
}
INDUSTRIAL_APPLICATIONS = ("modbus", "siemens-s7", "dnp3", "ethernet-ip", "cip-ethernet-ip", "opc-ua", "bacnet", "iec-60870-5-104")

_PLURAL = {"address": "addresses", "address-group": "address groups", "service": "services", "service-group": "service groups"}
_LOGGING_BY_RULE = ("panos", "checkpoint", "sophos", "fmc", "fdm")  # where the model says whether a rule logs its sessions at all
_PROFILES = ("panos", "fortios", "sophos", "fmc", "fdm")
_MAX_BOXES = 4096  # pieces a rule may fall into while earlier rules are taken out of it
_FEW_BOXES = 128  # pieces up to which the rules that take part of a rule are found by taking them out in their order


def _like(pattern: str, name: str) -> bool:
    """Whether a name answers to a pattern in which * stands for any text and ? for any one character.

    Nothing else stands for anything: a rule called "Allow [DMZ]" is a name, not a set of letters.
    (Written out, because a regular expression takes forever on a pattern with many stars.)
    """
    at, position, star, resume = 0, 0, -1, 0
    while position < len(name):
        if at < len(pattern) and pattern[at] == "*":
            star, resume = at, position
            at += 1
        elif at < len(pattern) and pattern[at] in ("?", name[position]):
            at, position = at + 1, position + 1
        elif star >= 0:
            resume += 1
            at, position = star + 1, resume
        else:
            return False
    return all(letter == "*" for letter in pattern[at:])


@dataclass
class Acceptance:
    """A rule (or object) that is allowed to pass a check, on somebody's say-so."""

    pattern: str  # name or origin, with * and ? as in file names
    checks: List[str] = field(default_factory=list)  # empty: every check
    reason: str = ""

    used: bool = False

    def covers(self, check: str, names: Sequence[str], kind: str = "rule") -> bool:
        if self.checks and check not in self.checks:
            return False
        if (kind == "policy" or check == "EXPOSED_BY_CONVERSION") and not self.checks:
            # What holds for the whole policy, and what a conversion did to a rule, is only accepted by the
            # name of its check: "this rule may pass every check" was said about the rule on the source.
            return False
        return any(name == self.pattern or _like(self.pattern, name) for name in names if name)


@dataclass
class AuditConfig:
    actions: Dict[str, str] = field(default_factory=dict)  # check -> action; the rest have their default
    levels: Dict[str, Level] = field(default_factory=dict)
    accepted: List[Acceptance] = field(default_factory=list)
    wide_network_v4: int = 8  # a network with this prefix length or shorter is "very large"
    wide_network_v6: int = 32
    wide_ports: int = 1024  # a range of at least this many ports is "very wide"
    usage_days: int = 90  # a hit counter that has counted for fewer days than this proves nothing by a zero
    hits_since: Optional[int] = None  # the user's word: the counters have counted since then (UTC seconds)
    risky_services: Dict[str, List[str]] = field(default_factory=lambda: copy.deepcopy(RISKY_SERVICES))
    industrial_services: Dict[str, List[str]] = field(default_factory=lambda: copy.deepcopy(INDUSTRIAL_SERVICES))
    risky_applications: List[str] = field(default_factory=lambda: list(RISKY_APPLICATIONS))
    industrial_applications: List[str] = field(default_factory=lambda: list(INDUSTRIAL_APPLICATIONS))
    fail_on: Optional[Level] = None

    def action(self, check: str) -> str:
        return self.actions.get(check, CHECKS[check].default)

    def level(self, check: str) -> Level:
        return self.levels.get(check, CHECKS[check].level)

    def set_action(self, check: str, action: str, option: str = "the audit configuration") -> None:
        check = check.strip().upper().replace("-", "_")
        action = action.strip().lower()
        if check not in CHECKS:
            raise FwshiftError(f"{option}: there is no check '{check[:40]}'. Checks: {', '.join(CHECKS)}")
        if action not in CHECKS[check].actions:
            raise FwshiftError(
                f"{option}: '{action[:20]}' cannot be done with {check}; it takes {', '.join(CHECKS[check].actions)}"
            )
        self.actions[check] = action

    def accept(self, pattern: str, checks: Sequence[str] = (), reason: str = "", option: str = "the audit configuration") -> None:
        names = [check.strip().upper().replace("-", "_") for check in checks if check.strip()]
        unknown = [name for name in names if name not in CHECKS]
        if unknown or not pattern:
            what = f"there is no check '{unknown[0][:40]}'" if unknown else "a rule name is needed"
            raise FwshiftError(f"{option}: {what}")
        self.accepted.append(Acceptance(pattern, names, reason))


def level_of(text: str, option: str) -> Level:
    if text.strip().lower() not in _LEVELS:
        raise FwshiftError(f"{option}: '{text[:20]}' is not a level; levels are {', '.join(_LEVELS)}")
    return _LEVELS[text.strip().lower()]


def _name(check: object, where: str) -> str:
    name = str(check).strip().upper().replace("-", "_")
    if name not in CHECKS:
        raise FwshiftError(f"{where}: there is no check '{name[:40]}'. Checks: {', '.join(CHECKS)}")
    return name


def _only(entry: Dict[str, Any], allowed: Sequence[str], where: str, what: str) -> None:
    unknown = sorted(str(key) for key in entry if key not in allowed)
    if unknown:
        raise FwshiftError(f"{where}: unknown key '{unknown[0][:40]}' in {what}; it takes {', '.join(allowed)}")


def load_config(text: str, where: str = "the audit configuration") -> AuditConfig:
    """Read an audit configuration (JSON). Everything in it is optional; what is unknown is refused."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise FwshiftError(f"{where} is not JSON: {str(exc)[:200]}") from None
    if not isinstance(data, dict):
        raise FwshiftError(f"{where}: a JSON object is expected")
    _only(data, ("checks", "accept", "thresholds", "services", "applications", "fail_on", "hits_since"), where, "the configuration")
    config = AuditConfig()
    checks = data.get("checks", {})
    if not isinstance(checks, dict):
        raise FwshiftError(f"{where}: 'checks' maps a check to an action")
    for check, setting in checks.items():
        name = _name(check, where)
        if isinstance(setting, dict):
            _only(setting, ("action", "level"), where, f"the settings of {name}")
            if "action" in setting:
                config.set_action(name, str(setting["action"]), where)
            if "level" in setting:
                config.levels[name] = level_of(str(setting["level"]), where)
        elif isinstance(setting, str):
            config.set_action(name, setting, where)
        else:
            raise FwshiftError(f"{where}: the setting of {name} is an action, or an object with 'action' and 'level'")
    accepted = data.get("accept", [])
    if not isinstance(accepted, list):
        raise FwshiftError(f"{where}: 'accept' is a list")
    for entry in accepted:
        if isinstance(entry, str):
            config.accept(entry, option=where)
        elif isinstance(entry, dict) and isinstance(entry.get("rule"), str):
            _only(entry, ("rule", "checks", "reason"), where, "an entry of 'accept'")
            wanted = entry.get("checks", [])
            wanted = [wanted] if isinstance(wanted, str) else wanted
            if not isinstance(wanted, list):
                raise FwshiftError(f"{where}: 'checks' of an accepted rule is a list of checks")
            config.accept(entry["rule"], [str(check) for check in wanted], str(entry.get("reason", "")), where)
        else:
            raise FwshiftError(f"{where}: an entry of 'accept' is a rule name, or an object with 'rule'")
    thresholds = data.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise FwshiftError(f"{where}: 'thresholds' is an object")
    limits = {"wide_network_v4": (0, 32), "wide_network_v6": (0, 128), "wide_ports": (2, 65536), "usage_days": (1, 3650)}
    for key, value in thresholds.items():
        if key not in limits or not isinstance(value, int) or isinstance(value, bool):
            raise FwshiftError(f"{where}: threshold '{str(key)[:40]}' is not known, or not a whole number")
        low, high = limits[key]
        if not low <= value <= high:
            raise FwshiftError(f"{where}: threshold {key} must lie between {low} and {high}")
        setattr(config, key, value)
    services = data.get("services", {})
    if not isinstance(services, dict) or set(services) - {"risky", "industrial"}:
        raise FwshiftError(f"{where}: 'services' holds 'risky' and 'industrial'")
    for key, target in (("risky", "risky_services"), ("industrial", "industrial_services")):
        if key not in services:
            continue
        table = services[key]
        if not isinstance(table, dict) or not all(isinstance(specs, list) for specs in table.values()):
            raise FwshiftError(f"{where}: services.{key} maps a name to a list such as [\"tcp/23\"]")
        cleaned = {str(name): [str(spec) for spec in specs] for name, specs in table.items()}
        for name, specs in cleaned.items():
            for spec in specs:
                if _spec_services(spec) is None:
                    raise FwshiftError(f"{where}: '{spec[:30]}' of services.{key}.{name[:30]} is not like tcp/23 or udp/161-162")
        setattr(config, target, cleaned)
    applications = data.get("applications", {})
    if not isinstance(applications, dict) or set(applications) - {"risky", "industrial"}:
        raise FwshiftError(f"{where}: 'applications' holds 'risky' and 'industrial'")
    for key, target in (("risky", "risky_applications"), ("industrial", "industrial_applications")):
        if key in applications:
            if not isinstance(applications[key], list):
                raise FwshiftError(f"{where}: applications.{key} is a list of application names")
            setattr(config, target, [str(name) for name in applications[key]])
    if "fail_on" in data:
        config.fail_on = level_of(str(data["fail_on"]), where)
    if "hits_since" in data:
        config.hits_since = day_of(str(data["hits_since"]), where)
    return config


def day_of(text: str, option: str) -> int:
    """A day written YYYY-MM-DD, as the UTC seconds of its start."""
    try:
        moment = datetime.datetime.strptime(text.strip(), "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        raise FwshiftError(f"{option}: '{text[:20]}' is not a day written YYYY-MM-DD") from None
    return int(moment.timestamp())


@dataclass
class Finding:
    check: str
    level: Level
    kind: str  # rule, nat, address, address-group, service, service-group, policy
    name: str  # origin of a rule, name of an object
    message: str
    shown: str = ""  # the name to print, where it differs from ``name``
    related: List[str] = field(default_factory=list)  # origins of the other rules that have a part in it
    action: str = REPORT
    done: str = ""  # what was done about it, or would be
    reason: str = ""  # why it was accepted
    dead: bool = False  # the rule never matches (and not: matches, but adds nothing)
    ids: Dict[str, str] = field(default_factory=dict)  # the source platform's own identifiers of the rule (Rule.source_ids)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "check": self.check, "level": _LEVEL_NAMES[self.level], "kind": self.kind, "name": self.shown or self.name,
            "message": self.message, "action": self.action,
        }  # fmt: skip
        if self.ids:
            out["source_ids"] = dict(self.ids)
        if self.related:
            out["related"] = self.related
        if self.done:
            out["done"] = self.done
        if self.reason:
            out["reason"] = self.reason
        return out


# -- sets of services -----------------------------------------------------------------------------

Rect = Tuple[int, int, int, int]
_WHOLE: Rect = (0, 65535, 0, 65535)
_NUMBER = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132, Protocol.ICMP: 1, Protocol.ICMP6: 58}
_PROTOCOL_NAMES = {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp6"}


@dataclass
class Services:
    """A set of (protocol, a, b): source and destination port for TCP, UDP and SCTP, type and code for ICMP.

    ``protocols`` holds rectangles per protocol number; ``rest`` says that every protocol not
    listed there is in the set as a whole.
    """

    protocols: Dict[int, List[Rect]] = field(default_factory=dict)
    rest: bool = False

    def of(self, number: int) -> List[Rect]:
        return self.protocols.get(number, [_WHOLE] if self.rest else [])

    def empty(self) -> bool:
        return not self.rest and not any(self.protocols.values())

    def everything(self) -> bool:
        return self.rest and all(not _rects_minus([_WHOLE], rects) for rects in self.protocols.values())

    def and_(self, other: "Services") -> "Services":
        numbers = set(self.protocols) | set(other.protocols)
        out = {n: [r for a in self.of(n) for b in other.of(n) for r in [_rect_and(a, b)] if r is not None] for n in numbers}
        return Services(out, self.rest and other.rest)

    def minus(self, other: "Services") -> "Services":
        numbers = set(self.protocols) | set(other.protocols)
        return Services({n: _rects_minus(self.of(n), other.of(n)) for n in numbers}, self.rest and not other.rest)

    def meets(self, other: "Services") -> bool:
        return not self.and_(other).empty()

    def volume(self, exact: bool = True) -> int:
        """How much is in the set; with ``exact`` off, rectangles that overlap count twice (never too little)."""
        total = 0
        for rects in self.protocols.values():
            seen: List[Rect] = []
            for rect in rects:
                for piece in _rects_minus([rect], seen) if exact else [rect]:
                    total += (piece[1] - piece[0] + 1) * (piece[3] - piece[2] + 1)
                seen.append(rect)
        if self.rest:
            total += (256 - sum(1 for number in self.protocols if 0 <= number <= 255)) * 65536 * 65536
        return total


def _rect_and(a: Rect, b: Rect) -> Optional[Rect]:
    low_a, high_a, low_b, high_b = max(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), min(a[3], b[3])
    return (low_a, high_a, low_b, high_b) if low_a <= high_a and low_b <= high_b else None


def _rect_minus(a: Rect, b: Rect) -> List[Rect]:
    cut = _rect_and(a, b)
    if cut is None:
        return [a]
    out: List[Rect] = []
    if a[0] < cut[0]:
        out.append((a[0], cut[0] - 1, a[2], a[3]))
    if cut[1] < a[1]:
        out.append((cut[1] + 1, a[1], a[2], a[3]))
    if a[2] < cut[2]:
        out.append((cut[0], cut[1], a[2], cut[2] - 1))
    if cut[3] < a[3]:
        out.append((cut[0], cut[1], cut[3] + 1, a[3]))
    return out


def _rects_minus(a: List[Rect], b: List[Rect]) -> List[Rect]:
    for piece in b:
        if not a:
            break
        a = [left for rect in a for left in _rect_minus(rect, piece)]
    return a


_ALL_SERVICES = Services({}, True)
_EVERY_ADDRESS: List[Interval] = [FULL_V4, FULL_V6]


def _port_ranges(ports: str) -> Optional[List[Tuple[int, int]]]:
    if not ports:
        return [(0, 65535)]
    out: List[Tuple[int, int]] = []
    for part in ports.split(","):
        first, _, last = part.partition("-")
        if not first.isdigit() or not (last or first).isdigit() or len(first) > 5 or len(last) > 5:
            return None
        low, high = int(first), int(last or first)
        if low > high or high > 65535:
            return None
        out.append((low, high))
    return out


def _entry_services(entry: ServiceEntry) -> Optional[Services]:
    if entry.protocol in L4_PROTOCOLS:
        src, dst = _port_ranges(entry.src_ports), _port_ranges(entry.dst_ports)
        if src is None or dst is None:
            return None
        return Services({_NUMBER[entry.protocol]: [(s[0], s[1], d[0], d[1]) for s in src for d in dst]})
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        kind = (0, 65535) if entry.icmp_type is None else (entry.icmp_type, entry.icmp_type)
        code = (0, 65535) if entry.icmp_code is None else (entry.icmp_code, entry.icmp_code)
        return Services({_NUMBER[entry.protocol]: [kind + code]})
    if entry.ip_protocol is None:
        return Services({}, True)
    return Services({entry.ip_protocol: [_WHOLE]})


def _spec_services(spec: str) -> Optional[Services]:
    """``tcp/23``, ``udp/161-162``: what a configured service stands for."""
    protocol, _, ports = spec.strip().lower().partition("/")
    numbers = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "sctp": Protocol.SCTP}
    if protocol not in numbers or not ports or _port_ranges(ports) is None:
        return None
    return _entry_services(ServiceEntry(numbers[protocol], ports))


def _union(sets: Sequence[Services]) -> Services:
    out = Services()
    for one in sets:
        numbers = set(out.protocols) | set(one.protocols)
        out = Services({n: out.of(n) + one.of(n) for n in numbers}, out.rest or one.rest)
    return out


# -- what a rule matches --------------------------------------------------------------------------

_OTHER = "\0other"  # the zones nobody names: "any" takes them in
_SAME, _DIFFERENT = 1, 2  # a packet stays inside one zone, or goes from one zone to another
# Findings of a parser that say a rule of the model is not quite the rule of the source. Those about
# destination NAT are not among them: the audit looks at such rules as the source did (see _Reader).
_ABOUT_NAT = frozenset({"NAT_DESTINATION_REWRITTEN", "NAT_DESTINATION_WIDENED", "NAT_ADDRESS_EXPOSED", "NAT_PORT_TRANSLATION",
                        "NAT_PORT_EXPOSED", "NAT_REDIRECT"})  # fmt: skip


class _Zones:
    """Zones as bits of a number: a set of zone pairs is (source zones, destination zones, relation).

    The relation says whether the two zones are one and the same. It is a dimension of its own, so
    that "inside a zone" and "between zones" can be taken out of each other like addresses can, and
    a set of pairs costs two numbers of as many bits as there are zones, not their product.
    """

    def __init__(self, names: Sequence[str]) -> None:
        self.names = list(dict.fromkeys(name for name in names if name != ANY)) + [_OTHER]
        self.index = {name: position for position, name in enumerate(self.names)}
        self.all = (1 << len(self.names)) - 1
        self.other = 1 << (len(self.names) - 1)

    def bits(self, zones: Sequence[str]) -> int:
        if ANY in zones:
            return self.all
        bits = 0
        for zone in zones:
            if zone in self.index:
                bits |= 1 << self.index[zone]
        return bits

    def of(self, src: Sequence[str], dst: Sequence[str], scope: RuleScope) -> Tuple[int, int, int]:
        if scope == RuleScope.INTRAZONE:
            return self.bits(src), self.all, _SAME
        return self.bits(src), self.bits(dst), _DIFFERENT if scope == RuleScope.INTERZONE else _SAME | _DIFFERENT

    def possible(self, src: int, dst: int, relation: int) -> bool:
        """Whether any pair of zones is in the set."""
        if not src or not dst:
            return False
        if relation & _SAME and src & dst:
            return True
        if relation & _DIFFERENT:
            union = src | dst
            # Two zones to choose from; or the zones nobody names, of which there may be two.
            return bool(union & (union - 1)) or bool(src & dst & self.other)
        return False


# Source zones, destination zones, relation, sources, destinations, services. The addresses of one box
# are of one IP version: no packet goes from an IPv4 address to an IPv6 one.
Box = Tuple[int, int, int, List[Interval], List[Interval], Services]
Hull = Tuple[int, int, int, int]  # the lowest and highest source, the lowest and highest destination
_V6_FROM = 1 << 129  # where the IPv6 addresses start when both versions are put on one line
_NOWHERE: Hull = (1, 0, 1, 0)  # the reach of a rule that matches nothing: it meets no other


def _reach(boxes: Sequence[Box]) -> Hull:
    """The lowest and highest address on each side of some boxes, the two IP versions on one line."""
    if not boxes:
        return _NOWHERE
    src = [(i[1] + _V6_FROM, i[2] + _V6_FROM) if i[0] == 6 else (i[1], i[2]) for box in boxes for i in box[3]]
    dst = [(i[1] + _V6_FROM, i[2] + _V6_FROM) if i[0] == 6 else (i[1], i[2]) for box in boxes for i in box[4]]
    return (min(low for low, _ in src), max(high for _, high in src), min(low for low, _ in dst), max(high for _, high in dst))


@dataclass
class _Match:
    """What a rule matches, from above (what it might) and from below (what it surely does)."""

    rule: Rule
    index: int
    zones: Tuple[int, int, int]
    sources: List[str]  # the lists as the source platform matched them
    destinations: List[str]
    src_over: List[Interval]
    src_under: List[Interval]
    dst_over: List[Interval]
    dst_under: List[Interval]
    svc_over: Services
    svc_under: Services
    covers: bool  # usable as a rule that takes traffic away from later ones
    loose: bool = False  # the parser said the model does not hold this rule exactly: nothing is claimed about it
    over: List[Box] = field(default_factory=list)  # one box per IP version
    hull: Hull = _NOWHERE
    key: Tuple[int, int, int, int, int, int] = (1, 0, 1, 0, 0, 0)  # the hull and the zones: what a pair of rules is first tried on

    def __post_init__(self) -> None:
        for version in (4, 6):
            src = [interval for interval in self.src_over if interval[0] == version]
            dst = [interval for interval in self.dst_over if interval[0] == version]
            if src and dst:
                self.over.append((self.zones[0], self.zones[1], self.zones[2], src, dst, self.svc_over))
        self.hull = _reach(self.over)
        self.key = self.hull + (self.zones[0], self.zones[1])


@dataclass
class Reading:
    """What a parser said about how well the model holds the source: taken before anything else is reported."""

    open_addresses: Set[str] = field(default_factory=set)
    open_services: Set[str] = field(default_factory=set)
    loose: Dict[str, List[str]] = field(default_factory=dict)  # origin of a rule -> the findings that say so

    @classmethod
    def of(cls, report: Any) -> "Reading":
        out = cls()
        for item in report.items.values():
            codes = [f.code for f in item.findings if f.severity >= 1 and f.code not in _ABOUT_NAT]
            if not codes:
                continue
            if item.kind in ("address", "address-group"):
                out.open_addresses.add(item.name)
            elif item.kind in ("service", "service-group"):
                out.open_services.add(item.name)
            elif item.kind == "rule":
                out.loose[item.name] = codes
        return out


class _Reader:
    """Reads rules into sets, with what it resolved once kept.

    A source that looks rules up after destination NAT is read as it matched: without the pre-NAT
    addresses its parser added to reach the model. Those stand for the translated traffic only,
    not for everything sent to that address.
    """

    def __init__(self, p: Policy, reading: Optional[Reading] = None, as_written: bool = False) -> None:
        self.p = p
        self.as_written = as_written  # the model an emitter writes from: every destination in it is one the target matches
        zones = list(p.zones) + [z for r in p.rules for z in r.src_zones + r.dst_zones]
        zones += [z for n in p.nat_rules for z in n.src_zones + n.dst_zones]
        self.zones = _Zones(zones)
        self.entries: Dict[str, Optional[List[ServiceEntry]]] = {}
        self.services: Dict[Tuple[str, ...], Tuple[Services, bool]] = {}
        self.sure: Dict[str, Tuple[List[Interval], bool]] = {}
        self.addresses: Dict[Tuple[Tuple[str, ...], bool], Tuple[List[Interval], List[Interval]]] = {}
        # Objects and rules the parser could only read approximately.
        reading = reading or Reading()
        self.open_addresses: Set[str] = set(reading.open_addresses)
        self.open_services: Set[str] = set(reading.open_services)
        self.loose: Dict[str, List[str]] = dict(reading.loose)
        if p.named_translations:
            # A virtual IP in a policy stands for the traffic it translates, not for an address.
            self.open_addresses |= {translation.pre for translation in transform.destination_translations(p)}

    def _entries(self, name: str, seen: Tuple[str, ...] = ()) -> Optional[List[ServiceEntry]]:
        if name in self.entries:
            return self.entries[name]
        p = self.p
        out: Optional[List[ServiceEntry]]
        if name in self.open_services:
            out = None
        elif name in p.services:
            service = p.services[name]
            out = None if service.unsupported or not service.entries else list(service.entries)
        elif name in p.service_groups and name not in seen:
            out = []
            for member in p.service_groups[name].members:
                inner = self._entries(member, seen + (name,))
                if inner is None:
                    out = None
                    break
                out += inner
        else:
            return None  # "application-default", a name nothing stands behind, a group inside itself
        self.entries[name] = out
        return out

    def service_set(self, names: Sequence[str]) -> Tuple[Services, bool]:
        """(the services that can be read off a list, whether that is all of it)."""
        key = tuple(names)
        if key not in self.services:
            sets: List[Services] = []
            complete = True
            for name in names:
                if name == ANY:
                    sets.append(_ALL_SERVICES)
                    continue
                entries = self._entries(name)
                converted = [_entry_services(entry) for entry in entries] if entries is not None else [None]
                if any(one is None for one in converted):
                    complete = False
                sets += [one for one in converted if one is not None]
            self.services[key] = (_union(sets), complete)
        return self.services[key]

    def _sure(self, member: str, seen: Tuple[str, ...] = ()) -> Tuple[List[Interval], bool]:
        """(the addresses a member surely holds, whether that is all it can hold)."""
        if member in self.sure:
            return self.sure[member]
        p = self.p
        out: Tuple[List[Interval], bool]
        if member in self.open_addresses:
            out = ([], False)
        elif member in p.address_groups:
            group = p.address_groups[member]
            if group.dynamic_filter or group.unsupported:
                out = ([], False)  # what is listed in it need not be what it matches (members that are excluded)
            elif member in seen:
                return [], False
            else:
                parts = [self._sure(inner, seen + (member,)) for inner in group.members]
                out = ([interval for intervals, _ in parts for interval in intervals], all(done for _, done in parts))
        else:
            resolved = transform.address_intervals(p, member)
            out = (resolved, True) if resolved is not None else ([], False)
        self.sure[member] = out
        return out

    def address_sets(self, members: Sequence[str], negated: bool) -> Tuple[List[Interval], List[Interval]]:
        """(the addresses a side of a rule might match, the addresses it surely matches)."""
        key = (tuple(members), negated)
        if key not in self.addresses:
            resolved = [self._sure(member) for member in members]
            sure = normalize([interval for intervals, _ in resolved for interval in intervals])
            complete = all(done for _, done in resolved)
            if negated:
                left = subtract(_EVERY_ADDRESS, sure)
                self.addresses[key] = (left, left if complete else [])
            else:
                self.addresses[key] = (sure if complete else list(_EVERY_ADDRESS), sure)
        return self.addresses[key]

    def destinations(self, rule: Rule) -> List[str]:
        if self.as_written or not self.p.lookup_after_dnat or not rule.nat_added:
            return rule.destinations
        return [member for member in rule.destinations if member not in rule.nat_added] or rule.destinations

    def match(self, rule: Rule, index: int) -> _Match:
        destinations = self.destinations(rule)
        src_over, src_under = self.address_sets(rule.sources, rule.negate_source)
        dst_over, dst_under = self.address_sets(destinations, rule.negate_destination)
        known, complete = self.service_set(rule.services)
        if rule.negate_service:
            left = _ALL_SERVICES.minus(known)
            svc_over, svc_under = left, (left if complete else Services())
        else:
            svc_over, svc_under = (known if complete else _ALL_SERVICES), known
        loose = (rule.origin or rule.name) in self.loose
        return _Match(
            rule, index, self.zones.of(rule.src_zones, rule.dst_zones, rule.scope), rule.sources, destinations,
            src_over, src_under, dst_over, dst_under, svc_over, svc_under,
            rule.enabled and not rule.unsupported and not loose, loose,
        )  # fmt: skip


def _names_within(inner: Sequence[str], inner_negated: bool, outer: Sequence[str], outer_negated: bool) -> bool:
    """Whether one list says no more than another, by the names in it: that holds whatever the names stand for."""
    if inner_negated != outer_negated:
        return False
    if inner_negated:
        return set(outer) <= set(inner)
    return ANY in outer or set(inner) <= set(outer)


def _weaker(outer: Sequence[str], inner: Sequence[str]) -> bool:
    """Whether a list of applications, users or categories lets through all that another does."""
    return list(outer) == [ANY] or (list(inner) != [ANY] and set(inner) <= set(outer))


def _blocks(rule: Rule) -> bool:
    return rule.action != Action.ALLOW


def _same_handling(a: Rule, b: Rule) -> bool:
    """Whether traffic gets the same from two rules: the verdict and what goes with it."""
    return (a.action, a.log_start, a.log_end, a.profiles, a.handling) == (b.action, b.log_start, b.log_end, b.profiles, b.handling)


class _Sets:
    """Taking what rules match out of each other."""

    def __init__(self, zones: _Zones) -> None:
        self.zones = zones

    def may_meet(self, a: _Match, b: _Match) -> bool:
        """A cheap test that settles most pairs of rules: no zone pair in common, or no address."""
        mine, theirs = a.hull, b.hull
        if not (mine[0] <= theirs[1] and theirs[0] <= mine[1] and mine[2] <= theirs[3] and theirs[2] <= mine[3]):
            return False
        return self.zones.possible(a.zones[0] & b.zones[0], a.zones[1] & b.zones[1], a.zones[2] & b.zones[2])

    @staticmethod
    def cover(earlier: _Match, later: _Match) -> Optional[Box]:
        """What one rule surely takes of another; None where a criterion the sets do not hold may keep it out."""
        a, b = earlier.rule, later.rule
        if not (_weaker(a.applications, b.applications) and _weaker(a.users, b.users) and _weaker(a.url_categories, b.url_categories)):
            return None
        if a.schedule and a.schedule != b.schedule:
            return None
        src = _EVERY_ADDRESS if _names_within(later.sources, b.negate_source, earlier.sources, a.negate_source) else earlier.src_under
        dst = (_EVERY_ADDRESS if _names_within(later.destinations, b.negate_destination, earlier.destinations, a.negate_destination)
               else earlier.dst_under)  # fmt: skip
        svc = _ALL_SERVICES if _names_within(b.services, b.negate_service, a.services, a.negate_service) else earlier.svc_under
        return (earlier.zones[0], earlier.zones[1], earlier.zones[2], src, dst, svc)

    def minus(self, a: Box, b: Box) -> Tuple[List[Box], bool]:
        """(what is left of one box without another, whether they met at all)."""
        possible = self.zones.possible
        src_zones, dst_zones, relation = a[0] & b[0], a[1] & b[1], a[2] & b[2]
        if not possible(src_zones, dst_zones, relation):
            return [a], False
        src = intersect(a[3], b[3])
        if not src:
            return [a], False
        dst = intersect(a[4], b[4])
        if not dst:
            return [a], False
        svc = a[5].and_(b[5])
        if svc.empty():
            return [a], False
        out: List[Box] = []
        if possible(a[0] & ~b[0], a[1], a[2]):
            out.append((a[0] & ~b[0], a[1], a[2], a[3], a[4], a[5]))
        if possible(src_zones, a[1] & ~b[1], a[2]):
            out.append((src_zones, a[1] & ~b[1], a[2], a[3], a[4], a[5]))
        if possible(src_zones, dst_zones, a[2] & ~b[2]):
            out.append((src_zones, dst_zones, a[2] & ~b[2], a[3], a[4], a[5]))
        left = subtract(a[3], b[3])
        if left:
            out.append((src_zones, dst_zones, relation, left, a[4], a[5]))
        left = subtract(a[4], b[4])
        if left:
            out.append((src_zones, dst_zones, relation, src, left, a[5]))
        rest = a[5].minus(b[5])
        if not rest.empty():
            out.append((src_zones, dst_zones, relation, src, dst, rest))
        return out, True

    def take(self, boxes: List[Box], cover: Box) -> Tuple[List[Box], bool]:
        pieces: List[Box] = []
        touched = False
        for box in boxes:
            rest, met = self.minus(box, cover)
            pieces += rest
            touched = touched or met
        return pieces, touched

    def both(self, a: Box, b: Box) -> Optional[Box]:
        """What two boxes have in common."""
        zones = (a[0] & b[0], a[1] & b[1], a[2] & b[2])
        if not self.zones.possible(*zones):
            return None
        src = intersect(a[3], b[3])
        dst = intersect(a[4], b[4]) if src else []
        svc = a[5].and_(b[5]) if dst else None
        if svc is None or svc.empty():
            return None
        return (zones[0], zones[1], zones[2], src, dst, svc)

    @staticmethod
    def weight(box: Box) -> int:
        """How much a box holds, zones aside (and never too little): what the covers are sorted by."""
        return sum(size(i) for i in box[3]) * sum(size(i) for i in box[4]) * box[5].volume(exact=False)

    def leaves(self, boxes: List[Box], covers: Sequence[Box], weights: Optional[Sequence[int]] = None) -> Optional[bool]:
        """Whether anything of the boxes is left once the covers are taken out; None when that cannot be followed.

        The largest covers go first: one rule that holds everything settles it at once, where taking
        thousands of single hosts out of a broad rule first would leave it in as many pieces.
        """
        if not boxes:
            return False
        if not covers or self.too_small(covers, boxes):
            return True
        weights = weights if weights is not None else [self.weight(cover) for cover in covers]
        by_size = [covers[position] for position in sorted(range(len(covers)), key=lambda position: -weights[position])]
        for order in (by_size, covers):
            left = boxes
            for cover in order:
                left = self.take(left, cover)[0]
                if not left:
                    return False
                if len(left) > _MAX_BOXES:
                    break
            else:
                return True
        return None

    @staticmethod
    def too_small(covers: Sequence[Box], boxes: Sequence[Box]) -> bool:
        """Whether boxes hold more addresses and services than all the covers have of them: then something is left.

        The zones are left out of the count: an address pair and a service that no cover has is left
        in every pair of zones a box is for.
        """
        for box in boxes:
            room = sum(size(i) for i in box[3]) * sum(size(i) for i in box[4]) * box[5].volume()
            for cover in covers:
                src = intersect(box[3], cover[3])
                dst = intersect(box[4], cover[4]) if src else []
                if dst:
                    room -= sum(size(i) for i in src) * sum(size(i) for i in dst) * box[5].and_(cover[5]).volume(exact=False)
                    if room <= 0:
                        break
            if room > 0:
                return True
        return False

    def meet(self, a: _Match, b: _Match) -> bool:
        """Whether two rules might match the same packet."""
        if not self.may_meet(a, b):
            return False
        return any(
            self.zones.possible(x[0] & y[0], x[1] & y[1], x[2] & y[2]) and overlaps(x[3], y[3]) and overlaps(x[4], y[4])
            and x[5].meets(y[5])
            for x in a.over for y in b.over
        )  # fmt: skip


# -- the checks -----------------------------------------------------------------------------------


def _quoted(names: Sequence[str], limit: int = 4) -> str:
    shown = ", ".join(f"'{name}'" for name in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _day(moment: int) -> str:
    """A time of a hit counter (UTC seconds) as its day."""
    try:
        return datetime.datetime.fromtimestamp(moment, datetime.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return f"{moment} (seconds since 1970)"


def _counted_on_source(rule: Rule) -> bool:
    """Whether the rule is a rule of the source with an identity of its own, which a hit counter could name.

    The implicit cleanup of a Check Point inline layer, a rule FWShift added, has none.
    """
    return any(key.endswith((".rule_uid", ".name", ".uuid", ".policyid")) for key in rule.source_ids)


def _where(rule: Rule) -> str:
    src = "any zone" if ANY in rule.src_zones else "zone " + ", ".join(rule.src_zones)
    if rule.scope == RuleScope.INTRAZONE:
        return f"inside {src}"
    dst = "any zone" if ANY in rule.dst_zones else "zone " + ", ".join(rule.dst_zones)
    return f"from {src} to {dst}"


class _Audit:
    def __init__(self, p: Policy, config: AuditConfig, reading: Optional[Reading] = None, as_written: bool = False) -> None:
        self.p = p
        self.config = config
        self.reader = _Reader(p, reading, as_written)
        self.sets = _Sets(self.reader.zones)
        self.findings: List[Finding] = []
        self.undecided: List[str] = []  # rules that fell into too many pieces to follow
        self.dead: Set[int] = set()  # positions of the rules that never match
        self.matches = [self.reader.match(rule, index) for index, rule in enumerate(p.rules)]

    def on(self, check: str) -> bool:
        return self.config.action(check) != OFF

    def add(self, check: str, kind: str, name: str, message: str, shown: str = "", related: Sequence[str] = (),
            level: Optional[Level] = None, names: Sequence[str] = (), dead: bool = False,
            ids: Optional[Dict[str, str]] = None) -> None:  # fmt: skip
        if not self.on(check):
            return
        finding = Finding(check, self.config.level(check) if level is None else level,
                          kind, name, message, shown if shown != name else "", list(related), self.config.action(check),
                          dead=dead, ids=dict(ids or {}))  # fmt: skip
        for acceptance in self.config.accepted:
            if acceptance.covers(check, [name, shown, *names], kind):
                finding.action, finding.reason, acceptance.used = ACCEPT, acceptance.reason, True
                break
        self.findings.append(finding)

    def rule(self, check: str, rule: Rule, message: str, related: Sequence[Rule] = (), level: Optional[Level] = None,
             dead: bool = False) -> None:  # fmt: skip
        self.add(check, "rule", rule.origin or rule.name, message, rule.name, [r.origin or r.name for r in related], level, dead=dead,
                 ids=rule.source_ids)  # fmt: skip

    def run(self) -> List[Finding]:
        self.permissive()
        self.order()
        self.nat_order()
        self.loose_ends()
        self.usage()
        return self.findings

    # .. use, from hit counters

    def usage(self) -> None:
        """Allow rules that a hit counter shows unused, and rules about which the counters say nothing.

        A zero proves something only for the time the counter has counted, from its start (the reset, creation or
        change of the rule; for Check Point no earlier than the counts of the export reach back; or the date the
        user gives with hits_since) to the moment it was read, for which the latest time its answer shows stands
        in: never later than that moment, so the period is never taken longer than it was. Shorter than
        ``usage_days``, not known, or not from every firewall the rule may be on: no evidence. A blocking rule gets
        no finding: that nothing tried to pass it says nothing about whether it is needed.
        """
        if not any(rule.hits is not None for rule in self.p.rules):
            return
        days, given = self.config.usage_days, self.config.hits_since
        for rule in self.p.rules:
            hits = rule.hits
            if not rule.enabled:
                continue
            if hits is None:
                if _counted_on_source(rule):
                    self.rule("NO_USAGE_EVIDENCE", rule, "has no hit counter in the input, while other rules have one: nothing can be "
                              "said about its use")  # fmt: skip
                continue
            if hits.count or _blocks(rule):
                continue
            where = f" ({hits.read_from})" if hits.read_from else ""
            note = f". {hits.note[:1].upper()}{hits.note[1:]}" if hits.note else ""
            zero = f"has a hit counter of 0{where}"
            if not hits.complete:
                self.rule("NO_USAGE_EVIDENCE", rule, f"{zero}, but not from every firewall it may be on{note}")
                continue
            if hits.counting_since is None and given is None:
                self.rule("NO_USAGE_EVIDENCE", rule, f"{zero}, but the input does not tell since when it counts (give the date with "
                          f"--hits-since, if it is known){note}")  # fmt: skip
                continue
            start = max(moment for moment in (hits.counting_since, hits.covers_from, given) if moment is not None)
            if hits.read_until is None:
                self.rule("NO_USAGE_EVIDENCE", rule, f"{zero}, but its answer shows no time at all, so how long it counted cannot be "
                          f"told{note}")  # fmt: skip
                continue
            if hits.read_until - start < days * 86400:
                age = max(hits.read_until - start, 0) // 86400
                self.rule("NO_USAGE_EVIDENCE", rule, f"{zero}, but it has counted only since {_day(start)}: {age} day(s) before the "
                          f"latest time its answer shows, fewer than the {days} the audit asks for{note}")  # fmt: skip
                continue
            told = " (from --hits-since)" if given is not None and start == given else ""
            self.rule("UNUSED_RULE", rule, f"allows traffic {_where(rule)}, and its hit counter{where} is 0 from {_day(start)}{told} to "
                      f"{_day(hits.read_until)} at least{note}. Check that the counters cover every firewall the rule is on")  # fmt: skip

    # .. rules that allow a lot

    def _side_any(self, members: Sequence[str], negated: bool) -> Tuple[bool, List[Interval]]:
        """(whether a side of a rule takes in a whole IP version, the addresses it is known to hold)."""
        _, under = self.reader.address_sets(members, negated)
        return FULL_V4 in under or FULL_V6 in under, under

    def _one_path(self, rule: Rule) -> bool:
        """Whether a rule names zones on both sides that keep it to part of the firewall.

        A rule from one zone to every other zone names zones without being kept anywhere: that is
        what a rule looks like on a platform that binds its rules to an interface.
        """
        if ANY in rule.src_zones:
            return False
        if rule.scope == RuleScope.INTRAZONE:
            return True
        if ANY in rule.dst_zones:
            return False
        known = set(self.reader.zones.names) - {_OTHER}
        return bool(known - set(rule.dst_zones) - set(rule.src_zones))

    def permissive(self) -> None:
        config, vendor = self.config, self.p.vendor
        risky = {name: _union([s for spec in specs for s in [_spec_services(spec)] if s]) for name, specs in config.risky_services.items()}
        industrial = {name: _union([s for spec in specs for s in [_spec_services(spec)] if s])
                      for name, specs in config.industrial_services.items()}  # fmt: skip
        for match in self.matches:
            rule = match.rule
            if not rule.enabled:
                continue
            if vendor in _LOGGING_BY_RULE and not (rule.log_start or rule.log_end):
                self.rule("NO_LOG", rule, f"{'allows' if not _blocks(rule) else 'blocks'} traffic {_where(rule)} without logging it")
            if _blocks(rule):
                continue
            if vendor in _PROFILES and not rule.profiles:
                self.rule("NO_PROFILE", rule, f"allows traffic {_where(rule)} without a security profile (antivirus, IPS, ...)")
            src_any, src = self._side_any(match.sources, rule.negate_source)
            dst_any, dst = self._side_any(match.destinations, rule.negate_destination)
            everything = match.svc_under.everything()
            apps_any = rule.applications == [ANY]
            svc_any = apps_any and (everything or rule.services == [APP_DEFAULT])  # "any application" is as wide
            where = _where(rule)
            # Kept to one path through the firewall by its zones: one level lower.
            fenced = self._one_path(rule)

            def level(check: str) -> Level:
                return Level(max(config.level(check) - 1, Level.INFO)) if fenced else config.level(check)

            if src_any and dst_any and svc_any:
                self.rule("ANY_ANY_ANY", rule, f"allows any source to reach any destination on any service, {where}",
                          level=level("ANY_ANY_ANY"))  # fmt: skip
            elif svc_any:
                side = "from any source" if src_any else "to any destination" if dst_any else "between its addresses"
                self.rule("ANY_SERVICE", rule, f"allows any service {side}, {where}", level=level("ANY_SERVICE"))
            elif src_any and dst_any:
                self.rule("ANY_TO_ANY", rule, f"allows its services from any source to any destination, {where}",
                          level=level("ANY_TO_ANY"))  # fmt: skip
            elif src_any:
                self.rule("ANY_SOURCE", rule, f"allows any source, {where}")
            elif dst_any:
                self.rule("ANY_DESTINATION", rule, f"allows its sources to reach any destination, {where}")
            wide = [
                interval_text(interval)
                for any_side, intervals in ((src_any, src), (dst_any, dst))
                if not any_side
                for interval in intervals
                if size(interval) >= 2 ** ((32 - config.wide_network_v4) if interval[0] == 4 else (128 - config.wide_network_v6))
            ]
            if wide:
                self.rule("WIDE_NETWORK", rule, f"allows traffic for {_quoted(wide)}, {where}")
            if svc_any:
                continue
            ports = [
                f"{_PROTOCOL_NAMES[number]}/{rect[2]}-{rect[3]}"
                for number in (6, 17, 132)
                for rect in match.svc_under.of(number)
                if rect[3] - rect[2] + 1 >= config.wide_ports
            ]
            if ports:
                self.rule("WIDE_PORTS", rule, f"allows the ports {', '.join(sorted(set(ports))[:4])}, {where}")
            for check, table, applications, what in (
                ("RISKY_SERVICE", risky, config.risky_applications, "the cleartext and remote administration protocols"),
                ("INDUSTRIAL_SERVICE", industrial, config.industrial_applications, "the industrial control protocols"),
            ):
                found = [name for name, services in table.items() if not everything and match.svc_under.meets(services)]
                found += [app for app in rule.applications if app in applications and app not in found]
                if found:
                    self.rule(check, rule, f"allows {', '.join(found)}, {where} (on the list of {what})")

    # .. the order of the rules

    @staticmethod
    def _near(match: _Match, others: Sequence[_Match]) -> List[_Match]:
        """The rules that share a zone on each side with a rule, and whose addresses reach into its own.

        Most pairs of rules of a large policy fail on that.
        """
        a, b, c, d, src, dst = match.key
        return [other for other in others for k in (other.key,)
                if k[4] & src and k[5] & dst and k[0] <= b and a <= k[1] and k[2] <= d and c <= k[3]]  # fmt: skip

    def _left_after(self, match: _Match, like_only: bool = False) -> Tuple[Optional[bool], List[Rule], List[Rule]]:
        """Whether anything is left of a rule once the rules above it took theirs, and who took of it.

        (whether, the rules that take part of it and do the same, those that do otherwise). The rules
        are named in their order: a rule takes part when the rules above it leave it something of
        this rule. ``like_only``: only rules with the same kind of action that ever match take
        anything. None when the rule fell into too many pieces to follow.
        """
        sets = self.sets
        covers: List[Tuple[_Match, bool, Box]] = []
        for earlier in self._near(match, self.matches[: match.index]):
            if not earlier.covers or not sets.may_meet(earlier, match):
                continue
            alike = _blocks(earlier.rule) == _blocks(match.rule)
            if like_only and (not alike or earlier.index in self.dead):
                continue
            cover = sets.cover(earlier, match)
            if cover is not None:
                covers.append((earlier, alike, cover))
        left = sets.leaves(match.over, [cover for _, _, cover in covers])
        if left is None:
            return None, [], []
        if left and (like_only or not self.on("OVERLAPPING_RULES")):
            return True, [], []
        same: List[Rule] = []
        other: List[Rule] = []
        # Taking the covers out in the order of the rules names those that take part, as long as the rule
        # stays in few pieces.
        rest = list(match.over)
        for earlier, alike, cover in covers:
            rest, touched = sets.take(rest, cover)
            if touched:
                (same if alike else other).append(earlier.rule)
            if not rest or len(rest) > _FEW_BOXES:
                break
        if len(rest) <= _FEW_BOXES:
            return left, same, other
        # Otherwise cover by cover: a rule takes part when the rules above it leave it something of this rule.
        same, other = [], []
        above: List[Tuple[Hull, Box, int]] = []
        for earlier, alike, cover in covers:
            pieces = [piece for box in match.over for piece in [sets.both(box, cover)] if piece is not None]
            if not pieces:
                continue
            a = _reach(pieces)
            near = [(box, weight) for b, box, weight in above if a[0] <= b[1] and b[0] <= a[1] and a[2] <= b[3] and b[2] <= a[3]]
            part = sets.leaves(pieces, [box for box, _ in near], [weight for _, weight in near])
            if part is None:
                return None, [], []
            if part:
                (same if alike else other).append(earlier.rule)
            above.append((a, cover, sets.weight(cover)))
        return left, same, other

    def order(self) -> None:
        if not any(self.on(check) for check in ("SHADOWED_RULE", "REDUNDANT_RULE", "EMPTY_RULE", "OVERLAPPING_RULES")):
            return
        matches, sets, dead = self.matches, self.sets, self.dead
        for match in matches:
            rule = match.rule
            if not rule.enabled or match.loose:
                continue
            if not match.over or not sets.zones.possible(*match.zones) or match.svc_over.empty():
                dead.add(match.index)
                what = ("its zones leave no pair of zones" if not sets.zones.possible(*match.zones)
                        else "its services hold nothing" if match.svc_over.empty()
                        else "its source holds no address" if not match.src_over
                        else "its destination holds no address" if not match.dst_over
                        else "its source and its destination have no IP version in common")  # fmt: skip
                self.rule("EMPTY_RULE", rule, f"can match nothing: {what}", dead=True)
                continue
            left, same, other = self._left_after(match)
            if left is None:
                self.undecided.append(rule.name)
                continue
            verdict = "blocks" if _blocks(rule) else "allows"
            does = "block" if _blocks(rule) else "allow"
            if not left:
                dead.add(match.index)
                like = same
                if other:
                    rest, like, _ = self._left_after(match, like_only=True)
                    like = like if rest is False else []
                if like:
                    # Rules that do the same hold all of it. (What rules above those decide otherwise, they
                    # decide for those rules just as well: this rule has nothing of its own.)
                    self.rule(
                        "REDUNDANT_RULE", rule,
                        f"never matches: {_quoted([r.name for r in like])} above it already "
                        f"{does}{'s' if len(like) == 1 else ''} everything it could match",
                        like, dead=True,
                    )  # fmt: skip
                else:
                    opposite = "allow" if _blocks(rule) else "block"
                    others = f", {_quoted([r.name for r in same])} {does}{'s' if len(same) == 1 else ''} the rest" if same else ""
                    self.rule(
                        "SHADOWED_RULE", rule,
                        f"never matches: the rule {verdict} traffic {_where(rule)}, but all it could match is taken by earlier "
                        f"rules: {_quoted([r.name for r in other])} {opposite}{'s' if len(other) == 1 else ''} "
                        f"{'part of ' if same else ''}it{others}",
                        other + same,
                        # A block that is not enforced weighs more than an access that is not given.
                        self.config.level("SHADOWED_RULE") if _blocks(rule) else Level(max(self.config.level("SHADOWED_RULE") - 1, 0)),
                        dead=True,
                    )  # fmt: skip
            elif other:
                self.rule(
                    "OVERLAPPING_RULES", rule,
                    f"{verdict} traffic {_where(rule)}, part of which earlier rules decide otherwise: {_quoted([r.name for r in other])}",
                    other,
                )  # fmt: skip
        if not self.on("REDUNDANT_RULE"):
            return
        # A rule that matches, but whose traffic a later rule would handle the same way.
        for match in matches:
            rule = match.rule
            if match.index in dead or not match.covers:
                continue
            for later in self._near(match, matches[match.index + 1 :]):
                if not later.rule.enabled or not sets.may_meet(later, match):
                    continue
                alike = _same_handling(rule, later.rule)
                # (A rule that never matches while this one is there is no reason to take this one away.)
                if alike and later.covers and later.index not in dead:
                    cover = sets.cover(later, match)
                    if cover is not None and not sets.take(list(match.over), cover)[0]:
                        self.rule(
                            "REDUNDANT_RULE", rule,
                            f"adds nothing: '{later.rule.name}' below it handles everything it matches the same way, "
                            "and no rule in between decides any of it otherwise",
                            [later.rule],
                        )  # fmt: skip
                        break
                if alike and not later.loose:
                    continue  # what it would take of this rule's traffic it handles the same way
                if later.loose or sets.meet(match, later):
                    break  # from here on part of its traffic would be decided by a rule that does something else

    def nat_order(self) -> None:
        if not self.on("SHADOWED_NAT"):
            return
        reader, sets = self.reader, self.sets
        rows: List[Tuple[NatRule, List[Box], List[Box], bool]] = []
        for nat in self.p.nat_rules:
            src_over, src_under = reader.address_sets(nat.sources, False)
            dst_over, dst_under = reader.address_sets(nat.destinations, False)
            known, complete = reader.service_set([nat.service])
            zones = reader.zones.of(nat.src_zones, nat.dst_zones, RuleScope.UNIVERSAL)

            def boxes(src: List[Interval], dst: List[Interval], svc: Services) -> List[Box]:
                out: List[Box] = []
                for version in (4, 6):
                    a, b = [i for i in src if i[0] == version], [i for i in dst if i[0] == version]
                    if a and b:
                        out.append((zones[0], zones[1], zones[2], a, b, svc))
                return out

            usable = nat.enabled and not nat.unsupported and not nat.combines
            rows.append((nat, boxes(src_over, dst_over, known if complete else _ALL_SERVICES), boxes(src_under, dst_under, known), usable))
        for position, (nat, over, _, usable) in enumerate(rows):
            both_ways = nat.source_translation is not None and nat.source_translation.bidirectional
            if not usable or both_ways or not over:
                continue  # where rules of two directions combine, "the first match" is not all there is
            left = list(over)
            hiding: List[str] = []
            for earlier, _, under, covers in rows[:position]:
                if not covers:
                    continue
                touched = False
                for cover in under:
                    left, met = sets.take(left, cover)
                    touched = touched or met
                if touched:
                    hiding.append(earlier.name)
                if not left or len(left) > _MAX_BOXES:
                    break
            if not left:
                self.add("SHADOWED_NAT", "nat", nat.origin or nat.name,
                         f"never matches: {_quoted(hiding)} above it translate{'s' if len(hiding) == 1 else ''} everything it could match",
                         nat.name)  # fmt: skip

    # .. loose ends

    def loose_ends(self) -> None:
        p = self.p
        for rule in p.rules:
            if not rule.enabled:
                self.rule("DISABLED_RULE", rule, "is disabled: remove it, or note why it is kept")
            elif not rule.description.strip():
                self.rule("NO_DESCRIPTION", rule, "has no description")
        if self.on("UNUSED_OBJECT"):
            kept = copy.copy(p)
            kept.addresses, kept.address_groups = dict(p.addresses), dict(p.address_groups)
            kept.services, kept.service_groups = dict(p.services), dict(p.service_groups)
            transform.prune_unused(kept)
            for kind, before, after in (
                ("address", p.addresses, kept.addresses), ("address-group", p.address_groups, kept.address_groups),
                ("service", p.services, kept.services), ("service-group", p.service_groups, kept.service_groups),
            ):  # fmt: skip
                unused = [name for name, item in before.items() if name not in after and not getattr(item, "builtin", "")]
                passed = [name for name in unused if any(a.covers("UNUSED_OBJECT", [name], kind) for a in self.config.accepted)]
                for name in passed:
                    self.add("UNUSED_OBJECT", kind, name, "no rule uses it")
                unused = [name for name in unused if name not in passed]
                if unused:
                    what = _PLURAL[kind] if len(unused) > 1 else kind.replace("-", " ")
                    self.add("UNUSED_OBJECT", kind, f"{len(unused)} {what}", f"{len(unused)} {what} no rule uses: {_quoted(unused, 12)}")
        if self.on("DUPLICATE_OBJECT"):
            by_value: Dict[Tuple[object, ...], List[str]] = {}
            for address in p.addresses.values():
                if address.builtin or address.kind == AddressKind.UNSUPPORTED or address.name in self.reader.open_addresses:
                    continue  # (an object that was read approximately is not known to be the same as another)
                value: object = address.value.lower()
                if address.kind != AddressKind.FQDN:
                    read = transform.address_intervals(p, address.name)
                    value = tuple(read) if read else address.value
                by_value.setdefault(("address", address.kind == AddressKind.FQDN, address.fqdn_family, value), []).append(address.name)
            for service in p.services.values():
                if service.builtin or service.unsupported or not service.entries or service.name in self.reader.open_services:
                    continue
                entries = tuple(sorted((e.protocol.value, e.dst_ports, e.src_ports, str(e.icmp_type), str(e.icmp_code),
                                        str(e.ip_protocol)) for e in service.entries))  # fmt: skip
                by_value.setdefault(("service", entries), []).append(service.name)
            for key, names in by_value.items():
                if len(names) > 1:
                    self.add("DUPLICATE_OBJECT", str(key[0]), names[0], f"the same {key[0]} under {len(names)} names: {_quoted(names, 8)}",
                             names=names)  # fmt: skip
        for group in p.address_groups.values():
            if not group.members and not group.dynamic_filter and not group.unsupported and not group.builtin:
                self.add("EMPTY_GROUP", "address-group", group.name, "has no members: it matches no address")
        for sgroup in p.service_groups.values():
            if not sgroup.members and not sgroup.builtin:
                self.add("EMPTY_GROUP", "service-group", sgroup.name, "has no members: it matches no service")
        if p.default_interzone == Action.ALLOW:
            self.add("DEFAULT_ALLOW", "policy", "default", "traffic between zones that no rule matches is allowed", "the policy")


# -- results --------------------------------------------------------------------------------------


@dataclass
class AuditResult:
    """What an audit found: in the policy as it was read, and - after a conversion - in what was written."""

    vendor: str = ""
    rules: int = 0
    before: List[Finding] = field(default_factory=list)
    undecided: List[str] = field(default_factory=list)
    loose: Dict[str, List[str]] = field(default_factory=dict)  # rules the parser read approximately, and why
    unmatched: List[str] = field(default_factory=list)  # accepted names that nothing answered to
    applied: bool = False  # the actions were carried out (a conversion), not just named
    after: Optional[List[Finding]] = None  # findings the converted policy has and the source had not
    gone: List[Finding] = field(default_factory=list)  # findings of the source whose rule is not in the output
    revived: List[Finding] = field(default_factory=list)  # rules that never matched and do now
    reading: Optional[Reading] = None  # what the parser said, for the audits that follow

    def reported(self) -> List[Finding]:
        """The findings that stand: not accepted, and not about a rule the audit disabled (what a conversion found after that does)."""
        off = {f.name for f in self.before if f.kind == "rule" and f.done.startswith("disabled")} if self.applied else set()
        return [f for f in self.before if f.action != ACCEPT and not (f.kind == "rule" and f.name in off)] + [
            f for f in self.after or [] if f.action != ACCEPT]  # fmt: skip

    def fails(self, level: Optional[Level]) -> bool:
        return level is not None and any(f.level >= level for f in self.reported())

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "summary": self.counts(self.before),
            "findings": [f.to_dict() for f in self.before],
            "not_followed": self.undecided,
            "read_approximately": self.loose,
            "accepted_nothing": self.unmatched,
        }
        if self.after is not None:
            out["after_conversion"] = {
                "summary": self.counts(self.after), "new": [f.to_dict() for f in self.after],
                "gone": [f.to_dict() for f in self.gone], "revived": [f.to_dict() for f in self.revived],
            }  # fmt: skip
        return out

    @staticmethod
    def counts(findings: Sequence[Finding]) -> Dict[str, int]:
        out = {name: 0 for name in ("high", "medium", "low", "info", "accepted")}
        for finding in findings:
            out["accepted" if finding.action == ACCEPT else _LEVEL_NAMES[finding.level]] += 1
        return out

    @staticmethod
    def _summary(counts: Dict[str, int]) -> str:
        return ", ".join(f"{name} {counts[name]}" for name in ("high", "medium", "low", "info")) + (
            f"; accepted {counts['accepted']}" if counts["accepted"] else "")  # fmt: skip

    def _lines(self, findings: Sequence[Finding]) -> List[str]:
        out: List[str] = []
        for finding in sorted((f for f in findings if f.action != ACCEPT), key=lambda f: -f.level):
            subject = f"{finding.kind.replace('-', ' ')} '{finding.shown or finding.name}' "
            several = finding.check == "DUPLICATE_OBJECT" or (finding.check == "UNUSED_OBJECT" and finding.name[:1].isdigit())
            if finding.kind == "policy" or several:
                subject = ""  # the message says what it is about
            out.append(f"  [{_LEVEL_NAMES[finding.level]}] {finding.check}: {subject}{finding.message}")
            if finding.done:
                out.append(f"      -> {finding.done}")
        return out

    def to_text(self, heading: str = "Audit") -> str:
        out = [heading, "  " + self._summary(self.counts(self.before))]
        lines = self._lines(self.before)
        out += ["", "Findings in the policy as it was read"] + (lines or ["  none"])
        accepted = [f for f in self.before + (self.after or []) if f.action == ACCEPT]
        if accepted:
            out += ["", "Accepted"]
            for finding in accepted:
                why = f" ({finding.reason})" if finding.reason else ""
                out.append(f"  {finding.check}: {finding.kind.replace('-', ' ')} '{finding.shown or finding.name}'{why}")
        if self.unmatched:
            out += ["", "Accepted, but not found", "  nothing answers to " + _quoted(self.unmatched, 8) + ": check the names"]
        if self.loose or self.undecided:
            out += ["", "Left out of the order checks"]
            if self.loose:
                out.append(f"  {len(self.loose)} rule(s) that the model holds only approximately are neither called dead nor used to "
                           "call another rule dead:")  # fmt: skip
                out += [f"    '{name}' ({', '.join(dict.fromkeys(codes))})" for name, codes in list(self.loose.items())[:20]]
                if len(self.loose) > 20:
                    out.append(f"    and {len(self.loose) - 20} more")
            if self.undecided:
                out.append(f"  {len(self.undecided)} rule(s) fell into too many pieces to tell whether earlier rules cover them: "
                           + _quoted(self.undecided, 8))  # fmt: skip
        if self.after is not None:
            out += ["", "After the conversion"]
            lines = self._lines(self.after)
            if lines:
                out.append("  " + self._summary(self.counts(self.after)))
            out += lines or ["  nothing new: the converted policy has no finding the source had not"
                             + (" (but see what was accepted)" if any(f.action == ACCEPT for f in self.after) else "")]  # fmt: skip
            if self.revived:
                out.append("  these never matched on the source and do in the output, because rules above them were not written: "
                           + _quoted([f.shown or f.name for f in self.revived], 12))  # fmt: skip
            if self.gone:
                out.append("  findings about rules that are not in the output, or are disabled there: "
                           + ", ".join(f"{f.check} '{f.shown or f.name}'" for f in self.gone[:12])
                           + (f" and {len(self.gone) - 12} more" if len(self.gone) > 12 else ""))  # fmt: skip
        return "\n".join(out) + "\n"


def run(p: Policy, config: Optional[AuditConfig] = None, reading: Optional[Any] = None) -> AuditResult:
    """Audit a policy as it stands. Nothing is changed; each finding names the action that is set for it.

    ``reading`` is the report the parser filled: a rule or object it could only read approximately
    is not used to prove anything.
    """
    config = config or AuditConfig()
    for acceptance in config.accepted:
        acceptance.used = False
    read = Reading.of(reading) if reading is not None else None
    audit = _Audit(p, config, read)
    findings = audit.run()
    for finding in findings:
        if finding.action == DISABLE:
            finding.done = "would be disabled by a conversion"
        elif finding.action == REORDER:
            finding.done = "would be moved up by a conversion"
    names = {rule.origin or rule.name: rule.name for rule in p.rules}
    loose = {names[origin]: codes for origin, codes in audit.reader.loose.items() if origin in names}
    unmatched = [acceptance.pattern for acceptance in config.accepted if not acceptance.used]
    return AuditResult(p.vendor, len(p.rules), findings, audit.undecided, loose, unmatched, reading=read)


def _order_only(config: AuditConfig) -> AuditConfig:
    again = copy.copy(config)
    again.accepted = []
    again.actions = {check: REPORT if CHECKS[check].changes_nothing else OFF for check in CHECKS}
    return again


Trial = Callable[[Policy], Tuple[Optional[Policy], List[str]]]


def _holds_as_written(written: Optional[Policy], lost: Sequence[str], config: AuditConfig) -> Optional[Set[str]]:
    """The rules that change nothing in the model an emitter writes from; None when there is no such model.

    A target need not match as the source did: it may look its rules up on the other side of a
    destination NAT, and two zones may have become one. (What an emitter does while it writes, such
    as turning applications into ports, is not in that model.) What the parser could only read
    approximately does not matter here: this is about what is written.
    """
    if written is None:
        return None
    return {f.name for f in _Audit(effective(written, lost), _order_only(config), None, as_written=True).run() if f.kind == "rule"}


def apply(p: Policy, result: AuditResult, config: AuditConfig, lost: Sequence[str] = (),
          trial: Optional[Trial] = None) -> List[Tuple[str, str, bool, str]]:  # fmt: skip
    """Carry out the actions of an audit on the policy.

    Returns what was done, per rule: (origin, check, whether verdicts change, description).

    First what changes verdicts: rules that are disabled for what they allow, and shadowed rules
    that are moved up. Then the order is looked at again, and of the rules that were found
    shadowed or redundant those that still are get disabled: that changes no verdict, and a rule
    that only looked redundant next to one that is gone now stays. ``lost`` holds the origins of
    the rules the target cannot take: they are gone as well, as far as this is concerned.

    ``trial`` converts a policy without writing anything and returns (the model the emitter wrote
    from, the rules the target cannot take). With it a rule is disabled only when it changes
    nothing in that model either: the proof is given on both sides of the conversion.
    """
    by_origin = {rule.origin or rule.name: rule for rule in p.rules}
    done: List[Tuple[str, str, bool, str]] = []
    result.applied = True
    for finding in result.before:
        finding.done = ""
        rule = by_origin.get(finding.name) if finding.kind == "rule" else None
        if rule is None or finding.action not in (DISABLE, REORDER):
            continue
        if finding.action == DISABLE and not CHECKS[finding.check].changes_nothing:
            if rule.enabled:
                rule.enabled = False
                finding.done = "disabled"
                done.append((finding.name, finding.check, True, "disabled"))
            else:
                finding.done = "disabled (for another finding)"
        elif finding.action == REORDER:
            hiding = [by_origin[origin] for origin in finding.related if origin in by_origin and _blocks(by_origin[origin]) != _blocks(rule)]
            positions = [p.rules.index(other) for other in hiding if other.enabled]
            if not rule.enabled or not positions or min(positions) > p.rules.index(rule):
                finding.done = "not moved: the rules above it have changed"
                continue
            target = p.rules[min(positions)]
            p.rules.remove(rule)
            p.rules.insert(p.rules.index(target), rule)
            finding.done = f"moved up, in front of '{target.name}'"
            done.append((finding.name, finding.check, True, finding.done))
    pending = [f for f in result.before if f.kind == "rule" and f.action == DISABLE and CHECKS[f.check].changes_nothing]
    moved = [f for f in result.before if f.done.startswith("moved")]
    if pending or moved:
        written: Optional[Policy] = None
        if trial is not None and pending:
            written, lost = trial(p)
        second = _Audit(effective(p, lost), _order_only(config), result.reading)
        again = second.run()
        still = {(f.check, f.name) for f in again}
        dead = {f.name for f in again if f.dead}
        holds = _holds_as_written(written, lost, config)
        for finding in moved:
            if finding.name in dead:
                # Another rule that was moved, or a rule above the one it was put in front of, has all of it.
                finding.done += "; it still never matches there"
        # All of them at once is safe: a rule that never matches is missed by no packet, and a rule that
        # adds nothing hands its traffic to rules that handle it alike, down to one that stays.
        for finding in pending:
            rule = by_origin[finding.name]
            if not rule.enabled:
                finding.done = "disabled (for another finding)"
            elif (finding.check, finding.name) in still and holds is not None and finding.name not in holds:
                finding.done = ("kept: in the output it decides traffic. The target does not match its rules as the source did "
                                "(on the other side of a destination NAT, or with zones that were mapped onto each other)")  # fmt: skip
            elif (finding.check, finding.name) in still:
                rule.enabled = False
                finding.done = "disabled; no traffic is decided differently"
                done.append((finding.name, finding.check, False, "disabled"))
            elif finding.name in lost:
                finding.done = "not in the output anyway"
            else:
                finding.done = "kept: with the other changes, or without the rules the target cannot take, it is needed"
    return done


def compare(result: AuditResult, converted: Policy, config: AuditConfig, lost: Sequence[str],
            written: Optional[Policy] = None) -> None:  # fmt: skip
    """Audit the policy as a conversion left it, and note what is new.

    ``converted`` is the policy with the rules the conversion could not write switched off;
    ``lost`` holds the origins of those rules; ``written`` is the model the emitter wrote from.
    """
    after = _Audit(converted, config, result.reading)
    found = after.run()
    seen = {(f.check, f.kind, f.name) for f in result.before}
    now = {(f.check, f.kind, f.name) for f in found}
    result.after = [f for f in found if (f.check, f.kind, f.name) not in seen and f.check != "DISABLED_RULE"]
    for finding in result.after:
        finding.done = ""
    enabled = {match.rule.origin or match.rule.name for match in after.matches if match.rule.enabled}
    missing = [f for f in result.before if (f.check, f.kind, f.name) not in now and f.action != ACCEPT
               and not f.done.startswith(("disabled", "moved"))]  # fmt: skip
    # (A rule that was accepted as dead on the source is still named when the conversion brought it to life.)
    result.revived = [f for f in result.before if (f.check, f.kind, f.name) not in now and f.kind == "rule" and f.name in enabled
                      and f.dead and not f.done.startswith(("disabled", "moved"))]  # fmt: skip
    result.gone = [f for f in missing if not (f.kind == "rule" and f.name in enabled and CHECKS[f.check].changes_nothing)]
    mark = len(after.findings)
    extra = after
    # A blocking rule that is not in the output, with something below it that allows what it blocked.
    matches = {match.rule.origin or match.rule.name: match for match in after.matches}
    zones = converted.zones
    for origin in lost:
        match = matches.get(origin)
        if match is None or not _blocks(match.rule):
            continue
        rule = match.rule
        below = [m.rule.name for m in after.matches[match.index + 1 :]
                 if m.rule.enabled and not _blocks(m.rule) and after.sets.meet(match, m)]  # fmt: skip
        possible = after.sets.zones.possible
        # Traffic inside a zone, where the rule is for any and the default (or the zone) lets it through.
        within = [name for name in after.sets.zones.names[:-1]
                  if possible(match.zones[0] & match.zones[1] & after.sets.zones.bits([name]), match.zones[1], match.zones[2] & _SAME)]
        inside = bool(within) and (converted.default_intrazone == Action.ALLOW
                                   or any(zones[name].intrazone_allow for name in within if name in zones))  # fmt: skip
        inside = inside or (possible(match.zones[0] & after.sets.zones.other, match.zones[1], match.zones[2] & _SAME)
                            and converted.default_intrazone == Action.ALLOW)  # fmt: skip
        between = possible(match.zones[0], match.zones[1], match.zones[2] & _DIFFERENT) and converted.default_interzone == Action.ALLOW
        if not (below or inside or between):
            continue
        takers = []
        if below:
            takers.append(f"{_quoted(below)} below it now allow{'s' if len(below) == 1 else ''}")
        if inside or between:
            takers.append("the default " + ("for traffic inside a zone " if inside and not between else "") + "now allows")
        extra.add("EXPOSED_BY_CONVERSION", "rule", origin,
                  f"blocks traffic {_where(rule)} on the source and is not enforced in the output: {' and '.join(takers)} part of "
                  "what it blocked. Fix the rule in the output before it goes live", rule.name)  # fmt: skip
    # A rule that was disabled because it changed nothing, next to rules that are not in the output after all.
    safe = [f for f in result.before if f.done.startswith("disabled; no traffic")]
    if safe:
        probe = copy.deepcopy(converted)
        for rule in probe.rules:
            if (rule.origin or rule.name) in {f.name for f in safe}:
                rule.enabled = True
        again = _Audit(probe, _order_only(config), result.reading)
        still = {f.name for f in again.run()}
        if written is not None:
            there = copy.deepcopy(written)
            for rule in there.rules:
                if (rule.origin or rule.name) in {f.name for f in safe}:
                    rule.enabled = True
            still &= _holds_as_written(there, lost, config) or set()
        for finding in safe:
            if finding.name not in still:
                rule = next(r for r in probe.rules if (r.origin or r.name) == finding.name)
                extra.add("EXPOSED_BY_CONVERSION", "rule", finding.name,
                          f"was disabled by the audit ({finding.check}) because other rules decided its traffic the same way, but "
                          "those are not in the output as they were: the rule is needed again. Enable it in the output", rule.name,
                          level=None if _blocks(rule) else Level(max(config.level("EXPOSED_BY_CONVERSION") - 1, 0)))  # fmt: skip
    result.after += extra.findings[mark:]


def effective(p: Policy, lost: Sequence[str]) -> Policy:
    """The policy as a conversion left it: without the rules it wrote disabled or left out."""
    out = copy.deepcopy(p)
    gone = set(lost)
    for rule in out.rules:
        if (rule.origin or rule.name) in gone:
            rule.enabled = False
    return out


def checks_table() -> List[Tuple[str, str, str, str, str]]:
    """(check, level, default action, possible actions, what it finds): for the help text and the manual."""
    return [(code, _LEVEL_NAMES[check.level], check.default, ", ".join(check.actions), check.title) for code, check in CHECKS.items()]


__all__ = [
    "ACCEPT", "CHECKS", "DISABLE", "OFF", "REORDER", "REPORT", "AuditConfig", "AuditResult", "Finding", "Level", "Reading", "Services",
    "apply", "checks_table", "compare", "day_of", "effective", "level_of", "load_config", "run",
]  # fmt: skip
