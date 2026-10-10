# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""iptables parser: ``iptables-save`` / ``ip6tables-save`` output -> neutral model.

How iptables behaviour is mapped onto the neutral model:

* Only forwarded traffic is policy: the ``FORWARD`` chain of the ``filter``
  table becomes the security rules. ``INPUT`` and ``OUTPUT`` filter traffic of
  the host itself and are reported, not converted.
* Interfaces (``-i``, ``-o``) are the zones.
* iptables filters packets, the model connections. A rule that accepts
  ``ESTABLISHED,RELATED`` packets is what every stateful platform does by
  itself and is left out; the remaining rules describe new connections.
* User-defined chains are flattened into the rule that jumps to them.
* An address-less rule in an IPv4 ruleset matches IPv4 only (``0.0.0.0/0``).
* ``FORWARD`` sees packets after ``PREROUTING`` destination NAT, so its rules
  name the translated address; the model wants the original one.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import shlex
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .. import transform
from ..appmap import valid_ports
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    Action,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import is_number, parse_literal, range_text
from ..report import Report, Severity

# Targets that end the journey of a packet through the filter table.
_VERDICTS = {"ACCEPT": Action.ALLOW, "DROP": Action.DROP, "REJECT": Action.DENY}
# Targets that do something to a packet and then let it continue.
_PASSIVE = {
    "LOG", "NFLOG", "ULOG", "MARK", "CONNMARK", "TCPMSS", "CLASSIFY", "AUDIT", "TRACE", "SET", "CT", "DSCP", "TOS",
    "TTL", "HL", "CHECKSUM", "SECMARK", "CONNSECMARK", "RATEEST", "TEE",
}  # fmt: skip
_PROTOCOL_NUMBERS = {
    "tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp", "sctp": "sctp", "132": "sctp", "icmp": "icmp", "1": "icmp",
    "icmpv6": "icmp6", "ipv6-icmp": "icmp6", "58": "icmp6", "all": "", "0": "", "igmp": "2", "ipip": "4",
    "ipencap": "4", "gre": "47", "esp": "50", "ah": "51", "eigrp": "88", "ospf": "89", "pim": "103", "vrrp": "112",
    "udplite": "136", "egp": "8", "dccp": "33", "ipv6": "41", "rsvp": "46", "etherip": "97", "encap": "98",
    "ipcomp": "108", "l2tp": "115", "isis": "124",
}  # fmt: skip
_ICMP_TYPES = {
    "any": (None, None), "echo-reply": (0, None), "pong": (0, None), "destination-unreachable": (3, None),
    "network-unreachable": (3, 0), "host-unreachable": (3, 1), "protocol-unreachable": (3, 2),
    "port-unreachable": (3, 3), "fragmentation-needed": (3, 4), "source-quench": (4, None), "redirect": (5, None),
    "echo-request": (8, None), "ping": (8, None), "router-advertisement": (9, None),
    "router-solicitation": (10, None), "time-exceeded": (11, None), "ttl-exceeded": (11, None),
    "parameter-problem": (12, None), "timestamp-request": (13, None), "timestamp-reply": (14, None),
    "address-mask-request": (17, None), "address-mask-reply": (18, None),
}  # fmt: skip
_ICMP6_TYPES = {
    "destination-unreachable": (1, None), "packet-too-big": (2, None), "time-exceeded": (3, None),
    "ttl-exceeded": (3, None), "parameter-problem": (4, None), "echo-request": (128, None), "ping": (128, None),
    "echo-reply": (129, None), "pong": (129, None), "router-solicitation": (133, None),
    "router-advertisement": (134, None), "neighbour-solicitation": (135, None),
    "neighbor-solicitation": (135, None), "neighbour-advertisement": (136, None),
    "neighbor-advertisement": (136, None), "redirect": (137, None),
}  # fmt: skip
# Match modules whose options are all understood below.
_KNOWN_MODULES = {"tcp", "udp", "sctp", "icmp", "icmp6", "ipv6-icmp", "multiport", "iprange", "conntrack", "state", "comment"}
_MAX_EFFECTIVE_RULES = 50000


@dataclass
class _Spec:
    """One ``-A`` line: what it matches and where it sends the packet."""

    chain: str
    number: int  # position in its chain, from 1
    in_if: str = ""
    out_if: str = ""
    src: str = ""
    src_negated: bool = False
    dst: str = ""
    dst_negated: bool = False
    proto: str = ""  # tcp, udp, sctp, icmp, icmp6, a protocol number, or "" for any
    dports: str = ""  # model syntax: 80,443,8000-8080
    sports: str = ""
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    has_icmp_type: bool = False
    states: Optional[FrozenSet[str]] = None
    comment: str = ""
    target: str = ""
    goto: bool = False
    args: Dict[str, str] = field(default_factory=dict)
    unsupported: List[str] = field(default_factory=list)
    icmp_matches: int = 0  # how many ICMP type matches the line has

    def matches_everything(self) -> bool:
        return not (
            self.in_if or self.out_if or self.src or self.dst or self.proto or self.dports or self.sports
            or self.has_icmp_type or self.states is not None or self.unsupported
        )  # fmt: skip


@dataclass
class _Table:
    policies: Dict[str, str] = field(default_factory=dict)  # chain -> ACCEPT, DROP or "-" for user chains
    rules: Dict[str, List[_Spec]] = field(default_factory=dict)


# -- reading the file ---------------------------------------------------------


def _ports(text: str) -> Optional[str]:
    """``80``, ``1000:2000``, ``:1023``, ``80,443`` -> model syntax; None if not numeric."""
    parts: List[str] = []
    for part in text.split(","):
        first, sep, last = part.partition(":")
        if sep:
            part = f"{first or '0'}-{last or '65535'}"
        parts.append(part)
    out = ",".join(parts)
    return out if valid_ports(out) else None


def _address(text: str) -> Tuple[Optional[str], bool]:
    """(canonical literal, valid). A literal of None with valid=True means "any address"."""
    interval = parse_literal(text)
    if interval is None or "-" in text:
        return None, False
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None, False
    if net.prefixlen == 0:
        return None, True
    return str(net), True


def _add_address(spec: _Spec, side: str, literal: str, negated: bool) -> None:
    """Record an address match; a second one on the same side (``-s`` next to ``--src-range``) must hold too."""
    current = getattr(spec, side)
    if current:
        merged, negated, expressible = _merge_address(current, getattr(spec, side + "_negated"), literal, negated)
        if merged is None or not expressible:
            what = "source" if side == "src" else "destination"
            spec.unsupported.append(
                f"two {what} matches that " + ("exclude each other" if merged is None else "one match cannot say")
            )
            return
        literal = merged
    setattr(spec, side, literal)
    setattr(spec, side + "_negated", negated)


def parse_rule(tokens: List[str], number: int, family: int) -> _Spec:
    """Parse the words of an ``-A CHAIN ...`` line."""
    spec = _Spec(chain=tokens[1], number=number)
    index = 2
    negate = False  # a "!" was seen and applies to the option being read
    unknown_module = False

    def take() -> str:
        nonlocal index, negate
        index += 1
        if index < len(tokens) and tokens[index] == "!":  # old style: -s ! 10.0.0.1
            negate = True
            index += 1
        return tokens[index] if index < len(tokens) else ""

    while index < len(tokens):
        option = tokens[index]
        if option == "!":
            negate = True
            index += 1
            continue
        negated, negate = negate, False
        if option in ("-j", "--jump", "-g", "--goto"):
            spec.goto = option in ("-g", "--goto")
            spec.target = take()
            index += 1
            key = ""
            while index < len(tokens):  # what follows the target are its options
                if tokens[index].startswith("--"):
                    key = tokens[index]
                    spec.args[key] = ""
                elif key:
                    spec.args[key] = (spec.args[key] + " " + tokens[index]).strip()
                else:
                    spec.unsupported.append(f"'{tokens[index]}' after the target")
                index += 1
            break
        if option in ("-i", "--in-interface", "-o", "--out-interface"):
            name = take()
            negated = negated or negate
            if negated or name.endswith("+"):
                spec.unsupported.append(f"interface match {'! ' if negated else ''}{name}")
            elif option in ("-i", "--in-interface"):
                spec.in_if = name
            else:
                spec.out_if = name
        elif option in ("-s", "--source", "--src", "-d", "--destination", "--dst"):
            text = take()
            negated = negated or negate
            literal, valid = _address(text)
            source = option in ("-s", "--source", "--src")
            if not valid:
                spec.unsupported.append(f"address '{text}' (a host name or unreadable)")
            elif literal is None:
                if negated:
                    spec.unsupported.append("negated 'any' address")
            else:
                _add_address(spec, "src" if source else "dst", literal, negated)
        elif option in ("--src-range", "--dst-range"):
            text = take()
            negated = negated or negate
            interval = parse_literal(text) if "-" in text else None
            if interval is None:
                spec.unsupported.append(f"address range '{text}'")
            else:
                _add_address(spec, "src" if option == "--src-range" else "dst", range_text(interval), negated)
        elif option in ("-p", "--protocol"):
            name = take().lower()
            negated = negated or negate
            proto = _PROTOCOL_NUMBERS.get(name, name if is_number(name) and 0 < int(name) < 256 else None)
            if negated or proto is None:
                spec.unsupported.append(f"protocol match {'! ' if negated else ''}{name}")
            else:
                spec.proto = proto
        elif option in ("-m", "--match"):
            module = take()
            unknown_module = module not in _KNOWN_MODULES
            if unknown_module:
                spec.unsupported.append(f"match module '{module}'")
        elif option in ("--dport", "--destination-port", "--dports", "--destination-ports",
                        "--sport", "--source-port", "--sports", "--source-ports"):  # fmt: skip
            text = take()
            negated = negated or negate
            ports = _ports(text)
            destination = option.startswith("--d")
            if negated or ports is None:
                spec.unsupported.append(f"port match {'! ' if negated else ''}{option} {text}")
            elif spec.dports if destination else spec.sports:
                spec.unsupported.append(f"second port match {option} {text}")
            elif destination:
                spec.dports = ports
            else:
                spec.sports = ports
        elif option in ("--ctstate", "--state"):
            text = take()
            negated = negated or negate
            states = frozenset(text.upper().split(","))
            if negated:
                spec.unsupported.append(f"negated connection state {text}")
            elif spec.states is not None and not (spec.states & states):
                spec.unsupported.append("two connection state matches that exclude each other")
            else:
                spec.states = states if spec.states is None else spec.states & states  # both have to hold
        elif option in ("--icmp-type", "--icmpv6-type"):
            text = take().lower()
            negated = negated or negate
            names = _ICMP6_TYPES if option == "--icmpv6-type" else _ICMP_TYPES
            kind, _, code = text.partition("/")
            if negated:
                spec.unsupported.append(f"negated ICMP type {text}")
            elif spec.icmp_matches:
                spec.unsupported.append(f"second ICMP type match {text}")  # both have to hold: never the last one
            elif text in names:
                spec.icmp_type, spec.icmp_code = names[text]
                spec.has_icmp_type = spec.icmp_type is not None
            elif is_number(kind) and (not code or is_number(code)) and int(kind) < 256:
                spec.icmp_type, spec.icmp_code, spec.has_icmp_type = int(kind), int(code) if code else None, True
            else:
                spec.unsupported.append(f"ICMP type '{text}'")
            spec.icmp_matches += 1
        elif option == "--comment":
            spec.comment = take()
        elif option == "--syn":
            if negated:
                spec.unsupported.append("match ! --syn")
            # A SYN-only packet opens a connection: nothing to add for a connection-based model.
        elif option == "--tcp-flags":
            mask, wanted = take(), take()
            if negated or wanted.upper() != "SYN" or "SYN" not in mask.upper().split(","):
                spec.unsupported.append(f"TCP flags match {mask} {wanted}")
        elif option.startswith("-"):
            # Unknown: never read it as "matches everything".
            if not unknown_module:  # the options of an unknown module were reported with the module
                spec.unsupported.append(f"match {'! ' if negated else ''}{option}")
            while index + 1 < len(tokens) and not tokens[index + 1].startswith("-") and tokens[index + 1] != "!":
                index += 1
        else:
            spec.unsupported.append(f"unexpected word '{option}'")
        index += 1
        negate = False
    if family == 4 and spec.proto == "icmp6":
        spec.unsupported.append("ICMPv6 in an IPv4 ruleset")
    return spec


def read_tables(text: str, family: int) -> Dict[str, _Table]:
    tables: Dict[str, _Table] = {}
    table: Optional[_Table] = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = tables.setdefault(line[1:].strip(), _Table())
            continue
        if line == "COMMIT":
            table = None
            continue
        if table is None:
            raise ParseError(f"line {number}: '{line[:40]}' outside a table; expected iptables-save output")
        if line.startswith(":"):
            words = line[1:].split()
            if words:
                table.policies[words[0]] = words[1] if len(words) > 1 else "-"
                table.rules.setdefault(words[0], [])
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as exc:
            raise ParseError(f"line {number}: {exc}") from None
        if tokens and tokens[0].startswith("["):  # packet and byte counters of iptables-save -c
            tokens = tokens[1:]
        if len(tokens) < 2 or tokens[0] not in ("-A", "--append"):
            raise ParseError(f"line {number}: only '-A CHAIN ...' rules are understood, got '{line[:40]}'")
        rules = table.rules.setdefault(tokens[1], [])
        rules.append(parse_rule(tokens, len(rules) + 1, family))
    if not tables:
        raise ParseError("no tables found; expected the output of iptables-save or ip6tables-save")
    return tables


_ADDRESS_OPTIONS = {"-s", "--source", "--src", "-d", "--destination", "--dst", "--src-range", "--dst-range",
                    "--to-destination", "--to-source", "--to"}  # fmt: skip
_V6_WORDS = {"icmpv6", "ipv6-icmp", "icmp6", "58"}


def detect_family(text: str) -> int:
    """4 or 6: what the header written by iptables-save says, else what the rules themselves use."""
    for line in text.splitlines()[:5]:
        if line.startswith("#") and "ip6tables" in line:
            return 6
        if line.startswith("#") and "iptables" in line:
            return 4
    for line in text.splitlines():
        if not line.startswith("-A"):
            continue
        try:
            words = shlex.split(line, posix=True)
        except ValueError:
            continue  # read_tables reports it
        for index, word in enumerate(words[:-1]):
            value = words[index + 1]
            if value == "!" and index + 2 < len(words):
                value = words[index + 2]
            # Only where an address or a protocol stands: a comment may hold anything.
            if words[index - 1] == "--comment":
                continue
            if word in _ADDRESS_OPTIONS and value.count(":") > 1:
                return 6
            if word in ("-p", "--protocol", "-m", "--match") and value.lower() in _V6_WORDS:
                return 6
            if word == "--icmpv6-type":
                return 6
    return 4


# -- flattening chains ----------------------------------------------------------


def _intersect_ports(a: str, b: str) -> str:
    """Ports that are in both lists, in model syntax; "" when there are none."""

    def ranges(text: str) -> List[Tuple[int, int]]:
        out = []
        for part in text.split(","):
            first, _, last = part.partition("-")
            out.append((int(first), int(last or first)))
        return out

    common = sorted({(max(x[0], y[0]), min(x[1], y[1])) for x in ranges(a) for y in ranges(b) if max(x[0], y[0]) <= min(x[1], y[1])})
    return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in common)


def _merge_address(
    outer: str, outer_negated: bool, inner: str, inner_negated: bool
) -> Tuple[Optional[str], bool, bool]:
    """Both address matches at once: (literal, negated, expressible). A literal of None matches nothing."""
    a, b = parse_literal(outer), parse_literal(inner)
    if a is None or b is None:
        return inner, inner_negated, False
    disjoint = a[0] != b[0] or a[2] < b[1] or b[2] < a[1]
    inner_in_outer = not disjoint and a[1] <= b[1] and b[2] <= a[2]
    outer_in_inner = not disjoint and b[1] <= a[1] and a[2] <= b[2]
    if not outer_negated and not inner_negated:
        if disjoint:
            return None, False, True
        if inner_in_outer:
            return inner, False, True
        if outer_in_inner:
            return outer, False, True
        return range_text((a[0], max(a[1], b[1]), min(a[2], b[2]))), False, True
    if outer_negated and inner_negated:  # neither of the two
        if inner_in_outer:
            return outer, True, True
        if outer_in_inner:
            return inner, True, True
        return inner, True, False
    plain, excluded = (inner, outer) if outer_negated else (outer, inner)
    plain_in_excluded = inner_in_outer if outer_negated else outer_in_inner
    if disjoint:
        return plain, False, True
    if plain_in_excluded:
        return None, False, True
    return plain, False, False  # a hole in the middle of a range cannot be written


def _merge(context: _Spec, spec: _Spec) -> Optional[_Spec]:
    """A rule seen through the rule that jumped to its chain; None if the two cannot both match."""
    out = dataclasses.replace(spec, unsupported=list(context.unsupported) + list(spec.unsupported), args=dict(spec.args))
    for name in ("in_if", "out_if", "proto"):
        outer, inner = getattr(context, name), getattr(spec, name)
        if outer and inner and outer != inner:
            return None
        setattr(out, name, inner or outer)
    for name in ("src", "dst"):
        outer, inner = getattr(context, name), getattr(spec, name)
        outer_negated, inner_negated = getattr(context, name + "_negated"), getattr(spec, name + "_negated")
        if not outer:
            continue
        if not inner:
            setattr(out, name, outer)
            setattr(out, name + "_negated", outer_negated)
            continue
        literal, negated, expressible = _merge_address(outer, outer_negated, inner, inner_negated)
        if literal is None:
            return None
        if not expressible:
            out.unsupported.append(f"{name} matched both by the jump and inside the chain, in a way one match cannot say")
        setattr(out, name, literal)
        setattr(out, name + "_negated", negated)
    for name in ("dports", "sports"):
        outer, inner = getattr(context, name), getattr(spec, name)
        if outer and inner:
            common = _intersect_ports(outer, inner)
            if not common:
                return None
            setattr(out, name, common)
        else:
            setattr(out, name, inner or outer)
    if context.has_icmp_type:
        if spec.has_icmp_type:
            if spec.icmp_type != context.icmp_type:
                return None
            if None not in (spec.icmp_code, context.icmp_code) and spec.icmp_code != context.icmp_code:
                return None
        # A type with a code is the narrower of the two.
        code = context.icmp_code if spec.icmp_code is None else spec.icmp_code
        out.icmp_type, out.icmp_code, out.has_icmp_type = context.icmp_type, code, True
    if context.states is not None:
        out.states = context.states if spec.states is None else context.states & spec.states
        if not out.states:
            return None
    out.comment = spec.comment or context.comment
    return out


class _Flattener:
    """Turns a built-in chain and the chains it jumps to into one ordered list of rules."""

    def __init__(self, table: _Table, builtin_targets: Set[str]) -> None:
        self.table = table
        self.builtin_targets = builtin_targets
        self.out: List[Tuple[_Spec, str]] = []  # (effective rule, where it comes from)
        self.visited = 0

    def run(self, chain: str) -> List[Tuple[_Spec, str]]:
        self._walk(chain, _Spec(chain=chain, number=0), (chain,), "")
        return self.out

    def _walk(self, chain: str, context: _Spec, stack: Tuple[str, ...], prefix: str) -> None:
        poisoned = ""
        for spec in self.table.rules.get(chain, []):
            where = f"{prefix}{chain}-{spec.number}"
            merged = _merge(context, spec)
            if merged is None:
                continue  # can never match under the rule that jumped here
            if poisoned:
                merged.unsupported.append(poisoned)
            self.visited += 1
            if self.visited > _MAX_EFFECTIVE_RULES:
                raise ParseError("the chains expand to more than 50000 rules; refusing to continue")
            target = spec.target
            if not target:
                continue  # a rule without a target only counts packets
            if target == "RETURN" and len(stack) > 1:
                if spec.matches_everything():
                    return
                poisoned = f"follows a conditional RETURN in chain {chain}, which cannot be expressed"
                continue
            user_chain = target in self.table.rules and target not in self.builtin_targets
            if user_chain and target in stack:
                merged.unsupported.append(f"jump loop through chain {target}")
            elif user_chain and not spec.goto:
                self._walk(target, merged, stack + (target,), where + ".")
                continue
            elif user_chain and spec.matches_everything():
                # An unconditional goto: the rest of this chain is never reached, and the end of the
                # other chain returns to where this chain would have returned to.
                self._walk(target, merged, stack + (target,), where + ".")
                return
            elif spec.goto:
                merged.unsupported.append(f"conditional goto {target}, which cannot be expressed")
                # Packets that take the goto never see the rest of this chain: nothing after it is certain.
                poisoned = f"follows a conditional goto in chain {chain}, which cannot be expressed"
            self.out.append((merged, where))


# -- building the model -----------------------------------------------------------


def parse(data: bytes, report: Report, family: int = 0) -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    family = family or detect_family(text)
    tables = read_tables(text, family)
    return _Builder(tables, report, family).build()


class _Builder:
    def __init__(self, tables: Dict[str, _Table], report: Report, family: int) -> None:
        self.tables, self.report, self.family = tables, report, family
        self.any_literal = ANY_V4 if family == 4 else ANY_V6
        self.p = Policy(vendor="iptables", scope=f"IPv{family}", lookup_after_dnat=True)
        self.names: Set[str] = set()
        self.nat_names: Set[str] = set()

    def build(self) -> Policy:
        filter_table = self.tables.get("filter", _Table())
        policy = filter_table.policies.get("FORWARD", "ACCEPT")
        default = Action.ALLOW if policy == "ACCEPT" else Action.DENY
        self.p.default_interzone = self.p.default_intrazone = default
        self._forward(filter_table)
        self._nat(self.tables.get("nat", _Table()))
        for interface in transform.dedupe(
            [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        ):
            self.p.zones[interface] = Zone(interface, [interface])
        # FORWARD sees the translated destination; the model matches the original one.
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes(filter_table)
        return self.p

    def _notes(self, filter_table: _Table) -> None:
        for chain in ("INPUT", "OUTPUT"):
            rules, policy = len(filter_table.rules.get(chain, [])), filter_table.policies.get(chain, "ACCEPT")
            if rules or policy != "ACCEPT":
                self.report.note(
                    Severity.REVIEW,
                    "HOST_CHAIN_NOT_CONVERTED",
                    f"chain {chain} ({rules} rules, policy {policy}) filters traffic of the host itself, not "
                    "forwarded traffic, and is not converted",
                )
        for name in ("mangle", "raw", "security"):
            count = sum(len(rules) for rules in self.tables.get(name, _Table()).rules.values())
            if count:
                self.report.note(
                    Severity.REVIEW, "TABLE_NOT_CONVERTED", f"table '{name}' has {count} rules and is not converted"
                )
        if self.p.default_interzone == Action.ALLOW:
            self.report.note(
                Severity.INFO,
                "FORWARD_POLICY_ACCEPT",
                "the FORWARD chain accepts what no rule matches; the model records that as its default action",
            )

    def _unique(self, name: str, taken: Set[str]) -> str:
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    # -- filter / FORWARD -------------------------------------------------

    def _forward(self, table: _Table) -> None:
        effective = _Flattener(table, {"INPUT", "FORWARD", "OUTPUT"}).run("FORWARD")
        accepts_established = False
        early_drops: List[str] = []  # deny rules ahead of the rule that accepts established connections
        passive: Dict[str, int] = {}
        logged: Optional[Tuple[object, ...]] = None
        accepts = 0
        for spec, where in effective:
            target = "ACCEPT" if spec.target == "RETURN" and self._policy(table) == "ACCEPT" else spec.target
            target = "DROP" if target == "RETURN" else target
            key = self._match_key(spec)
            if target in _PASSIVE:
                passive[target] = passive.get(target, 0) + 1
                logged = key if target in ("LOG", "NFLOG", "ULOG") else None
                continue
            log, logged = logged == key, None
            states = spec.states
            if states is not None and "NEW" not in states and not spec.unsupported:
                if target == "ACCEPT" and states <= {"ESTABLISHED", "RELATED"}:
                    # Replies and related packets: implicit on a connection-tracking platform.
                    accepts_established = True
                    continue
                if target in ("DROP", "REJECT") and states <= {"INVALID", "UNTRACKED"}:
                    continue  # likewise built in
            rule = self._rule(spec, where, target)
            rule.log_start = log
            if states is not None and "NEW" not in states:
                rule.unsupported.append("match on connection state " + ",".join(sorted(states)) + " without NEW")
            if rule.action == Action.ALLOW:
                accepts += 1
            elif not accepts_established and (states is None or states & {"ESTABLISHED", "RELATED"}):
                early_drops.append(rule.origin)
            self.p.rules.append(rule)
        for target, count in sorted(passive.items()):
            self.report.note(
                Severity.INFO,
                "PASSIVE_TARGETS",
                f"{count} FORWARD rule{'s' if count != 1 else ''} with target {target} decide{'' if count != 1 else 's'} "
                "nothing and " + ("were" if count != 1 else "was") + " left out"
                + ("; a LOG rule directly before a rule with the same match sets its logging" if target == "LOG" else ""),
            )
        if not accepts_established and accepts:
            self.report.note(
                Severity.REVIEW,
                "STATELESS_RULESET",
                "no FORWARD rule accepts ESTABLISHED,RELATED packets, so the source filters every packet on its "
                "own. The converted rules are connection-based: an allow rule also admits the replies, and a deny "
                "rule no longer stops the replies of connections opened from the other side",
            )
        elif accepts_established:
            for origin in early_drops:
                self.report.add(
                    "rule",
                    origin,
                    Severity.REVIEW,
                    "DROP_BEFORE_ESTABLISHED",
                    "this rule comes before the rule that accepts established connections, so on the source it "
                    "also drops the replies of connections opened from the other side. The converted rule only "
                    "blocks new connections in its own direction; add the mirror rule if that mattered",
                )

    @staticmethod
    def _policy(table: _Table) -> str:
        return table.policies.get("FORWARD", "ACCEPT")

    @staticmethod
    def _match_key(spec: _Spec) -> Tuple[object, ...]:
        return (
            spec.in_if, spec.out_if, spec.src, spec.src_negated, spec.dst, spec.dst_negated, spec.proto, spec.dports,
            spec.sports, spec.icmp_type, spec.icmp_code, spec.states, tuple(spec.unsupported),
        )  # fmt: skip

    def _rule(self, spec: _Spec, where: str, target: str) -> Rule:
        rule = Rule(name=self._unique(spec.comment or where, self.names))
        rule.origin = rule.name
        rule.description = "" if spec.comment == rule.name else f"iptables rule {where}"
        rule.src_zones = [spec.in_if or ANY]
        rule.dst_zones = [spec.out_if or ANY]
        rule.unsupported = list(spec.unsupported)
        rule.log_end = False
        self._addresses(rule, spec)
        service = self._service(spec, rule.unsupported)
        rule.services = [service] if service else [ANY]
        if target in _VERDICTS:
            rule.action = _VERDICTS[target]
            reject = spec.args.get("--reject-with", "")
            if target == "REJECT" and reject == "tcp-reset":
                rule.action = Action.RESET_CLIENT
            extra = [k for k in spec.args if k != "--reject-with"]
            if extra:
                rule.unsupported.append("target option " + " ".join(extra))
        else:
            rule.action = Action.DROP  # what the source did is not known: nothing is allowed on a guess
            if not any("goto " in text or "jump loop" in text for text in rule.unsupported):
                rule.unsupported.append(f"target {target}, which is neither a known target nor a chain of this table")
        return rule

    def _addresses(self, rule: Rule, spec: _Spec) -> None:
        """Sources and destinations; a side without a match is "any" of this ruleset's IP version only."""
        rule.sources = [spec.src or self.any_literal]
        rule.destinations = [spec.dst or self.any_literal]
        rule.negate_source, rule.negate_destination = spec.src_negated, spec.dst_negated
        if rule.negate_source and rule.negate_destination:
            # Negation covers both IP versions in the model: nothing would keep this to one version.
            rule.unsupported.append("source and destination both negated")
        # Plain "any" is enough where the other side keeps the rule to this IP version.
        if not spec.src and not spec.dst:
            rule.destinations = [ANY]
        elif not spec.src and not spec.dst_negated:
            rule.sources = [ANY]
        elif not spec.dst and not spec.src_negated:
            rule.destinations = [ANY]

    def _service(self, spec: _Spec, problems: List[str]) -> str:
        """Name of the service object standing for the protocol and ports of a rule; "" for any."""
        proto = spec.proto
        if not proto:
            if spec.dports or spec.sports or spec.has_icmp_type:
                problems.append("port or ICMP type match without a protocol")
            return ""
        if proto in ("tcp", "udp", "sctp"):
            name = f"{proto}-{spec.dports or 'any'}" + (f"-from-{spec.sports}" if spec.sports else "")
            entry = ServiceEntry(Protocol(proto), spec.dports, spec.sports)
        elif proto in ("icmp", "icmp6"):
            if spec.dports or spec.sports:
                problems.append("port match on ICMP")
            kind = "any" if spec.icmp_type is None else str(spec.icmp_type)
            name = f"{proto}-{kind}" + (f"-{spec.icmp_code}" if spec.icmp_code is not None else "")
            entry = ServiceEntry(Protocol.ICMP if proto == "icmp" else Protocol.ICMP6, icmp_type=spec.icmp_type,
                                 icmp_code=spec.icmp_code)  # fmt: skip
        else:
            if spec.dports or spec.sports:
                problems.append(f"port match on protocol {proto}")
            name, entry = f"ip-{proto}", ServiceEntry(Protocol.IP, ip_protocol=int(proto))
        if name not in self.p.services:
            self.p.services[name] = Service(name, [entry])
        return name

    # -- nat ----------------------------------------------------------------

    def _nat(self, table: _Table) -> None:
        builtin = {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"}
        destination: List[NatRule] = []
        source: List[NatRule] = []
        for chain, out in (("PREROUTING", destination), ("POSTROUTING", source)):
            for spec, where in _Flattener(table, builtin).run(chain):
                nat = self._nat_rule(spec, where, chain)
                if nat is not None:
                    out.append(nat)
        output = len(table.rules.get("OUTPUT", []))
        if output:
            self.report.note(
                Severity.REVIEW,
                "HOST_CHAIN_NOT_CONVERTED",
                f"nat chain OUTPUT ({output} rules) translates traffic of the host itself and is not converted",
            )
        # Destination translations first; a target with one first-match NAT rulebase says what that costs.
        self.p.nat_rules = destination + source

    def _nat_rule(self, spec: _Spec, where: str, chain: str) -> Optional[NatRule]:
        target = spec.target
        if target in _PASSIVE:
            return None
        nat = NatRule(name=self._unique(spec.comment or where, self.nat_names))
        nat.origin = nat.name
        nat.combines = True  # one PREROUTING rule and one POSTROUTING rule apply to a connection
        nat.description = "" if spec.comment == nat.name else f"iptables nat rule {where}"
        nat.unsupported = list(spec.unsupported)
        nat.sources = [spec.src or ANY]
        nat.destinations = [spec.dst or ANY]
        if spec.src_negated or spec.dst_negated:
            nat.unsupported.append("negated address in a NAT rule")
        service = self._service(spec, nat.unsupported)
        nat.service = service or ANY
        if service and self.p.services[service].entries[0].protocol not in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
            nat.unsupported.append(f"NAT limited to protocol {spec.proto}")
        if self.family == 6:
            nat.unsupported.append("IPv6 NAT")
        known = {"--to-destination", "--to-source", "--to", "--random", "--random-fully", "--persistent", "--to-ports"}
        extra = [k for k in spec.args if k not in known]
        if extra:
            nat.unsupported.append("target option " + " ".join(extra))
        if chain == "PREROUTING":
            # The translation applies to what arrives on the interface; that is also where the address lives.
            nat.src_zones = nat.dst_zones = [spec.in_if or ANY]
            if spec.out_if:
                nat.unsupported.append("output interface in PREROUTING")
            if target == "DNAT":
                address, port = self._translation(spec.args.get("--to-destination") or spec.args.get("--to", ""))
                if address is None:
                    nat.unsupported.append("DNAT target that could not be read")
                else:
                    nat.destination_translation = DestNat(address, port)
            elif target in ("ACCEPT", "RETURN"):
                # It ends PREROUTING only: POSTROUTING still translates the source. A rule without
                # translation in a NAT rulebase would stop both, and no target can say "this half only".
                nat.unsupported.append(
                    "exception from destination NAT only (PREROUTING ACCEPT); the destination NAT rules below it "
                    "are converted without this exception"
                )
            else:
                nat.unsupported.append(f"target {target} in PREROUTING")
        else:
            nat.dst_zones = [spec.out_if or ANY]
            if spec.in_if:
                nat.unsupported.append("input interface in POSTROUTING")
            if target == "MASQUERADE":
                nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=spec.out_if)
            elif target == "SNAT":
                address, port = self._translation(spec.args.get("--to-source") or spec.args.get("--to", ""))
                if address is None:
                    nat.unsupported.append("SNAT target that could not be read")
                else:
                    nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [address])
            elif target not in ("ACCEPT", "RETURN"):
                nat.unsupported.append(f"target {target} in POSTROUTING")
        return nat

    @staticmethod
    def _translation(text: str) -> Tuple[Optional[str], str]:
        """``10.0.0.1``, ``10.0.0.1-10.0.0.9`` or either with ``:port`` -> (address literal, port)."""
        address, _, port = text.partition(":")
        interval = parse_literal(address)
        if interval is None or interval[0] != 4 or "/" in address:
            return None, ""
        if port and not valid_ports(port):
            return None, ""
        return range_text(interval), port
