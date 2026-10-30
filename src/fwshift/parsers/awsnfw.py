# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS Network Firewall parser: the JSON of the AWS CLI for one firewall policy -> neutral model.

What is read: the answer of ``aws network-firewall describe-firewall-policy`` (required), the answers of
``describe-rule-group`` for the rule groups it names, and optionally ``aws ec2 describe-vpcs`` for the inspection VPC
(its CIDR blocks are ``HOME_NET`` when the policy does not set it) and ``get-managed-prefix-list-entries`` (wrapped as
``{"PrefixListId": ..., "Entries": [...]}``) for the prefix lists that IP set references name. The answers may be one
JSON array, an object with a ``RuleGroups`` list next to them, or simply one after the other in one file, as the CLI
prints them. Each answer is told by its top-level key.

How the firewall decides, and how that is mapped onto the neutral model (from the developer guide and the API
reference; not checked on a firewall):

* There are no zones: the firewall sits in a route path and sees addresses. The model has none either; a target with
  zones needs ``--zone-network``-style networks, as for AWS security groups.
* Every packet meets the stateless rules first: the rule groups by their priority in the policy, the rules of a group by
  their priority, first match; what none matches gets the policy's default action for full packets (UDP fragments have
  one of their own, other fragments are dropped). Actions are pass, drop and forward to the stateful engine; custom
  actions only publish metrics. Stateless rules see packets, not connections: the model's connection passes when its
  first packet and its reply both pass. So the replies are worked out as well (sets of connections, as for network ACLs):
  connections whose replies a stateless rule drops are blocked at the top; a pass rule allows what it matches where the
  replies pass too; a rule that forwards takes its traffic out of the stateless rules below it. Where one direction is
  passed and the other forwarded, the stateful engine sees half a flow: said, and left to the stateful rules.
* Then the stateful engine, for what was forwarded. With ``DEFAULT_ACTION_ORDER`` (the default) every pass rule comes
  before every drop rule, then reject, then alert, and what no rule matches passes. With ``STRICT_ORDER`` the groups go
  by priority and the rules in the order written, and the default actions decide the rest: ``aws:drop_strict`` drops
  what no rule passed on its first packet; ``aws:drop_established`` (and the application-layer variants) lets the TCP
  handshake through, drops what no rule passed once a connection is established, and drops other protocols at once.
  Alert rules and alert defaults decide nothing and are left out.
* A Suricata rule matches packets in the direction of its header: a rule without ``flow:to_server`` also matches the
  replies of connections that were opened the other way, and a pass or drop on the first reply decides the whole flow.
  The rules are therefore read for each moment a flow can be decided: the first packet (the rules as written), the
  first reply (the rules mirrored: their sources and destinations, and ports, exchanged), and for TCP the first
  established packet in either direction (rules with ``flow:established``, and rules of an application protocol, which
  is identified only once data flows). A default action ends this where it decides. That is exact for what is read,
  and it is why a pass rule from ``$HOME_NET`` without ``flow:to_server`` lets connections in under
  ``aws:drop_established``.
* Rules of an application protocol (``tls``, ``http``, ``dns`` ...) become the model's applications (App-ID names).
  ``<>`` and the 5-tuple direction ``ANY`` are both directions. ``icmp`` is ICMP of both IP versions.
* Variables: ``HOME_NET`` is the policy's, or the inspection VPC's CIDR blocks; ``EXTERNAL_NET`` is the negation of the
  policy's ``HOME_NET`` unless the rule group sets it (a group's own ``HOME_NET`` does not change it). IP set
  variables and port variables are the group's; IP set references (``@NAME``) are prefix lists, read from their
  entries when given. Unknown members are never read as any.
* Domain lists match TLS SNI and HTTP host names: an allow list is an allow rule for the names (not converted: names
  are not addresses) followed by a rule that drops the rest of that protocol, which is converted.
* Keywords that look into the payload or narrow the match otherwise (``content``, ``tls.sni``, ``flowbits``,
  ``threshold``, ``geoip``, TCP flags ...) make a rule not converted; ``msg``, ``sid``, ``rev``, ``priority`` and the like
  change nothing. A commented-out rule (``# drop ...``) is a disabled rule.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import ANY, APP_DEFAULT, Action, AddressGroup, Policy, Protocol, Rule, Service, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity

VENDOR = "aws-network-firewall"
_EVERYTHING: List[Interval] = [FULL_V4, FULL_V6]
_STANDARD = {"aws:pass": "pass", "aws:drop": "drop", "aws:forward_to_sfe": "forward"}
_DROP_DEFAULTS = ("aws:drop_strict", "aws:drop_established", "aws:drop_established_app_layer", "aws:drop_established_app_layer_to_server")
_ALERT_DEFAULTS = ("aws:alert_strict", "aws:alert_established", "aws:alert_established_app_layer", "aws:alert_established_app_layer_to_server")
_ACTIONS = {"pass": 0, "drop": 1, "reject": 2, "alert": 3}
# Application protocols of Suricata: the App-ID name and the transports it runs on.
_APPS: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "http": ("web-browsing", ("tcp",)), "http1": ("web-browsing", ("tcp",)), "http2": ("http2", ("tcp",)),
    "tls": ("ssl", ("tcp",)), "ssh": ("ssh", ("tcp",)), "smtp": ("smtp", ("tcp",)), "imap": ("imap", ("tcp",)),
    "pop3": ("pop3", ("tcp",)), "ftp": ("ftp", ("tcp",)), "smb": ("ms-ds-smb", ("tcp",)), "msn": ("msn", ("tcp",)),
    "rdp": ("ms-rdp", ("tcp",)), "mqtt": ("mqtt", ("tcp",)), "modbus": ("modbus", ("tcp",)), "dnp3": ("dnp3", ("tcp",)),
    "telnet": ("telnet", ("tcp",)), "pgsql": ("postgres", ("tcp",)), "rfb": ("vnc", ("tcp",)),
    "dns": ("dns", ("udp", "tcp")), "krb5": ("kerberos", ("udp", "tcp")), "dcerpc": ("msrpc", ("udp", "tcp")),
    "sip": ("sip", ("udp", "tcp")), "nfs": ("nfs", ("udp", "tcp")), "ldap": ("ldap", ("udp", "tcp")),
    "ntp": ("ntp", ("udp",)), "tftp": ("tftp", ("udp",)), "dhcp": ("dhcp", ("udp",)), "snmp": ("snmp", ("udp",)),
    "quic": ("quic", ("udp",)),
}  # fmt: skip
# Not supported by Network Firewall (its list of Suricata limitations).
_REFUSED_PROTOCOLS = {"sctp", "ikev2", "ftp-data", "enip", "cip"}
# Options that change nothing about what a rule matches.
_NEUTRAL = {"msg", "sid", "rev", "gid", "classtype", "reference", "metadata", "priority", "noalert", "target"}
# ICMP requests and their replies (the reply of a connection of one of these types).
_REPLY_TYPE = {1: {8: 0, 13: 14, 15: 16, 17: 18}, 58: {128: 129}}
_MAX_PIECES = 4096
_ALL_PORTS = [(0, 65535)]

# The moments at which the stateful engine can decide a flow.
_FIRST, _REPLY, _ESTABLISHED, _ESTABLISHED_REPLY = 1, 2, 3, 4


class _Bad(Exception):
    """Something of a rule that cannot be read: the rule is not converted."""


class _Nothing(_Bad):
    """A rule that matches no packet: it decides nothing."""


def looks_like_awsnfw(data: bytes) -> bool:
    """The JSON of describe-firewall-policy (with the answers of describe-rule-group next to it, or not)."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    return b'"FirewallPolicy"' in head and (b'"FirewallPolicyResponse"' in head or b'"StatelessDefaultActions"' in head)


# -- reading the documents --------------------------------------------------------------------------------------------


def _documents(data: bytes) -> List[Any]:
    """One JSON value, or several one after the other (the answers of several CLI calls in one file)."""
    text = data.decode("utf-8-sig", errors="replace")
    decoder = json.JSONDecoder()
    out: List[Any] = []
    position = 0
    while True:
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        if position >= len(text):
            break
        try:
            value, position = decoder.raw_decode(text, position)
        except ValueError as error:
            raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
        out.append(value)
        if len(out) > 10000:
            raise ParseError("more than 10000 JSON documents in one file")
    if not out:
        raise ParseError("the input is empty")
    return out


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _number(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


@dataclass
class _Found:
    policies: List[Dict[str, Any]] = field(default_factory=list)  # answers of describe-firewall-policy
    groups: List[Dict[str, Any]] = field(default_factory=list)  # answers of describe-rule-group
    vpcs: List[Dict[str, Any]] = field(default_factory=list)
    prefix_entries: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    prefix_names: Dict[str, str] = field(default_factory=dict)


def _collect(value: Any, found: _Found, depth: int = 0) -> None:
    if depth > 4:
        return
    if isinstance(value, list):
        for item in value:
            _collect(item, found, depth + 1)
        return
    if not isinstance(value, dict):
        return
    body = value.get("FirewallPolicy")
    if isinstance(body, dict):
        if "FirewallPolicy" in body and isinstance(body["FirewallPolicy"], dict):
            _collect(body, found, depth + 1)  # (an object that holds the answer under the key)
        else:
            found.policies.append(value)
    if isinstance(value.get("RuleGroup"), dict) or isinstance(value.get("RuleGroupResponse"), dict):
        found.groups.append(value)
    for key in ("RuleGroups", "Answers"):
        if isinstance(value.get(key), list):
            _collect(value[key], found, depth + 1)
    found.vpcs += _dicts(value.get("Vpcs"))
    if "Entries" in value and value.get("PrefixListId"):
        found.prefix_entries.setdefault(str(value["PrefixListId"]), []).extend(_dicts(value.get("Entries")))
    for item in _dicts(value.get("PrefixLists")):
        if item.get("PrefixListId"):
            found.prefix_names[str(item["PrefixListId"])] = str(item.get("PrefixListName") or "")


def parse(data: bytes, report: Report, policy: str = "") -> Policy:
    try:
        found = _Found()
        for document in _documents(data):
            _collect(document, found)
        if not found.policies:
            raise ParseError("no firewall policy found; expected the answer of 'aws network-firewall describe-firewall-policy --output "
                             "json', with the answers of describe-rule-group for its rule groups")  # fmt: skip
        chosen = found.policies
        if policy:
            chosen = [answer for answer in found.policies if _policy_name(answer) == policy]
            if not chosen:
                held = ", ".join(sorted({_policy_name(a) or "?" for a in found.policies}))
                raise ParseError(f"no firewall policy named '{policy[:80]}' in the input (it holds {held})")
        names = {_policy_name(a) for a in chosen}
        if len(chosen) > 1 and len(names) > 1:
            raise ParseError("the input holds several firewall policies (" + ", ".join(sorted(n or "?" for n in names))
                             + "): choose one with --policy")  # fmt: skip
        return _Builder(chosen[0], found, report).build()
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        if isinstance(error, ParseError):
            raise
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


def _policy_name(answer: Dict[str, Any]) -> str:
    response = answer.get("FirewallPolicyResponse")
    return str(response.get("FirewallPolicyName") or "") if isinstance(response, dict) else ""


# -- Suricata expressions -----------------------------------------------------------------------------------------------


@dataclass
class _Node:
    kind: str  # any, lit, var, ref, not, list (addresses); any, range, var, not, list (ports)
    value: Any = None
    items: List["_Node"] = field(default_factory=list)


def _split_top(text: str) -> List[str]:
    """Split at commas outside brackets."""
    out, depth, current = [], 0, ""
    for char in text:
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth < 0:
                raise _Bad(f"']' without '[' in '{text[:80]}'")
        if char == "," and depth == 0:
            out.append(current)
            current = ""
        else:
            current += char
    if depth:
        raise _Bad(f"'[' without ']' in '{text[:80]}'")
    out.append(current)
    return [part.strip() for part in out]


def _address_node(text: str, depth: int = 0) -> _Node:
    text = text.strip()
    if depth > 20:
        raise _Bad("addresses nested too deeply")
    if not text:
        raise _Bad("an empty address")
    if text.lower() == "any":
        return _Node("any")
    if text.startswith("!"):
        return _Node("not", items=[_address_node(text[1:], depth + 1)])
    if text.startswith("[") and text.endswith("]"):
        parts = _split_top(text[1:-1])
        if not parts or any(not part for part in parts):
            raise _Bad(f"an empty member in '{text[:80]}'")
        return _Node("list", items=[_address_node(part, depth + 1) for part in parts])
    if text.startswith("$") and re.fullmatch(r"\$[A-Za-z][A-Za-z0-9_]*", text):
        return _Node("var", text[1:])
    if text.startswith("@") and re.fullmatch(r"@[A-Za-z][A-Za-z0-9_]*", text):
        return _Node("ref", text[1:])
    interval = parse_literal(text)
    if interval is None or "-" in text:
        raise _Bad(f"'{text[:60]}' is not an address")
    return _Node("lit", interval)


def _port_node(text: str, depth: int = 0) -> _Node:
    text = text.strip()
    if depth > 20:
        raise _Bad("ports nested too deeply")
    if not text:
        raise _Bad("an empty port")
    if text.lower() == "any":
        return _Node("any")
    if text.startswith("!"):
        return _Node("not", items=[_port_node(text[1:], depth + 1)])
    if text.startswith("[") and text.endswith("]"):
        parts = _split_top(text[1:-1])
        if not parts or any(not part for part in parts):
            raise _Bad(f"an empty member in '{text[:80]}'")
        return _Node("list", items=[_port_node(part, depth + 1) for part in parts])
    if text.startswith("$") and re.fullmatch(r"\$[A-Za-z][A-Za-z0-9_]*", text):
        return _Node("var", text[1:])
    found = re.fullmatch(r"(\d{0,5})(:?)(\d{0,5})", text)
    if not found or (not found.group(1) and not found.group(3)) or (not found.group(2) and found.group(3)):
        raise _Bad(f"'{text[:60]}' is not a port")
    low = int(found.group(1)) if found.group(1) else 0
    high = int(found.group(3)) if found.group(3) else (65535 if found.group(2) else low)
    if not 0 <= low <= high <= 65535:
        raise _Bad(f"'{text[:60]}' is not a port range")
    return _Node("range", (low, high))


def _ports_minus(a: List[Tuple[int, int]], b: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for low, high in a:
        pieces = [(low, high)]
        for cut_low, cut_high in b:
            pieces = [p for piece in pieces for p in ((piece[0], min(piece[1], cut_low - 1)), (max(piece[0], cut_high + 1), piece[1]))
                      if p[0] <= p[1]]  # fmt: skip
        out += pieces
    return regions.merge_ranges(out)


def _port_text(ranges: List[Tuple[int, int]]) -> str:
    if ranges == _ALL_PORTS:
        return ""
    return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in ranges)


def _options(text: str) -> List[Tuple[str, str]]:
    """``key:value; key; key:"quoted; text";`` -> [(key, value)]."""
    out: List[Tuple[str, str]] = []
    current, quoted, escaped = "", False, False
    for char in text:
        if escaped:
            current += char
            escaped = False
        elif char == "\\":
            current += char
            escaped = True
        elif char == '"':
            current += char
            quoted = not quoted
        elif char == ";" and not quoted:
            if current.strip():
                key, _, value = current.strip().partition(":")
                out.append((key.strip().lower(), value.strip()))
            current = ""
        else:
            current += char
    if quoted:
        raise _Bad("a quote that is not closed in the options")
    if current.strip():
        key, _, value = current.strip().partition(":")
        out.append((key.strip().lower(), value.strip()))
    return out


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return re.sub(r"\\(.)", r"\1", value)


@dataclass
class _Parsed:
    """One stateful rule, as written."""

    group: "_Group"
    index: int
    text: str
    action: str = ""
    protocol: str = ""
    src: str = ""
    sport: str = ""
    both: bool = False
    dst: str = ""
    dport: str = ""
    options: List[Tuple[str, str]] = field(default_factory=list)
    disabled: bool = False
    problem: str = ""  # cannot be read at all

    def option(self, key: str) -> Optional[str]:
        for name, value in self.options:
            if name == key:
                return value
        return None

    @property
    def sid(self) -> str:
        value = self.option("sid")
        return value.strip() if value is not None else ""

    @property
    def message(self) -> str:
        value = self.option("msg")
        return _unquote(value) if value is not None else ""


def _header_tokens(text: str) -> Tuple[List[str], str]:
    """The seven words of the header (brackets kept together) and the options text."""
    opening = text.find("(")
    if opening < 0 or not text.rstrip().endswith(")"):
        raise _Bad("no options in parentheses")
    head, options = text[:opening], text[opening + 1:text.rstrip().rfind(")")]
    tokens: List[str] = []
    current, depth = "", 0
    for char in head:
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        if char.isspace() and depth == 0:
            if current:
                tokens.append(current)
                current = ""
        else:
            current += char
    if current:
        tokens.append(current)
    if len(tokens) != 7:
        raise _Bad(f"the header has {len(tokens)} words, not 7 (action protocol source port direction destination port)")
    return tokens, options


def _parse_rule(group: "_Group", index: int, text: str, disabled: bool = False) -> _Parsed:
    rule = _Parsed(group, index, text.strip(), disabled=disabled)
    opening, closing = rule.text.find("("), rule.text.rfind(")")
    if 0 <= opening < closing:
        try:  # (a rule whose header cannot be read keeps its sid and message)
            rule.options = _options(rule.text[opening + 1:closing])
        except _Bad:
            pass
    try:
        tokens, options = _header_tokens(rule.text)
        rule.action = tokens[0].lower()
        rule.protocol = tokens[1].lower()
        rule.src, rule.sport, direction, rule.dst, rule.dport = tokens[2], tokens[3], tokens[4], tokens[5], tokens[6]
        if direction not in ("->", "<>"):
            raise _Bad(f"direction '{direction[:10]}' (Suricata knows -> and <>)")
        rule.both = direction == "<>"
        rule.options = _options(options)
    except _Bad as error:
        rule.problem = str(error)
    return rule


def _rules_of_string(group: "_Group", text: str) -> List[_Parsed]:
    out: List[_Parsed] = []
    lines: List[str] = []
    pending = ""
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            # A rule that is commented out is a disabled rule; any other comment is a comment.
            inner = stripped.lstrip("#").strip()
            candidate = _parse_rule(group, len(out) + 1, inner, True)
            if not candidate.problem and candidate.action in _ACTIONS:
                out.append(candidate)
            continue
        out.append(_parse_rule(group, len(out) + 1, stripped))
    return out


# -- the rule groups ----------------------------------------------------------------------------------------------------


@dataclass
class _Group:
    arn: str
    name: str
    kind: str  # stateless, stateful, domain, missing
    body: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    override: str = ""
    order: str = ""


def _name_of_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn


# -- the builder --------------------------------------------------------------------------------------------------------


@dataclass
class _Reading:
    """A rule of the stateful engine, read at one moment of a flow. Its name is given, and its findings recorded, when it is
    written: a reading that can never decide is not in the model."""

    moment: int
    rule: Rule
    transports: Tuple[str, ...] = ()  # what it can match: "tcp", "other"
    key: str = ""
    # A rule with a flow keyword but neither established nor not_established matches the established packets of a TCP
    # connection as well (what decides them where every packet is decided on its own: aws:drop_strict). A rule without
    # any flow keyword is evaluated on the first packet of each direction only, as Suricata does with such rules.
    any_state: bool = False
    # A rule of both directions (<>) without a flow direction: its readings for the first packet, of both orientations,
    # are also what the replies match (the reader leaves its reply readings out as the same).
    both_ways: bool = False
    findings: List[Tuple[Severity, str, str]] = field(default_factory=list)


@dataclass
class _Stateless:
    name: str
    group: str
    priority: int
    action: str  # pass, drop, forward
    boxes: Optional[List[regions.Box]]
    problems: List[str] = field(default_factory=list)
    description: str = ""
    # Sources, destinations and services, for a rule that is not worked out.
    members: Tuple[List[str], List[str], List[str]] = field(default_factory=lambda: ([ANY], [ANY], [ANY]))


class _Builder:
    def __init__(self, answer: Dict[str, Any], found: _Found, report: Report) -> None:
        self.answer, self.found, self.report = answer, found, report
        body = answer.get("FirewallPolicy")
        self.body: Dict[str, Any] = body if isinstance(body, dict) else {}
        self.p = Policy(vendor=VENDOR)
        self.p.scope = _policy_name(answer)
        self.rule_names: Set[str] = set()
        self.taken: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.service_keys: Dict[str, str] = {}
        self.variables: Dict[Tuple[str, Tuple[Interval, ...]], str] = {}
        self.home: Optional[List[Interval]] = None
        self.home_from = ""
        self.home_group = ""
        self.groups: Dict[str, _Group] = {}
        self.references: Dict[str, str] = {}  # ARN of an IP set reference -> address group
        self.reachable = True  # the stateful engine gets traffic
        self.alerts = 0
        self.order = "DEFAULT_ACTION_ORDER"

    # -- names ----------------------------------------------------------------------------

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _object_name(self, label: str) -> str:
        if label.lower() in (ANY, APP_DEFAULT) or parse_literal(label) is not None:
            return self._unique(f"{label}-object", self.taken)
        return self._unique(label, self.taken)

    def _new_rule(self, base: str, **values: Any) -> Rule:
        rule = Rule(self._unique(base, self.rule_names), **values)
        rule.origin = rule.name
        rule.log_end = False
        return rule

    # -- the whole ------------------------------------------------------------------------

    def build(self) -> Policy:
        self._index_groups()
        self._home_net()
        self._stateless()
        self._stateful()
        self._notes()
        # Objects of readings that never decide anything (and so are not in the model) are left out.
        used = {m for r in self.p.rules for m in r.sources + r.destinations + r.services}
        self.p.services = {k: v for k, v in self.p.services.items() if k in used}
        self.p.address_groups = {k: v for k, v in self.p.address_groups.items() if k in used}
        return self.p

    def _index_groups(self) -> None:
        by_arn: Dict[str, Dict[str, Any]] = {}
        by_name: Dict[str, Dict[str, Any]] = {}
        for given in self.found.groups:
            response = _dict(given.get("RuleGroupResponse"))
            arn = str(response.get("RuleGroupArn") or "")
            name = str(response.get("RuleGroupName") or _name_of_arn(arn))
            if arn:
                by_arn.setdefault(arn, given)
            if name:
                by_name.setdefault(name, given)
        for key, stateful in (("StatelessRuleGroupReferences", False), ("StatefulRuleGroupReferences", True)):
            for reference in _dicts(self.body.get(key)):
                arn = str(reference.get("ResourceArn") or "")
                answer: Optional[Dict[str, Any]] = by_arn.get(arn) or by_name.get(_name_of_arn(arn))
                name = _name_of_arn(arn) or "unnamed-group"
                group = _Group(arn, name, "missing", priority=_number(reference.get("Priority"), 0))
                override = reference.get("Override")
                if isinstance(override, dict):
                    group.override = str(override.get("Action") or "")
                if answer is not None:
                    response = _dict(answer.get("RuleGroupResponse"))
                    group.name = str(response.get("RuleGroupName") or name)
                    body = _dict(answer.get("RuleGroup"))
                    group.body = body
                    source = _dict(body.get("RulesSource"))
                    if isinstance(source.get("StatelessRulesAndCustomActions"), dict):
                        group.kind = "stateless"
                    elif isinstance(source.get("RulesSourceList"), dict):
                        group.kind = "domain"
                    elif source.get("RulesString") is not None or source.get("StatefulRules") is not None:
                        group.kind = "stateful"
                    else:
                        group.kind = "unreadable"
                    options = body.get("StatefulRuleOptions")
                    if isinstance(options, dict):
                        group.order = str(options.get("RuleOrder") or "")
                    if (group.kind == "stateless") == stateful and group.kind in ("stateless", "stateful", "domain"):
                        self.report.note(Severity.REVIEW, "AWSNFW_GROUP_TYPE",
                                         f"rule group {group.name} is {'stateless' if group.kind == 'stateless' else 'stateful'} but the "
                                         f"policy names it among its {'stateful' if stateful else 'stateless'} groups; AWS refuses such a "
                                         "policy. Its rules are not converted")  # fmt: skip
                key_name = ("stateful:" if stateful else "stateless:") + arn + f"#{len(self.groups)}"
                self.groups[key_name] = group

    def _ordered(self, stateful: bool) -> List[_Group]:
        wanted = "stateful:" if stateful else "stateless:"
        found = [(g.priority, index, g) for index, (key, g) in enumerate(self.groups.items()) if key.startswith(wanted)]
        return [g for _, _, g in sorted(found, key=lambda item: (item[0], item[1]))]

    # -- HOME_NET -----------------------------------------------------------------------------

    def _home_net(self) -> None:
        variables = self.body.get("PolicyVariables")
        rule_variables = variables.get("RuleVariables") if isinstance(variables, dict) else None
        if isinstance(rule_variables, dict):
            for name in rule_variables:
                if name != "HOME_NET":
                    self.report.note(Severity.REVIEW, "AWSNFW_POLICY_VARIABLE",
                                     f"the policy sets variable {str(name)[:40]}; Network Firewall takes HOME_NET only there, and "
                                     "it is not read")  # fmt: skip
            home = rule_variables.get("HOME_NET")
            if isinstance(home, dict):
                found = self._definition(home.get("Definition"))
                if found is None:
                    self.report.note(Severity.REVIEW, "AWSNFW_VARIABLE_UNREADABLE",
                                     "the policy's HOME_NET cannot be read; rules that name it are not converted")  # fmt: skip
                    self.home_from = "unreadable"
                else:
                    self.home, self.home_from = found, "the policy variable"
                return
        blocks: List[Interval] = []
        if len(self.found.vpcs) > 1:
            self.report.note(Severity.REVIEW, "AWSNFW_HOME_NET_UNKNOWN",
                             "the input holds several VPCs; which one is the inspection VPC, whose CIDR blocks are HOME_NET, is not "
                             "known. Give the one of the firewall")  # fmt: skip
            return
        for vpc in self.found.vpcs:
            texts = [str(b.get("CidrBlock", "")) for b in _dicts(vpc.get("CidrBlockAssociationSet")) if _associated(b, "CidrBlockState")]
            texts += [str(b.get("Ipv6CidrBlock", "")) for b in _dicts(vpc.get("Ipv6CidrBlockAssociationSet"))
                      if _associated(b, "Ipv6CidrBlockState")]  # fmt: skip
            if not texts and vpc.get("CidrBlock"):
                texts.append(str(vpc["CidrBlock"]))
            blocks += [i for i in map(parse_literal, texts) if i is not None]
            if blocks:
                self.home = normalize(blocks)
                self.home_from = f"the CIDR blocks of VPC {vpc.get('VpcId', '?')}"

    def _definition(self, value: Any) -> Optional[List[Interval]]:
        found: List[Interval] = []
        for text in _list(value):
            interval = parse_literal(str(text)) if isinstance(text, str) else None
            if interval is None or "-" in str(text):
                return None
            found.append(interval)
        return normalize(found) if found else None

    def _home_name(self) -> str:
        if self.home_group:
            return self.home_group
        name = self._object_name("HOME_NET")
        self.home_group = name
        if self.home is not None:
            group = AddressGroup(name, [interval_text(i) for i in self.home], f"Suricata HOME_NET: {self.home_from}")
        else:
            group = AddressGroup(name, description="Suricata HOME_NET")
            group.unsupported = ("HOME_NET is the CIDR of the inspection VPC by default, which is not in the input: add the answer of aws "
                                 "ec2 describe-vpcs for that VPC, or set HOME_NET in the policy variables")  # fmt: skip
        self.p.address_groups[name] = group
        return name

    def _variable_group(self, name: str, intervals: List[Interval], scope: str) -> str:
        key = (name, tuple(intervals))
        if key in self.variables:
            return self.variables[key]
        taken = any(k[0] == name for k in self.variables) or name in ("HOME_NET", "EXTERNAL_NET")
        label = f"{name}-{scope}" if taken else name
        object_name = self._object_name(label)
        self.variables[key] = object_name
        self.p.address_groups[object_name] = AddressGroup(object_name, [interval_text(i) for i in intervals],
                                                          f"IP set variable {name} of rule group {scope}")  # fmt: skip
        return object_name

    # -- services -------------------------------------------------------------------------

    def _service(self, entries: List[ServiceEntry]) -> str:
        key = json.dumps([[e.protocol.value, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code, e.ip_protocol] for e in entries])
        if key in self.service_keys:
            return self.service_keys[key]
        parts = []
        for entry in entries[:3]:
            if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                label = f"{entry.protocol.value}-{entry.dst_ports or 'all'}"
                if entry.src_ports:
                    label += f"-from-{entry.src_ports}"
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                label = entry.protocol.value + ("-all" if entry.icmp_type is None else f"-{entry.icmp_type}")
                if entry.icmp_code is not None:
                    label += f"-{entry.icmp_code}"
            else:
                label = f"ip-{entry.ip_protocol}"
            parts.append(label)
        name = self._unique("+".join(parts)[:120] + ("+more" if len(entries) > 3 else ""), self.taken_services)
        self.p.services[name] = Service(name, list(entries))
        self.service_keys[key] = name
        return name

    def _box_services(self, svc: regions.Services, version: int) -> Optional[Tuple[List[str], bool]]:
        if svc.everything():
            return [ANY], False
        found = regions.entries_of(svc, version)
        if found is None:
            return None
        entries, negated = found
        if not entries:
            return ([ANY], False) if negated else None
        return [self._service(entries)], negated

    # -- the stateless engine -------------------------------------------------------------

    def _stateless_rules(self) -> List[_Stateless]:
        out: List[_Stateless] = []
        for group in self._ordered(False):
            if group.kind != "stateless":
                problem = (f"rule group {group.name} is not in the input (add the answer of describe-rule-group for {group.arn})"
                           if group.kind == "missing" else f"rule group {group.name} holds no stateless rules that can be read")
                item = _Stateless(f"{group.name}", group.name, 0, "drop", None, [problem])
                out.append(item)
                continue
            source = group.body["RulesSource"]["StatelessRulesAndCustomActions"]
            rules = sorted(_dicts(source.get("StatelessRules")), key=lambda r: _number(r.get("Priority"), 1 << 30))
            seen: Set[int] = set()
            for rule in rules:
                priority = _number(rule.get("Priority"), -1)
                item = self._stateless_rule(group, rule, priority)
                if priority in seen:
                    item.problems.append(f"priority {priority} twice in the group")
                seen.add(priority)
                out.append(item)
        return out

    def _stateless_rule(self, group: _Group, rule: Dict[str, Any], priority: int) -> _Stateless:
        definition = _dict(rule.get("RuleDefinition"))
        actions = [str(a) for a in _list(definition.get("Actions"))]
        standard = [_STANDARD[a] for a in actions if a in _STANDARD]
        item = _Stateless(f"{group.name}-{priority}", group.name, priority, standard[0] if len(standard) == 1 else "drop", None)
        if len(standard) != 1:
            item.problems.append(f"actions {', '.join(actions)[:80]}: a stateless rule has one of aws:pass, aws:drop, aws:forward_to_sfe")
        match = _dict(definition.get("MatchAttributes"))
        boxes, members, problems = self._match_boxes(match)
        item.members = members
        item.problems += problems
        if not item.problems:
            item.boxes = boxes
        return item

    def _members(self, item: _Stateless) -> Tuple[List[str], List[str], List[str]]:
        """The sources, destinations and services of a stateless rule as written (its services registered only now)."""
        sources, destinations, services = item.members
        if services != [ANY]:
            entries = [ServiceEntry(Protocol(p), d, s, ip_protocol=n) for p, d, s, n in json.loads(services[0][1:])]
            services = [self._service(entries)]
        return sources, destinations, services

    def _match_boxes(self, match: Dict[str, Any]) -> Tuple[List[regions.Box], Tuple[List[str], List[str], List[str]], List[str]]:
        problems: List[str] = []
        sides: List[Optional[List[Interval]]] = []
        texts: List[List[str]] = []
        for key in ("Sources", "Destinations"):
            given = _dicts(match.get(key))
            if not given:
                sides.append(None)
                texts.append([ANY])
                continue
            found: List[Interval] = []
            for item in given:
                text = str(item.get("AddressDefinition") or "")
                interval = parse_literal(text)
                if interval is None or "/" not in text:
                    problems.append(f"'{text[:60]}' is not a CIDR block")
                    continue
                found.append(interval)
            sides.append(normalize(found))
            texts.append([interval_text(i) for i in normalize(found)])
        protocols = [_number(n, -1) for n in _list(match.get("Protocols"))]
        if any(not 0 <= n <= 255 for n in protocols):
            problems.append("a protocol number that cannot be read")
        ports: List[List[Tuple[int, int]]] = []
        for key in ("SourcePorts", "DestinationPorts"):
            ranges: List[Tuple[int, int]] = []
            for item in _dicts(match.get(key)):
                low, high = _number(item.get("FromPort"), -1), _number(item.get("ToPort"), -1)
                if not 0 <= low <= high <= 65535:
                    problems.append(f"port range {item.get('FromPort')}-{item.get('ToPort')} cannot be read")
                    continue
                ranges.append((low, high))
            ports.append(regions.merge_ranges(ranges) or _ALL_PORTS)
        has_ports = any(_dicts(match.get(k)) for k in ("SourcePorts", "DestinationPorts"))
        if _list(match.get("TCPFlags")):
            problems.append("TCP flags: the rule matches some packets of a connection and not others")
        if has_ports and not protocols:
            problems.append("ports without a protocol (the ports are used for TCP and UDP only; what the rule does with other "
                            "protocols is not documented)")  # fmt: skip
        entries: List[ServiceEntry] = []
        svc = regions.ALL_SERVICES
        if protocols:
            rects: Dict[int, List[Tuple[int, int, int, int]]] = {}
            for number in sorted(set(protocols)):
                if number in (6, 17):
                    rects[number] = [(s[0], s[1], d[0], d[1]) for s in ports[0] for d in ports[1]]
                    kind = Protocol.TCP if number == 6 else Protocol.UDP
                    for s in ports[0]:
                        for d in ports[1]:
                            entries.append(ServiceEntry(kind, _port_text([d]), _port_text([s])))
                else:
                    rects[number] = [regions.WHOLE]
                    if number == 1:
                        entries.append(ServiceEntry(Protocol.ICMP))
                    elif number == 58:
                        entries.append(ServiceEntry(Protocol.ICMP6))
                    elif number == 132:
                        entries.append(ServiceEntry(Protocol.SCTP))
                    else:
                        entries.append(ServiceEntry(Protocol.IP, ip_protocol=number))
            svc = regions.Services(rects, False)
        service_names = ["\x00" + json.dumps([[e.protocol.value, e.dst_ports, e.src_ports, e.ip_protocol] for e in entries])] if entries else [ANY]
        boxes: List[regions.Box] = []
        for version in (4, 6):
            src = regions.everywhere(version) if sides[0] is None else regions.addresses(sides[0], version)
            dst = regions.everywhere(version) if sides[1] is None else regions.addresses(sides[1], version)
            if src and dst and not _meets_nothing((version, src, dst, svc)):
                boxes.append((version, src, dst, svc))
        return boxes, (texts[0], texts[1], service_names), problems

    def _stateless(self) -> None:
        full = self._default_action("StatelessDefaultActions")
        fragments = self._default_action("StatelessFragmentDefaultActions")
        if fragments and fragments != full:
            self.report.note(Severity.INFO, "AWSNFW_FRAGMENTS",
                             f"UDP fragments that no stateless rule matches are handled by aws:{'forward_to_sfe' if fragments == 'forward' else fragments}, "
                             "other packets by the default for full packets; the model has no fragments, and the converted policy "
                             "follows the default for full packets. Fragments of other protocols are dropped")  # fmt: skip
        rules = self._stateless_rules()
        if not full:
            self.report.note(Severity.REVIEW, "AWSNFW_DEFAULT_UNREADABLE",
                             "the policy's stateless default action for full packets cannot be read (it has one of aws:pass, aws:drop, "
                             "aws:forward_to_sfe); it is taken as aws:forward_to_sfe")  # fmt: skip
            full = "forward"
        if not rules:
            if full in ("pass", "drop"):
                rule = self._new_rule(f"stateless-default-{full}", action=Action.ALLOW if full == "pass" else Action.DROP)
                rule.description = f"the policy's stateless default action, aws:{full}, for every packet"
                self.p.rules.append(rule)
                self.reachable = False
            return
        self._compose(rules, full)

    def _default_action(self, key: str) -> str:
        actions = [str(a) for a in _list(self.body.get(key))]
        standard = [_STANDARD[a] for a in actions if a in _STANDARD]
        return standard[0] if len(standard) == 1 else ""

    def _compose(self, rules: List[_Stateless], default: str) -> None:
        """The stateless rules as connections: what a first packet meets, and what its reply meets."""
        everything = [(v, regions.everywhere(v), regions.everywhere(v), regions.ALL_SERVICES) for v in (4, 6)]
        earlier: List[regions.Box] = []
        firsts: List[Tuple[_Stateless, Optional[List[regions.Box]]]] = []
        complex_ = False
        for item in rules:
            if item.boxes is None:
                firsts.append((item, None))
                continue
            first = regions.minus_all(item.boxes, earlier, limit=_MAX_PIECES)
            if first is None:
                complex_ = True
                break
            firsts.append((item, first))
            earlier += item.boxes
        rest = None if complex_ else regions.minus_all(everything, earlier, limit=_MAX_PIECES)
        if complex_ or rest is None:
            self._stateless_as_written(rules, default)
            return
        # What the reply of a connection meets: its first match, by action.
        replies: Dict[str, List[regions.Box]] = {"pass": [], "drop": [], "forward": []}
        by_rule: List[Tuple[str, List[regions.Box], str]] = []  # (action, mirrored boxes, the rule that decides the reply)
        for item, first in firsts:
            if first is None:
                continue
            mirrored = [m for m in (_mirror_box(b) for b in first) if m is not None]
            replies[item.action] += mirrored
            by_rule.append((item.action, mirrored, item.name))
        mirrored_rest = [m for m in (_mirror_box(b) for b in rest) if m is not None]
        replies[default] += mirrored_rest
        by_rule.append((default, mirrored_rest, f"the stateless default action aws:{'forward_to_sfe' if default == 'forward' else default}"))
        # 1. Connections whose replies are dropped.
        for action, mirrored, decider in by_rule:
            if action != "drop" or not mirrored:
                continue
            base = (decider + "-replies") if not decider.startswith("the ") else "stateless-default-drop-replies"
            for rule in self._box_rules(base, mirrored, Action.DROP):
                rule.description = f"connections whose replies {decider} drops"
                self.report.add("rule", rule.origin, Severity.INFO, "AWSNFW_REPLY_DROPPED",
                                f"the stateless engine filters each packet: the replies of these connections meet {decider}, which drops "
                                "them, so the connections are blocked whatever else would allow them")  # fmt: skip
        # 2. The rules in their order, for the first packet.
        mixed: List[str] = []
        flagged = False
        for item, first in firsts:
            if first is None:
                sources, destinations, services = self._members(item)
                rule = self._new_rule(item.name, sources=sources, destinations=destinations, services=services,
                                      action=Action.ALLOW if item.action == "pass" else Action.DROP)  # fmt: skip
                rule.unsupported = list(item.problems)
                rule.source_ids = {"awsnfw.rule_group": item.group, "awsnfw.priority": str(item.priority)}
                rule.description = f"stateless rule, aws:{'forward_to_sfe' if item.action == 'forward' else item.action}"
                self.p.rules.append(rule)
                flagged = True
                continue
            if item.action == "drop":
                for rule in self._box_rules(item.name, first, Action.DROP, item):
                    rule.description = "stateless rule, aws:drop"
            elif item.action == "pass":
                allowed = regions.minus_all(first, replies["forward"], limit=_MAX_PIECES)
                half = _boxes_and(first, replies["forward"])
                written = self._box_rules(item.name, allowed or [], Action.ALLOW, item)
                for rule in written:
                    rule.description = "stateless rule, aws:pass"
                if allowed is None:
                    half = first
                dropped = _boxes_and(first, replies["drop"])
                for rule in written:
                    if dropped:
                        self.report.add("rule", rule.origin, Severity.INFO, "AWSNFW_STATELESS_REPLY",
                                        "a stateless pass lets packets through in one direction; the replies of some of the connections "
                                        "it passes are dropped by the stateless rules, and those connections are blocked, as on the "
                                        "firewall")  # fmt: skip
                    if half:
                        self.report.add("rule", rule.origin, Severity.REVIEW, "AWSNFW_ASYMMETRIC",
                                        "the replies of some of the connections this rule passes are forwarded to the stateful engine, "
                                        "which then sees half a flow; the converted policy leaves those connections to the stateful "
                                        "rules")  # fmt: skip
                if half and not written:
                    mixed.append(item.name)
                if not written and not half:
                    self.report.note(Severity.INFO, "AWSNFW_STATELESS_NOTHING",
                                     f"stateless rule {item.name} decides no connection: what it matches is taken by the rules above it, "
                                     "or its replies are dropped")  # fmt: skip
            else:
                if _boxes_and(first, replies["pass"]):
                    mixed.append(item.name)
        # 3. The default for what no stateless rule matched.
        if default == "pass":
            allowed = regions.minus_all(rest, replies["forward"], limit=_MAX_PIECES) or []
            for rule in self._box_rules("stateless-default-pass", allowed, Action.ALLOW):
                rule.description = "the policy's stateless default action, aws:pass"
            if _boxes_and(rest, replies["forward"]):
                mixed.append("the stateless default action aws:pass")
            self.reachable = bool(replies["forward"]) or any(item.action == "forward" for item, _ in firsts)
        elif default == "drop":
            self.reachable = any(item.action == "forward" for item, _ in firsts)
            if self.reachable:  # (what the rules forward is not written: the default must leave it to the stateful rules)
                written = self._box_rules("stateless-default-drop", rest, Action.DROP)
            else:
                written = [self._new_rule("stateless-default-drop", action=Action.DROP)]
                self.p.rules.append(written[0])
            for rule in written:
                rule.description = "the policy's stateless default action, aws:drop: what no stateless rule matched"
                rule.log_end = False
        elif _boxes_and(rest, replies["pass"]):
            mixed.append("the stateless default action aws:forward_to_sfe")
        if mixed:
            self.report.note(Severity.REVIEW, "AWSNFW_ASYMMETRIC",
                             "one direction of some connections is passed by the stateless rules and the other forwarded to the stateful "
                             "engine, which then sees half a flow and may drop it (" + ", ".join(mixed[:6])
                             + "). The converted policy leaves those connections to the stateful rules")  # fmt: skip
        forwards = [item.name for item, _ in firsts if item.action == "forward"]
        if forwards:
            self.report.note(Severity.INFO, "AWSNFW_STATELESS_FORWARD",
                             "these stateless rules forward what they match to the stateful engine, so the stateless rules below them do "
                             "not see it: " + ", ".join(forwards[:10]) + (" ..." if len(forwards) > 10 else ""))  # fmt: skip
        if flagged:
            self.report.note(Severity.REVIEW, "AWSNFW_STATELESS_NOT_WORKED_OUT",
                             "some stateless rules cannot be read (TCP flags, a rule group not in the input, a value that cannot be "
                             "read): they are not converted, and what the rules after them and the replies meet was worked out as if "
                             "they matched nothing")  # fmt: skip

    def _stateless_as_written(self, rules: List[_Stateless], default: str) -> None:
        self.report.note(Severity.REVIEW, "AWSNFW_STATELESS_NOT_WORKED_OUT",
                         "the stateless rules overlap in more ways than are worked out: what each rule decides, and what the replies "
                         "meet, is not converted. Each rule is written as it stands; pass and forward rules are not converted")  # fmt: skip
        for item in rules:
            sources, destinations, services = self._members(item)
            rule = self._new_rule(item.name, sources=sources, destinations=destinations, services=services,
                                  action=Action.ALLOW if item.action == "pass" else Action.DROP)  # fmt: skip
            rule.unsupported = list(item.problems)
            if item.action != "drop":
                rule.unsupported.append("a stateless rule whose replies and overlaps were not worked out")
            rule.source_ids = {"awsnfw.rule_group": item.group, "awsnfw.priority": str(item.priority)}
            self.p.rules.append(rule)
        if default != "forward":
            rule = self._new_rule(f"stateless-default-{default}", action=Action.ALLOW if default == "pass" else Action.DROP)
            rule.unsupported = ["the stateless default action, whose replies were not worked out"] if default == "pass" else []
            self.p.rules.append(rule)

    def _box_rules(self, base: str, boxes: List[regions.Box], action: Action, item: Optional[_Stateless] = None) -> List[Rule]:
        """Rules for a set of connections: a rule per box, a box of each IP version together where their services agree."""
        out: List[Rule] = []
        kept = [piece for box in boxes if not _meets_nothing(box) for piece in _icmp_apart(box)]
        used: Set[int] = set()
        for index, box in enumerate(kept):
            if index in used:
                continue
            used.add(index)
            chosen = [box]
            found = self._box_services(box[3], box[0])
            for other_index in range(index + 1, len(kept)):
                other = kept[other_index]
                if other_index in used or other[0] == box[0] or not _same(other[3], box[3]):
                    continue
                if self._box_services(other[3], other[0]) == found:
                    chosen.append(other)
                    used.add(other_index)
                    break
            sources = normalize([i for b in chosen for i in b[1]])
            destinations = normalize([i for b in chosen for i in b[2]])
            rule = self._new_rule(base, sources=_side_text(sources), destinations=_side_text(destinations), action=action)
            if found is None:
                rule.unsupported.append("more ICMP types and codes than can be listed")
            else:
                rule.services, rule.negate_service = found
            if item is not None:
                rule.source_ids = {"awsnfw.rule_group": item.group, "awsnfw.priority": str(item.priority)}
            rule.log_end = action != Action.ALLOW
            self.p.rules.append(rule)
            out.append(rule)
        return out

    # -- the stateful engine ---------------------------------------------------------------

    def _stateful(self) -> None:
        engine = _dict(self.body.get("StatefulEngineOptions"))
        order = str(engine.get("RuleOrder") or "DEFAULT_ACTION_ORDER")
        if order not in ("DEFAULT_ACTION_ORDER", "STRICT_ORDER"):
            self.report.note(Severity.REVIEW, "AWSNFW_ORDER_UNKNOWN", f"rule order {order[:40]} is not known; it is read as DEFAULT_ACTION_ORDER")
            order = "DEFAULT_ACTION_ORDER"
        self.order = order
        defaults = [str(a) for a in _list(self.body.get("StatefulDefaultActions"))]
        unknown = [a for a in defaults if a not in _DROP_DEFAULTS + _ALERT_DEFAULTS]
        if unknown:
            self.report.note(Severity.REVIEW, "AWSNFW_DEFAULT_UNREADABLE",
                             "stateful default actions that are not known: " + ", ".join(unknown)[:200] + "; they are not read")  # fmt: skip
        drops = [a for a in defaults if a in _DROP_DEFAULTS]
        if defaults and order != "STRICT_ORDER":
            self.report.note(Severity.REVIEW, "AWSNFW_DEFAULTS_IGNORED",
                             "the policy has stateful default actions but evaluates rules in action order, where they do not apply (AWS "
                             "takes them with STRICT_ORDER only); what no rule matches passes")  # fmt: skip
            drops = []
        if len(drops) > 1:
            self.report.note(Severity.REVIEW, "AWSNFW_DEFAULT_UNREADABLE",
                             "more than one stateful default drop action (" + ", ".join(drops) + "); AWS takes one. The strictest is "
                             "read")  # fmt: skip
        strict_drop = "aws:drop_strict" in drops
        established_drop = bool(drops) and not strict_drop
        if established_drop and drops[0] != "aws:drop_established":
            self.report.note(Severity.INFO, "AWSNFW_APP_LAYER_DEFAULT",
                             f"default action {drops[0]}: read as aws:drop_established (the handshake passes, what no rule passed once "
                             "the connection is established is dropped, other protocols are dropped at once); how it waits for TLS SNI "
                             "and HTTP host names in segmented packets is not modelled")  # fmt: skip
        self.p.default_interzone = self.p.default_intrazone = Action.DROP if drops else Action.ALLOW
        parsed = self._stateful_rules(order)
        readings: List[Tuple[_Parsed, List[_Reading]]] = [(rule, self._readings(rule)) for rule in parsed]
        readings = [(rule, found) for rule, found in readings if found]
        if not self.reachable:
            for rule, _ in readings:
                self._never(rule, "the stateless rules pass or drop every packet: nothing reaches the stateful engine")
            if readings:
                self.report.note(Severity.INFO, "AWSNFW_STATEFUL_UNREACHABLE",
                                 "no packet is forwarded to the stateful engine (the stateless default action passes or drops, and no "
                                 "stateless rule forwards): the stateful rules decide nothing and are disabled in the converted policy")  # fmt: skip
            self._alert_note()
            return
        if strict_drop:
            self._strict_replies([reading for _, found in readings for reading in found])
        written: Set[str] = set()
        for moment in (_FIRST, _REPLY, _ESTABLISHED, _ESTABLISHED_REPLY):
            if moment == _REPLY and strict_drop:
                break
            if moment == _ESTABLISHED_REPLY and established_drop:
                break
            if moment == _REPLY and established_drop:
                kill = self._new_rule("stateful-default-not-tcp", services=[self._service([ServiceEntry(Protocol.TCP)])], action=Action.DROP)
                kill.negate_service = True
                kill.log_end = True
                kill.description = (f"{drops[0]}: a connection of a protocol other than TCP that no rule passed on its first packet is "
                                    "dropped")  # fmt: skip
                self.p.rules.append(kill)
            for _, found in readings:
                for reading in found:
                    if reading.moment != moment:
                        continue
                    if established_drop and moment in (_REPLY, _ESTABLISHED) and reading.transports == ("other",):
                        continue  # (dropped at the first packet already)
                    self._place(reading)
                    written.add(reading.key)
        for rule, found in readings:
            if found[0].key not in written:
                why = ("with aws:drop_strict a flow is decided on its first packet, which this rule never matches" if strict_drop else
                       f"with {drops[0] if drops else 'its default action'} a flow that no rule passed is dropped before this rule can "
                       "match")  # fmt: skip
                self._never(rule, why)
        self._alert_note()

    def _strict_replies(self, readings: List[_Reading]) -> None:
        """With STRICT_ORDER and aws:drop_strict every packet is decided on its own: a pass rule passes the packets it
        matches, and any other packet of a connection is dropped unless a rule passes it too (the FWShift lab, 0.41.7:
        pass rules with flow:to_server and nothing for the replies blocked every connection). For the first reply, and
        for TCP the established packets each way, the first match in order decides (the default drops); the
        connections one of those packets of which no rule passes are blocked at the top, and the rules for the first
        packet follow."""
        # (the connections that have a reply: every protocol, but of ICMP the requests only; an ICMP message that is no
        # request is decided on its one packet)
        requests = {number: [(request, request, 0, 65535) for request in sorted(types)] for number, types in _REPLY_TYPE.items()}
        answered = regions.Services(requests, True)
        tcp = regions.Services({6: [regions.WHOLE]}, False)
        # (each in the order of the policy: the first match decides)
        moments = (
            (answered, [r for r in readings if r.moment == _REPLY or (r.moment == _FIRST and r.both_ways)]),
            (tcp, [r for r in readings if r.moment == _ESTABLISHED or (r.moment == _FIRST and r.any_state)]),
            (tcp, [r for r in readings if r.moment == _ESTABLISHED_REPLY or (r.moment == _ESTABLISHED and r.both_ways)
                   or (r.any_state and (r.moment == _REPLY or (r.moment == _FIRST and r.both_ways)))]),
        )
        def passed_by(found: List[_Reading]) -> Optional[List[regions.Box]]:
            """What the first match passes, in order (None when a rule cannot be read as sets)."""
            earlier: List[regions.Box] = []
            passed: List[regions.Box] = []
            for reading in found:
                boxes = self._rule_boxes(reading.rule)
                first = regions.minus_all(boxes, earlier, limit=_MAX_PIECES) if boxes is not None else None
                if boxes is None or first is None:
                    self.report.note(Severity.REVIEW, "AWSNFW_STRICT_REPLIES",
                                     "with aws:drop_strict every packet is decided on its own, and the replies and later packets of "
                                     "a connection are dropped unless a rule passes them; the rules that match them could not be "
                                     f"worked out as sets (rule {reading.rule.name}), so the connections are read as decided on their "
                                     "first packet: check that their replies pass")  # fmt: skip
                    return None
                if reading.rule.action == Action.ALLOW:
                    passed += first
                earlier += boxes
            return passed

        def failed() -> None:
            self.report.note(Severity.REVIEW, "AWSNFW_STRICT_REPLIES",
                             "with aws:drop_strict the replies and later packets of a connection are dropped unless a rule passes "
                             "them; which ones the rules pass could not be worked out as sets, so the connections are read as "
                             "decided on their first packet: check that their replies pass")  # fmt: skip

        # (only the connections the first packet passes matter: the default drops the others anyway)
        opened = passed_by([r for r in readings if r.moment == _FIRST])
        if opened is None:
            return
        blocked: List[regions.Box] = []
        for services, found in moments:
            scope = [(v, regions.everywhere(v), regions.everywhere(v), services) for v in (4, 6)]
            passed = passed_by(found)
            if passed is None:
                return
            left = regions.minus_all(scope, passed, limit=_MAX_PIECES)
            if left is None:
                failed()
                return
            for box in left:
                for other in opened:
                    both = regions.box_and(box, other)
                    if both is not None and not regions.empty(both):
                        blocked.append(both)
            if len(blocked) > _MAX_PIECES:
                failed()
                return
        written = self._box_rules("strict-replies-dropped", blocked, Action.DROP)
        for rule in written:
            rule.description = "aws:drop_strict: connections whose replies or later packets no rule passes"
            self.report.add("rule", rule.origin, Severity.INFO, "AWSNFW_REPLY_DROPPED",
                            "with aws:drop_strict every packet is decided on its own: the replies (or, for TCP, the established "
                            "packets) of these connections match no rule that passes them, so the default drops them and the "
                            "connections are blocked, whatever passes their first packet")  # fmt: skip
        if written:
            self.report.note(Severity.INFO, "AWSNFW_STRICT_REPLIES",
                             "with aws:drop_strict every packet is decided on its own (strict order): a pass rule with flow:to_server "
                             "passes the packets from the client and not the replies. Connections whose replies or later packets no "
                             "rule passes are blocked (rules strict-replies-dropped, at the top)")  # fmt: skip

    def _rule_boxes(self, rule: Rule) -> Optional[List[regions.Box]]:
        """A rule of the model as the connections it matches, or None when that cannot be read (applications, members
        without known addresses, more pieces than the limit)."""
        if rule.unsupported or [a for a in rule.applications if a != ANY]:
            return None
        if APP_DEFAULT in rule.services:
            return None
        if ANY in rule.services:
            svc: Optional[regions.Services] = regions.ALL_SERVICES
        else:
            entries: List[ServiceEntry] = []
            for name in rule.services:
                found = transform.flatten_services(self.p, name)
                if found is None:
                    return None
                entries += found
            svc = regions.service_set(entries)
        if svc is None:
            return None
        boxes: List[regions.Box] = []
        for version in (4, 6):
            sides: List[List[Interval]] = []
            for members, negate in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
                if ANY in members:
                    found_side = list(regions.everywhere(version))
                else:
                    found_side = []
                    for member in members:
                        intervals, complete = transform.known_intervals(self.p, member)
                        if not complete:
                            return None
                        found_side += intervals
                    found_side = regions.addresses(normalize(found_side), version)
                if negate:
                    found_side = subtract(list(regions.everywhere(version)), found_side)
                sides.append(found_side)
            if not sides[0] or not sides[1]:
                continue
            if rule.negate_service:  # (every service but those: what is left of all of them)
                rest = regions.minus_all([(version, sides[0], sides[1], regions.ALL_SERVICES)], [(version, sides[0], sides[1], svc)],
                                         limit=_MAX_PIECES)  # fmt: skip
                if rest is None:
                    return None
                boxes += [box for box in rest if not _meets_nothing(box)]
            elif not _meets_nothing((version, sides[0], sides[1], svc)):
                boxes.append((version, sides[0], sides[1], svc))
        return boxes

    def _alert_note(self) -> None:
        if self.alerts:
            self.report.note(Severity.INFO, "AWSNFW_ALERT_RULES",
                             f"{self.alerts} alert rule{'s' if self.alerts != 1 else ''} decide{'' if self.alerts != 1 else 's'} nothing "
                             "(an alert only logs) and " + ("were" if self.alerts != 1 else "was") + " left out")  # fmt: skip

    def _place(self, reading: _Reading) -> None:
        rule = reading.rule
        rule.name = self._unique(rule.name, self.rule_names)
        rule.origin = rule.name
        self.p.rules.append(rule)
        for severity, code, message in reading.findings:
            self.report.add("rule", rule.origin, severity, code, message)

    def _never(self, parsed: _Parsed, why: str) -> None:
        rule = self._new_rule(self._base_name(parsed), action=Action.ALLOW if parsed.action == "pass" else Action.DROP)
        rule.enabled = False
        rule.description = parsed.message
        rule.source_ids = {"awsnfw.rule_group": parsed.group.name, "awsnfw.sid": parsed.sid}
        self.p.rules.append(rule)
        self.report.add("rule", rule.origin, Severity.INFO, "AWSNFW_NEVER_MATCHES",
                        f"{why}; the rule is disabled in the converted policy: {parsed.text[:160]}")  # fmt: skip

    def _stateful_rules(self, order: str) -> List[_Parsed]:
        out: List[_Parsed] = []
        sids: Dict[Tuple[str, str], int] = {}
        for group in self._ordered(True):
            if group.order and group.order != order:
                self.report.note(Severity.REVIEW, "AWSNFW_GROUP_ORDER",
                                 f"rule group {group.name} has rule order {group.order[:30]} and the policy {order}; AWS refuses such a "
                                 f"policy. Its rules are read in the policy's order")  # fmt: skip
            found = self._group_rules(group)
            for rule in found:
                if rule.sid:
                    key = (group.name, rule.sid)
                    sids[key] = sids.get(key, 0) + 1
                    if sids[key] == 2:
                        self.report.note(Severity.REVIEW, "AWSNFW_SID_TWICE",
                                         f"sid {rule.sid[:20]} is used twice in rule group {group.name}; AWS refuses such a group")  # fmt: skip
            out += found
        if order == "DEFAULT_ACTION_ORDER":
            out.sort(key=lambda r: _ACTIONS.get(r.action, 9))
        return out

    def _group_rules(self, group: _Group) -> List[_Parsed]:
        if group.kind in ("missing", "unreadable", "stateless"):
            placeholder = _Parsed(group, 1, "", action="drop")
            placeholder.problem = (f"rule group {group.name} is not in the input; add the answer of describe-rule-group for {group.arn}"
                                   if group.kind == "missing" else f"rule group {group.name} holds no stateful rules that can be read")  # fmt: skip
            if ":aws-managed:" in group.arn:
                placeholder.problem += " (an AWS managed rule group, whose rules AWS may not show)"
            return [placeholder]
        source = group.body.get("RulesSource") or {}
        if group.kind == "domain":
            return self._domain_rules(group, source["RulesSourceList"])
        if source.get("RulesString") is not None:
            return _rules_of_string(group, str(source.get("RulesString") or ""))
        out: List[_Parsed] = []
        for index, item in enumerate(_dicts(source.get("StatefulRules")), 1):
            out.append(self._five_tuple(group, index, item))
        return out

    @staticmethod
    def _five_tuple(group: _Group, index: int, item: Dict[str, Any]) -> _Parsed:
        header = _dict(item.get("Header"))
        options = []
        for option in _dicts(item.get("RuleOptions")):
            keyword = str(option.get("Keyword") or "")
            settings = [str(s) for s in _list(option.get("Settings"))]
            options.append(keyword + (":" + ",".join(settings) if settings else "") + ";")
        direction = "<>" if str(header.get("Direction") or "").upper() == "ANY" else "->"
        if str(header.get("Direction") or "").upper() not in ("ANY", "FORWARD"):
            direction = "?"
        text = (f"{str(item.get('Action') or '').lower()} {str(header.get('Protocol') or '').lower()} {header.get('Source', '')} "
                f"{header.get('SourcePort', '')} {direction} {header.get('Destination', '')} {header.get('DestinationPort', '')} "
                f"({' '.join(options)})")  # fmt: skip
        return _parse_rule(group, index, text)

    def _domain_rules(self, group: _Group, source: Dict[str, Any]) -> List[_Parsed]:
        """The rules Network Firewall generates for a domain list."""
        kind = str(source.get("GeneratedRulesType") or "").upper()
        targets = [str(t) for t in _list(source.get("Targets"))]
        types = [str(t).upper() for t in _list(source.get("TargetTypes"))]
        lines: List[str] = []
        names = ", ".join(targets[:5]) + (" ..." if len(targets) > 5 else "")
        for target_type, protocol in (("TLS_SNI", "tls"), ("HTTP_HOST", "http")):
            if target_type not in types:
                continue
            keyword = "tls.sni" if protocol == "tls" else "http.host"
            if kind == "ALLOWLIST":
                lines.append(f'pass {protocol} $HOME_NET any -> $EXTERNAL_NET any ({keyword}; msg:"domain names {names}"; '
                             'flow:to_server, established;)')  # fmt: skip
                lines.append(f'drop {protocol} $HOME_NET any -> $EXTERNAL_NET any (msg:"not matching any {target_type} allowlisted '
                             'domain name"; flow:to_server, established;)')  # fmt: skip
            elif kind == "DENYLIST":
                lines.append(f'drop {protocol} $HOME_NET any -> $EXTERNAL_NET any ({keyword}; msg:"domain names {names}"; '
                             'flow:to_server, established;)')  # fmt: skip
            elif kind == "ALERTLIST":
                lines.append(f'alert {protocol} $HOME_NET any -> $EXTERNAL_NET any ({keyword}; msg:"domain names {names}"; '
                             'flow:to_server, established;)')  # fmt: skip
        if not lines:
            rule = _Parsed(group, 1, "", action="drop")
            rule.problem = f"a domain list of type {kind[:20] or '?'} for {', '.join(types)[:60] or 'nothing'}, which cannot be read"
            return [rule]
        out = [_parse_rule(group, index, line) for index, line in enumerate(lines, 1)]
        for rule in out:
            rule.options.append(("sid", str(rule.index)))
        return out

    # -- one stateful rule -------------------------------------------------------------------

    def _base_name(self, parsed: _Parsed) -> str:
        return f"{parsed.group.name}-{parsed.sid or parsed.index}"

    def _readings(self, parsed: _Parsed) -> List[_Reading]:
        if parsed.action == "alert" or (parsed.action == "drop" and parsed.group.override == "DROP_TO_ALERT"):
            self.alerts += 1
            return []
        action = parsed.action
        try:
            if parsed.problem:
                raise _Bad(parsed.problem)
            if action not in ("pass", "drop", "reject"):
                raise _Bad(f"action {action[:20]} (Network Firewall takes pass, drop, reject and alert)")
            return self._read(parsed)
        except _Nothing as error:
            rule = Rule(self._base_name(parsed), action=Action.ALLOW if action == "pass" else Action.DROP)
            rule.enabled = False
            rule.description = parsed.message or parsed.text[:200]
            rule.source_ids = {"awsnfw.rule_group": parsed.group.name, "awsnfw.sid": parsed.sid}
            reading = _Reading(_FIRST, rule, ("tcp", "other"), _key(parsed))
            reading.findings.append((Severity.INFO, "AWSNFW_MATCHES_NOTHING", f"{error}; the rule decides nothing and is disabled"))
            return [reading]
        except _Bad as error:
            rule = Rule(self._base_name(parsed), action=Action.ALLOW if action == "pass" else Action.DROP)
            rule.unsupported.append(str(error))
            rule.enabled = not parsed.disabled
            rule.description = parsed.message or parsed.text[:200]
            rule.source_ids = {"awsnfw.rule_group": parsed.group.name, "awsnfw.sid": parsed.sid}
            rule.log_end = action != "pass"
            return [_Reading(_FIRST, rule, ("tcp", "other"), _key(parsed))]

    def _read(self, parsed: _Parsed) -> List[_Reading]:
        protocol = parsed.protocol
        unsupported: List[str] = []
        flow_dir, established = "", None  # "", "server", "client"; None, True, False
        ip_proto: Optional[int] = None
        ip_not: List[int] = []
        itypes: Optional[List[int]] = None
        icode: Optional[int] = None
        for key, value in parsed.options:
            if key in _NEUTRAL:
                continue
            if key == "flow":
                for word in (w.strip().lower() for w in value.split(",")):
                    if word in ("to_server", "from_client"):
                        flow_dir = "server" if flow_dir in ("", "server") else "both"
                    elif word in ("to_client", "from_server"):
                        flow_dir = "client" if flow_dir in ("", "client") else "both"
                    elif word == "established":
                        established = True
                    elif word == "not_established":
                        established = False
                    else:
                        unsupported.append(f"flow:{word}")
                if flow_dir == "both":
                    raise _Nothing("flow to the server and to the client at once matches no packet")
            elif key == "ip_proto" and re.fullmatch(r"\s*!?\s*\d{1,3}\s*", value) and int(value.strip(" !")) <= 255:
                number = int(value.strip(" !"))
                if "!" in value:
                    ip_not.append(number)
                elif ip_proto not in (None, number):
                    raise _Nothing("two ip_proto keywords that exclude each other match no packet")
                else:
                    ip_proto = number
            elif key == "itype" and _icmp_values(value) is not None:
                found = _icmp_values(value) or []
                itypes = [t for t in found if itypes is None or t in itypes]
            elif key == "icode" and re.fullmatch(r"\s*\d{1,3}\s*", value) and int(value) <= 255:
                icode = int(value)
            elif key in ("tls.sni", "http.host"):
                unsupported.append(f"{key}: the rule matches by domain name, which is not an address")
            else:
                unsupported.append(f"keyword {key}" + (f":{value[:40]}" if value else ""))
        app = _APPS.get(protocol)
        if protocol in _REFUSED_PROTOCOLS:
            raise _Bad(f"protocol {protocol} (Network Firewall does not support it)")
        if app is None and protocol not in ("ip", "tcp", "udp", "icmp", "icmpv4", "icmpv6"):
            raise _Bad(f"protocol {protocol[:20]}, which is not known")
        if ip_proto is not None and ip_proto in ip_not:
            raise _Nothing(f"ip_proto:{ip_proto} and ip_proto:!{ip_proto} match no packet")
        # ip_proto with a protocol: the protocol, or one of the two ICMPs, or nothing.
        if protocol == "ip" and ip_proto in (1, 58):
            protocol = "icmpv4" if ip_proto == 1 else "icmpv6"
        elif protocol == "icmp" and (ip_proto is not None or {1, 58} & set(ip_not)):
            remaining = [n for n in (1, 58) if n not in ip_not and ip_proto in (None, n)]
            if not remaining:
                raise _Nothing("protocol icmp with ip_proto that is no ICMP matches no packet")
            protocol = "icmp" if len(remaining) == 2 else ("icmpv4" if remaining == [1] else "icmpv6")
        if protocol != "ip":
            own = {"tcp": {6}, "udp": {17}, "icmp": {1, 58}, "icmpv4": {1}, "icmpv6": {58}}.get(protocol) or (
                {6, 17} if app is None else {6 if t == "tcp" else 17 for t in app[1]})
            if (ip_proto is not None and ip_proto not in own) or own <= set(ip_not):
                raise _Nothing(f"protocol {protocol} with ip_proto that excludes it matches no packet")
            if ip_not and not own.isdisjoint(ip_not):
                unsupported.append(f"protocol {protocol} with ip_proto:!" + ",!".join(str(n) for n in ip_not))
            ip_proto, ip_not = None, []
        if (itypes is not None or icode is not None) and not protocol.startswith("icmp"):
            unsupported.append("itype or icode with a protocol other than ICMP")
        if icode is not None and itypes is None:
            unsupported.append("icode without itype")
        if itypes is not None and not itypes:
            raise _Nothing("itype that matches no ICMP type")
        src = self._address(parsed.src, parsed.group)
        dst = self._address(parsed.dst, parsed.group)
        sport = self._ports(parsed.sport, parsed.group)
        dport = self._ports(parsed.dport, parsed.group)
        if (sport or dport) and protocol in ("ip", "icmp", "icmpv4", "icmpv6"):
            raise _Bad(f"ports with protocol {protocol}")
        transports: Tuple[str, ...]
        if app is not None:
            transports = ("tcp",) if app[1] == ("tcp",) else ("tcp", "other") if "tcp" in app[1] else ("other",)
        elif protocol == "tcp" or (protocol == "ip" and ip_proto == 6):
            transports = ("tcp",)
        elif protocol == "ip" and ip_proto is None and 6 not in ip_not:
            transports = ("tcp", "other")
        else:
            transports = ("other",)
        action = {"pass": Action.ALLOW, "drop": Action.DROP, "reject": Action.RESET_CLIENT}[parsed.action]
        reject_not_tcp = parsed.action == "reject" and transports != ("tcp",)
        if reject_not_tcp:
            action = Action.DROP
        # When the flow can be decided: the first packet, or for TCP once it is established.
        if established is None:
            later = app is not None and app[1] == ("tcp",)
        else:
            later = established
            if app is not None and not established:
                raise _Bad(f"flow:not_established with application protocol {protocol}, which is identified once data flows")
        orientations = [(src, sport, dst, dport, "")]
        if parsed.both:
            orientations.append((dst, dport, src, sport, "-rev"))
        out: List[_Reading] = []
        base = self._base_name(parsed)
        key = _key(parsed)
        for o_src, o_sport, o_dst, o_dport, suffix in orientations:
            for mirror in (False, True):
                if (mirror and flow_dir == "server") or (not mirror and flow_dir == "client"):
                    continue
                if mirror and parsed.both and not flow_dir and itypes is None:
                    continue  # (both directions: what a reply matches, the other direction matches on the first packet)
                side_src, side_dst = (o_dst, o_src) if mirror else (o_src, o_dst)
                moment = (_ESTABLISHED_REPLY if later else _REPLY) if mirror else (_ESTABLISHED if later else _FIRST)
                # A reset goes to the sender of the packet that matched: for a reply, the server.
                verdict = Action.RESET_SERVER if mirror and action == Action.RESET_CLIENT else action
                parts = self._services(protocol, app, o_sport, o_dport, ip_proto, ip_not, itypes, icode, mirror)
                for part, (services, negated) in enumerate(parts):
                    name = base + suffix + ("-reply" if mirror else "") + ("-icmp" if part else "")
                    rule = Rule(name, sources=side_src[0], destinations=side_dst[0], action=verdict)
                    rule.negate_source, rule.negate_destination = side_src[1], side_dst[1]
                    rule.services, rule.negate_service = services, negated
                    if app is not None:
                        rule.applications = [app[0]]
                    rule.unsupported = list(dict.fromkeys(unsupported + [p for p in (side_src[2], side_dst[2]) if p]))
                    rule.enabled = not parsed.disabled
                    rule.description = parsed.message
                    rule.log_end = parsed.action != "pass"
                    rule.source_ids = {"awsnfw.rule_group": parsed.group.name, "awsnfw.sid": parsed.sid}
                    reading = _Reading(moment, rule, transports, key,
                                       any_state=established is None and not later and parsed.option("flow") is not None,
                                       both_ways=parsed.both and not flow_dir and itypes is None)  # fmt: skip
                    if mirror:
                        rule.source_ids["awsnfw.reading"] = "reply"
                        reading.findings.append((Severity.INFO, "AWSNFW_REPLY_READING",
                                                 f"rule {base} matches packets in the direction of its header, so also the first reply of "
                                                 "a connection opened the other way" + ("" if flow_dir else " (it has no flow:to_server)")
                                                 + "; this rule is what it decides then"))  # fmt: skip
                    if app is not None and len(app[1]) > 1:
                        reading.findings.append((Severity.APPROX, "AWSNFW_APP_TIMING",
                                                 f"{protocol} over UDP is identified on the first packet, over TCP once data flows; the "
                                                 "converted rule decides both on the first packet, so over TCP it may decide a connection "
                                                 "that a rule below it, or the default action, decides on the firewall"))  # fmt: skip
                    if reject_not_tcp:
                        reading.findings.append((Severity.INFO, "AWSNFW_REJECT_NOT_TCP",
                                                 "reject sends a TCP reset, and is for TCP only; the rule, which matches other protocols "
                                                 "too, is read as drop"))  # fmt: skip
                    out.append(reading)
        return out

    def _services(self, protocol: str, app: Optional[Tuple[str, Tuple[str, ...]]], sport: List[Tuple[int, int]],
                  dport: List[Tuple[int, int]], ip_proto: Optional[int], ip_not: List[int], itypes: Optional[List[int]],
                  icode: Optional[int], mirror: bool) -> List[Tuple[List[str], bool]]:  # fmt: skip
        """The services of a reading: (services, negated) for each rule it becomes; none when nothing has such a reply."""
        if mirror:
            sport, dport = dport, sport
        if protocol == "ip":
            if ip_proto is not None:
                return [([self._service([_ip_entry(ip_proto)])], False)]
            excluded = sorted(set(ip_not))
            if not mirror:
                return [([self._service([_ip_entry(n) for n in excluded])], True)] if excluded else [([ANY], False)]
            # The reply of an ICMP message that is no request is none: such a connection is not decided on its reply.
            out = [([self._service([_ip_entry(n) for n in sorted(set(excluded) | {1, 58})])], True)]
            families = [name for name, number in (("icmpv4", 1), ("icmpv6", 58)) if number not in excluded]
            for family in families:
                out += self._services(family, None, [], [], None, [], None, None, True)
            return out
        if protocol.startswith("icmp"):
            kinds = [Protocol.ICMP, Protocol.ICMP6] if protocol == "icmp" else [Protocol.ICMP if protocol == "icmpv4" else Protocol.ICMP6]
            entries: List[ServiceEntry] = []
            for kind in kinds:
                number = 1 if kind == Protocol.ICMP else 58
                if not mirror:
                    wanted: List[Optional[int]] = list(itypes) if itypes is not None else [None]
                    for kind_type in wanted:
                        entries.append(ServiceEntry(kind, icmp_type=kind_type, icmp_code=icode if kind_type is not None else None))
                    continue
                for request, reply in _REPLY_TYPE[number].items():
                    if itypes is None or reply in itypes:
                        entries.append(ServiceEntry(kind, icmp_type=request, icmp_code=icode if itypes is not None else None))
            return [([self._service(entries)], False)] if entries else []
        transports = app[1] if app is not None else (protocol,)
        if app is not None and not sport and not dport:
            return [([ANY], False)]
        entries = []
        for transport in transports:
            kind = Protocol.TCP if transport == "tcp" else Protocol.UDP
            entries.append(ServiceEntry(kind, _port_text(dport or _ALL_PORTS), _port_text(sport or _ALL_PORTS)))
        return [([self._service(entries)], False)]

    # -- addresses and ports of a stateful rule ------------------------------------------------

    def _address(self, text: str, group: _Group) -> Tuple[List[str], bool, str]:
        """(members, negated, why it cannot be converted)."""
        node = _address_node(text)
        if node.kind == "any":
            return [ANY], False, ""
        negated, inner = False, node
        if node.kind == "not":
            negated, inner = True, node.items[0]
        items = inner.items if inner.kind == "list" else [inner]
        if all(item.kind in ("lit", "var", "ref") for item in items):
            members: List[str] = []
            plain = True
            for item in items:
                if item.kind == "lit":
                    members.append(interval_text(item.value))
                    continue
                name, flipped, problem = self._named(item, group)
                if problem:
                    return [name or ANY], negated, problem
                if flipped:
                    plain = False
                    break
                members.append(name)
            if plain:
                return members, negated, ""
            if len(items) == 1:  # (the policy's EXTERNAL_NET, which is the negation of HOME_NET)
                name, _, _ = self._named(items[0], group)
                return [name], not negated, ""
        found = self._intervals(node, group)
        if found is None:
            return [ANY], False, f"address '{text[:80]}' names something whose addresses are not known"
        found = normalize(found)
        if found == _EVERYTHING:
            return [ANY], False, ""
        if not found:
            raise _Nothing(f"address '{text[:80]}' holds no address")
        return [interval_text(i) for i in found], False, ""

    def _named(self, node: _Node, group: _Group) -> Tuple[str, bool, str]:
        """A variable or a reference: (address group, whether it stands for its negation, why it cannot be read)."""
        if node.kind == "ref":
            return self._reference(node.value, group)
        name = str(node.value)
        variables = _dict(group.body.get("RuleVariables"))
        sets = _dict(variables.get("IPSets"))
        if name in sets:
            definition = sets[name].get("Definition") if isinstance(sets[name], dict) else None
            found = self._definition(definition)
            if found is None:
                holder = self._object_name(f"{name}-{group.name}")
                self.p.address_groups[holder] = AddressGroup(holder, unsupported=f"IP set variable {name} of rule group {group.name} "
                                                                                 "cannot be read")  # fmt: skip
                return holder, False, ""
            return self._variable_group(name, found, group.name), False, ""
        if name == "HOME_NET":
            return self._home_name(), False, ""
        if name == "EXTERNAL_NET":
            return self._home_name(), True, ""
        return "", False, f"variable ${name} is not defined in rule group {group.name}"

    def _reference(self, name: str, group: _Group) -> Tuple[str, bool, str]:
        sets = _dict(group.body.get("ReferenceSets"))
        references = _dict(sets.get("IPSetReferences"))
        item = references.get(name)
        if not isinstance(item, dict):
            return "", False, f"IP set reference @{name} is not defined in rule group {group.name}"
        arn = str(item.get("ReferenceArn") or "")
        if arn in self.references:
            return self.references[arn], False, ""
        found = re.search(r":prefix-list/(pl-[0-9a-zA-Z]+)$", arn)
        ident = found.group(1) if found else ""
        holder = self._object_name(self.found.prefix_names.get(ident) or name)
        self.references[arn] = holder
        node = AddressGroup(holder, description=f"IP set reference @{name}: {arn}")
        if not ident:
            node.unsupported = (f"IP set reference @{name} is a resource group ({arn[:120]}), whose addresses only AWS knows"
                                if ":resource-groups:" in arn else f"IP set reference @{name} ({arn[:120]}) cannot be read")
        elif ident not in self.found.prefix_entries:
            node.unsupported = (f"the entries of prefix list {ident} are not in the input (add the answer of aws ec2 "
                                "get-managed-prefix-list-entries, wrapped with its PrefixListId)")  # fmt: skip
        else:
            intervals = [parse_literal(str(e.get("Cidr", ""))) for e in self.found.prefix_entries[ident]]
            if not intervals or any(i is None for i in intervals):
                node.unsupported = f"prefix list {ident} has no entries, or one that cannot be read"
            else:
                node.members = [interval_text(i) for i in normalize([i for i in intervals if i is not None])]
        self.p.address_groups[holder] = node
        return holder, False, ""

    def _intervals(self, node: _Node, group: _Group) -> Optional[List[Interval]]:
        if node.kind == "any":
            return list(_EVERYTHING)
        if node.kind == "lit":
            return [node.value]
        if node.kind in ("var", "ref"):
            name, flipped, problem = self._named(node, group)
            if problem:
                return None
            group_node = self.p.address_groups.get(name)
            if group_node is None or group_node.unsupported:
                return None
            found: List[Interval] = []
            for member in group_node.members:
                interval = parse_literal(member)
                if interval is None:
                    return None
                found.append(interval)
            found = normalize(found)
            return subtract(_EVERYTHING, found) if flipped else found
        if node.kind == "not":
            inner = self._intervals(node.items[0], group)
            return None if inner is None else subtract(_EVERYTHING, inner)
        positives: List[Interval] = []
        negatives: List[Interval] = []
        any_positive = False
        for item in node.items:
            if item.kind == "not":
                found_neg = self._intervals(item.items[0], group)
                if found_neg is None:
                    return None
                negatives += found_neg
            else:
                found_pos = self._intervals(item, group)
                if found_pos is None:
                    return None
                positives += found_pos
                any_positive = True
        if not any_positive:
            positives = list(_EVERYTHING)
        return subtract(normalize(positives), normalize(negatives))

    def _ports(self, text: str, group: _Group) -> List[Tuple[int, int]]:
        """The ports of a side; [] for every port."""
        found = self._port_ranges(_port_node(text), group)
        if found == _ALL_PORTS:
            return []
        if not found:
            raise _Nothing(f"port '{text[:60]}' holds no port")
        return found

    def _port_ranges(self, node: _Node, group: _Group, depth: int = 0) -> List[Tuple[int, int]]:
        if depth > 10:
            raise _Bad("port variables that refer to each other")
        if node.kind == "any":
            return list(_ALL_PORTS)
        if node.kind == "range":
            return [node.value]
        if node.kind == "var":
            variables = _dict(group.body.get("RuleVariables"))
            sets = _dict(variables.get("PortSets"))
            item = sets.get(node.value)
            if not isinstance(item, dict):
                raise _Bad(f"port variable ${node.value} is not defined in rule group {group.name}")
            definitions = [str(d) for d in _list(item.get("Definition"))]
            if not definitions:
                raise _Bad(f"port variable ${node.value} has no ports")
            text = definitions[0] if len(definitions) == 1 else "[" + ",".join(definitions) + "]"
            return self._port_ranges(_port_node(text), group, depth + 1)
        if node.kind == "not":
            return _ports_minus(list(_ALL_PORTS), self._port_ranges(node.items[0], group, depth))
        positives: List[Tuple[int, int]] = []
        negatives: List[Tuple[int, int]] = []
        any_positive = False
        for item in node.items:
            if item.kind == "not":
                negatives += self._port_ranges(item.items[0], group, depth)
            else:
                positives += self._port_ranges(item, group, depth)
                any_positive = True
        if not any_positive:
            positives = list(_ALL_PORTS)
        return _ports_minus(regions.merge_ranges(positives), regions.merge_ranges(negatives))

    # -- notes ----------------------------------------------------------------------------

    def _notes(self) -> None:
        if self.body.get("TLSInspectionConfigurationArn"):
            self.report.note(Severity.INFO, "AWSNFW_TLS_INSPECTION",
                             "the policy decrypts TLS (a TLS inspection configuration): rules that look into the payload see decrypted "
                             "traffic; what the converted rules match by address and port does not change")  # fmt: skip
        validation = self.body.get("Route53ResolvedIPValidation")
        if isinstance(validation, dict) and validation:
            self.report.note(Severity.REVIEW, "AWSNFW_RESOLVED_IP_VALIDATION",
                             "the policy checks that destinations of domain rules were resolved by Route 53 Resolver; that is not "
                             "converted")  # fmt: skip
        custom = bool(_list(self.body.get("StatelessCustomActions")))
        for group in self.groups.values():
            source = _dict(group.body.get("RulesSource"))
            inner = _dict(source.get("StatelessRulesAndCustomActions"))
            custom = custom or bool(_list(inner.get("CustomActions")))
        if custom:
            self.report.note(Severity.INFO, "AWSNFW_CUSTOM_ACTIONS",
                             "custom actions publish metrics to CloudWatch; they decide nothing and are not converted")  # fmt: skip
        missing = [g.name for g in self.groups.values() if g.kind == "missing"]
        if missing:
            self.report.note(Severity.REVIEW, "AWSNFW_GROUP_MISSING",
                             "the policy names rule groups that are not in the input: " + ", ".join(missing[:10])
                             + ". Their rules are not converted; add the answers of describe-rule-group")  # fmt: skip
        if self.home_group and self.home is None:
            self.report.note(Severity.REVIEW, "AWSNFW_HOME_NET_UNKNOWN",
                             "rules name HOME_NET (or EXTERNAL_NET, its negation), which is the CIDR of the inspection VPC unless the "
                             "policy sets it; neither is in the input, and those rules are not converted. Add the answer of aws ec2 "
                             "describe-vpcs for the firewall's VPC")  # fmt: skip
        elif self.home_group:
            self.report.note(Severity.INFO, "AWSNFW_HOME_NET",
                             f"HOME_NET is {', '.join(self.p.address_groups[self.home_group].members[:6])} ({self.home_from}); "
                             "EXTERNAL_NET is everything else, unless a rule group sets it")  # fmt: skip
        self.report.note(Severity.INFO, "AWSNFW_NO_ZONES",
                         "the firewall sits in a route path and names no zones or interfaces: the converted policy has none. A "
                         "target with zones needs the networks behind them (--zone-network)")  # fmt: skip


def _key(parsed: _Parsed) -> str:
    return f"{parsed.group.name}\x1f{parsed.index}\x1f{id(parsed)}"


def _icmp_values(value: str) -> Optional[List[int]]:
    """The ICMP types of ``itype``: ``N``, ``<N``, ``>N`` or ``N<>M`` (the comparisons of Suricata are strict); None when the
    value cannot be read."""
    text = value.replace(" ", "")
    found = re.fullmatch(r"(\d{1,3})", text)
    if found:
        return [int(found.group(1))] if int(found.group(1)) <= 255 else None
    found = re.fullmatch(r"([<>])(\d{1,3})", text)
    if found:
        bound = int(found.group(2))
        return list(range(0, min(bound, 256))) if found.group(1) == "<" else list(range(bound + 1, 256))
    found = re.fullmatch(r"(\d{1,3})<>(\d{1,3})", text)
    if found:
        return list(range(int(found.group(1)) + 1, min(int(found.group(2)), 256)))
    return None


def _ip_entry(number: int) -> ServiceEntry:
    if number == 6:
        return ServiceEntry(Protocol.TCP)
    if number == 17:
        return ServiceEntry(Protocol.UDP)
    if number == 1:
        return ServiceEntry(Protocol.ICMP)
    if number == 58:
        return ServiceEntry(Protocol.ICMP6)
    if number == 132:
        return ServiceEntry(Protocol.SCTP)
    return ServiceEntry(Protocol.IP, ip_protocol=number)


def _side_text(intervals: List[Interval]) -> List[str]:
    if normalize(intervals) == _EVERYTHING:
        return [ANY]
    return [interval_text(i) for i in intervals] or [ANY]


def _same(a: regions.Services, b: regions.Services) -> bool:
    return a.minus(b).empty() and b.minus(a).empty()


def _boxes_and(a: Sequence[regions.Box], b: Sequence[regions.Box]) -> List[regions.Box]:
    return [piece for x in a for y in b for piece in [regions.box_and(x, y)] if piece is not None]


def _mirror_box(box: regions.Box) -> Optional[regions.Box]:
    """The connections whose replies are in ``box``: sources and destinations exchanged, ports too, an ICMP request for
    its reply. None when there are none."""
    version, src, dst, svc = box
    numbers = set(svc.protocols) | ({6, 17, 132, 1, 58} if svc.rest else set())
    out: Dict[int, List[Tuple[int, int, int, int]]] = {}
    for number in numbers:
        rects = svc.of(number)
        if number in (6, 17, 132):
            out[number] = [(r[2], r[3], r[0], r[1]) for r in rects]
        elif number in (1, 58):
            mapped: List[Tuple[int, int, int, int]] = []
            for rect in rects:
                for request, reply in _REPLY_TYPE[number].items():
                    if rect[0] <= reply <= rect[1]:
                        mapped.append((request, request, rect[2], rect[3]))
            out[number] = mapped
        else:
            out[number] = list(rects)
    mirrored = regions.Services(out, svc.rest)
    if mirrored.empty():
        return None
    return (version, list(dst), list(src), mirrored)


def _meets_nothing(box: regions.Box) -> bool:
    """Whether a box holds no connection: no address, or only the ICMP of the other IP version."""
    if regions.empty(box):
        return True
    foreign = 58 if box[0] == 4 else 1
    svc = box[3]
    return not svc.rest and all(not rects for number, rects in svc.protocols.items() if number != foreign)


def _icmp_apart(box: regions.Box) -> List[regions.Box]:
    """Every protocol but some ICMP types, as two boxes: every protocol but ICMP, and the ICMP types. Both are short to
    write; together they are long."""
    version, src, dst, svc = box
    icmp = 1 if version == 4 else 58
    if not svc.rest or icmp not in svc.protocols or svc.of(icmp) == [regions.WHOLE]:
        return [box]
    rest = regions.Services({**svc.protocols, icmp: []}, True)
    only = regions.Services({icmp: svc.of(icmp)}, False)
    return [b for b in ((version, src, dst, rest), (version, src, dst, only)) if not regions.empty(b)]


def _associated(block: Dict[str, Any], key: str) -> bool:
    state = block.get(key)
    return not isinstance(state, dict) or str(state.get("State", "associated")) == "associated"
