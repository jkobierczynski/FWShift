# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Check Point parser: Management API output (JSON) -> neutral model.

Check Point has no configuration file. The input is what the Management API
returns for ``show access-rulebase`` and ``show nat-rulebase`` with
``details-level full`` and ``use-object-dictionary true``: one response, or a
JSON array of responses (further pages, the NAT rulebase, inline layers, extra
object listings).

How Check Point behaviour is mapped onto the neutral model:

* Rules match the original packet, as the model does: nothing to rewrite for NAT.
* There are no zone columns. A security-zone object in the source or
  destination column becomes the zone of the rule; a column that mixes zones
  and addresses means "either", which the model cannot say.
* An inline layer is flattened: each of its rules is combined with the rule
  that applies the layer, followed by the layer's implicit cleanup when the
  layer does not end in a rule that matches everything.
* One ordered layer is converted per run; implied rules are not in the export.
* Objects of a data domain ("Check Point Data") are marked as predefined.
* An object with automatic static NAT stands for its translated address as
  well, wherever a rule or a group names it. Manual NAT has no such effect:
  there the rules name the address of the original packet themselves.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..appmap import valid_ports
from ..errors import ParseError
from ..model import (
    ANY,
    APP_DEFAULT,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    DestNat,
    L4_PROTOCOLS,
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
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, is_number, normalize, parse_literal, range_text
from ..report import Report, Severity

Obj = Dict[str, Any]

# Reject answers the client (a TCP reset or an ICMP error): the nearest action of the model.
_ACTIONS = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.RESET_CLIENT}
_OBJECT_LISTS = ("objects-dictionary", "objects", "access-layers")
_NOT_EXPORTED = "is not in the export in full (export with details-level full and dereference-group-members true)"
# Objects that stand for a device with interfaces of its own. Any other type that is not known
# below is unsupported, whatever fields it has: a wildcard object has an "ipv4-address" too.
_GATEWAY_TYPES = {
    "simple-gateway", "simple-cluster", "cluster-member", "checkpoint-host", "interoperable-device",
    "CpmiGatewayCluster", "CpmiClusterMember", "CpmiGatewayPlain", "CpmiHostCkp", "CpmiVsClusterNetobj",
    "CpmiVsNetobj", "CpmiVsxClusterNetobj", "CpmiVsxNetobj", "CpmiVsxClusterMember",
}  # fmt: skip
# Fields of an access rule that are read, or that say nothing about what the rule matches.
_RULE_FIELDS = {
    "uid", "name", "type", "domain", "rule-number", "enabled", "comments", "source", "source-negate", "destination",
    "destination-negate", "service", "service-negate", "service-resource", "vpn", "content", "content-negate",
    "content-direction", "time", "action", "action-settings", "inline-layer", "track", "install-on", "user-check",
    "custom-fields", "meta-info", "hits", "layer", "tags", "color", "icon", "read-only", "from", "to", "position",
    "available-actions", "source-ranges", "destination-ranges", "service-ranges",
}  # fmt: skip
_MAX_RULES = 50000
_MAX_NESTING = 30
_RESERVED_NAMES = (ANY, APP_DEFAULT)
_MAX_DEPTH = 8


def _ports(text: str) -> Optional[str]:
    """``80``, ``8000-8080``, ``>1023``, ``<1024`` -> model syntax; None if unreadable."""
    text = str(text).strip()
    if text.startswith(">") and is_number(text[1:]):
        text = f"{int(text[1:]) + 1}-65535"
    elif text.startswith("<") and is_number(text[1:]):
        text = f"1-{int(text[1:]) - 1}"
    return text if text and valid_ports(text) else None


def _responses(document: Any, depth: int = 0) -> List[Obj]:
    """Every API response in the input: one object, an array, or an object holding responses."""
    if depth > _MAX_NESTING:
        return []
    if isinstance(document, list):
        return [r for item in document for r in _responses(item, depth + 1)]
    if not isinstance(document, dict):
        return []
    if "rulebase" in document or any(key in document for key in _OBJECT_LISTS):
        return [document]
    return [r for value in document.values() if isinstance(value, (dict, list)) for r in _responses(value, depth + 1)]


def _rules_of(rulebase: List[Any], rule_type: str, depth: int = 0) -> List[Tuple[Obj, str]]:
    """(rule, section name) for every rule of a rulebase, sections flattened."""
    out: List[Tuple[Obj, str]] = []
    for entry in rulebase:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("rulebase"), list) and depth < _MAX_NESTING:
            inner = _rules_of(entry["rulebase"], rule_type, depth + 1)
            out += [(rule, str(entry.get("name") or "")) for rule, _ in inner]
        elif entry.get("type") == rule_type:
            out.append((entry, ""))
    return out


def _catch_all(rule: Rule) -> bool:
    """True for an enabled rule that matches every packet."""
    return (
        rule.enabled
        and not rule.unsupported
        and not rule.schedule
        and rule.src_zones == rule.dst_zones == rule.sources == rule.destinations == rule.services == [ANY]
        and not (rule.negate_source or rule.negate_destination or rule.negate_service)
    )


def _port_ranges(entries: List[ServiceEntry]) -> Optional[Dict[Protocol, List[Tuple[int, int]]]]:
    """Destination port ranges per protocol; None when the entries are not plain TCP/UDP/SCTP ports."""
    out: Dict[Protocol, List[Tuple[int, int]]] = {}
    for entry in entries:
        if entry.protocol not in L4_PROTOCOLS or entry.src_ports:
            return None
        for part in (entry.dst_ports or "1-65535").split(","):
            first, _, last = part.partition("-")
            out.setdefault(entry.protocol, []).append((int(first), int(last or first)))
    return out


def _intersect(a: List[Interval], b: List[Interval]) -> List[Interval]:
    out = [(x[0], max(x[1], y[1]), min(x[2], y[2])) for x in a for y in b if x[0] == y[0] and x[1] <= y[2] and y[1] <= x[2]]
    return normalize(out)


def _subtract(a: List[Interval], b: List[Interval]) -> List[Interval]:
    """What is left of ``a`` without the addresses of ``b``; both merged and sorted."""
    out: List[Interval] = []
    for version, first, last in a:
        for other_version, low, high in b:
            if other_version != version or high < first or low > last:
                continue
            if low > first:
                out.append((version, first, low - 1))
            first = high + 1
            if first > last:
                break
        if first <= last:
            out.append((version, first, last))
    return normalize(out)


def _literal(interval: Interval) -> str:
    """``10.0.0.0/24`` where the interval is one network, else ``first-last``."""
    version, first, last = interval
    networks = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
    return str(networks[0]) if len(networks) == 1 else range_text(interval)


def parse(data: bytes, report: Report, layer: str = "") -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ParseError(f"not valid JSON: {exc}") from None
    except RecursionError:
        raise ParseError("not usable JSON: nested too deeply") from None
    responses = _responses(document)
    if not responses:
        raise ParseError(
            "no Management API response found; expected the JSON output of 'show access-rulebase' "
            "(optionally in an array with 'show nat-rulebase' and further pages)"
        )
    try:
        return _Builder(responses, report, layer).build()
    except (TypeError, AttributeError, KeyError, IndexError, ValueError) as exc:
        # The fields that are read are checked where they are read; this is for a shape nobody thought of.
        raise ParseError(f"the export is not shaped like Management API output ({type(exc).__name__}: {exc})") from None


class _Builder:
    def __init__(self, responses: List[Obj], report: Report, layer: str) -> None:
        self.report = report
        self.wanted_layer = layer
        self.p = Policy(vendor="checkpoint", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.objects: Dict[str, Obj] = {}
        self.layers: Dict[str, List[Tuple[Obj, str]]] = {}  # layer uid or name -> rules, pages in order
        self.layer_names: Dict[str, str] = {}
        self.nat: List[Tuple[Obj, str]] = []
        self.address_names: Dict[str, str] = {}  # uid -> name in the model, for objects already converted
        self.service_names: Dict[str, str] = {}
        self.taken_addresses: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.totals: Dict[str, int] = {}  # layer -> number of rules the server says it has
        self.nat_total = 0
        self.expanded = 0  # rules written so far, inline layers flattened
        self.signature_services: Set[str] = set()  # services that also check the protocol itself
        self.gateways: Set[str] = set()  # model names of gateway and cluster objects
        # Objects with automatic NAT -> the object for the address they are translated to.
        self.valid: Dict[str, str] = {}  # static NAT: "Valid Address"
        self.hiding: Dict[str, str] = {}  # hide NAT behind an address: "Hiding Address"
        self._index(responses)

    def _index(self, responses: List[Obj]) -> None:
        pages: Dict[str, List[Tuple[int, List[Tuple[Obj, str]]]]] = {}
        nat_pages: List[Tuple[int, List[Tuple[Obj, str]]]] = []
        for response in responses:
            for key in _OBJECT_LISTS:
                listed = response.get(key)
                for obj in listed if isinstance(listed, list) else []:
                    if isinstance(obj, dict) and isinstance(obj.get("uid"), str) and obj["uid"]:
                        known = self.objects.get(obj["uid"], {})
                        self.objects[obj["uid"]] = obj if len(obj) >= len(known) else known
            rulebase = response.get("rulebase")
            if not isinstance(rulebase, list):
                continue
            start = response.get("from")
            start = start if isinstance(start, int) else 0
            access, nat = _rules_of(rulebase, "access-rule"), _rules_of(rulebase, "nat-rule")
            kinds = {str(entry.get("type")) for entry in rulebase if isinstance(entry, dict)}
            total = response.get("total")
            total = total if isinstance(total, int) and not isinstance(total, bool) else 0
            # A NAT rulebase has no name; an empty one has nothing else to tell it by.
            if nat or "nat-section" in kinds or (not kinds and not response.get("name")):
                nat_pages.append((start, nat))
                self.nat_total = max(self.nat_total, total)
            # An empty access layer has nothing to tell it by but its name; a NAT rulebase has none.
            if access or "access-section" in kinds or (not kinds and response.get("name")):
                identity = response.get("uid") or response.get("name") or ""
                identity = identity if isinstance(identity, str) else json.dumps(identity)
                pages.setdefault(identity, []).append((start, access))
                self.layer_names[identity] = str(response.get("name") or identity)
                self.totals[identity] = max(self.totals.get(identity, 0), total)
        for identity, parts in pages.items():
            self.layers[identity] = self._in_order(parts)
        self.nat = self._in_order(nat_pages)
        self.has_nat_rulebase = bool(nat_pages)

    @staticmethod
    def _in_order(parts: List[Tuple[int, List[Tuple[Obj, str]]]]) -> List[Tuple[Obj, str]]:
        """Rules of all pages, by position; a page that is in the input twice counts once."""
        out: List[Tuple[Obj, str]] = []
        seen: Set[str] = set()
        for _, rules in sorted(parts, key=lambda part: part[0]):
            for rule, section in rules:
                uid = rule.get("uid")
                if isinstance(uid, str) and uid in seen:
                    continue
                seen.update([uid] if isinstance(uid, str) else [])
                out.append((rule, section))
        return out

    # -- top level ----------------------------------------------------------

    def build(self) -> Policy:
        layer = self._main_layer()
        self.p.scope = self.layer_names.get(layer, layer) if layer else ""
        if layer:
            self.p.rules = self._layer(layer, (layer,))
            self._implicit_cleanup(layer)
        for index, (entry, _) in enumerate(self.nat, 1):
            self.p.nat_rules.append(self._nat_rule(entry, index))
        for zone in transform.dedupe(
            [z for r in self.p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        ):
            self.p.zones[zone] = Zone(zone)
        self.report.note(
            Severity.REVIEW,
            "IMPLIED_RULES",
            "Check Point implied rules (global properties) and the other ordered layers of the policy package "
            "are not part of the export; only the rules of one layer were read"
            + (f" ('{self.p.scope}')" if self.p.scope else ""),
        )
        short = [
            f"layer '{self.layer_names.get(identity, identity)}' ({len(rules)} of {self.totals[identity]} rules)"
            for identity, rules in self.layers.items()
            if len(rules) < self.totals.get(identity, 0)
        ]
        if len(self.nat) < self.nat_total:
            short.append(f"the NAT rulebase ({len(self.nat)} of {self.nat_total} rules)")
        if short:
            self.report.note(
                Severity.REVIEW,
                "INCOMPLETE_EXPORT",
                "pages are missing from the export: " + ", ".join(short) + ". The rules that are not in the input "
                "are not in the output either: what they denied is allowed by the rules that follow them. Export "
                "every page (offset) and convert again",
            )
        if not self.has_nat_rulebase:
            self.report.note(
                Severity.REVIEW,
                "NO_NAT_RULEBASE",
                "the input holds no NAT rulebase ('show nat-rulebase'): no NAT rule was read, automatic ones included",
            )
        if self.p.rules and not self.p.zones:
            self.report.note(
                Severity.INFO,
                "NO_ZONES",
                "the rules name no security zones, so the converted rules apply from any zone to any zone; "
                "the addresses alone decide, as they do on Check Point",
            )
        return self.p

    def _implicit_cleanup(self, layer: str) -> None:
        """What the layer does with traffic no rule matches, when its rules leave any."""
        if self.p.rules and _catch_all(self.p.rules[-1]):
            return
        action = str(self._object(layer).get("implicit-cleanup-action") or "").lower()
        name = self.layer_names.get(layer, layer)
        if action == "accept":
            self.p.default_intrazone = self.p.default_interzone = Action.ALLOW
            self.report.note(
                Severity.REVIEW,
                "IMPLICIT_CLEANUP",
                f"layer '{name}' accepts traffic that none of its rules matches (implicit cleanup action accept)",
            )
        elif action != "drop":
            self.report.note(
                Severity.REVIEW,
                "IMPLICIT_CLEANUP",
                f"layer '{name}' does not end in a rule that matches everything and the export does not show its "
                "implicit cleanup action; drop, the default of a firewall layer, was assumed. Add the output of "
                "'show access-layers details-level full' to the input to have it read",
            )

    def _main_layer(self) -> str:
        if not self.layers:
            return ""
        if self.wanted_layer:
            for identity, name in self.layer_names.items():
                if self.wanted_layer in (identity, name) and identity in self.layers:
                    return identity
            raise ParseError(
                f"layer '{self.wanted_layer}' not found; available: " + ", ".join(sorted(self.layer_names.values()))
            )
        inline = {str(rule.get("inline-layer")) for rules in self.layers.values() for rule, _ in rules if rule.get("inline-layer")}
        top = [identity for identity in self.layers if identity not in inline]
        if len(top) != 1:
            names = sorted(self.layer_names[i] for i in (top or list(self.layers)))
            raise ParseError("the export holds several access layers; choose one with --layer: " + ", ".join(names))
        return top[0]

    # -- objects ------------------------------------------------------------

    def _object(self, ref: Any) -> Obj:
        """The object a rule cell refers to: a uid, or an object given in place."""
        if isinstance(ref, dict):
            known = self.objects.get(str(ref.get("uid")), {})
            return ref if len(ref) >= len(known) else known
        key = ref if isinstance(ref, str) else json.dumps(ref)
        return self.objects.get(key, {"uid": key})

    def _label(self, ref: Any) -> str:
        """Name of the object a field refers to; a value that is no uid is taken as the name itself."""
        if isinstance(ref, str) and ref not in self.objects:
            return ref
        return str(self._object(ref).get("name") or "")

    @staticmethod
    def _predefined(obj: Obj) -> str:
        """Objects of a data domain (Check Point Data, APPI Data, ...) come with the product."""
        domain = obj.get("domain")
        if not isinstance(domain, dict):
            return ""
        shipped = domain.get("domain-type") == "data domain" or domain.get("name") == "Check Point Data"
        return "checkpoint" if shipped else ""

    @staticmethod
    def _flag(entry: Obj, key: str, default: bool, problems: List[str]) -> bool:
        """A true/false field. A value that is neither is reported, and read as the cautious one of the two."""
        value = entry.get(key)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in ("true", "false"):
            return value.lower() == "true"
        problems.append(f"field '{key}' that is neither true nor false")
        return default

    def _name(self, obj: Obj, taken: Set[str]) -> str:
        name = str(obj.get("name") or obj.get("uid") or "unnamed")
        if name in _RESERVED_NAMES:
            name = f"{name}-object"
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    @staticmethod
    def _is_any(obj: Obj) -> bool:
        return obj.get("type") == "CpmiAnyObject" or (obj.get("name") == "Any" and "ipv4-address" not in obj)

    def _address(self, ref: Any) -> str:
        """Name of the model object for a network object, creating it on first use."""
        obj = self._object(ref)
        uid = str(obj.get("uid") or id(obj))
        if self._is_any(obj):
            return ANY
        if uid in self.address_names:
            return self.address_names[uid]
        name = self.address_names[uid] = self._name(obj, self.taken_addresses)
        kind = str(obj.get("type") or "")
        comment = str(obj.get("comments") or "")
        literals: List[str] = []
        if kind == "network":
            if obj.get("subnet4") is not None and obj.get("mask-length4") is not None:
                literals.append(f"{obj['subnet4']}/{obj['mask-length4']}")
            if obj.get("subnet6") is not None and obj.get("mask-length6") is not None:
                literals.append(f"{obj['subnet6']}/{obj['mask-length6']}")
        elif kind == "address-range":
            for version in ("ipv4", "ipv6"):
                first, last = obj.get(f"{version}-address-first"), obj.get(f"{version}-address-last")
                if first and last:
                    literals.append(f"{first}-{last}")
        elif kind == "group":
            listed = obj.get("members")
            members = self._also_valid([self._address(member) for member in (listed if isinstance(listed, list) else [])])
            self.p.address_groups[name] = AddressGroup(name, members, comment, builtin=self._predefined(obj))
            return name
        elif kind == "dns-domain":
            domain = str(obj.get("name") or "").lstrip(".")
            if obj.get("is-sub-domain"):
                return self._unsupported_address(name, f"DNS domain '{domain}' including its sub-domains", comment)
            self.p.addresses[name] = Address(name, AddressKind.FQDN, domain, comment, builtin=self._predefined(obj))
            return name
        elif kind == "host" or kind in _GATEWAY_TYPES:
            literals += [f"{obj[key]}" for key in ("ipv4-address", "ipv6-address") if obj.get(key)]
        else:
            what = f"object of type '{kind}'" if kind else f"object that {_NOT_EXPORTED}"
            return self._unsupported_address(name, what, comment)
        valid = [literal for literal in literals if parse_literal(literal) is not None]
        if not valid or len(valid) != len(literals):
            return self._unsupported_address(name, f"{kind} object that {_NOT_EXPORTED}", comment)
        existing = self._predefined(obj)
        if kind in _GATEWAY_TYPES:
            # A gateway is not created by a script: a Check Point target has to have it already.
            existing = "checkpoint"
            self.gateways.add(name)
            self.report.add(
                "address",
                name,
                Severity.APPROX,
                "GATEWAY_OBJECT",
                "a gateway object stands for every address of the gateway; only its main address "
                + " and ".join(literal.split("/")[0] for literal in valid) + " is in the export",
            )
        if len(valid) == 1:
            range_kind = AddressKind.RANGE if "-" in valid[0] else AddressKind.NETWORK
            value = valid[0] if range_kind == AddressKind.RANGE else str(ipaddress.ip_network(valid[0], strict=False))
            self.p.addresses[name] = Address(name, range_kind, value, comment, builtin=existing)
        else:
            # An object with an IPv4 and an IPv6 address: a group of the two.
            self.p.address_groups[name] = AddressGroup(name, valid, comment, builtin=existing)
        self._automatic_nat(obj, name, valid)
        return name

    def _automatic_nat(self, obj: Obj, name: str, literals: List[str]) -> None:
        """Give an object with automatic NAT a second object for the address it is translated to."""
        settings = obj.get("nat-settings")
        if not isinstance(settings, dict) or settings.get("auto-rule") is not True:
            return
        method = str(settings.get("method") or "").lower()
        if method == "hide" and settings.get("hide-behind") == "gateway":
            return  # the address of the gateway: no object for it
        first = parse_literal(str(settings.get("ipv4-address") or settings.get("ip-address") or ""))
        own = parse_literal(literals[0]) if len(literals) == 1 else None
        readable = first is not None and own is not None and first[1] == first[2] and method in ("static", "hide")
        if first is not None and own is not None and readable:
            # Static NAT gives as many addresses as the object has; they have to exist.
            span = own[2] - own[1] if method == "static" else 0
            readable = first[1] + span <= (FULL_V4 if first[0] == 4 else FULL_V6)[2] and (span == 0 or first[0] == own[0])
        if first is None or own is None or not readable:
            self.report.add(
                "address", name, Severity.REVIEW, "AUTOMATIC_NAT",
                "the object has automatic NAT settings that could not be read; NAT for it is not converted",
            )  # fmt: skip
            return
        translated = (first[0], first[1], first[1] + span)
        suffix = "hiding_address" if method == "hide" else "valid_address"
        companion = f"{name}_{suffix}"
        counter = 2
        while companion in self.taken_addresses:
            companion = f"{name}_{suffix}_{counter}"
            counter += 1
        self.taken_addresses.add(companion)
        value = _literal(translated)
        kind = AddressKind.RANGE if "-" in value else AddressKind.NETWORK
        self.p.addresses[companion] = Address(companion, kind, value, f"address automatic NAT gives {name}")
        (self.hiding if method == "hide" else self.valid)[name] = companion
        if method == "static":
            self.report.add(
                "address",
                name,
                Severity.INFO,
                "AUTOMATIC_NAT",
                f"the object has automatic static NAT to {range_text(translated)}: as on Check Point, rules and groups "
                f"that name it also match that address, written as '{companion}'",
            )

    def _reaches_valid(self, name: str) -> bool:
        """Whether a group holds, at any depth, the translated address of an automatic static NAT."""
        seen: Set[str] = set()
        todo = list(self.p.address_groups[name].members) if name in self.p.address_groups else []
        while todo:
            member = todo.pop()
            if member in self.valid.values():
                return True
            if member not in seen and member in self.p.address_groups:
                seen.add(member)
                todo += self.p.address_groups[member].members
        return False

    def _also_valid(self, names: List[str]) -> List[str]:
        """Each name, followed by the translated address of an object with automatic static NAT."""
        out: List[str] = []
        for name in names:
            out += [name, self.valid[name]] if name in self.valid else [name]
        return transform.dedupe(out)

    def _unsupported_address(self, name: str, what: str, comment: str) -> str:
        self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", comment, raw=what)
        self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{what} cannot be converted")
        return name

    def _service(self, ref: Any) -> str:
        obj = self._object(ref)
        uid = str(obj.get("uid") or id(obj))
        if self._is_any(obj):
            return ANY
        if uid in self.service_names:
            return self.service_names[uid]
        name = self.service_names[uid] = self._name(obj, self.taken_services)
        kind = str(obj.get("type") or "")
        comment = str(obj.get("comments") or "")
        if kind == "service-group":
            listed = obj.get("members")
            members = [self._service(member) for member in (listed if isinstance(listed, list) else [])]
            self.p.service_groups[name] = ServiceGroup(name, members, comment, builtin=self._predefined(obj))
            return name
        service = Service(name, [], comment, builtin=self._predefined(obj))
        if kind in ("service-tcp", "service-udp", "service-sctp"):
            ports = _ports(obj.get("port", ""))
            source = obj.get("source-port") or ""
            source_ports = _ports(source) if source else ""
            if ports is None or source_ports is None:
                service.unsupported = f"port '{obj.get('port', '')}' that could not be interpreted"
            else:
                service.entries.append(ServiceEntry(Protocol(kind.split("-")[1]), ports, source_ports))
            if obj.get("match-by-protocol-signature") is True:
                self.signature_services.add(name)
                self.report.add(
                    "service",
                    name,
                    Severity.APPROX,
                    "PROTOCOL_SIGNATURE",
                    "the service matches the port and the signature of its protocol; only the port is converted",
                )
        elif kind in ("service-icmp", "service-icmp6"):
            icmp_type, icmp_code = obj.get("icmp-type"), obj.get("icmp-code")
            if not isinstance(icmp_type, int) or isinstance(icmp_type, bool) or not 0 <= icmp_type <= 255:
                service.unsupported = f"ICMP service that {_NOT_EXPORTED}"  # never "every ICMP type"
            else:
                code = icmp_code if isinstance(icmp_code, int) and not isinstance(icmp_code, bool) else None
                protocol = Protocol.ICMP if kind == "service-icmp" else Protocol.ICMP6
                service.entries.append(ServiceEntry(protocol, icmp_type=icmp_type, icmp_code=code))
        elif kind == "service-other":
            number = obj.get("ip-protocol")
            if obj.get("match"):
                service.unsupported = "service with an INSPECT match expression"
            elif isinstance(number, int) and not isinstance(number, bool) and 0 < number < 256:
                service.entries.append(ServiceEntry(Protocol.IP, ip_protocol=number))
            else:
                service.unsupported = "service without a readable IP protocol"
        else:
            service.unsupported = f"object of type '{kind}'" if kind else f"object that {_NOT_EXPORTED}"
        if service.unsupported:
            self.report.add(
                "service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{service.unsupported}: not converted"
            )
        self.p.services[name] = service
        return name

    # -- access rules -----------------------------------------------------

    def _cells(self, entry: Obj, column: str) -> List[Obj]:
        value = entry.get(column)
        refs = value if isinstance(value, list) else [] if value is None else [value]
        return [self._object(ref) for ref in refs]

    def _address_column(self, entry: Obj, column: str, rule: Rule, negated: bool) -> Tuple[List[str], List[str]]:
        """(zones, addresses) of a source or destination column."""
        cells = self._cells(entry, column)
        if not cells:
            rule.unsupported.append(f"rule without {column}")
        zones = [str(cell.get("name")) for cell in cells if cell.get("type") == "security-zone"]
        others = [cell for cell in cells if cell.get("type") != "security-zone"]
        addresses = self._also_valid([self._address(cell) for cell in others])
        if ANY in addresses:
            addresses = [ANY]
        if zones and others:
            rule.unsupported.append(
                f"{column} that lists zones and addresses, meaning either of them: one rule cannot say that"
            )
        if zones and negated:
            rule.unsupported.append(f"negated zone in {column}")
        return (zones or [ANY]), (addresses or [ANY])

    def _rule(self, entry: Obj, section: str, number: int) -> Rule:
        name = str(entry.get("name") or "") or f"rule-{entry.get('rule-number') or number}"
        rule = Rule(name=name)
        rule.description = str(entry.get("comments") or "")
        rule.tags = [section] if section else []
        negated = {
            column: self._flag(entry, f"{column}-negate", False, rule.unsupported)
            for column in ("source", "destination", "service", "content")
        }
        rule.src_zones, rule.sources = self._address_column(entry, "source", rule, negated["source"])
        rule.dst_zones, rule.destinations = self._address_column(entry, "destination", rule, negated["destination"])
        rule.negate_source = negated["source"] and rule.sources != [ANY]
        rule.negate_destination = negated["destination"] and rule.destinations != [ANY]
        for column in ("source", "destination"):
            if negated[column] and getattr(rule, "sources" if column == "source" else "destinations") == [ANY]:
                if not any("negated zone" in text for text in rule.unsupported):
                    rule.unsupported.append(f"negated 'Any' in {column}")
        services = transform.dedupe([self._service(cell) for cell in self._cells(entry, "service")])
        if not services:
            rule.unsupported.append("rule without service")
        rule.services = [ANY] if ANY in services or not services else services
        rule.negate_service = negated["service"] and rule.services != [ANY]
        if negated["service"] and rule.services == [ANY]:
            rule.unsupported.append("negated 'Any' service")
        for column, label in (("vpn", "VPN community"), ("content", "content"), ("time", "time")):
            named = [str(cell.get("name") or cell.get("uid")) for cell in self._cells(entry, column) if not self._is_any(cell)]
            if not named:
                continue
            if column == "time":
                rule.schedule = ", ".join(named)
            else:
                rule.unsupported.append(f"{label} match {', '.join(named)}")
        if negated["content"]:
            rule.unsupported.append("negated content match")
        if entry.get("service-resource"):
            rule.unsupported.append(f"service resource {entry.get('service-resource')}")
        settings = entry.get("action-settings")
        if isinstance(settings, dict) and settings.get("enable-identity-captive-portal") is True:
            rule.unsupported.append("identity captive portal: the rule applies to users who have signed in only")

        action = self._label(entry.get("action"))
        if action.lower() in _ACTIONS:
            rule.action = _ACTIONS[action.lower()]
        else:
            rule.action = Action.DROP
            if not entry.get("inline-layer"):
                rule.unsupported.append(f"action '{action or 'unknown'}'")
        rule.enabled = self._flag(entry, "enabled", True, rule.unsupported)
        track = entry.get("track")
        track_type = self._label(track.get("type")) if isinstance(track, dict) else self._label(track)
        rule.log_end = (track_type or "None").lower() != "none"
        rule.log_start = False
        return rule

    def _reach(self, members: List[str], groups: Dict[str, Any]) -> Set[str]:
        """The members and everything they hold through groups."""
        names: Set[str] = set()
        todo = [member for member in members if member != ANY]
        while todo:
            name = todo.pop()
            if name not in names:
                names.add(name)
                todo += groups[name].members if name in groups else []
        return names

    def _note_objects(self, rule: Rule) -> None:
        """Say on the rule what its objects lose in the conversion, and which way that goes."""
        allow = rule.action == Action.ALLOW
        sides = ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination))
        for members, negated in sides:
            gateways = sorted(self._reach(members, self.p.address_groups) & self.gateways)
            if not gateways:
                continue
            # The converted rule knows one address of the gateway. Matching fewer addresses makes an
            # allow rule narrower and a deny rule weaker; in a negated cell it is the other way round.
            if negated:
                effect = "now also applies to its other addresses"
                wider = allow
            else:
                effect = "no longer applies to its other addresses"
                wider = not allow
            self.report.add(
                "rule",
                rule.origin,
                Severity.REVIEW if wider else Severity.APPROX,
                "GATEWAY_OBJECT",
                ("excludes" if negated else "matches") + " gateway object " + ", ".join(gateways) + ", which stood "
                f"for every address of the gateway; only its main address is known, so the converted rule {effect}"
                + (": more traffic gets through than on the source" if wider else ""),
            )
        signed = sorted(self._reach(rule.services, self.p.service_groups) & self.signature_services)
        if signed:
            # Only the port is left of the service. With a deny rule either way matters: it blocks
            # more, or (negated) lets through what did not carry the signature.
            if rule.negate_service:
                effect = "everything on that port is now outside this rule"
            else:
                effect = "the converted rule matches everything on the port"
            self.report.add(
                "rule",
                rule.origin,
                Severity.APPROX if allow else Severity.REVIEW,
                "PROTOCOL_SIGNATURE",
                "service " + ", ".join(signed) + f" also checked the signature of its protocol; {effect}",
            )

    def _install_on(self, entry: Obj, kind: str, origin: str) -> None:
        targets = [str(cell.get("name") or "") for cell in self._cells(entry, "install-on")]
        specific = [t for t in targets if t and t != "Policy Targets"]
        if specific:
            self.report.add(
                kind,
                origin,
                Severity.REVIEW,
                "DEVICE_TARGET",
                "the rule is installed only on " + ", ".join(specific) + "; decide whether it belongs on the "
                "target firewall",
            )

    def _layer(self, layer: str, stack: Tuple[str, ...]) -> List[Rule]:
        out: List[Rule] = []
        for number, (entry, section) in enumerate(self.layers.get(layer, []), 1):
            rule = self._rule(entry, section, number)
            inline = str(entry.get("inline-layer") or "")
            if not inline:
                out.append(self._register(rule, entry))
                continue
            inline_name = self.layer_names.get(inline) or str(self._object(inline).get("name") or inline)
            if inline not in self.layers or inline in stack or len(stack) >= _MAX_DEPTH:
                rule.action = Action.DROP
                if inline not in self.layers:
                    why = "is not in the export; add its 'show access-rulebase' output"
                elif inline in stack:
                    why = "is applied from inside itself"
                else:
                    why = f"is nested more than {_MAX_DEPTH} layers deep"
                rule.unsupported.append(f"inline layer '{inline_name}' {why}")
                out.append(self._register(rule, entry))
                continue
            children = self._layer(inline, stack + (inline,))
            closed = bool(children) and _catch_all(children[-1])
            for child in children:
                combined = self._combine(rule, child)
                if combined is not None:
                    out.append(self._register(combined, entry, registered=child.origin))
            if closed:
                continue  # the layer ends in a rule that matches everything the layer receives
            implicit = str(self._object(inline).get("implicit-cleanup-action") or "").lower()
            cleanup = Rule(
                name=f"{rule.name} (cleanup of {inline_name})",
                src_zones=list(rule.src_zones), dst_zones=list(rule.dst_zones), sources=list(rule.sources),
                destinations=list(rule.destinations), services=list(rule.services),
                action=Action.ALLOW if implicit == "accept" else Action.DROP,
                enabled=rule.enabled, negate_source=rule.negate_source, negate_destination=rule.negate_destination,
                negate_service=rule.negate_service, schedule=rule.schedule, unsupported=list(rule.unsupported),
                log_end=False, description=f"implicit cleanup of inline layer {inline_name}", tags=list(rule.tags),
            )  # fmt: skip
            out.append(self._register(cleanup, entry))
            if implicit in ("accept", "drop"):
                self.report.add(
                    "rule",
                    cleanup.origin,
                    Severity.INFO,
                    "INLINE_CLEANUP",
                    f"added for the implicit cleanup of inline layer '{inline_name}', which is {implicit}",
                )
            else:
                self.report.add(
                    "rule",
                    cleanup.origin,
                    Severity.REVIEW,
                    "INLINE_CLEANUP",
                    f"added for the implicit cleanup of inline layer '{inline_name}'. The export does not show "
                    "its action; drop, the default of a firewall layer, was assumed. Add the output of "
                    "'show access-layers details-level full' to the input to have it read",
                )
        return out

    def _register(self, rule: Rule, entry: Obj, registered: str = "") -> Rule:
        candidate, counter = rule.name, 2
        while candidate in self.rule_names:
            candidate = f"{rule.name}-{counter}"
            counter += 1
        self.rule_names.add(candidate)
        rule.name = rule.origin = candidate
        self.expanded += 1
        if self.expanded > _MAX_RULES:
            raise ParseError(f"the inline layers expand to more than {_MAX_RULES} rules; refusing to continue")
        self._note_objects(rule)
        unknown = sorted(str(k) for k, v in entry.items() if k not in _RULE_FIELDS and v not in (None, "", [], {}, False))
        if unknown:
            self.report.add(
                "rule",
                candidate,
                Severity.REVIEW,
                "UNKNOWN_ATTRIBUTES",
                "the rule has fields this version does not know: " + ", ".join(unknown) + ". If one of them narrows "
                "what the rule matches, the converted rule is wider: check them",
            )
        if registered:
            # Findings were recorded for the rule inside the inline layer: carry them to the combined rule.
            for finding in self.report.item("rule", registered).findings:
                self.report.add("rule", candidate, finding.severity, finding.code, finding.message)
            self.report.discard("rule", registered)
        self._install_on(entry, "rule", candidate)
        return rule

    def _combine(self, parent: Rule, child: Rule) -> Optional[Rule]:
        """A rule of an inline layer, limited to what the rule applying the layer matches; None if nothing."""
        out = Rule(name=f"{parent.name} / {child.name}")
        out.origin = child.origin
        out.action, out.log_end, out.description, out.tags = child.action, child.log_end, child.description, parent.tags
        out.enabled = parent.enabled and child.enabled
        out.unsupported = transform.dedupe(parent.unsupported + child.unsupported)
        out.schedule = ", ".join(s for s in (parent.schedule, child.schedule) if s)
        for attribute in ("src_zones", "dst_zones"):
            outer, inner = getattr(parent, attribute), getattr(child, attribute)
            zones = inner if outer == [ANY] else outer if inner == [ANY] else [z for z in inner if z in outer]
            if not zones:
                return None
            setattr(out, attribute, list(zones))
        for attribute, flag in (("sources", "negate_source"), ("destinations", "negate_destination")):
            members, negated, expressible = self._both(
                getattr(parent, attribute), getattr(parent, flag), getattr(child, attribute), getattr(child, flag)
            )
            if members is None:
                return None
            if not expressible:
                what = attribute[:-1]
                out.unsupported.append(f"{what} limited both by the rule applying the layer and inside the layer")
            setattr(out, attribute, members)
            setattr(out, flag, negated)
        if parent.services == [ANY] and not parent.negate_service:
            out.services, out.negate_service = list(child.services), child.negate_service
        elif child.services == [ANY] and not child.negate_service:
            out.services, out.negate_service = list(parent.services), parent.negate_service
        elif set(parent.services) == set(child.services) and parent.negate_service == child.negate_service:
            out.services, out.negate_service = list(child.services), child.negate_service
        elif not parent.negate_service and not child.negate_service and self._services_within(child, parent):
            out.services = list(child.services)
        elif not parent.negate_service and not child.negate_service and self._services_within(parent, child):
            out.services = list(parent.services)
        else:
            out.services, out.negate_service = list(child.services), child.negate_service
            out.unsupported.append("service limited both by the rule applying the layer and inside the layer")
        return out

    def _services_within(self, inner: Rule, outer: Rule) -> bool:
        """True when every port the services of ``inner`` match is matched by those of ``outer`` too."""
        ranges: List[Dict[Protocol, List[Tuple[int, int]]]] = []
        for rule in (inner, outer):
            entries: List[ServiceEntry] = []
            for service in rule.services:
                flat = transform.flatten_services(self.p, service)
                if flat is None or service in transform.tainted_services(self.p):
                    return False
                entries += flat
            resolved = _port_ranges(entries)
            if resolved is None:
                return False
            ranges.append(resolved)
        return all(
            any(low <= first and last <= high for low, high in ranges[1].get(protocol, []))
            for protocol, parts in ranges[0].items()
            for first, last in parts
        )

    def _static(self, members: List[str]) -> Optional[List[Interval]]:
        """The addresses a list stands for, merged; None when they are not all known."""
        intervals: List[Interval] = []
        for member in members:
            known, complete = transform.known_intervals(self.p, member)
            if not complete:
                return None
            intervals += known
        return normalize(intervals)

    def _both(
        self, outer: List[str], outer_negated: bool, inner: List[str], inner_negated: bool
    ) -> Tuple[Optional[List[str]], bool, bool]:
        """Addresses matched by two lists at once: (members, negated, expressible); None matches nothing."""
        if outer == [ANY] and not outer_negated:
            return list(inner), inner_negated, True
        if inner == [ANY] and not inner_negated:
            return list(outer), outer_negated, True
        if outer_negated and inner_negated:
            return transform.dedupe(outer + inner), True, True  # in neither list
        first, second = self._static(outer), self._static(inner)
        if first is None or second is None:
            return list(inner), inner_negated, False
        if outer_negated or inner_negated:
            # In the plain list and not in the negated one.
            kept, names, removed = (second, inner, first) if outer_negated else (first, outer, second)
            common = _subtract(kept, removed)
            if common == kept:
                return list(names), False, True
        else:
            common = _intersect(first, second)
            # Keep the names where one list simply lies inside the other.
            if common == second:
                return list(inner), False, True
            if common == first:
                return list(outer), False, True
        if not common:
            return None, False, True
        return [_literal(interval) for interval in common], False, True

    # -- NAT ----------------------------------------------------------------

    def _nat_rule(self, entry: Obj, index: int) -> NatRule:
        number = entry.get("rule-number") or index
        name = str(entry.get("name") or "") or f"nat-{number}"
        candidate, counter = name, 2
        while candidate in self.rule_names:
            candidate = f"{name}-{counter}"
            counter += 1
        self.rule_names.add(candidate)
        nat = NatRule(name=candidate)
        nat.origin = nat.name
        nat.description = str(entry.get("comments") or "") or ("automatic NAT rule" if entry.get("auto-generated") else "")
        nat.enabled = self._flag(entry, "enabled", True, nat.unsupported)
        self._install_on(entry, "nat", nat.origin)

        def cell(column: str) -> Obj:
            return self._object(entry.get(column))

        def original(column: str) -> bool:
            return entry.get(column) is None or self._label(entry.get(column)) == "Original"

        # An automatic rule shows the object itself where its translated address is meant
        # ("Valid Address", "Hiding Address"): the address comes from the NAT settings of the object.
        automatic = self._flag(entry, "auto-generated", False, nat.unsupported)
        nat.combines = automatic  # two automatic rules can apply to one connection, source and destination

        def hides_behind_gateway(obj: Obj) -> bool:
            settings = obj.get("nat-settings")
            return automatic and isinstance(settings, dict) and settings.get("hide-behind") == "gateway"

        for column, attribute in (("original-source", "sources"), ("original-destination", "destinations")):
            obj = cell(column)
            if obj.get("type") == "security-zone":
                nat.unsupported.append(f"security zone in {column}")
                continue
            name = self._address(obj)
            if automatic and column == "original-destination" and not original("translated-destination"):
                # Inbound: sent to the translated address of the object and brought to the object itself.
                if name not in self.valid:
                    nat.unsupported.append(f"automatic rule for '{name}', whose NAT settings are not in the export")
                name = self.valid.get(name, name)
            elif name != ANY and self._reaches_valid(name):
                self.report.add(
                    "nat",
                    nat.origin,
                    Severity.REVIEW,
                    "AUTOMATIC_NAT_IN_GROUP",
                    f"'{name}' holds an object with automatic static NAT and so its translated address too; whether "
                    "Check Point matches that address in a NAT rule is not known: check what this rule should match",
                )
            setattr(nat, attribute, [name])
        for first, second in (("original-source", "translated-source"), ("original-destination", "translated-destination")):
            if automatic and not original(second) and entry.get(first) != entry.get(second):
                self.report.add(
                    "nat",
                    nat.origin,
                    Severity.REVIEW,
                    "AUTOMATIC_NAT_SHAPE",
                    f"automatic rule whose {second} is not the object of its {first}; it was read as it stands",
                )
        nat.service = self._service(cell("original-service"))
        method = str(entry.get("method") or "static").lower()
        if method not in ("static", "hide"):
            nat.unsupported.append(f"NAT method '{method}'")
        source, destination, service = cell("translated-source"), cell("translated-destination"), cell("translated-service")
        if not original("translated-source"):
            if method == "hide" and (source.get("type") in _GATEWAY_TYPES):
                # Hide behind the gateway: the address of the interface the traffic leaves by.
                nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=str(source.get("name") or ""))
            elif method == "hide" and hides_behind_gateway(source):
                nat.source_translation = SourceNat(SnatKind.INTERFACE)
            else:
                kind = SnatKind.DYNAMIC_PORT if method == "hide" else SnatKind.STATIC
                translated = self._address(source)
                if automatic:
                    companions = self.hiding if method == "hide" else self.valid
                    if translated not in companions:
                        nat.unsupported.append(
                            f"automatic rule for '{translated}', whose NAT settings are not in the export"
                        )
                    translated = companions.get(translated, translated)
                nat.source_translation = SourceNat(kind, [translated])
        port = ""
        if not original("translated-service"):
            translated = self._service(service)
            entries = self.p.services[translated].entries if translated in self.p.services else []
            if len(entries) == 1 and is_number(entries[0].dst_ports):
                port = entries[0].dst_ports
            else:
                nat.unsupported.append(f"translated service '{service.get('name')}' is not a single port")
        if not original("translated-destination"):
            nat.destination_translation = DestNat(self._address(destination), port)
        elif port:
            if nat.destinations == [ANY]:
                nat.unsupported.append("port translation without a destination address")
            else:
                nat.destination_translation = DestNat(nat.destinations[0], port)
        return nat
