# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco Secure Firewall parser: the JSON of its managers -> neutral model.

A Cisco Secure Firewall (Firepower Threat Defense) keeps its policy in its manager. Two are read:

* ``fmc``: what the REST API of a Firewall Management Center returns for the access rules of an
  access control policy, the rules of its prefilter policy and of a NAT policy, and the objects
  they use. The input is one JSON document or several, one after the other: the answers as they
  came, each fetched with ``expanded=true``.
* ``fdm``: the configuration export of the on-box Firewall Device Manager (the text file of the
  export, or the zip it comes in), or what its REST API returns.

How the behaviour of the device is mapped onto the neutral model:

* Access rules are first match, the mandatory rules of a policy before its default rules, and
  around them those of the policy it inherits from. What no rule matches gets the default action.
* The prefilter rules of a Management Center come first. *Fastpath* and *Block* decide; *Analyze*
  hands the traffic to the access rules and ends the prefilter for it. That last part has no
  equivalent in one list of rules: a later prefilter rule that overlaps an Analyze rule is
  reported, and a Fastpath one is not converted.
* A *Monitor* rule decides nothing and is left out.
* As on an ASA from 8.3 on, access rules name the real address and port of a host behind NAT; the
  model wants the original ones. NAT is one ordered list: manual rules, automatic rules (sorted
  the way the device sorts them), manual rules "after auto". A connection can use one rule for
  its destination and another for its source.
* A device forwards between and within its interfaces as far as the rules allow: there is no
  security level and no implicit rule.
* A condition that is not understood, or an object that is not in the input, makes its rule
  unusable, never wider.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..appmap import (
    FDM_ICMP6_CODES,
    FDM_ICMP6_TYPES,
    FDM_ICMP_CODES,
    FDM_ICMP_TYPES,
    FDM_PROTOCOLS,
    protocol_number,
    valid_ports,
)
from ..errors import ParseError
from ..model import (
    ANY,
    APP_DEFAULT,
    L4_PROTOCOLS,
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
from ..netutil import Interval, is_number, mask_length, overlaps, parse_literal, size
from ..report import Report, Severity
from .asa import _key, _label, _unique  # the same names for what an entry spells out, as for an ASA

Obj = Dict[str, Any]

# Type names that only one of the two managers writes, exactly as it writes them.
_FMC_TYPES = frozenset({
    "Host", "Network", "Range", "FQDN", "NetworkGroup", "ProtocolPortObject", "ICMPV4Object", "ICMPV6Object",
    "PortObjectGroup", "AccessRule", "AccessPolicy", "PrefilterRule", "PrefilterPolicy", "FTDNatPolicy",
    "FTDManualNatRule", "FTDAutoNatRule", "SecurityZone", "InterfaceGroup", "PhysicalInterface", "SubInterface",
    "EtherChannelInterface",
})  # fmt: skip
_FDM_TYPES = frozenset({
    "identitywrapper", "networkobject", "networkobjectgroup", "tcpportobject", "udpportobject", "protocolobject",
    "icmpv4portobject", "icmpv6portobject", "portobjectgroup", "accessrule", "accesspolicy", "manualnatrule",
    "objectnatrule", "manualnatrulecontainer", "objectnatrulecontainer", "securityzone", "physicalinterface",
    "subinterface", "etherchannelinterface",
})  # fmt: skip
_TYPE = re.compile(rb'"type"\s*:\s*"([A-Za-z0-9]{2,40})"')

# What an object is, by its type in lower case.
_NETWORK_TYPES = {"host", "network", "range", "fqdn", "networkgroup", "networkobject", "networkobjectgroup"}
_PORT_TYPES = {"protocolportobject", "icmpv4object", "icmpv6object", "portobjectgroup", "tcpportobject", "udpportobject",
               "protocolobject", "icmpv4portobject", "icmpv6portobject"}  # fmt: skip
_INTERFACE_TYPES = {"physicalinterface", "subinterface", "etherchannelinterface", "redundantinterface", "vlaninterface",
                    "bridgegroupinterface", "vtiinterface", "virtualtunnelinterface", "loopbackinterface"}  # fmt: skip
_ACCESS_RULES = ("accessrule",)
_NAT_RULES = ("ftdmanualnatrule", "ftdautonatrule", "manualnatrule", "objectnatrule")
# Fields of a rule that are read, or that say nothing about what the rule matches.
_RULE_FIELDS = {
    "id", "name", "type", "links", "metadata", "version", "enabled", "action", "ruleAction", "description",
    "sourceZones", "destinationZones", "sourceNetworks", "destinationNetworks", "sourcePorts", "destinationPorts",
    "logBegin", "logEnd", "logFiles", "sendEventsToFMC", "enableSyslog", "syslogSeverity", "syslogConfig", "snmpConfig",
    "ipsPolicy", "variableSet", "filePolicy", "intrusionPolicy", "eventLogAction", "syslogServer", "commentHistoryList",
    "newComments", "ruleId", "rulePosition", "hitCount", "isSystemDefined", "ruleIndex", "section", "category",
    # prefilter rules
    "ruleType", "sourceInterfaces", "destinationInterfaces", "bidirectional", "encapsulationPorts", "tunnelZone",
}  # fmt: skip
# Conditions that are known and not converted: (field, what it is). A rule that has one is not usable.
_CONDITIONS = (
    ("applications", "an application condition"), ("embeddedAppFilter", "an application condition"),
    ("urls", "a URL condition"), ("urlFilter", "a URL condition"), ("vlanTags", "a VLAN tag condition"),
    ("sourceSecurityGroupTags", "a security group tag as source"),
    ("destinationSecurityGroupTags", "a security group tag as destination"),
    ("sourceDynamicObjects", "a dynamic object as source"), ("destinationDynamicObjects", "a dynamic object as destination"),
    ("originalSourceNetworks", "a condition on the original client address"),
    ("endPointDeviceTypes", "an endpoint device type condition"), ("identitySources", "an identity source condition"),
)  # fmt: skip
_NAT_FIELDS = {
    "id", "name", "type", "links", "metadata", "version", "description", "enabled", "natType", "section", "targetIndex",
    "rulePosition", "sourceInterface", "destinationInterface", "originalSource", "translatedSource", "originalDestination",
    "translatedDestination", "originalSourcePort", "translatedSourcePort", "originalDestinationPort",
    "translatedDestinationPort", "originalNetwork", "translatedNetwork", "originalPort", "translatedPort",
    "serviceProtocol", "interfaceInTranslatedSource", "interfaceInOriginalDestination", "interfaceInTranslatedNetwork",
    "unidirectional", "patOptions", "dns", "netToNet", "noProxyArp", "routeLookup", "fallThrough", "interfaceIpv6",
    "interfaceIPv6", "isSystemDefined",
}  # fmt: skip
_LISTED = {"accessrules": ("accessrule",), "prefilterrules": ("prefilterrule",), "manualnatrules": ("ftdmanualnatrule", "manualnatrule"),
           "autonatrules": ("ftdautonatrule",), "natrules": ("ftdmanualnatrule", "ftdautonatrule"), "objectnatrules": ("objectnatrule",)}  # fmt: skip
_EVERY_ADDRESS = {"any-ipv4": "0.0.0.0/0", "any-ipv6": "::/0"}  # system objects of both managers
_GROUP_FIELDS = frozenset({"objects", "literals", "id", "name", "type", "links", "metadata", "description", "overridable", "overrides",
                           "version", "isSystemDefined", "overrideTargetId"})  # fmt: skip
_PAT_FIELDS = {"type", "patPoolAddress", "interfacePat", "roundRobin", "extendedPat", "extended", "flatPortRange", "flat",
               "includeReserve", "blockAllocation"}  # fmt: skip
_ENCAPSULATION = {
    "GRE": ServiceEntry(Protocol.IP, ip_protocol=47), "IP_IN_IP": ServiceEntry(Protocol.IP, ip_protocol=4),
    "IPV6_IN_IP": ServiceEntry(Protocol.IP, ip_protocol=41), "TEREDO": ServiceEntry(Protocol.UDP, dst_ports="3544"),
}  # fmt: skip
_RESERVED_NAMES = (ANY, APP_DEFAULT)
_MAX_UNZIPPED = 128 * 1024 * 1024  # the export of a device is a few megabytes
_MAX_PARENTS = 16  # policies an access control policy may inherit through
_POLICY_LINK = re.compile(r"/policy/(accesspolicies|prefilterpolicies|ftdnatpolicies|manualnatpolicies|objectnatpolicies)/([^/?#]+)/")
_POLICY_KINDS = ("accesspolicy", "prefilterpolicy", "ftdnatpolicy", "manualnatrulecontainer", "objectnatrulecontainer")
_FDM_SCOPE = "FTD {version} on {model}"


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _l(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _d(value: Any) -> Obj:
    return value if isinstance(value, dict) else {}


def _blank(value: Any, top: bool = True) -> bool:
    """Whether a field says nothing: absent, empty, switched off, or a holder of nothing but such values.

    The type and the links of the holder itself say nothing; a type further in does ("a country").
    """
    if value is None or value is False or value == "" or value == [] or value == {}:
        return True
    if isinstance(value, dict):
        return all(_blank(inner, False) for key, inner in value.items() if not (top and key in ("type", "links")))
    return False


def dialect_of(data: bytes) -> str:
    """The manager JSON comes from, going by the type names in it: "fmc", "fdm" or ""."""
    sample = data[:4_000_000]
    found = {match.group(1).decode("ascii") for match in _TYPE.finditer(sample)}
    fmc = len(found & _FMC_TYPES) + (2 if b"/api/fmc_config/" in sample else 0)
    fdm = len(found & _FDM_TYPES) + (2 if b"/api/fdm/" in sample else 0)
    if not fmc and not fdm:
        return ""
    return "fmc" if fmc >= fdm else "fdm"


def is_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")  # with files, empty, or in parts


def unzip(data: bytes) -> bytes:
    """The text file of the zip a Device Manager exports its configuration as."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = [info for info in archive.infolist() if not info.is_dir()]
            texts = [info for info in files if info.filename.lower().endswith((".txt", ".json"))]
            if any(info.flag_bits & 0x1 for info in texts or files):
                raise ParseError(
                    "the zip is encrypted. Export the configuration with doNotEncrypt, or unpack it with its key and give "
                    "FWShift the text file inside"
                )
            if len(texts) != 1:
                raise ParseError(
                    f"the zip holds {len(texts)} text files; the export of a Firewall Device Manager holds one. Unpack it "
                    "and give FWShift the file with the configuration"
                )
            if texts[0].file_size > _MAX_UNZIPPED:
                raise ParseError("the file in the zip is too large to be a configuration export")
            with archive.open(texts[0]) as handle:
                content = handle.read(_MAX_UNZIPPED + 1)
            if len(content) > _MAX_UNZIPPED:
                raise ParseError("the file in the zip is too large to be a configuration export")
            return content
    except ParseError:
        raise
    except (zipfile.BadZipFile, zlib.error, OSError, RuntimeError, NotImplementedError, EOFError, ValueError) as exc:
        raise ParseError(f"the zip could not be read ({type(exc).__name__}: {str(exc)[:80]})") from None


def _documents(data: bytes) -> List[Any]:
    """The JSON documents of the input: one, or several one after the other."""
    try:
        text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError(f"not valid JSON: the text is not UTF-8 ({exc.reason} at byte {exc.start})") from None
    decoder = json.JSONDecoder()
    out: List[Any] = []
    position, length = 0, len(text)
    while True:
        while position < length and text[position] in " \t\r\n":
            position += 1
        if position >= length:
            break
        try:
            value, position = decoder.raw_decode(text, position)
        except ValueError as exc:
            after = f" (after {len(out)} complete document{'s' if len(out) != 1 else ''})" if out else ""
            raise ParseError(f"not valid JSON{after}: {exc}") from None
        except RecursionError:
            raise ParseError("not usable JSON: nested too deeply") from None
        out.append(value)
    return out


@dataclass
class _Record:
    """An object of the input: what the answers hold about it, put together."""

    obj: Obj
    kind: str  # its type, in lower case
    seq: int  # where it first stood
    parent: str = ""  # Device Manager export: the name of what holds it (a policy)
    index: Optional[int] = None  # Device Manager export: its place in the list of its parent


@dataclass
class _Interface:
    key: str
    logical: str  # the name rules and zones of a Device Manager use (nameif)
    hardware: str
    zone: str = ""  # id of the security zone it says it is in
    address: str = ""
    networks: List[Interval] = field(default_factory=list)
    defined: bool = False  # the input holds the interface itself, not only its name where something uses it


class _Source:
    """Every object of the input, by id, by type and name, and in the order of the input."""

    def __init__(self, documents: List[Any]) -> None:
        self.records: Dict[Tuple[str, str], _Record] = {}  # by type and id (or name, for an object without an id)
        self.by_id: Dict[str, List[_Record]] = {}
        self.by_name: Dict[Tuple[str, str], _Record] = {}
        self.lists: List[Tuple[str, int, List[str]]] = []  # (what was listed, how many the manager has, the ids here)
        self.metadata: Obj = {}
        self.errors: List[str] = []  # what the manager said where it answered with an error instead of what was asked
        self.wrapped = False
        self.types: Set[str] = set()  # as written
        seq = 0
        stack: List[Tuple[Any, str, Optional[int]]] = [(document, "", None) for document in reversed(documents)]
        while stack:
            value, parent, index = stack.pop()
            if isinstance(value, list):
                stack.extend((item, "", None) for item in reversed(value))
                continue
            if not isinstance(value, dict):
                continue
            kind = value.get("type")
            if kind == "identitywrapper":
                self.wrapped = True
                self.types.add("identitywrapper")
                data = value.get("data")
                if isinstance(data, dict) and _s(value.get("action")).upper() != "DELETE":
                    place = value.get("index")
                    stack.append((data, _s(value.get("parentName")), place if isinstance(place, int) and not isinstance(place, bool) else None))
                continue
            if kind == "metadata" and ("apiVersion" in value or "softwareVersion" in value):
                self.metadata = value
                continue
            if isinstance(kind, str) and kind:
                self.types.add(kind)
                self._add(value, kind.lower(), seq, parent, index)
                seq += 1
            items, paging = value.get("items"), value.get("paging")
            if isinstance(paging, dict) and ("items" in value or "count" in paging):
                self._listed(value, items if isinstance(items, list) else [], paging)
            problem = value.get("error")
            if isinstance(problem, dict) and (isinstance(problem.get("messages"), list) or "severity" in problem or "category" in problem):
                texts = [_s(_d(message).get("description")) for message in _l(problem.get("messages"))]
                self.errors.append("; ".join(text for text in texts if text)[:200] or "no text")
                continue
            stack.extend((child, "", None) for child in reversed(list(value.values())) if isinstance(child, (dict, list)))

    def _add(self, obj: Obj, kind: str, seq: int, parent: str, index: Optional[int]) -> None:
        ident, name = _s(obj.get("id")), _s(obj.get("name"))
        if not ident and not name:
            return  # a literal, or a part of something else
        key = (kind, ident or f"\0{name}")
        held = self.records.get(key)
        if held is None and not ident:
            held = self.by_name.get((kind, name))  # the same object, said once with its id
        named = self.by_name.get((kind, name)) if name else None
        if held is None and ident and named is not None and not _s(named.obj.get("id")):
            # Said by name before, and now with its id: one object.
            self.records.pop((kind, f"\0{name}"), None)
            held = self.records[key] = named
            del self.by_name[(kind, name)]
            self.by_id.setdefault(ident, []).append(held)
        if held is None:
            held = self.records[key] = _Record(dict(obj), kind, seq, parent, index)
            if ident:
                self.by_id.setdefault(ident, []).append(held)
        else:
            # A reference and what it refers to carry the same id: together they are the object.
            for field_name, value in obj.items():
                if _blank(held.obj.get(field_name)) and not _blank(value):
                    held.obj[field_name] = value
            held.parent = held.parent or parent
            held.index = held.index if held.index is not None else index
        if name:
            self.by_name.setdefault((kind, name), held)

    def _listed(self, answer: Obj, items: List[Any], paging: Obj) -> None:
        count = paging.get("count")
        if not isinstance(count, int) or isinstance(count, bool):
            count = len(items)  # it does not say how many there are: at least what it lists
        link = _s(_d(answer.get("links")).get("self"))
        if not link:
            first = _s(_d(_d(items[0]).get("links") if items else None).get("self"))
            link = first.rsplit("/", 1)[0] if first else ""
        if not link and items:
            link = _s(_d(items[0]).get("type"))
        link = link.split("?", 1)[0]
        # In a list of rules only what is a rule of that kind counts: an item of another type, or of none, is not read.
        wanted = _LISTED.get(link.rstrip("/").rsplit("/", 1)[-1].lower())
        ids = [_s(_d(item).get("id")) for item in items if wanted is None or _s(_d(item).get("type")).lower() in wanted]
        self.lists.append((link, max(count, len(items)), [ident for ident in ids if ident]))

    def of(self, *kinds: str) -> List[_Record]:
        return sorted((record for record in self.records.values() if record.kind in kinds), key=lambda record: record.seq)

    def find(self, ref: Any) -> Optional[_Record]:
        """The object a reference names: by its id, or by type and name where it has none."""
        if not isinstance(ref, dict):
            return None
        ident, kind = _s(ref.get("id")), _s(ref.get("type")).lower()
        if ident and (kind, ident) in self.records:
            return self.records[(kind, ident)]
        if ident and len(self.by_id.get(ident, [])) == 1:
            return self.by_id[ident][0]  # the reference gives another type than the object has
        return self.by_name.get((kind, _s(ref.get("name"))))

    def get(self, ident: str, *kinds: str) -> Optional[_Record]:
        """The object with an id, of one of these types."""
        for kind in kinds:
            if (kind, ident) in self.records:
                return self.records[(kind, ident)]
        return None


def parse(data: bytes, report: Report, dialect: str, policy: str = "", nat_policy: str = "") -> Policy:
    """Read the JSON of a Management Center (``dialect`` "fmc") or of a Device Manager ("fdm")."""
    if is_zip(data):
        if dialect != "fdm":
            raise ParseError("the input is a zip; unpack it and give FWShift the JSON inside")
        data = unzip(data)
    documents = _documents(data)
    if not documents:
        raise ParseError("the input is empty")
    source = _Source(documents)
    fmc, fdm = bool(source.types & _FMC_TYPES), bool(source.types & _FDM_TYPES)
    name = {"fmc": "a Firewall Management Center", "fdm": "a Firewall Device Manager"}
    other = "fdm" if dialect == "fmc" else "fmc"
    if fmc and fdm:
        raise ParseError("the input holds objects of a Firewall Management Center and of a Firewall Device Manager; convert them apart")
    if (fdm if dialect == "fmc" else fmc):
        raise ParseError(f"the input is the JSON of {name[other]}; read it with --from {other}")
    if not (fmc or fdm):
        expected = (
            "what the REST API of a Firewall Management Center returns for access rules, NAT rules and objects"
            if dialect == "fmc" else "the configuration export of a Firewall Device Manager, or what its REST API returns"
        )  # fmt: skip
        raise ParseError(f"no Cisco Secure Firewall configuration found; expected {expected}")
    try:
        return _Reader(source, report, dialect == "fdm", policy, nat_policy).build()
    except ParseError:
        raise
    except (TypeError, AttributeError, KeyError, IndexError, ValueError, RecursionError) as exc:
        # The fields that are read are checked where they are read; this is for a shape nobody thought of.
        raise ParseError(f"the input is not shaped like the JSON of {name[dialect]} ({type(exc).__name__}: {str(exc)[:80]})") from None


def _number(value: Any) -> Optional[int]:
    """An integer that JSON gives as a number or as digits; None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and is_number(value.strip()) and len(value.strip()) <= 9:
        return int(value.strip())
    return None


class _Reader:
    def __init__(self, source: _Source, report: Report, fdm: bool, policy: str, nat_policy: str) -> None:
        self.source, self.report, self.fdm = source, report, fdm
        self.wanted_policy, self.wanted_nat = policy, nat_policy
        self.vendor = "fdm" if fdm else "fmc"
        self.p = Policy(vendor=self.vendor, default_intrazone=Action.DENY, default_interzone=Action.DENY, lookup_after_dnat=True)
        self.address_names: Set[str] = set()
        self.service_names: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.address_of: Dict[int, str] = {}  # id() of a record -> its name in the model
        self.service_of: Dict[int, str] = {}
        self.zone_of: Dict[int, str] = {}
        self.inline: Dict[Tuple[Tuple[object, ...], ...], str] = {}
        self.interfaces: Dict[str, _Interface] = {}  # by id, and by "\0" + logical name
        self.members: Dict[str, List[_Interface]] = {}  # zone of the model -> its interfaces, as far as the input tells
        self.zone_networks: Dict[str, List[Interval]] = {}
        self.interface_objects: Dict[str, str] = {}
        self.overridable: List[str] = []
        self.inherits: Dict[str, Tuple[str, bool]] = {}
        self.port_owner: Dict[int, str] = {}  # id() of the entry of a port object -> the name of the object
        self.analyzed: List[Rule] = []  # what earlier prefilter rules hand to the access rules
        self.tunnel_zones: Set[str] = set()

    # -- top level --------------------------------------------------------

    def build(self) -> Policy:
        self._zones()
        self._addresses()
        self._services()
        if self.fdm:
            self._fdm_rules()
        else:
            self._fmc_rules()
        self._nat()
        p = self.p
        if not (p.addresses or p.address_groups or p.services or p.service_groups or p.rules or p.nat_rules or p.zones):
            raise ParseError("no rules and no objects found in the input")
        transform.rewrite_destinations(p, self.report, to_post_nat=False)
        self._notes()
        return p

    def _notes(self) -> None:
        if self.overridable:
            shown = ", ".join(self.overridable[:8]) + (" ..." if len(self.overridable) > 8 else "")
            self.report.note(
                Severity.APPROX, "OBJECT_OVERRIDES",
                f"{len(self.overridable)} object(s) can have another value on a device than the one that was read (they allow "
                f"overrides): {shown}. The values of the manager were converted; check them against the device the policy is for",
            )  # fmt: skip
        for what, count, ids in self._incomplete():
            self.report.note(
                Severity.REVIEW, "EXPORT_INCOMPLETE",
                f"the manager has {count} {what}, the input holds {ids} that could be read: fetch every page (limit and offset) "
                "and convert again. With rules missing, the rules that are there decide traffic the missing ones decided",
            )  # fmt: skip
        if self.source.errors:
            shown = "; ".join(transform.dedupe(self.source.errors)[:3])
            self.report.note(
                Severity.REVIEW, "EXPORT_INCOMPLETE",
                f"{len(self.source.errors)} of the answers in the input are errors of the manager ({shown[:300]}): what was "
                "asked for there is not in the input. Fetch it again, and convert again",
            )  # fmt: skip

    def _incomplete(self) -> List[Tuple[str, int, int]]:
        """(what, how many the manager says it has, how many the input holds) for lists of rules that are not all there."""
        wanted = {"accessrules": "access rules", "prefilterrules": "prefilter rules", "manualnatrules": "manual NAT rules",
                  "autonatrules": "automatic NAT rules", "natrules": "NAT rules", "objectnatrules": "object NAT rules"}  # fmt: skip
        seen: Dict[str, Tuple[int, Set[str]]] = {}
        for link, count, ids in self.source.lists:
            last = link.rstrip("/").rsplit("/", 1)[-1].lower()
            if last not in wanted:
                continue
            held = seen.setdefault(link, (0, set()))
            seen[link] = (max(held[0], count), held[1] | set(ids))
        out: List[Tuple[str, int, int]] = []
        for link, (total, found) in seen.items():
            if len(found) < total:
                match = _POLICY_LINK.search(link + "/")
                holder = self.source.get(match.group(2), *_POLICY_KINDS) if match else None
                name = _s(holder.obj.get("name")) if holder else ""
                what = wanted[link.rstrip("/").rsplit("/", 1)[-1].lower()] + (f" in '{name}'" if name else "")
                out.append((what, total, len(found)))
        return out

    def _model_name(self, kind: str, name: str, taken: Set[str]) -> str:
        name = name or "unnamed"
        if name in _RESERVED_NAMES:
            new = _unique(f"{name}-object", taken)
            self.report.add(kind, new, Severity.INFO, "RENAMED", f"named '{name}' in the source, a reserved word; renamed to '{new}'")
            return new
        return _unique(name, taken)

    @staticmethod
    def _system(obj: Obj) -> bool:
        """Whether the manager comes with this object."""
        read_only = _d(_d(obj.get("metadata")).get("readOnly"))
        return obj.get("isSystemDefined") is True or (read_only.get("state") is True and _s(read_only.get("reason")).upper() == "SYSTEM")

    # -- zones and interfaces ---------------------------------------------

    def _zones(self) -> None:
        for record in self.source.of(*sorted(_INTERFACE_TYPES)):
            self._interface(record)
        for record in self.source.of("securityzone"):
            if any(key in record.obj for key in ("interfaces", "interfaceMode", "mode")):
                self._zone_name(record)  # a zone the input defines; the others are made where a rule names them

    def _zone_name(self, record: _Record) -> str:
        """The zone of the model for a security zone, with the interfaces the input gives it."""
        key = id(record)
        if key in self.zone_of:
            return self.zone_of[key]
        obj = record.obj
        name = _s(obj.get("name")) or "unnamed-zone"
        if name == ANY:
            name = "any-zone"
            self.report.note(Severity.INFO, "ZONE_RENAMED", "a zone is named 'any', which stands for every zone here: it is called 'any-zone'")
        name = _unique(name, set(self.p.zones))
        held: List[_Interface] = []
        for ref in _l(obj.get("interfaces")):
            interface = self._interface_of(ref)
            if interface is not None and not any(interface is other for other in held):
                held.append(interface)
        for interface in self.interfaces.values():
            if interface.zone and interface.zone == _s(obj.get("id")) and not any(interface is other for other in held):
                held.append(interface)
        self.p.zones[name] = Zone(name, transform.dedupe([interface.logical or interface.hardware for interface in held]))
        self.members[name] = held
        self.zone_networks[name] = [network for interface in held for network in interface.networks]
        self.zone_of[key] = name
        return name

    def _interface(self, record: _Record) -> None:
        obj = record.obj
        ident = _s(obj.get("id"))
        if self.fdm:
            logical, hardware = _s(obj.get("name")), _s(obj.get("hardwareName"))
        else:
            logical, hardware = _s(obj.get("ifname")), _s(obj.get("name"))
            sub = _number(obj.get("subIntfId"))
            if record.kind == "subinterface" and sub is not None and hardware and "." not in hardware:
                hardware = f"{hardware}.{sub}"
        if not (logical or hardware) or obj.get("managementOnly") is True:
            return
        interface = _Interface(ident or f"\0{logical}", logical, hardware, _s(_d(obj.get("securityZone")).get("id")), defined=True)
        four, six = _d(obj.get("ipv4")), _d(obj.get("ipv6"))
        static = _d(four.get("ipAddress")) if self.fdm else _d(four.get("static"))
        address = _s(static.get("ipAddress" if self.fdm else "address"))
        mask = static.get("netmask")
        length = _number(mask) if _number(mask) is not None else mask_length(_s(mask))
        if address and length is not None and "/" not in address:
            network = parse_literal(f"{address}/{length}")
            if network is not None and network[0] == 4 and parse_literal(address) is not None:
                interface.address = address
                interface.networks.append(network)
        for entry in _l(six.get("ipAddresses" if self.fdm else "addresses")):
            text = _s(_d(entry).get("ipAddress" if self.fdm else "address"))
            prefix = _number(_d(entry).get("prefix"))
            if text and "/" not in text and prefix is not None:
                text = f"{text}/{prefix}"
            network = parse_literal(text) if "/" in text else None
            if network is not None and network[0] == 6:
                interface.networks.append(network)
        if obj.get("enabled") is False:
            interface.networks = []  # shut down: its network is reached some other way, if at all
        self.interfaces[interface.key] = interface
        if logical:
            self.interfaces.setdefault(f"\0{logical}", interface)

    def _interface_of(self, ref: Any) -> Optional[_Interface]:
        ident, name = _s(_d(ref).get("id")), _s(_d(ref).get("name"))
        if ident in self.interfaces:
            return self.interfaces[ident]
        if self.fdm and f"\0{name}" in self.interfaces:
            return self.interfaces[f"\0{name}"]
        if self.fdm and name:
            # A Device Manager names an interface where it uses one: that is enough to know it by.
            made = _Interface(ident or f"\0{name}", name, _s(_d(ref).get("hardwareName")))
            self.interfaces[made.key] = made
            self.interfaces.setdefault(f"\0{name}", made)
            return made
        return None

    def _zone_ref(self, ref: Any, problems: List[str]) -> str:
        """The zone of the model for a reference to a security zone; a problem for anything else."""
        kind = _s(_d(ref).get("type")).lower()
        name = _s(_d(ref).get("name"))
        if kind in ("tunneltag", "tunnelzone"):
            problems.append(f"tunnel zone '{name[:40]}': the rule is for connections inside a tunnel")
            return name or "tunnel"
        if kind != "securityzone":
            problems.append(f"'{name[:40]}' of type '{kind[:30]}' where a security zone is expected")
            return name or "unknown"
        record = self.source.find(ref)
        if record is None:
            problems.append("a security zone without a name")
            return "unknown"
        return self._zone_name(record)

    # -- addresses --------------------------------------------------------

    def _addresses(self) -> None:
        defined = [record for record in self.source.of(*sorted(_NETWORK_TYPES)) if self._net_defined(record)]
        for record in defined:
            kind = "address-group" if self._is_net_group(record) else "address"
            self.address_of[id(record)] = self._model_name(kind, _s(record.obj.get("name")), self.address_names)
        for record in defined:
            name = self.address_of[id(record)]
            if self._is_net_group(record):
                self._net_group(name, record)
            else:
                self.p.addresses[name] = self._net_object(name, record)
            if record.obj.get("overridable") is True and not self._system(record.obj):
                self.overridable.append(name)

    def _is_net_group(self, record: _Record) -> bool:
        return record.kind in ("networkgroup", "networkobjectgroup")

    def _net_defined(self, record: _Record) -> bool:
        obj = record.obj
        if self._is_net_group(record):
            return "objects" in obj or "literals" in obj
        return "value" in obj

    def _net_object(self, name: str, record: _Record) -> Address:
        obj = record.obj
        value, description = _s(obj.get("value")).strip(), _s(obj.get("description"))
        kind = _s(obj.get("subType")).lower() if self.fdm else record.kind
        builtin = self.vendor if self._system(obj) else ""
        interval = parse_literal(value)
        family = {"IPV4_ONLY": 4, "IPV6_ONLY": 6}.get(_s(obj.get("dnsResolution")).upper(), 0)
        single = interval is not None and interval[1] == interval[2]
        if kind == "host" and single and "/" not in value and "-" not in value and interval is not None:
            return Address(name, AddressKind.NETWORK, f"{value}/{32 if interval[0] == 4 else 128}", description, builtin=builtin)
        if kind == "network" and interval is not None and "/" in value:
            return Address(name, AddressKind.NETWORK, value, description, builtin=builtin)
        if kind in ("range", "iprange") and interval is not None and "-" in value and "/" not in value:
            return Address(name, AddressKind.RANGE, value.replace(" ", ""), description, builtin=builtin)
        if kind == "fqdn" and value and parse_literal(value) is None:
            return Address(name, AddressKind.FQDN, value, description, fqdn_family=family, builtin=builtin)
        raw = f"{kind or 'network'} object with value '{value[:60]}'"
        self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
        return Address(name, AddressKind.UNSUPPORTED, "", description, raw=raw, builtin=builtin)

    def _net_group(self, name: str, record: _Record) -> None:
        obj = record.obj
        group = AddressGroup(name, description=_s(obj.get("description")), builtin=self.vendor if self._system(obj) else "")
        problems: List[str] = []
        for key in ("objects", "literals"):
            if obj.get(key) is not None and not isinstance(obj[key], list):
                problems.append(f"'{key}', which is not a list")
        for ref in _l(obj.get("objects")):
            group.members.append(self._address_ref(ref, problems, in_group=True))
        for literal in _l(obj.get("literals")):
            member = self._address_literal(literal, problems)
            if member:
                group.members.append(member)
        for key in obj:
            if key not in _GROUP_FIELDS and not _blank(obj[key]):
                problems.append(f"field '{key[:30]}'")
        if problems:
            group.unsupported = "member that could not be read: " + "; ".join(transform.dedupe(problems)[:3])
            self.report.add("address-group", name, Severity.REVIEW, "UNSUPPORTED_GROUP", group.unsupported)
        group.members = transform.dedupe(group.members)
        self.p.address_groups[name] = group

    def _address_literal(self, literal: Any, problems: List[str]) -> str:
        value = _s(_d(literal).get("value")).strip().replace(" ", "")
        if parse_literal(value) is None or not value:
            problems.append(f"address '{str(_d(literal).get('value'))[:40]}'")
            return ""
        return value

    def _address_ref(self, ref: Any, problems: List[str], in_group: bool = False) -> str:
        """The name in the model of the object a rule or group refers to.

        What is not in the input, or is of a kind that has no addresses to read, becomes an
        object that cannot be converted: whatever uses it is not converted either.
        """
        record = self.source.find(ref)
        if record is not None and id(record) in self.address_of:
            return self.address_of[id(record)]
        kind, name = _s(_d(ref).get("type")), _s(_d(ref).get("name"))
        if not isinstance(ref, dict) or not (name or _s(ref.get("id"))):
            problems.append("a reference without a name")
            return ""
        if kind.lower() in ("network", "networkobject") and name in _EVERY_ADDRESS:
            # Named and not in the input (a partial export, an import file): one of the two objects that
            # every manager comes with, and that it lets nobody change.
            new = self._model_name("address", name, self.address_names)
            self.p.addresses[new] = Address(new, AddressKind.NETWORK, _EVERY_ADDRESS[name], builtin=self.vendor)
            self.report.add("address", new, Severity.INFO, "PREDEFINED_OBJECT",
                            f"'{name}' is named and not in the input: it is the object for every "
                            f"IPv{6 if ':' in _EVERY_ADDRESS[name] else 4} address that the manager comes with")  # fmt: skip
            if record is not None:
                self.address_of[id(record)] = new
            return new
        if kind.lower() in _NETWORK_TYPES:
            raw = f"object '{name[:60]}', which is not in the input in full"
        else:
            raw = f"object '{name[:60]}' of type '{kind[:30]}', which has no addresses to read"
        new = self._model_name("address", name or kind, self.address_names)
        self.p.addresses[new] = Address(new, AddressKind.UNSUPPORTED, "", raw=raw)
        self.report.add("address", new, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw}: what uses it is not converted")
        if record is not None:
            self.address_of[id(record)] = new
        return new

    # -- services ---------------------------------------------------------

    def _services(self) -> None:
        defined = [record for record in self.source.of(*sorted(_PORT_TYPES)) if self._port_defined(record)]
        for record in defined:
            kind = "service-group" if record.kind == "portobjectgroup" else "service"
            self.service_of[id(record)] = self._model_name(kind, _s(record.obj.get("name")), self.service_names)
        for record in defined:
            name, obj = self.service_of[id(record)], record.obj
            builtin = self.vendor if self._system(obj) else ""
            if record.kind == "portobjectgroup":
                problems: List[str] = []
                if not isinstance(obj.get("objects"), list):
                    problems.append("'objects', which is not a list")
                problems += [f"field '{key[:30]}'" for key in obj if key not in _GROUP_FIELDS - {"literals"} and not _blank(obj[key])]
                members = [self._service_ref(ref, problems) for ref in _l(obj.get("objects"))]
                group = ServiceGroup(name, transform.dedupe([member for member in members if member]), _s(obj.get("description")), builtin=builtin)
                if problems:
                    group.members = []  # a group that is not known in full is not converted in part
                    self.report.add("service-group", name, Severity.REVIEW, "UNSUPPORTED_GROUP",
                                    "member that could not be read: " + "; ".join(transform.dedupe(problems)[:3]))  # fmt: skip
                self.p.service_groups[name] = group
                continue
            entry, problem = self._port_entry(obj, record.kind)
            service = Service(name, [entry] if entry is not None else [], _s(obj.get("description")), builtin=builtin)
            if entry is None:
                service.unsupported = problem
                self.report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{problem}: not converted")
            self.p.services[name] = service
            if obj.get("overridable") is True and not self._system(obj):
                self.overridable.append(name)

    @staticmethod
    def _port_defined(record: _Record) -> bool:
        obj = record.obj
        if record.kind == "portobjectgroup":
            return "objects" in obj
        if record.kind in ("icmpv4object", "icmpv6object"):
            # Every type and code is said by leaving both out: told from a reference by what else is there.
            return any(key in obj for key in ("icmpType", "code", "description", "overridable", "metadata"))
        return any(key in obj for key in ("protocol", "port", "icmpv4Type", "icmpv6Type"))

    def _port_entry(self, obj: Obj, kind: str) -> Tuple[Optional[ServiceEntry], str]:
        """(what a port object or a port literal matches, or why that cannot be said)."""
        kind = kind.lower()
        if kind in ("tcpportobject", "udpportobject"):
            if obj.get("port") is None or obj.get("port") == "":
                return None, "port object without a port"  # a Device Manager wants one; every port is 1-65535 there
            return self._l4(Protocol.TCP if kind.startswith("tcp") else Protocol.UDP, obj.get("port"))
        if kind in ("icmpv4portobject", "icmpv6portobject"):
            six = kind == "icmpv6portobject"
            prefix = "icmpv6" if six else "icmpv4"
            types, codes = (FDM_ICMP6_TYPES, FDM_ICMP6_CODES) if six else (FDM_ICMP_TYPES, FDM_ICMP_CODES)
            type_name, code_name = _s(obj.get(f"{prefix}Type")), _s(obj.get(f"{prefix}Code"))
            protocol = Protocol.ICMP6 if six else Protocol.ICMP
            if type_name == "ANY":
                if code_name and not code_name.startswith("ANY"):
                    return None, f"ICMP code '{code_name[:40]}' of every type"
                return ServiceEntry(protocol), ""
            if type_name not in types:
                return None, f"ICMP type '{type_name[:40]}', which is not a type FWShift knows the number of"
            if not code_name or code_name.startswith("ANY"):
                return ServiceEntry(protocol, icmp_type=types[type_name]), ""
            if code_name not in codes or codes[code_name][0] != types[type_name]:
                return None, f"ICMP code '{code_name[:40]}', which is not a code of type {type_name}"
            return ServiceEntry(protocol, icmp_type=types[type_name], icmp_code=codes[code_name][1]), ""
        if kind == "protocolobject":
            name = _s(obj.get("protocol"))
            if name not in FDM_PROTOCOLS:
                return None, f"protocol '{name[:40]}', which is not a protocol FWShift knows the number of"
            return self._by_number(FDM_PROTOCOLS[name], None)
        if kind in ("icmpv4object", "icmpv6object", "icmpv4portliteral", "icmpv6portliteral"):
            return self._icmp(Protocol.ICMP6 if "v6" in kind else Protocol.ICMP, obj.get("icmpType"), obj.get("code"))
        if kind not in ("protocolportobject", "portliteral"):
            return None, f"port of type '{kind[:30]}'"
        raw = obj.get("protocol")
        text = str(raw) if isinstance(raw, int) and not isinstance(raw, bool) else _s(raw)
        number = protocol_number(text)
        if number is None:
            return None, f"protocol '{text[:40]}', which is not a protocol FWShift knows the number of"
        if number in (1, 58) and ("icmpType" in obj or "code" in obj):
            return self._icmp(Protocol.ICMP if number == 1 else Protocol.ICMP6, obj.get("icmpType"), obj.get("code"))
        return self._by_number(number, obj.get("port"))

    def _by_number(self, number: int, port: Any) -> Tuple[Optional[ServiceEntry], str]:
        by_number = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}
        if number in by_number and number != 132:
            return self._l4(by_number[number], port)
        if port is not None and port != "":
            return None, f"a port ({str(port)[:20]}) for IP protocol {number}"
        if number == 132:
            return ServiceEntry(Protocol.SCTP), ""
        if number == 1:
            return ServiceEntry(Protocol.ICMP), ""
        if number == 58:
            return ServiceEntry(Protocol.ICMP6), ""
        return ServiceEntry(Protocol.IP, ip_protocol=number), ""

    @staticmethod
    def _l4(protocol: Protocol, port: Any) -> Tuple[Optional[ServiceEntry], str]:
        text = str(port) if isinstance(port, int) and not isinstance(port, bool) else _s(port)
        text = text.replace(" ", "")
        if port is None or port == "":
            return ServiceEntry(protocol), ""  # a port object of a Management Center without a port: every port
        if not valid_ports(text) or "," in text:
            return None, f"port '{text[:40]}'"
        return ServiceEntry(protocol, dst_ports=text), ""

    @staticmethod
    def _icmp(protocol: Protocol, icmp_type: Any, code: Any) -> Tuple[Optional[ServiceEntry], str]:
        def number(value: Any) -> Tuple[Optional[int], bool]:
            """(the number, whether the value could be read); no value and "Any" are every type or code."""
            if _blank(value):
                return None, True
            if isinstance(value, str) and value.strip().lower() == "any":
                return None, True
            found = _number(value)
            return found, found is not None and 0 <= found <= 255

        kind, kind_ok = number(icmp_type)
        sub, sub_ok = number(code)
        if not kind_ok:
            return None, f"ICMP type '{str(icmp_type)[:20]}'"
        if not sub_ok:
            return None, f"ICMP code '{str(code)[:20]}'"
        if kind is None and sub is not None:
            return None, f"ICMP code {sub} of every type"
        return ServiceEntry(protocol, icmp_type=kind, icmp_code=sub), ""

    def _service_ref(self, ref: Any, problems: List[str]) -> str:
        record = self.source.find(ref)
        if record is not None and id(record) in self.service_of:
            return self.service_of[id(record)]
        kind, name = _s(_d(ref).get("type")), _s(_d(ref).get("name"))
        if not isinstance(ref, dict) or not (name or _s(ref.get("id"))):
            problems.append("a reference without a name")
            return ""
        if kind.lower() in _PORT_TYPES:
            why = f"port object '{name[:60]}', which is not in the input in full"
        else:
            why = f"object '{name[:60]}' of type '{kind[:30]}', which is no port object"
        new = self._model_name("service", name or kind, self.service_names)
        self.p.services[new] = Service(new, [], unsupported=why)
        self.report.add("service", new, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{why}: what uses it is not converted")
        if record is not None:
            self.service_of[id(record)] = new
        return new

    def _inline(self, entries: List[ServiceEntry], hint: str = "") -> str:
        """The service for protocols and ports that a rule spells out."""
        key = _key(entries)
        if key not in self.inline:
            if hint:
                label = hint
            elif len(entries) == 1:
                label = _label(entries[0])
            else:
                label = "-".join([_label(entry) for entry in entries[:2]] + (["etc"] if len(entries) > 2 else []))
            name = _unique(label, self.service_names)
            self.p.services[name] = Service(name, list(entries))
            self.inline[key] = name
        return self.inline[key]

    # -- what a rule matches ----------------------------------------------

    @staticmethod
    def _parts(value: Any, what: str, problems: List[str]) -> Tuple[List[Any], List[Any]]:
        """(references, literals) of a condition. A Device Manager gives a list, a Management Center two."""
        if value is None:
            return [], []
        if isinstance(value, list):
            return value, []
        if not isinstance(value, dict):
            problems.append(f"{what} that could not be read")
            return [], []
        for key, inner in value.items():
            if key not in ("objects", "literals", "type", "links") and not _blank(inner, False):
                problems.append(f"'{key[:30]}' in the {what}")
        for key in ("objects", "literals"):
            if value.get(key) is not None and not isinstance(value[key], list):
                problems.append(f"'{key}' of the {what}, which is not a list")
        return _l(value.get("objects")), _l(value.get("literals"))

    def _networks(self, value: Any, what: str, problems: List[str]) -> List[str]:
        objects, literals = self._parts(value, what, problems)
        out = [self._address_ref(ref, problems) for ref in objects]
        out += [self._address_literal(literal, problems) for literal in literals]
        return transform.dedupe([member for member in out if member]) or [ANY]

    def _ports(self, value: Any, what: str, problems: List[str]) -> List[str]:
        """The services of a port condition, by name; empty when the rule has none."""
        objects, literals = self._parts(value, what, problems)
        out = [self._service_ref(ref, problems) for ref in objects]
        for literal in literals:
            entry, problem = self._port_entry(_d(literal), _s(_d(literal).get("type")) or "portliteral")
            if entry is None:
                problems.append(problem)
            else:
                out.append(self._inline([entry]))
        return transform.dedupe([name for name in out if name])

    def _rule_services(self, obj: Obj, problems: List[str]) -> List[str]:
        """Source and destination ports of a rule must both match: the services that say so."""
        sources = self._ports(obj.get("sourcePorts"), "source ports", problems)
        destinations = self._ports(obj.get("destinationPorts"), "destination ports", problems)
        if not sources:
            return destinations or [ANY]
        from_ports: List[ServiceEntry] = []
        for name in sources:
            entries = transform.flatten_services(self.p, name)
            if entries is None or any(entry.protocol not in L4_PROTOCOLS or entry.src_ports for entry in entries):
                problems.append(f"source port '{name[:40]}', which is not a TCP or UDP port")
                return [ANY]
            from_ports += entries
        if not destinations:
            combined = [ServiceEntry(entry.protocol, src_ports=entry.dst_ports) for entry in from_ports]
        else:
            to_ports: List[ServiceEntry] = []
            for name in destinations:
                entries = transform.flatten_services(self.p, name)
                if entries is None:
                    problems.append(f"destination port '{name[:40]}', which could not be read")
                    return [ANY]
                to_ports += entries
            combined = [
                ServiceEntry(target.protocol, dst_ports=target.dst_ports, src_ports=origin.dst_ports)
                for origin in from_ports for target in to_ports
                if target.protocol == origin.protocol and not target.src_ports
            ]  # fmt: skip
            if not combined:
                problems.append("source ports and destination ports that share no protocol")
                return [ANY]
        unique: List[ServiceEntry] = []
        for entry in combined:
            if entry not in unique:
                unique.append(entry)
        return [self._inline(unique)]

    def _zone_list(self, value: Any, what: str, problems: List[str]) -> List[str]:
        objects, literals = self._parts(value, what, problems)
        if literals:
            problems.append(f"{what} given as something else than zones")
        return transform.dedupe([self._zone_ref(ref, problems) for ref in objects]) or [ANY]

    def _interface_list(self, value: Any, what: str, problems: List[str]) -> List[str]:
        """Zones for the interface objects of a prefilter rule: a zone, or a group that is whole zones."""
        objects, literals = self._parts(value, what, problems)
        if literals:
            problems.append(f"{what} given as something else than interface objects")
        zones: List[str] = []
        for ref in objects:
            if _s(_d(ref).get("type")).lower() != "interfacegroup":
                zones.append(self._zone_ref(ref, problems))
                continue
            found, exact = self._group_zones(ref)
            if not exact:
                problems.append(f"interface group '{_s(_d(ref).get('name'))[:40]}', which is not the interfaces of whole security zones")
            zones += found
        return transform.dedupe(zones) or [ANY]

    def _zones_of(self, interface: Optional[_Interface]) -> List[str]:
        return [zone for zone, members in self.members.items() if any(interface is member for member in members)]

    def _group_zones(self, ref: Any) -> Tuple[List[str], bool]:
        """(zones the interfaces of an interface group are in, whether the group is all the interfaces of those zones)."""
        record = self.source.find(ref)
        refs = _l(record.obj.get("interfaces")) if record is not None else []
        held = [self._interface_of(inner) for inner in refs]
        if not held or any(interface is None for interface in held):
            return [], False
        zones: List[str] = []
        for interface in held:
            names = self._zones_of(interface)
            if len(names) != 1:
                return [], False
            if names[0] not in zones:
                zones.append(names[0])
        exact = all(any(member is other for other in held) for zone in zones for member in self.members[zone])
        return zones, exact

    # -- access rules -----------------------------------------------------

    def _rule(self, record: _Record, prefilter: bool = False) -> Optional[Rule]:
        """The rule of the model for an access rule or a prefilter rule; None for one that decides nothing."""
        obj = record.obj
        name = _unique(_s(obj.get("name")) or "rule", self.rule_names)
        rule = Rule(name=name, origin=name)
        problems = rule.unsupported
        action = _s(obj.get("ruleAction" if self.fdm else "action")).upper()
        if "action" not in obj and "ruleAction" not in obj:
            # A rule the manager listed without its content (no expanded=true): not a rule that matches everything.
            problems.append("rule that is in the input by name only (fetch the rules with expanded=true)")
            rule.action = Action.DENY
            self._review_listing()
            return rule
        if self.fdm:
            rule.enabled = obj.get("enabled") is not False  # a Device Manager has no rules that are switched off
        elif isinstance(obj.get("enabled"), bool):
            rule.enabled = bool(obj["enabled"])
        else:
            problems.append("rule that does not say whether it is enabled")
        kind = _s(obj.get("ruleType")).upper() if prefilter else ""
        if prefilter:
            rule.src_zones = self._interface_list(obj.get("sourceInterfaces"), "source interfaces", problems)
            rule.dst_zones = self._interface_list(obj.get("destinationInterfaces"), "destination interfaces", problems)
        else:
            rule.src_zones = self._zone_list(obj.get("sourceZones"), "source zones", problems)
            rule.dst_zones = self._zone_list(obj.get("destinationZones"), "destination zones", problems)
        rule.sources = self._networks(obj.get("sourceNetworks"), "source networks", problems)
        rule.destinations = self._networks(obj.get("destinationNetworks"), "destination networks", problems)
        if kind == "TUNNEL":
            rule.services = self._tunnel_services(obj, problems)
        else:
            rule.services = self._rule_services(obj, problems)
            if prefilter and kind != "PREFILTER":
                problems.append(f"prefilter rule of type '{kind[:30]}'")
            for extra in ("encapsulationPorts", "tunnelZone", "bidirectional"):
                if prefilter and not _blank(obj.get(extra)):
                    problems.append(f"'{extra}' on a rule that is not a tunnel rule")
        for key, what in _CONDITIONS:
            if not _blank(obj.get(key)):
                problems.append(what)
        users = [_s(_d(user).get("name")) or "a user" for user in self._parts(obj.get("users"), "users", problems)[0]]
        if users:
            rule.users = transform.dedupe(users)
        times = [_s(_d(entry).get("name")) or "a time range" for entry in _l(obj.get("timeRangeObjects"))]
        if times:
            rule.schedule = ", ".join(transform.dedupe(times))
        elif not _blank(obj.get("timeRangeObjects")):
            problems.append("a time range")
        for key in obj:
            known = key in _RULE_FIELDS or key in ("users", "timeRangeObjects") or any(key == condition for condition, _ in _CONDITIONS)
            if not known and not _blank(obj[key]):
                problems.append(f"field '{key[:30]}', which FWShift does not know")
        rule.unsupported[:] = transform.dedupe(problems)
        self._logging(rule, obj)
        rule.description = self._description(obj)
        category = _s(_d(obj.get("metadata")).get("category"))
        if category and category != "--Undefined--":
            rule.tags = [category]
        for field_name, label in (("ipsPolicy", "intrusion"), ("intrusionPolicy", "intrusion"), ("filePolicy", "file")):
            policy_name = _s(_d(obj.get(field_name)).get("name"))
            if policy_name:
                rule.profiles[label] = policy_name
        return self._decide(rule, action, kind, prefilter)

    def _review_listing(self) -> None:
        self.report.note(
            Severity.REVIEW, "RULES_NOT_EXPANDED",
            "rules are in the input by name only: the manager lists them that way unless it is asked for expanded=true. "
            "They are kept in their place and not converted",
        )  # fmt: skip

    def _decide(self, rule: Rule, action: str, kind: str, prefilter: bool) -> Optional[Rule]:
        name = rule.origin
        actions = {"ALLOW": Action.ALLOW, "PERMIT": Action.ALLOW, "TRUST": Action.ALLOW, "FASTPATH": Action.ALLOW,
                   "BLOCK": Action.DROP, "DENY": Action.DROP, "BLOCK_RESET": Action.RESET_BOTH,
                   "BLOCK_INTERACTIVE": Action.DROP, "BLOCK_RESET_INTERACTIVE": Action.RESET_BOTH}  # fmt: skip
        if prefilter and action == "ANALYZE":
            self.report.skip(
                "rule", name, "PREFILTER_ANALYZE",
                "prefilter rule with the action Analyze: it hands its traffic to the access rules, which is what happens "
                "to traffic no prefilter rule matches. Nothing to convert",
                Severity.INFO,
            )  # fmt: skip
            if rule.enabled:
                self.analyzed.append(rule)
            return None
        if action == "MONITOR" and not prefilter and not self.fdm:
            self.report.skip(
                "rule", name, "MONITOR_RULE",
                "rule with the action Monitor: it logs the traffic and leaves the decision to the rules below it. "
                "Nothing to convert",
                Severity.INFO,
            )  # fmt: skip
            return None
        if prefilter:
            valid: Tuple[str, ...] = ("FASTPATH", "BLOCK")
        elif self.fdm:
            valid = ("PERMIT", "TRUST", "DENY")
        else:
            valid = ("ALLOW", "TRUST", "BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE")
        if action not in valid:
            rule.unsupported.append(f"action '{action[:30]}', which FWShift does not know")
            rule.action = Action.DENY
            return rule
        rule.action = actions[action]
        if action in ("TRUST", "FASTPATH"):
            rule.handling["inspection"] = "none (trust)" if action == "TRUST" else "none (fastpath)"
        if "INTERACTIVE" in action:
            self.report.add(
                "rule", name, Severity.APPROX, "INTERACTIVE_BLOCK",
                "the source showed web users a page from which they could go on to the site (Interactive Block); it is "
                "converted as a rule that blocks",
            )  # fmt: skip
        if kind == "TUNNEL":
            self.report.add(
                "rule", name, Severity.APPROX, "TUNNEL_RULE",
                "tunnel rule of the prefilter policy: it is converted as a rule for the protocol that carries the tunnel, "
                "between the tunnel endpoints. What the source did with the connections inside the tunnel is not converted",
            )  # fmt: skip
        if prefilter and rule.enabled:
            self._after_analyze(rule)
        return rule

    def _after_analyze(self, rule: Rule) -> None:
        """A prefilter rule below an Analyze rule does not get the traffic of that rule: one list cannot say that."""
        for earlier in self.analyzed:
            if not self._may_overlap(earlier, rule):
                continue
            if rule.action == Action.ALLOW:
                rule.unsupported.append(
                    f"prefilter rule '{earlier.name}' above it hands part of the traffic it matches to the access rules "
                    "(Analyze), and one list of rules cannot make that exception"
                )
            else:
                self.report.add(
                    "rule", rule.origin, Severity.REVIEW, "PREFILTER_ANALYZE",
                    f"prefilter rule '{earlier.name}' above it hands part of the traffic it matches to the access rules "
                    "(Analyze). One list of rules cannot make that exception: this rule now blocks that traffic too",
                )  # fmt: skip
            return

    def _may_overlap(self, a: Rule, b: Rule) -> bool:
        if a.unsupported:
            return True  # what it matches is not known
        for mine, theirs in ((a.src_zones, b.src_zones), (a.dst_zones, b.dst_zones)):
            if ANY not in mine and ANY not in theirs and not set(mine) & set(theirs):
                return False
        for mine, theirs in ((a.sources, b.sources), (a.destinations, b.destinations)):
            if ANY in mine or ANY in theirs:
                continue
            left = [transform.known_intervals(self.p, member) for member in mine]
            right = [transform.known_intervals(self.p, member) for member in theirs]
            if all(complete for _, complete in left + right) and not overlaps(
                [i for found, _ in left for i in found], [i for found, _ in right for i in found]
            ):
                return False
        return True

    def _tunnel_services(self, obj: Obj, problems: List[str]) -> List[str]:
        entries: List[ServiceEntry] = []
        for word in _l(obj.get("encapsulationPorts")):
            entry = _ENCAPSULATION.get(_s(word).upper())
            if entry is None:
                problems.append(f"encapsulation '{str(word)[:30]}'")
            elif entry not in entries:
                entries.append(entry)
        if not entries:
            problems.append("tunnel rule without an encapsulation")
            return [ANY]
        for side in ("sourcePorts", "destinationPorts"):
            if not _blank(obj.get(side)):
                problems.append("ports on a tunnel rule")
        if not _blank(obj.get("tunnelZone")):
            problems.append("a tunnel zone on a rule that does not hand the tunnel to the access rules")
        return [self._inline([entry]) for entry in entries]

    def _logging(self, rule: Rule, obj: Obj) -> None:
        if self.fdm:
            mode = _s(obj.get("eventLogAction")).upper()
            rule.log_start, rule.log_end = mode in ("LOG_BOTH", "LOG_FLOW_START"), mode in ("LOG_BOTH", "LOG_FLOW_END")
        else:
            rule.log_start, rule.log_end = obj.get("logBegin") is True, obj.get("logEnd") is True

    @staticmethod
    def _description(obj: Obj) -> str:
        text = _s(obj.get("description"))
        if text:
            return text
        comments = [_s(_d(entry).get("comment")) for entry in _l(obj.get("commentHistoryList"))]
        return "; ".join(comment for comment in comments if comment)[:400]

    def _default_rule(self, name: str, action: str, known: bool) -> None:
        """What happens to traffic no rule matches."""
        allow = action in ("PERMIT", "TRUST", "NETWORK_DISCOVERY", "ALLOW")
        if not known:
            self.report.note(
                Severity.REVIEW, "DEFAULT_ACTION_UNKNOWN",
                "the input does not hold the access control policy itself, so its default action is not known: it was "
                "taken to block. Fetch the policy as well, or check what the source does with traffic no rule matches",
            )  # fmt: skip
        elif not allow and action not in ("BLOCK", "DENY"):
            self.report.note(
                Severity.REVIEW, "DEFAULT_ACTION_UNKNOWN",
                f"the default action of '{name}' is '{action[:30]}', which FWShift does not know: it was taken to block",
            )  # fmt: skip
        self.p.default_intrazone = self.p.default_interzone = Action.ALLOW if allow else Action.DENY

    # -- access rules of a Device Manager ----------------------------------

    def _fdm_rules(self) -> None:
        metadata = self.source.metadata
        version, model = _s(metadata.get("softwareVersion")), _s(metadata.get("hardwareModel"))
        if version and model:
            self.p.scope = _FDM_SCOPE.format(version=version, model=model)
        records = self.source.of(*_ACCESS_RULES)
        if all(record.index is not None for record in records) and len({record.index for record in records}) == len(records):
            records.sort(key=lambda record: record.index or 0)
        for record in records:
            rule = self._rule(record)
            if rule is not None:
                self.p.rules.append(rule)
        policies = [record for record in self.source.of("accesspolicy") if "defaultAction" in record.obj]
        if policies:
            policy = policies[0].obj
            self._default_rule(_s(policy.get("name")), _s(_d(policy.get("defaultAction")).get("action")).upper(), True)
        elif records:
            self._default_rule("", "", False)

    # -- access rules of a Management Center -------------------------------

    @staticmethod
    def _holder(record: _Record, collection: str) -> str:
        """The id of the policy a rule is in: the manager says it in the rule, and in the address of the rule."""
        named = _s(_d(_d(record.obj.get("metadata")).get("accessPolicy")).get("id")) if collection == "accesspolicies" else ""
        if named:
            return named
        match = _POLICY_LINK.search(_s(_d(record.obj.get("links")).get("self")))
        return match.group(2) if match and match.group(1) == collection else ""

    def _policy_name(self, ident: str) -> str:
        record = self.source.get(ident, *_POLICY_KINDS)
        return _s(record.obj.get("name")) if record is not None and _s(record.obj.get("name")) else ident or "(not named)"

    def _parent(self, ident: str) -> str:
        """The id of the policy an access control policy inherits from, as far as the input tells."""
        return self._inheritance(ident)[0]

    def _inheritance(self, ident: str) -> Tuple[str, bool]:
        """(id of the policy it inherits from or "", whether the input says anything about that)."""
        if ident in self.inherits:
            return self.inherits[ident]
        record = self.source.get(ident, "accesspolicy")
        metadata = _d(record.obj.get("metadata")) if record is not None else {}
        parent = _s(_d(metadata.get("parentPolicy")).get("id"))
        known = bool(parent) or isinstance(metadata.get("inherit"), bool)
        if not parent:
            for setting in self.source.of("accesspolicyinheritancesetting"):
                link = _s(_d(setting.obj.get("links")).get("self"))
                if f"/accesspolicies/{ident}/" in link or _s(setting.obj.get("id")) == ident:
                    parent = _s(_d(setting.obj.get("basePolicy")).get("id")) or parent
                    known = True
        if not parent:
            # The list of its rules holds rules that say they are those of another policy: the manager lists
            # the rules a policy inherits with its own.
            listed = {rule for link, _, ids in self.source.lists if f"/accesspolicies/{ident}/accessrules" in link + "/" for rule in ids}
            for rule in sorted(listed):
                held = self.source.get(rule, *_ACCESS_RULES)
                other = _s(_d(_d(held.obj.get("metadata")).get("accessPolicy")).get("id")) if held is not None else ""
                if other and other != ident:
                    parent, known = other, True
                    break
        self.inherits[ident] = (parent if parent != ident else "", known)
        return self.inherits[ident]

    def _labels(self, candidates: List[str]) -> str:
        """The names of policies; with their ids where two have one name (two domains of a manager, say)."""
        names = [self._policy_name(ident) for ident in candidates]
        shown = sorted(name if names.count(name) == 1 or name == ident else f"{name} (id {ident})" for name, ident in zip(names, candidates))
        return ", ".join(shown)[:400] or "none"

    def _choose(self, candidates: List[str], wanted: str, what: str, option: str) -> str:
        if wanted:
            found = [ident for ident in candidates if wanted in (ident, self._policy_name(ident))]
            if len(found) > 1:
                raise ParseError(f"{len(found)} {what[:-1]}ies are named '{wanted[:60]}': give {option} the id of one ({self._labels(found)})")
            if not found:
                raise ParseError(f"{what} '{wanted[:60]}' is not in the input (found: {self._labels(candidates)})")
            return found[0]
        if len(candidates) > 1:
            raise ParseError(f"the input holds several {what[:-1]}ies ({self._labels(candidates)}): choose one with {option}")
        return candidates[0] if candidates else ""

    def _fmc_rules(self) -> None:
        by_policy: Dict[str, List[_Record]] = {}
        for record in self.source.of(*_ACCESS_RULES):
            by_policy.setdefault(self._holder(record, "accesspolicies"), []).append(record)
        policies = transform.dedupe([record.obj["id"] for record in self.source.of("accesspolicy")
                                     if _s(record.obj.get("id")) and ("defaultAction" in record.obj or "rules" in record.obj)]
                                    + [ident for ident in by_policy if ident])  # fmt: skip
        parents = {self._parent(ident) for ident in policies}
        leaves = [ident for ident in policies if ident not in parents]
        if not policies and "" in by_policy:
            chosen = ""
        else:
            chosen = self._choose(leaves if not self.wanted_policy else policies, self.wanted_policy,
                                  "access control policy", "--policy")  # fmt: skip
        if not chosen and "" not in by_policy:
            if self.wanted_policy:
                raise ParseError(f"access control policy '{self.wanted_policy[:60]}' is not in the input")
            return  # objects and NAT rules only
        if chosen and "" in by_policy:
            # Rules that do not say which policy they are in: they can only be those of the one policy there is.
            if len(policies) > 1:
                raise ParseError(
                    f"{len(by_policy[''])} access rules do not say which policy they are in (no metadata, no link), and the "
                    "input holds several access control policies: fetch the rules of one policy, with expanded=true"
                )
            by_policy.setdefault(chosen, []).extend(by_policy.pop(""))
            by_policy[chosen].sort(key=lambda record: record.seq)
        self.p.scope = self._policy_name(chosen) if chosen else ""
        chain = [chosen]
        while len(chain) <= _MAX_PARENTS and self._parent(chain[-1]) and self._parent(chain[-1]) not in chain:
            chain.append(self._parent(chain[-1]))
        chain.reverse()  # the policy at the top first
        policy = self.source.get(chosen, "accesspolicy")
        self._prefilter(policy.obj if policy is not None else {}, policy is not None and "defaultAction" in policy.obj)
        missing = [f"'{self._policy_name(ident)}'" for ident in chain[:-1]
                   if ident not in by_policy and not self._listing_seen("accesspolicies", ident)]  # fmt: skip
        inherits = policy is not None and _d(policy.obj.get("metadata")).get("inherit") is True
        if inherits and len(chain) == 1:
            missing = ["a policy the input does not name"]
        if missing:
            self.report.note(
                Severity.REVIEW, "PARENT_POLICY_MISSING",
                f"'{self.p.scope}' inherits from " + ", ".join(missing) + ", whose rules are not in the input: its "
                "mandatory rules come before the rules that were read and its default rules after them. Fetch its rules "
                "as well, and convert again",
            )  # fmt: skip
        top = chain[0]
        if top and not self._inheritance(top)[1] and not (inherits and len(chain) == 1):
            others = len(policies) > 1
            self.report.note(
                Severity.REVIEW, "INHERITANCE_UNKNOWN",
                f"the input does not say whether access control policy '{self._policy_name(top)}' inherits from another policy"
                + (" (it holds other policies)" if others else "") + ". If it does, the mandatory rules of that policy come before "
                "the rules that were read and its default rules after them, and they are not in what was converted. Fetch "
                f"policy/accesspolicies/{top}/inheritancesettings as well (section 3 of the manual), and convert again",
            )  # fmt: skip
        if chosen and not by_policy.get(chosen) and not self._listing_seen("accesspolicies", chosen):
            self.report.note(
                Severity.REVIEW, "EXPORT_INCOMPLETE",
                f"the input holds access control policy '{self.p.scope}' and no list of its rules "
                f"(policy/accesspolicies/{chosen}/accessrules): it was read as a policy without rules of its own",
            )  # fmt: skip
        ordered: List[_Record] = []
        sections: Dict[str, Tuple[List[_Record], List[_Record]]] = {}
        for ident in chain:
            sections[ident] = self._sections(by_policy.get(ident, []), split=len(chain) > 1)
            ordered += sections[ident][0]
        for ident in reversed(chain):
            ordered += sections[ident][1]
        for record in ordered:
            rule = self._rule(record)
            if rule is not None:
                self.p.rules.append(rule)
        action, name, known = "", self.p.scope, False
        for ident in reversed(chain):  # its own default action, or the one it inherits
            held = self.source.get(ident, "accesspolicy")
            default = _d(held.obj.get("defaultAction")) if held is not None else {}
            action = _s(default.get("action")).upper()
            if not action and default:
                for other in self.source.of("accesspolicydefaultaction"):
                    link = _s(_d(other.obj.get("links")).get("self"))
                    if _s(other.obj.get("id")) == _s(default.get("id")) or f"/accesspolicies/{ident}/" in link:
                        action = _s(other.obj.get("action")).upper() or action
            if action and action != "INHERIT_FROM_PARENT":
                name, known = self._policy_name(ident), True
                break
        self._default_rule(name, action, known)

    def _listing_seen(self, collection: str, ident: str) -> bool:
        """Whether the input holds an answer that lists the rules of a policy, even an empty one."""
        rules = {"accesspolicies": "accessrules", "prefilterpolicies": "prefilterrules"}[collection]
        return any(f"/{collection}/{ident}/{rules}/" in link + "/" for link, _, _ in self.source.lists)

    def _sections(self, records: List[_Record], split: bool) -> Tuple[List[_Record], List[_Record]]:
        """(mandatory rules, default rules) of one policy, each in the order of evaluation."""

        def index(record: _Record) -> Optional[int]:
            metadata = _d(record.obj.get("metadata"))
            return _number(metadata.get("ruleIndex")) if "ruleIndex" in metadata else _number(record.obj.get("ruleIndex"))

        def section(record: _Record) -> str:
            return (_s(_d(record.obj.get("metadata")).get("section")) or _s(record.obj.get("section"))).lower()

        odd = transform.dedupe([section(record) for record in records if section(record) not in ("", "mandatory", "default")])
        if odd:
            self.report.note(
                Severity.REVIEW, "RULE_SECTIONS_UNKNOWN",
                f"rules say they are in a section FWShift does not know ({', '.join(odd)[:80]}): they were read as mandatory "
                "rules, in the place their index gives them",
            )  # fmt: skip

        indexes = [index(record) for record in records]
        if records and all(number is not None for number in indexes) and len(set(indexes)) == len(indexes):
            records = sorted(records, key=lambda record: index(record) or 0)
        if not all(section(record) for record in records):
            if split and records:
                self.report.note(
                    Severity.REVIEW, "RULE_SECTIONS_UNKNOWN",
                    "the rules do not say whether they are mandatory or default rules, which decides where the rules of "
                    "the policy they inherit from or that inherits from them go: they were read as mandatory rules",
                )  # fmt: skip
            return list(records), []
        return ([record for record in records if section(record) != "default"],
                [record for record in records if section(record) == "default"])  # fmt: skip

    def _prefilter(self, policy: Obj, known: bool) -> None:
        """The prefilter policy of the access control policy: its rules come first.

        ``known``: the input holds the access control policy itself, which names its prefilter policy.
        """
        by_policy: Dict[str, List[_Record]] = {}
        for record in self.source.of("prefilterrule"):
            by_policy.setdefault(self._holder(record, "prefilterpolicies"), []).append(record)
        setting = _d(policy.get("prefilterPolicySetting"))
        ident, name = _s(setting.get("id")), _s(setting.get("name"))
        if not ident:
            held_rules = [key for key in by_policy if key] or ([""] if "" in by_policy else [])
            if not held_rules:
                return
            if len(held_rules) > 1:
                names = ", ".join(sorted(self._policy_name(key) for key in held_rules))
                self.report.note(
                    Severity.REVIEW, "PREFILTER_NOT_READ",
                    f"the input holds the rules of several prefilter policies ({names[:200]}) and not the access control "
                    "policy that says which one it uses: none was read. Prefilter rules come before the access rules",
                )  # fmt: skip
                return
            ident = held_rules[0]
            self.report.note(
                Severity.INFO, "PREFILTER_ASSUMED",
                f"the rules of prefilter policy '{self._policy_name(ident)}' are in the input and were read as the "
                "prefilter of the access control policy, which the input does not say",
            )  # fmt: skip
        records = by_policy.get(ident, [])
        held = self.source.get(ident, "prefilterpolicy")
        system = held is not None and self._system(held.obj)
        if not records and not self._listing_seen("prefilterpolicies", ident) and not system and name != "Default Prefilter Policy":
            self.report.note(
                Severity.REVIEW, "PREFILTER_MISSING",
                f"the access control policy uses prefilter policy '{name or self._policy_name(ident)}', whose rules are not "
                "in the input. Prefilter rules come before the access rules, and one that blocks or fastpaths decides "
                "its traffic before any of them: fetch them as well, and convert again",
            )  # fmt: skip
        indexes = [_number(_d(record.obj.get("metadata")).get("ruleIndex")) for record in records]
        if records and all(number is not None for number in indexes) and len(set(indexes)) == len(indexes):
            records = [record for _, record in sorted(zip(indexes, records), key=lambda pair: pair[0] or 0)]
        for record in records:
            rule = self._rule(record, prefilter=True)
            if rule is None:
                continue
            self.p.rules.append(rule)
            if _s(record.obj.get("ruleType")).upper() == "TUNNEL" and record.obj.get("bidirectional") is True:
                self.p.rules.append(self._mirror(rule))
        default = _s(_d(held.obj.get("defaultAction")).get("action")).upper() if held is not None else ""
        if not default and known:
            self.report.note(
                Severity.REVIEW, "PREFILTER_DEFAULT_UNKNOWN",
                f"the input does not hold prefilter policy '{name or self._policy_name(ident)}' itself, so it is not known "
                "whether it blocks tunnel traffic that none of its rules match (GRE, IP in IP, IPv6 in IP, Teredo) or "
                "hands it to the access rules: it was read as handing it on. Fetch the prefilter policy as well",
            )  # fmt: skip
        if default == "BLOCK_TUNNELS":
            last = _unique("prefilter-default-block-tunnels", self.rule_names)
            rule = Rule(name=last, origin=last, action=Action.DROP, log_end=False,
                        services=[self._inline([entry]) for entry in _ENCAPSULATION.values()],
                        description="Default action of the prefilter policy: block tunnel traffic.")  # fmt: skip
            for earlier in self.analyzed:
                if self._may_overlap(earlier, rule):
                    self.report.add(
                        "rule", last, Severity.REVIEW, "PREFILTER_ANALYZE",
                        f"prefilter rule '{earlier.name}' hands tunnels to the access rules (Analyze). One list of rules "
                        "cannot make that exception: the default action of the prefilter policy now blocks them too",
                    )  # fmt: skip
                    break
            self.p.rules.append(rule)

    def _mirror(self, rule: Rule) -> Rule:
        """The other direction of a tunnel rule that matches tunnels from source and destination."""
        name = _unique(f"{rule.name}-reverse", self.rule_names)
        services: List[str] = []
        for service in rule.services:
            entries = transform.flatten_services(self.p, service) or []
            turned = [ServiceEntry(entry.protocol, src_ports=entry.dst_ports) if entry.protocol in L4_PROTOCOLS and entry.dst_ports
                      else entry for entry in entries]  # fmt: skip
            services.append(service if turned == entries else self._inline(turned))
        mirrored = Rule(
            name=name, origin=name, src_zones=list(rule.dst_zones), dst_zones=list(rule.src_zones),
            sources=list(rule.destinations), destinations=list(rule.sources), services=services, action=rule.action,
            enabled=rule.enabled, log_start=rule.log_start, log_end=rule.log_end, description=rule.description,
            schedule=rule.schedule, handling=dict(rule.handling), unsupported=list(rule.unsupported),
        )  # fmt: skip
        self.report.add("rule", name, Severity.INFO, "TUNNEL_RULE",
                        f"the other direction of tunnel rule '{rule.name}', which matches tunnels from source and destination")  # fmt: skip
        return mirrored

    # -- NAT --------------------------------------------------------------

    def _nat(self) -> None:
        records = self.source.of(*_NAT_RULES)
        if not self.fdm:
            by_policy: Dict[str, List[_Record]] = {}
            for record in records:
                by_policy.setdefault(self._holder(record, "ftdnatpolicies"), []).append(record)
            known = [ident for ident in by_policy if ident]
            if known and "" in by_policy and len(known) > 1:
                raise ParseError(
                    f"{len(by_policy[''])} NAT rules do not say which NAT policy they are in (no link), and the input holds "
                    "several NAT policies: fetch the rules of one policy, with expanded=true"
                )
            if known:
                chosen = self._choose(known, self.wanted_nat, "NAT policy", "--nat-policy")
                records = sorted(by_policy[chosen] + by_policy.get("", []), key=lambda record: record.seq)
            elif self.wanted_nat:
                raise ParseError(f"NAT policy '{self.wanted_nat[:60]}' is not in the input")
        before: List[Tuple[Tuple[int, int], NatRule]] = []
        after: List[Tuple[Tuple[int, int], NatRule]] = []
        automatic: List[Tuple[Tuple[int, int, int, str], NatRule]] = []
        counts = {"before": 0, "after": 0}
        for record in records:
            obj = record.obj
            manual = record.kind in ("ftdmanualnatrule", "manualnatrule")
            position = record.index if record.index is not None else _number(_d(obj.get("metadata")).get("index"))
            if manual:
                late = self._after_auto(record)
                counts["after" if late else "before"] += 1
                default = f"nat-after-auto-{counts['after']}" if late else f"nat-{counts['before']}"
                nat = self._nat_rule(record, _unique(_s(obj.get("name")) or default, self.nat_names), True)
                (after if late else before).append(((position if position is not None else 10**9, record.seq), nat))
            else:
                real = self.source.find(obj.get("originalNetwork"))
                label = self.address_of.get(id(real), "") if real is not None else ""
                nat = self._nat_rule(record, _unique(_s(obj.get("name")) or f"nat-{label or 'auto'}", self.nat_names), False)
                intervals = transform.address_intervals(self.p, label) or [] if label else []
                # The device sorts automatic NAT: static before dynamic, then the fewest real addresses,
                # then the lowest address, then the name of the object.
                key = (
                    0 if _s(obj.get("natType")).upper() == "STATIC" else 1,
                    sum(size(i) for i in intervals) if intervals else 2**129,
                    intervals[0][1] if intervals else 0,
                    _s(_d(obj.get("originalNetwork")).get("name")),
                )
                automatic.append((key, nat))
        before.sort(key=lambda item: item[0])
        after.sort(key=lambda item: item[0])
        automatic.sort(key=lambda item: item[0])
        self.p.nat_rules = [nat for _, nat in before] + [nat for _, nat in automatic] + [nat for _, nat in after]

    def _after_auto(self, record: _Record) -> bool:
        obj = record.obj
        section = (_s(_d(obj.get("metadata")).get("section")) or _s(obj.get("section"))).upper()
        if section:
            return section == "AFTER_AUTO"
        if not self.fdm:
            return False
        # A Device Manager keeps manual rules in two holders; the rule is in one of them.
        holder = self.source.by_name.get(("manualnatrulecontainer", record.parent)) if record.parent else None
        if holder is None:
            match = _POLICY_LINK.search(_s(_d(obj.get("links")).get("self")))
            holder = self.source.get(match.group(2), "manualnatrulecontainer") if match else None
        if holder is not None and isinstance(holder.obj.get("afterAuto"), bool):
            return bool(holder.obj["afterAuto"])
        return "after" in record.parent.lower()

    @staticmethod
    def _no_ref(ref: Any, what: str, problems: List[str]) -> bool:
        """Whether a field of a NAT rule names nothing. What is there and is no reference is a problem, not nothing."""
        if ref is None or (isinstance(ref, dict) and _blank(ref)):
            return True
        if not isinstance(ref, dict):
            problems.append(f"{what} that could not be read")
            return True
        return False

    def _nat_ref(self, ref: Any, problems: List[str]) -> str:
        if self._no_ref(ref, "an address", problems):
            return ""
        name = self._address_ref(ref, problems)
        return name

    def _nat_port(self, ref: Any, problems: List[str]) -> Optional[ServiceEntry]:
        """The single TCP, UDP or SCTP port of a port object a NAT rule names; None when it names none."""
        if self._no_ref(ref, "a port", problems):
            return None
        name = self._service_ref(ref, problems)
        service = self.p.services.get(name)
        if service is None or service.unsupported or len(service.entries) != 1 or service.entries[0].protocol not in L4_PROTOCOLS:
            problems.append(f"port object '{name[:40]}', which is not one TCP or UDP port")
            return None
        if not service.entries[0].src_ports:
            self.port_owner[id(service.entries[0])] = name
        return service.entries[0]

    def _port_service(self, entry: ServiceEntry) -> str:
        """The service for the port a NAT rule matches: the port object it names, where that says just this."""
        return self.port_owner.get(id(entry)) or self._inline([ServiceEntry(entry.protocol, dst_ports=entry.dst_ports)])

    def _nat_zones(self, ref: Any, nat: NatRule, inbound: bool) -> Tuple[List[str], Optional[_Interface]]:
        """(zones for the interface object of a NAT rule, the interface itself when it is one)."""
        if self._no_ref(ref, "an interface", nat.unsupported):
            return [ANY], None
        kind, name = _s(_d(ref).get("type")).lower(), _s(_d(ref).get("name"))
        direction = "that enters by" if inbound else "that leaves by"
        if kind == "securityzone":
            record = self.source.find(ref)
            if record is None:
                nat.unsupported.append("a security zone without a name")
                return [ANY], None
            zone = self._zone_name(record)
            held = self.members.get(zone, [])
            return [zone], held[0] if len(held) == 1 else None
        if kind == "interfacegroup":
            zones, exact = self._group_zones(ref)
            if not zones:
                self.report.add(
                    "nat", nat.origin, Severity.REVIEW, "NAT_INTERFACE",
                    f"the rule applied to traffic {direction} the interfaces of interface group '{name}' only; the input does "
                    "not say which security zones they are in, so the rule is written without a zone and applies whatever "
                    "the interface. Fetch the interface groups, the security zones and the interfaces of the device as well",
                )  # fmt: skip
                return [ANY], None
            if not exact:
                self.report.add(
                    "nat", nat.origin, Severity.APPROX, "NAT_INTERFACE",
                    f"the rule applied to traffic {direction} the interfaces of interface group '{name}' only; it is written "
                    f"for zone {', '.join(zones)}, which holds other interfaces as well",
                )  # fmt: skip
            return zones, None
        interface = self._interface_of(ref) if kind in _INTERFACE_TYPES else None
        if interface is None:
            nat.unsupported.append(f"interface object '{name[:40]}' of type '{kind[:30]}'")
            return [ANY], None
        names = self._zones_of(interface)
        if len(names) > 1:
            nat.unsupported.append(f"interface '{name[:40]}', which is in several security zones")
            return [ANY], interface
        if not names and not (interface.defined and any(self.members.values())):
            # Named where it is used and nowhere else, or no zone of the input holds any interface: which
            # zone it is in, if any, the input does not say.
            self.report.add(
                "nat", nat.origin, Severity.REVIEW, "NAT_INTERFACE",
                f"the rule applied to traffic {direction} interface {interface.logical or interface.hardware} only; the input "
                "does not say which security zone that interface is in, so the rule was read for any zone. Export the "
                "security zones and the interfaces with the rules",
            )  # fmt: skip
            return [ANY], interface
        if not names:
            # In no security zone: a zone of its own, which no access rule names and every rule for any zone covers.
            zone = _unique(interface.logical or interface.hardware, set(self.p.zones))
            self.p.zones[zone] = Zone(zone, [interface.logical or interface.hardware])
            self.members[zone] = [interface]
            self.zone_networks[zone] = list(interface.networks)
            return [zone], interface
        others = [other.logical or other.hardware for other in self.members[names[0]] if other is not interface]
        if others:
            self.report.add(
                "nat", nat.origin, Severity.APPROX, "NAT_INTERFACE",
                f"the rule applied to traffic {direction} interface {interface.logical or interface.hardware} only; it is "
                f"written for zone {names[0]}, which also holds {', '.join(others[:6])}{' ...' if len(others) > 6 else ''}",
            )  # fmt: skip
        return names, interface

    def _reached_in(self, member: str) -> str:
        """The zone in whose interface networks an address lies; any zone when the input does not tell."""
        intervals = transform.address_intervals(self.p, member) if member != ANY else None
        if not intervals:
            return ANY
        zones: List[str] = []
        for interval in intervals:
            holding = [zone for zone, networks in self.zone_networks.items()
                       if any(n[0] == interval[0] and n[1] <= interval[1] and interval[2] <= n[2] for n in networks)]  # fmt: skip
            if len(holding) != 1:
                return ANY
            if holding[0] not in zones:
                zones.append(holding[0])
        return zones[0] if len(zones) == 1 else ANY

    def _interface_address(self, nat: NatRule, zone: str, interface: Optional[_Interface]) -> str:
        """The object that stands for the address of an interface, where a NAT rule says "the interface"."""
        if interface is None or not interface.address:
            where = f"zone '{zone[:40]}'" if interface is None else f"interface '{(interface.logical or interface.hardware)[:40]}'"
            nat.unsupported.append(f"the address of the interface of {where}, which the input does not tell")
            return ANY
        label = interface.logical or interface.hardware
        if interface.key not in self.interface_objects:
            name = _unique(f"{label}-interface", self.address_names)
            self.p.addresses[name] = Address(
                name, AddressKind.NETWORK, f"{interface.address}/32",
                f"address of interface {label} when the configuration was read", raw=f"interface {zone}", builtin=self.vendor,
            )  # fmt: skip
            self.interface_objects[interface.key] = name
        self.report.add(
            "nat", nat.origin, Severity.APPROX, "NAT_INTERFACE_ADDRESS",
            f"the rule is for the address of interface '{label}', whatever that is at the time. It is converted with the "
            f"address the interface has in the input, {interface.address}",
        )  # fmt: skip
        return self.interface_objects[interface.key]

    def _families(self, member: str) -> Set[int]:
        return {4, 6} if member == ANY else transform.families(self.p, member)

    def _finish(self, nat: NatRule, ignored: List[str]) -> NatRule:
        sides: List[Tuple[List[str], List[str]]] = []
        if nat.source_translation is not None and nat.source_translation.addresses:
            sides.append((nat.sources, nat.source_translation.addresses))
        if nat.destination_translation is not None:
            sides.append((nat.destinations, [nat.destination_translation.address]))
        for before, after in sides:
            old: Set[int] = set().union(*[self._families(member) for member in before])
            new: Set[int] = set().union(*[self._families(member) for member in after])
            if not old & new:
                nat.unsupported.append("translation between IPv4 and IPv6")
        nat.unsupported = transform.dedupe(nat.unsupported)
        if ignored:
            self.report.add("nat", nat.origin, Severity.INFO, "ATTRIBUTES_IGNORED",
                            "NAT options without an equivalent were ignored: " + ", ".join(transform.dedupe(ignored)))  # fmt: skip
        return nat

    def _nat_rule(self, record: _Record, name: str, manual: bool) -> NatRule:
        """One NAT rule. The fields are those of the NAT command of an ASA, and so is what they mean."""
        obj = record.obj
        # One rule can translate the destination of a connection and another its source, unless the rule that
        # matches names both sides (a manual rule with a destination): then it is the rule of that connection.
        nat = NatRule(name=name, origin=name, description=_s(obj.get("description")), combines=True)
        problems = nat.unsupported
        ignored: List[str] = []
        for key in obj:
            if key not in _NAT_FIELDS and not _blank(obj[key]):
                problems.append(f"field '{key[:30]}', which FWShift does not know")
        if "natType" not in obj:
            problems.append("NAT rule that is in the input by name only (fetch the rules with expanded=true)")
            return self._finish(nat, ignored)
        if manual or self.fdm:
            if isinstance(obj.get("enabled"), bool):
                nat.enabled = bool(obj["enabled"])
            else:
                problems.append("NAT rule that does not say whether it is enabled")
        kind = _s(obj.get("natType")).upper()
        if kind not in ("STATIC", "DYNAMIC"):
            problems.append(f"NAT type '{kind[:30]}'")
            return self._finish(nat, ignored)
        real_zones, real_if = self._nat_zones(obj.get("sourceInterface"), nat, True)
        mapped_zones, mapped_if = self._nat_zones(obj.get("destinationInterface"), nat, False)
        nat.src_zones, nat.dst_zones = real_zones, mapped_zones
        ignored += [label for key, label in (("dns", "translate DNS replies"), ("netToNet", "net to net mapping"))
                    if obj.get(key) is True]  # fmt: skip
        six = obj.get("interfaceIpv6") is True or obj.get("interfaceIPv6") is True
        pool = _d(obj.get("patOptions"))
        if obj.get("patOptions") is not None and not isinstance(obj["patOptions"], dict):
            problems.append("PAT options that could not be read")
        for key, value in pool.items():
            if key not in _PAT_FIELDS and not _blank(value):
                problems.append(f"'{key[:30]}' in the PAT options, which FWShift does not know")
        if manual:
            real = self._nat_ref(obj.get("originalSource"), problems)
            mapped = self._nat_ref(obj.get("translatedSource"), problems)
            to_interface = obj.get("interfaceInTranslatedSource") is True
        else:
            real = self._nat_ref(obj.get("originalNetwork"), problems)
            mapped = self._nat_ref(obj.get("translatedNetwork"), problems)
            to_interface = obj.get("interfaceInTranslatedNetwork") is True
            if not real:
                problems.append("automatic NAT without an original network")
        nat.sources = [real or ANY]
        if to_interface and mapped:
            problems.append("a translated address and the address of the interface at once")
        if kind == "DYNAMIC":
            fallback = pool.get("interfacePat") is True or obj.get("fallThrough") is True
            nat.source_translation = self._dynamic(nat, mapped, to_interface or (fallback and not mapped and _blank(pool.get("patPoolAddress"))),
                                                   six, pool, mapped_zones, mapped_if, ignored)  # fmt: skip
            if fallback and nat.source_translation is not None and nat.source_translation.kind != SnatKind.INTERFACE:
                ignored.append("interface (as fallback)")
            if nat.source_translation is None and not problems:
                problems.append("dynamic NAT without a translated address")
        elif not _blank(pool.get("patPoolAddress")):
            problems.append("a PAT pool on a static NAT rule")
        if manual:
            return self._manual(nat, obj, kind, real, mapped, to_interface, six, real_zones, real_if, mapped_zones, mapped_if, ignored)
        return self._automatic(nat, obj, kind, real, mapped, to_interface, six, mapped_zones, mapped_if, ignored)

    def _dynamic(self, nat: NatRule, mapped: str, to_interface: bool, six: bool, pool: Obj, mapped_zones: List[str],
                 mapped_if: Optional[_Interface], ignored: List[str]) -> Optional[SourceNat]:  # fmt: skip
        """What a dynamic rule translates the source to: an address object, a PAT pool or the interface."""
        problems = nat.unsupported
        translation: Optional[SourceNat] = None
        pool_ref = self._nat_ref(pool.get("patPoolAddress"), problems)
        for key, label in (("roundRobin", "round robin"), ("extendedPat", "extended PAT"), ("extended", "extended PAT"),
                           ("flatPortRange", "flat port range"), ("flat", "flat port range"),
                           ("includeReserve", "include reserved ports"), ("blockAllocation", "block allocation")):  # fmt: skip
            if pool.get(key) is True and pool_ref:
                ignored.append(label)
        if pool_ref:
            translation = SourceNat(SnatKind.DYNAMIC_PORT, [pool_ref])
        elif mapped:
            intervals = transform.address_intervals(self.p, mapped) or []
            one = len(intervals) == 1 and size(intervals[0]) == 1
            # One address is port address translation; a range is handed out address by address.
            translation = SourceNat(SnatKind.DYNAMIC_PORT if one else SnatKind.DYNAMIC, [mapped])
        if to_interface:
            if six:
                problems.append("port address translation to the IPv6 address of the interface")
            elif mapped_zones == [ANY]:
                problems.append("port address translation to the interface address without a destination interface")
            else:
                label = (mapped_if.logical or mapped_if.hardware) if mapped_if is not None else ""
                translation = SourceNat(SnatKind.INTERFACE, interface=label, interface_address=mapped_if.address if mapped_if else "")
        return translation

    def _manual(self, nat: NatRule, obj: Obj, kind: str, real: str, mapped: str, to_interface: bool, six: bool,
                real_zones: List[str], real_if: Optional[_Interface], mapped_zones: List[str],
                mapped_if: Optional[_Interface], ignored: List[str]) -> NatRule:  # fmt: skip
        problems = nat.unsupported
        name = nat.origin
        if obj.get("fallThrough") is True and kind != "DYNAMIC":
            ignored.append("fall through to interface PAT")
        static_to = ""  # what a static rule maps the source to: an object, "interface", or nothing
        if kind == "STATIC":
            if to_interface:
                static_to = "interface"
                if six:
                    problems.append("static NAT to the IPv6 address of the interface")
            elif mapped:
                static_to = mapped
            elif real:
                problems.append("static NAT without a translated address")
        destination: Optional[Tuple[str, str]] = None  # (address in the packet, real address)
        seen = self._nat_ref(obj.get("originalDestination"), problems)
        real_destination = self._nat_ref(obj.get("translatedDestination"), problems)
        if obj.get("interfaceInOriginalDestination") is True:
            if seen:
                problems.append("an original destination and the address of the interface at once")
            seen = self._interface_address(nat, real_zones[0], real_if)
            if not real_destination:
                problems.append("the address of the interface as destination without a translated destination")
        if seen:
            destination = (seen, real_destination or seen)
        elif real_destination:
            problems.append("a translated destination without an original one")
        first_src, second_src = self._nat_port(obj.get("originalSourcePort"), problems), self._nat_port(obj.get("translatedSourcePort"), problems)
        first_dst, second_dst = self._nat_port(obj.get("originalDestinationPort"), problems), self._nat_port(obj.get("translatedDestinationPort"), problems)
        if problems:
            return self._finish(nat, ignored)
        for one, other, side in ((first_src, second_src, "source"), (first_dst, second_dst, "destination")):
            if (one is None) != (other is None):
                problems.append(f"a {side} port on one side of the translation only")
        ports = [entry for entry in (first_src, second_src, first_dst, second_dst) if entry is not None]
        if len({entry.protocol for entry in ports}) > 1:
            problems.append("port translation between two protocols")
        for one, other in ((first_src, second_src), (first_dst, second_dst)):
            # A range of ports that stays what it is is a condition; a range that becomes another is not one port for another.
            if one is not None and other is not None and one.dst_ports != other.dst_ports and not (is_number(one.dst_ports) and is_number(other.dst_ports)):
                problems.append("translation of a range of ports")
        if problems:
            return self._finish(nat, ignored)
        one_way = obj.get("unidirectional") is True
        if first_src is not None and second_src is not None:
            # Written from the side of the server: its port (the source port of its replies) is published.
            # For a connection that is the destination, coming in on the mapped interface.
            if first_dst is not None:
                problems.append("port translation of source and destination ports at once")
            if kind != "STATIC" or one_way or not real:
                problems.append("translation of a source port")
            if destination is not None and destination[0] != destination[1]:
                problems.append("port forwarding with a destination translation as well")
            if problems:
                return self._finish(nat, ignored)
            if static_to == "interface":
                published = self._interface_address(nat, mapped_zones[0], mapped_if)
            else:
                published = static_to or real
            nat.sources = [destination[1]] if destination is not None else [ANY]
            nat.destinations = [published]
            nat.service = self._port_service(second_src)
            port = "" if first_src.dst_ports == second_src.dst_ports else first_src.dst_ports
            nat.destination_translation = DestNat(real, port)
            nat.src_zones = list(mapped_zones)
            nat.dst_zones = list(mapped_zones) if mapped_zones != [ANY] else [self._reached_in(published)]
            return self._finish(nat, ignored)
        if static_to == "interface":
            problems.append("static NAT to the interface address without a port")
        elif kind == "STATIC" and static_to and static_to != real:
            nat.source_translation = SourceNat(SnatKind.STATIC, [static_to], bidirectional=not one_way and destination is None)
            if not one_way and destination is not None:
                self.report.add(
                    "nat", name, Severity.APPROX, "NAT_REVERSE_DIRECTION",
                    f"the rule also translates connections opened in the other direction, from '{destination[1]}' to "
                    f"'{static_to}'. That direction is not converted",
                )  # fmt: skip
        if destination is not None:
            nat.combines = False
            nat.destinations = [destination[0]]
            if destination[0] != destination[1]:
                nat.destination_translation = DestNat(destination[1])
        if first_dst is not None and second_dst is not None:
            nat.service = self._port_service(first_dst)
            if first_dst.dst_ports != second_dst.dst_ports:
                if destination is None:
                    problems.append("port translation without a destination address")
                elif nat.destination_translation is None:
                    nat.destination_translation = DestNat(destination[1], second_dst.dst_ports)
                else:
                    nat.destination_translation.port = second_dst.dst_ports
        if nat.destination_translation is not None:
            # The model wants the zone the original destination is reached in; the rule names the
            # interface behind which the real one is.
            nat.dst_zones = [self._reached_in(nat.destinations[0])]
        return self._finish(nat, ignored)

    def _automatic(self, nat: NatRule, obj: Obj, kind: str, real: str, mapped: str, to_interface: bool, six: bool,
                   mapped_zones: List[str], mapped_if: Optional[_Interface], ignored: List[str]) -> NatRule:  # fmt: skip
        problems = nat.unsupported
        if obj.get("fallThrough") is True and kind != "DYNAMIC":
            ignored.append("fall through to interface PAT")
        if kind != "STATIC" or problems:
            return self._finish(nat, ignored)
        port: Optional[Tuple[Protocol, str, str]] = None
        named: Optional[ServiceEntry] = None  # the port object of a Device Manager that says the published port
        if self.fdm:
            first, second = self._nat_port(obj.get("originalPort"), problems), self._nat_port(obj.get("translatedPort"), problems)
            if (first is None) != (second is None):
                problems.append("a port on one side of the translation only")
            elif first is not None and second is not None:
                if first.protocol != second.protocol:
                    problems.append("port translation between two protocols")
                port = (first.protocol, first.dst_ports, second.dst_ports)
                named = second
        elif not _blank(obj.get("originalPort")) or not _blank(obj.get("translatedPort")) or not _blank(obj.get("serviceProtocol")):
            protocol = _s(obj.get("serviceProtocol")).lower()
            real_port, mapped_port = _number(obj.get("originalPort")), _number(obj.get("translatedPort"))
            if protocol not in ("tcp", "udp") or real_port is None or mapped_port is None or not (0 < real_port < 65536 and 0 < mapped_port < 65536):
                problems.append("a port translation that could not be read")
            else:
                port = (Protocol(protocol), str(real_port), str(mapped_port))
        if problems:
            return self._finish(nat, ignored)
        if port is not None and port[1] != port[2] and any(not is_number(text) for text in port[1:]):
            problems.append("translation of a range of ports")
        elif port is not None:
            # A published port: connections come in on the mapped interface, for the mapped address.
            if to_interface:
                if six:
                    problems.append("static NAT to the IPv6 address of the interface")
                published = self._interface_address(nat, mapped_zones[0], mapped_if)
            else:
                published = mapped
            if not published:
                problems.append("static NAT without a translated address")
                return self._finish(nat, ignored)
            nat.sources = [ANY]
            nat.destinations = [published]
            nat.service = self._port_service(named) if named is not None else self._inline([ServiceEntry(port[0], dst_ports=port[2])])
            nat.destination_translation = DestNat(real, "" if port[1] == port[2] else port[1])
            nat.src_zones = list(mapped_zones)
            nat.dst_zones = list(mapped_zones) if mapped_zones != [ANY] else [self._reached_in(published)]
        elif to_interface:
            problems.append("static NAT to the interface address without a port")
        elif not mapped:
            problems.append("static NAT without a translated address")
        elif mapped != real:
            nat.source_translation = SourceNat(SnatKind.STATIC, [mapped], bidirectional=True)
        return self._finish(nat, ignored)

