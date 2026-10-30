# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Windows Defender Firewall with Advanced Security parser: the registry, as ``reg export`` writes it -> neutral model.

The input is a ``.reg`` file of the keys that hold the policy: the local store
(``HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy``), the store of Group
Policy (``HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall``) and, where Intune or another MDM manages the host,
its store (``...\\FirewallPolicy\\Mdm``), one after the other in one file. ``reg export`` writes UTF-16 with a byte
order mark; files joined with ``copy /b`` carry a second one, which is skipped. A rule is one string value, in the
grammar of [MS-GPFAS] 2.2.2.10 (``v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|...``); the profile
settings are DWORD values beside the rules. The binary ``.wfw`` of ``netsh advfirewall export`` is not read, and
neither is the JSON of ``Get-NetFirewallRule``: the registry holds every field of every rule in one documented
grammar, in one file a built-in command writes, and its stores show where each rule and setting comes from.

How Windows behaviour is mapped onto the neutral model:

* It is a host firewall: it filters connections to and from the host itself. The model has a zone ``Host`` (the
  host) and a zone per profile, ``Domain``, ``Private`` and ``Public``: the networks the host is connected to,
  each through the interfaces Windows put in that profile (since Windows 7 every interface has the profile of its
  network). An inbound rule is a rule from its profiles to ``Host``; an outbound rule one from ``Host`` to its
  profiles. Remote addresses and ports are the far end, local ones the host's: the sources and source ports of an
  inbound rule, the destinations and destination ports of an outbound one. Traffic between the networks is not
  the host firewall's to decide, and the model denies it (the default between zones).
* There is no rule order. A rule that allows with "override block rules" (authenticated bypass) decides first,
  then any rule that blocks, then any rule that allows, then the default of the profile for the direction. The
  model is first match: the bypass rules first (they match only IPsec-authenticated connections, which the model
  cannot say: not converted), then every block rule, then every allow rule, each in the order of the stores
  (Group Policy, MDM, local) and of the file, then the defaults of the profiles that allow, as rules
  ``(default) inbound`` and ``(default) outbound``. What no rule matches is denied, as is the default of a
  profile that blocks.
* A profile whose firewall is off allows everything, whatever the rules say: two rules at the top allow all to
  and from it, and the other rules leave it out. A profile that blocks every inbound connection (shielded,
  ``DoNotAllowExceptions``) gets a block rule at the top, and inbound rules leave it out.
* Group Policy wins: its value of a setting where it has one, else MDM's, else the local one, else Windows's
  default (on, inbound blocked, outbound allowed). Where Group Policy (or MDM) sets ``AllowLocalPolicyMerge`` to
  0 for a profile, the local rules do not apply in that profile. A rule of the same id in two stores is one rule
  (the one of the store that wins); the other is kept disabled.
* A rule that names a program, a service, an app package, users or computers, interfaces or interface types,
  requires IPsec, or names a port keyword (RPC, Teredo, IP-HTTPS, ...) matches less than its addresses and ports
  say: it goes into ``Rule.unsupported``. Address keywords (``LocalSubnet``, ``DNS``, ``Internet``, ...) are
  dynamic groups that only a Windows target writes again.
* Remote addresses of one IP version only make the rule match that version (the other has no addresses); a
  keyword in ``RA4`` only is the keyword for IPv4 (``LocalSubnet4``).
* A rule string Windows cannot parse is not enforced (event 4953): it is kept disabled.

Assumptions not confirmed on a host: the store of MDM, its place between Group Policy and local, and that its
``AllowLocalPolicyMerge`` acts as Group Policy's; ``DoNotAllowExceptions`` as the value of the shielded setting in
the Group Policy store; that a rule of the same id in Group Policy replaces the local one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..errors import ParseError
from ..model import ANY, Action, AddressGroup, Policy, Protocol, Rule, Service, ServiceEntry, Zone
from ..netutil import interval_text, is_number, parse_literal
from ..report import Report, Severity

HOST = "Host"
PROFILES = ("Domain", "Private", "Public")
VENDOR = "windows-firewall"
KEYWORD_PREFIX = "windows-firewall:"  # the dynamic filter of an address keyword group

_MAX_INPUT = 64 * 1024 * 1024
_MAX_RULES = 100_000
_HEADERS = ("windows registry editor version 5.00", "regedit4")
_LOCAL = re.compile(r"^hkey_local_machine\\system\\(currentcontrolset|controlset\d{3})\\services\\sharedaccess\\parameters"
                    r"\\firewallpolicy(\\.*)?$")  # fmt: skip
_GPO = re.compile(r"^hkey_local_machine\\software\\policies\\microsoft\\windowsfirewall(\\.*)?$")
_STORE_TITLES = {"gpo": "Group Policy", "mdm": "MDM", "local": "local"}
_PROFILE_KEYS = {
    "local": {"domainprofile": "Domain", "standardprofile": "Private", "publicprofile": "Public"},
    "gpo": {"domainprofile": "Domain", "privateprofile": "Private", "publicprofile": "Public"},
    "mdm": {"domainprofile": "Domain", "privateprofile": "Private", "publicprofile": "Public"},
}
# Settings of a profile: value name -> Windows's default.
_DEFAULTS = {"enablefirewall": 1, "defaultinboundaction": 1, "defaultoutboundaction": 0, "donotallowexceptions": 0,
             "allowlocalpolicymerge": 1}  # fmt: skip
_NOT_CONVERTED_SETTINGS = {"disableunicastresponsestomulticastbroadcast": "unicast responses to multicast and broadcast "
                           "traffic are blocked", "disablestealthmode": "stealth mode is off"}  # fmt: skip
_IGNORED_SETTINGS = {"disablenotifications", "allowlocalipsecpolicymerge", "disableinboundnotifications"}

# Address keywords: the word of the rule string -> the keyword of New-NetFirewallRule.
_ADDRESS_KEYWORDS = {"localsubnet": "LocalSubnet", "dns": "DNS", "dhcp": "DHCP", "wins": "WINS", "defaultgateway": "DefaultGateway",
                     "intranet": "Intranet", "internet": "Internet", "ply2renders": "PlayToDevice",
                     "rmtintranet": "IntranetRemoteAccess", "captiveportal": "CaptivePortal"}  # fmt: skip
_PORT_KEYWORDS = {"rpc": "RPC", "rpc-epmap": "RPC-EPMap", "teredo": "Teredo", "iptlsin": "IPTLSIn", "iphttpsin": "IPHTTPSIn",
                  "iptlsout": "IPTLSOut", "iphttpsout": "IPHTTPSOut", "ply2disc": "PlayToDiscovery", "dhcp": "DHCP"}  # fmt: skip
# Keys that may appear more than once.
_REPEATABLE = {"profile", "lport", "rport", "lport2_10", "rport2_10", "lport2_20", "la4", "la6", "ra4", "ra6", "ra42", "ra62",
               "icmp4", "icmp6", "if", "iftype", "platform", "ttk", "ttk2_22", "ttk2_27", "ttk2_28"}  # fmt: skip
# Keys that narrow the match in ways the model cannot hold: key -> what it is.
_NARROWING = {"app": "program", "svc": "service", "apppkgid": "app package", "luauth": "local users", "luauth2_24": "local users",
              "luown": "the local user who owns it", "rmauth": "remote computers", "ruauth": "remote users",
              "if": "interfaces", "ttk": "trust tuple keyword", "ttk2_22": "trust tuple keyword",
              "ttk2_27": "trust tuple keyword", "ttk2_28": "trust tuple keyword", "nnm": "network names",
              "securityrealmid": "security realm", "security": "IPsec", "security2_9": "IPsec", "security2": "IPsec"}  # fmt: skip
_KNOWN = _REPEATABLE | set(_NARROWING) | {"action", "dir", "protocol", "name", "desc", "embedctxt", "edge", "defer", "lsm", "active",
                                         "platform2", "skipver", "lom", "pcross", "authbypassout"}  # fmt: skip


def _decode(data: bytes) -> str:
    if data[:2] == b"\xff\xfe":
        text = data.decode("utf-16-le", errors="replace")
    elif data[:2] == b"\xfe\xff":
        text = data.decode("utf-16-be", errors="replace")
    elif len(data) > 1 and data[1:2] == b"\x00" and data[:1] != b"\x00":
        text = data.decode("utf-16-le", errors="replace")  # (UTF-16 that lost its byte order mark)
    else:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("cp1252", errors="replace")  # (regedit /a writes the code page of the system)
    return text.replace("﻿", "")


def looks_like_winfw(data: bytes) -> bool:
    """A registry export (``reg export``, regedit) that holds a key of the firewall policy."""
    head = _decode(data[:262144]).lstrip()
    if not head.lower().startswith(_HEADERS):
        return False
    for line in head.splitlines()[:5000]:
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            key = line[1:-1].lstrip("-").lower()
            if _LOCAL.match(key) or _GPO.match(key):
                return True
    return False


# -- the registry file --------------------------------------------------------------------------------------------------


@dataclass
class _Value:
    name: str
    kind: str  # "sz", "dword", "other", "deleted"
    text: str = ""
    number: int = 0


@dataclass
class _Key:
    path: str  # as written
    values: List[_Value] = field(default_factory=list)
    deleted: bool = False


def _unquote(text: str, start: int) -> Tuple[str, int]:
    """The string in double quotes at ``start`` (\\\\ and \\" unescaped), and the position after its closing quote."""
    out: List[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            out.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(out), index + 1
        out.append(char)
        index += 1
    raise ValueError("a string without its closing quote")


def _registry(text: str) -> List[_Key]:
    if not text.lstrip().lower().startswith(_HEADERS):
        raise ParseError("not a registry export: expected 'Windows Registry Editor Version 5.00' at the start (reg export)")
    keys: List[_Key] = []
    current: Optional[_Key] = None
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        number, line = index + 1, lines[index].strip()
        index += 1
        while line.endswith("\\") and index < len(lines) and not line.startswith(("[", ";")):
            line = line[:-1] + lines[index].strip()  # (hex values run over lines)
            index += 1
        if not line or line.startswith(";") or line.lower() in _HEADERS:
            continue
        if line.startswith("[") and line.endswith("]"):
            path = line[1:-1]
            current = _Key(path.lstrip("-"), deleted=path.startswith("-"))
            keys.append(current)
            continue
        if current is None:
            raise ParseError(f"line {number}: a value before any key")
        try:
            if line.startswith("@="):
                name, rest = "", line[2:]
            elif line.startswith('"'):
                name, end = _unquote(line, 0)
                if line[end:end + 1] != "=":
                    raise ValueError("no '=' after the name")
                rest = line[end + 1:]
            else:
                raise ValueError("neither a key nor a value")
            if rest.startswith('"'):
                value, end = _unquote(rest, 0)
                if rest[end:].strip():
                    raise ValueError("text after the closing quote")
                current.values.append(_Value(name, "sz", text=value))
            elif rest.lower().startswith("dword:"):
                digits = rest[6:].strip()
                if not re.fullmatch(r"[0-9A-Fa-f]{1,8}", digits):
                    raise ValueError(f"a DWORD that cannot be read: '{digits[:20]}'")
                current.values.append(_Value(name, "dword", number=int(digits, 16)))
            elif rest == "-":
                current.values.append(_Value(name, "deleted"))
            elif rest.lower().startswith("hex"):
                current.values.append(_Value(name, "other", text=rest[:40]))
            else:
                raise ValueError(f"a value that cannot be read: '{rest[:30]}'")
        except ValueError as error:
            raise ParseError(f"line {number}: {error}") from None
    return keys


# -- a rule string --------------------------------------------------------------------------------------------------------


@dataclass
class _Parsed:
    """What a rule string says, as far as the model can hold it."""

    ident: str
    store: str
    text: str
    version: str = ""
    fields: List[Tuple[str, str]] = field(default_factory=list)
    action: str = ""  # allow, block, bypass
    inbound: bool = True
    active: bool = False
    profiles: List[str] = field(default_factory=list)
    protocol: Optional[int] = None
    lports: List[str] = field(default_factory=list)
    rports: List[str] = field(default_factory=list)
    icmp: List[Tuple[Optional[int], Optional[int]]] = field(default_factory=list)
    local: List[str] = field(default_factory=list)  # literals
    remote: List[str] = field(default_factory=list)  # literals and keywords (as "kw:LocalSubnet4")
    name: str = ""
    description: str = ""
    group: str = ""
    unsupported: List[str] = field(default_factory=list)
    invalid: List[str] = field(default_factory=list)  # what makes Windows refuse the rule
    findings: List[Tuple[Severity, str, str]] = field(default_factory=list)


def _bool(value: str) -> Optional[bool]:
    upper = value.strip().upper()
    return True if upper == "TRUE" else False if upper == "FALSE" else None


def _port(text: str) -> Optional[str]:
    """``80`` or ``1024-2000`` in the model's syntax; None if it is neither."""
    first, dash, last = text.strip().partition("-")
    if not is_number(first) or (dash and not is_number(last)) or len(first) > 5 or len(last) > 5:
        return None
    low, high = int(first), int(last or first)
    if high > 65535 or low > high:
        return None
    return str(low) if low == high else f"{low}-{high}"


def _icmp(text: str) -> Optional[Tuple[Optional[int], Optional[int]]]:
    kind, colon, code = text.strip().partition(":")
    values: List[Optional[int]] = []
    for part in (kind, code if colon else "*"):
        part = part.strip()
        if part in ("*", ""):
            values.append(None)
        elif is_number(part) and int(part) <= 255:
            values.append(int(part))
        else:
            return None
    if values[0] is None and values[1] is not None:
        return None
    return values[0], values[1]


def read_rule(ident: str, store: str, text: str) -> _Parsed:
    """One rule string of the registry, by the grammar of [MS-GPFAS] 2.2.2.10."""
    rule = _Parsed(ident, store, text)
    head, _, body = text.partition("|")
    match = re.fullmatch(r"v(\d{1,3})\.(\d{1,3})", head.strip())
    if not match:
        rule.invalid.append(f"no version at the start ('{head[:20]}')")
        return rule
    rule.version = head.strip()
    if match.group(1) != "2":
        rule.invalid.append(f"version {rule.version}: Windows ignores a rule of a major version it does not know")
    parts = body.split("|")
    if parts and parts[-1] == "":
        parts.pop()
    seen: Set[str] = set()
    for part in parts:
        key, equals, value = part.partition("=")
        if not equals:
            rule.invalid.append(f"a field without '=' ('{part[:30]}')")
            continue
        lower = key.strip().lower()
        if lower in seen and lower not in _REPEATABLE:
            rule.invalid.append(f"{key} given twice")
        seen.add(lower)
        rule.fields.append((lower, value))
    values: Dict[str, List[str]] = {}
    for key, value in rule.fields:
        values.setdefault(key, []).append(value)

    def one(key: str) -> str:
        return values.get(key, [""])[-1]

    action = one("action").strip().lower()
    rule.action = {"allow": "allow", "block": "block", "bypass": "bypass"}.get(action, "")
    if not rule.action:
        rule.invalid.append(f"action '{one('action')[:20]}'" if "action" in values else "no action")
    direction = one("dir").strip().lower()
    if direction not in ("in", "out"):
        rule.invalid.append(f"direction '{one('dir')[:20]}'" if "dir" in values else "no direction")
    rule.inbound = direction != "out"
    active = _bool(one("active")) if "active" in values else False
    if active is None:
        rule.invalid.append(f"Active={one('active')[:20]}")
    rule.active = bool(active)
    for value in values.get("profile", []):
        name = {"domain": "Domain", "private": "Private", "public": "Public"}.get(value.strip().lower())
        if name is None:
            rule.invalid.append(f"profile '{value[:20]}'")
        elif name not in rule.profiles:
            rule.profiles.append(name)
    if not values.get("profile"):
        rule.profiles = list(PROFILES)
    rule.profiles = [p for p in PROFILES if p in rule.profiles]
    if "protocol" in values:
        number = one("protocol").strip()
        if not is_number(number) or int(number) > 256:
            rule.invalid.append(f"protocol '{number[:10]}'")
        elif int(number) < 256:
            rule.protocol = int(number)
    rule.name, rule.description, rule.group = one("name"), one("desc"), one("embedctxt")
    _ports(rule, values)
    _addresses(rule, values)
    _icmp_types(rule, values)
    _flags(rule, values)
    for key, _ in rule.fields:
        text = f"the field '{key[:30]}', which FWShift does not know"
        if key not in _KNOWN and text not in rule.unsupported:
            rule.unsupported.append(text)
    return rule


def _ports(rule: _Parsed, values: Dict[str, List[str]]) -> None:
    for side, keys in (("local", ("lport", "lport2_10", "lport2_20")), ("remote", ("rport", "rport2_10"))):
        found = rule.lports if side == "local" else rule.rports
        for key in keys:
            for value in values.get(key, []):
                if rule.protocol not in (6, 17):
                    rule.invalid.append(f"{side} ports without protocol TCP or UDP")
                    continue
                keyword = _PORT_KEYWORDS.get(value.strip().lower())
                if keyword is not None:
                    text = f"the {side} port keyword {keyword}"
                    if text not in rule.unsupported:
                        rule.unsupported.append(text)
                    continue
                if value.strip() == "*":
                    found.append("")  # (every port: the field says nothing)
                    continue
                port = _port(value)
                if port is None:
                    rule.invalid.append(f"{side} port '{value[:20]}'")
                else:
                    found.append(port)
        if "" in found:
            found.clear()


def _addresses(rule: _Parsed, values: Dict[str, List[str]]) -> None:
    for side, keys in (("local", (("la4", 4), ("la6", 6))), ("remote", (("ra4", 4), ("ra6", 6), ("ra42", 4), ("ra62", 6)))):
        found = rule.local if side == "local" else rule.remote
        keywords: Dict[str, Set[int]] = {}
        for key, version in keys:
            for value in values.get(key, []):
                text = value.strip()
                if text == "*":
                    found.append(ANY)
                    continue
                keyword = _ADDRESS_KEYWORDS.get(text.lower())
                if keyword is not None:
                    if side == "local":
                        rule.invalid.append(f"the address keyword {text[:20]} among the local addresses")
                    else:
                        keywords.setdefault(keyword, set()).add(version)
                    continue
                interval = parse_literal(text)
                if interval is None or interval[0] != version:
                    rule.invalid.append(f"{key.upper()}={text[:40]}, which is not an IPv{version} address, range or network")
                    continue
                literal = interval_text(interval)
                if literal not in found:
                    found.append(literal)
        for keyword, versions in keywords.items():
            found.append("kw:" + keyword + ("" if versions == {4, 6} else str(next(iter(versions)))))
        if ANY in found:
            found[:] = [ANY]


def _icmp_types(rule: _Parsed, values: Dict[str, List[str]]) -> None:
    for key, number in (("icmp4", 1), ("icmp6", 58)):
        for value in values.get(key, []):
            if rule.protocol != number:
                rule.invalid.append(f"{key.upper()} without protocol {number}")
                continue
            found = _icmp(value)
            if found is None:
                rule.invalid.append(f"ICMP type and code '{value[:20]}'")
            elif found not in rule.icmp:
                rule.icmp.append(found)
    if (None, None) in rule.icmp:
        rule.icmp = []
    if rule.icmp and (rule.lports or rule.rports):
        rule.invalid.append("ICMP types and ports in one rule")


def _flags(rule: _Parsed, values: Dict[str, List[str]]) -> None:
    for key, what in _NARROWING.items():
        for value in values.get(key, []):
            shown = value.strip()[:80]
            if key == "svc" and shown == "*":
                text = "any service (traffic of Windows services only)"
            elif key.startswith("security"):
                text = f"IPsec ({shown}): only connections IPsec protects match"
            elif key in ("app", "svc", "if"):
                text = f"{what} {shown}"
            else:
                text = what
            if text not in rule.unsupported:
                rule.unsupported.append(text)
    types = {value.strip().lower() for value in values.get("iftype", [])}
    known = {"lan", "wireless", "remoteaccess"}
    if types - known:
        rule.invalid.append("interface type " + ", ".join(sorted(types - known))[:40])
    elif types and types != known:
        rule.unsupported.append("interface types " + ", ".join(sorted(types)))
    if rule.action == "bypass":
        rule.unsupported.append("authenticated bypass: only IPsec-authenticated connections match, and they override block rules")
    if _bool(values.get("authbypassout", ["FALSE"])[-1]):
        rule.unsupported.append("authenticated bypass of outbound block rules")
    edge = _bool(values.get("edge", ["FALSE"])[-1])
    defer = values.get("defer", [""])[-1].strip()
    if (edge or defer) and rule.inbound and rule.action == "allow":
        how = "" if edge else f", when the {'application' if defer.lower() == 'app' else 'user'} asks for it,"
        rule.findings.append((Severity.APPROX, "WINFW_EDGE_TRAVERSAL",
                              f"the rule also accepts{how} traffic that came through edge traversal (Teredo); the model has no "
                              "such path: the converted rule does not let it in"))  # fmt: skip
    if _bool(values.get("lsm", ["FALSE"])[-1]) and rule.action == "allow":
        rule.findings.append((Severity.APPROX, "WINFW_LOOSE_SOURCE",
                              "loose source mapping: the rule accepts UDP replies from another host than the one the packets went "
                              "to; the converted rule does not"))  # fmt: skip
    platforms = values.get("platform", [])
    if platforms:
        operator = values.get("platform2", [""])[-1].strip().upper()
        listed = ", ".join(_platform(p) for p in platforms)
        if operator == "GTEQ":
            rule.findings.append((Severity.INFO, "WINFW_PLATFORM",
                                  f"the rule applies on Windows {listed} and later; it is taken as applying on this host"))  # fmt: skip
        else:
            rule.findings.append((Severity.APPROX, "WINFW_PLATFORM",
                                  f"the rule applies only on the Windows versions {listed}"
                                  + (f" ({operator[:10]})" if operator else "")
                                  + "; it is taken as applying on this host, which may not be one of them"))  # fmt: skip


def _platform(text: str) -> str:
    """``2:6:2`` (an entry of PlatformValidityList) as ``NT 6.2``."""
    match = re.fullmatch(r"\s*(\d+):(\d+):(\d+)\s*", text)
    if not match:
        return text.strip()[:20]
    return (f"NT {match.group(2)}.{match.group(3)}" if match.group(1) == "2" else
            f"platform {match.group(1)} {match.group(2)}.{match.group(3)}")  # fmt: skip


# -- the policy ------------------------------------------------------------------------------------------------------------


@dataclass
class _Store:
    kind: str  # gpo, mdm, local
    rules: List[Tuple[str, str]] = field(default_factory=list)  # (id, rule string)
    profiles: Dict[str, Dict[str, int]] = field(default_factory=dict)
    seen: bool = False


class _Builder:
    def __init__(self, keys: List[_Key], report: Report) -> None:
        self.keys, self.report = keys, report
        self.p = Policy(vendor=VENDOR, default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.stores = {kind: _Store(kind) for kind in ("gpo", "mdm", "local")}
        self.rule_names: Set[str] = set()
        self.not_read: List[str] = []
        self.settings: Dict[str, Dict[str, int]] = {}
        self.source: Dict[str, Dict[str, str]] = {}
        self.local_ignored = 0

    # -- the keys ------------------------------------------------------------------------------

    def _classify(self) -> None:
        control_sets = sorted({m.group(1).lower() for k in self.keys for m in [_LOCAL.match(k.path.lower())] if m})
        chosen = "currentcontrolset" if "currentcontrolset" in control_sets else (control_sets[0] if len(control_sets) == 1 else "")
        if len(control_sets) > 1 and not chosen:
            raise ParseError("the export holds the firewall policy of several control sets (" + ", ".join(control_sets)
                             + ") and not CurrentControlSet; export HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\"
                             "Parameters\\FirewallPolicy")  # fmt: skip
        if len(control_sets) > 1:
            self.report.note(Severity.INFO, "WINFW_CONTROL_SET",
                             "the export holds several control sets; the policy of CurrentControlSet is read")  # fmt: skip
        for key in self.keys:
            lower = key.path.lower()
            local, gpo = _LOCAL.match(lower), _GPO.match(lower)
            if local:
                if local.group(1) != chosen:
                    continue
                rest = (local.group(2) or "").lstrip("\\")
                kind = "local"
                if rest == "mdm" or rest.startswith("mdm\\"):
                    kind, rest = "mdm", rest[3:].lstrip("\\")
            elif gpo:
                kind, rest = "gpo", (gpo.group(1) or "").lstrip("\\")
            else:
                continue
            store = self.stores[kind]
            store.seen = True
            if key.deleted:
                self.not_read.append(f"[-{key.path}] (a key the file deletes)")
                continue
            if rest == "firewallrules":
                for value in key.values:
                    if value.kind == "sz" and not value.name:
                        self.not_read.append(f"the default value of {key.path}")
                    elif value.kind == "sz":
                        store.rules.append((value.name, value.text))
                    elif value.kind != "deleted":
                        self.not_read.append(f"the value '{value.name[:40]}' of {key.path} (not a string)")
            elif rest in _PROFILE_KEYS[kind]:
                profile = _PROFILE_KEYS[kind][rest]
                settings = store.profiles.setdefault(profile, {})
                for value in key.values:
                    name = value.name.lower()
                    if value.kind == "dword" and (name in _DEFAULTS or name in _NOT_CONVERTED_SETTINGS):
                        settings[name] = value.number
                    elif name in _DEFAULTS or name in _NOT_CONVERTED_SETTINGS:
                        self.not_read.append(f"the value {value.name} of {key.path} (not a DWORD)")
            elif kind == "gpo" and rest == "standardprofile" or rest.endswith(("\\globallyopenports\\list", "\\authorizedapplications\\list")):
                if key.values:
                    self.report.note(Severity.REVIEW, "WINFW_LEGACY_POLICY",
                                     f"{key.path} holds settings of the Windows Firewall of Windows XP (open ports, programs, the "
                                     "standard profile), which current Windows applies on top of the rules; they are not converted")  # fmt: skip
            elif rest == "consecrules" or rest.startswith(("restrictedservices", "consec")):
                if key.values:
                    label = "connection security (IPsec) rules" if "consec" in rest else "Windows Service Hardening rules"
                    self.not_read.append(f"{len(key.values)} {label} in {key.path}")
            elif rest == "" or rest.startswith(("logging", "domainprofile\\logging", "privateprofile\\logging", "publicprofile\\logging",
                                                "standardprofile\\logging", "phase1", "phase2", "crypto", "auth", "defaults")):
                continue
            elif rest.endswith("firewallrules"):
                self.not_read.append(f"the rules of {key.path} (not one of the stores Windows applies)")

    def _effective(self) -> None:
        """The settings of each profile as Windows merges them ([MS-FASP] 2.2.38)."""
        order = ("gpo", "mdm", "local")
        assumed: List[str] = []
        for profile in PROFILES:
            settings: Dict[str, int] = {}
            where: Dict[str, str] = {}
            for name, default in list(_DEFAULTS.items()) + [(n, 0) for n in _NOT_CONVERTED_SETTINGS]:
                if name == "allowlocalpolicymerge":
                    managed = [self.stores[k].profiles.get(profile, {}).get(name) for k in ("gpo", "mdm")]
                    values = [v for v in managed if v is not None]
                    settings[name] = 0 if any(v == 0 for v in values) else 1
                    where[name] = "Group Policy" if managed[0] is not None else "MDM" if managed[1] is not None else "default"
                    continue
                if name == "donotallowexceptions":
                    found = [self.stores[k].profiles.get(profile, {}).get(name) for k in order]
                    settings[name] = 1 if any(v for v in found if v is not None) else 0
                    where[name] = "a store" if any(v is not None for v in found) else "default"
                    continue
                for kind in order:
                    value = self.stores[kind].profiles.get(profile, {}).get(name)
                    if value is not None:
                        settings[name], where[name] = value, _STORE_TITLES[kind]
                        break
                else:
                    settings[name], where[name] = default, "default"
                    if name in ("enablefirewall", "defaultinboundaction", "defaultoutboundaction"):
                        assumed.append(f"{profile} {name}")
            self.settings[profile], self.source[profile] = settings, where
        if assumed:
            self.report.note(Severity.INFO, "WINFW_DEFAULT_ASSUMED",
                             "settings that no store of the input holds were taken as Windows's defaults (firewall on, inbound "
                             "blocked, outbound allowed): " + ", ".join(assumed))  # fmt: skip

    # -- the rules ------------------------------------------------------------------------------

    def build(self) -> Policy:
        self._classify()
        if not any(store.seen for store in self.stores.values()):
            raise ParseError("the registry export holds no key of the firewall policy (export HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
                             "SharedAccess\\Parameters\\FirewallPolicy and HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall)")  # fmt: skip
        if sum(len(store.rules) for store in self.stores.values()) > _MAX_RULES:
            raise ParseError(f"more than {_MAX_RULES} firewall rules")
        self._effective()
        for name in (HOST,) + PROFILES:
            self.p.zones[name] = Zone(name)
        self.p.scope = ", ".join(_STORE_TITLES[k] for k in ("gpo", "mdm", "local") if self.stores[k].seen)
        off = [p for p in PROFILES if not self.settings[p]["enablefirewall"]]
        shielded = [p for p in PROFILES if p not in off and self.settings[p]["donotallowexceptions"]]
        parsed = self._read_rules()
        self._top(off, shielded)
        bypass = [r for r in parsed if r.action == "bypass"]
        blocks = [r for r in parsed if r.action == "block"]
        allows = [r for r in parsed if r.action not in ("bypass", "block")]
        for item in bypass + blocks + allows:
            self._rule(item, off, shielded)
        self._defaults(off, shielded)
        self._notes(off, shielded)
        return self.p

    def _read_rules(self) -> List[_Parsed]:
        out: List[_Parsed] = []
        winner: Dict[str, str] = {}
        for kind in ("gpo", "mdm", "local"):
            for ident, text in self.stores[kind].rules:
                parsed = read_rule(ident, kind, text)
                key = ident.lower()
                if key in winner and winner[key] != kind:
                    parsed.findings.append((Severity.INFO, "WINFW_OVERRIDDEN",
                                            f"the {_STORE_TITLES[winner[key]]} store has a rule of the same id ('{ident[:60]}'), which "
                                            "replaces this one: it is kept disabled"))  # fmt: skip
                    parsed.active = False
                else:
                    winner.setdefault(key, kind)
                out.append(parsed)
        return out

    def _name(self, parsed: _Parsed) -> str:
        display = parsed.name.strip()
        base = display if display and not display.startswith("@") else parsed.ident.strip() or "rule"
        if base.lower() in self.rule_names:
            base = f"{base} [{parsed.ident.strip()}]" if parsed.ident.strip() and parsed.ident.strip() != base else base
        candidate, counter = base, 2
        while candidate.lower() in self.rule_names:
            candidate = f"{base} ({counter})"
            counter += 1
        self.rule_names.add(candidate.lower())
        return candidate

    def _service(self, parsed: _Parsed) -> List[str]:
        if parsed.protocol is None:
            return [ANY]
        number = parsed.protocol
        if number in (6, 17):
            proto = Protocol.TCP if number == 6 else Protocol.UDP
            local, remote = ",".join(parsed.lports), ",".join(parsed.rports)
            dst, src = (local, remote) if parsed.inbound else (remote, local)
            name = f"{proto.value}-{dst.replace(',', '_') or 'all'}" + (f"-from-{src.replace(',', '_')}" if src else "")
            entries = [ServiceEntry(proto, dst_ports=dst, src_ports=src)]
        elif number in (1, 58):
            proto = Protocol.ICMP if number == 1 else Protocol.ICMP6
            label = "icmp" if number == 1 else "icmp6"
            if not parsed.icmp:
                name, entries = f"{label}-all", [ServiceEntry(proto)]
            else:
                name = label + "-" + "_".join(str(t) if c is None else f"{t}.{c}" for t, c in parsed.icmp)
                entries = [ServiceEntry(proto, icmp_type=t, icmp_code=c) for t, c in parsed.icmp]
        elif number == 132:
            name, entries = "sctp-all", [ServiceEntry(Protocol.SCTP)]
        else:
            name, entries = f"ip-{number}", [ServiceEntry(Protocol.IP, ip_protocol=number)]
        if name not in self.p.services:
            self.p.services[name] = Service(name, entries)
        return [name]

    def _members(self, literals: List[str]) -> List[str]:
        if not literals:
            return [ANY]
        out: List[str] = []
        for literal in literals:
            if literal.startswith("kw:"):
                keyword = literal[3:]
                if keyword not in self.p.address_groups:
                    word = keyword.rstrip("46")
                    family = keyword[len(word):]
                    self.p.address_groups[keyword] = AddressGroup(
                        keyword, description=f"the address keyword {word} of Windows Firewall" + (f", IPv{family} only" if family else ""),
                        dynamic_filter=KEYWORD_PREFIX + keyword, builtin=VENDOR)  # fmt: skip
                out.append(keyword)
            else:
                out.append(literal)
        return out

    def _rule(self, parsed: _Parsed, off: List[str], shielded: List[str]) -> None:
        name = self._name(parsed)
        profiles = [p for p in parsed.profiles if p not in off and not (parsed.inbound and p in shielded)]
        rule = Rule(name=name, origin=name, action=Action.ALLOW if parsed.action != "block" else Action.DROP)
        rule.description = parsed.description if not parsed.description.startswith("@") else ""
        rule.tags = [parsed.group] if parsed.group else []
        rule.source_ids = {"windows-firewall.id": parsed.ident, "windows-firewall.store": parsed.store}
        rule.enabled = parsed.active and not parsed.invalid
        rule.log_end = False
        remote, local = self._members(parsed.remote), self._members(parsed.local)
        if parsed.inbound:
            rule.src_zones, rule.dst_zones, rule.sources, rule.destinations = profiles or list(parsed.profiles), [HOST], remote, local
        else:
            rule.src_zones, rule.dst_zones, rule.sources, rule.destinations = [HOST], profiles or list(parsed.profiles), local, remote
        if not parsed.invalid:
            rule.services = self._service(parsed)
        rule.unsupported = list(parsed.unsupported)
        self.p.rules.append(rule)
        for severity, code, message in parsed.findings:
            self.report.add("rule", rule.origin, severity, code, message)
        if parsed.invalid:
            self.report.add("rule", rule.origin, Severity.REVIEW, "WINFW_RULE_INVALID",
                            "Windows does not enforce a rule it cannot parse (" + "; ".join(dict.fromkeys(parsed.invalid))[:300]
                            + "): it is kept disabled")  # fmt: skip
            return
        if rule.unsupported:
            self.report.add("rule", rule.origin, Severity.REVIEW, "WINFW_NOT_MODELLED",
                            "the rule matches only part of what its addresses and ports say: " + "; ".join(rule.unsupported)
                            + ". It is not converted")  # fmt: skip
        if parsed.store == "local" and rule.enabled:
            ignored = [p for p in profiles if not self.settings[p]["allowlocalpolicymerge"]]
            if ignored:
                profiles = [p for p in profiles if p not in ignored]
                self.local_ignored += 1
                if not profiles:
                    self.report.add("rule", rule.origin, Severity.INFO, "WINFW_LOCAL_IGNORED",
                                    "a local rule, and Group Policy (or MDM) does not merge local rules in the profile "
                                    + ", ".join(ignored) + ": it applies nowhere and is kept disabled")  # fmt: skip
        left_out = [p for p in parsed.profiles if p in off or (parsed.inbound and p in shielded)]
        if left_out and rule.enabled:
            self.report.add("rule", rule.origin, Severity.INFO, "WINFW_PROFILE_LEFT_OUT",
                            "in the profile " + ", ".join(left_out) + " the firewall is off or blocks every inbound connection, "
                            "which the rules at the top decide; the rule is left out there" + ("" if profiles else ": it applies "
                            "nowhere and is kept disabled"))  # fmt: skip
        if rule.enabled and not profiles:
            rule.enabled = False
        elif profiles:
            if parsed.inbound:
                rule.src_zones = profiles
            else:
                rule.dst_zones = profiles

    def _top(self, off: List[str], shielded: List[str]) -> None:
        if off:
            for inbound in (True, False):
                name = f"(firewall off) {'inbound' if inbound else 'outbound'}"
                rule = Rule(name=name, origin=name, src_zones=off if inbound else [HOST], dst_zones=[HOST] if inbound else off,
                            log_end=False, description="the firewall is off in these profiles: nothing is blocked")  # fmt: skip
                self.rule_names.add(name.lower())
                self.p.rules.append(rule)
        if shielded:
            name = "(shielded) inbound"
            rule = Rule(name=name, origin=name, src_zones=list(shielded), dst_zones=[HOST], action=Action.DROP, log_end=False,
                        description="these profiles block every inbound connection, whatever the rules say")  # fmt: skip
            self.rule_names.add(name.lower())
            self.p.rules.append(rule)

    def _defaults(self, off: List[str], shielded: List[str]) -> None:
        on = [p for p in PROFILES if p not in off]
        inbound = [p for p in on if p not in shielded and not self.settings[p]["defaultinboundaction"]]
        outbound = [p for p in on if not self.settings[p]["defaultoutboundaction"]]
        for zones, word in ((inbound, "inbound"), (outbound, "outbound")):
            if not zones:
                continue
            name = f"(default) {word}"
            rule = Rule(name=name, origin=name, src_zones=zones if word == "inbound" else [HOST],
                        dst_zones=[HOST] if word == "inbound" else zones, log_end=False,
                        description=f"the default of these profiles for {word} connections that no rule matches: allow")  # fmt: skip
            self.rule_names.add(name.lower())
            self.p.rules.append(rule)

    def _notes(self, off: List[str], shielded: List[str]) -> None:
        self.report.note(Severity.INFO, "WINFW_HOST_POLICY",
                         "a host firewall: the zone Host is the host itself, the zones Domain, Private and Public the networks of "
                         "the interfaces in each profile. Windows has no rule order: block rules decide before allow rules, then "
                         "the default of the profile; the converted policy says that in first-match order (block rules, allow "
                         "rules, the defaults that allow). Traffic between the networks is not the host's to decide and is denied")  # fmt: skip
        counts = [f"{_STORE_TITLES[k]} {len(self.stores[k].rules)} rule{'s' if len(self.stores[k].rules) != 1 else ''}"
                  for k in ("gpo", "mdm", "local") if self.stores[k].seen]  # fmt: skip
        self.report.note(Severity.INFO, "WINFW_STORES", "stores read: " + ", ".join(counts))
        if not self.stores["gpo"].seen or not self.stores["local"].seen:
            missing = "Group Policy (HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall)" if not self.stores["gpo"].seen else \
                "local (HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy)"  # fmt: skip
            self.report.note(Severity.REVIEW, "WINFW_STORE_MISSING",
                             f"the input holds no {missing} store: what it holds on the host is not converted. If that key does not "
                             "exist on the host, nothing is missing")  # fmt: skip
        parts = []
        for profile in PROFILES:
            s, w = self.settings[profile], self.source[profile]
            state = "firewall off" if not s["enablefirewall"] else \
                ("inbound " + ("blocked" if s["defaultinboundaction"] else "allowed") + f" ({w['defaultinboundaction']}), outbound "
                 + ("blocked" if s["defaultoutboundaction"] else "allowed") + f" ({w['defaultoutboundaction']})"
                 + (", every inbound connection blocked" if s["donotallowexceptions"] else "")
                 + ("" if s["allowlocalpolicymerge"] else f", local rules not merged ({w['allowlocalpolicymerge']})"))  # fmt: skip
            parts.append(f"{profile}: {state}")
        self.report.note(Severity.INFO, "WINFW_PROFILES", "; ".join(parts))
        unmerged = [p for p in PROFILES if not self.settings[p]["allowlocalpolicymerge"]]
        if unmerged and self.stores["local"].rules:
            self.report.note(Severity.INFO, "WINFW_LOCAL_NOT_MERGED",
                             "Group Policy (or MDM) does not merge local rules in the profile " + ", ".join(unmerged) + ": the local "
                             f"rules are left out there ({self.local_ignored} rule{'s' if self.local_ignored != 1 else ''} named it)")  # fmt: skip
        if off:
            self.report.note(Severity.REVIEW, "WINFW_FIREWALL_OFF",
                             "the firewall is off in the profile " + ", ".join(off) + ": everything to and from those networks is "
                             "allowed (the first two rules)")  # fmt: skip
        if shielded:
            self.report.note(Severity.INFO, "WINFW_SHIELDED",
                             "the profile " + ", ".join(shielded) + " blocks every inbound connection, whatever the rules say "
                             "(the rule '(shielded) inbound')")  # fmt: skip
        settings = sorted({f"{profile}: {text}" for profile in PROFILES for name, text in _NOT_CONVERTED_SETTINGS.items()
                           if self.settings[profile].get(name)})  # fmt: skip
        if settings:
            self.report.note(Severity.INFO, "WINFW_SETTING_NOT_CONVERTED",
                             "profile settings that decide traffic no rule names are not converted: " + "; ".join(settings))  # fmt: skip
        keywords = sorted(self.p.address_groups)
        if keywords:
            self.report.note(Severity.INFO, "WINFW_ADDRESS_KEYWORDS",
                             "rules name address keywords, whose addresses only Windows knows at run time: " + ", ".join(keywords)
                             + ". They are dynamic groups; only a Windows target writes them again")  # fmt: skip
        if self.not_read:
            self.report.note(Severity.INFO, "WINFW_NOT_READ",
                             "not read: " + "; ".join(self.not_read[:12]) + (f"; and {len(self.not_read) - 12} more" if len(self.not_read) > 12 else ""))  # fmt: skip
        bypass = [r.origin for r in self.p.rules if any("authenticated bypass" in u for u in r.unsupported)]
        if bypass:
            self.report.note(Severity.REVIEW, "WINFW_BYPASS",
                             "rules with authenticated bypass let IPsec-authenticated connections through block rules; they are "
                             "first in the converted policy and not converted: " + ", ".join(bypass[:10]))  # fmt: skip


def parse(data: bytes, report: Report) -> Policy:
    if len(data) > _MAX_INPUT:
        raise ParseError(f"the registry export is larger than {_MAX_INPUT // (1024 * 1024)} MB")
    text = _decode(data)
    return _Builder(_registry(text), report).build()
