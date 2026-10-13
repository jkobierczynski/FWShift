# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""MikroTik RouterOS parser: the text of ``/export`` (RouterOS 6 or 7) -> neutral model.

How RouterOS behaviour is mapped onto the neutral model:

* Only forwarded traffic is policy: the ``forward`` chain of ``/ip firewall filter`` and ``/ipv6 firewall filter``
  becomes the security rules. ``input`` and ``output`` filter traffic of the router itself and are reported, not
  converted; so are ``raw`` and ``mangle``.
* A packet that no rule of a built-in chain decides is accepted: the model's defaults are allow, inside a zone and
  between zones. That cannot be changed on RouterOS.
* Interface lists are the zones when the lists the rules use do not overlap; otherwise every interface is a zone and
  a list stands for the zones of its members.
* RouterOS filters packets, the model connections. A rule that accepts established and related packets is what every
  stateful platform does by itself and is left out; the remaining rules describe new connections.
* Custom chains are flattened into the rule that jumps to them; a ``return`` that one condition can take away from
  the rules below it is followed exactly.
* The forward chain sees packets after destination NAT, so its rules name the translated address; the model wants
  the original one. ``connection-nat-state=!dstnat`` (the default configuration's "drop all from WAN not DSTNATed")
  is read as the deny it is, with the connections the destination NAT rules translate let through ahead of it.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

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
    Rule,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import interval_text, parse_literal, range_text, size
from ..report import Report, Severity
from . import nftables as _nft
from .nftables import _Cond, _meet, _with_problem, _without, constrain

_MAX_EFFECTIVE_RULES = 50000
_VERBS = {"add", "set", "remove", "unset", "enable", "disable", "move", "print", "export", "edit", "comment", "reset",
          "reset-counters", "reset-counters-all", "import", "find"}  # fmt: skip
_BUILTIN_FILTER = ("input", "forward", "output")
_BUILTIN_NAT = ("srcnat", "dstnat")
_BUILTIN_LISTS = ("all", "none", "dynamic", "static")
# Protocol names RouterOS takes, and their numbers. ipip, ipencap, encap and ipv6-encap are left out: which number
# RouterOS gives each is not known.
_PROTOCOLS = {
    "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "ipsec-esp": 50, "ipsec-ah": 51, "ospf": 89, "sctp": 132,
    "udp-lite": 136, "dccp": 33, "l2tp": 115, "vrrp": 112, "pim": 103, "igmp": 2, "rsvp": 46, "egp": 8, "etherip": 97,
    "ipv6": 41, "ipv6-frag": 44, "ipv6-route": 43, "ipv6-nonxt": 59, "ipv6-opts": 60, "ggp": 3, "st": 5, "pup": 12,
    "hmp": 20, "xns-idp": 22, "rdp": 27, "iso-tp4": 29, "xtp": 36, "ddp": 37, "idpr-cmtp": 38, "rspf": 73, "vmtp": 81,
}  # fmt: skip
_PORT_HEADS = {"tcp": "tcp", "udp": "udp", "sctp": "sctp", "udp-lite": "udplite", "dccp": "dccp"}
# Properties that hold no match.
_PLAIN = {
    "chain", "action", "comment", "disabled", "log", "log-prefix", "jump-target", "reject-with", "address-list",
    "address-list-timeout", "to-addresses", "to-address", "to-ports", "hw-offload", "randomise-ports", "same-not-by-dst",
    "place-before",
}  # fmt: skip
# Properties read below.
_READ = {
    "in-interface", "out-interface", "in-interface-list", "out-interface-list", "src-address", "dst-address",
    "src-address-list", "dst-address-list", "protocol", "dst-port", "src-port", "port", "icmp-options",
    "connection-state", "connection-nat-state", "time", "tcp-flags", "dst-address-type", "ipsec-policy", "limit",
}  # fmt: skip
# Matches the model has no place for, and what they test.
_UNSUPPORTED = {
    "layer7-protocol": "a layer-7 pattern", "content": "the content of packets", "tls-host": "the TLS server name",
    "src-mac-address": "a MAC address", "dst-limit": "a rate limit", "connection-limit": "a connection count",
    "connection-rate": "a connection rate", "connection-bytes": "the bytes of a connection", "nth": "every nth packet",
    "random": "a random part of the packets", "psd": "port scans", "per-connection-classifier": "a hash of connections",
    "packet-size": "the size of packets", "ttl": "the TTL", "hop-limit": "the hop limit", "headers": "IPv6 headers",
    "dscp": "the DSCP field", "tcp-mss": "the TCP MSS", "fragment": "fragments", "ipv4-options": "IPv4 options",
    "ingress-priority": "the ingress priority", "priority": "the priority", "realm": "the routing realm",
    "hotspot": "hotspot users", "p2p": "peer-to-peer traffic", "routing-mark": "a mark set by mangle",
    "connection-mark": "a mark set by mangle", "packet-mark": "a mark set by mangle",
    "routing-table": "the routing table", "src-address-type": "the type of the source address",
    "in-bridge-port": "a bridge port", "out-bridge-port": "a bridge port", "in-bridge-port-list": "bridge ports",
    "out-bridge-port-list": "bridge ports", "connection-type": "connections a helper relates to another one",
}  # fmt: skip
_FILTER_VERDICTS = {"accept", "drop", "reject", "tarpit"}
_NAT_TRANSLATIONS = {"masquerade", "src-nat", "dst-nat", "netmap", "same", "redirect", "endpoint-independent-nat"}
_PASSING = {"passthrough", "add-src-to-address-list", "add-dst-to-address-list"}
_GUARD = re.compile(r':if \(\[:len \[/ip(?:v6)? firewall filter find where chain="fwshift-forward"\]\] > 0\) do=\{ :error "[^"]*" \}$')


# -- reading the text ---------------------------------------------------------------


@dataclass
class _Cmd:
    menu: str  # "ip firewall filter"
    verb: str
    args: Dict[str, str]
    line: int
    selector: str = ""


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """Join the lines an export breaks with a backslash (inside quoted strings as well) and drop comment lines."""
    out: List[Tuple[int, str]] = []
    buf: List[str] = []
    line, start = 1, 1
    quoted = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "#" and not quoted and not "".join(buf).strip():
            while i < n and text[i] not in "\r\n":
                i += 1
            buf = []
            continue
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt in "\r\n":
                i += 3 if text[i + 1 : i + 3] == "\r\n" else 2
                line += 1
                while i < n and text[i] in " \t":
                    i += 1
                continue
            if quoted:
                buf.append(ch + nxt)  # an escape: the pair stays together
                i += 2
                continue
        if ch == '"':
            quoted = not quoted
        if ch in "\r\n":
            if quoted:
                raise ParseError(f"line {start}: a quoted string is not closed before the end of the line")
            if "".join(buf).strip():
                out.append((start, "".join(buf)))
            buf = []
            i += 2 if text[i : i + 2] == "\r\n" else 1
            line += 1
            start = line
            continue
        buf.append(ch)
        i += 1
    if quoted:
        raise ParseError(f"line {start}: a quoted string is not closed")
    if "".join(buf).strip():
        out.append((start, "".join(buf)))
    return out


_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t", "$": "$", "_": " ", "?": "?", "a": "\a",
            "b": "\b", "f": "\f", "v": "\v"}  # fmt: skip


def _decode(body: str, number: int) -> str:
    """The text of a quoted string (without its quotes), escapes decoded."""
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        nxt = body[i + 1 : i + 2]
        if nxt in _ESCAPES:
            out += _ESCAPES[nxt].encode("utf-8")
            i += 2
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", body[i + 1 : i + 3]):
            out.append(int(body[i + 1 : i + 3], 16))
            i += 3
        else:
            raise ParseError(f"line {number}: unknown escape '\\{nxt}' in a quoted string")
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("latin-1")


def _tokens(text: str, number: int) -> List[Tuple[str, str]]:
    """The words of a logical line: (kind, text) with kind "word", "pair" (key=value, decoded) or "selector"."""
    out: List[Tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] in " \t":
            i += 1
            continue
        if text[i] == "[":
            depth, j, quoted = 0, i, False
            while j < n:
                if text[j] == '"' and text[j - 1 : j] != "\\":
                    quoted = not quoted
                elif not quoted and text[j] == "[":
                    depth += 1
                elif not quoted and text[j] == "]":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append(("selector", text[i : j + 1]))
            i = j + 1
            continue
        j = i
        quoted = False
        while j < n and (quoted or text[j] not in " \t"):
            if text[j] == "\\" and quoted:
                j += 2
                continue
            if text[j] == '"':
                quoted = not quoted
            j += 1
        word = text[i:j]
        i = j
        key, eq, value = word.partition("=")
        if eq and key and '"' not in key:
            if value.startswith('"'):
                if len(value) < 2 or not value.endswith('"'):
                    raise ParseError(f"line {number}: cannot read the value of '{key}'")
                value = _decode(value[1:-1], number)
            out.append(("pair", f"{key}={value}"))
        elif word.startswith('"'):
            out.append(("word", _decode(word[1:-1], number)))
        else:
            out.append(("word", word))
    return out


def _commands(text: str, errors: List[str]) -> Tuple[List[_Cmd], int, str]:
    """(commands, scripting lines that were not read, the RouterOS version of the header). Menus the export could not
    write (other than the ones the conversion needs, which are an error) are added to ``errors``."""
    version = ""
    found = re.search(r"by RouterOS (\d+\.\d+(?:\.\d+)?)", text[:2000])
    if found:
        version = found.group(1)
    for failed in re.findall(r'^#error exporting "?([^"\n]*)"?(.*)$', text, re.MULTILINE):
        menu_failed = failed[0].replace("/", " ").strip()
        if menu_failed.startswith(("ip firewall", "ipv6 firewall", "interface list", "ip address", "ipv6 address")) or not menu_failed:
            raise ParseError(f"the export says it could not export /{failed[0].strip('/')}{failed[1]}: export again")
        errors.append(failed[0])
    lines = _logical_lines(text)
    if not any(line.lstrip().startswith("/") for _, line in lines):
        if any(re.match(r"\s*(Flags:|\d+\s+[XIDE*]*\s*(;;;|chain=))", line) for _, line in lines):
            raise ParseError("this is the output of 'print'; FWShift reads the output of '/export'")
    menu = ""
    out: List[_Cmd] = []
    scripting = 0
    for number, line in lines:
        stripped = line.strip()
        if stripped.startswith(":"):
            if not _GUARD.match(stripped):  # (the check at the top of a script FWShift writes adds nothing)
                scripting += 1
            continue
        words = _tokens(stripped, number)
        if not words:
            continue
        path: List[str] = []
        index = 0
        if words[0][0] == "word" and words[0][1].startswith("/"):
            path = [part for part in words[0][1].split("/") if part]
            index = 1
            while index < len(words) and words[index][0] == "word" and words[index][1] not in _VERBS:
                path.append(words[index][1])
                index += 1
            if index == len(words):
                menu = " ".join(path)
                continue
        current = " ".join(path) if path else menu
        kind, verb = words[index]
        if kind != "word" or verb not in _VERBS:
            raise ParseError(f"line {number}: cannot read '{stripped[:60]}'; expected the output of '/export'")
        if not current:
            raise ParseError(f"line {number}: '{verb}' before any menu (such as /ip firewall filter); give the whole "
                             "output of '/export', or add the menu as the first line")  # fmt: skip
        args: Dict[str, str] = {}
        selector = ""
        for kind, word in words[index + 1 :]:
            if kind == "pair":
                key, _, value = word.partition("=")
                if value:  # (a verbose export writes an unset property as key="")
                    args[key] = value
            elif kind == "selector":
                selector = word
            elif word.startswith("!"):
                continue  # verbose export: the property is not set
            else:
                args.setdefault("", word)  # an unnamed parameter (set ftp ...)
        out.append(_Cmd(current, verb, args, number, selector))
    return out, scripting, version


# -- what was read ----------------------------------------------------------------------


@dataclass
class _RRule:
    family: int
    kind: str  # filter or nat
    chain: str
    number: int  # position in its chain, from 1
    args: Dict[str, str]
    line: int

    @property
    def action(self) -> str:
        return self.args.get("action", "accept")

    @property
    def disabled(self) -> bool:
        return self.args.get("disabled", "no") in ("yes", "true")

    @property
    def comment(self) -> str:
        return self.args.get("comment", "")


@dataclass
class _Family:
    filter: Dict[str, List[_RRule]] = field(default_factory=dict)
    nat: Dict[str, List[_RRule]] = field(default_factory=dict)
    lists: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)  # name -> entries in order
    filled: Set[str] = field(default_factory=set)  # lists rules add addresses to
    raw: int = 0
    mangle: int = 0
    tracking: str = ""  # connection tracking enabled=
    addresses: List[Tuple[str, str]] = field(default_factory=list)  # (address, interface) of the router


@dataclass
class _Entry:
    cond: _Cond
    action: str  # accept, drop, reject, reset, unknown, log, nat
    rule: _RRule
    where: str
    log: bool = False
    why: str = ""
    disabled: bool = False
    limited: bool = False


def _neg(value: str) -> Tuple[bool, str]:
    return (True, value[1:]) if value.startswith("!") else (False, value)


def looks_like_routeros(data: bytes) -> bool:
    head = data[:8192].decode("utf-8", errors="replace")
    if re.search(r"^# .{0,40}by RouterOS \d", head, re.MULTILINE):
        return True
    for line in head.splitlines()[:60]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(":"):
            continue  # (the check at the top of a script FWShift writes)
        return re.match(r"/(ip|ipv6|interface|system|routing|tool|queue|user|ppp|snmp|certificate)[ /]", line) is not None
    return False


def parse(data: bytes, report: Report, activate: bool = False) -> Policy:
    """``activate``: read the disabled jumps a script of FWShift ends with as enabled (they are what the person
    enables after loading it), so that the output can be read back for a comparison."""
    text = data.decode("utf-8-sig", errors="replace")
    errors: List[str] = []
    commands, scripting, version = _commands(text, errors)
    for menu in errors:
        report.note(Severity.REVIEW, "ROUTEROS_EXPORT_ERROR",
                    f"the export says it could not export {menu}: what that menu holds is not in the conversion")  # fmt: skip
    return _Builder(commands, report, scripting, version, activate).build()


class _Builder:
    def __init__(self, commands: List[_Cmd], report: Report, scripting: int, version: str, activate: bool) -> None:
        self.report, self.scripting, self.version, self.activate = report, scripting, version, activate
        self.p = Policy(vendor="routeros", lookup_after_dnat=True)
        self.helper = _nft._Builder(_nft._Ruleset(), report)
        self.helper.p = self.p
        self.fam: Dict[int, _Family] = {4: _Family(), 6: _Family()}
        self.if_lists: Dict[str, Dict[str, str]] = {}
        self.members: List[Tuple[str, str]] = []  # (list, interface), enabled ones
        self.interfaces: List[str] = []  # known interfaces, in the order seen
        self.bridges: Set[str] = set()
        self.bridge_ports: Dict[str, str] = {}
        self.dynamic_ifs: Set[str] = set()  # interfaces whose address the export does not hold (DHCP client, PPPoE)
        self.use_ip_firewall = False
        self.upnp = False
        self.ip_forward_off = False
        self.l3hw = False
        self.names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.visited = 0
        self.groups: Dict[Tuple[int, str], str] = {}
        self.fqdn_groups: Set[str] = set()
        self.empty_used: Set[str] = set()
        self.dynamic_used: Set[str] = set()
        self.timeouts = 0
        self.passive = 0
        self.fasttrack_other: List[str] = []
        self.disabled_flow = 0
        self.pending: List[Tuple[int, List[Rule]]] = []
        self.zone_of_list: Dict[str, Optional[FrozenSet[str]]] = {}
        self.zone_of_if: Dict[str, str] = {}
        self.zone_ifs: Dict[str, List[str]] = {}
        self.universe: FrozenSet[str] = frozenset()
        self.list_mode = False
        self._read(commands)

    # -- the menus --------------------------------------------------------------

    def _known(self, name: str) -> None:
        if name and name not in self.interfaces and name not in _BUILTIN_LISTS:
            self.interfaces.append(name)

    def _read(self, commands: List[_Cmd]) -> None:
        for cmd in commands:
            words = cmd.menu.split()
            a = cmd.args
            if "l3-hw-offloading" in a and a["l3-hw-offloading"] == "yes":
                self.l3hw = True
            if len(words) >= 2 and words[0] in ("ip", "ipv6") and words[1] == "firewall":
                self._firewall(cmd, 4 if words[0] == "ip" else 6, " ".join(words[2:]))
                continue
            for key in ("address-list", "address-lists"):
                # DHCP leases, PPP profiles and others add the addresses of their clients while the router runs.
                for name in [x for x in a.get(key, "").split(",") if x]:
                    for family in (4, 6):
                        self.fam[family].filled.add(name)
            if cmd.menu == "interface list":
                if cmd.verb == "add" and a.get("name"):
                    self.if_lists[a["name"]] = a
            elif cmd.menu == "interface list member":
                if cmd.verb == "add" and a.get("list") and a.get("interface") and a.get("disabled", "no") != "yes":
                    self.members.append((a["list"], a["interface"]))
                    self._known(a["interface"])
            elif cmd.menu == "interface bridge port":
                if cmd.verb == "add" and a.get("interface"):
                    self.bridge_ports[a["interface"]] = a.get("bridge", "")
            elif cmd.menu == "interface bridge settings":
                if "use-ip-firewall" in a:
                    self.use_ip_firewall = a["use-ip-firewall"] == "yes"
            elif len(words) == 2 and words[0] == "interface" and words[1] != "list":
                found = re.search(r"default-name=([^\s\]]+)", cmd.selector)
                if found and not a.get("name"):
                    self._known(found.group(1).strip('"'))
                if a.get("name"):
                    self._known(a["name"])
                    if words[1] == "bridge":
                        self.bridges.add(a["name"])
                    if words[1] in ("pppoe-client", "l2tp-client", "sstp-client", "ovpn-client", "pptp-client", "lte"):
                        self.dynamic_ifs.add(a["name"])
            elif cmd.menu in ("ip address", "ipv6 address"):
                if cmd.verb == "add" and a.get("address") and a.get("disabled", "no") != "yes":
                    family = 4 if cmd.menu == "ip address" else 6
                    self.fam[family].addresses.append((a["address"], a.get("interface", "")))
                    self._known(a.get("interface", ""))
            elif cmd.menu in ("ip dhcp-client", "ipv6 dhcp-client"):
                if cmd.verb == "add" and a.get("interface") and a.get("disabled", "no") != "yes":
                    self.dynamic_ifs.add(a["interface"])
            elif cmd.menu == "ip upnp":
                if a.get("enabled") == "yes":
                    self.upnp = True
            elif cmd.menu == "ip settings":
                if a.get("ip-forward") == "no":
                    self.ip_forward_off = True

    def _firewall(self, cmd: _Cmd, family: int, sub: str) -> None:
        f = self.fam[family]
        a = cmd.args
        if sub in ("filter", "nat"):
            if cmd.verb != "add":
                raise ParseError(f"line {cmd.line}: '{cmd.verb}' in /{'ip' if family == 4 else 'ipv6'} firewall {sub}; "
                                 "FWShift reads the 'add' lines of an export")  # fmt: skip
            chain = a.get("chain", "")
            if not chain:
                raise ParseError(f"line {cmd.line}: a rule without a chain")
            table = f.filter if sub == "filter" else f.nat
            rules = table.setdefault(chain, [])
            rules.append(_RRule(family, sub, chain, len(rules) + 1, dict(a), cmd.line))
            if a.get("action") in ("add-src-to-address-list", "add-dst-to-address-list") and a.get("address-list"):
                f.filled.add(a["address-list"])
        elif sub == "address-list":
            if cmd.verb == "add" and a.get("list"):
                f.lists.setdefault(a["list"], []).append(dict(a))
        elif sub in ("raw", "mangle"):
            if cmd.verb == "add":
                if sub == "raw":
                    f.raw += 1
                else:
                    f.mangle += 1
                if a.get("action") in ("add-src-to-address-list", "add-dst-to-address-list") and a.get("address-list"):
                    f.filled.add(a["address-list"])
        elif sub == "connection tracking":
            if "enabled" in a:
                f.tracking = a["enabled"]

    # -- zones ------------------------------------------------------------------

    def _resolve(self, name: str, stack: Tuple[str, ...] = ()) -> Optional[Set[str]]:
        """The interfaces of an interface list; None when they cannot be listed (a built-in list, a loop)."""
        if name == "none":
            return set()
        if name in _BUILTIN_LISTS or name in stack:
            return None
        out = {interface for list_name, interface in self.members if list_name == name}
        a = self.if_lists.get(name, {})
        for key, sign in (("include", 1), ("exclude", -1)):
            for other in [x for x in a.get(key, "").split(",") if x]:
                found = self._resolve(other, stack + (name,))
                if found is None:
                    return None
                out = out | found if sign == 1 else out - found
        return out

    def _relevant(self) -> List[_RRule]:
        out: List[_RRule] = []
        for f in self.fam.values():
            for chain, rules in f.filter.items():
                if chain not in ("input", "output"):
                    out += rules
            for rules in f.nat.values():
                out += rules
        return out

    def _zones(self) -> None:
        used: List[str] = []
        named: List[str] = []
        for r in self._relevant():
            for side in ("in", "out"):
                value = r.args.get(f"{side}-interface-list")
                if value is not None:
                    name = _neg(value)[1]
                    if name not in _BUILTIN_LISTS and name not in used:
                        used.append(name)
                value = r.args.get(f"{side}-interface")
                if value is not None:
                    name = _neg(value)[1]
                    if name not in named:
                        named.append(name)
                    self._known(name)
        resolved = {name: self._resolve(name) for name in used}
        for members in resolved.values():
            for interface in sorted(members or ()):
                self._known(interface)
        order = [name for name in list(self.if_lists) + used if name in used]
        order = list(dict.fromkeys(order))
        listed = sorted({i for members in resolved.values() if members for i in members})
        signature = {i: frozenset(name for name in order if i in (resolved[name] or ())) for i in listed}
        classes: Dict[FrozenSet[str], List[str]] = {}
        for interface in listed:
            classes.setdefault(signature[interface], []).append(interface)
        list_mode = all(resolved[name] is not None for name in used) and bool(used)
        class_name: Dict[FrozenSet[str], str] = {}
        if list_mode:
            for sig, interfaces in classes.items():
                exact = [name for name in order if resolved[name] == set(interfaces)]
                if not exact:
                    list_mode = False
                    break
                class_name[sig] = exact[0]
        if list_mode:
            for name in named:
                own = signature.get(name)
                if own is not None and len(classes[own]) > 1:
                    list_mode = False  # a rule names part of a zone
        self.list_mode = list_mode
        taken: Set[str] = set()
        if list_mode:
            for sig, interfaces in classes.items():
                zone = class_name[sig]
                taken.add(zone)
                self.zone_ifs[zone] = sorted(interfaces)
                for interface in interfaces:
                    self.zone_of_if[interface] = zone
        for interface in self.interfaces:
            if interface in self.zone_of_if or interface in self.bridge_ports:
                continue
            zone = interface
            if zone in taken:
                zone = f"{interface}-interface"
            taken.add(zone)
            self.zone_of_if[interface] = zone
            self.zone_ifs[zone] = [interface]
        for name in used:
            members = resolved[name]
            if members is None:
                self.zone_of_list[name] = None
            else:
                self.zone_of_list[name] = frozenset(self.zone_of_if[i] for i in members if i in self.zone_of_if)
        self.universe = frozenset(self.zone_ifs)
        if list_mode:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_ZONES",
                "the interface lists the rules use do not overlap: each is a zone ("
                + ", ".join(f"{zone}: {', '.join(self.zone_ifs[zone])}" for zone in sorted(set(class_name.values())))
                + "); an interface in none of them is a zone of its own",
            )
        elif used:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_ZONES",
                "the interface lists the rules use overlap, or a rule names an interface that is only part of one: "
                "every interface is a zone, and a list stands for the zones of its members ("
                + "; ".join(f"{name}: {', '.join(sorted(self.zone_of_list[name] or ())) or '(none)'}" for name in used)
                + ")",
            )

    def _interface_zones(self, r: _RRule, side: str) -> Tuple[Optional[FrozenSet[str]], str, bool]:
        """(zones, problem, negated): None zones for any interface; an empty set never matches."""
        zones: Optional[FrozenSet[str]] = None
        negated_any = False
        for key in (f"{side}-interface", f"{side}-interface-list"):
            value = r.args.get(key)
            if value is None:
                continue
            negated, name = _neg(value)
            if key.endswith("-list"):
                if name == "all":
                    if negated:
                        zones = frozenset()  # no interface at all
                    continue
                if name in ("dynamic", "static"):
                    return None, f"{key}={value}, whose members are known only while the router runs", False
                members = self.zone_of_list.get(name)
                if members is None and name != "none":
                    return None, f"{key}={value}, whose members cannot be listed", False
                members = members or frozenset()
                if not members and name != "none":
                    return None, (f"{key}={value}: the list has no members in the export (the router can add some "
                                  "while it runs, for PPP or VPN connections)"), False  # fmt: skip
            else:
                if name in self.bridge_ports:
                    return None, (f"{key}={value}: {name} is a port of bridge {self.bridge_ports[name]}, and routed "
                                  "traffic comes in by the bridge"), False  # fmt: skip
                members = frozenset({self.zone_of_if[name]}) if name in self.zone_of_if else frozenset()
            if negated:
                members = self.universe - members
                negated_any = True
            zones = members if zones is None else zones & members
        if negated_any and zones is not None and not zones:
            return None, (f"{side}put interface match that leaves none of the interfaces the export shows (on the source "
                          "it matches interfaces the export leaves out)"), False  # fmt: skip
        return zones, "", negated_any

    # -- address lists ------------------------------------------------------------

    def _group(self, family: int, name: str) -> Tuple[str, List[str], bool, str]:
        """(group name, literals, holds host names, problem) for an address list."""
        entries = [e for e in self.fam[family].lists.get(name, []) if e.get("disabled", "no") != "yes"]
        literals: List[str] = []
        members: List[str] = []
        fqdn = False
        problem = ""
        for entry in entries:
            value = entry.get("address", "")
            interval = parse_literal(value)
            if entry.get("timeout") or entry.get("dynamic") == "yes":
                self.timeouts += 1
            if interval is not None:
                if interval[0] != family:
                    problem = f"address list '{name}' holds {value}, of the other IP version"
                    continue
                text = interval_text(interval)
                literals.append(text)
                members.append(text)
            elif re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.?", value) and "." in value:
                fqdn = True
                host = value.rstrip(".")
                address_name = host if family == 4 else f"{host}-ipv6"
                if address_name not in self.p.addresses:
                    self.p.addresses[address_name] = Address(
                        address_name, AddressKind.FQDN, host, description="host name in a RouterOS address list",
                        fqdn_family=family)  # fmt: skip
                members.append(address_name)
            else:
                problem = f"address list '{name}' holds '{value[:40]}', which FWShift cannot read"
        key = (family, name)
        if key not in self.groups:
            group = name
            if family == 6 and name in self.fam[4].lists:
                group = f"{name}-ipv6"
            taken = set(self.p.addresses) | set(self.p.address_groups)
            counter = 2
            base = group
            while group in taken:
                group = f"{base}-{counter}"
                counter += 1
            self.groups[key] = group
            what = "/ip" if family == 4 else "/ipv6"
            self.p.address_groups[group] = AddressGroup(group, list(dict.fromkeys(members)),
                                                        description=f"RouterOS {what} firewall address-list {name}")  # fmt: skip
            if fqdn:
                self.fqdn_groups.add(group)
        return self.groups[key], list(dict.fromkeys(literals)), fqdn, problem

    def _list_match(self, c: _Cond, r: _RRule, side: str, value: str) -> Optional[_Cond]:
        negated, name = _neg(value)
        family = r.family
        key = f"{'ip' if family == 4 else 'ip6'} {'saddr' if side == 'src' else 'daddr'}"
        if name in self.fam[family].filled:
            self.dynamic_used.add(f"{'/ip' if family == 4 else '/ipv6'} {name}")
            return _with_problem(c, f"address list '{name}', which rules fill while the router runs")
        group, literals, fqdn, problem = self._group(family, name)
        if problem:
            return _with_problem(c, problem)
        if fqdn:
            return _with_problem(c, f"\x00list:{side}:{'!' if negated else ''}{group}")
        if not literals:
            self.empty_used.add(f"{'/ip' if family == 4 else '/ipv6'} {name}")
        return constrain(c, key, "!=" if negated else "==", literals, (group,))

    # -- one rule as conditions ------------------------------------------------------

    def _conds(self, r: _RRule) -> List[_Cond]:
        family = r.family
        ip = "ip" if family == 4 else "ip6"
        a = r.args
        c: Optional[_Cond] = _Cond(families=frozenset({family}))
        assert c is not None
        logging = r.action == "log"
        for key, value in a.items():
            if key in _PLAIN or key in _READ or key == "":
                continue
            if key in _UNSUPPORTED:
                c = _with_problem(c, f"{key}={value} (a match on {_UNSUPPORTED[key]})")
            else:
                c = _with_problem(c, f"property {key}={value}, which FWShift does not know")
        for side in ("in", "out"):
            zones, problem, negated_if = self._interface_zones(r, side)
            if negated_if:
                c = _with_problem(c, f"\x00negif:{side}")
            if problem:
                c = _with_problem(c, problem)
            elif zones is not None:
                if not zones:
                    return []
                c = _meet(c, _Cond(iif=zones) if side == "in" else _Cond(oif=zones))
                if c is None:
                    return []
        for side, word in (("src", "saddr"), ("dst", "daddr")):
            literal = a.get(f"{side}-address")
            if literal is not None:
                negated, text = _neg(literal)
                c = constrain(c, f"{ip} {word}", "!=" if negated else "==", [text])
                if c is None:
                    return []
            listed = a.get(f"{side}-address-list")
            if listed is not None:
                c = self._list_match(c, r, side, listed)
                if c is None:
                    return []
        if "dst-address-type" in a:
            c = self._address_type(c, r, a["dst-address-type"])
            if c is None:
                return []
        proto_negated, proto = _neg(a.get("protocol", ""))
        if proto.isdigit():
            proto = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 132: "sctp", 136: "udp-lite", 33: "dccp"}.get(int(proto), proto)
        if proto:
            number = _PROTOCOLS.get(proto, int(proto) if proto.isdigit() and int(proto) < 256 else None)
            if number is None or (number == 58 and family == 4) or (number == 1 and family == 6):
                c = _with_problem(c, f"protocol={a['protocol']}")
            else:
                c = constrain(c, "meta l4proto", "!=" if proto_negated else "==", [str(number)])
                if c is None:
                    return []
        head = "th" if proto_negated else _PORT_HEADS.get(proto, "th")
        for key, word in (("dst-port", "dport"), ("src-port", "sport"), ("port", "")):
            ports = a.get(key)
            if ports is not None and head == "th":
                c = _with_problem(c, f"{key}={ports} without protocol tcp, udp, sctp, udp-lite or dccp")
            elif ports is not None and word:
                negated, text = _neg(ports)
                c = constrain(c, f"{head} {word}", "!=" if negated else "==", text.split(","))
                if c is None:
                    return []
        if "icmp-options" in a:
            c = self._icmp(c, family, proto, proto_negated, a["icmp-options"])
            if c is None:
                return []
        if "connection-state" in a:
            negated, text = _neg(a["connection-state"])
            c = constrain(c, "ct state", "!=" if negated else "==", text.split(","))
            if c is None:
                return []
        state = a.get("connection-nat-state")
        if state is not None and (state != "!dstnat" or r.action not in ("accept", "drop", "reject", "tarpit")):
            c = _with_problem(c, f"connection-nat-state={state}" + ("" if state != "!dstnat" else f" on action={r.action}"))
        if "time" in a:
            c = _with_problem(c, f"\x00schedule:time={a['time']}")
        flags = a.get("tcp-flags")
        if flags is not None and flags != "syn":
            c = _with_problem(c, f"tcp-flags={flags}")
        elif flags == "syn":
            c = constrain(c, "meta l4proto", "==", ["6"])  # (a SYN opens a TCP connection: nothing else to add)
            if c is None:
                return []
        policy = a.get("ipsec-policy")
        if policy is not None and not (r.kind == "nat" and r.chain == "srcnat" and policy == "out,none"):
            c = _with_problem(c, f"ipsec-policy={policy} (traffic of IPsec tunnels)")
        if "limit" in a and not logging:
            c = _with_problem(c, f"limit={a['limit']} (a rate limit)")
        if "port" in a and head != "th":
            negated, text = _neg(a["port"])
            if negated:
                return [_with_problem(c, f"port={a['port']}")]
            out = []
            for word in ("dport", "sport"):
                more = constrain(c, f"{head} {word}", "==", text.split(","))
                if more is not None:
                    out.append(more)
            return out
        return [c]

    def _address_type(self, c: _Cond, r: _RRule, value: str) -> Optional[_Cond]:
        if value != "local" or r.kind != "nat":
            return _with_problem(c, f"dst-address-type={value} (a match on the type of the destination address)")
        hosts = [interval_text((i[0], i[1], i[1])) for i in
                 [parse_literal(address.split("/")[0]) for address, _ in self.fam[r.family].addresses] if i]  # fmt: skip
        if not hosts:
            return _with_problem(c, "dst-address-type=local, and the export holds no address of the router")
        return constrain(c, f"{'ip' if r.family == 4 else 'ip6'} daddr", "==", hosts)

    @staticmethod
    def _icmp(c: _Cond, family: int, proto: str, negated: bool, value: str) -> Optional[_Cond]:
        wanted = "icmp" if family == 4 else "icmpv6"
        kind, sep, code = value.partition(":")
        if proto != wanted or negated or value.startswith("!"):
            return _with_problem(c, f"icmp-options={value} without protocol={wanted}")
        if not sep:
            return _with_problem(c, f"icmp-options={value}: a type without a code, which RouterOS may read as code 0 "
                                 "or as any code")  # fmt: skip
        out = constrain(c, f"{wanted} type", "==", [kind])
        if out is not None and code not in ("0-255", ""):
            out = constrain(out, f"{wanted} code", "==", [code])
        return out

    # -- following the chains ---------------------------------------------------------

    def _enabled(self, r: _RRule) -> bool:
        if not r.disabled:
            return True
        # A script of FWShift ends with the jumps that switch it on, disabled; read back, they count as enabled.
        return self.activate and r.action == "jump" and r.comment.startswith("fwshift:")

    def _walk(self, r_chains: Dict[str, List[_RRule]], builtin: Tuple[str, ...], chain: str, contexts: List[_Cond],
              stack: Tuple[str, ...], prefix: str, base: bool, out: List[_Entry]) -> None:  # fmt: skip
        """Walk one chain for the packets of ``contexts`` (conditions that do not overlap)."""
        poisoned = ""
        for r in r_chains.get(chain, []):
            where = f"{prefix}{chain}-{r.number}"
            action = r.action
            if not self._enabled(r):
                if action in _FILTER_VERDICTS | _NAT_TRANSLATIONS:
                    for context in contexts:
                        for cond in self._conds(r):
                            merged = _meet(context, cond)
                            if merged is not None:
                                out.append(_Entry(merged, self._verdict(r, merged), r, where, log=self._logs(r), disabled=True))
                else:
                    self.disabled_flow += 1
                continue
            following: List[_Cond] = []
            for context in contexts:
                pieces = [context]  # what of this context goes on to the next rule
                for cond in self._conds(r):
                    merged = _meet(context, cond)
                    if merged is None:
                        continue
                    if poisoned:
                        merged = _with_problem(merged, poisoned)
                    self.visited += 1
                    if self.visited > _MAX_EFFECTIVE_RULES:
                        raise ParseError("the chains expand to more than 50000 rules; refusing to continue")
                    if action in _PASSING:
                        self.passive += 1
                    elif action == "log":
                        self.passive += 1
                        out.append(_Entry(merged, "log", r, where, limited="limit" in r.args))
                    elif action == "fasttrack-connection":
                        if merged.states is None or not merged.states <= {"ESTABLISHED", "RELATED"}:
                            self.fasttrack_other.append(where)
                    elif action == "return" and base:
                        out.append(_Entry(merged, "accept", r, where + "-return"))
                    elif action == "return":
                        # The rules below see what did not return: exact where conditions can say it.
                        rest: List[_Cond] = []
                        for piece in pieces:
                            taken = _meet(piece, cond)
                            if taken is None:
                                rest.append(piece)
                                continue
                            if poisoned:
                                taken = _with_problem(taken, poisoned)
                            left = _split_without(piece, taken)
                            if left is None:
                                poisoned = f"follows a conditional return in chain {chain}, which cannot be expressed"
                                rest.append(piece)
                            else:
                                rest += left
                        pieces = rest
                    elif action == "jump":
                        target = r.args.get("jump-target", "")
                        if target in builtin:
                            out.append(_Entry(_with_problem(merged, f"jump to built-in chain {target}"), "unknown", r, where,
                                              why="jump"))  # fmt: skip
                        elif target in stack:
                            out.append(_Entry(_with_problem(merged, f"jump loop through chain {target}"), "unknown", r, where,
                                              why="jump"))  # fmt: skip
                        else:
                            self._walk(r_chains, builtin, target, [merged], stack + (target,), where + ".", False, out)
                    else:
                        out.append(_Entry(merged, self._verdict(r, merged), r, where, log=self._logs(r), why=action))
                following += pieces
            contexts = following
            if not contexts:
                return

    @staticmethod
    def _logs(r: _RRule) -> bool:
        return r.args.get("log", "no") in ("yes", "true")

    @staticmethod
    def _verdict(r: _RRule, c: _Cond) -> str:
        action = r.action
        if r.kind == "nat":
            if action in _NAT_TRANSLATIONS:
                return "nat"
            return "accept" if action == "accept" else "unknown"
        if action == "accept":
            return "accept"
        if action in ("drop", "tarpit"):
            return "drop"
        if action == "reject":
            return "reset" if r.args.get("reject-with") == "tcp-reset" and c.proto == frozenset({6}) else "reject"
        return "unknown"

    # -- the policy -------------------------------------------------------------------

    def build(self) -> Policy:
        self._zones()
        self.p.default_interzone = self.p.default_intrazone = Action.ALLOW
        dnat: Dict[int, List[_Entry]] = {}
        nat_entries: Dict[str, List[_Entry]] = {"dstnat": [], "srcnat": []}
        for family in (4, 6):
            for chain in ("dstnat", "srcnat"):
                found: List[_Entry] = []
                prefix = "" if family == 4 else "ipv6-"
                self._walk(self.fam[family].nat, _BUILTIN_NAT, chain, [_Cond(families=frozenset({family}))], (chain,), prefix,
                           True, found)  # fmt: skip
                nat_entries[chain] += found
                if chain == "dstnat":
                    dnat[family] = found
        entries: List[_Entry] = []
        for family in (4, 6):
            prefix = "" if family == 4 else "ipv6-"
            self._walk(self.fam[family].filter, _BUILTIN_FILTER, "forward", [_Cond(families=frozenset({family}))], ("forward",),
                       prefix, True, entries)  # fmt: skip
        self._forward(entries, dnat)
        destination = [n for n in (self._nat_rule(e, "dstnat") for e in nat_entries["dstnat"]) if n is not None]
        source = [n for n in (self._nat_rule(e, "srcnat") for e in nat_entries["srcnat"]) if n is not None]
        self.p.nat_rules = destination + source
        for zone in transform.dedupe(
            [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        ):
            self.p.zones[zone] = Zone(zone, list(self.zone_ifs.get(zone, [zone])))
        # The forward chain sees the translated destination; the model matches the original one.
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        for position, rules in sorted(self.pending, key=lambda item: -item[0]):
            self.p.rules[position:position] = rules
        self._notes()
        return self.p

    def _forward(self, entries: List[_Entry], dnat: Dict[int, List[_Entry]]) -> None:
        accepts_established = False
        decided: Dict[int, FrozenSet[str]] = {4: frozenset(), 6: frozenset()}
        early_drops: List[str] = []
        logged: Optional[Tuple[object, ...]] = None
        logged_prefix = ""
        everything: List[Tuple[Optional[FrozenSet[str]], str]] = []
        packets = False
        accepts = denies = 0
        for index, entry in enumerate(entries):
            c = entry.cond
            if entry.disabled:
                if entry.action == "log" or (c.states is not None and "NEW" not in c.states):
                    continue  # (a disabled accept of established connections would read as an allow of everything)
                rule = self._rule(entry)
                rule.enabled = False
                self.p.rules.append(rule)
                continue
            key = _nft._Builder.match_key(c)
            if entry.action == "log":
                prefix = entry.rule.args.get("log-prefix", "")
                logged, logged_prefix = (key, prefix) if not entry.limited else (None, "")
                if not entry.limited and _nft._Builder.logs_all(c):
                    everything.append((c.states, prefix))
                if not accepts_established and (c.states is None or c.states - {"NEW"}):
                    packets = True
                continue
            prefixes = [entry.rule.args.get("log-prefix", "")] if entry.log else []
            prefixes += [logged_prefix] if logged == key else []
            prefixes += [p for s, p in everything if _nft._Builder.logs_what(s, c.states, accepts_established)]
            log = bool(prefixes)
            logged = None
            if entry.log and not accepts_established and (c.states is None or c.states - {"NEW"}):
                packets = True
            states = c.states
            if states is not None and all(states <= decided[f] for f in c.families):
                continue
            plain = dataclasses.replace(c, states=None, comment="", families=frozenset({4, 6})).trivial()
            if states is not None and "NEW" not in states and not c.unsupported and plain:
                if entry.action == "accept" and states <= {"ESTABLISHED", "RELATED", "UNTRACKED"}:
                    accepts_established = accepts_established or "ESTABLISHED" in states
                    decided.update({f: decided[f] | states for f in c.families})
                    continue
                if entry.action in ("drop", "reject", "reset") and states <= {"INVALID", "UNTRACKED"}:
                    decided.update({f: decided[f] | states for f in c.families})
                    continue
            rule = self._rule(entry)
            rule.log_start = log
            if log and any(prefixes):
                rule.source_ids["routeros.log_prefix"] = next(p for p in prefixes if p)
            if states is not None and "NEW" not in states:
                rule.unsupported.append("match on connection state " + ",".join(sorted(states)).lower() + " without new")
            if entry.rule.args.get("connection-nat-state") == "!dstnat":
                self._natstate(rule, entry, entries[index + 1 :], dnat.get(entry.rule.family, []))
            if rule.action == Action.ALLOW:
                accepts += 1
            else:
                denies += 1
            if rule.action != Action.ALLOW and not accepts_established and (states is None or states & {"ESTABLISHED", "RELATED"}):
                early_drops.append(rule.origin)
            self.p.rules.append(rule)
        if packets:
            self.report.note(
                Severity.INFO,
                "LOG_EVERY_PACKET",
                "a rule that logs comes ahead of the rule that accepts established connections (or the ruleset has "
                "none), so it logs packets of connections already open, not only the first of each",
            )
        tracking_off = any(self.fam[f].tracking == "no" for f in (4, 6))
        if tracking_off:
            self.report.note(
                Severity.REVIEW,
                "STATELESS_RULESET",
                "connection tracking is switched off (/ip firewall connection tracking enabled=no): the source filters "
                "every packet on its own, and its NAT does not work. The converted rules are connection-based: an allow "
                "rule also admits the replies, and a deny rule no longer stops the replies of connections opened from "
                "the other side",
            )
        elif not accepts_established and accepts and denies:
            self.report.note(
                Severity.REVIEW,
                "STATELESS_RULESET",
                "no forward rule accepts established and related packets, so the rules that block also block replies. "
                "The converted rules are connection-based: an allow rule also admits the replies, and a deny rule no "
                "longer stops the replies of connections opened from the other side",
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

    def _unique(self, name: str, taken: Set[str]) -> str:
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    def _rule(self, entry: _Entry) -> Rule:
        r = entry.rule
        c = entry.cond
        rule = Rule(name=self._unique(r.comment or entry.where, self.names))
        rule.origin = rule.name
        menu = f"/{'ip' if r.family == 4 else 'ipv6'} firewall filter"
        rule.description = "" if r.comment == rule.name else f"RouterOS {menu} rule {entry.where}"
        rule.source_ids["routeros.rule"] = f"{menu} {entry.where}"
        tags = [text for text in c.unsupported if text.startswith("\x00")]
        c = dataclasses.replace(c, unsupported=tuple(text for text in c.unsupported if not text.startswith("\x00")))
        rule.src_zones = sorted(c.iif) if c.iif else [ANY]
        rule.dst_zones = sorted(c.oif) if c.oif else [ANY]
        rule.unsupported = list(c.unsupported)
        rule.log_end = False
        self.helper.addresses(rule, c)
        services, negated = self.helper.services(c, rule.unsupported)
        rule.services, rule.negate_service = services, negated
        negated_sides = self._tags(rule, c, tags)
        actions = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.DENY, "reset": Action.RESET_CLIENT}
        if entry.action in actions:
            rule.action = actions[entry.action]
        else:
            rule.action = Action.DROP  # what the source did is not known: nothing is allowed on a guess
            if not any("jump" in text for text in rule.unsupported):
                rule.unsupported.append(f"action={entry.why or r.action}, which the model has no place for")
        if r.action == "tarpit":
            self.report.add("rule", rule.origin, Severity.APPROX, "ROUTEROS_TARPIT",
                            "action=tarpit holds TCP connections open (the client sees an open port); converted as a drop")  # fmt: skip
        if r.action == "reject" and r.args.get("reject-with") == "tcp-reset" and entry.action != "reset":
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            "reject-with=tcp-reset on a rule that matches more than TCP: converted as a plain reject")  # fmt: skip
        for side in negated_sides:
            self._negated_interface("rule", rule.origin, side, c, Severity.APPROX if rule.action == Action.ALLOW else Severity.REVIEW,
                                    "allows" if rule.action == Action.ALLOW else "blocks")  # fmt: skip
        return rule

    def _negated_interface(self, kind: str, origin: str, side: str, c: _Cond, severity: Severity, does: str) -> None:
        found = c.iif if side == "in" else c.oif
        known = ", ".join(sorted(found or ())) or "none"
        self.report.add(
            kind, origin, severity, "ROUTEROS_NEGATED_INTERFACE",
            f"negated {side}put interface (on the rule or the jump to its chain): the export does not list every "
            f"interface of the router, and the {kind} covers the zones it does show ({known}). On the source it also "
            f"{does} traffic of interfaces the export leaves out",
        )  # fmt: skip

    def _tags(self, rule: Rule, c: _Cond, tags: List[str]) -> List[str]:
        """Put back what the conditions carried as tags: a schedule, an address list of host names. Returns the sides
        (in, out) with a negated interface match."""
        family_any = ANY_V4 if 4 in c.families else ANY_V6
        negated_sides: List[str] = []
        for tag in tags:
            kind, _, value = tag[1:].partition(":")
            if kind == "schedule":
                rule.schedule = value
                continue
            if kind == "negif":
                if value not in negated_sides:
                    negated_sides.append(value)
                continue
            side, _, group = value.partition(":")
            negated, group = _neg(group)
            if (c.src if side == "src" else c.dst) is not None:
                rule.unsupported.append(f"address list '{group}' (host names) together with another "
                                        f"{'source' if side == 'src' else 'destination'} address match")  # fmt: skip
                continue
            if side == "src":
                rule.sources, rule.negate_source = [group], negated
                if rule.destinations == [ANY]:
                    rule.destinations = [family_any]
            else:
                rule.destinations, rule.negate_destination = [group], negated
                if rule.sources == [ANY]:
                    rule.sources = [family_any]
            if rule.negate_source and rule.negate_destination:
                rule.unsupported.append("source and destination both negated")
        return negated_sides

    def _natstate(self, rule: Rule, entry: _Entry, later: List[_Entry], dnat: List[_Entry]) -> None:
        """``connection-nat-state=!dstnat``: the rule does not apply to connections a destination NAT rule translated.

        Exact when the rule matches on interfaces and states only, every destination NAT rule could be read, and no
        rule below it blocks what they translate: then those connections are let through by allow rules ahead of it.
        """
        c = entry.cond
        why = ""
        if rule.action == Action.ALLOW:
            why = "connection-nat-state=!dstnat on an allow rule"
        elif any(getattr(c, name) is not None for name in ("src", "dst", "proto", "dport", "sport", "icmp", "codes")):
            why = "connection-nat-state=!dstnat together with an address or service match"
        elif c.unsupported:
            return
        translating = [d for d in dnat if not d.disabled and d.action != "log"]
        if not why:
            for d in translating:
                if d.action != "nat" or d.rule.action not in ("dst-nat", "netmap") or d.cond.unsupported:
                    why = ("connection-nat-state=!dstnat, and a destination NAT rule cannot be read "
                           f"({d.where}: action={d.rule.action})")  # fmt: skip
                    break
        allows: List[Rule] = []
        if not why:
            base = dataclasses.replace(c, states=None)
            for d in translating:
                pre = _meet(base, d.cond)
                if pre is None:
                    continue
                post = self._post_dnat(d)
                if post is None:
                    why = f"connection-nat-state=!dstnat, and what destination NAT rule {d.where} translates to cannot be read"
                    break
                post = _meet(base, post)
                for other in later:
                    if other.disabled or other.action in ("log", "accept") or other.rule.args.get("connection-nat-state") == "!dstnat":
                        continue
                    if other.cond.states is not None and "NEW" not in other.cond.states:
                        continue
                    if post is not None and _meet(dataclasses.replace(other.cond, states=None), post) is not None:
                        why = (f"connection-nat-state=!dstnat, and rule {other.where} below it blocks part of what "
                               f"destination NAT rule {d.where} translates")  # fmt: skip
                        break
                if why:
                    break
                allow = Rule(name=self._unique(f"{rule.name} (allows {d.rule.comment or d.where})", self.names))
                allow.origin = allow.name
                allow.description = (f"what RouterOS rule {entry.where} does not block: connections that destination "
                                     f"NAT rule {d.where} translates")  # fmt: skip
                allow.source_ids["routeros.rule"] = rule.source_ids.get("routeros.rule", "")
                allow.src_zones = sorted(pre.iif) if pre.iif else [ANY]
                allow.dst_zones = sorted(pre.oif) if pre.oif else [ANY]
                allow.log_end = False
                self.helper.addresses(allow, pre)
                allow.services, allow.negate_service = self.helper.services(pre, allow.unsupported)
                allow.action = Action.ALLOW
                allows.append(allow)
        if why:
            rule.unsupported.append(why)
            return
        if allows:
            self.pending.append((len(self.p.rules), allows))
        self.report.add(
            "rule", rule.origin, Severity.INFO, "ROUTEROS_DSTNAT_EXCEPTION",
            "connection-nat-state=!dstnat: the rule does not block connections a destination NAT rule translated. "
            + (f"Those are allowed by {len(allows)} rule{'s' if len(allows) != 1 else ''} ahead of it ("
               + ", ".join(a.name for a in allows) + ")" if allows else "No destination NAT rule translates traffic it matches"),
        )  # fmt: skip

    def _post_dnat(self, d: _Entry) -> Optional[_Cond]:
        """What the traffic of a destination NAT rule looks like after it, as the forward chain sees it."""
        a = d.rule.args
        to = a.get("to-addresses", a.get("to-address", ""))
        port = a.get("to-ports", "")
        c: Optional[_Cond] = d.cond
        assert c is not None
        if to:
            c = constrain(dataclasses.replace(c, dst=None, dst_show=None), f"{'ip' if d.rule.family == 4 else 'ip6'} daddr",
                          "==", [to])  # fmt: skip
            if c is None:
                return None
        if port:
            heads = {6: "tcp", 17: "udp", 132: "sctp"}
            if c.proto is None or len(c.proto) != 1 or next(iter(c.proto)) not in heads:
                return None
            c = constrain(dataclasses.replace(c, dport=None), f"{heads[next(iter(c.proto))]} dport", "==", [port])
        return c

    # -- NAT ----------------------------------------------------------------------------

    def _nat_rule(self, entry: _Entry, chain: str) -> Optional[NatRule]:
        if entry.action == "log":
            return None
        r = entry.rule
        c = entry.cond
        nat = NatRule(name=self._unique(r.comment or entry.where, self.nat_names))
        nat.origin = nat.name
        nat.combines = True  # one dstnat rule and one srcnat rule apply to a connection
        nat.enabled = not entry.disabled
        menu = f"/{'ip' if r.family == 4 else 'ipv6'} firewall nat"
        nat.description = "" if r.comment == nat.name else f"RouterOS {menu} rule {entry.where}"
        tags = [text[1:] for text in c.unsupported if text.startswith("\x00")]
        nat.unsupported = [text for text in c.unsupported if not text.startswith("\x00")]
        for tag in tags:
            if tag.startswith("negif:"):
                self._negated_interface("nat", nat.origin, tag.split(":", 1)[1], c, Severity.APPROX, "translates")
            elif tag.startswith("schedule:"):
                nat.unsupported.append(f"{tag.split(':', 1)[1]} in a NAT rule")
            else:
                nat.unsupported.append("address list of host names in a NAT rule")
        if c.src_show and c.src_show[1] or c.dst_show and c.dst_show[1]:
            nat.unsupported.append("negated address in a NAT rule")
        nat.sources = self.helper.side(c.src, None)[0] if c.src is not None else [ANY]
        nat.destinations = self.helper.side(c.dst, None)[0] if c.dst is not None else [ANY]
        if c.src is not None and c.src_show is not None and not c.src_show[1]:
            nat.sources = list(c.src_show[0])
        if c.dst is not None and c.dst_show is not None and not c.dst_show[1]:
            nat.destinations = list(c.dst_show[0])
        services, negated = self.helper.services(c, nat.unsupported)
        if len(services) != 1 or negated:
            nat.unsupported.append("NAT limited to protocols the model cannot say")
        nat.service = services[0] if services else ANY
        if nat.service != ANY and any(e.protocol.value not in ("tcp", "udp", "sctp") for e in self.p.services[nat.service].entries):
            nat.unsupported.append("NAT limited to a protocol other than TCP, UDP or SCTP")
        if r.family == 6:
            nat.unsupported.append("IPv6 NAT")
        action = r.action
        to = r.args.get("to-addresses", r.args.get("to-address", ""))
        port = r.args.get("to-ports", "")
        if chain == "dstnat":
            nat.src_zones = nat.dst_zones = sorted(c.iif) if c.iif else [ANY]
            if c.oif:
                nat.unsupported.append("out-interface in chain dstnat")
            if entry.action == "accept":
                nat.unsupported.append(
                    "exception from destination NAT only (an accept in chain dstnat); the destination NAT rules below "
                    "it are converted without this exception"
                )
            elif entry.action != "nat":
                nat.unsupported.append(f"action={action} in chain dstnat")
            elif action == "dst-nat":
                address = to
                if not address:
                    single = c.dst is not None and len(c.dst) == 1 and size(c.dst[0]) == 1
                    address = interval_text(c.dst[0]) if single and c.dst is not None else ""
                interval = parse_literal(address) if address else None
                if interval is None or interval[0] != r.family or (port and not _ports_ok(port)):
                    nat.unsupported.append("dst-nat whose translation cannot be read")
                else:
                    nat.destination_translation = DestNat(range_text(interval), port, spread=size(interval) > 1)
            elif action == "netmap":
                interval = parse_literal(to) if to else None
                same = c.dst is not None and len(c.dst) == 1 and interval is not None and size(c.dst[0]) == size(interval)
                if interval is None or not same or (port and not _ports_ok(port)):
                    nat.unsupported.append("netmap whose addresses do not map one for one")
                else:
                    assert interval is not None
                    nat.destination_translation = DestNat(interval_text(interval), port)
            elif action == "redirect":
                nat.unsupported.append("action=redirect (to the router itself)")
            else:
                nat.unsupported.append(f"action={action} in chain dstnat")
        else:
            nat.dst_zones = sorted(c.oif) if c.oif else [ANY]
            if c.iif:
                nat.unsupported.append("in-interface in chain srcnat")
            if entry.action == "accept":
                pass  # no translation: an exception
            elif entry.action != "nat":
                nat.unsupported.append(f"action={action} in chain srcnat")
            elif action == "masquerade":
                interfaces = [i for zone in (c.oif or ()) for i in self.zone_ifs.get(zone, [])]
                nat.source_translation = SourceNat(SnatKind.INTERFACE, interface=interfaces[0] if len(interfaces) == 1 else "")
            elif action in ("src-nat", "same"):
                interval = parse_literal(to) if to else None
                if interval is None or interval[0] != r.family:
                    nat.unsupported.append(f"{action} whose translation cannot be read")
                else:
                    kind = SnatKind.DYNAMIC_PORT if action == "src-nat" else SnatKind.DYNAMIC
                    nat.source_translation = SourceNat(kind, [range_text(interval)])
                    if action == "same":
                        self.report.add("nat", nat.origin, Severity.APPROX, "ROUTEROS_NAT_PORTS",
                                        "action=same keeps one translated address per client; converted as dynamic source NAT")  # fmt: skip
            elif action == "netmap":
                interval = parse_literal(to) if to else None
                same = c.src is not None and len(c.src) == 1 and interval is not None and size(c.src[0]) == size(interval)
                if interval is None or not same:
                    nat.unsupported.append("netmap whose addresses do not map one for one")
                else:
                    assert interval is not None
                    nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(interval)])
            else:
                nat.unsupported.append(f"action={action} in chain srcnat")
            if port and nat.source_translation is not None:
                self.report.add("nat", nat.origin, Severity.APPROX, "ROUTEROS_NAT_PORTS",
                                f"to-ports={port}: the source ports the translation picks from are not converted")  # fmt: skip
            if r.args.get("ipsec-policy") == "out,none":
                self.report.add(
                    "nat", nat.origin, Severity.APPROX, "ROUTEROS_NAT_IPSEC_EXEMPT",
                    "ipsec-policy=out,none: on the source, traffic that goes into an IPsec tunnel is not translated; "
                    "the converted rule translates it unless the target exempts it",
                )  # fmt: skip
        if r.args.get("dst-address-type") == "local" and r.family == 4:
            dynamic = sorted(self.dynamic_ifs)
            if dynamic:
                self.report.add(
                    "nat", nat.origin, Severity.REVIEW, "ROUTEROS_LOCAL_ADDRESS",
                    "dst-address-type=local stands for every address of the router; the addresses of "
                    + ", ".join(dynamic) + " come from DHCP or PPP and are not in the export, so the rule was converted "
                    "for the static addresses only",
                )  # fmt: skip
        return nat

    # -- notes ----------------------------------------------------------------------

    def _notes(self) -> None:
        for family in (4, 6):
            f = self.fam[family]
            what = "/ip" if family == 4 else "/ipv6"
            for chain in ("input", "output"):
                count = len(f.filter.get(chain, []))
                if count:
                    self.report.note(
                        Severity.REVIEW,
                        "HOST_CHAIN_NOT_CONVERTED",
                        f"chain {chain} of {what} firewall filter ({count} rules) filters traffic of the router itself, "
                        "not forwarded traffic, and is not converted",
                    )
            for name, count in (("raw", f.raw), ("mangle", f.mangle)):
                if count:
                    self.report.note(
                        Severity.REVIEW,
                        "TABLE_NOT_CONVERTED",
                        f"{what} firewall {name} has {count} rules and is not converted"
                        + (" (a raw drop comes before the filter rules)" if name == "raw" else
                           " (it can mark connections and routes, which the filter rules may test)"),
                    )  # fmt: skip
            unused = [chain for chain in f.filter if chain not in _BUILTIN_FILTER and not self._reached(f.filter, chain)]
            if unused:
                self.report.note(
                    Severity.INFO,
                    "ROUTEROS_UNUSED_CHAIN",
                    f"chains of {what} firewall filter that no jump from forward reaches: " + ", ".join(unused),
                )
        if self.scripting:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_SCRIPT_LINES",
                f"{self.scripting} line{'s' if self.scripting != 1 else ''} of RouterOS scripting (starting with ':') "
                "were not read: rules they add are not in the conversion. An export holds none",
            )
        if self.passive:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_PASSIVE",
                f"{self.passive} rule{'s' if self.passive != 1 else ''} with action log, passthrough or add-*-to-address-list "
                "decide nothing and were left out. A log rule directly before a rule with the same match, or one that "
                "matches everything, sets the logging of the rules it logs for",
            )
        if self.disabled_flow:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_DISABLED_JUMP",
                f"{self.disabled_flow} disabled rule{'s' if self.disabled_flow != 1 else ''} that would jump, return or "
                "log were left out",
            )
        if self.fasttrack_other:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_FASTTRACK",
                "fasttrack-connection for more than established and related connections ("
                + ", ".join(self.fasttrack_other[:8]) + "): the rules below no longer see the later packets of those "
                "connections. Left out",
            )
        if self.dynamic_used:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_DYNAMIC_LIST",
                "address lists that rules fill while the router runs decide what their rules match; those rules are not "
                "converted: " + ", ".join(sorted(self.dynamic_used)),
            )
        if self.empty_used:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_EMPTY_LIST",
                "address lists with no entry in the export: a rule that names one matches nothing here. Entries the "
                "router adds while it runs are not in the export: " + ", ".join(sorted(self.empty_used)),
            )
        if self.fqdn_groups:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_FQDN_LIST",
                "address lists that hold host names, which RouterOS resolves while it runs: converted as host name "
                "objects (" + ", ".join(sorted(self.fqdn_groups)) + ")",
            )
        if self.timeouts:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_LIST_TIMEOUT",
                f"{self.timeouts} address list entr{'ies' if self.timeouts != 1 else 'y'} with a timeout: the router "
                "removes them when it runs out (or at a restart); they were converted as permanent",
            )
        if self.bridges and not self.use_ip_firewall:
            self.report.note(
                Severity.INFO,
                "ROUTEROS_BRIDGE",
                "traffic between the ports of one bridge (" + ", ".join(sorted(self.bridges)) + ") does not pass the "
                "IP firewall of the source (use-ip-firewall=no); the conversion is of routed traffic",
            )
        if self.upnp:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_UPNP",
                "UPnP is on: the router adds destination NAT rules for clients that ask for them while it runs, and "
                "they are not in the export",
            )
        if self.ip_forward_off:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_IP_FORWARD",
                "/ip settings ip-forward=no: the source forwards no IPv4 traffic at all, whatever the rules say",
            )
        if self.l3hw:
            self.report.note(
                Severity.REVIEW,
                "ROUTEROS_L3HW",
                "L3 hardware offloading is on for some switch ports: traffic routed between offloaded ports bypasses the "
                "firewall of the source",
            )
        if not any(self.fam[6].filter.get("forward", [])):
            self.report.note(
                Severity.INFO,
                "ROUTEROS_NO_IPV6_RULES",
                "the forward chain of /ipv6 firewall filter has no rules: the source forwards IPv6 unfiltered (where "
                "IPv6 is on), and the converted policy allows it as well",
            )
        self.report.note(
            Severity.INFO,
            "FORWARD_POLICY_ACCEPT",
            "RouterOS accepts what no rule of the forward chain decides; the model records that as its default action",
        )

    @staticmethod
    def _reached(chains: Dict[str, List[_RRule]], chain: str) -> bool:
        seen: Set[str] = set()
        todo = ["forward"]
        while todo:
            current = todo.pop()
            if current == chain:
                return True
            if current in seen:
                continue
            seen.add(current)
            todo += [r.args.get("jump-target", "") for r in chains.get(current, []) if r.action == "jump" and not r.disabled]
        return False


def _split_without(context: _Cond, taken: _Cond) -> Optional[List[_Cond]]:
    """What is left of ``context`` once the packets of ``taken`` (a part of it) are gone, as conditions that do not
    overlap: one per part in which the two differ. None when that cannot be said (an interface, an unread match)."""
    if taken.unsupported != context.unsupported:
        return None
    differ = [name for name in _nft._FIELDS if getattr(context, name) != getattr(taken, name)]
    if "families" in differ:
        return None
    out: List[_Cond] = []
    base = context
    for name in differ:
        changes = {name: getattr(taken, name)}
        if name in ("src", "dst"):
            changes[name + "_show"] = getattr(taken, name + "_show")
        step = dataclasses.replace(base, **changes)
        piece = _without(base, step)
        if piece is False:
            return None
        if piece is not None:
            out.append(piece)
        base = step
    return out


def _ports_ok(port: str) -> bool:
    first, _, last = port.partition("-")
    return first.isdigit() and (not last or last.isdigit()) and int(first) <= int(last or first) <= 65535
