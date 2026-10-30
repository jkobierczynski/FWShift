# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Windows Defender Firewall both ways.

``RegJudge`` decides connections as Windows does, from the rule strings and profile settings of the stores: the merge
of Group Policy and local settings, ``AllowLocalPolicyMerge``, the id that Group Policy wins, the firewall off,
shielded profiles, then any block rule that matches, then any allow rule, then the default of the profile; a rule
matches when every field it has holds. ``ScriptJudge`` reads the emitted PowerShell strictly (only what
``New-NetFirewallRule`` takes, each name once) and decides the same way. Neither shares code with the parser or the
emitter; both are written from the same reading of Microsoft's documentation as the code they check, so they find
where the code disagrees with that reading, not where the reading is wrong.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_gcp import model_decides, with_random_defaults
from test_iptables import PORTS, Packet, model_verdict, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.emitters import winfw as emit_winfw
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, Address, AddressKind, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import winfw as parse_winfw
from fwshift.report import Report, Severity

LOCAL = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
GPO = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall"
PROFILES = ("Domain", "Private", "Public")
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
# What the keywords stand for on the made-up host of the tests.
KEYWORDS = {"LocalSubnet": ["10.0.1.0/24", "2001:db8:1::/64"], "DNS": ["10.0.0.17", "2001:db8::53"],
            "DefaultGateway": ["10.0.1.1"], "Internet": ["10.0.4.0/22", "2001:db8:3::/48"]}  # fmt: skip


# -- the judges -------------------------------------------------------------------------------------------------------


@dataclass
class Conn:
    """A connection as the host sees it."""

    profile: str
    inbound: bool
    remote: str
    local: str
    proto: str  # tcp, udp, icmp, icmp6, or a number
    remote_port: int = 0
    local_port: int = 0
    icmp_type: int = 0
    icmp_code: int = 0

    def number(self) -> int:
        return PROTO.get(self.proto) or int(self.proto)

    def packet(self) -> Packet:
        """The same connection as a packet of the model (zones Host and the profile)."""
        if self.inbound:
            return Packet(self.profile, "Host", self.remote, self.local, self.proto, self.remote_port, self.local_port, self.icmp_type)
        return Packet("Host", self.profile, self.local, self.remote, self.proto, self.local_port, self.remote_port, self.icmp_type)


def _address_in(text: str, address: str, keywords: Dict[str, List[str]]) -> bool:
    probe = ipaddress.ip_address(address)
    word = text.rstrip("46")
    if word in keywords or word in ("LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway", "Intranet", "Internet"):
        family = text[len(word):]
        if family and int(family) != probe.version:
            return False
        return any(probe in ipaddress.ip_network(n) for n in keywords.get(word, []))
    if "-" in text:
        first, last = (ipaddress.ip_address(t) for t in text.split("-"))
        return first.version == probe.version and int(first) <= int(probe) <= int(last)
    if "/" in text and "." in text.split("/")[1]:
        network = ipaddress.ip_network(text, strict=False)  # (a mask written as an address)
    else:
        network = ipaddress.ip_network(text, strict=False)
    return network.version == probe.version and probe in network


def _port_in(text: str, port: int) -> bool:
    first, _, last = text.partition("-")
    return int(first) <= port <= int(last or first)


class RegJudge:
    """Windows deciding a connection from the stores of the registry: rule strings and profile settings."""

    def __init__(self, stores: Dict[str, List[Tuple[str, str]]], settings: Dict[str, Dict[str, Dict[str, int]]],
                 keywords: Optional[Dict[str, List[str]]] = None) -> None:  # fmt: skip
        self.keywords = keywords or {}
        self.settings = settings
        gpo_ids = {ident.lower() for ident, _ in stores.get("gpo", [])}
        self.rules: List[Tuple[str, Dict[str, List[str]]]] = []
        for store in ("gpo", "local"):
            for ident, text in stores.get(store, []):
                if store == "local" and ident.lower() in gpo_ids:
                    continue  # (Group Policy's rule of the same id replaces it)
                fields: Dict[str, List[str]] = {}
                for part in text.split("|")[1:]:
                    if part:
                        key, _, value = part.partition("=")
                        fields.setdefault(key, []).append(value)
                self.rules.append((store, fields))

    def setting(self, profile: str, name: str, default: int) -> int:
        for store in ("gpo", "local"):
            key = profile if store == "gpo" or profile != "Private" else "Standard"
            value = self.settings.get(store, {}).get(key, {}).get(name)
            if value is not None:
                return value
        return default

    def _matches(self, f: Dict[str, List[str]], c: Conn) -> bool:
        if f.get("Active", ["FALSE"])[0] != "TRUE":
            return False
        if f["Dir"][0] != ("In" if c.inbound else "Out"):
            return False
        if "Profile" in f and c.profile not in f["Profile"]:
            return False
        if "Protocol" in f and int(f["Protocol"][0]) != c.number():
            return False
        local_ports = f.get("LPort", []) + f.get("LPort2_10", [])
        remote_ports = f.get("RPort", []) + f.get("RPort2_10", [])
        if local_ports and not any(_port_in(p, c.local_port) for p in local_ports):
            return False
        if remote_ports and not any(_port_in(p, c.remote_port) for p in remote_ports):
            return False
        icmp = f.get("ICMP4", []) + f.get("ICMP6", [])
        if icmp:
            if not any(t == str(c.icmp_type) and (code == "*" or code == str(c.icmp_code)) for t, code in (e.split(":") for e in icmp)):
                return False
        for keys, address in ((("LA4", "LA6"), c.local), (("RA4", "RA6", "RA42", "RA62"), c.remote)):
            entries = [(k, v) for k in keys for v in f.get(k, [])]
            if not entries:
                continue
            version = ipaddress.ip_address(address).version
            mine = [v for k, v in entries if k[2] == str(version)]
            if not any(_address_in(v if v[0].isdigit() or ":" in v else v + str(version), address, self.keywords) for v in mine):
                return False
        return True

    def allows(self, c: Conn) -> bool:
        if not self.setting(c.profile, "EnableFirewall", 1):
            return True
        if c.inbound and any(self.settings.get(s, {}).get(c.profile if s == "gpo" or c.profile != "Private" else "Standard", {})
                             .get("DoNotAllowExceptions") for s in ("gpo", "local")):  # fmt: skip
            return False
        merge = self.settings.get("gpo", {}).get(c.profile, {}).get("AllowLocalPolicyMerge", 1)
        matching = [f for store, f in self.rules if (store == "gpo" or merge) and self._matches(f, c)]
        if any(f["Action"][0] == "Block" for f in matching):
            return False
        if any(f["Action"][0] == "Allow" for f in matching):
            return True
        name = "DefaultInboundAction" if c.inbound else "DefaultOutboundAction"
        return not self.setting(c.profile, name, 1 if c.inbound else 0)


_FIELD = re.compile(r"([A-Za-z]+) = ")


def _ps_value(text: str, index: int) -> Tuple[Any, int]:
    if text.startswith("@(", index):
        index += 2
        values: List[str] = []
        while text[index] != ")":
            value, index = _ps_value(text, index)
            values.append(value)
            if text.startswith(", ", index):
                index += 2
        return values, index + 1
    assert text[index] == "'", text[index:index + 30]
    out: List[str] = []
    index += 1
    while True:
        char = text[index]
        if char in "'\u2018\u2019\u201a\u201b":
            if index + 1 < len(text) and text[index + 1] in "'\u2018\u2019\u201a\u201b":
                out.append(char)
                index += 2
                continue
            return "".join(out), index + 1
        out.append(char)
        index += 1


class ScriptJudge:
    """The emitted script read strictly, and Windows deciding a connection by the rules it creates."""

    KEYS = {"Name", "DisplayName", "Description", "Direction", "Action", "Enabled", "Profile", "Protocol", "LocalPort", "RemotePort",
            "IcmpType", "LocalAddress", "RemoteAddress"}  # fmt: skip

    def __init__(self, text: str, keywords: Optional[Dict[str, List[str]]] = None, inbound_block: bool = True,
                 outbound_block: bool = True) -> None:  # fmt: skip
        self.keywords = keywords or {}
        self.defaults = (inbound_block, outbound_block)
        self.rules: List[Dict[str, Any]] = []
        names = set()
        for line in text.splitlines():
            code = re.sub(r"'(?:[^']|'')*'", "''", line)
            if line.lstrip().startswith("#"):
                continue
            assert "Remove-NetFirewallRule" not in code and "Set-NetFirewallProfile" not in code and "netsh" not in code, line
            if not line.startswith("Add-Rule"):
                continue
            assert line.startswith("Add-Rule @{ ") and line.endswith(" }"), line
            body, index, rule = line[len("Add-Rule @{ "):-2], 0, {}
            while index < len(body):
                match = _FIELD.match(body, index)
                assert match, body[index:index + 40]
                key = match.group(1)
                assert key in self.KEYS and key not in rule, key
                rule[key], index = _ps_value(body, match.end())
                if index < len(body):
                    assert body.startswith("; ", index), body[index:index + 20]
                    index += 2
            assert {"Name", "DisplayName", "Direction", "Action", "Enabled", "Profile"} <= set(rule), rule
            assert rule["Name"].lower() not in names and re.fullmatch(r"[A-Za-z0-9._-]{1,200}", rule["Name"]), rule["Name"]
            names.add(rule["Name"].lower())
            assert rule["DisplayName"] and rule["DisplayName"].lower() != "all"
            assert rule["Direction"] in ("Inbound", "Outbound") and rule["Action"] in ("Allow", "Block")
            assert rule["Enabled"] in ("True", "False")
            assert rule["Profile"] == "Any" or set(rule["Profile"].split(",")) <= set(PROFILES), rule["Profile"]
            proto = rule.get("Protocol", "")
            assert proto in ("", "TCP", "UDP", "ICMPv4", "ICMPv6") or (proto.isdigit() and int(proto) <= 255), proto
            if "LocalPort" in rule or "RemotePort" in rule:
                assert proto in ("TCP", "UDP"), rule  # (ports with TCP or UDP only)
                for port in rule.get("LocalPort", []) + rule.get("RemotePort", []):
                    assert re.fullmatch(r"\d{1,5}(-\d{1,5})?", port), port
            if "IcmpType" in rule:
                assert proto in ("ICMPv4", "ICMPv6"), rule
            for side in ("LocalAddress", "RemoteAddress"):
                for entry in rule.get(side, []):
                    if entry.rstrip("46") in ("LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway", "Intranet", "Internet",
                                              "IntranetRemoteAccess", "PlayToDevice", "CaptivePortal"):  # fmt: skip
                        assert side == "RemoteAddress", rule  # (keywords are remote addresses only)
                    else:
                        _address_in(entry, "10.0.0.1", {})  # (it can be read)
            self.rules.append(rule)

    def _matches(self, rule: Dict[str, Any], c: Conn) -> bool:
        if rule["Enabled"] != "True" or rule["Direction"] != ("Inbound" if c.inbound else "Outbound"):
            return False
        if rule["Profile"] != "Any" and c.profile not in rule["Profile"].split(","):
            return False
        proto = rule.get("Protocol", "")
        if proto:
            number = {"TCP": 6, "UDP": 17, "ICMPv4": 1, "ICMPv6": 58}.get(proto) or int(proto)
            if number != c.number():
                return False
        if "LocalPort" in rule and not any(_port_in(p, c.local_port) for p in rule["LocalPort"]):
            return False
        if "RemotePort" in rule and not any(_port_in(p, c.remote_port) for p in rule["RemotePort"]):
            return False
        if "IcmpType" in rule:
            def one(entry: str) -> bool:
                kind, _, code = entry.partition(":")
                return int(kind) == c.icmp_type and (not code or int(code) == c.icmp_code)
            if not any(one(e) for e in rule["IcmpType"]):
                return False
        for side, address in (("LocalAddress", c.local), ("RemoteAddress", c.remote)):
            if side in rule and not any(_address_in(e, address, self.keywords) for e in rule[side]):
                return False
        return True

    def allows(self, c: Conn) -> bool:
        matching = [r for r in self.rules if self._matches(r, c)]
        if any(r["Action"] == "Block" for r in matching):
            return False
        if any(r["Action"] == "Allow" for r in matching):
            return True
        return not self.defaults[0 if c.inbound else 1]


# -- making registry exports ------------------------------------------------------------------------------------------


def reg_bytes(stores: Dict[str, List[Tuple[str, str]]], settings: Dict[str, Dict[str, Dict[str, int]]], joined: bool = True) -> bytes:
    """The stores as reg export writes them: UTF-16 with a byte order mark, one export per store, joined as copy /b does."""

    def quoted(text: str) -> str:
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def export(base: str, store: str) -> bytes:
        lines = ["Windows Registry Editor Version 5.00", "", f"[{base}]", ""]
        for profile, values in settings.get(store, {}).items():
            lines.append(f"[{base}\\{profile}Profile]")
            lines += [f"{quoted(name)}=dword:{value:08x}" for name, value in values.items()] + [""]
        lines.append(f"[{base}\\FirewallRules]")
        lines += [f"{quoted(ident)}={quoted(text)}" for ident, text in stores.get(store, [])] + [""]
        return ("\ufeff" + "\r\n".join(lines) + "\r\n").encode("utf-16-le")

    parts = [export(LOCAL, "local")] if "local" in stores or "local" in settings else []
    if "gpo" in stores or "gpo" in settings:
        parts.append(export(GPO, "gpo"))
    return b"".join(parts)


def parse_stores(stores: Dict[str, List[Tuple[str, str]]], settings: Optional[Dict[str, Dict[str, Dict[str, int]]]] = None,
                 report: Optional[Report] = None) -> Policy:  # fmt: skip
    return parse_winfw.parse(reg_bytes(stores, settings or {}), report or Report())


LITERALS4 = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/255.255.255.128", "10.0.2.0/23", "10.0.0.17", "10.0.2.100-10.0.3.50", "10.0.4.0/22"]
LITERALS6 = ["2001:db8:1::/48", "2001:db8::/47", "2001:db8:2::1-2001:db8:2::3", "2001:db8:3::2"]


def random_rule_text(rng: random.Random, keywords: bool = False) -> str:
    fields = ["v2.30", f"Action={'Allow' if rng.random() < 0.6 else 'Block'}", f"Active={'TRUE' if rng.random() < 0.9 else 'FALSE'}",
              f"Dir={rng.choice(['In', 'Out'])}"]  # fmt: skip
    if rng.random() < 0.5:
        fields += [f"Profile={p}" for p in rng.sample(PROFILES, rng.randint(1, 2))]
    proto = rng.choice([None, None, 6, 6, 17, 1, 58, 47])
    if proto is not None:
        fields.append(f"Protocol={proto}")
    if proto in (6, 17):
        if rng.random() < 0.6:
            fields += [f"LPort={p}" for p in rng.sample(PORTS, rng.randint(1, 2))]
        if rng.random() < 0.2:
            fields.append("LPort2_10=8000-8010")
        if rng.random() < 0.25:
            fields.append(rng.choice(["RPort2_10=1024-65535", "RPort=40000", "RPort2_10=1-1023"]))
    if proto == 1 and rng.random() < 0.6:
        fields += [f"ICMP4={t}:*" for t in rng.sample([0, 3, 8, 13], rng.randint(1, 2))]
    if proto == 58 and rng.random() < 0.6:
        fields.append("ICMP6=128:*")
    for key, pool in (("RA4", LITERALS4), ("RA6", LITERALS6), ("LA4", LITERALS4), ("LA6", LITERALS6)):
        if rng.random() < 0.3:
            fields += [f"{key}={v}" for v in rng.sample(pool, rng.randint(1, 2))]
    if keywords and rng.random() < 0.2:
        word = rng.choice(["LocalSubnet", "DNS", "Internet"])
        fields += [f"RA4={word}"] + ([f"RA6={word}"] if rng.random() < 0.5 else [])
    fields.append("Name=r")
    return "|".join(fields) + "|"


def random_settings(rng: random.Random) -> Dict[str, Dict[str, Dict[str, int]]]:
    out: Dict[str, Dict[str, Dict[str, int]]] = {"local": {}, "gpo": {}}
    for store in ("local", "gpo"):
        for profile in PROFILES:
            key = "Standard" if store == "local" and profile == "Private" else profile
            values: Dict[str, int] = {}
            if rng.random() < 0.15:
                values["EnableFirewall"] = rng.choice([0, 1])
            if rng.random() < 0.3:
                values["DefaultInboundAction"] = rng.choice([0, 1, 1])
            if rng.random() < 0.3:
                values["DefaultOutboundAction"] = rng.choice([0, 1])
            if rng.random() < 0.08:
                values["DoNotAllowExceptions"] = 1
            if store == "gpo" and rng.random() < 0.2:
                values["AllowLocalPolicyMerge"] = rng.choice([0, 1])
            if values:
                out[store][key] = values
    return out


def random_export(rng: random.Random, keywords: bool = False) -> Tuple[Dict[str, List[Tuple[str, str]]], Dict[str, Dict[str, Dict[str, int]]]]:
    stores: Dict[str, List[Tuple[str, str]]] = {"local": [], "gpo": []}
    for index in range(rng.randint(3, 12)):
        store = rng.choice(["local", "gpo"])
        stores[store].append((f"rule-{index}", random_rule_text(rng, keywords)))
    if rng.random() < 0.3 and stores["gpo"]:
        ident, _ = rng.choice(stores["gpo"])
        stores["local"].append((ident, random_rule_text(rng, keywords)))  # (the same id in both: Group Policy wins)
    return stores, random_settings(rng)


def random_conn(rng: random.Random) -> Conn:
    pkt = random_packet(rng, rng.choice([4, 6]))
    remote, local = (pkt.src, pkt.dst) if rng.random() < 0.5 else (pkt.dst, pkt.src)
    return Conn(rng.choice(PROFILES), rng.random() < 0.5, remote, local, pkt.proto, rng.choice([40000, 1024, 53]), pkt.dport,
                rng.choice([0, 3, 8, 13, 128]))  # fmt: skip


def model_allows_conn(p: Policy, c: Conn) -> bool:
    verdict = model_verdict(p, c.packet())
    return p.default_interzone == Action.ALLOW if verdict is None else verdict


# -- the parser against the judge -------------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(60))
def test_parsed_policy_decides_like_windows(seed: int) -> None:
    """Random stores and profile settings: the model decides every connection as Windows does."""
    rng = random.Random(seed)
    stores, settings = random_export(rng)
    judge = RegJudge(stores, settings)
    model = parse_stores(stores, settings)
    assert not [r.name for r in model.rules if r.unsupported], seed
    for _ in range(400):
        conn = random_conn(rng)
        assert model_allows_conn(model, conn) == judge.allows(conn), (seed, conn, stores, settings)


# -- the emitter against the model ------------------------------------------------------------------------------------

NARROWER = {"WINFW_PART_NOT_WRITTEN"}


def compare_emitted(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    """At the destination (inbound) and at the source (outbound) of each packet, the host decides as the model."""
    judge = ScriptJudge(text)
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    narrower = {f.code for item in report.items.values() for f in item.findings} & NARROWER
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        wanted = model_decides(compared, pkt)
        profile = rng.choice(PROFILES)
        for inbound in (True, False):
            remote, local = (pkt.src, pkt.dst) if inbound else (pkt.dst, pkt.src)
            remote_port, local_port = (pkt.sport, pkt.dport) if inbound else (pkt.dport, pkt.sport)
            conn = Conn(profile, inbound, remote, local, pkt.proto, remote_port, local_port, pkt.icmp_type)
            verdict = judge.allows(conn)
            if narrower and not wanted:
                assert not verdict, (seed, pkt, inbound, text)
            elif not narrower:
                assert verdict == wanted, (seed, pkt, inbound, text)
        count += 1
    return count


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    """Zones as their networks, each rule for the host at either end; block rules without what the allow rules above
    them match, cleanup rules and what Windows cannot say left to the default, the allow rules below them cut."""
    rng = random.Random(seed)
    model = random_model(rng)
    report = Report()
    text = emit_winfw.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare_emitted(model, report, text, rng, seed) == 400


@pytest.mark.parametrize("seed", range(20))
def test_the_defaults_inside_and_between_zones_as_the_source_decides(seed: int) -> None:
    rng = random.Random(5000 + seed)
    model = with_random_defaults(rng, random_model(rng))
    report = Report()
    text = emit_winfw.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare_emitted(model, report, text, rng, seed, 300) == 300


@pytest.mark.parametrize("seed", range(40))
def test_roundtrip_of_random_hosts(seed: int) -> None:
    """A random host, read and written again: the script decides every connection as the host did, keywords included
    (both judges resolve them the same way). The target's defaults are Block both ways, which the report asks for
    where the policy needs it."""
    rng = random.Random(9000 + seed)
    stores, settings = random_export(rng, keywords=True)
    first = RegJudge(stores, settings, KEYWORDS)
    report = Report()
    text = cli.convert(parse_stores(stores, settings), "windows-firewall", report)
    second = ScriptJudge(text, KEYWORDS)
    assert not any(item.disabled for item in report.items.values()), seed
    for _ in range(300):
        conn = random_conn(rng)
        assert second.allows(conn) == first.allows(conn), (seed, conn, stores, settings, text)


# -- the sample -------------------------------------------------------------------------------------------------------


def test_winfw_sample_rules() -> None:
    p, report = load("winfw_sample.reg")
    assert p.vendor == "windows-firewall" and p.scope == "Group Policy, local" and not p.nat_rules
    assert list(p.zones) == ["Host", "Domain", "Private", "Public"]
    by_name = {r.name: r for r in p.rules}
    names = [r.name for r in p.rules]
    # No order on Windows: authenticated bypass first, then every block rule, then every allow rule, then the defaults.
    first_allow = names.index("Allow WinRM from management")
    assert names[0] == "Management over IPsec, overriding block rules"
    assert all(by_name[n].action == Action.DROP for n in names[1:first_allow])
    assert all(by_name[n].action == Action.ALLOW for n in names[first_allow:])
    assert names[-1] == "(default) outbound" and by_name["(default) outbound"].dst_zones == ["Domain", "Public"]
    # Group Policy first in each part, the profiles each rule applies in, and local rules left out of Domain.
    rdp = by_name["Remote Desktop from the admin networks"]
    assert (rdp.src_zones, rdp.dst_zones) == (["Private"], ["Host"])
    assert rdp.sources == ["192.0.2.0/24", "10.20.0.0/16", "2001:db8:20::/48"] and rdp.destinations == [ANY]
    web = by_name["Web server"]
    assert web.sources == [ANY] and web.destinations == ["10.10.0.5", "2001:db8:10::5"]
    assert p.services[web.services[0]].entries == [ServiceEntry(Protocol.TCP, dst_ports="80,443")]
    out = by_name["Backup agent to the backup server"]
    assert (out.src_zones, out.dst_zones, out.destinations) == (["Host"], ["Private", "Public"], ["10.30.0.20"])
    assert p.services[out.services[0]].entries == [ServiceEntry(Protocol.TCP, dst_ports="10000-10010")]
    snmp = by_name["SNMP from the local subnet"]
    assert snmp.sources == ["LocalSubnet4"] and p.address_groups["LocalSubnet4"].dynamic_filter == "windows-firewall:LocalSubnet4"
    assert p.services[snmp.services[0]].entries == [ServiceEntry(Protocol.UDP, dst_ports="161", src_ports="1024-65535")]
    icmp = by_name["Fragmentation needed and time exceeded"]
    assert p.services[icmp.services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4),
                                                    ServiceEntry(Protocol.ICMP, icmp_type=11, icmp_code=0)]  # fmt: skip
    assert p.services[by_name["Echo request (ICMPv4-In)"].services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    assert by_name["Echo request (ICMPv6-In)"].sources == ["LocalSubnet6"]
    assert by_name["GRE from the tunnel peer"].services == ["ip-47"]
    assert by_name["Block the scanner networks"].sources == ["203.0.113.0/24", "198.51.100.10-198.51.100.20"]
    # What the model cannot hold, and what Windows does not enforce.
    for name, what in (("Example application server", "program"), ("Print spooler (RPC)", "port keyword RPC"),
                       ("mDNS on wireless", "interface types"), ("Printer port", "newfield2_40"),
                       ("Management over IPsec, overriding block rules", "authenticated bypass")):  # fmt: skip
        assert any(what in u for u in by_name[name].unsupported), name
    assert not by_name["OpenSSH server"].enabled and not by_name["A rule Windows cannot parse"].enabled
    assert not by_name["DNS server (local copy)"].enabled and by_name["DNS server"].enabled
    codes = {f.code for f in report.notes}
    assert {"WINFW_HOST_POLICY", "WINFW_STORES", "WINFW_PROFILES", "WINFW_LOCAL_NOT_MERGED", "WINFW_NOT_READ",
            "WINFW_ADDRESS_KEYWORDS", "WINFW_BYPASS", "WINFW_SETTING_NOT_CONVERTED"} <= codes  # fmt: skip
    found = {f.code for item in report.items.values() for f in item.findings}
    assert {"WINFW_RULE_INVALID", "WINFW_OVERRIDDEN", "WINFW_EDGE_TRAVERSAL", "WINFW_PLATFORM", "WINFW_NOT_MODELLED"} <= found


def test_winfw_sample_decides_like_windows() -> None:
    """The sample, read by the judge from its own export (without the rules the model cannot hold, which are written
    disabled, and the one Windows cannot parse): the written script decides as Windows does, keywords resolved alike; the
    model too, where a keyword matches nothing (a dynamic group the model cannot resolve)."""
    stores, settings = _stores_of((DATA / "winfw_sample.reg").read_bytes())
    p, report = load("winfw_sample.reg")
    left_out = {r.source_ids["windows-firewall.id"] for r in p.rules
                if r.unsupported or any(f.code == "WINFW_RULE_INVALID" for f in report.item("rule", r.origin).findings)}  # fmt: skip
    stripped = {store: [(i, t) for i, t in rules if i not in left_out] for store, rules in stores.items()}
    judge, blind = RegJudge(stripped, settings, KEYWORDS), RegJudge(stripped, settings, {})
    script = ScriptJudge(cli.convert(p, "windows-firewall", Report()), KEYWORDS)
    rng = random.Random(4)
    remotes = ["192.0.2.5", "192.0.2.200", "192.0.2.66", "10.20.1.1", "10.0.1.9", "203.0.113.9", "198.51.100.15", "198.51.100.1",
               "10.30.0.20", "10.0.0.17", "2001:db8:20::1", "2001:db8:abcd::1", "2001:db8:1::5", "2001:db8:66::1", "2001:db8::53"]  # fmt: skip
    for _ in range(3000):
        remote = rng.choice(remotes)
        six = ":" in remote
        local = rng.choice(["2001:db8:10::5", "2001:db8:10::6"] if six else ["10.10.0.5", "10.10.0.6"])
        proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if six else "icmp", "47"])
        conn = Conn(rng.choice(PROFILES), rng.random() < 0.6, remote, local, proto, rng.choice([23, 80, 443, 10005, 40000, 53, 2000]),
                    rng.choice([22, 53, 80, 139, 161, 443, 445, 1900, 3389, 3544, 5985, 50050, 8443]), rng.choice([0, 3, 8, 11, 128]),
                    rng.choice([0, 0, 4]))  # fmt: skip
        assert script.allows(conn) == judge.allows(conn), conn
        if conn.icmp_type not in (3, 11) or conn.proto not in ("icmp", "icmp6"):  # (the model walk of the tests reads no ICMP codes)
            assert model_allows_conn(p, conn) == blind.allows(conn), conn


def _stores_of(data: bytes) -> Tuple[Dict[str, List[Tuple[str, str]]], Dict[str, Dict[str, Dict[str, int]]]]:
    """The judge's own reading of a registry export: keys, string values, DWORDs."""
    text = data.decode("utf-16-le").replace("\ufeff", "")
    stores: Dict[str, List[Tuple[str, str]]] = {"local": [], "gpo": []}
    settings: Dict[str, Dict[str, Dict[str, int]]] = {"local": {}, "gpo": {}}
    store, section = "", ""
    for line in text.splitlines():
        if line.startswith("["):
            path = line[1:-1]
            store = "local" if path.startswith(LOCAL + "\\") else "gpo" if path.startswith(GPO + "\\") else ""
            section = path.rsplit("\\", 1)[1] if store and path.count("\\") == (LOCAL if store == "local" else GPO).count("\\") + 1 else ""
            continue
        match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"=(.*)', line)
        if not store or not section or not match:
            continue
        name, value = match.group(1).replace('\\"', '"').replace("\\\\", "\\"), match.group(2)
        if section == "FirewallRules" and value.startswith('"'):
            stores[store].append((name, value[1:-1].replace('\\"', '"').replace("\\\\", "\\")))
        elif section.endswith("Profile") and value.startswith("dword:"):
            settings[store].setdefault(section[:-len("Profile")], {})[name] = int(value[6:], 16)
    return stores, settings


def test_winfw_sample_emitted_script() -> None:
    p, _ = load("winfw_sample.reg")
    report = Report()
    text = cli.convert(p, "windows-firewall", report)
    judge = ScriptJudge(text)
    by_display = {r["DisplayName"]: r for r in judge.rules}
    rdp = by_display["Remote Desktop from the admin networks"]
    assert rdp == {"Name": "FWShift-Remote_Desktop_from_the_admin_networks", "DisplayName": "Remote Desktop from the admin networks",
                   "Description": "FWShift: Remote Desktop from the admin networks", "Direction": "Inbound", "Action": "Allow",
                   "Enabled": "True", "Profile": "Private", "Protocol": "TCP", "LocalPort": ["3389"],
                   "RemoteAddress": ["10.20.0.0/16", "192.0.2.0/24", "2001:db8:20::/48"]}  # fmt: skip
    assert by_display["SNMP from the local subnet"]["RemoteAddress"] == ["LocalSubnet4"]
    assert by_display["SMB from the local subnet"]["RemoteAddress"] == ["LocalSubnet"]
    assert by_display["Block a known bad host"]["Action"] == "Block" and by_display["Block a known bad host"]["Direction"] == "Outbound"
    # Rules the model cannot hold are written disabled; rules disabled in the source are comments.
    assert by_display["Example application server"]["Enabled"] == "False"
    assert "#   rule OpenSSH server: disabled in the source, not written" in text
    assert "$OutboundBlock = @('Private')" in text and "-WhatIf" in text and "$Group = 'FWShift'" in text
    codes = {f.code for f in report.notes}
    assert {"WINFW_LOAD", "WINFW_HOST_RULES", "WINFW_DEFAULT_OUTBOUND", "WINFW_DEFAULT_INBOUND"} <= codes


# -- the traps of the platform, one by one ----------------------------------------------------------------------------


def _decide(model: Policy, profile: str, inbound: bool, remote: str, local: str = "10.10.0.5", proto: str = "tcp", port: int = 443,
            remote_port: int = 40000) -> bool:  # fmt: skip
    return model_allows_conn(model, Conn(profile, inbound, remote, local, proto, remote_port, port))


def test_a_block_rule_beats_an_allow_rule_whatever_comes_first() -> None:
    stores = {"local": [("a", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=443|Name=web|"),
                        ("b", "v2.30|Action=Block|Active=TRUE|Dir=In|RA4=10.0.9.0/24|Name=bad|")]}  # fmt: skip
    model = parse_stores(stores)
    assert [r.name for r in model.rules] == ["bad", "web", "(default) outbound"]
    assert _decide(model, "Public", True, "10.0.8.1") and not _decide(model, "Public", True, "10.0.9.1")
    assert not _decide(model, "Public", True, "10.0.8.1", port=444)  # (the default of the profile: block)
    assert _decide(model, "Public", False, "10.0.9.1")  # (outbound: allowed by default)


def test_profile_defaults_merge_and_local_rules() -> None:
    stores = {"local": [("a", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=22|Name=ssh|")]}
    settings = {"local": {"Domain": {"DefaultInboundAction": 0}, "Standard": {"DefaultOutboundAction": 1}},
                "gpo": {"Domain": {"DefaultInboundAction": 1, "AllowLocalPolicyMerge": 0}, "Public": {"DefaultOutboundAction": 1}}}  # fmt: skip
    report = Report()
    model = parse_stores(stores, settings, report)
    assert not _decide(model, "Domain", True, "10.0.8.1", port=22)  # (Group Policy's default wins, local rules not merged)
    assert _decide(model, "Private", True, "10.0.8.1", port=22)
    assert not _decide(model, "Private", False, "10.0.8.1") and not _decide(model, "Public", False, "10.0.8.1")
    assert _decide(model, "Domain", False, "10.0.8.1")
    assert "Domain: inbound blocked (Group Policy), outbound allowed (default), local rules not merged (Group Policy)" in next(n.message for n in report.notes if n.code == "WINFW_PROFILES")


def test_firewall_off_and_shielded_profiles() -> None:
    stores = {"gpo": [("a", "v2.30|Action=Block|Active=TRUE|Dir=In|Name=block all|"),
                      ("b", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|Name=web|")]}  # fmt: skip
    settings = {"gpo": {"Domain": {"EnableFirewall": 0}, "Private": {"DoNotAllowExceptions": 1}, "Public": {"DefaultInboundAction": 0}}}
    report = Report()
    model = parse_stores(stores, settings, report)
    assert [r.name for r in model.rules][:3] == ["(firewall off) inbound", "(firewall off) outbound", "(shielded) inbound"]
    assert _decide(model, "Domain", True, "10.0.8.1", port=1)  # (off: everything)
    assert not _decide(model, "Private", True, "10.0.8.1", port=80)  # (shielded: nothing in)
    assert not _decide(model, "Public", True, "10.0.8.1", port=80)  # (the block rule beats the allow rule)
    assert {"WINFW_FIREWALL_OFF", "WINFW_SHIELDED"} <= {n.code for n in report.notes}


def test_the_same_id_in_group_policy_replaces_the_local_rule() -> None:
    stores = {"gpo": [("x", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|Name=gpo|")],
              "local": [("X", "v2.30|Action=Block|Active=TRUE|Dir=In|Name=local|")]}  # fmt: skip
    report = Report()
    model = parse_stores(stores, report=report)
    assert _decide(model, "Public", True, "10.0.8.1", port=80)
    assert not next(r for r in model.rules if r.name == "local").enabled
    assert any(f.code == "WINFW_OVERRIDDEN" for f in report.item("rule", "local").findings)


def test_addresses_of_one_ip_version_and_keywords() -> None:
    stores = {"local": [("a", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|RA4=10.0.0.0/8|Name=v4|"),
                        ("b", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=81|RA4=LocalSubnet|RA6=2001:db8::/32|Name=kw|"),
                        ("c", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=82|RA42=IntErnet|RA62=IntErnet|Name=inet|"),
                        ("d", "v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RA4=10.1.1.1|RA4=*|Name=star|")]}  # fmt: skip
    model = parse_stores(stores)
    assert _decide(model, "Public", True, "10.1.2.3", port=80) and not _decide(model, "Public", True, "2001:db8::1", local="2001:db8::5", port=80)
    by_name = {r.name: r for r in model.rules}
    assert by_name["kw"].sources == ["2001:db8::/32", "LocalSubnet4"] and by_name["inet"].sources == ["Internet"]
    assert by_name["star"].destinations == [ANY]
    text = cli.convert(model, "windows-firewall", Report())
    rules = {r["DisplayName"]: r for r in ScriptJudge(text).rules}
    assert rules["kw"]["RemoteAddress"] == ["2001:db8::/32", "LocalSubnet4"] and rules["inet"]["RemoteAddress"] == ["Internet"]
    # Another target cannot write a keyword: the rule is not converted there.
    report = Report()
    cli.convert(model, "iptables", report)
    assert report.item("rule", "kw").disabled


def test_what_the_model_cannot_hold_is_never_read_as_any() -> None:
    texts = {"program": "App=C:\\x.exe", "service": "Svc=Dnscache", "users": "LUAuth=O:LSD:(A;;CC;;;WD)", "interfaces": "IF={0A1B2C3D-0000-0000-0000-000000000001}",
             "IPsec": "Security=AuthenticateEncrypt", "keyword": "LPort2_10=IPHTTPSIn", "package": "AppPkgId=S-1-15-2-1",
             "field": "Unknown=1", "bypass": "AuthByPassOut=TRUE"}  # fmt: skip
    for what, extra in texts.items():
        text = f"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|{extra}|Name=r|"
        report = Report()
        model = parse_stores({"local": [("a", text)]}, report=report)
        assert model.rules[0].unsupported, what
        assert any(f.code == "WINFW_NOT_MODELLED" for f in report.item("rule", "r").findings), what
    # An interface type list of all three is every interface.
    model = parse_stores({"local": [("a", "v2.30|Action=Allow|Active=TRUE|Dir=In|IFType=Lan|IFType=Wireless|IFType=RemoteAccess|Name=r|")]})
    assert not model.rules[0].unsupported


def test_rules_windows_cannot_parse_are_disabled() -> None:
    for text in ("v2.30|Action=Allow|Active=TRUE|Dir=In|LPort=80|Name=r|", "v2.30|Action=Maybe|Active=TRUE|Dir=In|Name=r|",
                 "v3.0|Action=Allow|Active=TRUE|Dir=In|Name=r|", "v2.30|Action=Allow|Active=TRUE|Dir=In|RA4=10.0.0.0/33|Name=r|",
                 "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP4=8:*|Name=r|", "no version|Name=r|",
                 "v2.30|Action=Allow|Active=TRUE|Dir=In|Dir=Out|Name=r|", "v2.30|Action=Allow|Active=TRUE|Dir=In|RA6=10.0.0.1|Name=r|"):  # fmt: skip
        report = Report()
        model = parse_stores({"local": [("a", text)]}, report=report)
        assert not model.rules[0].enabled, text
        assert any(f.code == "WINFW_RULE_INVALID" for f in report.item("rule", model.rules[0].name).findings), text


def test_input_forms_and_errors() -> None:
    stores = {"local": [("a", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|Name=web \"x\" \\ y|")]}
    data = reg_bytes(stores, {})
    assert parse_winfw.looks_like_winfw(data)
    # UTF-8 (as an editor saves it) and without a byte order mark, and the name with its quote and backslash.
    text = data.decode("utf-16-le").replace("\ufeff", "")
    for form in (text.encode("utf-8"), text.encode("utf-8-sig"), text.encode("utf-16-le")):
        model = parse_winfw.parse(form, Report())
        assert model.rules[0].name == 'web "x" \\ y'
    assert cli.detect_format(data) == "windows-firewall"
    with pytest.raises(ParseError):
        parse_winfw.parse("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software]\r\n".encode("utf-16"), Report())
    with pytest.raises(ParseError):
        parse_winfw.parse(b"REGEDIT4\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules]\r\nbroken\r\n", Report())
    with pytest.raises(ParseError):
        parse_winfw.parse(b"not a registry file", Report())
    # A hex value runs over lines, a deleted value and the default value are read past.
    extra = ('Windows Registry Editor Version 5.00\r\n\r\n[' + GPO + '\\FirewallRules]\r\n@=""\r\n"z"=hex(2):25,00,\\\r\n  00,00\r\n'
             '"y"=-\r\n"a"="v2.30|Action=Allow|Active=TRUE|Dir=In|Name=r|"\r\n')  # fmt: skip
    model = parse_winfw.parse(extra.encode("utf-16"), Report())
    assert [r.name for r in model.rules] == ["r", "(default) outbound"]


def test_detection_claims_no_other_sample() -> None:
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != "winfw_sample.reg":
            assert not parse_winfw.looks_like_winfw(path.read_bytes()), path.name
    assert cli.detect_format((DATA / "winfw_sample.reg").read_bytes()) == "windows-firewall"


def test_several_control_sets_and_the_mdm_store() -> None:
    def export(base: str, rule: str) -> str:
        return f"[{base}\\FirewallRules]\r\n\"a\"=\"{rule}\"\r\n\r\n"

    head = "Windows Registry Editor Version 5.00\r\n\r\n"
    one = LOCAL.replace("CurrentControlSet", "ControlSet001")
    two = LOCAL.replace("CurrentControlSet", "ControlSet002")
    rule = "v2.30|Action=Allow|Active=TRUE|Dir=In|Name=r|"
    with pytest.raises(ParseError, match="several control sets"):
        parse_winfw.parse((head + export(one, rule) + export(two, rule)).encode("utf-16"), Report())
    model = parse_winfw.parse((head + export(one, rule)).encode("utf-16"), Report())
    assert [r.name for r in model.rules] == ["r", "(default) outbound"]
    mdm = head + export(LOCAL + "\\Mdm", "v2.30|Action=Block|Active=TRUE|Dir=In|Name=m|") + export(LOCAL, rule).replace('"a"', '"b"')
    mdm += f"[{LOCAL}\\Mdm\\PublicProfile]\r\n\"AllowLocalPolicyMerge\"=dword:00000000\r\n"
    report = Report()
    model = parse_winfw.parse(mdm.encode("utf-16"), report)
    assert model.rules[0].name == "m" and model.rules[0].source_ids["windows-firewall.store"] == "mdm"
    local = next(r for r in model.rules if r.name == "r")
    assert local.src_zones == ["Domain", "Private"]


# -- the emitter, one by one ------------------------------------------------------------------------------------------


def host_policy(*rules: Rule, inbound_default: bool = False) -> Policy:
    p = Policy(vendor="windows-firewall", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.addresses["fqdn"] = Address("fqdn", AddressKind.FQDN, "www.example.com")
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def test_a_block_rule_loses_what_the_allow_rules_above_it_match() -> None:
    p = host_policy(Rule("web", ["Public"], ["Host"], services=["web"]),
                    Rule("block-net", ["Public"], ["Host"], sources=["10.0.0.0/8"], action=Action.DROP))  # fmt: skip
    report = Report()
    text = emit_winfw.emit(p, report, Options())
    rules = ScriptJudge(text).rules
    block = [r for r in rules if r["Action"] == "Block"]
    # What is left is TCP but 80 and 443, which a rule says, and every other protocol, which is left to the default.
    assert [(r["Protocol"], r["LocalPort"], r["RemoteAddress"]) for r in block] == [("TCP", ["0-79", "81-442", "444-65535"], ["10.0.0.0/8"])]
    assert {f.code for f in report.item("rule", "block-net").findings} == {"WINFW_BLOCK_CUT", "WINFW_LEFT_TO_DEFAULT"}
    judge = ScriptJudge(text)
    assert judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "tcp", 40000, 443))
    assert not judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "tcp", 40000, 22))
    assert not judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "udp", 40000, 53))


def test_a_cleanup_rule_is_left_to_the_default_and_the_allow_rules_below_it_are_cut() -> None:
    p = host_policy(Rule("web", ["Public"], ["Host"], services=["web"]),
                    Rule("cleanup", ["Public"], ["Host"], action=Action.DROP),
                    Rule("dead", ["Public"], ["Host"]),
                    Rule("out-cleanup", ["Host"], ["Public"], action=Action.DROP),
                    Rule("out-dead", ["Host"], ["Public"]))  # fmt: skip
    p.rules.insert(0, Rule("dns-out", ["Host"], ["Public"], services=["web"], origin="dns-out"))
    report = Report()
    text = emit_winfw.emit(p, report, Options())
    judge = ScriptJudge(text)
    assert report.item("rule", "dead").skipped and report.item("rule", "out-dead").skipped
    cleanup = report.item("rule", "cleanup").findings
    assert any(f.code == "WINFW_LEFT_TO_DEFAULT" and f.severity == Severity.INFO for f in cleanup)
    assert any(f.code == "WINFW_LEFT_TO_DEFAULT" and f.severity == Severity.REVIEW for f in report.item("rule", "out-cleanup").findings)
    assert not [r for r in judge.rules if r["Action"] == "Block"]
    assert "Public" in next(n.message for n in report.notes if n.code == "WINFW_DEFAULT_OUTBOUND")
    assert not judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "udp", 40000, 53))
    # With the default outbound action Allow (Windows's own), the cleanup rule outbound does not hold: the report said so.
    assert ScriptJudge(text, outbound_block=False).allows(Conn("Public", False, "10.1.1.1", "10.10.0.5", "udp", 53, 40000))


def test_what_windows_cannot_say_of_a_block_rule_is_left_to_the_default() -> None:
    p = host_policy(Rule("web", ["Public"], ["Host"], services=["web"]),
                    Rule("not-web", ["Public"], ["Host"], sources=["10.0.0.0/8"], services=["web"], negate_service=True,
                         action=Action.DROP),
                    Rule("sctp-block", ["Public"], ["Host"], services=["sctp"], action=Action.DROP),
                    Rule("all-from-net", ["Public"], ["Host"], sources=["10.0.0.0/8"]),
                    Rule("sctp-all", ["Public"], ["Host"], sources=["192.168.0.0/16"], services=["sctp-any"]))  # fmt: skip
    p.services["sctp-any"] = Service("sctp-any", [ServiceEntry(Protocol.SCTP)])
    report = Report()
    text = emit_winfw.emit(p, report, Options())
    judge = ScriptJudge(text)
    assert any(f.code == "WINFW_LEFT_TO_DEFAULT" for f in report.item("rule", "not-web").findings)
    assert any(f.code == "WINFW_LEFT_TO_DEFAULT" for f in report.item("rule", "sctp-block").findings)
    assert any(f.code == "WINFW_ALLOW_CUT" for f in report.item("rule", "all-from-net").findings)
    # (SCTP but port 2905 is more than a rule of Windows Firewall can say: not written, the rule allows less.)
    assert any(f.code == "WINFW_PART_NOT_WRITTEN" for f in report.item("rule", "sctp-all").findings)
    for remote, proto, port, wanted in (("10.1.1.1", "tcp", 443, True), ("10.1.1.1", "tcp", 22, False), ("10.1.1.1", "udp", 53, False),
                                        ("10.1.1.1", "47", 0, False), ("10.1.1.1", "sctp", 2906, False), ("192.168.1.1", "tcp", 443, True),
                                        ("192.168.1.1", "tcp", 22, False), ("192.168.1.1", "sctp", 2905, False)):  # fmt: skip
        assert judge.allows(Conn("Public", True, remote, "10.10.0.5", proto, 40000, port)) == wanted, (remote, proto, port)


def test_an_allow_rule_part_windows_cannot_say_is_not_written() -> None:
    p = host_policy(Rule("not-web", ["Public"], ["Host"], services=["web"], negate_service=True))
    report = Report()
    text = emit_winfw.emit(p, report, Options())
    assert any(f.code == "WINFW_PART_NOT_WRITTEN" for f in report.item("rule", "not-web").findings)
    judge = ScriptJudge(text)
    assert judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "tcp", 40000, 22))
    assert not judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "tcp", 40000, 80))
    assert not judge.allows(Conn("Public", True, "10.1.1.1", "10.10.0.5", "47", 40000, 0))  # (not written: allows less)


def test_zones_become_host_and_profiles_by_zone_map() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443")])
    p.rules = [Rule("in", ["untrust"], ["dmz"], services=["web"], origin="in"), Rule("out", ["dmz"], ["trust"], origin="out"),
               Rule("transit", ["trust"], ["untrust"], origin="transit")]  # fmt: skip
    report = Report()
    text = emit_winfw.emit(p, report, Options(zone_map={"dmz": "Host", "untrust": "Public", "trust": "Domain"}))
    rules = {r["DisplayName"]: r for r in ScriptJudge(text).rules}
    assert rules["in"]["Direction"] == "Inbound" and rules["in"]["Profile"] == "Public" and "RemoteAddress" not in rules["in"]
    assert rules["out"]["Direction"] == "Outbound" and rules["out"]["Profile"] == "Domain"
    assert report.item("rule", "transit").disabled  # (between two networks: the host's address in Domain is not known)
    # Without the map a zone named like a profile is a zone: a zone needs its networks.
    report = Report()
    emit_winfw.emit(p, report, Options())
    assert report.item("rule", "in").disabled and any(f.code == "ZONE_NETWORK_MISSING" for f in report.item("rule", "in").findings)


def test_a_keyword_block_below_an_allow_it_meets_is_not_enforced() -> None:
    model = parse_stores({"local": [("a", "v2.30|Action=Block|Active=TRUE|Dir=In|RA4=LocalSubnet|Name=kw-block|")]})
    model.rules.insert(0, Rule("web", ["Public"], ["Host"], origin="web"))
    report = Report()
    emit_winfw.emit(model, report, Options())
    item = report.item("rule", "kw-block")
    assert item.disabled and any(f.code == "WINFW_KEYWORD_ORDER" for f in item.findings)


def test_names_quotes_and_what_the_script_never_does() -> None:
    p = host_policy(Rule("it's \u2019quoted\u2019 & all", ["Public"], ["Host"], services=["ping"]), Rule("All", ["Host"], ["Public"]),
                    Rule("fqdn", ["Public"], ["Host"], sources=["fqdn"]))  # fmt: skip
    report = Report()
    text = emit_winfw.emit(p, report, Options(object_prefix="Corp FW"))
    rules = {r["DisplayName"]: r for r in ScriptJudge(text).rules}
    assert "it's \u2019quoted\u2019 & all" in rules and "All (rule)" in rules
    assert rules["it's \u2019quoted\u2019 & all"]["Name"].startswith("Corp_FW-") and "$Group = 'Corp FW'" in text
    assert rules["it's \u2019quoted\u2019 & all"]["Protocol"] == "ICMPv4" and rules["it's \u2019quoted\u2019 & all"]["IcmpType"] == ["8"]
    assert report.item("rule", "fqdn").disabled


def test_nat_is_not_written_and_rules_see_translated_addresses() -> None:
    p, _ = load("routeros_sample.rsc")
    report = Report()
    emit_winfw.emit(p, report, Options(zone_networks=ZONES_AT))
    assert all(item.skipped for (kind, _), item in report.items.items() if kind == "nat")


def test_emitted_findings_have_severities_the_manual_names() -> None:
    p, _ = load("winfw_sample.reg")
    report = Report()
    emit_winfw.emit(p, report, Options())
    assert all(n.severity in (Severity.INFO, Severity.APPROX, Severity.REVIEW) for n in report.notes)


def test_transit_rules_are_written_for_either_end() -> None:
    """A rule between two zones of networks: inbound for the host at the destination, outbound for the host at the source."""
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.rules = [Rule("lan-to-dmz", ["eth0"], ["eth1"], origin="lan-to-dmz", scope=RuleScope.UNIVERSAL)]
    text = emit_winfw.emit(p, Report(), Options(zone_networks=ZONES_AT))
    judge = ScriptJudge(text)
    assert judge.allows(Conn("Public", True, "10.0.0.5", "10.0.2.5", "tcp", 40000, 80))
    assert judge.allows(Conn("Domain", False, "10.0.2.5", "10.0.0.5", "udp", 53, 40000))
    assert not judge.allows(Conn("Public", True, "10.0.4.5", "10.0.2.5", "tcp", 40000, 80))
    assert not judge.allows(Conn("Public", False, "10.0.0.5", "10.0.2.5", "tcp", 40000, 80))

