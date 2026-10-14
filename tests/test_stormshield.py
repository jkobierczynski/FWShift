# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Stormshield SNS: parser, emitter, and packet-level equivalence with a judge of its own.

A random firewall is a plain description (interfaces, objects, groups, services, the rules of a slot) that
``render`` writes as the ConfigFiles of an SNS firewall, packed as decbackup unpacks a backup, and ``SnsJudge``
decides packets from, as SNS does: the rules top to bottom, first match, ``decrypt`` and ``log`` going on to the next,
and what no rule matches blocked. ``read_script`` reads the serverd commands the emitter writes back into such a
description, so the same judge decides the output. None of it shares code with the parser or the emitter.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import random
import tarfile
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, model_allows, random_model

from fwshift import cli
from fwshift.errors import FwshiftError, ParseError
from fwshift.options import Options
from fwshift.parsers import stormshield as parse_stormshield
from fwshift.report import Report

INTERFACES = {"out": ("203.0.113.2", 29, False), "in": ("10.10.0.254", 24, True), "dmz1": ("10.20.0.254", 24, True),
              "lab": ("10.30.0.254", 24, True)}  # fmt: skip
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}
POOL = ["10.10.0.5", "10.10.0.77", "10.10.0.200", "10.20.0.10", "10.20.0.25", "10.30.0.9", "10.30.0.254", "10.10.0.254", "203.0.113.2",
        "192.0.2.7", "198.51.100.4", "203.0.113.99", "2001:db8:10::5", "2001:db8:20::9", "2001:db8:99::1"]  # fmt: skip
HOSTS = ["10.10.0.5", "10.20.0.10", "10.20.0.25", "192.0.2.7", "2001:db8:10::5"]
NETS = ["10.10.0.0/25", "10.10.0.128/25", "10.20.0.0/24", "10.0.0.0/8", "198.51.100.0/24", "2001:db8:10::/64", "192.0.2.0/255.255.255.0"]
RANGES = [("10.10.0.60", "10.10.0.99"), ("10.20.0.1", "10.20.0.30")]
PORTS = [22, 25, 53, 80, 443, 8080, 8085, 8090, 8091, 1023, 1024, 5000, 0, 65535, 123, 113]


def addr(text: str) -> Any:
    return ipaddress.ip_address(text)


# -- the judge ------------------------------------------------------------------------------------------------


class SnsJudge:
    def __init__(self, sns: Dict[str, Any]) -> None:
        self.sns = sns
        self.addresses: Dict[str, List[Any]] = {k.lower(): v for k, v in sns["addresses"].items()}
        self.groups: Dict[str, List[str]] = {k.lower(): v for k, v in sns["groups"].items()}
        self.services: Dict[str, List[Any]] = {k.lower(): v for k, v in sns["services"].items()}
        self.service_groups: Dict[str, List[str]] = {k.lower(): v for k, v in sns["service_groups"].items()}
        self.protocols: Dict[str, int] = {k.lower(): v for k, v in sns["protocols"].items()}
        internals: List[Any] = []
        for name, (address, length, protected) in sns["interfaces"].items():
            net = ipaddress.ip_network(f"{address}/{length}", strict=False)
            self.addresses.setdefault(f"network_{name}".lower(), [("net", str(net))])
            self.addresses.setdefault(f"firewall_{name}".lower(), [("net", f"{address}/32")])
            if protected:
                internals.append(("net", str(net)))
        self.addresses.setdefault("firewall_all", [("net", f"{a}/32") for a, _, _ in sns["interfaces"].values()])
        self.addresses.setdefault("network_internals", internals)
        self.internals = internals

    def has(self, name: str, address: str, depth: int = 0) -> bool:
        key = name.lower()
        probe = addr(address)
        if key == "any":
            return True
        if key == "internet":
            return not self.has(self.sns.get("internet", "Network_internals"), address, depth + 1)
        if key in self.groups:
            assert depth < 10
            return any(self.has(member, address, depth + 1) for member in self.groups[key])
        for spec in self.addresses[key]:
            if spec[0] == "net":
                net = ipaddress.ip_network(spec[1], strict=False)
                if net.version == probe.version and probe in net:
                    return True
            elif spec[0] == "range":
                first, last = addr(spec[1]), addr(spec[2])
                if first.version == probe.version and int(first) <= int(probe) <= int(last):
                    return True
        return False

    def entries(self, name: str, depth: int = 0) -> List[Any]:
        key = name.lower()
        if key in self.service_groups:
            assert depth < 10
            return [e for member in self.service_groups[key] for e in self.entries(member, depth + 1)]
        return self.services[key]

    def allows(self, pkt: Packet, ingress: str, egress: str) -> Optional[bool]:
        number = str(NUMBERS.get(pkt.proto, pkt.proto))
        for rule in self.sns.get("global_rules", []) + [{"action": "end of the global policy"}] + self.sns["rules"]:
            if rule["action"] == "end of the global policy":
                continue
            if not rule["state"] or rule["action"] in ("decrypt", "log", "deleg"):
                continue
            if rule["srcif"] and rule["srcif"].lower() != ingress.lower():
                continue
            if rule["dstif"] and rule["dstif"].lower() != egress.lower():
                continue
            if rule["bad"] or rule.get("carried"):
                return None
            if any(self.has(n, pkt.src) for n in rule["src"]) == rule["src_neg"]:
                continue
            if any(self.has(n, pkt.dst) for n in rule["dst"]) == rule["dst_neg"]:
                continue
            ipproto = rule["ipproto"]
            if rule["ports"]:
                if ipproto in ("tcp", "udp") and pkt.proto != ipproto:
                    continue
                if not any(proto == pkt.proto and low <= pkt.dport <= high for name in rule["ports"] for proto, low, high in self.entries(name)):
                    continue
            elif ipproto in ("tcp", "udp", "icmp"):
                if pkt.proto != ipproto:
                    continue
                if ipproto == "icmp" and rule.get("icmptype") is not None and rule["icmptype"] != pkt.icmp_type:
                    continue
            elif ipproto:
                if str(self.protocols[ipproto.lower()]) != number:
                    continue
            if rule.get("srcport") and not any(proto == pkt.proto and low <= pkt.sport <= high for proto, low, high in self.entries(rule["srcport"])):
                continue
            return rule["action"] == "pass"
        return False


# -- random firewalls ---------------------------------------------------------------------------------------


def random_sns(rng: random.Random) -> Dict[str, Any]:
    sns: Dict[str, Any] = {"interfaces": dict(INTERFACES), "addresses": {}, "groups": {}, "services": {}, "service_groups": {},
                           "protocols": {"proto_200": 200, "proto_47": 47}, "rules": [], "dynamic": set(), "render": {}, "bad_objects": set()}  # fmt: skip
    for index in range(rng.randint(2, 6)):
        kind = rng.random()
        if kind < 0.35:
            sns["addresses"][f"h{index}"] = [("net", rng.choice(HOSTS) + ("/128" if False else ""))]
        elif kind < 0.6:
            sns["addresses"][f"n{index}"] = [("net", rng.choice(NETS))]
        elif kind < 0.75:
            first, last = rng.choice(RANGES)
            sns["addresses"][f"r{index}"] = [("range", first, last)]
        elif kind < 0.9:
            sns["addresses"][f"d{index}"] = [("net", "10.10.0.77"), ("net", "2001:db8:10::77")]
        elif kind < 0.95:
            sns["addresses"][f"dyn{index}.example.com"] = [("net", "192.0.2.80")]
            sns["dynamic"].add(f"dyn{index}.example.com")
        else:
            sns["addresses"][f"hp{index}"] = [("net", "10.10.0.5/24")]
            sns["bad_objects"].add(f"hp{index}")  # (a host with a prefix: not converted)
    names = list(sns["addresses"])
    for index in range(rng.randint(0, 2)):
        pool = names + list(sns["groups"])
        members = rng.sample(pool, min(len(pool), rng.randint(1, 3)))
        if rng.random() < 0.2:
            members.append(members[0])  # (a member twice)
        if rng.random() < 0.05:
            members.append(f"g{index}")  # (the group in itself: not converted)
            sns["bad_objects"].add(f"g{index}")
        sns["groups"][f"g{index}"] = members
        if any(m in sns["bad_objects"] for m in members):
            sns["bad_objects"].add(f"g{index}")
    if sns["groups"] and rng.random() < 0.15:
        sns["internet"] = rng.choice(list(sns["groups"]))  # ([Internet] operator=ne object=a group of its own)
    for index in range(rng.randint(1, 4)):
        proto = rng.choice(["tcp", "tcp", "udp", "any"])
        low = rng.choice([22, 25, 53, 80, 443, 8080, 5000, 113, 123])
        high = low if rng.random() < 0.6 else low + rng.choice([0, 10])
        protos = ["tcp", "udp"] if proto == "any" else [proto]
        sns["services"][f"s{index}"] = [(p, low, high) for p in protos]
        sns["render"][f"s{index}"] = (proto, low, high)
    sns["services"]["http"] = [("tcp", 80, 80)]
    sns["render"]["http"] = ("tcp", 80, 80)
    if rng.random() < 0.5:
        sns["service_groups"]["sg0"] = rng.sample(list(sns["services"]), min(2, len(sns["services"])))
    addresses = list(sns["addresses"]) + list(sns["groups"]) + ["Network_in", "Firewall_out", "firewall_all", "Network_internals", "Internet",
                                                                "Network_dmz1", "Network_lab"]  # fmt: skip
    services = [s for s in sns["services"]] + list(sns["service_groups"])
    for index in range(rng.randint(3, 12)):
        rule: Dict[str, Any] = {"action": rng.choice(["pass", "pass", "block", "reset"]), "srcif": "", "dstif": "", "src": ["any"], "src_neg": False,
                                "dst": ["any"], "dst_neg": False, "ports": [], "srcport": None, "ipproto": None, "icmptype": None,
                                "state": True, "bad": False, "extra": [], "log": rng.random() < 0.3}  # fmt: skip
        if rng.random() < 0.06:
            rule["action"] = rng.choice(["decrypt", "log"])
        if rng.random() < 0.4:
            rule["srcif"] = rng.choice(list(INTERFACES) + ["IN"])
        if rng.random() < 0.15:
            rule["dstif"] = rng.choice(list(INTERFACES))
        for side in ("src", "dst"):
            if rng.random() < 0.7:
                rule[side] = rng.sample(addresses, rng.randint(1, 2))
                rule[side + "_neg"] = rng.random() < 0.15
        if rng.random() < 0.15:
            rule["src"], rule["src_neg"] = [rule["src"][0] if rule["src"] != ["any"] else "Network_in"], False
            rule["users"] = 'group="staff"@' + rule["src"][0]
            rule["carried"] = True
        roll = rng.random()
        if roll < 0.45:
            rule["ports"] = rng.sample(services, rng.randint(1, 2))
            if rng.random() < 0.2:
                rule["ipproto"] = rng.choice(["tcp", "udp"])
        elif roll < 0.6:
            rule["ipproto"] = "icmp"
        elif roll < 0.7:
            rule["ipproto"] = rng.choice(["tcp", "udp", "proto_200", "proto_47"])
        for side in ("src", "dst"):
            if any(n in sns["dynamic"] for n in rule[side]) or any(n in sns["groups"] and _holds_dynamic(sns, n) for n in rule[side]):
                rule["carried"] = True  # (a host name: the model matches no address with it)
        if rule["ipproto"] in ("tcp", "udp") and rule["ports"] and not any(
                e[0] == rule["ipproto"] for name in rule["ports"] for e in _entries(sns, name)):
            rule["bad"] = True  # (no service of the rule is of that protocol: it matches nothing, not converted)
        if rng.random() < 0.05:
            rule["extra"].append(rng.choice(["schedule office", "via httpproxy", "srcgeo fr", "tos 8", "type 8"]))
            rule["bad"] = True
        if rng.random() < 0.05:
            rule["extra"].append(rng.choice(["settos 24", "route gw1"]))  # (what it does with the traffic, said)
        if any(n in sns["bad_objects"] for n in rule["src"] + rule["dst"]):
            rule["bad"] = True
        if _internet_bad(sns) and "Internet" in rule["src"] + rule["dst"]:
            rule["bad"] = True
        if rng.random() < 0.03 and rule["dst"] != ["any"]:
            rule["dst"], rule["bad"] = rule["dst"] + [""], True  # (an empty name in the list)
        if rng.random() < 0.03:
            rule["dst"], rule["bad"] = ["missing_object"], True
        sns["rules"].append(rule)
    if rng.random() < 0.25:
        sns["global_rules"] = []
        for _ in range(rng.randint(1, 3)):
            sns["global_rules"].append({"action": rng.choice(["pass", "block"]), "srcif": "", "dstif": "", "src": rng.sample(addresses, 1),
                                        "src_neg": False, "dst": ["any"], "dst_neg": False, "ports": rng.sample(services, 1), "srcport": None,
                                        "ipproto": None, "state": True, "bad": False, "extra": [], "log": False})  # fmt: skip
            rule = sns["global_rules"][-1]
            if any(n in sns["bad_objects"] for n in rule["src"]) or (_internet_bad(sns) and "Internet" in rule["src"]):
                rule["bad"] = True
            if any(n in sns["dynamic"] or _holds_dynamic(sns, n) for n in rule["src"]):
                rule["carried"] = True
    return sns


def _entries(sns: Dict[str, Any], name: str) -> List[Any]:
    if name in sns["service_groups"]:
        return [e for member in sns["service_groups"][name] for e in _entries(sns, member)]
    return sns["services"][name]


def _internet_bad(sns: Dict[str, Any]) -> bool:
    """Internet defined by an object that cannot be read, or holds a host name: not converted."""
    base = sns.get("internet")
    return base is not None and (base in sns["bad_objects"] or _holds_dynamic(sns, base))


def _holds_dynamic(sns: Dict[str, Any], name: str, depth: int = 0) -> bool:
    if name in sns["dynamic"]:
        return True
    return name in sns["groups"] and depth < 10 and any(_holds_dynamic(sns, m, depth + 1) for m in sns["groups"][name])


def _case(name: str, rng: random.Random) -> str:
    return name.upper() if rng.random() < 0.1 and name != "any" else name


def render_files(sns: Dict[str, Any], rng: random.Random) -> Dict[str, str]:
    network = ["[Config]", "IPv6State=0", ""]
    for index, (name, (address, length, protected)) in enumerate(sns["interfaces"].items()):
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)
        if name == "lab" and rng.random() < 0.5:
            network += [f"[ethernet{index}]", "State=1", f"Name={name}", f"Protected={int(protected)}", "Bridge=bridge0", "",
                        "[bridge0]", "State=1", "Name=labbridge", f"Protected={int(protected)}", f"Address={address}", f"Mask={mask}", ""]  # fmt: skip
        else:
            network += [f"[ethernet{index}]", "State=1", f"Name={name}", f"Protected={int(protected)}", f"Address={address}",
                        f"Mask={rng.choice([mask, str(length)])}", ""]  # fmt: skip
    hosts, networks = ["[Host]"], ["[Network]"]
    for name, specs in sns["addresses"].items():
        texts = [s[1] if s[0] == "net" else f"{s[1]}-{s[2]}" for s in specs]
        if name in sns["dynamic"]:
            hosts.append(f"{name}={texts[0]},resolve=dynamic")
        elif specs[0][0] == "range" or "/" not in texts[0]:
            hosts.append(f"{name}={','.join(texts)}" + rng.choice(["", ",resolve=static", "# a host", " # a host"]))
        else:
            networks.append(f"{name}={texts[0]}" + rng.choice(["", "# a network"]))
    services = ["[Service]"]
    for name in sns["services"]:
        proto, low, high = sns["render"][name]
        services.append(f"{name}={low}{'' if low == high else f'-{high}'}/{proto}")
    protocols = ["[Protocol]"] + [f"{name}={number}" for name, number in sns["protocols"].items()]
    internet = ["", "[Internet]", "operator=ne", f"object={sns['internet']}"] if "internet" in sns else []
    files = {"network": "\n".join(network) + "\n",
             "object": "\n".join(hosts + [""] + networks + [""] + services + [""] + protocols + internet) + "\n"}  # fmt: skip
    files["objectgroup"] = "".join(f"[{name}]{rng.choice(['', ' # group'])}\n" + "".join(f"{m}\n" for m in members) + "\n"
                                   for name, members in sns["groups"].items())  # fmt: skip
    files["servicegroup"] = "".join(f"[{name}]\n" + "".join(f"{m}\n" for m in members) for name, members in sns["service_groups"].items())
    slot = rng.choice(["03", "05", "07"])
    if sns.get("global_rules"):
        files["Global/Filter/slotinfo"] = "[Global]\nActive=02\n"
        files["Global/Filter/02"] = "[Filter]\n" + "".join(_rule_text(rule, index, rng) + "\n" for index, rule in enumerate(sns["global_rules"])) \
            + "deleg from any to any\n"
    lines = ["[Filter]"]
    for index, rule in enumerate(sns["rules"]):
        if rng.random() < 0.2:
            lines.append(f'separator color="c0c0c0" comment="part {index}" collapse="0" nb_elements="1" first_ruleid="{index + 1}"')
        lines.append(_rule_text(rule, index, rng))
    lines.append("")
    lines.append("[NAT]")
    files[f"Filter/{slot}"] = "\n".join(lines) + "\n"
    files["Filter/01"] = "[Filter]\nblock from any to any\n"
    files["Filter/slotinfo"] = f"[Global]\nActive={rng.choice([slot, str(int(slot))])}\nSync=1\n\n[01]\nName=\"Block all\"\n\n[{slot}]\nName=\"test\"\n"
    return files


def _rule_text(rule: Dict[str, Any], index: int, rng: random.Random) -> str:
    words = [rule["action"]]
    if rule["log"]:
        words.append("log")
    if rng.random() < 0.2:
        words += ["inspection", rng.choice(["firewall", "ids", "ips"])]
    if rule["ipproto"]:
        words += ["ipproto", rule["ipproto"]]
    if rng.random() < 0.15:
        words += ["proto", "none"]
    words += [x for extra in rule["extra"] for x in extra.split()]
    source = ",".join(_case(n, rng) for n in rule["src"])
    if rule.get("users"):
        words += ["from", rule["users"]] + (["domain", "corp.example"] if rng.random() < 0.5 else [])
    elif rule["src_neg"]:
        words += ["from"] + (["!", source] if rng.random() < 0.5 else ["!" + source])
    else:
        words += ["from", source]
    if rule["srcif"]:
        words += ["on", rule["srcif"]]
    elif rng.random() < 0.05:
        words += ["on", "any"]
    destination = ",".join(_case(n, rng) for n in rule["dst"])
    words += ["to", ("!" if rule["dst_neg"] else "") + destination]
    if rule["dstif"]:
        words += ["on", rule["dstif"]]
    if rule["ports"]:
        words += ["port", ",".join(rule["ports"])]
    comment = rng.choice(["", f"\t# rule {index}", f" # rule {index} Created on 2026-01-02 03:04:05, by admin (10.10.0.5)", "\t#",
                          " # Créée le 2026-01-02 03:04:05, par équipe (10.10.0.5)"])  # fmt: skip
    return " ".join(words) + comment


def pack(files: Dict[str, str], prefix: str = "usr/Firewall/ConfigFiles/", compress: bool = True) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name in sorted(files):
            data = files[name].encode("utf-8")
            info = tarfile.TarInfo(prefix + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue()) if compress else raw.getvalue()


def sns_packet(rng: random.Random) -> Optional[Tuple[Packet, str, str]]:
    src, dst = rng.choice(POOL), rng.choice(POOL)
    if (":" in src) != (":" in dst) or src == dst:
        return None
    proto = rng.choice(["tcp", "tcp", "udp", "icmp6" if ":" in src else "icmp", "200", "47"])
    pkt = Packet("", "", src, dst, proto, rng.choice([1024, 40000, 5005, 80]), rng.choice(PORTS), rng.choice([0, 8, 3]))
    return pkt, rng.choice(list(INTERFACES)), rng.choice(list(INTERFACES))


def parse(data: bytes, slot: str = "") -> Tuple[Any, Report]:
    report = Report()
    return parse_stormshield.parse(data, report, slot=slot), report


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def judged(sns: Dict[str, Any], model: Any, rng: random.Random, seed: int, packets: int = 300) -> int:
    judge = SnsJudge(sns)
    count = 0
    terminal = [r for r in sns.get("global_rules", []) + sns["rules"] if r["action"] not in ("decrypt", "log")]
    assert len(model.rules) == len(terminal), (seed, len(model.rules), len(terminal))
    for rule, converted in zip(terminal, model.rules):
        if rule["bad"]:
            assert converted.unsupported, (seed, rule, converted)
    for _ in range(packets):
        found = sns_packet(rng)
        if found is None:
            continue
        pkt, ingress, egress = found
        verdict = judge.allows(pkt, ingress, egress)
        if verdict is None:
            continue
        pkt.in_if, pkt.out_if = ingress, egress
        count += 1
        assert model_allows(model, pkt) == verdict, (seed, pkt, json.dumps(sns, indent=1, default=str))
    return count


def test_parsed_firewall_decides_like_the_judge() -> None:
    compared = 0
    for seed in range(500):
        rng = random.Random(seed)
        sns = random_sns(rng)
        data = pack(render_files(sns, rng), rng.choice(["usr/Firewall/ConfigFiles/", "ConfigFiles/", "./", ""]), rng.random() < 0.7)
        assert cli.detect_format(data) == "stormshield"
        model, _ = parse(data)
        compared += judged(sns, model, rng, seed)
    assert compared > 28000


# -- the emitted script, read back --------------------------------------------------------------------------


def _tokens(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    words: List[str] = []
    current, quoted = "", False
    for char in line:
        if char == '"':
            quoted = not quoted
            continue
        if char == " " and not quoted:
            words.append(current)
            current = ""
        else:
            current += char
    words.append(current)
    for word in words:
        if "=" in word:
            key, value = word.split("=", 1)
            assert key not in out, line
            out[key] = value
    return out


def read_script(text: str, interfaces: Dict[str, Any], firewall: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The serverd commands the emitter writes, as a random firewall; on ``firewall`` (the one read), whose own objects
    (Internet and what it is defined by) the commands may name."""
    sns: Dict[str, Any] = {"interfaces": interfaces, "addresses": {}, "groups": {}, "services": {}, "service_groups": {}, "protocols": {},
                           "rules": []}  # fmt: skip
    if firewall is not None and "internet" in firewall:
        sns["internet"] = "(the firewall's) " + firewall["internet"]
        own = {f"(the firewall's) {k}": v for k, v in firewall["addresses"].items()}
        groups = {f"(the firewall's) {k}": [f"(the firewall's) {m}" if m in firewall["addresses"] or m in firewall["groups"] else m for m in v]
                  for k, v in firewall["groups"].items()}  # fmt: skip
        sns["addresses"].update(own)
        sns["groups"].update(groups)
    lines = text.splitlines()
    assert lines[0].startswith("#") and "MODIFY FORCE ON" in lines
    for line in lines:
        assert len(line) < 8000 and line.isprintable(), line
        if not line or line.startswith("#"):
            continue
        words = line.split()
        tokens = _tokens(line)
        if words[:3] == ["CONFIG", "OBJECT", "HOST"]:
            assert words[3] == "NEW" and tokens["update"] == "1" and tokens["resolve"] == "static", line
            value = tokens.get("ip") or tokens["ipv6"]
            sns["addresses"][tokens["name"]] = [("net", value)]
        elif words[:3] == ["CONFIG", "OBJECT", "NETWORK"]:
            assert words[3] == "NEW", line
            if "ip" in tokens:
                sns["addresses"][tokens["name"]] = [("net", str(ipaddress.ip_network(f"{tokens['ip']}/{tokens['mask']}")))]
            else:
                sns["addresses"][tokens["name"]] = [("net", str(ipaddress.ip_network(f"{tokens['ipv6']}/{tokens['prefixlenv6']}")))]
        elif words[:3] == ["CONFIG", "OBJECT", "SERVICE"]:
            assert tokens["proto"] in ("tcp", "udp"), line
            low = int(tokens["port"])
            sns["services"][tokens["name"]] = [(tokens["proto"], low, int(tokens.get("toport", low)))]
        elif words[:3] == ["CONFIG", "OBJECT", "PROTOCOL"]:
            sns["protocols"][tokens["name"]] = int(tokens["protonumber"])
        elif words[:4] == ["CONFIG", "OBJECT", "GROUP", "NEW"]:
            sns["groups"][tokens["name"]] = []
        elif words[:4] == ["CONFIG", "OBJECT", "GROUP", "ADDTO"]:
            assert tokens["node"] in sns["addresses"] or tokens["node"] in sns["groups"] or _builtin(tokens["node"]), line
            sns["groups"][tokens["group"]].append(tokens["node"])
        elif words[:4] == ["CONFIG", "FILTER", "RULE", "INSERT"]:
            if tokens["type"] == "nat":
                continue
            assert tokens["state"] in ("on", "off") and tokens["action"] in ("pass", "block", "reset"), line
            allowed = {"type", "index", "state", "action", "loglevel", "ipproto", "icmptype", "icmpcode", "srcport", "dstport", "srctarget",
                       "srcif", "dsttarget", "dstif", "comment"}  # fmt: skip
            assert set(tokens) <= allowed, line
            rule: Dict[str, Any] = {"action": tokens["action"], "state": tokens["state"] == "on", "srcif": tokens.get("srcif", ""),
                                    "dstif": tokens.get("dstif", ""), "bad": False}  # fmt: skip
            for side, key in (("src", "srctarget"), ("dst", "dsttarget")):
                value = tokens[key]
                rule[side + "_neg"] = value.startswith("!")
                rule[side] = [value.lstrip("!")]
                assert value.lstrip("!") == "any" or "," not in value, line
            rule["ports"] = tokens["dstport"].split(",") if "dstport" in tokens else []
            rule["srcport"] = tokens.get("srcport")
            ipproto = tokens.get("ipproto")
            if ipproto and ipproto not in ("tcp", "udp", "icmp"):
                if ipproto not in sns["protocols"]:
                    sns["protocols"][ipproto] = {"gre": 47, "igmp": 2, "vpn-esp": 50, "vpn-ah": 51}[ipproto]
            rule["ipproto"] = ipproto
            rule["icmptype"] = int(tokens["icmptype"]) if "icmptype" in tokens else None
            assert "icmpcode" not in tokens or "icmptype" in tokens, line
            if rule["ports"] and ipproto is None:
                pass
            sns["rules"].append(rule)
        else:
            assert words[:3] in (["MODIFY", "FORCE", "ON"], ["CONFIG", "OBJECT", "ACTIVATE"], ["CONFIG", "FILTER", "ACTIVATE"],
                                 ["CONFIG", "SLOT", "UPDATE"], ["CONFIG", "FILTER", "RULE"]) or words[:2] == ["MODIFY", "FORCE"], line  # fmt: skip
    for rule in sns["rules"]:
        for name in rule["src"] + rule["dst"]:
            assert name.lower() == "any" or name in sns["addresses"] or name in sns["groups"] or _builtin(name), name
        for name in rule["ports"] + ([rule["srcport"]] if rule["srcport"] else []):
            assert name in sns["services"], name
    return sns


def _builtin(name: str) -> bool:
    return name.lower() in ("network_internals", "internet", "firewall_all") or name.lower().startswith(("network_", "firewall_"))


def emit(model: Any, options: Optional[Options] = None) -> Tuple[str, Report]:
    from fwshift.emitters import stormshield as emit_stormshield

    report = Report()
    return emit_stormshield.emit(model, report, options or Options()), report


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    from test_iptables import ZONES, random_packet

    from fwshift.model import Action, Zone

    rng = random.Random(seed)
    model = random_model(rng)
    for zone in ZONES:
        model.zones.setdefault(zone, Zone(zone))
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW
    text, report = emit(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    judge = SnsJudge(read_script(text, {}))
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if rng.random() < 0.1:
            pkt.proto = "50"
        if rng.random() < 0.3:
            pkt.dport = rng.choice([79, 81, 442, 444, 7999, 8011, 8999, 9001, 0, 65535])
            pkt.sport = rng.choice([1023, 2001, 1024, 2000])
        assert judge.allows(pkt, pkt.in_if, pkt.out_if) == model_allows(model, pkt), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(60))
def test_a_firewall_read_and_written_again_decides_the_same(seed: int) -> None:
    rng = random.Random(7000 + seed)
    sns = random_sns(rng)
    model, _ = parse(pack(render_files(sns, rng)))
    text, report = emit(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    judge = SnsJudge(read_script(text, sns["interfaces"], sns))
    for _ in range(300):
        found = sns_packet(rng)
        if found is None:
            continue
        pkt, ingress, egress = found
        pkt.in_if, pkt.out_if = ingress, egress
        assert judge.allows(pkt, ingress, egress) == model_allows(model, pkt), (seed, pkt, text)


# -- what is read, and what is not ----------------------------------------------------------------------

NETWORK = """[ethernet0]
Name=out
Protected=0
Address=203.0.113.2
Mask=255.255.255.248

[ethernet1]
Name=in
Protected=1
Address=10.10.0.254
Mask=255.255.255.0
"""


def firewall(rules: str, objects: str = "", **files: str) -> bytes:
    found = {"network": NETWORK, "object": objects, "Filter/slotinfo": "[Global]\nActive=05\n", "Filter/05": "[Filter]\n" + rules}
    found.update({name.replace("__", "/"): text for name, text in files.items()})
    return pack(found)


def verdict(model: Any, src: str, dst: str, proto: str = "tcp", dport: int = 80, ingress: str = "in", egress: str = "out") -> bool:
    return model_allows(model, Packet(ingress, egress, src, dst, proto, 40000, dport, 8))


def test_detection_and_errors() -> None:
    data = (DATA / "stormshield_sample.tgz").read_bytes()
    assert cli.detect_format(data) == "stormshield"
    assert cli.detect_format(pack({"object": "", "Filter/05": "[Filter]\n"}, compress=False)) == "stormshield"
    backup = b"[header]\nmajversion=2\nalgo=1\niv=00\nsalt=00\n".ljust(0x400, b"\0") + b"\x01" * 64
    assert cli.detect_format(backup) == "stormshield"
    with pytest.raises(ParseError, match="decbackup"):
        parse(backup)
    with pytest.raises(FwshiftError, match="compressed"):
        cli.detect_format(gzip.compress(b"hello"))
    with pytest.raises(ParseError, match="more than one firewall"):
        parse(pack({"a/ConfigFiles/object": "", "b/ConfigFiles/object": ""}, prefix=""))
    with pytest.raises(ParseError, match="--policy"):
        parse(pack({"object": "", "Filter/03": "[Filter]\n", "Filter/05": "[Filter]\n"}))
    with pytest.raises(ParseError, match="no filter slot 07"):
        parse(firewall("pass from any to any\n"), slot="7")


def test_slots_by_number_and_name() -> None:
    data = pack({"network": NETWORK, "object": "", "Filter/slotinfo": '[Global]\nActive=5\n\n[05]\nName="Office"\n\n[06]\nName="Lab"\n',
                 "Filter/05": "[Filter]\npass from any to any\n", "Filter/06": "[Filter]\nblock from any to any\n"})  # fmt: skip
    assert verdict(parse(data)[0], "10.10.0.5", "192.0.2.1")
    assert not verdict(parse(data, "6")[0], "10.10.0.5", "192.0.2.1")
    assert not verdict(parse(data, "lab")[0], "10.10.0.5", "192.0.2.1")
    with pytest.raises(ParseError, match="no filter slot is called"):
        parse(data, "nothing")


def test_objects() -> None:
    objects = """[Host]
web=10.20.0.10,resolve=static# web
dual=10.10.0.60,2001:db8:10::60
pool=10.10.0.100-10.10.0.199
updates.example.com=192.0.2.80,resolve=dynamic
odd=not-an-address
[Network]
lan=10.10.0.0/255.255.255.0
lan6=2001:db8:10::/64
[Service]
web_alt=8080-8090/tcp
both=5000/any
bad=99999/tcp
[Protocol]
p200=200
[Fqdn]
www.example.org=192.0.2.90
[Geo]
somewhere=fr
"""
    rules = """pass from LAN to WEB port WEB_ALT
pass from dual to any port both
pass from pool to any
pass from any to updates.example.com
pass from any to odd
pass from any to any port bad
pass from any to somewhere
pass ipproto p200 from lan6 to any
"""
    model, _ = parse(firewall(rules, objects, objectgroup="[servers]\nweb\nnothing_here\n"))
    assert verdict(model, "10.10.0.5", "10.20.0.10", dport=8085) and not verdict(model, "10.10.0.5", "10.20.0.10", dport=8091)
    assert verdict(model, "2001:db8:10::60", "2001:db8:99::1", proto="udp", dport=5000)
    assert verdict(model, "10.10.0.150", "198.51.100.1", dport=22)
    assert model.addresses["updates.example.com"].kind.name == "FQDN" and model.addresses["www.example.org"].kind.name == "FQDN"
    assert [r.unsupported != [] for r in model.rules] == [False, False, False, False, True, True, True, False]
    assert model.address_groups["servers"].unsupported
    assert verdict(model, "2001:db8:10::5", "2001:db8:99::1", proto="200")


def test_rule_grammar() -> None:
    rules = """separator color="c0c0c0" comment="Part" collapse="0"
pass log inspection ips ipproto tcp proto none from in_net on in to any on out port both	# a comment Created on 2026-01-02 03:04:05, by admin (10.10.0.5)
pass from group="staff"@in_net domain corp.example to any
block from ! in_net to any
pass ipproto icmp from any to Firewall_in
pass schedule office from any to any
pass from any on nowhere to any
decrypt from any to any port https
log from any to any
reset from any to any port both
"""
    model, report = parse(firewall(rules, "[Network]\nin_net=10.10.0.0/24\n[Service]\nboth=53/any\n"))
    first = model.rules[0]
    assert first.src_zones == ["in"] and first.dst_zones == ["out"] and first.log_start and first.profiles["inspection"] == "ips"
    assert first.description == "a comment" and first.tags == ["Part"]
    assert verdict(model, "10.10.0.5", "203.0.113.99", proto="tcp", dport=53) and not verdict(model, "10.10.0.5", "203.0.113.99", proto="udp", dport=53, ingress="out")
    assert model.rules[1].users == ["staff@corp.example"]
    assert model.rules[2].negate_source and model.rules[2].action.name == "DROP"
    assert not verdict(model, "192.0.2.1", "203.0.113.99")
    assert model.rules[3].services and verdict(model, "10.10.0.5", "10.10.0.254", proto="icmp")
    assert model.rules[4].unsupported and model.rules[5].unsupported
    assert len(model.rules) == 7 and model.rules[6].action.name == "RESET_CLIENT"
    assert {"STORMSHIELD_IMPLICIT", "STORMSHIELD_SOURCE"} <= codes(report)
    assert "STORMSHIELD_NON_TERMINAL" in codes(report)


def test_global_policy_and_deleg() -> None:
    files = {"Global__Filter__slotinfo": "[Global]\nActive=01\n", "Global__Filter__01": "[Filter]\nblock from bad to any\ndeleg from any to any\n",
             "Global__object": "[Network]\nbad=192.0.2.0/24\n"}  # fmt: skip
    model, report = parse(firewall("pass from any to any\n", **files))
    assert not verdict(model, "192.0.2.5", "203.0.113.99") and verdict(model, "10.10.0.5", "203.0.113.99")
    assert "STORMSHIELD_DELEG" in codes(report)
    files["Global__Filter__01"] = "[Filter]\ndeleg from bad to any\nblock from any to any\n"
    with pytest.raises(ParseError, match="deleg"):
        parse(firewall("pass from any to any\n", **files))
    clash = {"Global__object": "[Network]\nlan=192.0.2.0/24\n"}
    model, _ = parse(firewall("pass from lan to any\n", "[Network]\nlan=10.10.0.0/24\n", **clash))
    assert model.rules[0].unsupported


def test_internals_and_internet() -> None:
    model, report = parse(firewall("pass from Network_internals to Internet port http\n", "[Service]\nhttp=80/tcp\n"))
    assert verdict(model, "10.10.0.5", "203.0.113.99") and not verdict(model, "10.10.0.5", "10.10.0.9") and not verdict(model, "203.0.113.98", "203.0.113.99")
    assert "STORMSHIELD_INTERNALS" in codes(report)


def test_nat_is_said_not_read() -> None:
    model, report = parse(firewall("pass from any to any\n\n[NAT]\nsomething from a to b\n"))
    assert not model.nat_rules and "STORMSHIELD_NAT_NOT_READ" in codes(report)


def test_emitter_slot_prefix_nat_and_defaults() -> None:
    from fwshift.model import ANY, Action, DestNat, NatRule, Rule, SnatKind, SourceNat, Zone

    model = random_model(random.Random(3))
    for zone in ("in", "out"):
        model.zones[zone] = Zone(zone)
    model.rules = [Rule("web", src_zones=["out"], dst_zones=["in"], destinations=["host"], services=["web"], action=Action.ALLOW, origin="web")]
    model.nat_rules = [NatRule("dnat", src_zones=["out"], destinations=["203.0.113.10"], service="web80", origin="dnat",
                               destination_translation=DestNat("10.0.0.17", "8080")),
                       NatRule("masq", src_zones=["in"], dst_zones=["out"], origin="masq", source_translation=SourceNat(SnatKind.INTERFACE, interface="out")),
                       NatRule("none", destinations=[ANY], origin="none")]  # fmt: skip
    from fwshift.model import Protocol, Service, ServiceEntry

    model.services["web80"] = Service("web80", [ServiceEntry(Protocol.TCP, "80")])
    model.default_interzone = model.default_intrazone = Action.ALLOW
    text, report = emit(model, Options(target_policy="4:Office", object_prefix="new-"))
    assert "CONFIG FILTER RULE REMOVE type=filter index=4 position=all" in text and "CONFIG SLOT UPDATE type=filter slot=4 name=Office" in text
    assert "name=new-host" in text and "# CONFIG SLOT ACTIVATE type=filter slot=4" in text
    assert "natsrctarget=Firewall_out natsrcport=ephemeral_fw" in text and "natdsttarget=new-" in text and "natdstport=new-tcp_8080" in text
    assert report.item("nat", "none").disabled or "NAT_NOT_CONVERTED" in {f.code for f in report.item("nat", "none").findings}
    assert text.rstrip().splitlines()[-4].endswith("comment=\"the source allows what no rule matches\"") or "STORMSHIELD_DEFAULT_ALLOW" in codes(report)
    assert {"STORMSHIELD_LOAD", "STORMSHIELD_INTERFACES", "STORMSHIELD_DEFAULT_ALLOW"} <= codes(report)
    with pytest.raises(FwshiftError):
        emit(model, Options(target_policy="11"))
    with pytest.raises(FwshiftError):
        emit(model, Options(object_prefix="1x"))
    model.zones["has space"] = Zone("has space")
    model.rules[0].src_zones = ["has space"]
    text, report = emit(model)
    assert "srcif=has_space" in text and "has space as has_space" in " ".join(n.message for n in report.notes)


def test_sample_converts_to_every_target() -> None:
    data = (DATA / "stormshield_sample.tgz").read_bytes()
    model = cli.load(data, "stormshield", Report())
    assert len(model.rules) >= 12
    for target in sorted(cli.EMITTERS):
        cli.EMITTERS[target](model, Report(), Options())


# -- review round 38 ------------------------------------------------------------------------------------


def test_r38_tos_is_a_match_and_what_a_rule_does_is_said() -> None:
    model, report = parse(firewall("pass tos 8 from any to any\npass settos 24 route gw1 from any to any port http\n", "[Service]\nhttp=80/tcp\n"))
    assert model.rules[0].unsupported and not model.rules[1].unsupported
    assert "STORMSHIELD_HANDLING" in {f.code for f in report.item("rule", model.rules[1].origin).findings}


def test_r38_internet_by_its_own_definition() -> None:
    objects = "[Network]\nlan=10.20.0.0/16\n[Internet]\noperator=ne\nobject=corp\n"
    model, _ = parse(firewall("pass from Internet to any\n", objects, objectgroup="[corp]\nLAN\n"))
    assert not verdict(model, "10.20.0.5", "192.0.2.1") and verdict(model, "10.10.0.5", "192.0.2.1")
    model, _ = parse(firewall("pass from Internet to any\n", objects, objectgroup="[corp]\nlan\nnowhere\n"))
    assert model.rules[0].unsupported
    model, _ = parse(pack({"object": "", "Filter/05": "[Filter]\npass from Internet to any\n"}))
    assert model.rules[0].unsupported  # (no network file: what is internal is not known)


def test_r38_groups_with_members_twice_or_in_themselves() -> None:
    import time

    groups = "[g]\ng\ng\n" + "".join(f"[d{i}]\nd{i + 1}\nd{i + 1}\n" for i in range(30)) + "[d30]\nlan\n"
    started = time.monotonic()
    model, _ = parse(firewall("pass from g to any\npass from d0 to any\n", "[Network]\nlan=10.10.0.0/24\n", objectgroup=groups,
                              servicegroup="[s]\ns\ns\n"))  # fmt: skip
    assert time.monotonic() - started < 5
    assert model.rules[0].unsupported and not model.rules[1].unsupported and verdict(model, "10.10.0.5", "192.0.2.1")
    model, _ = parse(firewall("pass from any to any port s\n", servicegroup="[s]\ns\ns\n"))
    assert model.rules[0].unsupported


def test_r38_archives() -> None:
    corrupt = gzip.compress(pack({"object": "", "Filter/05": "[Filter]\n"}, compress=False))
    corrupt = corrupt[:20] + b"\xff" * 20 + corrupt[40:]
    with pytest.raises(FwshiftError):
        cli.detect_format(corrupt)
    sophos = pack({"Entities.xml": "<Configuration/>", "object": ""}, prefix="", compress=False)
    assert cli.detect_format(sophos) == "sophos"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, text in (("object", ""), ("network", NETWORK), ("Filter/slotinfo", "[Global]\nActive=05\n"), ("Filter/06", "[Filter]\nblock from any to any\n")):
            info = tarfile.TarInfo(name)
            info.size = len(text.encode())
            archive.addfile(info, io.BytesIO(text.encode()))
        link = tarfile.TarInfo("Filter/05")
        link.type, link.linkname = tarfile.LNKTYPE, "Filter/06"
        archive.addfile(link)
    model, _ = parse(raw.getvalue())
    assert not verdict(model, "10.10.0.5", "192.0.2.1")


def test_r38_global_slots_without_an_active_one() -> None:
    with pytest.raises(ParseError, match="global filter slot 01"):
        parse(firewall("pass from any to any\n", Global__Filter__01="[Filter]\nblock from any to any port http\ndeleg from any to any\n"))
    model, _ = parse(firewall("pass from any to any\n", Global__Filter__01="[Filter]\nseparator comment=\"empty\"\n"))
    assert verdict(model, "10.10.0.5", "192.0.2.1")


def test_r38_lists_hosts_lines_and_text() -> None:
    model, _ = parse(firewall("pass from , to h port ,\npass from h to any\npass from n to any\n",
                              "[Host]\nh=10.10.0.5/24\n[Network]\nn=10.10.0.77/24\n"))  # fmt: skip
    assert all(rule.unsupported for rule in model.rules)
    data = firewall("pass from any to srv port http # voir\x85pass from any to any\n", "[Host]\nsrv=10.20.0.10\n[Service]\nhttp=80/tcp\n")
    model, _ = parse(data)
    assert len(model.rules) == 1 and not verdict(model, "10.10.0.5", "192.0.2.1", dport=22)
    with pytest.raises(ParseError, match="before the"):
        parse(pack({"network": NETWORK, "object": "", "Filter/05": "pass from any to any\n[Filter]\n"}))


def test_r38_options_negations_and_users() -> None:
    rules = "pass ipproto icmp ipproto tcp from any to any\npass from ! !lan to any\npass from !user=\"x\"@lan to any\ndeleg from any to any\n"
    model, _ = parse(firewall(rules, "[Network]\nlan=10.10.0.0/24\n"))
    assert len(model.rules) == 4 and all(rule.unsupported for rule in model.rules)
    model, _ = parse(firewall("pass from srv1 to any\npass from odd to any\n", "[Host]\nsrv1=10.10.0.7,resolve=dynamic\nodd=10.10.0.8,foo=bar\n"))
    assert all(rule.unsupported for rule in model.rules)


def test_r38_tags_interface_objects_and_bridges() -> None:
    network = NETWORK + "\n[ethernet2]\nName=lab\nProtected=1\nBridge=bridge0\n\n[bridge0]\nName=labbridge\nProtected=1\nAddress=10.30.0.254\nMask=24\n"
    files = {"Global__Filter__slotinfo": "[Global]\nActive=01\n", "Global__Filter__01": "[Filter]\nseparator comment=\"global part\"\ndeleg from any to any\n"}
    data = pack({"network": network, "object": "", "Filter/slotinfo": "[Global]\nActive=05\n",
                 "Filter/05": "[Filter]\npass from Network_in on lab to firewall_all\n",
                 **{k.replace("__", "/"): v for k, v in files.items()}})  # fmt: skip
    model, report = parse(data)
    assert model.rules[0].tags == []
    found = {f.code for f in report.item("rule", model.rules[0].origin).findings}
    assert {"STORMSHIELD_BRIDGE", "STORMSHIELD_INTERFACE_OBJECTS"} <= found


def test_r38_emitter_names_values_and_nat_order() -> None:
    from fwshift.model import ANY, Action, NatRule, Rule, SnatKind, SourceNat, Zone

    model = random_model(random.Random(9))
    for zone in ("Any", "a b", "a_b"):
        model.zones[zone] = Zone(zone)
    model.rules = [Rule("r1", src_zones=["Any"], dst_zones=["a b"], description="x>y #z", action=Action.ALLOW, origin="r1"),
                   Rule("r2", src_zones=["a_b"], action=Action.ALLOW, origin="r2")]  # fmt: skip
    model.nat_rules = [NatRule("exempt", sources=["10.0.0.0/8"], destinations=["10.0.0.0/8"], origin="exempt"),
                       NatRule("masq", src_zones=["a_b"], dst_zones=["a b"], origin="masq", source_translation=SourceNat(SnatKind.INTERFACE))]  # fmt: skip
    text, report = emit(model)
    assert "srcif=zone_any" in text and "dstif=a_b_2" in text and "srcif=a_b " in text and 'comment="x>y #z"' in text
    assert "NAT_ORDER" in codes(report) and "CONFIG FILTER CHECK" in text
    with pytest.raises(FwshiftError):
        emit(model, Options(object_prefix="Firewall_x"))
    assert ANY


def test_r38_mutation_survivors() -> None:
    from fwshift.model import Action, Protocol, Rule, Service, ServiceEntry, Zone

    rules = ('pass from group="a#b"@lan to any\npass from !any to any\npass from any to any port http,,https\n'
             "pass from any to any port http extra\n")  # fmt: skip
    model, _ = parse(firewall(rules, "[Network]\nlan=10.10.0.0/24\n[Service]\nhttp=80/tcp\nhttps=443/tcp\n"))
    assert model.rules[0].users == ["a#b"] and not model.rules[0].unsupported
    assert all(rule.unsupported for rule in model.rules[1:])
    with pytest.raises(ParseError, match="deleg"):
        parse(firewall("pass from any to any\n", Global__Filter__slotinfo="[Global]\nActive=01\n",
                       Global__Filter__01="[Filter]\nblock from any to any port http\ndeleg from any to lan\n"))  # fmt: skip
    model = random_model(random.Random(11))
    model.zones = {"in": Zone("in"), "out": Zone("out", intrazone_allow=False)}
    model.services["all"] = Service("all", [ServiceEntry(Protocol.IP)])
    model.rules = [Rule("everything", src_zones=["in"], dst_zones=["out"], services=["all"], action=Action.ALLOW, origin="everything")]
    model.default_interzone, model.default_intrazone = Action.DENY, Action.ALLOW
    text, _ = emit(model)
    assert "action=pass srctarget=any srcif=in dsttarget=any dstif=out comment=" in text
    assert 'srcif=in dsttarget=any dstif=in comment="the source passes inside in"' in text and "inside out" not in text
    model.default_interzone = Action.ALLOW
    model.zones["in"].intrazone_allow = True
    text, _ = emit(model)
    assert "action=block srctarget=any srcif=out dsttarget=any dstif=out" in text and text.count("action=pass srctarget=any dsttarget=any") == 1
