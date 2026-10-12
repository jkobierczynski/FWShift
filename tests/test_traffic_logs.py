# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAN-OS and FortiOS traffic logs (0.16.0; docs/RULE_USAGE.md): the readers, attribution by the rule's identifiers,
and the usage of a PAN-OS and a FortiOS policy.

Every log line and configuration here is made up, with documentation and private addresses only.
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from fwshift import cli, hits, usage
from fwshift.logreaders import fortios as fortios_logs
from fwshift.logreaders import panos as panos_logs
from fwshift.model import Policy, Rule
from fwshift.report import Report

DATA = Path(__file__).resolve().parent / "data"
SERIAL = "012801000001"
UUID_A = "6f1c2a10-1111-4aaa-8aaa-000000000001"
UUID_B = "6f1c2a10-2222-4bbb-8bbb-000000000002"


def pan(subtype: str = "end", rule: str = "Allow-Web-Out", uuid: str = "", vsys: str = "vsys1", session: int = 7, action: str = "allow",
        flags: str = "0x400019", repeat: int = 1, proto: str = "tcp", port: int = 443, src: str = "10.10.4.20", dst: str = "203.0.113.200",
        zoned: str = "2026-10-01T12:00:00.000+02:00", fields: int = 115, serial: str = SERIAL, start: str = "2026/10/01 11:59:00",
        user: str = "") -> str:  # fmt: skip
    """A TRAFFIC line in the field order of the PAN-OS documentation (10.2: 115 fields)."""
    out = [""] * fields
    out[0:31] = ["1", "2026/10/01 12:00:00", serial, "TRAFFIC", subtype, "2562", "2026/10/01 12:00:00", src, dst, "", "", rule, user, "",
                 "ssl", vsys, "trust", "untrust", "ethernet1/2", "ethernet1/1", "default", "2026/10/01 12:00:00", str(session), str(repeat),
                 "40000", str(port), "0", "0", flags, proto, action]  # fmt: skip
    if fields > 35:
        out[35] = start
    if fields > 52:
        out[52] = "pa-edge"
    if fields > 65:
        out[65] = uuid
    if fields > 102:
        out[102] = zoned
    return ",".join(out)


def fgt(action: str = "close", policy: int = 1, uuid: str = "", vd: str = "root", session: int = 5, logid: str = "0000000013",
        extra: str = "", time: str = "eventtime=1790848800123456789 tz=\"+0200\"", subtype: str = "forward", kind: str = "traffic",
        proto: int = 6, port: str = "dstport=443") -> str:  # fmt: skip
    polu = f'poluuid="{uuid}" ' if uuid else ""
    return (f'date=2026-10-01 time=12:00:00 devname="fgt-edge" devid="FGT60F0000000001" {time} logid="{logid}" type="{kind}" '
            f'subtype="{subtype}" level="notice" vd="{vd}" srcip=10.10.4.20 srcport=40000 srcintf="port2" dstip=198.51.100.200 {port} '
            f'dstintf="wan1" {polu}sessionid={session} proto={proto} action="{action}" policyid={policy} policytype="policy" '
            f'service="HTTPS" {extra}')


# -- PAN-OS lines ----------------------------------------------------------------------------------


def test_a_pan_os_line_in_its_forms() -> None:
    reader = panos_logs.Reader()
    for text in (pan(), "<14>Oct  1 12:00:00 pa-edge.example.net " + pan(), "<14>1 2026-10-01T12:00:00+02:00 pa-edge - - - - " + pan(),
                 "Oct  1 12:00:00 " + pan()):  # fmt: skip
        record = reader.read_line(text).record
        assert record is not None, text
        assert (record.gateway, record.src, record.dst, record.protocol, record.port, record.action) == (SERIAL, "10.10.4.20", "203.0.113.200", 6, 443, "accept")
        assert record.time == 1790848800 and record.ids == {"panos.name": "Allow-Web-Out", "vsys": "vsys1"}
    assert reader.zoneless == 0
    # The old form, without the high resolution timestamp: local time, read as UTC unless the offset is given.
    old = pan(fields=67, uuid=UUID_A.upper())
    record = reader.read_line(old).record
    assert record is not None and record.time == 1790856000 and reader.zoneless == 1 and record.ids["panos.uuid"] == UUID_A
    record = panos_logs.Reader(offset=120).read_line(old).record
    assert record is not None and record.time == 1790848800
    # The fields of an ICMP error, a quoted category with commas, link switches in braces.
    quoted = pan().replace(",default,", ',"a,b,c",').replace(",,,,,,2026-10-01T", ",{x, y, z},,,,,2026-10-01T")
    record = reader.read_line(quoted).record
    assert record is not None and record.time == 1790848800
    icmp = reader.read_line(pan(proto="icmp", port=0)).record
    assert icmp is not None and (icmp.protocol, icmp.port) == (1, None)


def test_what_a_pan_os_line_counts_for() -> None:
    reader = panos_logs.Reader()
    drop = reader.read_line(pan(subtype="drop", action="drop", repeat=4, session=0)).record
    assert drop is not None and drop.action == "drop" and drop.count == 4
    reset = reader.read_line(pan(subtype="deny", action="reset-both")).record
    assert reset is not None and reset.action == "drop"
    temporary = reader.read_line(pan(flags="0x402019")).record
    assert temporary is not None and temporary.possible  # (a temporary match for an application dependency)
    start = reader.read_line(pan(subtype="start")).record
    assert start is not None and start.possible  # (a start on its own: the rule may have been left)
    user = reader.read_line(pan(user="example\\alice")).record
    assert user is not None and user.users == ["example\\alice"]
    cases = {
        pan().replace(",TRAFFIC,", ",THREAT,"): ("another type", False),
        pan(subtype="info"): ("no connection", False),
        pan(rule="", uuid=""): ("names no rule", True),
        pan()[:120]: ("cannot be read", True),
        "Domain,Receive Time,Serial #,Type,Threat/Content Type": ("header of a CSV export", False),
        "<14>Oct  1 12:00:00 pa CEF:0|Palo Alto Networks|PAN-OS|10.2|end|TRAFFIC|1|rt=...": ("CEF", True),
        "Oct  1 12:00:00 host sshd[1]: Accepted publickey": ("not a PAN-OS log", False),
        pan().replace("2026/10/01 12:00:00", "2026/13/01 12:00:00").replace("2026-10-01T12:00:00.000+02:00", ""): ("time", True),
    }
    for text, (reason, doubt) in cases.items():
        got = reader.read_line(text)
        assert got.record is None and reason in got.reason and got.doubt == doubt, (text[:80], got)
    exported = ",".join(f'"{field}"' for field in pan().split(","))
    record = reader.read_line(exported).record
    assert record is not None and record.ids["panos.name"] == "Allow-Web-Out"


def test_starts_and_ends_of_one_session() -> None:
    lines = [pan(subtype="start", session=1), pan(session=1),  # one connection
             pan(subtype="start", session=2), pan(subtype="start", session=2, rule="Web-Apps"), pan(session=2, rule="Web-Apps"),  # the application changed
             pan(subtype="start", session=3, rule="Mail")]  # still open: possible  # fmt: skip
    read = list(panos_logs.Reader().read("\n".join(lines).encode()))
    records = [line.record for line in read if line.record is not None]
    assert [(r.ids["panos.name"], r.possible) for r in records] == [("Allow-Web-Out", False), ("Allow-Web-Out", False), ("Web-Apps", False),
                                                                    ("Mail", True)]  # fmt: skip
    assert sum("counted once" in line.reason for line in read) == 2 and len(read) == len(lines)


# -- FortiOS lines ---------------------------------------------------------------------------------


def test_a_fortios_line_in_its_forms() -> None:
    reader = fortios_logs.Reader()
    record = reader.read_line(fgt(uuid=UUID_A.upper())).record
    assert record is not None and record.time == 1790848800 and record.gateway == "fgt-edge"
    assert (record.src, record.dst, record.protocol, record.port, record.action) == ("10.10.4.20", "198.51.100.200", 6, 443, "accept")
    assert record.ids == {"fortios.policyid": "1", "fortios.uuid": UUID_A, "vdom": "root"}
    for time, expected in (('eventtime=1790848800 ', 1790848800), ('eventtime=1790848800123 ', 1790848800), ('tz="+0200"', 1790848800),
                           ('tz="-0500"', 1790874000), ('tz="UTC+2:00"', 1790848800), ("", 1790856000)):  # fmt: skip
        record = fortios_logs.Reader().read_line(fgt(time=time)).record
        assert record is not None and record.time == expected, time
    zoneless = fortios_logs.Reader(offset=120)
    record = zoneless.read_line(fgt(time='tz="CEST"')).record
    assert record is not None and record.time == 1790848800
    behind = fortios_logs.Reader().read_line("<189>Oct  1 12:00:00 fgt-edge " + fgt()).record
    forwarded = fortios_logs.Reader().read_line('logver=702111740 timestamp=1790848800 devname="fgt-edge" devid="FGT60F0000000001" vd="root" ' + fgt())
    assert behind is not None and forwarded.record is not None and forwarded.record.gateway == "fgt-edge"
    escaped = fortios_logs.Reader().read_line(fgt(extra='msg="a \\"quoted\\" policyid=99 word" user="example\\\\bob"')).record
    assert escaped is not None and escaped.ids["fortios.policyid"] == "1" and escaped.users == ["example\\bob"]
    icmp = fortios_logs.Reader().read_line(fgt(proto=1, port='icmptype="0x08" icmpcode="0x00"')).record
    assert icmp is not None and (icmp.protocol, icmp.port) == (1, 8)


def test_what_a_fortios_line_counts_for() -> None:
    reader = fortios_logs.Reader()
    for action, verdict in (("accept", "accept"), ("close", "accept"), ("timeout", "accept"), ("server-rst", "accept"), ("ip-conn", "accept"),
                            ("deny", "drop")):  # fmt: skip
        record = reader.read_line(fgt(action=action)).record
        assert record is not None and record.action == verdict, action
    cases = {
        fgt(subtype="local"): ("FortiGate itself", False),
        fgt(subtype="multicast"): ("another kind than forward", False),
        fgt(kind="event"): ("another type", False),
        fgt(logid="0000000020"): ("interim statistics", False),
        fgt().replace('policytype="policy"', 'policytype="local-in-policy"'): ("another kind of policy", False),
        fgt().replace("policyid=1 ", ""): ("names no policy", True),
        fgt(time="").replace("date=2026-10-01", "date=2026-10-41"): ("time", True),
        "<189>CEF:0|Fortinet|Fortigate|v7.2.0|00013|traffic:forward close|3|src=10.10.4.20": ("CEF", True),
        "Oct  1 12:00:00 host sshd[1]: Accepted publickey": ("not a FortiOS log", False),
    }
    for text, (reason, doubt) in cases.items():
        got = reader.read_line(text)
        assert got.record is None and reason in got.reason and got.doubt == doubt, (text[:80], got)
    lines = [fgt(action="start", logid="0000000015"), fgt(), fgt(action="start", session=6, logid="0000000015")]
    read = list(fortios_logs.Reader().read("\n".join(lines).encode()))
    assert [line.record is not None for line in read] == [False, True, True] and "counted once" in read[0].reason


# -- attribution by the identifiers ----------------------------------------------------------------


def _policy(vendor: str, rules: List[Tuple[str, Dict[str, str]]], scope: str = "") -> Policy:
    p = Policy(vendor=vendor, scope=scope)
    for name, ids in rules:
        rule = Rule(name=name)
        rule.origin = name
        rule.source_ids = dict(ids)
        rule.log_end = True
        rule.changed = 1700000000
        p.rules.append(rule)
    return p


def _reference(vendor: str, p: Policy, ids: Dict[str, str]) -> Optional[str]:
    """What a line names, by reading the rules one by one: the UUID decides where both have one; else the name or ID."""
    weak = "panos.name" if vendor == "panos" else "fortios.policyid"
    strong = "panos.uuid" if vendor == "panos" else "fortios.uuid"
    if ids.get(strong):
        for rule in p.rules:
            if rule.source_ids.get(strong, "").lower() == ids[strong].lower():
                return rule.name
    for rule in p.rules:
        theirs = rule.source_ids.get(strong, "").lower()
        if ids.get(weak) and rule.source_ids.get(weak) == ids[weak] and (not theirs or not ids.get(strong) or theirs == ids[strong].lower()):
            return rule.name
    return None


@pytest.mark.parametrize("seed", range(20))
def test_attribution_by_identifiers_against_a_reference(seed: int) -> None:
    rng = random.Random(seed)
    for vendor, weak, strong in (("panos", "panos.name", "panos.uuid"), ("fortios", "fortios.policyid", "fortios.uuid")):
        uuids = [f"{rng.getrandbits(32):08x}-0000-4000-8000-{n:012x}" for n in range(8)]
        names = [f"r{n}" if vendor == "panos" else str(n + 1) for n in range(8)]
        rules = []
        for n in range(6):
            ids = {weak: names[n]}
            if rng.random() < 0.6:
                ids[strong] = uuids[n]
            rules.append((f"rule {n}", ids))
        p = _policy(vendor, rules)
        finder = usage._Ids(p)
        for _ in range(60):
            ids = {}
            if rng.random() < 0.8:
                ids[weak] = rng.choice(names)
            if rng.random() < 0.5:
                ids[strong] = rng.choice(uuids).upper() if rng.random() < 0.3 else rng.choice(uuids)
            if not ids:
                continue
            found, reason, by_uuid = finder.find(ids)
            expected = _reference(vendor, p, ids)
            assert [rule.name for rule in found] == ([expected] if expected else []), (vendor, ids, reason)
            assert by_uuid == bool(found and ids.get(strong) and found[0].source_ids.get(strong, "").lower() == ids[strong].lower())
            assert found or reason


def test_where_a_line_is_not_of_this_policy() -> None:
    pan_policy = _policy("panos", [("Web", {"panos.name": "Web"}), ("Off", {"panos.name": "Off"})], scope="vsys1")
    pan_policy.rules[1].enabled = False
    finder = usage._Ids(pan_policy)
    assert "another virtual system" in finder.find({"panos.name": "Web", "vsys": "vsys2"})[1]
    assert finder.find({"panos.name": "Web", "vsys": "vsys1"})[0] == [pan_policy.rules[0]]
    assert "default rule" in finder.find({"panos.name": "interzone-default"})[1]
    assert "disabled" in finder.find({"panos.name": "Off"})[1]
    assert "does not have" in finder.find({"panos.name": "Gone"})[1]
    panorama = _policy("panos", [("Web", {"panos.name": "Web"})], scope="device-group branches")
    assert usage._Ids(panorama).find({"panos.name": "Web", "vsys": "vsys3"})[0]  # (a device group's rules run in any vsys)
    forti = _policy("fortios", [("p1", {"fortios.policyid": "1"})])
    finder = usage._Ids(forti)
    assert finder.find({"fortios.policyid": "1", "vdom": "root"})[0] and "another VDOM" in finder.find({"fortios.policyid": "1", "vdom": "dmz"})[1]
    assert "implicit deny" in finder.find({"fortios.policyid": "0"})[1]
    vdom = _policy("fortios", [("p1", {"fortios.policyid": "1"})], scope="tenant1")
    assert "another VDOM" in usage._Ids(vdom).find({"fortios.policyid": "1", "vdom": "root"})[1]


# -- the usage of a PAN-OS and a FortiOS policy ----------------------------------------------------


def _usage(sample: str, args: List[str], capsys: pytest.CaptureFixture[str], log: str = "") -> str:
    config, logs = {"panos": ("panos_logged.xml", "panos_logged.log"), "fortios": ("fortios_sample.conf", "fortios_sample.log")}[sample]
    assert cli.main(["usage", str(DATA / config), "--logs", log or str(DATA / logs), *args]) == 0
    return capsys.readouterr().out


@pytest.mark.parametrize("sample", ["panos", "fortios"])
def test_the_samples_match_their_golden_files(sample: str, capsys: pytest.CaptureFixture[str]) -> None:
    text = _usage(sample, ["--unchanged-since", "2026-01-01"], capsys).replace(str(DATA) + os.sep, "")
    out = DATA / "expected" / {"panos": "panos_logged.usage.txt", "fortios": "fortios_sample.usage.txt"}[sample]
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        out.write_text(text, encoding="utf-8")
    assert text == out.read_text(encoding="utf-8")


def test_what_the_pan_os_sample_shows(capsys: pytest.CaptureFixture[str]) -> None:
    data = json.loads(_usage("panos", ["--unchanged-since", "2026-01-01", "--json"], capsys))
    rules = {rule["name"]: rule for rule in data["rules"]}
    assert rules["Inbound-Web"]["connections"] == 30  # (start and end of one session: once)
    assert rules["Allow-Web-Out"]["connections"] == 91 and rules["App-Server-Ports"]["connections"] == 14  # (the application changed once)
    assert rules["Inbound-Mail"]["connections"] == 13 and rules["Inbound-Mail"]["possible"] == 1
    assert rules["Block-Region"]["connections"] == 39  # (13 lines of 3 sessions)
    assert rules["Tagged-Servers-Updates"]["connections"] == 0 and rules["Tagged-Servers-Updates"]["possible"] == 9
    found = {(f["check"], f["name"]) for f in data["findings"]}
    assert ("UNUSED_RULE", "Engineering to PLCs") in found and ("NO_USAGE_EVIDENCE", "Not-From-Guests") in found
    assert "no log forwarding profile" in {f["name"]: f["message"] for f in data["findings"]}["Not-From-Guests"]
    assert ("NO_USAGE_EVIDENCE", "Tagged-Servers-Updates") in found and not any(name == "Inbound-Mail" for _, name in found)
    assert data["connections"]["not_attributed"]["a line of another virtual system (vsys2)"] == 90
    # Without the age of the rules nothing is called unused; the hit counters of the firewall give it.
    text = _usage("panos", [], capsys)
    assert "UNUSED_RULE:" not in text and "give the day with --unchanged-since" in text


def test_pan_os_hit_counters_give_the_age_of_the_rules(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    entries = "".join(f"<entry name=\"{name}\"><hit-count>0</hit-count><last-hit-timestamp>0</last-hit-timestamp>"
                      f"<rule-creation-timestamp>1760000000</rule-creation-timestamp><rule-modification-timestamp>{changed}"
                      "</rule-modification-timestamp></entry>"
                      for name, changed in (("Engineering to PLCs", 1770000000), ("Not-From-Guests", 1785000000)))  # fmt: skip
    answer = tmp_path / "hits.xml"
    answer.write_text(f'<response status="success"><result><rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="security">'
                      f"<rules>{entries}</rules></entry></rule-base></entry></vsys></rule-hit-count></result></response>", encoding="utf-8")  # fmt: skip
    data = json.loads(_usage("panos", ["--hits", str(answer), "--json"], capsys))
    found = {f["name"]: f for f in data["findings"] if f["check"] in ("UNUSED_RULE", "NO_USAGE_EVIDENCE")}
    assert found["Engineering to PLCs"]["check"] == "UNUSED_RULE"  # (unchanged since 2026-02-02)
    assert "after the window began" in found["Not-From-Guests"]["message"]  # (changed on 2026-07-25, within the window)
    p = cli.load((DATA / "panos_logged.xml").read_bytes(), "panos", Report())
    hits.apply(p, answer.read_bytes(), "hits.xml")
    assert {r.name: r.changed for r in p.rules if r.changed} == {"Engineering to PLCs": 1770000000, "Not-From-Guests": 1785000000}


def test_what_the_fortios_sample_shows(capsys: pytest.CaptureFixture[str]) -> None:
    data = json.loads(_usage("fortios", ["--unchanged-since", "2026-01-01", "--json"], capsys))
    rules = {rule["name"]: rule for rule in data["rules"]}
    assert rules["LAN to Internet"]["connections"] == 183  # (90 + 90 + the three lines of FortiOS 6.0; no interim statistics)
    assert rules["Inbound web"]["connections"] == 30 and rules["Inbound web"]["members"]["destination"] == {"vip-web": 30}
    assert rules["OT no internet"]["connections"] == 13 and rules["policy-12"]["connections"] == 9
    found = {(f["check"], f["name"]) for f in data["findings"]}
    assert ("UNUSED_RULE", "SCADA to PLCs") in found and ("NO_USAGE_EVIDENCE", "Inbound mail") in found
    assert data["connections"]["not_attributed"] == {"a line of another VDOM (tenant2)": 90,
                                                     "the implicit deny of the policy (policy ID 0): no rule": 22}  # fmt: skip


def test_the_lines_of_several_firewalls(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """A policy ID or a rule name is only this policy's when the line is of a firewall the policy is on."""
    log = tmp_path / "two.log"
    log.write_text((DATA / "fortios_sample.log").read_text(encoding="utf-8") + "\n".join(
        fgt(policy=8, session=900 + n).replace("fgt-edge", "fgt-branch").replace("eventtime=1790848800", f"eventtime={1783080000 + n * 86400}")
        for n in range(3)) + "\n", encoding="utf-8")  # fmt: skip
    data = json.loads(_usage("fortios", ["--unchanged-since", "2026-01-01", "--json"], capsys, str(log)))
    rules = {rule["name"]: rule for rule in data["rules"]}
    assert rules["SCADA to PLCs"]["connections"] == 0 and rules["SCADA to PLCs"]["possible"] == 3
    assert rules["LAN to Internet"]["connections"] == 183  # (by its UUID: certain whoever logged it)
    assert "2 firewalls" in data["connections"]["possible_only_because"][0]
    data = json.loads(_usage("fortios", ["--unchanged-since", "2026-01-01", "--json", "--gateway", "fgt-edge"], capsys, str(log)))
    rules = {rule["name"]: rule for rule in data["rules"]}
    assert rules["SCADA to PLCs"]["connections"] == 0 and "possible" not in rules["SCADA to PLCs"]
    assert data["connections"]["not_attributed"]["a line from a host that is not among the gateways given (--gateway)"] == 3
    assert ("UNUSED_RULE", "SCADA to PLCs") in {(f["check"], f["name"]) for f in data["findings"]}


def test_panorama_targets_by_serial_number(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    p = _policy("panos", [("Web", {"panos.name": "Web", "panos.uuid": UUID_A}), ("Mail", {"panos.name": "Mail"})], scope="device-group dg")
    for rule in p.rules:
        rule.targets = [SERIAL]
    store = usage.Store(":memory:")
    lines = "\n".join(pan(rule="Mail", session=n, serial=other, zoned=f"2026-10-{1 + n:02d}T12:00:00.000+02:00")
                      for n, other in enumerate([SERIAL, "012801000009"]))  # fmt: skip
    usage.ingest(store, [("a.log", lines.encode())], kind="panos")
    usage.evaluate(p, store, usage.window(store), gateways=[f"pa-edge={SERIAL}"])
    mail = p.rules[1].log_usage
    assert mail is not None and mail.connections == 1 and mail.gateways == ["pa-edge"]
    store.close()


def test_a_split_rule_of_pan_os_counts_as_one(capsys: pytest.CaptureFixture[str]) -> None:
    p = _policy("panos", [("Web", {"panos.name": "Web"}), ("Web-2", {"panos.name": "Web"})])
    p.rules[0].sources, p.rules[1].sources = ["10.10.0.0/16"], ["10.20.0.0/16"]
    store = usage.Store(":memory:")
    usage.ingest(store, [("a.log", pan(rule="Web").encode())], kind="panos")
    usage.evaluate(p, store, usage.window(store))
    assert p.rules[0].log_usage is not None and p.rules[0].log_usage.connections == 1
    assert p.rules[1].log_usage is not None and p.rules[1].log_usage.shared == 1
    store.close()


# -- review round 24 ------------------------------------------------------------------------------------


def _evaluate(p: Policy, lines: List[str], kind: str, gateways: List[str] = ()) -> usage.Evaluation:  # type: ignore[assignment]
    store = usage.Store(":memory:")
    usage.ingest(store, [("a.log", "\n".join(lines).encode())], kind=kind)
    result = usage.evaluate(p, store, usage.window(store, "30d"), gateways=gateways)
    store.close()
    return result


def _days(make: Any, days: int = 30) -> List[str]:
    return [make(day) for day in range(days)]


def test_r24_the_lines_of_a_target_not_given_still_count() -> None:
    other = "012801000009"
    p = _policy("panos", [("Web", {"panos.name": "Web"}), ("Mail", {"panos.name": "Mail"})], scope="device-group dg")
    p.rules[0].targets, p.rules[1].targets = [other], [SERIAL]
    for rule in p.rules:
        rule.handling["log-setting"] = "to-syslog"
    lines = _days(lambda d: pan(rule="Mail", session=d + 1, zoned=f"2026-09-{1 + d:02d}T12:00:00.000+02:00"))
    lines += _days(lambda d: pan(rule="Mail", session=d + 100, serial=other, zoned=f"2026-09-{1 + d:02d}T12:00:00.000+02:00"))
    lines += [pan(rule="Web", session=500 + d, serial=other, zoned=f"2026-09-0{1 + d}T13:00:00.000+02:00") for d in range(3)]
    _evaluate(p, lines, "panos", [SERIAL])
    web = p.rules[0].log_usage
    assert web is not None and web.connections == 3  # (the other firewall is a target of the rule: its lines are its connections)
    assert p.rules[1].log_usage is not None and p.rules[1].log_usage.connections == 30


def test_r24_a_virtual_ip_on_either_side(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    # Port forwarding: the log's port is the original one, the policy names the mapped one.
    text = (DATA / "fortios_sample.log").read_text(encoding="utf-8")
    log = tmp_path / "vip.log"
    log.write_text(text.replace('dstport=8443 dstintf="dmz"', 'dstport=443 dstintf="dmz"').replace(
        'service="tcp/8443" trandisp="noop"', 'service="tcp/8443" trandisp="dnat" tranip=10.20.0.10 tranport=8443'), encoding="utf-8")  # fmt: skip
    data = json.loads(_usage("fortios", ["--unchanged-since", "2026-01-01", "--json"], capsys, str(log)))
    rules = {rule["name"]: rule for rule in data["rules"]}
    assert rules["Inbound web"]["members"]["service"] == {"app-ports": 30}
    assert not [f for f in data["findings"] if f["name"] == "Inbound web"]
    # Central NAT: the policy names the mapped address, the log has the external one first.
    from fwshift.model import Address, AddressKind

    p = _policy("fortios", [("Inbound web", {"fortios.policyid": "3"})])
    p.addresses = {"web-1": Address("web-1", AddressKind.NETWORK, "10.20.0.10/32"), "web-2": Address("web-2", AddressKind.NETWORK, "10.20.0.11/32")}
    p.rules[0].destinations = ["web-1", "web-2"]
    line = fgt(policy=3, extra='trandisp="dnat" tranip=10.20.0.10 tranport=443').replace("dstip=198.51.100.200", "dstip=203.0.113.10")
    _evaluate(p, [line], "fortios")
    log_usage = p.rules[0].log_usage
    assert log_usage is not None and log_usage.members["destination"] == {"web-1": 1, "web-2": 0}


def test_r24_a_session_id_taken_again_is_another_session() -> None:
    lines = [fgt(action="start", policy=3, session=100, logid="0000000015"), fgt(policy=5, session=100).replace("srcip=10.10.4.20", "srcip=10.10.4.21")]
    read = list(fortios_logs.Reader().read("\n".join(lines).encode()))
    assert sorted(line.record.ids["fortios.policyid"] for line in read if line.record is not None) == ["3", "5"]


def test_r24_logs_that_name_no_rule_of_this_policy_prove_nothing() -> None:
    p = _policy("fortios", [("p1", {"fortios.policyid": "1"})])
    _evaluate(p, _days(lambda d: fgt(policy=77, session=d + 1, time=f"eventtime={1788000000 + d * 86400}")), "fortios")
    assert p.rules[0].log_usage is not None and any("names a rule of this policy" in why for why in p.rules[0].log_usage.no_evidence)
    p = _policy("panos", [("Web", {"panos.name": "Web"})], scope="vsys1")
    p.rules[0].handling["log-setting"] = "to-syslog"
    _evaluate(p, _days(lambda d: pan(rule="intrazone-default", session=d + 1, zoned=f"2026-09-{1 + d:02d}T12:00:00.000+02:00")), "panos")
    assert p.rules[0].log_usage is not None and not p.rules[0].log_usage.no_evidence  # (the default rule is of this policy: the logs are)


def test_r24_the_days_of_another_virtual_system_prove_nothing() -> None:
    p = _policy("panos", [("Web", {"panos.name": "Web"}), ("Mail", {"panos.name": "Mail"})], scope="vsys1")
    for rule in p.rules:
        rule.handling["log-setting"] = "to-syslog"
    lines = [pan(rule="Web", session=1, zoned="2026-09-01T12:00:00.000+02:00")]
    lines += _days(lambda d: pan(rule="Other", vsys="vsys2", session=d + 10, zoned=f"2026-09-{1 + d:02d}T12:00:00.000+02:00"))
    result = _evaluate(p, lines, "panos")
    mail = p.rules[1].log_usage
    assert mail is not None and any("sent logs on 1 of the 30 days" in why for why in mail.no_evidence), mail.no_evidence
    assert result.gateways[SERIAL] == (1, 0)


def test_r24_a_time_that_cannot_be_right() -> None:
    store = usage.Store(":memory:")
    done = usage.ingest(store, [("a.log", (pan(zoned="0268-10-01T12:00:00.000+02:00").replace("2026/10/01", "0268/10/01") + "\n" + pan(session=2)).encode())],
                        kind="panos")  # fmt: skip
    assert done.skipped == {"a time before 2000 or after 2099": 1} and store.days() == ("2026-10-01", "2026-10-01")
    assert usage.window(store).first == "2026-07-04"
    store.close()


def test_r24_the_latest_change_of_several_firewalls(tmp_path: Any) -> None:
    p = cli.load((DATA / "panos_logged.xml").read_bytes(), "panos", Report())
    for changed in (1790000000, 1770000000):
        answer = (f'<response status="success"><result><rule-hit-count><vsys><entry name="vsys1"><rule-base><entry name="security"><rules>'
                  f'<entry name="Allow-DNS"><hit-count>1</hit-count><rule-modification-timestamp>{changed}</rule-modification-timestamp></entry>'
                  "</rules></entry></rule-base></entry></vsys></rule-hit-count></result></response>")  # fmt: skip
        hits.apply(p, answer.encode(), "hits.xml")
    assert next(rule for rule in p.rules if rule.name == "Allow-DNS").changed == 1790000000


def test_r24_fortios_odds() -> None:
    record = fortios_logs.Reader().read_line("<189>1 2026-10-01T10:00:00Z fgt-edge - - - " + fgt(time="eventtime=1790848800").split(" ", 2)[2]).record
    assert record is not None and record.time == 1790848800  # (no date=: the eventtime is enough)
    conf = (b"config firewall policy\n edit 1\n  set srcintf port2\n  set dstintf wan1\n  set srcaddr all\n  set dstaddr all\n"
            b"  set action accept\n  set schedule always\n  set service ALL\n  set logtraffic disable\n  set logtraffic-start enable\n next\n"
            b" edit 2\n  set srcintf port2\n  set dstintf wan1\n  set srcaddr all\n  set dstaddr all\n  set action accept\n  set schedule always\n"
            b"  set service ALL\n  set logtraffic-start enable\n next\nend\n")  # fmt: skip
    p = cli.load(conf, "fortios", Report())
    assert [(r.log_start, r.log_end) for r in p.rules] == [(False, False), (True, False)]
    _evaluate(p, _days(lambda d: fgt(policy=2, session=d + 1, time=f"eventtime={1788000000 + d * 86400}")), "fortios")
    assert p.rules[1].log_usage is not None and p.rules[1].log_usage.connections == 30
    assert p.rules[0].log_usage is not None and "does not log its connections" in p.rules[0].log_usage.no_evidence[0]
    unknown = _policy("fortios", [("p1", {"fortios.policyid": "1"})])
    unknown.rules[0].log_start, unknown.rules[0].log_end = True, False
    _evaluate(unknown, _days(lambda d: fgt(policy=2, session=d + 1, time=f"eventtime={1788000000 + d * 86400}")), "fortios")
    assert unknown.rules[0].log_usage is not None and "logtraffic utm" in unknown.rules[0].log_usage.no_evidence[0]
    numeric = panos_logs.Reader().read_line(pan(proto="50")).record
    assert numeric is not None and numeric.protocol == 50
