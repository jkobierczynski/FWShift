# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Simulated attribution (0.15.0; docs/RULE_USAGE.md 6.5): the first rule a connection meets, certain or possible.

Every log line and ruleset here is made up, with documentation and private addresses only.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
from pathlib import Path
from typing import Any, List, Optional, Set

import pytest
from test_iptables import Packet, _entry_matches, _member_matches, random_model, random_packet

from fwshift import audit, cli, simulate, transform, usage
from fwshift.errors import FwshiftError
from fwshift.logreaders import iptables as iptables_logs
from fwshift.model import ANY, Action, Policy, Rule, RuleScope
from fwshift.report import Report

DATA = Path(__file__).resolve().parent / "data"
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}


# -- the simulator against a walk through the rules -------------------------------------------------


def _base_matches(p: Policy, rule: Rule, pkt: Packet) -> bool:
    """Zones, addresses and services, as the model says; nothing else."""
    zone_ok = (ANY in rule.src_zones or pkt.in_if in rule.src_zones) and (ANY in rule.dst_zones or pkt.out_if in rule.dst_zones)
    if rule.scope == RuleScope.INTRAZONE:
        zone_ok = pkt.in_if == pkt.out_if and (ANY in rule.src_zones or pkt.in_if in rule.src_zones)
    elif rule.scope == RuleScope.INTERZONE:
        zone_ok = zone_ok and pkt.in_if != pkt.out_if
    if not zone_ok:
        return False
    if any(_member_matches(p, m, pkt.src) for m in rule.sources) == rule.negate_source:
        return False
    if any(_member_matches(p, m, pkt.dst) for m in rule.destinations) == rule.negate_destination:
        return False
    if rule.services == [ANY]:
        service_ok = True
    else:
        entries = [e for s in rule.services for e in (transform.flatten_services(p, s) or [])]
        service_ok = any(_entry_matches(e, pkt) for e in entries)
    return service_ok != rule.negate_service


def _first(p: Policy, pkt: Packet, world: Set[str]) -> Optional[str]:
    """The rule that decides, in a world where the rules in ``world`` that the model holds approximately do match."""
    for rule in p.rules:
        if not rule.enabled or not _base_matches(p, rule, pkt):
            continue
        inexact = bool(rule.unsupported) or rule.users != [ANY] or bool(rule.schedule)
        if inexact and rule.name not in world:
            continue
        return rule.name
    return None


@pytest.mark.parametrize("seed", range(30))
def test_certain_is_what_every_world_gives_and_possible_holds_the_rest(seed: int) -> None:
    """Oracle: whatever the rules the model holds approximately do, the certain rule decides; what decides is never left out."""
    rng = random.Random(seed)
    p = random_model(rng)
    for rule in p.rules:
        roll = rng.random()
        if roll < 0.1:
            rule.unsupported.append("a criterion the model does not hold")
        elif roll < 0.15:
            rule.users = ["someone"]
        elif roll < 0.2:
            rule.schedule = "work-hours"
    sim = simulate.Simulator(p)
    inexact = [r.name for r in p.rules if r.unsupported or r.users != [ANY] or r.schedule]
    worlds = [set(), set(inexact)] + [{name for name in inexact if rng.random() < 0.5} for _ in range(4)]
    for _ in range(300):
        family = rng.choice([4, 6])
        pkt = random_packet(rng, family)
        if rng.random() < 0.1:
            pkt.out_if = "eth9"  # an interface no rule names
        known_zones = rng.random() > 0.1
        proto = NUMBERS.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        port: Optional[int] = pkt.dport if proto in (6, 17) else pkt.icmp_type if proto in (1, 58) else None
        if rng.random() < 0.1:
            port = rng.choice([None, -1])  # a port the log does not give, either way it says so
        src = pkt.src
        if rng.random() < 0.1:
            # A store keeps addresses beyond its cap as their network: the packet's address is one of it.
            src = str(ipaddress.ip_network(f"{pkt.src}/{24 if family == 4 else 64}", strict=False))
        point = (pkt.in_if if known_zones else "", pkt.out_if if known_zones else "", src, pkt.dst, proto, port)
        answer = sim.attribute(point)
        offered = {r.name for r in answer.possible} | ({answer.certain.name} if answer.certain else set())
        for world in worlds:
            truth = _first(p, pkt, world)
            if answer.certain is not None:
                assert truth == answer.certain.name, (seed, pkt, world, truth, answer)
            elif truth is not None:
                assert truth in offered, (seed, pkt, world, truth, answer)
            else:
                assert answer.certain is None


def test_the_verdict_of_the_log_must_agree() -> None:
    rng = random.Random(3)
    p = random_model(rng)
    sim = simulate.Simulator(p)
    for _ in range(300):
        pkt = random_packet(rng)
        proto = NUMBERS.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
        point = (pkt.in_if, pkt.out_if, pkt.src, pkt.dst, proto, pkt.dport if proto in (6, 17) else None)
        for action in ("accept", "drop"):
            answer = sim.attribute(point, action)
            for rule in ([answer.certain] if answer.certain else []) + answer.possible:
                assert (rule.action == Action.ALLOW) == (action == "accept")


# -- the iptables LOG lines ---------------------------------------------------------------------------


def test_kernel_lines_in_their_forms() -> None:
    reader = iptables_logs.Reader(year=2026, offset=120)
    line = reader.read_line("Oct  1 12:00:00 fw1 kernel: [99.1] fw-new IN=eth1 OUT=eth0 MAC=aa:bb SRC=10.10.4.20 DST=192.0.2.53 LEN=60 "
                            "PROTO=UDP SPT=53001 DPT=53 LEN=40")  # fmt: skip
    record = line.record
    assert record is not None and (record.gateway, record.in_zone, record.out_zone, record.protocol, record.port) == ("fw1", "eth1", "eth0", 17, 53)
    assert record.time == 1790848800  # 2026-10-01 12:00 at +02:00 is 10:00 UTC
    iso = iptables_logs.Reader().read_line("2026-10-01T12:00:00.5+0200 fw1 kernel: x IN=eth1 OUT=eth2 SRC=2001:db8::5 DST=2001:db8::10 "
                                           "LEN=104 TC=0 HOPLIMIT=63 FLOWLBL=0 PROTO=ICMPv6 TYPE=128 CODE=0 ID=1 SEQ=1").record  # fmt: skip
    assert iso is not None and (iso.src, iso.protocol, iso.port, iso.time) == ("2001:db8::5", 58, 128, 1790848800)
    error = reader.read_line("Oct  1 12:00:00 fw1 kernel: IN=eth2 OUT=eth0 SRC=10.20.0.5 DST=192.0.2.1 LEN=60 PROTO=ICMP TYPE=3 CODE=3 "
                             "[SRC=192.0.2.1 DST=10.20.0.5 LEN=60 PROTO=UDP SPT=53 DPT=40000 LEN=40]").record  # fmt: skip
    assert error is not None and (error.src, error.protocol, error.port) == ("10.20.0.5", 1, 3)  # (not the quoted packet)
    gre = reader.read_line("Oct  1 12:00:00 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.10.4.24 DST=198.51.100.5 LEN=60 PROTO=47").record
    assert gre is not None and (gre.protocol, gre.port) == (47, None)


def test_what_is_no_forwarded_connection() -> None:
    reader = iptables_logs.Reader(year=2026)
    cases = {
        "Oct  1 12:00:00 fw1 kernel: IN=eth1 OUT= SRC=10.10.4.20 DST=10.10.4.1 PROTO=TCP SPT=1 DPT=22": ("firewall itself", False),
        "Oct  1 12:00:00 fw1 systemd[1]: Started something.": ("not a line of an iptables LOG rule", False),
        "[12345.678] fw-new IN=eth1 OUT=eth0 SRC=10.10.4.20 DST=192.0.2.53 PROTO=UDP SPT=1 DPT=53": ("dmesg", True),
        "Xyz  1 12:00:00 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.10.4.20 DST=192.0.2.53 PROTO=UDP SPT=1 DPT=53": ("cannot be read", True),
    }
    for text, (reason, doubt) in cases.items():
        got = reader.read_line(text)
        assert got.record is None and reason in got.reason and got.doubt == doubt, (text, got)
    yearless = iptables_logs.Reader().read_line("Oct  1 12:00:00 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.10.4.20 DST=192.0.2.53 PROTO=UDP DPT=53")
    assert yearless.record is None and "without a year" in yearless.reason and yearless.doubt and yearless.gateway == "fw1"


def test_the_year_goes_up_where_the_months_run_back_and_zoneless_times_are_counted() -> None:
    reader = iptables_logs.Reader(year=2026)
    lines = [f"{month} 31 23:59:59 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.10.4.20 DST=192.0.2.53 PROTO=UDP DPT=53" for month in ("Dec",)]
    lines.append("Jan  1 00:00:01 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.10.4.20 DST=192.0.2.53 PROTO=UDP DPT=53")
    records = [line.record for line in reader.read("\n".join(lines).encode())]
    assert records[0] is not None and records[1] is not None
    assert records[1].time - records[0].time == 2 and reader.zoneless == 2


def test_a_log_rule_for_everything_logs_the_rules_below_it() -> None:
    policy = cli.load((DATA / "iptables_logged.rules").read_bytes(), "iptables", Report())
    assert all(rule.log_start for rule in policy.rules)
    limited = (DATA / "iptables_logged.rules").read_text(encoding="utf-8").replace("--ctstate NEW -j LOG", "--ctstate NEW -m limit --limit 5/min -j LOG")
    policy = cli.load(limited.encode(), "iptables", Report())
    assert not any(rule.log_start for rule in policy.rules)  # (a rate-limited LOG rule does not log everything)


# -- the usage of an iptables policy ------------------------------------------------------------------


def _usage(args: List[str], capsys: pytest.CaptureFixture[str]) -> str:
    assert cli.main(["usage", str(DATA / "iptables_logged.rules"), "--logs", str(DATA / "iptables_logged.log"), "--log-year", "2026", *args]) == 0
    return capsys.readouterr().out


def test_the_iptables_sample_matches_its_golden_file(capsys: pytest.CaptureFixture[str]) -> None:
    text = _usage(["--unchanged-since", "2026-01-01"], capsys).replace(str(DATA) + os.sep, "")
    out = DATA / "expected" / "iptables_logged.usage.txt"
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        out.write_text(text, encoding="utf-8")
    assert text == out.read_text(encoding="utf-8")


def test_certain_possible_and_what_the_policy_cannot_place(capsys: pytest.CaptureFixture[str]) -> None:
    data = json.loads(_usage(["--unchanged-since", "2026-01-01", "--json"], capsys))
    rules = {rule["name"]: rule for rule in data["rules"]}
    assert rules["LAN web"]["connections"] == rules["LAN web"]["by_simulation"] == 90
    assert rules["Rate limited mail"]["connections"] == 0 and rules["Rate limited mail"]["possible"] == 13
    assert data["connections"]["not_attributed"] == {"no rule matches it: the default of the policy": 13}
    found = {(f["check"], f["name"]) for f in data["findings"]}
    assert ("UNUSED_RULE", "Admins RDP") in found and ("NO_USAGE_EVIDENCE", "Rate limited mail") in found
    assert not any(name == "LAN web" for _, name in found)


def test_without_the_age_of_the_rules_iptables_proves_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    text = _usage([], capsys)
    assert "UNUSED_RULE" not in text and "give the day with --unchanged-since" in text


def test_a_rule_that_does_not_log_proves_nothing(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = tmp_path / "fw.rules"
    rules.write_text((DATA / "iptables_logged.rules").read_text(encoding="utf-8").replace("-m conntrack --ctstate NEW -j LOG", "-i eth9 -j LOG"),
                     encoding="utf-8")  # fmt: skip
    assert cli.main(["usage", str(rules), "--logs", str(DATA / "iptables_logged.log"), "--log-year", "2026", "--unchanged-since", "2026-01-01"]) == 0
    text = capsys.readouterr().out
    assert "UNUSED_RULE" not in text and "does not log its connections" in text


def test_the_offset_and_the_store_in_the_audit(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    store = tmp_path / "usage.db"
    text = _usage(["--log-offset", "+02:00", "--store", str(store)], capsys)
    assert "read as UTC" not in text and "window: 2026-07-03 to 2026-09-30" in text
    assert cli.main(["audit", str(DATA / "iptables_logged.rules"), "--usage-store", str(store), "--unchanged-since", "2026-01-01"]) == 0
    assert "UNUSED_RULE: rule 'Admins RDP'" in capsys.readouterr().out
    for bad in ("2", "+25:00", "+02:99", "0200"):
        assert cli.main(["usage", str(DATA / "iptables_logged.rules"), "--logs", str(DATA / "iptables_logged.log"), "--log-offset", bad]) == 1
        assert "--log-offset" in capsys.readouterr().err
    with pytest.raises(FwshiftError, match="not a day"):
        audit.load_config('{"unchanged_since": "soon"}')


def test_check_point_lines_that_name_rules_loosely_are_possible() -> None:
    """The rules a log names but cannot put on their rows, and the parts of a rule that more than one fits, are possible, not certain."""
    from test_logs import MAIN, _evaluate, _filler, _regression, line

    policy = _regression().policy()
    _evaluate(policy, _filler() + [line(1, [(MAIN, 1, 0, "Accept", "u1"), ("uid-x", 5, 0, "Accept", None), ("uid-y", 6, 0, "Accept", "u9")])])
    r1 = next(rule for rule in policy.rules if rule.name == "R1").log_usage
    assert r1 is not None and r1.connections == 0 and r1.possible == 1
    found = {f.name: f for f in audit.run(policy).before if f.check in ("UNUSED_RULE", "NO_USAGE_EVIDENCE")}
    assert found["R1"].check == "NO_USAGE_EVIDENCE" and "may have gone through it" in found["R1"].message
    assert usage.VENDORS["iptables"] == "iptables"


# -- review round 23 ----------------------------------------------------------------------------------

HEAD = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
NEW_LOG = '-A FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix "fw-new "\n'
ESTABLISHED = "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"


def _days(rest: str, host: str = "fw1", days: int = 30) -> str:
    return "".join(f"Oct {day:2d} 10:00:00 {host} kernel: fw-new {rest}\n" for day in range(1, days + 1))


WEB = "IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=60 PROTO=TCP SPT=40000 DPT=443 WINDOW=1 RES=0x00 SYN URGP=0"


def _run(tmp_path: Any, capsys: pytest.CaptureFixture[str], rules: str, log: str, *extra: str) -> Any:
    (tmp_path / "fw.rules").write_text(HEAD + rules + "COMMIT\n", encoding="utf-8")
    (tmp_path / "fw.log").write_text(log, encoding="utf-8")
    assert cli.main(["usage", str(tmp_path / "fw.rules"), "--logs", str(tmp_path / "fw.log"), "--log-year", "2026", "--since", "30d",
                     "--unchanged-since", "2026-01-01", "--json", *extra]) == 0  # fmt: skip
    data = json.loads(capsys.readouterr().out)
    return data, {f["name"]: f["check"] for f in data["findings"] if f["check"].startswith(("UNUSED", "NO_USAGE"))}, {r["name"]: r for r in data["rules"]}


def test_r23_a_line_without_a_port_may_be_any_rule_of_its_protocol(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ESTABLISHED + NEW_LOG + '-A FORWARD -p tcp --dport 443 -m comment --comment "web" -j ACCEPT\n' + \
        '-A FORWARD -p tcp --dport 8443 -m comment --comment "alt web" -j ACCEPT\n-A FORWARD -p icmp --icmp-type 8 -m comment --comment "ping" -j ACCEPT\n'  # fmt: skip
    log = _days(WEB) + "Oct 15 10:00:00 fw1 kernel: fw-new IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=40 PROTO=TCP INCOMPLETE [8 bytes]\n"
    log += "Oct 15 10:00:00 fw1 kernel: fw-new IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=28 PROTO=ICMP INCOMPLETE [2 bytes]\n"
    _, found, rules_ = _run(tmp_path, capsys, rules, log)
    assert "alt web" not in found or found["alt web"] == "NO_USAGE_EVIDENCE"
    assert found.get("ping") == "NO_USAGE_EVIDENCE" and rules_["ping"]["possible"] == 1
    sim = simulate.Simulator(cli.load((tmp_path / "fw.rules").read_bytes(), "iptables", Report()))
    point = ("eth1", "eth0", "10.0.0.1", "192.0.2.1", 6)
    assert [r.name for r in sim.attribute(point + (-1,)).possible] == [r.name for r in sim.attribute(point + (None,)).possible] == ["web", "alt web"]


def test_r23_a_log_of_new_connections_does_not_log_what_only_other_packets_reach() -> None:
    def load(text: str) -> Policy:
        return cli.load((HEAD + text + "COMMIT\n").encode(), "iptables", Report())

    related = load(ESTABLISHED.replace("RELATED,", "") + NEW_LOG + '-A FORWARD -p tcp -m conntrack --ctstate RELATED -m helper --helper ftp '
                   '-m comment --comment "ftp data" -j ACCEPT\n-A FORWARD -p tcp --dport 21 -m comment --comment "ftp ctl" -j ACCEPT\n')  # fmt: skip
    assert {r.name: r.log_start for r in related.rules} == {"ftp data": False, "ftp ctl": True}
    stateless = load(NEW_LOG + '-A FORWARD -i eth0 -o eth1 -p tcp --sport 443 -m comment --comment "web replies" -j ACCEPT\n'
                     '-A FORWARD -p tcp --dport 443 -m conntrack --ctstate NEW -m comment --comment "web" -j ACCEPT\n')  # fmt: skip
    assert {r.name: r.log_start for r in stateless.rules} == {"web replies": False, "web": True}
    every = load('-A FORWARD -j LOG\n-A FORWARD -p tcp --sport 443 -m comment --comment "web replies" -j ACCEPT\n')
    assert every.rules[0].log_start  # (a LOG of every packet logs every rule below it)


def test_r23_nflog_is_not_the_kernel_log(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ESTABLISHED + '-A FORWARD -m conntrack --ctstate NEW -j NFLOG --nflog-group 1\n' + \
        '-A FORWARD -p tcp --dport 443 -j LOG --log-prefix "fw-new "\n-A FORWARD -p tcp --dport 443 -m comment --comment "web" -j ACCEPT\n' + \
        '-A FORWARD -p tcp --dport 22 -m comment --comment "ssh out" -j ACCEPT\n'  # fmt: skip
    _, found, rules_ = _run(tmp_path, capsys, rules, _days(WEB))
    assert found == {"ssh out": "NO_USAGE_EVIDENCE"} and "NFLOG" in " ".join(rules_["ssh out"]["no_evidence"])
    assert rules_["web"]["connections"] == 30


def test_r23_udplite_is_not_udp(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ESTABLISHED + NEW_LOG + '-A FORWARD -p udplite -m comment --comment "UDPLITE allow" -j ACCEPT\n' + \
        '-A FORWARD -p udp --dport 5000 -m comment --comment "UDP 5000" -j ACCEPT\n'  # fmt: skip
    _, found, rules_ = _run(tmp_path, capsys, rules, _days("IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=40 PROTO=UDPLITE SPT=1 DPT=5000 LEN=20"))
    assert rules_["UDPLITE allow"]["connections"] == 30 and rules_["UDP 5000"]["connections"] == 0
    assert found == {"UDP 5000": "UNUSED_RULE"}


def test_r23_lines_that_say_lines_were_lost_are_doubts() -> None:
    reader = iptables_logs.Reader(year=2026)
    for text in ("Oct 15 10:00:00 fw1 kernel: ** 12 printk messages dropped **", "Oct 15 10:00:00 fw1 systemd-journald[312]: Missed 23 kernel messages",
                 "Oct 15 10:00:00 fw1 rsyslogd: imjournal: 1200 messages lost due to rate-limiting",
                 "Oct 15 10:00:00 fw1 kernel: net_ratelimit: 5 callbacks suppressed"):  # fmt: skip
        got = reader.read_line(text)
        assert got.doubt and got.gateway == "fw1" and got.time is not None and "lost" in got.reason, text
    assert not reader.read_line("Oct 15 10:00:00 fw1 sshd[1]: Accepted publickey for admin").doubt
    cut = reader.read_line("Oct 15 10:00:00 fw1 kernel: fw-new IN=eth1 SRC=10.0.0.1")
    assert cut.doubt and cut.gateway == "fw1"


def test_r23_the_pre_nat_address_the_parser_adds_is_not_called_unused(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ESTABLISHED + NEW_LOG + '-A FORWARD -i eth0 -o eth2 -d 10.20.0.10/32 -p tcp --dport 443 -m comment --comment "Inbound web" -j ACCEPT\n'
    nat = "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A PREROUTING -i eth0 -d 203.0.113.10/32 -p tcp --dport 443 -j DNAT " \
        "--to-destination 10.20.0.10\nCOMMIT\n"  # fmt: skip
    (tmp_path / "fw.rules").write_text(HEAD + rules + "COMMIT\n" + nat, encoding="utf-8")
    (tmp_path / "fw.log").write_text(_days("IN=eth0 OUT=eth2 SRC=198.51.100.7 DST=10.20.0.10 LEN=60 PROTO=TCP SPT=1 DPT=443 SYN URGP=0"), encoding="utf-8")
    assert cli.main(["usage", str(tmp_path / "fw.rules"), "--logs", str(tmp_path / "fw.log"), "--log-year", "2026", "--since", "30d",
                     "--unchanged-since", "2026-01-01"]) == 0  # fmt: skip
    text = capsys.readouterr().out
    assert "UNUSED_RULE_OBJECT" not in text and "'Inbound web' (allow): 30 connection(s)" in text


def test_r23_packets_of_open_connections_are_not_connections(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = '-A FORWARD -j LOG --log-prefix "fw-new "\n' + ESTABLISHED + '-A FORWARD -i eth1 -o eth0 -p tcp --dport 443 -m comment --comment "web out" -j ACCEPT\n' + \
        '-A FORWARD -i eth0 -o eth1 -p tcp --dport 1024:65535 -m comment --comment "inbound high ports" -j ACCEPT\n' + \
        '-A FORWARD -i eth0 -o eth1 -p udp -m comment --comment "inbound udp" -j ACCEPT\n'  # fmt: skip
    reply = "IN=eth0 OUT=eth1 SRC=192.0.2.1 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=443 DPT=40000 WINDOW=1 RES=0x00 ACK SYN URGP=0"
    dns = "IN=eth0 OUT=eth1 SRC=192.0.2.53 DST=10.0.0.1 LEN=60 PROTO=UDP SPT=53 DPT=40000 LEN=40"
    data, found, rules_ = _run(tmp_path, capsys, rules, _days(WEB) + _days(reply) + _days(dns))
    assert rules_["inbound high ports"]["connections"] == 0 and found["inbound high ports"] == "UNUSED_RULE"
    assert rules_["web out"]["connections"] == 30  # (the SYN is the connection)
    assert rules_["inbound udp"]["connections"] == 0 and rules_["inbound udp"]["possible"] == 30 and found["inbound udp"] == "NO_USAGE_EVIDENCE"
    assert data["read"]["skipped"]["a TCP packet that opens no connection (not SYN alone): a packet of one already open"] == 30
    assert "packets of connections already open" in data["connections"]["possible_only_because"][0]


def test_r23_the_year_starts_again_with_every_file_and_a_line_out_of_order_keeps_it() -> None:
    reader = iptables_logs.Reader(year=2025, offset=0)
    first = [line.record for line in reader.read(b"Dec 31 23:59:00 fw1 kernel: IN=a OUT=b SRC=10.0.0.1 DST=10.0.0.2 PROTO=47\n"
                                                b"Jan  1 00:01:00 fw1 kernel: IN=a OUT=b SRC=10.0.0.1 DST=10.0.0.2 PROTO=47\n"
                                                b"Dec 31 23:59:30 fw1 kernel: IN=a OUT=b SRC=10.0.0.1 DST=10.0.0.2 PROTO=47\n"
                                                b"Jan  1 00:02:00 fw1 kernel: IN=a OUT=b SRC=10.0.0.1 DST=10.0.0.2 PROTO=47\n")]  # fmt: skip
    assert [r.time - first[0].time for r in first if r is not None] == [0, 120, 30, 180]
    again = [line.record for line in reader.read(b"Dec 30 12:00:00 fw1 kernel: IN=a OUT=b SRC=10.0.0.1 DST=10.0.0.2 PROTO=47\n")]
    assert again[0] is not None and again[0].time == 1767096000  # 2025-12-30 12:00 UTC, not 2026


def test_r23_lines_of_other_hosts(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ESTABLISHED + NEW_LOG + '-A FORWARD -i eth1 -o eth0 -p tcp --dport 443 -m comment --comment "web" -j ACCEPT\n' + \
        '-A FORWARD -i eth1 -o eth0 -p tcp --dport 22 -m comment --comment "ssh out" -j ACCEPT\n'  # fmt: skip
    ssh = "IN=eth1 OUT=eth0 SRC=172.17.0.2 DST=192.0.2.9 LEN=60 PROTO=TCP SPT=1000 DPT=22 SYN URGP=0"
    log = _days(WEB) + _days(ssh, host="dockerhost")
    data, found, rules_ = _run(tmp_path, capsys, rules, log, "--gateway", "fw1")
    assert rules_["ssh out"]["connections"] == 0 and found == {"ssh out": "UNUSED_RULE"} and data["judged_by"] == ["fw1"]
    assert data["connections"]["not_attributed"] == {"a line from a host that is not among the gateways given (--gateway)": 30}
    data, found, rules_ = _run(tmp_path, capsys, rules, log)
    assert rules_["ssh out"]["connections"] == 0 and rules_["ssh out"]["possible"] == 30
    assert found == {"ssh out": "NO_USAGE_EVIDENCE", "web": "NO_USAGE_EVIDENCE"}  # (which host runs the policy is not known)
    assert "2 hosts" in data["connections"]["possible_only_because"][0]


def test_r23_addresses_kept_as_networks_are_still_placed(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = ESTABLISHED + NEW_LOG + '-A FORWARD -s 10.0.0.0/16 -p tcp --dport 443 -m comment --comment "LAN web" -j ACCEPT\n' + \
        '-A FORWARD -p tcp --dport 443 -m comment --comment "guest web" -j ACCEPT\n'  # fmt: skip
    log = "".join(f"Oct {1 + n % 30:2d} 10:00:00 fw1 kernel: fw-new IN=eth1 OUT=eth0 SRC=10.0.{n // 250}.{n % 250 + 1} DST=192.0.2.1 LEN=60 "
                  "PROTO=TCP SPT=1 DPT=443 SYN URGP=0\n" for n in range(600))  # fmt: skip
    _, found, rules_ = _run(tmp_path, capsys, rules, log, "--roll-up", "50")
    assert rules_["LAN web"]["connections"] == 600 and rules_["LAN web"].get("rolled_up") and found == {"guest web": "UNUSED_RULE"}


def test_r23_reader_edge_cases() -> None:
    reader = iptables_logs.Reader(year=2026)
    tagged = reader.read_line("Oct  1 10:00:00 fw1 kernel: IN=eth9 OUT=eth9 IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 PROTO=TCP DPT=22 SYN URGP=0")
    assert tagged.record is not None and (tagged.record.in_zone, tagged.record.out_zone) == ("eth1", "eth0")  # (the last are the fields)
    for text, reason in (("Oct  1 10:00:00 fw1 kernel: TRACE: filter:FORWARD:rule:3 IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 PROTO=47", "TRACE"),
                         ("Oct  1 10:00:00 fw1 kernel: IN=br0 OUT=br1 MAC source = 52:54:00:00:00:01 MAC dest = 52:54:00:00:00:02 proto = "
                          "0x0800 IP SRC=10.0.0.1 IP DST=10.0.0.2", "ebtables")):  # fmt: skip
        got = reader.read_line(text)
        assert got.record is None and reason in got.reason and not got.doubt
    sctp = reader.read_line("Oct  1 10:00:00 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=60 PROTO=132").record
    assert sctp is not None and (sctp.protocol, sctp.port) == (132, None)
    for flags, kept in (("SYN", True), ("ACK SYN", False), ("ACK", False), ("RST", False), ("ACK FIN", False)):
        got = reader.read_line(f"Oct  1 10:00:00 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=22 {flags} URGP=0")
        assert (got.record is not None) == kept, flags
    unknown = reader.read_line("Oct  1 10:00:00 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 PROTO=TCP INCOMPLETE [8 bytes]")
    assert unknown.record is not None and unknown.record.port is None  # (flags not given: it may be the first)
    zones = iptables_logs.Reader().read_line("2026-10-01T10:00:00Z fw1 kernel: IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 PROTO=47").record
    assert zones is not None and zones.time == 1790848800
    minus = iptables_logs.Reader().read_line("2026-10-01T05:30:00-04:30 fw1 kernel: IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 PROTO=47").record
    assert minus is not None and minus.time == 1790848800


def test_r23_a_drop_the_policy_gives_is_no_accepted_connection(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Logs of drops only prove nothing for an allow rule: a connection certainly dropped is not an accepted one."""
    rules = ESTABLISHED + NEW_LOG + '-A FORWARD -p tcp --dport 23 -m comment --comment "no telnet" -j DROP\n' + \
        '-A FORWARD -p tcp --dport 22 -m comment --comment "ssh out" -j ACCEPT\n'  # fmt: skip
    telnet = "IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=60 PROTO=TCP SPT=40000 DPT=23 WINDOW=1 RES=0x00 SYN URGP=0"
    data, found, rules_ = _run(tmp_path, capsys, rules, _days(telnet))
    assert rules_["no telnet"]["connections"] == 30 and data["gateways"]["fw1"]["days_with_logs"] == 30
    assert found == {"ssh out": "NO_USAGE_EVIDENCE"} and "no accepted connection" in " ".join(rules_["ssh out"]["no_evidence"])


def test_r23_parts_of_a_split_rule_that_all_fit_are_possible() -> None:
    """A rule split by its access roles: one part that fits the line is certain, several are possible."""
    from test_logs import MAIN, _evaluate, _filler, line, seen
    from test_usage import _roles_export

    cp = _roles_export()
    cp.layer("Main", [cp.rule("PLC", ["operators", "vendors", "admins", "operators-office", "anyone-office"], ["plc"], uid="u-plc")])
    policy = seen(cp).policy()
    rows = [(MAIN, 1, 0, "Accept", "u-plc")]
    _evaluate(policy, _filler() + [line(1, rows, src="10.10.5.7", dst="10.30.1.5")])
    parts = {rule.name: rule.log_usage for rule in policy.rules if rule.name.startswith("PLC")}
    assert {name: (log.connections, log.possible) for name, log in parts.items() if log} == {
        "PLC": (1, 0), "PLC (operators, operators-office)": (0, 0), "PLC (vendors)": (0, 0)}  # (no user: the part of any user)
    policy = seen(cp).policy()
    _evaluate(policy, _filler() + [line(1, rows, src="10.10.5.7", dst="10.30.1.5", extra=[("src_user_name", "alice")])])
    parts = {rule.name: rule.log_usage for rule in policy.rules if rule.name.startswith("PLC")}
    assert {name: (log.connections, log.possible) for name, log in parts.items() if log} == {
        "PLC": (0, 1), "PLC (operators, operators-office)": (0, 1), "PLC (vendors)": (0, 1)}
