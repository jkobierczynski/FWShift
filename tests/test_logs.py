# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Rule usage from logs (0.14.0; docs/RULE_USAGE.md): the Check Point log readers, the store, attribution and evidence.

Every log line here is made up from the shapes the documentation and published parsers show, with documentation
and private addresses only.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import random
import sqlite3
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

import pytest
from test_usage import Export, hit

from fwshift import audit, cli, usage
from fwshift.errors import FwshiftError
from fwshift.logreaders import checkpoint as logs
from fwshift.model import ANY, Policy
from fwshift.report import Report

DATA = Path(__file__).resolve().parent / "data"
DAY0 = datetime.datetime(2026, 7, 1, 12, tzinfo=datetime.timezone.utc)
SIC = "CN={gw},O=mgmt.example.net.abc123"


def moment(day: int, minute: int = 0) -> int:
    return int((DAY0 + datetime.timedelta(days=day, minutes=minute)).timestamp())


def line(day: int, rows: Sequence[Tuple[str, int, int, str, Optional[str]]], src: str = "10.1.5.5", dst: str = "172.16.0.10",
         proto: int = 6, port: Optional[int] = 443, gateway: str = "gw-a", action: str = "Accept", extra: Sequence[Tuple[str, str]] = (),
         minute: int = 0) -> str:  # fmt: skip
    """A Log Exporter syslog line; rows: (layer uuid, match_id, parent_rule, action, rule uid or None), outer first."""
    fields = [("action", action), ("loguid", "{0x1,0x2,0x3,0x4}"), ("origin", "198.51.100.1"), ("originsicname", SIC.format(gw=gateway)),
              ("time", str(moment(day, minute))), ("version", "5"), ("dst", dst)]  # fmt: skip
    for column, index in (("layer_uuid", 0), ("match_id", 1), ("parent_rule", 2), ("rule_action", 3)):
        fields += [(column, str(row[index])) for row in rows]
    fields += [("rule_uid", row[4]) for row in rows if row[4]]
    fields += [("product", "VPN-1 & FireWall-1"), ("proto", str(proto))]
    if port is not None and proto in (6, 17):
        fields += [("s_port", "40000"), ("service", str(port))]
    elif port is not None:
        fields += [("icmp_type", str(port))]
    fields += [("src", src)] + list(extra)
    body = "; ".join(f'{key}:"{value}"' for key, value in fields)
    return f"<134>1 {datetime.datetime.fromtimestamp(moment(day, minute), datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} mgmt CheckPoint 1 - [{body}]"


# -- the readers -------------------------------------------------------------------------------------


def test_a_syslog_line_with_everything_odd_in_it() -> None:
    text = ('<134>1 2026-07-01T12:00:00Z mgmt CheckPoint 7 - [action:"Accept"; origin:"198.51.100.1"; originsicname:"CN=gw-a,O=m..x"; '
            'time:"1782907200"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={X};mgmt=m;date=1;policy_name=Standard\\]"; '
            'comment:"a \\"quoted\\" word; a #hash; a \\\\ back"; sys_message::"note: x"; dst:"172.16.0.10"; layer_uuid:"L1"; '
            'match_id:"3"; parent_rule:"0"; rule_action:"Accept"; rule_uid:"{AB-12}"; product:"VPN-1 & FireWall-1"; proto:"6"; '
            'service:"8443"; service_id:"port_8443"; src:"10.1.5.5"; ]')  # fmt: skip
    got = logs.read_line(text)
    assert got.record is not None, got.reason
    record = got.record
    assert (record.gateway, record.time, record.protocol, record.port, record.src, record.dst) == ("gw-a", 1782907200, 6, 8443, "10.1.5.5", "172.16.0.10")
    assert [(row.layer_uuid, row.match_id, row.parent_rule, row.rule_uid) for row in record.layers] == [("l1", 3, 0, "ab-12")]


def test_inline_layers_cleanups_and_columns_that_do_not_line_up() -> None:
    inline = logs.read_line(line(0, [("L1", 14, 0, "Inline", "u-apply"), ("L2", 16777217, 14, "Accept", "u-web")])).record
    assert inline is not None and [r.rule_uid for r in inline.layers] == ["u-apply", "u-web"] and not inline.loose_uids
    # The implicit cleanup of a layer has no uid: the others are put on the rows that are rules.
    cleanup = logs.read_line(line(0, [("L1", 14, 0, "Inline", "u-apply"), ("L2", 33554431, 14, "Drop", None)])).record
    assert cleanup is not None and cleanup.layers[1].implicit and [r.rule_uid for r in cleanup.layers] == ["u-apply", ""]
    # Three rows, one uid missing that is no implicit cleanup: the uids name rules loosely.
    loose = logs.read_line(line(0, [("L1", 1, 0, "Inline", "a"), ("L2", 16777218, 1, "Inline", "b"), ("L3", 33554427, 16777218, "Accept", None)])).record
    assert loose is not None and loose.loose_uids == ["a", "b"] and not any(r.rule_uid for r in loose.layers)


def test_splunk_and_cef_lines() -> None:
    splunk = ("time=1782907200|hostname=mgmt|product=Firewall|layer_name=Network|layer_uuid=L1|match_id=1|parent_rule=0|rule_action=Accept|"
              "rule_uid=u1|action=Accept|origin=198.51.100.1|originsicname=CN\\=gw-a,O\\=m..x|time=1782907200|dst=172.16.0.10|proto=17|"
              "s_port=5000|service=53|src=10.1.5.5|comment=a\\=b; c|")  # fmt: skip
    record = logs.read_line("Oct  1 12:00:00 collector " + splunk).record
    assert record is not None and (record.gateway, record.protocol, record.port, record.layers[0].rule_uid) == ("gw-a", 17, 53, "u1")
    cef = ("CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|https|Unknown|act=Accept rt=1782907200123 spt=5000 dpt=443 "
           "cs2Label=Rule Name cs2=Allow all layer_name=Firewall Example layer_name=Example Application layer_uuid=L1 layer_uuid=L9 "
           "match_id=19 match_id=16777244 parent_rule=0 parent_rule=0 rule_action=Accept rule_action=Accept rule_uid=u1 rule_uid=u9 "
           "origin=198.51.100.1 originsicname=CN\\=gw-b,O\\=m..x dst=172.16.0.10 product=VPN-1 & FireWall-1 proto=6 src=10.1.5.5")  # fmt: skip
    record = logs.read_line("<134>Oct  1 12:00:00 collector " + cef).record
    assert record is not None and record.time == 1782907200 and record.gateway == "gw-b" and record.port == 443
    assert [(r.layer_uuid, r.rule_uid, r.layer_name) for r in record.layers] == [("l1", "u1", "Firewall Example"), ("l9", "u9", "Example Application")]


def test_the_answer_of_show_logs() -> None:
    answer = {"logs": [{"time": "2026-07-01T12:00:00Z", "orig": "gw-a", "action": "Accept", "src": "10.1.5.5", "dst": "172.16.0.10",
                        "proto": "6", "service": "443", "product": "VPN-1 & FireWall-1",
                        "match_table": [{"layer_uuid": "L1", "match_id": 1, "parent_rule": 0, "rule_action": "Accept", "rule_uid": "u1"}]},
                       "not a log"]}  # fmt: skip
    lines = list(logs.read(json.dumps(answer).encode()))
    assert lines[0].record is not None and lines[0].record.gateway == "gw-a" and lines[0].record.layers[0].rule_uid == "u1"
    assert lines[1].record is None and lines[1].doubt


def test_what_is_no_connection_of_a_rule_is_counted_by_its_reason() -> None:
    rows = [("L1", 1, 0, "Accept", "u1")]
    cases = {
        line(0, rows, extra=[("product", "Log Update")]).replace('product:"VPN-1 & FireWall-1"; ', ""): ("Log Update", False),
        line(0, [], action="Drop"): ("names no rule", False),
        line(0, []).replace("VPN-1 & FireWall-1", "SmartDefense"): ("another blade", False),
        line(0, [], extra=[("drop_reason", "matched optimized drop")]): ("optimized drop", False),
        line(0, rows).replace('time:"', 'tim:"').replace("2026-07-01T12:00:00Z", "-"): ("without a time", True),
        line(0, rows)[:-40]: ("cannot be read", True),
        "Oct  1 12:00:00 host sshd[1]: something else": ("not a line of Check Point", False),
        '<85>1 2026-07-01T12:00:00Z 198.51.100.1 CP-GW - Log [Fields@1.3.6.1.4.1.2620 src="10.1.5.5" rule_uid="u1"]': ("does not read", True),
        'LEEF:2.0|Check Point|VPN-1 & FireWall-1|1.0|Accept|devTime=1782907200': ("does not read", True),
    }
    for text, (reason, doubt) in cases.items():
        got = logs.read_line(text)
        assert got.record is None and reason in got.reason and got.doubt == doubt, (reason, got)


def test_a_line_that_names_a_rule_is_a_connection_whatever_else_it_lacks() -> None:
    """Review round 22, H1: the blade, the protocol, an address or a port the line lacks leaves those open, never the rule."""
    rows = [("L1", 1, 0, "Accept", "u1")]
    cases = [
        (line(0, rows).replace("VPN-1 & FireWall-1", "Application Control"), ("10.1.5.5", 6, 443)),
        (line(0, rows, extra=[("packets", "24"), ("bytes", "9000")]), ("10.1.5.5", 6, 443)),
        (line(0, rows, proto=0, port=None), ("10.1.5.5", -1, None)),
        (line(0, rows, proto=4294967295, port=None), ("10.1.5.5", -1, None)),
        (line(0, rows, src="not-an-address"), ("", 6, 443)),
        (line(0, rows, src="0.0.0.0"), ("", 6, 443)),
        (line(0, rows).replace('service:"443"', 'service:"x"'), ("10.1.5.5", 6, None)),
        ("Oct  1 12:00:00 relay CheckPoint[1234]: " + line(0, rows).split(" - ", 1)[1], ("10.1.5.5", 6, 443)),
    ]
    for text, (src, protocol, port) in cases:
        record = logs.read_line(text).record
        assert record is not None and (record.src, record.protocol, record.port) == (src, protocol, port), text[-120:]
        assert record.layers[0].rule_uid == "u1"


def test_ipv6_icmp_and_other_protocols() -> None:
    rows = [("L1", 1, 0, "Accept", "u1")]
    v6 = logs.read_line(line(0, rows, src="", dst="").replace('src:""', 'ipv6_src:"2001:db8::5"').replace('dst:""', 'ipv6_dst:"2001:db8::10"')).record
    assert v6 is not None and (v6.src, v6.dst) == ("2001:db8::5", "2001:db8::10")
    icmp = logs.read_line(line(0, rows, proto=1, port=8)).record
    assert icmp is not None and (icmp.protocol, icmp.port) == (1, 8)
    esp = logs.read_line(line(0, rows, proto=50, port=None)).record
    assert esp is not None and (esp.protocol, esp.port) == (50, None)
    aggregated = logs.read_line(line(0, rows, extra=[("connection_count", "7")])).record
    assert aggregated is not None and aggregated.count == 7
    milli = logs.read_line(line(0, rows).replace(f'time:"{moment(0)}"', f'time:"{moment(0)}123"')).record
    assert milli is not None and milli.time == moment(0)


# -- a policy and its logs ---------------------------------------------------------------------------


def aged(cp: Export) -> Export:
    """Every rule created long before the logs, as an export with details-level full says (meta-info)."""
    for layer in cp.layers:
        for rule in layer["rulebase"]:
            rule.setdefault("meta-info", {"creation-time": {"posix": 1735689600000}})
    return cp


def seen(cp: Export) -> Export:
    """A rule the daily lines of _filler name: what shows that a gateway logged its connections that day."""
    cp.layers[0]["rulebase"].append(cp.rule("Seen", ["Any"], uid="u-seen"))
    return aged(cp)


def _regression() -> Export:
    """The policy of docs/RULE_USAGE.md section 8, the defects of fwanalyser."""
    cp = Export()
    cp.network("Net10", "10.0.0.0/8")
    cp.network("Net10_1", "10.1.0.0/16")
    cp.add("Host1", "host", ipv4_address="10.1.1.1")
    cp.add("Srv", "host", ipv4_address="172.16.0.10")
    cp.add("BigSrc", "group", members=[cp.objects["Net10"]["uid"], cp.objects["Host1"]["uid"]])
    cp.add("http", "service-tcp", port="80")
    cp.add("https", "service-tcp", port="443")
    rules = [
        dict(cp.rule("R1", ["Net10_1"], ["Srv"], uid="u1"), service=[cp.objects["http"]["uid"]]),
        dict(cp.rule("R2", ["Net10_1"], ["Srv"], uid="u2"), service=[cp.objects["http"]["uid"]], **{"source-negate": True}),
        dict(cp.rule("R3", ["BigSrc"], ["Srv"], uid="u3"), service=[cp.objects["https"]["uid"], cp.objects["http"]["uid"]]),
        cp.rule("R4", ["Any"], ["Any"], "Drop", uid="u4"),
    ]
    cp.layer("Main", rules)
    return seen(cp)


MAIN = "uid-main"


def _rows(uid: str, number: int = 1) -> List[Tuple[str, int, int, str, Optional[str]]]:
    return [(MAIN, number, 0, "Accept", uid)]


def _filler(days: int = 90, gateway: str = "gw-a") -> List[str]:
    """One accepted connection a day, of the rule 'Seen', and one line that is no connection: the gateway was logging."""
    return [text for day in range(days) for text in (line(day, [(MAIN, 99, 0, "Accept", "u-seen")], gateway=gateway, minute=5),
                                                     line(day, [], action="Drop", gateway=gateway, minute=6))]  # fmt: skip


def _evaluate(policy: Policy, lines: Sequence[str], since: str = "", until: str = "", gateways: Sequence[str] = (),
              cap: int = usage.DEFAULT_CAP) -> usage.Evaluation:  # fmt: skip
    store = usage.Store(":memory:")
    usage.ingest(store, [("log", "\n".join(lines).encode())], cap=cap)
    result = usage.evaluate(policy, store, usage.window(store, since, until), gateways)
    store.close()
    return result


def _findings(policy: Policy, config: Optional[audit.AuditConfig] = None) -> List[audit.Finding]:
    checks = ("UNUSED_RULE", "UNUSED_RULE_OBJECT", "UNUSED_RULE_SERVICE", "NO_USAGE_EVIDENCE")
    return [f for f in audit.run(policy, config or audit.AuditConfig()).before if f.check in checks]


def test_the_defects_of_fwanalyser_do_not_come_back() -> None:
    """D1 (a negated cell), D5 (every object that holds the address, also two of the same address)."""
    policy = _regression().policy()
    lines = _filler() + [
        line(1, _rows("u3", 3), "10.1.5.5", port=443),  # rule 3: Net10 (not Host1)
        line(2, _rows("u2", 2), "10.2.0.1", port=80),  # rule 2, negated: outside Net10_1
        line(3, _rows("u3", 3), "10.1.1.1", port=443),  # rule 3: Net10 and Host1
        line(4, _rows("u2", 2), "192.168.1.1", port=80),  # rule 2 again
    ]
    _evaluate(policy, lines)
    rules = {rule.name: rule for rule in policy.rules}
    r3 = rules["R3"].log_usage
    assert r3 is not None and r3.connections == 2
    assert r3.members["source"] == {"BigSrc": 2, "Net10": 2, "Host1": 1}
    assert r3.members["service"] == {"https": 2, "http": 0}
    r2 = rules["R2"].log_usage
    assert r2 is not None and r2.connections == 2 and r2.members["source"] == {usage.OUTSIDE: 2}
    found = {(f.check, f.name) for f in _findings(policy)}
    assert ("UNUSED_RULE", "R1") in found and ("UNUSED_RULE_SERVICE", "R3") in found
    assert not any(name == "R2" for _, name in found) and not any(name == "R4" for _, name in found)  # (a negated cell, a drop)


def test_install_on_and_the_gateway_that_logged() -> None:
    """D3: the gateway decides; a rule installed on gw-a depends on the logs of gw-a only."""
    cp = _regression()
    cp.layers[0]["rulebase"][2]["install-on"] = [cp.add("gw-a", "simple-gateway", ipv4_address="198.51.100.1")]
    policy = cp.policy()
    lines = _filler() + _filler(30, "gw-b") + [line(5, _rows("u3", 3), gateway="gw-b")]
    _evaluate(policy, lines)
    r3 = next(rule for rule in policy.rules if rule.name == "R3").log_usage
    assert r3 is not None and r3.connections == 1 and r3.elsewhere == ["gw-b"] and not r3.no_evidence
    r1 = next(rule for rule in policy.rules if rule.name == "R1").log_usage
    assert r1 is not None and any("gw-b sent logs on 30 of the 90 days" in reason for reason in r1.no_evidence)


@pytest.mark.parametrize("case", ["gap", "declared", "doubt", "unplaced", "no-log", "changed"])
def test_what_keeps_the_logs_from_proving_anything(case: str) -> None:
    cp = _regression()
    if case == "no-log":
        cp.layers[0]["rulebase"][0]["track"] = {"type": cp.add("None", "Track")}
    if case == "changed":
        cp.layers[0]["rulebase"][0]["meta-info"] = {"last-modify-time": {"posix": moment(40) * 1000}}
    policy = cp.policy()
    lines = _filler()
    gateways: List[str] = []
    if case == "gap":
        lines = lines[:100] + lines[120:]
    if case == "declared":
        gateways = ["gw-z"]
    if case == "doubt":  # rule fields that do not line up: a connection of some rule, from gw-a on day 7
        lines.append(line(7, [(MAIN, 1, 0, "Accept", "u1"), ("L2", 2, 0, "Accept", "u9")]).replace('match_id:"2"; ', ""))
    if case == "unplaced":
        lines.append('<134>1 - mgmt CheckPoint 1 - [action:"Accept"; src:"10.1.5.5"')
    _evaluate(policy, lines, gateways=gateways)
    found = {f.name: f for f in _findings(policy)}
    assert found["R1"].check == "NO_USAGE_EVIDENCE", found["R1"].message
    expected = {"gap": "sent logs on 80 of the 90 days", "declared": "gw-z sent no logs", "doubt": "could not be read",
                "unplaced": "their gateway and day are not known", "no-log": "does not log", "changed": "after the window began"}  # fmt: skip
    assert expected[case] in found["R1"].message


def test_inline_layers_their_cleanup_and_other_layers() -> None:
    cp = Export()
    cp.network("dmz", "10.20.0.0/24")
    cp.add("Inner", "access-layer")
    cp.layer("Main", [cp.rule("Apply", ["Any"], ["dmz"], "Inner Layer", uid="u-apply", inline_layer="Inner"), cp.rule("Rest", ["Any"], uid="u-rest")])
    cp.layers.append({"uid": "uid-Inner", "name": "Inner", "from": 1, "to": 2, "total": 2,
                      "rulebase": [cp.rule("Web", ["Any"], ["dmz"], uid="u-web"), cp.rule("Mail", ["Any"], ["dmz"], uid="u-mail")]})  # fmt: skip
    policy = seen(cp).policy()
    main, inner, app = MAIN, "uid-inner", "uid-application"
    lines = _filler() + [
        line(1, [(main, 1, 0, "Inline", "u-apply"), (inner, 16777217, 1, "Accept", "u-web")], dst="10.20.0.5"),
        line(2, [(main, 1, 0, "Inline", "u-apply"), (inner, 33554431, 1, "Drop", None)], dst="10.20.0.6"),
        line(3, [(main, 2, 0, "Accept", "u-rest"), (app, 1, 0, "Accept", "u-app")]),  # another ordered layer as well
        line(4, [(main, 33554431, 0, "Drop", None)]),  # the implicit cleanup of the main layer
        line(5, [(app, 1, 0, "Accept", "u-app")]),  # only another layer
        line(6, _rows("u-gone")),  # a rule this policy does not have
    ]
    result = _evaluate(policy, lines)
    counted = {rule.name: rule.log_usage.connections for rule in policy.rules if rule.log_usage is not None and rule.name != "Seen"}
    assert counted == {"Apply / Web": 1, "Apply / Mail": 0, "Apply (cleanup of Inner)": 1, "Rest": 1}
    assert result.unattributed == {"a rule this policy does not have (another revision of it?)": 1,
                                   "rules of a layer this policy does not hold (another ordered layer, or another policy)": 1,
                                   "the implicit cleanup of the layer (no rule)": 1}  # fmt: skip


def test_rules_named_loosely_count_as_used() -> None:
    policy = _regression().policy()
    lines = _filler() + [line(1, [(MAIN, 1, 0, "Accept", "u1"), ("uid-x", 5, 0, "Accept", None), ("uid-y", 6, 0, "Accept", "u9")])]
    record = logs.read_line(lines[-1]).record
    assert record is not None and record.loose_uids == ["u1", "u9"]
    _evaluate(policy, lines)
    r1 = next(rule for rule in policy.rules if rule.name == "R1").log_usage
    # A uid named loosely (not under its layer) may be a rule of another layer: possible, not certain (0.15).
    assert r1 is not None and r1.connections == 0 and r1.possible == 1


def test_one_file_is_counted_once_and_a_store_keeps_what_it_read(tmp_path: Any) -> None:
    policy = _regression().policy()
    data = "\n".join(_filler() + [line(1, _rows("u3", 3))]).encode()
    path = str(tmp_path / "usage.db")
    store = usage.Store(path)
    first = usage.ingest(store, [("a.log", data), ("copy.log", data)])
    assert first.files == ["a.log"] and first.already == [("copy.log", "a.log")]
    store.close()
    store = usage.Store(path, create=False)
    again = usage.ingest(store, [("b.log", data)])
    assert again.files == [] and again.already == [("b.log", "a.log")]
    assert store.runs() == 1  # (a run that read nothing new leaves no trace)
    usage.evaluate(policy, store, usage.window(store))
    assert next(rule for rule in policy.rules if rule.name == "R3").log_usage.connections == 1  # type: ignore[union-attr]
    store.close()
    # D9: the rules reordered and renamed in a new revision; the counts stay with the rule by its uid.
    cp = _regression()
    cp.layers[0]["rulebase"] = [dict(cp.layers[0]["rulebase"][2], name="Renamed")] + cp.layers[0]["rulebase"][:2] + cp.layers[0]["rulebase"][3:]
    moved = cp.policy()
    store = usage.Store(path, create=False)
    usage.evaluate(moved, store, usage.window(store))
    store.close()
    assert moved.rules[0].name == "Renamed" and moved.rules[0].log_usage is not None and moved.rules[0].log_usage.connections == 1


def test_a_file_that_is_no_store_is_refused(tmp_path: Any) -> None:
    other = tmp_path / "other.db"
    db = sqlite3.connect(str(other))
    db.execute("CREATE TABLE things (x)")
    db.commit()
    db.close()
    for path, message in ((other, "not a usage store of FWShift"), (tmp_path / "missing.db", "no such usage store")):
        with pytest.raises(FwshiftError, match=message):
            usage.Store(str(path), create=False)
    text = tmp_path / "text.db"
    text.write_text("hello, not sqlite at all" * 100, encoding="utf-8")
    with pytest.raises(FwshiftError, match="not a usage store"):
        usage.Store(str(text))


def test_addresses_beyond_the_limit_are_kept_as_networks() -> None:
    policy = _regression().policy()
    lines = _filler() + [line(1 + i % 80, _rows("u3", 3), f"10.1.{i}.7") for i in range(20)]
    _evaluate(policy, lines, cap=1)
    r3 = next(rule for rule in policy.rules if rule.name == "R3").log_usage
    assert r3 is not None and r3.rolled_up and r3.connections == 20
    # 10.1.1.0/24 holds Host1 (10.1.1.1) whatever the address was: a network kept for the rest counts for what it may hold.
    assert r3.members["source"]["Host1"] >= 1


def test_objects_that_cannot_be_told_are_never_called_unused() -> None:
    cp = _regression()
    cp.add("updates", "dns-domain", is_sub_domain=False)
    cp.objects["updates"]["name"] = ".updates.example.com"
    cp.add("app", "application-site")
    cp.layers[0]["rulebase"][2]["destination"].append(cp.objects["updates"]["uid"])
    cp.layers[0]["rulebase"][2]["service"].append(cp.objects["app"]["uid"])
    policy = cp.policy()
    _evaluate(policy, _filler() + [line(1, _rows("u3", 3), port=443)])
    found = [f for f in _findings(policy) if f.name == "R3"]
    assert all(".updates.example.com" not in f.message and "'app'" not in f.message for f in found)
    assert [f.check for f in found] == ["UNUSED_RULE_SERVICE"]  # http only


def test_counters_and_logs_decide_together() -> None:
    cp = _regression()
    rules = cp.layers[0]["rulebase"]
    rules[0]["hits"] = hit(5, moment(1), moment(80))  # used by its counter, silent in the logs
    rules[2]["hits"] = hit(0)  # the counter proves nothing (no start), the logs show it used
    created = {"creation-time": {"posix": moment(-400) * 1000}}
    rules[1]["hits"] = hit(0)
    rules[1]["meta-info"] = created
    policy = cp.policy()
    _evaluate(policy, _filler() + [line(1, _rows("u3", 3), port=443), line(2, _rows("u3", 3), port=80)])
    found = {(f.check, f.name) for f in _findings(policy)}
    assert not any(name in ("R1", "R3") for _, name in found)
    assert ("UNUSED_RULE", "R2") in found  # the logs prove it, whatever the counter


def test_the_window() -> None:
    policy = _regression().policy()
    store = usage.Store(":memory:")
    usage.ingest(store, [("log", "\n".join(_filler()).encode())])
    assert usage.window(store) == usage.Window("2026-07-01", "2026-09-28")  # (90 days of _filler)
    assert usage.window(store, "30d").first == "2026-08-30"
    assert usage.window(store, "2026-09-01", "2026-09-10") == usage.Window("2026-09-01", "2026-09-10")
    for since, until, message in (("soon", "", "neither a number"), ("", "x", "not a day"), ("2026-12-01", "", "no window")):
        with pytest.raises(FwshiftError, match=message):
            usage.window(store, since, until)
    usage.evaluate(policy, store, usage.window(store, "30d"))
    assert policy.rules[0].log_usage is not None and policy.rules[0].log_usage.first_day == "2026-08-30"
    with pytest.raises(FwshiftError, match="holds no logs"):
        usage.window(usage.Store(":memory:"))


def test_members_are_counted_as_a_walk_through_the_addresses_counts_them() -> None:
    """Oracle: random groups, random connections; every object counts the connections whose address it holds."""
    rng = random.Random(23)
    for _ in range(25):
        cp = Export()
        nets = []
        for index in range(8):
            prefix = rng.choice([8, 16, 24, 28])
            base = ipaddress.ip_network(f"10.{rng.randrange(4)}.{rng.randrange(4)}.{rng.randrange(256) & 0xF0}/{prefix}", strict=False)
            cp.network(f"n{index}", str(base))
            nets.append((f"n{index}", base))
        for index in range(3):
            members = rng.sample([name for name, _ in nets] + [f"g{j}" for j in range(index)], rng.randint(1, 3))
            cp.add(f"g{index}", "group", members=[cp.objects[m]["uid"] for m in members])
        cell = rng.sample([name for name, _ in nets] + ["g0", "g1", "g2"], rng.randint(1, 4))
        cp.layer("Main", [cp.rule("R", cell, uid="u")])
        policy = seen(cp).policy()
        sources = [f"10.{rng.randrange(4)}.{rng.randrange(4)}.{rng.randrange(256)}" for _ in range(30)]
        _evaluate(policy, _filler() + [line(1 + i, _rows("u"), src) for i, src in enumerate(sources)])
        log = policy.rules[0].log_usage
        assert log is not None

        def holds(name: str, address: str) -> bool:
            if name in policy.address_groups:
                return any(holds(m, address) for m in policy.address_groups[name].members)
            return ipaddress.ip_address(address) in ipaddress.ip_network(policy.addresses[name].value)

        reach: List[str] = []
        todo = list(policy.rules[0].sources)
        while todo:
            name = todo.pop(0)
            if name not in reach:
                reach.append(name)
                todo += policy.address_groups[name].members if name in policy.address_groups else []
        expected = {name: sum(1 for src in sources if holds(name, src)) for name in reach}
        assert log.members["source"] == expected


# -- the command -------------------------------------------------------------------------------------


def test_the_sample_matches_its_golden_file(capsys: pytest.CaptureFixture[str]) -> None:
    import os

    out = DATA / "expected" / "checkpoint_sample.usage.txt"
    assert cli.main(["usage", str(DATA / "checkpoint_sample.json"), "--logs", str(DATA / "checkpoint_sample.log")]) == 0
    text = capsys.readouterr().out.replace(str(DATA) + os.sep, "")
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        out.write_text(text, encoding="utf-8")
    assert text == out.read_text(encoding="utf-8")


def test_the_command_writes_text_json_and_a_page(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    store, page = tmp_path / "usage.db", tmp_path / "usage.html"
    sample = [str(DATA / "checkpoint_sample.json"), "--logs", str(DATA / "checkpoint_sample.log"), "--store", str(store)]
    assert cli.main(["usage", *sample, "--json", "--html", str(page)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["window"] == {"first": "2026-07-03", "last": "2026-09-30", "days": 90}
    assert data["gateways"] == {"gw-edge": {"days_with_logs": 90, "unreadable_lines": 0}}
    assert {f["name"] for f in data["findings"] if f["check"] == "UNUSED_RULE"} >= {"Admins", "DMZ users", "DMZ access / Mail in"}
    html = page.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>") and "http://" not in html and "https://" not in html and "<script" not in html
    assert "Admins" in html and "prefers-color-scheme: dark" in html
    # A second run reads nothing again and says so; the store alone is enough after that.
    assert cli.main(["usage", *sample]) == 0
    assert "not read again" in capsys.readouterr().out
    assert cli.main(["usage", str(DATA / "checkpoint_sample.json"), "--store", str(store), "--since", "30d"]) == 0
    assert "window: 2026-09-01 to 2026-09-30 (30 days)" in capsys.readouterr().out


def test_the_command_refuses_what_it_cannot_do(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["usage", str(DATA / "asa_sample.cfg"), "--logs", str(DATA / "checkpoint_sample.log")]) == 1
    assert "Check Point, PAN-OS, FortiOS or iptables policy" in capsys.readouterr().err
    assert cli.main(["usage", str(DATA / "checkpoint_sample.json")]) == 1
    assert "--logs" in capsys.readouterr().err


def test_a_store_in_the_audit_and_in_a_conversion(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    store = tmp_path / "usage.db"
    assert cli.main(["usage", str(DATA / "checkpoint_sample.json"), "--logs", str(DATA / "checkpoint_sample.log"), "--store", str(store)]) == 0
    capsys.readouterr()
    assert cli.main(["audit", str(DATA / "checkpoint_sample.json"), "--usage-store", str(store)]) == 0
    text = capsys.readouterr().out
    assert "logs: " in text and "UNUSED_RULE: rule 'DMZ users'" in text and "UNUSED_RULE_OBJECT: rule 'DNS'" in text
    out, report = tmp_path / "out.set", tmp_path / "report.json"
    assert cli.main(["convert", str(DATA / "checkpoint_sample.json"), "--to", "panos", "-o", str(out), "--report-json", str(report), "-q",
                     "--usage-store", str(store), "--audit-action", "UNUSED_RULE=disable"]) == 0  # fmt: skip
    items = {item["name"]: item for item in json.loads(report.read_text(encoding="utf-8"))["items"]}
    assert "AUDIT_DISABLED" in [f["code"] for f in items["DMZ users"]["findings"]]
    assert cli.main(["audit", str(DATA / "asa_sample.cfg"), "--usage-store", str(store)]) == 1
    assert "Check Point, PAN-OS, FortiOS or iptables policy only" in capsys.readouterr().err
    assert ANY == "any"


# -- found in review (round 22) ----------------------------------------------------------------------


def test_the_layer_of_the_policy_is_found_however_it_is_applied() -> None:
    """H2: a main layer that only applies inline layers; a policy read from an inline layer; an export without the layer's uid."""
    cp = Export()
    cp.network("dmz", "10.20.0.0/24")
    cp.add("Inner", "access-layer")
    cp.layer("Main", [cp.rule("Apply", ["Any"], ["dmz"], "Inner Layer", uid="u-apply", inline_layer="Inner")])
    cp.layers.append({"uid": "uid-Inner", "name": "Inner", "from": 1, "to": 2, "total": 2,
                      "rulebase": [cp.rule("Web", ["Any"], ["dmz"], uid="u-web"), cp.rule("Seen", ["Any"], uid="u-seen")]})  # fmt: skip
    aged(cp)
    daily = [line(day, [(MAIN, 1, 0, "Inline", "u-apply"), ("uid-inner", 16777218, 1, "Accept", "u-seen")], minute=5) for day in range(90)]
    web = [line(3, [(MAIN, 1, 0, "Inline", "u-apply"), ("uid-inner", 16777217, 1, "Accept", "u-web")], dst="10.20.0.5")]
    policy = cp.policy()
    _evaluate(policy, daily + web)
    assert {rule.name: rule.log_usage.connections for rule in policy.rules if rule.log_usage} == {"Apply / Web": 1, "Apply / Seen": 90}  # type: ignore[union-attr]
    # Read from the inline layer itself: its rows have a parent rule, and still start the chain.
    inner = parse_inline(cp)
    _evaluate(inner, daily + web)
    assert {rule.name: rule.log_usage.connections for rule in inner.rules if rule.log_usage} == {"Web": 1, "Seen": 90}  # type: ignore[union-attr]
    # Without the uid of the layer the logs cannot be read against it.
    data = json.loads(cp.data())
    for layer in data:
        del layer["uid"]
    from fwshift.parsers import checkpoint as parse_checkpoint

    bare = parse_checkpoint.parse(json.dumps(data).encode(), Report(), layer="Main")
    _evaluate(bare, daily + web)
    assert all("does not give the uid of the layer" in " ".join(r.log_usage.no_evidence) for r in bare.rules if r.log_usage)  # type: ignore[union-attr]


def parse_inline(cp: Export) -> Policy:
    from fwshift.parsers import checkpoint as parse_checkpoint

    return parse_checkpoint.parse(cp.data(), Report(), layer="Inner")


def test_gateways_that_sent_no_logs_and_clusters(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """H3: --usage-gateway in the audit; a cluster whose members log under their own names."""
    cp = _regression()
    cp.layers[0]["rulebase"][2]["install-on"] = [cp.add("cluster-a", "CpmiGatewayCluster", ipv4_address="198.51.100.1")]
    policy = cp.policy()
    lines = _filler(gateway="member-1") + [line(4, _rows("u3", 3), gateway="member-2")]
    _evaluate(policy, lines, gateways=["cluster-a=member-1,member-2"])
    r3 = next(rule for rule in policy.rules if rule.name == "R3").log_usage
    assert r3 is not None and r3.connections == 1 and not r3.elsewhere and not r3.no_evidence
    store = tmp_path / "usage.db"
    path = tmp_path / "cp.json"
    path.write_bytes(_regression().data())
    log = tmp_path / "a.log"
    log.write_text("\n".join(_filler()), encoding="utf-8")
    assert cli.main(["usage", str(path), "--logs", str(log), "--store", str(store)]) == 0
    capsys.readouterr()
    assert cli.main(["audit", str(path), "--usage-store", str(store)]) == 0
    assert "UNUSED_RULE: rule 'R1'" in capsys.readouterr().out
    assert cli.main(["audit", str(path), "--usage-store", str(store), "--usage-gateway", "gw-b"]) == 0
    text = capsys.readouterr().out
    assert "UNUSED_RULE: rule 'R1'" not in text and "gw-b sent no logs" in text


def test_show_logs_rows_are_read_from_their_own_objects() -> None:
    """M1: the fields of the log next to its match table are not rows; pages one after the other (M6)."""
    page = {"logs": [{"time": "2026-07-01T12:00:00Z", "orig": "gw-a", "action": "Accept", "src": "10.1.5.5", "dst": "10.20.0.5",
                      "proto": "6", "service": "443", "rule_uid": "u-web", "rule_name": "Web", "layer_name": "Inner",
                      "match_table": [{"layer_uuid": "L1", "match_id": 1, "parent_rule": 0, "rule_action": "Inline", "rule_uid": "u-apply"},
                                      {"layer_uuid": "L2", "match_id": 16777217, "parent_rule": 1, "rule_action": "Accept", "rule_uid": "u-web"}]}]}  # fmt: skip
    lines = list(logs.read((json.dumps(page) + "\n" + json.dumps(page)).encode()))
    assert len(lines) == 2 and all(l.record is not None for l in lines)
    assert [r.rule_uid for r in lines[0].record.layers] == ["u-apply", "u-web"] and not lines[0].record.loose_uids  # type: ignore[union-attr]


def test_a_gateway_that_logged_no_accepted_connection_proves_nothing_for_allow_rules() -> None:
    """M3: an exporter that sends drops only; lines that name no rule do not count as a day logged."""
    policy = _regression().policy()
    drops = [line(day, _rows("u4", 4), action="Drop", minute=5) for day in range(90)]
    _evaluate(policy, drops)
    r1 = next(rule for rule in policy.rules if rule.name == "R1").log_usage
    assert r1 is not None and any("logged no accepted connection" in reason for reason in r1.no_evidence)
    nothing = [line(day, [], action="Drop", minute=5) for day in range(90)] + [line(89, _rows("u-seen", 99))]
    _evaluate(policy, nothing)
    r1 = next(rule for rule in policy.rules if rule.name == "R1").log_usage
    assert r1 is not None and "gateway gw-a sent logs on 1 of the 90 days" in r1.no_evidence


def test_the_limit_of_addresses_holds_across_runs(tmp_path: Any) -> None:
    """M4: the addresses kept per rule are in a table of their own, and the limit counts them across runs."""
    policy = _regression().policy()
    path = str(tmp_path / "usage.db")
    for run in range(3):
        store = usage.Store(path)
        usage.ingest(store, [(f"{run}.log", "\n".join(_filler() + [line(1, _rows("u3", 3), f"10.1.{run}.{i}") for i in range(4)]).encode())], cap=6)
        store.close()
    store = usage.Store(path, create=False)
    kept = store.db.execute("SELECT COUNT(*) FROM kept WHERE side = 'source' AND rule_key LIKE '%u3%'").fetchone()[0]
    rows = {row[0] for row in store.db.execute("SELECT DISTINCT src FROM records WHERE rule_key LIKE '%u3%'")}
    usage.evaluate(policy, store, usage.window(store))
    store.close()
    assert kept == 6 and "10.1.2.0/24" in rows
    assert next(rule for rule in policy.rules if rule.name == "R3").log_usage.rolled_up  # type: ignore[union-attr]


def test_splunk_keys_with_a_dash_and_users_with_a_comma() -> None:
    """M5, L6."""
    text = ("time=1782907200|product=Firewall|layer_uuid=L1|match_id=1|parent_rule=0|rule_uid=u1|action=Accept|origin=198.51.100.1|"
            "originsicname=CN\\=gw-a,O\\=m|fg-1_client_in_rule_name=x|dst=10.20.0.5|proto=6|service=443|src=10.1.5.5|src_user_name=Doe, John (jdoe)|")  # fmt: skip
    record = logs.read_line(text).record
    assert record is not None and record.users == ["Doe, John (jdoe)"]
    cp = _regression()
    policy = cp.policy()
    _evaluate(policy, _filler() + [line(1, _rows("u3", 3), extra=[("src_user_name", "Doe, John (jdoe)")])])
    r3 = next(rule for rule in policy.rules if rule.name == "R3").log_usage
    assert r3 is not None and r3.members["user"] == {"Doe, John (jdoe)": 1}


def test_a_file_in_which_nothing_could_be_read_is_read_again_later(tmp_path: Any) -> None:
    """M6: not marked as read."""
    store = usage.Store(str(tmp_path / "usage.db"))
    first = usage.ingest(store, [("odd.log", b"LEEF:2.0|Check Point|VPN-1 & FireWall-1|1.0|Accept|devTime=1\n")])
    again = usage.ingest(store, [("odd.log", b"LEEF:2.0|Check Point|VPN-1 & FireWall-1|1.0|Accept|devTime=1\n")])
    assert first.files == again.files == ["odd.log"] and not again.already
    store.close()


def test_the_translated_address_of_automatic_nat_is_not_a_member_of_its_own() -> None:
    """L1."""
    cp = _regression()
    cp.objects["Srv"]["nat-settings"] = {"auto-rule": True, "ipv4-address": "203.0.113.10", "method": "static"}
    policy = cp.policy()
    assert "Srv_valid_address" in policy.rules[2].destinations
    _evaluate(policy, _filler() + [line(1, _rows("u3", 3), dst="172.16.0.10", port=443), line(2, _rows("u3", 3), dst="172.16.0.10", port=80)])
    assert not [f for f in _findings(policy) if f.name == "R3"]


def test_without_the_age_of_a_rule_the_logs_prove_nothing() -> None:
    """L3, as for hit counters."""
    cp = _regression()
    for rule in cp.layers[0]["rulebase"]:
        rule.pop("meta-info", None)
    policy = cp.policy()
    _evaluate(policy, _filler())
    assert {f.check for f in _findings(policy) if f.name == "R1"} == {"NO_USAGE_EVIDENCE"}


def test_odd_stores_and_windows_end_in_a_message(tmp_path: Any) -> None:
    """L4: no traceback."""
    path = tmp_path / "usage.db"
    store = usage.Store(str(path))
    usage.ingest(store, [("a.log", "\n".join(_filler()).encode())])
    store.db.execute("INSERT INTO records VALUES ('2026-07-02', 'gw-a', 'not json', '1.2.3.4', '5.6.7.8', 6, 443, '', 3)")
    store.db.commit()
    policy = _regression().policy()
    result = usage.evaluate(policy, store, usage.window(store))
    assert result.unattributed.get("a record of the store that cannot be read") == 3
    with pytest.raises(FwshiftError, match="calendar"):
        usage.window(store, "2d", "0001-01-01")
    store.close()
    other = tmp_path / "other.db"
    db = sqlite3.connect(str(other))
    db.executescript(usage._SCHEMA.replace("count INTEGER NOT NULL,", "hits INTEGER NOT NULL,"))
    db.execute("INSERT INTO meta VALUES ('format', ?)", (usage.FORMAT,))
    db.commit()
    db.close()
    with pytest.raises(FwshiftError, match="not as this version writes them"):
        usage.Store(str(other), create=False)


def test_reasons_carry_no_text_of_the_line() -> None:
    """L5: a reason is one of a few, whatever the line held."""
    reasons = set()
    for index in range(200):
        text = f'<134>1 2026-07-01T12:00:00Z m CheckPoint 1 - [action:"Accept"; \x1b[31mkey{index}: "v"; time:"1"]'
        reasons.add(logs.read_line(text).reason)
    assert len(reasons) == 1 and "\x1b" not in reasons.pop()
