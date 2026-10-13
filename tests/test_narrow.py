# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Narrower rules from what the logs show (0.17.0; docs/RULE_USAGE.md 6.7): WIDER_THAN_TRAFFIC and fwshift usage --propose.

The promise: a proposed rule is never wider than its rule, holds every connection the logs show went through it, and
is never made for a blocking rule or a rule whose logs prove nothing. Every address here is a documentation or
private address.
"""

from __future__ import annotations

import ipaddress
import json
import random
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

import pytest

from fwshift import audit, cli, narrow
from fwshift.model import ANY, Action, Address, AddressKind, LogUsage, Policy, Protocol, Rule, Service, ServiceEntry
from fwshift.netutil import Interval
from fwshift.report import Report

DATA = Path(__file__).resolve().parent / "data"


def _span(text: str) -> Tuple[int, int, int]:
    network = ipaddress.ip_network(text, strict=False)
    return network.version, int(network.network_address), int(network.broadcast_address)


def _inside(span: Tuple[int, int, int], intervals: Sequence[Interval]) -> bool:
    """Whether every address of the span is in the intervals, which may touch one another."""
    version, first, last = span
    point = first
    for v, a, b in sorted(intervals):
        if v != version or b < point:
            continue
        if a > point:
            return False
        point = b + 1
        if point > last:
            return True
    return point > last


def _random_cell(rng: random.Random) -> List[Interval]:
    out: List[Interval] = []
    for _ in range(rng.randrange(1, 4)):
        if rng.random() < 0.15:
            out.append((4, 0, 2**32 - 1) if rng.random() < 0.5 else (6, 0, 2**128 - 1))
        elif rng.random() < 0.7:
            length = rng.choice([16, 20, 23, 24, 26, 28, 30, 32])
            network = ipaddress.ip_network(f"10.{rng.randrange(4)}.{rng.randrange(256)}.{rng.randrange(256)}/{length}", strict=False)
            out.append((4, int(network.network_address), int(network.broadcast_address)))
        else:
            first = int(ipaddress.ip_address("2001:db8::")) + rng.randrange(2**20)
            out.append((6, first, first + rng.randrange(1, 2**12)))
    return out


def _point_in(rng: random.Random, cell: Sequence[Interval]) -> str:
    version, first, last = rng.choice(list(cell))
    value = rng.randint(first, last)
    if rng.random() < 0.3 and version == 4 and first <= value & ~0xFF and (value | 0xFF) <= last:
        return f"{ipaddress.IPv4Address(value & ~0xFF)}/24"  # (what a store keeps beyond its limit)
    return str(ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value))


@pytest.mark.parametrize("seed", range(40))
def test_narrower_addresses_are_inside_the_cell_and_hold_what_was_seen(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(30):
        cell = _random_cell(rng)
        seen = [_point_in(rng, cell) for _ in range(rng.choice([1, 2, 5, 20, 60]))]
        found = narrow.addresses(seen, cell)
        if found is None:
            continue  # (too many parts: the cell is left as it is)
        networks, held, kept, share = found
        assert len(networks) <= narrow.MAX_PARTS
        spans = [_span(network) for network in networks]
        assert all(_inside(span, cell) for span in spans), (seed, cell, networks)  # never wider than the cell
        assert all(_inside(_span(text), spans) for text in seen), (seed, seen, networks)  # every connection kept
        assert 0 < share <= 1 and kept <= held
    outside = narrow.addresses(["192.0.2.1"], [(4, int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.0.0.255")))])
    assert outside is None  # (the model and the log disagree: nothing is proposed)


def _services(rng: random.Random) -> Tuple[Any, List[ServiceEntry]]:
    entries: List[ServiceEntry] = []
    for _ in range(rng.randrange(1, 4)):
        roll = rng.random()
        if roll < 0.5:
            low = rng.choice([22, 80, 443, 1000, 8000])
            entries.append(ServiceEntry(rng.choice([Protocol.TCP, Protocol.UDP]), dst_ports=f"{low}-{low + rng.randrange(0, 50)}"))
        elif roll < 0.6:
            entries.append(ServiceEntry(Protocol.TCP, dst_ports="443", src_ports="1024-65535"))  # (a source port: not whole)
        elif roll < 0.75:
            entries.append(ServiceEntry(Protocol.ICMP, icmp_type=rng.choice([0, 8])))
        elif roll < 0.85:
            entries.append(ServiceEntry(Protocol.IP, ip_protocol=47))
        else:
            entries.append(ServiceEntry(Protocol.IP))  # (every protocol)
    p = Policy(vendor="panos")
    p.services["s"] = Service("s", entries)
    known, _ = audit._Reader(p).service_set(["s"])
    return known, entries


def _holds(entries: Sequence[ServiceEntry], protocol: int, port: int) -> bool:
    for entry in entries:
        if entry.protocol == Protocol.IP and entry.ip_protocol in (None, protocol):
            return True
        number = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.ICMP: 1}.get(entry.protocol)
        if number != protocol:
            continue
        if protocol in (6, 17) and not entry.src_ports:
            low, _, high = entry.dst_ports.partition("-")
            if int(low) <= port <= int(high or low):
                return True
        if protocol == 1 and entry.icmp_type == port and entry.icmp_code is None:
            return True
    return False


@pytest.mark.parametrize("seed", range(30))
def test_narrower_services_are_inside_the_cell(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(20):
        cell, entries = _services(rng)
        used = [f"{rng.choice([6, 17, 1, 47])}/{rng.choice([22, 25, 80, 443, 1010, 8020, 0, 8])}" for _ in range(rng.randrange(1, 6))]
        used = [text if not text.startswith("47/") else "47/-1" for text in used]
        found = narrow.services(used, cell)
        inside = all(_holds(entries, int(t.split("/")[0]), int(t.split("/")[1])) for t in used)
        if not inside:
            assert found is None, (seed, entries, used)
            continue
        assert found is not None, (seed, entries, used)
        proposed, held, kept, share = found
        assert kept == len(set(used)) and kept <= held and len(proposed) == kept


# -- the check ------------------------------------------------------------------------------------------


def _rule(name: str = "Web", sources: Sequence[str] = (ANY,), destinations: Sequence[str] = (ANY,), services: Sequence[str] = (ANY,),
          action: Action = Action.ALLOW) -> Rule:  # fmt: skip
    rule = Rule(name=name, sources=list(sources), destinations=list(destinations), services=list(services), action=action)
    rule.origin = name
    rule.log_usage = LogUsage("2026-07-01", "2026-09-28", connections=40, seen={"source": ["10.10.4.20", "10.10.4.21"],
                              "destination": ["192.0.2.80"], "service": ["6/443"]})  # fmt: skip
    return rule


def _findings(p: Policy, config: Optional[audit.AuditConfig] = None) -> List[audit.Finding]:
    return [f for f in audit.run(p, config or audit.AuditConfig()).before if f.check == "WIDER_THAN_TRAFFIC"]


def test_what_gets_a_narrower_rule_and_what_does_not() -> None:
    p = Policy(vendor="panos")
    p.rules = [_rule()]
    found = _findings(p)
    assert len(found) == 1 and found[0].proposal == {"sources": ["10.10.4.20/31"], "destinations": ["192.0.2.80/32"], "services": ["tcp/443"],
                                                     "narrowed": ["sources", "destinations", "services"]}  # fmt: skip
    assert "less than 0.01%" in found[0].message and "had 40 connection(s)" in found[0].message
    for change in ("deny", "no evidence", "unused", "possible only", "negated", "unsupported", "shared", "nat", "blind"):
        rule = _rule()
        log = rule.log_usage
        assert log is not None
        if change == "deny":
            rule.action = Action.DENY
        elif change == "no evidence":
            log.no_evidence = ["it does not log its connections"]
        elif change == "unused":
            log.connections = 0
        elif change == "possible only":
            log.connections, log.possible = 0, 40
        elif change == "negated":
            rule.sources, rule.negate_source = ["10.10.0.0/16"], True
            p.addresses["10.10.0.0/16"] = Address("10.10.0.0/16", AddressKind.NETWORK, "10.10.0.0/16")
            log.seen = {"source": ["192.0.2.7"]}  # (outside the listed: what the rule matched)
        elif change == "unsupported":
            rule.unsupported = ["a criterion the model does not hold"]
        elif change == "shared":
            log.shared = 10
        elif change == "nat":
            rule.nat_added = {ANY: ["nat-1"]}
            log.seen.pop("source")
            log.seen.pop("service")
        elif change == "blind":
            log.blind = ["source", "destination", "service"]
        p.rules = [rule]
        assert not _findings(p), change
    # The share decides: 2 of 16 addresses is 12.5%, more than the 10% of the default.
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.10.4.16/28")
    p.rules = [_rule(sources=["lan"], destinations=["lan"])]
    p.rules[0].log_usage.seen = {"source": ["10.10.4.20", "10.10.4.21"], "destination": ["10.10.4.20", "10.10.4.21"]}  # type: ignore[union-attr]
    assert not _findings(p)
    config = audit.AuditConfig()
    config.wider_than_traffic = 20
    assert _findings(p, config)[0].proposal["sources"] == ["10.10.4.20/31"]


def test_a_host_name_and_a_negation_stay_as_they_are() -> None:
    p = Policy(vendor="panos")
    p.addresses["updates"] = Address("updates", AddressKind.FQDN, "updates.example.com")
    p.rules = [_rule(destinations=["updates"])]
    found = _findings(p)
    assert found and found[0].proposal["destinations"] == ["updates"]  # (a host name: what it holds is not known)


def test_the_threshold_in_the_configuration() -> None:
    config = audit.load_config('{"thresholds": {"wider_than_traffic": 25}}')
    assert config.wider_than_traffic == 25
    with pytest.raises(Exception, match="wider_than_traffic must lie between 1 and 99"):
        audit.load_config('{"thresholds": {"wider_than_traffic": 100}}')


# -- the samples, and what --propose writes --------------------------------------------------------------


def _usage(args: List[str], capsys: pytest.CaptureFixture[str]) -> Any:
    assert cli.main(["usage", str(DATA / "iptables_logged.rules"), "--logs", str(DATA / "iptables_logged.log"), "--log-year", "2026",
                     "--unchanged-since", "2026-01-01", *args]) == 0  # fmt: skip
    return capsys.readouterr().out


def test_the_proposals_of_iptables_loaded_back_are_inside_their_rules(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """The proposed rules, written as iptables rules and read back, are never wider than their rules, and hold their traffic."""
    out = tmp_path / "narrow.rules"
    data = json.loads(_usage(["--json", "--propose", str(out), "--propose-to", "iptables"], capsys))
    proposals = {f["name"]: f["proposal"] for f in data["findings"] if f["check"] == "WIDER_THAN_TRAFFIC"}
    assert set(proposals) == {"LAN web", "LAN DNS", "Inbound web", "Admins SSH", "Ping the DMZ", "Partner tunnel"}
    original = cli.load((DATA / "iptables_logged.rules").read_bytes(), "iptables", Report())
    proposed = cli.load(out.read_bytes(), "iptables", Report())
    assert sorted(rule.name for rule in proposed.rules) == sorted(f"{name}-narrowed" for name in proposals)
    before, after = audit._Reader(original), audit._Reader(proposed)
    rules = {rule["name"]: rule for rule in data["rules"]}
    for rule in proposed.rules:
        source = next(r for r in original.rules if r.name == rule.name[: -len("-narrowed")])
        old, new = before.match(source, original.rules.index(source)), after.match(rule, proposed.rules.index(rule))
        assert new.covers and old.covers and new.zones == old.zones
        for wide, narrow_ in ((old.src_under, new.src_over), (old.dst_under, new.dst_over)):
            assert all(_inside(span, wide) for span in narrow_), rule.name
        assert new.svc_over.minus(old.svc_under).empty(), rule.name
        members = rules[source.name]["members"]
        assert members  # (the rule was used)
    log = Path(DATA / "iptables_logged.log").read_text(encoding="utf-8")
    assert "SRC=10.10.4.20 DST=203.0.113.200" in log and "-s 10.10.4.20/32 -d 203.0.113.200/32 -p tcp -m tcp --dport 443" in out.read_text()


def test_accepted_findings_are_not_written(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "narrow.json"
    text = _usage(["--propose", str(out), "--audit-accept", "LAN web=WIDER_THAN_TRAFFIC"], capsys)
    model = json.loads(out.read_text(encoding="utf-8"))
    assert "LAN web-narrowed" not in [rule["name"] for rule in model["rules"]] and len(model["rules"]) == 5
    assert "Narrower rules" in text and "written to" in text and "(5 rule(s), json)" in text
    assert all(rule["source_ids"] == {} and rule["log_usage"] is None for rule in model["rules"])
    nothing = tmp_path / "none.rules"
    _usage(["--propose", str(nothing), "--audit-action", "WIDER_THAN_TRAFFIC=off"], capsys)
    assert nothing.read_text(encoding="utf-8") == ""


def test_objects_of_a_proposal_do_not_take_a_name_that_holds_something_else() -> None:
    p = Policy(vendor="panos")
    p.addresses["10.10.4.20"] = Address("10.10.4.20", AddressKind.NETWORK, "10.10.9.9/32")
    p.services["tcp-443"] = Service("tcp-443", [ServiceEntry(Protocol.TCP, dst_ports="8443")])
    rule = _rule()
    p.rules = [rule]
    built = narrow.build(p, [(rule, {"sources": ["10.10.4.20/32"], "destinations": [ANY], "services": ["tcp/443"]})])
    new = built.rules[0]
    assert new.name == "Web-narrowed" and new.sources == ["10.10.4.20-narrow"] and new.services == ["tcp-443-narrow"]
    assert built.addresses["10.10.4.20-narrow"].value == "10.10.4.20/32" and built.services["tcp-443-narrow"].entries[0].dst_ports == "443"
    assert p.rules == [rule] and "10.10.4.20-narrow" not in p.addresses  # (the policy itself is left as it is)


# -- review round 25 ------------------------------------------------------------------------------------


def test_r25_a_proposal_does_not_keep_the_pre_nat_address_of_a_dropped_nat_rule(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rules = tmp_path / "nat.rules"
    rules.write_text("*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A PREROUTING -i eth0 -d 203.0.113.10/32 -p tcp --dport 443 "
                     "-j DNAT --to-destination 10.20.0.10:8443\nCOMMIT\n*filter\n:FORWARD DROP [0:0]\n"
                     "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix \"n \"\n"
                     "-A FORWARD -i eth0 -o eth2 -d 10.20.0.10/32 -p tcp --dport 8443 -m comment --comment \"Inbound web\" -j ACCEPT\nCOMMIT\n",
                     encoding="utf-8")  # fmt: skip
    log = tmp_path / "nat.log"
    log.write_text("".join(f"Sep {day:2d} 10:00:00 fw1 kernel: n IN=eth0 OUT=eth2 SRC=192.0.2.80 DST=10.20.0.10 LEN=60 PROTO=TCP SPT=1 "
                           "DPT=8443 SYN URGP=0\n" for day in range(1, 31)), encoding="utf-8")  # fmt: skip
    out = tmp_path / "narrow.rules"
    assert cli.main(["usage", str(rules), "--logs", str(log), "--log-year", "2026", "--unchanged-since", "2026-01-01", "--propose", str(out),
                     "--propose-to", "iptables", "--since", "30d"]) == 0  # fmt: skip
    text = capsys.readouterr().out
    written = [line for line in out.read_text(encoding="utf-8").splitlines() if "narrowed" in line]
    assert len(written) == 1 and "-s 192.0.2.80/32 -d 10.20.0.10/32" in written[0] and "203.0.113.10" not in written[0]
    report = Path(str(out) + ".report.txt")
    assert report.exists() and "its conversion report" in text and "do not load it as it is" in text


def test_r25_what_a_pan_os_proposal_keeps(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "narrow.set"
    assert cli.main(["usage", str(DATA / "panos_logged.xml"), "--logs", str(DATA / "panos_logged.log"), "--unchanged-since", "2026-01-01",
                     "--propose", str(out), "--propose-to", "panos"]) == 0  # fmt: skip
    text = out.read_text(encoding="utf-8")
    assert "set rulebase security rules Allow-Web-Out-narrowed log-setting to-syslog" in text  # (its logs still reach syslog)
    assert "set rulebase security rules Allow-DNS-narrowed destination dns-1" in text  # (an object that holds just that address)
    assert "set vsys" not in text
    capsys.readouterr()


def test_r25_fortios_destinations_are_narrowed_unless_they_name_a_virtual_ip(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["usage", str(DATA / "fortios_sample.conf"), "--logs", str(DATA / "fortios_sample.log"), "--unchanged-since", "2026-01-01",
                     "--json"]) == 0  # fmt: skip
    data = json.loads(capsys.readouterr().out)
    proposals = {f["name"]: f["proposal"] for f in data["findings"] if f["check"] == "WIDER_THAN_TRAFFIC"}
    assert "destinations" in proposals["LAN to Internet"]["narrowed"] and proposals["Inbound web"]["destinations"] == ["vip-web"]
    assert "destinations" not in proposals["Inbound web"]["narrowed"]


def test_r25_too_many_services_and_a_connection_without_an_address() -> None:
    p = Policy(vendor="panos")
    rule = _rule()
    rule.log_usage.seen = {"service": [f"6/{port}" for port in range(1000, 1000 + narrow.MAX_PARTS + 1)]}  # type: ignore[union-attr]
    p.rules = [rule]
    assert not _findings(p)
    # A line without its source address: the sources may have been any of them, and are not narrowed.
    from test_traffic_logs import _evaluate, _policy, pan

    q = _policy("panos", [("Web", {"panos.name": "Web"})], scope="vsys1")
    q.rules[0].handling["log-setting"] = "to-syslog"
    lines = [pan(rule="Web", session=d + 1, zoned=f"2026-09-{1 + d:02d}T12:00:00.000+02:00") for d in range(30)]
    lines.append(pan(rule="Web", session=99, src="", zoned="2026-09-15T13:00:00.000+02:00"))
    _evaluate(q, lines, "panos")
    log = q.rules[0].log_usage
    assert log is not None and log.blind == ["source"] and log.seen["destination"] == ["203.0.113.200"]
    found = _findings(q)
    assert found and found[0].proposal["narrowed"] == ["destinations", "services"]


def test_r25_a_narrowed_cell_of_a_negated_rule_is_not_negated() -> None:
    p = Policy(vendor="panos")
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.10.0.0/16")
    rule = _rule(sources=["lan"])
    rule.negate_source = True
    p.rules = [rule]
    built = narrow.build(p, [(rule, {"sources": ["192.0.2.7/32"], "destinations": [ANY], "services": [ANY]})])
    assert built.rules[0].sources == ["192.0.2.7"] and not built.rules[0].negate_source
