# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The test plan of the FWShift lab, and the check of what the probes saw against it.

The plan is every flow between the test hosts for a fixed set of services. What each flow should get is worked out
from the *source* policy (``lab/policy/lab_panos.xml``) with FWShift's own first-match simulation, not from the
conversion: the lab checks the converted policy on a real device against what the source meant.

A flow is **asserted** when the source decides it without doubt and every rule that might match it was converted
exactly (the conversion report says so). Any other flow is still sent and its result shown, but a difference there is
one the report already announced, not a failure of the lab run.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "policy" / "lab_panos.xml"


@dataclass(frozen=True)
class Host:
    name: str
    zone: str
    ip: str


ZONES: Dict[str, str] = {"inside": "10.20.1.0/24", "dmz": "10.20.2.0/24", "outside": "10.20.3.0/24"}
HOSTS: Tuple[Host, ...] = (
    Host("in10", "inside", "10.20.1.10"),
    Host("in11", "inside", "10.20.1.11"),
    Host("dmz10", "dmz", "10.20.2.10"),
    Host("dmz11", "dmz", "10.20.2.11"),
    Host("out10", "outside", "10.20.3.10"),
)
# (protocol, port or ICMP type). 8011 lies outside the range the policy opens, 123 is a UDP port no rule names.
SERVICES: Tuple[Tuple[str, int], ...] = (("tcp", 22), ("tcp", 80), ("tcp", 443), ("tcp", 8005), ("tcp", 8011), ("udp", 53),
                                         ("udp", 123), ("icmp", 8))
TCP_PORTS = sorted({p for proto, p in SERVICES if proto == "tcp"})
UDP_PORTS = sorted({p for proto, p in SERVICES if proto == "udp"})
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}


def gateway(zone: str) -> str:
    """The first address of a zone's network, where a firewall of tier 2 and 3 has its interface (.4 on AWS)."""
    return str(ipaddress.ip_network(ZONES[zone]).network_address + 1)


def zone_options(names: Optional[Dict[str, str]] = None) -> List[str]:
    """--zone-network for each lab zone; with --zone-map, the option takes the zone's name after the map (names)."""
    out: List[str] = []
    for zone, net in ZONES.items():
        out += ["--zone-network", f"{(names or {}).get(zone, zone)}={net}"]
    return out


def _load_source() -> Any:
    from fwshift import cli
    from fwshift.report import Report

    return cli.load(POLICY.read_bytes(), "panos", Report())


def _statuses(report: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Rule name -> status of the conversion ("exact", "approximated", "needs-review", "skipped"; "disabled" too)."""
    if report is None:
        return {}
    out: Dict[str, str] = {}
    for item in report.get("items", []):
        if item.get("kind") == "rule":
            out[item["name"]] = "disabled" if item.get("disabled") else item.get("status", "")
    return out


def _default_notes(report: Optional[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """The notes of a conversion that say the default inside a zone, or between zones, was not written as it is
    (INTRAZONE_DEFAULT, INTERZONE_DEFAULT, AWS_DEFAULT_NOT_WRITTEN ...): anything above info."""
    inside: List[str] = []
    between: List[str] = []
    for note in (report or {}).get("notes", []):
        code, severity = note.get("code", ""), note.get("severity", "info")
        if severity == "info":
            continue
        if "INTRAZONE" in code:
            inside.append(code)
        elif "INTERZONE" in code or "DEFAULT" in code:
            between.append(code)
    return inside, between


def build_plan(target: str, report: Optional[Dict[str, Any]] = None, hosts: Sequence[Host] = HOSTS, through_target_inside_zone: bool = True,
               refused_means: str = "blocked") -> Dict[str, Any]:  # fmt: skip
    """The flows, what the source decides for each, and which are asserted.

    through_target_inside_zone: whether traffic between two hosts of one zone passes the target (security groups and
    NSGs apply per interface: yes; a firewall between bridges or subnets: no, those flows test nothing there).
    refused_means: what a TCP reset says on this target: "blocked" where the target can reject, "passed" where it
    cannot (cloud security groups never answer: a reset came from the host behind them)."""
    from fwshift.model import Action
    from fwshift.simulate import Simulator

    policy = _load_source()
    simulator = Simulator(policy)
    statuses = _statuses(report)
    inside_notes, between_notes = _default_notes(report)
    flows: List[Dict[str, Any]] = []
    for a in hosts:
        for b in hosts:
            if a == b:
                continue
            for protocol, port in SERVICES:
                point = (a.zone, b.zone, a.ip, b.ip, NUMBERS[protocol], port)
                found = simulator.attribute(point)
                might = _might(simulator, point)
                if found.certain is not None:
                    expected, decided_by = ("passed" if found.certain.action == Action.ALLOW else "blocked"), found.certain.name
                elif not found.possible and found.reason.startswith("no rule"):
                    default = policy.default_intrazone if a.zone == b.zone else policy.default_interzone
                    expected, decided_by = ("passed" if default == Action.ALLOW else "blocked"), "(default)"
                else:
                    expected, decided_by = "unknown", ", ".join(r.name for r in found.possible)
                inexact = sorted({name for name in might if statuses and statuses.get(name, "missing") != "exact"})
                local = a.zone == b.zone and not through_target_inside_zone
                notes = (inside_notes if a.zone == b.zone else between_notes) if decided_by == "(default)" else []
                if local:
                    why = "inside one zone: it does not pass the target"
                elif expected == "unknown":
                    why = "the source does not decide it surely"
                elif inexact:
                    why = "rules not converted exactly: " + ", ".join(inexact)
                elif notes:
                    why = "the default is not written as it is: " + ", ".join(notes)
                else:
                    why = ""
                flows.append({"id": f"{a.name}>{b.name}:{protocol}/{port}", "src": a.ip, "dst": b.ip, "src_zone": a.zone, "dst_zone": b.zone,
                              "protocol": protocol, "port": port, "expected": expected, "decided_by": decided_by, "asserted": not why,
                              "local": local, "why_not_asserted": why})  # fmt: skip
    return {"target": target, "policy": str(POLICY.relative_to(ROOT.parent)), "hosts": [h.__dict__ for h in hosts], "refused_means": refused_means,
            "flows": flows}  # fmt: skip


def _might(simulator: Any, point: Tuple[str, str, str, str, int, int]) -> List[str]:
    """The rules that might match a connection: those that decide it, and those a conversion that is not exact could
    make decide it instead."""
    from fwshift.simulate import _span

    in_zone, out_zone, src, dst, protocol, port = point
    names = []
    for rule, match in simulator.rules:
        if simulator._zones(match, in_zone, out_zone, sure=False) and simulator._addresses(match, _span(src), _span(dst), sure=False) and \
                simulator._services(match, protocol, port, sure=False):  # fmt: skip
            names.append(rule.name)
    return names


def check(plan: Dict[str, Any], results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """What the probes saw against the plan. A "refused" TCP flow counts as the plan says (blocked, unless the target
    cannot reject). A flow inside one zone that does not pass the target is "local": shown, not counted."""
    seen = {r["id"]: r["observed"] for r in results}
    refused = plan.get("refused_means", "blocked")
    rows = []
    for flow in plan["flows"]:
        observed = seen.get(flow["id"], "missing")
        got = refused if observed == "refused" else observed
        if observed in ("missing", "error"):
            verdict = "error"
        elif flow.get("local"):
            verdict = "local"
        elif flow["expected"] == "unknown":
            verdict = "info"
        elif got == flow["expected"]:
            verdict = "ok" if flow["asserted"] else "ok-unasserted"
        else:
            verdict = "FAIL" if flow["asserted"] else "differs-announced"
        rows.append({**flow, "observed": observed, "verdict": verdict})
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    # Not a vacuous pass: asserted flows that should pass and asserted flows that should be blocked, both seen right.
    both = {row["expected"] for row in rows if row["verdict"] == "ok"} >= {"passed", "blocked"}
    passed = counts.get("FAIL", 0) == 0 and counts.get("error", 0) == 0 and both
    return {"target": plan["target"], "counts": counts, "passed": passed, "vacuous": not both, "rows": rows}


def render(summary: Dict[str, Any]) -> str:
    lines = [f"FWShift lab: {summary['target']}", "  " + ", ".join(f"{k} {v}" for k, v in sorted(summary["counts"].items()))]
    for row in summary["rows"]:
        if row["verdict"] in ("FAIL", "error", "differs-announced"):
            note = f" ({row['why_not_asserted']})" if row["verdict"] == "differs-announced" else ""
            lines.append(f"  {row['verdict']:<18} {row['id']:<28} expected {row['expected']:<7} saw {row['observed']:<8} "
                         f"decided by {row['decided_by']}{note}")  # fmt: skip
    if summary.get("vacuous"):
        lines.append("  no asserted flow both passed and was blocked as expected: the run shows nothing")
    if summary.get("dry_run"):
        lines.append("  result: DRY RUN (no connection was made: the results are what the plan expects)")
    else:
        lines.append("  result: " + ("PASSED" if summary["passed"] else "FAILED"))
    return "\n".join(lines) + "\n"


def save(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
