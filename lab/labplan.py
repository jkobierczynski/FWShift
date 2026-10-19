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
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

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


# -- NAT ---------------------------------------------------------------------------------------------------------------
#
# The lab policy hides the inside behind the firewall's outside address and publishes the web server on the outside
# (0.37.0). What each connection should look like after NAT is worked out here from the source's NAT rules, first match
# on the connection as it arrives (PAN-OS): which address the receiving host sees the connection come from (seen_from),
# and which host answers a connection to a published address (answered_by). The probe reports both.

# Findings of a NAT conversion that only widen where a rule applies: the translation of a connection the rule matched
# in the source is the same; a connection the rule did not match, and now might, is not asserted. NAT_INPUT_INTERFACE:
# the rule applies whatever interface a connection comes in by (its source zone); NAT_ZONES: whatever its zones.
WIDENING = {"NAT_INPUT_INTERFACE": (False, True), "NAT_ZONES": (False, False)}


def _networks(policy: Any, name: str, depth: int = 0) -> List[Any]:
    """The networks an address object or group stands for (any: everything)."""
    if name in ("any", "ANY") or depth > 16:
        return [ipaddress.ip_network("0.0.0.0/0")]
    if name in policy.addresses:
        value = policy.addresses[name].value
        try:
            return [ipaddress.ip_network(value, strict=False)]
        except ValueError:
            return []
    if name in policy.address_groups:
        return [n for member in policy.address_groups[name].members for n in _networks(policy, member, depth + 1)]
    try:
        return [ipaddress.ip_network(name, strict=False)]
    except ValueError:
        return []


def _in(policy: Any, ip: str, names: Sequence[str]) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in net for name in names for net in _networks(policy, name))


def _service_matches(policy: Any, name: str, protocol: str, port: Optional[int], depth: int = 0) -> bool:
    if name in ("any", "ANY", "application-default"):
        return True
    if name in policy.service_groups and depth < 16:
        return any(_service_matches(policy, m, protocol, port, depth + 1) for m in policy.service_groups[name].members)
    service = policy.services.get(name)
    if service is None:
        return False
    for entry in service.entries:
        if entry.protocol.value != protocol:
            continue
        if not entry.dst_ports or port is None:
            return True
        for part in entry.dst_ports.split(","):
            low, _, high = part.strip().partition("-")
            if low and int(low) <= port <= int(high or low):
                return True
    return False


def _nat_matches(policy: Any, nat: Any, src_zone: str, dst_zone: str, src: str, dst: str, protocol: str, port: Optional[int],
                 from_zone: bool = True, to_zone: bool = True) -> bool:  # fmt: skip
    """Whether a NAT rule matches a connection as it arrives (the destination's zone: before translation); without
    from_zone or to_zone, whatever that zone."""
    if not nat.enabled:
        return False
    if from_zone and not ("any" in nat.src_zones or src_zone in nat.src_zones):
        return False
    if to_zone and not ("any" in nat.dst_zones or dst_zone in nat.dst_zones):
        return False
    return _in(policy, src, nat.sources) and _in(policy, dst, nat.destinations) and _service_matches(policy, nat.service, protocol, port)


def _zone_of(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    return next((zone for zone, net in ZONES.items() if address in ipaddress.ip_network(net)), "")


def published(policy: Any = None) -> List[Dict[str, Any]]:
    """The addresses the source policy publishes: a NAT rule that translates one destination address and one TCP or UDP
    port to a host, for traffic from some zones. (zone of the address, address, protocol, port, translated address,
    translated port, from zones, rule)."""
    policy = policy or _load_source()
    out = []
    for nat in policy.nat_rules:
        dnat = nat.destination_translation
        if dnat is None or not nat.enabled or len(nat.destinations) != 1:
            continue
        nets = _networks(policy, nat.destinations[0])
        service = policy.services.get(nat.service)
        if len(nets) != 1 or nets[0].num_addresses != 1 or service is None or len(service.entries) != 1:
            continue
        entry = service.entries[0]
        if entry.protocol.value not in ("tcp", "udp") or not entry.dst_ports.isdigit():
            continue
        to = _networks(policy, dnat.address)
        if len(to) != 1 or to[0].num_addresses != 1:
            continue
        address = str(nets[0].network_address)
        out.append({"zone": _zone_of(address), "address": address, "protocol": entry.protocol.value, "port": int(entry.dst_ports),
                    "to": str(to[0].network_address), "to_port": int(dnat.port) if dnat.port.isdigit() else int(entry.dst_ports),
                    "from_zones": list(nat.src_zones), "rule": nat.name})  # fmt: skip
    return out


def _nat_report(report: Optional[Dict[str, Any]]) -> Dict[str, Tuple[str, List[str]]]:
    """NAT rule name -> (status of its conversion, the codes of its findings)."""
    out: Dict[str, Tuple[str, List[str]]] = {}
    for item in (report or {}).get("items", []):
        if item.get("kind") == "nat":
            out[item["name"]] = (item.get("status", ""), [f.get("code", "") for f in item.get("findings", [])])
    return out


def _nat_doubt(policy: Any, nat_report: Optional[Dict[str, Tuple[str, List[str]]]], deciding: Any, src_zone: str, dst_zone: str,
               src: str, dst: str, protocol: str, port: Optional[int]) -> str:  # fmt: skip
    """Why what NAT does to a connection is not asserted, or "": the rule that decides it was not converted exactly (a
    finding that only widens where it applies does not count for it), or another rule would match it but for its
    zones and was widened."""
    if nat_report is None:
        return ""  # (no conversion report: everything as the source has it, as for the security rules)
    for nat in policy.nat_rules:
        status, codes = nat_report.get(nat.name, ("missing", []))
        if nat is deciding:
            if status != "exact" and not (status == "approximated" and set(codes) <= set(WIDENING)):
                return f"NAT rule {nat.name} not converted exactly ({status})"
            break  # (first match: the rules after it do not apply)
        widened = [WIDENING[code] for code in codes if code in WIDENING]
        from_zone = all(w[0] for w in widened)
        to_zone = all(w[1] for w in widened)
        if widened and _nat_matches(policy, nat, src_zone, dst_zone, src, dst, protocol, port, from_zone, to_zone):
            return f"NAT rule {nat.name}, widened by its conversion, may apply"
    return ""


def _nat_for(policy: Any, src_zone: str, dst_zone: str, src: str, dst: str, protocol: str, port: Optional[int]) -> Any:
    return next((nat for nat in policy.nat_rules if _nat_matches(policy, nat, src_zone, dst_zone, src, dst, protocol, port)), None)


def _seen_from(nat: Any, src: str, dst_zone: str, nat_address: Callable[[str], str]) -> Optional[str]:
    """The address the receiving host sees a connection come from: the source's, or the one the source NAT gives it
    (the firewall's address in the zone it leaves by, for a translation to the interface address); None: not known."""
    snat = nat.source_translation if nat is not None else None
    if snat is None:
        return src
    if snat.kind.value == "interface" or (snat.interface and not snat.addresses):
        return nat_address(dst_zone) or None
    if len(snat.addresses) == 1:
        try:
            net = ipaddress.ip_network(snat.addresses[0], strict=False)
        except ValueError:
            return None
        return str(net.network_address) if net.num_addresses == 1 else None
    return None


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
               refused_means: str = "blocked", nat_address: Optional[Callable[[str], str]] = None) -> Dict[str, Any]:  # fmt: skip
    """The flows, what the source decides for each, and which are asserted.

    through_target_inside_zone: whether traffic between two hosts of one zone passes the target (security groups and
    NSGs apply per interface: yes; a firewall between bridges or subnets: no, those flows test nothing there).
    refused_means: what a TCP reset says on this target: "blocked" where the target can reject, "passed" where it
    cannot (cloud security groups never answer: a reset came from the host behind them).
    nat_address: the firewall's address in a zone, which a translation to the interface address gives (tier 2: .1,
    tier 3: .4); None for a target that is no firewall of its own (the clouds' security groups), where NAT is not
    asserted."""
    from fwshift.model import Action
    from fwshift.simulate import Simulator

    policy = _load_source()
    simulator = Simulator(policy)
    statuses = _statuses(report)
    nat_report = _nat_report(report) if report is not None else None
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
                flow = {"id": f"{a.name}>{b.name}:{protocol}/{port}", "src": a.ip, "dst": b.ip, "src_zone": a.zone, "dst_zone": b.zone,
                        "protocol": protocol, "port": port, "expected": expected, "decided_by": decided_by, "asserted": not why,
                        "local": local, "why_not_asserted": why}  # fmt: skip
                if expected == "passed" and not local and protocol in ("tcp", "udp"):
                    _expect_nat(flow, policy, nat_report, nat_address, a, b, protocol, port)
                flows.append(flow)
    # Connections to the addresses the source publishes, from the zones it publishes them to: the security rule that
    # decides one is the one for the translated address's zone (PAN-OS: the zone after NAT, the address before it). A
    # target that is no firewall of its own publishes nothing.
    for pub in published(policy) if nat_address is not None else []:
        for a in hosts:
            if a.zone not in pub["from_zones"] and "any" not in pub["from_zones"]:
                continue
            to_zone = _zone_of(pub["to"])
            point = (a.zone, to_zone, a.ip, pub["address"], NUMBERS[pub["protocol"]], pub["port"])
            found = simulator.attribute(point)
            if found.certain is not None:
                expected, decided_by = ("passed" if found.certain.action == Action.ALLOW else "blocked"), found.certain.name
            else:
                expected, decided_by = "unknown", ", ".join(r.name for r in found.possible) or "(default)"
            might = _might(simulator, point)
            inexact = sorted({name for name in might if statuses and statuses.get(name, "missing") != "exact"})
            deciding = _nat_for(policy, a.zone, pub["zone"], a.ip, pub["address"], pub["protocol"], pub["port"])
            doubt = _nat_doubt(policy, nat_report, deciding, a.zone, pub["zone"], a.ip, pub["address"], pub["protocol"], pub["port"])
            if expected == "unknown":
                why = "the source does not decide it surely"
            elif inexact:
                why = "rules not converted exactly: " + ", ".join(inexact)
            else:
                why = doubt
            flow = {"id": f"{a.name}>{pub['address']}:{pub['protocol']}/{pub['port']}", "src": a.ip, "dst": pub["address"], "src_zone": a.zone,
                    "dst_zone": to_zone, "protocol": pub["protocol"], "port": pub["port"], "expected": expected, "decided_by": decided_by,
                    "asserted": not why, "local": False, "why_not_asserted": why, "published": pub["rule"]}  # fmt: skip
            if expected == "passed":
                # (what NAT does to a connection that passes is the NAT rules' alone: asserted apart from the verdict)
                flow["answered_by"] = pub["to"]
                flow["seen_from"] = _seen_from(deciding, a.ip, to_zone, nat_address or (lambda zone: "")) or ""
                flow["nat_rule"] = deciding.name if deciding is not None else ""
                flow["nat_asserted"] = not doubt
                flow["nat_why"] = doubt
            flows.append(flow)
    return {"target": target, "policy": str(POLICY.relative_to(ROOT.parent)), "hosts": [h.__dict__ for h in hosts], "refused_means": refused_means,
            "flows": flows}  # fmt: skip


def _expect_nat(flow: Dict[str, Any], policy: Any, nat_report: Optional[Dict[str, Tuple[str, List[str]]]],
                nat_address: Optional[Callable[[str], str]], a: Host, b: Host, protocol: str, port: int) -> None:  # fmt: skip
    """The address host b should see a passing connection from host a come from, and whether that is asserted. The probe
    tells it for TCP and UDP to its own listeners (not for TCP 22, which sshd answers)."""
    if protocol == "tcp" and port == 22:
        return
    deciding = _nat_for(policy, a.zone, b.zone, a.ip, b.ip, protocol, port)
    seen = _seen_from(deciding, a.ip, b.zone, nat_address or (lambda zone: ""))
    why = _nat_doubt(policy, nat_report, deciding, a.zone, b.zone, a.ip, b.ip, protocol, port)
    if not why and seen is None:
        why = "the source NAT gives an address the lab does not know"
    flow["seen_from"] = seen if seen is not None else ""
    flow["nat_rule"] = deciding.name if deciding is not None else ""
    flow["nat_asserted"] = not why  # (the NAT rules' alone: whether the connection passes is the flow's verdict)
    flow["nat_why"] = why


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
    cannot reject). A flow inside one zone that does not pass the target is "local": shown, not counted.

    NAT (row "nat"): where a passing flow has an expected source address as the receiving host sees it (seen_from) or
    an expected host that answers (answered_by), and the probe told them: "ok", or "FAIL" when the plan asserts what NAT
    does to it (and the flow's verdict is FAIL too), "differs-announced" when it does not; "unseen" when the probe did
    not tell (an older probe)."""
    seen = {r["id"]: r["observed"] for r in results}
    told = {r["id"]: r for r in results}
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
        row = {**flow, "observed": observed, "verdict": verdict}
        _check_nat(row, told.get(flow["id"], {}))
        rows.append(row)
    counts: Dict[str, int] = {}
    nat_counts: Dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
        if row.get("nat"):
            nat_counts[row["nat"]] = nat_counts.get(row["nat"], 0) + 1
    # Not a vacuous pass: asserted flows that should pass and asserted flows that should be blocked, both seen right.
    both = {row["expected"] for row in rows if row["verdict"] == "ok"} >= {"passed", "blocked"}
    passed = counts.get("FAIL", 0) == 0 and counts.get("error", 0) == 0 and both
    return {"target": plan["target"], "counts": counts, "nat_counts": nat_counts, "passed": passed, "vacuous": not both, "rows": rows}


def _check_nat(row: Dict[str, Any], result: Dict[str, Any]) -> None:
    expect = {k: row[k] for k in ("seen_from", "answered_by") if row.get(k)}
    if not expect or row["observed"] != "passed" or row["verdict"] in ("local", "info", "error"):
        return
    got = {k: result[k.replace("seen_from", "seen_as")] for k in expect if result.get(k.replace("seen_from", "seen_as"))}
    if not got:
        row["nat"] = "unseen"
        return
    wrong = [f"{k.replace('_', ' ')} {got[k]}, not {v}" for k, v in expect.items() if k in got and got[k] != v]
    row["nat_seen"] = got
    if not wrong:
        row["nat"] = "ok" if row.get("nat_asserted") else "ok-unasserted"
    elif row.get("nat_asserted"):
        row["nat"] = "FAIL"
        row["nat_wrong"] = "; ".join(wrong)
        row["verdict"] = "FAIL"
    else:
        row["nat"] = "differs-announced"
        row["nat_wrong"] = "; ".join(wrong)


def render(summary: Dict[str, Any]) -> str:
    lines = [f"FWShift lab: {summary['target']}", "  " + ", ".join(f"{k} {v}" for k, v in sorted(summary["counts"].items()))]
    if summary.get("nat_counts"):
        lines.append("  NAT: " + ", ".join(f"{k} {v}" for k, v in sorted(summary["nat_counts"].items())))
    for row in summary["rows"]:
        if row.get("nat_wrong"):
            note = "" if row["nat"] == "FAIL" else f" ({row.get('nat_why', '')})"
            lines.append(f"  {'NAT ' + row['nat']:<18} {row['id']:<28} {row['nat_wrong']} (NAT rule {row.get('nat_rule') or 'none'}){note}")
        elif row["verdict"] in ("FAIL", "error", "differs-announced"):
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
