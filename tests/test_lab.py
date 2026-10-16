# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The lab (lab/README.md): its plan against the test suite's own judge, its probe on loopback, the parts that read
the conversions (security groups, NSGs, IOS zones, pfSense and OPNsense areas), every run dry, and, where the host
allows it (root, ip, nft or iptables), a real run with packets through the Linux kernel in network namespaces."""

from __future__ import annotations

import base64
import errno
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

import pytest
from helpers import DATA
from test_iptables import Packet, model_verdict

LAB = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB))

import labplan  # noqa: E402
import labrun  # noqa: E402
import lab as labcli  # noqa: E402
import probe as labprobe  # noqa: E402
import tier1  # noqa: E402
import tier2  # noqa: E402
import tier3  # noqa: E402

from fwshift import cli  # noqa: E402
from fwshift.report import Report  # noqa: E402


# -- the plan ------------------------------------------------------------------------------------------------------


def test_the_plan_agrees_with_the_judge_of_the_test_suite() -> None:
    """What the plan expects is worked out with the simulation of fwshift; the judge of the test suite is another
    reading of the same model."""
    plan = labplan.build_plan("none")
    policy = cli.load(labplan.POLICY.read_bytes(), "panos", Report())
    assert len(plan["flows"]) == len(labplan.HOSTS) * (len(labplan.HOSTS) - 1) * len(labplan.SERVICES)
    for flow in plan["flows"]:
        assert flow["expected"] in ("passed", "blocked"), flow
        pkt = Packet(flow["src_zone"], flow["dst_zone"], flow["src"], flow["dst"], flow["protocol"], 40000, flow["port"], flow["port"])
        verdict = model_verdict(policy, pkt)
        if verdict is None:  # (no rule: the default, which the judge takes for traffic between zones only)
            verdict = (policy.default_intrazone if flow["src_zone"] == flow["dst_zone"] else policy.default_interzone).value == "allow"
        assert verdict == (flow["expected"] == "passed"), flow


def test_what_the_plan_expects() -> None:
    flows = {f["id"]: f for f in labplan.build_plan("none")["flows"]}
    assert flows["in10>dmz10:tcp/80"]["expected"] == "passed" and flows["in10>dmz10:tcp/80"]["decided_by"] == "web-to-dmz"
    assert flows["in11>dmz10:tcp/80"]["expected"] == "blocked" and flows["in11>dmz10:tcp/80"]["decided_by"] == "guest-not-to-dmz"
    assert flows["in10>dmz11:tcp/22"]["expected"] == "passed" and flows["in11>dmz11:tcp/22"]["expected"] == "blocked"
    assert flows["in10>out10:udp/53"]["expected"] == "blocked" and flows["in10>out10:udp/123"]["expected"] == "passed"
    assert flows["dmz10>out10:tcp/8005"]["expected"] == "passed" and flows["dmz10>out10:tcp/8011"]["expected"] == "blocked"
    assert flows["out10>dmz10:tcp/80"]["expected"] == "passed" and flows["out10>dmz10:tcp/443"]["expected"] == "blocked"
    assert flows["dmz10>in10:tcp/22"]["expected"] == "blocked" and flows["dmz10>in10:tcp/22"]["decided_by"] == "(default)"
    assert flows["in10>in11:udp/123"]["expected"] == "passed"  # (inside a zone: the default of PAN-OS)
    # Nothing to compare with: every flow is asserted; a rule not converted exactly takes its flows out.
    assert all(f["asserted"] for f in flows.values())
    report = {"items": [{"kind": "rule", "name": name, "status": "exact"} for name in
                        ("guest-not-to-dmz", "web-to-dmz", "admin-ssh", "outside-web", "no-dns-out", "dmz-high-ports")] +
              [{"kind": "rule", "name": "inside-out", "status": "approximated"}]}  # fmt: skip
    flows = {f["id"]: f for f in labplan.build_plan("x", report)["flows"]}
    assert not flows["in10>out10:udp/123"]["asserted"] and "inside-out" in flows["in10>out10:udp/123"]["why_not_asserted"]
    assert not flows["in10>out10:udp/53"]["asserted"]  # (inside-out might match it too)
    assert flows["in10>dmz10:tcp/80"]["asserted"] and flows["out10>dmz10:tcp/80"]["asserted"]
    # A default the conversion did not write as it is takes out the flows the default decides, there only.
    noted = dict(report, notes=[{"severity": "needs-review", "code": "INTRAZONE_DEFAULT", "message": ""},
                                {"severity": "info", "code": "INTERZONE_DEFAULT", "message": ""}])  # fmt: skip
    flows = {f["id"]: f for f in labplan.build_plan("x", noted)["flows"]}
    assert not flows["in10>in11:tcp/80"]["asserted"] and "INTRAZONE_DEFAULT" in flows["in10>in11:tcp/80"]["why_not_asserted"]
    assert flows["dmz10>in10:tcp/22"]["asserted"]  # (between zones: the note was only info)
    # Behind a firewall two hosts of one zone talk past it: those flows are shown, not counted.
    plan = labplan.build_plan("x", None, through_target_inside_zone=False)
    local = [f for f in plan["flows"] if f["local"]]
    assert len(local) == 32 and all(not f["asserted"] and f["src_zone"] == f["dst_zone"] for f in local)


def test_the_check() -> None:
    plan = {"target": "t", "flows": [
        {"id": "a", "expected": "passed", "asserted": True, "decided_by": "r", "why_not_asserted": ""},
        {"id": "b", "expected": "blocked", "asserted": True, "decided_by": "r", "why_not_asserted": ""},
        {"id": "c", "expected": "blocked", "asserted": False, "decided_by": "r", "why_not_asserted": "rules not converted exactly: r"},
        {"id": "d", "expected": "passed", "asserted": True, "decided_by": "r", "why_not_asserted": ""},
        {"id": "e", "expected": "blocked", "asserted": True, "decided_by": "r", "why_not_asserted": ""}]}  # fmt: skip
    summary = labplan.check(plan, [{"id": "a", "observed": "passed"}, {"id": "b", "observed": "refused"}, {"id": "c", "observed": "passed"},
                                   {"id": "d", "observed": "blocked"}])  # fmt: skip
    verdicts = {r["id"]: r["verdict"] for r in summary["rows"]}
    assert verdicts == {"a": "ok", "b": "ok", "c": "differs-announced", "d": "FAIL", "e": "error"} and not summary["passed"]
    text = labplan.render(summary)
    assert "FAIL" in text and "d " in text and "result: FAILED" in text
    good = [{"id": i, "observed": o} for i, o in (("a", "passed"), ("b", "blocked"), ("c", "passed"), ("d", "passed"), ("e", "blocked"))]
    assert labplan.check(plan, good)["passed"]
    # A reset where the target cannot send one (security groups): the packet reached the host.
    assert labplan.check({**plan, "refused_means": "passed"}, [*good[:1], {"id": "b", "observed": "refused"}, *good[2:]])["counts"]["FAIL"] == 1
    # Nothing that should be blocked was seen blocked: no pass, however few the failures.
    vacuous = labplan.check({"target": "t", "flows": plan["flows"][:1]}, good[:1])
    assert not vacuous["passed"] and vacuous["vacuous"] and "shows nothing" in labplan.render(vacuous)


# -- the probe -----------------------------------------------------------------------------------------------------


def free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_the_probe_on_loopback() -> None:
    tcp, closed, udp, silent = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_STREAM), free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM)
    server = threading.Thread(target=labprobe.serve, args=("127.0.0.1", [tcp], [udp], 20), daemon=True)
    server.start()
    import time

    time.sleep(0.5)
    plan = {"flows": [{"id": "open", "src": "127.0.0.1", "dst": "127.0.0.1", "protocol": "tcp", "port": tcp},
                      {"id": "closed", "src": "127.0.0.1", "dst": "127.0.0.1", "protocol": "tcp", "port": closed},
                      {"id": "udp", "src": "127.0.0.1", "dst": "127.0.0.1", "protocol": "udp", "port": udp},
                      {"id": "silent", "src": "127.0.0.1", "dst": "127.0.0.1", "protocol": "udp", "port": silent},
                      {"id": "other", "src": "127.0.0.2", "dst": "127.0.0.1", "protocol": "tcp", "port": tcp}]}  # fmt: skip
    # Windows sends the SYN again after each reset, and reports a closed port only after about 2 seconds.
    timeout = 5.0 if sys.platform.startswith("win") else 1.0
    seen = {r["id"]: r["observed"] for r in labprobe.send(plan, "127.0.0.1", timeout, 4)}
    assert seen == {"open": "passed", "closed": "refused", "udp": "passed", "silent": "blocked"}  # ("other" is not sent from here)
    # From an address this host does not have, nothing can be tried: an error, never "blocked".
    assert labprobe.try_tcp("192.0.2.254", "127.0.0.1", tcp, 1.0) == "error"
    assert labprobe.try_udp("192.0.2.254", "127.0.0.1", udp, 1.0) == "error"
    assert labprobe.selfcheck("127.0.0.1", [tcp], [udp]) == []
    assert labprobe.selfcheck("127.0.0.1", [closed], []) == [("tcp", closed)]


@pytest.mark.skipif(not shutil.which("ping"), reason="no ping")
def test_the_probe_pings() -> None:
    outcome = labprobe.try_icmp("127.0.0.1", "127.0.0.1", 2)
    assert outcome in ("passed", "error")  # (a host may forbid ping to unprivileged users)


def test_the_probe_speaks_each_systems_ping_and_errors() -> None:
    assert labprobe.ping_command("10.20.1.10", "10.20.2.10", 3, "linux") == ["ping", "-n", "-c", "1", "-W", "3", "-I", "10.20.1.10", "10.20.2.10"]
    assert labprobe.ping_command("10.20.1.10", "10.20.2.10", 3, "darwin") == ["ping", "-n", "-c", "1", "-W", "3000", "-S", "10.20.1.10", "10.20.2.10"]
    assert labprobe.ping_command("10.20.1.10", "10.20.2.10", 3, "win32") == ["ping", "-n", "1", "-w", "3000", "-S", "10.20.1.10", "10.20.2.10"]
    # A port unreachable answering UDP: ECONNREFUSED on Linux, WSAECONNRESET on Windows; host unreachable on any system.
    assert labprobe._udp_rejected(ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
    assert labprobe._udp_rejected(ConnectionResetError(10054, "reset"))
    assert labprobe._udp_rejected(OSError(errno.EHOSTUNREACH, "unreachable"))
    assert not labprobe._udp_rejected(OSError(errno.EADDRNOTAVAIL, "not here"))


def test_the_probe_reads_windows_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows' ping exits 0 for "destination host unreachable" too: only a reply line with TTL= is a pass."""
    monkeypatch.setattr(labprobe.sys, "platform", "win32")
    for out, code, expected in ((b"Reply from 10.20.2.10: bytes=32 time<1ms TTL=64", 0, "passed"),
                                (b"Reply from 10.20.1.1: Destination host unreachable.", 0, "blocked"),
                                (b"Request timed out.", 1, "blocked"), (b"", 2, "error")):  # fmt: skip
        monkeypatch.setattr(labprobe.subprocess, "run", lambda *a, _o=out, _c=code, **k: subprocess.CompletedProcess(a, _c, _o, b""))
        assert labprobe.try_icmp("10.20.1.10", "10.20.2.10", 2) == expected, out


def test_a_host_that_fails_its_self_check_says_why(tmp_path: Path) -> None:
    """Before the teardown takes it, the host is asked about itself (addresses, routing, the probe's service, its first
    boot): into diagnose-HOST.txt, named in the error."""
    runner = labrun.Runner(tmp_path, echo=False)
    target = labrun.Target("in11", "127.0.0.1", ["sh", "-c"])
    with pytest.raises(labrun.LabError, match=r"in11 does not answer.*diagnose-in11\.txt"):
        labrun.wait_ready(runner, [target], minutes=0, probe_path=str(tmp_path / "missing-probe.py"))
    text = (tmp_path / "diagnose-in11.txt").read_text()
    assert "== the last self-check failed with" in text and "== addresses" in text and "== first boot" in text
    assert "missing-probe.py" in text  # (the self-check's own error)


def test_the_first_boot_script() -> None:
    script = labrun.host_init("10.20.1.10", "10.20.1.1", "10.20.1.0/24")
    assert "${" not in script and "TEST_IP='10.20.1.10'" in script and "--tcp 22,80,443,8005,8011" in script
    encoded = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d", script)
    assert encoded is not None
    assert base64.b64decode(encoded.group(1)) == (LAB / "probe.py").read_bytes()
    # The own subnet: on the link (AWS, Azure answer ARP for every address), or through the gateway (Google Cloud gives an
    # interface a /32 and answers ARP for its gateway only).
    assert "SUBNET_VIA_GW='no'" in script
    gcp = labrun.host_init("10.20.1.10", "10.20.1.1", "10.20.1.0/24", subnet_via_gateway=True)
    assert "SUBNET_VIA_GW='yes'" in gcp and 'ip route replace "$TEST_NET" via "$TEST_GW"' in gcp
    sh = shutil.which("sh")
    if sh:
        for text in (script, gcp):
            done = subprocess.run([sh, "-n"], input=text, text=True, capture_output=True)
            assert done.returncode == 0, done.stderr


# -- reading the conversions ----------------------------------------------------------------------------------------


def lab_conversion(tmp_path: Path, target: str, options: List[str]) -> Dict[str, Any]:
    runner = labrun.Runner(tmp_path, echo=False)
    out = tmp_path / f"out.{target}"
    report = labrun.fwshift(runner, target, out, options)
    return {"out": out, "report": report}


def test_the_security_groups_go_where_their_attach_lines_say(tmp_path: Path) -> None:
    done = lab_conversion(tmp_path, "aws", labplan.zone_options() + [x for z in labplan.ZONES for x in ("--inside-zone", z)] + ["--target-prefix", "fwlab1-"])
    attach = tier1.parse_attach(done["out"].read_text())
    assert attach and all(name.startswith("fwlab1-") for name in attach)
    for host in labplan.HOSTS:
        groups = tier1.groups_for(host.ip, attach)
        assert groups, host
    assert tier1.groups_for("10.20.2.10", attach) != tier1.groups_for("10.20.2.11", attach)  # (the web server has rules of its own)
    assert tier1.parse_created("created fwlab1-dmz sg-0123abcd\nother\ncreated fwlab1-x sg-99\n") == {"fwlab1-dmz": "sg-0123abcd", "fwlab1-x": "sg-99"}
    assert labrun.addresses("10.20.2.0-10.20.2.9 10.20.3.10") == [ipaddress.ip_network("10.20.2.0/29"), ipaddress.ip_network("10.20.2.8/31"),
                                                                    ipaddress.ip_network("10.20.3.10/32")]  # fmt: skip


def test_each_zone_gets_its_nsg(tmp_path: Path) -> None:
    done = lab_conversion(tmp_path, "azure", labplan.zone_options() + [x for z in labplan.ZONES for x in ("--inside-zone", z)] + ["--target-prefix", "fwlab1-"])
    assert tier1.nsg_for_zones(json.loads(done["out"].read_text())) == {"inside": "fwlab1-inside", "dmz": "fwlab1-dmz", "outside": "fwlab1-outside"}
    with pytest.raises(labrun.LabError):
        tier1.nsg_for_zones({"metadata": {"networks": {}}})


def test_the_ios_zones_are_put_on_the_interfaces(tmp_path: Path) -> None:
    vendor = tier3.VENDORS["c8000v"]
    done = lab_conversion(tmp_path, "ios", vendor.options)
    members = tier3.ios_zone_members(done["out"].read_text())
    assert set(members) == {"GigabitEthernet2", "GigabitEthernet3", "GigabitEthernet4"}
    session = vendor.session(done["out"])
    assert "interface GigabitEthernet2" in session and f" zone-member security {members['GigabitEthernet2']}" in session
    assert session.index("interface GigabitEthernet2") > session.index("configure terminal")
    # Configuration mode lasts to the end: one `end`, and after it only `exit`.
    assert session.count("end") == 1 and session[session.index("end") + 1:] == ["exit"]


@pytest.mark.parametrize("name", sorted(tier3.VENDORS))
def test_the_sessions_of_tier_3(tmp_path: Path, name: str) -> None:
    vendor = tier3.VENDORS[name]
    done = lab_conversion(tmp_path, vendor.target, vendor.options)
    assert done["report"]["summary"]  # (converted)
    session = vendor.session(done["out"])
    assert session and all("\n" not in line for line in session)
    assert session[-1] == "exit"  # (the session ends, or it would wait for the CLI's idle timeout)
    if vendor.target in ("ios", "asa"):
        assert session.count("end") == 1
    addresses = [labplan.ZONES[z].replace(".0/24", ".4") for z in tier3.ORDER]
    text = "\n".join(session) + vendor.user_data
    assert all(a in text for a in addresses), name
    re.compile(vendor.errors)
    # What an image may or may not ship with is deleted in a session of its own, whose answers do not count: never in the
    # session that is checked (PAN-OS 11.2 has no rule1, default-vwire, trust or untrust, and refuses to delete them).
    if name == "panos":
        prepare = vendor.prepare()
        assert "delete zone trust" in prepare and prepare[-3:] == ["commit", "exit", "exit"]
        assert not any(line.startswith("delete ") for line in session)


def test_the_areas_of_pfsense_and_opnsense() -> None:
    for flavour in ("pfsense", "opnsense"):
        base = (DATA / f"{flavour}_sample.xml").read_text(encoding="utf-8")
        converted = (DATA / "expected" / f"panos_to_{flavour}.xml").read_text(encoding="utf-8")
        merged = ET.fromstring(tier2.merge_areas(base, converted, flavour).split("\n", 1)[1])
        old, new = ET.fromstring(base), ET.fromstring(converted)
        if flavour == "pfsense":
            for area in ("aliases", "nat", "filter"):
                assert ET.tostring(merged.find(area)) == ET.tostring(new.find(area)), area
            for kept in ("system", "interfaces", "schedules"):
                assert ET.tostring(merged.find(kept)) == ET.tostring(old.find(kept)), kept
        else:
            for path in ("OPNsense/Firewall/Alias", "OPNsense/Firewall/Filter/rules", "OPNsense/Firewall/Filter/snatrules", "nat"):
                assert ET.tostring(merged.find(path)) == ET.tostring(new.find(path)), path
            assert merged.find("filter") is not None and not merged.find("filter").findall("rule")
            assert ET.tostring(merged.find("interfaces")) == ET.tostring(old.find("interfaces"))
            assert ET.tostring(merged.find("OPNsense/Firewall/Category")) == ET.tostring(old.find("OPNsense/Firewall/Category"))
    with pytest.raises(ValueError):
        tier2.merge_areas("<x/>", "<y/>", "other")


# -- every run, dry -------------------------------------------------------------------------------------------------

DRY = [["tier1", "aws"], ["tier1", "azure"], ["tier1", "gcp", "--project", "p"], ["tier2", "nftables"], ["tier2", "iptables"],
       *[["tier2", n, "--image", "IMAGE", "--ssh-key", "KEY"] for n in ("routeros", "opnsense", "pfsense")], *[["tier3", n] for n in sorted(tier3.VENDORS)]]  # fmt: skip


@pytest.mark.parametrize("run", DRY, ids=lambda r: f"{r[0]}-{r[1]}")
def test_every_run_dry(tmp_path: Path, run: List[str], capsys: pytest.CaptureFixture[str]) -> None:
    run = [str(tmp_path / a) if a in ("IMAGE", "KEY") else a for a in run]
    for name in ("IMAGE", "KEY"):
        (tmp_path / name).write_text("")
    assert labcli.main(["run", *run, "--dry-run", "--work", str(tmp_path / "work")]) == 0
    work = next((tmp_path / "work").iterdir())
    log = (work / "commands.log").read_text().splitlines()
    assert "result: DRY RUN" in (work / "summary.txt").read_text()
    assert json.loads((work / "run.json").read_text())["torn_down"]
    plan = json.loads((work / "plan.json").read_text())
    assert len(plan["flows"]) == 160
    joined = "\n".join(log)
    if run[0] in ("tier1", "tier3"):
        apply = next(i for i, line in enumerate(log) if " apply " in line)
        destroy = next(i for i, line in enumerate(log) if " destroy " in line)
        assert apply < destroy and destroy >= len(log) - 1 - 0, joined  # (the teardown is the last step)
        variables = json.loads((work / "terraform" / "terraform.tfvars.json").read_text())
        declared = re.findall(r'^variable "(\w+)"', (work / "terraform" / "main.tf").read_text(), re.M)
        required = re.findall(r'^variable "(\w+)" \{ type = [^}]*\}$', (work / "terraform" / "main.tf").read_text(), re.M)
        assert set(variables) <= set(declared) and set(required) <= set(variables), (set(variables) ^ set(declared))
        assert all(line.count("--region") <= 1 for line in log)
        # The run's key is of a type the cloud takes: Azure's VMs only RSA (its provider refuses the rest before
        # anything is made); the Marketplace images of tier 3 get RSA as well.
        rsa = run[1] == "azure" or run[0] == "tier3"
        assert variables["ssh_public_key"].startswith("ssh-rsa " if rsa else "ssh-ed25519 "), variables["ssh_public_key"]
        # Google Cloud delivers through the gateway, also inside a subnet: its hosts route their own subnet there.
        via = {name: "SUBNET_VIA_GW='yes'" in host["user_data"] for name, host in variables["hosts"].items()}
        assert set(via.values()) == {run[1] == "gcp"}, via
        if run[0] == "tier3":  # (which image, and so which version, the firewall ran: in run.json)
            state = json.loads((work / "run.json").read_text())
            assert state["image"].startswith("ami-") and "image_name" in state and "product_code" in state
            # VM-Series: BYOL and the bundles share their name; the image is chosen by the product code of PAYG Bundle 1.
            searched = next(line for line in log if "describe-images" in line)
            assert ("Name=product-code,Values=e9yfvyj3uag5uo5j2hjikv74n" in searched) == (run[1] == "panos"), searched
        if run[0] == "tier1":
            via = {name: "SUBNET_VIA_GW='yes'" in host["user_data"] for name, host in variables["hosts"].items()}
            assert set(via.values()) == {run[1] == "gcp"}, via
        # The stand-in key of a dry run is in the format of a real one, and says what it is.
        kind, blob = variables["ssh_public_key"].split()[:2]
        decoded = base64.b64decode(blob, validate=True)
        assert decoded[4:4 + int.from_bytes(decoded[:4], "big")].decode() == kind and b"not a key" in decoded
        assert any(line.startswith("ssh-keygen") and ("-t rsa -b 4096" in line) == rsa for line in log)
    if run[0] == "tier2":
        assert any("ip netns add" in line for line in log) and any("ip netns del" in line for line in log)
        assert not any("bridge-nf" in line for line in log)  # (nothing of the host's own networking changes)
        if "--image" in run:
            assert any(line.startswith("ip netns exec fwl-sw qemu-system-x86_64") for line in log)
    probes = [line for line in log if " send --plan " in line]
    assert len(probes) == len(labplan.HOSTS)
    assert labcli.main(["check", str(work / "plan.json"), str(work / "results.json")]) == 0


def test_a_kept_run_is_destroyed_later(tmp_path: Path) -> None:
    assert labcli.main(["run", "tier1", "aws", "--dry-run", "--keep", "--work", str(tmp_path)]) == 0
    work = next(tmp_path.iterdir())
    state = json.loads((work / "run.json").read_text())
    assert not state.get("torn_down") and state["outputs"]["vpc_id"] and state["created"]
    assert labcli.main(["destroy", str(work), "--dry-run"]) == 0
    log = (work / "commands.log").read_text()
    assert "delete-security-group" in log and " destroy " in log and json.loads((work / "run.json").read_text())["torn_down"]
    assert labcli.main(["destroy-all", str(tmp_path), "--dry-run"]) == 0  # (torn down already: nothing to do)


def test_the_admin_address_is_one_address(tmp_path: Path) -> None:
    runner = labrun.Runner(tmp_path, dry_run=True, echo=False)
    assert labrun.admin_cidr("198.51.100.7/32", runner) == "198.51.100.7/32"
    with pytest.raises(labrun.LabError, match="one address"):
        labrun.admin_cidr("0.0.0.0/0", runner)
    assert labrun.admin_cidr("198.51.100.0/24", runner, wide=True) == "198.51.100.0/24"


def test_plan_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert labcli.main(["plan", "tier1", "gcp", "--work", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "160 flows" in out
    assert labcli.main(["plan", "tier2", "nftables", "--work", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "inside one zone: it does not pass the target" in out


def test_the_list_and_wrong_runs(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert labcli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert all(name in out for name in ("aws", "azure", "gcp", "nftables", "routeros", "fortigate", "not scripted"))
    assert labcli.main(["run", "tier1", "fortigate", "--dry-run", "--work", str(tmp_path)]) == 2
    assert labcli.main(["run", "tier2", "routeros", "--dry-run", "--work", str(tmp_path)]) == 2  # (no --image)


def test_the_terraform_modules_name_what_the_lab_uses() -> None:
    """Each module's outputs are the keys the lab reads from them."""
    for module, keys in (("tier1/aws", {"vpc_id", "hold_group", "user", "hosts"}), ("tier1/azure", {"resource_group", "vnet", "user", "hosts"}),
                         ("tier1/gcp", {"test_network", "user", "hosts"}), ("tier3/aws", {"firewall_ip", "firewall_instance", "user", "hosts"})):  # fmt: skip
        text = (LAB / module / "main.tf").read_text()
        assert set(re.findall(r'^output "(\w+)"', text, re.M)) == keys, module
        assert text.count("{") == text.count("}"), module
        assert "fwshift-lab" in text  # (everything it makes is tagged or labelled with the run)


def test_the_lab_workflow() -> None:
    text = (LAB.parent / ".github" / "workflows" / "lab.yml").read_text()
    assert "workflow_dispatch" in text and "id-token: write" in text and "environment: lab" in text
    for line in text.splitlines():
        found = re.search(r"uses: ([\w./-]+)@(\S+)", line)
        if found:
            assert re.fullmatch(r"[0-9a-f]{40}", found.group(2)), line  # (pinned to a commit)
    choices = re.findall(r"^\s+- (tier\d \w+)$", text, re.M)
    for choice in choices:
        tier, name = choice.split()
        assert name in labcli.TIERS[tier], choice
    assert "id_lab" in text  # (the run's private key is not kept with the results)


# -- a real run: packets through the Linux kernel -------------------------------------------------------------------


def _kernel(tool: str) -> bool:
    return sys.platform.startswith("linux") and os.geteuid() == 0 and all(shutil.which(t) for t in ("ip", "ping", tool))


@pytest.mark.parametrize("name,tool", [("nftables", "nft"), ("iptables", "iptables-restore")])
def test_a_real_run_through_the_kernel(tmp_path: Path, name: str, tool: str) -> None:
    if not _kernel(tool):
        pytest.skip(f"needs Linux, root, ip, ping and {tool}")
    before = Path("/proc/sys/net/bridge/bridge-nf-call-iptables").read_text() if Path("/proc/sys/net/bridge/bridge-nf-call-iptables").exists() else ""
    assert labcli.main(["run", "tier2", name, "--work", str(tmp_path)]) == 0
    work = next(tmp_path.iterdir())
    summary = json.loads((work / "summary.json").read_text())
    assert summary["passed"] and summary["counts"].get("ok", 0) == 128 and summary["counts"].get("local", 0) == 32, summary["counts"]
    assert not subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout.count("fwl-")  # (all taken down)
    if before:
        assert Path("/proc/sys/net/bridge/bridge-nf-call-iptables").read_text() == before  # (the host's setting was not touched)


def test_a_real_run_sees_a_wrong_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The lab is no rubber stamp: a ruleset that lets everything through fails it."""
    if not _kernel("nft"):
        pytest.skip("needs Linux, root, ip, ping and nft")
    original = labrun.fwshift

    def wrong(runner: Any, target: str, out: Path, options: Any) -> Dict[str, Any]:
        report = original(runner, target, out, options)
        out.write_text("table inet fwshift\ndelete table inet fwshift\ntable inet fwshift {\n  chain forward {\n    type filter hook forward priority 0; policy accept;\n  }\n}\n")
        return report

    monkeypatch.setattr(labrun, "fwshift", wrong)
    assert labcli.main(["run", "tier2", "nftables", "--work", str(tmp_path)]) == 1
    work = next(tmp_path.iterdir())
    summary = json.loads((work / "summary.json").read_text())
    assert summary["counts"].get("FAIL", 0) > 50


def test_a_run_ends_through_its_teardown_on_sigterm(tmp_path: Path) -> None:
    """A cancelled workflow sends SIGTERM: the run tears itself down as on Ctrl-C."""
    if not _kernel("nft"):
        pytest.skip("needs Linux, root, ip, ping and nft")
    import signal
    import time

    proc = subprocess.Popen([sys.executable, str(LAB / "lab.py"), "run", "tier2", "nftables", "--work", str(tmp_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # fmt: skip
    deadline = time.time() + 60
    while time.time() < deadline:
        listed = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
        if "fwl-fw" in listed:
            break
        time.sleep(0.2)
    time.sleep(1)
    proc.send_signal(signal.SIGTERM)
    proc.communicate(timeout=120)
    assert proc.returncode == 2
    assert "fwl-" not in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    work = next(tmp_path.iterdir())
    assert json.loads((work / "run.json").read_text())["torn_down"]
