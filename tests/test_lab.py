# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The lab (lab/README.md): its plan against the test suite's own judge, its probe on loopback, the parts that read
the conversions (security groups, NSGs, IOS zones, pfSense and OPNsense areas), every run dry, and, where the host
allows it (root, ip, nft or iptables), a real run with packets through the Linux kernel in network namespaces."""

from __future__ import annotations

import base64
import errno
import gzip
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
    assert labprobe.ping_command("10.20.1.10", "10.20.2.10", 3, "linux") == ["ping", "-n", "-c", "2", "-W", "3", "-I", "10.20.1.10", "10.20.2.10"]
    assert labprobe.ping_command("10.20.1.10", "10.20.2.10", 3, "darwin") == ["ping", "-n", "-c", "2", "-W", "3000", "-S", "10.20.1.10", "10.20.2.10"]
    assert labprobe.ping_command("10.20.1.10", "10.20.2.10", 3, "win32") == ["ping", "-n", "2", "-w", "3000", "-S", "10.20.1.10", "10.20.2.10"]
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
    encoded = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d \| gunzip", script)
    assert encoded is not None
    assert gzip.decompress(base64.b64decode(encoded.group(1))) == (LAB / "probe.py").read_bytes()
    # AWS takes at most 16 KB of user data (the fifth pfSense run: 17.5 KB, every test host refused); keep room to grow.
    for host in tier1.host_variables(gateway="firewall").values():
        assert len(host["user_data"].encode("utf-8")) < 12 * 1024
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
    if vendor.load is not None:  # (pfSense, OPNsense: no lines typed; their config.xml is merged, test_the_pf_family_*)
        assert vendor.as_command and not vendor.session(done["out"])
        return
    session = vendor.session(done["out"])
    assert session and all("\n" not in line for line in session)
    assert session[-1] == "exit"  # (the session ends, or it would wait for the CLI's idle timeout)
    if vendor.target in ("ios", "asa"):
        assert session.count("end") == 1
    addresses = [labplan.ZONES[z].replace(".0/24", ".4") for z in tier3.ORDER]
    uploaded = [f.read_text(encoding="utf-8") for f in vendor.uploads(done["out"]) if f != done["out"]]  # (Check Point: the lab's driver)
    text = "\n".join(session) + vendor.user_data + "".join(uploaded)
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
        bits = tier3.VENDORS[run[1]].key_bits if run[0] == "tier3" else 4096  # (the ASAv: 2048, its key line fits)
        assert any(line.startswith("ssh-keygen") and (f"-t rsa -b {bits}" in line) == rsa for line in log)
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


def test_a_firewall_whose_cli_never_answers_leaves_why(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ASAv's first run (0.36.0) timed out with nothing to go on: every SSH try is kept in boot.txt, the last one in
    the error, and the firewall's console is saved before the teardown."""
    runner = labrun.Runner(tmp_path, echo=False)
    calls: List[List[str]] = []

    def fake_run(args: List[str], **kwargs: object) -> str:
        calls.append(list(args))
        if args[0] == "ssh":
            raise labrun.LabError("ssh failed (255): admin@192.0.2.4: Permission denied (publickey).")
        return "console text" if "get-console-output" in args else ""

    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(tier3.time, "sleep", lambda seconds: None)
    with pytest.raises(labrun.LabError, match="Permission denied"):
        tier3.wait_cli(runner, tmp_path / "id_lab", "admin", "192.0.2.4", "show version", " up ", 0)
    assert "Permission denied (publickey)" in (tmp_path / "boot.txt").read_text()
    tier3.save_console(runner, "eu-west-1", "i-0abc")
    assert (tmp_path / "console.txt").read_text() == "console text"
    assert any("get-console-screenshot" in call for call in calls)


def test_the_asav_is_given_a_day0_configuration_with_ssh_and_the_runs_key(tmp_path: Path) -> None:
    """Without one, the ASAv boots with SSH off (its first run: Connection refused for 30 minutes)."""
    key = tmp_path / "id_lab"
    key.with_suffix(".pub").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 fwlab-test\n")
    data = tier3.user_data(tier3.VENDORS["asav"], key, "Lab-0123abcd")
    lines = data.splitlines()
    assert "enable password Lab-0123abcd" in lines  # (else the ASA asks for one at the first login)
    with pytest.raises(labrun.LabError, match="needs a password"):
        tier3.user_data(tier3.VENDORS["asav"], key)
    password = tier3.run_password(tmp_path)
    assert re.fullmatch(r"Lab-[0-9a-f]{20}", password) and (tmp_path / "enable_password.txt").read_text() == password + "\n"
    if os.name == "posix":  # (Windows keeps no such mode bits: chmod sets only read-only there)
        assert (tmp_path / "enable_password.txt").stat().st_mode & 0o077 == 0
    assert "ssh 0.0.0.0 0.0.0.0 management" in lines and " ip address dhcp setroute" in lines
    assert " ssh authentication publickey AAAAB3NzaC1yc2EAAAADAQABAAABAQC7" in lines and "{ssh_key}" not in data
    assert "aaa authorization exec LOCAL auto-enable" in lines  # (the session starts with configure terminal)
    assert tier3.user_data(tier3.VENDORS["fortigate"], key) == tier3.VENDORS["fortigate"].user_data



def _asav_longest_line(tmp_path: Path, bits: int) -> str:
    key = tmp_path / "id_lab"
    key.with_suffix(".pub").write_text(labrun._dry_key("rsa", bits) + "\n")
    return max(tier3.user_data(tier3.VENDORS["asav"], key, "Lab-" + "0" * 20).splitlines(), key=len)


def test_every_asav_day0_line_fits_the_asa_with_the_runs_key(tmp_path: Path) -> None:
    """The ASAv's third run: the key line of a 4096-bit key ran over the ASA's 511 characters and was cut off."""
    longest = _asav_longest_line(tmp_path, tier3.VENDORS["asav"].key_bits)
    assert "publickey" in longest and len(longest) <= 511
    assert len(_asav_longest_line(tmp_path, 4096)) > 511


def test_ssh_to_the_asav_allows_ssh_rsa_and_only_there() -> None:
    """The ASAv offers only an ssh-rsa host key, which OpenSSH turns down unless it is asked for."""
    prefix = labrun.ssh_prefix(Path("k"), "admin", "192.0.2.4", Path("kh"), options=tier3.VENDORS["asav"].ssh_options)
    assert "HostKeyAlgorithms=+ssh-rsa" in prefix and "PubkeyAcceptedAlgorithms=+ssh-rsa" in prefix
    assert prefix[-1] == "admin@192.0.2.4"
    others = {name: v.ssh_options for name, v in tier3.VENDORS.items() if name not in ("asav", "c8000v")}
    assert all(value == () for value in others.values()), others
    assert tier3.VENDORS["c8000v"].ssh_options == ("PubkeyAcceptedAlgorithms=+ssh-rsa",)
    # 2048 bits for the ASAv (its 511-character key line) and the 8000V (the size AWS makes); 4096 elsewhere
    bits = {name: v.key_bits for name, v in tier3.VENDORS.items()}
    assert {name for name, value in bits.items() if value != 4096} == {"asav", "c8000v"} and bits["asav"] == 2048


def test_no_algorithm_in_common_ends_the_wait_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """It does not change while the firewall boots: the third ASAv run tried it for 30 minutes."""
    runner = labrun.Runner(tmp_path, echo=False)
    calls: List[List[str]] = []

    def fake_run(args: List[str], **kwargs: object) -> str:
        calls.append(list(args))
        raise labrun.LabError("ssh failed (255): Unable to negotiate with 192.0.2.4 port 22: no matching host key type found. Their offer: ssh-rsa")

    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(tier3.time, "sleep", lambda seconds: None)
    with pytest.raises(labrun.LabError, match="no algorithm in common"):
        tier3.wait_cli(runner, tmp_path / "id_lab", "admin", "192.0.2.4", "show version", " up ", 30)
    assert len(calls) == 1
    assert "Unable to negotiate" in (tmp_path / "boot.txt").read_text()


def test_a_command_that_hangs_keeps_what_it_wrote(tmp_path: Path) -> None:
    """The fourth ASAv run: SSH got in, then hung; the error said only that it did not finish."""
    runner = labrun.Runner(tmp_path, echo=False)
    script = "import sys, time; print('ciscoasa# '); sys.stdout.flush(); print('Enter Password:', file=sys.stderr); sys.stderr.flush(); time.sleep(30)"
    with pytest.raises(labrun.LabError) as caught:
        runner.run([sys.executable, "-c", script], stdin="show version\n", timeout=2)
    assert "did not finish within 2 s" in str(caught.value)
    assert "ciscoasa#" in str(caught.value) and "Enter Password:" in str(caught.value)


def test_the_asav_run_keeps_the_firewalls_own_view_after_the_probes(tmp_path: Path) -> None:
    """The sixth ASAv run forwarded nothing, and was torn down before anyone could look: its counters are kept."""
    lines = tier3.VENDORS["asav"].diagnose()
    assert lines[0] == "terminal pager 0" and lines[-1] == "exit"
    assert "show interface ip brief" in lines and "show asp drop" in lines and "show access-list" in lines
    assert "packet-tracer input inside tcp 10.20.1.10 40000 10.20.2.10 22 detailed" in lines  # (admin-ssh passes it)
    assert all(not v.diagnose() for name, v in tier3.VENDORS.items() if name not in ("asav", "vsrx", "checkpoint", "c8000v", "pfsense", "opnsense", "sonicwall"))
    assert "show policy-map type inspect zone-pair sessions" in tier3.VENDORS["c8000v"].diagnose()
    assert "show security policies hit-count" in tier3.VENDORS["vsrx"].diagnose()
    runner = labrun.Runner(tmp_path, echo=False)
    runner.dry_run = True
    tier3.diagnose(runner, tier3.VENDORS["asav"], tmp_path / "id_lab", "192.0.2.4")
    assert (tmp_path / "diagnose.commands.txt").read_text().splitlines() == lines and (tmp_path / "diagnose.txt").exists()


_FAKE_CLI = r"""
import sys
sys.stdout.write("User admin logged in\r\nciscoasa# "); sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if line == "exit":
        sys.stdout.write("exit\r\nLogoff\r\n"); sys.stdout.flush(); break
    if line == "hang":
        sys.stdout.write(line + "\r\n"); sys.stdout.flush(); continue  # (no prompt after it)
    sys.stdout.write(line + "\r\nok\r\nciscoasa(config)# "); sys.stdout.flush()
"""


def test_a_paced_session_types_each_line_after_its_prompt(tmp_path: Path) -> None:
    """The sixth ASAv run: given all its lines ahead, the ASA closed the session after one letter; typed one at a time,
    each after the prompt, every line is answered."""
    runner = labrun.Runner(tmp_path, echo=False)
    out = runner.run_paced([sys.executable, "-c", _FAKE_CLI], ["configure terminal", "interface Gi0/0", "exit"], r"[>#] ?$", step=10)
    assert out.count("ok") == 2 and "Logoff" in out and "interface Gi0/0" in out
    with pytest.raises(labrun.LabError, match="prompt did not come back.*'exit'"):
        runner.run_paced([sys.executable, "-c", _FAKE_CLI], ["hang", "exit"], r"[>#] ?$", step=1)
    with pytest.raises(labrun.LabError, match="ended before the prompt"):
        runner.run_paced([sys.executable, "-c", "print('U')"], ["terminal pager 0"], r"[>#] ?$", step=5)


def test_a_session_that_answers_almost_nothing_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The sixth ASAv run: the load session wrote "U", refused no line, and the run went on with nothing configured."""
    runner = labrun.Runner(tmp_path, echo=False)
    monkeypatch.setattr(runner, "run_paced", lambda *args, **kwargs: "U")
    with pytest.raises(labrun.LabError, match="answered almost nothing"):
        tier3.session(runner, tmp_path / "id_lab", "admin", "192.0.2.4", ["terminal pager 0"], "ERROR:", "load", prompt=r"[>#] ?$")
    paced = {name for name, v in tier3.VENDORS.items() if v.prompt}
    assert paced == {"asav", "c8000v", "sonicwall"}, paced  # (the 8000V paced too, before its first run: an IOS CLI like the ASA's)


def test_the_asav_interface_names_are_read_from_the_firewall() -> None:
    """The seventh ASAv run: on a c5 instance there was no GigabitEthernet0/0 ("Invalid input" for every interface line)."""
    answer = """ciscoasa# show interface ip brief
Interface                  IP-Address      OK? Method Status                Protocol
Management0/0              10.20.0.20      YES DHCP   up                    up
TenGigabitEthernet0/0      unassigned      YES unset  administratively down up
TenGigabitEthernet0/1      unassigned      YES unset  administratively down up
TenGigabitEthernet0/2      unassigned      YES unset  administratively down up
ciscoasa# exit"""
    ports = tier3.asa_data_ports(answer)
    assert ports == ["TenGigabitEthernet0/0", "TenGigabitEthernet0/1", "TenGigabitEthernet0/2"]
    lines = tier3.fill_ports(tier3.VENDORS["asav"].session(_asa_policy()), ports)
    assert "interface TenGigabitEthernet0/0" in lines and " nameif inside" in lines and not any("{port" in line for line in lines)
    with pytest.raises(labrun.LabError, match="data interfaces"):
        tier3.fill_ports(["interface {port3}"], ports[:2])


def _asa_policy() -> Path:
    import tempfile
    path = Path(tempfile.mkdtemp()) / "policy.asa"
    path.write_text("! a comment\naccess-list a extended permit ip any any\naccess-group a global\nend\n", encoding="utf-8")
    return path


def test_a_session_that_ends_early_names_the_refused_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The seventh ASAv run ended at an `exit` that left config mode; the reason was the refused lines before it."""
    runner = labrun.Runner(tmp_path, echo=False)
    said = "ciscoasa(config)# interface GigabitEthernet0/0\n ^\nERROR: % Invalid input detected at '^' marker.\nciscoasa# exit\nLogoff\n"

    def ended(*args: object, **kwargs: object) -> str:
        raise labrun.SessionEnded("ssh ended before the prompt came back", said)

    monkeypatch.setattr(runner, "run_paced", ended)
    with pytest.raises(labrun.LabError, match=r"refused 1 lines.*Invalid input.*ended early"):
        tier3.session(runner, tmp_path / "id_lab", "admin", "192.0.2.4", ["interface x"], r"ERROR:", "load", prompt=r"[>#] ?$")
    assert "Invalid input" in (tmp_path / "load.txt").read_text()


def test_no_ready_check_stops_at_a_pager() -> None:
    """The first vSRX run: `show version` stopped at ---(more)---, which took the `exit` after it for a filter; every
    try hung until the boot time ran out. A ready check whose answer is long turns the pager off."""
    assert tier3.VENDORS["vsrx"].ready.endswith("| no-more")
    for name, vendor in tier3.VENDORS.items():
        assert "|" in vendor.ready or name in ("fortigate", "panos", "checkpoint", "sonicwall") or vendor.as_command, (name, vendor.ready)  # (a shell: no pager; SonicOS's show version is short)


def test_the_vsrx_is_ready_once_its_data_interfaces_exist() -> None:
    """The second vSRX run: `show version` answered, the policy was committed and the probes ran within 30 seconds, and
    the forwarding engine had made no ge-0/0/x yet; nothing passed. Ready means all three data interfaces listed."""
    vendor = tier3.VENDORS["vsrx"]
    typed = "ec2-user> show interfaces terse | match ge-0/0 | no-more \r\n"
    two = typed + "ge-0/0/0                up    up\r\nge-0/0/0.0              up    up   inet\r\nge-0/0/1                up    up\r\n"
    three = two + "ge-0/0/2                up    up\r\nec2-user> exit\r\n"
    assert not re.search(vendor.ready_answer, typed + "\r\nec2-user> exit\r\n")
    assert not re.search(vendor.ready_answer, two) and re.search(vendor.ready_answer, three)
    assert vendor.ready.endswith("| no-more")


def test_the_check_point_standalone_is_set_up_as_check_points_templates_do(tmp_path: Path) -> None:
    """Check Point (never run): the image's own /etc/cloud_config.py, as Check Point's Terraform module for a standalone
    writes it; bash for admin (mgmt_cli over SSH); the version from the image's name; no password (the key, -r true)."""
    vendor = tier3.VENDORS["checkpoint"]
    data = tier3.user_data(vendor, tmp_path / "id_lab", "", "Check Point CloudGuard IaaS Standalone R82.20-391.2248 PAYG")
    assert data.startswith("#cloud-config\nruncmd:\n  - |\n    python3 /etc/cloud_config.py ")
    for part in ('installationType=\\"standalone\\"', 'shell=\\"/bin/bash\\"', 'osVersion=\\"R82.20\\"', 'hostName=\\"fwlab-cp\\"',
                 'passwordHash=\\"\\"'):
        assert part in data, part
    assert tier3.checkpoint_version("") == "R82" and tier3.checkpoint_version("x R81.20-628 y") == "R81.20"
    assert vendor.boot_minutes == 60 and vendor.instance_type == "m5.xlarge" and vendor.ready == "api status"
    assert "Check Point*" in vendor.ami_pattern  # (Check Point's templates use a map of ids: the subscribed product of the name, find_ami)


def test_the_check_point_load_names_every_interface_in_one_call_and_installs(tmp_path: Path) -> None:
    """`set simple-gateway` replaces the interface list: eth0 must be in the same call as eth1-3, each data interface
    in its zone. The driver stops at the first failing step (FWLAB-FAILED) and ends with FWLAB-LOADED-42."""
    driver = tier3.checkpoint_driver()
    sets = [line for line in driver.splitlines() if line.startswith("mgmt_cli set simple-gateway")]
    assert len(sets) == 1
    for name in ("eth0", "eth1", "eth2", "eth3"):
        assert f" {name} " in sets[0]
    for zone in ("inside", "dmz", "outside"):
        assert f"security-zone-settings.specific-zone {zone}" in sets[0]
    order = [driver.index(x) for x in ("SID=fwshift.sid sh ./policy.checkpoint", "mgmt_cli set simple-gateway", "mgmt_cli publish",
                                       "mgmt_cli install-policy", 'FWLAB-LOADED-$((40 + 2))')]
    assert order == sorted(order)
    vendor = tier3.VENDORS["checkpoint"]
    files = vendor.uploads(tmp_path / "policy.checkpoint")
    assert [f.name for f in files] == ["policy.checkpoint", "fwlab_load.sh"] and (tmp_path / "fwlab_load.sh").read_text() == driver
    assert re.search(vendor.success, "FWLAB-LOADED-42") and not re.search(vendor.success, "echo FWLAB-LOADED-$((40 + 2))")
    assert re.search(vendor.errors, "FWLAB-FAILED: publish") and re.search(vendor.errors, "FAILED: mgmt_cli add host")
    with pytest.raises(labrun.LabError, match="--ami"):
        tier3.find_ami(labrun.Runner(tmp_path, echo=False), "eu-west-1", "")


def test_the_c8000v_waits_for_its_data_interfaces() -> None:
    """Ready once `show ip interface brief` lists GigabitEthernet2 to 4, not when the command alone is echoed."""
    vendor = tier3.VENDORS["c8000v"]
    answer = ("Interface              IP-Address      OK? Method Status                Protocol\n"
              "GigabitEthernet1       10.0.0.5        YES DHCP   up                    up\n"
              "GigabitEthernet2       unassigned      YES unset  administratively down down\n"
              "GigabitEthernet3       unassigned      YES unset  administratively down down\n"
              "GigabitEthernet4       unassigned      YES unset  administratively down down\n")  # fmt: skip
    assert re.search(vendor.ready_answer, answer)
    typed = "router#show ip interface brief | include GigabitEthernet2 GigabitEthernet3 GigabitEthernet4\n"
    assert not re.search(vendor.ready_answer, typed + "GigabitEthernet1       10.0.0.5  YES DHCP up up\n")
    assert "|" in vendor.ready
    assert vendor.key_bits == 2048 and vendor.prompt and vendor.diagnose()[-1] == "exit"
    assert re.search(vendor.prompt, "fwlab(config-if)#") and re.search(vendor.prompt, "ip-10-0-0-5#")


def test_an_image_id_of_another_region_stops_the_run_at_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The first 8000V run: the id was of another region; describe-images said so and the run went on to Terraform."""
    runner = labrun.Runner(tmp_path, echo=False)
    monkeypatch.setattr(runner, "run", lambda *args, **kwargs: "")  # (stdout: nothing; the error went to stderr)
    with pytest.raises(labrun.LabError, match="does not exist in us-east-1.*one region"):
        tier3.describe_ami(runner, "us-east-1", "ami-0896874345732e1ce")
    monkeypatch.setattr(runner, "run", lambda *args, **kwargs: "Cisco-C8K-PAYG-ESS-26.02.01-x\tabc123\n")
    tier3.describe_ami(runner, "us-east-1", "ami-0896874345732e1ce")


def test_only_the_runs_key_is_offered() -> None:
    """The second 8000V run: "Permission denied (publickey...)" for the whole boot. An ssh agent's keys are offered before
    -i unless IdentitiesOnly says otherwise, and IOS XE allows three tries: only the run's key is offered."""
    for batch in (True, False):
        prefix = labrun.ssh_prefix(Path("k"), "ec2-user", "192.0.2.4", Path("kh"), batch=batch)
        assert prefix[prefix.index("IdentitiesOnly=yes") - 1] == "-o"
    for name in ("tier1.py", "tier2.py", "tier3.py"):  # (the scp commands; ssh_prefix above)
        text = (Path(labrun.__file__).parent / name).read_text(encoding="utf-8")
        assert text.count('"BatchMode=yes"') == text.count('"BatchMode=yes", "-o", "IdentitiesOnly=yes"'), name


def test_the_c8000v_gets_the_runs_key_whole_and_takes_rsa_signatures(tmp_path: Path) -> None:
    """The second 8000V run: every login refused; IOS XE 26.02 takes no ssh-rsa signature by default, and its own set-up
    gave ec2-user an MD5 key-hash of the AWS key. Day 0: the key as a key-string, the RSA signatures allowed."""
    key = tmp_path / "id_lab"
    blob = "AAAAB3NzaC1yc2E" + "x" * 357
    key.with_suffix(".pub").write_text(f"ssh-rsa {blob} fwlab\n", encoding="utf-8")
    data = tier3.user_data(tier3.VENDORS["c8000v"], key)
    lines = data.splitlines()
    assert lines[0] == "Section: IOS configuration"
    assert "ip ssh server algorithm publickey rsa-sha2-512 rsa-sha2-256 ssh-rsa" in lines
    start = lines.index("  key-string") + 1
    body = lines[start:lines.index("  exit")]
    assert "".join(part.strip() for part in body) == blob and all(len(part) <= 67 for part in body)
    assert lines[lines.index("ip ssh pubkey-chain") + 1] == " username ec2-user"
    assert "{" not in data


def test_a_refused_key_is_traced_once_with_ssh_v(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The second 8000V run kept only "Permission denied" thirty times: the first refusal is followed by one ssh -v,
    whose lines about the login go to boot.txt."""
    runner = labrun.Runner(tmp_path, echo=False)
    calls: List[List[str]] = []

    def fake_run(args: List[str], **kwargs: object) -> str:
        calls.append(list(args))
        if "-v" in args:
            runner.last_stderr = ("debug1: Remote protocol version 2.0, remote software version Cisco-1.25\n"
                                  "debug1: kex_input_ext_info: server-sig-algs=<rsa-sha2-256,rsa-sha2-512>\n"
                                  "debug1: Offering public key: k RSA SHA256:abc explicit\ndebug1: noise\n")  # fmt: skip
            return ""
        if len(calls) < 4:
            raise labrun.LabError("ssh failed (255): ec2-user@192.0.2.4: Permission denied (publickey,keyboard-interactive,password).")
        return "GigabitEthernet2  x\nGigabitEthernet3  x\nGigabitEthernet4  x\n"

    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(tier3.time, "sleep", lambda seconds: None)
    tier3.wait_cli(runner, tmp_path / "id_lab", "ec2-user", "192.0.2.4", "show ip interface brief", tier3._C8000V_READY, 30)
    text = (tmp_path / "boot.txt").read_text()
    assert text.count("ssh -v, once") == 1 and "server-sig-algs=" in text and "Offering public key" in text and "noise" not in text
    assert sum("-v" in c for c in calls) == 1


@pytest.mark.parametrize("flavour", ["pfsense", "opnsense"])
def test_the_pf_family_gets_its_zones_on_the_data_cards(tmp_path: Path, flavour: str) -> None:
    """pfSense and OPNsense on AWS: the image's WAN (the first card, DHCP) is management; the zones are OPT1 to OPT3 on
    ena1 to ena3 with the lab's addresses, and the converted rules name those interfaces."""
    vendor = tier3.VENDORS[flavour]
    done = lab_conversion(tmp_path, flavour, vendor.options)
    base = (Path(__file__).parent / "data" / f"{flavour}_sample.xml").read_text(encoding="utf-8")
    merged = tier3.assign_zone_interfaces(tier2.merge_areas(base, done["out"].read_text(encoding="utf-8"), flavour), flavour)
    root = ET.fromstring(merged)
    interfaces = root.find("interfaces")
    assert interfaces is not None
    seen = {child.tag: (child.findtext("if"), child.findtext("ipaddr"), child.findtext("subnet")) for child in interfaces}
    assert seen["opt1"] == ("ena1", "10.20.1.4", "24") and seen["opt2"] == ("ena2", "10.20.2.4", "24") and seen["opt3"] == ("ena3", "10.20.3.4", "24")
    assert seen["wan"][0] == base.split("<wan>")[1].split("<if>")[1].split("</if>")[0]  # (management stays as it was)
    assert interfaces.find("opt3/blockpriv") is None and interfaces.find("opt3/enable") is not None
    assert (interfaces.find("opt1/enable").text or "") == ("" if flavour == "pfsense" else "1")  # type: ignore[union-attr]
    named = set(re.findall(r"<interface>([^<]+)</interface>", done["out"].read_text(encoding="utf-8")))
    assert named and named <= {"opt1", "opt2", "opt3"}


def test_a_card_the_image_gave_another_interface_is_taken_back() -> None:
    """An image that put LAN on the second card: LAN is taken out, so that the card is OPT1's alone."""
    base = "<pfsense><interfaces><wan><if>ena0</if><ipaddr>dhcp</ipaddr></wan><lan><if>ena1</if><ipaddr>192.168.1.1</ipaddr></lan></interfaces></pfsense>"
    root = ET.fromstring(tier3.assign_zone_interfaces(base, "pfsense"))
    tags = [child.tag for child in root.find("interfaces")]  # type: ignore[union-attr]
    assert tags == ["wan", "opt1", "opt2", "opt3"]


def test_the_pf_family_is_loaded_and_checked_after_a_reboot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The load reads /conf/config.xml (with sudo for OPNsense's ec2-user), writes the merged file back, reboots, and
    stops when a zone has no address or pf no rule for the web server."""
    vendor = tier3.VENDORS["opnsense"]
    done = lab_conversion(tmp_path, "opnsense", vendor.options)
    runner = labrun.Runner(tmp_path, echo=False)
    calls: List[List[str]] = []
    sample = (Path(__file__).parent / "data" / "opnsense_sample.xml").read_text(encoding="utf-8")

    def fake_run(args: List[str], **kwargs: object) -> str:
        calls.append(list(args))
        last = args[-1]
        if last.endswith("cat /conf/config.xml"):
            return sample
        if "FWLAB-WRITTEN" in last:
            return "FWLAB-WRITTEN"
        if last == "ifconfig":
            return "ena1: inet 10.20.1.4\nena2: inet 10.20.2.4\n"  # (no address for outside)
        if last.endswith("pfctl -sr"):
            return "pass in quick on ena1 inet proto tcp from 10.20.1.0/24 to 10.20.2.10"
        return ""

    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(tier3.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(tier3, "wait_cli", lambda *args, **kwargs: None)
    with pytest.raises(labrun.LabError, match="outside have no address"):
        tier3.load_pf_config(runner, vendor, tmp_path / "id_lab", "192.0.2.4", done["out"])
    commands = [c[-1] for c in calls if c[0] == "ssh"]
    assert commands[0] == "sudo cat /conf/config.xml" and any(c.startswith("sudo cp fwlab-config.xml /conf/config.xml") for c in commands)
    assert "sudo shutdown -r now" in commands
    assert any(c[0] == "scp" and c[-1].endswith(":fwlab-config.xml") for c in calls)
    assert "<if>ena3</if>" in (tmp_path / "config.merged.xml").read_text(encoding="utf-8")


def test_a_question_before_the_prompt_is_answered_once(tmp_path: Path) -> None:
    """SonicOS asks for its own user and password in the SSH session before its prompt: the paced typing answers each
    question once, then types the lines after the prompt."""
    cli = (
        "import sys\n"
        "sys.stdout.write('User: '); sys.stdout.flush(); user = sys.stdin.readline().strip()\n"
        "sys.stdout.write('Password: '); sys.stdout.flush(); word = sys.stdin.readline().strip()\n"
        "ok = user == 'admin' and word == 'i-0abc'\n"
        "sys.stdout.write(('admin@NSV> ' if ok else 'Access denied\\n')); sys.stdout.flush()\n"
        "for line in sys.stdin:\n"
        "    if line.strip() == 'exit': break\n"
        "    sys.stdout.write(line.strip() + '\\nok\\nadmin@NSV> '); sys.stdout.flush()\n"
    )
    runner = labrun.Runner(tmp_path, echo=False)
    out = runner.run_paced([sys.executable, "-c", cli], ["show version", "exit"], r"[>#] ?$", step=10,
                           answers=((r"(?i)user(name)?: ?$", "admin"), (r"(?i)password: ?$", "i-0abc")))
    assert "Access denied" not in out and out.count("ok") == 1


def test_the_sonicwall_logs_in_by_password_and_makes_its_zones(tmp_path: Path) -> None:
    """The NSv: no key, the instance id as the password (SSH_ASKPASS, without BatchMode, which ssh would keep as the
    first value); the zones made, trusted, and X0, X2 and X3 put in them before FWShift's commands."""
    vendor = tier3.VENDORS["sonicwall"]
    assert vendor.password_login and any("{password}" in answer for _, answer in vendor.answers)
    prefix = labrun.ssh_prefix(Path("k"), "admin", "192.0.2.4", Path("kh"), batch=False)
    assert "BatchMode=yes" not in prefix and "NumberOfPasswordPrompts=1" in prefix
    done = lab_conversion(tmp_path, "sonicwall", vendor.options)
    lines = vendor.session(done["out"])
    for zone, port in (("inside", "X0"), ("dmz", "X2"), ("outside", "X3")):
        assert lines.index(f"zone {zone}") < lines.index(f"interface {port}") < lines.index(f"ip-assignment {zone} static")
    assert lines.index("commit") < lines.index("configure terminal", 1) and lines[-1] == "exit"
    keep = dict(os.environ)
    try:
        labrun.askpass(tmp_path, "i-0abc")
        script = Path(os.environ["SSH_ASKPASS"])
        assert os.environ["SSH_ASKPASS_REQUIRE"] == "force"
        if os.name == "posix":
            assert subprocess.run([str(script)], capture_output=True, text=True).stdout == "i-0abc"
            assert (tmp_path / "askpass.secret").stat().st_mode & 0o077 == 0
    finally:
        os.environ.clear()
        os.environ.update(keep)


def test_the_image_is_the_newest_of_a_subscribed_product(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """vSRX bundles, VM-Series BYOL and bundles, third-party OPNsense images: one name, several products. Of the images
    named, the newest of a product this account is subscribed to is taken: a dry-run launch answers OptInRequired for
    a product not subscribed to."""
    runner = labrun.Runner(tmp_path, echo=False)
    listing = ("ami-0new\tjunos-vsrx3-x86-64-24.2-byol\tbyolcode\n"
               "ami-0mid\tjunos-vsrx3-x86-64-24.2-payg\tpaygcode\n"
               "ami-0old\tjunos-vsrx3-x86-64-23.4-payg\tpaygcode\n")  # fmt: skip
    tried: List[str] = []

    def fake_run(args: List[str], **kwargs: object) -> str:
        if "describe-images" in args:
            assert "Name=name,Values=junos-vsrx3-x86-64-*,*vSRX*" in args
            return listing
        ami = args[args.index("--image-id") + 1]
        tried.append(ami)
        runner.last_stderr = ("An error occurred (OptInRequired) when calling the RunInstances operation" if ami == "ami-0new"
                              else "An error occurred (DryRunOperation) when calling the RunInstances operation: Request would have succeeded")
        return ""

    monkeypatch.setattr(runner, "run", fake_run)
    assert tier3.find_ami(runner, "us-east-1", "junos-vsrx3-x86-64-*, *vSRX*") == "ami-0mid"
    assert tried == ["ami-0new", "ami-0mid"]  # (one try per product, the newest image of each)
    kept = (tmp_path / "amis.txt").read_text()
    assert "byolcode: not subscribed (OptInRequired)" in kept and "paygcode: subscribed" in kept
    assert json.loads((tmp_path / "run.json").read_text())["product_code"] == "paygcode"

    runner.last_stderr = ""
    monkeypatch.setattr(runner, "run", lambda args, **kw: listing if "describe-images" in args else
                        setattr(runner, "last_stderr", "(OptInRequired)") or "")  # type: ignore[func-returns-value]
    with pytest.raises(labrun.LabError, match="subscribed to none of the 2 products"):
        tier3.find_ami(runner, "us-east-1", "junos-vsrx3-x86-64-*")


def test_a_product_alone_is_taken_without_a_try_and_every_vendor_has_names(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = labrun.Runner(tmp_path, echo=False)
    calls: List[List[str]] = []
    monkeypatch.setattr(runner, "run", lambda args, **kw: calls.append(list(args)) or "ami-0one\tpfSense-plus-ec2-26.07-RELEASE-amd64\tcphb\n")
    assert tier3.find_ami(runner, "us-east-1", "pfSense-plus-ec2-*-RELEASE-amd64*") == "ami-0one" and len(calls) == 1
    assert all(vendor.ami_pattern for vendor in tier3.VENDORS.values())  # (--ami no longer needed for any of them)


def test_the_elastic_ip_waits_for_the_firewall_to_run() -> None:
    """The first pfSense run: the address attached to the interface of an instance still being made, refused."""
    text = (Path(labrun.__file__).parent / "tier3" / "aws" / "main.tf").read_text(encoding="utf-8")
    block = text[text.index('resource "aws_eip" "fw"'):]
    block = block[:block.index("\n}")]
    assert "aws_instance.firewall" in block


@pytest.mark.parametrize("flavour", ["pfsense", "opnsense"])
def test_the_images_own_management_rules_survive_the_merge(tmp_path: Path, flavour: str) -> None:
    """The first pfSense run: the merge replaced the rules, the image's "Default SSH rule" on WAN went with them, and
    after the reboot SSH timed out for good. The image's WAN rules stay, in front of the converted ones."""
    vendor = tier3.VENDORS[flavour]
    done = lab_conversion(tmp_path, flavour, vendor.options)
    wan_rule = ("<rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol><source><any/></source>"
                "<destination><network>wanip</network><port>22</port></destination><descr>Default SSH rule</descr></rule>")
    base = (Path(__file__).parent / "data" / f"{flavour}_sample.xml").read_text(encoding="utf-8")
    base = base.replace("<filter>", "<filter>" + wan_rule, 1) if "<filter>" in base else base.replace("</interfaces>", "</interfaces><filter>" + wan_rule + "</filter>", 1)
    merged = tier3.keep_management_rules(base, tier2.merge_areas(base, done["out"].read_text(encoding="utf-8"), flavour))
    root = ET.fromstring(merged)
    legacy = root.find("filter")
    assert legacy is not None
    rules = legacy.findall("rule")
    assert rules and rules[0].findtext("descr") == "Default SSH rule"
    if flavour == "pfsense":  # (the image's WAN rules first, all of them; then the converted rules, on the zones' interfaces)
        names = [r.findtext("interface") for r in rules]
        first_zone = next(i for i, name in enumerate(names) if name != "wan")
        assert set(names[:first_zone]) == {"wan"} and set(names[first_zone:]) <= {"opt1", "opt2", "opt3"}


def test_the_web_servers_rule_is_found_by_its_alias_too() -> None:
    """The third pfSense run: every converted rule in pf, the web server as the table <web_server>, not its address."""
    rules = 'pass in log quick on ena1 inet proto tcp from <inside_net> to <web_server> port = http flags S/SA keep state (if-bound) label "descr=web-to-dmz"'
    assert re.search(tier2.WEB_SERVER_IN_PF, rules) and re.search(tier2.WEB_SERVER_IN_PF, "pass in quick on vtnet1 inet proto tcp from 10.20.1.0/24 to 10.20.2.10")
    assert not re.search(tier2.WEB_SERVER_IN_PF, "pass in quick on ena3 from any to 10.20.2.100")


def test_the_probe_waits_for_an_address_its_host_does_not_have_yet(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fourth pfSense run: in11's probe started before its test interface had 10.20.1.11; every bind failed with
    "Cannot assign requested address", once, and the host answered on nothing for the whole run. The probe waits for
    the address, and still gives up on other errors (a port taken, as sshd's 22)."""
    attempts: List[int] = []

    class FakeSocket:
        def bind(self, where: Any) -> None:
            attempts.append(where[1])
            if len(attempts) < 3:
                raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

    monkeypatch.setattr(labprobe.time, "sleep", lambda seconds: None)
    labprobe._bind(FakeSocket(), "10.20.1.11", 80, "tcp", threading.Event())
    assert attempts == [80, 80, 80]

    class Taken:
        def bind(self, where: Any) -> None:
            raise OSError(errno.EADDRINUSE, "Address already in use")

    with pytest.raises(OSError):
        labprobe._bind(Taken(), "10.20.1.11", 22, "tcp", threading.Event())


def test_an_instance_type_the_product_takes_is_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The first OPNsense runs: neither c5.xlarge nor m5.xlarge ("UnsupportedOperation: The instance configuration for
    this AWS Marketplace product is not supported"). The lab tries the vendor's type, then the others, by dry-run."""
    runner = labrun.Runner(tmp_path, echo=False)
    tried: List[str] = []

    def fake_run(args: List[str], **kwargs: object) -> str:
        instance_type = args[args.index("--instance-type") + 1]
        tried.append(instance_type)
        runner.last_stderr = ("(UnsupportedOperation) The instance configuration for this AWS Marketplace product is not supported"
                              if instance_type in ("c5.xlarge", "m5.xlarge") else "(DryRunOperation) Request would have succeeded")
        return ""

    monkeypatch.setattr(runner, "run", fake_run)
    assert tier3.pick_instance_type(runner, "us-east-1", "ami-0opn", "c5.xlarge") == "t3.xlarge"
    assert tried == ["c5.xlarge", "m5.xlarge", "t3.xlarge"]
    assert "c5.xlarge: type not supported" in (tmp_path / "instance-types.txt").read_text()
    # A try that does not tell (no default VPC): the vendor's own, as before.
    monkeypatch.setattr(runner, "run", lambda args, **kw: setattr(runner, "last_stderr", "(VPCIdNotSpecified)") or "")  # type: ignore[func-returns-value]
    assert tier3.pick_instance_type(runner, "us-east-1", "ami-0opn", "m5.xlarge") == "m5.xlarge"
    # None taken: said so.
    monkeypatch.setattr(runner, "run", lambda args, **kw: setattr(runner, "last_stderr", "(UnsupportedOperation)") or "")  # type: ignore[func-returns-value]
    with pytest.raises(labrun.LabError, match="takes none of the instance types"):
        tier3.pick_instance_type(runner, "us-east-1", "ami-0opn", "c5.xlarge")
    assert all(t.endswith("xlarge") for t in tier3.INSTANCE_TYPES)
