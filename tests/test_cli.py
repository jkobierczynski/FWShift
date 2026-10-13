# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from helpers import DATA

from fwshift import __version__
from fwshift.cli import VENDORS, detect_format, main
from fwshift.emitters.cisco import loader_source

GOLDEN = DATA / "expected"
CASES = [
    ("panos_sample.xml", "fortios", "panos_to_fortios.conf"),
    ("fortios_sample.conf", "panos", "fortios_to_panos.set"),
    ("iptables_sample.rules", "panos", "iptables_to_panos.set"),
    ("iptables_sample.rules", "fortios", "iptables_to_fortios.conf"),
    ("panos_sample.xml", "iptables", "panos_to_iptables.rules"),
    ("fortios_sample.conf", "iptables", "fortios_to_iptables.rules"),
    ("checkpoint_sample.json", "panos", "checkpoint_to_panos.set"),
    ("checkpoint_sample.json", "fortios", "checkpoint_to_fortios.conf"),
    ("checkpoint_sample.json", "iptables", "checkpoint_to_iptables.rules"),
    ("checkpoint_sample.json", "checkpoint", "checkpoint_to_checkpoint.sh"),
    ("panos_sample.xml", "checkpoint", "panos_to_checkpoint.sh"),
    ("fortios_sample.conf", "checkpoint", "fortios_to_checkpoint.sh"),
    ("iptables_sample.rules", "checkpoint", "iptables_to_checkpoint.sh"),
    ("asa_sample.cfg", "panos", "asa_to_panos.set"),
    ("asa_sample.cfg", "fortios", "asa_to_fortios.conf"),
    ("asa_sample.cfg", "checkpoint", "asa_to_checkpoint.sh"),
    ("asa_sample.cfg", "iptables", "asa_to_iptables.rules"),
    ("asa_sample.cfg", "asa", "asa_to_asa.cfg"),
    ("panos_sample.xml", "asa", "panos_to_asa.cfg"),
    ("fortios_sample.conf", "asa", "fortios_to_asa.cfg"),
    ("checkpoint_sample.json", "asa", "checkpoint_to_asa.cfg"),
    ("iptables_sample.rules", "asa", "iptables_to_asa.cfg"),
    ("sophos_sample.xml", "sophos", "sophos_to_sophos.xml"),
    ("sophos_sample.xml", "panos", "sophos_to_panos.set"),
    ("sophos_sample.xml", "fortios", "sophos_to_fortios.conf"),
    ("sophos_sample.xml", "checkpoint", "sophos_to_checkpoint.sh"),
    ("sophos_sample.xml", "asa", "sophos_to_asa.cfg"),
    ("sophos_sample.xml", "iptables", "sophos_to_iptables.rules"),
    ("panos_sample.xml", "sophos", "panos_to_sophos.xml"),
    ("fortios_sample.conf", "sophos", "fortios_to_sophos.xml"),
    ("checkpoint_sample.json", "sophos", "checkpoint_to_sophos.xml"),
    ("asa_sample.cfg", "sophos", "asa_to_sophos.xml"),
    ("iptables_sample.rules", "sophos", "iptables_to_sophos.xml"),
    ("fmc_sample.json", "fmc", "fmc_to_fmc.policy.txt"),
    ("fmc_sample.json", "fdm", "fmc_to_fdm.json"),
    ("fmc_sample.json", "panos", "fmc_to_panos.set"),
    ("fmc_sample.json", "fortios", "fmc_to_fortios.conf"),
    ("fmc_sample.json", "checkpoint", "fmc_to_checkpoint.sh"),
    ("fmc_sample.json", "asa", "fmc_to_asa.cfg"),
    ("fmc_sample.json", "sophos", "fmc_to_sophos.xml"),
    ("fmc_sample.json", "iptables", "fmc_to_iptables.rules"),
    ("fdm_sample.txt", "fdm", "fdm_to_fdm.json"),
    ("fdm_sample.txt", "fmc", "fdm_to_fmc.policy.txt"),
    ("fdm_sample.txt", "panos", "fdm_to_panos.set"),
    ("fdm_sample.txt", "fortios", "fdm_to_fortios.conf"),
    ("fdm_sample.txt", "checkpoint", "fdm_to_checkpoint.sh"),
    ("fdm_sample.txt", "asa", "fdm_to_asa.cfg"),
    ("fdm_sample.txt", "sophos", "fdm_to_sophos.xml"),
    ("fdm_sample.txt", "iptables", "fdm_to_iptables.rules"),
    ("panos_sample.xml", "fmc", "panos_to_fmc.policy.txt"),
    ("fortios_sample.conf", "fmc", "fortios_to_fmc.policy.txt"),
    ("checkpoint_sample.json", "fmc", "checkpoint_to_fmc.policy.txt"),
    ("asa_sample.cfg", "fmc", "asa_to_fmc.policy.txt"),
    ("sophos_sample.xml", "fmc", "sophos_to_fmc.policy.txt"),
    ("iptables_sample.rules", "fmc", "iptables_to_fmc.policy.txt"),
    ("panos_sample.xml", "fdm", "panos_to_fdm.json"),
    ("fortios_sample.conf", "fdm", "fortios_to_fdm.json"),
    ("checkpoint_sample.json", "fdm", "checkpoint_to_fdm.json"),
    ("asa_sample.cfg", "fdm", "asa_to_fdm.json"),
    ("sophos_sample.xml", "fdm", "sophos_to_fdm.json"),
    ("iptables_sample.rules", "fdm", "iptables_to_fdm.json"),
    ("pfsense_sample.xml", "pfsense", "pfsense_to_pfsense.xml"),
    ("pfsense_sample.xml", "panos", "pfsense_to_panos.set"),
    ("pfsense_sample.xml", "fortios", "pfsense_to_fortios.conf"),
    ("pfsense_sample.xml", "checkpoint", "pfsense_to_checkpoint.sh"),
    ("pfsense_sample.xml", "asa", "pfsense_to_asa.cfg"),
    ("pfsense_sample.xml", "sophos", "pfsense_to_sophos.xml"),
    ("pfsense_sample.xml", "fmc", "pfsense_to_fmc.policy.txt"),
    ("pfsense_sample.xml", "fdm", "pfsense_to_fdm.json"),
    ("pfsense_sample.xml", "iptables", "pfsense_to_iptables.rules"),
    ("panos_sample.xml", "pfsense", "panos_to_pfsense.xml"),
    ("fortios_sample.conf", "pfsense", "fortios_to_pfsense.xml"),
    ("checkpoint_sample.json", "pfsense", "checkpoint_to_pfsense.xml"),
    ("asa_sample.cfg", "pfsense", "asa_to_pfsense.xml"),
    ("sophos_sample.xml", "pfsense", "sophos_to_pfsense.xml"),
    ("fmc_sample.json", "pfsense", "fmc_to_pfsense.xml"),
    ("fdm_sample.txt", "pfsense", "fdm_to_pfsense.xml"),
    ("iptables_sample.rules", "pfsense", "iptables_to_pfsense.xml"),
    ("sonicwall_sample.exp", "sonicwall", "sonicwall_to_sonicwall.cli"),
    ("sonicwall_sample.exp", "panos", "sonicwall_to_panos.set"),
    ("sonicwall_sample.exp", "fortios", "sonicwall_to_fortios.conf"),
    ("sonicwall_sample.exp", "checkpoint", "sonicwall_to_checkpoint.sh"),
    ("sonicwall_sample.exp", "asa", "sonicwall_to_asa.cfg"),
    ("sonicwall_sample.exp", "sophos", "sonicwall_to_sophos.xml"),
    ("sonicwall_sample.exp", "fmc", "sonicwall_to_fmc.policy.txt"),
    ("sonicwall_sample.exp", "fdm", "sonicwall_to_fdm.json"),
    ("sonicwall_sample.exp", "pfsense", "sonicwall_to_pfsense.xml"),
    ("sonicwall_sample.exp", "iptables", "sonicwall_to_iptables.rules"),
    ("panos_sample.xml", "sonicwall", "panos_to_sonicwall.cli"),
    ("fortios_sample.conf", "sonicwall", "fortios_to_sonicwall.cli"),
    ("checkpoint_sample.json", "sonicwall", "checkpoint_to_sonicwall.cli"),
    ("asa_sample.cfg", "sonicwall", "asa_to_sonicwall.cli"),
    ("sophos_sample.xml", "sonicwall", "sophos_to_sonicwall.cli"),
    ("fmc_sample.json", "sonicwall", "fmc_to_sonicwall.cli"),
    ("fdm_sample.txt", "sonicwall", "fdm_to_sonicwall.cli"),
    ("pfsense_sample.xml", "sonicwall", "pfsense_to_sonicwall.cli"),
    ("iptables_sample.rules", "sonicwall", "iptables_to_sonicwall.cli"),
    ("watchguard_sample.xml", "watchguard", "watchguard_to_watchguard.xml"),
    ("watchguard_sample.xml", "panos", "watchguard_to_panos.set"),
    ("watchguard_sample.xml", "fortios", "watchguard_to_fortios.conf"),
    ("watchguard_sample.xml", "checkpoint", "watchguard_to_checkpoint.sh"),
    ("watchguard_sample.xml", "asa", "watchguard_to_asa.cfg"),
    ("watchguard_sample.xml", "sophos", "watchguard_to_sophos.xml"),
    ("watchguard_sample.xml", "fmc", "watchguard_to_fmc.policy.txt"),
    ("watchguard_sample.xml", "fdm", "watchguard_to_fdm.json"),
    ("watchguard_sample.xml", "pfsense", "watchguard_to_pfsense.xml"),
    ("watchguard_sample.xml", "sonicwall", "watchguard_to_sonicwall.cli"),
    ("watchguard_sample.xml", "iptables", "watchguard_to_iptables.rules"),
    ("panos_sample.xml", "watchguard", "panos_to_watchguard.xml"),
    ("fortios_sample.conf", "watchguard", "fortios_to_watchguard.xml"),
    ("checkpoint_sample.json", "watchguard", "checkpoint_to_watchguard.xml"),
    ("asa_sample.cfg", "watchguard", "asa_to_watchguard.xml"),
    ("sophos_sample.xml", "watchguard", "sophos_to_watchguard.xml"),
    ("fmc_sample.json", "watchguard", "fmc_to_watchguard.xml"),
    ("fdm_sample.txt", "watchguard", "fdm_to_watchguard.xml"),
    ("pfsense_sample.xml", "watchguard", "pfsense_to_watchguard.xml"),
    ("sonicwall_sample.exp", "watchguard", "sonicwall_to_watchguard.xml"),
    ("iptables_sample.rules", "watchguard", "iptables_to_watchguard.xml"),
    ("barracuda_sample.json", "barracuda", "barracuda_to_barracuda.sh"),
    ("barracuda_sample.json", "panos", "barracuda_to_panos.set"),
    ("barracuda_sample.json", "fortios", "barracuda_to_fortios.conf"),
    ("barracuda_sample.json", "checkpoint", "barracuda_to_checkpoint.sh"),
    ("barracuda_sample.json", "asa", "barracuda_to_asa.cfg"),
    ("barracuda_sample.json", "sophos", "barracuda_to_sophos.xml"),
    ("barracuda_sample.json", "fmc", "barracuda_to_fmc.policy.txt"),
    ("barracuda_sample.json", "fdm", "barracuda_to_fdm.json"),
    ("barracuda_sample.json", "pfsense", "barracuda_to_pfsense.xml"),
    ("barracuda_sample.json", "sonicwall", "barracuda_to_sonicwall.cli"),
    ("barracuda_sample.json", "watchguard", "barracuda_to_watchguard.xml"),
    ("barracuda_sample.json", "iptables", "barracuda_to_iptables.rules"),
    ("panos_sample.xml", "barracuda", "panos_to_barracuda.sh"),
    ("fortios_sample.conf", "barracuda", "fortios_to_barracuda.sh"),
    ("checkpoint_sample.json", "barracuda", "checkpoint_to_barracuda.sh"),
    ("asa_sample.cfg", "barracuda", "asa_to_barracuda.sh"),
    ("sophos_sample.xml", "barracuda", "sophos_to_barracuda.sh"),
    ("fmc_sample.json", "barracuda", "fmc_to_barracuda.sh"),
    ("fdm_sample.txt", "barracuda", "fdm_to_barracuda.sh"),
    ("pfsense_sample.xml", "barracuda", "pfsense_to_barracuda.sh"),
    ("sonicwall_sample.exp", "barracuda", "sonicwall_to_barracuda.sh"),
    ("watchguard_sample.xml", "barracuda", "watchguard_to_barracuda.sh"),
    ("iptables_sample.rules", "barracuda", "iptables_to_barracuda.sh"),
    ("junos_sample.conf", "junos", "junos_to_junos.set.conf"),
    ("junos_sample.conf", "panos", "junos_to_panos.set"),
    ("junos_sample.conf", "fortios", "junos_to_fortios.conf"),
    ("junos_sample.conf", "checkpoint", "junos_to_checkpoint.sh"),
    ("junos_sample.conf", "asa", "junos_to_asa.cfg"),
    ("junos_sample.conf", "sophos", "junos_to_sophos.xml"),
    ("junos_sample.conf", "fmc", "junos_to_fmc.policy.txt"),
    ("junos_sample.conf", "fdm", "junos_to_fdm.json"),
    ("junos_sample.conf", "pfsense", "junos_to_pfsense.xml"),
    ("junos_sample.conf", "sonicwall", "junos_to_sonicwall.cli"),
    ("junos_sample.conf", "watchguard", "junos_to_watchguard.xml"),
    ("junos_sample.conf", "barracuda", "junos_to_barracuda.sh"),
    ("junos_sample.conf", "iptables", "junos_to_iptables.rules"),
    ("panos_sample.xml", "junos", "panos_to_junos.set.conf"),
    ("fortios_sample.conf", "junos", "fortios_to_junos.set.conf"),
    ("checkpoint_sample.json", "junos", "checkpoint_to_junos.set.conf"),
    ("asa_sample.cfg", "junos", "asa_to_junos.set.conf"),
    ("sophos_sample.xml", "junos", "sophos_to_junos.set.conf"),
    ("fmc_sample.json", "junos", "fmc_to_junos.set.conf"),
    ("fdm_sample.txt", "junos", "fdm_to_junos.set.conf"),
    ("pfsense_sample.xml", "junos", "pfsense_to_junos.set.conf"),
    ("sonicwall_sample.exp", "junos", "sonicwall_to_junos.set.conf"),
    ("watchguard_sample.xml", "junos", "watchguard_to_junos.set.conf"),
    ("barracuda_sample.json", "junos", "barracuda_to_junos.set.conf"),
    ("iptables_sample.rules", "junos", "iptables_to_junos.set.conf"),
    ("nftables_sample.nft", "nftables", "nftables_to_nftables.nft"),
    ("nftables_sample.nft", "panos", "nftables_to_panos.set"),
    ("nftables_sample.nft", "fortios", "nftables_to_fortios.conf"),
    ("nftables_sample.nft", "checkpoint", "nftables_to_checkpoint.sh"),
    ("nftables_sample.nft", "asa", "nftables_to_asa.cfg"),
    ("nftables_sample.nft", "sophos", "nftables_to_sophos.xml"),
    ("nftables_sample.nft", "fmc", "nftables_to_fmc.policy.txt"),
    ("nftables_sample.nft", "fdm", "nftables_to_fdm.json"),
    ("nftables_sample.nft", "pfsense", "nftables_to_pfsense.xml"),
    ("nftables_sample.nft", "sonicwall", "nftables_to_sonicwall.cli"),
    ("nftables_sample.nft", "watchguard", "nftables_to_watchguard.xml"),
    ("nftables_sample.nft", "barracuda", "nftables_to_barracuda.sh"),
    ("nftables_sample.nft", "iptables", "nftables_to_iptables.rules"),
    ("nftables_sample.nft", "junos", "nftables_to_junos.set.conf"),
    ("panos_sample.xml", "nftables", "panos_to_nftables.nft"),
    ("fortios_sample.conf", "nftables", "fortios_to_nftables.nft"),
    ("checkpoint_sample.json", "nftables", "checkpoint_to_nftables.nft"),
    ("asa_sample.cfg", "nftables", "asa_to_nftables.nft"),
    ("sophos_sample.xml", "nftables", "sophos_to_nftables.nft"),
    ("fmc_sample.json", "nftables", "fmc_to_nftables.nft"),
    ("fdm_sample.txt", "nftables", "fdm_to_nftables.nft"),
    ("pfsense_sample.xml", "nftables", "pfsense_to_nftables.nft"),
    ("sonicwall_sample.exp", "nftables", "sonicwall_to_nftables.nft"),
    ("watchguard_sample.xml", "nftables", "watchguard_to_nftables.nft"),
    ("barracuda_sample.json", "nftables", "barracuda_to_nftables.nft"),
    ("iptables_sample.rules", "nftables", "iptables_to_nftables.nft"),
    ("junos_sample.conf", "nftables", "junos_to_nftables.nft"),
    ("nsx_sample.json", "nsx", "nsx_to_nsx.json"),
    ("nsx_sample.json", "panos", "nsx_to_panos.set"),
    ("nsx_sample.json", "fortios", "nsx_to_fortios.conf"),
    ("nsx_sample.json", "checkpoint", "nsx_to_checkpoint.sh"),
    ("nsx_sample.json", "asa", "nsx_to_asa.cfg"),
    ("nsx_sample.json", "sophos", "nsx_to_sophos.xml"),
    ("nsx_sample.json", "fmc", "nsx_to_fmc.policy.txt"),
    ("nsx_sample.json", "fdm", "nsx_to_fdm.json"),
    ("nsx_sample.json", "pfsense", "nsx_to_pfsense.xml"),
    ("nsx_sample.json", "sonicwall", "nsx_to_sonicwall.cli"),
    ("nsx_sample.json", "watchguard", "nsx_to_watchguard.xml"),
    ("nsx_sample.json", "barracuda", "nsx_to_barracuda.sh"),
    ("nsx_sample.json", "iptables", "nsx_to_iptables.rules"),
    ("nsx_sample.json", "junos", "nsx_to_junos.set.conf"),
    ("nsx_sample.json", "nftables", "nsx_to_nftables.nft"),
    ("panos_sample.xml", "nsx", "panos_to_nsx.json"),
    ("fortios_sample.conf", "nsx", "fortios_to_nsx.json"),
    ("checkpoint_sample.json", "nsx", "checkpoint_to_nsx.json"),
    ("asa_sample.cfg", "nsx", "asa_to_nsx.json"),
    ("sophos_sample.xml", "nsx", "sophos_to_nsx.json"),
    ("fmc_sample.json", "nsx", "fmc_to_nsx.json"),
    ("fdm_sample.txt", "nsx", "fdm_to_nsx.json"),
    ("pfsense_sample.xml", "nsx", "pfsense_to_nsx.json"),
    ("sonicwall_sample.exp", "nsx", "sonicwall_to_nsx.json"),
    ("watchguard_sample.xml", "nsx", "watchguard_to_nsx.json"),
    ("barracuda_sample.json", "nsx", "barracuda_to_nsx.json"),
    ("iptables_sample.rules", "nsx", "iptables_to_nsx.json"),
    ("junos_sample.conf", "nsx", "junos_to_nsx.json"),
    ("nftables_sample.nft", "nsx", "nftables_to_nsx.json"),
]


def test_detect_format() -> None:
    assert detect_format(b"\n  <?xml version='1.0'?><config/>") == "panos"
    assert detect_format(b"\xef\xbb\xbf<config/>") == "panos"
    assert detect_format(b"#config-version=FGT\nconfig system global\nend\n") == "fortios"
    assert detect_format(b"# Generated by iptables-save v1.8.9\n*filter\n") == "iptables"
    assert detect_format((DATA / "nftables_sample.nft").read_bytes()) == "nftables"
    assert detect_format((DATA / "nftables_sample.json").read_bytes()) == "nftables"
    assert detect_format((DATA / "nsx_sample.json").read_bytes()) == "nsx"
    assert detect_format(b'\n[\n {"uid": "x", "rulebase": []}]') == "checkpoint"
    assert detect_format(b": Saved\n:\nASA Version 9.12(4)\n!\nhostname fw\n") == "asa"
    assert detect_format(b'<?xml version="1.0" encoding="UTF-8"?>\n<Configuration APIVersion="2000.1">') == "sophos"
    assert detect_format((DATA / "sophos_sample.xml").read_bytes()) == "sophos"
    assert detect_format((DATA / "fmc_sample.json").read_bytes()) == "fmc" and detect_format((DATA / "fdm_sample.txt").read_bytes()) == "fdm"
    assert detect_format((DATA / "checkpoint_sample.json").read_bytes()) == "checkpoint"
    assert detect_format(b'{"items": [{"type": "AccessRule", "name": "r"}], "paging": {"count": 1}}') == "fmc"
    assert detect_format(b'[{"type": "identitywrapper", "data": {"type": "accessrule", "name": "r"}}]') == "fdm"


@pytest.mark.parametrize("source,target,expected", CASES)
def test_golden_output(source: str, target: str, expected: str, tmp_path: Path) -> None:
    """The converted samples, byte for byte. Regenerate with FWSHIFT_UPDATE_GOLDEN=1 and review the diff."""
    out, report = tmp_path / "out", tmp_path / "report.txt"
    assert main(["convert", str(DATA / source), "--to", target, "-o", str(out), "--report", str(report), "-q"]) == 0
    golden_out, golden_report = GOLDEN / expected, GOLDEN / (expected + ".report.txt")
    written = out.read_text(encoding="utf-8")
    if target == "fmc":
        # The script is the loader, which is a file of its own in the package, and then the policy: the policy is what is kept.
        head, marker, tail = written.partition("\n# The policy, as data.")
        assert head == loader_source() and marker
        written = (marker.lstrip("\n") + tail).replace(f'"generator": "FWShift {__version__}"', '"generator": "FWShift (this version)"')
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        GOLDEN.mkdir(exist_ok=True)
        golden_out.write_text(written, encoding="utf-8", newline="\n")
        golden_report.write_text(report.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    assert written == golden_out.read_text(encoding="utf-8")
    assert report.read_text(encoding="utf-8") == golden_report.read_text(encoding="utf-8")


def test_convert_writes_reports_and_strict_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out, text, data = tmp_path / "o.conf", tmp_path / "r.txt", tmp_path / "r.json"
    args = ["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "-o", str(out)]
    args += ["--report", str(text), "--report-json", str(data)]
    assert main(args) == 0
    assert "14 rules" in capsys.readouterr().err
    assert main(args + ["--strict", "-q"]) == 2  # the sample has rules that need review
    assert out.read_text(encoding="utf-8").startswith("# Generated by FWShift")
    assert "Security rules:" in text.read_text(encoding="utf-8")
    report = json.loads(data.read_text(encoding="utf-8"))
    assert report["summary"]["rule"]["total"] == 14
    by_name = {i["name"]: i for i in report["items"] if i["kind"] == "rule"}
    assert by_name["Admin-SSH"]["disabled"] is True and by_name["Admin-SSH"]["status"] == "needs-review"
    assert by_name["Block-OT-Outbound"]["status"] == "exact"


def test_stdout_output_and_maps(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["convert", str(DATA / "fortios_sample.conf"), "--to", "panos", "-q"]
    args += ["--zone-map", "wan1=untrust", "--interface-map", "wan1=ethernet1/1", "--target-vsys", "vsys2"]
    args += ["--prune-unused"]
    assert main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert 'set vsys vsys2 rulebase security rules "LAN to Internet" to untrust' in captured.out
    assert "interface-address interface ethernet1/1" in captured.out
    assert "internal-all" not in captured.out  # unused group pruned


def test_app_map_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    app_map = tmp_path / "apps.json"
    app_map.write_text('{"bittorrent": ["tcp/6881-6889"]}', encoding="utf-8")
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "-q", "--app-map", str(app_map)]) == 0
    assert 'edit "app-bittorrent"' in capsys.readouterr().out
    app_map.write_text('{"bittorrent": ["nonsense"]}', encoding="utf-8")
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "-q", "--app-map", str(app_map)]) == 1
    assert "invalid port spec" in capsys.readouterr().err


def test_errors_are_reported_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", str(tmp_path / "missing.xml"), "--to", "fortios"]) == 1
    assert "cannot read" in capsys.readouterr().err
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "--vsys", "vsys9"]) == 1
    assert "vsys9" in capsys.readouterr().err
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "--zone-map", "broken"]) == 1
    assert "SOURCE=TARGET" in capsys.readouterr().err


def test_inspect(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inspect", str(DATA / "fortios_sample.conf")]) == 0
    out = capsys.readouterr().out
    assert "format:          fortios" in out and "security rules:  14 (1 disabled)" in out
    assert "geo-blocked" in out


def test_manual_and_code_name_the_same_findings(tmp_path: Path) -> None:
    """Section 7 of the manual is the reference for finding codes: nothing in it is stale, nothing raised is missing."""
    root = Path(__file__).resolve().parents[1]
    manual = (root / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    section = manual.split("## 7. Finding reference")[1].split("## 8. ")[0]
    documented = set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", section))
    source = "".join(path.read_text(encoding="utf-8") for path in (root / "src" / "fwshift").rglob("*.py"))
    stale = sorted(code for code in documented if f'"{code}"' not in source)
    assert not stale, stale
    raised = set()
    samples = sorted(path.name for path in DATA.iterdir() if path.is_file() and "_sample." in path.name and path.suffix != ".log")  # (logs, not configurations)
    assert len(samples) >= 13
    for sample in samples:
        for target in VENDORS:
            report = tmp_path / "report.json"
            args = ["convert", str(DATA / sample), "--to", target, "-o", str(tmp_path / "out"), "--report-json", str(report)]
            assert main(args + ["-q", "--prune-unused"]) == 0
            data = json.loads(report.read_text(encoding="utf-8"))
            raised |= {note["code"] for note in data["notes"]}
            raised |= {finding["code"] for item in data["items"] for finding in item["findings"]}
    assert len(raised) > 60  # the samples exercise most of the reference
    assert not sorted(raised - documented), sorted(raised - documented)


def test_version_is_the_same_everywhere_a_release_reads_it() -> None:
    """The release workflow takes the version from __init__.py and its text from the development log."""
    import fwshift

    root = Path(__file__).resolve().parents[1]
    version = fwshift.__version__
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    # The line as the workflow reads it (sed: ^__version__ = "(.*)"$).
    lines = (root / "src" / "fwshift" / "__init__.py").read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if re.fullmatch(r'__version__ = ".*"', line)] == [f'__version__ = "{version}"']
    log = (root / "DEVELOPMENT.md").read_text(encoding="utf-8")
    assert f"| Version | {version} (alpha) |" in log
    entry = [part for part in log.split("\n### ") if part.splitlines()[0].endswith(f": version {version}")]
    assert len(entry) == 1, "the development log needs one entry for this version"
    built = entry[0].split("**Built**", 1)[1].split("\n**", 1)[0]
    assert built.strip().startswith("* "), "what is listed under **Built** is the text of the release"
    short = version.rsplit(".", 1)[0]
    assert f"This manual covers version {short}." in (root / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    assert f"**Status: alpha ({short}).**" in (root / "README.md").read_text(encoding="utf-8")
    # The guide, and every file name of the single-file package the documents give, say this version too.
    guide = (root / "docs" / "guide.html").read_text(encoding="utf-8")
    assert f"Field guide · version {short}" in guide
    for name in ("README.md", "docs/MANUAL.md", "docs/guide.html"):
        named = set(re.findall(r"fwshift-([0-9]+\.[0-9]+\.[0-9]+)\.pyz", (root / name).read_text(encoding="utf-8")))
        assert named <= {version}, (name, named)
    workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "src/fwshift/__init__.py" in workflow and 's/^__version__ = "\\(.*\\)"$/\\1/p' in workflow
