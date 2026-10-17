# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Results as SARIF, CSV and HTML (0.36.0): what each format must hold, checked on the samples.

SARIF is checked against the parts of the SARIF 2.1.0 specification FWShift writes (and what code scanning reads):
the version, a tool with its rules, results whose rule is one of them, levels of the specification, a location with a
line, artifacts with their SHA-256, fingerprints that stay the same between runs, suppressions for accepted findings.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List

import pytest

from fwshift import __version__, cli, export
from fwshift.errors import FwshiftError

DATA = Path(__file__).parent / "data"
PANOS = DATA / "panos_sample.xml"
FORTIOS = DATA / "fortios_sample.conf"


def run(args: List[str], tmp_path: Path, name: str = "out") -> str:
    out = tmp_path / name
    code = cli.main(args + ["-o", str(out)])
    assert code in (0, 3), code
    return out.read_text(encoding="utf-8")


def check_sarif(document: Dict[str, Any]) -> None:
    """The parts of SARIF 2.1.0 that FWShift writes, as the specification requires them."""
    assert document["version"] == "2.1.0" and document["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(document["runs"], list) and document["runs"]
    for run_ in document["runs"]:
        driver = run_["tool"]["driver"]
        assert driver["name"] == "FWShift" and driver["version"] == __version__
        ids = [rule["id"] for rule in driver["rules"]]
        assert len(ids) == len(set(ids)) and all(isinstance(i, str) and 0 < len(i) <= 255 for i in ids)
        for rule in driver["rules"]:
            assert rule["shortDescription"]["text"] and rule["helpUri"].startswith("https://")
        artifacts = run_.get("artifacts", [])
        assert len({json.dumps(a, sort_keys=True) for a in artifacts}) == len(artifacts)  # (uniqueItems)
        for artifact in artifacts:
            assert (artifact.get("location", {}).get("uri") or artifact.get("description")) and re.fullmatch(r"[0-9a-f]{64}", artifact["hashes"]["sha-256"])
        assert re.fullmatch(r"fwshift/[a-z]+/[A-Za-z0-9._/-]*/", run_["automationDetails"]["id"])
        for result in run_["results"]:
            assert result["ruleId"] in ids and ids[result["ruleIndex"]] == result["ruleId"]
            assert result["level"] in ("none", "note", "warning", "error")
            assert isinstance(result["message"]["text"], str) and result["message"]["text"]
            prints = result["partialFingerprints"]
            assert re.fullmatch(r"[0-9a-f]{64}", prints["fwshiftFinding/v1"]) and re.fullmatch(r"[0-9a-f]{16}:1", prints["primaryLocationLineHash"])
            for location in result.get("locations", []):
                physical = location.get("physicalLocation")
                if physical:
                    assert physical["artifactLocation"]["index"] < len(artifacts)
                    assert physical["artifactLocation"]["uri"] == artifacts[physical["artifactLocation"]["index"]]["location"]["uri"]
                    assert " " not in physical["artifactLocation"]["uri"] and "#" not in physical["artifactLocation"]["uri"]
                    if "region" in physical:
                        assert isinstance(physical["region"]["startLine"], int) and physical["region"]["startLine"] >= 1
                for logical in location.get("logicalLocations", []):
                    assert logical["name"] and logical["kind"]
            for suppression in result.get("suppressions", []):
                assert suppression["kind"] in ("inSource", "external") and suppression["justification"]


def test_audit_as_sarif_holds_every_finding_with_its_place(tmp_path: Path) -> None:
    findings = json.loads(run(["audit", str(PANOS), "--json"], tmp_path))["findings"]
    document = json.loads(run(["audit", str(PANOS), "--format", "sarif"], tmp_path))
    check_sarif(document)
    results = document["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [f["check"] for f in findings]
    assert document["runs"][0]["artifacts"][0]["hashes"]["sha-256"] == hashlib.sha256(PANOS.read_bytes()).hexdigest()
    lines = PANOS.read_text(encoding="utf-8").splitlines()
    assert document["runs"][0]["automationDetails"]["id"].endswith("tests/data/panos_sample.xml/")
    first = next(r for r in results if r["locations"][0]["logicalLocations"][0]["name"] == "Allow-Web-Out")
    assert "Allow-Web-Out" in lines[first["locations"][0]["physicalLocation"]["region"]["startLine"] - 1]


def test_fingerprints_stay_the_same_between_runs_and_tell_findings_apart(tmp_path: Path) -> None:
    one = json.loads(run(["audit", str(PANOS), "--format", "sarif"], tmp_path, "a"))
    two = json.loads(run(["audit", str(PANOS), "--format", "sarif"], tmp_path, "b"))
    prints = [r["partialFingerprints"]["fwshiftFinding/v1"] for r in one["runs"][0]["results"]]
    assert prints == [r["partialFingerprints"]["fwshiftFinding/v1"] for r in two["runs"][0]["results"]]
    assert len(set(prints)) == len(prints)


def test_an_accepted_finding_is_suppressed_not_left_out(tmp_path: Path) -> None:
    document = json.loads(run(["audit", str(PANOS), "--format", "sarif", "--audit-accept", "Allow-Web-Out=ANY_DESTINATION"], tmp_path))
    check_sarif(document)
    accepted = [r for r in document["runs"][0]["results"] if r.get("suppressions")]
    assert [r["ruleId"] for r in accepted] == ["ANY_DESTINATION"]


def test_convert_writes_the_report_and_its_audit_as_two_runs(tmp_path: Path) -> None:
    sarif, html_file, csv_file, report = (tmp_path / name for name in ("r.sarif", "r.html", "r.csv", "r.json"))
    assert cli.main(["convert", str(PANOS), "--to", "fortios", "-o", str(tmp_path / "out"), "-q", "--audit", "--report-json", str(report),
                     "--report-sarif", str(sarif), "--report-html", str(html_file), "--report-csv", str(csv_file)]) == 0  # fmt: skip
    document = json.loads(sarif.read_text(encoding="utf-8"))
    check_sarif(document)
    data = json.loads(report.read_text(encoding="utf-8"))
    count = len(data["notes"]) + sum(len(item["findings"]) for item in data["items"])
    assert len(document["runs"]) == 2 and len(document["runs"][0]["results"]) == count
    rows = list(csv.reader(io.StringIO(csv_file.read_text(encoding="utf-8"))))
    audited = data["audit"]["findings"] + data["audit"]["after_conversion"]["new"] + data["audit"]["after_conversion"]["gone"]
    assert rows[0][:7] == ["section", "severity", "code", "kind", "name", "status", "message"] and len(rows) == count + len(audited) + 1
    assert any("EXPOSED_BY_CONVERSION" in row for row in rows)  # (the audit after the conversion)
    assert len(document["runs"][1]["results"]) == len(audited)
    assert "EXPOSED_BY_CONVERSION" in sarif.read_text(encoding="utf-8")
    text = html_file.read_text(encoding="utf-8")
    assert "Conversion findings" in text and "Audit findings" in text and hashlib.sha256(PANOS.read_bytes()).hexdigest() in text
    assert "EXPOSED_BY_CONVERSION" in text and "after conversion: new" in text


def test_conduits_and_compare_as_sarif(tmp_path: Path) -> None:
    conduits = json.loads(run(["conduits", str(PANOS), "--model", str(DATA / "zone_model.json"), "--format", "sarif", "--fail-on", "none"], tmp_path))
    check_sarif(conduits)
    assert len(conduits["runs"][0]["artifacts"]) == 2  # (the policy and the model)
    data = json.loads(run(["compare", str(PANOS), str(FORTIOS), "--json", "--fail-on", "none"], tmp_path, "c.json"))
    compared = json.loads(run(["compare", str(PANOS), str(FORTIOS), "--format", "sarif", "--fail-on", "none"], tmp_path, "c.sarif"))
    check_sarif(compared)
    results = compared["runs"][0]["results"]
    assert len(results) == len(data["differences"])
    levels = {(d["change"], d["certain"]): r["level"] for d, r in zip(data["differences"], results)}
    assert levels.get(("opened", True), "error") == "error" and levels.get(("closed", False), "note") == "note"


def test_the_matrix_is_no_sarif_but_csv_and_html(tmp_path: Path) -> None:
    with pytest.raises(FwshiftError, match="holds no findings"):
        export.render("matrix", {"conduits": []}, "sarif")
    assert cli.main(["matrix", str(PANOS), "--format", "csv", "-o", str(tmp_path / "m.csv")]) == 0
    assert (tmp_path / "m.csv").read_text(encoding="utf-8") == run(["matrix", str(PANOS), "--csv"], tmp_path, "old.csv")
    page = run(["matrix", str(PANOS), "--format", "html"], tmp_path, "m.html")
    assert re.search(r"Cells \((\d+)\)", page) and "trust" in page


def test_json_stays_what_it_was_and_two_formats_are_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["audit", str(PANOS), "--json"], tmp_path, "a") == run(["audit", str(PANOS), "--format", "json"], tmp_path, "b")
    assert cli.main(["audit", str(PANOS), "--json", "--format", "csv"]) != 0
    assert "say different things" in capsys.readouterr().err


def test_csv_cells_are_no_formulas_and_html_escapes_everything() -> None:
    row = export.Row("X", "error", "=1+1", "=HYPERLINK(\"http://example.invalid\")", "rule",
                     {"name": "=HYPERLINK(\"http://example.invalid\")", "message": "-2+3", "plain": "ok", "at": "@SUM(A1)"})  # fmt: skip
    rows = list(csv.reader(io.StringIO(export._csv(("name", "message", "plain", "at"), [row]))))
    assert rows[1] == ["'=HYPERLINK(\"http://example.invalid\")", "'-2+3", "ok", "'@SUM(A1)"]
    assert export.formula_safe("  =1+1") == "'  =1+1" and export.formula_safe("\uff1d1+1") == "'\uff1d1+1"
    assert export.formula_safe("Rule  A") == "Rule  A" and export.formula_safe("a=b") == "a=b"
    data = {"source": "<script>alert(1)</script>", "findings": [{"check": "C", "level": "high", "kind": "rule",
            "name": "<img src=x onerror=alert(1)>", "message": "a & b \"c\"", "action": "report"}], "summary": {"high": 1}}  # fmt: skip
    page = export.render("audit", data, "html", [export.Source("in<put>.xml", b"x")])

    class Collect(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.tags: List[str] = []

        def handle_starttag(self, tag: str, attrs: Any) -> None:
            self.tags.append(tag)

    parser = Collect()
    parser.feed(page)
    assert "script" not in parser.tags and "img" not in parser.tags
    assert "&lt;img src=x onerror=alert(1)&gt;" in page and "Signature" in page and "in&lt;put&gt;.xml" in page


def test_sarif_of_a_policy_without_findings_and_without_a_file() -> None:
    assert export.render("audit", {"findings": []}, "csv").startswith("phase,level,check,kind,name,message")
    document = json.loads(export.render("audit", {"findings": [], "summary": {}}, "sarif"))
    check_sarif(document)
    assert document["runs"][0]["results"] == [] and "artifacts" not in document["runs"][0]
    document = json.loads(export.render("audit", {"findings": [{"check": "C", "level": "low", "kind": "rule", "name": "r",
                                                                "message": "m", "action": "report"}]}, "sarif"))  # fmt: skip
    check_sarif(document)
    assert document["runs"][0]["results"][0]["locations"] == [{"logicalLocations": [{"name": "r", "kind": "rule"}]}]


def test_uris_are_uri_references_and_standard_input_is_no_file() -> None:
    assert export.Source("my fw#1 %20.xml").uri() == "my%20fw%231%20%2520.xml"
    assert export.Source("C:\\fw dir\\a#1.xml").uri() == "file:///C:/fw%20dir/a%231.xml"
    assert export.Source("/srv/fw/a b.xml").uri() == "file:///srv/fw/a%20b.xml"
    assert export.Source("conf/fw.xml").uri() == "conf/fw.xml"
    data = {"findings": [{"check": "C", "level": "low", "kind": "rule", "name": "r", "message": "m", "action": "report"}]}
    document = json.loads(export.render("audit", data, "sarif", [export.Source("-", b"x")]))
    check_sarif(document)
    run_ = document["runs"][0]
    assert run_["artifacts"] == [{"description": {"text": "standard input"}, "hashes": {"sha-256": hashlib.sha256(b"x").hexdigest()}}]
    assert "physicalLocation" not in run_["results"][0]["locations"][0]


def test_fingerprints_do_not_follow_the_wording_and_a_line_is_given_only_where_known() -> None:
    one = {"findings": [{"check": "NO_USAGE_EVIDENCE", "level": "info", "kind": "rule", "name": "r", "message": "since 41 day(s)", "action": "report"}]}
    two = {"findings": [{"check": "NO_USAGE_EVIDENCE", "level": "info", "kind": "rule", "name": "r", "message": "since 42 day(s)", "action": "report"}]}
    source = export.Source("p.conf", b"edit 1\n  set name \"other\"\n")
    a = json.loads(export.render("audit", one, "sarif", [source]))["runs"][0]["results"][0]
    b = json.loads(export.render("audit", two, "sarif", [source]))["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"] and "region" not in a["locations"][0]["physicalLocation"]
    named = export.Source("p.conf", b'edit 1\n  set name "r"\n')
    c = json.loads(export.render("audit", one, "sarif", [named]))["runs"][0]["results"][0]
    assert c["locations"][0]["physicalLocation"]["region"] == {"startLine": 2}
    escaped = export.Source("p.xml", b'<a>\n<entry name="a &amp; b"/>\n')
    assert escaped.line_of("a & b") == 2


def test_the_same_file_twice_is_one_artifact_and_a_closed_conduit_is_in_the_model(tmp_path: Path) -> None:
    compared = json.loads(run(["compare", str(PANOS), str(PANOS), "--format", "sarif", "--fail-on", "none"], tmp_path, "s"))
    check_sarif(compared)
    assert len(compared["runs"][0]["artifacts"]) == 1
    data = {"findings": [{"check": "CONDUIT_CLOSED", "level": "low", "from": "a", "to": "b", "rule": "historian", "message": "m"}]}
    sources = [export.Source("p.xml", b"<x/>"), export.Source("model.json", b'{\n "name": "historian"\n}')]
    result = json.loads(export.render("conduits", data, "sarif", sources))["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["index"] == 1
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 2}
    assert result["locations"][0]["logicalLocations"][0]["kind"] == "conduit"


def test_html_shows_what_was_not_checked_and_the_accepted_apart(tmp_path: Path) -> None:
    page = run(["conduits", str(PANOS), "--model", str(DATA / "zone_model.json"), "--format", "html", "--fail-on", "none"], tmp_path)
    assert "Not checked, or read in part" in page and "Inside these zones: not checked" in page and "Conduits of the model" in page
    page = run(["audit", str(PANOS), "--format", "html", "--audit-accept", "Allow-Web-Out=ANY_DESTINATION"], tmp_path, "a.html")
    assert "<h2>Accepted (1)</h2>" in page and 'class="accepted"' in page


def test_a_model_from_standard_input_keeps_its_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    model = (DATA / "zone_model.json").read_bytes()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(model)))
    page = run(["conduits", str(PANOS), "--model", "-", "--format", "html", "--fail-on", "none"], tmp_path)
    assert hashlib.sha256(model).hexdigest() in page


def test_a_run_github_would_refuse_is_said(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(export, "SARIF_RESULT_LIMIT", 1)
    data = {"findings": [{"check": "C", "level": "low", "kind": "rule", "name": n, "message": "m", "action": "report"} for n in "ab"]}
    warnings: List[str] = []
    export.render("audit", data, "sarif", [], warnings)
    assert warnings and "refuses" in warnings[0]


def test_the_matrix_csv_guards_formulas_after_spaces() -> None:
    from fwshift.matrix import _plain

    assert _plain(" =1+1") == "' =1+1"


def test_a_number_among_the_ids_does_not_give_the_line_and_a_kept_line_does(tmp_path: Path) -> None:
    document = json.loads(run(["audit", str(FORTIOS), "--format", "sarif"], tmp_path))
    lines = FORTIOS.read_text(encoding="utf-8").splitlines()
    for result in document["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"].get("region")
        name = result["locations"][0].get("logicalLocations", [{}])[0].get("name", "")
        if region and result["properties"].get("kind") == "rule":
            line = lines[region["startLine"] - 1]
            ids = [part.split("=", 1)[1] for part in result["properties"].get("source_ids", "").split("; ") if "=" in part]
            assert name in line or any(len(i) >= 8 and i in line for i in ids), (name, line)  # (the name, or the policy's uuid)
    ios = json.loads(run(["audit", str(DATA / "ios_sample.cfg"), "--format", "sarif"], tmp_path, "ios"))
    ios_lines = (DATA / "ios_sample.cfg").read_text(encoding="utf-8").splitlines()
    placed = [r for r in ios["runs"][0]["results"] if r["locations"][0]["physicalLocation"].get("region")]
    assert placed and all(ios_lines[r["locations"][0]["physicalLocation"]["region"]["startLine"] - 1].strip() for r in placed)


def test_fingerprints_survive_a_line_added_above_and_are_the_same_in_a_conversion(tmp_path: Path) -> None:
    moved = tmp_path / "ios_moved.cfg"
    moved.write_text("!\n!\n" + (DATA / "ios_sample.cfg").read_text(encoding="utf-8"), encoding="utf-8")

    def prints(path: Path, name: str) -> List[str]:
        return [r["partialFingerprints"]["fwshiftFinding/v1"] for r in json.loads(run(["audit", str(path), "--format", "sarif"], tmp_path, name))["runs"][0]["results"]]

    assert prints(DATA / "ios_sample.cfg", "a") == prints(moved, "b")
    sarif = tmp_path / "c.sarif"
    assert cli.main(["convert", str(PANOS), "--to", "fortios", "-o", str(tmp_path / "out"), "-q", "--audit", "--report-sarif", str(sarif)]) == 0
    in_conversion = {r["partialFingerprints"]["fwshiftFinding/v1"] for r in json.loads(sarif.read_text(encoding="utf-8"))["runs"][1]["results"]}
    alone = set(prints(PANOS, "d"))
    assert alone <= in_conversion


def test_categories_and_uris_of_absolute_paths(tmp_path: Path) -> None:
    inside = export.Source(str(Path.cwd() / "conf" / "fw a.xml"))
    assert inside.category() == "conf/fw%20a.xml"
    assert export.Source("/elsewhere/../srv/x.xml").uri() == "file:///srv/x.xml"
    assert export.Source("dir\\\\sub\\\\f.xml").category() == export.Source("dir/sub/f.xml").category() == "dir/sub/f.xml"
    assert export.Source("-").category() == "standard-input"


def test_csv_columns_stay_the_same_whatever_the_findings(tmp_path: Path) -> None:
    plain = run(["audit", str(PANOS), "--format", "csv"], tmp_path, "a").splitlines()[0]
    accepted = run(["audit", str(PANOS), "--format", "csv", "--audit-accept", "Allow-DNS"], tmp_path, "b").splitlines()[0]
    assert plain == accepted == ",".join(export._COLUMNS["audit"])
    run(["matrix", str(PANOS), "--format", "csv"], tmp_path, "m")
    assert (tmp_path / "m").read_bytes().count(b"\r\n") > 1  # (CRLF, as RFC 4180)
