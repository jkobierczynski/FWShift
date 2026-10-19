# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The read-back of a lab run (0.38.0): the policy as the firewall holds it after the probes, exported from it, read by
FWShift and compared, with `fwshift compare`, with what was loaded (the converted output) and with the source.

* **Against the output**: whether the firewall holds what FWShift wrote: nothing refused without a word, nothing
  changed on the way, nothing of the image's own in the way. Counted in the lab's zones only (the networks of the plan):
  what an image has for its management interface lies outside them. Where FWShift cannot read its own output (a
  Check Point script, the CLI commands of a SonicWall, the clouds' CLI calls), this part is left out.
* **Against the source**: the differences the conversion report announced, now as the firewall decides them.

The read-back does not change the run's result: its line in the summary says what it found (readback.txt has the
comparisons, export.* the export)."""

import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import labplan
import labrun
from labrun import LabError, Runner

# FWShift's own output it reads back (convert --compare), by target. Not RouterOS: its script holds the jumps to its
# chains disabled, which the lab switches on after the import. pfSense and OPNsense output holds areas, not a whole
# configuration; IOS output its interfaces' zones only as comments.
OUTPUT_FORMAT = {"fortios": "fortios", "panos": "panos", "junos": "junos", "asa": "asa", "nftables": "nftables", "iptables": "iptables"}


def _plain(text: str) -> str:
    return labrun.screen_text(text).replace("\r", "")


def between(first: str, last: str, keep_last: bool = True) -> Callable[[str], str]:
    """What a session wrote from the first line that matches `first` to the last that matches `last`."""

    def cut(text: str) -> str:
        lines = _plain(text).splitlines()
        start = next((i for i, line in enumerate(lines) if re.search(first, line)), None)
        ends = [i for i, line in enumerate(lines) if re.search(last, line)]
        if start is None or not ends or ends[-1] < start:
            return ""
        return "\n".join(lines[start:ends[-1] + (1 if keep_last else 0)]) + "\n"

    return cut


def only(pattern: str) -> Callable[[str], str]:
    """The lines of a session that match a pattern (Junos `display set`: the set commands)."""
    return lambda text: "".join(line + "\n" for line in _plain(text).splitlines() if re.match(pattern, line))


_FORTI_PROMPT = re.compile(r"^\S+ (\(\S+\) )?[#$] ")


def fortios_sections(text: str) -> str:
    """The `config ... end` blocks of a FortiOS session; the prompts and the echoed commands left out."""
    out, depth = [], 0
    for line in _plain(text).splitlines():
        if _FORTI_PROMPT.match(line):
            continue
        stripped = line.strip()
        if stripped.startswith("config "):
            depth += 1
        if depth:
            out.append(line)
        if stripped == "end" and depth:
            depth -= 1
    return "\n".join(out) + "\n"


def json_array(text: str) -> str:
    """The JSON documents a shell printed one after another, as one array (Check Point's answers)."""
    decoder, found, index = json.JSONDecoder(), [], 0
    plain = text.replace("\r", "")
    while True:
        start = plain.find("{", index)
        if start < 0:
            break
        try:
            value, end = decoder.raw_decode(plain, start)
        except ValueError:
            index = start + 1
            continue
        found.append(value)
        index = end
    return json.dumps(found, indent=1) + "\n" if found else ""


@dataclass(frozen=True)
class Export:
    """How to export a firewall's policy: the lines typed into its CLI (or run as commands, or in a shell), what of the
    answer is the configuration, and the format FWShift reads it as."""

    fmt: str
    lines: Tuple[str, ...]
    extract: Callable[[str], str] = _plain
    suffix: str = "txt"
    options: Tuple[str, ...] = field(default_factory=tuple)  # (for the comparison: --vsys, --layer ...)


NOT_READ = {
    "sonicwall": "SonicOS exports its settings from the web console only (the file FWShift reads); its CLI's own listing is not that file",
}


def networks(zone_map: Dict[str, str]) -> List[str]:
    """--zone-network for the lab's zones, named as the target names them."""
    return [w for zone, net in labplan.ZONES.items() for w in ("--zone-network", f"{zone_map.get(zone, zone)}={net}")]


def zone_map_of(options: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for flag, value in zip(options, list(options)[1:]):
        if flag == "--zone-map" and "=" in value:
            zone, _, name = value.partition("=")
            out[zone] = name
    return out


def compare(runner: Runner, first: Path, first_fmt: str, second: Path, second_fmt: str, options: Sequence[str],
            name: str) -> Dict[str, Any]:  # fmt: skip
    """fwshift compare, as JSON (the text beside it)."""
    base = [sys.executable, "-m", "fwshift", "compare", str(first), str(second), "--from", first_fmt, "--from-second", second_fmt,
            "--fail-on", "none", *options]  # fmt: skip
    env = {**os.environ, "PYTHONPATH": str(labrun.REPO / "src")}
    shown = "fwshift " + " ".join(shlex.quote(a) for a in base[3:])
    print("$ " + shown, file=sys.stderr)
    runner.log.append(shown)
    text = subprocess.run(base, env=env, text=True, capture_output=True)
    done = subprocess.run(base + ["--json"], env=env, text=True, capture_output=True)
    (runner.work / f"{name}.txt").write_text(text.stdout + text.stderr, encoding="utf-8")
    if done.returncode not in (0, 3):
        return {"error": (done.stderr.strip() or done.stdout.strip())[-400:]}
    result: Dict[str, Any] = json.loads(done.stdout)
    return result


def in_lab(result: Dict[str, Any], zones: Sequence[str]) -> List[Dict[str, Any]]:
    """The differences between two of the lab's zones, and not inside one (those flows do not pass the firewall in
    tiers 2 and 3)."""
    return [d for d in result.get("differences", []) if d.get("from") in zones and d.get("to") in zones and d.get("from") != d.get("to")]


def _plain_name(text: str) -> str:
    return "".join(letter for letter in text.lower() if letter.isalnum())


def zones_read(text: str, fmt: str) -> Optional[List[str]]:
    """The zones FWShift reads from an export (None: it reads no rule from it)."""
    sys.path.insert(0, str(labrun.REPO / "src"))
    from fwshift import cli
    from fwshift.report import Report

    policy = cli.load(text.encode("utf-8"), fmt, Report())
    if not policy.rules:
        return None
    return list(dict.fromkeys(list(policy.zones) + [z for rule in policy.rules for z in rule.src_zones + rule.dst_zones if z != "any"]))


def descriptions(text: str, fmt: str) -> Dict[str, str]:
    """pfSense and OPNsense: an interface's key (opt1, wan) -> its description, which names the zone FWShift reads."""
    if fmt not in ("pfsense", "opnsense"):
        return {}
    import xml.etree.ElementTree as ET

    try:
        interfaces = ET.fromstring(text).find("interfaces")
    except ET.ParseError:
        return {}
    return {i.tag: (i.findtext("descr") or i.tag).strip() for i in (interfaces if interfaces is not None else [])}


def aligned(zone_map: Dict[str, str], names: Sequence[str]) -> Dict[str, str]:
    """The lab's zones as the export names them: the names the conversion gave them, or their own, as FWShift reads
    them there (pfSense: the interface's description; FortiOS: the port, port2)."""
    by_plain = {_plain_name(name): name for name in names}
    out = {}
    for zone in labplan.ZONES:
        for candidate in (zone_map.get(zone, ""), zone):  # (the name the conversion gave it first: another zone may have its own)
            if candidate and _plain_name(candidate) in by_plain:
                if by_plain[_plain_name(candidate)] != zone:
                    out[zone] = by_plain[_plain_name(candidate)]
                break
    return out


def check(runner: Runner, target: str, out: Path, export_text: str, export: Export, conversion_options: Sequence[str],
          intrazone: bool = False) -> Dict[str, Any]:  # fmt: skip
    """Reads the export and compares it; writes readback.txt and returns what the summary says of it."""
    if not export_text.strip():
        return finish(runner, {"status": "not read", "why": "the firewall's answer held no configuration (export.txt)"})
    path = runner.work / f"export.{export.suffix}"
    path.write_text(export_text, encoding="utf-8")
    try:
        names = zones_read(export_text, export.fmt)
    except Exception as error:  # (whatever FWShift says of the export: the read-back's line, not the run's end)
        return finish(runner, {"status": "not read", "why": f"FWShift could not read the export: {str(error)[:300]}"})
    if names is None:
        return finish(runner, {"status": "not read", "why": f"FWShift read no rule from the export ({path.name})"})
    zone_map = {zone: descriptions(export_text, export.fmt).get(name, name) for zone, name in zone_map_of(conversion_options).items()}
    lab_zones = [zone_map.get(z, z) for z in labplan.ZONES]
    found: Dict[str, Any] = {"status": "read", "format": export.fmt, "export": path.name}
    parts = []
    if target in OUTPUT_FORMAT:
        result = compare(runner, out, OUTPUT_FORMAT[target], path, export.fmt, [*networks(zone_map), *export.options], "readback-output")
        if "error" in result:
            found.update(status="not read", why=f"FWShift could not read the export: {result['error']}")
            return finish(runner, found)
        differences = result.get("differences", []) if intrazone else in_lab(result, lab_zones)
        found["against_output"] = _count(differences)
        parts.append(_section("against what was loaded (the converted output)", result, differences))
    source_options = [w for zone, name in aligned(zone_map, names).items() for w in ("--zone-map", f"{zone}={name}")]
    result = compare(runner, labplan.POLICY, "panos", path, export.fmt, [*source_options, *networks({}), *export.options], "readback-source")
    if "error" in result:
        found.update(status="not read", why=f"FWShift could not read the export: {result['error']}")
        return finish(runner, found)
    differences = result.get("differences", []) if intrazone else in_lab(result, list(labplan.ZONES))
    found["against_source"] = _count(differences)
    parts.append(_section("against the source (what the conversion report announced shows here)", result, differences))
    (runner.work / "readback.txt").write_text("\n".join(parts), encoding="utf-8")
    return finish(runner, found)


def _count(differences: List[Dict[str, Any]]) -> Dict[str, int]:
    """Certain differences (whatever the policies cannot read) and possible ones (they may differ: something one of them
    holds is not read exactly)."""
    certain = sum(1 for d in differences if d.get("certain"))
    return {"certain": certain, "possible": len(differences) - certain}


def _section(title: str, result: Dict[str, Any], differences: List[Dict[str, Any]]) -> str:
    count = _count(differences)
    lines = [f"== {title}: {count['certain']} certain and {count['possible']} possible differences between the lab's zones"]
    for d in differences:
        lines.append(f"  {d.get('from')} -> {d.get('to')}: {d.get('change')}, {'certain' if d.get('certain') else 'possible'}; "
                     f"{d.get('first_policy', '')} / {d.get('second_policy', '')}")  # fmt: skip
        for connection in d.get("connections", [])[:4]:
            lines.append(f"    {', '.join(connection.get('sources', []))} -> {', '.join(connection.get('destinations', []))}: "
                         f"{', '.join(connection.get('services', []))}")  # fmt: skip
    lines += [f"  note: {n}" for n in result.get("notes", [])]
    return "\n".join(lines) + "\n"


def _n(count: int, what: str) -> str:
    return f"{count} {what}" + ("" if count == 1 else "s")


def line(found: Dict[str, Any]) -> str:
    """The read-back's line of the summary."""
    if found.get("status") != "read":
        return f"  read-back: not read ({found.get('why', '')})"
    def possible(count: Dict[str, int]) -> str:
        return f" ({count['possible']} possible)" if count.get("possible") else ""

    parts = []
    if "against_output" in found:
        n = found["against_output"]
        parts.append(("the firewall holds the policy as converted" if not n["certain"] else
                      f"{_n(n['certain'], 'certain difference')} from the converted policy") + possible(n))  # fmt: skip
    n = found.get("against_source", {"certain": 0, "possible": 0})
    parts.append(("decides as the source" if not n["certain"] else
                  f"{_n(n['certain'], 'certain difference')} from the source (announced in the report, or not)") + possible(n))  # fmt: skip
    return f"  read-back ({found.get('format')}): " + "; ".join(parts) + " (readback.txt)"


def finish(runner: Runner, found: Dict[str, Any]) -> Dict[str, Any]:
    """Adds the read-back to the run's summary (summary.json, summary.txt) and prints its line."""
    text = line(found)
    summary_json = runner.work / "summary.json"
    if summary_json.exists():
        summary = json.loads(summary_json.read_text(encoding="utf-8"))
        summary["readback"] = found
        labplan.save(summary_json, summary)
    summary_txt = runner.work / "summary.txt"
    if summary_txt.exists():
        lines = summary_txt.read_text(encoding="utf-8").splitlines()
        at = next((i for i, l in enumerate(lines) if l.startswith("  result: ")), len(lines))
        lines.insert(at, text)
        summary_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(text)
    return found


def not_read(runner: Runner, why: str) -> Dict[str, Any]:
    return finish(runner, {"status": "not read", "why": why})


def safely(runner: Runner, step: Callable[[], Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The read-back never fails the run: an error is its line in the summary."""
    try:
        return step()
    except (LabError, OSError, ValueError) as error:
        return not_read(runner, f"the export failed: {str(error)[:300]}")
