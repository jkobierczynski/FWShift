# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from typing import Callable, Dict, List, Optional, Sequence, TextIO

from . import __version__, transform
from .appmap import load_app_map
from .emitters import fortios as emit_fortios
from .emitters import panos as emit_panos
from .errors import FwshiftError
from .model import Policy
from .options import Options
from .parsers import fortios as parse_fortios
from .parsers import panos as parse_panos
from .report import Report, Severity

EMITTERS: Dict[str, Callable[[Policy, Report, Options], str]] = {
    "panos": emit_panos.emit,
    "fortios": emit_fortios.emit,
}
VENDORS = ("panos", "fortios")


def detect_format(data: bytes) -> str:
    """PAN-OS exports are XML; FortiOS backups are CLI text."""
    return "panos" if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<") else "fortios"


def load(data: bytes, source: str, report: Report, vsys: str = "", device_group: str = "", vdom: str = "") -> Policy:
    if source == "panos":
        return parse_panos.parse(data, report, vsys=vsys, device_group=device_group)
    if source == "fortios":
        return parse_fortios.parse(data, report, vdom=vdom)
    raise FwshiftError(f"unknown source format '{source}'")


def convert(policy: Policy, target: str, report: Report, options: Optional[Options] = None) -> str:
    """Convert a parsed policy; the report is filled in as a side effect."""
    report.target = target
    if target == "json":
        return policy.to_json()
    report.register("service-group", list(policy.service_groups))
    report.register("service", list(policy.services))
    report.register("address-group", list(policy.address_groups))
    report.register("address", list(policy.addresses))
    report.register("nat", [nat.origin for nat in policy.nat_rules])
    report.register("rule", [rule.origin for rule in policy.rules])
    if target not in EMITTERS:
        raise FwshiftError(f"unknown target format '{target}'")
    return EMITTERS[target](policy, report, options or Options())


def _pairs(values: Sequence[str], option: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for value in values:
        key, sep, new = value.partition("=")
        if not sep or not key or not new:
            raise FwshiftError(f"{option} expects SOURCE=TARGET, got '{value}'")
        out[key] = new
    return out


def _read(path: str) -> bytes:
    try:
        if path == "-":
            return sys.stdin.buffer.read()
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise FwshiftError(f"cannot read {path}: {exc.strerror}") from None


def _write(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError as exc:
        raise FwshiftError(f"cannot write {path}: {exc.strerror}") from None


def _print(stream: TextIO, text: str) -> None:
    """Write UTF-8 whatever the console encoding is (a redirected Windows console is not UTF-8)."""
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        stream.write(text)
        return
    stream.flush()
    buffer.write(text.encode("utf-8"))
    buffer.flush()


def _source_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="configuration file to read, or - for standard input")
    parser.add_argument("--from", dest="source", choices=VENDORS, help="source format (default: detected)")
    parser.add_argument("--vsys", default="", help="PAN-OS source: virtual system to read")
    parser.add_argument("--device-group", default="", help="Panorama source: device group to read")
    parser.add_argument("--vdom", default="", help="FortiOS source: VDOM to read")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwshift", description="Convert firewall policies between PAN-OS and FortiOS, with a lossiness report."
    )
    parser.add_argument("--version", action="version", version=f"fwshift {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    conv = commands.add_parser("convert", help="convert a configuration to another vendor's format")
    _source_options(conv)
    conv.add_argument("--to", dest="target", required=True, choices=VENDORS + ("json",), help="target format")
    conv.add_argument("-o", "--output", help="write the converted configuration here (default: standard output)")
    conv.add_argument("--report", help="write the text report here (default: standard error)")
    conv.add_argument("--report-json", help="also write the report as JSON")
    conv.add_argument("--zone-map", action="append", default=[], metavar="SRC=DST", help="rename a zone or interface")
    conv.add_argument(
        "--interface-map", action="append", default=[], metavar="SRC=DST", help="map a source interface to a target one"
    )
    conv.add_argument("--app-map", metavar="FILE", help="JSON file: application name -> list of port specs")
    conv.add_argument("--prune-unused", action="store_true", help="leave out objects no rule uses")
    target = conv.add_mutually_exclusive_group()
    target.add_argument("--target-vsys", metavar="NAME", help="PAN-OS target: write into this virtual system")
    target.add_argument("--target-device-group", metavar="NAME", help="Panorama target: write into this device group")
    target.add_argument("--target-shared", action="store_true", help="Panorama target: write into shared")
    conv.add_argument("--target-vdom", default="", metavar="NAME", help="FortiOS target: write into this VDOM")
    conv.add_argument(
        "--policy-id-start", type=int, default=0, metavar="N", help="FortiOS target: first policy id (default: automatic)"
    )
    conv.add_argument("--strict", action="store_true", help="exit with status 2 when anything needs review")
    conv.add_argument("-q", "--quiet", action="store_true", help="do not print the report or the summary")

    insp = commands.add_parser("inspect", help="show what was read from a configuration")
    _source_options(insp)
    return parser


def _run_convert(args: argparse.Namespace) -> int:
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom)
    report.source = source + (f" ({policy.scope})" if policy.scope else "")
    if args.prune_unused:
        dropped = transform.prune_unused(policy)
        report.note(Severity.INFO, "PRUNED", f"{dropped} objects not used by any rule were left out")
    scope = ""
    if args.target_vsys:
        scope = f"vsys:{args.target_vsys}"
    elif args.target_device_group:
        scope = f"device-group:{args.target_device_group}"
    elif args.target_shared:
        scope = "shared"
    options = Options(
        zone_map=_pairs(args.zone_map, "--zone-map"),
        interface_map=_pairs(args.interface_map, "--interface-map"),
        app_ports=load_app_map(args.app_map) if args.app_map else {},
        target_scope=scope,
        target_vdom=args.target_vdom,
        policy_id_start=max(args.policy_id_start, 0),
    )
    output = convert(policy, args.target, report, options)
    if args.output:
        _write(args.output, output)
    else:
        _print(sys.stdout, output)
    if args.report:
        _write(args.report, report.to_text())
    elif not args.quiet and args.target != "json":
        _print(sys.stderr, report.to_text())
    if args.report_json:
        _write(args.report_json, report.to_json())
    if args.report and not args.quiet:
        rules = report.counts("rule")
        _print(
            sys.stderr,
            f"fwshift: {rules['total']} rules: {rules['exact']} exact, {rules['approximated']} approximated, "
            f"{rules['needs-review']} need review, {rules['skipped']} skipped. Report: {args.report}\n",
        )
    return 2 if args.strict and report.needs_review else 0


def _run_inspect(args: argparse.Namespace) -> int:
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom)
    lines: List[str] = [
        f"format:          {source}",
        f"scope:           {policy.scope or '-'}",
        f"addresses:       {len(policy.addresses)}",
        f"address groups:  {len(policy.address_groups)}",
        f"services:        {len(policy.services)}",
        f"service groups:  {len(policy.service_groups)}",
        f"zones:           {', '.join(policy.zones) or '-'}",
        f"security rules:  {len(policy.rules)} ({sum(1 for r in policy.rules if not r.enabled)} disabled)",
        f"NAT rules:       {len(policy.nat_rules)}",
    ]
    findings = [(item, f) for item in report.items.values() for f in item.findings]
    if findings or report.notes:
        lines += ["", "findings while reading:"]
        lines += [f"  {note.code}: {note.message}" for note in report.notes]
        lines += [f"  {item.kind} {item.name}: {finding.code}: {finding.message}" for item, finding in findings]
    _print(sys.stdout, "\n".join(lines) + "\n")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "convert":
            return _run_convert(args)
        return _run_inspect(args)
    except FwshiftError as exc:
        _print(sys.stderr, f"fwshift: error: {exc}\n")
        return 1
