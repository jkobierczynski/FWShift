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
from .emitters import asa as emit_asa
from .emitters import checkpoint as emit_checkpoint
from .emitters import fortios as emit_fortios
from .emitters import iptables as emit_iptables
from .emitters import panos as emit_panos
from .errors import FwshiftError
from .model import ANY, Policy
from .netutil import parse_literal
from .options import Options
from .parsers import asa as parse_asa
from .parsers import checkpoint as parse_checkpoint
from .parsers import fortios as parse_fortios
from .parsers import iptables as parse_iptables
from .parsers import panos as parse_panos
from .report import Report, Severity

EMITTERS: Dict[str, Callable[[Policy, Report, Options], str]] = {
    "panos": emit_panos.emit,
    "fortios": emit_fortios.emit,
    "iptables": emit_iptables.emit,
    "ip6tables": emit_iptables.emit_v6,
    "checkpoint": emit_checkpoint.emit,
    "asa": emit_asa.emit,
}
VENDORS = ("panos", "fortios", "checkpoint", "asa", "iptables", "ip6tables")


def detect_format(data: bytes) -> str:
    """PAN-OS exports are XML, Check Point API output is JSON, iptables-save output starts with a table,
    an ASA configuration has lines only an ASA writes; anything else is taken as FortiOS."""
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"<"):
        return "panos"
    if head.startswith((b"{", b"[")):
        return "checkpoint"
    for line in head.splitlines()[:50]:
        line = line.strip()
        if line.startswith(b"*") or (line.startswith(b"#") and b"tables-save" in line):
            return "iptables"  # the parser tells IPv4 from IPv6
        if line and not line.startswith(b"#"):
            break
    if parse_asa.looks_like_asa(head[:1_000_000].decode("utf-8", errors="replace")):
        return "asa"
    return "fortios"


def load(
    data: bytes, source: str, report: Report, vsys: str = "", device_group: str = "", vdom: str = "", layer: str = ""
) -> Policy:
    if source == "panos":
        return parse_panos.parse(data, report, vsys=vsys, device_group=device_group)
    if source == "fortios":
        return parse_fortios.parse(data, report, vdom=vdom)
    if source == "checkpoint":
        return parse_checkpoint.parse(data, report, layer=layer)
    if source == "asa":
        return parse_asa.parse(data, report)
    if source in ("iptables", "ip6tables"):
        return parse_iptables.parse(data, report, family=6 if source == "ip6tables" else 0)
    raise FwshiftError(f"unknown source format '{source}'")


def convert(policy: Policy, target: str, report: Report, options: Optional[Options] = None) -> str:
    """Convert a parsed policy; the report is filled in as a side effect."""
    report.target = target
    options = options or Options()
    words = {"--zone-map": " ".join(list(options.zone_map) + list(options.zone_map.values())),
             "--interface-map": " ".join(list(options.interface_map) + list(options.interface_map.values())),
             "target scope": options.target_scope, "--target-vdom": options.target_vdom,
             "--target-nat-zone": options.nat_zone, "--target-layer": options.target_layer,
             "--target-package": options.target_package, "--target-gateway": options.target_gateway,
             "--target-prefix": options.object_prefix,
             "--zone-network": " ".join(options.zone_networks)}  # fmt: skip
    transform.check_words(words)
    if ANY in options.zone_map.values():
        raise FwshiftError("--zone-map: 'any' stands for every zone and cannot be the name of one")
    transform.harden(policy, report)
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
    return EMITTERS[target](policy, report, options)


def _pairs(values: Sequence[str], option: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for value in values:
        key, sep, new = value.partition("=")
        if not sep or not key or not new:
            raise FwshiftError(f"{option} expects SOURCE=TARGET, got '{value}'")
        out[key] = new
    return out


def _networks(values: Sequence[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for value in values:
        zone, sep, networks = value.partition("=")
        listed = [network.strip() for network in networks.split(",")]
        bad = [network for network in listed if parse_literal(network) is None]
        if not sep or not zone or bad:
            raise FwshiftError(f"--zone-network expects ZONE=NETWORK[,NETWORK...], got '{value[:60]}'")
        out.setdefault(zone, []).extend(listed)
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
    parser.add_argument("--layer", default="", help="Check Point source: access layer to read")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwshift",
        description="Convert firewall policies between PAN-OS, FortiOS, Check Point, Cisco ASA and iptables, with a lossiness report.",
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
    conv.add_argument(
        "--zone-network", action="append", default=[], metavar="ZONE=NET[,NET]",
        help="ASA target: the networks behind a zone, so that rules for other zones can leave them out. Give them "
        "for every zone; 0.0.0.0/0,::/0 for the zone with the default route",
    )  # fmt: skip
    conv.add_argument("--app-map", metavar="FILE", help="JSON file: application name -> list of port specs")
    conv.add_argument("--prune-unused", action="store_true", help="leave out objects no rule uses")
    target = conv.add_mutually_exclusive_group()
    target.add_argument("--target-vsys", metavar="NAME", help="PAN-OS target: write into this virtual system")
    target.add_argument("--target-device-group", metavar="NAME", help="Panorama target: write into this device group")
    target.add_argument("--target-shared", action="store_true", help="Panorama target: write into shared")
    conv.add_argument(
        "--target-nat-zone", default="", metavar="ZONE",
        help="PAN-OS target: destination zone for NAT rules of a source that names none; "
        "ASA target: interface for NAT to the outgoing interface where the rule names none",
    )  # fmt: skip
    conv.add_argument("--target-vdom", default="", metavar="NAME", help="FortiOS target: write into this VDOM")
    conv.add_argument(
        "--policy-id-start", type=int, default=0, metavar="N", help="FortiOS target: first policy id (default: automatic)"
    )
    conv.add_argument(
        "--target-layer", default="Network", metavar="NAME", help="Check Point target: access layer (default: Network)"
    )
    conv.add_argument(
        "--target-package", default="Standard", metavar="NAME", help="Check Point target: policy package of the NAT rules"
    )
    conv.add_argument(
        "--target-gateway", default="", metavar="NAME", help="Check Point target: gateway object that hide NAT uses"
    )
    conv.add_argument(
        "--target-prefix", default="", metavar="TEXT", help="Check Point and ASA targets: prefix for the names of created objects"
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
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer)
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
        nat_zone=args.target_nat_zone,
        target_vdom=args.target_vdom,
        policy_id_start=max(args.policy_id_start, 0),
        target_layer=args.target_layer,
        target_package=args.target_package,
        target_gateway=args.target_gateway,
        object_prefix=args.target_prefix,
        zone_networks=_networks(args.zone_network),
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
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer)
    transform.harden(policy, report)
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
