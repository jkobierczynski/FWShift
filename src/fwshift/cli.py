# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line interface."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import sys
from typing import Callable, Dict, List, Optional, Sequence, TextIO, Tuple

from . import __version__, audit, matrix, transform
from .appmap import load_app_map
from .emitters import asa as emit_asa
from .emitters import checkpoint as emit_checkpoint
from .emitters import cisco as emit_cisco
from .emitters import fortios as emit_fortios
from .emitters import iptables as emit_iptables
from .emitters import panos as emit_panos
from .emitters import pfsense as emit_pfsense
from .emitters import barracuda as emit_barracuda
from .emitters import sonicwall as emit_sonicwall
from .emitters import sophos as emit_sophos
from .emitters import watchguard as emit_watchguard
from .errors import FwshiftError
from .model import ANY, Policy
from .netutil import parse_literal
from .options import Options
from .parsers import asa as parse_asa
from .parsers import checkpoint as parse_checkpoint
from .parsers import cisco as parse_cisco
from .parsers import fortios as parse_fortios
from .parsers import iptables as parse_iptables
from .parsers import panos as parse_panos
from .parsers import pfsense as parse_pfsense
from .parsers import barracuda as parse_barracuda
from .parsers import sonicwall as parse_sonicwall
from .parsers import sophos as parse_sophos
from .parsers import watchguard as parse_watchguard
from .report import Report, Severity

EMITTERS: Dict[str, Callable[[Policy, Report, Options], str]] = {
    "panos": emit_panos.emit,
    "fortios": emit_fortios.emit,
    "iptables": emit_iptables.emit,
    "ip6tables": emit_iptables.emit_v6,
    "checkpoint": emit_checkpoint.emit,
    "asa": emit_asa.emit,
    "sophos": emit_sophos.emit,
    "pfsense": emit_pfsense.emit,
    "sonicwall": emit_sonicwall.emit,
    "barracuda": emit_barracuda.emit,
    "watchguard": emit_watchguard.emit,
    "fmc": emit_cisco.emit_fmc,
    "fdm": emit_cisco.emit_fdm,
}
VENDORS = ("panos", "fortios", "checkpoint", "asa", "fmc", "fdm", "sophos", "pfsense", "sonicwall", "watchguard", "barracuda", "iptables",
           "ip6tables")  # fmt: skip


def detect_format(data: bytes) -> str:
    """A Sophos export is a tar archive or XML that starts with <Configuration>, other XML is PAN-OS; JSON is what a
    Cisco manager or the Check Point API returns, told apart by the types of the objects in it; a zip is the export
    of a Cisco Firewall Device Manager; iptables-save output starts with a table, an ASA configuration has lines
    only an ASA writes; anything else is taken as FortiOS."""
    if parse_cisco.is_zip(data):
        # The one zip that is read as it is: the configuration export of a Cisco Firewall Device Manager.
        try:
            why = "" if parse_cisco.dialect_of(parse_cisco.unzip(data)) == "fdm" else "the file in it is not a configuration of a Device Manager"
        except FwshiftError as error:
            why = str(error)
        if not why:
            return "fdm"
        raise FwshiftError("the input is compressed (a zip), and not the configuration export of a Firewall Device Manager as FWShift "
                           f"reads it ({why}). Unpack it and give FWShift the file inside")  # fmt: skip
    if data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        raise FwshiftError("the input is compressed (gzip, bzip2 or xz); unpack it and give FWShift the file inside")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        data = data[:65536].decode("utf-16", errors="replace").encode("utf-8")  # the start is enough to tell
    if parse_sophos.looks_like_sophos(data):
        return "sophos"
    if parse_pfsense.looks_like_pfsense(data):
        return "pfsense"
    if parse_sonicwall.looks_like_sonicwall(data):
        return "sonicwall"
    if parse_watchguard.looks_like_watchguard(data):
        return "watchguard"
    if parse_barracuda.looks_like_barracuda(data):
        return "barracuda"
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"<"):
        return "panos"
    if head.startswith((b"{", b"[")):
        return parse_cisco.dialect_of(data) or "checkpoint"
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
    data: bytes, source: str, report: Report, vsys: str = "", device_group: str = "", vdom: str = "", layer: str = "",
    policy: str = "", nat_policy: str = "", interface_addresses: Sequence[str] = (),
) -> Policy:  # fmt: skip
    if interface_addresses and source not in ("pfsense", "sonicwall"):
        raise FwshiftError("--interface-address is for a pfSense or SonicWall source")
    if source == "panos":
        return parse_panos.parse(data, report, vsys=vsys, device_group=device_group)
    if source == "fortios":
        return parse_fortios.parse(data, report, vdom=vdom)
    if source == "checkpoint":
        return parse_checkpoint.parse(data, report, layer=layer)
    if source == "asa":
        return parse_asa.parse(data, report)
    if source == "sophos":
        return parse_sophos.parse(data, report)
    if source == "pfsense":
        return parse_pfsense.parse(data, report, interface_addresses=interface_addresses)
    if source == "sonicwall":
        return parse_sonicwall.parse(data, report, interface_addresses=interface_addresses)
    if source == "watchguard":
        return parse_watchguard.parse(data, report)
    if source == "barracuda":
        return parse_barracuda.parse(data, report)
    if source in ("fmc", "fdm"):
        return parse_cisco.parse(data, report, source, policy=policy, nat_policy=nat_policy)
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
             "--target-prefix": options.object_prefix, "--target-policy": options.target_policy,
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


def _audit_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("audit")
    group.add_argument("--audit-config", metavar="FILE", help="JSON file with the actions, accepted rules and thresholds of the audit")
    group.add_argument(
        "--audit-action", action="append", default=[], metavar="CHECK=ACTION",
        help="what to do with the findings of a check: off, accept, report, disable, or reorder (shadowed rules). "
        "'fwshift audit --list-checks' shows the checks",
    )  # fmt: skip
    group.add_argument(
        "--audit-accept", action="append", default=[], metavar="RULE[=CHECK,...]",
        help="let a rule pass a check, or every check; * and ? match as in file names",
    )  # fmt: skip
    group.add_argument("--audit-fail-on", metavar="LEVEL", help="exit with status 3 when a finding of this level or higher is reported: info, low, medium, high")


def _audit_config(args: argparse.Namespace) -> audit.AuditConfig:
    config = audit.AuditConfig()
    if args.audit_config:
        config = audit.load_config(_read(args.audit_config).decode("utf-8", errors="replace"), args.audit_config)
    for value in args.audit_action:
        check, sep, action = value.partition("=")
        if not sep:
            raise FwshiftError(f"--audit-action expects CHECK=ACTION, got '{value[:60]}'")
        config.set_action(check, action, "--audit-action")
    for value in args.audit_accept:
        rule, _, checks = value.partition("=")
        config.accept(rule, checks.split(",") if checks else [], "accepted on the command line", "--audit-accept")
    if args.audit_fail_on:
        config.fail_on = audit.level_of(args.audit_fail_on, "--audit-fail-on")
    return config


def _lost(policy: Policy, report: Report) -> List[str]:
    """The rules a conversion wrote disabled or left out, of those that were enabled."""
    return [rule.origin for rule in policy.rules
            if rule.enabled and (report.item("rule", rule.origin).disabled or report.item("rule", rule.origin).skipped)]  # fmt: skip


def _trial(target: str, options: Options) -> audit.Trial:
    """A conversion that writes nothing: it tells which rules the target cannot take, and what it would write from."""

    def convert_on_trial(policy: Policy) -> Tuple[Optional[Policy], List[str]]:
        kept: List[Policy] = []
        report = Report()
        convert(copy.deepcopy(policy), target, report, dataclasses.replace(options, written=kept))
        return (kept[-1] if kept else None), _lost(policy, report)

    return convert_on_trial


def _audit_apply(policy: Policy, result: audit.AuditResult, config: audit.AuditConfig, report: Report,
                 trial: Optional[audit.Trial] = None) -> None:  # fmt: skip
    """Carry out the audit's actions before a conversion, and say in the conversion report what was done."""
    names = {rule.origin: rule.name for rule in policy.rules}
    for origin, check, changes, what in audit.apply(policy, result, config, (), trial):
        if not changes:
            report.add("rule", origin, Severity.INFO, "AUDIT_DISABLED",
                       f"disabled by the audit ({check}): the rule decided no traffic that other rules do not decide the same way")  # fmt: skip
        elif what == "disabled":
            report.add("rule", origin, Severity.APPROX, "AUDIT_DISABLED",
                       f"disabled by the audit ({check}), as asked: what '{names.get(origin, origin)}' allowed is no longer allowed by it")  # fmt: skip
        else:
            report.add("rule", origin, Severity.REVIEW, "AUDIT_MOVED",
                       f"{what} by the audit ({check}), as asked: on the source this rule never matched, now it decides its "
                       "traffic before the rules that used to. Check that this is what was meant")  # fmt: skip


def _audit_after(policy: Policy, result: audit.AuditResult, config: audit.AuditConfig, report: Report,
                 written: Optional[Policy] = None) -> None:  # fmt: skip
    """Audit the policy as the conversion left it: without the rules it wrote disabled or left out."""
    lost = _lost(policy, report)
    audit.compare(result, audit.effective(policy, lost), config, lost, written)


def _read(path: str) -> bytes:
    try:
        if path == "-":
            return sys.stdin.buffer.read()
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise FwshiftError(f"cannot read {path}: {exc.strerror}") from None


def _write(path: str, text: str) -> None:
    if path == "-":
        _print(sys.stdout, text)  # as "-" for the input is standard input
        return
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError as exc:
        raise FwshiftError(f"cannot write {path}: {exc.strerror}") from None


def _write_bytes(path: str, data: bytes) -> None:
    try:
        with open(path, "wb") as handle:
            handle.write(data)
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


def _source_options(parser: argparse.ArgumentParser, optional: bool = False) -> None:
    if optional:
        parser.add_argument("input", nargs="?", help="configuration file to read, or - for standard input")
    else:
        parser.add_argument("input", help="configuration file to read, or - for standard input")
    parser.add_argument("--from", dest="source", choices=VENDORS, help="source format (default: detected)")
    parser.add_argument("--vsys", default="", help="PAN-OS source: virtual system to read")
    parser.add_argument("--device-group", default="", help="Panorama source: device group to read")
    parser.add_argument("--vdom", default="", help="FortiOS source: VDOM to read")
    parser.add_argument("--layer", default="", help="Check Point source: access layer to read")
    parser.add_argument("--policy", default="", help="Management Center source (fmc): access control policy to read")
    parser.add_argument("--nat-policy", default="", help="Management Center source (fmc): NAT policy to read")
    parser.add_argument(
        "--interface-address", action="append", default=[], metavar="INTERFACE=ADDRESS/BITS",
        help="pfSense and SonicWall sources: address and network of an interface that gets them from somewhere else (DHCP, "
        "PPPoE, a delegated prefix), for the rules that name them; repeatable, IPv4 and IPv6 (SonicWall: IPv4)",
    )  # fmt: skip


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwshift",
        description="Convert firewall policies between PAN-OS, FortiOS, Check Point, Cisco ASA, Cisco Secure Firewall "
        "(Management Center and Device Manager), Sophos Firewall, pfSense, SonicWall, WatchGuard, Barracuda and iptables, with a lossiness "
        "report.",
    )
    parser.add_argument("--version", action="version", version=f"fwshift {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    conv = commands.add_parser("convert", help="convert a configuration to another vendor's format")
    _source_options(conv)
    conv.add_argument("--to", dest="target", required=True, choices=VENDORS + ("json",), help="target format")
    conv.add_argument("-o", "--output", help="write the converted configuration here (default: standard output). Sophos target: "
                      "a name that ends in .tar gives the archive an import takes")
    conv.add_argument("--report", help="write the text report here (default: standard error)")
    conv.add_argument("--report-json", help="also write the report as JSON")
    conv.add_argument("--zone-map", action="append", default=[], metavar="SRC=DST", help="rename a zone or interface")
    conv.add_argument(
        "--interface-map", action="append", default=[], metavar="SRC=DST", help="map a source interface to a target one"
    )
    conv.add_argument(
        "--zone-network", action="append", default=[], metavar="ZONE=NET[,NET]",
        help="ASA, pfSense and Barracuda targets: the networks behind a zone, so that rules for other zones can leave them out. Give them "
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
        "ASA target: interface for NAT to the outgoing interface where the rule names none; "
        "Cisco Secure Firewall targets: its zone; pfSense target: interface for port forwards of a rule from every "
        "zone, and for outbound NAT where the rule does not say where its traffic leaves",
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
        "--target-prefix", default="", metavar="TEXT",
        help="Check Point, ASA, Sophos, pfSense, SonicWall, WatchGuard, Barracuda and Cisco Secure Firewall targets: prefix for the names of created objects",
    )  # fmt: skip
    conv.add_argument(
        "--target-policy", default="FWShift", metavar="NAME",
        help="Management Center target (fmc): name of the access control policy and the NAT policy the script creates (default: FWShift)",
    )  # fmt: skip
    conv.add_argument("--strict", action="store_true", help="exit with status 2 when anything needs review")
    conv.add_argument("-q", "--quiet", action="store_true", help="do not print the report or the summary")
    conv.add_argument(
        "--audit", action="store_true",
        help="audit the policy before and after the conversion (rules that allow too much, rules that never match, loose "
        "ends) and carry out the actions set for the checks",
    )  # fmt: skip
    _audit_options(conv)

    aud = commands.add_parser("audit", help="audit a configuration: rules that allow too much, rules that never match, loose ends")
    _source_options(aud, optional=True)
    aud.add_argument("-o", "--output", help="write the audit here (default: standard output)")
    aud.add_argument("--json", action="store_true", help="write the audit as JSON")
    aud.add_argument("--list-checks", action="store_true", help="show the checks, their levels and what can be done with them")
    _audit_options(aud)

    mat = commands.add_parser("matrix", help="show what each zone may reach in each other zone, on which services, through which rules")
    _source_options(mat)
    mat.add_argument("-o", "--output", help="write the matrix here (default: standard output)")
    mat.add_argument("--json", action="store_true", help="write the matrix as JSON")
    mat.add_argument("--csv", action="store_true", help="write a line per rule and conduit, for a spreadsheet")
    mat.add_argument("--summary", action="store_true", help="text output: leave out the rules of each conduit")
    mat.add_argument("--network-zone", action="append", default=[], metavar="NAME[@ZONE]=NETWORK[,NETWORK...]",
                     help="a zone of your own, as networks; repeatable. With it the matrix is between these zones (and "
                     "'elsewhere'), not between the zones of the policy. @ZONE names the zone of the policy the networks lie behind")  # fmt: skip
    mat.add_argument("--audit-config", metavar="FILE", help="JSON file of the audit: its lists of risky and industrial services are used")

    insp = commands.add_parser("inspect", help="show what was read from a configuration")
    _source_options(insp)
    return parser


def _run_convert(args: argparse.Namespace) -> int:
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy,
                  args.interface_address)  # fmt: skip
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
        target_policy=args.target_policy,
        zone_networks=_networks(args.zone_network),
    )
    auditing = bool(args.audit or args.audit_config or args.audit_action or args.audit_accept or args.audit_fail_on)
    if auditing and args.target == "json":
        raise FwshiftError("--to json writes the model as it was read; audit the configuration with 'fwshift audit'")
    config = _audit_config(args) if auditing else audit.AuditConfig()
    audited: Optional[audit.AuditResult] = None
    if auditing:
        transform.harden(policy, report)
        audited = report.audit = audit.run(policy, config, report)
        # A rule is only redundant next to rules that are written, and as they are written: the audit
        # converts on trial to see which rules the target cannot take and what it makes of the others.
        _audit_apply(policy, audited, config, report, _trial(args.target, options))
    kept: List[Policy] = []
    output = convert(policy, args.target, report, dataclasses.replace(options, written=kept))
    if audited is not None:
        _audit_after(policy, audited, config, report, kept[-1] if kept else None)
    if args.output and args.target == "sophos" and args.output.lower().endswith(".tar"):
        _write_bytes(args.output, emit_sophos.archive(output))
    elif args.output:
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
    if args.strict and report.needs_review:
        return 2
    return 3 if audited is not None and audited.fails(config.fail_on) else 0


def _run_audit(args: argparse.Namespace) -> int:
    if args.list_checks:
        rows = audit.checks_table()
        width = max(len(row[0]) for row in rows)
        lines = [f"{'check':<{width}}  level   default  what it finds"]
        lines += [f"{code:<{width}}  {level:<6}  {default:<7}  {title} (can be: {actions})" for code, level, default, actions, title in rows]
        _print(sys.stdout, "\n".join(lines) + "\n")
        return 0
    if not args.input:
        raise FwshiftError("audit: a configuration file is needed (or - for standard input)")
    config = _audit_config(args)
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy,
                  args.interface_address)  # fmt: skip
    transform.harden(policy, report)
    result = audit.run(policy, config, report)
    disabled = sum(1 for rule in policy.rules if not rule.enabled)
    if args.json:
        text = json.dumps({"source": source, "scope": policy.scope, **result.to_dict()}, indent=2, ensure_ascii=False) + "\n"
    else:
        head = (f"FWShift audit\n  source: {source}{f' ({policy.scope})' if policy.scope else ''}\n"
                f"  security rules: {len(policy.rules)} ({disabled} disabled), NAT rules: {len(policy.nat_rules)}\n\n")  # fmt: skip
        text = head + result.to_text("Summary")
    if args.output:
        _write(args.output, text)
    else:
        _print(sys.stdout, text)
    return 3 if result.fails(config.fail_on) else 0


def _run_matrix(args: argparse.Namespace) -> int:
    if args.json and args.csv:
        raise FwshiftError("matrix: --json or --csv, not both")
    config = audit.AuditConfig()
    if args.audit_config:
        config = audit.load_config(_read(args.audit_config).decode("utf-8", errors="replace"), args.audit_config)
    networks = matrix.parse_networks(args.network_zone)
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy,
                  args.interface_address)  # fmt: skip
    transform.harden(policy, report)
    result = matrix.build(policy, config, report, networks)
    if args.json:
        text = json.dumps({"source": source, "scope": policy.scope, **result.to_dict()}, indent=2, ensure_ascii=False) + "\n"
    elif args.csv:
        text = result.to_csv()
    else:
        head = (f"FWShift zone matrix\n  source: {source}{f' ({policy.scope})' if policy.scope else ''}\n"
                f"  security rules: {result.rules} ({result.disabled} disabled, {result.dead} never match)\n\n")  # fmt: skip
        text = head + result.to_text(args.summary)
    if args.output:
        _write(args.output, text)
    else:
        _print(sys.stdout, text)
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy,
                  args.interface_address)  # fmt: skip
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
        if args.command == "audit":
            return _run_audit(args)
        if args.command == "matrix":
            return _run_matrix(args)
        return _run_inspect(args)
    except FwshiftError as exc:
        _print(sys.stderr, f"fwshift: error: {exc}\n")
        return 1
