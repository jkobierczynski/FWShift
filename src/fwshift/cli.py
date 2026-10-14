# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line interface."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import functools
import json
import os
import pkgutil
import sys
from typing import Callable, Dict, List, Optional, Sequence, Set, TextIO, Tuple

from . import __version__, audit, compare, conduits, hits, matrix, narrow, transform, usage
from .appmap import load_app_map
from .emitters import asa as emit_asa
from .emitters import aws as emit_aws
from .emitters import azure as emit_azure
from .emitters import terraform as emit_terraform
from .emitters import checkpoint as emit_checkpoint
from .emitters import cisco as emit_cisco
from .emitters import fortios as emit_fortios
from .emitters import iptables as emit_iptables
from .emitters import panos as emit_panos
from .emitters import forcepoint as emit_forcepoint
from .emitters import gcp as emit_gcp
from .emitters import opnsense as emit_opnsense
from .emitters import pfsense as emit_pfsense
from .emitters import routeros as emit_routeros
from .emitters import barracuda as emit_barracuda
from .emitters import ios as emit_ios
from .emitters import junos as emit_junos
from .emitters import nftables as emit_nftables
from .emitters import nsx as emit_nsx
from .emitters import sonicwall as emit_sonicwall
from .emitters import sophos as emit_sophos
from .emitters import watchguard as emit_watchguard
from .errors import FwshiftError
from .model import ANY, Policy
from .netutil import parse_literal
from .options import Options
from .parsers import asa as parse_asa
from .parsers import aws as parse_aws
from .parsers import azure as parse_azure
from .parsers import checkpoint as parse_checkpoint
from .parsers import cisco as parse_cisco
from .parsers import fortios as parse_fortios
from .parsers import iptables as parse_iptables
from .parsers import panos as parse_panos
from .parsers import forcepoint as parse_forcepoint
from .parsers import gcp as parse_gcp
from .parsers import opnsense as parse_opnsense
from .parsers import pfsense as parse_pfsense
from .parsers import routeros as parse_routeros
from .parsers import barracuda as parse_barracuda
from .parsers import ios as parse_ios
from .parsers import junos as parse_junos
from .parsers import nftables as parse_nftables
from .parsers import nsx as parse_nsx
from .parsers import sonicwall as parse_sonicwall
from .parsers import sophos as parse_sophos
from .parsers import terraform as parse_terraform
from .parsers import watchguard as parse_watchguard
from .report import Report, Severity

EMITTERS: Dict[str, Callable[[Policy, Report, Options], str]] = {
    "panos": emit_panos.emit,
    "fortios": emit_fortios.emit,
    "iptables": emit_iptables.emit,
    "ip6tables": emit_iptables.emit_v6,
    "nftables": emit_nftables.emit,
    "nsx": emit_nsx.emit,
    "aws": emit_aws.emit,
    "azure": emit_azure.emit,
    "terraform-aws": emit_terraform.emit_terraform_aws,
    "terraform-azure": emit_terraform.emit_terraform_azure,
    "gcp": emit_gcp.emit,
    "terraform-google": emit_terraform.emit_terraform_google,
    "routeros": emit_routeros.emit,
    "checkpoint": emit_checkpoint.emit,
    "asa": emit_asa.emit,
    "ios": emit_ios.emit,
    "sophos": emit_sophos.emit,
    "pfsense": emit_pfsense.emit,
    "opnsense": emit_opnsense.emit,
    "forcepoint": emit_forcepoint.emit,
    "sonicwall": emit_sonicwall.emit,
    "barracuda": emit_barracuda.emit,
    "junos": emit_junos.emit,
    "watchguard": emit_watchguard.emit,
    "fmc": emit_cisco.emit_fmc,
    "fdm": emit_cisco.emit_fdm,
}
VENDORS = ("panos", "fortios", "checkpoint", "asa", "ios", "fmc", "fdm", "sophos", "pfsense", "opnsense", "sonicwall", "watchguard", "barracuda", "junos",
           "iptables", "ip6tables", "nftables", "nsx", "aws", "azure", "terraform-aws", "terraform-azure", "terraform-google", "gcp", "routeros", "forcepoint")  # fmt: skip


def detect_format(data: bytes) -> str:
    """A Sophos export is a tar archive or XML that starts with <Configuration>, other XML is PAN-OS; JSON is what a
    Cisco manager or the Check Point API returns, told apart by the types of the objects in it; a zip is the export
    of a Cisco Firewall Device Manager; nft list ruleset output starts with "table" (its JSON with "nftables"), JSON of the NSX Policy API has the
    resource types of NSX,
    iptables-save output starts with a table, an IOS configuration has lines only IOS writes (and none only an ASA writes),
    an ASA configuration has lines only an ASA writes; anything else is taken as FortiOS."""
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
    if parse_terraform.looks_like_terraform(data):
        providers = parse_terraform.providers_of(data)
        if len(providers) == 1:
            return "terraform-" + providers.pop()
        if providers:
            raise FwshiftError("the Terraform state holds firewall resources of several providers: say which to read with --from "
                               "terraform-aws, terraform-azure or terraform-google")  # fmt: skip
        raise FwshiftError("a Terraform state or plan without the firewall resources FWShift reads (the security groups and network "
                           "ACLs of hashicorp/aws, the network security groups of hashicorp/azurerm, the firewall rules and network "
                           "firewall policies of hashicorp/google)")  # fmt: skip
    if parse_forcepoint.looks_like_forcepoint(data):
        return "forcepoint"
    if parse_gcp.looks_like_gcp(data):
        return "gcp"
    if parse_opnsense.looks_like_opnsense(data):
        return "opnsense"
    if parse_pfsense.looks_like_pfsense(data):
        return "pfsense"
    if parse_sonicwall.looks_like_sonicwall(data):
        return "sonicwall"
    if parse_watchguard.looks_like_watchguard(data):
        return "watchguard"
    if parse_barracuda.looks_like_barracuda(data):
        return "barracuda"
    if parse_nftables.looks_like_nftables(data):
        return "nftables"
    if parse_nsx.looks_like_nsx(data):
        return "nsx"
    if parse_aws.looks_like_aws(data):
        return "aws"
    if parse_azure.looks_like_azure(data):
        return "azure"
    if parse_routeros.looks_like_routeros(data):
        return "routeros"
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
    if parse_junos.looks_like_junos(head):
        return "junos"
    if parse_ios.looks_like_ios(head[:1_000_000].decode("utf-8", errors="replace")):
        return "ios"
    if parse_asa.looks_like_asa(head[:1_000_000].decode("utf-8", errors="replace")):
        return "asa"
    return "fortios"


def load(
    data: bytes, source: str, report: Report, vsys: str = "", device_group: str = "", vdom: str = "", layer: str = "",
    policy: str = "", nat_policy: str = "", interface_addresses: Sequence[str] = (),
) -> Policy:  # fmt: skip
    if interface_addresses and source not in ("pfsense", "opnsense", "sonicwall"):
        raise FwshiftError("--interface-address is for a pfSense, OPNsense or SonicWall source")
    if source == "panos":
        return parse_panos.parse(data, report, vsys=vsys, device_group=device_group)
    if source == "fortios":
        return parse_fortios.parse(data, report, vdom=vdom)
    if source == "checkpoint":
        return parse_checkpoint.parse(data, report, layer=layer)
    if source == "asa":
        return parse_asa.parse(data, report)
    if source == "ios":
        return parse_ios.parse(data, report)
    if source == "sophos":
        return parse_sophos.parse(data, report)
    if source == "pfsense":
        return parse_pfsense.parse(data, report, interface_addresses=interface_addresses)
    if source == "opnsense":
        return parse_opnsense.parse(data, report, interface_addresses=interface_addresses)
    if source == "sonicwall":
        return parse_sonicwall.parse(data, report, interface_addresses=interface_addresses)
    if source == "watchguard":
        return parse_watchguard.parse(data, report)
    if source == "barracuda":
        return parse_barracuda.parse(data, report)
    if source == "junos":
        return parse_junos.parse(data, report)
    if source in ("fmc", "fdm"):
        return parse_cisco.parse(data, report, source, policy=policy, nat_policy=nat_policy)
    if source in ("iptables", "ip6tables"):
        return parse_iptables.parse(data, report, family=6 if source == "ip6tables" else 0)
    if source == "nftables":
        return parse_nftables.parse(data, report)
    if source == "nsx":
        return parse_nsx.parse(data, report)
    if source == "aws":
        return parse_aws.parse(data, report)
    if source == "azure":
        return parse_azure.parse(data, report)
    if source in ("terraform-aws", "terraform-azure", "terraform-google"):
        if policy and source == "terraform-azure":
            raise FwshiftError("--policy is for a Management Center, Forcepoint, gcp, terraform-aws or terraform-google source")
        return parse_terraform.parse(data, report, provider=source.split("-", 1)[1], vpc=policy)
    if source == "gcp":
        return parse_gcp.parse(data, report, network=policy)
    if source == "routeros":
        return parse_routeros.parse(data, report)
    if source == "forcepoint":
        return parse_forcepoint.parse(data, report, policy=policy)
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
             "--target-template": options.target_template,
             "--zone-network": " ".join(options.zone_networks), "--inside-zone": " ".join(options.inside_zones)}  # fmt: skip
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
    group.add_argument(
        "--hits", action="append", default=[], metavar="FILE",
        help="hit counters of the firewall, for UNUSED_RULE: the XML answer of PAN-OS 'show rule-hit-count' or the JSON answer of the "
        "FortiOS monitor 'firewall/policy'; repeatable (counters of several firewalls are added up). A Check Point rulebase "
        "exported with show-hits carries its own",
    )  # fmt: skip
    group.add_argument("--unchanged-since", metavar="YYYY-MM-DD",
                       help="the rules have been as they are since this day, where the configuration does not say (iptables, a "
                       "Check Point export without meta-info): your word, for what the logs prove")  # fmt: skip
    group.add_argument("--hits-since", metavar="YYYY-MM-DD",
                       help="the hit counters have counted since this day (UTC), where they do not say so themselves (Check Point, "
                       "FortiOS): your word, for UNUSED_RULE")  # fmt: skip


def _usage_store_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--usage-store", metavar="FILE",
                        help="the store of 'fwshift usage': what the logs say about each rule over the last usage_days (90) days it "
                        "holds, for UNUSED_RULE, UNUSED_RULE_OBJECT and UNUSED_RULE_SERVICE")  # fmt: skip
    parser.add_argument("--usage-gateway", action="append", default=[], metavar="NAME[=LOGNAME,...]",
                        help="with --usage-store: a gateway the policy is installed on, as --gateway of 'fwshift usage'. Repeatable")


def _from_store(args: argparse.Namespace, policy: Policy, config: audit.AuditConfig, reading: Optional[audit.Reading] = None) -> List[str]:
    """What a usage store says about the rules (--usage-store); a line saying what was used."""
    if not getattr(args, "usage_store", None):
        return []
    if policy.vendor not in usage.VENDORS:
        raise FwshiftError("--usage-store: logs are read for a Check Point, PAN-OS, FortiOS, iptables or nftables policy only, in this version")
    store = usage.Store(args.usage_store, create=False)
    try:
        span = usage.window(store, days=config.usage_days)
        evaluation = usage.evaluate(policy, store, span, args.usage_gateway, reading, config.unchanged_since)
    finally:
        store.close()
    return [f"{args.usage_store}: {span.first} to {span.last}, {evaluation.attributed} of {evaluation.connections} connection(s) "
            "attributed to a rule of the policy"]


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
    if args.hits_since:
        config.hits_since = audit.day_of(args.hits_since, "--hits-since")
    if args.unchanged_since:
        config.unchanged_since = audit.day_of(args.unchanged_since, "--unchanged-since")
    return config


def _hit_counters(args: argparse.Namespace, policy: Policy) -> List[str]:
    """Put the counters of the --hits files on the rules; a line per file, and one for the counters the input held itself.

    With several files, a rule that not every file counts has a counter that may leave out a firewall.
    """
    lines: List[str] = []
    counted_by: List[Set[str]] = []
    seen: Dict[bytes, str] = {}
    for path in args.hits:
        data = _read(path)
        if data in seen:
            raise FwshiftError(f"--hits {path}: the same counters as {seen[data]}; given twice, they would be counted twice")
        seen[data] = path
        applied = hits.apply(policy, data, path)
        lines.append(applied.text())
        counted_by.append(applied.rules)
    if len(counted_by) > 1:
        for rule in policy.rules:
            missing = sum(1 for origins in counted_by if (rule.origin or rule.name) not in origins)
            if rule.hits is not None and missing:
                rule.hits.complete = False
                rule.hits.note = "; ".join(part for part in (rule.hits.note, f"{missing} of the {len(counted_by)} answers given do not "
                                                             "count it") if part)  # fmt: skip
    counted = sum(1 for rule in policy.rules if rule.hits is not None)
    if counted and not args.hits:
        lines.append(f"the configuration: counters of {counted} of {len(policy.rules)} rule(s)")
    return lines


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


MAX_INPUT_MB = 1024  # the largest input read, in MiB; FWSHIFT_MAX_INPUT_MB sets another


def _max_input() -> int:
    value = os.environ.get("FWSHIFT_MAX_INPUT_MB", "").strip()
    if not value:
        return MAX_INPUT_MB * 1024 * 1024
    if not value.isdigit() or int(value) < 1:
        raise FwshiftError(f"FWSHIFT_MAX_INPUT_MB is '{value[:20]}': give a number of MiB (1 or more)")
    return int(value) * 1024 * 1024


def _read(path: str) -> bytes:
    limit = _max_input()
    try:
        if path == "-":
            data = sys.stdin.buffer.read(limit + 1)
        else:
            with open(path, "rb") as handle:
                data = handle.read(limit + 1)
    except OSError as exc:
        raise FwshiftError(f"cannot read {path}: {exc.strerror}") from None
    except MemoryError:
        raise FwshiftError(f"cannot read {path}: not enough memory") from None
    if len(data) > limit:
        raise FwshiftError(f"{path} is larger than {limit // (1024 * 1024)} MiB, more than FWShift reads (set FWSHIFT_MAX_INPUT_MB "
                           "to read it anyway)")  # fmt: skip
    return data


def _write(path: str, text: str) -> None:
    if path == "-":
        _print(sys.stdout, text)  # as "-" for the input is standard input
        return
    try:
        with open(path, "w", encoding="utf-8", errors="backslashreplace", newline="\n") as handle:
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
    buffer.write(text.encode("utf-8", errors="backslashreplace"))
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
    parser.add_argument("--policy", default="", help="Management Center source (fmc): access control policy to read; Forcepoint: "
                        "firewall policy to read; terraform-aws: the VPC to read (its id or the address of its aws_vpc); gcp and terraform-google: "
                        "the network to read")
    parser.add_argument("--nat-policy", default="", help="Management Center source (fmc): NAT policy to read")
    parser.add_argument(
        "--interface-address", action="append", default=[], metavar="INTERFACE=ADDRESS/BITS",
        help="pfSense, OPNsense and SonicWall sources: address and network of an interface that gets them from somewhere else (DHCP, "
        "PPPoE, a delegated prefix), for the rules that name them; repeatable, IPv4 and IPv6 (SonicWall: IPv4)",
    )  # fmt: skip


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwshift",
        description="Convert firewall policies between PAN-OS, FortiOS, Check Point, Cisco ASA, Cisco IOS and IOS XE routers, Cisco Secure Firewall "
        "(Management Center and Device Manager), Sophos Firewall, pfSense, OPNsense, SonicWall, WatchGuard, Barracuda, Juniper SRX, iptables, "
        "nftables, VMware NSX, AWS security groups, Azure network security groups, Google Cloud firewall rules (these three also as Terraform), "
        "MikroTik RouterOS and Forcepoint NGFW, "
        "with a lossiness report.",
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
        help="ASA, pfSense, OPNsense, Barracuda, NSX, AWS, Azure and Google Cloud targets (also as Terraform): the networks behind a zone, so that rules for other zones can leave them out. Give "
        "them for every zone; 0.0.0.0/0,::/0 for the zone with the default route",
    )  # fmt: skip
    conv.add_argument(
        "--inside-zone", action="append", default=[], metavar="ZONE",
        help="AWS and Azure targets (also terraform-aws and terraform-azure): a zone whose networks (--zone-network) are inside the VPC or virtual network; only its "
        "addresses get security groups (Azure: only it gets a network security group). Repeatable",
    )  # fmt: skip
    conv.add_argument("--app-map", metavar="FILE", help="JSON file: application name -> list of port specs")
    conv.add_argument("--compare", nargs="?", const="", metavar="FILE",
                      help="read the output back (for the targets FWShift reads: asa, azure, fdm, fortios, iptables, ip6tables, junos, "
                      "nftables, nsx, sophos, watchguard) and report every connection whose verdict differs from the source; with "
                      "FILE, the whole comparison is written there")  # fmt: skip
    conv.add_argument("--prune-unused", action="store_true", help="leave out objects no rule uses")
    target = conv.add_mutually_exclusive_group()
    target.add_argument("--target-vsys", metavar="NAME", help="PAN-OS target: write into this virtual system")
    target.add_argument("--target-device-group", metavar="NAME", help="Panorama target: write into this device group")
    target.add_argument("--target-shared", action="store_true", help="Panorama target: write into shared")
    conv.add_argument(
        "--target-nat-zone", default="", metavar="ZONE",
        help="PAN-OS target: destination zone for NAT rules of a source that names none; "
        "ASA target: interface for NAT to the outgoing interface where the rule names none; "
        "Cisco Secure Firewall targets: its zone; pfSense and OPNsense targets: interface for port forwards of a rule from every "
        "zone, and for outbound NAT where the rule does not say where its traffic leaves",
    )  # fmt: skip
    conv.add_argument("--target-vdom", default="", metavar="NAME", help="FortiOS target: write into this VDOM")
    conv.add_argument(
        "--target-version", default="", metavar="SERIES",
        help="OPNsense target: the series to write for: 24.7, 25.1, 25.7, 26.1 or 26.7 (default: 26.7)",
    )  # fmt: skip
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
        help="Check Point, ASA, IOS, Sophos, pfSense, OPNsense, SonicWall, WatchGuard, Barracuda, Juniper, Cisco Secure Firewall, NSX, AWS and Azure "
             "targets (also as Terraform), and the policy Google Cloud targets create: prefix for the names of created objects",
    )  # fmt: skip
    conv.add_argument(
        "--target-policy", default="FWShift", metavar="NAME",
        help="Management Center target (fmc): name of the access control policy and the NAT policy the script creates; NSX: of "
             "the security policy; Forcepoint: of the firewall policy; Azure and terraform-azure: of the one group when no zone has networks; "
             "gcp and terraform-google: of the network firewall policy "
             "(default: FWShift)",
    )  # fmt: skip
    conv.add_argument(
        "--target-template", default="Firewall Template", metavar="NAME",
        help="Forcepoint target: the template the new firewall policy is based on (default: Firewall Template)",
    )  # fmt: skip
    conv.add_argument("--strict", action="store_true", help="exit with status 2 when anything needs review")
    conv.add_argument("-q", "--quiet", action="store_true", help="do not print the report or the summary")
    conv.add_argument(
        "--audit", action="store_true",
        help="audit the policy before and after the conversion (rules that allow too much, rules that never match, loose "
        "ends) and carry out the actions set for the checks",
    )  # fmt: skip
    _audit_options(conv)
    _usage_store_option(conv)

    aud = commands.add_parser("audit", help="audit a configuration: rules that allow too much, rules that never match, loose ends")
    _source_options(aud, optional=True)
    aud.add_argument("-o", "--output", help="write the audit here (default: standard output)")
    aud.add_argument("--json", action="store_true", help="write the audit as JSON")
    aud.add_argument("--list-checks", action="store_true", help="show the checks, their levels and what can be done with them")
    _audit_options(aud)
    _usage_store_option(aud)

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

    cond = commands.add_parser("conduits", help="check a configuration against a zone and conduit model (IEC 62443), or draft a "
                               "model from what it allows")  # fmt: skip
    _source_options(cond)
    cond.add_argument("--model", metavar="FILE", help="the zone and conduit model to check against (JSON, see the manual)")
    cond.add_argument("--draft", metavar="FILE", help="write a model of what the configuration allows today, as a start for one")
    cond.add_argument("--network-zone", action="append", default=[], metavar="NAME[@ZONE]=NETWORK[,NETWORK...]",
                      help="--draft: a zone of the model as networks, as for fwshift matrix; repeatable")
    cond.add_argument("-o", "--output", help="write the result here (default: standard output)")
    cond.add_argument("--json", action="store_true", help="write the result as JSON")
    cond.add_argument("--fail-on", default="medium", metavar="LEVEL",
                      help="exit with status 3 when a finding of this level or higher is found: info, low, medium (default), high")
    cond.add_argument("--audit-config", metavar="FILE", help="JSON file of the audit: its lists of risky and industrial services are used")
    cond.add_argument("--app-map", metavar="FILE", help="JSON file: application name -> list of port specs (the default ports of applications)")

    cmp = commands.add_parser("compare", help="every connection whose verdict differs between two configurations (the equivalence check)")
    cmp.add_argument("first", help="the first configuration (before)")
    cmp.add_argument("second", help="the second configuration (after)")
    cmp.add_argument("--from", dest="source", choices=VENDORS, help="format of the first (default: detected)")
    cmp.add_argument("--from-second", choices=VENDORS, help="format of the second (default: detected)")
    for option, text in (("--vsys", "PAN-OS: virtual system to read"), ("--device-group", "Panorama: device group to read"),
                         ("--vdom", "FortiOS: VDOM to read"), ("--layer", "Check Point: access layer to read"),
                         ("--policy", "Management Center (fmc), Forcepoint: access control or firewall policy to read; terraform-aws: the VPC; gcp and terraform-google: the network"),
                         ("--nat-policy", "Management Center (fmc): NAT policy to read")):  # fmt: skip
        cmp.add_argument(option, default="", help=text + " (of both)")
    cmp.add_argument("--zone-map", action="append", default=[], metavar="FIRST=SECOND",
                     help="a zone of the first as the second names it (several may become one); repeatable")
    cmp.add_argument("--zone-network", action="append", default=[], metavar="ZONE=NET[,NET]",
                     help="the networks behind a zone, named as the first configuration names it: only connections that can happen "
                     "are compared; repeatable")
    cmp.add_argument("--app-map", metavar="FILE", help="JSON file: application name -> list of port specs (the default ports of applications)")
    cmp.add_argument("-o", "--output", help="write the result here (default: standard output)")
    cmp.add_argument("--json", action="store_true", help="write the result as JSON")
    cmp.add_argument("--fail-on", default="low", metavar="LEVEL",
                     help="exit with status 3 when a difference of this weight or more is found: low (any difference, the default), "
                     "medium (opened possibly, or closed for certain), high (opened for certain), none")  # fmt: skip

    use = commands.add_parser("usage", help="which rules, objects and services the firewall's logs show used (Check Point, PAN-OS, FortiOS, iptables, nftables)")
    _source_options(use)
    use.add_argument("--logs", action="append", default=[], metavar="FILE",
                     help="a log file: what Check Point's Log Exporter sends (syslog, splunk or cef format), or the JSON answer of "
                     "show-logs; PAN-OS and FortiOS: the traffic logs they send to syslog (their default formats), or a PAN-OS CSV export; "
                     "iptables and nftables: the kernel lines of its LOG rules (log statements) as syslog or journalctl writes them; repeatable")  # fmt: skip
    use.add_argument("--store", metavar="FILE", help="keep the connections in this file (SQLite) and add to it on every run; a log file "
                     "that is in it already is not read again. Without it, nothing is kept")  # fmt: skip
    use.add_argument("--since", default="", metavar="DAYS|YYYY-MM-DD",
                     help="the first day of the window: a number of days back from its last (90d), or a day (default: usage_days, 90)")
    use.add_argument("--until", default="", metavar="YYYY-MM-DD", help="the last day of the window (default: the last day the store has logs of)")
    use.add_argument("--gateway", action="append", default=[], metavar="NAME[=LOGNAME,...]",
                     help="a gateway the policy is installed on; one that sent no logs proves nothing for its rules. NAME=LOGNAME,... "
                     "names the members of a cluster, whose logs carry their own names. Repeatable")  # fmt: skip
    use.add_argument("--log-year", type=int, metavar="YYYY",
                     help="iptables, nftables: the year of the first line of a log whose times have none (the old syslog form); it goes up "
                     "where the months run back")  # fmt: skip
    use.add_argument("--log-offset", metavar="+HH:MM",
                     help="iptables, nftables, PAN-OS, FortiOS: the offset from UTC of the times of a log that give none (default: UTC)")
    use.add_argument("--roll-up", type=int, default=usage.DEFAULT_CAP, metavar="N",
                     help=f"addresses kept per rule and side (per pair of interfaces, for logs that name no rule) before the rest are kept as "
                     f"their /24 or /64 (default {usage.DEFAULT_CAP})")  # fmt: skip
    use.add_argument("--propose", metavar="FILE", help="write the narrower rules of WIDER_THAN_TRAFFIC here, as new rules named "
                     "<rule>-narrowed, for review: the neutral model (JSON), or --propose-to")  # fmt: skip
    use.add_argument("--propose-to", choices=VENDORS + ("json",), metavar="FORMAT", default="json",
                     help="the format of --propose: json (default), or a target of fwshift convert. That is a conversion of a policy "
                     "that holds the narrowed rules only, with what the target needs around them: take the rules from it, do not "
                     "load it as it is. Its conversion report is written next to it (FILE.report.txt)")  # fmt: skip
    use.add_argument("-o", "--output", help="write the report here (default: standard output)")
    use.add_argument("--json", action="store_true", help="write the report as JSON")
    use.add_argument("--html", metavar="FILE", help="also write the report as a page of its own (HTML)")
    _audit_options(use)

    insp = commands.add_parser("inspect", help="show what was read from a configuration")
    _source_options(insp)

    scr = commands.add_parser("script", help="write a program FWShift works with: forcepoint-dump reads a policy out of a Forcepoint "
                              "SMC through its REST API, for --from forcepoint")  # fmt: skip
    scr.add_argument("name", choices=("forcepoint-dump",), help="the program to write")
    scr.add_argument("-o", "--output", help="write it here (default: standard output)")
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
        target_version=args.target_version,
        policy_id_start=max(args.policy_id_start, 0),
        target_layer=args.target_layer,
        target_package=args.target_package,
        target_gateway=args.target_gateway,
        object_prefix=args.target_prefix,
        target_policy=args.target_policy,
        target_template=args.target_template,
        zone_networks=_networks(args.zone_network),
        inside_zones=list(dict.fromkeys(args.inside_zone)),
    )
    auditing = bool(args.audit or args.audit_config or args.audit_action or args.audit_accept or args.audit_fail_on or args.hits
                    or args.hits_since or args.usage_store)
    if auditing and args.target == "json":
        raise FwshiftError("--to json writes the model as it was read; audit the configuration with 'fwshift audit'")
    config = _audit_config(args) if auditing else audit.AuditConfig()
    audited: Optional[audit.AuditResult] = None
    # For --compare: the policy as it was read (the audit's actions and the conversion are what is compared), and what the
    # parser said of it (not the emitter's findings).
    original = copy.deepcopy(policy) if args.compare is not None else None
    reading = audit.Reading.of(report)
    if auditing:
        transform.harden(policy, report)
        for line in _hit_counters(args, policy):
            report.note(Severity.INFO, "HIT_COUNTERS", line)
        for line in _from_store(args, policy, config, audit.Reading.of(report)):
            report.note(Severity.INFO, "USAGE_STORE", line)
        audited = report.audit = audit.run(policy, config, report)
        # A rule is only redundant next to rules that are written, and as they are written: the audit
        # converts on trial to see which rules the target cannot take and what it makes of the others.
        _audit_apply(policy, audited, config, report, _trial(args.target, options))
    kept: List[Policy] = []
    output = convert(policy, args.target, report, dataclasses.replace(options, written=kept))
    if original is not None:
        _compare_output(args, original, reading, output, report, options)
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
    counters = _hit_counters(args, policy)
    stored = _from_store(args, policy, config, audit.Reading.of(report))
    result = audit.run(policy, config, report)
    disabled = sum(1 for rule in policy.rules if not rule.enabled)
    if args.json:
        extra: Dict[str, object] = {"hit_counters": counters} if counters else {}
        if stored:
            extra["usage_store"] = stored
        text = json.dumps({"source": source, "scope": policy.scope, **extra, **result.to_dict()}, indent=2, ensure_ascii=False) + "\n"
    else:
        head = (f"FWShift audit\n  source: {source}{f' ({policy.scope})' if policy.scope else ''}\n"
                f"  security rules: {len(policy.rules)} ({disabled} disabled), NAT rules: {len(policy.nat_rules)}\n"
                + "".join(f"  hit counters: {line}\n" for line in counters)
                + "".join(f"  logs: {line}\n" for line in stored) + "\n")  # fmt: skip
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


def _run_conduits(args: argparse.Namespace) -> int:
    if bool(args.model) == bool(args.draft):
        raise FwshiftError("conduits: give --model FILE to check against, or --draft FILE to write one")
    if args.network_zone and not args.draft:
        raise FwshiftError("conduits: --network-zone is for --draft; a model gives its networks itself")
    fail_on = None if args.fail_on.lower() == "none" else audit.level_of(args.fail_on, "--fail-on")
    config = audit.AuditConfig()
    if args.audit_config:
        config = audit.load_config(_read(args.audit_config).decode("utf-8", errors="replace"), args.audit_config)
    model = conduits.load_model(_read(args.model).decode("utf-8-sig", errors="replace"), args.model) if args.model else None
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy,
                  args.interface_address)  # fmt: skip
    transform.harden(policy, report)
    if model is None:
        found = matrix.build(policy, config, report, matrix.parse_networks(args.network_zone))
        drafted = conduits.draft(found, os.path.basename(args.input))
        _write(args.draft, json.dumps(drafted, indent=2, ensure_ascii=False) + "\n")
        text = (f"fwshift: a draft of {len(drafted['zones'])} zones and {len(drafted['conduits'])} conduits written to {args.draft}: "
                "review it\n")  # fmt: skip
        if args.output:
            _write(args.output, text)
        else:
            _print(sys.stdout, text)
        return 0
    result = conduits.check(policy, model, config, report, app_ports=load_app_map(args.app_map) if args.app_map else None)
    if args.json:
        text = json.dumps({"source": source, "model_file": args.model, **result.to_dict()}, indent=2, ensure_ascii=False) + "\n"
    else:
        head = (f"FWShift zone and conduit check\n  model: {args.model}" + (f" ({model.name})" if model.name else "")
                + f", {len(model.zones)} zones, {len(model.conduits)} conduits\n  policy: {args.input} ({source}"
                + (f", {policy.scope}" if policy.scope else "") + ")\n\n")  # fmt: skip
        text = head + result.to_text()
    if args.output:
        _write(args.output, text)
    else:
        _print(sys.stdout, text)
    return 3 if result.fails(fail_on) else 0


_WEIGHTS = {"none": 4, "low": 1, "medium": 2, "high": 3}


def _run_compare(args: argparse.Namespace) -> int:
    weight = _WEIGHTS.get(args.fail_on.lower())
    if weight is None:
        raise FwshiftError(f"--fail-on expects low, medium, high or none, got '{args.fail_on[:20]}'")
    loaded = []
    for path, given in ((args.first, args.source), (args.second, args.from_second)):
        data = _read(path)
        source = given or detect_format(data)
        report = Report()
        policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy)
        transform.harden(policy, report)
        loaded.append((path, source, policy, report))
    (first, first_source, a, ra), (second, second_source, b, rb) = loaded
    result = compare.compare(a, b, f"{first} ({first_source})", f"{second} ({second_source})", (ra, rb),
                             compare.parse_zone_map(args.zone_map), _networks(args.zone_network),
                             app_ports=load_app_map(args.app_map) if args.app_map else None)  # fmt: skip
    text = (json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n") if args.json else "FWShift comparison\n" + result.to_text()
    if args.output:
        _write(args.output, text)
    else:
        _print(sys.stdout, text)
    return 3 if result.level() >= weight else 0


READ_BACK = ("asa", "azure", "fdm", "fortios", "iptables", "ip6tables", "junos", "nftables", "nsx", "routeros", "sophos", "watchguard")


def _alignment(source: Policy, back: Policy, options: Options) -> Tuple[Dict[str, str], List[str]]:
    """The zones of the source as the output read back names them: (map, zones not found there)."""
    def plain(text: str) -> str:
        return "".join(letter for letter in text.lower() if letter.isalnum())

    theirs = list(dict.fromkeys(list(back.zones) + [z for r in back.rules for z in r.src_zones + r.dst_zones if z != ANY]))
    if not theirs:
        return {}, []
    by_plain: Dict[str, str] = {}
    prefix = plain(options.object_prefix or ("fws-" if back.vendor == "routeros" else ""))
    for name in theirs:
        key = plain(name)
        by_plain.setdefault(key, name)
        if prefix and key.startswith(prefix):
            by_plain.setdefault(key[len(prefix):], name)
    out: Dict[str, str] = {}
    missing: List[str] = []
    ours = list(dict.fromkeys(options.zone_map.get(z, z) for z in list(source.zones) + [z for r in source.rules for z in r.src_zones + r.dst_zones]
                              if z != ANY))  # fmt: skip
    for zone in ours:
        for candidate in (zone, options.interface_map.get(zone, "")):
            if candidate in theirs:
                out[zone] = candidate
                break
            if candidate and plain(candidate) in by_plain:
                out[zone] = by_plain[plain(candidate)]
                break
        else:
            missing.append(zone)
    return out, missing


def _compare_output(args: argparse.Namespace, source: Policy, source_report: audit.Reading, output: str, report: Report,
                    options: Options) -> None:  # fmt: skip
    """Read the output back and compare it with the policy it came from; what differs goes into the report."""
    if args.target not in READ_BACK:
        report.note(Severity.REVIEW, "COMPARE_NOT_READ_BACK",
                    f"--compare: FWShift does not read {args.target} output back (it reads {', '.join(READ_BACK)}); nothing was compared")  # fmt: skip
        return
    back_report = Report()
    try:
        if args.target == "routeros":
            # The jumps that switch the script on are disabled in it; what is compared is the policy once they are on.
            back = parse_routeros.parse(output.encode("utf-8"), back_report, activate=True)
        else:
            back = load(output.encode("utf-8"), args.target, back_report)
        transform.harden(back, back_report)
    except FwshiftError as error:
        report.note(Severity.REVIEW, "COMPARE_NOT_READ_BACK", f"--compare: the output could not be read back: {str(error)[:200]}")
        return
    if args.target == "asa" and not options.zone_networks:
        report.note(Severity.REVIEW, "COMPARE_NOT_READ_BACK", "--compare: ASA output names no interfaces or routes, so the zones its "
                    "access lists lead to are not known when it is read back: give the networks of the zones with --zone-network")  # fmt: skip
        return
    mapped, missing = _alignment(source, back, options)
    raw = list(dict.fromkeys(list(source.zones) + [z for r in source.rules for z in r.src_zones + r.dst_zones if z != ANY]))
    zone_map = {zone: mapped.get(options.zone_map.get(zone, zone), options.zone_map.get(zone, zone)) for zone in raw}
    # --zone-network names the zones as the target does (after --zone-map); the comparison by the zones of the source.
    networks: Dict[str, List[str]] = {}
    for zone in raw:
        target = options.zone_map.get(zone, zone)
        if target in options.zone_networks:
            networks[zone] = list(options.zone_networks[target])
    targets = {options.zone_map.get(zone, zone) for zone in raw}
    networks.update({zone: list(nets) for zone, nets in options.zone_networks.items() if zone not in targets and zone not in networks})
    pairs = None
    if back.vendor == "azure" and "outside" in back.zones:
        # Between two zones no group stands for, nothing of the template decides: not compared.
        groups = {zone for zone in back.zones if zone != "outside"}
        for zone in raw:
            if options.zone_map.get(zone, zone) not in mapped:
                zone_map[zone] = "outside"
        names = list(dict.fromkeys(raw + list(networks) + [zone for zone in back.zones if zone not in zone_map.values()]))
        names += [compare.OTHER, compare.ELSEWHERE]
        pairs = [(a, b) for a in names for b in names if zone_map.get(a, a) in groups or zone_map.get(b, b) in groups]
        missing = []
    try:
        result = compare.compare(source, back, "the source", "the output read back", (source_report, back_report), zone_map, networks,
                                 pairs, options.app_ports)  # fmt: skip
    except FwshiftError as error:
        report.note(Severity.REVIEW, "COMPARE_NOT_READ_BACK", f"--compare: nothing was compared: {error}")
        return
    if args.compare:
        _write(args.compare, "FWShift comparison of a conversion\n" + result.to_text())
    where = f" (all of it: {args.compare})" if args.compare else ""
    if missing:
        report.note(Severity.INFO, "COMPARE_ZONES", "--compare: zones of the source the output does not name (compared as zones it does "
                    "not name either): " + ", ".join(missing[:12]))  # fmt: skip
    if result.equal:
        restricted = [note for note in result.notes if "only that is compared" in note]
        report.note(Severity.INFO, "COMPARE_EQUIVALENT", "--compare: the output read back: " + result.summary()
                    + (" " + " ".join(restricted) if restricted else ""))  # fmt: skip
        return
    counts = result.counts()
    opened = [d for d in result.differences if d.opened]
    closed = [d for d in result.differences if not d.opened]
    def lines(found: List[compare.Difference]) -> str:
        return "; ".join(f"{d.src} -> {d.dst}" + (f" ({d.condition})" if d.condition else "") + ": " + d.lines(2)[0] for d in found[:6]) \
            + (f"; and {len(found) - 6} more" if len(found) > 6 else "")
    if opened:
        report.note(Severity.REVIEW, "COMPARE_OPENED",
                    f"--compare: the output read back allows connections the source does not ({counts['opened, certain']} for certain, "
                    f"{counts['opened, possible']} possibly){where}: " + lines(opened))  # fmt: skip
    if closed:
        report.note(Severity.APPROX, "COMPARE_CLOSED",
                    f"--compare: the output read back blocks connections the source allows ({counts['closed, certain']} for certain, "
                    f"{counts['closed, possible']} possibly){where}: " + lines(closed))  # fmt: skip


def _offset(text: Optional[str]) -> Optional[int]:
    """+HH:MM (or -HH:MM, or Z) as minutes."""
    if not text:
        return None
    value = text.strip()
    if value.upper() == "Z":
        return 0
    sign = value[:1]
    hours, colon, minutes = value[1:].partition(":")
    if sign not in "+-" or not hours.isdigit() or (colon and not minutes.isdigit()) or int(hours) > 14 or int(minutes or 0) > 59:
        raise FwshiftError(f"--log-offset expects +HH:MM or -HH:MM, got '{text[:20]}'")
    return (1 if sign == "+" else -1) * (int(hours) * 60 + int(minutes or 0))


USAGE_CHECKS = ("UNUSED_RULE", "UNUSED_RULE_OBJECT", "UNUSED_RULE_SERVICE", "NO_USAGE_EVIDENCE", "WIDER_THAN_TRAFFIC")


def _run_usage(args: argparse.Namespace) -> int:
    if not args.logs and not args.store:
        raise FwshiftError("usage: give log files with --logs, or a store of logs read before with --store")
    if args.roll_up < 1:
        raise FwshiftError("--roll-up: at least 1 address per rule and side")
    config = _audit_config(args)
    for check in audit.CHECKS:
        if check not in USAGE_CHECKS:
            config.actions[check] = audit.OFF  # (the audit of the policy itself is 'fwshift audit')
    data = _read(args.input)
    source = args.source or detect_format(data)
    report = Report()
    policy = load(data, source, report, args.vsys, args.device_group, args.vdom, args.layer, args.policy, args.nat_policy,
                  args.interface_address)  # fmt: skip
    if policy.vendor not in usage.VENDORS:
        raise FwshiftError(f"usage: logs are read for a Check Point, PAN-OS, FortiOS, iptables or nftables policy in this version, not {source}")
    reading = audit.Reading.of(report)
    transform.harden(policy, report)
    counters = _hit_counters(args, policy)
    store = usage.Store(args.store or ":memory:", create=True)
    try:
        ingested = usage.ingest(store, [(path, functools.partial(_read, path)) for path in args.logs], policy.scope, usage.digest(data),
                                args.roll_up, usage.VENDORS[policy.vendor], args.log_year, _offset(args.log_offset))  # fmt: skip
        span = usage.window(store, args.since, args.until, config.usage_days)
        evaluation = usage.evaluate(policy, store, span, args.gateway, reading, config.unchanged_since)
    finally:
        store.close()
    result = audit.run(policy, config, report)
    document = usage.to_dict(policy, source, args.store or "(none: nothing is kept)", evaluation, ingested if args.logs else None,
                             result.before, counters)  # fmt: skip
    if args.propose:
        chosen = [(rule, finding.proposal) for finding in result.before if finding.check == "WIDER_THAN_TRAFFIC" and finding.proposal
                  and finding.action != audit.ACCEPT for rule in policy.rules if (rule.origin or rule.name) == finding.name]  # fmt: skip
        target = args.propose_to
        proposed = narrow.build(policy, chosen, f"{span.first} to {span.last}")
        written = [f"written to {args.propose} ({len(proposed.rules)} rule(s), {target})"]
        if target == "json" or not proposed.rules:
            _write(args.propose, convert(proposed, "json", Report()) if proposed.rules else "")
        else:
            # The rules of the policy where they are: its virtual system or device group, its VDOM, its layer.
            options = Options(target_scope=("device-group:" + policy.scope.split(" ", 1)[1] if policy.scope.startswith("device-group ")
                                            else f"vsys:{policy.scope}" if policy.scope.startswith("vsys") and policy.scope != "vsys1" else "")
                              if target == "panos" and policy.vendor == "panos" else "",
                              target_vdom=policy.scope if target == "fortios" and policy.vendor == "fortios" else "",
                              target_layer=policy.scope if target == "checkpoint" and policy.vendor == "checkpoint" and policy.scope else "Network")  # fmt: skip
            converted = Report()
            _write(args.propose, convert(proposed, target, converted, options))
            _write(args.propose + ".report.txt", converted.to_text())
            written += [f"its conversion report: {args.propose}.report.txt (read it: what the target could not write, rules it wrote "
                        "disabled)", "this is a conversion of a policy that holds the narrowed rules only, with what the target needs "
                        "around them (a whole table, a cleanup rule, access-groups): take the narrowed rules from it, do not load it as it is"]  # fmt: skip
        document["proposals_written"] = written
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n" if args.json else usage.to_text(document)
    if args.output:
        _write(args.output, text)
    else:
        _print(sys.stdout, text)
    if args.html:
        _write(args.html, usage.to_html(document))
    return 3 if result.fails(config.fail_on) else 0


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


def _run_script(args: argparse.Namespace) -> int:
    data = pkgutil.get_data("fwshift.parsers", "smc_dump.py")
    if data is None:
        raise FwshiftError("the program smc_dump.py is missing from this installation of FWShift")
    text = data.decode("utf-8").replace("\r\n", "\n")
    if args.output:
        _write(args.output, text)
        try:
            os.chmod(args.output, 0o755)
        except OSError:
            pass
    else:
        _print(sys.stdout, text)
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
        if args.command == "usage":
            return _run_usage(args)
        if args.command == "conduits":
            return _run_conduits(args)
        if args.command == "compare":
            return _run_compare(args)
        if args.command == "script":
            return _run_script(args)
        return _run_inspect(args)
    except FwshiftError as exc:
        _print(sys.stderr, f"fwshift: error: {exc}\n")
        return 1
