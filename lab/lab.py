#!/usr/bin/env python3
# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The FWShift lab: converts the lab policy for a target, puts the result on a real target (a cloud network, a local
virtual machine or a Marketplace firewall), sends test connections through it and checks them against what the source
policy decides. Everything it makes is destroyed at the end, also when a step fails (unless --keep).

    python3 lab/lab.py list
    python3 lab/lab.py plan tier1 aws
    python3 lab/lab.py run tier1 aws --region eu-west-1
    python3 lab/lab.py run tier1 azure --region westeurope
    python3 lab/lab.py run tier1 gcp --project my-project --region europe-west1
    sudo -E python3 lab/lab.py run tier2 routeros --image chr-base.qcow2 --ssh-key ~/.ssh/fwlab
    python3 lab/lab.py run tier3 fortigate --region eu-west-1

    python3 lab/lab.py destroy RUN          tear down a run that was interrupted or kept (--keep), from its work folder
    python3 lab/lab.py destroy-all DIR      the same for every run under DIR that is not torn down yet

--dry-run converts and plans for real, and only writes down the commands that would make and change things.
lab/README.md says what each tier needs, costs and verifies.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parent.parent / "src"))

import labplan  # noqa: E402
import labrun  # noqa: E402
import tier1  # noqa: E402
import tier2  # noqa: E402
import tier3  # noqa: E402

TIERS = {
    "tier1": sorted(tier1.RUNS),
    "tier2": sorted(tier2.IMAGES),
    "tier3": sorted(tier3.VENDORS),
}


def describe() -> str:
    return "\n".join([
        "tier1  free and easy: the cloud's own firewall, no image (tests in your account cost the small test hosts only)",
        "  aws          security groups (--to aws)",
        "  azure        network security groups (--to azure)",
        "  gcp          a global network firewall policy (--to gcp)",
        "tier2  free images on a local Linux host with KVM (root; base images prepared once)",
        *[f"  {i.name:<12} --to {i.target}" for i in tier2.IMAGES.values()],
        "tier3  AWS Marketplace images, pay per hour (subscribe once in the console)",
        tier3.describe(),
    ]) + "\n"  # fmt: skip


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="lab.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = top.add_subparsers(dest="command")
    sub.add_parser("list", help="the tiers and the targets of each")
    p = sub.add_parser("plan", help="convert the lab policy as a run would and write its test plan (makes nothing)")
    p.add_argument("tier", choices=sorted(TIERS))
    p.add_argument("firewall")
    p.add_argument("--target-version", help="tier2, OPNsense: as for run")
    p.add_argument("--work", help="where runs keep their files (default ./lab-work, or FWLAB_WORK)")
    d = sub.add_parser("destroy", help="tear down a run from its work folder (interrupted, failed, or kept with --keep)")
    d.add_argument("run", help="the run's id, or the path of its work folder")
    d.add_argument("--work", help="where runs keep their files (default ./lab-work, or FWLAB_WORK)")
    d.add_argument("--terraform", help="terraform or tofu")
    d.add_argument("--dry-run", action="store_true", help="only write down the commands")
    a = sub.add_parser("destroy-all", help="tear down every run under a folder that is not torn down yet")
    a.add_argument("folder")
    a.add_argument("--terraform", help="terraform or tofu")
    a.add_argument("--dry-run", action="store_true", help="only write down the commands")
    c = sub.add_parser("check", help="check results a probe wrote against a plan")
    c.add_argument("plan")
    c.add_argument("results")
    r = sub.add_parser("run", help="run the lab for a target")
    r.add_argument("tier", choices=sorted(TIERS))
    r.add_argument("firewall", help="tier1: aws, azure, gcp; tier2: routeros, opnsense, pfsense; tier3: " + ", ".join(sorted(tier3.VENDORS)))
    r.add_argument("--dry-run", action="store_true", help="convert and plan, and only write down the other commands")
    r.add_argument("--keep", action="store_true", help="leave everything running at the end (and pay for it): for looking at a failure")
    r.add_argument("--work", help="where runs keep their files (default ./lab-work, or FWLAB_WORK)")
    r.add_argument("--region", help="the cloud region (eu-west-1, westeurope, europe-west1 when not given)")
    r.add_argument("--project", help="Google Cloud: the project")
    r.add_argument("--zone", help="Google Cloud: the zone (REGION-b when not given)")
    r.add_argument("--admin-cidr", help="the address the run is managed from, as a /32 (asked of checkip.amazonaws.com when not given)")
    r.add_argument("--allow-wide-admin", action="store_true", help="let --admin-cidr be a network: management open to all of its addresses")
    r.add_argument("--terraform", help="terraform or tofu (whichever is on PATH when not given)")
    r.add_argument("--image", help="tier2: the base image of the firewall")
    r.add_argument("--ssh-key", help="tier2: the private key the base image lets in")
    r.add_argument("--ssh-user", help="tier2: the user (admin for RouterOS, root for OPNsense and pfSense when not given)")
    r.add_argument("--memory", type=int, default=2048, help="tier2: MiB for the firewall (2048)")
    r.add_argument("--target-version", help="tier2, OPNsense: the series of the base image (as --target-version of fwshift)")
    r.add_argument("--ami", help="tier3: the image id, where the name the lab looks for does not find it")
    r.add_argument("--instance-type", help="tier3: the firewall's instance type")
    r.add_argument("--boot-minutes", type=float, default=30, help="how long to wait for the firewall's CLI (30)")
    return top


def plan_options(tier: str, firewall: str, target_version: Optional[str]) -> "tuple[str, List[str], bool, str]":
    """(target, options, flows inside a zone pass the target, what a reset means) as a run of that tier makes them."""
    if tier == "tier1":
        target, options = tier1.conversion(firewall, "fwlabplan")
        return target, options, True, "passed"
    if tier == "tier2":
        target, options = tier2.conversion(firewall, target_version)
        return target, options, False, "blocked"
    target, options = tier3.conversion(firewall)
    return target, options, False, "blocked"


def destroy(work: Path, terraform: Optional[str], dry_run: bool = False) -> bool:
    """Tears a run down from what its work folder holds (run.json, the Terraform state)."""
    state = labrun.load_state(work)
    if not state:
        print(f"{work}: no run.json: not the work folder of a run", file=sys.stderr)
        return False
    if state.get("torn_down"):
        print(f"{work.name}: torn down already")
        return True
    runner = labrun.Runner(work, dry_run=dry_run)
    tier, firewall = state.get("tier"), state.get("firewall", "")
    with labrun.shielded():
        if tier == "tier1":
            tf = tier1.Terraform(runner, labrun.ROOT / tier1.MODULES[firewall], tier1.terraform_binary(terraform))
            tier1.TEARDOWNS[firewall](runner, tf)
        elif tier == "tier3":
            tier3.teardown(runner, tier1.Terraform(runner, labrun.ROOT / "tier3" / "aws", tier1.terraform_binary(terraform)))
        elif tier == "tier2":
            tier2.teardown(runner, [])
    runner.save_log()
    return bool(labrun.load_state(work).get("torn_down"))


def main(argv: Optional[List[str]] = None) -> int:
    args = parser().parse_args(argv)
    labrun.install_signals()
    try:
        return _main(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 2
    except labrun.LabError as error:
        print(f"lab: {error}", file=sys.stderr)
        return 2


def _main(args: argparse.Namespace) -> int:
    if args.command == "list":
        sys.stdout.write(describe())
        return 0
    if args.command == "check":
        summary = labplan.check(json.loads(Path(args.plan).read_text()), json.loads(Path(args.results).read_text()))
        sys.stdout.write(labplan.render(summary))
        return 0 if summary["passed"] else 1
    if args.command == "plan":
        if args.firewall not in TIERS[args.tier]:
            print(f"{args.tier} has no {args.firewall}: it has " + ", ".join(TIERS[args.tier]), file=sys.stderr)
            return 2
        work = labrun.work_dir(args.work, labrun.new_run_id())
        runner = labrun.Runner(work)
        target, options, inside, refused = plan_options(args.tier, args.firewall, args.target_version)
        report = labrun.fwshift(runner, target, work / f"policy.{target}", options)
        data = labplan.build_plan(target, report, through_target_inside_zone=inside, refused_means=refused)
        labplan.save(work / "plan.json", data)
        asserted = sum(1 for f in data["flows"] if f["asserted"])
        print(f"{work / 'plan.json'}: {len(data['flows'])} flows, {asserted} asserted")
        for flow in data["flows"]:
            if not flow["asserted"]:
                print(f"  not asserted: {flow['id']:<28} {flow['why_not_asserted']}")
        return 0
    if args.command == "destroy":
        work = Path(args.run) if Path(args.run).is_dir() else Path(args.work or os.environ.get("FWLAB_WORK", "lab-work")) / args.run
        return 0 if destroy(work, args.terraform, args.dry_run) else 1
    if args.command == "destroy-all":
        folder = Path(args.folder)
        runs = sorted(p for p in folder.iterdir() if (p / "run.json").exists()) if folder.is_dir() else []
        ok = all([destroy(work, args.terraform, args.dry_run) for work in runs])
        return 0 if ok else 1
    if args.command != "run":
        parser().print_help()
        return 2
    if args.firewall not in TIERS[args.tier]:
        print(f"{args.tier} has no {args.firewall}: it has " + ", ".join(TIERS[args.tier]), file=sys.stderr)
        return 2
    work = labrun.work_dir(args.work, labrun.new_run_id())
    runner = labrun.Runner(work, dry_run=args.dry_run)
    print(f"lab run {work.name}: {args.tier} {args.firewall}" + (" (dry run)" if args.dry_run else "") + f"; files in {work}", file=sys.stderr)
    try:
        if args.tier == "tier1":
            passed = tier1.RUNS[args.firewall](runner, args)
        elif args.tier == "tier2":
            passed = tier2.run_image(runner, args)
        else:
            passed = tier3.run_vendor(runner, args)
    except labrun.LabError as error:
        print(f"lab run {work.name} failed: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(f"lab run {work.name} interrupted (torn down unless --keep)", file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 (any other failure: the run could not be made, and says why)
        import traceback

        traceback.print_exc()
        return 2
    finally:
        runner.save_log()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
