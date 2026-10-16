# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""What every lab run does: a work folder, an SSH key, the conversion, the plan, commands that are logged (and only
logged with --dry-run), the probes, the check, and a teardown that always runs.

Interrupting a run (Ctrl-C, SIGTERM, SIGHUP: a cancelled workflow) passes the interrupt to the command that is running
and waits for it to stop as it should (Terraform saves its state), then tears the run down with interrupts held off.
What a teardown could not remove is looked for by the run's id and named; ``lab.py destroy`` tries again later."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

import labplan

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent


class LabError(Exception):
    pass


@dataclass
class Runner:
    """Runs commands, or with dry_run only writes them down and returns what the caller says a real run would."""

    work: Path
    dry_run: bool = False
    echo: bool = True
    log: List[str] = field(default_factory=list)
    last_stderr: str = ""

    def run(self, args: Sequence[str], *, env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None, stdin: Optional[str] = None,
            check: bool = True, fake: str = "", quiet: bool = False, timeout: Optional[float] = None) -> str:  # fmt: skip
        shown = " ".join(shlex.quote(a) for a in args)
        extra = " ".join(f"{k}={shlex.quote(v)}" for k, v in sorted((env or {}).items()))
        line = (f"(cd {cwd}) " if cwd else "") + (extra + " " if extra else "") + shown
        self.log.append(line)
        if self.echo and not quiet:
            sys.stderr.write("$ " + line + "\n")  # (one write: the probes run side by side)
        if self.dry_run:
            return fake
        # A session of its own: an interrupt of the run reaches the command only as the run passes it on, once.
        proc = subprocess.Popen(list(args), env={**os.environ, **(env or {})}, cwd=str(cwd) if cwd else None, text=True,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)  # fmt: skip
        try:
            out, err = proc.communicate(input=stdin, timeout=timeout)
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGINT)  # (Terraform stops gracefully and writes its state)
            try:
                proc.communicate(timeout=900)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
            raise
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise LabError(f"{args[0]} did not finish within {timeout:.0f} s") from None
        if err and not quiet:
            sys.stderr.write(err[-4000:])
        if check and proc.returncode != 0:
            raise LabError(f"{args[0]} failed ({proc.returncode}): {(err or out).strip()[-800:]}")
        self.last_stderr = err
        return out

    def save_log(self) -> None:
        (self.work / "commands.log").write_text("\n".join(self.log) + "\n", encoding="utf-8")


def _interrupt(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt(f"signal {signum}")


def install_signals() -> None:
    """SIGTERM and SIGHUP (a cancelled workflow, a closed terminal) end a run as Ctrl-C does: through its teardown."""
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _interrupt)


@contextmanager
def shielded() -> Iterator[None]:
    """Interrupts held off while a teardown runs: a second Ctrl-C must not leave half of a run behind."""
    names = [n for n in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, n)]
    old = {n: signal.getsignal(getattr(signal, n)) for n in names}
    for n in names:
        signal.signal(getattr(signal, n), signal.SIG_IGN)
    try:
        yield
    finally:
        for n in names:
            signal.signal(getattr(signal, n), old[n])


def save_state(work: Path, **values: Any) -> None:
    """What a later ``lab.py destroy`` needs to find the run's resources again (run.json in the work folder)."""
    path = work / "run.json"
    data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data.update(values)
    path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


def load_state(work: Path) -> Dict[str, Any]:
    path = work / "run.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def need(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise LabError("not found on PATH: " + ", ".join(missing))


def new_run_id() -> str:
    """fwlab, the time and 4 random letters: lower case and short, for the names of every cloud."""
    return "fwlab" + time.strftime("%y%m%d%H%M") + secrets.token_hex(2)


def work_dir(base: Optional[str], run_id: str) -> Path:
    path = Path(base or os.environ.get("FWLAB_WORK", "lab-work")) / run_id
    path.mkdir(parents=True, exist_ok=False)
    return path


def admin_cidr(given: Optional[str], runner: Runner, wide: bool = False) -> str:
    """The address the runs are managed from: given, or what checkip.amazonaws.com sees. One address only, unless
    wide is allowed (--allow-wide-admin): management open to a network is management open to many."""
    if given:
        network = ipaddress.ip_network(given, strict=False)
        if network.num_addresses > 1 and not wide:
            raise LabError(f"--admin-cidr {given}: one address (/32 or /128); --allow-wide-admin to open management to a network")
        return str(network)
    if runner.dry_run:
        return "198.51.100.7/32"
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=15) as answer:  # noqa: S310 (a fixed https URL)
        address = answer.read().decode().strip()
    ipaddress.ip_address(address)
    return f"{address}/32"


def _dry_key(kind: str) -> str:
    """A public key line for a dry run, where ssh-keygen does not run: in the format of a real one (so what reads it
    reads it), and plainly no key: its numbers spell out what it is. There is no private key to it."""

    def field(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    filler = b"FWShift lab dry run: not a key. "
    if kind == "rsa":  # (type, exponent 65537, a 4096-bit modulus)
        blob = field(b"ssh-rsa") + field(b"\x01\x00\x01") + field(b"\x00" + (filler * 16)[:512])
    else:  # (type, 32 bytes)
        blob = field(b"ssh-ed25519") + field(filler[:32])
    return f"ssh-{'rsa' if kind == 'rsa' else 'ed25519'} {base64.b64encode(blob).decode()} dry-run"


def ssh_key(runner: Runner, kind: str = "ed25519") -> Path:
    """A key made for the run. Azure takes only RSA keys for its VMs, and so do some firewall images: those runs ask
    for "rsa" (4096 bits)."""
    key = runner.work / "id_lab"
    size = ["-b", "4096"] if kind == "rsa" else []
    runner.run(["ssh-keygen", "-q", "-t", kind, *size, "-N", "", "-C", runner.work.name, "-f", str(key)])
    if runner.dry_run:
        key.with_suffix(".pub").write_text(_dry_key(kind) + "\n")
    return key


def fwshift(runner: Runner, target: str, out: Path, options: Sequence[str]) -> Dict[str, Any]:
    """Converts the lab policy for a target; returns the JSON report. The conversion runs for real also with --dry-run:
    it touches nothing outside the work folder."""
    report = out.with_name(out.name + ".report.json")
    args = [sys.executable, "-m", "fwshift", "convert", str(labplan.POLICY), "--to", target, "-o", str(out), "-q",
            "--report", str(out.with_name(out.name + ".report.txt")), "--report-json", str(report), *options]  # fmt: skip
    print("$ fwshift " + " ".join(shlex.quote(a) for a in args[3:]), file=sys.stderr)
    runner.log.append("fwshift " + " ".join(shlex.quote(a) for a in args[3:]))
    env = {**os.environ, "PYTHONPATH": str(REPO / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}
    done = subprocess.run(args, env=env, text=True, capture_output=True)
    if done.returncode not in (0, 3):  # (3: converted, with findings to review)
        raise LabError(f"fwshift convert --to {target} failed: {done.stderr.strip()[-800:]}")
    data: Dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    return data


def host_init(test_ip: str, test_gw: str, test_net: str, subnet_via_gateway: bool = False) -> str:
    """The first-boot script of a test host (the same on every cloud): the probe, routing of the test address through
    its own interface, and the probe's answers on it."""
    template = (ROOT / "hostinit.sh.tpl").read_text(encoding="utf-8")
    probe = base64.b64encode((ROOT / "probe.py").read_bytes()).decode()
    values = {"test_ip": test_ip, "test_gw": test_gw, "test_net": test_net, "probe_b64": probe,
              "subnet_via_gw": "yes" if subnet_via_gateway else "no",
              "tcp_ports": ",".join(map(str, labplan.TCP_PORTS)), "udp_ports": ",".join(map(str, labplan.UDP_PORTS))}  # fmt: skip
    for key, value in values.items():
        template = template.replace("${" + key + "}", value)
    return template


@dataclass
class Target:
    """A host the probes run on, as the driver reaches it."""

    name: str
    test_ip: str
    via: List[str]  # the command prefix that runs a command there: ssh ..., or ip netns exec NAME


def ssh_prefix(key: Path, user: str, host: str, known: Path, port: int = 22) -> List[str]:
    return ["ssh", "-i", str(key), "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
            f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", f"{user}@{host}"]  # fmt: skip


def wait_ready(runner: Runner, targets: Sequence[Target], minutes: float = 15, probe_path: str = "/opt/fwlab/probe.py",
               python: str = "python3") -> None:  # fmt: skip
    """Until the probe of each host answers on every port of its test address (first boot can take minutes): a port
    that does not answer there would read as blocked."""
    deadline = time.time() + minutes * 60
    ports = f"--tcp {','.join(map(str, labplan.TCP_PORTS))} --udp {','.join(map(str, labplan.UDP_PORTS))}"
    for target in targets:
        while True:
            try:
                runner.run(target.via + [f"{python} {probe_path} selfcheck --bind {target.test_ip} {ports}"], quiet=True, timeout=60)
                break
            except LabError as error:
                if time.time() > deadline:
                    where = diagnose(runner, target, f"{python} {probe_path} selfcheck --bind {target.test_ip} {ports}", str(error))
                    raise LabError(f"the probe of host {target.name} does not answer on all its ports after {minutes:.0f} minutes"
                                   f" (what the host says: {where})") from None  # fmt: skip
                time.sleep(15)


# What a host that fails its self-check says about itself, before the teardown takes it: its addresses, the routing of
# its test address, the probe's service and the end of its first boot (cloud-init on AWS and Azure, the startup script
# on Google Cloud).
_DIAGNOSE = "; ".join([
    "echo '== selfcheck'; {selfcheck} 2>&1",
    "echo '== addresses'; ip -o addr",
    "echo '== rules'; ip rule",
    "echo '== table 120'; ip route show table 120",
    "echo '== routes'; ip route",
    "echo '== listening'; (ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null) | head -40",
    "echo '== probe service'; sudo -n systemctl status fwlab-probe --no-pager 2>&1 | tail -25",
    "echo '== first boot'; (sudo -n tail -60 /var/log/cloud-init-output.log 2>/dev/null"
    " || sudo -n journalctl -u google-startup-scripts --no-pager 2>/dev/null | tail -60)",
])  # fmt: skip


def diagnose(runner: Runner, target: Target, selfcheck: str, last_error: str) -> str:
    """Asks the host about itself (never fails), into diagnose-HOST.txt in the work folder; returns that file's name."""
    path = runner.work / f"diagnose-{target.name}.txt"
    try:
        out = runner.run(target.via + [_DIAGNOSE.format(selfcheck=selfcheck)], check=False, quiet=True, timeout=120,
                         fake="(dry run)")  # fmt: skip
    except LabError as error:
        out = f"(the host could not be asked: {error})"
    path.write_text(f"== the last self-check failed with\n{last_error}\n{out}{runner.last_stderr}", encoding="utf-8")
    return path.name


def probe(runner: Runner, targets: Sequence[Target], data: Dict[str, Any], copy: Callable[[Target, Path], "tuple[str, str]"],
          python: str = "python3") -> List[Dict[str, Any]]:  # fmt: skip
    """Sends the flows of the plan from every host at once; returns what each saw. ``copy`` puts the plan where the
    host can read it and says (the probe, the plan) as paths there."""
    plan_file = runner.work / "plan.json"

    def one(target: Target) -> List[Dict[str, Any]]:
        probe_path, plan_path = copy(target, plan_file)
        fake = json.dumps([{"id": f["id"], "observed": f["expected"] if f["expected"] != "unknown" else "blocked"}
                           for f in data["flows"] if f["src"] == target.test_ip])  # fmt: skip
        out = runner.run(target.via + [f"{python} {probe_path} send --plan {plan_path} --source {target.test_ip}"], fake=fake, timeout=900)
        found: List[Dict[str, Any]] = json.loads(out.strip().splitlines()[-1]) if out.strip() else []
        return found

    with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
        results = [r for found in pool.map(one, targets) for r in found]
    labplan.save(runner.work / "results.json", results)
    return results


def finish(runner: Runner, data: Dict[str, Any], results: List[Dict[str, Any]]) -> bool:
    summary = labplan.check(data, results)
    summary["dry_run"] = runner.dry_run
    labplan.save(runner.work / "summary.json", summary)
    text = labplan.render(summary)
    (runner.work / "summary.txt").write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return bool(summary["passed"])


def addresses(text: str) -> List[ipaddress.IPv4Network]:
    """'10.20.2.0-10.20.2.9 10.20.2.11 10.20.3.0/24' -> networks."""
    out: List[ipaddress.IPv4Network] = []
    for part in text.split():
        if "-" in part:
            first, last = (ipaddress.ip_address(x) for x in part.split("-", 1))
            out += [n for n in ipaddress.summarize_address_range(first, last) if isinstance(n, ipaddress.IPv4Network)]
        else:
            net = ipaddress.ip_network(part, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                out.append(net)
    return out
