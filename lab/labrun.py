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
import gzip
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

import labplan

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent


class LabError(Exception):
    pass


_ESCAPE = re.compile(r"\x1b\[(\d*)C|(\x1b\[[0-9;]*[Hf]|\x1b\[[0-9]*J)|\x1b\[[0-9;?]*[@-~]|\x1b[=>]|\x1b[()][0-9A-Za-z]")


def screen_text(raw: str, noise: str = "") -> str:
    """What a full-screen console wrote, as plain text: a cursor move to the right as that many spaces (the NSv writes
    its spaces so), a move to a place on the screen or a clearing of it as a new line (the NSv writes its lines so: its
    "User:" and its console's "NSv >" start a line), other escape codes left out, and the noise (a status bar redrawn
    after every output) taken out. (An insertion of characters, `ESC [20@`, is an escape code too: the NSv writes it
    when it redraws a line longer than the terminal, the ninth run.)"""

    def plain(found: "re.Match[str]") -> str:
        if found.group(1) is not None:  # (only the cursor move to the right has the group)
            return " " * int(found.group(1) or 1)
        return "\n" if found.group(2) else ""

    text = _ESCAPE.sub(plain, raw)
    return re.sub(noise, "", text) if noise else text


class SessionEnded(LabError):
    """A session typed line by line that stopped before its last line: with what the command line wrote till then."""

    def __init__(self, message: str, output: str) -> None:
        super().__init__(message)
        self.output = output


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
            out, err = proc.communicate()  # (what it wrote before it hung: where an SSH session stopped, and at what)
            wrote = "\n".join(part.strip()[-1500:] for part in (out or "", err or "") if part and part.strip())
            raise LabError(f"{args[0]} did not finish within {timeout:.0f} s" + (f"; what it wrote:\n{wrote}" if wrote else "")) from None
        if err and not quiet:
            sys.stderr.write(err[-4000:])
        if check and proc.returncode != 0:
            raise LabError(f"{args[0]} failed ({proc.returncode}): {(err or out).strip()[-800:]}")
        self.last_stderr = err
        return out

    def run_paced(self, args: Sequence[str], lines: Sequence[str], prompt: str, *, fake: str = "", timeout: float = 1200,
                  step: float = 120, answers: Sequence[Tuple[str, str]] = (), preamble: str = "", close_after: float = 0,
                  noise: str = "", preamble_when: str = "", pager: str = "", idle: float = 0, slow: str = "") -> str:  # fmt: skip
        """Types the lines one at a time, each once the command line shows its prompt again, and keeps the input open
        until the command ends: for a CLI that drops a session given its lines ahead of its prompt (the ASA: a single
        "U" of its greeting, and the session closed). Returns all it wrote; fails when a prompt does not come within
        `step` seconds, or the whole within `timeout`. answers: (pattern, text) for questions the command line may ask
        while a prompt is awaited (SonicOS's own "User:" and "Password:"), each answered once. preamble: keys sent as
        they are once the command line has written something (the NSv: Ctrl+S and a space switch its management console
        to the SonicOS CLI); what came before them is not searched for the prompt. close_after: a session that does not
        end by itself after its last line (the NSv's console stays) is closed after that many seconds. noise: for a
        full-screen console, the prompt and the questions are looked for in its plain text (screen_text), without that
        pattern (the NSv redraws its status bar after every output, so its prompt is never last in what it wrote).
        preamble_when: the keys only when the screen, drawn, shows this (the NSv's SSH lands in the window it was left
        in: the keys switch to the other one). A reply "{previous}" is the last one given to a question about a password
        in this session (an old password asked for again), or Enter where none was given. pager: a long answer stopped
        at this (SonicOS's "--MORE--") is shown on with a space, as often as it comes (the eleventh NSv run: the commit's
        error below the pager, which no command switched off). idle: a session quiet for that many seconds after a line
        (no question, no pager) is taken to be at its prompt, for a console whose prompt may not be seen (the sixteenth
        NSv run: SonicOS scrolled its screen to the left after a long line, and its prompt showed without its start);
        six times as long after a line that matches `slow` (a commit, which can be quiet for a while)."""
        shown = " ".join(shlex.quote(a) for a in args) + "  (typed line by line)"
        self.log.append(shown)
        if self.echo:
            sys.stderr.write("$ " + shown + "\n")
        if self.dry_run:
            return fake
        proc = subprocess.Popen(list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        chunks: List[bytes] = []
        lock = threading.Lock()

        def read() -> None:
            assert proc.stdout is not None
            while True:
                data = os.read(proc.stdout.fileno(), 4096)
                if not data:
                    return
                with lock:
                    chunks.append(data)

        def text() -> str:
            with lock:
                return b"".join(chunks).decode("utf-8", "replace")

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        pattern, deadline, mark = re.compile(prompt), time.time() + timeout, 0
        pending = [(re.compile(question), reply) for question, reply in answers]
        previous = ""

        def view() -> str:
            seen = text()[mark:]
            return screen_text(seen, noise).rstrip() if noise else seen

        try:
            assert proc.stdin is not None
            if preamble:
                limit = min(deadline, time.time() + step)
                while not text():
                    if proc.poll() is not None or time.time() > limit:
                        raise SessionEnded(f"{args[0]} wrote nothing to send its first keys to; what it wrote:\n{text().strip()[-1500:]}", text())
                    time.sleep(0.1)
                time.sleep(3)  # (the console drawn whole)
                if proc.poll() is not None:  # (what it wrote was ssh's own error: the firewall not up yet)
                    raise SessionEnded(f"{args[0]} ended before its first keys; what it wrote:\n{text().strip()[-1500:]}", text())
                drawn = screen_text(text(), noise).rstrip() if noise else text()
                if not preamble_when or re.search(preamble_when, drawn):
                    mark = len(text())  # (from here on: what came after the keys, a login question among it)
                    self._send(proc, preamble, args[0], text)
            sent = ""
            for line in lines:
                limit = min(deadline, time.time() + step)
                quiet = idle * (6 if slow and re.search(slow, sent) else 1)
                seen, changed = len(text()), time.time()
                while not pattern.search(view()):
                    if len(text()) != seen:
                        seen, changed = len(text()), time.time()
                    elif idle and sent and view().strip() and time.time() - changed >= quiet \
                            and not any(q.search(view()) for q, _ in pending) and not (pager and re.search(pager, view())):
                        break  # (quiet at what is taken to be its prompt)
                    if pager and re.search(pager, view()):
                        mark = len(text())
                        self._send(proc, " ", args[0], text)
                        limit = min(deadline, time.time() + step)
                        continue
                    asked = next((pair for pair in pending if pair[0].search(view())), None)
                    if asked is not None:  # (a question first: answered, and the prompt awaited again)
                        pending.remove(asked)
                        mark = len(text())
                        reply = asked[1].replace("{previous}", previous)
                        if "password" in asked[0].pattern.lower() and "{previous}" not in asked[1]:
                            previous = reply
                        self._send(proc, reply + "\n", args[0], text)
                        limit = min(deadline, time.time() + step)
                        continue
                    if proc.poll() is not None:
                        raise SessionEnded(f"{args[0]} ended before the prompt came back, before: {line!r}; what it wrote:\n{text().strip()[-1500:]}",
                                           text())  # fmt: skip
                    if time.time() > limit:
                        raise SessionEnded(f"the prompt did not come back within {step:.0f} s, before: {line!r}; what it wrote:\n{text().strip()[-1500:]}",
                                           text())  # fmt: skip
                    time.sleep(0.1)
                mark = len(text())
                self._send(proc, line + "\n", args[0], text)
                sent = line
            try:
                proc.wait(timeout=close_after or max(1.0, min(step, deadline - time.time())))
            except subprocess.TimeoutExpired:
                if not close_after:
                    raise LabError(f"{args[0]} did not end after the last line; what it wrote:\n{text().strip()[-1500:]}") from None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            try:  # (a pipe to a session that has ended: closed quietly, not complained about at exit)
                if proc.stdin is not None:
                    proc.stdin.close()
            except OSError:
                pass
            reader.join(timeout=5)
        return text()

    @staticmethod
    def _send(proc: "subprocess.Popen[bytes]", data: str, name: str, text: Callable[[], str]) -> None:
        """Writes to the session; one that has ended in the meantime ends the session as one that stopped early (the
        second NSv run: the keys went to an ssh that had failed to connect, and BrokenPipeError ended the run)."""
        assert proc.stdin is not None
        try:
            proc.stdin.write(data.encode("utf-8"))
            proc.stdin.flush()
        except OSError as error:
            raise SessionEnded(f"{name} ended while it was being written to ({error}); what it wrote:\n{text().strip()[-1500:]}", text()) from None

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


def _dry_key(kind: str, bits: int = 4096) -> str:
    """A public key line for a dry run, where ssh-keygen does not run: in the format of a real one (so what reads it
    reads it), and plainly no key: its numbers spell out what it is. There is no private key to it."""

    def field(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    filler = b"FWShift lab dry run: not a key. "
    if kind == "rsa":  # (type, exponent 65537, a modulus of the size asked)
        blob = field(b"ssh-rsa") + field(b"\x01\x00\x01") + field(b"\x00" + (filler * 32)[: bits // 8])
    else:  # (type, 32 bytes)
        blob = field(b"ssh-ed25519") + field(filler[:32])
    return f"ssh-{'rsa' if kind == 'rsa' else 'ed25519'} {base64.b64encode(blob).decode()} dry-run"


def ssh_key(runner: Runner, kind: str = "ed25519", bits: int = 4096) -> Path:
    """A key made for the run. Azure takes only RSA keys for its VMs, and so do some firewall images: those runs ask
    for "rsa" (4096 bits, unless a firewall cannot take a key that long: the ASAv reads its key from one configuration
    line of at most 511 characters)."""
    key = runner.work / "id_lab"
    size = ["-b", str(bits)] if kind == "rsa" else []
    runner.run(["ssh-keygen", "-q", "-t", kind, *size, "-N", "", "-C", runner.work.name, "-f", str(key)])
    if runner.dry_run:
        key.with_suffix(".pub").write_text(_dry_key(kind, bits) + "\n")
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
    # Compressed: AWS takes at most 16 KB of user data, and the probe in plain base64 made 17.5 KB of it (the fifth
    # pfSense run: Terraform refused every test host).
    probe = base64.b64encode(gzip.compress((ROOT / "probe.py").read_bytes(), mtime=0)).decode()
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


def ssh_prefix(key: Path, user: str, host: str, known: Path, port: int = 22, options: Sequence[str] = (), batch: bool = True) -> List[str]:
    """The ssh command that reaches a host; options: more -o settings, for a host that needs them (an old host key type).
    Only the run's key is offered (IdentitiesOnly): the keys of an ssh agent go first otherwise, and a router that allows
    three tries (IOS XE) can refuse the login before the run's key is tried (the second 8000V run: "Permission denied
    (publickey...)" for the whole boot). batch=False: a password may be asked as well (SonicWall NSv: the instance id),
    and SSH_ASKPASS gives it (ssh takes the first value of an option, so BatchMode is left out, not overridden)."""
    extra = [word for option in options for word in ("-o", option)]
    mode = ["-o", "BatchMode=yes"] if batch else ["-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=publickey,keyboard-interactive,password"]
    return ["ssh", "-i", str(key), "-p", str(port), *mode, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
            f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", *extra, f"{user}@{host}"]  # fmt: skip


def askpass(work: Path, password: str) -> None:
    """ssh asks this script for a password (SSH_ASKPASS, forced, OpenSSH 8.4 and later); only a session without BatchMode
    asks at all. The password is kept in the run's folder, readable by its owner only."""
    secret = work / "askpass.secret"
    secret.write_text(password, encoding="utf-8")
    script = work / "askpass.sh"
    script.write_text(f"#!/bin/sh\ncat {shlex.quote(str(secret))}\n", encoding="utf-8")
    if os.name == "posix":
        secret.chmod(0o600)
        script.chmod(0o700)
    os.environ.update({"SSH_ASKPASS": str(script), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": os.environ.get("DISPLAY", ":0")})


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


def _expected_result(flow: Dict[str, Any]) -> Dict[str, Any]:
    """What the probe would report for a flow that goes as the plan expects (a dry run)."""
    observed = flow["expected"] if flow["expected"] != "unknown" else "blocked"
    result: Dict[str, Any] = {"id": flow["id"], "observed": observed}
    if observed == "passed" and flow.get("seen_from"):
        result["seen_as"] = flow["seen_from"]
    if observed == "passed" and (flow.get("answered_by") or flow.get("seen_from")):
        result["answered_by"] = flow.get("answered_by") or flow["dst"]
    return result


def probe(runner: Runner, targets: Sequence[Target], data: Dict[str, Any], copy: Callable[[Target, Path], "tuple[str, str]"],
          python: str = "python3") -> List[Dict[str, Any]]:  # fmt: skip
    """Sends the flows of the plan from every host at once; returns what each saw. ``copy`` puts the plan where the
    host can read it and says (the probe, the plan) as paths there."""
    plan_file = runner.work / "plan.json"

    def one(target: Target) -> List[Dict[str, Any]]:
        probe_path, plan_path = copy(target, plan_file)
        fake = json.dumps([_expected_result(f) for f in data["flows"] if f["src"] == target.test_ip])
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
