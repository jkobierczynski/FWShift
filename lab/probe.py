#!/usr/bin/env python3
# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The probe of the FWShift lab: runs on each test host, with nothing but Python 3 (3.6 or newer) and ping.

    probe.py serve --bind 10.20.1.10 --tcp 22,80 --udp 53       answers on those ports of that address
    probe.py send --plan plan.json --source 10.20.1.10          tries each flow of the plan from that address,
                                                                and prints the results as JSON

A TCP flow passed when the handshake completes, a UDP flow when the answer of the other side's probe comes back, an
ICMP flow when ping gets an echo reply. The other side's probe answers with its own address and the address the
connection came from, as it saw it: what NAT did on the way ("answered_by" and "seen_as" in the results; not for a
port another listener has, such as sshd on 22). What does not come back within the timeout was blocked; a TCP reset is
"refused" (a firewall that rejects, or no listener). A flow that could not be tried at all (the source address is not
this host's, no route, ping refused) is "error", never "blocked". It never sends anything but to the addresses of the
plan.

    probe.py selfcheck --bind 10.20.1.10 --tcp 22,80 --udp 53      exits 0 when every port answers on that address
"""

import argparse
import errno
import json
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

MAGIC = b"fwshift-lab "


def _bind(sock, address, port, kind, stop):
    """Binds the socket, waiting for the address while the host does not have it yet: a test interface is attached
    after the host boots, and the probe may start first (the fourth pfSense run: every port of in11 failed with "Cannot
    assign requested address", once, and the host never answered). Other errors are raised."""
    told = False
    while True:
        try:
            sock.bind((address, port))
            if told:
                print("%s/%d: %s is there now" % (kind, port, address), file=sys.stderr)
            return
        except OSError as error:
            if error.errno != errno.EADDRNOTAVAIL or stop.is_set():
                raise
            if not told:
                print("%s/%d: %s; waiting for the address" % (kind, port, error), file=sys.stderr)
                told = True
            time.sleep(2)


def _serve_tcp(address, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        _bind(sock, address, port, "tcp", stop)
    except OSError as error:
        # Taken already (sshd on 22): that listener completes the handshake, which is all a TCP flow needs.
        print("tcp/%d: %s; the listener there answers" % (port, error), file=sys.stderr)
        return
    sock.listen(64)
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            conn, peer = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.sendall(MAGIC + address.encode() + b" " + peer[0].encode() + b"\n")
        except OSError:
            pass
        finally:
            conn.close()


def _serve_udp(address, port, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        _bind(sock, address, port, "udp", stop)
    except OSError as error:
        print("udp/%d: %s" % (port, error), file=sys.stderr)
        return
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(512)
        except socket.timeout:
            continue
        except OSError:
            break
        if data.startswith(MAGIC):
            sock.sendto(MAGIC + address.encode() + b" " + peer[0].encode(), peer)


def serve(address, tcp, udp, seconds=0):
    stop = threading.Event()
    threads = [threading.Thread(target=_serve_tcp, args=(address, p, stop), daemon=True) for p in tcp]
    threads += [threading.Thread(target=_serve_udp, args=(address, p, stop), daemon=True) for p in udp]
    for thread in threads:
        thread.start()
    print("serving %s tcp %s udp %s" % (address, tcp, udp), file=sys.stderr)
    try:
        if seconds:
            time.sleep(seconds)
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    stop.set()


# An ICMP error came back, as a rejecting firewall sends: host or network unreachable (the numbers differ between
# Linux, the BSDs and macOS, and Windows, whose sockets report WSA codes).
_UNREACHABLE = {getattr(errno, n) for n in ("EHOSTUNREACH", "ENETUNREACH", "WSAEHOSTUNREACH", "WSAENETUNREACH") if hasattr(errno, n)}


def _udp_rejected(error):
    """An ICMP error answered a UDP datagram: unreachable, or the port closed (Linux reports that as ECONNREFUSED on a
    connected socket, Windows as WSAECONNRESET on any socket)."""
    return error.errno in _UNREACHABLE or isinstance(error, (ConnectionRefusedError, ConnectionResetError))


def _answer(data, reply):
    """What the other side's probe said: its address, and the one the connection came from as it saw it."""
    if reply is None or not data.startswith(MAGIC):
        return
    words = data[len(MAGIC):].decode("ascii", "replace").split()
    if words:
        reply["answered_by"] = words[0]
    if len(words) > 1:
        reply["seen_as"] = words[1]


def _read_line(sock, timeout):
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\n" not in data and len(data) < 512:
            chunk = sock.recv(512)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass  # (no answer, or not a probe: sshd waits for the client to speak first)
    return data


def try_tcp(source, destination, port, timeout, reply=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.bind((source, 0))
        except OSError:
            return "error"  # (not an address of this host)
        try:
            sock.connect((destination, port))
            if reply is not None:
                _answer(_read_line(sock, min(timeout, 1.5)), reply)
            return "passed"
        except ConnectionRefusedError:
            return "refused"
        except socket.timeout:
            return "blocked"
        except OSError as error:
            return "refused" if error.errno in _UNREACHABLE else "error"
    finally:
        sock.close()


def try_udp(source, destination, port, timeout, tries=2, reply=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout / tries)
    try:
        try:
            sock.bind((source, 0))
        except OSError:
            return "error"
        for _ in range(tries):
            try:
                sock.sendto(MAGIC + source.encode(), (destination, port))
                data, _ = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError as error:
                if _udp_rejected(error):
                    return "blocked"  # (an ICMP error: rejected on the way, or no answer from the port)
                return "error"
            if data.startswith(MAGIC):
                _answer(data, reply)
                return "passed"
        return "blocked"
    finally:
        sock.close()


# Echo requests per ICMP flow: one reply is enough. One request lost on the way (the vSRX's first run that forwarded:
# one of 128 flows, a ping, blocked, while the TCP and UDP flows of the host passed) is not a block; a firewall that
# blocks drops both. UDP has two tries as well, TCP the kernel's own.
ECHOES = 2


def ping_command(source, destination, timeout, platform=None):
    """Echo requests from source, as the ping of this system takes them; it exits 0 when one is answered."""
    platform = platform or sys.platform
    count = str(ECHOES)
    if platform.startswith("win"):
        return ["ping", "-n", count, "-w", str(max(1, int(timeout * 1000))), "-S", source, destination]
    if platform.startswith(("darwin", "freebsd", "openbsd", "netbsd")):  # (-W in milliseconds there, -S the source)
        return ["ping", "-n", "-c", count, "-W", str(max(1, int(timeout * 1000))), "-S", source, destination]
    return ["ping", "-n", "-c", count, "-W", str(max(1, int(timeout))), "-I", source, destination]


def try_icmp(source, destination, timeout):
    windows = sys.platform.startswith("win")
    try:
        done = subprocess.run(ping_command(source, destination, timeout), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout + ECHOES + 5)  # fmt: skip  (a second apart)
    except (OSError, subprocess.TimeoutExpired):
        return "error"
    if windows:
        # Windows' ping exits 0 also for "destination host unreachable" from a router, and 1 for a wrong option:
        # an echo reply is the line with "TTL=".
        if b"TTL=" in done.stdout.upper():
            return "passed"
        return "blocked" if done.returncode in (0, 1) else "error"
    # ping: 0 a reply, 1 no reply, anything else could not send (no such address, not allowed).
    return "passed" if done.returncode == 0 else "blocked" if done.returncode == 1 else "error"


def selfcheck(address, tcp, udp, timeout=2.0):
    """Every port of this host's probe answers on its test address (over the loopback, not through any firewall)."""
    bad = [("tcp", p) for p in tcp if try_tcp(address, address, p, timeout) != "passed"]
    bad += [("udp", p) for p in udp if try_udp(address, address, p, timeout) != "passed"]
    return bad


def attempt(flow, timeout, reply=None):
    protocol, port = flow["protocol"], flow.get("port")
    if protocol == "tcp":
        return try_tcp(flow["src"], flow["dst"], port, timeout, reply=reply)
    if protocol == "udp":
        return try_udp(flow["src"], flow["dst"], port, timeout, reply=reply)
    if protocol == "icmp":
        return try_icmp(flow["src"], flow["dst"], timeout)
    return "error"


def send(plan, source, timeout, workers):
    flows = [f for f in plan["flows"] if f["src"] == source]
    replies = [{} for _ in flows]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(lambda i: attempt(flows[i], timeout, replies[i]), range(len(flows))))
    out = []
    for flow, outcome, reply in zip(flows, outcomes, replies):
        result = {"id": flow["id"], "observed": outcome}
        if outcome == "passed":
            result.update(reply)
        out.append(result)
    return out


def _ports(text):
    return [int(p) for p in text.split(",") if p.strip()] if text else []


def main(argv=None):
    parser = argparse.ArgumentParser(prog="probe.py", description="The probe of the FWShift lab")
    sub = parser.add_subparsers(dest="command")
    s = sub.add_parser("serve")
    s.add_argument("--bind", required=True)
    s.add_argument("--tcp", default="")
    s.add_argument("--udp", default="")
    s.add_argument("--seconds", type=int, default=0)
    c = sub.add_parser("selfcheck")
    c.add_argument("--bind", required=True)
    c.add_argument("--tcp", default="")
    c.add_argument("--udp", default="")
    t = sub.add_parser("send")
    t.add_argument("--plan", required=True)
    t.add_argument("--source", required=True)
    t.add_argument("--timeout", type=float, default=3.0)
    t.add_argument("--workers", type=int, default=16)
    args = parser.parse_args(argv)
    if args.command == "serve":
        serve(args.bind, _ports(args.tcp), _ports(args.udp), args.seconds)
        return 0
    if args.command == "selfcheck":
        bad = selfcheck(args.bind, _ports(args.tcp), _ports(args.udp))
        if bad:
            print("not answering: " + ", ".join("%s/%d" % b for b in bad), file=sys.stderr)
        return 1 if bad else 0
    if args.command == "send":
        with open(args.plan) as handle:
            plan = json.load(handle)
        json.dump(send(plan, args.source, args.timeout, args.workers), sys.stdout)
        print()
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
