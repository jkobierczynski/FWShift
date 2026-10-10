# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ground truth for iptables: forward real packets through the kernel and compare with the model.

The unit tests compare the model with a simulator of iptables. This script
asks netfilter itself. It builds three veth pairs in the current network
namespace, loads a ruleset with ``iptables-restore``, injects packets on one
pair and watches whether they come out of another.

Two things are checked, with the generators of ``tests/test_iptables.py``:

* emitter: a random model is written for iptables; the kernel must forward
  exactly the packets the model allows;
* parser: a random hand-written ruleset is loaded; the kernel must forward
  exactly the packets that the model read from it allows.

Half of the packets are random, the other half are aimed at an allow rule of
the model, so that "forwarded" is tested about as often as "dropped".

Run it as root on Linux, in a network namespace of its own so that nothing of
the host is touched (needs iptables and the ``pyroute2`` package)::

    unshare -n python3 tests/tools/kernel_check.py [number of rulesets, default 10]

It is not part of the test suite: it needs root and a kernel with netfilter.
"""

from __future__ import annotations

import os
import random
import select
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from pyroute2 import IPRoute  # noqa: E402
from test_iptables import ZONES, Packet, model_allows, random_model, random_packet, random_ruleset  # noqa: E402

from fwshift import cli, transform  # noqa: E402
from fwshift.model import ANY, Action, Policy, Protocol  # noqa: E402
from fwshift.parsers import iptables as parse_iptables  # noqa: E402
from fwshift.report import Report  # noqa: E402

PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}
WAIT = 0.04  # seconds to wait for a packet that may have been dropped


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_packet(pkt: Packet) -> bytes:
    """An IPv4 packet that opens a connection: a TCP SYN, a UDP datagram, an ICMP request, or a bare protocol."""
    src, dst = socket.inet_aton(pkt.src), socket.inet_aton(pkt.dst)
    number = PROTOCOLS.get(pkt.proto) or int(pkt.proto)
    if pkt.proto == "tcp":
        header = struct.pack("!HHIIBBHHH", pkt.sport, pkt.dport, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(header))
        payload = header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]
    elif pkt.proto == "udp":
        header = struct.pack("!HHHH", pkt.sport, pkt.dport, 8, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 17, 8)
        payload = header[:6] + struct.pack("!H", checksum(pseudo + header) or 0xFFFF)
    elif pkt.proto == "icmp":
        body = struct.pack("!BBHHH", pkt.icmp_type, 0, 0, 1, 1) + b"\x00" * 12
        payload = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    else:
        payload = struct.pack("!HH", 0, 0x0800) + b"\x00" * 20  # as much as a GRE header
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, number, 0, src, dst)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


class Lab:
    """A router with interfaces eth0, eth1, eth2; behind each a wire end h0, h1, h2 to talk to."""

    def __init__(self) -> None:
        self.ipr = IPRoute()
        self.index: Dict[str, int] = {}
        self.mac: Dict[str, bytes] = {}
        self.wire: Dict[str, socket.socket] = {}
        for zone in ZONES:
            end = "h" + zone[-1]
            self.ipr.link("add", ifname=zone, kind="veth", peer=end)
            for name in (zone, end):
                link = self.ipr.link_lookup(ifname=name)[0]
                self.ipr.link("set", index=link, state="up")
                self.index[name] = link
                address = self.ipr.get_links(link)[0].get_attr("IFLA_ADDRESS")
                self.mac[name] = bytes.fromhex(address.replace(":", ""))
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            sock.bind((end, 0))
            sock.setblocking(False)
            self.wire[zone] = sock
        for path, value in [("ip_forward", "1"), ("conf/all/rp_filter", "0"), ("conf/default/rp_filter", "0")] + [
            (f"conf/{zone}/rp_filter", "0") for zone in ZONES
        ]:
            Path("/proc/sys/net/ipv4", path).write_text(value)
        self.routed: Set[Tuple[str, str]] = set()

    def load(self, ruleset: str) -> None:
        done = subprocess.run(["iptables-restore"], input=ruleset.encode(), capture_output=True)
        if done.returncode:
            raise SystemExit(f"iptables-restore refused the ruleset:\n{done.stderr.decode()}\n{ruleset}")

    def forwards(self, pkt: Packet) -> bool:
        """Send the packet in on its input interface; True when it comes out of its output interface."""
        if (pkt.dst, pkt.out_if) not in self.routed:
            self.ipr.route("replace", dst=pkt.dst + "/32", oif=self.index[pkt.out_if])
            wire_mac = ":".join(f"{byte:02x}" for byte in self.mac["h" + pkt.out_if[-1]])
            self.ipr.neigh("replace", dst=pkt.dst, lladdr=wire_mac, ifindex=self.index[pkt.out_if], state=0x80)
            self.routed = {entry for entry in self.routed if entry[0] != pkt.dst} | {(pkt.dst, pkt.out_if)}
        out = self.wire[pkt.out_if]
        while select.select([out], [], [], 0)[0]:
            out.recv(4096)  # what is left of earlier packets
        packet = ip_packet(pkt)
        frame = self.mac[pkt.in_if] + self.mac["h" + pkt.in_if[-1]] + b"\x08\x00" + packet
        self.wire[pkt.in_if].send(frame)
        while select.select([out], [], [], WAIT)[0]:
            seen = out.recv(4096)
            # The forwarded copy comes from the router's own interface, with one hop taken off.
            if seen[6:12] == self.mac[pkt.out_if] and seen[26:34] == packet[12:20] and seen[22] == 63:
                return True
        return False


def aimed_packet(model: Policy, rng: random.Random) -> Packet:
    """A packet built to match one allow rule of the model (it may still be caught by a rule above it)."""
    pkt = random_packet(rng, 4)
    allows = [r for r in model.rules if r.enabled and not r.unsupported and r.action == Action.ALLOW]
    if not allows:
        return pkt
    rule = rng.choice(allows)
    if ANY not in rule.src_zones:
        pkt.in_if = rng.choice(rule.src_zones)
    if ANY not in rule.dst_zones:
        pkt.out_if = rng.choice(rule.dst_zones)
    for members, negated, field in ((rule.sources, rule.negate_source, "src"), (rule.destinations, rule.negate_destination, "dst")):
        intervals = [i for member in members for i in transform.known_intervals(model, member)[0] if i[0] == 4 and i[2] < 2**32 - 1]
        if intervals and not negated:
            _, first, last = rng.choice(intervals)
            setattr(pkt, field, socket.inet_ntoa(struct.pack("!I", rng.randint(first, last))))
    entries = [e for name in rule.services for e in (transform.flatten_services(model, name) or [])]
    if entries and not rule.negate_service:
        entry = rng.choice(entries)
        if entry.protocol in (Protocol.TCP, Protocol.UDP):
            first, _, last = rng.choice((entry.dst_ports or "1-65535").split(",")).partition("-")
            pkt.proto, pkt.dport = entry.protocol.value, rng.randint(int(first), int(last or first))
            if entry.src_ports:
                first, _, last = entry.src_ports.split(",")[0].partition("-")
                pkt.sport = int(first)
        elif entry.protocol == Protocol.ICMP:
            pkt.proto, pkt.icmp_type = "icmp", 8 if entry.icmp_type is None else entry.icmp_type
        elif entry.protocol == Protocol.IP and entry.ip_protocol not in (None, 1, 6, 17):
            pkt.proto = str(entry.ip_protocol)
    return pkt


def usable(pkt: Packet, replied: Set[Tuple[str, str, str]]) -> bool:
    """Packets that open a connection whatever was sent before."""
    if pkt.proto == "icmp6" or (pkt.proto == "icmp" and pkt.icmp_type not in (8, 13)):
        return False  # an ICMP reply without a request is INVALID to conntrack, not a new connection
    if pkt.proto not in ("tcp", "udp") and (pkt.dst, pkt.src, pkt.proto) in replied:
        return False  # would be the reply to an earlier packet, and so ESTABLISHED
    return True


def compare(
    lab: Lab, model: Policy, ruleset: str, rng: random.Random, packets: int, what: str, replied: Set[Tuple[str, str, str]]
) -> Tuple[int, int]:
    """``replied`` lives as long as the connection table of the kernel: for the whole run."""
    lab.load(ruleset)
    checked = forwarded = 0
    for number in range(packets):
        pkt = aimed_packet(model, rng) if number % 2 else random_packet(rng, 4)
        if not usable(pkt, replied):
            continue
        expected, got = model_allows(model, pkt), lab.forwards(pkt)
        if got:
            replied.add((pkt.src, pkt.dst, pkt.proto))
        if expected != got:
            raise SystemExit(f"{what}: the kernel {'forwards' if got else 'drops'} {pkt}, the model says otherwise\n{ruleset}")
        checked += 1
        forwarded += got
    return checked, forwarded


def main(argv: List[str]) -> int:
    if os.geteuid() != 0:
        raise SystemExit("needs root; run it as: unshare -n python3 tests/tools/kernel_check.py")
    count = int(argv[1]) if len(argv) > 1 else 10
    lab = Lab()
    total = forwarded = rulesets = 0
    replied: Set[Tuple[str, str, str]] = set()
    for seed in range(count):
        rng = random.Random(seed)
        model = random_model(rng)
        emitted = cli.convert(model, "iptables", Report())
        checked, passed = compare(lab, model, emitted, rng, 200, f"emitter, seed {seed}", replied)
        total, forwarded, rulesets = total + checked, forwarded + passed, rulesets + 1
        text = random_ruleset(rng)
        parsed = parse_iptables.parse(text.encode(), Report())
        if not any(rule.unsupported for rule in parsed.rules):
            checked, passed = compare(lab, parsed, text, rng, 200, f"parser, seed {seed}", replied)
            total, forwarded, rulesets = total + checked, forwarded + passed, rulesets + 1
    print(
        f"{rulesets} rulesets, {total} packets ({forwarded} forwarded, {total - forwarded} dropped): "
        "the kernel and the model agree on every one"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
