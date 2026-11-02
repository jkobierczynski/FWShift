# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""A small TFTP server (RFC 1350) for the lab: it runs on a test host, and a firewall whose CLI can only export and
import its configuration to and from a URL (WatchGuard: ``export config to tftp://...``) writes and reads its files
here. One folder, plain file names, one transfer at a time; options (RFC 2347) are not answered, so the client falls
back to 512-byte blocks, as the RFC says it must. Python 3.9, standard library only.

usage: python3 tftpd.py FOLDER [ADDRESS [PORT]]   (port 69, the default: run it as root)
"""

from __future__ import annotations

import os
import re
import socket
import struct
import sys
import time

RRQ, WRQ, DATA, ACK, ERROR = 1, 2, 3, 4, 5
BLOCK = 512
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
TIMEOUT, RETRIES = 3.0, 8
LIMIT = 64 * 1024 * 1024


def log(text: str) -> None:
    sys.stdout.write(time.strftime("%H:%M:%S ") + text + "\n")
    sys.stdout.flush()


def error(sock: socket.socket, peer: tuple, code: int, text: str) -> None:
    sock.sendto(struct.pack("!HH", ERROR, code) + text.encode("ascii", "replace") + b"\0", peer)


def send_file(path: str, peer: tuple) -> None:
    """RRQ: the file in blocks, each acknowledged before the next."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    with open(path, "rb") as handle:
        data = handle.read()
    block = 1
    while True:
        chunk = data[(block - 1) * BLOCK:block * BLOCK]
        packet = struct.pack("!HH", DATA, block & 0xFFFF) + chunk
        for _ in range(RETRIES):
            sock.sendto(packet, peer)
            try:
                answer, source = sock.recvfrom(1024)
            except socket.timeout:
                continue
            if source != peer or len(answer) < 4:
                continue
            op, number = struct.unpack("!HH", answer[:4])
            if op == ERROR:
                log(f"read {os.path.basename(path)}: the client stopped ({answer[4:].rstrip(bytes(1)).decode('ascii', 'replace')})")
                return
            if op == ACK and number == block & 0xFFFF:
                break
        else:
            log(f"read {os.path.basename(path)}: no answer to block {block}")
            return
        if len(chunk) < BLOCK:
            log(f"read {os.path.basename(path)}: {len(data)} bytes to {peer[0]}")
            return
        block += 1


def receive_file(path: str, peer: tuple) -> None:
    """WRQ: acknowledges block 0, then each block; the file is written once it is complete."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    parts = []
    size = 0
    expected = 1
    ack = struct.pack("!HH", ACK, 0)
    while True:
        for _ in range(RETRIES):
            sock.sendto(ack, peer)
            try:
                packet, source = sock.recvfrom(BLOCK + 4)
            except socket.timeout:
                continue
            if source != peer or len(packet) < 4:
                continue
            op, number = struct.unpack("!HH", packet[:4])
            if op == ERROR:
                log(f"write {os.path.basename(path)}: the client stopped")
                return
            if op == DATA and number == expected & 0xFFFF:
                break
            if op == DATA:  # (a block sent again: acknowledged again)
                sock.sendto(struct.pack("!HH", ACK, number), peer)
        else:
            log(f"write {os.path.basename(path)}: no block {expected}")
            return
        chunk = packet[4:]
        parts.append(chunk)
        size += len(chunk)
        if size > LIMIT:
            error(sock, peer, 3, "too large")
            return
        ack = struct.pack("!HH", ACK, expected & 0xFFFF)
        if len(chunk) < BLOCK:
            sock.sendto(ack, peer)
            with open(path + ".part", "wb") as handle:
                handle.write(b"".join(parts))
            os.replace(path + ".part", path)
            log(f"write {os.path.basename(path)}: {size} bytes from {peer[0]}")
            return
        expected += 1


def serve(folder: str, address: str = "0.0.0.0", port: int = 69) -> None:
    os.makedirs(folder, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))
    log(f"serving {folder} on {address}:{port}")
    while True:
        packet, peer = sock.recvfrom(1024)
        if len(packet) < 4:
            continue
        op = struct.unpack("!H", packet[:2])[0]
        fields = packet[2:].split(b"\0")
        name = fields[0].decode("ascii", "replace").lstrip("/") if fields else ""
        name = name.rsplit("/", 1)[-1]  # (a path in the URL: its file name, in the one folder)
        if op not in (RRQ, WRQ):
            continue
        if not NAME.fullmatch(name):
            error(sock, peer, 2, "file name not allowed")
            log(f"refused {fields[0][:80]!r} from {peer[0]}")
            continue
        path = os.path.join(folder, name)
        if op == RRQ:
            if not os.path.isfile(path):
                error(sock, peer, 1, "file not found")
                log(f"read {name}: not found")
                continue
            send_file(path, peer)
        else:
            receive_file(path, peer)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__ or "")
        sys.exit(2)
    serve(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0", int(sys.argv[3]) if len(sys.argv) > 3 else 69)
