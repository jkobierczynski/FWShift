# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/iptables_logged.log: made-up kernel lines of the LOG rule of iptables_logged.rules.

90 days (2026-07-03 to 2026-09-30) of one host, fw1, in the old syslog form (no year: give --log-year 2026), with
the firewall's own packets and a few lines that are no LOG lines between them. Every address is a documentation
or private address.

    python3 tests/tools/make_iptables_logs.py
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import List

DATA = Path(__file__).resolve().parents[1] / "data"
START = datetime.datetime(2026, 7, 3)
DAYS = 90


def kernel(moment: datetime.datetime, uptime: float, fields: str) -> str:
    return f"{moment.strftime('%b %e %H:%M:%S')} fw1 kernel: [{uptime:.6f}] fw-new {fields}"


def tcp(i: str, o: str, src: str, dst: str, port: int, number: int) -> str:
    return (f"IN={i} OUT={o} MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=63 "
            f"ID={number} DF PROTO=TCP SPT={40000 + number % 20000} DPT={port} WINDOW=64240 RES=0x00 SYN URGP=0")


def main() -> None:
    lines: List[str] = []
    number = 0
    for day in range(DAYS):
        noon = START + datetime.timedelta(days=day, hours=12)
        uptime = 86400.0 * day + 43200

        def add(minute: int, fields: str) -> None:
            nonlocal number
            number += 1
            lines.append(kernel(noon + datetime.timedelta(minutes=minute), uptime + minute * 60, fields))

        add(1, tcp("eth1", "eth0", "10.10.4.20", "203.0.113.200", 443, number))
        add(2, f"IN=eth1 OUT=eth0 SRC=10.10.4.20 DST=192.0.2.53 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID={number} PROTO=UDP SPT=53001 DPT=53 LEN=40")
        if day % 3 == 0:
            add(3, tcp("eth0", "eth2", "192.0.2.80", "10.20.0.10", 8443, number))
            add(4, tcp("eth1", "eth2", "10.10.5.12", "10.20.0.10", 22, number))
        if day % 7 == 0:
            add(5, tcp("eth1", "eth0", "10.10.4.22", "192.0.2.25", 25, number))  # the rate-limited rule: possible
            add(6, f"IN=eth1 OUT=eth2 SRC=10.10.4.23 DST=10.20.0.10 LEN=84 TOS=0x00 PREC=0x00 TTL=63 ID={number} DF PROTO=ICMP TYPE=8 CODE=0 "
                   f"ID=7 SEQ={number}")
            add(7, tcp("eth2", "eth0", "10.20.0.5", "203.0.113.9", 80, number))  # no rule: the default drops it
        if day % 10 == 0:
            add(8, tcp("eth0", "eth1", "198.51.100.66", "10.10.4.20", 443, number))  # the bad host
            add(9, f"IN=eth1 OUT=eth0 SRC=10.10.4.24 DST=198.51.100.5 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID={number} PROTO=47")
        # The firewall's own packets, and other kernel lines.
        add(20, tcp("eth1", "", "10.10.4.20", "10.10.4.1", 22, number))
        lines.append(f"{(noon + datetime.timedelta(minutes=21)).strftime('%b %e %H:%M:%S')} fw1 systemd[1]: Started Daily apt download activities.")
    path = DATA / "iptables_logged.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
