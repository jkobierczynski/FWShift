# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/fortios_sample.log: made-up FortiOS traffic logs for the policies of fortios_sample.conf.

90 days (2026-07-03 to 2026-09-30) of one FortiGate (fgt-edge, VDOM root) in its default syslog format, FortiOS 7.2
style (``eventtime`` in nanoseconds, ``tz``). Between them: the implicit deny (policy 0), the FortiGate's own traffic,
event logs, the interim statistics of a long session, a log of a local-in policy, a line of another VDOM, sessions
logged at their start and their end, and a few lines in the form of FortiOS 6.0 (seconds, no ``tz``). Every address
is a documentation or private address.

    python3 tests/tools/make_fortios_logs.py
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import List

DATA = Path(__file__).resolve().parents[1] / "data"
START = datetime.datetime(2026, 7, 3, tzinfo=datetime.timezone(datetime.timedelta(hours=2)))
DAYS = 90
POLICY_1 = "11111111-1111-4111-8111-111111111111"


def header(moment: datetime.datetime, logid: str, kind: str, subtype: str, vd: str = "root") -> str:
    stamp = int(moment.timestamp()) * 1_000_000_000 + 123456789
    return (f'<189>date={moment.strftime("%Y-%m-%d")} time={moment.strftime("%H:%M:%S")} devname="fgt-edge" devid="FGT60F0000000001" '
            f'eventtime={stamp} tz="+0200" logid="{logid}" type="{kind}" subtype="{subtype}" level="notice" vd="{vd}"')


def traffic(moment: datetime.datetime, src: str, sintf: str, dst: str, dintf: str, proto: int, port: int, action: str, policy: int,
            session: int, uuid: str = "", service: str = "", logid: str = "0000000013", vd: str = "root", policytype: str = "policy",
            user: str = "") -> str:  # fmt: skip
    ports = f"srcport={40000 + session % 20000} " if proto in (6, 17) else ""
    target = f"dstport={port} " if proto in (6, 17) else f'icmptype="0x{port:02x}" icmpcode="0x00" ' if proto == 1 else ""
    polu = f'poluuid="{uuid}" ' if uuid else ""
    who = f'user="{user}" ' if user else ""
    return (header(moment, logid, "traffic", "forward", vd) + f' srcip={src} {ports}srcintf="{sintf}" srcintfrole="lan" dstip={dst} {target}'
            f'dstintf="{dintf}" dstintfrole="wan" {polu}sessionid={session} proto={proto} action="{action}" policyid={policy} '
            f'policytype="{policytype}" service="{service}" {who}trandisp="noop" duration=12 sentbyte=1200 rcvdbyte=3400 sentpkt=10 rcvdpkt=9')


def main() -> None:
    lines: List[str] = []
    session = 0
    for day in range(DAYS):
        noon = START + datetime.timedelta(days=day, hours=12)

        def add(minute: int, *args: object, **kwargs: object) -> None:
            nonlocal session
            session += 1
            lines.append(traffic(noon + datetime.timedelta(minutes=minute), *args, session=session, **kwargs))  # type: ignore[arg-type]

        add(1, "10.10.4.20", "port2", "198.51.100.200", "wan1", 6, 443, "close", 1, uuid=POLICY_1, service="HTTPS")
        add(2, "10.10.4.20", "port2", "192.0.2.53", "wan1", 17, 53, "accept", 1, uuid=POLICY_1, service="DNS")
        if day % 3 == 0:
            # Inbound web logs at the start and at the end of a session: one connection. The destination is the virtual IP.
            moment = noon + datetime.timedelta(minutes=3)
            session += 1
            lines.append(traffic(moment, "198.51.100.80", "wan1", "203.0.113.10", "dmz", 6, 8443, "start", 3, session, service="tcp/8443",
                                 logid="0000000015"))  # fmt: skip
            lines.append(traffic(moment + datetime.timedelta(seconds=30), "198.51.100.80", "wan1", "203.0.113.10", "dmz", 6, 8443, "close", 3,
                                 session, service="tcp/8443"))  # fmt: skip
        if day % 7 == 0:
            add(5, "10.30.1.5", "ot", "198.51.100.9", "wan1", 6, 80, "deny", 9, service="HTTP", logid="0000000013")
            add(6, "10.10.4.30", "port2", "198.51.100.66", "wan1", 6, 443, "deny", 0, service="HTTPS")  # the implicit deny
            add(7, "10.10.4.31", "port2", "198.51.100.30", "wan1", 6, 443, "server-rst", 2, service="HTTPS", user="alice")  # (a UTM session)
        if day % 10 == 0:
            add(8, "10.10.5.12", "port2", "10.20.0.10", "dmz", 6, 80, "close", 12, service="HTTP")  # policy 12 does not log: still seen
            add(9, "10.10.5.13", "port2", "10.20.0.25", "dmz", 1, 8, "accept", 0, service="PING")  # an ICMP type, written as 0x08
        # Lines that are no connection of the policy.
        moment = noon + datetime.timedelta(minutes=20)
        lines.append(header(moment, "0000000014", "traffic", "local") + ' srcip=10.10.4.20 srcport=50000 srcintf="port2" dstip=10.10.4.1 '
                     'dstport=443 dstintf="root" sessionid=9 proto=6 action="close" policyid=0 policytype="local-in-policy" service="HTTPS"')
        lines.append(header(moment, "0100032001", "event", "system") + ' logdesc="Admin login successful" user="admin" ui="https(10.10.4.20)" '
                     'action="login" status="success" msg="Administrator admin logged in successfully from https(10.10.4.20)"')
        add(21, "10.10.4.20", "port2", "198.51.100.200", "wan1", 6, 443, "accept", 1, uuid=POLICY_1, service="HTTPS", logid="0000000020")
        add(22, "10.50.0.5", "port5", "198.51.100.200", "wan1", 6, 443, "close", 1, service="HTTPS", vd="tenant2")
        add(23, "10.10.4.20", "port2", "10.10.4.1", "port2", 6, 22, "accept", 1, service="SSH", policytype="local-in-policy")
    # Three lines in the form of FortiOS 6.0: eventtime in seconds, no tz.
    for day in (10, 11, 12):
        moment = START + datetime.timedelta(days=day, hours=15)
        session += 1
        lines.append(f'date={moment.strftime("%Y-%m-%d")} time={moment.strftime("%H:%M:%S")} logid="0000000013" type="traffic" '
                     f'subtype="forward" level="notice" vd="root" eventtime={int(moment.timestamp())} srcip=10.10.4.21 srcport=41000 '
                     f'srcintf="port2" dstip=198.51.100.201 dstport=443 dstintf="wan1" poluuid="{POLICY_1}" sessionid={session} proto=6 '
                     'action="close" policyid=1 policytype="policy" service="HTTPS" devname="fgt-edge" devid="FGT60F0000000001"')
    path = DATA / "fortios_sample.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
