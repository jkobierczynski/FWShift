# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/panos_logged.xml and tests/data/panos_logged.log: made-up PAN-OS traffic logs for its rules.

panos_logged.xml is panos_sample.xml with a log forwarding profile on every security rule but Not-From-Guests: a
firewall sends the traffic logs of a rule to syslog only through one.

90 days (2026-07-03 to 2026-09-30) of one firewall (serial 012801000001, device name pa-edge, vsys1), in the
syslog form of PAN-OS 10.2 (115 fields; the high resolution timestamp carries the offset, +02:00) behind a BSD
header. Between them: threat logs, a line of another virtual system, lines of the default rules, a start whose end
names another rule (the application changed), a start without an end, a line with the flag of a temporary match.
Every address is a documentation or private address.

    python3 tests/tools/make_panos_logs.py
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import List

DATA = Path(__file__).resolve().parents[1] / "data"
START = datetime.datetime(2026, 7, 3)
DAYS = 90
SERIAL = "012801000001"
ZONE = datetime.timezone(datetime.timedelta(hours=2))


def traffic(moment: datetime.datetime, subtype: str, src: str, dst: str, rule: str, app: str, zones: str, session: int, port: int,
            proto: str = "tcp", action: str = "allow", user: str = "", vsys: str = "vsys1", flags: str = "0x400019",
            repeat: int = 1, started: datetime.datetime = START) -> str:  # fmt: skip
    """One TRAFFIC line of 115 fields, in the order of the PAN-OS documentation."""
    when = moment.strftime("%Y/%m/%d %H:%M:%S")
    begun = (started if started != START else moment).strftime("%Y/%m/%d %H:%M:%S")
    source_zone, destination_zone = zones.split(">")
    reason = "n/a" if subtype == "start" else "policy-deny" if action != "allow" else "tcp-fin"
    fields = [""] * 115
    fields[0:31] = ["1", when, SERIAL, "TRAFFIC", subtype, "2562", when, src, dst, "", "", rule, user, "", app, vsys, source_zone,
                    destination_zone, "ethernet1/2", "ethernet1/1", "default", when, str(session), str(repeat), str(40000 + session % 20000),
                    str(port), "0", "0", flags, proto, action]  # fmt: skip
    fields[31:47] = ["1200", "600", "600", "12", begun, "4", "any", "", str(7000000000 + session), "0x0", "10.0.0.0-10.255.255.255",
                     "Reserved", "", "6", "6", reason]  # fmt: skip
    fields[47:54] = ["0", "0", "0", "0", "", "pa-edge", "from-policy"]
    fields[102] = moment.replace(tzinfo=ZONE).isoformat(timespec="milliseconds")
    return f"<14>{moment.strftime('%b %e %H:%M:%S')} pa-edge.example.net " + ",".join(fields)


def config() -> None:
    text = (DATA / "panos_sample.xml").read_text(encoding="utf-8")
    head, rules, tail = re.split(r"(<security>.*?</security>)", text, maxsplit=1, flags=re.S)
    rules = re.sub(r'(<entry name="(?!Not-From-Guests")[^"]*">.*?<action>[a-z-]+</action>)', r"\1<log-setting>to-syslog</log-setting>",
                   rules, flags=re.S)  # fmt: skip
    path = DATA / "panos_logged.xml"
    path.write_text(head + rules + tail, encoding="utf-8")
    print(f"wrote {path}")


def main() -> None:
    config()
    lines: List[str] = []
    session = 0
    for day in range(DAYS):
        noon = START + datetime.timedelta(days=day, hours=12)

        def add(minute: int, subtype: str, *args: object, **kwargs: object) -> None:
            nonlocal session
            session += 1
            lines.append(traffic(noon + datetime.timedelta(minutes=minute), subtype, *args, session=session, **kwargs))  # type: ignore[arg-type]

        add(1, "end", "10.10.4.20", "203.0.113.200", "Allow-Web-Out", "ssl", "trust>untrust", port=443)
        add(2, "end", "10.10.4.20", "192.0.2.53", "Allow-DNS", "dns", "trust>untrust", port=53, proto="udp")
        if day % 3 == 0:
            # Inbound-Web logs at the start and at the end of a session: one connection.
            moment = noon + datetime.timedelta(minutes=3)
            session += 1
            lines.append(traffic(moment, "start", "198.51.100.80", "203.0.113.10", "Inbound-Web", "ssl", "untrust>dmz", session, 443))
            lines.append(traffic(moment + datetime.timedelta(seconds=20), "end", "198.51.100.80", "203.0.113.10", "Inbound-Web", "ssl",
                                 "untrust>dmz", session, 443, started=moment))  # fmt: skip
            add(4, "end", "10.10.5.12", "10.20.0.10", "Admin-SSH", "ssh", "trust>dmz", port=22, user="example\\alice")
        if day % 7 == 0:
            add(5, "end", "198.51.100.25", "203.0.113.25", "Inbound-Mail", "smtp", "untrust>dmz", port=25)
            add(6, "deny", "10.30.1.5", "198.51.100.9", "Block-OT-Outbound", "web-browsing", "ot>untrust", port=80, action="deny")
            add(7, "drop", "10.10.4.30", "198.51.100.200", "Block-Region", "incomplete", "trust>untrust", port=443, action="drop",
                repeat=3)  # (three sessions in one line)
            add(8, "end", "10.10.4.31", "10.20.0.10", "App-Server-Ports", "web-browsing", "trust>dmz", port=8443)
        if day % 10 == 0:
            add(9, "deny", "10.20.0.10", "10.20.0.25", "DMZ-Intrazone", "ssh", "dmz>dmz", port=22, action="deny")
            add(10, "drop", "198.51.100.66", "10.20.0.10", "interzone-default", "incomplete", "untrust>dmz", port=3389, action="drop")
            # The updates of the tagged servers: a temporary match only (flag 0x2000), possible.
            add(11, "end", "10.20.0.10", "198.51.100.30", "Tagged-Servers-Updates", "ssl", "dmz>untrust", port=443, flags="0x402019")
        # Lines that are no connection of the policy.
        add(20, "end", "10.50.0.5", "203.0.113.200", "Allow-Web-Out", "ssl", "trust>untrust", port=443, vsys="vsys2")
        lines.append(f"<14>{(noon + datetime.timedelta(minutes=21)).strftime('%b %e %H:%M:%S')} pa-edge.example.net 1,"
                     f"{(noon + datetime.timedelta(minutes=21)).strftime('%Y/%m/%d %H:%M:%S')},{SERIAL},THREAT,vulnerability,2562,"
                     f"{(noon + datetime.timedelta(minutes=21)).strftime('%Y/%m/%d %H:%M:%S')},198.51.100.80,203.0.113.10,,,Inbound-Web,,,"
                     "ssl,vsys1,untrust,dmz,ethernet1/1,ethernet1/2,default")  # fmt: skip
    # The application changed: the start names Allow-Web-Out, the end App-Server-Ports. Both rules matched it.
    moment = START + datetime.timedelta(days=45, hours=13)
    session += 1
    lines.append(traffic(moment, "start", "10.10.4.40", "10.20.0.10", "Allow-Web-Out", "ssl", "trust>dmz", session, 8443))
    lines.append(traffic(moment + datetime.timedelta(minutes=2), "end", "10.10.4.40", "10.20.0.10", "App-Server-Ports", "web-browsing",
                         "trust>dmz", session, 8443, started=moment))  # fmt: skip
    # A start without an end: the session was still open when the file ends; possible only.
    session += 1
    lines.append(traffic(START + datetime.timedelta(days=89, hours=23), "start", "198.51.100.81", "203.0.113.10", "Inbound-Mail", "smtp",
                         "untrust>dmz", session, 25))  # fmt: skip
    # The disabled rule, once.
    session += 1
    lines.append(traffic(START + datetime.timedelta(days=50, hours=9), "end", "10.20.1.2", "198.51.100.40", "Old-Rule", "syslog",
                         "trust>untrust", session, 514, proto="udp"))  # fmt: skip
    path = DATA / "panos_logged.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
