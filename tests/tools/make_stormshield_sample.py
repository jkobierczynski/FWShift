# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/stormshield_sample.tgz: the ConfigFiles of a made-up Stormshield SNS firewall (v4) at a small
office, packed as decbackup unpacks a backup (usr/Firewall/ConfigFiles/...).

Interfaces (out, in, dmz1, lab), objects (hosts, a range, a dual-stack host, a dynamic host, networks, services,
a protocol, an FQDN), groups, two local filter slots (the factory "Block all" and the active one), a global slot that
ends in a deleg, and a [NAT] section. The lines of the [NAT] section are made up: Stormshield does not publish their
syntax, and FWShift does not read them. Every address is a documentation or private address; nothing is taken from a
real firewall. The archive is the same, byte for byte, every time it is written.

    python3 tests/tools/make_stormshield_sample.py
"""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

FILES = {
    "network": """[Config]
IPv6State=0

[ethernet0]
State=1
Name=out
Protected=0
Address=203.0.113.2
Mask=255.255.255.248
Comment=uplink

[ethernet1]
State=1
Name=in
Protected=1
Address=10.10.0.254
Mask=255.255.255.0

[ethernet2]
State=1
Name=dmz1
Protected=1
Address=10.20.0.254
Mask=255.255.255.0

[ethernet3]
State=1
Name=lab
Protected=1
Bridge=bridge0

[bridge0]
State=1
Name=labbridge
Protected=1
Address=10.30.0.254
Mask=255.255.255.0
""",
    "object": """[Host]
web_srv=10.20.0.10,resolve=static# web server
mail_srv=10.20.0.25,resolve=static
web_pub=203.0.113.3,resolve=static# public address of the web server
admin_ws=10.10.0.50,resolve=static
dual_ws=10.10.0.60,2001:db8:10::60# dual stack
dhcp_pool=10.10.0.100-10.10.0.199
updates.example.com=192.0.2.80,resolve=dynamic

[Network]
lan=10.10.0.0/24
lan6=2001:db8:10::/64
lab_net=10.30.0.0/255.255.255.0
blocked=198.51.100.0/24

[Service]
http=80/tcp
https=443/tcp
ssh=22/tcp
dns_udp=53/udp
smtp=25/tcp
ident=113/tcp
web_alt=8080-8090/tcp
syslog=514/udp
lab_tools=5000-5010/any

[Protocol]
proto_200=200

[Fqdn]
www.example.org=192.0.2.90

[Internet]
operator=ne
object=Network_internals
""",
    "objectgroup": """[dmz_servers] # published servers
web_srv
mail_srv

[admins]
admin_ws
dual_ws
""",
    "servicegroup": """[web_ports]# Web
http
https
web_alt
""",
    "Filter/slotinfo": """[Global]
Active=05
Sync=1

[01]
Name="Block all"

[05]
Name="Office"
""",
    "Filter/01": """[Filter]
separator color="c0c0c0" comment="Remote Management" collapse="0" nb_elements="2" first_ruleid="1"
pass from any to firewall_all port firewall_srv,https	# Admin from everywhere
pass ipproto icmp from any to firewall_all	# Allow Ping from everywhere
separator color="c0c0c0" comment="Default policy" collapse="0" nb_elements="1" first_ruleid="3"
block from any to any	# Block all

[NAT]
""",
    "Filter/05": """[Filter]
separator color="c0c0c0" comment="Administration" collapse="0" nb_elements="2" first_ruleid="1"
pass from admins on in to firewall_all port ssh,https	# admin access
pass ipproto icmp from Network_internals to firewall_all	# ping the firewall
separator color="c0c0c0" comment="Outbound" collapse="0" nb_elements="5" first_ruleid="3"
block from any to blocked	# known bad
pass inspection ips log from Network_internals to Internet port web_ports	# web Created on 2026-03-01 10:00:00, by admin (10.10.0.50)
pass ipproto udp from lan on in to any port dns_udp	# dns
reset from Network_internals to any port ident
decrypt from lan to any port https
separator color="c0c0c0" comment="Published servers" collapse="0" nb_elements="2" first_ruleid="8"
pass log from any on out to web_pub port http,https	# public web, as it arrives
pass from any on out to dmz_servers port smtp
separator color="c0c0c0" comment="Lab and users" collapse="0" nb_elements="6" first_ruleid="10"
pass from lab_net on lab to any port lab_tools
pass from group="staff"@lan domain corp.example to dmz_servers port web_ports
pass ipproto proto_200 from lab_net to any
pass from !lan to updates.example.com port https
pass from lan6 to any
pass proto http from lan to www.example.org port http,web_alt
block from any to any	# Block all

[NAT]
nat from lan on in to Internet on out -> from Firewall_out port ephemeral_fw	# made up: the syntax is not published
""",
    "Global/Filter/slotinfo": """[Global]
Active=01
""",
    "Global/Filter/01": """[Filter]
separator color="c0c0c0" comment="Company rules" collapse="0" nb_elements="2" first_ruleid="1"
block from global_bad to any	# blocked company-wide
deleg from any to any	# the rest: the local policy
""",
    "Global/object": """[Network]
global_bad=192.0.2.128/25
""",
}


def build() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(FILES):
            data = FILES[name].encode("utf-8")
            info = tarfile.TarInfo("usr/Firewall/ConfigFiles/" + name)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(data), 1767225600, 0o644, 0, 0
            archive.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as handle:
        handle.write(raw.getvalue())
    return out.getvalue()


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "data" / "stormshield_sample.tgz"
    path.write_bytes(build())
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
