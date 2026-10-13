# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/nftables_sample.nft and nftables_sample.json: a made-up ruleset, as the kernel gives it back.

The ruleset below is loaded with 'nft -f' into a network namespace of its own and listed with 'nft list ruleset'
and 'nft -j list ruleset', so the files are what nft itself prints. It needs nft and root (for unshare -n).

Every address is a documentation or private address. Not taken from any real host.

    sudo python3 tests/tools/make_nftables_sample.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

RULESET = r"""
flush ruleset
table inet raw {
	chain prerouting {
		type filter hook prerouting priority raw; policy accept;
		fib saddr . iif oif missing counter drop comment "Reverse path filter"
	}
}
table inet f2b {
	set banned {
		type ipv4_addr
		flags timeout
	}
	chain forward {
		type filter hook forward priority filter - 5; policy accept;
		ip saddr @banned counter drop comment "Banned by fail2ban"
	}
}
table inet filter {
	set blocked {
		type ipv4_addr
		flags interval
		elements = { 198.51.100.66, 192.0.2.128/25 }
	}
	set admins {
		type ipv4_addr
		flags interval
		elements = { 10.10.5.10-10.10.5.20 }
	}
	set dmz_v6 {
		type ipv6_addr
		elements = { 2001:db8:20::10, 2001:db8:20::25 }
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state established,related accept
		iifname "eth1" tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		ip saddr @blocked counter drop comment "Block bad hosts"
		ct state vmap { invalid : drop, established : accept, related : accept }
		iifname vmap { "eth1" : jump from_lan, "eth3" : jump from_ot }
		iifname "eth0" oifname "eth2" ip daddr 10.20.0.10 tcp dport 8443 ct state new counter accept comment "Inbound web"
		iifname "eth0" oifname "eth2" ip daddr 10.20.0.25 tcp dport 25 ct state new counter accept comment "Inbound mail"
		iifname "eth0" oifname "eth2" ip6 daddr @dmz_v6 tcp dport { 25, 443 } ct state new counter accept comment "Inbound IPv6"
		iifname "eth2" oifname "eth0" ip daddr != 10.0.0.0/8 tcp dport { 80, 443 } ct state new counter accept comment "DMZ updates"
		icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept comment "ICMPv6 basics"
	}
	chain from_lan {
		oifname "eth0" ip saddr 10.10.200.0/24 counter drop comment "Guests stay in"
		oifname "eth0" tcp dport { 80, 443 } ct state new counter accept comment "LAN web"
		oifname "eth0" meta l4proto { tcp, udp } th dport 53 ct state new counter accept comment "LAN DNS"
		oifname "eth0" tcp dport 25 limit rate 10/minute accept comment "Rate limited mail"
		oifname "eth0" meta l4proto gre accept comment "Partner tunnel"
		oifname "eth2" ip saddr @admins ip daddr 10.20.0.0/24 tcp dport { 22, 3389 } ct state new counter accept comment "Admins"
		oifname "eth2" icmp type echo-request accept comment "Ping the DMZ"
		oifname "eth3" ip saddr 10.10.7.15 ip daddr 10.30.1.0/24 tcp dport 502 ct state new counter accept comment "SCADA to PLCs"
	}
	chain from_ot {
		oifname "eth0" log prefix "ot-out " reject comment "OT no internet"
	}
}
table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" ip daddr 203.0.113.10 tcp dport 443 dnat to 10.20.0.10:8443 comment "Web DNAT"
		iifname "eth0" ip daddr 203.0.113.25 dnat to 10.20.0.25 comment "Mail DNAT"
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" ip saddr 10.10.0.0/16 ip daddr 10.99.0.0/16 accept comment "No NAT to partner"
		oifname "eth0" ip saddr 10.20.0.0/24 snat to 198.51.100.20-198.51.100.23 comment "DMZ out"
		oifname "eth0" ip saddr 10.10.0.0/16 masquerade comment "LAN out"
	}
}
"""

HEADER = """# Synthetic ruleset for FWShift tests, as 'nft list ruleset' prints it. Not taken from any real host.
# Addresses come from RFC 1918, RFC 5737 and RFC 3849 documentation ranges.
# Written by tests/tools/make_nftables_sample.py.
"""


def listed(command: str) -> str:
    script = f"nft -f - && {command}"
    done = subprocess.run(["unshare", "-n", "sh", "-c", script], input=RULESET.encode(), capture_output=True, check=True)
    return done.stdout.decode()


def main() -> None:
    data = Path(__file__).resolve().parent.parent / "data"
    (data / "nftables_sample.nft").write_text(HEADER + listed("nft list ruleset"), encoding="utf-8")
    document = json.loads(listed("nft -j list ruleset"))
    (data / "nftables_sample.json").write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
