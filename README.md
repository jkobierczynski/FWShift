# FWShift

Multi-vendor firewall policy converter. It reads a firewall configuration,
turns it into a vendor-neutral model, and writes it out for another platform,
together with a report that says, rule by rule, what was converted exactly,
what was approximated and what a person has to look at.

| | Read | Write |
|---|---|---|
| Palo Alto PAN-OS / Panorama | XML configuration export | `set` commands |
| Fortinet FortiOS | configuration backup (CLI text) | CLI configuration |
| Check Point | Management API export (JSON) | shell script of `mgmt_cli` calls |
| Linux iptables / ip6tables | `iptables-save` output | `iptables-restore` file |

Pure Python, standard library only, Python 3.9 or newer.

> **Status: alpha (0.2).** The converter is tested against synthetic
> configurations and went through several rounds of adversarial review.
>
> * **iptables** is checked against the real thing: generated rulesets are
>   loaded into a Linux kernel, and real packets forwarded through it are
>   compared with the model, in both directions. That covers the IPv4 filter
>   rules on one kernel (iptables 1.8.10, nf_tables backend); NAT rules and
>   IPv6 rulesets are loaded but no packets are sent through them.
> * **PAN-OS, FortiOS and Check Point** output has **not been loaded on a
>   device or management server**, and the Check Point input format is taken
>   from the API documentation, not from a real export. Several conversion
>   rules rest on vendor behaviour taken from documentation rather than from a
>   lab.
>
> Treat the output as a draft for a lab, read the report, and never load it in
> production unreviewed.

## Documentation

* **[User manual](docs/MANUAL.md)**: getting a configuration out of the
  source firewall, every command and option, how to read the report, a
  reference of all findings, how each difference between the platforms is
  handled, and how to load the result.
* **[DEVELOPMENT.md](DEVELOPMENT.md)**: architecture, the rules the code
  follows, how to add a vendor, testing, and the development log.

## Why

Every vendor ships a migration tool that converts *into* its own platform.
FWShift converts in any direction between the platforms it knows, and adding a
platform costs one parser and one emitter instead of one converter per pair.

The hard part of a migration is not syntax, it is semantics: the same rule
means something different on each platform. FWShift's rule is:

**A conversion never makes the policy more permissive without saying so.**

* A rule whose match cannot be expressed on the target is still emitted, in its
  original position, but **disabled**, and listed as *needs review*.
* A deny rule that could not be converted is reported loudly, because the allow
  rules below it then match more than they did.
* An approximation that is enabled (an application reduced to its ports, for
  example) is listed as *approximated* with what was lost.
* Objects that cannot be converted become placeholders that match nothing, so
  the output still loads and every reference stays visible.
* Nothing missing or unknown is read as "any": a rule without a source, an
  object that is not in the export, a port list or a match module the
  converter cannot read, all end up as a disabled rule in the report instead
  of as a wider rule. A rule attribute the converter does not know is reported
  for review on that rule.

## Install

```sh
pip install .            # or: pip install -e ".[dev]" for development
fwshift --version
```

Without installing: `PYTHONPATH=src python3 -m fwshift ...`.

## Quick start

```sh
# PAN-OS to FortiOS
fwshift convert running-config.xml --to fortios -o fortigate.conf --report report.txt

# FortiOS to PAN-OS, naming the zones and the interface of the target
fwshift convert fgt-backup.conf --to panos -o panos.set --report report.txt \
    --zone-map wan1=untrust --zone-map lan=trust --interface-map wan1=ethernet1/1

# Check Point to PAN-OS (NAT rules need a destination zone there)
fwshift convert checkpoint.json --to panos -o panos.set --report report.txt --target-nat-zone untrust

# PAN-OS to iptables: one file per IP version, zones mapped to interfaces
fwshift convert running-config.xml --to iptables  -o rules.v4 --zone-map trust=eth1 --zone-map untrust=eth0
fwshift convert running-config.xml --to ip6tables -o rules.v6 --zone-map trust=eth1 --zone-map untrust=eth0

# iptables to Check Point: a script of mgmt_cli calls that publishes nothing
fwshift convert rules.v4 --to checkpoint -o checkpoint.sh --report report.txt --target-prefix mig_

# What did the parser read?
fwshift inspect fgt-backup.conf
```

The [manual](docs/MANUAL.md#3-getting-the-source-configuration) shows how to
get the input for each platform; for Check Point that is three `mgmt_cli show`
calls.

The report starts with a summary and then lists every rule that is not exact:

```
Summary
  Security rules:     14   exact 3, approximated 5, needs review 6 (5 emitted disabled), skipped 0
  NAT rules:           5   exact 4, approximated 1, needs review 0, skipped 0

Security rules
  Admin-SSH  ->  needs-review, emitted disabled
      [approximated] APP_TO_PORTS: applications ssh reduced to their well-known ports; ...
      [needs-review] USER_MATCH: source user match example\netadmins is not converted.
```

Four synthetic configurations to try it on, one per format, are in
[`tests/data`](tests/data), with their conversions in
[`tests/data/expected`](tests/data/expected).

## What is converted

| | PAN-OS | FortiOS |
|---|---|---|
| Address objects | IP/netmask, range, FQDN; IPv4 and IPv6 | subnet, range, FQDN; `address` and `address6` |
| Address groups | static, nested; dynamic kept only PAN-OS to PAN-OS | static, nested; `addrgrp` and `addrgrp6` |
| Services | TCP, UDP, SCTP with port lists and source ports | the same, plus ICMP, ICMPv6 and IP-protocol services |
| Service groups | yes | yes |
| Security rules | zones, addresses, negation, applications, services, action, logging, rule type, disabled, description, tags | interfaces/zones, addresses, negation, services, action, logging, status, comments |
| NAT | source (interface, pool, static, bi-directional), destination with port, no-NAT | per-policy NAT, IP pools, virtual IPs with port forwarding, central SNAT |
| Scope | vsys, `shared`, Panorama device-group hierarchy with pre/post rulebases | single VDOM or one VDOM of a multi-VDOM backup |

| | Check Point | iptables |
|---|---|---|
| Address objects | host, network, address range, DNS domain; gateways by their main address | none: addresses are written into the rules |
| Address groups | group, nested | read: none. Written: one chain per list |
| Services | TCP, UDP, SCTP with source ports, ICMP, ICMPv6, IP protocol | protocol, port lists, ICMP type and code |
| Service groups | yes | none |
| Security rules | one ordered layer with its inline layers flattened; zones in cells, negation, action, track, disabled, install-on reported | `FORWARD` chain with the chains it jumps to flattened; interfaces as zones, negation, connection state |
| NAT | manual and automatic rules: hide, static, port translation, no-NAT | `DNAT`, `SNAT`, `MASQUERADE` and exemptions of the `nat` table (IPv4) |
| Scope | one access layer and the NAT rulebase of one policy package | one IP version per file |

Not converted, and reported where a rule depends on it: security profiles,
schedules, user and group matches, URL categories, HIP profiles, application
filters, wildcard-mask and geography addresses, external dynamic lists,
internet-service (ISDB) policies, load-balancing virtual IPs, NAT64/NAT46,
Check Point access roles, application objects, VPN communities and implied
rules, iptables match modules beyond addresses, ports and state, the `INPUT`
and `OUTPUT` chains, routing, interfaces, VPN, and everything else outside the
policy.

## Roadmap

1. Validation of the output on PAN-OS and FortiOS lab devices, a Check Point
   management server and a Linux host.
2. FortiOS output with per-policy NAT as an alternative to central NAT.
3. Service correction for port-translating NAT; schedules; user and group mapping.
4. PAN-OS `set`-format input; nftables.
5. Differential check for every format: evaluate source and converted policy
   against sample flows and report every flow whose verdict changed. The test
   suite does this today for iptables and Check Point.

## Licence

Copyright (C) 2026 Jurgen Kobierczynski

FWShift is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

FWShift is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License in
[LICENSE](LICENSE) for more details.

**Test data is synthetic.** Every configuration in this repository is written
by hand with documentation address ranges. Do not add configurations from real
networks, anonymised or not.
