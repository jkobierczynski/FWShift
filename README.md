# FWShift

Multi-vendor firewall policy converter. It reads a firewall configuration,
turns it into a vendor-neutral model, and writes it out for another platform,
together with a report that says, rule by rule, what was converted exactly,
what was approximated and what a person has to look at.

| | Read | Write |
|---|---|---|
| Palo Alto PAN-OS / Panorama | XML configuration export | `set` commands |
| Fortinet FortiOS | configuration backup (CLI text) | CLI configuration |
| Check Point | planned | planned |

Pure Python, standard library only, Python 3.9 or newer.

> **Status: alpha (0.1).** The converter is tested against synthetic
> configurations and its own parsers, and went through three rounds of
> adversarial review. The emitted configuration has **not yet been loaded on
> real PAN-OS or FortiOS devices**, and several conversion rules rest on vendor
> behaviour taken from documentation rather than from a lab. Treat the output
> as a draft for a lab, read the report, and never paste it into production
> unreviewed.

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
* Nothing missing or unknown is read as "any": a rule without a source, a
  FortiOS policy attribute the converter does not know, a port list it cannot
  read, all end up in the report instead of in a wider rule.

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

# What did the parser read?
fwshift inspect fgt-backup.conf
```

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

Two synthetic configurations to try it on are in [`tests/data`](tests/data),
with their conversions in [`tests/data/expected`](tests/data/expected).

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

Not converted, and reported where a rule depends on it: security profiles,
schedules, user and group matches, URL categories, HIP profiles, application
filters, wildcard-mask and geography addresses, external dynamic lists,
internet-service (ISDB) policies, load-balancing virtual IPs, NAT64/NAT46,
routing, interfaces, VPN, and everything else outside the policy.

## Roadmap

1. Validation of the output on PAN-OS and FortiOS lab devices.
2. Check Point (Management API export in, `mgmt_cli` or API calls out).
3. FortiOS output with per-policy NAT as an alternative to central NAT.
4. Service correction for port-translating NAT; schedules; user and group mapping.
5. PAN-OS `set`-format input.
6. Differential check: evaluate source and converted policy against sample
   flows and report every flow whose verdict changed.

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
