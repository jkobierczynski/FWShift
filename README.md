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
| Cisco ASA (and the running configuration of an FTD, read only) | `show running-config` | ASA commands (9.x) |
| Cisco Secure Firewall (FTD) managed by a Management Center (FMC) | the JSON its REST API returns | a Python script that creates a new policy through the REST API |
| Cisco Secure Firewall (FTD) managed by its Device Manager (FDM) | the configuration export (`.txt` or `.zip`), or the JSON of its REST API | a file for the configuration import |
| Sophos Firewall (SFOS 18 and later) | the export of *Import export* (`.tar` or its `Entities.xml`) | the same, for import |
| pfSense (2.6 and later; CE and Plus) | the configuration backup (`config.xml`) | the areas Aliases, NAT and Firewall Rules, for *Backup & Restore* |
| SonicWall (SonicOS 6.5 and 7) | the settings export (`.exp`) | commands of the SonicOS 7 command line |
| WatchGuard (Fireware 12) | the configuration file of Policy Manager (XML) | its policy part, to merge into a configuration of the target |
| Barracuda CloudGen Firewall (8.0 and later) | the answers of its REST API (JSON) | a shell script that creates the rules through that API |
| Juniper SRX (Junos OS) | `show configuration \| display set`, or the configuration in braces | `set` commands, for `load set` |
| Linux iptables / ip6tables | `iptables-save` output | `iptables-restore` file |

It also **audits** a policy, of any of these formats: rules that allow too
much, rules that never match because earlier rules cover them, unused and
duplicate objects. On its own, or before and after a conversion. And it draws
the **zone matrix** of a policy: what each zone may reach in each other zone,
on which services, through which rules.

Pure Python, standard library only, Python 3.9 or newer.

> **Status: alpha (0.12).** The converter is tested against synthetic
> configurations and went through several rounds of adversarial review.
>
> * **iptables** is checked against the real thing: generated rulesets are
>   loaded into a Linux kernel, and real packets forwarded through it are
>   compared with the model, in both directions. That covers the IPv4 filter
>   rules on one kernel (iptables 1.8.10, nf_tables backend); NAT rules and
>   IPv6 rulesets are loaded but no packets are sent through them.
> * **PAN-OS, FortiOS, Check Point, Cisco ASA, Cisco Secure Firewall,
>   Sophos Firewall, pfSense, SonicWall, WatchGuard, Barracuda and Juniper SRX** output has **not been loaded on a
>   device or management server**. The Check Point input format is taken from the API
>   documentation, not from a real export, the ASA and FTD syntax from Cisco's
>   command references, and the Sophos format from the documentation of its
>   XML API and the templates of Sophos's own SDK; a few element names of a
>   Sophos NAT rule are in neither. The JSON of a Management Center and of a
>   Device Manager is taken from the API documentation and from the tooling
>   Cisco publishes for both (Ansible, Terraform, its Python client); the
>   script for a Management Center has only ever talked to a stand-in written
>   for the tests. How pfSense turns its configuration into pf rules is taken
>   from its source code (2.6, 2.7.2 and the current development branch), and
>   checked against a model of it written for the tests, not against pf. The
>   SonicWall settings export is undocumented beyond its encoding: its keys are
>   those the published readers of the format agree on, and the commands are
>   those of SonicWall's knowledge base, a few of them assumed. The WatchGuard
>   configuration file is not documented at all: its elements are those the
>   published readers of the format agree on. The REST API of a Barracuda
>   CloudGen Firewall is documented by examples only, and so is what FWShift
>   reads and writes of it. Junos is taken from Juniper's documentation and the
>   grammar of a published reader of it. Several conversion rules rest on
>   vendor behaviour taken from documentation rather than from a lab.
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
* **[TODO.md](TODO.md)**: what is planned, release by release.

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

Each version tag has a release with packages: `fwshift-X.Y.Z.zip`, the
project as tagged; a wheel for `pip install`; and `fwshift-X.Y.Z.pyz`, one
file that needs nothing but Python 3.9 or newer:

```sh
python3 fwshift-0.12.3.pyz --version
python3 fwshift-0.12.3.pyz convert running-config.xml --to fortios -o fortigate.conf
```

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

# Cisco ASA to PAN-OS: interface names become zones
fwshift convert asa-running.cfg --to panos -o panos.set --report report.txt \
    --interface-map GigabitEthernet0/0=ethernet1/1

# FortiOS to Cisco ASA: an access list cannot name the outgoing interface,
# so say which networks lie behind every zone; "everything else" is said
# as a default route would say it
fwshift convert fgt-backup.conf --to asa -o asa.cfg --report report.txt \
    --zone-map wan1=outside --zone-map lan=inside \
    --zone-network inside=10.10.0.0/16 --zone-network dmz=10.20.0.0/24 \
    --zone-network outside=0.0.0.0/0,::/0

# Sophos Firewall: the export archive is read as it is; to a Sophos Firewall,
# a name that ends in .tar gives the archive an import takes
fwshift convert sophos-export.tar --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to sophos -o import.tar --report report.txt \
    --zone-map trust=LAN --zone-map untrust=WAN \
    --interface-map ethernet1/1=Port2 --interface-map ethernet1/2=Port1

# Cisco Secure Firewall, Management Center: what its REST API answers, saved
# to a file, is the input. To one, the output is a script: look at what it
# would do, try it without creating anything, then run it. It creates a new
# policy and assigns it to no device
fwshift convert fmc-export.json --to panos -o panos.set --report report.txt
fwshift convert asa-running.cfg --to fmc -o load_policy.py --report report.txt --target-policy "From the ASA"
python3 load_policy.py --show
python3 load_policy.py --host fmc.example.net --user api-user --dry-run

# Cisco Secure Firewall, Device Manager: the export is read as it is (the zip
# too); to one, the output is a file for its configuration import
fwshift convert fdm-export.zip --to fortios -o fortigate.conf --report report.txt
fwshift convert fgt-backup.conf --to fdm -o import.txt --report report.txt \
    --zone-map lan=inside_zone --zone-map wan1=outside_zone \
    --interface-map lan=inside --interface-map wan1=outside

# pfSense: config.xml from Diagnostics > Backup & Restore. Addresses an
# interface gets by DHCP or PPPoE are not in it: give them. To a pfSense, the
# output is restored once per area (Aliases, NAT, Firewall Rules); it
# REPLACES what the firewall has in that area
fwshift convert config.xml --to panos -o panos.set --report report.txt \
    --interface-address wan=198.51.100.7/24
fwshift convert running-config.xml --to pfsense -o restore.xml --report report.txt \
    --zone-map trust=lan --zone-map untrust=wan \
    --zone-network lan=10.10.0.0/16 --zone-network wan=0.0.0.0/0,::/0

# SonicWall: the settings export (.exp) is read as it is. To a SonicWall,
# the output is commands to paste into an SSH session; NAT policies need the
# interfaces of the target (X0, X1, ...)
fwshift convert sonicwall.exp --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to sonicwall -o sonicwall.cli --report report.txt \
    --zone-map trust=LAN --zone-map untrust=WAN --interface-map ethernet1/1=X1

# WatchGuard: the file Policy Manager saves (File > Save > As File). To a
# Firebox, the output is the policy part of such a file: merge it into the
# configuration of the target in Policy Manager; zones are interfaces there
fwshift convert firebox.xml --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to watchguard -o policies.xml --report report.txt \
    --zone-map trust=Trusted --zone-map untrust=External

# Barracuda CloudGen Firewall: what its REST API answers, saved to one file, is
# the input. To one, the output is a script of REST calls; a rule there names
# no zone, so give the interface behind each source zone and the networks
# behind every zone
fwshift convert barracuda.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to barracuda -o rules.sh --report report.txt \
    --interface-map trust=port2 --interface-map untrust=port1 \
    --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0
DRY_RUN=1 sh rules.sh

# Juniper SRX: show configuration | display inheritance no-comments | display set.
# To an SRX, the output is set commands for 'load set'
fwshift convert srx.conf --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to junos -o srx.set --report report.txt \
    --zone-map trust=trust --zone-map untrust=untrust

# What did the parser read?
fwshift inspect fgt-backup.conf

# Audit a policy: nothing is converted, nothing is changed
fwshift audit asa-running.cfg

# Convert with an audit before and after; disable what is proven redundant,
# let the published web servers pass the "any source" check
fwshift convert asa-running.cfg --to panos -o panos.set --report report.txt \
    --audit-action REDUNDANT_RULE=disable --audit-accept 'outside_access_in-*=ANY_SOURCE'

# Who can reach whom? Between the zones of the policy, or between zones of
# your own, given as networks and the zone of the policy they lie behind
fwshift matrix running-config.xml
fwshift matrix running-config.xml --network-zone office@trust=10.10.0.0/16 \
    --network-zone plant@ot=10.30.0.0/16 --network-zone internet@untrust=0.0.0.0/0,::/0
```

The [manual](docs/MANUAL.md#3-getting-the-source-configuration) shows how to
get the input for each platform; for Check Point that is three `mgmt_cli show`
calls, for an ASA `show running-config`, for a Sophos Firewall an export under
*Backup & firmware > Import export*, for a Management Center a handful of
`curl` calls to its REST API, for a Device Manager its configuration export,
for a pfSense the backup under *Diagnostics > Backup & Restore*, for a
SonicWall *Export Settings*, for a WatchGuard the file Policy Manager saves,
for a Barracuda a few `curl` calls to its REST API, for an SRX
`show configuration | display inheritance no-comments | display set`.

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

## Audit

```
$ fwshift audit asa-running.cfg
Summary
  high 0, medium 4, low 10, info 2

Findings in the policy as it was read
  [medium] RISKY_SERVICE: rule 'inside_access_in-7' allows rdp, from zone inside to zone outside, dmz, guest (on the list of the cleartext and remote administration protocols)
  [low] REDUNDANT_RULE: rule 'inside_access_in-4' never matches: 'inside_access_in-2' above it already allows everything it could match
  [info] UNUSED_OBJECT: 2 services no rule uses: 'svc-http', 'svc-http-alt'
  ...
```

| | Checks |
|---|---|
| Rules that allow a lot | any/any/any and its partial forms, very large networks, very wide port ranges, cleartext and remote administration protocols, industrial protocols, no logging, no security profile |
| Rule order | shadowed rules (never match; earlier rules decide otherwise), redundant rules (can go without a change), rules that match nothing, shadowed NAT rules |
| Loose ends | disabled rules, unused and duplicate objects, empty groups, a default that allows |
| After a conversion | a blocking rule the target could not take, with what now allows its traffic (the rules below it, or a default) |

Each check can be switched off, accepted (for all rules, or for one rule
with a reason), or acted on in a conversion: `disable` the rules, or
`reorder` shadowed ones. A rule is only called dead when that is proven from
zones, addresses and ports against all earlier rules together, and disabling
such a rule changes no verdict; the tests check that against every packet of
a small world. A rule that was read only approximately is not called dead and
proves nothing about another rule: the audit lists it instead.
`--audit-fail-on high` makes it a gate for a pipeline. See
[section 13 of the manual](docs/MANUAL.md#13-auditing-a-policy).

Synthetic configurations to try it on, one per format, are in
[`tests/data`](tests/data), with their conversions in
[`tests/data/expected`](tests/data/expected).

## Zone matrix

```
$ fwshift matrix running-config.xml --summary
What each zone may reach (rows: from, columns: to)
           trust             untrust           dmz               ot
  trust    any               app:web-brow… +2  tcp/80 +6         app:modbus +1
  untrust  -                 any               app:ssl app:smtp  -
  dmz      -                 app:dns app:ssl~  -                 -
  ot       -                 -                 -                 any

Conduits
trust -> ot
  allowed: app:modbus, app:siemens-s7
  industrial protocols: modbus (rule 'Engineering to PLCs'); siemens-s7 (rule 'Engineering to PLCs')
...
```

Per pair of zones: the services the policy allows there and the rules that
allow them, each with what the blocking rules above it leave of it; rules
that never match are left out. Of the rules FWShift read, it shows at most
what they allow, never less: what cannot be read exactly is shown in full
and marked, and what a parser did not read is named. Zones can be those
of the policy or networks of your own (`--network-zone`), which is how the
zones of an IEC 62443 zone and conduit model are laid over a firewall that
knows only interfaces. Text, JSON or CSV. See
[section 14 of the manual](docs/MANUAL.md#14-the-zone-matrix).

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

| | Cisco ASA |
|---|---|
| Address objects | `object network`: host, subnet, range, FQDN (per IP version); names from `name` |
| Address groups | `object-group network`, nested |
| Services | `object service`, `object-group service` (with ports or with service entries), protocol and ICMP-type groups, ports and ICMP types spelled out in an entry |
| Security rules | access lists bound with `access-group`: per interface (inbound), global, and outbound lists that only deny; `inactive`, remarks, logging; the ASA's own rules (no traffic back out of an interface, security levels) made explicit |
| NAT | twice NAT and object NAT in the order the ASA applies them: static, dynamic, PAT pools, interface PAT, published ports, exemptions (8.3 and later) |
| Scope | one configuration (one context); ASA 8.3 and later in full, older releases without NAT; an FTD as far as its device configuration shows |

| | Sophos Firewall |
|---|---|
| Address objects | IP host (address, network, range, list), FQDN host; system hosts by name, Sophos to Sophos |
| Address groups | IP host group, FQDN host group. Written flat, per IP version, host names apart |
| Services | TCP and UDP with source and destination ports, IP protocols by name, ICMP and ICMPv6 type and code; one kind of protocol per service |
| Service groups | yes, flat |
| Security rules | firewall rules of both rulebases (IPv4, IPv6) in the order of evaluation; zones, networks, services, exclusions (which apply together), action, logging, status; a rule per IP version when written |
| NAT | NAT rules, first match: source (MASQ, host, range), destination with port translation, both in one rule, no-NAT, load balancing as "one of these addresses"; linked NAT rules as rules of their own; interfaces as zones |
| Scope | SFOS 18 and later; the whole export |

| | Cisco Secure Firewall (Management Center, Device Manager) |
|---|---|
| Address objects | host, network, range, FQDN; literals of a rule or a group. Written: the same, with the predefined `any-ipv4` and `any-ipv6` for every address |
| Address groups | network groups, nested. Written without host names, which the rules then name; flat for a Device Manager |
| Services | port objects (TCP, UDP), ICMP and ICMPv6 objects, other protocols, port groups; source ports and destination ports of a rule together. Written: one port or range per object, more as a group; a rule per set of source ports |
| Security rules | access rules, first match: mandatory before default, inherited policies around their children; Allow, Trust, Block, Block with reset, Interactive Block as Block, Monitor left out. The prefilter policy of a Management Center first: Fastpath, Block, tunnel rules as rules for GRE, IP in IP, IPv6 in IP and Teredo, its default action. Written: a new access control policy that blocks by default, or rules for an import; no negation (the addresses that are left are written) |
| NAT | manual and automatic NAT in the order the device applies them: static, dynamic, PAT pools, the address of an interface, published ports, exemptions. Written as manual rules before the automatic ones |
| Scope | one access control policy with the policies it inherits from, its prefilter policy and one NAT policy (Management Center); the device (Device Manager) |

| | pfSense |
|---|---|
| Address objects | aliases of hosts and networks (addresses, networks, ranges, host names), the networks and addresses of interfaces and virtual IPs, *This Firewall* |
| Address groups | aliases, nested; a rule for one IP version takes the addresses of that version |
| Services | protocol and ports of a rule, port aliases (nested), ICMP types by name; services named by their port name |
| Security rules | floating rules (quick and not, in, out and both), rules of interface groups and of interfaces, in the order pfSense evaluates them, which depends on its version; pass, block, reject; negation; IPv4, IPv6 or both; disabled; the rules pfSense adds by itself for "block private networks", port forwards that pass by themselves and automatic outbound NAT |
| NAT | port forwards (with NAT reflection), 1:1 NAT, outbound NAT in all four modes (automatic, hybrid, manual, disabled) with "do not NAT", static port and address pools |
| Scope | the whole configuration, pfSense 2.6 and later. Written for pfSense 2.7 and later |

| | SonicWall |
|---|---|
| Address objects | host, range, network, FQDN; the objects SonicOS has by itself (`X1 IP`, `X0 Subnet`, `LAN Subnets`, `Firewalled Subnets`, ...) worked out from the interfaces of the export. Written: host, network, range, FQDN, with a zone |
| Address groups | nested. Written per IP version |
| Services | TCP and UDP port ranges, IP protocols, groups; the default services of SonicOS a rule names. Written: TCP and UDP, ICMP echo as `Ping` |
| Security rules | access rules per pair of zones, first match, by priority where the export has it; allow, deny, discard; IPv4 and IPv6; the default rule of a pair that the export has none for, by the security types of its zones. Written: one rule per pair of zones and IP version, with its place in the pair, and a rule that denies at the end of every pair |
| NAT | NAT policies, first match: source, destination and service translated in one policy, interfaces as zones, reflexive policies as a policy of their own. Written the same way, one policy per pair of interfaces |
| Scope | SonicOS 6.5 and 7 in Classic mode; the whole export |

| | WatchGuard |
|---|---|
| Address objects | address groups of hosts, networks, ranges and host names; `Firebox`, from the interfaces of the file. Written: the same |
| Address groups | aliases, nested, whose members are an address at an interface. Written: aliases |
| Services | TCP and UDP ports and ranges, ICMP and ICMPv6 type and code, IP protocols |
| Service groups | none: a service holds several members. Written: one service per rule that needs several |
| Security rules | policies, first match, in the order of the file; allow (proxy policies too), deny; enabled; interfaces as zones, a policy split into one rule per pair of interfaces it names. Written: one policy per rule, in manual order, with aliases of every zone and address it names; negation as the addresses that are left |
| NAT | static NAT actions of a policy, as a NAT rule of their own. Written: a NAT rule that translates the destination to one address, as the static NAT action of the policy that allows exactly its traffic |
| Scope | Fireware 12; the whole file. Written: the policy part of a file, not a file to restore |

| | Barracuda CloudGen Firewall |
|---|---|
| Address objects | network objects: addresses, networks, ranges, host names, excluded entries subtracted, the interface of an entry where the object is a source. Written: addresses and networks (a range as its networks), host names as placeholders |
| Address groups | references between network objects, nested. Written: the addresses, in one object |
| Services | TCP and UDP ports and client ports, ICMP and ICMPv6 (every type), IP protocols |
| Service groups | references between service objects. Written: the entries, in one object |
| Security rules | forwarding rules, first match; pass, block, deny; IPv4 and IPv6; deactivated; bi-directional as two rules; interfaces of source entries as zones. Written: one rule per IP version, created deactivated at the top of the list and activated in order; zones as interfaces of the source or as networks; negation as the addresses that are left |
| NAT | not read and not written: Dst NAT, Map and connection objects are reported |
| Scope | the forwarding firewall of one box. Written: rules and objects through the REST API, above the rules the firewall has |

| | Juniper SRX |
|---|---|
| Address objects | address books: global, attached to a zone, of a zone; prefixes, ranges, DNS names. Written: the global address book |
| Address groups | address sets, nested |
| Services | applications with terms: TCP and UDP ports (numbers, ranges, names) and source ports, ICMP and ICMPv6 type and code, IP protocols; the predefined `junos-*` applications of FWShift's table |
| Service groups | application sets, nested |
| Security rules | policies per pair of zones, then global policies (with their zones), then the default policy; permit, deny, reject; negation (`...-excluded`); deactivated; logging. Written: a policy per pair of zones in the order of the model, the rules for every zone at the end as global policies |
| NAT | static, destination and source NAT, with pools; policies looked up after destination NAT, brought back to the original destination. Written: the same, in rule sets per zone and pair of zones |
| Scope | the root system. Written: set commands for `load set` |

Not converted, and reported where a rule depends on it: security profiles,
schedules, user and group matches, URL categories, HIP profiles, application
filters, wildcard-mask and geography addresses, external dynamic lists,
internet-service (ISDB) policies, load-balancing virtual IPs, NAT64/NAT46,
Check Point access roles, application objects, VPN communities and implied
rules, iptables match modules beyond addresses, ports and state, the `INPUT`
and `OUTPUT` chains, ASA time ranges, identity (user and TrustSec) matches,
outbound access lists that do more than deny, NAT of ASA releases before 8.3,
the application, URL, user, VLAN, security group tag and dynamic object
conditions of FTD rules, its intrusion, file and SSL policies, what a prefilter
rule with the action Analyze does to the traffic inside a tunnel, Sophos web server
protection rules, Security Heartbeat conditions, MAC hosts and country groups,
pfSense schedules, URL table aliases, policy routing (a gateway on a rule),
tags, limiters and traffic shaping, match rules, NPt, IPv6 NAT, bogon
networks, the rules of the captive portal and of packages, OPNsense
configurations, SonicWall ICMP service objects, users, schedules, source-port
services and the security services of a rule (Geo-IP, botnet filter), its
IPv6 and MAC address objects and Policy mode (SonicOSX), WatchGuard network
dynamic NAT and 1-to-1 NAT, proxy actions and schedules, Barracuda rule lists
(Cascade), NAT, App Redirect and the host firewall, Junos logical systems,
unified policies, schedulers and policy-based VPN, routing, interfaces, VPN,
and everything else outside the policy.

## Roadmap

[TODO.md](TODO.md) has the list. In short:

* **Firewall brands**, one per release: Sophos Firewall 0.6, Cisco Secure
  Firewall (formerly Firepower) 0.7, pfSense 0.8, SonicWall 0.9, WatchGuard
  0.10, Barracuda 0.11, Juniper SRX 0.12. Next on the list: nftables,
  OPNsense and others (see TODO.md).
* Audit and matrix: the matrix before and after a conversion, a zone and
  conduit model as a file to check a policy against, an equivalence check as
  a command, zone ranks, hit counts.
* Validation of the output on lab devices of every platform.

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
