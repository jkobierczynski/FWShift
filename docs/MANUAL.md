# FWShift user manual

FWShift converts firewall policies between Palo Alto PAN-OS, Fortinet FortiOS,
Check Point, Cisco ASA and Linux iptables, and tells you, rule by rule, how
faithful the result is. It can also audit a policy: rules that allow too much,
rules that never match, loose ends. This manual covers version 0.4.

**Contents**

1. [What FWShift does, and what it does not](#1-what-fwshift-does-and-what-it-does-not)
2. [Installation](#2-installation)
3. [Getting the source configuration](#3-getting-the-source-configuration)
4. [A conversion from start to finish](#4-a-conversion-from-start-to-finish)
5. [Command reference](#5-command-reference)
6. [The report](#6-the-report)
7. [Finding reference](#7-finding-reference)
8. [How the differences between platforms are handled](#8-how-the-differences-between-platforms-are-handled)
9. [The application map](#9-the-application-map)
10. [Loading the output](#10-loading-the-output)
11. [Errors and troubleshooting](#11-errors-and-troubleshooting)
12. [Limits](#12-limits)
13. [Auditing a policy](#13-auditing-a-policy)

---

## 1. What FWShift does, and what it does not

FWShift reads a configuration, builds a vendor-neutral model of its policy
(objects, security rules, NAT rules), and writes that model in the syntax of
another platform. Alongside the configuration it writes a report.

It follows one rule above all others: **a conversion never makes the policy
more permissive without saying so.** In practice:

* Every rule of the source appears in the output, in the same order, or in
  the report as *skipped* with the reason. (One kind is counted instead of
  listed: permit entries of an ASA that can match nothing the ASA forwards,
  `RULE_WITHOUT_EFFECT`.)
* A rule whose match cannot be expressed on the target is written
  **disabled** and listed in the report as *needs review*.
* An object that cannot be converted becomes a placeholder that matches
  nothing, with `FWSHIFT PLACEHOLDER` in its comment, so the output loads and
  the gap is visible.
* Nothing missing or unknown is read as "any".

FWShift converts the **policy**. It does not convert interfaces, routing, VPN,
users, security profiles, or system settings, and it is not a substitute for
testing the result.

> **Status.** Version 0.4 is tested against synthetic configurations. iptables
> output and input are checked against a Linux kernel (filter rules, one
> kernel and iptables version). Output for PAN-OS, FortiOS, Check Point and
> Cisco ASA has not been loaded on a device or management server yet; the
> Check Point input format follows the API documentation, the ASA and FTD
> syntax Cisco's command references. Use FWShift to produce a draft for a lab.

## 2. Installation

FWShift needs Python 3.9 or newer and nothing else.

```sh
pip install .
fwshift --version
```

To run it from the source tree without installing:

```sh
PYTHONPATH=src python3 -m fwshift --version
```

## 3. Getting the source configuration

**PAN-OS firewall.** FWShift reads the XML configuration, for example the
`running-config.xml` exported from *Device > Setup > Operations > Export named
configuration snapshot*. Output in `set` format is not read yet.

**Panorama.** Export the Panorama configuration the same way. FWShift reads one
device group together with its parent device groups and `shared`. The
hierarchy of device groups is recorded in the `<readonly>` section of the
export; if that section is missing, parents cannot be found and the report
says so (`NO_HIERARCHY`). Rules that exist only on a firewall, and zones, which
live in templates, are not in a Panorama export.

**FortiOS.** Use an unencrypted configuration backup. A complete backup is
best: it contains the definitions of the factory-default services. If a
fragment refers to a default service such as `HTTPS` without defining it,
FWShift assumes the factory definition and reports that (`FACTORY_DEFAULT`).
With VDOMs enabled, one VDOM is converted per run.

Do not use the output of `show full-configuration`. It lists every attribute
of every policy with its default value, and FWShift treats attributes it does
not know as something to review, so nearly every rule would be flagged.

**iptables.** Save the running ruleset, one file per IP version:

```sh
iptables-save  > rules.v4
ip6tables-save > rules.v6
```

Each file is converted on its own. The files written by `iptables-persistent`
and `netfilter-persistent` have the same format, and so has the output of
`iptables-nft-save`. A ruleset written in the `nft` language is not read.
FWShift converts the `FORWARD` chain of the `filter` table, with the chains it
jumps to, and the `PREROUTING` and `POSTROUTING` chains of the `nat` table;
section 8 says what happens to the rest.

**Cisco ASA.** FWShift reads the running configuration as the ASA prints it:

```
terminal pager 0
show running-config
```

A saved copy (`copy running-config tftp:`, a backup file) is the same text.
In multiple context mode, take the configuration of each context
(`changeto context NAME`, then `show running-config`) and convert each on its
own; the system configuration holds no policy. The output of
`show access-list`, with its expanded groups and hit counts, is not a
configuration and is not read.

Give FWShift the whole configuration, not the access lists alone. It uses

* the **interface sections** (`nameif`, `security-level`, `ip address`): they
  say which interfaces there are and what the ASA forwards between them
  without being told (section 8);
* the **static routes**: together with the interface addresses they say
  behind which interface a destination lies;
* the **`ASA Version` line**: from 9.0 on `any` means IPv4 and IPv6, from 8.3
  on access lists name the real address of a translated host. Without that
  line 9.0 or later is assumed, and the report says so (`VERSION_ASSUMED`).
  NAT in the syntax of 8.2 and earlier is not converted (`LEGACY_NAT`).

Only access lists that an `access-group` line binds are policy. Lists that
serve a crypto map, NAT or a class map are counted and left out
(`UNBOUND_ACL`).

**Cisco Firepower Threat Defense.** The `show running-config` of an FTD device
shows what its manager deployed, in ASA syntax, and FWShift reads that. It is
the policy as far as addresses, ports and interfaces go, and no further: a
rule with application, URL or user conditions is in it **without** those
conditions. FWShift recognises such rules by the remark the manager writes
(`L7 RULE`) and converts them disabled; intrusion and file policies are not in
the device configuration at all (`FTD_CONFIGURATION`). NAT is read in full.

**Check Point.** There is no configuration file to export. FWShift reads what
the Management API answers to `show access-rulebase` and `show nat-rulebase`,
as JSON. On the management server, or on any host with `mgmt_cli`:

```sh
mgmt_cli login -r true > sid.txt        # as root on the server; elsewhere: login user <admin> -m <server>

opts='details-level full use-object-dictionary true dereference-group-members true limit 500 --format json -s sid.txt'
mgmt_cli show access-rulebase name "Network" offset 0 $opts > access-0.json
mgmt_cli show nat-rulebase package "Standard" offset 0 $opts > nat-0.json
mgmt_cli show access-layers details-level full limit 500 --format json -s sid.txt > layers.json

mgmt_cli logout -s sid.txt
```

Then put the answers into one JSON array:

```sh
jq -s . access-*.json nat-*.json layers.json > checkpoint.json
```

Three things decide whether the export is complete:

* **Pages.** One call returns at most 500 rules. Each answer says `"to"` and
  `"total"`; repeat the call with `offset 500`, `offset 1000` and so on until
  `to` reaches `total`, and include every page. FWShift compares the number of
  rules it read with `total` and reports a shortfall (`INCOMPLETE_EXPORT`);
  the rules of a missing page are simply not there, including its denies.
* **Inline layers.** A rule with action *Apply Layer* only names its layer.
  Export each inline layer with the same `show access-rulebase` call and the
  name of that layer.
* **Detail.** `details-level full` and `dereference-group-members true` are
  what put addresses, ports and group members into the export. Without them
  FWShift sees names only, cannot convert the objects, and disables the rules
  that use them (it never reads a missing object as "any").

`show access-layers` is optional. It tells FWShift what each layer does with
traffic that none of its rules matches; without it, a layer that does not end
in a cleanup rule is assumed to drop, and the report says so.

One ordered layer is converted per run (`--layer` chooses it when the input
holds several). A policy package with several ordered layers accepts a
connection only if every one of them does: convert each and compare.

Check what FWShift understood before converting:

```console
$ fwshift inspect running-config.xml
format:          panos
scope:           vsys1
addresses:       15
address groups:  4
services:        5
service groups:  1
zones:           trust, untrust, dmz, ot
security rules:  14 (1 disabled)
NAT rules:       5

findings while reading:
  address odd-hosts: UNSUPPORTED_ADDRESS: wildcard mask 10.20.1.2/0.0.254.0 cannot be converted
```

Configurations hold sensitive data. FWShift works offline and sends nothing
anywhere, but treat its output and reports like the source.

## 4. A conversion from start to finish

1. **Inspect** the source (`fwshift inspect`) and check the counts.
2. **Convert** with a report file:

   ```sh
   fwshift convert running-config.xml --to fortios -o fortigate.conf --report report.txt
   ```

3. **Read the report**, starting with *Notes for the whole policy*, then every
   rule that is *needs review*. Section 7 explains each finding.
4. **Rerun with options** where the report asks for them: `--zone-map` and
   `--interface-map` for the names of the target, `--app-map` for applications
   FWShift does not know, `--target-prefix`, `--target-gateway` and
   `--target-nat-zone` where a Check Point source or target needs them,
   `--zone-network` for an ASA target.
5. **Fix what remains by hand** in the output: placeholders, disabled rules.
6. **Load it in a lab** (section 10) and test.

The samples in `tests/data`, one per format, can be used to try this. For example the
PAN-OS rule

```xml
<entry name="Engineering to PLCs">
  <from><member>trust</member></from><to><member>ot</member></to>
  <source><member>eng-station</member></source><destination><member>plc-net</member></destination>
  <application><member>modbus</member><member>siemens-s7</member></application>
  <service><member>application-default</member></service>
  <action>allow</action>
</entry>
```

becomes, on FortiOS,

```
    edit 0
        set name "Engineering to PLCs"
        set srcintf "trust"
        set dstintf "ot"
        set action accept
        set srcaddr "eng-station"
        set dstaddr "plc-net"
        set schedule "always"
        set service "app-modbus" "app-siemens-s7"
        set logtraffic all
    next
```

and the report lists it as *approximated*, because a FortiOS policy matches
TCP 502 and TCP 102, not the applications themselves.

## 5. Command reference

### `fwshift convert`

```
fwshift convert INPUT --to {panos,fortios,checkpoint,asa,iptables,ip6tables,json} [options]
```

`INPUT` is a file, or `-` for standard input.

**Source**

| Option | Meaning |
|---|---|
| `--from {panos,fortios,checkpoint,asa,iptables,ip6tables}` | Source format. Detected when left out: XML is PAN-OS, JSON is Check Point, a file that starts with a table (`*filter`) or the header of `iptables-save` is iptables, a file with an `ASA Version` line or with `access-list ... extended`, `object network` and similar lines is Cisco ASA, anything else FortiOS. |
| `--vsys NAME` | PAN-OS source with several virtual systems: the one to read. |
| `--device-group NAME` | Panorama source: the device group to read, with its parents and `shared`. |
| `--vdom NAME` | FortiOS source with several VDOMs: the one to read. |
| `--layer NAME` | Check Point source with several access layers: the one to read. |

For iptables the IP version is taken from the header that `iptables-save` or
`ip6tables-save` writes, and otherwise from the addresses and protocols in the
rules. `--from ip6tables` settles it for a file that shows neither.

**Target**

| Option | Meaning |
|---|---|
| `--to panos` | PAN-OS `set` commands. |
| `--to fortios` | FortiOS CLI configuration. |
| `--to checkpoint` | A shell script of `mgmt_cli` calls for a Check Point management server. |
| `--to asa` | Cisco ASA commands (9.x): objects, access lists, twice NAT. |
| `--to iptables` | A file for `iptables-restore`: the IPv4 half of the policy. |
| `--to ip6tables` | A file for `ip6tables-restore`: the IPv6 half. |
| `--to json` | The neutral model as JSON, for inspection or other tools. It is the model as it was read: the audit options cannot be combined with it. |
| `--target-vsys NAME` | PAN-OS: prefix commands with `vsys NAME`. Default: a single-vsys firewall, no prefix. |
| `--target-device-group NAME` | Panorama: write into this device group; rules go to its pre-rulebase. |
| `--target-shared` | Panorama: write into `shared`; rules go to the shared pre-rulebase. |
| `--target-nat-zone ZONE` | PAN-OS: destination zone for NAT rules of a source that names none (Check Point, some iptables and ASA rules). Without it those NAT rules are skipped. ASA: the interface for source NAT "to the address of the outgoing interface" where the rule does not name one. |
| `--target-vdom NAME` | FortiOS: wrap the output in `config vdom` / `edit NAME`. |
| `--policy-id-start N` | FortiOS: number policies from N. Default is `edit 0`, which lets the FortiGate pick free ids and appends after existing policies. |
| `--target-layer NAME` | Check Point: the access layer the rules are written to. Default `Network`. It must exist. |
| `--target-package NAME` | Check Point: the policy package whose NAT rulebase gets the NAT rules. Default `Standard`. |
| `--target-gateway NAME` | Check Point: the gateway or cluster object to hide behind, for source NAT "to the address of the outgoing interface". Without it such rules are skipped unless the source gives an address. |
| `--target-prefix TEXT` | Check Point and ASA: put `TEXT` in front of the name of every object (on an ASA also every access list) that is created, so that none collides with one the target has. |

**Adapting the policy**

| Option | Meaning |
|---|---|
| `--zone-map SRC=DST` | Use `DST` wherever the source names zone or interface `SRC`. Repeatable. For iptables and ASA this is how a zone becomes an interface name, and the other way round. |
| `--zone-network ZONE=NET[,NET...]` | ASA target: the networks that lie behind a zone (its name after `--zone-map`). Repeatable. An ASA access list cannot name the interface traffic leaves by; with the networks FWShift keeps a rule for one destination zone to that zone (section 8). Networks may be addresses, prefixes or ranges. Give the networks of **every** zone, IPv4 and IPv6: nothing is assumed about a zone without networks, or about an address that lies in none of them. Of two networks, one inside the other, the smaller one decides, as a route would: give the zone that has the default route `0.0.0.0/0,::/0`, which then says "everything that is not behind another zone". |
| `--interface-map SRC=DST` | Map a source interface to a target interface: zone members written for FortiOS, and source NAT to an interface address on PAN-OS. Repeatable. |
| `--app-map FILE` | JSON file that adds or overrides application port definitions (section 9). |
| `--prune-unused` | Leave out objects that no rule or NAT rule uses, directly or through a group. |

**Output**

| Option | Meaning |
|---|---|
| `-o FILE`, `--output FILE` | Where the configuration goes. Default: standard output. |
| `--report FILE` | Where the text report goes. Default: standard error. |
| `--report-json FILE` | Also write the report as JSON. |
| `--strict` | Exit with status 2 when anything needs review. |
| `-q`, `--quiet` | Do not print the report or the one-line summary. |
| `--audit` | Audit the policy before and after the conversion, and carry out the actions set for the checks (section 13). The audit options below switch it on as well. |
| `--audit-config FILE` | JSON file with the actions, accepted rules, thresholds and service lists of the audit. |
| `--audit-action CHECK=ACTION` | What to do with the findings of a check: `off`, `accept`, `report`, `disable`, and for shadowed rules `reorder`. Not every check takes every action (section 13). Repeatable. |
| `--audit-accept RULE[=CHECK,...]` | Let a rule (or a NAT rule, or an object) pass a check, or every check. `*` and `?` stand for any text and any one character. Repeatable. |
| `--audit-fail-on LEVEL` | Exit with status 3 when a finding of this level (`info`, `low`, `medium`, `high`) or higher is reported. |

All output is UTF-8.

### `fwshift audit`

```
fwshift audit INPUT [--from ...] [-o FILE] [--json] [--audit-config FILE]
                    [--audit-action CHECK=ACTION] [--audit-accept RULE[=CHECK,...]] [--audit-fail-on LEVEL]
fwshift audit --list-checks
```

Audits a configuration of any format that can be read and prints what it
found (section 13). Nothing is converted and nothing is changed: an action
such as `disable` is shown as what a conversion would do. `--json` writes the
findings as JSON; `--list-checks` shows the checks, their levels and the
actions each can take.

### `fwshift inspect`

```
fwshift inspect INPUT [--from ...] [--vsys ...] [--device-group ...] [--vdom ...] [--layer ...]
```

Prints what was read and the findings raised while reading. Nothing is
converted.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Converted. The report may still hold findings. |
| 1 | Error: the input could not be read or an option is wrong. A message starting with `fwshift: error:` says why. |
| 2 | `--strict` was given and something needs review. (An invalid command line also ends with 2.) |
| 3 | `--audit-fail-on` was given and the audit reported a finding of that level or higher (in a conversion: before or after it) that was not accepted and whose rule was not disabled. Status 2 comes first. |

## 6. The report

```
FWShift conversion report
  source: panos (vsys1)
  target: fortios

Summary
  Security rules:     14   exact 3, approximated 5, needs review 6 (5 emitted disabled), skipped 0
  NAT rules:           5   exact 4, approximated 1, needs review 0, skipped 0
  Addresses:          16   exact 14, approximated 0, needs review 2, skipped 0
  ...

Notes for the whole policy
  [needs-review] CENTRAL_NAT: NAT is emitted as central NAT. Enable it first ...

Security rules
  Admin-SSH  ->  needs-review, emitted disabled
      [approximated] APP_TO_PORTS: applications ssh reduced to their well-known ports; ...
      [needs-review] USER_MATCH: source user match example\netadmins is not converted.
```

* **Summary** counts every item of the source by status.
* **Notes for the whole policy** are not tied to one rule: settings the target
  needs, default behaviour that differs.
* The sections after that list every item that has a finding. Items that are
  exact and have nothing to say are counted but not listed.
* With `--audit`, the audit follows as a section of its own (section 13), and
  the JSON report has an `audit` key.

### Status of an item

| Status | Meaning |
|---|---|
| exact | Same match and action on the target. |
| approximated | Converted and enabled, but not with identical semantics. The finding says what differs. |
| needs-review | A person must decide. With "emitted disabled" the rule is in the output but switched off. Without it the rule is enabled and the finding describes a risk to check. |
| skipped | Not in the output: a NAT rule that cannot be expressed, or a rule that can match nothing. |

The status of an item is that of its most severe finding. Each finding has a
severity (`info`, `approximated`, `needs-review`), a code, and a message.

### Disabled deny rules

When a **deny** rule is emitted disabled, the message ends with *"This deny
rule is NOT enforced until fixed; allow rules below it may match more
traffic."* Fix these first: until then the converted policy is wider than the
source below that rule.

### JSON report

`--report-json` writes the same content for scripts:

```json
{
  "source": "panos (vsys1)",
  "target": "fortios",
  "summary": {"rule": {"total": 14, "exact": 3, "approximated": 5, "needs-review": 6, "skipped": 0, "disabled": 5}},
  "notes": [{"severity": "info", "code": "EXISTING_OBJECTS", "message": "..."}],
  "items": [
    {
      "kind": "rule",
      "name": "Admin-SSH",
      "status": "needs-review",
      "disabled": true,
      "emitted_as": ["Admin-SSH"],
      "findings": [{"severity": "needs-review", "code": "USER_MATCH", "message": "..."}]
    }
  ]
}
```

`kind` is one of `rule`, `nat`, `address`, `address-group`, `service`,
`service-group`. `name` is the name in the source; `emitted_as` lists the
names in the output when they differ or when one rule became several.

## 7. Finding reference

Severity: **I** info, **A** approximated, **R** needs review. "Disabled" means
the rule is emitted switched off; "skipped" means it is not emitted.

### Security rules

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `AUDIT_DISABLED` | I or A | With `--audit`: the rule was disabled because a check was set to `disable` (section 13). I: a rule that never matched or added nothing; no traffic is decided differently. A: a rule disabled for what it allowed; that traffic is no longer allowed by it. |
| `AUDIT_MOVED` | R | With `--audit` and `SHADOWED_RULE=reorder`: the rule never matched on the source and was moved up, in front of the first rule that decided its traffic otherwise. It decides that traffic now. Check that this is what was meant: a moved allow rule opens what was blocked. |
| `APP_TO_PORTS` | A (R on deny) | To FortiOS, Check Point or iptables: applications were replaced by services with their well-known ports. Layer-7 identification is lost; add application control if needed. On a deny rule the scope of the block changes, so check it. |
| `APP_FILTER_DROPPED` | A (R on deny) | To a port-based target: the rule named applications *and* explicit services. The services are kept, the application match is dropped. |
| `APP_UNKNOWN` | R, disabled | To a port-based target: an application is not in the port table. Add it with `--app-map`. |
| `APP_DEFAULT_ANY` | R, disabled | To a port-based target: "any application on its default ports" has no port-based equivalent. Decide which services the rule should allow. |
| `USER_MATCH`, `URL_CATEGORY` | R, disabled | The rule matched users or URL categories, which are not converted. |
| `UNSUPPORTED_MATCH` | R, disabled | The source rule had a match that is not modelled: HIP profiles, an application filter, FortiOS identity groups, internet-service, ZTNA tags and similar attributes, a negation that cannot be expressed, a missing mandatory field; in an ASA access list entry anything that could not be read in full, `user any`, a TrustSec security group, the address of an interface; an FTD rule with application, URL or user conditions. The message names it. |
| `UNCONVERTIBLE_OBJECT` | R, disabled | The rule refers to an object that could not be converted (see the object's own finding). |
| `SCHEDULE` | R, disabled | The rule had a schedule; converted without it, it would apply at all times. |
| `SERVICE_NEGATE` | R, disabled | To PAN-OS or ASA: a negated service match does not exist there. On an ASA only a remark is written for the rule: an inactive entry without the negation would say the opposite. |
| `EGRESS_INTERFACE` | A, or R and disabled | To ASA: the rule is for traffic to certain zones, and an access list entry cannot name the interface traffic leaves by. A: the rule names destination addresses and is written for those, by whatever interface they are reached; also on an intrazone rule, which an ASA only serves with `same-security-traffic permit intra-interface`. R, disabled: the rule is for any address; give the networks behind the zones with `--zone-network`, or the rule a destination. |
| `EGRESS_BY_NETWORKS` | I or A | To ASA: with `--zone-network`, the networks given for the other zones were left out of the destination of the entry, which keeps the rule to its zones. A: the networks do not cover every address; what they leave out lies behind no zone that is known, so a permit rule for any address does not cover it and a deny rule does (`ZONE_NETWORK_GAP`). |
| `EGRESS_NO_ADDRESS` | A or R, skipped | To ASA: by the networks given with `--zone-network`, no address of the destination lies behind the zones the rule is for, so it matched nothing and is left out (or, with several source zones, has no entry for some of them). R for a deny rule: if one of the networks is wrong, a deny is missing. |
| `NEGATION_EXPANDED` | I | To ASA: an access list cannot negate. The negated address list was written as the address ranges it leaves, which matches the same addresses. |
| `NEGATION_NOT_STATIC` | R, disabled | To ASA: a negated list with a host name. What it leaves cannot be written out; only a remark is written for the rule. |
| `IMPLICIT_PERMIT` | I | ASA source: a rule for an interface without access list, which the ASA lets send traffic to interfaces of a lower security level (section 8). |
| `NO_SERVICE` | R, disabled | To PAN-OS: none of the rule's services could be converted. |
| `RULE_TYPE` | R, disabled | To FortiOS or iptables: an intrazone or interzone rule with zone `any` cannot be written as interface pairs. To ASA: an intrazone rule with zone `any`. |
| `RULE_TYPE_EMPTY` | I, skipped (R to Check Point with zone `any`) | An interzone rule whose zones leave no pair of different zones. It matched nothing. |
| `RULE_TYPE_ANY_ZONE` | R | To Check Point: an intrazone or interzone rule for zone `any` is written for the zones the policy names. For traffic between zones that no rule names it cannot be known whether they are one zone or two: a deny is applied to all of it, an allow to none. |
| `NEGATED_ANY` | R, disabled | To Check Point: a negated "any" matches nothing. |
| `NOT_THIS_IP_VERSION` | I, skipped | To iptables or ip6tables: nothing in the rule can match this IP version. It is in the output for the other one. |
| `INTERFACE_NAME` | R, disabled | To iptables or ASA: a zone name that cannot be an interface name. Map it with `--zone-map`. |
| `FQDN_RESOLVED_ONCE` | A | To iptables: a host name is resolved once, when the rules are loaded. |
| `DROP_BEFORE_ESTABLISHED` | R | iptables source: a deny that comes before the rule accepting established connections also dropped the replies of connections opened from the other side. The converted rule blocks new connections in its own direction only. |
| `INLINE_CLEANUP` | I or R | Check Point source: a rule added for the implicit cleanup of an inline layer. R when the export does not show whether the layer drops or accepts and drop was assumed (section 3). |
| `GATEWAY_OBJECT` | A or R | Check Point source: the rule names a gateway object, which stood for every address of the gateway; only its main address is in the export. R where that lets more traffic through: a deny that matches it, or an allow that excludes it. |
| `PROTOCOL_SIGNATURE` | A (R on deny) | Check Point source: a service of the rule also checked the signature of its protocol. Only the port is converted. |
| `NO_COMMON_FAMILY` | R, skipped (I to ASA) | Source and destination share no IP version, or a negation excludes everything: the rule matches nothing. |
| `UNKNOWN_ATTRIBUTES` | R | FortiOS or Check Point source: the rule has attributes or fields FWShift does not know. If one of them narrows the match, the converted rule is wider. Check them. |
| `NAT_ADDRESS_EXPOSED` | R | The rule covers addresses on one side of a destination NAT without the addresses that go with them on the other side, and the two platforms look rules up on different sides of the translation (section 8). The message names the addresses. The rule matches traffic it did not match on the source, or the other way round for a deny. Also raised for a rule that names both sides, for the part that has no counterpart. |
| `NAT_PORT_EXPOSED` | R | The same for ports: the service of the rule covers the port on one side of a port translation and not the port on the other, so the rule applies to traffic it did not apply to on the source. Looked at for rules to any destination too. Withdrawn where the target looks rules up as the source did and gets the NAT rule. |
| `NAT_PORT_TRANSLATION` | R | A destination NAT used by this rule also changes the port, and the service of the rule names the port of one side only. FortiOS policies, ASA access lists and iptables rules name the mapped port, PAN-OS and Check Point rules the original one; correct the service by hand. Not raised for a service that holds both ports. |
| `NAT_DESTINATION_WIDENED` | R | The rule names part of what a destination NAT translates, and that NAT does not map address for address (several addresses to one, or to a pool). On the other side of the translation the part cannot be told apart: the rule now covers all of it. |
| `NAT_REDIRECT` | R | iptables source: a DNAT rule without a destination address sends traffic for every destination to one address, and this rule matched it there. A platform that looks rules up before NAT cannot match that traffic with the converted rule: write the rule for the original destinations. |
| `NAT_DESTINATION_REWRITTEN` | A | The destination was changed, or extended, to the address on the other side of a destination NAT. A rule for part of a translated network gets the same part of the other side. Check that the rule is meant to cover that traffic. |
| `DENY_AND_VIP` | A | FortiOS source: a deny policy covers a virtual IP but has no `set match-vip enable`. FortiOS may have let that traffic through to a later policy; the converted rule blocks it. |
| `FQDN_FAMILY` | A | To PAN-OS or Check Point: an FQDN that FortiOS resolved for one IP version is resolved for both on the target, and this rule can match the other version. |
| `PROTOCOL_AS_APP` | A | To PAN-OS: ICMP or IP-protocol services became applications (`ping`, `icmp`, `gre`, ...). Verify the App-ID names. |
| `ICMP_TYPE` | A | To PAN-OS: a service for one ICMP type became App-ID `icmp`, which matches every type. |
| `PROFILES_NOT_CONVERTED` | A | Security profiles on the rule are not converted. Attach equivalent inspection on the target. |
| `PROFILES_BY_NAME` | I | PAN-OS to PAN-OS: profiles are referenced by name and must exist on the target. |
| `DEVICE_TARGET` | R | Panorama or Check Point source: the rule is installed on selected devices only. Decide whether it belongs on the target. |
| `RULE_SPLIT` | I | One rule became several: one per zone pair on FortiOS, or one for port-based and one for application-based services on PAN-OS. |
| `RESET_ACTION` | I | A reset action has no exact equivalent: deny on FortiOS and ASA, a plain `REJECT` on iptables when the rule is not TCP only, `Reject` on Check Point. |
| `ATTRIBUTES_IGNORED` | I | FortiOS source: NAT details such as `fixedport` have no equivalent. ASA source, on a NAT rule: options such as `dns`, `round-robin` or the fallback to the interface address. |
| `INCOMPLETE_ADDRESS_PAIR` | I | FortiOS source: addresses of one IP version on one side only. FortiOS cannot match that version, so they were left out. |

### NAT rules

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `NAT_NOT_CONVERTED` | R, skipped | The rule uses something that is not converted (NAT64, dynamic destination translation, an unconvertible object, an ASA NAT line that could not be read in full), or something the target cannot say: the message names it. To PAN-OS, a rule without a destination zone needs `--target-nat-zone`; to Check Point, source NAT to the outgoing interface needs `--target-gateway`; to ASA it needs an interface, from the rule or from `--target-nat-zone`. |
| `NAT_ORDER` | R | From PAN-OS or Check Point to FortiOS, iptables or ASA: the source applies one NAT rule to a connection, the first that matches; the target translates destinations and sources apart. This rule now also applies to traffic that another rule used to claim, or loses its source translation to one (section 8). On every target: a NAT rule above this one was not converted, and its traffic now reaches this rule. |
| `NAT_REVERSE_DIRECTION` | A | ASA source: a static twice NAT rule with a destination also translates connections opened from the other side. That direction is not converted. |
| `NAT_ZONE_BY_ROUTE` | I | ASA source: the destination zone of a NAT rule that translates the destination is the zone its original address is reached in, taken from the interface addresses and static routes. |
| `NAT_DYNAMIC_ONE_ADDRESS`, `NAT_STATIC_SIZE` | A | To ASA: dynamic NAT to a single address is port address translation on an ASA; static NAT between address sets of different size is mapped in order and wraps around. |
| `NAT_ZONES` | A or R | To Check Point: the rule applied to some zones only and is written without them. R where the zone was the only limit: a source NAT towards one zone now translates traffic towards every zone. |
| `NAT_ZONE_ASSUMED` | A | To PAN-OS: the source rule names no destination zone; the zone given with `--target-nat-zone` was used. |
| `NAT_GROUP` | I | To Check Point: a group was created, because a NAT rule cell holds one object. |
| `NAT_ADDRESSES`, `NAT_SERVICE`, `NAT_RANGE` | R, skipped (`NAT_RANGE`: A) | To iptables: the rule needs static IPv4 addresses and a TCP, UDP or SCTP service. DNAT to a range picks an address per connection. To ASA: the rule needs static addresses of one IP version per object, and a service of at most 16 TCP, UDP or SCTP ports or ranges without source ports. |
| `NAT_ANY_DESTINATION` | R | To iptables: the rule translates traffic to every destination; the security rules were not adjusted to the translated address. |
| `NAT_INPUT_INTERFACE` | A or R | To iptables: source NAT is done in `POSTROUTING`, which cannot match the interface the traffic came in on. R when that was the rule's only limit. |
| `NAT_OUTPUT_INTERFACE` | A | To iptables or FortiOS: a rule that translates destination and source. After the destination translation the traffic leaves by another interface than the rule names, so the source translation is written for every interface. |
| `NAT_AFTER_DNAT` | A | The same kind of rule. Its source translation is matched after the destination was translated, and cannot be tied to the original destination: it also applies to traffic from the same sources that is sent to the translated address directly. iptables output avoids this where the original destination is an address or network (`--ctorigdst`); FortiOS central SNAT cannot. |
| `AUTOMATIC_NAT_IN_GROUP` | R | Check Point source: a manual NAT rule names a group that holds an object with automatic static NAT. In the converted rule the group also matches the translated address; whether Check Point does is not known. |
| `AUTOMATIC_NAT_SHAPE` | R | Check Point source: an automatic NAT rule that does not name the same object in its original and translated column. It was read as it stands. |
| `NAT_DESTINATION`, `NAT_DESTINATION_SIZE`, `NAT_PORT` | R, skipped | To FortiOS: the destination NAT cannot become a virtual IP: it needs one IPv4 address or range on each side, of equal size, and for a port translation a service with one protocol and one port or range. To ASA: one static address object on each side; a port translation needs a service with single ports. |
| `NAT_POOL` | R, skipped | To FortiOS or iptables: the translated address is not a static IPv4 address, or not exactly one address or range. To ASA: it is not a static address. |
| `NAT_IPV6` | R or I, skipped | To FortiOS: the rule is not IPv4 (R). With `--to ip6tables`: NAT rules are written for IPv4 only (I, on every NAT rule). |
| `NAT_DISABLED` | I | A NAT rule that is disabled in the source. To FortiOS no virtual IP is created for it (skipped); to iptables it is written as a comment line. |
| `NAT_OVERLAP` | R | FortiOS source: another policy passes overlapping traffic without NAT, for other services. NAT rules do not match on service, so that traffic would be translated. Add a no-NAT rule or narrow this one. |
| `NAT_EXEMPTION` | A | FortiOS source: a no-NAT rule was added for an earlier policy that passes this traffic untranslated. It applies to all services. |
| `NAT_SERVICE_DROPPED` | A or R | To FortiOS: the rule translated one service only; the virtual IP (A) or central SNAT entry (R) applies to all. |
| `NAT_SOURCE_DROPPED` | A | To FortiOS: the destination NAT applied to some sources only; the virtual IP applies to all. |
| `NAT_BIDIRECTIONAL` | I, A or R | Bi-directional static NAT is written as two parts: a central SNAT entry plus a virtual IP on FortiOS, an SNAT and a DNAT rule on iptables, two NAT rules on Check Point. R when the inbound half could not be written. |
| `NAT_STATIC_RANGE` | A | To FortiOS: static NAT of several addresses becomes a one-to-one pool, which does not promise the same translated address per host. |
| `NAT_INTERFACE_ADDRESS` | A | To PAN-OS or Check Point: source NAT to an interface address was written with the address that interface has in the backup. Use `--interface-map` (PAN-OS) or `--target-gateway` (Check Point) to follow the interface instead. ASA source: a rule that publishes a port on the address of an interface (`interface`) is converted with the address the interface has in the configuration; back to an ASA it is written with `interface` again. |
| `VIP_REVERSE_NAT` | A | FortiOS source: a static virtual IP also translates sessions the mapped host opens, when the outgoing policy has NAT. That direction is not converted. |
| `NAT_MERGED` | I | FortiOS source: several policies had identical source NAT and share one rule. |
| `RULE_SPLIT` | I | To PAN-OS: one rule per destination zone. |

### Objects

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `UNSUPPORTED_ADDRESS`, `INVALID_ADDRESS` | R | An address type that is not converted (wildcard mask, geography, dynamic, a Check Point access role, group with exclusion or updatable object), an object that is not in a Check Point export in full, or a value that cannot be read. Emitted as a placeholder; rules using it are disabled. |
| `UNSUPPORTED_VIP` | R | A virtual IP that is not a static NAT (load balancing and others) or cannot be read. |
| `GROUP_EXCLUDE` | R | A FortiOS address group with excluded members. |
| `UNSUPPORTED_GROUP` | R | A group that holds itself, directly or through other groups: no platform takes one. ASA source: an object group with a member that could not be read, or object groups nested more than 64 deep. Emitted as a placeholder; rules using it are disabled. |
| `UNDEFINED_REFERENCE` | R | A rule names something that is not an object in the input: a region, an external dynamic list, a missing object. Emitted as a placeholder. |
| `UNSUPPORTED_SERVICE` | R | A service that cannot be converted: a proxy service, one limited to a destination address, an unreadable port list, a Check Point application or RPC object, an object that is not in the export in full. |
| `AUTOMATIC_NAT` | I or R | Check Point source: the object has automatic static NAT. As on Check Point, rules and groups that name it also match its translated address, written as a second object `<name>_valid_address`. R when the NAT settings could not be read. |
| `GATEWAY_OBJECT` | A | Check Point source: a gateway or cluster object. It is converted as its main address; a Check Point target refers to it by name and does not create it. |
| `PROTOCOL_SIGNATURE` | A | Check Point source: the service also matches on the signature of its protocol. |
| `EXISTING_OBJECT` | I | Check Point to Check Point: an object the management server has already (predefined, or a gateway). It is referred to by name and not created. |
| `POOL_TYPE` | A | A FortiOS IP pool type other than overload or one-to-one, converted as port address translation. |
| `FACTORY_DEFAULT` | I | A FortiOS default service was referenced but not defined in the input; the factory definition was assumed. |
| `RENAMED` | I | The name was changed: characters or length the target rejects, a collision, or a name the target predefines. |

### Notes for the whole policy

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `CENTRAL_NAT` | R | To FortiOS: NAT is written as central NAT, which has to be enabled first (section 10). |
| `INTRAZONE_DEFAULT` | R | To FortiOS, iptables or ASA: the source allowed traffic inside a zone by default and the target does not, or (iptables with `FORWARD` policy `ACCEPT`) the other way round. |
| `INTRAZONE_ALLOW` | R | To iptables or ASA: a FortiOS zone with `set intrazone allow`. No rule was written for the traffic between its interfaces. |
| `INTERZONE_DEFAULT` | R | The source allows what no rule matches (a PAN-OS `interzone-default` override, an iptables `FORWARD` policy `ACCEPT`, a Check Point layer whose implicit cleanup accepts). That is not carried over; only iptables output keeps it, as the chain policy, and ASA output, as a final `permit ip any any` in the global access list. |
| `ZONES_WITHOUT_INTERFACES` | R | To FortiOS: zones were created empty. Assign interfaces or use `--zone-map` / `--interface-map`. |
| `ZONES_REQUIRED` | R | To PAN-OS or Check Point: the zones named by the rules must exist on the target and be assigned to interfaces. |
| `INTERFACES_REQUIRED` | R | To iptables or ASA: zones are written as interface names. Map each zone to its interface with `--zone-map`. For an ASA the note also states what the access lists count on: that the ASA has no other interfaces than the policy names, and does not send traffic back out of the interface it came in on (section 8). |
| `INTRAZONE_ALLOW_MERGED` | R | To PAN-OS or Check Point: `--zone-map` merges a zone that allows intrazone traffic with another one; no allow rule was written for it. |
| `NAT_ORDER` | A | To PAN-OS or Check Point, from FortiOS, iptables, ASA, or Check Point automatic NAT rules: the source applies a destination NAT rule and a source NAT rule to one connection, the target one NAT rule only (section 8). To ASA from those sources: a destination NAT without a port is written as a rule that leaves the source alone, with the same effect. |
| `TABLE_NOT_CONVERTED` | R | FortiOS source: a table such as `firewall policy6` or `firewall local-in-policy` has entries and is not converted. iptables source: the `mangle`, `raw` or `security` table has rules. ASA source before 9.0: `ipv6 access-list` lines; the result has no IPv6 rules. |
| `SUSPICIOUS_QUOTING` | R | FortiOS source: a quoted value runs over lines that look like configuration. An unescaped quote may have hidden entries; check the line given. |
| `NO_HIERARCHY` | R | Panorama source without `<readonly>`: parent device groups could not be found. |
| `INTRAZONE_DENY_ADDED` | I | To PAN-OS: `fwshift-intrazone-deny` was appended (section 8). |
| `EXISTING_OBJECTS` | I | To FortiOS or ASA: objects are created by name and change existing ones of the same name; an ASA object group that exists gets the new members added to its own. |
| `PANORAMA_SOURCE` | I | Reminder of what a Panorama export does not contain. |
| `PRUNED` | I | `--prune-unused` left out this many objects. |

Notes that only an iptables source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `HOST_CHAIN_NOT_CONVERTED` | R | Source: `INPUT`, `OUTPUT` or the `nat` `OUTPUT` chain has rules. They filter the traffic of the host itself and are not converted. |
| `STATELESS_RULESET` | R | Source: no rule accepts `ESTABLISHED,RELATED` packets, so the ruleset filters every packet on its own. The converted rules are connection-based: an allow also admits the replies. |
| `FORWARD_POLICY_ACCEPT` | I | Source: the `FORWARD` chain accepts what no rule matches. See `INTERZONE_DEFAULT`. |
| `PASSIVE_TARGETS` | I | Source: rules with targets such as `LOG` or `MARK` decide nothing and were left out. A `LOG` rule directly before a rule with the same match sets its logging. |
| `IPTABLES_LOAD` | R | Target: how to load the output without replacing `INPUT` and `OUTPUT` (section 10). |
| `OTHER_IP_VERSION` | I | Target: some rules match the other IP version (too). Convert with `--to ip6tables` or `--to iptables` as well. |
| `LOGGING_NOT_CONVERTED` | I | Target: logging settings are not converted. Add `LOG` or `NFLOG` rules where needed. |

Notes that only a Cisco ASA source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `VERSION_ASSUMED` | I | Source: no `ASA Version` line. The configuration was read as 9.0 or later. |
| `LEGACY_NAT` | R | Source: NAT commands of ASA 8.2 and earlier (`static`, `global`, `nat` with a NAT id) are not converted. The access lists of that release name translated addresses and were read as such. |
| `NO_ACCESS_GROUP` | R | Source: no `access-group` line binds an access list. No security rules were read. |
| `UNBOUND_ACL` | I | Source: access lists that no `access-group` binds serve something else (NAT, VPN, class maps) and are not rules. |
| `ACL_MISSING` | R | Source: an `access-group` names an access list that is not in the input. Its interface was read as passing nothing; check that the input is complete. |
| `OUTBOUND_ACL` | R | Source: an access list bound `out` that does more than deny. A connection has to pass it as well as the inbound list, which a first-match rulebase cannot say. It is not converted: add its restrictions by hand. A list of denies followed by `permit ip any any` is converted, as deny rules towards that interface. |
| `NO_INTERFACES` | R | Source: the input shows fewer than two interfaces. The rules were read without what an ASA never forwards (below), because which interfaces there are is not known. |
| `EGRESS_BY_ROUTE` | I | Source: the destination zone of permit entries with destination addresses was taken from the interface addresses and static routes. |
| `RULE_WITHOUT_EFFECT` | I | Source: this many permit entries can match nothing the ASA forwards (their destination lies behind the interface the traffic comes in on, or behind one of the same security level) and were left out. |
| `MANAGEMENT_INTERFACE` | I | Source: management-only interfaces forward nothing. Their access lists were left out. |
| `PER_USER_OVERRIDE` | A | Source: an access list with `per-user-override` can be replaced per user by one from the authentication server, which is not in the configuration. |
| `BRIDGE_GROUPS` | R | Source: interfaces in bridge groups are read as zones of their own. That members of a group share a network is not modelled. |
| `ICMP_STATELESS` | A | Source: without `inspect icmp` the ASA lets the reply to a permitted ICMP request through only where an access list permits the reply. Every target lets replies through by itself. |
| `VPN_BYPASS` | A | Source: traffic arriving through VPN tunnels bypasses the interface access lists (`sysopt connection permit-vpn`). The converted rules do not allow it: add rules for it. |
| `FTD_CONFIGURATION` | R | Source: the configuration of an FTD device (section 3). |
| `ASA_LOAD` | R | Target: what loading the output does to the ASA (section 10). |
| `SAME_SECURITY_TRAFFIC` | I | ASA to ASA: the access lists rely on the security levels and `same-security-traffic` settings of the source. Keep them. |
| `ZONE_NETWORK_UNKNOWN` | R | Target: `--zone-network` names a zone the policy does not know. It was taken as a further interface, and rules for other zones leave its networks out. Check the name: it is the name after `--zone-map`. |
| `ZONE_NETWORK_GAP` | A | Target: the networks given with `--zone-network` leave addresses out (the note lists them; "every IPv6 address" when only IPv4 networks were given). Nobody said behind which zone they lie: in rules for any address that are kept to their zones, a permit does not cover them and a deny does. Give the zone with the default route `0.0.0.0/0` and `::/0`. |
| `ZONE_NETWORK_INCOMPLETE` | R | Target: the networks given cover every address of an IP version, and a zone was given none. "Everything else" for one zone only means something when every other zone has its networks: as it is, what lies behind the zone without networks counts as lying behind another. Rules that had to be told apart from traffic to that zone were not kept to their zones (`EGRESS_INTERFACE`). |
| `FQDN_DNS` | I | Target: objects with a host name need `dns domain-lookup` and a DNS server group. |

Notes that only a Check Point source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `IMPLIED_RULES` | R | Implied rules (Global Properties) and the other ordered layers of a policy package are not part of the export, and not of the output. Check that they allow no more and no less than intended. |
| `IMPLICIT_CLEANUP` | R | Source: the layer does not end in a rule that matches everything. Either the export shows that its implicit cleanup accepts, or it does not show it and drop was assumed. |
| `NO_NAT_RULEBASE` | R | Source: the input holds no answer of `show nat-rulebase`. No NAT rule was read, automatic ones included. |
| `INCOMPLETE_EXPORT` | R | Source: fewer rules were read than the server says the layer or the NAT rulebase has. Pages are missing (section 3). |
| `NO_ZONES` | I | Source: no rule names a security zone, so the converted rules apply from any zone to any zone. |
| `CHECKPOINT_SCRIPT` | R | Target: the output is a script that changes one session and publishes nothing (section 10). |
| `LAYER_PLACEMENT` | I | Target: the rules go to the top of the target layer, in order, and end in a cleanup rule. Rules the layer held before stay below it and are no longer reached. |
| `ZONE_RENAMED` | I | Target: a zone name that cannot be an object name was changed. Choose another with `--zone-map`. |
| `NAME_COLLISIONS`, `NAMES_DIFFER_BY_CASE`, `OBJECT_PREFIX` | I | Target: what to do when a name exists on the server already (`--target-prefix`), names that differ only in case, and the prefix in use. |
| `DOMAIN_OBJECTS` | I | Target: host names are written as domain objects, named after the domain with a leading dot. The gateway needs DNS. |
| `NAT_MANUAL_RULES` | R | Target: NAT rules are written as manual rules below the automatic ones. Manual NAT does not answer ARP for translated addresses: add proxy ARP where needed. |
| `ANY_ONE_IP_VERSION` | I | Target: "any IPv4 address" is written as a range object `All-IPv4` (or `All-IPv6`). |
| `TAGS_NOT_CONVERTED` | I | Target: tags are not converted. |

## 8. How the differences between platforms are handled

### Applications and services

PAN-OS matches applications; FortiOS policies, Check Point firewall rules and
iptables rules match ports. What is said here for FortiOS holds for those two
targets as well.

*To FortiOS.* An application on `application-default`, or on service `any`,
becomes a service named `app-<application>` with the well-known ports of that
protocol, taken from the table in `src/fwshift/appmap.py`. That table is small
on purpose and is **not** Palo Alto's application database. An application
that is not in it disables the rule; add it with `--app-map`. If the rule names
explicit services as well, those are kept and the application match is
dropped.

*To PAN-OS.* FortiOS policies become port-based rules with `application any`,
which is what they were. FortiOS services for ICMP and for IP protocols have no
PAN-OS service equivalent and become applications; a policy that mixes them
with TCP/UDP services becomes two rules, `name` and `name-apps`. A FortiOS
service that holds TCP and UDP ports becomes `name-tcp`, `name-udp` and a
service group `name`.

### IPv4 and IPv6

FortiOS `all` is IPv4-only unless the policy also sets `srcaddr6` and
`dstaddr6`; PAN-OS `any` is both versions.

* A FortiOS policy from `all` to `all` becomes `source 0.0.0.0/0`, not
  `source any`. Where the other side is IPv4-only anyway, plain `any` is used.
* A PAN-OS `any` becomes `all` in both the IPv4 and the IPv6 fields of the
  FortiOS policy; address lists are split by version.
* An FQDN object is resolved for both versions on PAN-OS and for one on
  FortiOS. To FortiOS, an IPv6 twin of the object is created where a rule needs
  it. To PAN-OS, the difference is reported (`FQDN_FAMILY`).

### Negation

PAN-OS negates an address list for both IP versions at once; FortiOS has one
flag per version. "Not 10.1.0.0/24" from PAN-OS becomes a negated IPv4 list
plus an un-negated IPv6 `all`. A FortiOS policy negated for one version only,
or negated on both sides while holding a single version, has no PAN-OS
equivalent and is disabled.

An ASA access list cannot negate at all. A negated address list is written as
the address ranges it leaves, which matches exactly the same addresses
(`NEGATION_EXPANDED`); a negated service, or a negated list with a host name,
cannot be written and the rule is reported (`SERVICE_NEGATE`,
`NEGATION_NOT_STATIC`).

### Zones and interfaces

Zone and interface names are carried over unchanged; rename them with
`--zone-map`. To FortiOS, zones are created, empty unless `--interface-map`
names their interfaces; a zone you map onto an existing name is not created.
To PAN-OS, zones are not created: they must exist.

PAN-OS rule types are translated for FortiOS: an intrazone rule becomes one
policy per zone, an interzone rule one policy per pair of different zones.

iptables and Cisco ASA have interfaces and nothing else: zones are written as
interface names, so every zone needs a `--zone-map` entry. An ASA access list
names only the interface traffic comes in on, not the one it leaves by; what
that means for rules with a destination zone is described under *Cisco ASA*
below. Check Point rules have no zone columns; how zones are read and written
there is described under *Check Point* below.

### Default behaviour

PAN-OS allows traffic inside a zone unless a rule denies it; FortiOS denies it
unless a policy allows it or the zone has `set intrazone allow`.

*To PAN-OS,* FWShift appends `fwshift-intrazone-deny` (rule type intrazone, any
zone), preceded by `fwshift-intrazone-allow` for the zones that have
`set intrazone allow`. If you merge the output into an existing rulebase, place
these two rules deliberately.

*To FortiOS,* the difference is reported (`INTRAZONE_DEFAULT`). Overrides of
the PAN-OS default rules are read.

*To Check Point,* which has no default of its own inside a zone, the layer
for traffic inside a zone ends in an accept where the source allowed it and in
a drop where it did not. *To iptables,* the difference is reported.

A source that allows what **no** rule matches (an iptables `FORWARD` chain
with policy `ACCEPT`, a Check Point layer whose implicit cleanup accepts, a
PAN-OS `interzone-default` override) keeps that only in iptables output. The
other targets end in their own deny, and the report says so
(`INTERZONE_DEFAULT`); ASA output ends its global access list in
`permit ip any any` instead, and the report says that.

### NAT

The neutral model follows PAN-OS: security rules match **pre-NAT** addresses
and the **post-NAT** destination zone, and NAT is a separate ordered rulebase.
FortiOS applies destination NAT first and then looks the policy up against the
**mapped** address. This is where conversions go wrong quietly, so FWShift
reports the places it touches. It works from addresses and zones: what it
cannot tell from those (routing, the services of a NAT rule on FortiOS) it
cannot report, and NAT is the part of a converted policy to test first.

**FortiOS to PAN-OS**

* A virtual IP becomes a destination NAT rule from, and to, the zone of its
  external interface. A port-forwarding VIP gets a service for its external
  port.
* A policy that names the VIP becomes a rule to the VIP's external address.
* A policy that names the *mapped* address matched the translated traffic on
  FortiOS, so the external address is added to it
  (`NAT_DESTINATION_REWRITTEN`).
* A policy that covers the external address without naming the VIP did not
  match that traffic on FortiOS; the converted rule does (`NAT_ADDRESS_EXPOSED`).
* A policy with `set nat enable` becomes a source NAT rule, to its IP pool or
  to the outgoing interface. Identical ones are merged.
* NAT rules do not match on service. An *earlier* policy that passes
  overlapping traffic without NAT gets a no-NAT rule in front
  (`NAT_EXEMPTION`); overlaps that addresses cannot tell apart are reported
  (`NAT_OVERLAP`).
* Central NAT sources (`central-snat-map`) are read as they are.

**PAN-OS to FortiOS**

* NAT is written as **central NAT**: source NAT rules become
  `central-snat-map` entries with IP pools, destination NAT rules become
  virtual IPs with `extintf any`, and a no-NAT rule becomes an entry with
  `set nat disable`.
* The destination of each security rule that names the pre-NAT address is
  rewritten to the internal address (`NAT_DESTINATION_REWRITTEN`).
* A rule that names only the internal address now also matches the translated
  traffic (`NAT_ADDRESS_EXPOSED`).
* A NAT rule that cannot be written leaves nothing behind: no virtual IP and
  no rewritten rule.
* Bi-directional static NAT becomes a central SNAT entry with a one-to-one
  pool, plus a virtual IP for the inbound direction.

In both directions, a destination NAT that changes the **port** is reported on
the rules that use it (`NAT_PORT_TRANSLATION`): the service has to be corrected
by hand.

**Which side of the translation, per platform**

| | Security rules match | NAT rules applied to one connection |
|---|---|---|
| PAN-OS | the original (pre-NAT) addresses and ports | one: the first that matches |
| Check Point | the original packet | one manual rule, the first that matches; automatic rules can combine |
| FortiOS | the address after destination NAT | a virtual IP and a central SNAT entry, each on its own |
| iptables | the address after `PREROUTING` | one `PREROUTING` rule and one `POSTROUTING` rule |
| Cisco ASA (8.3 and later) | the real address and port, after destination NAT | one rule for the destination and one for the source; a twice NAT rule that names both sides applies alone |

What is said above for FortiOS holds for iptables and ASA, and what is said
for PAN-OS holds for Check Point. A rule for *part* of a translated network
gets the same part of the other side: a rule for host .10 of a network that is
translated address for address stays a rule for one host. Where the translation
is not address for address (four public addresses to one server) that cannot
be done, and the rule is reported (`NAT_DESTINATION_WIDENED`). A rule that
names addresses of **both** sides is looked at part by part: what it names on
one side without its counterpart on the other is reported
(`NAT_ADDRESS_EXPOSED`), because one of the two platforms let that traffic in
and the other did not. The same care goes for ports, also on rules to any
destination: a rule whose service covers only the port on the wrong side of a
port translation is reported (`NAT_PORT_EXPOSED`), one that names the port of
the side being left has to be adjusted (`NAT_PORT_TRANSLATION`). What is
compared is addresses, ports and source zones; a rule that tells such traffic
apart by something else is reported all the same. All of this is worked out
per rule against what the rule named to begin with and what it names in the
end, so the order of the NAT rules does not decide what is found: a rule for
one of two public addresses of a server is a rule for the server after NAT,
and is reported whichever NAT rule comes first.

A **negated** destination has to name the same on both sides of a
translation (all of both, none of either, or the same part of a network that
is translated address for address). Otherwise the rule would change meaning,
and it is converted disabled.

Between two platforms of the **same kind** (FortiOS, iptables and ASA among
each other) none of this is needed when the target gets the NAT rule: the
rule is written with the destinations the source had, and the findings above
are withdrawn. They stay for a NAT rule that could not be written.

The second column matters too:

* **From FortiOS, iptables or ASA to PAN-OS or Check Point.** A connection that got
  a destination translation *and* a source translation from two rules gets
  only the first of them on the target (note `NAT_ORDER`). Combine the two in
  one NAT rule where that matters.
* **From PAN-OS or Check Point to FortiOS or iptables.** On the source, a rule
  higher up claims a connection and the rules below never see it: a no-NAT
  rule above a destination NAT keeps part of the traffic untranslated, a
  destination NAT above a source NAT keeps the source address of what it
  forwards. The target applies both tables to every connection, and matches
  source translations *after* the destination was translated. FWShift compares
  the NAT rules pairwise, by zones, addresses and services, and reports the
  rules whose effect it can see changing (`NAT_ORDER` on the rule). Where it
  cannot tell whether two rules meet, it assumes they do; where the translated
  traffic leaves the firewall it reads from the security rules that allow it.
  That finds the usual cases, not provably all of them, and it does not
  rewrite the order: test NAT on the target, and add an exemption where it
  matters.
* **A NAT rule that is not converted** no longer claims its traffic. The
  translating rules below it that now receive that traffic are reported
  (`NAT_ORDER`), on every target.
* **iptables `ACCEPT` in `PREROUTING`** keeps a destination untranslated and
  nothing else, while the source translations of `POSTROUTING` still apply.
  The model has no rule that says "this half only", so it is not converted,
  on any target, and reported.
* A rule that translates destination **and** source is written in both tables.
  Its source half is matched after the destination was translated, so it is
  written for the new address and port and for every outgoing interface
  (`NAT_OUTPUT_INTERFACE`, `NAT_AFTER_DNAT`).
* **To ASA** every NAT rule becomes one twice NAT line, in order. A line that
  names source and destination claims its connections whole, as a rule of the
  model does; a line without a destination part does not keep a later rule
  from translating the destination, and that is what `NAT_ORDER` reports
  there.

### iptables

**What is read**

* The `FORWARD` chain of the `filter` table is the policy. `INPUT` and
  `OUTPUT` filter the traffic of the host itself and are reported, not
  converted (`HOST_CHAIN_NOT_CONVERTED`).
* Interfaces are the zones: `-i eth1 -o eth0` is a rule from zone `eth1` to
  zone `eth0`. Use `--zone-map eth1=trust` to give them the names of the
  target.
* Chains that `FORWARD` jumps to are flattened: every rule of a chain is
  combined with the rule that jumped to it, exactly. A jump for `10.0.0.0/8`
  to a chain with a rule for `10.1.0.0/16` gives a rule for `10.1.0.0/16`; a
  rule that can never match under its jump is left out. What cannot be
  flattened exactly is not guessed: a rule after a conditional `RETURN` or a
  conditional `-g`, a loop, a combination of negations that one match cannot
  say. Those rules are written disabled.
* iptables filters packets, the other platforms connections. The rule that
  accepts `ESTABLISHED,RELATED` is what a stateful firewall does by itself and
  is left out, as are drops of `INVALID` packets. If no such rule exists the
  ruleset is stateless and the report says what that means
  (`STATELESS_RULESET`).
* A rule without addresses in an IPv4 ruleset matches IPv4 only and becomes
  `0.0.0.0/0`, not `any`.
* A match FWShift does not know (`-m recent`, `-m limit`, `-m set`, `-m owner`,
  a negated interface, ...) is never read as "matches everything": the rule is
  written disabled and the report names the match.
* `LOG` rules decide nothing. One that stands directly before a rule with the
  same match turns on logging for that rule.
* `nat` table: `DNAT` rules of `PREROUTING` and `SNAT` / `MASQUERADE` rules of
  `POSTROUTING` become NAT rules, an `ACCEPT` in `POSTROUTING` a no-NAT rule.
  `REDIRECT`, `NETMAP`, an `ACCEPT` in `PREROUTING` and IPv6 NAT are not
  converted.
* An address with a mask that is not a network mask (`-s 0.0.2.34/0.0.255.255`)
  is not read as a network: the rule is written disabled.

**What is written**

* A file for `iptables-restore` (or `ip6tables-restore`) with the `FORWARD`
  chain and, for IPv4, the `nat` table. It never contains `INPUT` or `OUTPUT`.
  Section 10 says how to load it.
* The chain starts with the two rules the other platforms have built in:
  accept `RELATED,ESTABLISHED`, drop `INVALID`. Allow rules match new
  connections (`--ctstate NEW`).
* The policy of the chain is `DROP`, or `ACCEPT` when the source allows what
  no rule matches.
* Objects do not exist in iptables: addresses and ports are written into the
  rules. A rule with a few combinations is written as that many lines. A rule
  with long lists, or with a negated list, becomes a chain of its own
  (`FWS1`, `FWS1-1`, ...): the packet walks source, destination and service
  and falls back into `FORWARD` as soon as one of them does not match.
* IPv4 and IPv6 are separate programs. `--to iptables` writes what can match
  IPv4, `--to ip6tables` what can match IPv6; run both.
* A rule that cannot be enforced is written as a comment line that starts with
  `# FWSHIFT disabled`, in its place.
* A host name is written as it is; iptables resolves it once, when the file is
  loaded (`FQDN_RESOLVED_ONCE`).
* Logging is not written (`LOGGING_NOT_CONVERTED`).

### Check Point

**What is read**

* One ordered access layer. Rules match the original packet, like the model.
* Rules have no zone columns. A security zone object in the source or
  destination cell becomes the zone of the rule; a rule without one applies
  from any zone to any zone. A cell that lists zones *and* addresses means
  "either" on Check Point, which a rule on the other platforms cannot say: it
  is written disabled.
* An **inline layer** is flattened. Each of its rules is combined with the
  rule that applies the layer (addresses are intersected exactly, also where a
  cell is negated), in the place of that rule. A connection that enters an
  inline layer never returns, so the layer's cleanup follows its rules: its
  own last rule if that matches everything, otherwise a rule for the layer's
  implicit cleanup action (`INLINE_CLEANUP`).
* **Implied rules** and the settings in Global Properties are not in the
  export (`IMPLIED_RULES`).
* An object with **automatic static NAT** also stands for its translated
  address wherever a rule or group names it, as it does on Check Point. That
  address becomes a second object, `<name>_valid_address`, next to it. With
  manual NAT rules nothing of the kind happens: there the rules name the
  address of the original packet themselves.
* The NAT rulebase is read as it stands, automatic rules included. An
  automatic rule shows the object itself where its translated address is
  meant; the address is taken from the NAT settings of the object.
* A **gateway object** in a rule stands for every address of the gateway. The
  export has its main address only (`GATEWAY_OBJECT`).
* Not converted, and reported on the rules that use them: access roles, groups
  with exclusion, wildcard, dynamic and updatable objects, application and
  site objects, RPC and other services with a match expression, VPN
  communities, content, time objects, service resources, the identity captive
  portal.

**What is written**

* A shell script of `mgmt_cli add ...` calls: objects, the rules of one access
  layer, the NAT rules of one policy package. It never publishes and never
  installs a policy. Section 10 says how to run it.
* A rule that names a zone and nothing else on that side is written with the
  zone object in its cell. A rule that names a zone **and** addresses on the
  same side cannot be one Check Point rule. Such rules are sorted into inline
  layers, one per pair of zones (`<layer>_<from>_to_<to>`): the rule that
  applies the layer matches the zones, the rules inside match the addresses,
  in their original order, together with every other rule that can apply to
  that pair. Policies with many zone pairs get many layers.
* Every layer written ends in an explicit cleanup rule (`FWShift cleanup`),
  unless its last rule matches everything already. Nothing depends on the
  implicit cleanup action of a layer.
* The zones are created if they do not exist. They have to be assigned to the
  interfaces of the gateway; an interface without a zone only reaches the
  rules that name no zone.
* All objects of a Check Point management server share one namespace. A
  service named like an address is renamed, and so is anything named like a
  zone. Check Point also predefines several hundred objects (`http`, `ssh`,
  ...); the script stops when it tries to create one that exists. Convert
  with `--target-prefix` to put a prefix in front of every created object.
* A service with several ports or protocols becomes one service object per
  port and a service group; a literal address in a rule gets an object
  (`h-192.0.2.1`, `n-10.0.0.0_24`).
* NAT rules are written as manual rules. Zones are left out of them
  (`NAT_ZONES`); source NAT to "the outgoing interface" needs the gateway
  object (`--target-gateway`).

### Cisco ASA

**What is read**

* The interface names (`nameif`) are the zones. Interfaces marked
  `management-only` forward nothing and are left out.
* The access list bound **inbound** to an interface holds the rules for
  traffic arriving on it; the **global** access list follows it for every
  interface; then everything is denied. Entries become rules named
  `<list>-<number>`; the remarks above an entry become its description.
* An ASA does **not** send traffic back out of the interface it came in on,
  nor between two interfaces of the same security level, unless
  `same-security-traffic permit intra-interface` / `inter-interface` says so,
  whatever the access lists permit. A permit entry therefore becomes a rule
  to the interfaces its traffic can leave by, not to "any". An entry of a
  list that serves several interfaces, or of the global list, becomes an
  interzone rule over all interfaces. Deny entries need none of this.
* Where a permit entry names **destination addresses**, the destination zone
  is narrowed to the interface those addresses are routed to, going by the
  interface addresses and static routes (`EGRESS_BY_ROUTE`). That is what
  makes "permit any to the web server" a rule from outside to dmz. With a
  routing protocol, a route map or policy routing in the configuration only
  connected networks are trusted; with bridge groups or for networks of an
  interface that is shut down nothing is narrowed. A permit that can then
  match nothing (its destination lies behind the interface it comes in on)
  is left out and counted (`RULE_WITHOUT_EFFECT`).
* An interface **without** an access list, on an ASA without a global one,
  lets traffic out to interfaces of a lower security level. That becomes a
  rule (`implicit-<interface>`, `IMPLICIT_PERMIT`).
* An access list bound **outbound** is a second check on the way out. A list
  that only denies and then permits everything is converted: its denies come
  first, for traffic towards that interface. Anything else is reported and
  not converted (`OUTBOUND_ACL`).
* Ports and ICMP types by name, port operators (`eq`, `lt`, `gt`, `neq`,
  `range`), protocol, port and ICMP-type object groups, service objects and
  groups, `inactive`, `log`. A service that an entry spells out becomes an
  object named after it (`tcp-443`, `icmp-8`).
* Whatever in an entry is not understood in full makes the rule unusable,
  never wider: it is converted disabled, with the reason. That goes for
  `time-range` (a schedule), TrustSec matches, the address of an interface,
  and for anything that follows where the entry should end. A `user` or
  `user-group` match is kept as a user match of the rule: PAN-OS gets it as
  `source-user`, a target without users gets the rule disabled.
* **NAT** (8.3 and later) is read in the order the ASA applies it: twice NAT,
  then object NAT sorted the ASA's way (static before dynamic, the fewest
  real addresses first), then twice NAT `after-auto`. Access lists name the
  real address of a translated host; the model wants the original one, so the
  rules are extended by it (`NAT_DESTINATION_REWRITTEN`). A port published
  with `static ... service` is read as a destination translation for traffic
  arriving on the mapped interface. `interface` as an address becomes an
  object with the address the interface has (`NAT_INTERFACE_ADDRESS`).
* **Before 9.0** `any` is IPv4 and the `ipv6 access-list` lines are not
  converted. **Before 8.3** NAT is not converted, and the access lists are
  taken to name translated addresses, as they did.
* **FTD.** Entries name their interfaces (`ifc`), and one rule of the manager
  is several entries with one rule id: they are merged back into one rule,
  named after the manager's remark. An FTD forwards between and within all
  interfaces. Rules with application, URL or user conditions are converted
  disabled (section 3).
* Not read: time ranges, inspection and service policies, VPN, routing
  protocols, failover, and everything else outside the policy. Traffic from
  VPN tunnels bypasses the access lists by default (`VPN_BYPASS`), and ICMP
  is not stateful without `inspect icmp` (`ICMP_STATELESS`).

**What is written**

* Commands for the configuration mode of an ASA 9.x: `object network`,
  `object-group network`, `object service`, `object-group service`,
  `access-list`, `nat`, `access-group`. Interfaces are not configured.
* One access list per source zone, `<zone>_access_in`, bound inbound, and
  `global_access` for rules from any zone. The ASA reads the list of an
  interface before the global one, so a rule for every zone that stands above
  a rule of one zone is repeated in that zone's list, in place. The global
  list always ends the policy, with a deny (or with a permit where the source
  accepts what no rule matches): no interface is left to the ASA's own permit
  towards lower security levels.
* An entry holds one source, one destination and one service. Lists become
  object groups (`FWSHIFT_NETWORK_1`, `FWSHIFT_SERVICE_1`), literal addresses
  are written into the entry or get an object (`h-192.0.2.1`,
  `r-10.0.0.1-10.0.0.9`).
* **Destination zones.** An entry cannot name the interface traffic leaves
  by. A rule to zone `any`, or to every other zone the policy knows, needs
  nothing: it is an entry for any destination. For any other rule:
  * with `--zone-network` for every zone the rule is for and every zone it
    has to be told apart from, the networks of the zones it is *not* for are
    left out of its destination (`EGRESS_BY_NETWORKS`). That is exact when
    the networks are right and complete, for IPv4 and for IPv6. Nothing is
    assumed where they are not:
    * a zone without networks is not "the rest". A rule that is for it, or
      has to be kept away from it, is treated as if no networks were given
      (below), and the finding names the zone;
    * an address that lies in none of the networks lies behind no zone that
      is known. The side that allows less is taken: a permit rule for any
      address does not cover it, a deny rule does, and the report says so
      (`ZONE_NETWORK_GAP`). `0.0.0.0/0,::/0` for the zone with the default
      route leaves no such address;
    * with IPv4 networks only, every IPv6 address is such an address;
    * a zone given "everything else" while another zone has no networks
      is reported (`ZONE_NETWORK_INCOMPLETE`).

    A rule whose destination then has no address left behind its zones matched
    nothing and is left out, with a finding (`EGRESS_NO_ADDRESS`; needs review
    for a deny rule). What cannot be noticed is a network that is wrong: a
    range given for one zone that holds a network of a zone given another
    range, without that smaller network being given too;
  * otherwise, a rule that names destination addresses is written for those
    addresses, by whatever interface they are reached (`EGRESS_INTERFACE`,
    approximated), and a rule to any address is written `inactive`
    (`EGRESS_INTERFACE`, needs review): enabled, it would allow traffic to
    every zone.

  The lists are written for an ASA whose interfaces are the zones of the
  policy and no others, and that does not send traffic back out of the
  interface it came in on (`INTERFACES_REQUIRED` says so). With the networks
  of a zone given, rules from that zone leave them out, and the second
  assumption is not needed.
* A rule that cannot be enforced is written `inactive`, with a remark. Where
  an inactive entry would read as the opposite of the rule (a negation that
  cannot be written), only a remark is written.
* A service that one entry can say (`tcp ... eq 443`) is written into the
  entry when it comes from an ASA; services of other sources become objects.
  A host name resolved for both IP versions becomes two `fqdn` objects and a
  group.
* **NAT** is written as twice NAT, one line per rule (per port of its
  service). A destination translation names the source side as well and is
  marked `unidirectional`, so that it does what the rule of the model does and
  no more. From a source that applies a destination NAT and a source NAT to
  the same connection (FortiOS, iptables, ASA), a published port is written
  the way an ASA does it, from the side of the server, and source NAT rules
  still apply to its clients. Rules without translation get `no-proxy-arp`.
  Source NAT "to the outgoing interface" needs to know the interface: from
  the rule, or from `--target-nat-zone`.
* Names keep to letters, digits, `.`, `_` and `-`, 64 characters; names that
  come from an ASA are kept as they are (printable characters without `?`
  and `"`). Words of the command line (`any`, `interface`, `host`, ...) are
  not used as names, and network and service objects do not share a name.

### Names

Names the target would reject are changed: `10.0.0.0/8` becomes `10.0.0.0_8`
on PAN-OS, FortiOS policy names are cut to 35 characters, collisions get a
numeric suffix, and every reference follows. An object named like something
the target predefines (`all`, `ALL`, `HTTP` on FortiOS; `any`, `service-http`
on PAN-OS) is renamed rather than allowed to redefine it. Each change is
reported as `RENAMED`.

### Names from the input

Every output format is line-based. A control character in a name of the input
(a line break, a tab) is replaced by `_` before anything is written, a host
name that holds anything but host name characters makes its object unusable,
and option values with control characters are refused.

### What is not carried over

Security profiles, schedules, users and groups, URL categories, HIP profiles
and tags (to FortiOS, Check Point and iptables) are not converted. Where a rule depends on one of them
for its *match*, the rule is disabled; where it only adds inspection, the rule
is reported as approximated.

## 9. The application map

`--app-map FILE` names a JSON file that maps application names to port
specifications. It adds to, and overrides, the built-in table.

```json
{
  "bittorrent": ["tcp/6881-6889", "udp/6881-6889"],
  "my-erp": ["tcp/8443"],
  "ssl": ["tcp/443", "tcp/8443"]
}
```

| Spec | Meaning |
|---|---|
| `tcp/443`, `udp/53`, `sctp/2905` | one port |
| `tcp/8000-8080`, `tcp/80,443` | a range or a list |
| `icmp/8`, `icmp/any` | ICMP type, or every type |
| `icmp6/128`, `icmp6/any` | the same for ICMPv6 |
| `ip/47` | an IP protocol number (1 to 255) |

The built-in table covers common protocols, among them `web-browsing`, `ssl`,
`dns`, `ssh`, `ntp`, `smtp`, `ldap`, `ms-rdp`, `ms-ds-smb`, `snmp`, `syslog`,
`mysql`, `bgp`, `ike`, `ping`, and the industrial protocols `modbus`, `dnp3`,
`siemens-s7`, `bacnet` and `mqtt`. See `src/fwshift/appmap.py` for all of it.

## 10. Loading the output

**Always in a lab first.**

### PAN-OS

The output contains nothing but `set` commands.

1. Make sure the zones named in `ZONES_REQUIRED` exist.
2. In the CLI: `set cli scripting-mode on`, then `configure`.
3. Paste the file.
4. Review the candidate configuration, then `commit`.

Rules are created in the order of the file and land after existing rules. For
Panorama, convert with `--target-device-group NAME` or `--target-shared`.

### FortiOS

1. If the output contains `config firewall vip` or `config firewall
   central-snat-map`, enable central NAT first:

   ```
   config system settings
       set central-nat enable
   end
   ```

   On a FortiGate that uses per-policy NAT this changes how its existing
   policies translate. Do it on a new or lab device.
2. Assign interfaces to the zones the output creates, or convert again with
   `--zone-map` so that the policies name existing interfaces.
3. Paste the file into the CLI, or run it as a script.

Policies use `edit 0` and are appended after existing ones. Objects are
created by name: an object that already exists under the same name is
overwritten.

### iptables

The output holds the `FORWARD` chain (and the `nat` table) only. Plain
`iptables-restore` **replaces** every table that is in the file. The `INPUT`
and `OUTPUT` rules of the host are in the `filter` table: they would be gone,
and the host with them unprotected or, with a `DROP` policy left behind,
unreachable.

1. Convert with `--zone-map` so that the rules name the interfaces of the
   host, for both IP versions:

   ```sh
   fwshift convert policy.xml --to iptables  -o rules.v4 --zone-map trust=eth1 --zone-map untrust=eth0
   fwshift convert policy.xml --to ip6tables -o rules.v6 --zone-map trust=eth1 --zone-map untrust=eth0
   ```

2. Check the syntax without loading: `iptables-restore --test rules.v4`.
3. On a host whose `FORWARD` chain is empty, add the rules to what is there:
   `iptables-restore --noflush rules.v4`. Do it once: a second run adds every
   rule a second time. Otherwise merge the file into your own ruleset by hand.
4. Forwarding itself (`net.ipv4.ip_forward`) is a setting of the host.

### Check Point

The output is a shell script. It needs `mgmt_cli`, which is on every
management server and in the SmartConsole installation.

1. Create the target layer and policy package if they do not exist, and
   convert with `--target-layer` / `--target-package` naming them.
2. Log in and keep the session in a file:

   ```sh
   mgmt_cli login -r true > fwshift.sid            # as root on the management server
   mgmt_cli login user admin -m 192.0.2.10 > fwshift.sid     # from elsewhere
   ```

3. Run the script: `sh checkpoint.sh`. From elsewhere:
   `MGMT_OPTS='-m 192.0.2.10' sh checkpoint.sh`.
4. The script stops at the first call the server refuses and prints it. A
   policy with rules missing is not a safe policy: discard the session
   (`mgmt_cli discard -s fwshift.sid`), fix the cause and run it again. The
   usual cause is a name that exists already; if the existing object is the
   one you want, delete its line from the script, otherwise convert again with
   `--target-prefix`.
5. Look at the session in SmartConsole. Nothing is published:
   `mgmt_cli publish -s fwshift.sid` keeps the changes, `discard` throws them
   away. Installing the policy is up to you.
6. Assign the security zones to the interfaces of the gateway, and add proxy
   ARP for translated addresses (`NAT_MANUAL_RULES`).

### Cisco ASA

The output is a list of commands for configuration mode.

1. Convert with `--zone-map` so that the access lists name the interfaces
   (`nameif`) of the ASA, and with `--zone-network` where the report asks for
   it. The interfaces must exist; give them different security levels, or set
   `same-security-traffic permit inter-interface`.
2. Read the lines at the end first. `access-group <list> in interface <name>`
   **replaces** the access list bound to that interface now, and
   `access-group global_access global` ends the policy for every interface of
   the ASA, including those the output does not name. Remove these lines if
   you want to look at the lists before they take effect.
3. An access list that exists under the same name gets the new entries added
   to its own, and an object group its new members. Load the output on an ASA
   that has neither, or convert with `--target-prefix`.
4. The NAT lines are twice NAT rules. An ASA adds them at the **end of
   section 1** of its NAT table: manual NAT rules the ASA already has stay in
   front of the new ones and win; only its network object NAT (section 2) and
   `after-auto` rules (section 3) come after them. Load the output on an ASA
   without manual NAT rules, or check the order with `show nat`.
5. `configure terminal`, paste the file, check with `show access-list` and
   `show nat`, then `write memory`.
6. Objects with a host name need DNS (`dns domain-lookup <interface>` and a
   DNS server group).

### After loading

Search the configuration for `FWSHIFT`: every placeholder object and every
rule the converter disabled carries that word in its comment or description.

## 11. Errors and troubleshooting

| Message | Cause and remedy |
|---|---|
| `configuration with several virtual systems; choose one with --vsys: ...` | Name one of the listed virtual systems. |
| `Panorama configuration with several device groups; choose one with --device-group: ...` | Name one of the listed device groups. |
| `configuration with several VDOMs; choose one with --vdom: ...` | Name one of the listed VDOMs. |
| `no <config> element found` | The XML is not a PAN-OS configuration export. |
| `not well-formed XML: ...` | The file is damaged or is not XML; a `set`-format file is not supported as input. |
| `the XML contains a DOCTYPE or entity declaration` | PAN-OS exports never do; the file is refused as a precaution. |
| `no 'config' sections found` | The file is not a FortiOS configuration. An encrypted backup looks like this. |
| `unterminated quoted string starting on line N` | A double quote on that line is never closed. Fix or escape it. |
| `invalid port spec '...'` | An entry in the `--app-map` file is not in the format of section 9. |
| `no tables found; expected the output of iptables-save or ip6tables-save` | The file is not a saved iptables ruleset. A script of `iptables -A ...` commands is not one: load it and save the result. |
| `only '-A CHAIN ...' rules are understood` | The same: `-I`, `-D` and other commands do not occur in saved rulesets. |
| `the chains expand to more than 50000 rules` | Chains that jump to each other many times over. Not converted. |
| `not valid JSON` / `no Management API response found` | The file is not the JSON output of `show access-rulebase`. Use `--format json`. |
| `the export holds several access layers; choose one with --layer: ...` | Name one of the listed layers. Inline layers are found by themselves. |
| `layer '...' not found; available: ...` | `--layer` names a layer that is not in the input. |
| `the inline layers expand to more than 50000 rules` | Inline layers nested many times over. Not converted. |
| `no Cisco ASA configuration found; expected the output of 'show running-config'` | `--from asa` on a file that has no interfaces, objects, access lists or NAT of an ASA. |
| `this is the system configuration of an ASA in multiple context mode` | It holds no policy. Convert the configuration of each context. |
| `the configuration could not be read (...)` | An ASA configuration that is damaged in a way FWShift did not foresee. Please report it. |
| `--zone-network expects ZONE=NETWORK[,NETWORK...]` | Write the option as `--zone-network dmz=10.20.0.0/24,2001:db8:20::/64`. |
| `--zone-network: ... overlap without one lying inside the other` | Two zones were given the same network, or ranges that cut across each other. A network inside another one is fine. |
| `--target-nat-zone: '...' cannot be an interface name` | ASA target: the value is not a name an interface can have. |
| `--zone-map: 'any' stands for every zone and cannot be the name of one` | Map the zone to a real name. |
| `control characters are not allowed in ...` | An option value holds a line break or another control character. |
| `--target-layer '...' is not a name mgmt_cli can be given` | The name starts with a hyphen. The same message exists for `--target-package` and `--target-gateway`. |
| `--zone-map expects SOURCE=TARGET` | Write the option as `--zone-map old=new`. |

**Most rules are "needs review".** Read the first finding of a few rules. A
single cause usually explains many: applications missing from the port table
(`--app-map`), an object type that is not converted, FortiOS attributes
FWShift does not know, or a Check Point export without `details-level full`
and `dereference-group-members true`, in which the objects are names without
content.

**Most rules for an ASA are inactive, with `EGRESS_INTERFACE`.** The source
policy has rules "from zone A to zone B, any address", and an ASA access list
cannot say "to zone B". Tell FWShift which networks lie behind the zones with
`--zone-network`: the networks of every zone, with `0.0.0.0/0,::/0` for the
one that stands for "everything else" (the Internet side). A rule stays
inactive as long as a zone it is for, or has to be told apart from, has no
networks; the finding names that zone.

**Rules for an ASA allow less than expected, with `ZONE_NETWORK_GAP`.** The
networks given do not cover every address: the default route is missing, or
only IPv4 networks were given. What no network covers is allowed by no rule
for any address that is kept to its zone. Add `0.0.0.0/0,::/0` to the zone
the default route points to.

**The output is larger than expected.** Every object of the source is
converted, used or not; a FortiOS backup alone defines some ninety default
services. Use `--prune-unused`.

**The report mentions `0.0.0.0/0` where the source says `all`.** That is
deliberate: see *IPv4 and IPv6* in section 8.

## 12. Limits

* The emitted syntax follows the vendors' documented formats. Only iptables
  output has been loaded into the real thing (a Linux kernel with iptables
  1.8.10, nf_tables backend; filter rules, not NAT); nothing has been
  validated on PAN-OS, FortiOS or ASA devices or a Check Point management
  server, or across versions.
* Statements about vendor behaviour that the conversion relies on (FortiOS
  policy lookup after destination NAT, `match-vip`, PAN-OS FQDN resolution, the
  commands each CLI accepts, the fields of the Check Point Management API, what
  an object with automatic NAT matches, what an ASA forwards without being
  told and how it orders and combines NAT rules) come from documentation and
  still need confirming. `DEVELOPMENT.md` lists them.
* A port-translating destination NAT is reported, not corrected.
* A connection that needs destination *and* source NAT from separate FortiOS,
  iptables or ASA rules gets one of them on PAN-OS and Check Point; the order
  of a first-match NAT rulebase is reported, not reproduced, on FortiOS,
  iptables and ASA (section 8).
* Source NAT rules derived from FortiOS policies match on zones and addresses,
  not on the policy's services.
* Dynamic address groups survive only PAN-OS to PAN-OS.
* iptables: only forwarded traffic is converted. Matches beyond interfaces,
  addresses, protocols, ports, ICMP types and connection state disable the
  rule. IPv6 NAT and `nft` rulesets are not read.
* Check Point: one ordered layer per run; implied rules, Global Properties,
  identity awareness, application control, content awareness and VPN
  communities are not converted. The output is `mgmt_cli` calls for the
  firewall (network) blade only.
* Cisco ASA: one configuration (one context) per run. Time ranges, user and
  TrustSec matches, outbound access lists that do more than deny, NAT of
  releases before 8.3, IPv6 access lists of releases before 9.0, inspection
  and service policies and VPN are not converted. Destination zones are worked
  out from interface addresses and static routes: where routing is decided by
  a routing protocol, FWShift does not narrow and the rules name every
  interface the traffic could leave by. Bridge groups are not modelled. ASA
  to ASA is not a copy: the names of access lists, `log` on a deny, time
  ranges and object NAT (written back as twice NAT) change.
* Cisco FTD: only what the device configuration shows. Rules with
  application, URL or user conditions come out disabled; for those the
  manager's policy is the source, and FWShift does not read it.
* To an ASA, a rule "to zone B, any address" needs `--zone-network`; without
  it the rule is written inactive. The networks you give are taken to be
  right: a zone or an address nobody mentioned is handled on the side that
  allows less and reported, but a network given to the wrong zone is not
  noticed.
* ASA before 9.0: an interface whose only access list is an IPv4 one gets no
  rule for the IPv6 traffic the ASA let out by security level.
* A rule that names an address which a destination NAT translates away (dead
  on a platform that looks rules up after NAT) is converted as a rule for
  that address, with a finding (`NAT_ADDRESS_EXPOSED`). Back to a platform
  of the same kind, with the same NAT rule, it is left as it was.
* PAN-OS `set`-format input, schedules, and user and group mapping are not
  implemented yet.

## 13. Auditing a policy

A migration is the moment a rulebase gets looked at. The audit looks at it
for you, in the vendor-neutral model, so it is the same for every format
FWShift reads:

```sh
fwshift audit asa-running.cfg                      # a report, nothing else
fwshift convert asa-running.cfg --to panos --audit # before and after the conversion
```

```
FWShift audit
  source: asa (ASA Version 9.12(4))
  security rules: 18 (1 disabled), NAT rules: 5

Summary
  high 0, medium 4, low 10, info 2

Findings in the policy as it was read
  [medium] RISKY_SERVICE: rule 'inside_access_in-7' allows rdp, from zone inside to zone outside, dmz, guest (on the list of the cleartext and remote administration protocols)
  [low] REDUNDANT_RULE: rule 'inside_access_in-4' never matches: 'inside_access_in-2' above it already allows everything it could match
  [info] UNUSED_OBJECT: 2 services no rule uses: 'svc-http', 'svc-http-alt'
  ...
```

### The checks

`fwshift audit --list-checks` prints this table.

| Check | Level | What it finds | Can be |
|---|---|---|---|
| `ANY_ANY_ANY` | high | An allow rule for any source, any destination and any service. | off, accept, report, disable |
| `ANY_SERVICE` | medium | An allow rule for any service (or any application on its default ports). | off, accept, report, disable |
| `ANY_TO_ANY` | medium | An allow rule from any source to any destination, for named services. | off, accept, report, disable |
| `ANY_SOURCE` | low | An allow rule from any source to named destinations. Normal for a published service. | off, accept, report, disable |
| `ANY_DESTINATION` | low | An allow rule from named sources to any destination. Normal for outbound access. | off, accept, report, disable |
| `WIDE_NETWORK` | low | An allow rule that names a network of /8 or larger (IPv6: /32). | off, accept, report, disable |
| `WIDE_PORTS` | low | An allow rule for a range of 1024 ports or more. | off, accept, report, disable |
| `RISKY_SERVICE` | medium | An allow rule for a protocol on the list of those that carry passwords in the clear or give a remote session: telnet, FTP, TFTP, the r-services, NetBIOS, SMB, RDP, VNC, SNMP, X11. | off, accept, report, disable |
| `INDUSTRIAL_SERVICE` | low | An allow rule for a control system protocol (Modbus, S7, DNP3, EtherNet/IP, OPC UA, BACnet, IEC 104, PROFINET, FINS, Niagara Fox). Nothing wrong with it; where such a protocol crosses a firewall is worth knowing. | off, accept, report, disable |
| `NO_LOG` | low | A rule that does not log. PAN-OS and Check Point sources only: there the model holds whether a rule logs. | off, accept, report |
| `NO_PROFILE` | low | An allow rule without a security profile. PAN-OS and FortiOS sources only. | off, accept, report |
| `SHADOWED_RULE` | high | A rule that never matches, because earlier rules take all it could match, and some of that they decide the other way. High for a blocking rule (a block that is not enforced), medium for an allow rule. | off, accept, report, disable, reorder |
| `REDUNDANT_RULE` | low | A rule that can go without anything changing: it never matches because earlier rules with the same action hold all of it, or it matches but a later rule handles all of its traffic the same way. | off, accept, report, disable |
| `EMPTY_RULE` | low | A rule that can match nothing by itself: zones that leave no pair of zones, a negation that leaves nothing, a group without members, an IPv4 source with an IPv6 destination. | off, accept, report, disable |
| `OVERLAPPING_RULES` | info | A rule of which earlier rules with another action take a part. Usually intended (the exception above the rule); off by default. | off, accept, report |
| `SHADOWED_NAT` | medium | A NAT rule that never matches because earlier NAT rules translate all it could match. Only where one NAT rule applies to a connection (PAN-OS, Check Point manual rules). | off, accept, report |
| `DISABLED_RULE` | info | A rule that is disabled. | off, accept, report |
| `NO_DESCRIPTION` | info | A rule without a description. Off by default. | off, accept, report |
| `UNUSED_OBJECT` | info | Objects that no rule, NAT rule or group in use refers to. Predefined objects are left out. | off, accept, report |
| `DUPLICATE_OBJECT` | info | Addresses or services with the same content under several names. Objects a parser made up (for an inline address, say) are among them. | off, accept, report |
| `EMPTY_GROUP` | low | A group without members: it matches nothing. | off, accept, report |
| `DEFAULT_ALLOW` | high | Traffic between zones that no rule matches is allowed. | off, accept, report |
| `EXPOSED_BY_CONVERSION` | high | After a conversion only: a blocking rule that is not in the output as it was, with something that now allows part of what it blocked. | off, accept, report |

The level of `ANY_ANY_ANY`, `ANY_SERVICE` and `ANY_TO_ANY` is one lower for
a rule whose zones keep it to a part of the firewall: there is a zone it
neither comes from nor goes to, or it is for traffic inside a zone. A rule
from one zone to *every* other zone
names zones without being kept anywhere, and keeps its level: that is what
every access list on an ASA or a chain on iptables looks like.

Only enabled rules are looked at. The audit knows what a policy *says*, not
how it is used: which rules are hit, and which zone is the trusted one, is
not in a configuration.

### Rules that never match

A rule is called shadowed, redundant or empty only when that follows from
what can be read: zones, addresses, protocols, ports and ICMP types, with
every negation and every group resolved. The comparison is with **all**
earlier rules together, not rule by rule: a rule that three earlier rules
cover between them is found. IPv4 and IPv6 are kept apart: a rule from an
IPv4 network to "any" matches no IPv6 packet.

"Never matches" is a statement about the policy as FWShift read it. What
cannot be read, or was read only approximately, is taken on the side that
makes the claim harder:

* a host name, a dynamic group, a group with excluded members, an
  application on its default ports, an object that could not be converted:
  a rule that is *covered* counts as matching whatever such a member might
  stand for; a rule that *covers* counts as matching only what it surely
  does. Two rules that use the same name are compared by the name;
* an application, user, URL category or schedule on an earlier rule keeps it
  from covering a later rule that does not have the same or a narrower one;
* a rule with a criterion the model does not hold covers nothing;
* **a rule the parser itself reported as approximated or needs-review**
  (installed on one gateway only, an attribute FWShift does not know, a
  match that was widened) is left out on both sides: it is not called dead,
  and it is not used to call another rule dead. The same goes for the
  addresses of an object that was read approximately (a Check Point gateway
  object, of which only the main address is in the export). These rules are
  listed under *Left out of the order checks*, with the finding that put
  them there.

So what the audit calls dead is dead in the model, and it may miss a dead
rule where names, applications or an approximate reading decide. A rule that
falls into more than 4096 pieces while earlier rules are taken out of it is
not followed further; it is listed in the same place.

**Destination NAT.** iptables, FortiOS and the ASA match a rule on the
address *after* destination NAT; the model holds every rule the PAN-OS way,
on the address before it, and the parser adds that address (section 8). The
audit reads such a source as the firewall did: without the addresses the
parser added. A FortiOS policy that names a virtual IP is taken as matching
the traffic that virtual IP translates, which proves nothing about a policy
for the plain address.

The difference between the two findings is what the rule was for. If rules
above it with the *same* action hold all of it, it has nothing of its own:
`REDUNDANT_RULE`, even where a blocking rule further up takes part of that
traffic (it takes it from those rules just the same). If part of what it
could match is only ever decided the *other* way, the rule says something the
policy does not do: `SHADOWED_RULE`, and the message names who takes what.

A rule that *does* match is redundant when a later rule handles all of its
traffic the same way and no rule in between decides any of it otherwise.
"The same way" is more than the verdict: logging, security profiles, and
what else the source rule does to a session (NAT in a FortiOS policy, a
traffic shaper, a PAN-OS log forwarding profile or QoS marking, the track
setting of a Check Point rule).

### What to do with a finding

Each check has an action:

| Action | Meaning |
|---|---|
| `report` | List the finding. The default for most checks. |
| `off` | Do not run the check. |
| `accept` | The findings of this check are fine: they are counted and listed under *Accepted* (those from after a conversion too), and do not make `--audit-fail-on` fail. |
| `disable` | In a conversion: write the rule disabled. Not for `NO_LOG` and `NO_PROFILE`: a rule that does not log, or has no profile, is not a rule that should go (and `NO_LOG` finds blocking rules too). |
| `reorder` | `SHADOWED_RULE` only, in a conversion: move the rule up, in front of the first rule that decides its traffic the other way. |

```sh
fwshift convert in.cfg --to panos -o out.set --report report.txt \
    --audit-action REDUNDANT_RULE=disable --audit-action SHADOWED_RULE=reorder \
    --audit-accept 'Inbound-*=ANY_SOURCE' --audit-accept Legacy-FTP
```

**One rule can be let through** with `--audit-accept RULE` (every check) or
`RULE=CHECK,CHECK`. A NAT rule or an object is accepted by its name the same
way. The name as it is written comes first; in a pattern only `*` and `?`
stand for something else, so a rule called `Allow [DMZ]` is accepted under
that name. Two findings are not accepted by "every check of this rule", only
with the check named: a finding about the whole policy (`DEFAULT_ALLOW`,
accepted as `default=DEFAULT_ALLOW` or with `--audit-action
DEFAULT_ALLOW=accept`), and `EXPOSED_BY_CONVERSION`, which is about what a
conversion did to a rule and not about the rule as it was reviewed. In the
configuration file an accepted rule can carry the reason, which is printed
with it. An acceptance that nothing answers to is listed under *Accepted,
but not found*: a typing error in a name does not go unnoticed.

**Disabling is of two kinds**, and the conversion report says which:

* `REDUNDANT_RULE`, `SHADOWED_RULE` and `EMPTY_RULE`: no traffic is decided
  differently, in verdict, logging, profiles or handling (`AUDIT_DISABLED`,
  info). This is proven before it is done, and twice. Once on the policy as
  it was read: after the other actions, and without the rules the target
  cannot take. And once on the rules as the target gets them, for which
  FWShift converts on trial: a target that matches its rules on the other
  side of a destination NAT than the source did (iptables to PAN-OS, PAN-OS
  to a FortiGate), or for which two zones became one, sees other addresses
  and zones in the same rule. A rule that changes nothing on the source and
  decides traffic in the output is kept, and so is a rule that only looked
  redundant next to a rule that is itself disabled or that the target cannot
  express. The audit says which rules it kept, and why.
* every other check: the rule allowed something, and no longer does
  (`AUDIT_DISABLED`, approximated). That is your decision; FWShift only
  carries it out.

**Reordering changes verdicts.** A shadowed rule that is moved up decides its
traffic from then on. For a blocking rule that closes something, for an allow
rule it opens something, and FWShift cannot know which of the two rules was
the mistake. Every moved rule is therefore listed as *needs review*
(`AUDIT_MOVED`). Rules that are not moved keep their order. Where a moved rule
still never matches (another moved rule, or a rule above its new place, has
all of it), the audit says so.

`fwshift audit` on its own changes nothing: `disable` and `reorder` are shown
as what a conversion would do, which makes it the place to try a
configuration out. `--to json` writes the model as it was read and refuses
the audit options.

### The configuration file

Everything in it is optional; a key that is not known is refused, at every
level, and so is a check that does not exist.

```json
{
  "checks": {
    "SHADOWED_RULE": "reorder",
    "REDUNDANT_RULE": "disable",
    "NO_PROFILE": "off",
    "ANY_SOURCE": {"action": "report", "level": "info"}
  },
  "accept": [
    "Legacy-*",
    {"rule": "Inbound-Web", "checks": ["ANY_SOURCE"], "reason": "the public web server"}
  ],
  "thresholds": {"wide_network_v4": 8, "wide_network_v6": 32, "wide_ports": 1024},
  "services": {
    "risky": {"telnet": ["tcp/23"], "rdp": ["tcp/3389", "udp/3389"]},
    "industrial": {"modbus": ["tcp/502"]}
  },
  "applications": {"risky": ["telnet", "ms-rdp"], "industrial": ["modbus"]},
  "fail_on": "high"
}
```

`services.risky` and `services.industrial` replace the built-in lists of
ports; `applications.risky` and `applications.industrial` replace the lists
of application names (for sources that name applications). Options on the
command line are applied after the file.

### Before and after a conversion

With `--audit`, `fwshift convert` audits twice:

1. **The policy as it was read.** The actions are carried out on it, and then
   it is converted.
2. **The policy as it was converted**: the same rules, without those the
   conversion wrote disabled or left out. Only what is new is listed, under
   *After the conversion*, with a summary line of its own.

The second audit is where a conversion that lost a rule shows its
consequence. A blocking rule that could not be written (to an ASA without
`--zone-network`, say) leaves the allow rules below it with more traffic
than they had:

```
After the conversion
  high 1, medium 0, low 0, info 0
  [high] EXPOSED_BY_CONVERSION: rule 'no-out' blocks traffic from zone trust to zone untrust on the source and is not enforced in the output: 'rest' below it now allows part of what it blocked. Fix the rule in the output before it goes live
  these never matched on the source and do in the output, because rules above them were not written: 'no-partner'
```

What takes the traffic may be a rule below, or the default of the target
(traffic inside a zone, where the lost rule blocked it and the zone allows
it). Two more lines can follow: the rules that never matched on the source
and do in the output, as above, and the findings about rules that are not in
the output or are disabled there.

`EXPOSED_BY_CONVERSION` has a second form. A rule that the audit disabled
because other rules decided its traffic the same way is checked once more
against the policy as it was written; should those other rules not be in the
output as they were, the finding says that the rule *is needed again*.

The second audit works on FWShift's model of what it wrote, not on the
output read back: it shows what the conversion knows it changed. It does not
replace testing the output.

### In a pipeline

`--audit-fail-on high` makes both commands end with status 3 when a finding
of that level is reported and not accepted, before or after the conversion.
The findings of a rule that the audit disabled do not count: it was dealt
with. (What the conversion finds about such a rule afterwards does.)
Together with a configuration file that accepts what was reviewed, that
turns the audit into a gate: a new any-to-any rule fails the run, the ones
that were signed off do not.

### Time

The order checks compare every rule with the rules above it. A policy of
1000 rules takes under a second, one of 3000 rules about five seconds, one
of 6000 rules about half a minute (measured on random policies in which a
third of the rules is dead; a tidy rulebase is faster). A policy in which
nearly every rule overlaps with many others takes several times as long:
finding out which rules take part in a dead rule is the expensive part.
Memory stays in the tens of megabytes.

### Limits of the audit

* It reads the policy, not the traffic: no hit counts, no "unused for a
  year".
* Zones have no rank in a configuration. `ANY_SOURCE` from the Internet and
  from the server network look the same.
* `NO_LOG` and `NO_PROFILE` are only raised where the model holds what the
  rule does: logging for PAN-OS and Check Point, profiles for PAN-OS and
  FortiOS. On FortiOS the default of a policy, `logtraffic utm`, logs
  security events and not sessions; the model does not hold that
  difference, so `NO_LOG` is not raised there.
* What is called dead is dead in the model. Where FWShift read a rule
  approximately it says so and claims nothing; where a parser is wrong about
  a rule without knowing it, the audit is wrong with it. A rule that is
  disabled as dead is still in the output, disabled (for iptables: as a
  comment), and in the report.
* NAT rules are checked for shadowing only where one rule applies to a
  connection. NAT is otherwise not audited.
* Applications are compared by name. Two applications that overlap on the
  wire are not known to.
* The audit is new in 0.4 and has, like the converters, been tested on
  synthetic policies only.
