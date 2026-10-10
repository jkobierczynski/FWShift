# FWShift user manual

FWShift converts firewall policies between Palo Alto PAN-OS, Fortinet FortiOS,
Check Point and Linux iptables, and tells you, rule by rule, how faithful the
result is. This manual covers version 0.2.

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

---

## 1. What FWShift does, and what it does not

FWShift reads a configuration, builds a vendor-neutral model of its policy
(objects, security rules, NAT rules), and writes that model in the syntax of
another platform. Alongside the configuration it writes a report.

It follows one rule above all others: **a conversion never makes the policy
more permissive without saying so.** In practice:

* Every rule of the source appears in the output, in the same order, or in
  the report as *skipped* with the reason.
* A rule whose match cannot be expressed on the target is written
  **disabled** and listed in the report as *needs review*.
* An object that cannot be converted becomes a placeholder that matches
  nothing, with `FWSHIFT PLACEHOLDER` in its comment, so the output loads and
  the gap is visible.
* Nothing missing or unknown is read as "any".

FWShift converts the **policy**. It does not convert interfaces, routing, VPN,
users, security profiles, or system settings, and it is not a substitute for
testing the result.

> **Status.** Version 0.2 is tested against synthetic configurations. iptables
> output and input are checked against a Linux kernel (filter rules, one
> kernel and iptables version). Output for PAN-OS, FortiOS and Check Point has
> not been loaded on a device or management server yet, and the Check Point
> input format follows the API documentation. Use FWShift to produce a draft
> for a lab.

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
   `--target-nat-zone` where a Check Point source or target needs them.
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
fwshift convert INPUT --to {panos,fortios,checkpoint,iptables,ip6tables,json} [options]
```

`INPUT` is a file, or `-` for standard input.

**Source**

| Option | Meaning |
|---|---|
| `--from {panos,fortios,checkpoint,iptables,ip6tables}` | Source format. Detected when left out: XML is PAN-OS, JSON is Check Point, a file that starts with a table (`*filter`) or the header of `iptables-save` is iptables, anything else FortiOS. |
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
| `--to iptables` | A file for `iptables-restore`: the IPv4 half of the policy. |
| `--to ip6tables` | A file for `ip6tables-restore`: the IPv6 half. |
| `--to json` | The neutral model as JSON, for inspection or other tools. |
| `--target-vsys NAME` | PAN-OS: prefix commands with `vsys NAME`. Default: a single-vsys firewall, no prefix. |
| `--target-device-group NAME` | Panorama: write into this device group; rules go to its pre-rulebase. |
| `--target-shared` | Panorama: write into `shared`; rules go to the shared pre-rulebase. |
| `--target-nat-zone ZONE` | PAN-OS: destination zone for NAT rules of a source that names none (Check Point, some iptables rules). Without it those NAT rules are skipped. |
| `--target-vdom NAME` | FortiOS: wrap the output in `config vdom` / `edit NAME`. |
| `--policy-id-start N` | FortiOS: number policies from N. Default is `edit 0`, which lets the FortiGate pick free ids and appends after existing policies. |
| `--target-layer NAME` | Check Point: the access layer the rules are written to. Default `Network`. It must exist. |
| `--target-package NAME` | Check Point: the policy package whose NAT rulebase gets the NAT rules. Default `Standard`. |
| `--target-gateway NAME` | Check Point: the gateway or cluster object to hide behind, for source NAT "to the address of the outgoing interface". Without it such rules are skipped unless the source gives an address. |
| `--target-prefix TEXT` | Check Point: put `TEXT` in front of the name of every object the script creates, so that none collides with an object the server has. |

**Adapting the policy**

| Option | Meaning |
|---|---|
| `--zone-map SRC=DST` | Use `DST` wherever the source names zone or interface `SRC`. Repeatable. For iptables this is how a zone becomes an interface name, and the other way round. |
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

All output is UTF-8.

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
| `APP_TO_PORTS` | A (R on deny) | To FortiOS, Check Point or iptables: applications were replaced by services with their well-known ports. Layer-7 identification is lost; add application control if needed. On a deny rule the scope of the block changes, so check it. |
| `APP_FILTER_DROPPED` | A (R on deny) | To a port-based target: the rule named applications *and* explicit services. The services are kept, the application match is dropped. |
| `APP_UNKNOWN` | R, disabled | To a port-based target: an application is not in the port table. Add it with `--app-map`. |
| `APP_DEFAULT_ANY` | R, disabled | To a port-based target: "any application on its default ports" has no port-based equivalent. Decide which services the rule should allow. |
| `USER_MATCH`, `URL_CATEGORY` | R, disabled | The rule matched users or URL categories, which are not converted. |
| `UNSUPPORTED_MATCH` | R, disabled | The source rule had a match that is not modelled: HIP profiles, an application filter, FortiOS identity groups, internet-service, ZTNA tags and similar attributes, a negation that cannot be expressed, a missing mandatory field. The message names it. |
| `UNCONVERTIBLE_OBJECT` | R, disabled | The rule refers to an object that could not be converted (see the object's own finding). |
| `SCHEDULE` | R, disabled | The rule had a schedule; converted without it, it would apply at all times. |
| `SERVICE_NEGATE` | R, disabled | To PAN-OS: a negated service match does not exist there. |
| `NO_SERVICE` | R, disabled | To PAN-OS: none of the rule's services could be converted. |
| `RULE_TYPE` | R, disabled | To FortiOS or iptables: an intrazone or interzone rule with zone `any` cannot be written as interface pairs. |
| `RULE_TYPE_EMPTY` | I, skipped (R to Check Point with zone `any`) | An interzone rule whose zones leave no pair of different zones. It matched nothing. |
| `RULE_TYPE_ANY_ZONE` | R | To Check Point: an intrazone or interzone rule for zone `any` is written for the zones the policy names. For traffic between zones that no rule names it cannot be known whether they are one zone or two: a deny is applied to all of it, an allow to none. |
| `NEGATED_ANY` | R, disabled | To Check Point: a negated "any" matches nothing. |
| `NOT_THIS_IP_VERSION` | I, skipped | To iptables or ip6tables: nothing in the rule can match this IP version. It is in the output for the other one. |
| `INTERFACE_NAME` | R, disabled | To iptables: a zone name that cannot be an interface name. Map it with `--zone-map`. |
| `FQDN_RESOLVED_ONCE` | A | To iptables: a host name is resolved once, when the rules are loaded. |
| `DROP_BEFORE_ESTABLISHED` | R | iptables source: a deny that comes before the rule accepting established connections also dropped the replies of connections opened from the other side. The converted rule blocks new connections in its own direction only. |
| `INLINE_CLEANUP` | I or R | Check Point source: a rule added for the implicit cleanup of an inline layer. R when the export does not show whether the layer drops or accepts and drop was assumed (section 3). |
| `GATEWAY_OBJECT` | A or R | Check Point source: the rule names a gateway object, which stood for every address of the gateway; only its main address is in the export. R where that lets more traffic through: a deny that matches it, or an allow that excludes it. |
| `PROTOCOL_SIGNATURE` | A (R on deny) | Check Point source: a service of the rule also checked the signature of its protocol. Only the port is converted. |
| `NO_COMMON_FAMILY` | R, skipped | Source and destination share no IP version, or a negation excludes everything. |
| `UNKNOWN_ATTRIBUTES` | R | FortiOS or Check Point source: the rule has attributes or fields FWShift does not know. If one of them narrows the match, the converted rule is wider. Check them. |
| `NAT_ADDRESS_EXPOSED` | R | The rule covers only one of the two addresses of a destination NAT, and the two platforms look rules up on different sides of the translation (section 8). The rule matches traffic it did not match on the source, or the other way round for a deny. |
| `NAT_PORT_TRANSLATION` | R | A destination NAT used by this rule also changes the port. FortiOS policies and iptables rules name the mapped port, PAN-OS and Check Point rules the original one; correct the service by hand. |
| `NAT_REDIRECT` | R | iptables source: a DNAT rule without a destination address sends traffic for every destination to one address, and this rule matched it there. A platform that looks rules up before NAT cannot match that traffic with the converted rule: write the rule for the original destinations. |
| `NAT_DESTINATION_REWRITTEN` | A | The destination was changed, or extended, to the address on the other side of a destination NAT. Check that the rule is meant to cover that traffic. |
| `DENY_AND_VIP` | A | FortiOS source: a deny policy covers a virtual IP but has no `set match-vip enable`. FortiOS may have let that traffic through to a later policy; the converted rule blocks it. |
| `FQDN_FAMILY` | A | To PAN-OS or Check Point: an FQDN that FortiOS resolved for one IP version is resolved for both on the target, and this rule can match the other version. |
| `PROTOCOL_AS_APP` | A | To PAN-OS: ICMP or IP-protocol services became applications (`ping`, `icmp`, `gre`, ...). Verify the App-ID names. |
| `ICMP_TYPE` | A | To PAN-OS: a service for one ICMP type became App-ID `icmp`, which matches every type. |
| `PROFILES_NOT_CONVERTED` | A | Security profiles on the rule are not converted. Attach equivalent inspection on the target. |
| `PROFILES_BY_NAME` | I | PAN-OS to PAN-OS: profiles are referenced by name and must exist on the target. |
| `DEVICE_TARGET` | R | Panorama or Check Point source: the rule is installed on selected devices only. Decide whether it belongs on the target. |
| `RULE_SPLIT` | I | One rule became several: one per zone pair on FortiOS, or one for port-based and one for application-based services on PAN-OS. |
| `RESET_ACTION` | I | A reset action has no exact equivalent: deny on FortiOS, a plain `REJECT` on iptables when the rule is not TCP only, `Reject` on Check Point. |
| `ATTRIBUTES_IGNORED` | I | FortiOS source: NAT details such as `fixedport` have no equivalent. |
| `INCOMPLETE_ADDRESS_PAIR` | I | FortiOS source: addresses of one IP version on one side only. FortiOS cannot match that version, so they were left out. |

### NAT rules

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `NAT_NOT_CONVERTED` | R, skipped | The rule uses something that is not converted (NAT64, dynamic destination translation, an unconvertible object), or something the target cannot say: the message names it. To PAN-OS, a rule without a destination zone needs `--target-nat-zone`; to Check Point, source NAT to the outgoing interface needs `--target-gateway`. |
| `NAT_ORDER` | R | From PAN-OS or Check Point to FortiOS or iptables: the source applies one NAT rule to a connection, the first that matches; the target translates destinations and sources in separate tables. This rule now also applies to traffic that another rule used to claim, or loses its source translation to one (section 8). On every target: a NAT rule above this one was not converted, and its traffic now reaches this rule. |
| `NAT_ZONES` | A or R | To Check Point: the rule applied to some zones only and is written without them. R where the zone was the only limit: a source NAT towards one zone now translates traffic towards every zone. |
| `NAT_ZONE_ASSUMED` | A | To PAN-OS: the source rule names no destination zone; the zone given with `--target-nat-zone` was used. |
| `NAT_GROUP` | I | To Check Point: a group was created, because a NAT rule cell holds one object. |
| `NAT_ADDRESSES`, `NAT_SERVICE`, `NAT_RANGE` | R, skipped (`NAT_RANGE`: A) | To iptables: the rule needs static IPv4 addresses and a TCP, UDP or SCTP service. DNAT to a range picks an address per connection. |
| `NAT_ANY_DESTINATION` | R | To iptables: the rule translates traffic to every destination; the security rules were not adjusted to the translated address. |
| `NAT_INPUT_INTERFACE` | A or R | To iptables: source NAT is done in `POSTROUTING`, which cannot match the interface the traffic came in on. R when that was the rule's only limit. |
| `NAT_OUTPUT_INTERFACE` | A | To iptables or FortiOS: a rule that translates destination and source. After the destination translation the traffic leaves by another interface than the rule names, so the source translation is written for every interface. |
| `NAT_AFTER_DNAT` | A | The same kind of rule. Its source translation is matched after the destination was translated, and cannot be tied to the original destination: it also applies to traffic from the same sources that is sent to the translated address directly. iptables output avoids this where the original destination is an address or network (`--ctorigdst`); FortiOS central SNAT cannot. |
| `AUTOMATIC_NAT_IN_GROUP` | R | Check Point source: a manual NAT rule names a group that holds an object with automatic static NAT. In the converted rule the group also matches the translated address; whether Check Point does is not known. |
| `AUTOMATIC_NAT_SHAPE` | R | Check Point source: an automatic NAT rule that does not name the same object in its original and translated column. It was read as it stands. |
| `NAT_DESTINATION`, `NAT_DESTINATION_SIZE`, `NAT_PORT` | R, skipped | To FortiOS: the destination NAT cannot become a virtual IP: it needs one IPv4 address or range on each side, of equal size, and for a port translation a service with one protocol and one port or range. |
| `NAT_POOL` | R, skipped | To FortiOS or iptables: the translated address is not a static IPv4 address, or not exactly one address or range. |
| `NAT_IPV6` | R or I, skipped | To FortiOS: the rule is not IPv4 (R). With `--to ip6tables`: NAT rules are written for IPv4 only (I, on every NAT rule). |
| `NAT_DISABLED` | I | A NAT rule that is disabled in the source. To FortiOS no virtual IP is created for it (skipped); to iptables it is written as a comment line. |
| `NAT_OVERLAP` | R | FortiOS source: another policy passes overlapping traffic without NAT, for other services. NAT rules do not match on service, so that traffic would be translated. Add a no-NAT rule or narrow this one. |
| `NAT_EXEMPTION` | A | FortiOS source: a no-NAT rule was added for an earlier policy that passes this traffic untranslated. It applies to all services. |
| `NAT_SERVICE_DROPPED` | A or R | To FortiOS: the rule translated one service only; the virtual IP (A) or central SNAT entry (R) applies to all. |
| `NAT_SOURCE_DROPPED` | A | To FortiOS: the destination NAT applied to some sources only; the virtual IP applies to all. |
| `NAT_BIDIRECTIONAL` | I, A or R | Bi-directional static NAT is written as two parts: a central SNAT entry plus a virtual IP on FortiOS, an SNAT and a DNAT rule on iptables, two NAT rules on Check Point. R when the inbound half could not be written. |
| `NAT_STATIC_RANGE` | A | To FortiOS: static NAT of several addresses becomes a one-to-one pool, which does not promise the same translated address per host. |
| `NAT_INTERFACE_ADDRESS` | A | To PAN-OS or Check Point: source NAT to an interface address was written with the address that interface has in the backup. Use `--interface-map` (PAN-OS) or `--target-gateway` (Check Point) to follow the interface instead. |
| `VIP_REVERSE_NAT` | A | FortiOS source: a static virtual IP also translates sessions the mapped host opens, when the outgoing policy has NAT. That direction is not converted. |
| `NAT_MERGED` | I | FortiOS source: several policies had identical source NAT and share one rule. |
| `RULE_SPLIT` | I | To PAN-OS: one rule per destination zone. |

### Objects

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `UNSUPPORTED_ADDRESS`, `INVALID_ADDRESS` | R | An address type that is not converted (wildcard mask, geography, dynamic, a Check Point access role, group with exclusion or updatable object), an object that is not in a Check Point export in full, or a value that cannot be read. Emitted as a placeholder; rules using it are disabled. |
| `UNSUPPORTED_VIP` | R | A virtual IP that is not a static NAT (load balancing and others) or cannot be read. |
| `GROUP_EXCLUDE` | R | A FortiOS address group with excluded members. |
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
| `INTRAZONE_DEFAULT` | R | To FortiOS or iptables: the source allowed traffic inside a zone by default and the target does not, or (iptables with `FORWARD` policy `ACCEPT`) the other way round. |
| `INTRAZONE_ALLOW` | R | To iptables: a FortiOS zone with `set intrazone allow`. No rule was written for the traffic between its interfaces. |
| `INTERZONE_DEFAULT` | R | The source allows what no rule matches (a PAN-OS `interzone-default` override, an iptables `FORWARD` policy `ACCEPT`, a Check Point layer whose implicit cleanup accepts). That is not carried over; only iptables output keeps it, as the chain policy. |
| `ZONES_WITHOUT_INTERFACES` | R | To FortiOS: zones were created empty. Assign interfaces or use `--zone-map` / `--interface-map`. |
| `ZONES_REQUIRED` | R | To PAN-OS or Check Point: the zones named by the rules must exist on the target and be assigned to interfaces. |
| `INTERFACES_REQUIRED` | R | To iptables: zones are written as interface names. Map each zone to its interface with `--zone-map`. |
| `INTRAZONE_ALLOW_MERGED` | R | To PAN-OS or Check Point: `--zone-map` merges a zone that allows intrazone traffic with another one; no allow rule was written for it. |
| `NAT_ORDER` | A | To PAN-OS or Check Point, from FortiOS, iptables, or Check Point automatic NAT rules: the source applies a destination NAT rule and a source NAT rule to one connection, the target one NAT rule only (section 8). |
| `TABLE_NOT_CONVERTED` | R | FortiOS source: a table such as `firewall policy6` or `firewall local-in-policy` has entries and is not converted. iptables source: the `mangle`, `raw` or `security` table has rules. |
| `SUSPICIOUS_QUOTING` | R | FortiOS source: a quoted value runs over lines that look like configuration. An unescaped quote may have hidden entries; check the line given. |
| `NO_HIERARCHY` | R | Panorama source without `<readonly>`: parent device groups could not be found. |
| `INTRAZONE_DENY_ADDED` | I | To PAN-OS: `fwshift-intrazone-deny` was appended (section 8). |
| `EXISTING_OBJECTS` | I | To FortiOS: objects are created by name and overwrite existing ones of the same name. |
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

### Zones and interfaces

Zone and interface names are carried over unchanged; rename them with
`--zone-map`. To FortiOS, zones are created, empty unless `--interface-map`
names their interfaces; a zone you map onto an existing name is not created.
To PAN-OS, zones are not created: they must exist.

PAN-OS rule types are translated for FortiOS: an intrazone rule becomes one
policy per zone, an interzone rule one policy per pair of different zones.

iptables has interfaces and nothing else: zones are written as interface
names, so every zone needs a `--zone-map` entry. Check Point rules have no
zone columns; how zones are read and written there is described under
*Check Point* below.

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
(`INTERZONE_DEFAULT`).

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

What is said above for FortiOS holds for iptables, and what is said for PAN-OS
holds for Check Point. The second column matters too:

* **From FortiOS or iptables to PAN-OS or Check Point.** A connection that got
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
| `control characters are not allowed in ...` | An option value holds a line break or another control character. |
| `--target-layer '...' is not a name mgmt_cli can be given` | The name starts with a hyphen. The same message exists for `--target-package` and `--target-gateway`. |
| `--zone-map expects SOURCE=TARGET` | Write the option as `--zone-map old=new`. |

**Most rules are "needs review".** Read the first finding of a few rules. A
single cause usually explains many: applications missing from the port table
(`--app-map`), an object type that is not converted, FortiOS attributes
FWShift does not know, or a Check Point export without `details-level full`
and `dereference-group-members true`, in which the objects are names without
content.

**The output is larger than expected.** Every object of the source is
converted, used or not; a FortiOS backup alone defines some ninety default
services. Use `--prune-unused`.

**The report mentions `0.0.0.0/0` where the source says `all`.** That is
deliberate: see *IPv4 and IPv6* in section 8.

## 12. Limits

* The emitted syntax follows the vendors' documented formats. Only iptables
  output has been loaded into the real thing (a Linux kernel with iptables
  1.8.10, nf_tables backend; filter rules, not NAT); nothing has been
  validated on PAN-OS or FortiOS devices or a Check Point management server,
  or across versions.
* Statements about vendor behaviour that the conversion relies on (FortiOS
  policy lookup after destination NAT, `match-vip`, PAN-OS FQDN resolution, the
  commands each CLI accepts, the fields of the Check Point Management API, what
  an object with automatic NAT matches) come from documentation and still need
  confirming. `DEVELOPMENT.md` lists them.
* A port-translating destination NAT is reported, not corrected.
* A connection that needs destination *and* source NAT from separate FortiOS
  or iptables rules gets one of them on PAN-OS and Check Point; the order of a
  first-match NAT rulebase is reported, not reproduced, on FortiOS and
  iptables (section 8).
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
* PAN-OS `set`-format input, schedules, and user and group mapping are not
  implemented yet.
