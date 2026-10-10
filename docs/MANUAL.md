# FWShift user manual

FWShift converts firewall policies between Palo Alto PAN-OS and Fortinet
FortiOS and tells you, rule by rule, how faithful the result is. This manual
covers version 0.1.

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

* Every rule of the source appears in the output, in the same order.
* A rule whose match cannot be expressed on the target is written
  **disabled** and listed in the report as *needs review*.
* An object that cannot be converted becomes a placeholder that matches
  nothing, with `FWSHIFT PLACEHOLDER` in its comment, so the output loads and
  the gap is visible.
* Nothing missing or unknown is read as "any".

FWShift converts the **policy**. It does not convert interfaces, routing, VPN,
users, security profiles, or system settings, and it is not a substitute for
testing the result.

> **Status.** Version 0.1 is tested against synthetic configurations. Its
> output has not been validated on PAN-OS or FortiOS devices yet. Use it to
> produce a draft for a lab.

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
   FWShift does not know.
5. **Fix what remains by hand** in the output: placeholders, disabled rules.
6. **Load it in a lab** (section 10) and test.

The two samples in `tests/data` can be used to try this. For example the
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
fwshift convert INPUT --to {panos,fortios,json} [options]
```

`INPUT` is a file, or `-` for standard input.

**Source**

| Option | Meaning |
|---|---|
| `--from {panos,fortios}` | Source format. Detected when left out: XML is PAN-OS, anything else FortiOS. |
| `--vsys NAME` | PAN-OS source with several virtual systems: the one to read. |
| `--device-group NAME` | Panorama source: the device group to read, with its parents and `shared`. |
| `--vdom NAME` | FortiOS source with several VDOMs: the one to read. |

**Target**

| Option | Meaning |
|---|---|
| `--to panos` | PAN-OS `set` commands. |
| `--to fortios` | FortiOS CLI configuration. |
| `--to json` | The neutral model as JSON, for inspection or other tools. |
| `--target-vsys NAME` | PAN-OS: prefix commands with `vsys NAME`. Default: a single-vsys firewall, no prefix. |
| `--target-device-group NAME` | Panorama: write into this device group; rules go to its pre-rulebase. |
| `--target-shared` | Panorama: write into `shared`; rules go to the shared pre-rulebase. |
| `--target-vdom NAME` | FortiOS: wrap the output in `config vdom` / `edit NAME`. |
| `--policy-id-start N` | FortiOS: number policies from N. Default is `edit 0`, which lets the FortiGate pick free ids and appends after existing policies. |

**Adapting the policy**

| Option | Meaning |
|---|---|
| `--zone-map SRC=DST` | Use `DST` wherever the source names zone or interface `SRC`. Repeatable. |
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
fwshift inspect INPUT [--from ...] [--vsys ...] [--device-group ...] [--vdom ...]
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
| `APP_TO_PORTS` | A (R on deny) | To FortiOS: applications were replaced by services with their well-known ports. Layer-7 identification is lost; add application control if needed. On a deny rule the scope of the block changes, so check it. |
| `APP_FILTER_DROPPED` | A (R on deny) | To FortiOS: the rule named applications *and* explicit services. The services are kept, the application match is dropped. |
| `APP_UNKNOWN` | R, disabled | To FortiOS: an application is not in the port table. Add it with `--app-map`. |
| `APP_DEFAULT_ANY` | R, disabled | To FortiOS: "any application on its default ports" has no port-based equivalent. Decide which services the rule should allow. |
| `USER_MATCH`, `URL_CATEGORY` | R, disabled | The rule matched users or URL categories, which are not converted. |
| `UNSUPPORTED_MATCH` | R, disabled | The source rule had a match that is not modelled: HIP profiles, an application filter, FortiOS identity groups, internet-service, ZTNA tags and similar attributes, a negation that cannot be expressed, a missing mandatory field. The message names it. |
| `UNCONVERTIBLE_OBJECT` | R, disabled | The rule refers to an object that could not be converted (see the object's own finding). |
| `SCHEDULE` | R, disabled | The rule had a schedule; converted without it, it would apply at all times. |
| `SERVICE_NEGATE` | R, disabled | To PAN-OS: a negated service match does not exist there. |
| `NO_SERVICE` | R, disabled | To PAN-OS: none of the rule's services could be converted. |
| `RULE_TYPE` | R, disabled | To FortiOS: an intrazone or interzone rule with zone `any` cannot be written as interface pairs. |
| `RULE_TYPE_EMPTY` | I, skipped | An interzone rule whose zones leave no pair of different zones. It matched nothing. |
| `NO_COMMON_FAMILY` | R, skipped | Source and destination share no IP version, or a negation excludes everything. |
| `UNKNOWN_ATTRIBUTES` | R | FortiOS source: the policy has attributes FWShift does not know. If one of them narrows the match, the converted rule is wider. Check them. |
| `NAT_ADDRESS_EXPOSED` | R | The rule covers only one of the two addresses of a destination NAT, and the two platforms look rules up on different sides of the translation (section 8). The rule matches traffic it did not match on the source, or the other way round for a deny. |
| `NAT_PORT_TRANSLATION` | R | A destination NAT used by this rule also changes the port. FortiOS policies name the mapped port, PAN-OS rules the original one; correct the service by hand. |
| `NAT_DESTINATION_REWRITTEN` | A | The destination was changed, or extended, to the address on the other side of a destination NAT. Check that the rule is meant to cover that traffic. |
| `DENY_AND_VIP` | A | FortiOS source: a deny policy covers a virtual IP but has no `set match-vip enable`. FortiOS may have let that traffic through to a later policy; the converted rule blocks it. |
| `FQDN_FAMILY` | A | To PAN-OS: an FQDN that FortiOS resolved for one IP version is resolved for both on PAN-OS, and this rule can match the other version. |
| `PROTOCOL_AS_APP` | A | To PAN-OS: ICMP or IP-protocol services became applications (`ping`, `icmp`, `gre`, ...). Verify the App-ID names. |
| `ICMP_TYPE` | A | To PAN-OS: a service for one ICMP type became App-ID `icmp`, which matches every type. |
| `PROFILES_NOT_CONVERTED` | A | Security profiles on the rule are not converted. Attach equivalent inspection on the target. |
| `PROFILES_BY_NAME` | I | PAN-OS to PAN-OS: profiles are referenced by name and must exist on the target. |
| `DEVICE_TARGET` | R | Panorama source: the rule is pushed to selected devices only. Decide whether it belongs on the target. |
| `RULE_SPLIT` | I | One rule became several: one per zone pair on FortiOS, or one for port-based and one for application-based services on PAN-OS. |
| `RESET_ACTION` | I | To FortiOS: a reset action became deny. |
| `ATTRIBUTES_IGNORED` | I | FortiOS source: NAT details such as `fixedport` have no equivalent. |
| `INCOMPLETE_ADDRESS_PAIR` | I | FortiOS source: addresses of one IP version on one side only. FortiOS cannot match that version, so they were left out. |

### NAT rules

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `NAT_NOT_CONVERTED` | R, skipped | The rule uses something that is not converted (NAT64, dynamic destination translation, an unconvertible object). |
| `NAT_DESTINATION`, `NAT_DESTINATION_SIZE`, `NAT_PORT` | R, skipped | To FortiOS: the destination NAT cannot become a virtual IP: it needs one IPv4 address or range on each side, of equal size, and for a port translation a service with one protocol and one port or range. |
| `NAT_POOL`, `NAT_IPV6` | R, skipped | To FortiOS: the translated address is not a static IPv4 address, or the rule is not IPv4. |
| `NAT_DISABLED` | I, skipped | To FortiOS: a disabled destination NAT rule. No virtual IP is created. |
| `NAT_OVERLAP` | R | FortiOS source: another policy passes overlapping traffic without NAT, for other services. NAT rules do not match on service, so that traffic would be translated. Add a no-NAT rule or narrow this one. |
| `NAT_EXEMPTION` | A | FortiOS source: a no-NAT rule was added for an earlier policy that passes this traffic untranslated. It applies to all services. |
| `NAT_SERVICE_DROPPED` | A or R | To FortiOS: the rule translated one service only; the virtual IP (A) or central SNAT entry (R) applies to all. |
| `NAT_SOURCE_DROPPED` | A | To FortiOS: the destination NAT applied to some sources only; the virtual IP applies to all. |
| `NAT_BIDIRECTIONAL` | A or R | To FortiOS: bi-directional static NAT is written as a central SNAT entry plus a virtual IP. R when the inbound half could not be written. |
| `NAT_STATIC_RANGE` | A | To FortiOS: static NAT of several addresses becomes a one-to-one pool, which does not promise the same translated address per host. |
| `NAT_INTERFACE_ADDRESS` | A | To PAN-OS: source NAT to an interface address was written with the address that interface has in the backup. Use `--interface-map` to follow the interface instead. |
| `VIP_REVERSE_NAT` | A | FortiOS source: a static virtual IP also translates sessions the mapped host opens, when the outgoing policy has NAT. That direction is not converted. |
| `NAT_MERGED` | I | FortiOS source: several policies had identical source NAT and share one rule. |
| `RULE_SPLIT` | I | To PAN-OS: one rule per destination zone. |

### Objects

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `UNSUPPORTED_ADDRESS`, `INVALID_ADDRESS` | R | An address type that is not converted (wildcard mask, geography, dynamic) or a value that cannot be read. Emitted as a placeholder; rules using it are disabled. |
| `UNSUPPORTED_VIP` | R | A virtual IP that is not a static NAT (load balancing and others) or cannot be read. |
| `GROUP_EXCLUDE` | R | A FortiOS address group with excluded members. |
| `UNDEFINED_REFERENCE` | R | A rule names something that is not an object in the input: a region, an external dynamic list, a missing object. Emitted as a placeholder. |
| `UNSUPPORTED_SERVICE` | R | A service that cannot be converted: a proxy service, one limited to a destination address, an unreadable port list. |
| `POOL_TYPE` | A | A FortiOS IP pool type other than overload or one-to-one, converted as port address translation. |
| `FACTORY_DEFAULT` | I | A FortiOS default service was referenced but not defined in the input; the factory definition was assumed. |
| `RENAMED` | I | The name was changed: characters or length the target rejects, a collision, or a name the target predefines. |

### Notes for the whole policy

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `CENTRAL_NAT` | R | To FortiOS: NAT is written as central NAT, which has to be enabled first (section 10). |
| `INTRAZONE_DEFAULT` | R | To FortiOS: PAN-OS allowed traffic inside a zone by default; FortiOS does not. |
| `INTERZONE_DEFAULT` | R | The PAN-OS source overrides `interzone-default` to allow. That is not carried over. |
| `ZONES_WITHOUT_INTERFACES` | R | To FortiOS: zones were created empty. Assign interfaces or use `--zone-map` / `--interface-map`. |
| `ZONES_REQUIRED` | R | To PAN-OS: the zones named by the rules must exist on the target. |
| `INTRAZONE_ALLOW_MERGED` | R | To PAN-OS: `--zone-map` merges a zone that allows intrazone traffic with another one; no allow rule was written for it. |
| `TABLE_NOT_CONVERTED` | R | FortiOS source: a table such as `firewall policy6` or `firewall local-in-policy` has entries and is not converted. |
| `SUSPICIOUS_QUOTING` | R | FortiOS source: a quoted value runs over lines that look like configuration. An unescaped quote may have hidden entries; check the line given. |
| `NO_HIERARCHY` | R | Panorama source without `<readonly>`: parent device groups could not be found. |
| `INTRAZONE_DENY_ADDED` | I | To PAN-OS: `fwshift-intrazone-deny` was appended (section 8). |
| `EXISTING_OBJECTS` | I | To FortiOS: objects are created by name and overwrite existing ones of the same name. |
| `PANORAMA_SOURCE` | I | Reminder of what a Panorama export does not contain. |
| `PRUNED` | I | `--prune-unused` left out this many objects. |

## 8. How the differences between platforms are handled

### Applications and services

PAN-OS matches applications; a FortiOS policy matches ports.

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

### Default behaviour

PAN-OS allows traffic inside a zone unless a rule denies it; FortiOS denies it
unless a policy allows it or the zone has `set intrazone allow`.

*To PAN-OS,* FWShift appends `fwshift-intrazone-deny` (rule type intrazone, any
zone), preceded by `fwshift-intrazone-allow` for the zones that have
`set intrazone allow`. If you merge the output into an existing rulebase, place
these two rules deliberately.

*To FortiOS,* the difference is reported (`INTRAZONE_DEFAULT`). Overrides of
the PAN-OS default rules are read.

### NAT

The neutral model follows PAN-OS: security rules match **pre-NAT** addresses
and the **post-NAT** destination zone, and NAT is a separate ordered rulebase.
FortiOS applies destination NAT first and then looks the policy up against the
**mapped** address. This is where conversions go wrong quietly, so FWShift
reports every place it touches.

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

### Names

Names the target would reject are changed: `10.0.0.0/8` becomes `10.0.0.0_8`
on PAN-OS, FortiOS policy names are cut to 35 characters, collisions get a
numeric suffix, and every reference follows. An object named like something
the target predefines (`all`, `ALL`, `HTTP` on FortiOS; `any`, `service-http`
on PAN-OS) is renamed rather than allowed to redefine it. Each change is
reported as `RENAMED`.

### What is not carried over

Security profiles, schedules, users and groups, URL categories, HIP profiles
and tags (to FortiOS) are not converted. Where a rule depends on one of them
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
| `--zone-map expects SOURCE=TARGET` | Write the option as `--zone-map old=new`. |

**Most rules are "needs review".** Read the first finding of a few rules. A
single cause usually explains many: applications missing from the port table
(`--app-map`), an object type that is not converted, or FortiOS attributes
FWShift does not know.

**The output is larger than expected.** Every object of the source is
converted, used or not; a FortiOS backup alone defines some ninety default
services. Use `--prune-unused`.

**The report mentions `0.0.0.0/0` where the source says `all`.** That is
deliberate: see *IPv4 and IPv6* in section 8.

## 12. Limits

* The emitted syntax follows the vendors' documented formats but has not been
  validated on devices or across OS versions.
* Statements about vendor behaviour that the conversion relies on (FortiOS
  policy lookup after destination NAT, `match-vip`, PAN-OS FQDN resolution, the
  commands each CLI accepts) come from documentation and still need confirming
  on devices.
* A port-translating destination NAT is reported, not corrected.
* A flow that needs destination *and* source NAT from separate FortiOS central
  NAT entries becomes two PAN-OS rules, of which PAN-OS applies only the first.
* Source NAT rules derived from FortiOS policies match on zones and addresses,
  not on the policy's services.
* Dynamic address groups survive only PAN-OS to PAN-OS.
* PAN-OS `set`-format input, Check Point, schedules, and user and group
  mapping are not implemented yet.
